# Azure Key Vault RBAC Migration — Incident Root Cause Analysis

## Executive Summary

During a routine migration of Azure Key Vault from **Access Policies** to **RBAC authorization**,
a `terraform plan` detected a force-replacement trigger on the Key Vault resource. Because the
Azure DevOps pipeline had no approval gate before `terraform apply`, the change was automatically
applied — cascading through **50+ AKS clusters** across multiple sub-environments within the dev
environment. All clusters were destroyed and recreated with new secrets, causing a major outage
and ArgoCD failures across the entire development platform.

This document provides:
1. **Root cause analysis** — why this happened at the Terraform provider level
2. **Why Kubernetes clusters were affected** — the cascade chain from Key Vault to AKS
3. **Why 50+ clusters were destroyed** — the multi-environment blast radius
4. **Prevention strategy** — three-tier protection with pipeline gates
5. **Correct migration approach** — out-of-band migration pattern

---

## Table of Contents

- [1. What Happened](#1-what-happened)
- [2. Root Cause — Force-Replace Trigger](#2-root-cause--force-replace-trigger)
- [3. Why Kubernetes Clusters Were Affected](#3-why-kubernetes-clusters-were-affected)
- [4. The Full Cascade Chain](#4-the-full-cascade-chain)
- [5. Why 50+ Clusters Were Destroyed](#5-why-50-clusters-were-destroyed)
- [6. Timeline of Failure](#6-timeline-of-failure)
- [7. Three-Tier Prevention Strategy](#7-three-tier-prevention-strategy)
- [8. The Correct Migration Approach](#8-the-correct-migration-approach)
- [9. Pipeline with Approval Gates](#9-pipeline-with-approval-gates)
- [10. Terraform Lifecycle Protections](#10-terraform-lifecycle-protections)
- [11. Post-Incident Recovery Playbook](#11-post-incident-recovery-playbook)
- [12. Lessons Learned](#12-lessons-learned)

---

## 1. What Happened

### The Change

A team member added a single line to the Terraform configuration for the Key Vault:

```hcl
# BEFORE — Access Policies model
resource "azurerm_key_vault" "main" {
  name                = "kv-platform-dev"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku_name            = "standard"
  tenant_id           = data.azurerm_client_config.current.tenant_id

  # Access policies defined inline or via separate resources
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = var.aks_identity_object_id
    key_permissions    = ["Get", "List", "WrapKey", "UnwrapKey"]
    secret_permissions = ["Get", "List"]
  }
}

# AFTER — RBAC model (the "simple" one-line change)
resource "azurerm_key_vault" "main" {
  name                       = "kv-platform-dev"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = azurerm_resource_group.main.location
  sku_name                   = "standard"
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  enable_rbac_authorization  = true    # <-- THIS LINE CAUSED THE OUTAGE
}
```

### The Result

```
Plan: 127 to add, 0 to change, 127 to destroy.
```

Every Key Vault, every AKS cluster, every node pool, every Helm release, every ArgoCD
application — all marked for destruction and recreation.

---

## 2. Root Cause — Force-Replace Trigger

### Why `enable_rbac_authorization` Is Destructive

In the AzureRM Terraform provider, the `enable_rbac_authorization` property on
`azurerm_key_vault` is flagged as **ForceNew**. This means:

```
ForceNew = changing this property DESTROYS the existing resource
           and CREATES a brand new one
```

The Azure Resource Manager API treats the authorization model as an **immutable property**
of the Key Vault. You cannot simply flip a switch from Access Policies to RBAC on an
existing vault — the underlying Azure API requires the resource to be recreated.

### What Terraform Sees

When Terraform detects that `enable_rbac_authorization` changed from `false` to `true`:

```
# azurerm_key_vault.main must be replaced
-/+ resource "azurerm_key_vault" "main" {
      ~ id                          = "/subscriptions/.../kv-platform-dev" -> (known after apply)
      ~ enable_rbac_authorization   = false -> true  # forces replacement
      ~ vault_uri                   = "https://kv-platform-dev.vault.azure.net/" -> (known after apply)
        name                        = "kv-platform-dev"
        # ... all other attributes recomputed
    }
```

The critical detail: **the resource ID changes**. The old vault is destroyed, a new vault
is created, and every resource that references the old vault's ID or URI is now pointing
at a resource that no longer exists.

### Important Note on Azure API Versions

As of Azure API version `2023-07-01`, Microsoft has been working on making RBAC migration
non-destructive. However:

- The AzureRM Terraform provider may still treat it as ForceNew depending on version
- The `azapi` provider can work around this in some cases
- **Always verify the behavior in your specific provider version before planning**

---

## 3. Why Kubernetes Clusters Were Affected

This is the critical question: **why did a Key Vault change destroy AKS clusters?**

The answer: **AKS clusters are NOT just "infrastructure" — they are deeply integrated with
Key Vault through encryption, identity, and secret management.**

### The AKS-to-Key-Vault Dependency Chain

```
┌─────────────────────────────────────────────────────────────────────┐
│  WHAT PEOPLE THINK THE CHANGE IS:                                  │
│                                                                     │
│    Key Vault (Access Policy → RBAC)  ← Just a permission change    │
│                                                                     │
│  WHAT ACTUALLY HAPPENS IN TERRAFORM:                                │
│                                                                     │
│    Key Vault DESTROYED → New Key Vault created → New resource ID   │
│         │                                                           │
│         ├── KMS Encryption Key references old vault ID              │
│         │    └── AKS disk encryption set references old key         │
│         │         └── AKS cluster uses old encryption config        │
│         │              └── FORCE REPLACE AKS CLUSTER                │
│         │                                                           │
│         ├── AKS Key Vault Secrets Provider references old vault     │
│         │    └── CSI SecretProviderClass points to old vault URI     │
│         │         └── Pod volumes can't mount → pods crash          │
│         │                                                           │
│         ├── AKS identity had access policy on OLD vault             │
│         │    └── New vault has no policies → AKS can't auth         │
│         │         └── Kubelet can't pull secrets → node failure     │
│         │                                                           │
│         └── Terraform state has old vault ID everywhere             │
│              └── Every dependent resource shows drift               │
│                   └── Mass force-replacement cascade                │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Specific AKS Dependencies on Key Vault

Here is every way an AKS cluster depends on Key Vault:

#### 1. Disk Encryption (Customer-Managed Keys)

```hcl
# The encryption key lives IN the Key Vault
resource "azurerm_key_vault_key" "aks_encryption" {
  name         = "aks-disk-encryption"
  key_vault_id = azurerm_key_vault.main.id    # ← references vault ID
  key_type     = "RSA"
  key_size     = 2048
}

# The disk encryption set references the key
resource "azurerm_disk_encryption_set" "aks" {
  name                = "des-aks-dev"
  key_vault_key_id    = azurerm_key_vault_key.aks_encryption.id  # ← chain continues
}

# AKS references the disk encryption set
resource "azurerm_kubernetes_cluster" "main" {
  disk_encryption_set_id = azurerm_disk_encryption_set.aks.id   # ← AKS depends on vault
}
```

**When the vault is destroyed**, the encryption key is destroyed, the disk encryption set
becomes invalid, and AKS must be recreated because its encryption configuration is broken.

#### 2. Secrets Provider (CSI Driver)

```hcl
resource "azurerm_kubernetes_cluster" "main" {
  key_vault_secrets_provider {
    secret_rotation_enabled  = true
    secret_rotation_interval = "5m"
  }
}
```

The AKS Secrets Provider addon is configured at cluster creation time. When the vault
it points to is destroyed, the addon configuration becomes invalid.

#### 3. etcd Encryption (KMS Plugin)

```hcl
resource "azurerm_kubernetes_cluster" "main" {
  key_management_service {
    key_vault_key_id         = azurerm_key_vault_key.etcd_encryption.id
    key_vault_network_access = "Public"
  }
}
```

AKS uses Key Vault keys to encrypt etcd at rest. The `key_vault_key_id` is an
**immutable** property — changing it forces cluster replacement.

#### 4. Managed Identity Permissions

```hcl
resource "azurerm_key_vault_access_policy" "aks_kubelet" {
  key_vault_id = azurerm_key_vault.main.id    # ← old vault ID
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
}
```

When the vault is recreated, all access policies are gone. AKS identity loses all
permissions immediately.

### Why This Is NOT "Just Infrastructure"

People often think of "infrastructure" as VNets, subnets, and load balancers — things that
are decoupled from the application layer. But AKS clusters are:

- **Stateful**: They contain running pods, persistent volumes, secrets, and configs
- **Identity-bound**: Kubelet, CSI drivers, and workload identities all authenticate to Key Vault
- **Encryption-coupled**: Disk encryption and etcd encryption reference specific vault keys
- **Configuration-immutable**: Many AKS properties (encryption, identity) are ForceNew in Terraform

**AKS is infrastructure AND application platform simultaneously.** Destroying an AKS cluster
doesn't just destroy infrastructure — it destroys the entire application runtime:

```
AKS Cluster Destroyed
    ├── All worker nodes terminated
    │    └── All running pods killed instantly
    ├── All node pools deleted
    │    └── Any local PVs lost permanently
    ├── All Helm releases orphaned
    │    ├── Prometheus — monitoring gone
    │    ├── Grafana — dashboards lost
    │    ├── ArgoCD — GitOps engine gone
    │    ├── Falco — security monitoring gone
    │    └── All application deployments gone
    ├── All Kubernetes secrets deleted
    │    ├── TLS certificates
    │    ├── Database connection strings
    │    └── API keys (if stored in K8s secrets)
    ├── All ConfigMaps deleted
    │    └── Application configuration gone
    ├── Service Mesh configuration gone
    └── DNS records pointing to old LB IPs
         └── External traffic black-holed
```

---

## 4. The Full Cascade Chain

Here is the exact order of operations when Terraform processes the force-replace:

```
Step 1: Terraform detects enable_rbac_authorization changed
        → Marks azurerm_key_vault.main for REPLACEMENT

Step 2: All resources referencing key_vault.main.id detected
        → azurerm_key_vault_key.aks_encryption marked REPLACE
        → azurerm_key_vault_key.etcd_encryption marked REPLACE
        → azurerm_key_vault_access_policy.* marked DESTROY
        → azurerm_key_vault_secret.* marked REPLACE

Step 3: Resources referencing the keys detected
        → azurerm_disk_encryption_set.aks marked REPLACE

Step 4: Resources referencing disk encryption set detected
        → azurerm_kubernetes_cluster.main marked REPLACE (ForceNew)

Step 5: Resources depending on AKS cluster detected
        → azurerm_kubernetes_cluster_node_pool.* marked REPLACE
        → helm_release.* marked DESTROY/RECREATE
        → kubernetes_namespace.* marked DESTROY/RECREATE
        → kubernetes_secret.* marked DESTROY/RECREATE

Step 6: ArgoCD applications referencing old cluster
        → All synced resources become orphaned
        → ArgoCD itself is destroyed (it runs IN the cluster)
        → GitOps loop broken

TOTAL IMPACT: 1 property change → 127+ resource replacements
```

### The Terraform Dependency Graph (Visual)

```
                    enable_rbac_authorization = true
                              │
                    ┌─────────▼─────────┐
                    │  azurerm_key_vault │  ◄── FORCE REPLACE
                    │   (kv-platform-*)  │
                    └─────────┬─────────┘
                              │
            ┌─────────────────┼─────────────────┐
            │                 │                 │
    ┌───────▼───────┐ ┌──────▼──────┐ ┌───────▼────────┐
    │ key_vault_key │ │ access_policy│ │ key_vault_secret│
    │ (encryption)  │ │  (AKS RBAC) │ │  (app secrets)  │
    └───────┬───────┘ └─────────────┘ └────────────────┘
            │
    ┌───────▼──────────┐
    │ disk_encryption   │
    │ _set              │
    └───────┬──────────┘
            │
    ┌───────▼──────────────────────────────┐
    │ azurerm_kubernetes_cluster           │  ◄── FORCE REPLACE
    │ (Every AKS cluster using this vault) │
    └───────┬──────────────────────────────┘
            │
    ┌───────┼───────────┬────────────────┐
    │       │           │                │
┌───▼──┐ ┌─▼────┐ ┌────▼────┐ ┌────────▼────────┐
│Node  │ │Node  │ │ Helm    │ │ K8s Resources   │
│Pool 1│ │Pool 2│ │Releases │ │ (ns, secrets,   │
│      │ │      │ │         │ │  configmaps)    │
└──────┘ └──────┘ └────┬────┘ └─────────────────┘
                       │
            ┌──────────┼──────────┐
            │          │          │
      ┌─────▼──┐ ┌────▼───┐ ┌───▼─────┐
      │ArgoCD  │ │Promethe│ │ Falco   │
      │        │ │us Stack│ │ + Trivy │
      └────────┘ └────────┘ └─────────┘
```

---

## 5. Why 50+ Clusters Were Destroyed

### The Multi-Environment Within Dev Pattern

In large organizations, "dev" is not a single environment. It typically contains
**multiple sub-environments**, each with their own AKS cluster:

```
Dev Environment (Azure Subscription: sub-dev-001)
├── dev-team-alpha        (AKS cluster: aks-dev-alpha)
├── dev-team-beta         (AKS cluster: aks-dev-beta)
├── dev-team-gamma        (AKS cluster: aks-dev-gamma)
├── dev-integration       (AKS cluster: aks-dev-integration)
├── dev-performance       (AKS cluster: aks-dev-perf)
├── dev-sandbox-01..20    (AKS clusters: aks-dev-sandbox-*)
├── dev-feature-xyz       (AKS cluster: aks-dev-feature-xyz)
├── dev-qa-01..10         (AKS clusters: aks-dev-qa-*)
├── dev-demo              (AKS cluster: aks-dev-demo)
└── dev-training-01..15   (AKS clusters: aks-dev-training-*)
                          ──────────────────────────────────
                          Total: 50+ AKS clusters
```

### Three Patterns That Cause Mass Destruction

#### Pattern 1: Shared Key Vault Across Sub-Environments

The most common and most dangerous pattern:

```hcl
# ONE Key Vault shared by ALL dev clusters
resource "azurerm_key_vault" "dev_shared" {
  name = "kv-platform-dev"
  # ... all 50+ clusters reference THIS vault
}

# Each cluster references the shared vault
resource "azurerm_kubernetes_cluster" "team_alpha" {
  key_management_service {
    key_vault_key_id = azurerm_key_vault_key.dev_shared_etcd.id
  }
}

resource "azurerm_kubernetes_cluster" "team_beta" {
  key_management_service {
    key_vault_key_id = azurerm_key_vault_key.dev_shared_etcd.id
  }
}

# ... 48 more clusters all pointing to the same vault
```

When the shared vault is force-replaced, **every cluster** referencing it gets marked
for replacement. One Key Vault change → 50+ cluster replacements.

#### Pattern 2: Single Terraform State Managing All Dev Clusters

```
terraform/
└── environments/
    └── dev/
        └── main.tf        # ← Defines ALL 50+ clusters in one state file
```

When all clusters are in a single Terraform state:
- `terraform plan` evaluates ALL resources together
- A single dependency change cascades to EVERYTHING in the state
- `terraform apply` modifies ALL affected resources at once
- There is no isolation between teams or sub-environments

#### Pattern 3: Module-Level Cascade Through `for_each`

```hcl
# Common pattern: generate clusters dynamically
variable "dev_environments" {
  default = {
    "alpha"        = { node_count = 2, vm_size = "Standard_D4s_v3" }
    "beta"         = { node_count = 2, vm_size = "Standard_D4s_v3" }
    "gamma"        = { node_count = 3, vm_size = "Standard_D8s_v3" }
    # ... 47 more entries
  }
}

module "aks_cluster" {
  for_each = var.dev_environments
  source   = "../../modules/aks"

  cluster_name   = "aks-dev-${each.key}"
  key_vault_id   = azurerm_key_vault.dev_shared.id   # ← ALL share one vault
}
```

With `for_each`, all 50 clusters are generated from the same module. When the shared
`key_vault_id` input changes (due to vault recreation), ALL module instances are affected.

### Why "Just the Infrastructure" Wasn't the Only Casualty

When AKS is managed by Terraform AND Helm releases are also managed by Terraform (or
by a provider that depends on the AKS kubeconfig), the blast radius extends to everything:

```hcl
# Helm provider depends on AKS cluster's kubeconfig
provider "helm" {
  kubernetes {
    host                   = azurerm_kubernetes_cluster.main.kube_config[0].host
    client_certificate     = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_certificate)
    client_key             = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].client_key)
    cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.main.kube_config[0].cluster_ca_certificate)
  }
}

# When AKS is replaced → kubeconfig changes → ALL Helm releases destroyed
resource "helm_release" "argocd" {
  name       = "argocd"
  # ← depends on the Helm provider which depends on AKS
}

resource "helm_release" "prometheus" {
  name       = "kube-prometheus-stack"
  # ← also destroyed and recreated
}
```

**This is why "infrastructure" and "Kubernetes" are not separate concerns in Terraform.**
The Helm provider, Kubernetes provider, and AzureRM provider all share the same dependency
graph. Destroying AKS destroys everything that runs on it.

---

## 6. Timeline of Failure

```
T+0:00   Developer pushes Terraform change (enable_rbac_authorization = true)
T+0:01   Azure DevOps pipeline triggered automatically
T+0:02   terraform init completes
T+0:03   terraform plan runs — shows 127 resources to destroy/recreate
         ⚠️  NO HUMAN REVIEWS THE PLAN OUTPUT
T+0:04   Pipeline proceeds directly to terraform apply (NO GATE)
T+0:05   terraform apply begins destroying resources
T+0:06   Key Vault destroyed — all secrets, keys, certificates GONE
T+0:10   First AKS cluster replacement begins
T+0:15   Worker nodes draining — pods evicted
T+0:20   10 clusters destroyed — ArgoCD errors flooding Slack
T+0:30   Teams notice applications are down
T+0:35   Incident declared — pipeline still running
T+0:40   Pipeline manually cancelled — but 50+ clusters already destroyed
T+1:00   New clusters being created by Terraform — but empty
T+2:00   ArgoCD reinstalled — but can't sync (old secrets don't match)
T+4:00   Manual secret rotation begins across all clusters
T+8:00   Most applications restored with manual intervention
T+24:00  Full recovery verified across all sub-environments
```

---

## 7. Three-Tier Prevention Strategy

### Tier 1: Terraform Lifecycle Blocks

**Purpose**: Prevent Terraform from ever planning the destruction of critical resources.

```hcl
# Protect Key Vault from accidental destruction
resource "azurerm_key_vault" "main" {
  name                      = "kv-platform-dev"
  resource_group_name       = azurerm_resource_group.main.name
  location                  = azurerm_resource_group.main.location
  sku_name                  = "standard"
  tenant_id                 = data.azurerm_client_config.current.tenant_id
  enable_rbac_authorization = true  # Only change AFTER out-of-band migration

  # CRITICAL: Prevent accidental destruction
  lifecycle {
    prevent_destroy = true

    # Also prevent changes to immutable properties
    ignore_changes = [
      enable_rbac_authorization,  # Only change via out-of-band migration
    ]
  }
}

# Protect EVERY AKS cluster
resource "azurerm_kubernetes_cluster" "main" {
  name                = "aks-${var.environment}"
  # ... cluster config

  lifecycle {
    prevent_destroy = true

    ignore_changes = [
      # Ignore properties that should only change via controlled rollout
      key_management_service,
      disk_encryption_set_id,
    ]
  }
}
```

**What this does**: If anyone tries to `terraform apply` a change that would destroy the
Key Vault or AKS cluster, Terraform will **hard-fail** with an error instead of proceeding.

### Tier 2: Pipeline Critical Resource Check

**Purpose**: Analyze `terraform plan` output and block if critical resources would be destroyed.

```bash
#!/bin/bash
# scripts/check-critical-resources.sh
#
# Analyzes terraform plan JSON output for dangerous operations
# on critical resource types. Returns exit code 1 if any are found.

set -euo pipefail

PLAN_JSON="${1:?Usage: $0 <plan.json>}"
CRITICAL_TYPES=(
  "azurerm_key_vault"
  "azurerm_kubernetes_cluster"
  "azurerm_kubernetes_cluster_node_pool"
  "azurerm_disk_encryption_set"
  "azurerm_key_vault_key"
  "azurerm_sql_server"
  "azurerm_cosmosdb_account"
  "azurerm_storage_account"
)

echo "=== Critical Resource Protection Check ==="
echo "Analyzing plan for destructive operations..."
echo ""

BLOCKED=false

for resource_type in "${CRITICAL_TYPES[@]}"; do
  # Count resources of this type being destroyed or replaced
  DESTROY_COUNT=$(jq -r "
    [.resource_changes[]
     | select(.type == \"${resource_type}\")
     | select(.change.actions | contains([\"delete\"]))
    ] | length
  " "$PLAN_JSON")

  REPLACE_COUNT=$(jq -r "
    [.resource_changes[]
     | select(.type == \"${resource_type}\")
     | select(.change.actions == [\"delete\", \"create\"])
    ] | length
  " "$PLAN_JSON")

  if [ "$DESTROY_COUNT" -gt 0 ] || [ "$REPLACE_COUNT" -gt 0 ]; then
    echo "🚨 BLOCKED: ${resource_type}"
    echo "   Destroying: ${DESTROY_COUNT}  |  Replacing: ${REPLACE_COUNT}"

    # Show which specific resources
    jq -r "
      .resource_changes[]
      | select(.type == \"${resource_type}\")
      | select(.change.actions | contains([\"delete\"]))
      | \"   → \" + .address + \" (\" + (.change.actions | join(\", \")) + \")\"
    " "$PLAN_JSON"

    BLOCKED=true
  fi
done

echo ""

if [ "$BLOCKED" = true ]; then
  echo "════════════════════════════════════════════════════════════════"
  echo "  PIPELINE BLOCKED: Critical resources would be destroyed     "
  echo "                                                              "
  echo "  This requires manual review and approval.                   "
  echo "  If this change is intentional, use the manual override      "
  echo "  pipeline with the 'FORCE_APPLY' parameter.                  "
  echo "════════════════════════════════════════════════════════════════"
  exit 1
else
  echo "✅ No critical resources affected. Safe to proceed."
  exit 0
fi
```

### Tier 3: Manual Approval Gate

**Purpose**: Require human approval before any `terraform apply` that modifies
infrastructure — especially for changes that affect production or shared resources.

This is implemented in the pipeline YAML (see [Section 9](#9-pipeline-with-approval-gates)).

---

## 8. The Correct Migration Approach

### Out-of-Band Migration (Zero-Drift Pattern)

The correct way to migrate Key Vault from Access Policies to RBAC is to **make the
change outside of Terraform first**, then update Terraform to match the new state.

```bash
# ============================================================
# Step 1: Pre-Migration Preparation
# ============================================================

# 1a. Document current access policies
az keyvault show --name kv-platform-dev \
  --query "properties.accessPolicies" -o json > access-policies-backup.json

# 1b. Map access policies to RBAC role assignments
# For each access policy, determine the equivalent RBAC role:
#
#   Key Permissions:
#     Get, List, Decrypt, Encrypt, WrapKey, UnwrapKey
#     → "Key Vault Crypto User" (or "Key Vault Crypto Officer")
#
#   Secret Permissions:
#     Get, List
#     → "Key Vault Secrets User"
#     Set, Delete
#     → "Key Vault Secrets Officer"
#
#   Certificate Permissions:
#     Get, List
#     → "Key Vault Certificate User"
#     Create, Import, Delete
#     → "Key Vault Certificates Officer"

# 1c. Create RBAC role assignments BEFORE enabling RBAC
VAULT_ID=$(az keyvault show --name kv-platform-dev --query id -o tsv)

# For each identity that had access policies:
az role assignment create \
  --assignee "<object-id-of-aks-identity>" \
  --role "Key Vault Crypto User" \
  --scope "$VAULT_ID"

az role assignment create \
  --assignee "<object-id-of-aks-identity>" \
  --role "Key Vault Secrets User" \
  --scope "$VAULT_ID"

# For the pipeline service principal:
az role assignment create \
  --assignee "<object-id-of-pipeline-sp>" \
  --role "Key Vault Secrets Officer" \
  --scope "$VAULT_ID"

# For each developer/team that needs access:
az role assignment create \
  --assignee "<object-id-of-developer>" \
  --role "Key Vault Secrets User" \
  --scope "$VAULT_ID"

# ============================================================
# Step 2: Enable RBAC on the Key Vault (via Azure CLI, not Terraform)
# ============================================================

# This changes the vault IN AZURE without Terraform knowing
az keyvault update \
  --name kv-platform-dev \
  --enable-rbac-authorization true

# ============================================================
# Step 3: Verify Access Still Works
# ============================================================

# Test that AKS can still access secrets
az keyvault secret show \
  --vault-name kv-platform-dev \
  --name test-secret

# Test from inside an AKS pod
kubectl exec -it test-pod -- \
  cat /mnt/secrets-store/test-secret

# ============================================================
# Step 4: Import the New State into Terraform
# ============================================================

# Update your Terraform code to match the new reality
# Add enable_rbac_authorization = true
# Remove access_policy blocks
# Add azurerm_role_assignment resources

# Then import the existing (now RBAC-enabled) vault into state
terraform import azurerm_key_vault.main \
  "/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/kv-platform-dev"

# Import each role assignment
terraform import azurerm_role_assignment.aks_crypto_user \
  "/subscriptions/<sub-id>/providers/Microsoft.Authorization/roleAssignments/<assignment-id>"

# ============================================================
# Step 5: Verify Zero Drift
# ============================================================

terraform plan
# Should show: "No changes. Your infrastructure matches the configuration."
```

### Why This Works

1. **Azure CLI changes the vault in-place** — no destroy/recreate
2. **RBAC role assignments are created first** — no access gap
3. **Terraform state is updated to match** — no drift
4. **Plan shows no changes** — verification that everything aligns

---

## 9. Pipeline with Approval Gates

See the companion file: `pipelines/azure-pipelines-with-gates.yml`

The pipeline implements all three tiers of protection:

1. **Plan stage** — Generates plan JSON output and counts destructive operations
2. **Critical Resource Check** — Hard-blocks on Key Vault, AKS, DB destruction
3. **Manual Approval** — Requires human review for any destructive changes
4. **Auto-Approve** — Non-destructive changes proceed automatically
5. **Apply stage** — Only runs after gate clearance

---

## 10. Terraform Lifecycle Protections

### Complete Protection Template

Apply these lifecycle blocks to ALL critical resources:

```hcl
# ================================================================
# Key Vault — ALWAYS protect
# ================================================================
resource "azurerm_key_vault" "main" {
  # ... config ...

  lifecycle {
    prevent_destroy = true
  }
}

# ================================================================
# AKS Clusters — ALWAYS protect
# ================================================================
resource "azurerm_kubernetes_cluster" "main" {
  # ... config ...

  lifecycle {
    prevent_destroy = true
    ignore_changes = [
      key_management_service,
      disk_encryption_set_id,
      microsoft_defender,
    ]
  }
}

# ================================================================
# Node Pools — Protect in production
# ================================================================
resource "azurerm_kubernetes_cluster_node_pool" "system" {
  # ... config ...

  lifecycle {
    prevent_destroy = true
    ignore_changes = [
      node_count,  # Let autoscaler manage
    ]
  }
}

# ================================================================
# Disk Encryption Sets — Protect always
# ================================================================
resource "azurerm_disk_encryption_set" "aks" {
  # ... config ...

  lifecycle {
    prevent_destroy = true
  }
}

# ================================================================
# Databases — ALWAYS protect
# ================================================================
resource "azurerm_mssql_server" "main" {
  # ... config ...

  lifecycle {
    prevent_destroy = true
  }
}

# ================================================================
# Storage Accounts — Protect if they hold state or data
# ================================================================
resource "azurerm_storage_account" "tfstate" {
  # ... config ...

  lifecycle {
    prevent_destroy = true
  }
}
```

### What `prevent_destroy` Does

```
Without prevent_destroy:
  terraform plan  → "1 to destroy"
  terraform apply → Resource destroyed ❌

With prevent_destroy:
  terraform plan  → "1 to destroy"
  terraform apply → ERROR: Instance cannot be destroyed ✅
                    "Resource azurerm_key_vault.main has lifecycle
                     prevent_destroy set, but the plan calls for
                     this resource to be destroyed."
```

The pipeline stops. No resources are destroyed. An engineer must explicitly
remove the lifecycle block to proceed — which requires a code review.

---

## 11. Post-Incident Recovery Playbook

If the cascade has already happened, here is the recovery procedure:

### Phase 1: Stop the Bleeding (0-15 minutes)

```bash
# 1. Cancel the running pipeline IMMEDIATELY
# Azure DevOps → Pipelines → Running → Cancel

# 2. Lock Terraform state to prevent further damage
az storage blob lease acquire \
  --account-name tfstateaccount \
  --container-name tfstate \
  --blob-name dev/terraform.tfstate \
  --lease-duration 60

# 3. Take a snapshot of current state (for forensics)
az storage blob snapshot \
  --account-name tfstateaccount \
  --container-name tfstate \
  --blob-name dev/terraform.tfstate
```

### Phase 2: Assess Damage (15-30 minutes)

```bash
# List all AKS clusters that still exist
az aks list --query "[].{Name:name, State:provisioningState, RG:resourceGroup}" -o table

# Check Key Vault status
az keyvault list --query "[].{Name:name, State:properties.provisioningState}" -o table

# Check for soft-deleted vaults (recoverable!)
az keyvault list-deleted --query "[].{Name:name, DeletedDate:properties.deletionDate}" -o table
```

### Phase 3: Recover Key Vault (30-60 minutes)

```bash
# If Key Vault has soft-delete enabled (default since 2020):
az keyvault recover --name kv-platform-dev

# Verify secrets are intact
az keyvault secret list --vault-name kv-platform-dev -o table
```

### Phase 4: Recover AKS Clusters (1-4 hours)

```bash
# For each destroyed cluster, Terraform will create new ones
# But they will be EMPTY — no applications deployed

# Option A: Let Terraform recreate and ArgoCD resync
terraform apply  # Creates new clusters
# Then reinstall ArgoCD and let it sync everything

# Option B: Import existing clusters if some survived
terraform import azurerm_kubernetes_cluster.main \
  "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ContainerService/managedClusters/<name>"
```

### Phase 5: Restore Applications (2-8 hours)

```bash
# 1. Reinstall ArgoCD on each cluster
helm install argocd argo/argo-cd -n argocd --create-namespace

# 2. Apply ArgoCD ApplicationSets (this will sync everything)
kubectl apply -f kubernetes/argocd/applicationsets.yaml

# 3. Rotate secrets that were in the old Key Vault
# (Even if recovered, rotate as a security precaution)

# 4. Verify all applications are healthy
argocd app list --server argocd.internal
```

---

## 12. Lessons Learned

### 1. Never Modify Immutable Properties In-Place

Some Azure resource properties are immutable and trigger recreation. Always check the
Terraform provider documentation for `ForceNew` flags before modifying:

| Resource | Immutable Properties |
|----------|---------------------|
| Key Vault | `enable_rbac_authorization`, `purge_protection_enabled`, `name` |
| AKS | `dns_prefix`, `key_management_service`, `disk_encryption_set_id` |
| SQL Server | `administrator_login`, `version` |
| Storage Account | `account_kind`, `is_hns_enabled` |

### 2. Always Use Pipeline Gates

Every Terraform pipeline should have:
- **Plan output review** — humans read what will change
- **Critical resource check** — automated detection of dangerous operations
- **Manual approval** — required for any destructive change
- **Environment-scoped apply** — never apply all environments at once

### 3. Isolate State by Blast Radius

```
❌ BAD: All 50 clusters in one state file
   One change can cascade to everything

✅ GOOD: State per team/sub-environment
   terraform/environments/dev/team-alpha/
   terraform/environments/dev/team-beta/
   terraform/environments/dev/integration/
   Each has its own state — blast radius is 1 cluster
```

### 4. Use Lifecycle Blocks on ALL Critical Resources

`prevent_destroy` is your last line of defense. Even if the pipeline gate fails,
even if the manual approval is bypassed, Terraform itself will refuse to destroy
the resource.

### 5. Test Migrations in an Isolated Sandbox First

Before applying any change to `enable_rbac_authorization`:
1. Create a throwaway Key Vault + AKS cluster
2. Apply the change
3. Observe what Terraform plans to do
4. If it shows force-replace, use the out-of-band approach instead

### 6. Monitor for Drift Separately

Run `terraform plan` on a schedule (without auto-apply) to detect drift early:

```yaml
# Scheduled drift detection — runs daily, never applies
schedules:
  - cron: "0 6 * * *"
    displayName: "Daily Drift Check"
    branches:
      include: [main]
    always: true
```

---

## Related Documents

- [Migration Guide](MIGRATION-GUIDE.md) — ARM-to-Terraform conversion process
- [Architecture Decisions](ARCHITECTURE.md) — State management and layer isolation
- [Pipeline with Gates](../pipelines/azure-pipelines-with-gates.yml) — Complete pipeline YAML
- [Critical Resource Check Script](../scripts/check-critical-resources.sh) — Automated safety check
