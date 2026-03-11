# Architecture Decisions

## State Management Strategy

### Multi-Layer State Isolation

State files are split by infrastructure layer to minimize blast radius:

```
tfstate/
├── prod/networking.tfstate     # VNet, subnets, NSGs, Bastion
├── prod/compute.tfstate        # AKS, ACR, identities
├── prod/database.tfstate       # SQL Server, databases, audit
├── prod/security.tfstate       # Key Vault, Log Analytics
├── staging/...
└── dev/...
```

**Why**: A failed `terraform apply` on the database layer doesn't risk corrupting networking state. Each layer can be deployed independently with separate approval gates.

### State Backend: Azure Storage with AAD Auth

- **Blob storage** with container-level RBAC (no storage account keys)
- **State locking** via Azure blob lease (prevents concurrent modifications)
- **Versioning enabled** for state file recovery
- **Geo-redundant** storage for disaster recovery

## Authentication Architecture

### CI/CD Pipeline Authentication

```
Azure DevOps Pipeline
        │
        ▼
Workload Identity Federation (OIDC)
        │  (no secrets stored)
        ▼
Azure AD App Registration
        │
        ▼
Service Principal with RBAC
        │
        ├── Contributor (subscription scope)
        └── User Access Administrator (for RBAC assignments)
```

**Why OIDC over client secrets**: No secret rotation needed, no secret storage risk. The pipeline gets a short-lived token via federated identity each run.

### Application Authentication (SAML SSO)

```
User Browser
    │
    ▼
Application (SAML SP)
    │  SAML AuthnRequest
    ▼
Azure AD (SAML IdP)
    │  SAML Response + Assertion
    ▼
Application validates assertion
    │  Extract claims (UPN, groups, employee_id)
    ▼
RBAC based on group membership
```

### Service-to-Service Authentication

```
Azure Function / AKS Pod
        │
        ▼
Managed Identity / Workload Identity
        │  (automatic token from IMDS)
        ▼
OAuth 2.0 Bearer Token
        │
        ├── Azure Resource Manager API
        ├── Azure Key Vault API
        ├── Azure SQL (AAD auth)
        └── ServiceNow REST API (via Key Vault secret)
```

## Event-Driven Integration Architecture

```
Azure Resource (created/modified)
        │
        ▼
Azure Event Grid (system topic)
        │  ResourceWriteSuccess event
        ▼
Event Subscription (webhook)
        │
        ▼
Azure Function (Python)
        │
        ├─── sync_cmdb() ──────► ServiceNow CMDB (REST API)
        │                         POST /api/now/table/cmdb_ci_cloud_object
        │
        ├─── notify_security() ─► Azure Sentinel / Splunk (REST API)
        │                         POST /services/collector/event
        │
        └─── validate_compliance() ► Check HIPAA policies
                                     Alert on violations
```

## Module Dependency Graph

```
monitoring (Layer 1)
    │
    ├────────────────────────────┐
    ▼                            ▼
networking (Layer 3)         security (Layer 2)
    │                            │
    ├────────────┐               │
    ▼            ▼               ▼
compute       database ◄────── security
(Layer 4)     (Layer 5)     (private endpoints)
```

Deployment order: monitoring → networking → compute → security → database

## Network Security Architecture (HIPAA)

```
Internet ──► Azure Firewall ──► App Gateway (WAF)
                                      │
                                      ▼
                              ┌── snet-app ──────── NSG: HTTPS only
                              │
VNet 10.0.0.0/16 ────────────┼── snet-aks ──────── NSG: 443 + 10250
                              │
                              ├── snet-data ─────── NSG: 1433 from app+aks
                              │
                              ├── snet-pe ───────── NSG: Deny all (PE only)
                              │
                              └── AzureBastionSubnet
                                        │
                                        ▼
                                  Azure Bastion (management access)

All data subnets: Private Endpoints only, no public IPs
All traffic: Forced through Azure Firewall via UDR
```
