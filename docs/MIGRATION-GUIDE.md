# ARM-to-Terraform Migration Guide

## Phase 1: Discovery & Inventory

### 1.1 Catalog ARM Templates

```bash
# Find all ARM templates in the repository
find . -name "azuredeploy.json" -o -name "*.arm.json" | sort

# List resources defined in each template
for f in $(find . -name "azuredeploy.json"); do
  echo "=== $f ==="
  jq '.resources[].type' "$f"
done
```

### 1.2 Catalog Deployed Resources

```bash
# List all resources in the target resource group
az resource list \
  --resource-group rg-healthcare-prod \
  --output table

# Export to JSON for cross-referencing
az resource list \
  --resource-group rg-healthcare-prod \
  --output json > deployed-resources.json
```

### 1.3 Map Dependencies

Create a dependency matrix:
- Which ARM templates reference outputs from other templates?
- Which resources have cross-resource-group references?
- Which resources use managed identities or RBAC that span scopes?

## Phase 2: aztfexport — Initial Code Generation

### 2.1 Install Prerequisites

```bash
# Install aztfexport
go install github.com/Azure/aztfexport@latest

# Or via Homebrew (macOS)
brew install aztfexport

# Verify
aztfexport --version
```

### 2.2 Run Export

```bash
# Use our wrapper script for enterprise-grade export
./scripts/aztfexport-wrapper.sh "rg-healthcare-prod" "./aztfexport-output"

# Or run aztfexport directly
aztfexport resource-group rg-healthcare-prod \
  --output-dir ./aztfexport-output \
  --non-interactive \
  --generate-import-block
```

### 2.3 Review aztfexport Output

The raw output requires significant refactoring:

| Issue | Action |
|-------|--------|
| Flat structure (no modules) | Reorganize into `modules/` directory |
| Hardcoded values | Extract to variables with defaults |
| Resource IDs in references | Replace with Terraform resource references |
| Missing properties | Compare with ARM template and add manually |
| Deprecated syntax | Update to current provider version |
| No validation blocks | Add input validation for safety |

## Phase 3: Module Refactoring

### 3.1 Module Design Principles

- One module per infrastructure layer (networking, compute, database, security)
- Modules should be self-contained with clear inputs/outputs
- Use variable validation to enforce constraints
- Extract subnet resources from VNet (avoids lifecycle conflicts)
- Use separate NSG association resources (not inline)

### 3.2 Conversion Patterns — ARM to Terraform

#### Parameters → Variables
```json
// ARM
"parameters": {
  "environment": {
    "type": "string",
    "allowedValues": ["dev", "staging", "prod"]
  }
}
```
```hcl
# Terraform
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}
```

#### Variables → Locals
```json
// ARM
"variables": {
  "vnetName": "[concat('vnet-healthcare-', parameters('environment'))]"
}
```
```hcl
# Terraform — use string interpolation directly in resource names
resource "azurerm_virtual_network" "main" {
  name = "vnet-healthcare-${var.environment}"
}
```

#### dependsOn → Implicit Dependencies
```json
// ARM — explicit dependency declaration required
"dependsOn": [
  "[resourceId('Microsoft.Network/networkSecurityGroups', variables('nsgAppName'))]"
]
```
```hcl
# Terraform — dependencies inferred from references (no explicit dependsOn needed)
resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = azurerm_subnet.app.id                    # implicit dependency
  network_security_group_id = azurerm_network_security_group.app.id    # implicit dependency
}
```

#### uniqueString() → random_string
```json
// ARM — deterministic hash function
"[concat('kv-hc-', parameters('environment'), '-', uniqueString(resourceGroup().id))]"
```
```hcl
# Terraform — random resource persisted in state
resource "random_string" "kv_suffix" {
  length  = 8
  special = false
  upper   = false
}
# Name: "kv-hc-${var.environment}-${random_string.kv_suffix.result}"
```

#### secureString → sensitive variable
```json
// ARM
"sqlAdminPassword": { "type": "securestring" }
```
```hcl
# Terraform
variable "sql_admin_password" {
  type      = string
  sensitive = true  # Redacted in plan/apply output; still in state file
}
```

## Phase 4: State Import

### 4.1 Terraform 1.5+ Import Blocks (Recommended)

```hcl
# imports/import.tf
import {
  to = module.networking.azurerm_virtual_network.main
  id = "/subscriptions/xxx/resourceGroups/rg-healthcare-prod/providers/Microsoft.Network/virtualNetworks/vnet-healthcare-prod"
}
```

```bash
# Plan to verify imports
terraform plan

# Expected output:
# Plan: X to import, 0 to add, 0 to change, 0 to destroy
```

### 4.2 Safety Protocol

1. **Always back up state** before imports: `terraform state pull > backup-$(date +%s).tfstate`
2. **Plan first**: Never apply without reviewing the plan
3. **Import in batches**: One module/layer at a time
4. **Validate after each batch**: Run `terraform plan` to confirm zero drift

### 4.3 Common Import Issues

| Issue | Solution |
|-------|---------|
| Resource has properties Terraform doesn't manage | Add `lifecycle { ignore_changes = [...] }` |
| Import shows unexpected changes | Align Terraform config to match actual state |
| Circular dependencies during import | Import parent resources first, then children |
| Key Vault name with uniqueString suffix | Pass actual name as variable (not regenerated) |

## Phase 5: Validation & Parity

### 5.1 Zero-Diff Verification

```bash
# After all imports, this should show NO changes
terraform plan

# If changes appear, investigate:
# - Is the Terraform config missing a property?
# - Is there a default value mismatch?
# - Did the ARM template set something that's now managed externally?
```

### 5.2 Automated Parity Check

```bash
./scripts/validate-parity.sh "rg-healthcare-prod"
```

### 5.3 Compliance Scan

```bash
# Run OPA/Rego policies
conftest test terraform/environments/prod/ --policy tests/compliance/

# Run Checkov
checkov -d terraform/environments/prod/ --framework terraform
```

## Phase 6: Pipeline Cutover

1. Disable ARM template deployment pipeline
2. Enable Terraform pipeline (azure-pipelines.yml)
3. Run first Terraform apply through pipeline (should be no-op)
4. Monitor for 1-2 weeks
5. Archive ARM templates after validation period

## Phase 7: Decommission

- Move ARM templates to `arm-templates/archived/`
- Update documentation to reference Terraform
- Remove ARM deployment pipeline definitions
- Retain ARM templates in version control for historical reference
