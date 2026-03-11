# Azure ARM-to-Terraform Migration Platform

Enterprise-grade migration framework for converting Azure ARM templates to Terraform modules in a HIPAA-compliant healthcare environment. Includes OAuth 2.0/SAML authentication, ServiceNow ITSM integration, event-driven automation, and comprehensive compliance controls.

## Architecture Overview

```
                        ┌─────────────────────────────────────────────┐
                        │          Azure DevOps Pipeline              │
                        │  ┌─────────┐ ┌──────┐ ┌───────┐ ┌───────┐ │
                        │  │Validate │→│ Plan │→│Import │→│ Apply │ │
                        │  └─────────┘ └──────┘ └───────┘ └───────┘ │
                        └──────┬───────────┬──────────┬──────────────┘
                               │           │          │
                    ┌──────────▼───┐  ┌────▼────┐  ┌──▼──────────────┐
                    │  Checkov     │  │ServiceNow│  │ Event Grid      │
                    │  TFLint      │  │  ITSM    │  │ → Azure Function│
                    │  OPA/Rego    │  │  (REST)  │  │ → CMDB Sync     │
                    └──────────────┘  └─────────┘  └─────────────────┘
                                            │
              ┌─────────────────────────────────────────────────────┐
              │                    Terraform Modules                 │
              │  ┌────────────┐ ┌─────────┐ ┌──────────┐ ┌───────┐│
              │  │ Networking │ │ Compute │ │ Database │ │Security││
              │  │  VNet/NSG  │ │ AKS/ACR │ │ SQL/PE   │ │ KV/LAW││
              │  └────────────┘ └─────────┘ └──────────┘ └───────┘│
              └─────────────────────────────────────────────────────┘
                                            │
              ┌─────────────────────────────────────────────────────┐
              │              Authentication Layer                    │
              │  ┌──────────────┐  ┌──────┐  ┌───────────────────┐ │
              │  │ OAuth 2.0    │  │ SAML │  │Workload Identity  │ │
              │  │ Client Creds │  │ SSO  │  │Federation (OIDC)  │ │
              │  └──────────────┘  └──────┘  └───────────────────┘ │
              └─────────────────────────────────────────────────────┘
```

## Project Structure

```
azure-arm-terraform-migration/
├── arm-templates/                    # Original ARM templates (source)
│   ├── networking/azuredeploy.json   # VNet, subnets, NSGs, Bastion
│   ├── compute/azuredeploy.json      # AKS, ACR, managed identities
│   ├── database/azuredeploy.json     # Azure SQL, auditing, TDE, PE
│   └── security/azuredeploy.json     # Key Vault, Log Analytics, RBAC
│
├── terraform/                        # Converted Terraform modules (target)
│   ├── modules/
│   │   ├── networking/               # ARM networking → Terraform
│   │   ├── compute/                  # ARM compute → Terraform
│   │   ├── database/                 # ARM database → Terraform
│   │   ├── security/                 # ARM security → Terraform
│   │   └── monitoring/               # New: observability stack
│   ├── environments/
│   │   ├── dev/
│   │   ├── staging/
│   │   └── prod/
│   ├── imports/                      # Import blocks for state adoption
│   ├── backend.tf
│   └── versions.tf
│
├── automation/
│   ├── api-integrations/
│   │   ├── servicenow/              # ServiceNow ITSM REST API integration
│   │   └── event-driven/            # Event Grid → Azure Function → CMDB
│   └── auth/
│       ├── oauth2/                  # OAuth 2.0 client credentials + OIDC
│       └── saml/                    # SAML SSO with Azure AD
│
├── scripts/
│   ├── aztfexport-wrapper.sh        # Enterprise aztfexport automation
│   ├── validate-parity.sh           # ARM vs Terraform parity validation
│   └── state-migration.sh           # Safe state import/move operations
│
├── pipelines/
│   ├── azure-pipelines.yml          # Multi-stage CI/CD pipeline
│   └── .tflint.hcl                  # Linting configuration
│
├── tests/compliance/
│   └── hipaa_policy.rego            # OPA policy for HIPAA enforcement
│
└── docs/
    ├── MIGRATION-GUIDE.md           # Step-by-step conversion guide
    ├── ARCHITECTURE.md              # Technical architecture decisions
    └── COMPLIANCE.md                # HIPAA compliance mapping
```

## Key Skills Demonstrated

| Skill | Implementation |
|-------|---------------|
| ARM → Terraform Conversion | Side-by-side ARM templates and equivalent Terraform modules with inline conversion notes |
| Terraform Module Design | Reusable, composable modules with input validation, sensible defaults, and output chaining |
| State Management | Remote backend, import blocks, state migration scripts, multi-layer state isolation |
| aztfexport Workflow | Wrapper script for enterprise aztfexport with post-processing and parity validation |
| OAuth 2.0 | Client credentials flow, workload identity federation (OIDC), managed identity — all with Azure AD |
| SAML | SP metadata generation, assertion parsing, signature validation, Azure AD SAML SSO Terraform config |
| REST API Integration | ServiceNow ITSM change management via REST API with full lifecycle |
| Event-Driven Patterns | Azure Event Grid → Azure Function pipeline for CMDB sync and compliance monitoring |
| Healthcare Compliance | HIPAA controls: encryption at rest/transit, audit logging, PHI access monitoring, OPA policies |
| CI/CD | Azure DevOps multi-stage pipeline with approval gates, compliance scanning, and ServiceNow integration |

## Quick Start

### Prerequisites

- Azure CLI >= 2.55.0
- Terraform >= 1.6.0
- aztfexport >= 0.15.0
- Python >= 3.10
- Azure DevOps organization with service connection

### 1. Export Existing ARM Resources

```bash
# Authenticate to Azure
az login

# Export a resource group using the wrapper script
./scripts/aztfexport-wrapper.sh "rg-healthcare-prod" "./output"
```

### 2. Validate Conversion Parity

```bash
# After refactoring aztfexport output into modules and running terraform import
terraform plan  # Should show: 0 to add, 0 to change, 0 to destroy

# Run automated parity check
./scripts/validate-parity.sh "rg-healthcare-prod"
```

### 3. Deploy via Pipeline

Push to `main` branch to trigger the Azure DevOps pipeline, which will:
1. Validate and lint Terraform code
2. Generate and store the plan
3. Create a ServiceNow change request
4. Wait for approval
5. Apply changes
6. Verify parity and compliance

## Conversion Methodology

This project follows the **Strangler Fig Pattern** for ARM-to-Terraform migration:

1. **Inventory**: Catalog all ARM templates and deployed resources
2. **Export**: Use `aztfexport` to generate initial Terraform from live resources
3. **Refactor**: Restructure exported code into reusable modules
4. **Import**: Adopt existing resources into Terraform state using import blocks
5. **Validate**: Confirm zero-diff plan (functional equivalency)
6. **Cutover**: Switch deployment pipeline from ARM to Terraform
7. **Decommission**: Archive ARM templates after validation period

## License

MIT
