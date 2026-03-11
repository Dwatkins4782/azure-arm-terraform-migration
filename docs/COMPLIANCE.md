# HIPAA Compliance Controls Mapping

## Overview

This document maps HIPAA Security Rule requirements to specific infrastructure controls implemented in this Terraform codebase.

## Technical Safeguards (45 CFR 164.312)

### Access Control (164.312(a)(1))

| Control | Implementation | Terraform Resource |
|---------|---------------|-------------------|
| Unique User ID | Azure AD authentication for all services | `azuread_application`, AAD-only SQL auth |
| Emergency Access | Break-glass admin accounts in Azure AD | Managed outside Terraform (PIM) |
| Automatic Logoff | AKS pod session timeouts, SQL connection timeouts | App-level configuration |
| Encryption & Decryption | TDE for SQL, encryption at host for AKS, Key Vault | `azurerm_mssql_server_transparent_data_encryption`, AKS `enable_encryption_at_host` |

### Audit Controls (164.312(b))

| Control | Implementation | Terraform Resource |
|---------|---------------|-------------------|
| SQL Audit Logging | Extended auditing with 365-day retention | `azurerm_mssql_server_extended_auditing_policy` |
| Key Vault Audit | Diagnostic settings for all operations | `azurerm_monitor_diagnostic_setting.key_vault` |
| Network Audit | VNet diagnostic settings, NSG flow logs | `azurerm_monitor_diagnostic_setting.vnet` |
| Activity Logging | Azure Activity Log → Log Analytics | `azurerm_log_analytics_workspace` |
| Failed Auth Alerts | Scheduled query alert on SigninLogs | `azurerm_monitor_scheduled_query_rules_alert_v2.failed_auth` |
| PHI Access Alerts | SQL access pattern anomaly detection | `azurerm_monitor_scheduled_query_rules_alert_v2.phi_access_anomaly` |

### Integrity Controls (164.312(c)(1))

| Control | Implementation | Terraform Resource |
|---------|---------------|-------------------|
| ePHI Integrity | SQL Ledger (immutable audit trail) | `azurerm_mssql_database` with `ledger_enabled = true` |
| Data Validation | SQL vulnerability assessments | `azurerm_mssql_server_vulnerability_assessment` |
| Threat Detection | Advanced Threat Protection | `azurerm_mssql_server_security_alert_policy` |

### Transmission Security (164.312(e)(1))

| Control | Implementation | Terraform Resource |
|---------|---------------|-------------------|
| Encryption in Transit | TLS 1.2 minimum on all services | SQL `minimum_tls_version = "1.2"`, Storage `min_tls_version = "TLS1_2"` |
| Private Networking | Private endpoints for SQL, Key Vault | `azurerm_private_endpoint.sql`, `azurerm_private_endpoint.key_vault` |
| No Public Access | Public network access disabled | `public_network_access = "Disabled"` on SQL, KV, ACR, LAW |
| Network Segmentation | NSGs with deny-all defaults | `azurerm_network_security_group` with explicit allow rules |

### Person/Entity Authentication (164.312(d))

| Control | Implementation | Terraform Resource |
|---------|---------------|-------------------|
| Azure AD Auth | AAD-integrated AKS, SQL AAD admin | AKS `aad_profile`, SQL `azuread_administrator` |
| Workload Identity | Pod-level identity (no shared secrets) | AKS `workload_identity_enabled`, `oidc_issuer_enabled` |
| Managed Identity | Service-to-service auth without secrets | `azurerm_user_assigned_identity` |
| RBAC | Role-based access, least privilege | `azurerm_role_assignment` (Key Vault Secrets User) |

## Physical Safeguards (Managed by Azure)

- Data center physical security: Azure SOC 2 Type II certified
- Availability zones: AKS deployed across zones 1, 2, 3
- Geo-redundant backups: SQL `requestedBackupStorageRedundancy = "Geo"`

## OPA/Rego Policy Enforcement

The `tests/compliance/hipaa_policy.rego` file enforces:

1. **Encryption at rest** must be enabled on all data stores
2. **Public network access** must be disabled
3. **TLS version** must be 1.2 or higher
4. **Audit logging** must be enabled
5. **Soft delete** must be enabled on Key Vault
6. **Compliance tags** must be present on all resources

These policies run in the CI/CD pipeline before `terraform apply`.
