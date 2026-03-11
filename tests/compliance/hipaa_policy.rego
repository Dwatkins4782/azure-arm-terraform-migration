# =============================================================================
# HIPAA Compliance Policy for Terraform Plans
#
# Evaluated by OPA (Open Policy Agent) against a Terraform plan JSON.
# Each rule inspects planned resource configurations to enforce HIPAA
# security requirements for Azure infrastructure.
#
# Usage:
#   terraform plan -out=tfplan.binary
#   terraform show -json tfplan.binary > tfplan.json
#   opa eval --input tfplan.json --data hipaa_policy.rego "data.terraform.compliance"
#
# Structure:
#   deny[msg]  — Hard failures that block deployment
#   warn[msg]  — Advisory warnings that should be reviewed
# =============================================================================

package terraform.compliance

import input as tfplan
import future.keywords.in
import future.keywords.contains
import future.keywords.if

# ---------------------------------------------------------------------------
# Helper: extract all planned resources from the Terraform plan JSON.
# Handles both root module and child module resources.
# ---------------------------------------------------------------------------
planned_resources[resource] {
    resource := tfplan.planned_values.root_module.resources[_]
}

planned_resources[resource] {
    module := tfplan.planned_values.root_module.child_modules[_]
    resource := module.resources[_]
}

# Recursive helper for deeply nested child modules
planned_resources[resource] {
    module := tfplan.planned_values.root_module.child_modules[_]
    child := module.child_modules[_]
    resource := child.resources[_]
}

# ---------------------------------------------------------------------------
# Helper: extract resource changes (create/update) from the plan
# ---------------------------------------------------------------------------
resource_changes[change] {
    change := tfplan.resource_changes[_]
    # Only evaluate resources being created or updated
    some action in change.change.actions
    action in ["create", "update"]
}

# =============================================================================
# DENY: Encryption at rest must be enabled
#
# HIPAA 164.312(a)(2)(iv) — Encryption and decryption.
# All data at rest must be encrypted.
# =============================================================================

# -- Storage accounts must have infrastructure encryption enabled
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_storage_account"
    not resource.values.infrastructure_encryption_enabled
    msg := sprintf(
        "HIPAA-ENC-001: Storage account '%s' does not have infrastructure encryption enabled. Enable infrastructure_encryption_enabled = true.",
        [resource.address]
    )
}

# -- SQL Server databases must have transparent data encryption (TDE)
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_mssql_database"
    vals := resource.values
    # TDE is enabled by default on Azure SQL, but can be explicitly disabled
    vals.transparent_data_encryption_enabled == false
    msg := sprintf(
        "HIPAA-ENC-002: SQL Database '%s' has Transparent Data Encryption disabled. TDE must be enabled for HIPAA compliance.",
        [resource.address]
    )
}

# -- Managed disks must use encryption
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_managed_disk"
    vals := resource.values
    # disk_encryption_set_id should be set for customer-managed key encryption
    not vals.disk_encryption_set_id
    vals.encryption_settings == null
    msg := sprintf(
        "HIPAA-ENC-003: Managed disk '%s' does not reference a disk encryption set. Use customer-managed keys for HIPAA data.",
        [resource.address]
    )
}

# -- Cosmos DB accounts must enforce encryption
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_cosmosdb_account"
    vals := resource.values
    not vals.key_vault_key_id
    msg := sprintf(
        "HIPAA-ENC-004: Cosmos DB account '%s' does not use a customer-managed encryption key. Set key_vault_key_id for HIPAA compliance.",
        [resource.address]
    )
}

# =============================================================================
# DENY: Public network access must be disabled
#
# HIPAA 164.312(e)(1) — Transmission security.
# Resources containing PHI must not be publicly accessible.
# =============================================================================

# -- Storage accounts must disable public network access
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_storage_account"
    vals := resource.values
    vals.public_network_access_enabled == true
    msg := sprintf(
        "HIPAA-NET-001: Storage account '%s' has public network access enabled. Set public_network_access_enabled = false.",
        [resource.address]
    )
}

# -- SQL Servers must disable public network access
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_mssql_server"
    vals := resource.values
    vals.public_network_access_enabled == true
    msg := sprintf(
        "HIPAA-NET-002: SQL Server '%s' has public network access enabled. Set public_network_access_enabled = false.",
        [resource.address]
    )
}

# -- Key Vaults must disable public network access
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_key_vault"
    vals := resource.values
    vals.public_network_access_enabled == true
    msg := sprintf(
        "HIPAA-NET-003: Key Vault '%s' has public network access enabled. Restrict access to private endpoints only.",
        [resource.address]
    )
}

# -- Cosmos DB must disable public network access
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_cosmosdb_account"
    vals := resource.values
    vals.public_network_access_enabled == true
    msg := sprintf(
        "HIPAA-NET-004: Cosmos DB account '%s' has public network access enabled. Set public_network_access_enabled = false.",
        [resource.address]
    )
}

# -- PostgreSQL Flexible Server must disable public network access
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_postgresql_flexible_server"
    vals := resource.values
    vals.public_network_access_enabled == true
    msg := sprintf(
        "HIPAA-NET-005: PostgreSQL Flexible Server '%s' has public network access enabled. Set public_network_access_enabled = false.",
        [resource.address]
    )
}

# =============================================================================
# DENY: TLS version must be 1.2 or higher
#
# HIPAA 164.312(e)(2)(ii) — Encryption for data in transit.
# All services must enforce TLS 1.2 as the minimum version.
# =============================================================================

# -- Storage accounts must enforce TLS 1.2+
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_storage_account"
    vals := resource.values
    vals.min_tls_version != "TLS1_2"
    msg := sprintf(
        "HIPAA-TLS-001: Storage account '%s' minimum TLS version is '%s'. Must be 'TLS1_2' or higher.",
        [resource.address, vals.min_tls_version]
    )
}

# -- SQL Server must enforce TLS 1.2+
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_mssql_server"
    vals := resource.values
    vals.minimum_tls_version != "1.2"
    msg := sprintf(
        "HIPAA-TLS-002: SQL Server '%s' minimum TLS version is '%s'. Must be '1.2'.",
        [resource.address, vals.minimum_tls_version]
    )
}

# -- PostgreSQL Flexible Server must enforce TLS 1.2+
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_postgresql_flexible_server"
    vals := resource.values
    # PostgreSQL uses ssl_enforcement_enabled and ssl_minimal_tls_version_enforced
    vals.ssl_enforcement_enabled == false
    msg := sprintf(
        "HIPAA-TLS-003: PostgreSQL server '%s' does not enforce SSL. Set ssl_enforcement_enabled = true.",
        [resource.address]
    )
}

# -- App Service / Function App must enforce TLS 1.2+
deny contains msg if {
    resource := planned_resources[_]
    resource.type in ["azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_linux_function_app", "azurerm_windows_function_app"]
    site_config := resource.values.site_config[_]
    site_config.minimum_tls_version != "1.2"
    msg := sprintf(
        "HIPAA-TLS-004: App Service '%s' minimum TLS is '%s'. Must be '1.2'.",
        [resource.address, site_config.minimum_tls_version]
    )
}

# =============================================================================
# DENY: Audit logging must be enabled
#
# HIPAA 164.312(b) — Audit controls.
# All systems must maintain audit logs of access and changes.
# =============================================================================

# -- SQL Server must have auditing enabled
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_mssql_server"

    # Check that a corresponding audit policy exists in the plan
    not sql_server_has_audit_policy(resource.values.name)
    msg := sprintf(
        "HIPAA-AUD-001: SQL Server '%s' does not have an associated audit policy (azurerm_mssql_server_extended_auditing_policy). Enable audit logging.",
        [resource.address]
    )
}

sql_server_has_audit_policy(server_name) {
    audit := planned_resources[_]
    audit.type == "azurerm_mssql_server_extended_auditing_policy"
}

# -- Storage accounts should have logging via diagnostic settings
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_storage_account"

    not storage_has_diagnostic_setting(resource.values.name)
    msg := sprintf(
        "HIPAA-AUD-002: Storage account '%s' does not have an associated diagnostic setting (azurerm_monitor_diagnostic_setting). Enable audit logging.",
        [resource.address]
    )
}

storage_has_diagnostic_setting(storage_name) {
    diag := planned_resources[_]
    diag.type == "azurerm_monitor_diagnostic_setting"
}

# -- Key Vault must have logging enabled
deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_key_vault"

    not keyvault_has_diagnostic_setting(resource.values.name)
    msg := sprintf(
        "HIPAA-AUD-003: Key Vault '%s' does not have an associated diagnostic setting. Enable audit logging for all Key Vault operations.",
        [resource.address]
    )
}

keyvault_has_diagnostic_setting(vault_name) {
    diag := planned_resources[_]
    diag.type == "azurerm_monitor_diagnostic_setting"
}

# =============================================================================
# DENY: Soft delete must be enabled on Key Vault
#
# HIPAA 164.312(c)(1) — Integrity controls.
# Key material must be protected from accidental or malicious deletion.
# =============================================================================

deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_key_vault"
    vals := resource.values
    vals.soft_delete_retention_days == 0
    msg := sprintf(
        "HIPAA-KV-001: Key Vault '%s' does not have soft delete enabled. Set soft_delete_retention_days >= 7.",
        [resource.address]
    )
}

deny contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_key_vault"
    vals := resource.values
    not vals.purge_protection_enabled
    msg := sprintf(
        "HIPAA-KV-002: Key Vault '%s' does not have purge protection enabled. Set purge_protection_enabled = true.",
        [resource.address]
    )
}

# =============================================================================
# WARN: Resources should have compliance tags
#
# Not a hard HIPAA requirement, but strongly recommended for governance.
# All resources should be tagged with data classification and compliance scope.
# =============================================================================

required_tags := {"environment", "data_classification", "compliance"}

warn contains msg if {
    resource := planned_resources[_]
    vals := resource.values
    tags := object.get(vals, "tags", {})
    tags != null

    some required_tag in required_tags
    not tags[required_tag]

    msg := sprintf(
        "HIPAA-TAG-001: Resource '%s' (%s) is missing required tag '%s'. Add tags: environment, data_classification, compliance.",
        [resource.address, resource.type, required_tag]
    )
}

warn contains msg if {
    resource := planned_resources[_]
    vals := resource.values
    tags := object.get(vals, "tags", null)
    tags == null

    msg := sprintf(
        "HIPAA-TAG-002: Resource '%s' (%s) has no tags defined. Add tags including: environment, data_classification, compliance.",
        [resource.address, resource.type]
    )
}

# =============================================================================
# WARN: Network security groups should not have overly permissive rules
# =============================================================================

warn contains msg if {
    resource := planned_resources[_]
    resource.type == "azurerm_network_security_rule"
    vals := resource.values
    vals.direction == "Inbound"
    vals.access == "Allow"
    vals.source_address_prefix == "*"
    vals.destination_port_range == "*"
    msg := sprintf(
        "HIPAA-NSG-001: NSG rule '%s' allows inbound traffic from any source to any port. Restrict source and destination for HIPAA environments.",
        [resource.address]
    )
}

# =============================================================================
# Summary output — aggregate deny and warn counts for CI/CD reporting
# =============================================================================

violation_count := count(deny)
warning_count := count(warn)

compliance_status := "PASS" if {
    violation_count == 0
} else := "FAIL"

summary := {
    "status": compliance_status,
    "violations": violation_count,
    "warnings": warning_count,
    "deny_messages": deny,
    "warn_messages": warn,
}
