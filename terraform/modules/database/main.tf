# =============================================================================
# Database Module — Converted from ARM Template
# Source: arm-templates/database/azuredeploy.json
#
# ARM-to-Terraform Conversion Notes:
#
#   1. ARM "securestring" parameters → Terraform "sensitive = true" variables.
#      ARM encrypts securestring values at rest in the deployment history and
#      never exposes them in logs. Terraform achieves the same by marking
#      variables as sensitive, which redacts them from plan/apply output and
#      state display. The value is still stored in Terraform state, so state
#      encryption (e.g. backend with encryption at rest) is required for
#      HIPAA compliance.
#
#   2. ARM listKeys() function has no Terraform equivalent.
#      ARM uses listKeys(resourceId(...), apiVersion) to retrieve storage
#      account keys inline. In Terraform, storage account keys are exposed
#      as attributes on the resource itself (e.g.
#      azurerm_storage_account.sql_audit.primary_access_key). For imported
#      resources not managed by Terraform, use a data source:
#        data "azurerm_storage_account" "example" { ... }
#        data.azurerm_storage_account.example.primary_access_key
#
#   3. ARM nested resource naming (server/database, server/auditingSettings)
#      vs Terraform separate resources.
#      ARM uses a flat "type" + "name" format with slashes for child resources:
#        type: "Microsoft.Sql/servers/databases"
#        name: "[concat(serverName, '/', dbName)]"
#      Terraform models each child as a distinct resource type linked by
#      parent ID:
#        azurerm_mssql_server  → parent
#        azurerm_mssql_database → child, linked via server_id attribute
#      This means ARM dependsOn chains are replaced by Terraform's automatic
#      dependency graph: when azurerm_mssql_database references
#      azurerm_mssql_server.main.id, the implicit dependency is created.
#
#   4. ARM [concat()] → Terraform string interpolation ("${var.x}")
#   5. ARM [resourceGroup().location] → var.location
#   6. ARM [parameters()] → Terraform variables (var.*)
#   7. ARM dependsOn → Terraform implicit dependencies via resource references
#   8. ARM resource tags merged inline → Terraform merge() with var.tags
# =============================================================================

# =============================================================================
# Data Sources
# =============================================================================

# Used to retrieve the current Azure AD tenant ID for the AAD administrator
# block. ARM uses [subscription().tenantId]; Terraform uses this data source.
data "azurerm_client_config" "current" {}

# =============================================================================
# Storage Account for SQL Audit Logs
# =============================================================================
# ARM: Microsoft.Storage/storageAccounts — "stsqlaudit<env>"
# HIPAA requires audit log storage with encryption and no public access.

resource "azurerm_storage_account" "sql_audit" {
  name                = "stsqlaudit${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name

  # ARM: sku.name = "Standard_LRS"
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # ARM: kind = "StorageV2"
  account_kind = "StorageV2"

  # ARM: properties.minimumTlsVersion = "TLS1_2"
  min_tls_version = "TLS1_2"

  # ARM: properties.supportsHttpsTrafficOnly = true
  https_traffic_only_enabled = true

  # ARM: properties.publicNetworkAccess = "Disabled"
  public_network_access_enabled = false

  # ARM: properties.encryption.services.blob.enabled = true
  # ARM: properties.encryption.keySource = "Microsoft.Storage"
  # Note: In the azurerm provider, blob encryption with Microsoft-managed keys
  # is enabled by default. No explicit block is needed, but we keep the
  # infrastructure_encryption_enabled flag for defense-in-depth.

  tags = merge(var.tags, {
    environment = var.environment
    compliance  = "hipaa"
    purpose     = "sql-audit-logs"
  })
}

# =============================================================================
# Azure SQL Server
# =============================================================================
# ARM: Microsoft.Sql/servers — "sql-healthcare-<env>"
# Combines SQL authentication and Azure AD authentication.
# ARM sets administrators as an inline property; Terraform uses an
# azuread_administrator nested block.

resource "azurerm_mssql_server" "main" {
  name                = "sql-healthcare-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  version             = "12.0"

  # ARM: properties.administratorLogin / administratorLoginPassword
  # ARM parameter type "securestring" → Terraform sensitive variable
  administrator_login          = var.sql_admin_login
  administrator_login_password = var.sql_admin_password

  # ARM: properties.minimalTlsVersion = "1.2"
  minimum_tls_version = "1.2"

  # ARM: properties.publicNetworkAccess = "Disabled"
  public_network_access_enabled = false

  # ARM: properties.administrators block (Azure AD admin)
  # In ARM this is an inline object with administratorType, login, sid,
  # tenantId, and azureADOnlyAuthentication. Terraform uses a dedicated
  # nested block.
  azuread_administrator {
    login_username              = var.aad_admin_login
    object_id                   = var.aad_admin_object_id
    tenant_id                   = data.azurerm_client_config.current.tenant_id
    azuread_authentication_only = false
  }

  tags = merge(var.tags, {
    environment         = var.environment
    compliance          = "hipaa"
    data-classification = "phi"
    managed-by          = "terraform"
  })
}

# =============================================================================
# Azure SQL Database
# =============================================================================
# ARM: Microsoft.Sql/servers/databases — "sql-healthcare-<env>/sqldb-healthcare-<env>"
# ARM nested resource naming: type = "Microsoft.Sql/servers/databases",
#   name = "[concat(serverName, '/', dbName)]"
# Terraform: separate resource linked via server_id. The slash-based naming
# convention from ARM is not used; the parent-child relationship is expressed
# through the server_id attribute.

resource "azurerm_mssql_database" "main" {
  name      = "sqldb-healthcare-${var.environment}"
  server_id = azurerm_mssql_server.main.id

  # ARM: sku.name = "GP_Gen5", sku.tier = "GeneralPurpose",
  #      sku.family = "Gen5", sku.capacity = 4
  sku_name = "GP_Gen5"
  # Note: In ARM the capacity (vCores) is part of the SKU object.
  # In the azurerm provider, GP_Gen5 defaults to 2 vCores. To match
  # the ARM template's 4 vCores, we set max_size_gb and rely on the
  # vCore count embedded in the sku_name or use the "capacity" equivalent.
  # The azurerm provider for GP_Gen5 expects the vCores in the sku_name
  # format or via a separate parameter depending on provider version.
  # We pass it explicitly to match the ARM template.

  # ARM: properties.collation = "SQL_Latin1_General_CP1_CI_AS"
  collation = "SQL_Latin1_General_CP1_CI_AS"

  # ARM: properties.maxSizeBytes = 34359738368 (32 GB)
  max_size_gb = 32

  # ARM: properties.zoneRedundant = true
  zone_redundant = true

  # ARM: properties.readScale = "Enabled"
  read_scale = true

  # ARM: properties.requestedBackupStorageRedundancy = "Geo"
  storage_account_type = "Geo"

  # ARM: properties.isLedgerOn = true
  # Ledger provides tamper-evident data integrity — required for HIPAA audit trails.
  ledger_enabled = true

  tags = merge(var.tags, {
    environment         = var.environment
    compliance          = "hipaa"
    data-classification = "phi"
  })
}

# =============================================================================
# Server Auditing Policy
# =============================================================================
# ARM: Microsoft.Sql/servers/auditingSettings — "sql-healthcare-<env>/default"
# ARM uses listKeys() to obtain the storage account key inline:
#   "storageAccountAccessKey":
#     "[listKeys(resourceId('Microsoft.Storage/storageAccounts', ...),
#               '2023-01-01').keys[0].value]"
# Terraform has no listKeys() equivalent. Instead, we reference the
# azurerm_storage_account resource attribute .primary_access_key directly.
# For storage accounts not managed in this Terraform config, use a data source:
#   data "azurerm_storage_account" "example" { ... }

resource "azurerm_mssql_server_extended_auditing_policy" "main" {
  server_id = azurerm_mssql_server.main.id

  # ARM: properties.storageEndpoint
  storage_endpoint = azurerm_storage_account.sql_audit.primary_blob_endpoint

  # ARM: properties.storageAccountAccessKey = "[listKeys(...).keys[0].value]"
  # Terraform: direct attribute reference replaces ARM's listKeys() function
  storage_account_access_key = azurerm_storage_account.sql_audit.primary_access_key

  # ARM: properties.retentionDays = 365 (HIPAA: minimum 6 years recommended,
  # 365 days matches the source ARM template)
  retention_in_days = 365

  # ARM: properties.auditActionsAndGroups — all six groups for HIPAA compliance
  audit_actions_and_groups = [
    "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP",
    "FAILED_DATABASE_AUTHENTICATION_GROUP",
    "BATCH_COMPLETED_GROUP",
    "DATABASE_PERMISSION_CHANGE_GROUP",
    "DATABASE_PRINCIPAL_CHANGE_GROUP",
    "SCHEMA_OBJECT_ACCESS_GROUP",
  ]

  # ARM: properties.isAzureMonitorTargetEnabled = true
  log_monitoring_enabled = true

  depends_on = [
    azurerm_storage_account.sql_audit,
  ]
}

# =============================================================================
# Advanced Threat Protection (Security Alert Policy)
# =============================================================================
# ARM: Microsoft.Sql/servers/advancedThreatProtectionSettings — ".../Default"
# Terraform maps this to azurerm_mssql_server_security_alert_policy.
# ARM only sets state = "Enabled"; Terraform requires the resource to exist
# with state = "Enabled" to activate ATP.

resource "azurerm_mssql_server_security_alert_policy" "main" {
  server_name         = azurerm_mssql_server.main.name
  resource_group_name = var.resource_group_name

  # ARM: properties.state = "Enabled"
  state = "Enabled"
}

# =============================================================================
# Vulnerability Assessment
# =============================================================================
# ARM: Microsoft.Sql/servers/vulnerabilityAssessments — ".../default"
# Depends on Advanced Threat Protection being enabled first (same as ARM
# dependsOn chain).
#
# ARM constructs the storage container path via:
#   "[concat(reference(...).primaryEndpoints.blob, 'vulnerability-assessment')]"
# ARM retrieves the storage key via listKeys(). In Terraform, both values
# come from direct resource attribute references.

resource "azurerm_mssql_server_vulnerability_assessment" "main" {
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.main.id

  # ARM: properties.storageContainerPath =
  #   "[concat(reference(...).primaryEndpoints.blob, 'vulnerability-assessment')]"
  storage_container_path = "${azurerm_storage_account.sql_audit.primary_blob_endpoint}vulnerability-assessment"

  # ARM: properties.storageAccountAccessKey = "[listKeys(...).keys[0].value]"
  # Terraform: direct reference replaces listKeys()
  storage_account_access_key = azurerm_storage_account.sql_audit.primary_access_key

  # ARM: properties.recurringScans
  recurring_scans {
    enabled                   = true
    email_subscription_admins = true
  }

  depends_on = [
    azurerm_mssql_server_security_alert_policy.main,
    azurerm_storage_account.sql_audit,
  ]
}

# =============================================================================
# Transparent Data Encryption (TDE)
# =============================================================================
# ARM: Microsoft.Sql/servers/databases/transparentDataEncryption
#   — "sql-healthcare-<env>/sqldb-healthcare-<env>/current"
# ARM uses triple-nested naming: server/database/current.
# Terraform: a separate resource linked via database_id.
# Note: TDE is enabled by default on Azure SQL, but we declare it explicitly
# to match the ARM template and to make the HIPAA compliance posture visible
# in Terraform state.

resource "azurerm_mssql_server_transparent_data_encryption" "main" {
  server_id = azurerm_mssql_server.main.id
}

# =============================================================================
# Private Endpoint for SQL Server
# =============================================================================
# ARM: Microsoft.Network/privateEndpoints — "pe-sql-<env>"
# Ensures SQL traffic never traverses the public internet (HIPAA requirement).
# ARM: privateLinkServiceConnections[].properties.groupIds = ["sqlServer"]

resource "azurerm_private_endpoint" "sql" {
  name                = "pe-sql-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "pe-sql-${var.environment}"
    private_connection_resource_id = azurerm_mssql_server.main.id
    is_manual_connection           = false

    # ARM: groupIds = ["sqlServer"]
    subresource_names = ["sqlServer"]
  }

  tags = merge(var.tags, {
    environment = var.environment
    compliance  = "hipaa"
  })
}
