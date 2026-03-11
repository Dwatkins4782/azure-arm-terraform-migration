# =============================================================================
# Security Module — Converted from ARM Template
# Source: arm-templates/security/azuredeploy.json
#
# Conversion notes:
#   - ARM [concat()] replaced with Terraform string interpolation
#   - ARM [resourceGroup().location] replaced with var.location
#   - ARM [parameters()] replaced with Terraform variables
#   - ARM dependsOn replaced with implicit Terraform dependency graph
#   - ARM uniqueString(resourceGroup().id) replaced with random_string resource
#     (see note on random_string below)
#   - ARM subscription().tenantId replaced with data.azurerm_client_config
#     (see note on tenant_id below)
#   - ARM guid() for role assignment names replaced by Terraform auto-generated
#     names (see note on role assignments below)
#   - ARM nested diagnostic settings provider path replaced with dedicated
#     azurerm_monitor_diagnostic_setting resource
# =============================================================================

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

# ARM equivalent: subscription().tenantId
#
# In ARM templates, the tenant ID is retrieved via [subscription().tenantId],
# which is a built-in function that resolves at deployment time.
# In Terraform, we use the azurerm_client_config data source to fetch the
# tenant ID (and other identity details) from the currently authenticated
# provider session. This avoids hard-coding tenant IDs and mirrors the
# ARM behavior of deriving the value from the subscription context.
data "azurerm_client_config" "current" {}

# -----------------------------------------------------------------------------
# Random String for Key Vault Name Uniqueness
# -----------------------------------------------------------------------------

# ARM equivalent: uniqueString(resourceGroup().id)
#
# ARM's uniqueString() is a deterministic hash function — given the same input
# (e.g., resourceGroup().id), it always produces the same 13-character string.
# This ensures idempotent deployments: redeploying the same template to the
# same resource group yields the same Key Vault name every time.
#
# Terraform's random_string resource generates a random value once and stores
# it in state, achieving persistence across applies. However, unlike ARM's
# uniqueString(), the value is NOT derived from the resource group — it is
# truly random on first creation. If the Terraform state is lost, a new
# random value will be generated, resulting in a different Key Vault name.
#
# To achieve ARM-like determinism, you could use a combination of
# terraform_data or external data sources with hashing, but random_string
# is the idiomatic Terraform approach for name uniqueness.
resource "random_string" "key_vault_suffix" {
  length  = 8
  upper   = false
  special = false
}

# -----------------------------------------------------------------------------
# Log Analytics Workspace
# -----------------------------------------------------------------------------
# ARM: Microsoft.OperationalInsights/workspaces (apiVersion: 2022-10-01)
#
# The ARM template defines this workspace with PerGB2018 pricing, 365-day
# retention for HIPAA compliance, data export enabled, and public network
# access disabled for both ingestion and query.

resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-healthcare-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name

  # ARM: properties.sku.name = "PerGB2018"
  sku = "PerGB2018"

  # ARM: properties.retentionInDays = 365
  # Required for HIPAA compliance — retains audit data for one full year
  retention_in_days = 365

  # ARM: properties.features.enableDataExport = true
  allow_resource_only_permissions = true

  # ARM: properties.publicNetworkAccessForIngestion = "Disabled"
  # ARM: properties.publicNetworkAccessForQuery = "Disabled"
  # Disabling public access forces traffic through private endpoints,
  # aligning with the zero-trust network posture of this deployment.
  internet_ingestion_enabled = false
  internet_query_enabled     = false

  tags = merge(var.tags, {
    environment = var.environment
    compliance  = "hipaa"
  })
}

# -----------------------------------------------------------------------------
# Key Vault
# -----------------------------------------------------------------------------
# ARM: Microsoft.KeyVault/vaults (apiVersion: 2023-07-01)
#
# The ARM template creates a Premium-tier Key Vault with:
#   - RBAC authorization (no vault-level access policies)
#   - Soft delete with 90-day retention and purge protection
#   - Public network access disabled, default network action Deny
#   - AzureServices bypass for trusted Microsoft services
#
# ARM variable: [concat('kv-hc-', parameters('environment'), '-', uniqueString(resourceGroup().id))]
# Terraform:    "kv-hc-${var.environment}-${random_string.key_vault_suffix.result}"

resource "azurerm_key_vault" "main" {
  name                = "kv-hc-${var.environment}-${random_string.key_vault_suffix.result}"
  location            = var.location
  resource_group_name = var.resource_group_name

  # ARM: parameters('tenantId') with defaultValue of [subscription().tenantId]
  # Terraform: defaults to data.azurerm_client_config.current.tenant_id via
  # the variable default, mirroring the ARM pattern of auto-resolving the
  # tenant ID from the subscription context.
  tenant_id = coalesce(var.tenant_id, data.azurerm_client_config.current.tenant_id)

  # ARM: properties.sku.name = "premium", properties.sku.family = "A"
  sku_name = "premium"

  # ARM: properties.enabledForDeployment = false
  enabled_for_deployment = false

  # ARM: properties.enabledForDiskEncryption = true
  enabled_for_disk_encryption = true

  # ARM: properties.enabledForTemplateDeployment = true
  enabled_for_template_deployment = true

  # ARM: properties.enableSoftDelete = true, properties.softDeleteRetentionInDays = 90
  # Note: In recent Azure API versions, soft delete is enabled by default and
  # cannot be disabled. We set it explicitly here for clarity and parity with
  # the ARM template.
  soft_delete_retention_days = 90

  # ARM: properties.enablePurgeProtection = true
  # WARNING: Once enabled, purge protection cannot be disabled. This is
  # intentional for HIPAA compliance — it prevents permanent key deletion
  # during the soft-delete retention period.
  purge_protection_enabled = true

  # ARM: properties.enableRbacAuthorization = true
  # Uses Azure RBAC for data plane access instead of vault access policies.
  # This aligns with the role assignment defined below for AKS identity.
  enable_rbac_authorization = true

  # ARM: properties.publicNetworkAccess = "Disabled"
  public_network_access_enabled = false

  # ARM: properties.networkAcls
  network_acls {
    # ARM: properties.networkAcls.defaultAction = "Deny"
    default_action = "Deny"

    # ARM: properties.networkAcls.bypass = "AzureServices"
    # Allows trusted Azure services (e.g., Azure Backup, Azure Disk Encryption)
    # to access the vault even when public network access is disabled.
    bypass = "AzureServices"

    # ARM: properties.networkAcls.ipRules = [], properties.networkAcls.virtualNetworkRules = []
    # No IP or VNet rules — all access is via private endpoint.
  }

  tags = merge(var.tags, {
    environment         = var.environment
    compliance          = "hipaa"
    data-classification = "confidential"
    managed-by          = "terraform"
  })
}

# -----------------------------------------------------------------------------
# Key Vault Diagnostic Settings
# -----------------------------------------------------------------------------
# ARM: Microsoft.KeyVault/vaults/providers/diagnosticSettings
#      (apiVersion: 2021-05-01-preview)
#
# In ARM, diagnostic settings use a nested provider path:
#   "[concat(variables('keyVaultName'), '/Microsoft.Insights/diagSettings')]"
# In Terraform, this is a dedicated resource (azurerm_monitor_diagnostic_setting)
# with a target_resource_id pointing to the Key Vault.
#
# The ARM template sends AuditEvent logs (with 365-day retention), Azure Policy
# evaluation details, and AllMetrics to the Log Analytics workspace.

resource "azurerm_monitor_diagnostic_setting" "key_vault" {
  name                       = "diagSettings"
  target_resource_id         = azurerm_key_vault.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  # ARM: logs[0] — AuditEvent with 365-day retention
  # Note: The ARM template sets retentionPolicy on this log category.
  # In Terraform's azurerm provider, log retention is managed at the
  # Log Analytics workspace level (retention_in_days), not per diagnostic
  # setting. The workspace is already configured with 365-day retention.
  enabled_log {
    category = "AuditEvent"
  }

  # ARM: logs[1] — AzurePolicyEvaluationDetails
  enabled_log {
    category = "AzurePolicyEvaluationDetails"
  }

  # ARM: metrics[0] — AllMetrics
  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

# -----------------------------------------------------------------------------
# Role Assignment — Key Vault Secrets User for AKS Identity
# -----------------------------------------------------------------------------
# ARM: Microsoft.Authorization/roleAssignments (apiVersion: 2022-04-01)
#
# ARM role assignment naming:
#   ARM uses [guid(resourceGroup().id, variables('keyVaultName'), 'secrets-user')]
#   to generate a deterministic GUID for the role assignment name. This is
#   required because ARM role assignments must have a GUID as their resource
#   name, and using guid() ensures idempotency across redeployments.
#
#   In Terraform, the azurerm_role_assignment resource auto-generates a unique
#   name internally — you do not need to provide a GUID. Terraform tracks the
#   resource by its state key, making the ARM guid() pattern unnecessary.
#
# ARM scope:
#   The ARM template scopes this assignment to the Key Vault resource via:
#     "scope": "[resourceId('Microsoft.KeyVault/vaults', variables('keyVaultName'))]"
#   In Terraform, we use the scope argument with the Key Vault resource ID.
#
# Role: Key Vault Secrets User (4633458b-17de-408a-b874-0445c86b69e6)
#   Grants read-only access to Key Vault secrets. The AKS managed identity
#   uses this to retrieve application secrets at runtime without granting
#   broader permissions (e.g., Key Vault Administrator).

resource "azurerm_role_assignment" "aks_kv_secrets_user" {
  scope                = azurerm_key_vault.main.id
  principal_id         = var.aks_identity_object_id
  principal_type       = "ServicePrincipal"

  # ARM: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-...')
  # Terraform: Use the built-in role definition ID for "Key Vault Secrets User"
  role_definition_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/4633458b-17de-408a-b874-0445c86b69e6"
}

# -----------------------------------------------------------------------------
# Private Endpoint for Key Vault
# -----------------------------------------------------------------------------
# ARM: Microsoft.Network/privateEndpoints (apiVersion: 2023-05-01)
#
# Provides private connectivity to the Key Vault over the VNet, eliminating
# the need for public internet access. This is critical for HIPAA compliance
# and aligns with the Key Vault's publicNetworkAccess = "Disabled" setting.
#
# ARM variable: [concat('pe-kv-', parameters('environment'))]
# Terraform:    "pe-kv-${var.environment}"

resource "azurerm_private_endpoint" "key_vault" {
  name                = "pe-kv-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  # ARM: properties.privateLinkServiceConnections[0]
  private_service_connection {
    name                           = "pe-kv-${var.environment}"
    private_connection_resource_id = azurerm_key_vault.main.id
    is_manual_connection           = false

    # ARM: properties.privateLinkServiceConnections[0].properties.groupIds = ["vault"]
    subresource_names = ["vault"]
  }

  tags = merge(var.tags, {
    environment = var.environment
    compliance  = "hipaa"
  })
}
