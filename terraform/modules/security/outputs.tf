# =============================================================================
# Outputs — Security Module
# Source: arm-templates/security/azuredeploy.json outputs section
#
# These outputs mirror the ARM template outputs for parity validation,
# plus additional outputs useful for downstream Terraform modules.
#
# ARM outputs converted:
#   outputs.keyVaultId              -> key_vault_id
#   outputs.keyVaultUri             -> key_vault_uri
#   outputs.logAnalyticsWorkspaceId -> log_analytics_workspace_id
#
# Additional Terraform outputs (not in ARM):
#   key_vault_name              — useful for downstream resource naming
#   log_analytics_workspace_name — useful for downstream module references
# =============================================================================

output "key_vault_id" {
  description = "Resource ID of the Key Vault. ARM equivalent: outputs.keyVaultId"
  value       = azurerm_key_vault.main.id
}

output "key_vault_uri" {
  description = "URI of the Key Vault (e.g., https://<name>.vault.azure.net/). ARM equivalent: outputs.keyVaultUri via reference().vaultUri"
  value       = azurerm_key_vault.main.vault_uri
}

output "key_vault_name" {
  description = "Name of the Key Vault (includes random suffix for uniqueness)"
  value       = azurerm_key_vault.main.name
}

output "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace. ARM equivalent: outputs.logAnalyticsWorkspaceId"
  value       = azurerm_log_analytics_workspace.main.id
}

output "log_analytics_workspace_name" {
  description = "Name of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.main.name
}
