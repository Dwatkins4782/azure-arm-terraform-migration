# =============================================================================
# Terraform Import Blocks — ARM-to-Terraform State Migration
#
# These import blocks bring existing Azure resources (previously deployed by
# ARM templates) under Terraform management WITHOUT recreating them.
#
# Workflow:
#   1. Run aztfexport to generate initial import mappings
#   2. Refine the import blocks to match our module structure
#   3. Run `terraform plan` to verify zero-diff (functional equivalency)
#   4. Run `terraform apply` to write state
#   5. Remove import blocks after successful state adoption
#
# CRITICAL: Always run `terraform plan` before `terraform apply` during imports.
# A plan with ONLY "import" actions and NO "create/update/destroy" confirms parity.
# =============================================================================

# --- Networking Layer Imports ---

import {
  to = module.networking.azurerm_virtual_network.main
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Network/virtualNetworks/vnet-healthcare-prod"
}

import {
  to = module.networking.azurerm_subnet.app
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Network/virtualNetworks/vnet-healthcare-prod/subnets/snet-app"
}

import {
  to = module.networking.azurerm_subnet.data
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Network/virtualNetworks/vnet-healthcare-prod/subnets/snet-data"
}

import {
  to = module.networking.azurerm_subnet.aks
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Network/virtualNetworks/vnet-healthcare-prod/subnets/snet-aks"
}

import {
  to = module.networking.azurerm_subnet.private_endpoints
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Network/virtualNetworks/vnet-healthcare-prod/subnets/snet-private-endpoints"
}

import {
  to = module.networking.azurerm_subnet.bastion
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Network/virtualNetworks/vnet-healthcare-prod/subnets/AzureBastionSubnet"
}

import {
  to = module.networking.azurerm_network_security_group.app
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-app-prod"
}

import {
  to = module.networking.azurerm_network_security_group.data
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-data-prod"
}

import {
  to = module.networking.azurerm_network_security_group.aks
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-aks-prod"
}

import {
  to = module.networking.azurerm_network_security_group.private_endpoints
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-pe-prod"
}

import {
  to = module.networking.azurerm_bastion_host.main
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Network/bastionHosts/bastion-prod"
}

# --- Compute Layer Imports ---

import {
  to = module.compute.azurerm_kubernetes_cluster.main
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.ContainerService/managedClusters/aks-healthcare-prod"
}

import {
  to = module.compute.azurerm_container_registry.main
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.ContainerRegistry/registries/acrhealthcareprod"
}

import {
  to = module.compute.azurerm_user_assigned_identity.aks
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-aks-prod"
}

# --- Database Layer Imports ---

import {
  to = module.database.azurerm_mssql_server.main
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Sql/servers/sql-healthcare-prod"
}

import {
  to = module.database.azurerm_mssql_database.main
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.Sql/servers/sql-healthcare-prod/databases/sqldb-healthcare-prod"
}

# --- Security Layer Imports ---

import {
  to = module.security.azurerm_key_vault.main
  id = "/subscriptions/${var.subscription_id}/resourceGroups/rg-healthcare-prod/providers/Microsoft.KeyVault/vaults/${var.key_vault_name}"
}

variable "subscription_id" {
  description = "Azure Subscription ID for resource import paths"
  type        = string
}

variable "key_vault_name" {
  description = "Existing Key Vault name (includes uniqueString suffix from ARM)"
  type        = string
}
