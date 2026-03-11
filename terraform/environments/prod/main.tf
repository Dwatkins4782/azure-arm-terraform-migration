# =============================================================================
# Production Environment — Root Module
# Composes all modules for the healthcare production environment.
# This is the target state after ARM-to-Terraform conversion.
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "stterraformhcstate"
    container_name       = "tfstate"
    key                  = "prod/main.tfstate"
    use_azuread_auth     = true
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = false # Safety: never purge in prod
    }
  }
}

locals {
  environment = "prod"
  location    = "eastus2"

  common_tags = {
    environment    = local.environment
    compliance     = "hipaa"
    managed-by     = "terraform" # Changed from "arm-template" after migration
    cost-center    = "healthcare-platform"
    data-sensitivity = "phi"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "rg-healthcare-${local.environment}"
  location = local.location
  tags     = local.common_tags
}

# --- Layer 1: Monitoring (deployed first, referenced by other modules) ---

module "monitoring" {
  source = "../../modules/monitoring"

  environment         = local.environment
  location            = local.location
  resource_group_name = azurerm_resource_group.main.name
  retention_days      = 365
  alert_email_addresses = var.alert_email_addresses

  tags = local.common_tags
}

# --- Layer 2: Security (Key Vault, Log Analytics) ---

module "security" {
  source = "../../modules/security"

  environment                = local.environment
  location                   = local.location
  resource_group_name        = azurerm_resource_group.main.name
  aks_identity_object_id     = module.compute.aks_identity_principal_id
  private_endpoint_subnet_id = module.networking.private_endpoint_subnet_id

  tags = local.common_tags

  depends_on = [module.networking, module.compute]
}

# --- Layer 3: Networking ---

module "networking" {
  source = "../../modules/networking"

  environment                    = local.environment
  location                       = local.location
  resource_group_name            = azurerm_resource_group.main.name
  vnet_address_prefix            = "10.0.0.0/16"
  app_subnet_prefix              = "10.0.1.0/24"
  data_subnet_prefix             = "10.0.2.0/24"
  bastion_subnet_prefix          = "10.0.3.0/27"
  aks_subnet_prefix              = "10.0.4.0/22"
  private_endpoint_subnet_prefix = "10.0.8.0/24"
  log_analytics_workspace_id     = module.monitoring.log_analytics_workspace_id

  tags = local.common_tags
}

# --- Layer 4: Compute (AKS + ACR) ---

module "compute" {
  source = "../../modules/compute"

  environment                = local.environment
  location                   = local.location
  resource_group_name        = azurerm_resource_group.main.name
  aks_subnet_id              = module.networking.aks_subnet_id
  log_analytics_workspace_id = module.monitoring.log_analytics_workspace_id
  aks_version                = "1.28.5"
  aks_node_count             = 3
  aks_node_vm_size           = "Standard_D4s_v5"

  tags = local.common_tags
}

# --- Layer 5: Database ---

module "database" {
  source = "../../modules/database"

  environment                = local.environment
  location                   = local.location
  resource_group_name        = azurerm_resource_group.main.name
  sql_admin_login            = var.sql_admin_login
  sql_admin_password         = var.sql_admin_password
  aad_admin_object_id        = var.aad_admin_object_id
  aad_admin_login            = var.aad_admin_login
  private_endpoint_subnet_id = module.networking.private_endpoint_subnet_id
  log_analytics_workspace_id = module.monitoring.log_analytics_workspace_id

  tags = local.common_tags
}
