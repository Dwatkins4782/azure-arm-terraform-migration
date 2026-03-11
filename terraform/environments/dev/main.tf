# =============================================================================
# Development Environment — Root Module
# Lighter-weight configuration for dev with cost optimizations.
# =============================================================================

terraform {
  required_version = ">= 1.6.0"

  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "stterraformhcstate"
    container_name       = "tfstate"
    key                  = "dev/main.tfstate"
    use_azuread_auth     = true
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true # OK in dev
    }
  }
}

locals {
  environment = "dev"
  location    = "eastus2"

  common_tags = {
    environment      = local.environment
    compliance       = "hipaa"
    managed-by       = "terraform"
    cost-center      = "healthcare-platform"
    auto-shutdown    = "true"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "rg-healthcare-${local.environment}"
  location = local.location
  tags     = local.common_tags
}

module "monitoring" {
  source = "../../modules/monitoring"

  environment         = local.environment
  location            = local.location
  resource_group_name = azurerm_resource_group.main.name
  retention_days      = 30 # Shorter retention in dev to save costs

  tags = local.common_tags
}

module "networking" {
  source = "../../modules/networking"

  environment                    = local.environment
  location                       = local.location
  resource_group_name            = azurerm_resource_group.main.name
  vnet_address_prefix            = "10.1.0.0/16" # Different CIDR from prod
  app_subnet_prefix              = "10.1.1.0/24"
  data_subnet_prefix             = "10.1.2.0/24"
  bastion_subnet_prefix          = "10.1.3.0/27"
  aks_subnet_prefix              = "10.1.4.0/22"
  private_endpoint_subnet_prefix = "10.1.8.0/24"
  log_analytics_workspace_id     = module.monitoring.log_analytics_workspace_id

  tags = local.common_tags
}

module "compute" {
  source = "../../modules/compute"

  environment                = local.environment
  location                   = local.location
  resource_group_name        = azurerm_resource_group.main.name
  aks_subnet_id              = module.networking.aks_subnet_id
  log_analytics_workspace_id = module.monitoring.log_analytics_workspace_id
  aks_version                = "1.28.5"
  aks_node_count             = 1           # Minimal in dev
  aks_node_vm_size           = "Standard_D2s_v5" # Smaller VMs in dev

  tags = local.common_tags
}

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
