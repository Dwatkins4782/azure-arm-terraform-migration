# Remote state backend using Azure Storage with state locking via blob lease.
# Each environment and layer gets its own state file to minimize blast radius.
#
# State file layout:
#   - {env}/networking.tfstate
#   - {env}/compute.tfstate
#   - {env}/database.tfstate
#   - {env}/security.tfstate
#
# Prerequisites:
#   1. Create resource group: az group create -n rg-terraform-state -l eastus2
#   2. Create storage account: az storage account create -n stterraformhcstate -g rg-terraform-state --sku Standard_GRS --encryption-services blob
#   3. Create container: az storage container create -n tfstate --account-name stterraformhcstate
#   4. Enable versioning: az storage account blob-service-properties update --account-name stterraformhcstate --enable-versioning true

terraform {
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "stterraformhcstate"
    container_name       = "tfstate"
    key                  = "prod/networking.tfstate" # Override per environment/layer
    use_azuread_auth     = true
  }
}
