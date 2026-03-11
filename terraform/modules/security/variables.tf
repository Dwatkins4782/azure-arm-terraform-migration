# =============================================================================
# Variables — Security Module
# Source: arm-templates/security/azuredeploy.json parameters section
#
# Mapping from ARM parameters to Terraform variables:
#   ARM parameters.environment       -> var.environment (with validation)
#   ARM parameters.tenantId          -> var.tenant_id (defaults to data source)
#   ARM parameters.aksIdentityObjId  -> var.aks_identity_object_id
#   ARM parameters.privateEndpointSubnetId -> var.private_endpoint_subnet_id
#   ARM parameters.location          -> var.location
#   (ARM parameters.logAnalyticsWorkspaceId is not needed — the workspace is
#    created within this module, not passed in as an external reference)
# =============================================================================

variable "environment" {
  description = "Environment name (dev, staging, prod). Maps to ARM allowedValues constraint."
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "location" {
  description = "Azure region for resources. ARM equivalent: parameters('location') with defaultValue of resourceGroup().location."
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group to deploy into"
  type        = string
}

# ARM equivalent: parameters('tenantId') with defaultValue of [subscription().tenantId]
#
# In ARM, the tenantId parameter defaults to subscription().tenantId, which
# automatically resolves from the deployment context. In Terraform, we default
# to null and resolve it in main.tf using data.azurerm_client_config.current.
# This gives callers the option to override while preserving the ARM behavior
# of automatic resolution when no value is provided.
variable "tenant_id" {
  description = "Azure AD tenant ID for Key Vault. Defaults to the tenant of the current azurerm provider session (mirrors ARM subscription().tenantId behavior)."
  type        = string
  default     = null
}

variable "aks_identity_object_id" {
  description = "Object ID of the AKS managed identity for Key Vault RBAC role assignment. ARM equivalent: parameters('aksIdentityObjectId')."
  type        = string
}

variable "private_endpoint_subnet_id" {
  description = "Resource ID of the subnet for the Key Vault private endpoint. ARM equivalent: parameters('privateEndpointSubnetId')."
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources. Module-specific tags (environment, compliance) are merged on top."
  type        = map(string)
  default     = {}
}
