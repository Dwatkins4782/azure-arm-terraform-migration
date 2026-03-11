# =============================================================================
# Database Module Variables — Converted from ARM Template Parameters
# Source: arm-templates/database/azuredeploy.json → parameters section
#
# Conversion notes:
#   - ARM "securestring" type → Terraform string with sensitive = true.
#     ARM encrypts securestring values so they never appear in deployment logs
#     or the Azure portal's deployment history. Terraform's sensitive flag
#     redacts the value from CLI output and plan files, but the value IS stored
#     in Terraform state. Protect state files with encryption at rest (required
#     for HIPAA compliance).
#
#   - ARM "allowedValues" → Terraform validation block with condition.
#
#   - ARM "defaultValue": "[resourceGroup().location]" has no direct equivalent.
#     The caller must pass the location explicitly; there is no implicit
#     resource-group location in Terraform.
# =============================================================================

variable "sql_admin_login" {
  description = "SQL Server administrator login name"
  type        = string

  validation {
    condition     = length(var.sql_admin_login) > 0
    error_message = "SQL admin login must not be empty."
  }
}

# ARM parameter type: "securestring"
# In ARM, securestring values are encrypted in transit and at rest within
# Azure Resource Manager. They never appear in deployment logs or the portal.
# Terraform equivalent: sensitive = true redacts the value from plan/apply
# output. However, the value is persisted in Terraform state — ensure state
# backend encryption is enabled for HIPAA compliance.
variable "sql_admin_password" {
  description = "SQL Server administrator password (sensitive)"
  type        = string
  sensitive   = true

  validation {
    condition     = length(var.sql_admin_password) >= 12
    error_message = "SQL admin password must be at least 12 characters for HIPAA compliance."
  }
}

variable "aad_admin_object_id" {
  description = "Azure AD Object ID for the SQL Admin group"
  type        = string

  validation {
    condition     = can(regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", var.aad_admin_object_id))
    error_message = "AAD admin object ID must be a valid GUID."
  }
}

variable "aad_admin_login" {
  description = "Azure AD Admin group display name"
  type        = string
}

variable "private_endpoint_subnet_id" {
  description = "Resource ID of the subnet for the SQL private endpoint"
  type        = string
}

variable "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace for diagnostics"
  type        = string
}

# ARM: "allowedValues": ["dev", "staging", "prod"]
# Terraform: validation block with contains() check
variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

# ARM: "defaultValue": "[resourceGroup().location]"
# Terraform has no implicit resourceGroup().location. The caller must provide
# the location explicitly. This is a fundamental difference: ARM templates
# can inherit the resource group's location at deploy time, whereas Terraform
# requires it as an input variable.
variable "location" {
  description = "Azure region for resources"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
