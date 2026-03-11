# =============================================================================
# Variables for the Compute Module
# Source: arm-templates/compute/azuredeploy.json parameters section
#
# Conversion notes:
#   - ARM parameters with allowedValues -> Terraform validation blocks
#   - ARM parameters with defaultValue -> Terraform default values
#   - ARM parameters with minValue/maxValue -> Terraform validation with
#     condition expressions
#   - ARM parameter types (string, int, array) -> Terraform types
#     (string, number, list)
# =============================================================================

# --- Common Variables ---

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string

  # ARM: allowedValues = ["dev", "staging", "prod"]
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "location" {
  description = "Azure region for all resources"
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

# --- Networking Variables (cross-module references) ---

variable "aks_subnet_id" {
  description = "Resource ID of the AKS subnet from the networking module"
  type        = string
}

# --- ACR Variables ---
# ARM: parameters for Microsoft.ContainerRegistry/registries

variable "acr_name" {
  description = "Name of the Azure Container Registry (must be globally unique, alphanumeric only)"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9]{5,50}$", var.acr_name))
    error_message = "ACR name must be 5-50 alphanumeric characters with no hyphens or special characters."
  }
}

variable "acr_encryption_key_id" {
  description = "Key Vault key ID for ACR encryption (CMK). Full URI including version."
  type        = string
}

variable "acr_retention_days" {
  description = "Number of days to retain untagged manifests in ACR"
  type        = number
  default     = 30

  validation {
    condition     = var.acr_retention_days >= 0 && var.acr_retention_days <= 365
    error_message = "ACR retention days must be between 0 and 365."
  }
}

# --- AKS Variables ---
# ARM: parameters for Microsoft.ContainerService/managedClusters

variable "kubernetes_version" {
  description = "Kubernetes version for the AKS cluster"
  type        = string
  default     = "1.29"

  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+", var.kubernetes_version))
    error_message = "Kubernetes version must be in the format X.Y or X.Y.Z (e.g., 1.29 or 1.29.2)."
  }
}

variable "aks_admin_group_object_ids" {
  description = "List of Azure AD group object IDs that will have admin access to the AKS cluster"
  type        = list(string)

  validation {
    condition     = length(var.aks_admin_group_object_ids) > 0
    error_message = "At least one admin group object ID must be provided for AKS AAD integration."
  }
}

variable "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace for Container Insights and Defender"
  type        = string
}

# --- System Node Pool Variables ---
# ARM: properties.agentPoolProfiles[0] (mode: System)

variable "system_node_pool_vm_size" {
  description = "VM size for the system node pool"
  type        = string
  default     = "Standard_D4s_v5"
}

variable "system_node_pool_min_count" {
  description = "Minimum number of nodes in the system pool (autoscaler lower bound)"
  type        = number
  default     = 2

  # ARM: minValue equivalent
  validation {
    condition     = var.system_node_pool_min_count >= 1 && var.system_node_pool_min_count <= 10
    error_message = "System node pool minimum count must be between 1 and 10."
  }
}

variable "system_node_pool_max_count" {
  description = "Maximum number of nodes in the system pool (autoscaler upper bound)"
  type        = number
  default     = 5

  # ARM: maxValue equivalent
  validation {
    condition     = var.system_node_pool_max_count >= 1 && var.system_node_pool_max_count <= 20
    error_message = "System node pool maximum count must be between 1 and 20."
  }
}

# --- User Node Pool Variables ---
# ARM: properties.agentPoolProfiles[1] (mode: User)

variable "user_node_pool_vm_size" {
  description = "VM size for the user (workload) node pool"
  type        = string
  default     = "Standard_D8s_v5"
}

variable "user_node_pool_min_count" {
  description = "Minimum number of nodes in the user pool (autoscaler lower bound)"
  type        = number
  default     = 2

  validation {
    condition     = var.user_node_pool_min_count >= 1 && var.user_node_pool_min_count <= 20
    error_message = "User node pool minimum count must be between 1 and 20."
  }
}

variable "user_node_pool_max_count" {
  description = "Maximum number of nodes in the user pool (autoscaler upper bound)"
  type        = number
  default     = 10

  validation {
    condition     = var.user_node_pool_max_count >= 1 && var.user_node_pool_max_count <= 50
    error_message = "User node pool maximum count must be between 1 and 50."
  }
}
