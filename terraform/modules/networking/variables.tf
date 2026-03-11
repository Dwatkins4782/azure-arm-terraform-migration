variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "location" {
  description = "Azure region for resources"
  type        = string
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
}

variable "vnet_address_prefix" {
  description = "Address prefix for the Virtual Network"
  type        = string
  default     = "10.0.0.0/16"
}

variable "app_subnet_prefix" {
  description = "Address prefix for the application subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "data_subnet_prefix" {
  description = "Address prefix for the data subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "bastion_subnet_prefix" {
  description = "Address prefix for the Azure Bastion subnet"
  type        = string
  default     = "10.0.3.0/27"
}

variable "aks_subnet_prefix" {
  description = "Address prefix for the AKS subnet"
  type        = string
  default     = "10.0.4.0/22"
}

variable "private_endpoint_subnet_prefix" {
  description = "Address prefix for private endpoints"
  type        = string
  default     = "10.0.8.0/24"
}

variable "firewall_private_ip" {
  description = "Private IP of the Azure Firewall for UDR"
  type        = string
  default     = "10.0.100.4"
}

variable "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace for diagnostics"
  type        = string
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
