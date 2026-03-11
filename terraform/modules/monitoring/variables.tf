variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "retention_days" {
  description = "Log retention in days. HIPAA requires minimum 6 years (2190 days) for audit logs."
  type        = number
  default     = 365
}

variable "alert_email_addresses" {
  description = "Email addresses for security alert notifications"
  type        = list(string)
  default     = []
}

variable "tags" {
  type    = map(string)
  default = {}
}
