variable "sql_admin_login" {
  description = "SQL Server administrator login"
  type        = string
}

variable "sql_admin_password" {
  description = "SQL Server administrator password"
  type        = string
  sensitive   = true
}

variable "aad_admin_object_id" {
  description = "Azure AD Object ID for the SQL Admin group"
  type        = string
}

variable "aad_admin_login" {
  description = "Azure AD Admin group display name"
  type        = string
}

variable "alert_email_addresses" {
  description = "Email addresses for security alert notifications"
  type        = list(string)
  default     = []
}
