variable "sql_admin_login" {
  type = string
}

variable "sql_admin_password" {
  type      = string
  sensitive = true
}

variable "aad_admin_object_id" {
  type = string
}

variable "aad_admin_login" {
  type = string
}
