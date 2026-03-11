# =============================================================================
# Database Module Outputs — Mirrors ARM Template Outputs
# Source: arm-templates/database/azuredeploy.json → outputs section
#
# Conversion notes:
#   - ARM outputs use reference() to read runtime properties:
#       "[reference(resourceId('Microsoft.Sql/servers', serverName)).fullyQualifiedDomainName]"
#     Terraform exposes the same values as resource attributes:
#       azurerm_mssql_server.main.fully_qualified_domain_name
#
#   - ARM outputs use resourceId() to build full Azure resource IDs:
#       "[resourceId('Microsoft.Sql/servers/databases', serverName, dbName)]"
#     Terraform exposes the .id attribute on every resource, which is the full
#     Azure resource ID (identical format to ARM's resourceId() output).
#
#   - sql_server_id is added beyond the ARM template outputs because downstream
#     modules (e.g. monitoring, diagnostics) often need the server resource ID.
# =============================================================================

# ARM: outputs.sqlServerFqdn
#   value: "[reference(resourceId('Microsoft.Sql/servers', ...)).fullyQualifiedDomainName]"
output "sql_server_fqdn" {
  description = "Fully qualified domain name of the Azure SQL Server"
  value       = azurerm_mssql_server.main.fully_qualified_domain_name
}

# ARM: outputs.sqlDatabaseId
#   value: "[resourceId('Microsoft.Sql/servers/databases', serverName, dbName)]"
output "sql_database_id" {
  description = "Resource ID of the Azure SQL Database"
  value       = azurerm_mssql_database.main.id
}

# Not in original ARM template outputs — added for downstream module consumption.
# Diagnostic settings, RBAC assignments, and private DNS zone links commonly
# require the server resource ID.
output "sql_server_id" {
  description = "Resource ID of the Azure SQL Server"
  value       = azurerm_mssql_server.main.id
}
