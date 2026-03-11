# =============================================================================
# Monitoring Module — Healthcare Compliance Monitoring Stack
# No direct ARM template source — this module adds observability that was
# previously handled ad-hoc or missing from the ARM deployment.
# =============================================================================

resource "azurerm_log_analytics_workspace" "main" {
  name                       = "law-healthcare-${var.environment}"
  location                   = var.location
  resource_group_name        = var.resource_group_name
  sku                        = "PerGB2018"
  retention_in_days          = var.retention_days
  internet_ingestion_enabled = false
  internet_query_enabled     = false

  tags = var.tags
}

resource "azurerm_application_insights" "main" {
  name                = "ai-healthcare-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  workspace_id        = azurerm_log_analytics_workspace.main.id
  application_type    = "web"

  tags = var.tags
}

# HIPAA-required: Alert on unauthorized access attempts
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "failed_auth" {
  name                = "alert-failed-auth-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  description         = "HIPAA: Alert on repeated failed authentication attempts"

  scopes                = [azurerm_log_analytics_workspace.main.id]
  evaluation_frequency  = "PT5M"
  window_duration       = "PT15M"
  severity              = 1
  enabled               = true

  criteria {
    query = <<-QUERY
      SigninLogs
      | where ResultType != "0"
      | summarize FailedCount = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 5m)
      | where FailedCount > 5
    QUERY

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
  }

  auto_mitigation_enabled = true

  tags = var.tags
}

# HIPAA-required: Alert on PHI data access anomalies
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "phi_access_anomaly" {
  name                = "alert-phi-access-${var.environment}"
  location            = var.location
  resource_group_name = var.resource_group_name
  description         = "HIPAA: Alert on unusual PHI data access patterns"

  scopes                = [azurerm_log_analytics_workspace.main.id]
  evaluation_frequency  = "PT10M"
  window_duration       = "PT30M"
  severity              = 2
  enabled               = true

  criteria {
    query = <<-QUERY
      AzureDiagnostics
      | where Category == "SQLSecurityAuditEvents"
      | where action_name_s in ("BATCH_COMPLETED_GROUP", "SCHEMA_OBJECT_ACCESS_GROUP")
      | summarize AccessCount = count() by server_principal_name_s, database_name_s, bin(TimeGenerated, 10m)
      | where AccessCount > 100
    QUERY

    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
  }

  tags = var.tags
}

# Azure Monitor action group for security alerts
resource "azurerm_monitor_action_group" "security" {
  name                = "ag-security-${var.environment}"
  resource_group_name = var.resource_group_name
  short_name          = "SecAlerts"

  dynamic "email_receiver" {
    for_each = var.alert_email_addresses
    content {
      name          = "security-team-${email_receiver.key}"
      email_address = email_receiver.value
    }
  }

  tags = var.tags
}
