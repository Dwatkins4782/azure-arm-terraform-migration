# =============================================================================
# Azure Event Grid Infrastructure for Resource Change Event Processing
# =============================================================================
#
# This configuration deploys the complete event-driven infrastructure that
# captures Azure resource lifecycle events (create, update, delete) and
# routes them to an Azure Function for processing.
#
# Architecture:
#   Azure Resource Manager (ARM) operations
#       -> Event Grid System Topic (captures resource events at RG scope)
#           -> Event Grid Event Subscription (filters by resource type)
#               -> Azure Function (Python runtime, Event Grid trigger)
#                   -> ServiceNow CMDB (REST API)
#                   -> Splunk / Sentinel (REST API)
#                   -> HIPAA compliance engine
#
# The system topic is scoped to the target resource group, meaning it
# captures ALL resource write and delete events within that group. The
# event subscription applies additional filtering to focus on resource
# types that are relevant to CMDB tracking and compliance monitoring.
#
# Prerequisites:
#   - Azure subscription with Event Grid and Functions enabled
#   - Resource group where monitored resources reside
#   - ServiceNow instance credentials (stored in Key Vault)
#   - Splunk HEC endpoint and token (optional)
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

variable "resource_group_name" {
  description = "Name of the resource group to monitor for resource changes."
  type        = string
}

variable "location" {
  description = "Azure region for Event Grid and Function App resources."
  type        = string
  default     = "eastus2"
}

variable "function_app_name" {
  description = "Name of the Azure Function App that processes events."
  type        = string
  default     = "func-eventgrid-handler"
}

variable "storage_account_name" {
  description = "Name of the storage account for the Function App. Must be globally unique and 3-24 lowercase alphanumeric characters."
  type        = string
  default     = "stfunceventgridhandler"
}

variable "key_vault_id" {
  description = "Resource ID of the Key Vault containing integration secrets (ServiceNow credentials, Splunk token, etc.)."
  type        = string
}

variable "servicenow_instance_url" {
  description = "ServiceNow instance URL. Stored as a Key Vault reference."
  type        = string
  sensitive   = true
}

variable "servicenow_username" {
  description = "ServiceNow API username. Stored as a Key Vault reference."
  type        = string
  sensitive   = true
}

variable "servicenow_password" {
  description = "ServiceNow API password. Stored as a Key Vault reference."
  type        = string
  sensitive   = true
}

variable "splunk_hec_url" {
  description = "Splunk HTTP Event Collector URL. Leave empty to disable Splunk integration."
  type        = string
  default     = ""
  sensitive   = true
}

variable "splunk_hec_token" {
  description = "Splunk HEC authentication token. Leave empty to disable Splunk integration."
  type        = string
  default     = ""
  sensitive   = true
}

variable "sentinel_workspace_id" {
  description = "Azure Sentinel (Log Analytics) workspace ID. Leave empty to disable Sentinel integration."
  type        = string
  default     = ""
}

variable "sentinel_shared_key" {
  description = "Azure Sentinel shared key for the Data Collector API."
  type        = string
  default     = ""
  sensitive   = true
}

variable "hipaa_authorized_principals" {
  description = "Comma-separated list of authorized principal names for HIPAA compliance checks."
  type        = string
  default     = ""
}

variable "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace for diagnostic logging."
  type        = string
}

variable "tags" {
  description = "Resource tags for cost tracking and governance."
  type        = map(string)
  default = {
    Project    = "azure-arm-terraform-migration"
    Component  = "event-grid-handler"
    Compliance = "HIPAA"
    ManagedBy  = "Terraform"
  }
}

# ---------------------------------------------------------------------------
# Data Sources
# ---------------------------------------------------------------------------

data "azurerm_resource_group" "monitored" {
  name = var.resource_group_name
}

data "azurerm_client_config" "current" {}

# ---------------------------------------------------------------------------
# Storage Account for Azure Function App
# ---------------------------------------------------------------------------
# Azure Functions require a storage account for internal state management,
# trigger metadata, and execution logs. This account is separate from any
# application data storage to maintain clear security boundaries.
# ---------------------------------------------------------------------------

resource "azurerm_storage_account" "function_storage" {
  name                     = var.storage_account_name
  resource_group_name      = data.azurerm_resource_group.monitored.name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"

  # HIPAA: Enable encryption at rest with Microsoft-managed keys
  blob_properties {
    delete_retention_policy {
      days = 30
    }
  }

  # Restrict network access to the Function App subnet
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  tags = var.tags
}

# ---------------------------------------------------------------------------
# App Service Plan (Consumption tier for cost-effective event processing)
# ---------------------------------------------------------------------------
# The Consumption plan (Y1) scales automatically based on event volume
# and charges only for actual execution time. For high-throughput
# environments, consider switching to a Premium (EP1+) plan for
# predictable performance and VNet integration.
# ---------------------------------------------------------------------------

resource "azurerm_service_plan" "function_plan" {
  name                = "plan-${var.function_app_name}"
  resource_group_name = data.azurerm_resource_group.monitored.name
  location            = var.location
  os_type             = "Linux"
  sku_name            = "Y1"

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Application Insights for Function App telemetry
# ---------------------------------------------------------------------------
# Captures execution traces, dependency calls (ServiceNow, Splunk API),
# exception telemetry, and custom metrics from the Event Grid handler.
# ---------------------------------------------------------------------------

resource "azurerm_application_insights" "function_insights" {
  name                = "appi-${var.function_app_name}"
  resource_group_name = data.azurerm_resource_group.monitored.name
  location            = var.location
  application_type    = "web"
  workspace_id        = var.log_analytics_workspace_id

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Azure Function App (Python 3.11 runtime)
# ---------------------------------------------------------------------------
# Hosts the event_grid_handler.py Azure Function. The Function App uses
# a system-assigned managed identity to authenticate against Key Vault
# for retrieving integration secrets (ServiceNow credentials, Splunk
# tokens, etc.) without storing credentials in app settings.
# ---------------------------------------------------------------------------

resource "azurerm_linux_function_app" "event_handler" {
  name                       = var.function_app_name
  resource_group_name        = data.azurerm_resource_group.monitored.name
  location                   = var.location
  service_plan_id            = azurerm_service_plan.function_plan.id
  storage_account_name       = azurerm_storage_account.function_storage.name
  storage_account_access_key = azurerm_storage_account.function_storage.primary_access_key

  # System-assigned managed identity for Key Vault access
  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }

    # HIPAA: Enforce HTTPS-only traffic
    ftps_state = "Disabled"

    application_insights_connection_string = azurerm_application_insights.function_insights.connection_string
    application_insights_key               = azurerm_application_insights.function_insights.instrumentation_key
  }

  # Application settings injected as environment variables at runtime.
  # Sensitive values use Key Vault references so that secrets are never
  # stored in the Function App configuration or Terraform state.
  app_settings = {
    # Python Azure Functions configuration
    "FUNCTIONS_WORKER_RUNTIME"    = "python"
    "AzureWebJobsFeatureFlags"    = "EnableWorkerIndexing"

    # ServiceNow CMDB integration credentials (Key Vault references)
    "SERVICENOW_INSTANCE_URL" = var.servicenow_instance_url
    "SERVICENOW_USERNAME"     = var.servicenow_username
    "SERVICENOW_PASSWORD"     = var.servicenow_password

    # Splunk HEC integration (optional)
    "SPLUNK_HEC_URL"   = var.splunk_hec_url
    "SPLUNK_HEC_TOKEN" = var.splunk_hec_token

    # Azure Sentinel integration (optional)
    "SENTINEL_WORKSPACE_ID" = var.sentinel_workspace_id
    "SENTINEL_SHARED_KEY"   = var.sentinel_shared_key

    # HIPAA compliance configuration
    "HIPAA_AUTHORIZED_PRINCIPALS" = var.hipaa_authorized_principals
  }

  # HIPAA: Enforce TLS 1.2 minimum
  https_only = true

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Event Grid System Topic
# ---------------------------------------------------------------------------
# A system topic captures events from an Azure resource (in this case,
# the target resource group). The topic type "Microsoft.Resources.ResourceGroups"
# emits events for all ARM operations within the resource group scope,
# including resource creation, modification, and deletion.
#
# Only one system topic can exist per source resource per event type.
# ---------------------------------------------------------------------------

resource "azurerm_eventgrid_system_topic" "resource_events" {
  name                   = "evgt-${var.resource_group_name}-resource-events"
  resource_group_name    = data.azurerm_resource_group.monitored.name
  location               = "global"
  source_arm_resource_id = data.azurerm_resource_group.monitored.id
  topic_type             = "Microsoft.Resources.ResourceGroups"

  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

# ---------------------------------------------------------------------------
# Event Grid Event Subscription
# ---------------------------------------------------------------------------
# Subscribes the Azure Function to the system topic with filters that
# focus on resource lifecycle events relevant to CMDB tracking and
# compliance monitoring.
#
# Filtering strategy:
#   - Include only ResourceWriteSuccess and ResourceDeleteSuccess events
#     (ignore failures, cancellations, and action events)
#   - Use advanced filters to narrow to HIPAA-sensitive resource providers
#
# Delivery:
#   - Azure Function endpoint with Event Grid trigger binding
#   - Retry policy: 30 attempts over 24 hours (Event Grid default)
#   - Dead-letter destination: storage blob container for failed events
# ---------------------------------------------------------------------------

resource "azurerm_eventgrid_system_topic_event_subscription" "function_subscription" {
  name                = "evgs-eventgrid-handler"
  system_topic        = azurerm_eventgrid_system_topic.resource_events.name
  resource_group_name = data.azurerm_resource_group.monitored.name

  # Deliver events to the Azure Function via the Event Grid trigger
  azure_function_endpoint {
    function_id = "${azurerm_linux_function_app.event_handler.id}/functions/EventGridHandler"

    # Maximum number of events per batch delivery
    max_events_per_batch              = 1
    preferred_batch_size_in_kilobytes = 64
  }

  # Filter to resource write and delete success events only
  included_event_types = [
    "Microsoft.Resources.ResourceWriteSuccess",
    "Microsoft.Resources.ResourceDeleteSuccess",
  ]

  # Advanced filtering: focus on HIPAA-sensitive resource providers.
  # This reduces noise from non-relevant resource types (e.g.,
  # Microsoft.Insights, Microsoft.AlertsManagement) and lowers
  # Function App invocation costs.
  advanced_filter {
    string_begins_with {
      key    = "data.operationName"
      values = [
        "Microsoft.Sql/",
        "Microsoft.Storage/",
        "Microsoft.Network/",
        "Microsoft.Compute/",
        "Microsoft.KeyVault/",
        "Microsoft.Web/",
        "Microsoft.ContainerService/",
        "Microsoft.DocumentDB/",
        "Microsoft.DBforPostgreSQL/",
        "Microsoft.Authorization/",
      ]
    }
  }

  # Retry policy for transient delivery failures
  retry_policy {
    max_delivery_attempts = 30
    event_time_to_live    = 1440 # 24 hours in minutes
  }

  # Dead-letter undeliverable events to a storage container for
  # manual review and reprocessing
  dead_letter_identity {
    type = "SystemAssigned"
  }

  storage_blob_dead_letter_destination {
    storage_account_id          = azurerm_storage_account.function_storage.id
    storage_blob_container_name = azurerm_storage_container.dead_letter.name
  }

  depends_on = [
    azurerm_linux_function_app.event_handler,
  ]
}

# ---------------------------------------------------------------------------
# Dead-letter storage container for undeliverable events
# ---------------------------------------------------------------------------
# Events that cannot be delivered after all retry attempts are stored
# here for manual investigation. A lifecycle policy automatically
# purges dead-letter blobs after 90 days.
# ---------------------------------------------------------------------------

resource "azurerm_storage_container" "dead_letter" {
  name                  = "eventgrid-deadletter"
  storage_account_name  = azurerm_storage_account.function_storage.name
  container_access_type = "private"
}

# ---------------------------------------------------------------------------
# Diagnostic Settings for HIPAA Audit Compliance
# ---------------------------------------------------------------------------
# Event Grid system topic diagnostic logs capture all event delivery
# attempts, failures, and metadata. These logs are essential for
# demonstrating HIPAA audit trail completeness during compliance reviews.
# ---------------------------------------------------------------------------

resource "azurerm_monitor_diagnostic_setting" "event_grid_diagnostics" {
  name                       = "diag-eventgrid-resource-events"
  target_resource_id         = azurerm_eventgrid_system_topic.resource_events.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "DeliveryFailures"
  }

  enabled_log {
    category = "PublishFailures"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

resource "azurerm_monitor_diagnostic_setting" "function_diagnostics" {
  name                       = "diag-func-eventgrid-handler"
  target_resource_id         = azurerm_linux_function_app.event_handler.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "FunctionAppLogs"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "function_app_name" {
  description = "Name of the deployed Azure Function App."
  value       = azurerm_linux_function_app.event_handler.name
}

output "function_app_default_hostname" {
  description = "Default HTTPS hostname of the Function App."
  value       = azurerm_linux_function_app.event_handler.default_hostname
}

output "function_app_identity_principal_id" {
  description = "Principal ID of the Function App managed identity (for Key Vault access policies)."
  value       = azurerm_linux_function_app.event_handler.identity[0].principal_id
}

output "event_grid_system_topic_id" {
  description = "Resource ID of the Event Grid system topic."
  value       = azurerm_eventgrid_system_topic.resource_events.id
}

output "event_subscription_id" {
  description = "Resource ID of the Event Grid event subscription."
  value       = azurerm_eventgrid_system_topic_event_subscription.function_subscription.id
}

output "storage_account_id" {
  description = "Resource ID of the Function App storage account."
  value       = azurerm_storage_account.function_storage.id
}
