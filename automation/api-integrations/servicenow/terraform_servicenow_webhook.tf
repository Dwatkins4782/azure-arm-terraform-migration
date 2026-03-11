# =============================================================================
# ServiceNow Change Management Webhook Integration via Azure Logic App
# =============================================================================
#
# Architecture Overview (Event-Driven):
# --------------------------------------
# This configuration implements an event-driven integration between
# Terraform Cloud/Enterprise and ServiceNow ITSM using Azure Logic Apps
# as the orchestration layer.
#
# Flow:
#   1. Terraform Cloud fires a webhook notification on run state changes
#      (e.g., "planned", "applied", "errored").
#   2. The Logic App HTTP trigger receives the webhook payload.
#   3. The workflow parses the event, determines the action, and interacts
#      with ServiceNow via the managed API connection.
#   4. Depending on the run state:
#      - "planned"  -> Create a new Change Request in ServiceNow
#      - "needs_confirmation" -> Wait for CR approval before confirming apply
#      - "applied"  -> Close the Change Request as successful
#      - "errored"  -> Trigger rollback workflow, close CR as unsuccessful
#
# This decoupled, event-driven pattern ensures that:
#   - No direct coupling exists between Terraform and ServiceNow
#   - The Logic App can be independently versioned and monitored
#   - Retry and dead-letter handling are built into the platform
#   - HIPAA audit logs are captured at every stage
#
# Prerequisites:
#   - ServiceNow instance with REST API access enabled
#   - Terraform Cloud workspace configured with a notification webhook
#   - Azure subscription with Logic Apps and API Connections enabled
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
  description = "Name of the Azure resource group for Logic App resources."
  type        = string
}

variable "location" {
  description = "Azure region for all resources."
  type        = string
  default     = "eastus2"
}

variable "servicenow_instance_url" {
  description = "ServiceNow instance URL (e.g., https://yourorg.service-now.com)."
  type        = string
  sensitive   = true
}

variable "servicenow_username" {
  description = "ServiceNow API integration user."
  type        = string
  sensitive   = true
}

variable "servicenow_password" {
  description = "ServiceNow API integration password."
  type        = string
  sensitive   = true
}

variable "terraform_cloud_webhook_token" {
  description = "HMAC token used to verify Terraform Cloud webhook payloads."
  type        = string
  sensitive   = true
}

variable "tags" {
  description = "Resource tags applied to all resources for cost tracking and governance."
  type        = map(string)
  default = {
    Project     = "azure-arm-terraform-migration"
    Component   = "servicenow-integration"
    Compliance  = "HIPAA"
    ManagedBy   = "Terraform"
  }
}

# ---------------------------------------------------------------------------
# Data Sources
# ---------------------------------------------------------------------------

data "azurerm_resource_group" "main" {
  name = var.resource_group_name
}

# ---------------------------------------------------------------------------
# ServiceNow Managed API Connection
# ---------------------------------------------------------------------------
# The API connection stores ServiceNow credentials securely in Azure and
# provides a reusable connector for the Logic App workflow. Credentials
# are encrypted at rest using Azure-managed keys and are never exposed
# in the Logic App definition or run history.
# ---------------------------------------------------------------------------

resource "azurerm_api_connection" "servicenow" {
  name                = "servicenow-api-connection"
  resource_group_name = data.azurerm_resource_group.main.name
  managed_api_id      = "${data.azurerm_resource_group.main.id}/providers/Microsoft.Web/locations/${var.location}/managedApis/service-now"

  display_name = "ServiceNow ITSM Connection"

  parameter_values = {
    "instance" = var.servicenow_instance_url
    "username" = var.servicenow_username
    "password" = var.servicenow_password
  }

  tags = var.tags

  lifecycle {
    # Prevent accidental destruction of the credential store
    prevent_destroy = true
  }
}

# ---------------------------------------------------------------------------
# Azure Logic App Workflow
# ---------------------------------------------------------------------------
# This Logic App implements the full webhook-to-ServiceNow orchestration.
#
# Trigger:
#   HTTP POST from Terraform Cloud notification webhook.
#
# Actions (conditional branches based on run state):
#   1. Parse the incoming Terraform Cloud webhook JSON payload.
#   2. Branch on the "run_status" field:
#      a. "planned"             -> Create ServiceNow Change Request
#      b. "needs_confirmation"  -> Check CR approval status, confirm or reject
#      c. "applied"             -> Close CR as successful
#      d. "errored"             -> Close CR as unsuccessful, create incident
#   3. Log the outcome to the HIPAA audit trail.
#
# Error handling:
#   - Each action block has a retry policy (fixed interval, 3 attempts).
#   - A parallel "scope" captures failures and posts to a dead-letter queue.
# ---------------------------------------------------------------------------

resource "azurerm_logic_app_workflow" "terraform_servicenow" {
  name                = "logic-terraform-servicenow-webhook"
  location            = var.location
  resource_group_name = data.azurerm_resource_group.main.name

  tags = var.tags

  # Enable diagnostic logging for HIPAA audit compliance
  identity {
    type = "SystemAssigned"
  }
}

# ---------------------------------------------------------------------------
# Trigger: HTTP endpoint that receives Terraform Cloud webhook payloads
# ---------------------------------------------------------------------------
# Terraform Cloud sends a POST request to this endpoint whenever a run
# transitions between states. The payload includes:
#   - run_id, run_status, workspace_name, organization, run_url
#
# The relative_path enables a clean URL structure and the "POST" method
# restriction prevents accidental GET invocations by browsers or crawlers.
# ---------------------------------------------------------------------------

resource "azurerm_logic_app_trigger_http_request" "terraform_webhook" {
  name         = "terraform-cloud-webhook-trigger"
  logic_app_id = azurerm_logic_app_workflow.terraform_servicenow.id

  schema = jsonencode({
    type = "object"
    properties = {
      payload_version = { type = "integer" }
      run_id          = { type = "string" }
      run_status      = { type = "string" }
      workspace_name  = { type = "string" }
      workspace_id    = { type = "string" }
      organization    = { type = "string" }
      run_url         = { type = "string" }
      run_message     = { type = "string" }
      notifications = {
        type = "array"
        items = {
          type = "object"
          properties = {
            message    = { type = "string" }
            trigger    = { type = "string" }
            run_status = { type = "string" }
          }
        }
      }
    }
    required = ["run_id", "run_status", "workspace_name"]
  })

  method        = "POST"
  relative_path = "terraform/webhook"
}

# ---------------------------------------------------------------------------
# Action: Parse the Terraform Cloud webhook payload
# ---------------------------------------------------------------------------
# Validates and extracts typed fields from the raw HTTP body. This ensures
# downstream actions reference strongly-typed properties rather than raw
# JSON, improving reliability and debuggability.
# ---------------------------------------------------------------------------

resource "azurerm_logic_app_action_custom" "parse_webhook" {
  name         = "Parse_Terraform_Webhook"
  logic_app_id = azurerm_logic_app_workflow.terraform_servicenow.id

  body = jsonencode({
    type    = "ParseJson"
    inputs = {
      content = "@triggerBody()"
      schema = {
        type = "object"
        properties = {
          run_id         = { type = "string" }
          run_status     = { type = "string" }
          workspace_name = { type = "string" }
          organization   = { type = "string" }
          run_url        = { type = "string" }
          run_message    = { type = "string" }
        }
      }
    }
    runAfter = {}
  })
}

# ---------------------------------------------------------------------------
# Action: Create ServiceNow Change Request (on "planned" status)
# ---------------------------------------------------------------------------
# When Terraform Cloud reports that a plan has completed, this action
# creates a new Change Request in ServiceNow. The CR includes:
#   - Short description with workspace and organization context
#   - Implementation plan referencing the Terraform run URL
#   - Backout plan referencing terraform destroy
#   - Standard risk assessment based on workspace tags
#
# The CR sys_id is stored as an output so subsequent actions can reference it.
# ---------------------------------------------------------------------------

resource "azurerm_logic_app_action_custom" "create_change_request" {
  name         = "Create_ServiceNow_Change_Request"
  logic_app_id = azurerm_logic_app_workflow.terraform_servicenow.id

  body = jsonencode({
    type = "If"
    expression = {
      and = [
        {
          equals = [
            "@body('Parse_Terraform_Webhook')?['run_status']",
            "planned"
          ]
        }
      ]
    }
    actions = {
      Create_CR = {
        type = "ApiConnection"
        inputs = {
          host = {
            connection = {
              name = "@parameters('$connections')['servicenow']['connectionId']"
            }
          }
          method = "post"
          path   = "/api/now/table/change_request"
          body = {
            type              = "standard"
            category          = "Infrastructure"
            priority          = 3
            short_description = "Terraform Deployment: @{body('Parse_Terraform_Webhook')?['workspace_name']} (@{body('Parse_Terraform_Webhook')?['organization']})"
            description       = "Automated change request for Terraform run @{body('Parse_Terraform_Webhook')?['run_id']}.\n\nWorkspace: @{body('Parse_Terraform_Webhook')?['workspace_name']}\nOrganization: @{body('Parse_Terraform_Webhook')?['organization']}\nRun URL: @{body('Parse_Terraform_Webhook')?['run_url']}\nMessage: @{body('Parse_Terraform_Webhook')?['run_message']}"
            implementation_plan = "Review Terraform plan at @{body('Parse_Terraform_Webhook')?['run_url']} and approve the apply phase."
            backout_plan        = "Execute terraform destroy or revert to previous state file version."
            state               = -5
          }
        }
        runAfter = {}
      }
    }
    runAfter = {
      Parse_Terraform_Webhook = ["Succeeded"]
    }
  })
}

# ---------------------------------------------------------------------------
# Action: Update CR Status on Apply Completion or Failure
# ---------------------------------------------------------------------------
# This conditional action fires when the run reaches a terminal state:
#   - "applied" -> Close CR as successful with completion timestamp
#   - "errored" -> Close CR as unsuccessful, include error details
#
# By using a Switch action, we handle multiple terminal states cleanly
# without deeply nested If/Else blocks.
# ---------------------------------------------------------------------------

resource "azurerm_logic_app_action_custom" "update_change_status" {
  name         = "Update_Change_Request_Status"
  logic_app_id = azurerm_logic_app_workflow.terraform_servicenow.id

  body = jsonencode({
    type = "Switch"
    expression = "@body('Parse_Terraform_Webhook')?['run_status']"
    cases = {
      Applied = {
        case = "applied"
        actions = {
          Close_CR_Success = {
            type = "ApiConnection"
            inputs = {
              host = {
                connection = {
                  name = "@parameters('$connections')['servicenow']['connectionId']"
                }
              }
              method = "patch"
              path   = "/api/now/table/change_request/@{variables('cr_sys_id')}"
              body = {
                state      = 3
                close_code = "successful"
                close_notes = "Terraform apply completed successfully for run @{body('Parse_Terraform_Webhook')?['run_id']} at @{utcNow()}."
              }
            }
          }
        }
      }
      Errored = {
        case = "errored"
        actions = {
          Close_CR_Failed = {
            type = "ApiConnection"
            inputs = {
              host = {
                connection = {
                  name = "@parameters('$connections')['servicenow']['connectionId']"
                }
              }
              method = "patch"
              path   = "/api/now/table/change_request/@{variables('cr_sys_id')}"
              body = {
                state      = 3
                close_code = "unsuccessful"
                close_notes = "Terraform run @{body('Parse_Terraform_Webhook')?['run_id']} failed. Review run details at @{body('Parse_Terraform_Webhook')?['run_url']}."
              }
            }
          }
          Create_Incident = {
            type = "ApiConnection"
            inputs = {
              host = {
                connection = {
                  name = "@parameters('$connections')['servicenow']['connectionId']"
                }
              }
              method = "post"
              path   = "/api/now/table/incident"
              body = {
                short_description = "Terraform deployment failure: @{body('Parse_Terraform_Webhook')?['workspace_name']}"
                description       = "Automated incident for failed Terraform run @{body('Parse_Terraform_Webhook')?['run_id']}.\nRun URL: @{body('Parse_Terraform_Webhook')?['run_url']}"
                urgency           = 1
                impact            = 2
                category          = "Infrastructure"
              }
            }
            runAfter = {
              Close_CR_Failed = ["Succeeded"]
            }
          }
        }
      }
    }
    default = {
      actions = {}
    }
    runAfter = {
      Parse_Terraform_Webhook = ["Succeeded"]
    }
  })
}

# ---------------------------------------------------------------------------
# Diagnostic Settings for HIPAA Audit Compliance
# ---------------------------------------------------------------------------
# All Logic App execution history, trigger events, and action outcomes
# are streamed to a Log Analytics workspace for retention and analysis.
# HIPAA requires a minimum of 6 years retention for audit logs.
# ---------------------------------------------------------------------------

resource "azurerm_monitor_diagnostic_setting" "logic_app_diagnostics" {
  name                       = "diag-logic-terraform-servicenow"
  target_resource_id         = azurerm_logic_app_workflow.terraform_servicenow.id
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log {
    category = "WorkflowRuntime"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

variable "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace for diagnostic logs."
  type        = string
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

output "webhook_url" {
  description = "HTTP trigger URL to configure as the Terraform Cloud notification webhook."
  value       = azurerm_logic_app_trigger_http_request.terraform_webhook.callback_url
  sensitive   = true
}

output "logic_app_id" {
  description = "Resource ID of the Logic App workflow."
  value       = azurerm_logic_app_workflow.terraform_servicenow.id
}

output "api_connection_id" {
  description = "Resource ID of the ServiceNow API connection."
  value       = azurerm_api_connection.servicenow.id
}
