# =============================================================================
# Azure AD (Entra ID) App Registration for Terraform CI/CD Pipeline
# =============================================================================
#
# OAuth 2.0 Client Credentials Flow for Machine-to-Machine Authentication
# -----------------------------------------------------------------------
# This configuration implements the OAuth 2.0 Client Credentials Grant
# (RFC 6749 Section 4.4) for automated Terraform deployments.
#
# In OAuth 2.0 terminology:
#   - Resource Owner: The Azure subscription and its resources
#   - Client: The Terraform CI/CD pipeline (this app registration)
#   - Authorization Server: Azure AD (Entra ID) token endpoint
#   - Resource Server: Azure Resource Manager (ARM) API
#
# The client credentials flow is used because:
#   1. No interactive user is present during CI/CD execution
#   2. The pipeline acts on its own behalf, not on behalf of a user
#   3. The application needs pre-consented permissions
#
# Authentication Methods (in order of preference):
#   1. Workload Identity Federation (OIDC) - No secrets, most secure
#   2. Managed Identity - For Azure-hosted runners
#   3. Client Secret - Fallback with short expiry for legacy systems
#
# Enterprise Healthcare Context:
#   This pattern is used in HIPAA-regulated environments where:
#   - All service principals must have least-privilege access
#   - Secret rotation must be automated with short TTLs
#   - Audit logging of all authentication events is mandatory
#   - Workload identity federation eliminates secret sprawl
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.85"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.10"
    }
  }
}

# -----------------------------------------------------------------------------
# Data Sources - Retrieve current context for role assignments
# -----------------------------------------------------------------------------

# The current Azure AD client context — used to determine the tenant and
# to set ownership on the app registration for lifecycle management.
data "azuread_client_config" "current" {}

# The Azure subscription where Terraform will manage resources.
# Role assignments are scoped to this subscription.
data "azurerm_subscription" "primary" {}

# Well-known Application ID for Azure Service Management API.
# This is Microsoft's first-party API that ARM requests are authorized against.
# Application ID: 797f4846-ba00-4fd7-ba43-dac1f8f63013
data "azuread_application_published_app_ids" "well_known" {}

# Service principal for the Azure Service Management API.
# We need this to reference the OAuth 2.0 permission (scope) for user_impersonation.
data "azuread_service_principal" "azure_service_mgmt" {
  client_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftAzureManagement"]
}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "arm-tf-migration"
}

variable "azure_devops_org_url" {
  description = "Azure DevOps organization URL for workload identity federation"
  type        = string
  default     = "https://dev.azure.com/contoso-healthcare"
}

variable "azure_devops_project_name" {
  description = "Azure DevOps project name for OIDC subject claim"
  type        = string
  default     = "InfrastructureMigration"
}

variable "azure_devops_service_connection_id" {
  description = "Service connection ID in Azure DevOps (GUID)"
  type        = string
  default     = ""
}

variable "enable_client_secret_fallback" {
  description = "Enable client secret as fallback auth method (set false when OIDC is confirmed working)"
  type        = bool
  default     = true
}

variable "client_secret_expiry_days" {
  description = "Client secret expiry in days. HIPAA requires <= 90 days for automated credentials."
  type        = number
  default     = 90

  validation {
    condition     = var.client_secret_expiry_days <= 90
    error_message = "Client secret expiry must not exceed 90 days per HIPAA security requirements."
  }
}

variable "additional_role_assignments" {
  description = "Additional role assignments beyond the defaults (Contributor + User Access Admin)"
  type = list(object({
    role_definition_name = string
    scope                = string
    description          = string
  }))
  default = []
}

# -----------------------------------------------------------------------------
# Locals
# -----------------------------------------------------------------------------

locals {
  app_display_name = "sp-${var.project_name}-terraform-${var.environment}"

  # Tags applied to all resources for governance and cost tracking
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Purpose     = "CI/CD Pipeline Authentication"
    Compliance  = "HIPAA"
  }
}

# =============================================================================
# Azure AD Application Registration
# =============================================================================
#
# The Application object is the global definition of the OAuth 2.0 client.
# It exists in the home tenant and defines:
#   - What API permissions the client needs
#   - What authentication methods are allowed
#   - What redirect URIs are valid (not needed for client credentials)
#
# In OAuth 2.0 terms, this is the "client" registration at the
# authorization server (Azure AD).
# =============================================================================

resource "azuread_application" "terraform_pipeline" {
  display_name = local.app_display_name

  # The owners can manage this app registration. In production, this should
  # be a security group, not individual users.
  owners = [data.azuread_client_config.current.object_id]

  # Sign-in audience: AzureADMyOrg means only users/services in this tenant
  # can authenticate. This is the correct setting for internal CI/CD.
  sign_in_audience = "AzureADMyOrg"

  # Tags help categorize the app in the Azure AD portal.
  # "HideApp" prevents it from appearing in the My Apps portal since
  # this is a service principal, not a user-facing application.
  tags = ["Terraform", "CI/CD", "HideApp", var.environment]

  # ---------------------------------------------------------------------------
  # API Permissions (OAuth 2.0 Scopes)
  # ---------------------------------------------------------------------------
  # These define what OAuth 2.0 scopes the client can request.
  #
  # "required_resource_access" maps to the API permissions blade in Azure AD.
  # Each block specifies a resource API and the permissions needed.
  #
  # Permission types:
  #   - "Role"  = Application permission (client credentials flow, no user context)
  #   - "Scope" = Delegated permission (authorization code flow, user context)
  #
  # For CI/CD pipelines, we use delegated "Scope" type with admin consent
  # because Azure Service Management API exposes user_impersonation as a
  # delegated permission, and the service principal acts with admin consent.
  # ---------------------------------------------------------------------------

  required_resource_access {
    # Azure Service Management API
    # This grants the service principal access to manage Azure resources
    # through the ARM API (management.azure.com).
    resource_app_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftAzureManagement"]

    resource_access {
      # user_impersonation scope: Allows the app to call ARM APIs.
      # With admin consent, the service principal can call ARM without
      # an interactive user present.
      id   = data.azuread_service_principal.azure_service_mgmt.oauth2_permission_scope_ids["user_impersonation"]
      type = "Scope"
    }
  }

  # Optional: Microsoft Graph permissions for reading directory data.
  # Useful if Terraform needs to manage Azure AD resources (groups, users).
  required_resource_access {
    resource_app_id = data.azuread_application_published_app_ids.well_known.result["MicrosoftGraph"]

    resource_access {
      # Directory.Read.All - Read directory data (application permission).
      # Needed if Terraform manages AD groups for RBAC.
      id   = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" # Directory.Read.All
      type = "Role"
    }
  }

  # Prevent accidental deletion of this critical auth resource
  lifecycle {
    prevent_destroy = true
  }
}

# =============================================================================
# Service Principal
# =============================================================================
#
# The Service Principal is the local (tenant-specific) instance of the
# Application. While the Application is the "blueprint," the Service
# Principal is the actual identity that authenticates and receives
# role assignments.
#
# Think of it as:
#   Application = OAuth 2.0 client registration (global)
#   Service Principal = The identity in this tenant (local)
#
# Role assignments (RBAC) are granted to the Service Principal, not
# the Application.
# =============================================================================

resource "azuread_service_principal" "terraform_pipeline" {
  client_id = azuread_application.terraform_pipeline.client_id

  # App role assignment required = true means users/groups must be explicitly
  # assigned to this app before they can get tokens. For service principals
  # this adds an extra layer of governance.
  app_role_assignment_required = false

  owners = [data.azuread_client_config.current.object_id]

  # Feature tags control how the app appears in the portal
  feature_tags {
    enterprise = true  # Shows in Enterprise Applications blade
    hide       = true  # Hidden from user-facing My Apps portal
  }

  tags = ["Terraform", "CI/CD", var.environment]
}

# =============================================================================
# Workload Identity Federation (OIDC) - Primary Auth Method
# =============================================================================
#
# Workload Identity Federation eliminates the need for client secrets by
# establishing a trust relationship between Azure AD and an external
# identity provider (in this case, Azure DevOps).
#
# How it works (OAuth 2.0 Token Exchange - RFC 8693):
# 1. Azure DevOps pipeline requests an OIDC token from its own IdP
# 2. The pipeline presents this token to Azure AD's token endpoint
# 3. Azure AD validates the token against the federated credential config
# 4. If the issuer, subject, and audience match, Azure AD issues an
#    access token for the requested resource (ARM API)
#
# Security benefits:
#   - No secrets to rotate, leak, or manage
#   - Tokens are short-lived (pipeline-scoped)
#   - Subject claim restricts which pipelines can authenticate
#   - Audit trail shows the originating pipeline run
#
# This is the RECOMMENDED auth method for all new deployments.
# =============================================================================

resource "azuread_application_federated_identity_credential" "azure_devops_oidc" {
  application_id = azuread_application.terraform_pipeline.id
  display_name   = "oidc-azdo-${var.environment}"

  # Description for audit and governance purposes
  description = "OIDC federation with Azure DevOps for ${var.environment} Terraform deployments"

  # The OIDC issuer URL for Azure DevOps.
  # Azure DevOps issues OIDC tokens from this endpoint. Azure AD will
  # fetch the OIDC discovery document and signing keys from here.
  issuer = "https://vstoken.dev.azure.com/${replace(var.azure_devops_org_url, "https://dev.azure.com/", "")}"

  # The subject claim identifies which specific pipeline/service connection
  # is allowed to use this federated credential.
  #
  # Format: sc://<org>/<project>/<service-connection-name>
  # This ensures only the designated service connection can authenticate.
  subject = "sc://${replace(var.azure_devops_org_url, "https://dev.azure.com/", "")}/${var.azure_devops_project_name}/${local.app_display_name}"

  # The audience claim specifies who the token is intended for.
  # For Azure AD workload identity federation, this is always:
  audiences = ["api://AzureADTokenExchange"]
}

# Optional: Additional federated credential for GitHub Actions if using
# a multi-platform CI/CD strategy.
resource "azuread_application_federated_identity_credential" "github_actions_oidc" {
  count = var.environment == "prod" ? 0 : 1 # Only for non-prod environments

  application_id = azuread_application.terraform_pipeline.id
  display_name   = "oidc-github-${var.environment}"
  description    = "OIDC federation with GitHub Actions for ${var.environment} environment"

  # GitHub's OIDC issuer
  issuer = "https://token.actions.githubusercontent.com"

  # Subject restricts to a specific repo and environment
  subject = "repo:contoso-healthcare/azure-arm-terraform-migration:environment:${var.environment}"

  audiences = ["api://AzureADTokenExchange"]
}

# =============================================================================
# Client Secret (Fallback Authentication)
# =============================================================================
#
# The client secret is an OAuth 2.0 client credential (RFC 6749 Section 2.3.1).
# It functions like a password for the application.
#
# IMPORTANT: This is a FALLBACK method. Prefer Workload Identity Federation.
#
# In healthcare/HIPAA environments:
#   - Secrets must have short expiry (<=90 days)
#   - Secret rotation must be automated
#   - Secrets must be stored in a Key Vault, never in code or pipeline vars
#   - All secret access must be logged and monitored
#
# The time_rotating resource ensures the secret is recreated before expiry,
# triggering downstream automation to update Key Vault references.
# =============================================================================

resource "time_rotating" "secret_rotation" {
  count = var.enable_client_secret_fallback ? 1 : 0

  # Rotate 7 days before expiry to allow propagation time
  rotation_days = var.client_secret_expiry_days - 7
}

resource "azuread_application_password" "terraform_pipeline" {
  count = var.enable_client_secret_fallback ? 1 : 0

  application_id = azuread_application.terraform_pipeline.id
  display_name   = "terraform-ci-${var.environment}-${formatdate("YYYY-MM", timestamp())}"

  # End date is set to the configured expiry period.
  # The time_rotating resource will trigger recreation before this date.
  end_date_relative = "${var.client_secret_expiry_days * 24}h"

  # Rotate when the time_rotating resource triggers
  rotate_when_changed = var.enable_client_secret_fallback ? {
    rotation = time_rotating.secret_rotation[0].id
  } : {}

  lifecycle {
    # Create the new secret before destroying the old one to avoid
    # authentication gaps during rotation.
    create_before_destroy = true
  }
}

# =============================================================================
# Azure RBAC Role Assignments
# =============================================================================
#
# Role assignments grant the Service Principal permissions to manage
# Azure resources. These follow the principle of least privilege.
#
# OAuth 2.0 provides authentication (proving identity).
# Azure RBAC provides authorization (what the identity can do).
#
# The access token issued by Azure AD contains the service principal's
# object ID. When ARM receives an API call, it checks the RBAC assignments
# for that object ID at the relevant scope.
#
# For the migration project, we need:
#   - Contributor: Create/modify/delete Azure resources (VMs, networks, etc.)
#   - User Access Administrator: Assign roles to managed identities
#     (needed when Terraform creates resources with managed identities)
# =============================================================================

# Contributor role at subscription scope.
# Allows creating and managing all Azure resources, but not granting access.
resource "azurerm_role_assignment" "contributor" {
  scope                = data.azurerm_subscription.primary.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.terraform_pipeline.object_id

  # Skip the AAD check — service principals can take a few seconds to propagate
  skip_service_principal_aad_check = true

  description = "Terraform CI/CD pipeline - manages Azure resources for ${var.project_name} (${var.environment})"
}

# User Access Administrator role at subscription scope.
# Allows managing role assignments. Needed when Terraform creates
# resources with managed identities that need their own RBAC assignments.
#
# WARNING: This is a powerful role. In production, consider using
# a custom role with constrained permissions or scoping to specific
# resource groups instead of the entire subscription.
resource "azurerm_role_assignment" "user_access_admin" {
  scope                = data.azurerm_subscription.primary.id
  role_definition_name = "User Access Administrator"
  principal_id         = azuread_service_principal.terraform_pipeline.object_id

  skip_service_principal_aad_check = true

  description = "Terraform CI/CD pipeline - assigns roles to managed identities for ${var.project_name} (${var.environment})"

  # Condition to restrict which roles can be assigned (Azure ABAC).
  # This limits the blast radius — the pipeline can only assign specific roles,
  # not grant itself Owner or other high-privilege access.
  condition = <<-EOT
    (
      !(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})
    )
    OR
    (
      @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {
        acdd72a7-3385-48ef-bd42-f606fba81ae7,
        b24988ac-6180-42a0-ab88-20f7382dd24c
      }
    )
  EOT
  condition_version = "2.0"
}

# Additional role assignments from variable input
resource "azurerm_role_assignment" "additional" {
  for_each = { for idx, ra in var.additional_role_assignments : idx => ra }

  scope                = each.value.scope
  role_definition_name = each.value.role_definition_name
  principal_id         = azuread_service_principal.terraform_pipeline.object_id

  skip_service_principal_aad_check = true
  description                      = each.value.description
}

# =============================================================================
# Admin Consent Grant
# =============================================================================
#
# OAuth 2.0 delegated permissions require consent. For service principals
# in CI/CD, we use admin consent so no interactive user prompt is needed.
#
# This grants the service principal the user_impersonation scope on the
# Azure Service Management API with tenant-wide admin consent.
# =============================================================================

resource "azuread_service_principal_delegated_permission_grant" "arm_access" {
  service_principal_object_id          = azuread_service_principal.terraform_pipeline.object_id
  resource_service_principal_object_id = data.azuread_service_principal.azure_service_mgmt.object_id
  claim_values                         = ["user_impersonation"]
}

# =============================================================================
# Outputs
# =============================================================================

output "application_client_id" {
  description = "The OAuth 2.0 client_id for the Terraform pipeline"
  value       = azuread_application.terraform_pipeline.client_id
}

output "application_object_id" {
  description = "The Azure AD Application object ID"
  value       = azuread_application.terraform_pipeline.object_id
}

output "service_principal_object_id" {
  description = "The Service Principal object ID (used for RBAC assignments)"
  value       = azuread_service_principal.terraform_pipeline.object_id
}

output "tenant_id" {
  description = "The Azure AD tenant ID (OAuth 2.0 authorization server identifier)"
  value       = data.azuread_client_config.current.tenant_id
}

# Sensitive output — the client secret value.
# This should be stored in Key Vault immediately after creation.
output "client_secret_value" {
  description = "The OAuth 2.0 client_secret (store in Key Vault, do not log)"
  value       = var.enable_client_secret_fallback ? azuread_application_password.terraform_pipeline[0].value : null
  sensitive   = true
}

output "client_secret_expiry" {
  description = "The client secret expiration date"
  value       = var.enable_client_secret_fallback ? azuread_application_password.terraform_pipeline[0].end_date : null
}

output "oidc_issuer_url" {
  description = "The OIDC issuer URL for Azure DevOps federation"
  value       = azuread_application_federated_identity_credential.azure_devops_oidc.issuer
}

# OAuth 2.0 token endpoint for this tenant.
# The client credentials flow sends POST requests to this URL.
output "oauth2_token_endpoint" {
  description = "Azure AD OAuth 2.0 token endpoint (v2.0)"
  value       = "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/oauth2/v2.0/token"
}

# The resource/scope to request when calling ARM APIs.
output "arm_api_scope" {
  description = "The OAuth 2.0 scope to request for ARM API access"
  value       = "https://management.azure.com/.default"
}
