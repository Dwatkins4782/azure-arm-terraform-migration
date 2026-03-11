# =============================================================================
# Azure AD (Entra ID) SAML SSO Configuration for Enterprise Healthcare
# =============================================================================
#
# SAML 2.0 Single Sign-On Flow with Azure AD
# --------------------------------------------
# This configuration sets up Azure AD as an Identity Provider (IdP) for
# SAML-based SSO with enterprise healthcare applications.
#
# Enterprise SAML SSO Flow (SP-Initiated):
#   1. User navigates to the healthcare application (Service Provider / SP)
#   2. SP detects unauthenticated user, generates SAML AuthnRequest
#   3. SP redirects user's browser to Azure AD's SSO URL (IdP)
#      - HTTP-Redirect binding: AuthnRequest in query parameter (deflated + base64)
#   4. Azure AD authenticates the user:
#      - Password + MFA (Conditional Access policy)
#      - Certificate-based auth for clinical workstations
#      - Windows Integrated Auth for domain-joined machines
#   5. Azure AD creates a SAML Response containing:
#      - Assertion with authentication statement
#      - Attribute statement with user claims (name, email, groups, custom claims)
#      - Digital signature using Azure AD's signing certificate
#   6. Azure AD POST-redirects user to SP's Assertion Consumer Service (ACS) URL
#      - HTTP-POST binding: SAML Response in hidden form field, auto-submitted
#   7. SP validates the SAML Response:
#      - Verifies XML signature using Azure AD's public certificate
#      - Checks assertion conditions (time validity, audience)
#      - Extracts user claims for authorization decisions
#   8. SP creates a local session for the authenticated user
#
# IdP-Initiated Flow:
#   - User clicks app tile in Azure AD My Apps portal
#   - Steps 5-8 from above (no AuthnRequest was sent)
#
# HIPAA Considerations:
#   - Custom claims carry employee ID and department for audit trails
#   - Group claims determine PHI access levels
#   - Session lifetime aligns with HIPAA workstation timeout requirements
#   - All SAML assertions are signed and optionally encrypted
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
  }
}

# -----------------------------------------------------------------------------
# Data Sources
# -----------------------------------------------------------------------------

data "azuread_client_config" "current" {}

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------

variable "application_name" {
  description = "Display name for the SAML enterprise application"
  type        = string
  default     = "Healthcare Portal - ARM Migration"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "sp_entity_id" {
  description = <<-EOT
    The Service Provider Entity ID (also called Identifier or Audience URI).
    This is a globally unique identifier for the SP, usually the application URL.
    The IdP includes this in the Audience Restriction of the SAML assertion.
    The SP validates that the assertion is intended for it using this value.
  EOT
  type        = string
  default     = "https://healthcare-portal.contoso.com"
}

variable "sp_acs_url" {
  description = <<-EOT
    Assertion Consumer Service (ACS) URL.
    This is the SP endpoint that receives the SAML Response from the IdP
    via HTTP-POST binding. After Azure AD authenticates the user, it
    POST-redirects the browser to this URL with the signed SAML assertion.
  EOT
  type        = string
  default     = "https://healthcare-portal.contoso.com/auth/saml/callback"
}

variable "sp_logout_url" {
  description = "Single Logout (SLO) URL for coordinated session termination"
  type        = string
  default     = "https://healthcare-portal.contoso.com/auth/saml/logout"
}

variable "sp_sign_on_url" {
  description = "The URL where users are sent to initiate SP-initiated SSO"
  type        = string
  default     = "https://healthcare-portal.contoso.com/login"
}

variable "saml_token_lifetime_minutes" {
  description = <<-EOT
    SAML token (assertion) lifetime in minutes.
    For HIPAA compliance, this should be short to limit the window
    for token replay attacks. The SP should enforce its own session
    timeout independent of this value.
  EOT
  type        = number
  default     = 60

  validation {
    condition     = var.saml_token_lifetime_minutes >= 5 && var.saml_token_lifetime_minutes <= 480
    error_message = "Token lifetime must be between 5 and 480 minutes."
  }
}

variable "notification_email_addresses" {
  description = "Email addresses to notify about certificate expiry and SSO issues"
  type        = list(string)
  default     = ["infra-team@contoso.com", "security-ops@contoso.com"]
}

# -----------------------------------------------------------------------------
# Locals
# -----------------------------------------------------------------------------

locals {
  # SAML claim URIs follow established namespace conventions.
  # These map Azure AD user attributes to SAML assertion claims.
  saml_claims = {
    # Standard identity claims
    email = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
    name  = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
    given = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
    sur   = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"
    # Microsoft-specific claims
    groups = "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
    role   = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
  }
}

# =============================================================================
# Azure AD Application Registration (SAML)
# =============================================================================
#
# The Application object defines the SAML SP trust relationship.
# Key differences from OAuth 2.0 app registrations:
#   - No redirect URIs (SAML uses ACS URLs instead)
#   - identifier_uris contains the SP Entity ID
#   - No API permissions (SAML uses claims, not scopes)
#   - Web section configures SAML-specific URLs
# =============================================================================

resource "azuread_application" "saml_app" {
  display_name = "${var.application_name} (${var.environment})"

  owners = [data.azuread_client_config.current.object_id]

  # The identifier URI serves as the Entity ID / Audience URI.
  # Azure AD includes this in the AudienceRestriction condition of the
  # SAML assertion. The SP validates this to ensure the assertion was
  # intended for it and not another application.
  identifier_uris = [var.sp_entity_id]

  # Sign-in audience: AzureADMyOrg restricts authentication to users
  # in this Azure AD tenant only. For B2B scenarios with partner
  # hospitals, use AzureADMultipleOrgs.
  sign_in_audience = "AzureADMyOrg"

  # Group membership claims in the SAML assertion.
  # "SecurityGroup" includes security groups the user belongs to.
  # These claims drive RBAC decisions in the healthcare application.
  #
  # Options: "None", "SecurityGroup", "DirectoryRole", "ApplicationGroup", "All"
  group_membership_claims = ["SecurityGroup"]

  # Web configuration for SAML endpoints
  web {
    # Homepage URL: Where users land when clicking the app in My Apps portal
    homepage_url = var.sp_sign_on_url

    # Implicit grant is not used with SAML (it's an OAuth 2.0 concept)
    implicit_grant {
      access_token_issuance_enabled = false
      id_token_issuance_enabled     = false
    }
  }

  # Optional claims customize what appears in the SAML assertion.
  # These are in addition to the default claims Azure AD includes.
  optional_claims {
    # SAML token claims (type "saml2")
    # Each claim adds an Attribute element to the AttributeStatement
    # in the SAML assertion.

    saml2_token {
      # Employee ID from Azure AD (synced from on-prem AD or HR system).
      # HIPAA requires this for audit trail correlation with HR systems.
      name                  = "employeeid"
      essential             = true
      additional_properties = []
    }

    saml2_token {
      # User's department. Used for compartmentalized PHI access.
      # Example: Only "Radiology" department users can access imaging data.
      name                  = "department"
      essential             = false
      additional_properties = []
    }

    saml2_token {
      # UPN (User Principal Name) in the SAML assertion.
      # Useful when NameID format doesn't carry the UPN.
      name                  = "upn"
      essential             = false
      additional_properties = []
    }

    saml2_token {
      # Tenant ID for multi-tenant scenarios with partner hospitals.
      name                  = "tenantid"
      essential             = false
      additional_properties = []
    }
  }

  tags = ["SAML", "SSO", "Healthcare", var.environment]

  lifecycle {
    prevent_destroy = true
  }
}

# =============================================================================
# Service Principal (SAML Enterprise Application)
# =============================================================================
#
# The Service Principal is the tenant-local instance of the application.
# For SAML SSO, the service principal configuration includes:
#   - Preferred SSO mode set to "saml"
#   - SAML SSO endpoint URLs (ACS, logout, sign-on)
#   - Certificate configuration for signing
#   - User/group assignment for access control
#
# The service principal is what appears in the "Enterprise Applications"
# blade in the Azure AD portal.
# =============================================================================

resource "azuread_service_principal" "saml_sp" {
  client_id = azuread_application.saml_app.client_id

  # Set the preferred SSO mode to SAML.
  # This tells Azure AD to use SAML 2.0 protocol when users access
  # this application, instead of OpenID Connect or other methods.
  preferred_single_sign_on_mode = "saml"

  # Login URL for SP-initiated SSO.
  # When users click the app tile in My Apps, Azure AD redirects here
  # first, which triggers the SP to generate an AuthnRequest.
  login_url = var.sp_sign_on_url

  # App role assignment required: When true, users must be explicitly
  # assigned to this application (directly or via group) to sign in.
  # This is CRITICAL for healthcare - it prevents unauthorized users
  # from accessing PHI-containing applications.
  app_role_assignment_required = true

  owners = [data.azuread_client_config.current.object_id]

  # SAML SSO URLs configuration
  # These URLs are sent to the SP in the SAML metadata and used during
  # the SSO flow.
  saml_single_sign_on {
    relay_state = "/"
  }

  # Notification emails for certificate expiry and SSO configuration issues.
  # Azure AD sends alerts 60, 30, and 7 days before certificate expiry.
  notification_email_addresses = var.notification_email_addresses

  feature_tags {
    enterprise = true  # Show in Enterprise Applications
    hide       = false # Show in My Apps portal for end users
  }

  tags = ["SAML", "SSO", "Healthcare", "WindowsAzureActiveDirectoryIntegratedApp"]
}

# =============================================================================
# Claims Mapping Policy
# =============================================================================
#
# Claims mapping policies customize which claims appear in the SAML
# assertion beyond the defaults. This is essential for healthcare
# applications that need:
#   - Employee ID for HIPAA audit trail correlation
#   - Department for compartmentalized access to PHI
#   - Custom role claims for fine-grained authorization
#
# The policy is a JSON document that defines:
#   - ClaimsSchema: Maps source attributes to SAML claim URIs
#   - IncludeBasicClaimSet: Whether to include default claims
#
# IMPORTANT: Claims mapping policies override the default claims.
# Always test SSO after applying a new policy to ensure the SP
# receives all required attributes.
# =============================================================================

resource "azuread_claims_mapping_policy" "healthcare_claims" {
  display_name = "Healthcare SAML Claims - ${var.environment}"

  definition = [jsonencode({
    ClaimsMappingPolicy = {
      Version = 1

      # Include the basic claim set (name, email, etc.) in addition
      # to our custom claims.
      IncludeBasicClaimSet = "true"

      ClaimsSchema = [
        {
          # Employee ID: Maps the Azure AD employeeId attribute to a
          # custom SAML claim. This is the primary identifier used in
          # HIPAA audit logs to track who accessed what PHI.
          #
          # Source: Azure AD user profile (synced from on-prem AD or HR)
          # SAML Claim: <Attribute Name="employeeid">
          Source    = "user"
          ID        = "employeeid"
          SamlClaimType = "employeeid"
        },
        {
          # Department: Maps the user's department to a SAML claim.
          # Used for compartmentalized access control:
          #   - "Cardiology" -> access to cardiology patient records
          #   - "Radiology"  -> access to imaging data
          #   - "Pharmacy"   -> access to medication records
          Source    = "user"
          ID        = "department"
          SamlClaimType = "department"
        },
        {
          # Job Title: Additional context for access decisions.
          # Physicians get different access levels than nurses or admins.
          Source    = "user"
          ID        = "jobtitle"
          SamlClaimType = "http://schemas.contoso.com/identity/claims/jobtitle"
        },
        {
          # On-premises Security Identifier (SID): For applications that
          # need to correlate with on-premises Active Directory.
          Source    = "user"
          ID        = "onpremisessecurityidentifier"
          SamlClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"
        },
        {
          # Display Name: Full name for display in the application UI
          # and audit logs.
          Source    = "user"
          ID        = "displayname"
          SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
        },
        {
          # Email Address: Primary communication address and often
          # used as the NameID in the SAML Subject.
          Source    = "user"
          ID        = "userprincipalname"
          SamlClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
        },
      ]
    }
  })]
}

# Associate the claims mapping policy with the service principal.
# This tells Azure AD to use our custom claims schema when issuing
# SAML assertions for this application.
resource "azuread_service_principal_claims_mapping_policy_assignment" "healthcare" {
  service_principal_id   = azuread_service_principal.saml_sp.id
  claims_mapping_policy_id = azuread_claims_mapping_policy.healthcare_claims.id
}

# =============================================================================
# Token Signing Certificate Configuration
# =============================================================================
#
# Azure AD signs SAML assertions using an X.509 certificate.
# The SP validates this signature to ensure:
#   1. The assertion was issued by Azure AD (not forged)
#   2. The assertion was not tampered with in transit
#
# Azure AD auto-generates a signing certificate when SAML SSO is configured.
# This certificate:
#   - Has a 3-year validity period
#   - Uses SHA-256 for signing
#   - Is automatically included in the IdP metadata
#   - Must be shared with the SP (via metadata or manual export)
#
# Certificate rotation process:
#   1. Azure AD sends notification emails before expiry
#   2. Admin creates a new certificate in Azure AD
#   3. New certificate is shared with the SP
#   4. SP is updated to trust both old and new certificates
#   5. Azure AD is switched to use the new certificate for signing
#   6. Old certificate is removed after confirming SSO works
# =============================================================================

resource "azuread_service_principal_token_signing_certificate" "saml_signing" {
  service_principal_id = azuread_service_principal.saml_sp.id

  # Display name for the certificate (visible in Azure AD portal)
  display_name = "SAML Signing Certificate - ${var.environment}"

  # End date for the certificate. Set to 3 years for production.
  # Monitor expiry via the notification_email_addresses on the SP.
  end_date = timeadd(timestamp(), "26280h") # ~3 years
}

# =============================================================================
# Outputs
# =============================================================================

output "application_id" {
  description = "Azure AD Application (client) ID"
  value       = azuread_application.saml_app.client_id
}

output "service_principal_object_id" {
  description = "Service Principal object ID"
  value       = azuread_service_principal.saml_sp.object_id
}

output "sp_entity_id" {
  description = "SAML SP Entity ID (Audience URI)"
  value       = var.sp_entity_id
}

output "acs_url" {
  description = "Assertion Consumer Service URL"
  value       = var.sp_acs_url
}

# The IdP metadata URL provides all information the SP needs to configure
# trust with Azure AD, including:
#   - IdP Entity ID
#   - SSO endpoint URL
#   - Signing certificate
#   - Supported NameID formats
output "idp_metadata_url" {
  description = <<-EOT
    Azure AD SAML IdP Metadata URL.
    The SP imports this URL to auto-configure the trust relationship.
    It contains the IdP's signing certificate, SSO URL, and Entity ID.
  EOT
  value = "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/federationmetadata/2007-06/federationmetadata.xml?appid=${azuread_application.saml_app.client_id}"
}

# The SAML SSO login URL. The SP redirects users here to initiate
# IdP-side authentication.
output "idp_sso_url" {
  description = "Azure AD SAML SSO Login URL"
  value       = "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/saml2"
}

# The SAML SLO URL for Single Logout.
output "idp_slo_url" {
  description = "Azure AD SAML Single Logout URL"
  value       = "https://login.microsoftonline.com/${data.azuread_client_config.current.tenant_id}/saml2"
}

output "tenant_id" {
  description = "Azure AD Tenant ID"
  value       = data.azuread_client_config.current.tenant_id
}

output "signing_certificate_thumbprint" {
  description = "Thumbprint of the SAML signing certificate"
  value       = azuread_service_principal_token_signing_certificate.saml_signing.thumbprint
}

output "signing_certificate_expiry" {
  description = "Expiry date of the SAML signing certificate"
  value       = azuread_service_principal_token_signing_certificate.saml_signing.end_date
}
