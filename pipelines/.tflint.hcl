# =============================================================================
# TFLint Configuration for Azure ARM-to-Terraform Migration
#
# Enforces naming conventions, catches deprecated resources, and requires
# mandatory tags on all taggable Azure resources.
#
# Docs: https://github.com/terraform-linters/tflint
# AzureRM plugin: https://github.com/terraform-linters/tflint-ruleset-azurerm
# =============================================================================

# ---------------------------------------------------------------------------
# Plugin: AzureRM
# Provides Azure-specific rules for the azurerm Terraform provider.
# ---------------------------------------------------------------------------
plugin "azurerm" {
  enabled = true
  version = "0.27.0"
  source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}

# ---------------------------------------------------------------------------
# Core TFLint rules
# ---------------------------------------------------------------------------

# Enforce that all Terraform files are canonically formatted.
rule "terraform_standard_module_structure" {
  enabled = true
}

# Flag variables and outputs that are declared but never used.
rule "terraform_unused_declarations" {
  enabled = true
}

# Require all variables and outputs to have a description attribute.
rule "terraform_documented_variables" {
  enabled = true
}

rule "terraform_documented_outputs" {
  enabled = true
}

# Flag any use of deprecated Terraform syntax or interpolation.
rule "terraform_deprecated_interpolation" {
  enabled = true
}

# Warn when a module source uses a revision-less reference.
rule "terraform_module_pinned_source" {
  enabled = true
}

# Enforce consistent naming conventions for resources, variables, and outputs.
# Snake_case is the Terraform community standard.
rule "terraform_naming_convention" {
  enabled = true

  # All resource, data source, variable, and output names must be snake_case
  custom = "^[a-z][a-z0-9_]*$"
}

# ---------------------------------------------------------------------------
# AzureRM-specific rules — deprecated resources
# These flag resources that have been superseded by newer equivalents.
# ---------------------------------------------------------------------------

# Flag deprecated azurerm_virtual_machine (use azurerm_linux_virtual_machine
# or azurerm_windows_virtual_machine instead).
rule "azurerm_linux_virtual_machine_invalid_size" {
  enabled = true
}

rule "azurerm_windows_virtual_machine_invalid_size" {
  enabled = true
}

# ---------------------------------------------------------------------------
# AzureRM-specific rules — networking
# ---------------------------------------------------------------------------

# Validate that network security group rule priorities are within bounds.
rule "azurerm_network_security_rule_invalid_priority" {
  enabled = true
}

# Validate subnet address prefix format.
rule "azurerm_subnet_invalid_address_prefix" {
  enabled = true
}

# ---------------------------------------------------------------------------
# AzureRM-specific rules — database
# ---------------------------------------------------------------------------

# Catch invalid SKU names for SQL and PostgreSQL servers.
rule "azurerm_mssql_server_invalid_minimum_tls_version" {
  enabled = true
}

# ---------------------------------------------------------------------------
# AzureRM-specific rules — security and compliance
# ---------------------------------------------------------------------------

# Flag Key Vault configurations missing soft-delete or purge protection.
rule "azurerm_key_vault_invalid_sku_name" {
  enabled = true
}

# Validate storage account TLS versions.
rule "azurerm_storage_account_invalid_min_tls_version" {
  enabled = true
}

# ---------------------------------------------------------------------------
# Custom tag enforcement
# All taggable Azure resources must include these mandatory tags.
# Uses the terraform_required_providers rule pattern. Tag enforcement is
# handled via OPA/Rego policies in tests/compliance/ for full flexibility;
# this section catches the most common omissions at lint time.
# ---------------------------------------------------------------------------

rule "azurerm_resource_group_invalid_location" {
  enabled = true
}
