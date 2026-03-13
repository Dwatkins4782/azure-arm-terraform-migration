#!/bin/bash
# =============================================================================
# Critical Resource Protection Check
#
# PURPOSE:
#   Analyzes a Terraform plan JSON file for destructive operations on critical
#   resource types. If any critical resource would be destroyed or replaced,
#   this script exits with code 1, blocking the pipeline.
#
# USAGE:
#   ./check-critical-resources.sh <path-to-tfplan.json>
#
# EXIT CODES:
#   0 — No critical resources affected. Safe to proceed.
#   1 — Critical resources would be destroyed. Pipeline should be blocked.
#   2 — Invalid arguments or missing plan file.
#
# CONTEXT:
#   This script was created after an incident where changing Key Vault's
#   enable_rbac_authorization property caused a cascade destruction of 50+
#   AKS clusters. See docs/RBAC-MIGRATION-INCIDENT-ANALYSIS.md.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
PLAN_JSON="${1:-}"

if [[ -z "$PLAN_JSON" ]]; then
  echo "Usage: $0 <plan.json>"
  echo "  Analyzes terraform plan JSON for destructive operations on critical resources."
  exit 2
fi

if [[ ! -f "$PLAN_JSON" ]]; then
  echo "ERROR: Plan file not found: $PLAN_JSON"
  exit 2
fi

# ---------------------------------------------------------------------------
# Critical resource types
#
# These are resource types where destruction causes data loss, outages,
# or cascading failures. Add new types as needed.
# ---------------------------------------------------------------------------
CRITICAL_TYPES=(
  "azurerm_key_vault"
  "azurerm_key_vault_key"
  "azurerm_kubernetes_cluster"
  "azurerm_kubernetes_cluster_node_pool"
  "azurerm_disk_encryption_set"
  "azurerm_mssql_server"
  "azurerm_mssql_database"
  "azurerm_cosmosdb_account"
  "azurerm_storage_account"
  "azurerm_postgresql_server"
  "azurerm_postgresql_flexible_server"
  "azurerm_redis_cache"
  "azurerm_container_registry"
  "azurerm_virtual_network"
  "azurerm_subnet"
  "azurerm_application_gateway"
  "azurerm_firewall"
)

# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
echo "═══════════════════════════════════════════════════════════════════"
echo "  CRITICAL RESOURCE PROTECTION CHECK"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Analyzing plan: $(basename "$PLAN_JSON")"
echo "Checking ${#CRITICAL_TYPES[@]} critical resource types..."
echo ""

BLOCKED=false
TOTAL_CRITICAL_DESTROY=0
TOTAL_CRITICAL_REPLACE=0
DETAILS=""

for resource_type in "${CRITICAL_TYPES[@]}"; do
  # Count resources of this type being destroyed (pure delete)
  DESTROY_COUNT=$(jq -r "
    [.resource_changes[]
     | select(.type == \"${resource_type}\")
     | select(.change.actions == [\"delete\"])
    ] | length
  " "$PLAN_JSON" 2>/dev/null || echo 0)

  # Count resources of this type being replaced (delete + create)
  REPLACE_COUNT=$(jq -r "
    [.resource_changes[]
     | select(.type == \"${resource_type}\")
     | select(.change.actions == [\"delete\", \"create\"])
    ] | length
  " "$PLAN_JSON" 2>/dev/null || echo 0)

  if [ "$DESTROY_COUNT" -gt 0 ] || [ "$REPLACE_COUNT" -gt 0 ]; then
    BLOCKED=true
    TOTAL_CRITICAL_DESTROY=$((TOTAL_CRITICAL_DESTROY + DESTROY_COUNT))
    TOTAL_CRITICAL_REPLACE=$((TOTAL_CRITICAL_REPLACE + REPLACE_COUNT))

    echo "  🚨 BLOCKED: ${resource_type}"
    echo "     Destroying: ${DESTROY_COUNT}  |  Replacing: ${REPLACE_COUNT}"

    # Show which specific resources are affected
    AFFECTED=$(jq -r "
      .resource_changes[]
      | select(.type == \"${resource_type}\")
      | select(.change.actions | contains([\"delete\"]))
      | \"     → \" + .address + \" (\" + (.change.actions | join(\", \")) + \")\"
    " "$PLAN_JSON" 2>/dev/null || echo "")

    if [[ -n "$AFFECTED" ]]; then
      echo "$AFFECTED"
    fi
    echo ""
  fi
done

# ---------------------------------------------------------------------------
# Cascade Detection
#
# Check for patterns that indicate a cascade is happening:
# - Key Vault being replaced + AKS clusters being replaced = cascade
# ---------------------------------------------------------------------------
echo "───────────────────────────────────────────────────────────────────"
echo "  CASCADE DETECTION"
echo "───────────────────────────────────────────────────────────────────"

KV_REPLACING=$(jq '[.resource_changes[] | select(.type == "azurerm_key_vault") | select(.change.actions | contains(["delete"]))] | length' "$PLAN_JSON" 2>/dev/null || echo 0)
AKS_REPLACING=$(jq '[.resource_changes[] | select(.type == "azurerm_kubernetes_cluster") | select(.change.actions | contains(["delete"]))] | length' "$PLAN_JSON" 2>/dev/null || echo 0)

if [ "$KV_REPLACING" -gt 0 ] && [ "$AKS_REPLACING" -gt 0 ]; then
  echo ""
  echo "  🔴 CASCADE DETECTED: Key Vault replacement → AKS cluster destruction"
  echo ""
  echo "  This is the exact pattern that caused the RBAC migration incident."
  echo "  ${KV_REPLACING} Key Vault(s) being replaced → ${AKS_REPLACING} AKS cluster(s) cascading"
  echo ""
  echo "  RECOMMENDED ACTION:"
  echo "    1. Do NOT apply this plan"
  echo "    2. Use the out-of-band migration approach instead"
  echo "    3. See docs/RBAC-MIGRATION-INCIDENT-ANALYSIS.md Section 8"
  echo ""
  BLOCKED=true
elif [ "$KV_REPLACING" -gt 0 ]; then
  echo ""
  echo "  ⚠️  WARNING: Key Vault replacement detected but no AKS cascade (yet)"
  echo "  Review carefully — dependent resources may be in a different state file."
  echo ""
  BLOCKED=true
else
  echo ""
  echo "  ✅ No cascade patterns detected."
  echo ""
fi

# ---------------------------------------------------------------------------
# High Destroy Count Warning
# ---------------------------------------------------------------------------
TOTAL_DESTROY=$(jq '[.resource_changes[] | select(.change.actions | contains(["delete"]))] | length' "$PLAN_JSON" 2>/dev/null || echo 0)

if [ "$TOTAL_DESTROY" -gt 10 ]; then
  echo "───────────────────────────────────────────────────────────────────"
  echo "  ⚠️  HIGH DESTRUCTION COUNT: ${TOTAL_DESTROY} resources to destroy"
  echo "  This may indicate a misconfiguration or state drift."
  echo "  Review the full plan output carefully before proceeding."
  echo "───────────────────────────────────────────────────────────────────"
  echo ""
fi

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------
echo "═══════════════════════════════════════════════════════════════════"

if [ "$BLOCKED" = true ]; then
  echo ""
  echo "  ❌ PIPELINE BLOCKED"
  echo ""
  echo "  Critical resources would be destroyed or replaced:"
  echo "    Destroy: ${TOTAL_CRITICAL_DESTROY}"
  echo "    Replace: ${TOTAL_CRITICAL_REPLACE}"
  echo ""
  echo "  This pipeline requires manual approval before proceeding."
  echo "  Review the plan output in the Plan stage artifacts."
  echo ""
  echo "  If this change is intentional:"
  echo "    1. Review docs/RBAC-MIGRATION-INCIDENT-ANALYSIS.md"
  echo "    2. Consider using the out-of-band migration approach"
  echo "    3. If you must proceed, request manual approval"
  echo ""
  echo "═══════════════════════════════════════════════════════════════════"
  exit 1
else
  echo ""
  echo "  ✅ SAFE TO PROCEED"
  echo ""
  echo "  No critical resources will be destroyed or replaced."
  echo "  Total destructive operations: ${TOTAL_DESTROY}"
  echo ""
  echo "═══════════════════════════════════════════════════════════════════"
  exit 0
fi
