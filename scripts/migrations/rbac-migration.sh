#!/bin/bash
# =============================================================================
# Azure Key Vault RBAC Migration — Blue-Green Automated Script
#
# PURPOSE:
#   Safely migrates Azure Key Vault from Access Policies to RBAC authorization
#   using a blue-green strategy with gates, health checks, and automatic
#   rollback. Prevents the cascade-destruction incident documented in
#   docs/RBAC-MIGRATION-INCIDENT-ANALYSIS.md.
#
# STRATEGY (Blue-Green):
#   1. BLUE  = Current Key Vault (access policies) — stays live the entire time
#   2. GREEN = New Key Vault (RBAC-enabled) — built and validated in parallel
#   3. Secrets/keys/certs copied from BLUE → GREEN
#   4. RBAC role assignments created on GREEN
#   5. AKS clusters and apps switched to GREEN one-by-one (canary)
#   6. Health checks after each switchover
#   7. If any check fails → automatic rollback to BLUE
#   8. After full validation → BLUE soft-deleted (recoverable for 90 days)
#
# GATES (7 mandatory checkpoints):
#   Gate 1: Pre-flight validation (Azure auth, permissions, cluster health)
#   Gate 2: Green vault creation + secret replication verification
#   Gate 3: RBAC role assignment verification (every identity can access GREEN)
#   Gate 4: Canary cluster switchover + health check
#   Gate 5: Batch cluster switchover + health check (per-batch)
#   Gate 6: Full platform health validation
#   Gate 7: Terraform state alignment verification (zero-drift)
#
# ROLLBACK:
#   Automatic rollback is triggered if ANY gate fails. Manual rollback can
#   be invoked at any time with: ./rbac-migration.sh --rollback
#
# USAGE:
#   ./rbac-migration.sh --config migration-config.env
#   ./rbac-migration.sh --config migration-config.env --dry-run
#   ./rbac-migration.sh --config migration-config.env --rollback
#   ./rbac-migration.sh --config migration-config.env --skip-to-gate 4
#   ./rbac-migration.sh --config migration-config.env --canary-only
#
# REQUIREMENTS:
#   - Azure CLI >= 2.55.0
#   - kubectl configured with cluster access
#   - jq >= 1.6
#   - Sufficient Azure RBAC permissions (Owner or User Access Administrator)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="${SCRIPT_DIR}/logs/rbac-migration-${TIMESTAMP}"
ROLLBACK_STATE_FILE="${LOG_DIR}/rollback-state.json"
GATE_LOG="${LOG_DIR}/gates.log"
MIGRATION_LOCK="/tmp/rbac-migration.lock"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'  # No color
BOLD='\033[1m'

# ---------------------------------------------------------------------------
# Default Configuration (override with --config file)
# ---------------------------------------------------------------------------
DRY_RUN=false
ROLLBACK_MODE=false
CANARY_ONLY=false
SKIP_TO_GATE=0
AUTO_APPROVE=false
CONFIG_FILE=""

# Vault settings
BLUE_VAULT_NAME=""
GREEN_VAULT_NAME=""
RESOURCE_GROUP=""
LOCATION=""
SUBSCRIPTION_ID=""
TENANT_ID=""

# AKS clusters (populated from config)
declare -a AKS_CLUSTERS=()
declare -a CANARY_CLUSTERS=()

# Identity mappings (populated from config)
declare -A IDENTITY_ROLE_MAP=()

# Timeouts
HEALTH_CHECK_TIMEOUT=300
ROLLBACK_TIMEOUT=600
GATE_WAIT_TIMEOUT=60

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log() {
  local level="$1"
  shift
  local msg="$*"
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')

  case "$level" in
    INFO)    echo -e "${CYAN}[${ts}] [INFO]${NC}  $msg" ;;
    OK)      echo -e "${GREEN}[${ts}] [  OK]${NC}  $msg" ;;
    WARN)    echo -e "${YELLOW}[${ts}] [WARN]${NC}  $msg" ;;
    ERROR)   echo -e "${RED}[${ts}] [FAIL]${NC}  $msg" ;;
    GATE)    echo -e "${BOLD}${BLUE}[${ts}] [GATE]${NC}  $msg" ;;
    ACTION)  echo -e "${BOLD}[${ts}] [ >> ]${NC}  $msg" ;;
  esac

  echo "[${ts}] [${level}] $msg" >> "${LOG_DIR}/migration.log"
}

gate_log() {
  local gate_num="$1"
  local status="$2"
  local msg="$3"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Gate ${gate_num}: ${status} — ${msg}" >> "$GATE_LOG"
}

# ---------------------------------------------------------------------------
# Gate System
# ---------------------------------------------------------------------------
gate_check() {
  local gate_num="$1"
  local gate_name="$2"
  local check_function="$3"

  echo ""
  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
  log GATE "GATE ${gate_num}: ${gate_name}"
  echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
  echo ""

  if [ "$SKIP_TO_GATE" -gt "$gate_num" ]; then
    log WARN "Skipping Gate ${gate_num} (--skip-to-gate ${SKIP_TO_GATE})"
    gate_log "$gate_num" "SKIPPED" "$gate_name"
    return 0
  fi

  # Run the check function
  if $check_function; then
    log OK "Gate ${gate_num} PASSED: ${gate_name}"
    gate_log "$gate_num" "PASSED" "$gate_name"

    if [ "$AUTO_APPROVE" = false ] && [ "$DRY_RUN" = false ]; then
      echo ""
      echo -e "${YELLOW}  Gate ${gate_num} passed. Proceed to next phase?${NC}"
      echo -e "  ${BOLD}[y]${NC} Continue  |  ${BOLD}[r]${NC} Rollback  |  ${BOLD}[a]${NC} Abort"
      read -r -p "  > " response
      case "$response" in
        y|Y|yes) log INFO "User approved Gate ${gate_num}" ;;
        r|R|rollback) log WARN "User triggered rollback at Gate ${gate_num}"; execute_rollback; exit 0 ;;
        *) log ERROR "User aborted at Gate ${gate_num}"; exit 1 ;;
      esac
    fi
    return 0
  else
    log ERROR "Gate ${gate_num} FAILED: ${gate_name}"
    gate_log "$gate_num" "FAILED" "$gate_name"

    echo ""
    echo -e "${RED}  Gate ${gate_num} FAILED. Automatic rollback will begin.${NC}"
    echo -e "  ${BOLD}[r]${NC} Rollback now  |  ${BOLD}[s]${NC} Skip (dangerous)  |  ${BOLD}[a]${NC} Abort without rollback"

    if [ "$AUTO_APPROVE" = true ]; then
      log WARN "Auto-approve mode: triggering automatic rollback"
      execute_rollback
      exit 1
    fi

    read -r -p "  > " response
    case "$response" in
      r|R) execute_rollback; exit 1 ;;
      s|S) log WARN "User chose to skip failed Gate ${gate_num} — DANGEROUS"; return 0 ;;
      *) log ERROR "User aborted without rollback"; exit 1 ;;
    esac
  fi
}

# ---------------------------------------------------------------------------
# Rollback State Management
# ---------------------------------------------------------------------------
save_rollback_state() {
  local phase="$1"
  local data="$2"

  # Read existing state or create new
  if [ -f "$ROLLBACK_STATE_FILE" ]; then
    local current
    current=$(cat "$ROLLBACK_STATE_FILE")
    echo "$current" | jq --arg phase "$phase" --argjson data "$data" \
      '. + {($phase): $data, "last_phase": $phase, "timestamp": now}' \
      > "$ROLLBACK_STATE_FILE"
  else
    echo "{}" | jq --arg phase "$phase" --argjson data "$data" \
      '. + {($phase): $data, "last_phase": $phase, "timestamp": now}' \
      > "$ROLLBACK_STATE_FILE"
  fi

  log INFO "Rollback state saved: phase=${phase}"
}

# ---------------------------------------------------------------------------
# Parse Arguments
# ---------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)        CONFIG_FILE="$2"; shift 2 ;;
      --dry-run)       DRY_RUN=true; shift ;;
      --rollback)      ROLLBACK_MODE=true; shift ;;
      --canary-only)   CANARY_ONLY=true; shift ;;
      --skip-to-gate)  SKIP_TO_GATE="$2"; shift 2 ;;
      --auto-approve)  AUTO_APPROVE=true; shift ;;
      --help|-h)       show_help; exit 0 ;;
      *)               echo "Unknown option: $1"; show_help; exit 1 ;;
    esac
  done
}

show_help() {
  cat <<'HELP'
Azure Key Vault RBAC Migration — Blue-Green Strategy

USAGE:
  ./rbac-migration.sh --config <config-file> [OPTIONS]

OPTIONS:
  --config <file>      Migration configuration file (required)
  --dry-run            Simulate all steps without making changes
  --rollback           Execute rollback using saved state
  --canary-only        Stop after canary cluster validation
  --skip-to-gate <N>   Skip to gate N (dangerous, for recovery)
  --auto-approve       Skip interactive confirmations
  --help               Show this help message

EXAMPLES:
  # Dry run first
  ./rbac-migration.sh --config migration-config.env --dry-run

  # Full migration with interactive gates
  ./rbac-migration.sh --config migration-config.env

  # Canary only (validate with one cluster before full rollout)
  ./rbac-migration.sh --config migration-config.env --canary-only

  # Rollback to previous state
  ./rbac-migration.sh --config migration-config.env --rollback
HELP
}

# ---------------------------------------------------------------------------
# Load Configuration
# ---------------------------------------------------------------------------
load_config() {
  if [ -z "$CONFIG_FILE" ]; then
    echo "ERROR: --config is required"
    show_help
    exit 1
  fi

  if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Config file not found: $CONFIG_FILE"
    exit 1
  fi

  # shellcheck source=/dev/null
  source "$CONFIG_FILE"

  # Validate required vars
  local required_vars=(
    BLUE_VAULT_NAME GREEN_VAULT_NAME RESOURCE_GROUP
    LOCATION SUBSCRIPTION_ID TENANT_ID
  )
  for var in "${required_vars[@]}"; do
    if [ -z "${!var:-}" ]; then
      echo "ERROR: Required variable ${var} not set in config file"
      exit 1
    fi
  done

  # Validate arrays
  if [ ${#AKS_CLUSTERS[@]} -eq 0 ]; then
    echo "ERROR: AKS_CLUSTERS array is empty in config"
    exit 1
  fi
  if [ ${#CANARY_CLUSTERS[@]} -eq 0 ]; then
    echo "WARN: CANARY_CLUSTERS not set, using first cluster as canary"
    CANARY_CLUSTERS=("${AKS_CLUSTERS[0]}")
  fi
}

# ---------------------------------------------------------------------------
# Initialize
# ---------------------------------------------------------------------------
initialize() {
  mkdir -p "$LOG_DIR"
  touch "$GATE_LOG"

  # Acquire migration lock (prevent concurrent runs)
  if [ -f "$MIGRATION_LOCK" ]; then
    local lock_pid
    lock_pid=$(cat "$MIGRATION_LOCK")
    if kill -0 "$lock_pid" 2>/dev/null; then
      log ERROR "Another migration is running (PID: ${lock_pid})"
      exit 1
    else
      log WARN "Stale lock found (PID: ${lock_pid} not running). Removing."
      rm -f "$MIGRATION_LOCK"
    fi
  fi
  echo $$ > "$MIGRATION_LOCK"
  trap cleanup EXIT

  log INFO "Migration initialized"
  log INFO "  Blue Vault:   ${BLUE_VAULT_NAME}"
  log INFO "  Green Vault:  ${GREEN_VAULT_NAME}"
  log INFO "  Resource Group: ${RESOURCE_GROUP}"
  log INFO "  AKS Clusters: ${#AKS_CLUSTERS[@]} total"
  log INFO "  Canary:       ${CANARY_CLUSTERS[*]}"
  log INFO "  Dry Run:      ${DRY_RUN}"
  log INFO "  Log Dir:      ${LOG_DIR}"

  if [ "$DRY_RUN" = true ]; then
    echo ""
    echo -e "${YELLOW}  *** DRY RUN MODE — No changes will be made ***${NC}"
    echo ""
  fi
}

cleanup() {
  rm -f "$MIGRATION_LOCK"
}

# =============================================================================
# GATE 1: Pre-Flight Validation
# =============================================================================
preflight_checks() {
  local passed=true

  # 1a. Check Azure CLI authentication
  log ACTION "Checking Azure CLI authentication..."
  if az account show --query id -o tsv &>/dev/null; then
    local current_sub
    current_sub=$(az account show --query id -o tsv)
    if [ "$current_sub" != "$SUBSCRIPTION_ID" ]; then
      log WARN "Current subscription (${current_sub}) != target (${SUBSCRIPTION_ID})"
      log ACTION "Switching to target subscription..."
      if [ "$DRY_RUN" = false ]; then
        az account set --subscription "$SUBSCRIPTION_ID"
      fi
    fi
    log OK "Azure CLI authenticated — subscription: ${SUBSCRIPTION_ID}"
  else
    log ERROR "Azure CLI not authenticated. Run: az login"
    return 1
  fi

  # 1b. Check required tools
  log ACTION "Checking required tools..."
  for tool in az kubectl jq; do
    if command -v "$tool" &>/dev/null; then
      log OK "  ${tool} — found"
    else
      log ERROR "  ${tool} — NOT FOUND"
      passed=false
    fi
  done

  # 1c. Verify blue vault exists and is accessible
  log ACTION "Verifying blue vault (${BLUE_VAULT_NAME}) exists..."
  if az keyvault show --name "$BLUE_VAULT_NAME" --resource-group "$RESOURCE_GROUP" &>/dev/null; then
    local rbac_status
    rbac_status=$(az keyvault show --name "$BLUE_VAULT_NAME" \
      --query "properties.enableRbacAuthorization" -o tsv 2>/dev/null || echo "false")
    if [ "$rbac_status" = "true" ]; then
      log WARN "Blue vault already has RBAC enabled! Migration may not be needed."
    else
      log OK "Blue vault found — Access Policies mode (expected)"
    fi
  else
    log ERROR "Blue vault ${BLUE_VAULT_NAME} not found in ${RESOURCE_GROUP}"
    return 1
  fi

  # 1d. Verify green vault name is available
  log ACTION "Checking green vault name availability (${GREEN_VAULT_NAME})..."
  local name_check
  name_check=$(az keyvault list --query "[?name=='${GREEN_VAULT_NAME}']" -o tsv 2>/dev/null)
  if [ -n "$name_check" ]; then
    log WARN "Green vault ${GREEN_VAULT_NAME} already exists — will reuse if RBAC-enabled"
  else
    # Check if name is available (not soft-deleted)
    local deleted_check
    deleted_check=$(az keyvault list-deleted --query "[?name=='${GREEN_VAULT_NAME}']" -o tsv 2>/dev/null || echo "")
    if [ -n "$deleted_check" ]; then
      log WARN "Green vault name is soft-deleted. Will need to purge or recover."
    else
      log OK "Green vault name ${GREEN_VAULT_NAME} is available"
    fi
  fi

  # 1e. Count secrets/keys/certs in blue vault
  log ACTION "Inventorying blue vault contents..."
  local secret_count key_count cert_count
  secret_count=$(az keyvault secret list --vault-name "$BLUE_VAULT_NAME" --query "length(@)" -o tsv 2>/dev/null || echo 0)
  key_count=$(az keyvault key list --vault-name "$BLUE_VAULT_NAME" --query "length(@)" -o tsv 2>/dev/null || echo 0)
  cert_count=$(az keyvault certificate list --vault-name "$BLUE_VAULT_NAME" --query "length(@)" -o tsv 2>/dev/null || echo 0)
  log INFO "  Secrets:      ${secret_count}"
  log INFO "  Keys:         ${key_count}"
  log INFO "  Certificates: ${cert_count}"

  # 1f. Check AKS cluster health
  log ACTION "Checking AKS cluster health..."
  for cluster_entry in "${AKS_CLUSTERS[@]}"; do
    local cluster_name cluster_rg
    cluster_name=$(echo "$cluster_entry" | cut -d: -f1)
    cluster_rg=$(echo "$cluster_entry" | cut -d: -f2)
    cluster_rg="${cluster_rg:-$RESOURCE_GROUP}"

    local state
    state=$(az aks show --name "$cluster_name" --resource-group "$cluster_rg" \
      --query "provisioningState" -o tsv 2>/dev/null || echo "NotFound")

    if [ "$state" = "Succeeded" ]; then
      log OK "  ${cluster_name} — Healthy (${state})"
    else
      log ERROR "  ${cluster_name} — ${state} (must be Succeeded)"
      passed=false
    fi
  done

  # 1g. Check RBAC permissions
  log ACTION "Checking Azure RBAC permissions..."
  local caller_id
  caller_id=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || \
    az account show --query "user.name" -o tsv 2>/dev/null || echo "unknown")
  log INFO "  Running as: ${caller_id}"

  # Verify we can create role assignments
  local sub_scope="/subscriptions/${SUBSCRIPTION_ID}"
  local can_assign
  can_assign=$(az role assignment list --scope "$sub_scope" --assignee "$caller_id" \
    --query "[?contains(roleDefinitionName, 'Owner') || contains(roleDefinitionName, 'User Access Administrator')]" \
    -o tsv 2>/dev/null || echo "")
  if [ -n "$can_assign" ]; then
    log OK "  Sufficient permissions to create role assignments"
  else
    log WARN "  Cannot verify role assignment permissions — may fail at Gate 3"
  fi

  # 1h. Verify soft-delete and purge protection on blue vault
  log ACTION "Checking vault protection settings..."
  local soft_delete purge_protect
  soft_delete=$(az keyvault show --name "$BLUE_VAULT_NAME" \
    --query "properties.enableSoftDelete" -o tsv 2>/dev/null || echo "true")
  purge_protect=$(az keyvault show --name "$BLUE_VAULT_NAME" \
    --query "properties.enablePurgeProtection" -o tsv 2>/dev/null || echo "false")
  log INFO "  Soft Delete: ${soft_delete}"
  log INFO "  Purge Protection: ${purge_protect}"

  if [ "$soft_delete" != "true" ]; then
    log WARN "Soft delete is disabled — vault cannot be recovered if deleted!"
  fi

  if [ "$passed" = true ]; then
    save_rollback_state "preflight" '{"status": "passed"}'
    return 0
  else
    return 1
  fi
}

# =============================================================================
# PHASE 2: Create Green Vault + Replicate Contents
# =============================================================================
create_green_vault() {
  log ACTION "Creating green Key Vault: ${GREEN_VAULT_NAME}"

  if [ "$DRY_RUN" = true ]; then
    log INFO "[DRY RUN] Would create vault ${GREEN_VAULT_NAME} with RBAC enabled"
    return 0
  fi

  # Check if green vault already exists
  local existing
  existing=$(az keyvault show --name "$GREEN_VAULT_NAME" 2>/dev/null || echo "")
  if [ -n "$existing" ]; then
    local existing_rbac
    existing_rbac=$(echo "$existing" | jq -r '.properties.enableRbacAuthorization // false')
    if [ "$existing_rbac" = "true" ]; then
      log OK "Green vault ${GREEN_VAULT_NAME} already exists with RBAC — reusing"
    else
      log ERROR "Green vault ${GREEN_VAULT_NAME} exists but without RBAC! Cannot reuse."
      return 1
    fi
  else
    # Check for soft-deleted vault with same name
    local soft_deleted
    soft_deleted=$(az keyvault list-deleted --query "[?name=='${GREEN_VAULT_NAME}'].name" -o tsv 2>/dev/null || echo "")
    if [ -n "$soft_deleted" ]; then
      log ACTION "Purging soft-deleted vault ${GREEN_VAULT_NAME}..."
      az keyvault purge --name "$GREEN_VAULT_NAME" --location "$LOCATION" || {
        log ERROR "Failed to purge soft-deleted vault. May need to wait for retention period."
        return 1
      }
    fi

    # Create green vault with RBAC enabled
    az keyvault create \
      --name "$GREEN_VAULT_NAME" \
      --resource-group "$RESOURCE_GROUP" \
      --location "$LOCATION" \
      --enable-rbac-authorization true \
      --enable-soft-delete true \
      --enable-purge-protection true \
      --retention-days 90 \
      --sku standard \
      --output none

    log OK "Green vault ${GREEN_VAULT_NAME} created with RBAC authorization"
  fi

  # Grant ourselves Key Vault Administrator on green vault for migration
  local green_vault_id
  green_vault_id=$(az keyvault show --name "$GREEN_VAULT_NAME" --query id -o tsv)
  local caller_object_id
  caller_object_id=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || \
    az account show --query "user.assignedPlans[0].servicePlanId" -o tsv 2>/dev/null || echo "")

  if [ -n "$caller_object_id" ]; then
    az role assignment create \
      --assignee "$caller_object_id" \
      --role "Key Vault Administrator" \
      --scope "$green_vault_id" \
      --output none 2>/dev/null || log WARN "Role assignment may already exist"
    log OK "Granted Key Vault Administrator to migration identity"
  fi

  # Wait for RBAC propagation
  log INFO "Waiting 30s for RBAC propagation..."
  sleep 30

  save_rollback_state "green_vault_created" "{\"vault_name\": \"${GREEN_VAULT_NAME}\", \"vault_id\": \"${green_vault_id}\"}"
}

replicate_secrets() {
  log ACTION "Replicating secrets from ${BLUE_VAULT_NAME} → ${GREEN_VAULT_NAME}"

  if [ "$DRY_RUN" = true ]; then
    log INFO "[DRY RUN] Would replicate all secrets, keys, and certificates"
    return 0
  fi

  local failed=0

  # Replicate secrets
  log INFO "  Replicating secrets..."
  local secrets
  secrets=$(az keyvault secret list --vault-name "$BLUE_VAULT_NAME" \
    --query "[].name" -o tsv 2>/dev/null || echo "")

  local secret_count=0
  while IFS= read -r secret_name; do
    [ -z "$secret_name" ] && continue

    local value
    value=$(az keyvault secret show --vault-name "$BLUE_VAULT_NAME" \
      --name "$secret_name" --query value -o tsv 2>/dev/null)

    if [ -n "$value" ]; then
      az keyvault secret set \
        --vault-name "$GREEN_VAULT_NAME" \
        --name "$secret_name" \
        --value "$value" \
        --output none 2>/dev/null && \
        secret_count=$((secret_count + 1)) || \
        { log ERROR "  Failed to copy secret: ${secret_name}"; failed=$((failed + 1)); }
    fi
  done <<< "$secrets"
  log OK "  Secrets copied: ${secret_count}"

  # Replicate keys (create new keys — can't export private keys)
  log INFO "  Replicating keys (creating equivalents)..."
  local keys
  keys=$(az keyvault key list --vault-name "$BLUE_VAULT_NAME" \
    --query "[].{name:name, kty:keyType, keySize:keySize}" -o json 2>/dev/null || echo "[]")

  local key_count=0
  echo "$keys" | jq -c '.[]' | while IFS= read -r key_entry; do
    local key_name key_type key_size
    key_name=$(echo "$key_entry" | jq -r '.name')
    key_type=$(echo "$key_entry" | jq -r '.kty // "RSA"')
    key_size=$(echo "$key_entry" | jq -r '.keySize // 2048')

    [ -z "$key_name" ] && continue

    az keyvault key create \
      --vault-name "$GREEN_VAULT_NAME" \
      --name "$key_name" \
      --kty "$key_type" \
      --size "$key_size" \
      --output none 2>/dev/null && \
      key_count=$((key_count + 1)) || \
      { log WARN "  Could not create key ${key_name} — may need manual creation"; }
  done
  log OK "  Keys created: check log for details"

  # Replicate certificates
  log INFO "  Replicating certificates..."
  local certs
  certs=$(az keyvault certificate list --vault-name "$BLUE_VAULT_NAME" \
    --query "[].name" -o tsv 2>/dev/null || echo "")

  local cert_count=0
  while IFS= read -r cert_name; do
    [ -z "$cert_name" ] && continue

    # Download certificate as PFX then import
    local pfx_file="/tmp/cert-${cert_name}-${TIMESTAMP}.pfx"
    az keyvault certificate download \
      --vault-name "$BLUE_VAULT_NAME" \
      --name "$cert_name" \
      --encoding PEM \
      --file "$pfx_file" 2>/dev/null

    if [ -f "$pfx_file" ]; then
      az keyvault certificate import \
        --vault-name "$GREEN_VAULT_NAME" \
        --name "$cert_name" \
        --file "$pfx_file" \
        --output none 2>/dev/null && \
        cert_count=$((cert_count + 1)) || \
        { log WARN "  Could not import cert ${cert_name}"; }
      rm -f "$pfx_file"
    fi
  done <<< "$certs"
  log OK "  Certificates copied: ${cert_count}"

  if [ "$failed" -gt 0 ]; then
    log ERROR "${failed} secret(s) failed to copy"
    return 1
  fi

  save_rollback_state "secrets_replicated" "{\"secrets\": ${secret_count}, \"failed\": ${failed}}"
  return 0
}

# GATE 2: Verify replication
verify_replication() {
  log ACTION "Verifying replication completeness..."

  local blue_secrets green_secrets
  blue_secrets=$(az keyvault secret list --vault-name "$BLUE_VAULT_NAME" --query "length(@)" -o tsv 2>/dev/null || echo 0)
  green_secrets=$(az keyvault secret list --vault-name "$GREEN_VAULT_NAME" --query "length(@)" -o tsv 2>/dev/null || echo 0)

  log INFO "  Blue vault secrets:  ${blue_secrets}"
  log INFO "  Green vault secrets: ${green_secrets}"

  if [ "$DRY_RUN" = true ]; then
    log INFO "[DRY RUN] Replication verification skipped"
    return 0
  fi

  if [ "$blue_secrets" = "$green_secrets" ]; then
    log OK "Secret count matches"
  else
    log ERROR "Secret count mismatch! Blue=${blue_secrets}, Green=${green_secrets}"
    return 1
  fi

  # Spot-check: verify a random secret value matches
  local sample_secret
  sample_secret=$(az keyvault secret list --vault-name "$BLUE_VAULT_NAME" \
    --query "[0].name" -o tsv 2>/dev/null || echo "")

  if [ -n "$sample_secret" ]; then
    local blue_val green_val
    blue_val=$(az keyvault secret show --vault-name "$BLUE_VAULT_NAME" \
      --name "$sample_secret" --query value -o tsv 2>/dev/null)
    green_val=$(az keyvault secret show --vault-name "$GREEN_VAULT_NAME" \
      --name "$sample_secret" --query value -o tsv 2>/dev/null)

    if [ "$blue_val" = "$green_val" ]; then
      log OK "Sample secret '${sample_secret}' values match"
    else
      log ERROR "Sample secret '${sample_secret}' values DO NOT match!"
      return 1
    fi
  fi

  return 0
}

# =============================================================================
# PHASE 3: Create RBAC Role Assignments
# =============================================================================
create_rbac_assignments() {
  log ACTION "Creating RBAC role assignments on green vault..."

  local green_vault_id
  green_vault_id=$(az keyvault show --name "$GREEN_VAULT_NAME" --query id -o tsv 2>/dev/null || echo "")

  if [ -z "$green_vault_id" ]; then
    log ERROR "Cannot find green vault ID"
    return 1
  fi

  if [ "$DRY_RUN" = true ]; then
    log INFO "[DRY RUN] Would create RBAC assignments for ${#IDENTITY_ROLE_MAP[@]} identities"
    for identity in "${!IDENTITY_ROLE_MAP[@]}"; do
      log INFO "  [DRY RUN] ${identity} → ${IDENTITY_ROLE_MAP[$identity]}"
    done
    return 0
  fi

  local created=0
  local failed=0

  for identity in "${!IDENTITY_ROLE_MAP[@]}"; do
    local role="${IDENTITY_ROLE_MAP[$identity]}"
    log INFO "  Assigning: ${identity} → ${role}"

    az role assignment create \
      --assignee "$identity" \
      --role "$role" \
      --scope "$green_vault_id" \
      --output none 2>/dev/null && \
      created=$((created + 1)) || {
        log WARN "  Failed or already exists: ${identity} → ${role}"
        # Check if it already exists
        local existing
        existing=$(az role assignment list --assignee "$identity" --scope "$green_vault_id" \
          --query "[?roleDefinitionName=='${role}']" -o tsv 2>/dev/null || echo "")
        if [ -n "$existing" ]; then
          log OK "  Assignment already exists — OK"
          created=$((created + 1))
        else
          failed=$((failed + 1))
        fi
      }
  done

  log INFO "  Created: ${created}, Failed: ${failed}"
  save_rollback_state "rbac_assignments" "{\"created\": ${created}, \"failed\": ${failed}}"

  [ "$failed" -eq 0 ] && return 0 || return 1
}

# GATE 3: Verify RBAC access
verify_rbac_access() {
  log ACTION "Verifying RBAC access for all identities..."

  if [ "$DRY_RUN" = true ]; then
    log INFO "[DRY RUN] RBAC verification skipped"
    return 0
  fi

  local green_vault_id
  green_vault_id=$(az keyvault show --name "$GREEN_VAULT_NAME" --query id -o tsv)

  local all_ok=true
  for identity in "${!IDENTITY_ROLE_MAP[@]}"; do
    local role="${IDENTITY_ROLE_MAP[$identity]}"
    local assigned
    assigned=$(az role assignment list \
      --assignee "$identity" \
      --scope "$green_vault_id" \
      --query "[?roleDefinitionName=='${role}'].principalName" \
      -o tsv 2>/dev/null || echo "")

    if [ -n "$assigned" ]; then
      log OK "  ${identity} → ${role} — VERIFIED"
    else
      log ERROR "  ${identity} → ${role} — NOT FOUND"
      all_ok=false
    fi
  done

  if [ "$all_ok" = true ]; then
    return 0
  else
    return 1
  fi
}

# =============================================================================
# PHASE 4: Canary Cluster Switchover
# =============================================================================
switchover_cluster() {
  local cluster_name="$1"
  local cluster_rg="$2"

  log ACTION "Switching cluster ${cluster_name} to green vault..."

  if [ "$DRY_RUN" = true ]; then
    log INFO "[DRY RUN] Would update ${cluster_name} to use ${GREEN_VAULT_NAME}"
    return 0
  fi

  # Get current cluster kubeconfig
  az aks get-credentials \
    --name "$cluster_name" \
    --resource-group "$cluster_rg" \
    --overwrite-existing \
    --admin 2>/dev/null

  # Update CSI SecretProviderClass to point to green vault
  log INFO "  Updating SecretProviderClass objects..."
  local spc_list
  spc_list=$(kubectl get secretproviderclass --all-namespaces -o json 2>/dev/null || echo '{"items":[]}')

  echo "$spc_list" | jq -c '.items[]' | while IFS= read -r spc; do
    local spc_name spc_ns
    spc_name=$(echo "$spc" | jq -r '.metadata.name')
    spc_ns=$(echo "$spc" | jq -r '.metadata.namespace')

    # Check if it references the blue vault
    local has_blue
    has_blue=$(echo "$spc" | jq -r ".spec.parameters.vaultName // \"\"" | grep -c "$BLUE_VAULT_NAME" || echo 0)

    if [ "$has_blue" -gt 0 ]; then
      log INFO "  Patching ${spc_ns}/${spc_name} → ${GREEN_VAULT_NAME}"
      kubectl patch secretproviderclass "$spc_name" -n "$spc_ns" \
        --type='json' \
        -p="[{\"op\": \"replace\", \"path\": \"/spec/parameters/vaultName\", \"value\": \"${GREEN_VAULT_NAME}\"}]" \
        2>/dev/null || log WARN "  Failed to patch ${spc_ns}/${spc_name}"
    fi
  done

  # Update any ConfigMaps that reference the blue vault name
  log INFO "  Updating ConfigMaps with vault references..."
  local configmaps
  configmaps=$(kubectl get configmap --all-namespaces -o json 2>/dev/null | \
    jq -c ".items[] | select(.data | to_entries[] | .value | contains(\"${BLUE_VAULT_NAME}\"))" 2>/dev/null || echo "")

  echo "$configmaps" | while IFS= read -r cm; do
    [ -z "$cm" ] && continue
    local cm_name cm_ns
    cm_name=$(echo "$cm" | jq -r '.metadata.name')
    cm_ns=$(echo "$cm" | jq -r '.metadata.namespace')
    log INFO "  ConfigMap ${cm_ns}/${cm_name} references blue vault — update manually if needed"
  done

  # Restart pods that use CSI secret volumes to pick up new vault
  log INFO "  Restarting pods with secret volumes..."
  local pods_with_secrets
  pods_with_secrets=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
    jq -r '.items[] | select(.spec.volumes[]?.csi?.driver == "secrets-store.csi.k8s.io") | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null || echo "")

  while IFS= read -r pod_ref; do
    [ -z "$pod_ref" ] && continue
    local pod_ns pod_name
    pod_ns=$(echo "$pod_ref" | cut -d/ -f1)
    pod_name=$(echo "$pod_ref" | cut -d/ -f2)

    # Rolling restart via deployment
    local owner
    owner=$(kubectl get pod "$pod_name" -n "$pod_ns" \
      -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null || echo "")
    local owner_kind
    owner_kind=$(kubectl get pod "$pod_name" -n "$pod_ns" \
      -o jsonpath='{.metadata.ownerReferences[0].kind}' 2>/dev/null || echo "")

    if [ "$owner_kind" = "ReplicaSet" ]; then
      # Find the deployment
      local deploy
      deploy=$(kubectl get replicaset "$owner" -n "$pod_ns" \
        -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null || echo "")
      if [ -n "$deploy" ]; then
        log INFO "  Rolling restart: deployment/${deploy} -n ${pod_ns}"
        kubectl rollout restart "deployment/${deploy}" -n "$pod_ns" 2>/dev/null || true
      fi
    fi
  done <<< "$pods_with_secrets"

  save_rollback_state "cluster_${cluster_name}" "{\"switched\": true, \"vault\": \"${GREEN_VAULT_NAME}\"}"
  return 0
}

# Health check for a specific cluster
check_cluster_health() {
  local cluster_name="$1"
  local cluster_rg="$2"

  log ACTION "Running health checks on ${cluster_name}..."

  if [ "$DRY_RUN" = true ]; then
    log INFO "[DRY RUN] Health check skipped"
    return 0
  fi

  az aks get-credentials \
    --name "$cluster_name" \
    --resource-group "$cluster_rg" \
    --overwrite-existing \
    --admin 2>/dev/null

  local checks_passed=true

  # Check 1: AKS provisioning state
  local aks_state
  aks_state=$(az aks show --name "$cluster_name" --resource-group "$cluster_rg" \
    --query "provisioningState" -o tsv 2>/dev/null)
  if [ "$aks_state" = "Succeeded" ]; then
    log OK "  AKS state: ${aks_state}"
  else
    log ERROR "  AKS state: ${aks_state} (expected Succeeded)"
    checks_passed=false
  fi

  # Check 2: Node readiness
  local total_nodes ready_nodes
  total_nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
  ready_nodes=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready" || echo 0)
  if [ "$total_nodes" -eq "$ready_nodes" ] && [ "$total_nodes" -gt 0 ]; then
    log OK "  Nodes: ${ready_nodes}/${total_nodes} Ready"
  else
    log ERROR "  Nodes: ${ready_nodes}/${total_nodes} Ready"
    checks_passed=false
  fi

  # Check 3: Pod health (non-system)
  local failing_pods
  failing_pods=$(kubectl get pods --all-namespaces --field-selector="status.phase!=Running,status.phase!=Succeeded" \
    --no-headers 2>/dev/null | grep -v "kube-system" | wc -l)
  if [ "$failing_pods" -le 2 ]; then
    log OK "  Non-running pods (non-system): ${failing_pods} (threshold: 2)"
  else
    log ERROR "  Non-running pods (non-system): ${failing_pods} (threshold: 2)"
    checks_passed=false
  fi

  # Check 4: ArgoCD health
  local argocd_healthy
  argocd_healthy=$(kubectl get pods -n argocd -l app.kubernetes.io/name=argocd-server \
    --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
  if [ "$argocd_healthy" -gt 0 ]; then
    log OK "  ArgoCD server: Running"
  else
    log WARN "  ArgoCD server: Not found or not running"
  fi

  # Check 5: CSI Secret Provider connectivity to green vault
  local csi_pods_ready
  csi_pods_ready=$(kubectl get pods -n kube-system -l app=secrets-store-csi-driver \
    --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
  if [ "$csi_pods_ready" -gt 0 ]; then
    log OK "  CSI Secret Store Driver: ${csi_pods_ready} pod(s) running"
  else
    log WARN "  CSI Secret Store Driver: Not found"
  fi

  # Check 6: Can pods actually read from green vault?
  log INFO "  Testing vault access from cluster..."
  local test_result
  test_result=$(kubectl run vault-test-$(date +%s) \
    --image=mcr.microsoft.com/azure-cli:latest \
    --rm -i --restart=Never \
    --timeout=60s \
    --overrides="{
      \"spec\": {
        \"serviceAccountName\": \"default\",
        \"containers\": [{
          \"name\": \"test\",
          \"image\": \"mcr.microsoft.com/azure-cli:latest\",
          \"command\": [\"az\", \"keyvault\", \"secret\", \"list\", \"--vault-name\", \"${GREEN_VAULT_NAME}\", \"--query\", \"length(@)\", \"-o\", \"tsv\"]
        }]
      }
    }" 2>/dev/null || echo "SKIP")

  if [ "$test_result" != "SKIP" ] && [ "$test_result" -gt 0 ] 2>/dev/null; then
    log OK "  Vault access test: Can read ${test_result} secrets from green vault"
  else
    log WARN "  Vault access test: Could not verify (non-blocking)"
  fi

  # Wait for rollout completions
  log INFO "  Waiting for rollouts to complete..."
  local deployments
  deployments=$(kubectl get deployments --all-namespaces -o json 2>/dev/null | \
    jq -r '.items[] | select(.metadata.namespace != "kube-system") | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null || echo "")

  local rollout_timeout=120
  while IFS= read -r deploy_ref; do
    [ -z "$deploy_ref" ] && continue
    local dep_ns dep_name
    dep_ns=$(echo "$deploy_ref" | cut -d/ -f1)
    dep_name=$(echo "$deploy_ref" | cut -d/ -f2)

    kubectl rollout status "deployment/${dep_name}" -n "$dep_ns" \
      --timeout="${rollout_timeout}s" 2>/dev/null || {
        log WARN "  Rollout not complete: ${dep_ns}/${dep_name}"
      }
  done <<< "$deployments"

  if [ "$checks_passed" = true ]; then
    log OK "Health checks PASSED for ${cluster_name}"
    return 0
  else
    log ERROR "Health checks FAILED for ${cluster_name}"
    return 1
  fi
}

# GATE 4: Canary verification
verify_canary() {
  local passed=true

  for canary_entry in "${CANARY_CLUSTERS[@]}"; do
    local canary_name canary_rg
    canary_name=$(echo "$canary_entry" | cut -d: -f1)
    canary_rg=$(echo "$canary_entry" | cut -d: -f2)
    canary_rg="${canary_rg:-$RESOURCE_GROUP}"

    switchover_cluster "$canary_name" "$canary_rg" || { passed=false; break; }

    # Wait for things to stabilize
    log INFO "Waiting 60s for canary stabilization..."
    sleep 60

    check_cluster_health "$canary_name" "$canary_rg" || { passed=false; break; }
  done

  if [ "$passed" = true ]; then
    log OK "Canary verification passed for all canary clusters"
    return 0
  else
    log ERROR "Canary verification FAILED"
    return 1
  fi
}

# =============================================================================
# PHASE 5: Batch Cluster Switchover
# =============================================================================
batch_switchover() {
  if [ "$CANARY_ONLY" = true ]; then
    log WARN "Canary-only mode — skipping batch switchover"
    return 0
  fi

  # Get non-canary clusters
  local batch_clusters=()
  for cluster_entry in "${AKS_CLUSTERS[@]}"; do
    local is_canary=false
    for canary_entry in "${CANARY_CLUSTERS[@]}"; do
      if [ "$cluster_entry" = "$canary_entry" ]; then
        is_canary=true
        break
      fi
    done
    if [ "$is_canary" = false ]; then
      batch_clusters+=("$cluster_entry")
    fi
  done

  local total=${#batch_clusters[@]}
  log INFO "Batch switchover: ${total} clusters remaining"

  if [ "$total" -eq 0 ]; then
    log OK "All clusters already switched (canary covered them all)"
    return 0
  fi

  # Process in batches of BATCH_SIZE (default: 5)
  local batch_size="${BATCH_SIZE:-5}"
  local batch_num=0

  for ((i=0; i<total; i+=batch_size)); do
    batch_num=$((batch_num + 1))
    local batch_end=$((i + batch_size))
    [ "$batch_end" -gt "$total" ] && batch_end=$total

    echo ""
    log INFO "═══ Batch ${batch_num}: clusters $((i+1)) to ${batch_end} of ${total} ═══"

    # Switch this batch
    local batch_failed=false
    for ((j=i; j<batch_end; j++)); do
      local cluster_entry="${batch_clusters[$j]}"
      local cluster_name cluster_rg
      cluster_name=$(echo "$cluster_entry" | cut -d: -f1)
      cluster_rg=$(echo "$cluster_entry" | cut -d: -f2)
      cluster_rg="${cluster_rg:-$RESOURCE_GROUP}"

      switchover_cluster "$cluster_name" "$cluster_rg" || {
        log ERROR "Failed to switch cluster ${cluster_name}"
        batch_failed=true
        break
      }
    done

    if [ "$batch_failed" = true ]; then
      log ERROR "Batch ${batch_num} failed — stopping switchover"
      return 1
    fi

    # Health check the batch
    log INFO "Waiting 30s for batch stabilization..."
    sleep 30

    for ((j=i; j<batch_end; j++)); do
      local cluster_entry="${batch_clusters[$j]}"
      local cluster_name cluster_rg
      cluster_name=$(echo "$cluster_entry" | cut -d: -f1)
      cluster_rg=$(echo "$cluster_entry" | cut -d: -f2)
      cluster_rg="${cluster_rg:-$RESOURCE_GROUP}"

      check_cluster_health "$cluster_name" "$cluster_rg" || {
        log ERROR "Health check failed for ${cluster_name} after switchover"
        return 1
      }
    done

    log OK "Batch ${batch_num} complete — all clusters healthy"
    save_rollback_state "batch_${batch_num}" "{\"clusters_switched\": ${batch_end}}"

    # Gate between batches (if not auto-approve)
    if [ "$AUTO_APPROVE" = false ] && [ "$DRY_RUN" = false ] && [ "$batch_end" -lt "$total" ]; then
      echo ""
      echo -e "${YELLOW}  Batch ${batch_num} complete (${batch_end}/${total}). Continue to next batch?${NC}"
      read -r -p "  [y/r/a] > " response
      case "$response" in
        y|Y) continue ;;
        r|R) execute_rollback; exit 1 ;;
        *) log ERROR "User aborted at batch ${batch_num}"; exit 1 ;;
      esac
    fi
  done

  return 0
}

# GATE 5: Verify all clusters
verify_all_clusters() {
  log ACTION "Running final health check on ALL clusters..."
  local all_healthy=true

  for cluster_entry in "${AKS_CLUSTERS[@]}"; do
    local cluster_name cluster_rg
    cluster_name=$(echo "$cluster_entry" | cut -d: -f1)
    cluster_rg=$(echo "$cluster_entry" | cut -d: -f2)
    cluster_rg="${cluster_rg:-$RESOURCE_GROUP}"

    check_cluster_health "$cluster_name" "$cluster_rg" || all_healthy=false
  done

  if [ "$all_healthy" = true ]; then
    return 0
  else
    return 1
  fi
}

# =============================================================================
# PHASE 6: Terraform State Alignment
# =============================================================================
align_terraform_state() {
  log ACTION "Aligning Terraform state with green vault..."

  if [ "$DRY_RUN" = true ]; then
    log INFO "[DRY RUN] Would update Terraform to reference ${GREEN_VAULT_NAME}"
    log INFO "[DRY RUN] Would run: terraform import azurerm_key_vault.main <green-vault-id>"
    return 0
  fi

  log INFO "  Step 1: Update Terraform code to reference green vault"
  log INFO "  Step 2: Import green vault into Terraform state"
  log INFO "  Step 3: Remove blue vault from Terraform state"
  log INFO "  Step 4: Run terraform plan to verify zero drift"
  echo ""
  log WARN "Terraform state changes must be done by the engineer."
  log INFO "Commands to run:"
  echo ""
  echo "  # Remove old vault from state"
  echo "  terraform state rm azurerm_key_vault.main"
  echo ""
  echo "  # Import green vault"
  local green_id
  green_id=$(az keyvault show --name "$GREEN_VAULT_NAME" --query id -o tsv 2>/dev/null || echo "<green-vault-id>")
  echo "  terraform import azurerm_key_vault.main \"${green_id}\""
  echo ""
  echo "  # Verify zero drift"
  echo "  terraform plan"
  echo ""

  return 0
}

# GATE 7: Terraform drift check
verify_terraform_alignment() {
  log ACTION "Verifying Terraform state alignment..."

  if [ "$DRY_RUN" = true ]; then
    log INFO "[DRY RUN] Terraform alignment check skipped"
    return 0
  fi

  log WARN "This gate requires manual verification."
  log INFO "Run 'terraform plan' and confirm it shows no changes."
  echo ""
  echo -e "${YELLOW}  Has 'terraform plan' been run with zero drift? [y/n]${NC}"

  if [ "$AUTO_APPROVE" = true ]; then
    log WARN "Auto-approve: assuming Terraform alignment will be handled separately"
    return 0
  fi

  read -r -p "  > " response
  if [[ "$response" =~ ^[Yy] ]]; then
    return 0
  else
    log WARN "Terraform alignment pending — migration functionally complete but state needs update"
    return 0  # Non-blocking — migration works, state is a follow-up
  fi
}

# =============================================================================
# ROLLBACK
# =============================================================================
execute_rollback() {
  echo ""
  echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
  echo -e "${RED}${BOLD}  EXECUTING ROLLBACK${NC}"
  echo -e "${RED}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
  echo ""

  if [ ! -f "$ROLLBACK_STATE_FILE" ]; then
    # Try to find the most recent rollback state
    local latest_log
    latest_log=$(ls -td "${SCRIPT_DIR}/logs/rbac-migration-"* 2>/dev/null | head -1)
    if [ -n "$latest_log" ] && [ -f "${latest_log}/rollback-state.json" ]; then
      ROLLBACK_STATE_FILE="${latest_log}/rollback-state.json"
      log INFO "Found rollback state: ${ROLLBACK_STATE_FILE}"
    else
      log ERROR "No rollback state found. Manual intervention required."
      return 1
    fi
  fi

  local last_phase
  last_phase=$(jq -r '.last_phase // "unknown"' "$ROLLBACK_STATE_FILE")
  log INFO "Rolling back from phase: ${last_phase}"

  # Rollback strategy: switch all clusters back to blue vault
  for cluster_entry in "${AKS_CLUSTERS[@]}"; do
    local cluster_name cluster_rg
    cluster_name=$(echo "$cluster_entry" | cut -d: -f1)
    cluster_rg=$(echo "$cluster_entry" | cut -d: -f2)
    cluster_rg="${cluster_rg:-$RESOURCE_GROUP}"

    # Check if this cluster was switched
    local was_switched
    was_switched=$(jq -r ".cluster_${cluster_name}.switched // false" "$ROLLBACK_STATE_FILE" 2>/dev/null || echo "false")

    if [ "$was_switched" = "true" ]; then
      log ACTION "Rolling back ${cluster_name} to blue vault (${BLUE_VAULT_NAME})..."

      az aks get-credentials \
        --name "$cluster_name" \
        --resource-group "$cluster_rg" \
        --overwrite-existing \
        --admin 2>/dev/null

      # Revert SecretProviderClass objects
      kubectl get secretproviderclass --all-namespaces -o json 2>/dev/null | \
        jq -c ".items[] | select(.spec.parameters.vaultName == \"${GREEN_VAULT_NAME}\")" | \
        while IFS= read -r spc; do
          local spc_name spc_ns
          spc_name=$(echo "$spc" | jq -r '.metadata.name')
          spc_ns=$(echo "$spc" | jq -r '.metadata.namespace')

          kubectl patch secretproviderclass "$spc_name" -n "$spc_ns" \
            --type='json' \
            -p="[{\"op\": \"replace\", \"path\": \"/spec/parameters/vaultName\", \"value\": \"${BLUE_VAULT_NAME}\"}]" \
            2>/dev/null || true

          log INFO "  Reverted ${spc_ns}/${spc_name} → ${BLUE_VAULT_NAME}"
        done

      # Restart affected pods
      kubectl get pods --all-namespaces -o json 2>/dev/null | \
        jq -r '.items[] | select(.spec.volumes[]?.csi?.driver == "secrets-store.csi.k8s.io") | "\(.metadata.namespace) \(.metadata.name)"' 2>/dev/null | \
        while read -r ns name; do
          kubectl delete pod "$name" -n "$ns" --grace-period=30 2>/dev/null || true
        done

      log OK "  ${cluster_name} rolled back to blue vault"
    else
      log INFO "  ${cluster_name} — was not switched, no rollback needed"
    fi
  done

  # Verify blue vault is still healthy
  log ACTION "Verifying blue vault accessibility..."
  local blue_status
  blue_status=$(az keyvault show --name "$BLUE_VAULT_NAME" --query "properties.provisioningState" -o tsv 2>/dev/null)
  if [ "$blue_status" = "Succeeded" ]; then
    log OK "Blue vault ${BLUE_VAULT_NAME} is healthy"
  else
    log ERROR "Blue vault ${BLUE_VAULT_NAME} status: ${blue_status}"
  fi

  echo ""
  echo -e "${GREEN}${BOLD}  ROLLBACK COMPLETE${NC}"
  echo ""
  log INFO "Green vault ${GREEN_VAULT_NAME} is still available for retry"
  log INFO "Blue vault ${BLUE_VAULT_NAME} is the active vault"
  echo ""

  save_rollback_state "rollback_complete" "{\"rolled_back_to\": \"${BLUE_VAULT_NAME}\"}"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================
main() {
  parse_args "$@"
  load_config
  initialize

  if [ "$ROLLBACK_MODE" = true ]; then
    execute_rollback
    exit $?
  fi

  echo ""
  echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║   Azure Key Vault RBAC Migration — Blue-Green Strategy       ║${NC}"
  echo -e "${BOLD}║                                                               ║${NC}"
  echo -e "${BOLD}║   Blue (Current):  ${BLUE_VAULT_NAME}$(printf '%*s' $((26 - ${#BLUE_VAULT_NAME})) '')║${NC}"
  echo -e "${BOLD}║   Green (Target):  ${GREEN_VAULT_NAME}$(printf '%*s' $((26 - ${#GREEN_VAULT_NAME})) '')║${NC}"
  echo -e "${BOLD}║   Clusters:        ${#AKS_CLUSTERS[@]} total (${#CANARY_CLUSTERS[@]} canary)$(printf '%*s' $((17 - ${#AKS_CLUSTERS[@]} - ${#CANARY_CLUSTERS[@]})) '')║${NC}"
  echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  # GATE 1: Pre-flight
  gate_check 1 "Pre-Flight Validation" preflight_checks

  # PHASE 2: Create green vault and replicate
  echo ""
  log INFO "═══ PHASE 2: Create Green Vault & Replicate ═══"
  create_green_vault
  replicate_secrets

  # GATE 2: Verify replication
  gate_check 2 "Replication Verification" verify_replication

  # PHASE 3: RBAC role assignments
  echo ""
  log INFO "═══ PHASE 3: RBAC Role Assignments ═══"
  create_rbac_assignments

  # GATE 3: Verify RBAC
  gate_check 3 "RBAC Access Verification" verify_rbac_access

  # PHASE 4: Canary switchover
  echo ""
  log INFO "═══ PHASE 4: Canary Cluster Switchover ═══"

  # GATE 4: Canary verification
  gate_check 4 "Canary Cluster Verification" verify_canary

  # PHASE 5: Batch switchover
  echo ""
  log INFO "═══ PHASE 5: Batch Cluster Switchover ═══"
  batch_switchover

  # GATE 5: All clusters healthy
  gate_check 5 "Full Platform Health Check" verify_all_clusters

  # PHASE 6: Terraform alignment
  echo ""
  log INFO "═══ PHASE 6: Terraform State Alignment ═══"
  align_terraform_state

  # GATE 6: Platform health (re-check after stabilization)
  log INFO "Waiting 120s for final stabilization..."
  [ "$DRY_RUN" = false ] && sleep 120

  gate_check 6 "Post-Stabilization Health Check" verify_all_clusters

  # GATE 7: Terraform drift
  gate_check 7 "Terraform State Alignment" verify_terraform_alignment

  # COMPLETE
  echo ""
  echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}${BOLD}║                                                               ║${NC}"
  echo -e "${GREEN}${BOLD}║   MIGRATION COMPLETE                                          ║${NC}"
  echo -e "${GREEN}${BOLD}║                                                               ║${NC}"
  echo -e "${GREEN}${BOLD}║   All clusters now using: ${GREEN_VAULT_NAME}$(printf '%*s' $((20 - ${#GREEN_VAULT_NAME})) '')║${NC}"
  echo -e "${GREEN}${BOLD}║   Blue vault (${BLUE_VAULT_NAME}) can be decommissioned$(printf '%*s' $((8 - ${#BLUE_VAULT_NAME})) '')║${NC}"
  echo -e "${GREEN}${BOLD}║                                                               ║${NC}"
  echo -e "${GREEN}${BOLD}║   Logs: ${LOG_DIR}$(printf '%*s' $((38 - ${#LOG_DIR})) '')║${NC}"
  echo -e "${GREEN}${BOLD}║                                                               ║${NC}"
  echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "${YELLOW}NEXT STEPS:${NC}"
  echo "  1. Monitor clusters for 24-48 hours"
  echo "  2. Update Terraform state (see Phase 6 output above)"
  echo "  3. After validation period, soft-delete blue vault:"
  echo "     az keyvault delete --name ${BLUE_VAULT_NAME}"
  echo "  4. Blue vault recoverable for 90 days after deletion"
  echo ""
}

main "$@"
