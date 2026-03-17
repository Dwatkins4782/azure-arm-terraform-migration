#!/bin/bash
# =============================================================================
# AKS Kubernetes Upgrade — Blue-Green with Gates & Rollback
#
# PURPOSE:
#   Safely upgrades AKS clusters to a new Kubernetes version using a
#   blue-green node pool strategy. Instead of upgrading nodes in-place
#   (which can leave the cluster in a mixed-version state if something
#   fails), this script:
#
#   1. Creates NEW node pools on the target K8s version (GREEN)
#   2. Cordons and drains OLD node pools (BLUE)
#   3. Validates workloads are healthy on GREEN pools
#   4. Removes BLUE pools after validation
#   5. Rolls back by uncordoning BLUE pools if anything fails
#
# STRATEGY:
#   ┌──────────────────────────────────────────────────────────────┐
#   │  BEFORE                          AFTER (success)            │
#   │  ┌──────────┐                    ┌──────────┐               │
#   │  │ BLUE     │ ← running pods     │ GREEN    │ ← running    │
#   │  │ v1.28    │                    │ v1.29    │   pods        │
#   │  └──────────┘                    └──────────┘               │
#   │                                                              │
#   │  AFTER (rollback)                                            │
#   │  ┌──────────┐                                                │
#   │  │ BLUE     │ ← pods restored                                │
#   │  │ v1.28    │   (uncordoned)                                 │
#   │  └──────────┘                                                │
#   └──────────────────────────────────────────────────────────────┘
#
# GATES (6 mandatory checkpoints):
#   Gate 1: Pre-flight — K8s version compatibility, cluster health, PDB check
#   Gate 2: Control plane upgraded — API server on target version
#   Gate 3: Green node pools ready — new nodes joined and Ready
#   Gate 4: Workload migration — all pods rescheduled on green pools
#   Gate 5: Application health — endpoints responding, ArgoCD synced
#   Gate 6: Blue pool removal — old pools deleted (final, after soak)
#
# USAGE:
#   ./aks-upgrade.sh --config upgrade-config.env
#   ./aks-upgrade.sh --config upgrade-config.env --dry-run
#   ./aks-upgrade.sh --config upgrade-config.env --rollback
#   ./aks-upgrade.sh --config upgrade-config.env --control-plane-only
#   ./aks-upgrade.sh --config upgrade-config.env --skip-to-gate 3
#
# REQUIREMENTS:
#   - Azure CLI >= 2.55.0 with aks-preview extension
#   - kubectl configured with cluster access
#   - jq >= 1.6
#   - Sufficient Azure RBAC (Contributor on the AKS resource)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="${SCRIPT_DIR}/logs/aks-upgrade-${TIMESTAMP}"
ROLLBACK_STATE_FILE="${LOG_DIR}/rollback-state.json"
GATE_LOG="${LOG_DIR}/gates.log"
UPGRADE_LOCK="/tmp/aks-upgrade.lock"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
BOLD='\033[1m'

# ---------------------------------------------------------------------------
# Configuration Defaults
# ---------------------------------------------------------------------------
DRY_RUN=false
ROLLBACK_MODE=false
CONTROL_PLANE_ONLY=false
SKIP_TO_GATE=0
AUTO_APPROVE=false
CONFIG_FILE=""

# Cluster settings
CLUSTER_NAME=""
CLUSTER_RG=""
SUBSCRIPTION_ID=""
TARGET_K8S_VERSION=""

# Node pool settings
declare -a NODE_POOLS=()          # Existing pools to upgrade
SURGE_MAX_PERCENT=33              # Max surge for node creation (%)
DRAIN_TIMEOUT=300                 # Pod eviction timeout (seconds)
SOAK_PERIOD=600                   # Time to wait before removing blue pools
POD_DISRUPTION_BUDGET_CHECK=true  # Respect PDBs during drain

# Health check settings
HEALTH_CHECK_RETRIES=5
HEALTH_CHECK_INTERVAL=30

# ---------------------------------------------------------------------------
# Logging (shared with rbac-migration.sh pattern)
# ---------------------------------------------------------------------------
log() {
  local level="$1"; shift
  local msg="$*"
  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
  case "$level" in
    INFO)    echo -e "${CYAN}[${ts}] [INFO]${NC}  $msg" ;;
    OK)      echo -e "${GREEN}[${ts}] [  OK]${NC}  $msg" ;;
    WARN)    echo -e "${YELLOW}[${ts}] [WARN]${NC}  $msg" ;;
    ERROR)   echo -e "${RED}[${ts}] [FAIL]${NC}  $msg" ;;
    GATE)    echo -e "${BOLD}${BLUE}[${ts}] [GATE]${NC}  $msg" ;;
    ACTION)  echo -e "${BOLD}[${ts}] [ >> ]${NC}  $msg" ;;
  esac
  echo "[${ts}] [${level}] $msg" >> "${LOG_DIR}/upgrade.log" 2>/dev/null || true
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
    return 0
  fi

  if $check_function; then
    log OK "Gate ${gate_num} PASSED: ${gate_name}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Gate ${gate_num}: PASSED — ${gate_name}" >> "$GATE_LOG"

    if [ "$AUTO_APPROVE" = false ] && [ "$DRY_RUN" = false ]; then
      echo ""
      echo -e "${YELLOW}  Gate ${gate_num} passed. Proceed? [y]es / [r]ollback / [a]bort${NC}"
      read -r -p "  > " response
      case "$response" in
        y|Y|yes) ;;
        r|R) execute_rollback; exit 0 ;;
        *) log ERROR "User aborted at Gate ${gate_num}"; exit 1 ;;
      esac
    fi
    return 0
  else
    log ERROR "Gate ${gate_num} FAILED: ${gate_name}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Gate ${gate_num}: FAILED — ${gate_name}" >> "$GATE_LOG"

    echo ""
    echo -e "${RED}  Gate ${gate_num} FAILED. [r]ollback / [s]kip (dangerous) / [a]bort${NC}"

    if [ "$AUTO_APPROVE" = true ]; then
      log WARN "Auto-approve mode: triggering automatic rollback"
      execute_rollback
      exit 1
    fi

    read -r -p "  > " response
    case "$response" in
      r|R) execute_rollback; exit 1 ;;
      s|S) log WARN "Skipping failed Gate ${gate_num}"; return 0 ;;
      *) exit 1 ;;
    esac
  fi
}

save_state() {
  local phase="$1"; local data="$2"
  if [ -f "$ROLLBACK_STATE_FILE" ]; then
    local current; current=$(cat "$ROLLBACK_STATE_FILE")
    echo "$current" | jq --arg p "$phase" --argjson d "$data" \
      '. + {($p): $d, "last_phase": $p}' > "$ROLLBACK_STATE_FILE"
  else
    echo "{}" | jq --arg p "$phase" --argjson d "$data" \
      '. + {($p): $d, "last_phase": $p}' > "$ROLLBACK_STATE_FILE"
  fi
}

# ---------------------------------------------------------------------------
# Parse Arguments
# ---------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)              CONFIG_FILE="$2"; shift 2 ;;
      --dry-run)             DRY_RUN=true; shift ;;
      --rollback)            ROLLBACK_MODE=true; shift ;;
      --control-plane-only)  CONTROL_PLANE_ONLY=true; shift ;;
      --skip-to-gate)        SKIP_TO_GATE="$2"; shift 2 ;;
      --auto-approve)        AUTO_APPROVE=true; shift ;;
      --help|-h)             show_help; exit 0 ;;
      *)                     echo "Unknown option: $1"; exit 1 ;;
    esac
  done
}

show_help() {
  cat <<'HELP'
AKS Kubernetes Upgrade — Blue-Green Node Pool Strategy

USAGE:
  ./aks-upgrade.sh --config <config-file> [OPTIONS]

OPTIONS:
  --config <file>          Upgrade configuration file (required)
  --dry-run                Simulate all steps without making changes
  --rollback               Rollback: uncordon blue pools, delete green pools
  --control-plane-only     Only upgrade the control plane, skip node pools
  --skip-to-gate <N>       Skip to gate N (for recovery)
  --auto-approve           Skip interactive confirmations
  --help                   Show this help message

EXAMPLES:
  # Dry run
  ./aks-upgrade.sh --config upgrade-config.env --dry-run

  # Full upgrade with interactive gates
  ./aks-upgrade.sh --config upgrade-config.env

  # Control plane only (node pools done separately)
  ./aks-upgrade.sh --config upgrade-config.env --control-plane-only

  # Rollback to previous version
  ./aks-upgrade.sh --config upgrade-config.env --rollback
HELP
}

load_config() {
  if [ -z "$CONFIG_FILE" ]; then
    echo "ERROR: --config is required"; show_help; exit 1
  fi
  if [ ! -f "$CONFIG_FILE" ]; then
    echo "ERROR: Config file not found: $CONFIG_FILE"; exit 1
  fi
  # shellcheck source=/dev/null
  source "$CONFIG_FILE"

  for var in CLUSTER_NAME CLUSTER_RG SUBSCRIPTION_ID TARGET_K8S_VERSION; do
    if [ -z "${!var:-}" ]; then
      echo "ERROR: Required variable ${var} not set in config"; exit 1
    fi
  done
}

initialize() {
  mkdir -p "$LOG_DIR"
  touch "$GATE_LOG"

  if [ -f "$UPGRADE_LOCK" ]; then
    local lock_pid; lock_pid=$(cat "$UPGRADE_LOCK")
    if kill -0 "$lock_pid" 2>/dev/null; then
      log ERROR "Another upgrade is running (PID: ${lock_pid})"; exit 1
    fi
    rm -f "$UPGRADE_LOCK"
  fi
  echo $$ > "$UPGRADE_LOCK"
  trap 'rm -f "$UPGRADE_LOCK"' EXIT

  az account set --subscription "$SUBSCRIPTION_ID" 2>/dev/null

  log INFO "AKS Upgrade initialized"
  log INFO "  Cluster:     ${CLUSTER_NAME} (${CLUSTER_RG})"
  log INFO "  Target K8s:  ${TARGET_K8S_VERSION}"
  log INFO "  Node Pools:  ${#NODE_POOLS[@]}"
  log INFO "  Dry Run:     ${DRY_RUN}"
  log INFO "  Log Dir:     ${LOG_DIR}"
}

# =============================================================================
# GATE 1: Pre-Flight Validation
# =============================================================================
preflight_checks() {
  local passed=true

  # 1a. Azure auth
  log ACTION "Checking Azure CLI authentication..."
  if az account show &>/dev/null; then
    log OK "Azure CLI authenticated"
  else
    log ERROR "Azure CLI not authenticated"; return 1
  fi

  # 1b. Tools check
  for tool in az kubectl jq; do
    if command -v "$tool" &>/dev/null; then
      log OK "  ${tool} found"
    else
      log ERROR "  ${tool} NOT FOUND"; passed=false
    fi
  done

  # 1c. Cluster exists and is healthy
  log ACTION "Checking cluster ${CLUSTER_NAME}..."
  local cluster_info
  cluster_info=$(az aks show --name "$CLUSTER_NAME" --resource-group "$CLUSTER_RG" -o json 2>/dev/null)
  if [ -z "$cluster_info" ]; then
    log ERROR "Cluster ${CLUSTER_NAME} not found"; return 1
  fi

  local current_version prov_state
  current_version=$(echo "$cluster_info" | jq -r '.kubernetesVersion')
  prov_state=$(echo "$cluster_info" | jq -r '.provisioningState')

  log INFO "  Current version: ${current_version}"
  log INFO "  Target version:  ${TARGET_K8S_VERSION}"
  log INFO "  Provisioning:    ${prov_state}"

  if [ "$prov_state" != "Succeeded" ]; then
    log ERROR "Cluster provisioning state is ${prov_state} (must be Succeeded)"
    passed=false
  fi

  # 1d. Target version is available
  log ACTION "Checking target version availability..."
  local available_versions
  available_versions=$(az aks get-upgrades \
    --name "$CLUSTER_NAME" \
    --resource-group "$CLUSTER_RG" \
    --query "controlPlaneProfile.upgrades[].kubernetesVersion" \
    -o tsv 2>/dev/null || echo "")

  if echo "$available_versions" | grep -q "$TARGET_K8S_VERSION"; then
    log OK "  Target version ${TARGET_K8S_VERSION} is available for upgrade"
  else
    # Check if already on target version
    if [ "$current_version" = "$TARGET_K8S_VERSION" ]; then
      log WARN "  Cluster is already on ${TARGET_K8S_VERSION}"
    else
      log ERROR "  Target version ${TARGET_K8S_VERSION} is NOT available"
      log INFO "  Available versions: ${available_versions}"
      passed=false
    fi
  fi

  # 1e. Version skip check (can't skip minor versions)
  local current_minor target_minor
  current_minor=$(echo "$current_version" | cut -d. -f2)
  target_minor=$(echo "$TARGET_K8S_VERSION" | cut -d. -f2)
  local version_gap=$((target_minor - current_minor))

  if [ "$version_gap" -gt 1 ]; then
    log ERROR "Cannot skip minor versions! Current: ${current_version}, Target: ${TARGET_K8S_VERSION}"
    log ERROR "  Version gap: ${version_gap} (max 1). Upgrade incrementally."
    passed=false
  elif [ "$version_gap" -lt 0 ]; then
    log ERROR "Target version ${TARGET_K8S_VERSION} is OLDER than current ${current_version}"
    passed=false
  fi

  # 1f. Node pool inventory
  log ACTION "Inventorying node pools..."
  local pool_info
  pool_info=$(az aks nodepool list --cluster-name "$CLUSTER_NAME" \
    --resource-group "$CLUSTER_RG" -o json 2>/dev/null)

  echo "$pool_info" | jq -r '.[] | "\(.name)\t\(.provisioningState)\t\(.count)\t\(.orchestratorVersion)\t\(.mode)"' | \
    while IFS=$'\t' read -r name state count version mode; do
      local status_icon="✅"
      [ "$state" != "Succeeded" ] && status_icon="❌"
      log INFO "  ${status_icon} ${name}: ${count} nodes, v${version}, ${mode} mode, ${state}"
    done

  if [ ${#NODE_POOLS[@]} -eq 0 ]; then
    log INFO "  NODE_POOLS not specified — will discover from cluster"
    while IFS= read -r pool; do
      [ -n "$pool" ] && NODE_POOLS+=("$pool")
    done < <(echo "$pool_info" | jq -r '.[].name')
    log INFO "  Discovered ${#NODE_POOLS[@]} node pools"
  fi

  # 1g. Get kubectl context
  az aks get-credentials --name "$CLUSTER_NAME" --resource-group "$CLUSTER_RG" \
    --overwrite-existing --admin 2>/dev/null

  # 1h. Check for PodDisruptionBudgets that might block draining
  log ACTION "Checking PodDisruptionBudgets..."
  local pdb_list
  pdb_list=$(kubectl get pdb --all-namespaces -o json 2>/dev/null || echo '{"items":[]}')
  local pdb_count
  pdb_count=$(echo "$pdb_list" | jq '.items | length')

  if [ "$pdb_count" -gt 0 ]; then
    log INFO "  Found ${pdb_count} PodDisruptionBudgets:"
    echo "$pdb_list" | jq -r '.items[] | "    \(.metadata.namespace)/\(.metadata.name): minAvailable=\(.spec.minAvailable // "N/A"), maxUnavailable=\(.spec.maxUnavailable // "N/A")"' | head -20
  else
    log INFO "  No PodDisruptionBudgets found"
  fi

  # 1i. Check for pods without owners (won't be rescheduled)
  log ACTION "Checking for unmanaged pods..."
  local orphan_pods
  orphan_pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
    jq -r '.items[] | select(.metadata.ownerReferences == null or (.metadata.ownerReferences | length) == 0) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null || echo "")

  local orphan_count
  orphan_count=$(echo "$orphan_pods" | grep -c . || echo 0)
  if [ "$orphan_count" -gt 0 ]; then
    log WARN "  Found ${orphan_count} unmanaged pods (won't auto-reschedule):"
    echo "$orphan_pods" | head -10 | while IFS= read -r p; do
      log WARN "    ${p}"
    done
  else
    log OK "  All pods are managed by controllers"
  fi

  # 1j. Snapshot current state for rollback
  log ACTION "Saving pre-upgrade state snapshot..."
  local snapshot
  snapshot=$(jq -n \
    --arg cluster "$CLUSTER_NAME" \
    --arg version "$current_version" \
    --arg target "$TARGET_K8S_VERSION" \
    --argjson pools "$(echo "$pool_info" | jq '[.[] | {name, count, vmSize, orchestratorVersion, mode, osDiskSizeGB, maxPods, enableAutoScaling, minCount, maxCount, nodeLabels, nodeTaints}]')" \
    '{cluster: $cluster, original_version: $version, target_version: $target, original_pools: $pools}')

  save_state "preflight" "$snapshot"

  if [ "$passed" = true ]; then
    return 0
  else
    return 1
  fi
}

# =============================================================================
# PHASE 2: Upgrade Control Plane
# =============================================================================
upgrade_control_plane() {
  local current_version
  current_version=$(az aks show --name "$CLUSTER_NAME" --resource-group "$CLUSTER_RG" \
    --query kubernetesVersion -o tsv 2>/dev/null)

  if [ "$current_version" = "$TARGET_K8S_VERSION" ]; then
    log OK "Control plane already on ${TARGET_K8S_VERSION}"
    return 0
  fi

  log ACTION "Upgrading control plane: ${current_version} → ${TARGET_K8S_VERSION}"

  if [ "$DRY_RUN" = true ]; then
    log INFO "[DRY RUN] Would upgrade control plane to ${TARGET_K8S_VERSION}"
    return 0
  fi

  # Upgrade control plane only (--control-plane-only flag)
  az aks upgrade \
    --name "$CLUSTER_NAME" \
    --resource-group "$CLUSTER_RG" \
    --kubernetes-version "$TARGET_K8S_VERSION" \
    --control-plane-only \
    --yes \
    --output none 2>&1 | tee -a "${LOG_DIR}/control-plane-upgrade.log"

  local exit_code=${PIPESTATUS[0]}
  if [ "$exit_code" -ne 0 ]; then
    log ERROR "Control plane upgrade failed (exit code: ${exit_code})"
    return 1
  fi

  # Wait for control plane to stabilize
  log INFO "Waiting for control plane to stabilize (60s)..."
  sleep 60

  save_state "control_plane" "{\"version\": \"${TARGET_K8S_VERSION}\"}"
  return 0
}

# GATE 2: Verify control plane
verify_control_plane() {
  log ACTION "Verifying control plane upgrade..."

  if [ "$DRY_RUN" = true ]; then
    log INFO "[DRY RUN] Control plane verification skipped"; return 0
  fi

  local cp_version
  cp_version=$(az aks show --name "$CLUSTER_NAME" --resource-group "$CLUSTER_RG" \
    --query kubernetesVersion -o tsv 2>/dev/null)

  if [ "$cp_version" = "$TARGET_K8S_VERSION" ]; then
    log OK "Control plane version: ${cp_version}"
  else
    log ERROR "Control plane version mismatch: ${cp_version} (expected ${TARGET_K8S_VERSION})"
    return 1
  fi

  # Check API server responsiveness
  if kubectl get nodes &>/dev/null; then
    log OK "API server is responsive"
  else
    log ERROR "API server not responding"
    return 1
  fi

  # Check cluster provisioning state
  local state
  state=$(az aks show --name "$CLUSTER_NAME" --resource-group "$CLUSTER_RG" \
    --query provisioningState -o tsv 2>/dev/null)
  if [ "$state" = "Succeeded" ]; then
    log OK "Cluster provisioning state: ${state}"
  else
    log ERROR "Cluster provisioning state: ${state}"
    return 1
  fi

  return 0
}

# =============================================================================
# PHASE 3: Create Green Node Pools
# =============================================================================
create_green_pools() {
  if [ "$CONTROL_PLANE_ONLY" = true ]; then
    log WARN "Control-plane-only mode — skipping green pool creation"
    return 0
  fi

  log ACTION "Creating green (target version) node pools..."

  # Get current pool configurations
  local pool_info
  pool_info=$(az aks nodepool list --cluster-name "$CLUSTER_NAME" \
    --resource-group "$CLUSTER_RG" -o json 2>/dev/null)

  for pool_name in "${NODE_POOLS[@]}"; do
    local pool_config
    pool_config=$(echo "$pool_info" | jq -r ".[] | select(.name == \"${pool_name}\")")

    if [ -z "$pool_config" ]; then
      log ERROR "Pool ${pool_name} not found in cluster"
      continue
    fi

    local pool_version
    pool_version=$(echo "$pool_config" | jq -r '.orchestratorVersion')

    if [ "$pool_version" = "$TARGET_K8S_VERSION" ]; then
      log OK "Pool ${pool_name} already on ${TARGET_K8S_VERSION} — skipping"
      continue
    fi

    # Extract pool configuration
    local vm_size node_count mode max_pods os_disk_size
    local autoscale min_count max_count os_type
    vm_size=$(echo "$pool_config" | jq -r '.vmSize')
    node_count=$(echo "$pool_config" | jq -r '.count')
    mode=$(echo "$pool_config" | jq -r '.mode')
    max_pods=$(echo "$pool_config" | jq -r '.maxPods // 110')
    os_disk_size=$(echo "$pool_config" | jq -r '.osDiskSizeGB // 128')
    autoscale=$(echo "$pool_config" | jq -r '.enableAutoScaling // false')
    min_count=$(echo "$pool_config" | jq -r '.minCount // 1')
    max_count=$(echo "$pool_config" | jq -r '.maxCount // 3')
    os_type=$(echo "$pool_config" | jq -r '.osType // "Linux"')

    # Green pool name: append "g" (must be <=12 chars for AKS)
    local green_name="${pool_name}g"
    if [ ${#green_name} -gt 12 ]; then
      green_name=$(echo "$pool_name" | cut -c1-11)"g"
    fi

    log ACTION "Creating green pool: ${green_name} (from ${pool_name})"
    log INFO "  VM Size:     ${vm_size}"
    log INFO "  Node Count:  ${node_count}"
    log INFO "  Mode:        ${mode}"
    log INFO "  K8s Version: ${TARGET_K8S_VERSION}"
    log INFO "  Autoscale:   ${autoscale} (${min_count}-${max_count})"

    if [ "$DRY_RUN" = true ]; then
      log INFO "[DRY RUN] Would create pool ${green_name}"
      continue
    fi

    # Build the create command
    local create_cmd="az aks nodepool add \
      --cluster-name ${CLUSTER_NAME} \
      --resource-group ${CLUSTER_RG} \
      --name ${green_name} \
      --kubernetes-version ${TARGET_K8S_VERSION} \
      --node-vm-size ${vm_size} \
      --node-count ${node_count} \
      --mode ${mode} \
      --max-pods ${max_pods} \
      --os-disk-size-gb ${os_disk_size} \
      --os-type ${os_type} \
      --output none"

    # Add autoscaling if enabled
    if [ "$autoscale" = "true" ]; then
      create_cmd+=" --enable-cluster-autoscaler --min-count ${min_count} --max-count ${max_count}"
    fi

    # Copy labels from old pool
    local labels
    labels=$(echo "$pool_config" | jq -r '.nodeLabels // {} | to_entries | map("\(.key)=\(.value)") | join(" ")' 2>/dev/null || echo "")
    if [ -n "$labels" ]; then
      create_cmd+=" --labels ${labels}"
    fi

    # Copy taints from old pool
    local taints
    taints=$(echo "$pool_config" | jq -r '.nodeTaints // [] | join(" ")' 2>/dev/null || echo "")
    if [ -n "$taints" ]; then
      create_cmd+=" --node-taints ${taints}"
    fi

    # Execute
    eval "$create_cmd" 2>&1 | tee -a "${LOG_DIR}/pool-${green_name}.log"
    local exit_code=${PIPESTATUS[0]}

    if [ "$exit_code" -eq 0 ]; then
      log OK "Green pool ${green_name} created"
      save_state "green_pool_${green_name}" "{\"name\": \"${green_name}\", \"source\": \"${pool_name}\", \"version\": \"${TARGET_K8S_VERSION}\"}"
    else
      log ERROR "Failed to create green pool ${green_name}"
      return 1
    fi
  done

  return 0
}

# GATE 3: Verify green pools
verify_green_pools() {
  log ACTION "Verifying green node pools..."

  if [ "$DRY_RUN" = true ] || [ "$CONTROL_PLANE_ONLY" = true ]; then
    log INFO "[DRY RUN/CP-ONLY] Green pool verification skipped"; return 0
  fi

  local all_ready=true

  for pool_name in "${NODE_POOLS[@]}"; do
    local green_name="${pool_name}g"
    if [ ${#green_name} -gt 12 ]; then
      green_name=$(echo "$pool_name" | cut -c1-11)"g"
    fi

    # Check pool provisioning state
    local pool_state
    pool_state=$(az aks nodepool show --cluster-name "$CLUSTER_NAME" \
      --resource-group "$CLUSTER_RG" --name "$green_name" \
      --query provisioningState -o tsv 2>/dev/null || echo "NotFound")

    if [ "$pool_state" = "Succeeded" ]; then
      log OK "  ${green_name}: Provisioning ${pool_state}"
    elif [ "$pool_state" = "NotFound" ]; then
      # Pool might already be on target version (skipped creation)
      local orig_ver
      orig_ver=$(az aks nodepool show --cluster-name "$CLUSTER_NAME" \
        --resource-group "$CLUSTER_RG" --name "$pool_name" \
        --query orchestratorVersion -o tsv 2>/dev/null || echo "")
      if [ "$orig_ver" = "$TARGET_K8S_VERSION" ]; then
        log OK "  ${pool_name}: Already on target version (no green pool needed)"
        continue
      fi
      log ERROR "  ${green_name}: ${pool_state}"; all_ready=false
    else
      log ERROR "  ${green_name}: ${pool_state}"; all_ready=false
    fi

    # Check node readiness
    local green_nodes
    green_nodes=$(kubectl get nodes -l "agentpool=${green_name}" \
      --no-headers 2>/dev/null | wc -l)
    local green_ready
    green_ready=$(kubectl get nodes -l "agentpool=${green_name}" \
      --no-headers 2>/dev/null | grep -c " Ready" || echo 0)

    if [ "$green_nodes" -gt 0 ] && [ "$green_nodes" -eq "$green_ready" ]; then
      log OK "  ${green_name}: ${green_ready}/${green_nodes} nodes Ready"
    elif [ "$green_nodes" -gt 0 ]; then
      log ERROR "  ${green_name}: ${green_ready}/${green_nodes} nodes Ready"
      all_ready=false
    fi
  done

  if [ "$all_ready" = true ]; then
    return 0
  else
    return 1
  fi
}

# =============================================================================
# PHASE 4: Drain Blue Pools (migrate workloads to green)
# =============================================================================
drain_blue_pools() {
  if [ "$CONTROL_PLANE_ONLY" = true ]; then
    log WARN "Control-plane-only mode — skipping drain"
    return 0
  fi

  log ACTION "Cordoning and draining blue (old version) node pools..."

  for pool_name in "${NODE_POOLS[@]}"; do
    # Skip if already on target version
    local pool_version
    pool_version=$(az aks nodepool show --cluster-name "$CLUSTER_NAME" \
      --resource-group "$CLUSTER_RG" --name "$pool_name" \
      --query orchestratorVersion -o tsv 2>/dev/null || echo "")

    if [ "$pool_version" = "$TARGET_K8S_VERSION" ]; then
      log OK "Pool ${pool_name} already on target version — skipping drain"
      continue
    fi

    log ACTION "Draining pool: ${pool_name}"

    if [ "$DRY_RUN" = true ]; then
      log INFO "[DRY RUN] Would cordon and drain nodes in ${pool_name}"
      continue
    fi

    # Get nodes in this pool
    local blue_nodes
    blue_nodes=$(kubectl get nodes -l "agentpool=${pool_name}" \
      -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")

    if [ -z "$blue_nodes" ]; then
      log WARN "No nodes found for pool ${pool_name}"
      continue
    fi

    # Cordon all blue nodes first (prevent new scheduling)
    for node in $blue_nodes; do
      log INFO "  Cordoning: ${node}"
      kubectl cordon "$node" 2>/dev/null || log WARN "  Failed to cordon ${node}"
    done
    save_state "cordoned_${pool_name}" "{\"nodes\": \"${blue_nodes}\"}"

    # Drain nodes one by one
    for node in $blue_nodes; do
      log INFO "  Draining: ${node} (timeout: ${DRAIN_TIMEOUT}s)"

      local drain_cmd="kubectl drain ${node} \
        --ignore-daemonsets \
        --delete-emptydir-data \
        --timeout=${DRAIN_TIMEOUT}s \
        --grace-period=60"

      if [ "$POD_DISRUPTION_BUDGET_CHECK" = false ]; then
        drain_cmd+=" --disable-eviction"
      fi

      if eval "$drain_cmd" 2>&1 | tee -a "${LOG_DIR}/drain-${node}.log"; then
        log OK "  Drained: ${node}"
      else
        log ERROR "  Failed to drain: ${node}"
        log WARN "  Pods may be stuck due to PDB constraints"

        # Show what's blocking
        kubectl get pods --all-namespaces --field-selector="spec.nodeName=${node}" \
          --no-headers 2>/dev/null | head -10
        return 1
      fi
    done

    log OK "Pool ${pool_name} fully drained"
    save_state "drained_${pool_name}" '{"status": "drained"}'
  done

  # Wait for pods to reschedule
  log INFO "Waiting 60s for pod rescheduling..."
  sleep 60

  return 0
}

# GATE 4: Verify workload migration
verify_workload_migration() {
  log ACTION "Verifying workloads migrated to green pools..."

  if [ "$DRY_RUN" = true ] || [ "$CONTROL_PLANE_ONLY" = true ]; then
    log INFO "[DRY RUN/CP-ONLY] Workload migration verification skipped"; return 0
  fi

  local all_good=true

  # Check no pods running on blue (cordoned) nodes
  for pool_name in "${NODE_POOLS[@]}"; do
    local pool_version
    pool_version=$(az aks nodepool show --cluster-name "$CLUSTER_NAME" \
      --resource-group "$CLUSTER_RG" --name "$pool_name" \
      --query orchestratorVersion -o tsv 2>/dev/null || echo "$TARGET_K8S_VERSION")

    [ "$pool_version" = "$TARGET_K8S_VERSION" ] && continue

    local blue_nodes
    blue_nodes=$(kubectl get nodes -l "agentpool=${pool_name}" \
      -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")

    for node in $blue_nodes; do
      local running_pods
      running_pods=$(kubectl get pods --all-namespaces \
        --field-selector="spec.nodeName=${node},status.phase=Running" \
        --no-headers 2>/dev/null | grep -v "kube-system" | wc -l)

      if [ "$running_pods" -gt 0 ]; then
        log WARN "  ${node}: Still has ${running_pods} non-system pods"
        kubectl get pods --all-namespaces \
          --field-selector="spec.nodeName=${node},status.phase=Running" \
          --no-headers 2>/dev/null | grep -v "kube-system" | head -5
        all_good=false
      else
        log OK "  ${node}: All workloads evacuated"
      fi
    done
  done

  # Check that green nodes have workloads
  for pool_name in "${NODE_POOLS[@]}"; do
    local green_name="${pool_name}g"
    [ ${#green_name} -gt 12 ] && green_name=$(echo "$pool_name" | cut -c1-11)"g"

    local green_pods
    green_pods=$(kubectl get nodes -l "agentpool=${green_name}" \
      -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | \
      xargs -I{} kubectl get pods --all-namespaces \
        --field-selector="spec.nodeName={}" --no-headers 2>/dev/null | wc -l)

    if [ "${green_pods:-0}" -gt 0 ]; then
      log OK "  Green pool ${green_name}: ${green_pods} pods running"
    else
      log WARN "  Green pool ${green_name}: No pods scheduled yet"
    fi
  done

  # Check for pending/failing pods
  local pending_pods
  pending_pods=$(kubectl get pods --all-namespaces \
    --field-selector="status.phase=Pending" --no-headers 2>/dev/null | wc -l)

  if [ "$pending_pods" -gt 2 ]; then
    log WARN "  ${pending_pods} pods in Pending state"
    kubectl get pods --all-namespaces --field-selector="status.phase=Pending" \
      --no-headers 2>/dev/null | head -10
    all_good=false
  else
    log OK "  Pending pods: ${pending_pods} (threshold: 2)"
  fi

  [ "$all_good" = true ] && return 0 || return 1
}

# =============================================================================
# GATE 5: Application Health Check
# =============================================================================
verify_application_health() {
  log ACTION "Running application health checks..."

  if [ "$DRY_RUN" = true ] || [ "$CONTROL_PLANE_ONLY" = true ]; then
    log INFO "[DRY RUN/CP-ONLY] Application health check skipped"; return 0
  fi

  local all_healthy=true
  local retry=0

  while [ "$retry" -lt "$HEALTH_CHECK_RETRIES" ]; do
    all_healthy=true

    # Check 1: All deployments available
    log INFO "  Checking deployments (attempt $((retry+1))/${HEALTH_CHECK_RETRIES})..."
    local unavailable
    unavailable=$(kubectl get deployments --all-namespaces -o json 2>/dev/null | \
      jq '[.items[] | select(.status.unavailableReplicas > 0)] | length')

    if [ "${unavailable:-0}" -eq 0 ]; then
      log OK "  All deployments fully available"
    else
      log WARN "  ${unavailable} deployment(s) have unavailable replicas"
      all_healthy=false
    fi

    # Check 2: ArgoCD application sync status
    local argocd_apps
    argocd_apps=$(kubectl get applications -n argocd -o json 2>/dev/null || echo '{"items":[]}')
    local total_apps degraded_apps
    total_apps=$(echo "$argocd_apps" | jq '.items | length')
    degraded_apps=$(echo "$argocd_apps" | jq '[.items[] | select(.status.health.status != "Healthy")] | length')

    if [ "$total_apps" -gt 0 ]; then
      if [ "$degraded_apps" -eq 0 ]; then
        log OK "  ArgoCD: ${total_apps} apps, all Healthy"
      else
        log WARN "  ArgoCD: ${degraded_apps}/${total_apps} apps degraded"
        echo "$argocd_apps" | jq -r '.items[] | select(.status.health.status != "Healthy") | "    \(.metadata.name): \(.status.health.status)"' | head -10
        all_healthy=false
      fi
    fi

    # Check 3: No CrashLoopBackOff pods
    local crashloop_pods
    crashloop_pods=$(kubectl get pods --all-namespaces -o json 2>/dev/null | \
      jq -r '.items[] | select(.status.containerStatuses[]? | select(.state.waiting?.reason == "CrashLoopBackOff")) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null | wc -l)

    if [ "${crashloop_pods:-0}" -eq 0 ]; then
      log OK "  No CrashLoopBackOff pods"
    else
      log WARN "  ${crashloop_pods} pod(s) in CrashLoopBackOff"
      all_healthy=false
    fi

    # Check 4: Ingress / services responding
    log INFO "  Checking service endpoints..."
    local endpoints_ready
    endpoints_ready=$(kubectl get endpoints --all-namespaces -o json 2>/dev/null | \
      jq '[.items[] | select(.metadata.namespace != "kube-system") | select((.subsets // []) | length == 0)] | length')

    if [ "${endpoints_ready:-0}" -le 2 ]; then
      log OK "  Service endpoints: ${endpoints_ready} without backends (threshold: 2)"
    else
      log WARN "  ${endpoints_ready} services without backends"
      all_healthy=false
    fi

    if [ "$all_healthy" = true ]; then
      break
    fi

    retry=$((retry + 1))
    if [ "$retry" -lt "$HEALTH_CHECK_RETRIES" ]; then
      log INFO "  Waiting ${HEALTH_CHECK_INTERVAL}s before retry..."
      sleep "$HEALTH_CHECK_INTERVAL"
    fi
  done

  [ "$all_healthy" = true ] && return 0 || return 1
}

# =============================================================================
# PHASE 6: Remove Blue Pools (with soak period)
# =============================================================================
remove_blue_pools() {
  if [ "$CONTROL_PLANE_ONLY" = true ]; then
    log WARN "Control-plane-only mode — skipping pool removal"
    return 0
  fi

  log ACTION "Soak period before removing blue pools..."
  log INFO "  Soak period: ${SOAK_PERIOD}s ($(( SOAK_PERIOD / 60 )) minutes)"

  if [ "$DRY_RUN" = false ]; then
    local elapsed=0
    while [ "$elapsed" -lt "$SOAK_PERIOD" ]; do
      local remaining=$(( SOAK_PERIOD - elapsed ))
      echo -ne "\r  Soaking... ${remaining}s remaining  "
      sleep 30
      elapsed=$((elapsed + 30))

      # Quick health check during soak
      local failing
      failing=$(kubectl get pods --all-namespaces \
        --field-selector="status.phase!=Running,status.phase!=Succeeded" \
        --no-headers 2>/dev/null | grep -v "kube-system" | wc -l)
      if [ "$failing" -gt 5 ]; then
        echo ""
        log ERROR "Health degraded during soak period! ${failing} failing pods"
        return 1
      fi
    done
    echo ""
  fi

  log OK "Soak period complete — proceeding to remove blue pools"

  for pool_name in "${NODE_POOLS[@]}"; do
    local pool_version
    pool_version=$(az aks nodepool show --cluster-name "$CLUSTER_NAME" \
      --resource-group "$CLUSTER_RG" --name "$pool_name" \
      --query orchestratorVersion -o tsv 2>/dev/null || echo "$TARGET_K8S_VERSION")

    [ "$pool_version" = "$TARGET_K8S_VERSION" ] && continue

    local green_name="${pool_name}g"
    [ ${#green_name} -gt 12 ] && green_name=$(echo "$pool_name" | cut -c1-11)"g"

    log ACTION "Removing blue pool: ${pool_name}"

    if [ "$DRY_RUN" = true ]; then
      log INFO "[DRY RUN] Would delete pool ${pool_name} and rename ${green_name} → ${pool_name}"
      continue
    fi

    az aks nodepool delete \
      --cluster-name "$CLUSTER_NAME" \
      --resource-group "$CLUSTER_RG" \
      --name "$pool_name" \
      --yes \
      --output none 2>&1 | tee -a "${LOG_DIR}/delete-pool-${pool_name}.log"

    if [ ${PIPESTATUS[0]} -eq 0 ]; then
      log OK "Blue pool ${pool_name} deleted"
      save_state "deleted_pool_${pool_name}" '{"status": "deleted"}'
    else
      log ERROR "Failed to delete blue pool ${pool_name}"
      return 1
    fi
  done

  return 0
}

# GATE 6: Final verification after blue removal
verify_final() {
  log ACTION "Running final verification..."

  if [ "$DRY_RUN" = true ] || [ "$CONTROL_PLANE_ONLY" = true ]; then
    log INFO "[DRY RUN/CP-ONLY] Final verification skipped"; return 0
  fi

  verify_application_health || return 1

  # Verify all nodes are on target version
  log INFO "  Checking all node versions..."
  local wrong_version_nodes
  wrong_version_nodes=$(kubectl get nodes -o json 2>/dev/null | \
    jq -r ".items[] | select(.status.nodeInfo.kubeletVersion | startswith(\"v${TARGET_K8S_VERSION}\") | not) | .metadata.name" 2>/dev/null || echo "")

  if [ -z "$wrong_version_nodes" ]; then
    log OK "  All nodes running v${TARGET_K8S_VERSION}"
  else
    local count
    count=$(echo "$wrong_version_nodes" | wc -l)
    log WARN "  ${count} node(s) still on old version:"
    echo "$wrong_version_nodes" | head -5 | while IFS= read -r n; do
      log WARN "    ${n}"
    done
  fi

  return 0
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

  # Find rollback state
  if [ ! -f "$ROLLBACK_STATE_FILE" ]; then
    local latest_log
    latest_log=$(ls -td "${SCRIPT_DIR}/logs/aks-upgrade-"* 2>/dev/null | head -1)
    if [ -n "$latest_log" ] && [ -f "${latest_log}/rollback-state.json" ]; then
      ROLLBACK_STATE_FILE="${latest_log}/rollback-state.json"
    else
      log ERROR "No rollback state found"; return 1
    fi
  fi

  local state
  state=$(cat "$ROLLBACK_STATE_FILE")
  local last_phase
  last_phase=$(echo "$state" | jq -r '.last_phase // "unknown"')
  log INFO "Rolling back from phase: ${last_phase}"

  az aks get-credentials --name "$CLUSTER_NAME" --resource-group "$CLUSTER_RG" \
    --overwrite-existing --admin 2>/dev/null

  # Step 1: Uncordon blue nodes
  log ACTION "Step 1: Uncordoning blue nodes..."
  for pool_name in "${NODE_POOLS[@]}"; do
    local blue_nodes
    blue_nodes=$(kubectl get nodes -l "agentpool=${pool_name}" \
      -o jsonpath='{.items[*].metadata.name}' 2>/dev/null || echo "")

    for node in $blue_nodes; do
      local schedulable
      schedulable=$(kubectl get node "$node" \
        -o jsonpath='{.spec.unschedulable}' 2>/dev/null || echo "false")

      if [ "$schedulable" = "true" ]; then
        log INFO "  Uncordoning: ${node}"
        kubectl uncordon "$node" 2>/dev/null || log WARN "  Failed to uncordon ${node}"
      fi
    done
  done
  log OK "Blue nodes uncordoned"

  # Step 2: Delete green pools
  log ACTION "Step 2: Removing green pools..."
  for pool_name in "${NODE_POOLS[@]}"; do
    local green_name="${pool_name}g"
    [ ${#green_name} -gt 12 ] && green_name=$(echo "$pool_name" | cut -c1-11)"g"

    local green_exists
    green_exists=$(az aks nodepool show --cluster-name "$CLUSTER_NAME" \
      --resource-group "$CLUSTER_RG" --name "$green_name" \
      --query name -o tsv 2>/dev/null || echo "")

    if [ -n "$green_exists" ]; then
      log INFO "  Deleting green pool: ${green_name}"
      az aks nodepool delete \
        --cluster-name "$CLUSTER_NAME" \
        --resource-group "$CLUSTER_RG" \
        --name "$green_name" \
        --yes \
        --output none 2>/dev/null || log WARN "  Failed to delete ${green_name}"
    fi
  done
  log OK "Green pools removed"

  # Step 3: Wait for pods to reschedule back to blue
  log INFO "Waiting 90s for pods to reschedule..."
  sleep 90

  # Step 4: Verify rollback health
  log ACTION "Step 3: Verifying rollback health..."
  local total_nodes ready_nodes
  total_nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
  ready_nodes=$(kubectl get nodes --no-headers 2>/dev/null | grep -c " Ready" || echo 0)
  log INFO "  Nodes: ${ready_nodes}/${total_nodes} Ready"

  local failing_pods
  failing_pods=$(kubectl get pods --all-namespaces \
    --field-selector="status.phase!=Running,status.phase!=Succeeded" \
    --no-headers 2>/dev/null | grep -v "kube-system" | wc -l)
  log INFO "  Failing pods (non-system): ${failing_pods}"

  echo ""
  echo -e "${GREEN}${BOLD}  ROLLBACK COMPLETE${NC}"
  echo ""
  log INFO "  Cluster: ${CLUSTER_NAME}"
  log INFO "  Blue pools restored and accepting workloads"
  log INFO "  Green pools deleted"
  log WARN "  NOTE: Control plane may still be on ${TARGET_K8S_VERSION}"
  log WARN "  Control plane downgrades are NOT supported by AKS."
  log WARN "  The cluster will run with mixed versions until the next upgrade."
  echo ""
}

# =============================================================================
# MAIN
# =============================================================================
main() {
  parse_args "$@"
  load_config
  initialize

  if [ "$ROLLBACK_MODE" = true ]; then
    execute_rollback; exit $?
  fi

  echo ""
  echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${BOLD}║   AKS Kubernetes Upgrade — Blue-Green Strategy               ║${NC}"
  echo -e "${BOLD}║                                                               ║${NC}"
  echo -e "${BOLD}║   Cluster: ${CLUSTER_NAME}$(printf '%*s' $((34 - ${#CLUSTER_NAME})) '')║${NC}"
  echo -e "${BOLD}║   Target:  ${TARGET_K8S_VERSION}$(printf '%*s' $((34 - ${#TARGET_K8S_VERSION})) '')║${NC}"
  echo -e "${BOLD}║   Pools:   ${#NODE_POOLS[@]}$(printf '%*s' $((34 - ${#NODE_POOLS[@]})) '')║${NC}"
  echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
  echo ""

  # Gate 1: Pre-flight
  gate_check 1 "Pre-Flight Validation" preflight_checks

  # Phase 2: Upgrade control plane
  echo ""
  log INFO "═══ PHASE 2: Control Plane Upgrade ═══"
  upgrade_control_plane

  # Gate 2: Verify control plane
  gate_check 2 "Control Plane Verification" verify_control_plane

  if [ "$CONTROL_PLANE_ONLY" = true ]; then
    log OK "Control-plane-only mode complete. Node pool upgrade can be run separately."
    exit 0
  fi

  # Phase 3: Create green node pools
  echo ""
  log INFO "═══ PHASE 3: Create Green Node Pools ═══"
  create_green_pools

  # Gate 3: Verify green pools
  gate_check 3 "Green Node Pool Verification" verify_green_pools

  # Phase 4: Drain blue pools
  echo ""
  log INFO "═══ PHASE 4: Drain Blue Node Pools ═══"
  drain_blue_pools

  # Gate 4: Verify workload migration
  gate_check 4 "Workload Migration Verification" verify_workload_migration

  # Gate 5: Application health
  gate_check 5 "Application Health Check" verify_application_health

  # Phase 6: Remove blue pools (with soak)
  echo ""
  log INFO "═══ PHASE 6: Remove Blue Pools ═══"
  remove_blue_pools

  # Gate 6: Final verification
  gate_check 6 "Final Verification" verify_final

  # COMPLETE
  echo ""
  echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}${BOLD}║                                                               ║${NC}"
  echo -e "${GREEN}${BOLD}║   UPGRADE COMPLETE                                            ║${NC}"
  echo -e "${GREEN}${BOLD}║                                                               ║${NC}"
  echo -e "${GREEN}${BOLD}║   Cluster: ${CLUSTER_NAME}$(printf '%*s' $((34 - ${#CLUSTER_NAME})) '')║${NC}"
  echo -e "${GREEN}${BOLD}║   Version: ${TARGET_K8S_VERSION}$(printf '%*s' $((34 - ${#TARGET_K8S_VERSION})) '')║${NC}"
  echo -e "${GREEN}${BOLD}║                                                               ║${NC}"
  echo -e "${GREEN}${BOLD}║   Logs: ${LOG_DIR}$(printf '%*s' $((38 - ${#LOG_DIR})) '')║${NC}"
  echo -e "${GREEN}${BOLD}║                                                               ║${NC}"
  echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo -e "${YELLOW}POST-UPGRADE:${NC}"
  echo "  1. Monitor cluster for 24-48 hours"
  echo "  2. Update Terraform to reflect new K8s version"
  echo "  3. Update CI/CD pipelines if version is pinned"
  echo "  4. Run integration and smoke tests"
  echo "  5. Note: Green pools have 'g' suffix — rename in Terraform if needed"
  echo ""
}

main "$@"
