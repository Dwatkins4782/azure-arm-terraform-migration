#!/usr/bin/env bash
#
# aztfexport-wrapper.sh
#
# Enterprise wrapper around aztfexport (Azure Export for Terraform) that provides:
#   - Pre-flight validation of required tooling
#   - Automated export of Azure resource groups to Terraform HCL
#   - Post-processing: formatting, cleanup, mapping file generation
#   - Import command generation as a fallback mechanism
#
# Usage:
#   ./aztfexport-wrapper.sh -g <resource-group> -o <output-dir> [-s <subscription-id>] [-n] [-v]
#
# Exit codes:
#   0 - Success
#   1 - Pre-flight check failure
#   2 - Export failure
#   3 - Post-processing failure

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE=""
RESOURCE_GROUP=""
OUTPUT_DIR=""
SUBSCRIPTION_ID=""
DRY_RUN=false
VERBOSE=false

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info()  { echo "[INFO]  $(date '+%H:%M:%S') $*" | tee -a "${LOG_FILE:-/dev/null}"; }
log_warn()  { echo "[WARN]  $(date '+%H:%M:%S') $*" | tee -a "${LOG_FILE:-/dev/null}" >&2; }
log_error() { echo "[ERROR] $(date '+%H:%M:%S') $*" | tee -a "${LOG_FILE:-/dev/null}" >&2; }
log_debug() { if $VERBOSE; then echo "[DEBUG] $(date '+%H:%M:%S') $*" | tee -a "${LOG_FILE:-/dev/null}"; fi; }

# ---------------------------------------------------------------------------
# Usage / help
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $(basename "$0") -g <resource-group> -o <output-dir> [OPTIONS]

Required:
  -g    Azure resource group name to export
  -o    Output directory for generated Terraform files

Options:
  -s    Azure subscription ID (defaults to current az context)
  -n    Dry-run mode -- validate inputs but skip actual export
  -v    Verbose output (debug logging)
  -h    Show this help message

Examples:
  $(basename "$0") -g rg-prod-networking -o ./exported/networking
  $(basename "$0") -g rg-prod-database -o ./exported/database -s 00000000-0000-0000-0000-000000000000
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while getopts ":g:o:s:nvh" opt; do
    case $opt in
        g) RESOURCE_GROUP="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        s) SUBSCRIPTION_ID="$OPTARG" ;;
        n) DRY_RUN=true ;;
        v) VERBOSE=true ;;
        h) usage ;;
        :) log_error "Option -$OPTARG requires an argument."; exit 1 ;;
        *) log_error "Unknown option -$OPTARG"; usage ;;
    esac
done

# Validate required arguments
if [[ -z "$RESOURCE_GROUP" || -z "$OUTPUT_DIR" ]]; then
    log_error "Both -g (resource group) and -o (output directory) are required."
    usage
fi

# Set up logging directory and log file
mkdir -p "${OUTPUT_DIR}"
LOG_FILE="${OUTPUT_DIR}/aztfexport_${TIMESTAMP}.log"
touch "$LOG_FILE"

log_info "=== aztfexport wrapper started ==="
log_info "Resource group : $RESOURCE_GROUP"
log_info "Output dir     : $OUTPUT_DIR"
log_info "Dry-run        : $DRY_RUN"

# ---------------------------------------------------------------------------
# Pre-flight checks — ensure all required tooling is available and configured
# ---------------------------------------------------------------------------
preflight_checks() {
    log_info "--- Running pre-flight checks ---"
    local failed=false

    # 1. Check that az CLI is installed
    if ! command -v az &>/dev/null; then
        log_error "Azure CLI (az) is not installed. Install from https://aka.ms/install-azure-cli"
        failed=true
    else
        log_info "az CLI found: $(az version --output tsv 2>/dev/null | head -1)"
    fi

    # 2. Check that the user is logged in to Azure
    if ! az account show &>/dev/null; then
        log_error "Not logged in to Azure. Run 'az login' first."
        failed=true
    else
        local current_sub
        current_sub="$(az account show --query 'name' -o tsv 2>/dev/null)"
        log_info "Logged in to subscription: $current_sub"
    fi

    # 3. If a subscription was specified, set it as the active context
    if [[ -n "$SUBSCRIPTION_ID" ]]; then
        log_info "Setting active subscription to: $SUBSCRIPTION_ID"
        if ! az account set --subscription "$SUBSCRIPTION_ID"; then
            log_error "Failed to set subscription $SUBSCRIPTION_ID"
            failed=true
        fi
    fi

    # 4. Verify the target resource group exists
    if ! az group show --name "$RESOURCE_GROUP" &>/dev/null; then
        log_error "Resource group '$RESOURCE_GROUP' not found in current subscription."
        failed=true
    else
        log_info "Resource group '$RESOURCE_GROUP' confirmed."
    fi

    # 5. Check that aztfexport is installed
    if ! command -v aztfexport &>/dev/null; then
        log_error "aztfexport is not installed. Install from https://github.com/Azure/aztfexport"
        failed=true
    else
        log_info "aztfexport found: $(aztfexport --version 2>/dev/null || echo 'version unknown')"
    fi

    # 6. Check that terraform is installed
    if ! command -v terraform &>/dev/null; then
        log_error "Terraform is not installed. Install from https://www.terraform.io/downloads"
        failed=true
    else
        log_info "Terraform found: $(terraform version -json 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin)['terraform_version'])" 2>/dev/null || terraform version | head -1)"
    fi

    if $failed; then
        log_error "Pre-flight checks FAILED. Resolve the issues above and retry."
        exit 1
    fi
    log_info "Pre-flight checks PASSED."
}

# ---------------------------------------------------------------------------
# Export phase — run aztfexport against the resource group
# ---------------------------------------------------------------------------
run_export() {
    log_info "--- Starting aztfexport ---"
    local export_dir="${OUTPUT_DIR}/raw_export"
    mkdir -p "$export_dir"

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would run: aztfexport resource-group $RESOURCE_GROUP --output-dir $export_dir --non-interactive"
        return 0
    fi

    # Run aztfexport in non-interactive mode; capture stdout and stderr
    if ! aztfexport resource-group "$RESOURCE_GROUP" \
        --output-dir "$export_dir" \
        --non-interactive \
        --overwrite 2>&1 | tee -a "$LOG_FILE"; then
        log_error "aztfexport failed. Check the log at $LOG_FILE for details."
        exit 2
    fi

    log_info "aztfexport completed. Raw output in: $export_dir"
}

# ---------------------------------------------------------------------------
# Post-processing — format, clean up, and generate mapping artifacts
# ---------------------------------------------------------------------------
postprocess() {
    log_info "--- Post-processing exported files ---"
    local export_dir="${OUTPUT_DIR}/raw_export"
    local clean_dir="${OUTPUT_DIR}/terraform"
    mkdir -p "$clean_dir"

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would post-process files from $export_dir into $clean_dir"
        return 0
    fi

    # Copy exported .tf files into the clean output directory
    if ls "${export_dir}"/*.tf 1>/dev/null 2>&1; then
        cp "${export_dir}"/*.tf "$clean_dir/"
    else
        log_warn "No .tf files found in $export_dir. Export may have produced no resources."
        return 0
    fi

    # Format all Terraform files with canonical style
    log_info "Running terraform fmt on exported files..."
    terraform fmt -recursive "$clean_dir" 2>&1 | tee -a "$LOG_FILE" || true

    # Remove commonly exported default/empty values that add noise.
    # These patterns match attributes aztfexport often sets to empty or default.
    log_info "Removing default/empty attribute values..."
    for tf_file in "$clean_dir"/*.tf; do
        [[ -f "$tf_file" ]] || continue
        # Remove lines that are empty string assignments (e.g., key = "")
        sed -i '/^\s*[a-z_]*\s*=\s*""\s*$/d' "$tf_file"
        # Remove lines that are null assignments (e.g., key = null)
        sed -i '/^\s*[a-z_]*\s*=\s*null\s*$/d' "$tf_file"
    done

    # Re-format after sed edits to ensure clean HCL
    terraform fmt -recursive "$clean_dir" 2>&1 | tee -a "$LOG_FILE" || true

    log_info "Clean Terraform files written to: $clean_dir"
}

# ---------------------------------------------------------------------------
# Generate ARM-to-Terraform resource mapping CSV
# ---------------------------------------------------------------------------
generate_mapping() {
    log_info "--- Generating resource mapping file ---"
    local mapping_file="${OUTPUT_DIR}/resource_mapping_${TIMESTAMP}.csv"

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would generate mapping file at $mapping_file"
        return 0
    fi

    # CSV header
    echo "arm_resource_id,arm_resource_type,terraform_resource_type,terraform_resource_name,terraform_resource_address" \
        > "$mapping_file"

    # Query all resources in the resource group from ARM
    local arm_resources
    arm_resources="$(az resource list --resource-group "$RESOURCE_GROUP" \
        --query "[].{id:id, type:type, name:name}" -o json 2>/dev/null)"

    # For each ARM resource, attempt to find a matching Terraform resource
    # by searching the import block or resource id in the exported .tf files
    echo "$arm_resources" | python3 -c "
import json, sys, os, re, csv

arm = json.load(sys.stdin)
export_dir = '${OUTPUT_DIR}/terraform'
mapping_rows = []

# Parse terraform files for resource blocks and any import blocks
tf_resources = []
for fname in sorted(os.listdir(export_dir)):
    if not fname.endswith('.tf'):
        continue
    with open(os.path.join(export_dir, fname)) as f:
        content = f.read()
    # Match resource blocks: resource \"type\" \"name\" { ... }
    for m in re.finditer(r'resource\s+\"([^\"]+)\"\s+\"([^\"]+)\"', content):
        tf_resources.append({'type': m.group(1), 'name': m.group(2), 'file': fname})

# Build mapping by matching ARM resource type to TF resource type heuristic
for arm_res in arm:
    arm_id = arm_res['id']
    arm_type = arm_res['type']
    matched_tf = None
    for tf_res in tf_resources:
        # aztfexport names resources after their ARM name by convention
        tf_addr = f'{tf_res[\"type\"]}.{tf_res[\"name\"]}'
        if arm_res['name'].replace('-','_') in tf_res['name']:
            matched_tf = tf_res
            break
    if matched_tf:
        mapping_rows.append([arm_id, arm_type, matched_tf['type'], matched_tf['name'],
                             f\"{matched_tf['type']}.{matched_tf['name']}\"])
    else:
        mapping_rows.append([arm_id, arm_type, 'UNMATCHED', '', ''])

writer = csv.writer(sys.stdout)
for row in mapping_rows:
    writer.writerow(row)
" >> "$mapping_file" 2>>"$LOG_FILE" || log_warn "Mapping generation encountered issues; partial mapping created."

    log_info "Resource mapping written to: $mapping_file"
}

# ---------------------------------------------------------------------------
# Generate terraform import commands as a fallback / backup mechanism
# ---------------------------------------------------------------------------
generate_import_commands() {
    log_info "--- Generating import commands file ---"
    local import_file="${OUTPUT_DIR}/import_commands_${TIMESTAMP}.sh"

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would generate import commands at $import_file"
        return 0
    fi

    cat > "$import_file" <<'HEADER'
#!/usr/bin/env bash
# Auto-generated terraform import commands
# Run these if you need to re-import resources into a fresh state file.
# Generated by aztfexport-wrapper.sh
set -euo pipefail
HEADER

    # Read the mapping CSV (skip header) and produce import statements
    tail -n +2 "${OUTPUT_DIR}/resource_mapping_${TIMESTAMP}.csv" | while IFS=',' read -r arm_id arm_type tf_type tf_name tf_addr; do
        if [[ "$tf_type" != "UNMATCHED" && -n "$tf_addr" ]]; then
            echo "terraform import '${tf_addr}' '${arm_id}'"
        else
            echo "# UNMATCHED: ARM resource ${arm_id} (${arm_type}) -- manual mapping required"
        fi
    done >> "$import_file"

    chmod +x "$import_file"
    log_info "Import commands written to: $import_file"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    log_info "=== Export Summary ==="
    log_info "Resource Group  : $RESOURCE_GROUP"
    log_info "Output Dir      : $OUTPUT_DIR"
    log_info "Terraform Files : ${OUTPUT_DIR}/terraform/"
    log_info "Resource Mapping: ${OUTPUT_DIR}/resource_mapping_${TIMESTAMP}.csv"
    log_info "Import Commands : ${OUTPUT_DIR}/import_commands_${TIMESTAMP}.sh"
    log_info "Full Log        : $LOG_FILE"

    if [[ -d "${OUTPUT_DIR}/terraform" ]]; then
        local tf_count
        tf_count="$(find "${OUTPUT_DIR}/terraform" -name '*.tf' | wc -l)"
        log_info "Total .tf files : $tf_count"
    fi

    log_info "=== aztfexport wrapper finished ==="
}

# ---------------------------------------------------------------------------
# Main execution flow
# ---------------------------------------------------------------------------
main() {
    preflight_checks
    run_export
    postprocess
    generate_mapping
    generate_import_commands
    print_summary
}

main "$@"
