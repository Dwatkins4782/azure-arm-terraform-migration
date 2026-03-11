#!/usr/bin/env bash
#
# state-migration.sh
#
# Safe Terraform state operations for the ARM-to-Terraform migration.
# Provides backup, import, move, bulk-import, and rollback functions with
# safety checks that include automatic backups and plan validation after
# every mutating operation.
#
# Usage:
#   ./state-migration.sh <command> [options]
#
# Commands:
#   backup              Back up current state to a timestamped file
#   import              Import a single resource into Terraform state
#   move                Move a resource address within or between state files
#   bulk-import         Import multiple resources from a CSV manifest
#   rollback            Restore state from a previous backup
#
# Global Options:
#   -d <terraform-dir>  Working directory containing Terraform config (required)
#   -n                  Dry-run mode (no state mutations)
#   -v                  Verbose output
#
# Exit codes:
#   0 - Success
#   1 - Operation failure
#   2 - Validation failure (plan shows unexpected changes after operation)
#   3 - Usage / argument error

set -euo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
TERRAFORM_DIR=""
DRY_RUN=false
VERBOSE=false
BACKUP_DIR=""

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_info()  { echo "[INFO]  $(date '+%H:%M:%S') $*"; }
log_warn()  { echo "[WARN]  $(date '+%H:%M:%S') $*" >&2; }
log_error() { echo "[ERROR] $(date '+%H:%M:%S') $*" >&2; }
log_debug() { if $VERBOSE; then echo "[DEBUG] $(date '+%H:%M:%S') $*"; fi; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $(basename "$0") <command> -d <terraform-dir> [OPTIONS]

Commands:
  backup                          Back up current Terraform state
  import  -a <address> -i <id>    Import a single resource
  move    -a <source> -t <dest>   Move a resource between addresses
  bulk-import -f <csv-file>       Bulk import from CSV (address,resource_id)
  rollback -b <backup-file>       Restore state from a backup file

Global Options:
  -d    Terraform working directory (required for all commands)
  -n    Dry-run mode (validate but do not mutate state)
  -v    Verbose output
  -h    Show this help message

Examples:
  $(basename "$0") backup -d ./terraform
  $(basename "$0") import -d ./terraform -a 'azurerm_virtual_network.main' -i '/subscriptions/.../resourceGroups/.../providers/Microsoft.Network/virtualNetworks/vnet-main'
  $(basename "$0") move -d ./terraform -a 'azurerm_nsg.old' -t 'module.networking.azurerm_nsg.main'
  $(basename "$0") bulk-import -d ./terraform -f import_manifest.csv
  $(basename "$0") rollback -d ./terraform -b ./backups/terraform_state_20240101_120000.tfstate
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# backup_state — Downloads and backs up current state to timestamped file
# ---------------------------------------------------------------------------
backup_state() {
    log_info "--- Backing up Terraform state ---"
    BACKUP_DIR="${TERRAFORM_DIR}/state_backups"
    mkdir -p "$BACKUP_DIR"

    local backup_file="${BACKUP_DIR}/terraform_state_${TIMESTAMP}.tfstate"

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would back up state to: $backup_file"
        echo "$backup_file"
        return 0
    fi

    # Pull the current state into a local file
    (cd "$TERRAFORM_DIR" && terraform state pull) > "$backup_file" 2>/dev/null || {
        log_error "Failed to pull Terraform state. Is the backend configured and 'terraform init' run?"
        return 1
    }

    # Validate the backup is not empty
    local size
    size="$(wc -c < "$backup_file")"
    if [[ "$size" -lt 10 ]]; then
        log_error "Backup file appears empty or invalid ($size bytes)."
        rm -f "$backup_file"
        return 1
    fi

    log_info "State backed up to: $backup_file ($size bytes)"
    echo "$backup_file"
}

# ---------------------------------------------------------------------------
# validate_plan — Runs terraform plan and checks for unexpected changes.
# Returns 0 if plan is clean (no changes) or only expected import additions.
# ---------------------------------------------------------------------------
validate_plan() {
    log_info "Running terraform plan for post-operation validation..."

    local plan_output
    plan_output="$(cd "$TERRAFORM_DIR" && terraform plan -detailed-exitcode -no-color 2>&1)" || {
        local exit_code=$?
        # exit code 2 from terraform plan means changes detected
        if [[ $exit_code -eq 2 ]]; then
            log_warn "Terraform plan detected changes after state operation."
            log_warn "Review the plan output below to confirm these are expected:"
            echo "$plan_output" | tail -30
            return 2
        else
            log_error "Terraform plan failed with exit code $exit_code."
            echo "$plan_output" | tail -20
            return 1
        fi
    }

    log_info "Terraform plan shows no changes -- state is consistent."
    return 0
}

# ---------------------------------------------------------------------------
# import_resource — Import a single Azure resource into Terraform state
# Arguments: -a <terraform-address> -i <azure-resource-id>
# ---------------------------------------------------------------------------
import_resource() {
    local tf_address=""
    local resource_id=""

    # Parse subcommand-specific arguments
    while getopts ":a:i:" opt; do
        case $opt in
            a) tf_address="$OPTARG" ;;
            i) resource_id="$OPTARG" ;;
            *) ;;
        esac
    done

    if [[ -z "$tf_address" || -z "$resource_id" ]]; then
        log_error "import requires -a <terraform-address> and -i <resource-id>"
        exit 3
    fi

    log_info "--- Importing resource ---"
    log_info "  TF Address : $tf_address"
    log_info "  Resource ID: $resource_id"

    # Safety: always back up state before importing
    log_info "Creating pre-import backup..."
    local backup_file
    backup_file="$(backup_state)"

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would run: terraform import '$tf_address' '$resource_id'"
        log_info "[DRY-RUN] Would validate with terraform plan"
        return 0
    fi

    # Check that the resource address exists in the configuration
    if ! (cd "$TERRAFORM_DIR" && terraform state list 2>/dev/null | grep -qF "$tf_address"); then
        log_debug "Address '$tf_address' not yet in state (expected for import)."
    fi

    # Perform the import
    if ! (cd "$TERRAFORM_DIR" && terraform import "$tf_address" "$resource_id" 2>&1); then
        log_error "Import failed for $tf_address."
        log_error "State backup available at: $backup_file"
        return 1
    fi

    log_info "Import succeeded. Validating with plan..."
    validate_plan || {
        log_warn "Post-import plan shows changes. State backup at: $backup_file"
        return 2
    }

    log_info "Resource imported and validated successfully."
}

# ---------------------------------------------------------------------------
# move_resource — Move a resource address (rename/refactor) in state
# Arguments: -a <source-address> -t <destination-address>
# ---------------------------------------------------------------------------
move_resource() {
    local source_addr=""
    local dest_addr=""

    while getopts ":a:t:" opt; do
        case $opt in
            a) source_addr="$OPTARG" ;;
            t) dest_addr="$OPTARG" ;;
            *) ;;
        esac
    done

    if [[ -z "$source_addr" || -z "$dest_addr" ]]; then
        log_error "move requires -a <source-address> and -t <destination-address>"
        exit 3
    fi

    log_info "--- Moving resource in state ---"
    log_info "  From: $source_addr"
    log_info "  To  : $dest_addr"

    # Safety: back up first
    log_info "Creating pre-move backup..."
    local backup_file
    backup_file="$(backup_state)"

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would run: terraform state mv '$source_addr' '$dest_addr'"
        return 0
    fi

    # Verify the source exists in current state
    if ! (cd "$TERRAFORM_DIR" && terraform state list 2>/dev/null | grep -qF "$source_addr"); then
        log_error "Source address '$source_addr' not found in current state."
        return 1
    fi

    # Perform the move
    if ! (cd "$TERRAFORM_DIR" && terraform state mv "$source_addr" "$dest_addr" 2>&1); then
        log_error "State move failed."
        log_error "State backup at: $backup_file"
        return 1
    fi

    log_info "Move succeeded. Validating with plan..."
    validate_plan || {
        log_warn "Post-move plan shows changes. State backup at: $backup_file"
        return 2
    }

    log_info "Resource moved and validated successfully."
}

# ---------------------------------------------------------------------------
# bulk_import — Read a CSV file and import each resource sequentially.
# CSV format: terraform_address,azure_resource_id
# Lines starting with # are treated as comments. Empty lines are skipped.
# ---------------------------------------------------------------------------
bulk_import() {
    local csv_file=""

    while getopts ":f:" opt; do
        case $opt in
            f) csv_file="$OPTARG" ;;
            *) ;;
        esac
    done

    if [[ -z "$csv_file" ]]; then
        log_error "bulk-import requires -f <csv-file>"
        exit 3
    fi

    if [[ ! -f "$csv_file" ]]; then
        log_error "CSV file not found: $csv_file"
        exit 3
    fi

    log_info "--- Bulk Import from CSV ---"
    log_info "Manifest: $csv_file"

    # Safety: single backup before the entire bulk operation
    log_info "Creating pre-bulk-import backup..."
    local backup_file
    backup_file="$(backup_state)"

    local total=0
    local success=0
    local failed=0
    local skipped=0

    while IFS=',' read -r tf_address resource_id || [[ -n "$tf_address" ]]; do
        # Skip comments and empty lines
        [[ -z "$tf_address" || "$tf_address" =~ ^[[:space:]]*# ]] && continue

        # Trim whitespace
        tf_address="$(echo "$tf_address" | xargs)"
        resource_id="$(echo "$resource_id" | xargs)"

        total=$((total + 1))
        log_info "[$total] Importing: $tf_address"

        if $DRY_RUN; then
            log_info "[DRY-RUN] Would import '$tf_address' <- '$resource_id'"
            skipped=$((skipped + 1))
            continue
        fi

        # Check if already in state (skip if so)
        if (cd "$TERRAFORM_DIR" && terraform state list 2>/dev/null | grep -qF "$tf_address"); then
            log_warn "[$total] '$tf_address' already exists in state. Skipping."
            skipped=$((skipped + 1))
            continue
        fi

        if (cd "$TERRAFORM_DIR" && terraform import "$tf_address" "$resource_id" 2>&1); then
            success=$((success + 1))
            log_info "[$total] Import succeeded for $tf_address"
        else
            failed=$((failed + 1))
            log_error "[$total] Import FAILED for $tf_address"
            log_error "  Continuing with remaining resources. Backup at: $backup_file"
        fi
    done < "$csv_file"

    log_info "--- Bulk Import Summary ---"
    log_info "Total : $total"
    log_info "OK    : $success"
    log_info "Failed: $failed"
    log_info "Skipped: $skipped"

    # Run a single plan validation after all imports
    if ! $DRY_RUN && [[ $success -gt 0 ]]; then
        log_info "Running post-bulk-import plan validation..."
        validate_plan || log_warn "Post-bulk plan shows changes. Review before applying."
    fi

    if [[ $failed -gt 0 ]]; then
        log_error "Some imports failed. Review output and consider rollback to: $backup_file"
        return 1
    fi

    log_info "Bulk import completed successfully."
}

# ---------------------------------------------------------------------------
# rollback_state — Restore state from a backup file
# Arguments: -b <backup-file>
# ---------------------------------------------------------------------------
rollback_state() {
    local backup_file=""

    while getopts ":b:" opt; do
        case $opt in
            b) backup_file="$OPTARG" ;;
            *) ;;
        esac
    done

    if [[ -z "$backup_file" ]]; then
        log_error "rollback requires -b <backup-file>"
        exit 3
    fi

    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        exit 3
    fi

    log_info "--- Rolling back state ---"
    log_info "Backup file: $backup_file"

    # Safety: back up the current (possibly broken) state before overwriting
    log_info "Backing up current state before rollback..."
    backup_state || log_warn "Could not back up current state (may already be corrupted)."

    if $DRY_RUN; then
        log_info "[DRY-RUN] Would push state from: $backup_file"
        return 0
    fi

    # Push the backup state to the backend
    if ! (cd "$TERRAFORM_DIR" && terraform state push "$backup_file" 2>&1); then
        log_error "State push failed. Manual intervention may be needed."
        return 1
    fi

    log_info "State restored from backup. Validating..."
    validate_plan || {
        log_warn "Post-rollback plan shows changes. Review carefully."
        return 2
    }

    log_info "Rollback completed and validated successfully."
}

# ---------------------------------------------------------------------------
# Main — Parse global options then dispatch to subcommand
# ---------------------------------------------------------------------------
main() {
    if [[ $# -lt 1 ]]; then
        usage
    fi

    local command="$1"
    shift

    # Parse global options first. We consume -d, -n, -v, -h and leave the rest
    # for subcommand parsers.
    local global_args=()
    local subcmd_args=()
    local parsing_globals=true

    for arg in "$@"; do
        if $parsing_globals; then
            case "$arg" in
                -d) global_args+=("$arg"); parsing_globals=true ;;
                -n) DRY_RUN=true ;;
                -v) VERBOSE=true ;;
                -h) usage ;;
                *)
                    if [[ "${global_args[-1]:-}" == "-d" ]]; then
                        TERRAFORM_DIR="$arg"
                        global_args=()
                    else
                        parsing_globals=false
                        subcmd_args+=("$arg")
                    fi
                    ;;
            esac
        else
            subcmd_args+=("$arg")
        fi
    done

    if [[ -z "$TERRAFORM_DIR" ]]; then
        log_error "Terraform directory (-d) is required for all commands."
        exit 3
    fi

    if [[ ! -d "$TERRAFORM_DIR" ]]; then
        log_error "Terraform directory not found: $TERRAFORM_DIR"
        exit 3
    fi

    BACKUP_DIR="${TERRAFORM_DIR}/state_backups"

    case "$command" in
        backup)
            backup_state
            ;;
        import)
            OPTIND=1
            import_resource "${subcmd_args[@]}"
            ;;
        move)
            OPTIND=1
            move_resource "${subcmd_args[@]}"
            ;;
        bulk-import)
            OPTIND=1
            bulk_import "${subcmd_args[@]}"
            ;;
        rollback)
            OPTIND=1
            rollback_state "${subcmd_args[@]}"
            ;;
        *)
            log_error "Unknown command: $command"
            usage
            ;;
    esac
}

main "$@"
