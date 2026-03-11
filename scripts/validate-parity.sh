#!/usr/bin/env bash
#
# validate-parity.sh
#
# Validates that ARM-deployed resources and Terraform-managed resources are in
# parity. Compares resource IDs, types, tags, and key configuration properties
# to detect drift between the ARM source of truth and the Terraform state.
#
# Usage:
#   ./validate-parity.sh -g <resource-group> -d <terraform-dir> [-s <subscription-id>] [-o <report-dir>]
#
# Exit codes:
#   0 - Full parity (all ARM resources matched in Terraform state)
#   1 - Drift detected (missing, extra, or property mismatches found)
#   2 - Script error (pre-flight failure, bad arguments)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
RESOURCE_GROUP=""
TERRAFORM_DIR=""
SUBSCRIPTION_ID=""
REPORT_DIR=""

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_info()  { echo "[INFO]  $(date '+%H:%M:%S') $*"; }
log_warn()  { echo "[WARN]  $(date '+%H:%M:%S') $*" >&2; }
log_error() { echo "[ERROR] $(date '+%H:%M:%S') $*" >&2; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $(basename "$0") -g <resource-group> -d <terraform-dir> [OPTIONS]

Required:
  -g    Azure resource group name
  -d    Directory containing Terraform configuration and state

Options:
  -s    Azure subscription ID (defaults to current context)
  -o    Directory for parity reports (defaults to <terraform-dir>/reports)
  -h    Show this help message

Exit codes:
  0  Full parity
  1  Drift detected
  2  Script error
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while getopts ":g:d:s:o:h" opt; do
    case $opt in
        g) RESOURCE_GROUP="$OPTARG" ;;
        d) TERRAFORM_DIR="$OPTARG" ;;
        s) SUBSCRIPTION_ID="$OPTARG" ;;
        o) REPORT_DIR="$OPTARG" ;;
        h) usage ;;
        :) log_error "Option -$OPTARG requires an argument."; exit 2 ;;
        *) log_error "Unknown option -$OPTARG"; usage ;;
    esac
done

if [[ -z "$RESOURCE_GROUP" || -z "$TERRAFORM_DIR" ]]; then
    log_error "Both -g (resource group) and -d (terraform dir) are required."
    usage
fi

REPORT_DIR="${REPORT_DIR:-${TERRAFORM_DIR}/reports}"
mkdir -p "$REPORT_DIR"

# Set subscription if provided
if [[ -n "$SUBSCRIPTION_ID" ]]; then
    az account set --subscription "$SUBSCRIPTION_ID" || { log_error "Failed to set subscription."; exit 2; }
fi

log_info "=== Parity Validation Started ==="
log_info "Resource Group : $RESOURCE_GROUP"
log_info "Terraform Dir  : $TERRAFORM_DIR"

# ---------------------------------------------------------------------------
# Step 1: Collect ARM-deployed resources from Azure
# ---------------------------------------------------------------------------
log_info "Fetching ARM-deployed resources..."
ARM_RESOURCES_FILE="${REPORT_DIR}/arm_resources_${TIMESTAMP}.json"

az resource list \
    --resource-group "$RESOURCE_GROUP" \
    --query "[].{id:id, name:name, type:type, location:location, tags:tags, sku:sku}" \
    --output json > "$ARM_RESOURCES_FILE" 2>/dev/null

ARM_COUNT="$(python3 -c "import json; print(len(json.load(open('${ARM_RESOURCES_FILE}'))))")"
log_info "ARM resources found: $ARM_COUNT"

# ---------------------------------------------------------------------------
# Step 2: Collect Terraform state resources
# ---------------------------------------------------------------------------
log_info "Reading Terraform state..."
TF_STATE_FILE="${REPORT_DIR}/tf_state_${TIMESTAMP}.json"

# Run terraform show to get the full state as JSON
(cd "$TERRAFORM_DIR" && terraform show -json 2>/dev/null) > "$TF_STATE_FILE" || {
    log_error "Failed to read Terraform state. Ensure 'terraform init' has been run in $TERRAFORM_DIR."
    exit 2
}

# Extract resource IDs from the Terraform state
TF_RESOURCE_IDS_FILE="${REPORT_DIR}/tf_resource_ids_${TIMESTAMP}.json"
python3 -c "
import json, sys

with open('${TF_STATE_FILE}') as f:
    state = json.load(f)

resources = []
# Navigate the state JSON structure to extract managed resources
values = state.get('values', {})
root_module = values.get('root_module', {})

def extract_resources(module):
    result = []
    for res in module.get('resources', []):
        vals = res.get('values', {})
        result.append({
            'address': res.get('address', ''),
            'type': res.get('type', ''),
            'name': res.get('name', ''),
            'id': vals.get('id', ''),
            'location': vals.get('location', ''),
            'tags': vals.get('tags', {}),
        })
    # Recurse into child modules
    for child in module.get('child_modules', []):
        result.extend(extract_resources(child))
    return result

resources = extract_resources(root_module)
json.dump(resources, sys.stdout, indent=2)
" > "$TF_RESOURCE_IDS_FILE"

TF_COUNT="$(python3 -c "import json; print(len(json.load(open('${TF_RESOURCE_IDS_FILE}'))))")"
log_info "Terraform state resources found: $TF_COUNT"

# ---------------------------------------------------------------------------
# Step 3: Cross-reference ARM resources against Terraform state
# ---------------------------------------------------------------------------
log_info "Cross-referencing resources..."
PARITY_REPORT_JSON="${REPORT_DIR}/parity_report_${TIMESTAMP}.json"
PARITY_REPORT_TXT="${REPORT_DIR}/parity_report_${TIMESTAMP}.txt"

python3 <<PYEOF
import json

# Load ARM resources
with open("${ARM_RESOURCES_FILE}") as f:
    arm_resources = json.load(f)

# Load Terraform resources
with open("${TF_RESOURCE_IDS_FILE}") as f:
    tf_resources = json.load(f)

# Build a set of Azure resource IDs from Terraform state (case-insensitive)
tf_ids = {}
for r in tf_resources:
    if r.get("id"):
        tf_ids[r["id"].lower()] = r

# Build a set of ARM resource IDs (case-insensitive)
arm_ids = {}
for r in arm_resources:
    if r.get("id"):
        arm_ids[r["id"].lower()] = r

# --- Classification ---
matched = []
missing_from_tf = []
extra_in_tf = []
property_mismatches = []

# Find ARM resources present/absent in Terraform
for arm_id_lower, arm_res in arm_ids.items():
    if arm_id_lower in tf_ids:
        tf_res = tf_ids[arm_id_lower]
        matched.append({"arm_id": arm_res["id"], "tf_address": tf_res["address"]})

        # --- Property-level comparison ---
        mismatches = []

        # Compare tags
        arm_tags = arm_res.get("tags") or {}
        tf_tags = tf_res.get("tags") or {}
        if arm_tags != tf_tags:
            mismatches.append({
                "property": "tags",
                "arm_value": arm_tags,
                "tf_value": tf_tags,
            })

        # Compare location
        arm_loc = (arm_res.get("location") or "").lower().replace(" ", "")
        tf_loc = (tf_res.get("location") or "").lower().replace(" ", "")
        if arm_loc and tf_loc and arm_loc != tf_loc:
            mismatches.append({
                "property": "location",
                "arm_value": arm_res.get("location"),
                "tf_value": tf_res.get("location"),
            })

        if mismatches:
            property_mismatches.append({
                "resource_id": arm_res["id"],
                "tf_address": tf_res["address"],
                "mismatches": mismatches,
            })
    else:
        missing_from_tf.append({
            "arm_id": arm_res["id"],
            "arm_type": arm_res.get("type", ""),
            "arm_name": arm_res.get("name", ""),
        })

# Find Terraform resources not in ARM (extra resources)
for tf_id_lower, tf_res in tf_ids.items():
    if tf_id_lower not in arm_ids:
        extra_in_tf.append({
            "tf_address": tf_res["address"],
            "tf_id": tf_res["id"],
            "tf_type": tf_res.get("type", ""),
        })

# --- Build report ---
parity = len(missing_from_tf) == 0 and len(extra_in_tf) == 0 and len(property_mismatches) == 0

report = {
    "timestamp": "${TIMESTAMP}",
    "resource_group": "${RESOURCE_GROUP}",
    "summary": {
        "arm_resource_count": len(arm_ids),
        "tf_resource_count": len(tf_ids),
        "matched_count": len(matched),
        "missing_from_terraform": len(missing_from_tf),
        "extra_in_terraform": len(extra_in_tf),
        "property_mismatches": len(property_mismatches),
        "parity": parity,
    },
    "matched": matched,
    "missing_from_terraform": missing_from_tf,
    "extra_in_terraform": extra_in_tf,
    "property_mismatches": property_mismatches,
}

# Write JSON report
with open("${PARITY_REPORT_JSON}", "w") as f:
    json.dump(report, f, indent=2)

# Write human-readable report
with open("${PARITY_REPORT_TXT}", "w") as f:
    f.write("=" * 70 + "\n")
    f.write("  ARM-to-Terraform Parity Report\n")
    f.write("  Generated: ${TIMESTAMP}\n")
    f.write("  Resource Group: ${RESOURCE_GROUP}\n")
    f.write("=" * 70 + "\n\n")
    f.write(f"ARM Resources  : {len(arm_ids)}\n")
    f.write(f"TF Resources   : {len(tf_ids)}\n")
    f.write(f"Matched        : {len(matched)}\n")
    f.write(f"Missing from TF: {len(missing_from_tf)}\n")
    f.write(f"Extra in TF    : {len(extra_in_tf)}\n")
    f.write(f"Prop Mismatches: {len(property_mismatches)}\n")
    f.write(f"Parity         : {'PASS' if parity else 'FAIL'}\n\n")

    if missing_from_tf:
        f.write("-" * 70 + "\n")
        f.write("  Resources MISSING from Terraform State\n")
        f.write("-" * 70 + "\n")
        for r in missing_from_tf:
            f.write(f"  [{r['arm_type']}] {r['arm_name']}\n")
            f.write(f"    ARM ID: {r['arm_id']}\n\n")

    if extra_in_tf:
        f.write("-" * 70 + "\n")
        f.write("  Resources EXTRA in Terraform (not in ARM resource group)\n")
        f.write("-" * 70 + "\n")
        for r in extra_in_tf:
            f.write(f"  [{r['tf_type']}] {r['tf_address']}\n")
            f.write(f"    TF ID: {r['tf_id']}\n\n")

    if property_mismatches:
        f.write("-" * 70 + "\n")
        f.write("  Property Mismatches (resource exists in both, values differ)\n")
        f.write("-" * 70 + "\n")
        for r in property_mismatches:
            f.write(f"  Resource: {r['resource_id']}\n")
            f.write(f"  TF Addr : {r['tf_address']}\n")
            for m in r["mismatches"]:
                f.write(f"    {m['property']}:\n")
                f.write(f"      ARM: {m['arm_value']}\n")
                f.write(f"      TF : {m['tf_value']}\n")
            f.write("\n")

    f.write("=" * 70 + "\n")
    f.write(f"  RESULT: {'PARITY ACHIEVED' if parity else 'DRIFT DETECTED'}\n")
    f.write("=" * 70 + "\n")

# Print the exit-code indicator for the shell wrapper
print("PARITY" if parity else "DRIFT")
PYEOF

# ---------------------------------------------------------------------------
# Step 4: Determine exit code and print summary
# ---------------------------------------------------------------------------
RESULT="$(tail -1 <(python3 -c "
import json
with open('${PARITY_REPORT_JSON}') as f:
    r = json.load(f)
print('PARITY' if r['summary']['parity'] else 'DRIFT')
"))"

log_info "JSON report : $PARITY_REPORT_JSON"
log_info "Text report : $PARITY_REPORT_TXT"

# Print the human-readable report to stdout
cat "$PARITY_REPORT_TXT"

if [[ "$RESULT" == "PARITY" ]]; then
    log_info "Result: PARITY ACHIEVED (exit 0)"
    exit 0
else
    log_warn "Result: DRIFT DETECTED (exit 1)"
    exit 1
fi
