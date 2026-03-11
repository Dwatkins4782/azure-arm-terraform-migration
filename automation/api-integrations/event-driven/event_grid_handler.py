"""
Azure Event Grid Handler for Infrastructure Change Events.

This Azure Function processes infrastructure events published by Azure
Event Grid and orchestrates downstream integrations:

    1. CMDB Synchronization  - Keeps ServiceNow CMDB in sync with actual
       Azure resource state by creating/updating/retiring CIs.
    2. Security Notification - Forwards security-relevant events to SIEM
       platforms (Splunk HEC or Azure Sentinel) for threat detection.
    3. Compliance Validation - Evaluates resource changes against HIPAA
       compliance policies and flags violations.

Architecture:
    Azure Resource Manager
        -> Event Grid System Topic (resource write/delete events)
            -> Event Grid Subscription (filtered by resource type)
                -> This Azure Function (Event Grid trigger)
                    -> ServiceNow CMDB REST API
                    -> Splunk HEC / Azure Sentinel REST API
                    -> HIPAA compliance policy engine

Trigger:
    Azure Event Grid (EventGridTrigger binding in function.json)

Environment Variables Required:
    SERVICENOW_INSTANCE_URL  - ServiceNow instance base URL
    SERVICENOW_USERNAME      - ServiceNow API user
    SERVICENOW_PASSWORD      - ServiceNow API password
    SPLUNK_HEC_URL           - Splunk HTTP Event Collector URL
    SPLUNK_HEC_TOKEN         - Splunk HEC authentication token
    SENTINEL_WORKSPACE_ID    - Azure Sentinel Log Analytics workspace ID
    SENTINEL_SHARED_KEY      - Azure Sentinel shared key for data ingestion
"""

import base64
import hashlib
import hmac
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import azure.functions as func
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# HIPAA-relevant resource types
# ---------------------------------------------------------------------------
# These Azure resource types handle ePHI or provide security controls.
# Changes to these resources trigger compliance validation.
HIPAA_SENSITIVE_RESOURCE_TYPES = {
    "Microsoft.Sql/servers",
    "Microsoft.Sql/servers/databases",
    "Microsoft.Storage/storageAccounts",
    "Microsoft.KeyVault/vaults",
    "Microsoft.Network/networkSecurityGroups",
    "Microsoft.Network/virtualNetworks",
    "Microsoft.Compute/virtualMachines",
    "Microsoft.ContainerService/managedClusters",
    "Microsoft.DocumentDB/databaseAccounts",
    "Microsoft.DBforPostgreSQL/servers",
    "Microsoft.Web/sites",
}

# Security-critical event operations that warrant SIEM notification
SECURITY_OPERATIONS = {
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Network/networkSecurityGroups/delete",
    "Microsoft.KeyVault/vaults/write",
    "Microsoft.KeyVault/vaults/delete",
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleAssignments/delete",
    "Microsoft.Sql/servers/firewallRules/write",
    "Microsoft.Sql/servers/firewallRules/delete",
    "Microsoft.Storage/storageAccounts/write",
}


class EventGridHandler:
    """Processes Azure Event Grid infrastructure events and orchestrates
    downstream CMDB sync, security notification, and compliance checks.

    This handler is designed to run inside an Azure Function with an
    Event Grid trigger binding. Each public method corresponds to a
    specific event type or downstream integration.
    """

    def __init__(self) -> None:
        """Initialize the handler with configuration from environment variables.

        Creates a shared requests session with retry logic for all
        outbound REST API calls.
        """
        # ServiceNow CMDB configuration
        self.servicenow_url = os.environ.get("SERVICENOW_INSTANCE_URL", "")
        self.servicenow_user = os.environ.get("SERVICENOW_USERNAME", "")
        self.servicenow_pass = os.environ.get("SERVICENOW_PASSWORD", "")

        # Splunk HEC configuration
        self.splunk_hec_url = os.environ.get("SPLUNK_HEC_URL", "")
        self.splunk_hec_token = os.environ.get("SPLUNK_HEC_TOKEN", "")

        # Azure Sentinel configuration
        self.sentinel_workspace_id = os.environ.get(
            "SENTINEL_WORKSPACE_ID", ""
        )
        self.sentinel_shared_key = os.environ.get("SENTINEL_SHARED_KEY", "")

        # Shared HTTP session with retry strategy
        self._session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "PATCH"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

    # ------------------------------------------------------------------
    # Event dispatch
    # ------------------------------------------------------------------

    def process_event(self, event: func.EventGridEvent) -> Dict[str, Any]:
        """Main entry point: route an Event Grid event to the appropriate handler.

        Dispatches based on the event type field:
          - Microsoft.Resources.ResourceWriteSuccess  -> handle_resource_write
          - Microsoft.Resources.ResourceDeleteSuccess  -> handle_resource_delete

        After routing, triggers downstream integrations (CMDB sync,
        security notification, compliance validation) as appropriate.

        Args:
            event: The Azure Event Grid event object from the function binding.

        Returns:
            A summary dictionary describing actions taken.
        """
        event_data = event.get_json()
        event_type = event.event_type
        resource_uri = event_data.get("resourceUri", "")
        operation = event_data.get("operationName", "")

        logger.info(
            "Processing event: type=%s, operation=%s, resource=%s",
            event_type,
            operation,
            resource_uri,
        )

        results: Dict[str, Any] = {
            "event_id": event.id,
            "event_type": event_type,
            "resource_uri": resource_uri,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actions": [],
        }

        # --- Route to the correct handler based on event type ---
        if event_type == "Microsoft.Resources.ResourceWriteSuccess":
            self.handle_resource_write(event_data, results)
        elif event_type == "Microsoft.Resources.ResourceDeleteSuccess":
            self.handle_resource_delete(event_data, results)
        else:
            logger.info("Ignoring unhandled event type: %s", event_type)
            results["actions"].append({"action": "ignored", "reason": "unhandled_event_type"})

        # --- Cross-cutting concerns ---
        # Security notification for sensitive operations
        if operation in SECURITY_OPERATIONS:
            self.notify_security(event_data, results)

        # Compliance validation for HIPAA-sensitive resource types
        resource_type = self._extract_resource_type(resource_uri)
        if resource_type in HIPAA_SENSITIVE_RESOURCE_TYPES:
            self.validate_compliance(event_data, results)

        return results

    # ------------------------------------------------------------------
    # Resource event handlers
    # ------------------------------------------------------------------

    def handle_resource_write(
        self,
        event_data: Dict[str, Any],
        results: Dict[str, Any],
    ) -> None:
        """Handle resource creation or modification events.

        When Azure Resource Manager reports a successful write operation,
        this method syncs the resource state to the ServiceNow CMDB.
        This ensures the CMDB always reflects the actual infrastructure
        state, which is a core ITIL and HIPAA requirement.

        Args:
            event_data: The event payload from Event Grid.
            results: Mutable results dictionary for tracking actions.
        """
        resource_uri = event_data.get("resourceUri", "")
        operation = event_data.get("operationName", "")

        logger.info(
            "Resource write event: operation=%s, resource=%s",
            operation,
            resource_uri,
        )

        # Sync the created/modified resource to the ServiceNow CMDB
        cmdb_result = self.sync_cmdb(
            resource_uri=resource_uri,
            operation="create_or_update",
            event_data=event_data,
        )

        results["actions"].append({
            "action": "cmdb_sync",
            "operation": "create_or_update",
            "resource_uri": resource_uri,
            "cmdb_result": cmdb_result,
        })

    def handle_resource_delete(
        self,
        event_data: Dict[str, Any],
        results: Dict[str, Any],
    ) -> None:
        """Handle resource deletion events.

        When a resource is deleted, the corresponding CMDB Configuration
        Item must be retired (not deleted) to maintain a full audit trail.

        Args:
            event_data: The event payload from Event Grid.
            results: Mutable results dictionary for tracking actions.
        """
        resource_uri = event_data.get("resourceUri", "")
        operation = event_data.get("operationName", "")

        logger.info(
            "Resource delete event: operation=%s, resource=%s",
            operation,
            resource_uri,
        )

        # Retire the CI in ServiceNow CMDB (do not hard-delete)
        cmdb_result = self.sync_cmdb(
            resource_uri=resource_uri,
            operation="retire",
            event_data=event_data,
        )

        results["actions"].append({
            "action": "cmdb_sync",
            "operation": "retire",
            "resource_uri": resource_uri,
            "cmdb_result": cmdb_result,
        })

    # ------------------------------------------------------------------
    # ServiceNow CMDB synchronization
    # ------------------------------------------------------------------

    def sync_cmdb(
        self,
        resource_uri: str,
        operation: str,
        event_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Synchronize an Azure resource change to the ServiceNow CMDB.

        Uses the ServiceNow CMDB Identification and Reconciliation (IRE)
        API to create, update, or retire Configuration Items. The Azure
        resource URI serves as the unique correlation identifier.

        For "create_or_update":
            - Looks up existing CI by azure_resource_id attribute.
            - Creates a new CI if none exists; updates attributes otherwise.
        For "retire":
            - Sets the CI install_status to "Retired" (7).

        Args:
            resource_uri: Full Azure resource ID.
            operation: Either "create_or_update" or "retire".
            event_data: Raw event data for attribute extraction.

        Returns:
            Dictionary with CMDB operation outcome.
        """
        if not self.servicenow_url:
            logger.warning("ServiceNow URL not configured; skipping CMDB sync.")
            return {"status": "skipped", "reason": "not_configured"}

        resource_type = self._extract_resource_type(resource_uri)
        resource_name = resource_uri.split("/")[-1]
        resource_group = self._extract_resource_group(resource_uri)

        # Map Azure resource types to ServiceNow CI classes
        ci_class = self._map_resource_to_ci_class(resource_type)

        try:
            if operation == "retire":
                # Find the existing CI and set it to retired status
                ci_sys_id = self._find_cmdb_ci(resource_uri)
                if ci_sys_id:
                    self._update_cmdb_ci(ci_sys_id, {
                        "install_status": 7,  # Retired
                        "u_decommission_date": datetime.now(
                            timezone.utc
                        ).strftime("%Y-%m-%d %H:%M:%S"),
                    })
                    return {"status": "retired", "ci_sys_id": ci_sys_id}
                else:
                    return {"status": "not_found", "resource_uri": resource_uri}
            else:
                # Create or update the CI
                ci_payload = {
                    "name": resource_name,
                    "sys_class_name": ci_class,
                    "install_status": 1,  # Installed
                    "u_azure_resource_id": resource_uri,
                    "u_resource_group": resource_group,
                    "u_resource_type": resource_type,
                    "u_last_sync_time": datetime.now(
                        timezone.utc
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                    "u_managed_by": "Terraform",
                }

                ci_sys_id = self._find_cmdb_ci(resource_uri)
                if ci_sys_id:
                    self._update_cmdb_ci(ci_sys_id, ci_payload)
                    return {"status": "updated", "ci_sys_id": ci_sys_id}
                else:
                    new_ci = self._create_cmdb_ci(ci_payload)
                    return {"status": "created", "ci_sys_id": new_ci}

        except requests.HTTPError as exc:
            logger.error("CMDB sync failed for %s: %s", resource_uri, exc)
            return {"status": "error", "message": str(exc)}

    def _find_cmdb_ci(self, resource_uri: str) -> Optional[str]:
        """Look up a CMDB CI by its Azure resource ID.

        Args:
            resource_uri: The full Azure resource URI used as the
                unique correlation key.

        Returns:
            The sys_id of the matching CI, or None if not found.
        """
        url = f"{self.servicenow_url}/api/now/table/cmdb_ci"
        params = {
            "sysparm_query": f"u_azure_resource_id={resource_uri}",
            "sysparm_fields": "sys_id",
            "sysparm_limit": "1",
        }
        response = self._session.get(
            url,
            params=params,
            auth=(self.servicenow_user, self.servicenow_pass),
            headers={"Accept": "application/json"},
            timeout=15,
        )
        response.raise_for_status()
        records = response.json().get("result", [])
        return records[0]["sys_id"] if records else None

    def _create_cmdb_ci(self, payload: Dict[str, Any]) -> str:
        """Create a new Configuration Item in the ServiceNow CMDB.

        Args:
            payload: CI attribute dictionary.

        Returns:
            sys_id of the newly created CI.
        """
        url = f"{self.servicenow_url}/api/now/table/cmdb_ci"
        response = self._session.post(
            url,
            json=payload,
            auth=(self.servicenow_user, self.servicenow_pass),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=15,
        )
        response.raise_for_status()
        return response.json()["result"]["sys_id"]

    def _update_cmdb_ci(
        self, ci_sys_id: str, payload: Dict[str, Any]
    ) -> None:
        """Update an existing Configuration Item in the ServiceNow CMDB.

        Args:
            ci_sys_id: sys_id of the CI to update.
            payload: Dictionary of attributes to update.
        """
        url = f"{self.servicenow_url}/api/now/table/cmdb_ci/{ci_sys_id}"
        response = self._session.patch(
            url,
            json=payload,
            auth=(self.servicenow_user, self.servicenow_pass),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=15,
        )
        response.raise_for_status()

    # ------------------------------------------------------------------
    # Security event notification (SIEM integration)
    # ------------------------------------------------------------------

    def notify_security(
        self,
        event_data: Dict[str, Any],
        results: Dict[str, Any],
    ) -> None:
        """Forward security-relevant events to SIEM platforms via REST API.

        Sends to both Splunk (via HTTP Event Collector) and Azure Sentinel
        (via the Log Analytics Data Collector API) when configured. This
        dual-destination approach supports organizations that use Splunk
        for operational security and Sentinel for cloud-native SIEM.

        Args:
            event_data: The raw Event Grid event payload.
            results: Mutable results dictionary for tracking actions.
        """
        siem_event = {
            "source": "azure-event-grid",
            "sourcetype": "azure:infrastructure:change",
            "event_time": datetime.now(timezone.utc).isoformat(),
            "operation": event_data.get("operationName", ""),
            "resource_uri": event_data.get("resourceUri", ""),
            "caller": event_data.get("claims", {}).get(
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
                "unknown",
            ),
            "source_ip": event_data.get("httpRequest", {}).get(
                "clientIpAddress", "unknown"
            ),
            "status": event_data.get("status", ""),
            "correlation_id": event_data.get("correlationId", ""),
        }

        siem_results: List[Dict[str, str]] = []

        # --- Splunk HEC integration ---
        if self.splunk_hec_url and self.splunk_hec_token:
            try:
                splunk_payload = {
                    "source": "azure-event-grid-function",
                    "sourcetype": "_json",
                    "event": siem_event,
                }
                response = self._session.post(
                    self.splunk_hec_url,
                    json=splunk_payload,
                    headers={
                        "Authorization": f"Splunk {self.splunk_hec_token}",
                    },
                    timeout=10,
                )
                response.raise_for_status()
                siem_results.append({"target": "splunk", "status": "sent"})
                logger.info("Security event sent to Splunk HEC.")
            except requests.RequestException as exc:
                logger.error("Failed to send to Splunk HEC: %s", exc)
                siem_results.append({
                    "target": "splunk",
                    "status": "error",
                    "message": str(exc),
                })

        # --- Azure Sentinel (Log Analytics Data Collector API) ---
        if self.sentinel_workspace_id and self.sentinel_shared_key:
            try:
                self._send_to_sentinel(
                    log_type="InfrastructureSecurityEvent",
                    body=json.dumps([siem_event]),
                )
                siem_results.append({"target": "sentinel", "status": "sent"})
                logger.info("Security event sent to Azure Sentinel.")
            except requests.RequestException as exc:
                logger.error("Failed to send to Sentinel: %s", exc)
                siem_results.append({
                    "target": "sentinel",
                    "status": "error",
                    "message": str(exc),
                })

        results["actions"].append({
            "action": "security_notification",
            "siem_results": siem_results,
        })

    def _send_to_sentinel(self, log_type: str, body: str) -> None:
        """Send log data to Azure Sentinel via the Log Analytics Data
        Collector API.

        Constructs the required HMAC-SHA256 authorization header and
        posts the JSON payload to the ingestion endpoint.

        Args:
            log_type: Custom log table name in Log Analytics.
            body: JSON-encoded array of log records.
        """
        rfc1123_date = datetime.now(timezone.utc).strftime(
            "%a, %d %b %Y %H:%M:%S GMT"
        )
        content_length = len(body)

        # Build the signature string per the Data Collector API spec
        string_to_sign = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{rfc1123_date}\n/api/logs"
        )
        decoded_key = base64.b64decode(self.sentinel_shared_key)
        encoded_hash = base64.b64encode(
            hmac.new(
                decoded_key,
                string_to_sign.encode("utf-8"),
                digestmod=hashlib.sha256,
            ).digest()
        ).decode("utf-8")

        signature = (
            f"SharedKey {self.sentinel_workspace_id}:{encoded_hash}"
        )

        url = (
            f"https://{self.sentinel_workspace_id}.ods.opinsights.azure.com"
            f"/api/logs?api-version=2016-04-01"
        )

        response = self._session.post(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": signature,
                "Log-Type": log_type,
                "x-ms-date": rfc1123_date,
            },
            timeout=15,
        )
        response.raise_for_status()

    # ------------------------------------------------------------------
    # HIPAA compliance validation
    # ------------------------------------------------------------------

    def validate_compliance(
        self,
        event_data: Dict[str, Any],
        results: Dict[str, Any],
    ) -> None:
        """Validate that a resource change complies with HIPAA policies.

        Runs a series of policy checks against the event metadata:
          1. Encryption at rest must remain enabled.
          2. Network access must not be set to public/unrestricted.
          3. Diagnostic logging must not be disabled.
          4. Changes must originate from an authorized principal.

        Violations are logged at WARNING level and included in the results
        for downstream alerting (e.g., PagerDuty, Slack).

        Args:
            event_data: The raw Event Grid event payload.
            results: Mutable results dictionary for tracking actions.
        """
        resource_uri = event_data.get("resourceUri", "")
        operation = event_data.get("operationName", "")
        violations: List[Dict[str, str]] = []

        # --- Policy 1: Encryption enforcement ---
        # Flag operations that could disable encryption on storage or databases
        encryption_risk_ops = {
            "Microsoft.Storage/storageAccounts/write",
            "Microsoft.Sql/servers/databases/write",
            "Microsoft.DocumentDB/databaseAccounts/write",
        }
        if operation in encryption_risk_ops:
            violations.append({
                "policy": "HIPAA-ENCRYPT-001",
                "description": (
                    "Resource write detected on encryption-sensitive resource. "
                    "Verify that encryption at rest remains enabled."
                ),
                "severity": "high",
                "resource_uri": resource_uri,
            })

        # --- Policy 2: Network access restriction ---
        network_risk_ops = {
            "Microsoft.Sql/servers/firewallRules/write",
            "Microsoft.Storage/storageAccounts/write",
            "Microsoft.Network/networkSecurityGroups/write",
        }
        if operation in network_risk_ops:
            violations.append({
                "policy": "HIPAA-NETWORK-001",
                "description": (
                    "Network configuration change detected. Verify that "
                    "public network access is not inadvertently enabled."
                ),
                "severity": "high",
                "resource_uri": resource_uri,
            })

        # --- Policy 3: Audit logging enforcement ---
        if "diagnosticSettings/delete" in operation.lower():
            violations.append({
                "policy": "HIPAA-AUDIT-001",
                "description": (
                    "Diagnostic settings deletion detected. HIPAA requires "
                    "continuous audit logging for ePHI-related resources."
                ),
                "severity": "critical",
                "resource_uri": resource_uri,
            })

        # --- Policy 4: Authorized principal check ---
        caller = event_data.get("claims", {}).get(
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
            "unknown",
        )
        authorized_principals = os.environ.get(
            "HIPAA_AUTHORIZED_PRINCIPALS", ""
        ).split(",")
        if (
            authorized_principals
            and authorized_principals != [""]
            and caller not in authorized_principals
        ):
            violations.append({
                "policy": "HIPAA-ACCESS-001",
                "description": (
                    f"Change performed by unauthorized principal: {caller}. "
                    "Only pre-approved service principals and operators "
                    "should modify HIPAA-sensitive resources."
                ),
                "severity": "critical",
                "resource_uri": resource_uri,
            })

        # Log violations
        for violation in violations:
            logger.warning("COMPLIANCE_VIOLATION: %s", json.dumps(violation))

        results["actions"].append({
            "action": "compliance_validation",
            "resource_uri": resource_uri,
            "violations": violations,
            "compliant": len(violations) == 0,
        })

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_resource_type(resource_uri: str) -> str:
        """Extract the Azure resource type from a resource URI.

        Example:
            "/subscriptions/.../Microsoft.Sql/servers/myserver"
            -> "Microsoft.Sql/servers"

        Args:
            resource_uri: Full Azure resource ID.

        Returns:
            The resource provider and type string.
        """
        parts = resource_uri.split("/providers/")
        if len(parts) < 2:
            return "unknown"

        provider_path = parts[-1]
        segments = provider_path.split("/")

        # Resource type is provider/type (first two segments after providers/)
        if len(segments) >= 2:
            return f"{segments[0]}/{segments[1]}"
        return segments[0] if segments else "unknown"

    @staticmethod
    def _extract_resource_group(resource_uri: str) -> str:
        """Extract the resource group name from a resource URI.

        Args:
            resource_uri: Full Azure resource ID.

        Returns:
            Resource group name, or "unknown" if not found.
        """
        parts = resource_uri.lower().split("/resourcegroups/")
        if len(parts) >= 2:
            return parts[1].split("/")[0]
        return "unknown"

    @staticmethod
    def _map_resource_to_ci_class(resource_type: str) -> str:
        """Map an Azure resource type to a ServiceNow CMDB CI class.

        ServiceNow uses specific CI classes for different infrastructure
        types. This mapping ensures Azure resources are stored in the
        correct CMDB table for reporting and impact analysis.

        Args:
            resource_type: Azure resource provider/type string.

        Returns:
            ServiceNow CI class name.
        """
        mapping = {
            "Microsoft.Compute/virtualMachines": "cmdb_ci_vm_instance",
            "Microsoft.Sql/servers": "cmdb_ci_db_instance",
            "Microsoft.Sql/servers/databases": "cmdb_ci_database",
            "Microsoft.Storage/storageAccounts": "cmdb_ci_storage_device",
            "Microsoft.Network/virtualNetworks": "cmdb_ci_network",
            "Microsoft.Network/networkSecurityGroups": "cmdb_ci_firewall",
            "Microsoft.KeyVault/vaults": "cmdb_ci_credential_store",
            "Microsoft.Web/sites": "cmdb_ci_web_site",
            "Microsoft.ContainerService/managedClusters": "cmdb_ci_kubernetes_cluster",
        }
        return mapping.get(resource_type, "cmdb_ci")


# ---------------------------------------------------------------------------
# Azure Function entry point
# ---------------------------------------------------------------------------
# This is the function that Azure Functions runtime invokes when an
# Event Grid event arrives. It instantiates the handler and delegates
# processing to the process_event method.
# ---------------------------------------------------------------------------

handler = EventGridHandler()


def main(event: func.EventGridEvent) -> None:
    """Azure Function entry point for Event Grid trigger.

    This function is invoked by the Azure Functions runtime when an
    Event Grid event matches the subscription filter. It processes the
    event and logs the outcome.

    Args:
        event: The Event Grid event object provided by the runtime.
    """
    logger.info(
        "Event Grid function triggered: id=%s, type=%s, subject=%s",
        event.id,
        event.event_type,
        event.subject,
    )

    try:
        results = handler.process_event(event)
        logger.info(
            "Event processing complete: %s",
            json.dumps(results, default=str),
        )
    except Exception:
        logger.exception(
            "Unhandled exception processing event %s", event.id
        )
        raise
