"""
ServiceNow ITSM Change Management Integration for Terraform Deployments.

This module provides a comprehensive integration layer between Terraform
infrastructure-as-code deployments and the ServiceNow IT Service Management
platform. It automates the creation, tracking, and closure of change requests
(CRs) in alignment with ITIL change management best practices and HIPAA
compliance requirements.

Architecture:
    Terraform CLI / CI Pipeline
        -> ServiceNowChangeManager
            -> ServiceNow REST API (Table API + Attachment API)
                -> Change Request lifecycle management
                -> CMDB CI association
                -> Audit trail for HIPAA compliance

Dependencies:
    - requests >= 2.28.0
    - urllib3 >= 1.26.0

Usage:
    manager = ServiceNowChangeManager(
        instance_url="https://yourinstance.service-now.com",
        username="api_user",
        password="api_password"
    )
    cr_number = manager.create_change_request(
        description="Deploy Azure VNet via Terraform",
        affected_cis=["CI00123456"],
        risk_assessment="low",
        implementation_plan="terraform apply -auto-approve",
        backout_plan="terraform destroy -auto-approve"
    )
"""

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# ServiceNow Table API paths
CHANGE_REQUEST_TABLE = "/api/now/table/change_request"
ATTACHMENT_API = "/api/now/attachment/file"
CMDB_CI_TABLE = "/api/now/table/cmdb_ci"

# Change request state mapping (ServiceNow integer states)
CR_STATES = {
    "new": -5,
    "assess": -4,
    "authorize": -3,
    "scheduled": -2,
    "implement": -1,
    "review": 0,
    "closed": 3,
    "cancelled": 4,
}

# Risk level mapping
RISK_LEVELS = {
    "high": 1,
    "moderate": 2,
    "low": 3,
    "none": 4,
}

# Rate limiting: maximum requests per minute to ServiceNow REST API
DEFAULT_RATE_LIMIT = 60


class ServiceNowChangeManager:
    """Manages the full lifecycle of ServiceNow change requests for Terraform
    infrastructure deployments.

    This class encapsulates all interactions with the ServiceNow REST API
    required to create, update, and close change requests that correspond
    to Terraform plan/apply operations. It enforces HIPAA audit logging
    and provides retry logic for transient network failures.

    Attributes:
        instance_url: Base URL of the ServiceNow instance (no trailing slash).
        session: A requests.Session configured with auth, retries, and headers.
    """

    def __init__(
        self,
        instance_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        oauth_token: Optional[str] = None,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        verify_ssl: bool = True,
    ) -> None:
        """Initialize the ServiceNow change manager.

        Supports two authentication modes:
            1. Basic authentication (username + password)
            2. OAuth 2.0 bearer token

        Args:
            instance_url: ServiceNow instance URL, e.g.
                "https://yourorg.service-now.com".
            username: ServiceNow API username (basic auth).
            password: ServiceNow API password (basic auth).
            oauth_token: OAuth 2.0 bearer token (takes precedence over
                basic auth when provided).
            rate_limit: Maximum API calls per minute. Defaults to 60.
            verify_ssl: Whether to verify TLS certificates. Defaults to True.

        Raises:
            ValueError: If neither basic auth credentials nor an OAuth token
                are provided.
        """
        if not oauth_token and not (username and password):
            raise ValueError(
                "Provide either (username, password) or oauth_token for "
                "ServiceNow authentication."
            )

        self.instance_url = instance_url.rstrip("/")
        self._rate_limit = rate_limit
        self._request_timestamps: List[float] = []

        # ----- Session configuration with retry strategy -----
        self.session = requests.Session()
        self.session.verify = verify_ssl

        # Retry on 429 (rate-limited), 500, 502, 503, 504
        retry_strategy = Retry(
            total=4,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        # Authentication
        if oauth_token:
            self.session.headers.update(
                {"Authorization": f"Bearer {oauth_token}"}
            )
        else:
            self.session.auth = (username, password)

        # Common headers for the ServiceNow JSON REST API
        self.session.headers.update(
            {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        )

        logger.info(
            "ServiceNowChangeManager initialized for instance: %s",
            self.instance_url,
        )

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------
    def _enforce_rate_limit(self) -> None:
        """Block until a request slot is available within the rate window.

        Uses a sliding-window approach: we track timestamps of recent
        requests and sleep if the window is full.
        """
        now = time.monotonic()
        window_start = now - 60.0

        # Purge timestamps older than the 60-second window
        self._request_timestamps = [
            ts for ts in self._request_timestamps if ts > window_start
        ]

        if len(self._request_timestamps) >= self._rate_limit:
            # Sleep until the oldest request in the window expires
            sleep_duration = self._request_timestamps[0] - window_start + 0.1
            logger.debug("Rate limit reached; sleeping %.2fs", sleep_duration)
            time.sleep(sleep_duration)

        self._request_timestamps.append(time.monotonic())

    # ------------------------------------------------------------------
    # Low-level HTTP helpers
    # ------------------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, str]] = None,
        files: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute an HTTP request against the ServiceNow REST API.

        Handles rate limiting, error logging, and HIPAA audit trail
        generation for every API interaction.

        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE).
            path: API path relative to instance_url.
            payload: JSON-serializable request body.
            params: URL query parameters.
            files: Multipart file upload payload.

        Returns:
            Parsed JSON response body as a dictionary.

        Raises:
            requests.HTTPError: On 4xx/5xx responses after retries.
        """
        self._enforce_rate_limit()

        url = f"{self.instance_url}{path}"
        headers = {}

        # When uploading files, let requests set the Content-Type boundary
        if files:
            headers["Content-Type"] = None  # type: ignore[assignment]

        response = self.session.request(
            method=method,
            url=url,
            json=payload if not files else None,
            params=params,
            files=files,
            headers=headers,
            timeout=30,
        )

        # -- HIPAA audit trail entry --
        self._log_audit_event(method, path, response.status_code)

        response.raise_for_status()
        return response.json()

    def _log_audit_event(
        self, method: str, path: str, status_code: int
    ) -> None:
        """Write an immutable audit log entry for HIPAA compliance.

        Every interaction with ServiceNow is recorded with a UTC timestamp,
        HTTP method, target path, and response status code. In a production
        deployment this would be forwarded to a tamper-evident log store
        (e.g., Azure Immutable Blob Storage or Splunk).

        Args:
            method: HTTP method used.
            path: API endpoint path.
            status_code: HTTP response status code.
        """
        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": f"{method} {path}",
            "status_code": status_code,
            "instance": self.instance_url,
            "component": "ServiceNowChangeManager",
        }
        logger.info("HIPAA_AUDIT: %s", json.dumps(audit_entry))

    # ------------------------------------------------------------------
    # Change Request lifecycle methods
    # ------------------------------------------------------------------
    def create_change_request(
        self,
        description: str,
        affected_cis: Optional[List[str]] = None,
        risk_assessment: str = "moderate",
        implementation_plan: str = "",
        backout_plan: str = "",
        assigned_to: Optional[str] = None,
        category: str = "Infrastructure",
        priority: int = 3,
        scheduled_start: Optional[datetime] = None,
        scheduled_end: Optional[datetime] = None,
    ) -> str:
        """Create a new ServiceNow change request for a Terraform deployment.

        This method opens a standard change request, populates it with
        deployment metadata, and links the specified Configuration Items
        (CIs) from the CMDB. The CR is created in the 'New' state and
        must be approved through normal channels before apply begins.

        Args:
            description: Human-readable description of the change.
            affected_cis: List of CMDB CI sys_ids affected by the change.
            risk_assessment: Risk level — "high", "moderate", "low", or "none".
            implementation_plan: Step-by-step implementation procedure.
            backout_plan: Rollback procedure in case of failure.
            assigned_to: sys_id of the user assigned to implement the change.
            category: Change category. Defaults to "Infrastructure".
            priority: ServiceNow priority (1=Critical .. 4=Low). Defaults to 3.
            scheduled_start: Planned start datetime. Defaults to now + 1 hour.
            scheduled_end: Planned end datetime. Defaults to start + 2 hours.

        Returns:
            The ServiceNow change request number (e.g., "CHG0012345").
        """
        if scheduled_start is None:
            scheduled_start = datetime.now(timezone.utc) + timedelta(hours=1)
        if scheduled_end is None:
            scheduled_end = scheduled_start + timedelta(hours=2)

        payload: Dict[str, Any] = {
            "type": "standard",
            "category": category,
            "priority": priority,
            "risk": RISK_LEVELS.get(risk_assessment.lower(), 2),
            "short_description": (
                f"Terraform Deployment: {description[:80]}"
            ),
            "description": description,
            "implementation_plan": implementation_plan,
            "backout_plan": backout_plan,
            "start_date": scheduled_start.strftime("%Y-%m-%d %H:%M:%S"),
            "end_date": scheduled_end.strftime("%Y-%m-%d %H:%M:%S"),
            "state": CR_STATES["new"],
        }

        if assigned_to:
            payload["assigned_to"] = assigned_to

        result = self._request("POST", CHANGE_REQUEST_TABLE, payload=payload)
        cr_sys_id = result["result"]["sys_id"]
        cr_number = result["result"]["number"]

        logger.info(
            "Created change request %s (sys_id=%s)", cr_number, cr_sys_id
        )

        # Associate affected Configuration Items with the change request
        if affected_cis:
            self._associate_cis(cr_sys_id, affected_cis)

        return cr_number

    def _associate_cis(
        self, cr_sys_id: str, ci_sys_ids: List[str]
    ) -> None:
        """Link CMDB Configuration Items to a change request.

        Creates records in the task_ci (affected CI) association table
        so that impact analysis dashboards reflect the change correctly.

        Args:
            cr_sys_id: sys_id of the parent change request.
            ci_sys_ids: List of CMDB CI sys_ids to associate.
        """
        for ci_sys_id in ci_sys_ids:
            payload = {
                "task": cr_sys_id,
                "ci_item": ci_sys_id,
            }
            self._request(
                "POST", "/api/now/table/task_ci", payload=payload
            )
            logger.info(
                "Associated CI %s with change request %s",
                ci_sys_id,
                cr_sys_id,
            )

    def update_change_status(
        self,
        cr_number: str,
        status: str,
        work_notes: str = "",
    ) -> Dict[str, Any]:
        """Transition a change request to a new lifecycle state.

        Valid status transitions follow the ServiceNow state model:
            new -> assess -> authorize -> scheduled -> implement
            -> review -> closed

        Args:
            cr_number: The change request number (e.g., "CHG0012345").
            status: Target state name (see CR_STATES keys).
            work_notes: Optional work notes to append to the CR.

        Returns:
            Updated change request record from the API.

        Raises:
            ValueError: If the provided status is not recognized.
        """
        if status.lower() not in CR_STATES:
            raise ValueError(
                f"Invalid status '{status}'. Must be one of: "
                f"{list(CR_STATES.keys())}"
            )

        # Resolve the CR number to a sys_id
        cr_sys_id = self._resolve_cr_sys_id(cr_number)

        payload: Dict[str, Any] = {
            "state": CR_STATES[status.lower()],
        }
        if work_notes:
            payload["work_notes"] = work_notes

        result = self._request(
            "PATCH",
            f"{CHANGE_REQUEST_TABLE}/{cr_sys_id}",
            payload=payload,
        )

        logger.info(
            "Updated change request %s to status '%s'", cr_number, status
        )
        return result.get("result", {})

    def attach_terraform_plan(
        self,
        cr_number: str,
        plan_output: str,
        filename: str = "terraform_plan.txt",
    ) -> str:
        """Attach a Terraform plan output file to a change request.

        The plan output is uploaded as a text attachment so that reviewers
        and auditors can inspect exactly what Terraform intends to change
        before the apply phase executes.

        Args:
            cr_number: The change request number.
            plan_output: Raw text output from `terraform plan`.
            filename: Attachment filename. Defaults to "terraform_plan.txt".

        Returns:
            sys_id of the created attachment record.
        """
        cr_sys_id = self._resolve_cr_sys_id(cr_number)

        params = {
            "table_name": "change_request",
            "table_sys_id": cr_sys_id,
            "file_name": filename,
        }

        # Upload the plan output as a binary file attachment
        files = {
            "file": (filename, plan_output.encode("utf-8"), "text/plain"),
        }

        result = self._request(
            "POST", ATTACHMENT_API, params=params, files=files
        )
        attachment_id = result["result"]["sys_id"]

        logger.info(
            "Attached Terraform plan to %s (attachment_id=%s)",
            cr_number,
            attachment_id,
        )
        return attachment_id

    def close_change_request(
        self,
        cr_number: str,
        close_code: str = "successful",
        close_notes: str = "",
    ) -> Dict[str, Any]:
        """Close a change request after successful Terraform deployment.

        Transitions the CR to the 'closed' state and records the outcome.
        This finalizes the audit trail for the deployment.

        Args:
            cr_number: The change request number.
            close_code: Outcome code — "successful", "successful_with_issues",
                or "unsuccessful". Defaults to "successful".
            close_notes: Implementation notes summarizing the outcome.

        Returns:
            Closed change request record.
        """
        cr_sys_id = self._resolve_cr_sys_id(cr_number)

        payload = {
            "state": CR_STATES["closed"],
            "close_code": close_code,
            "close_notes": close_notes or (
                f"Terraform deployment completed at "
                f"{datetime.now(timezone.utc).isoformat()}"
            ),
        }

        result = self._request(
            "PATCH",
            f"{CHANGE_REQUEST_TABLE}/{cr_sys_id}",
            payload=payload,
        )

        logger.info(
            "Closed change request %s with code '%s'",
            cr_number,
            close_code,
        )
        return result.get("result", {})

    def rollback_change(
        self,
        cr_number: str,
        failure_reason: str,
        trigger_backout: bool = True,
    ) -> Dict[str, Any]:
        """Initiate rollback procedures when a Terraform deployment fails.

        This method:
            1. Updates the CR status to 'implement' with failure notes.
            2. Creates a child incident record for tracking.
            3. Optionally triggers the backout plan workflow.
            4. Closes the CR as unsuccessful.

        Args:
            cr_number: The change request number.
            failure_reason: Description of why the deployment failed.
            trigger_backout: Whether to trigger the automated backout plan
                workflow. Defaults to True.

        Returns:
            Dictionary with rollback details including incident number.
        """
        cr_sys_id = self._resolve_cr_sys_id(cr_number)

        # Step 1: Mark the change as failed in work notes
        self.update_change_status(
            cr_number,
            "implement",
            work_notes=f"DEPLOYMENT FAILED: {failure_reason}",
        )

        # Step 2: Create an incident record linked to the failed change
        incident_payload = {
            "short_description": (
                f"Terraform deployment failure for {cr_number}"
            ),
            "description": failure_reason,
            "urgency": 1,
            "impact": 2,
            "category": "Infrastructure",
            "caused_by": cr_sys_id,
        }
        incident_result = self._request(
            "POST", "/api/now/table/incident", payload=incident_payload
        )
        incident_number = incident_result["result"]["number"]

        logger.warning(
            "Created incident %s for failed change %s",
            incident_number,
            cr_number,
        )

        # Step 3: Trigger the backout plan workflow if requested
        if trigger_backout:
            self._trigger_backout_workflow(cr_sys_id, cr_number)

        # Step 4: Close the change request as unsuccessful
        self.close_change_request(
            cr_number,
            close_code="unsuccessful",
            close_notes=(
                f"Deployment failed: {failure_reason}. "
                f"Incident {incident_number} created. "
                f"Backout plan {'executed' if trigger_backout else 'skipped'}."
            ),
        )

        return {
            "cr_number": cr_number,
            "incident_number": incident_number,
            "backout_triggered": trigger_backout,
            "failure_reason": failure_reason,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _resolve_cr_sys_id(self, cr_number: str) -> str:
        """Look up the sys_id of a change request by its number.

        Args:
            cr_number: The human-readable CR number (e.g., "CHG0012345").

        Returns:
            The sys_id string.

        Raises:
            ValueError: If the CR number does not exist.
        """
        params = {
            "sysparm_query": f"number={cr_number}",
            "sysparm_fields": "sys_id",
            "sysparm_limit": "1",
        }
        result = self._request("GET", CHANGE_REQUEST_TABLE, params=params)
        records = result.get("result", [])

        if not records:
            raise ValueError(
                f"Change request '{cr_number}' not found in ServiceNow."
            )

        return records[0]["sys_id"]

    def _trigger_backout_workflow(
        self, cr_sys_id: str, cr_number: str
    ) -> None:
        """Trigger the backout/rollback workflow in ServiceNow.

        This invokes the ServiceNow Workflow REST API to start the
        pre-configured backout plan workflow associated with the
        change request.

        Args:
            cr_sys_id: sys_id of the change request.
            cr_number: Human-readable CR number (for logging).
        """
        workflow_payload = {
            "context": {
                "table": "change_request",
                "sys_id": cr_sys_id,
            },
            "operation": "execute_backout_plan",
        }

        try:
            self._request(
                "POST",
                "/api/now/workflow/execute",
                payload=workflow_payload,
            )
            logger.info("Backout workflow triggered for %s", cr_number)
        except requests.HTTPError as exc:
            # Log but do not re-raise -- the incident is already created
            logger.error(
                "Failed to trigger backout workflow for %s: %s",
                cr_number,
                exc,
            )
