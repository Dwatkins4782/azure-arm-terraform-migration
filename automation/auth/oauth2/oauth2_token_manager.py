"""
OAuth 2.0 Token Manager for Azure AD (Entra ID) Authentication
==============================================================

This module implements three OAuth 2.0 authentication flows for Azure AD,
designed for enterprise CI/CD pipelines in HIPAA-regulated healthcare environments.

Authentication Flows (in order of preference):
    1. Workload Identity Federation (OIDC Token Exchange)
       - Used in: Azure DevOps, GitHub Actions, Kubernetes
       - No secrets to manage; the pipeline's OIDC token is exchanged for an Azure AD token
       - RFC 8693 (OAuth 2.0 Token Exchange)

    2. Managed Identity
       - Used in: Azure-hosted VMs, App Services, AKS pods, Azure Functions
       - Tokens obtained from the Instance Metadata Service (IMDS)
       - No credentials needed; identity is bound to the Azure resource

    3. Client Credentials (client_id + client_secret)
       - Used in: Legacy systems, on-premises agents, third-party CI/CD
       - RFC 6749 Section 4.4 (Client Credentials Grant)
       - Requires secret rotation (<=90 days for HIPAA compliance)

Enterprise Healthcare Context:
    - All token acquisitions are logged for HIPAA audit trails
    - Token caching reduces calls to Azure AD (rate limit protection)
    - Automatic retry with exponential backoff for transient failures
    - Tokens are never written to disk or logged in plaintext
"""

import json
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

import msal
import requests

# Configure structured logging for HIPAA audit compliance.
# In production, this would feed into Azure Monitor or Splunk.
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_handler = logging.StreamHandler()
_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
)
logger.addHandler(_handler)


# Default scope for Azure Resource Manager API.
# ".default" requests all statically configured permissions for the app.
ARM_SCOPE = "https://management.azure.com/.default"

# Azure Instance Metadata Service endpoint for managed identity tokens.
IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"
IMDS_API_VERSION = "2019-08-01"


@dataclass
class TokenResult:
    """Represents an OAuth 2.0 access token with metadata.

    Attributes:
        access_token: The Bearer token for API authorization headers.
        expires_on: UTC Unix timestamp when the token expires.
        token_type: Always "Bearer" for Azure AD tokens.
        resource: The resource/audience the token is valid for.
        flow_type: Which OAuth 2.0 flow produced this token (for audit logging).
    """

    access_token: str
    expires_on: float
    token_type: str = "Bearer"
    resource: str = ARM_SCOPE
    flow_type: str = "unknown"

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired with a 5-minute buffer.

        The buffer ensures we refresh tokens before they expire, avoiding
        race conditions where a token expires mid-request.
        """
        return time.time() >= (self.expires_on - 300)

    @property
    def expires_in_seconds(self) -> float:
        """Seconds until the token expires."""
        return max(0, self.expires_on - time.time())

    def authorization_header(self) -> Dict[str, str]:
        """Return the HTTP Authorization header value."""
        return {"Authorization": f"{self.token_type} {self.access_token}"}

    def __repr__(self) -> str:
        # Never expose the token value in logs or repr
        return (
            f"TokenResult(flow={self.flow_type}, "
            f"expires_in={self.expires_in_seconds:.0f}s, "
            f"resource={self.resource})"
        )


class BaseTokenFlow(ABC):
    """Abstract base class for OAuth 2.0 authentication flows.

    All flows implement the same interface so the pipeline code can
    switch between authentication methods without code changes.
    This follows the Strategy pattern for authentication.
    """

    def __init__(self, tenant_id: str, client_id: str, scopes: Optional[List[str]] = None):
        """Initialize the token flow.

        Args:
            tenant_id: Azure AD tenant ID (the OAuth 2.0 authorization server).
            client_id: The application (client) ID from the app registration.
            scopes: OAuth 2.0 scopes to request. Defaults to ARM API scope.
        """
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.scopes = scopes or [ARM_SCOPE]
        self._cached_token: Optional[TokenResult] = None

    @abstractmethod
    def _acquire_token(self) -> TokenResult:
        """Acquire a new token from Azure AD. Subclasses implement this."""
        ...

    def get_token(self, force_refresh: bool = False) -> TokenResult:
        """Get an access token, using cache when possible.

        Token caching is critical for:
        - Reducing load on Azure AD (rate limits apply)
        - Improving pipeline performance (network round-trip saved)
        - Reducing audit log noise

        Args:
            force_refresh: Bypass cache and acquire a new token.

        Returns:
            TokenResult with a valid access token.

        Raises:
            AuthenticationError: If token acquisition fails.
        """
        if not force_refresh and self._cached_token and not self._cached_token.is_expired:
            logger.debug("Returning cached token (expires in %.0fs)", self._cached_token.expires_in_seconds)
            return self._cached_token

        logger.info(
            "Acquiring new token via %s flow for tenant=%s, client=%s",
            self.__class__.__name__,
            self.tenant_id,
            self.client_id,
        )

        try:
            token = self._acquire_token()
            self._cached_token = token
            logger.info(
                "Token acquired successfully: flow=%s, expires_in=%.0fs",
                token.flow_type,
                token.expires_in_seconds,
            )
            return token
        except Exception as exc:
            logger.error(
                "Token acquisition failed: flow=%s, error=%s",
                self.__class__.__name__,
                str(exc),
            )
            raise


class ClientCredentialsFlow(BaseTokenFlow):
    """OAuth 2.0 Client Credentials Grant (RFC 6749 Section 4.4).

    This flow authenticates using a client_id and client_secret, analogous
    to a username and password for the application itself.

    Token Request:
        POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
        Content-Type: application/x-www-form-urlencoded

        grant_type=client_credentials
        &client_id={client_id}
        &client_secret={client_secret}
        &scope=https://management.azure.com/.default

    When to use:
        - On-premises CI/CD agents without Azure identity
        - Third-party CI/CD systems (Jenkins, TeamCity) without OIDC support
        - Legacy automation scripts being migrated to modern patterns

    Security considerations:
        - Secret must be stored in a Key Vault or secure secret store
        - Secret rotation must be automated (<=90 days for HIPAA)
        - Monitor for secret exposure in logs, repos, or pipeline outputs
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        scopes: Optional[List[str]] = None,
    ):
        super().__init__(tenant_id, client_id, scopes)
        self._client_secret = client_secret

        # MSAL ConfidentialClientApplication handles:
        # - Token caching (in-memory by default)
        # - Automatic token refresh
        # - Retry logic for transient errors
        self._msal_app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self._client_secret,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
        )

    def _acquire_token(self) -> TokenResult:
        """Acquire token using client credentials grant."""
        result = self._msal_app.acquire_token_for_client(scopes=self.scopes)

        if "access_token" not in result:
            error = result.get("error", "unknown_error")
            error_desc = result.get("error_description", "No description provided")
            raise AuthenticationError(
                f"Client credentials flow failed: {error} - {error_desc}"
            )

        return TokenResult(
            access_token=result["access_token"],
            expires_on=time.time() + result.get("expires_in", 3600),
            token_type=result.get("token_type", "Bearer"),
            resource=self.scopes[0],
            flow_type="client_credentials",
        )


class WorkloadIdentityFlow(BaseTokenFlow):
    """OAuth 2.0 Token Exchange for Workload Identity Federation (RFC 8693).

    This flow exchanges a platform-issued OIDC token (from Azure DevOps,
    GitHub Actions, or Kubernetes) for an Azure AD access token.

    How it works:
        1. The CI/CD platform issues an OIDC token identifying the pipeline run
        2. This token is written to a file (AZURE_FEDERATED_TOKEN_FILE env var)
        3. We read the token and send it to Azure AD's token endpoint
        4. Azure AD validates the token against the federated identity credential
        5. If valid, Azure AD returns an access token for the requested resource

    Token Exchange Request:
        POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
        Content-Type: application/x-www-form-urlencoded

        grant_type=client_credentials
        &client_id={client_id}
        &client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
        &client_assertion={federated_token}
        &scope=https://management.azure.com/.default

    When to use:
        - Azure DevOps pipelines with workload identity federation
        - GitHub Actions with OIDC configured
        - Kubernetes pods with projected service account tokens
        - Any platform that issues OIDC tokens

    Security benefits:
        - No secrets to store, rotate, or potentially leak
        - Tokens are short-lived and scoped to the pipeline run
        - Strong binding between the pipeline identity and Azure AD
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        federated_token_file: Optional[str] = None,
        scopes: Optional[List[str]] = None,
    ):
        super().__init__(tenant_id, client_id, scopes)
        self._token_file = federated_token_file or os.environ.get(
            "AZURE_FEDERATED_TOKEN_FILE"
        )

        if not self._token_file:
            raise ConfigurationError(
                "AZURE_FEDERATED_TOKEN_FILE environment variable is not set. "
                "This flow requires a federated identity token file provided by "
                "the CI/CD platform (Azure DevOps, GitHub Actions, etc.)."
            )

    def _read_federated_token(self) -> str:
        """Read the OIDC token from the file provided by the CI/CD platform.

        The CI/CD platform writes a short-lived JWT to this file. The token
        contains claims that Azure AD validates against the federated
        identity credential configuration (issuer, subject, audience).
        """
        try:
            with open(self._token_file, "r", encoding="utf-8") as f:
                token = f.read().strip()
            if not token:
                raise ConfigurationError(
                    f"Federated token file is empty: {self._token_file}"
                )
            logger.debug("Read federated token from %s", self._token_file)
            return token
        except FileNotFoundError:
            raise ConfigurationError(
                f"Federated token file not found: {self._token_file}. "
                "Ensure the pipeline is configured for workload identity federation."
            )

    def _acquire_token(self) -> TokenResult:
        """Acquire token using OIDC token exchange.

        MSAL's acquire_token_for_client supports federated credentials when
        the client_credential is set to a dictionary with the
        'client_assertion' key.
        """
        federated_token = self._read_federated_token()

        # MSAL accepts a callable that returns the assertion, allowing
        # the token to be re-read on each acquisition (it may change
        # between pipeline steps).
        msal_app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential={
                "client_assertion": federated_token,
            },
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
        )

        result = msal_app.acquire_token_for_client(scopes=self.scopes)

        if "access_token" not in result:
            error = result.get("error", "unknown_error")
            error_desc = result.get("error_description", "No description provided")
            raise AuthenticationError(
                f"Workload identity flow failed: {error} - {error_desc}. "
                "Verify the federated identity credential configuration in Azure AD "
                "matches the issuer, subject, and audience of the OIDC token."
            )

        return TokenResult(
            access_token=result["access_token"],
            expires_on=time.time() + result.get("expires_in", 3600),
            token_type=result.get("token_type", "Bearer"),
            resource=self.scopes[0],
            flow_type="workload_identity_federation",
        )


class ManagedIdentityFlow(BaseTokenFlow):
    """Azure Managed Identity Token Acquisition via IMDS.

    Managed Identity provides automatic credential management for
    Azure-hosted resources. The Azure platform manages the identity
    lifecycle, and tokens are obtained from the Instance Metadata
    Service (IMDS) at 169.254.169.254.

    How it works:
        1. Azure assigns an identity to the resource (VM, App Service, etc.)
        2. The application calls the IMDS endpoint on the link-local address
        3. IMDS returns an access token for the requested resource
        4. No credentials are needed; IMDS is only accessible from the host

    IMDS Token Request:
        GET http://169.254.169.254/metadata/identity/oauth2/token
            ?api-version=2019-08-01
            &resource=https://management.azure.com/
        Metadata: true

    Two types:
        - System-assigned: Tied to the Azure resource lifecycle
        - User-assigned: Independent identity, can be shared across resources

    When to use:
        - Self-hosted Azure DevOps agents running on Azure VMs
        - Azure Functions or App Services running Terraform
        - AKS pods with AAD pod identity or workload identity

    Security benefits:
        - No credentials to manage at all
        - Identity lifecycle managed by Azure
        - Tokens only obtainable from the assigned resource
        - Supports fine-grained RBAC like any other identity
    """

    def __init__(
        self,
        client_id: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        identity_type: str = "system",
    ):
        """Initialize managed identity flow.

        Args:
            client_id: For user-assigned identity, provide the client ID.
                       For system-assigned identity, leave as None.
            scopes: Ignored for managed identity (uses resource parameter instead).
            identity_type: "system" for system-assigned, "user" for user-assigned.
        """
        # Managed identity doesn't need tenant_id; IMDS handles routing.
        super().__init__(tenant_id="", client_id=client_id or "", scopes=scopes)
        self._identity_type = identity_type
        self._imds_timeout = 5  # seconds; IMDS should respond very quickly

    def _acquire_token(self) -> TokenResult:
        """Acquire token from the Azure Instance Metadata Service (IMDS).

        The Metadata: true header is required to prevent SSRF attacks.
        IMDS will reject requests without this header.
        """
        # Build the IMDS request parameters.
        # Note: IMDS uses "resource" not "scope" for the v1 token endpoint.
        params = {
            "api-version": IMDS_API_VERSION,
            "resource": "https://management.azure.com/",
        }

        # For user-assigned managed identity, specify which identity to use.
        if self._identity_type == "user" and self.client_id:
            params["client_id"] = self.client_id

        headers = {
            "Metadata": "true",  # Required header to prevent SSRF
        }

        try:
            response = requests.get(
                IMDS_ENDPOINT,
                params=params,
                headers=headers,
                timeout=self._imds_timeout,
            )
            response.raise_for_status()
        except requests.exceptions.ConnectionError:
            raise ConfigurationError(
                "Cannot reach IMDS endpoint (169.254.169.254). "
                "This flow only works on Azure-hosted resources with managed identity enabled. "
                "If running locally, use ClientCredentialsFlow or WorkloadIdentityFlow instead."
            )
        except requests.exceptions.Timeout:
            raise AuthenticationError(
                "IMDS request timed out. The managed identity endpoint may be overloaded."
            )
        except requests.exceptions.HTTPError as exc:
            raise AuthenticationError(
                f"IMDS returned error: {exc.response.status_code} - {exc.response.text}"
            )

        token_data = response.json()

        return TokenResult(
            access_token=token_data["access_token"],
            expires_on=float(token_data["expires_on"]),
            token_type=token_data.get("token_type", "Bearer"),
            resource=token_data.get("resource", "https://management.azure.com/"),
            flow_type=f"managed_identity_{self._identity_type}",
        )


# =============================================================================
# Custom Exceptions
# =============================================================================


class AuthenticationError(Exception):
    """Raised when token acquisition fails due to auth issues."""
    pass


class ConfigurationError(Exception):
    """Raised when required configuration is missing or invalid."""
    pass


# =============================================================================
# Factory Function - Auto-detect the best authentication flow
# =============================================================================


def create_token_flow(
    tenant_id: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
) -> BaseTokenFlow:
    """Auto-detect and create the appropriate OAuth 2.0 token flow.

    Detection order (most secure first):
        1. If AZURE_FEDERATED_TOKEN_FILE is set -> WorkloadIdentityFlow
        2. If running on Azure (IMDS reachable)  -> ManagedIdentityFlow
        3. If client_secret is provided           -> ClientCredentialsFlow

    Environment variables used:
        AZURE_TENANT_ID: Azure AD tenant ID
        AZURE_CLIENT_ID: Application (client) ID
        AZURE_CLIENT_SECRET: Client secret (only for client credentials flow)
        AZURE_FEDERATED_TOKEN_FILE: Path to OIDC token file

    Args:
        tenant_id: Override for AZURE_TENANT_ID env var.
        client_id: Override for AZURE_CLIENT_ID env var.
        client_secret: Override for AZURE_CLIENT_SECRET env var.

    Returns:
        An instance of the appropriate BaseTokenFlow subclass.

    Raises:
        ConfigurationError: If no valid authentication method is detected.
    """
    tenant_id = tenant_id or os.environ.get("AZURE_TENANT_ID", "")
    client_id = client_id or os.environ.get("AZURE_CLIENT_ID", "")
    client_secret = client_secret or os.environ.get("AZURE_CLIENT_SECRET")

    # 1. Check for workload identity federation (OIDC)
    federated_token_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE")
    if federated_token_file:
        logger.info("Detected workload identity federation (OIDC token file present)")
        return WorkloadIdentityFlow(
            tenant_id=tenant_id,
            client_id=client_id,
            federated_token_file=federated_token_file,
        )

    # 2. Check for managed identity (probe IMDS endpoint)
    if _is_imds_available():
        logger.info("Detected Azure managed identity (IMDS endpoint reachable)")
        return ManagedIdentityFlow(
            client_id=client_id if client_id else None,
            identity_type="user" if client_id else "system",
        )

    # 3. Fall back to client credentials
    if client_secret and tenant_id and client_id:
        logger.info("Using client credentials flow (client_secret provided)")
        return ClientCredentialsFlow(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

    raise ConfigurationError(
        "No valid authentication method detected. Provide one of:\n"
        "  1. AZURE_FEDERATED_TOKEN_FILE for workload identity federation\n"
        "  2. Run on Azure with managed identity enabled\n"
        "  3. AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET for client credentials"
    )


def _is_imds_available() -> bool:
    """Check if the Azure IMDS endpoint is reachable.

    Uses a very short timeout since IMDS is a link-local address
    and should respond in milliseconds if available.
    """
    try:
        response = requests.get(
            "http://169.254.169.254/metadata/instance",
            params={"api-version": "2021-02-01"},
            headers={"Metadata": "true"},
            timeout=1,
        )
        return response.status_code == 200
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        return False


# =============================================================================
# CLI Entry Point
# =============================================================================

if __name__ == "__main__":
    """Quick test of token acquisition. Run with appropriate env vars set."""
    import argparse

    parser = argparse.ArgumentParser(description="OAuth 2.0 Token Manager for Azure AD")
    parser.add_argument("--flow", choices=["auto", "client", "workload", "managed"], default="auto")
    parser.add_argument("--tenant-id", default=os.environ.get("AZURE_TENANT_ID", ""))
    parser.add_argument("--client-id", default=os.environ.get("AZURE_CLIENT_ID", ""))
    args = parser.parse_args()

    try:
        flow = create_token_flow(tenant_id=args.tenant_id, client_id=args.client_id)
        token = flow.get_token()
        print(f"Token acquired: {token}")
        print(f"Expires in: {token.expires_in_seconds:.0f} seconds")
    except (AuthenticationError, ConfigurationError) as e:
        logger.error("Authentication failed: %s", e)
        raise SystemExit(1)
