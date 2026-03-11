"""
SAML Service Provider (SP) Configuration for Enterprise SSO
============================================================

This module implements a SAML 2.0 Service Provider for integrating with
Azure AD (Entra ID) as the Identity Provider (IdP) in healthcare environments.

SAML 2.0 Key Concepts:
    Identity Provider (IdP):
        The system that authenticates users and issues SAML assertions.
        In this project, Azure AD is the IdP. It holds the user directory
        and performs the actual authentication (password, MFA, etc.).

    Service Provider (SP):
        The application that relies on the IdP for authentication.
        This module implements the SP side. The SP trusts assertions from
        the IdP and uses them to establish user sessions.

    SAML Assertion:
        An XML document issued by the IdP containing:
        - Authentication statement (when and how the user authenticated)
        - Attribute statement (user claims: name, email, groups, etc.)
        - Conditions (validity period, audience restriction)
        The assertion is digitally signed by the IdP for integrity.

    Assertion Consumer Service (ACS) URL:
        The SP endpoint that receives SAML responses from the IdP.
        After authentication, the IdP POST-redirects the user's browser
        to this URL with the SAML response in the request body.

    SAML Bindings:
        How SAML messages are transported between IdP and SP:
        - HTTP-POST: SAML message in an HTML form auto-submitted via browser
        - HTTP-Redirect: SAML message in URL query parameters (deflated + base64)
        - HTTP-Artifact: Reference exchanged via browser, actual message via back-channel

    SP-Initiated Flow (most common):
        1. User visits the SP application
        2. SP generates AuthnRequest and redirects user to IdP
        3. IdP authenticates user (login page, MFA, etc.)
        4. IdP creates SAML Response with assertion
        5. IdP POST-redirects user back to SP's ACS URL
        6. SP validates the response signature and assertion
        7. SP extracts user attributes and creates a session

    IdP-Initiated Flow:
        1. User logs into IdP portal (e.g., Azure My Apps)
        2. User clicks the application tile
        3. IdP sends SAML Response directly to SP's ACS URL
        4. SP validates and creates session (no AuthnRequest was sent)

Enterprise Healthcare Context:
    - SAML assertions carry HIPAA-relevant attributes (department, role)
    - Group claims determine access to PHI systems
    - Assertion signatures must be validated to prevent tampering
    - Session timeouts must align with HIPAA access controls
"""

import base64
import logging
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlencode

from lxml import etree
from signxml import XMLSigner, XMLVerifier
from signxml.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

# SAML 2.0 XML Namespaces
SAML_NAMESPACES = {
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
}


@dataclass
class SAMLUserClaims:
    """Parsed user claims extracted from a SAML assertion.

    In healthcare environments, these claims drive authorization decisions
    for access to PHI (Protected Health Information).

    Attributes:
        name_id: The primary user identifier from the SAML Subject.
        email: User's email address (often the UPN in Azure AD).
        display_name: Human-readable name for audit logs.
        first_name: Given name.
        last_name: Surname.
        groups: Azure AD group memberships (used for RBAC).
        employee_id: HR system identifier (for HIPAA audit trails).
        department: Organizational department (for access control).
        roles: Application-specific roles from the IdP.
        raw_attributes: All attributes from the assertion for extensibility.
    """

    name_id: str = ""
    email: str = ""
    display_name: str = ""
    first_name: str = ""
    last_name: str = ""
    groups: List[str] = field(default_factory=list)
    employee_id: str = ""
    department: str = ""
    roles: List[str] = field(default_factory=list)
    raw_attributes: Dict[str, List[str]] = field(default_factory=dict)


class SAMLServiceProvider:
    """SAML 2.0 Service Provider implementation.

    This class handles the SP side of SAML SSO, including metadata
    generation, assertion parsing, signature validation, and claims extraction.

    Args:
        entity_id: Unique identifier for this SP (usually the application URL).
                   The IdP uses this to identify which SP the assertion is for.
        acs_url: Assertion Consumer Service URL. The endpoint where the IdP
                 sends the SAML response after authentication.
        slo_url: Single Logout URL. Optional endpoint for coordinated logout.
        sp_cert_pem: The SP's X.509 certificate in PEM format. Used by the IdP
                     to encrypt assertions meant for this SP.
        sp_key_pem: The SP's private key in PEM format. Used to decrypt
                    encrypted assertions and sign AuthnRequests.
        idp_cert_pem: The IdP's X.509 certificate in PEM format. Used to
                      validate the digital signature on SAML responses.
        idp_sso_url: The IdP's SSO endpoint URL where AuthnRequests are sent.
        want_assertions_signed: Whether to require signed assertions (always True
                                in healthcare/HIPAA environments).
    """

    def __init__(
        self,
        entity_id: str,
        acs_url: str,
        slo_url: Optional[str] = None,
        sp_cert_pem: Optional[str] = None,
        sp_key_pem: Optional[str] = None,
        idp_cert_pem: Optional[str] = None,
        idp_sso_url: Optional[str] = None,
        want_assertions_signed: bool = True,
    ):
        self.entity_id = entity_id
        self.acs_url = acs_url
        self.slo_url = slo_url
        self.sp_cert_pem = sp_cert_pem
        self.sp_key_pem = sp_key_pem
        self.idp_cert_pem = idp_cert_pem
        self.idp_sso_url = idp_sso_url
        self.want_assertions_signed = want_assertions_signed

    def generate_metadata(self) -> str:
        """Generate SAML SP Metadata XML document.

        SP metadata is an XML document that describes the SP's capabilities
        and endpoints. The IdP imports this to configure the trust relationship.

        The metadata includes:
        - EntityDescriptor: Root element with the SP's entity ID
        - SPSSODescriptor: Describes the SP's SAML capabilities
        - KeyDescriptor: The SP's certificate for encryption and signing
        - AssertionConsumerService: The ACS URL and binding type
        - NameIDFormat: What format the SP expects for the user identifier

        Returns:
            XML string of the SP metadata document.
        """
        md_ns = SAML_NAMESPACES["md"]
        ds_ns = SAML_NAMESPACES["ds"]

        # Root EntityDescriptor element
        entity_descriptor = etree.Element(
            f"{{{md_ns}}}EntityDescriptor",
            nsmap={"md": md_ns, "ds": ds_ns},
            attrib={"entityID": self.entity_id},
        )

        # SPSSODescriptor - describes our SP capabilities
        sp_sso = etree.SubElement(
            entity_descriptor,
            f"{{{md_ns}}}SPSSODescriptor",
            attrib={
                "AuthnRequestsSigned": "true" if self.sp_key_pem else "false",
                "WantAssertionsSigned": str(self.want_assertions_signed).lower(),
                "protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
            },
        )

        # KeyDescriptor for signing - IdP uses this to verify our AuthnRequests
        if self.sp_cert_pem:
            for use in ["signing", "encryption"]:
                key_descriptor = etree.SubElement(
                    sp_sso, f"{{{md_ns}}}KeyDescriptor", attrib={"use": use}
                )
                key_info = etree.SubElement(key_descriptor, f"{{{ds_ns}}}KeyInfo")
                x509_data = etree.SubElement(key_info, f"{{{ds_ns}}}X509Data")
                x509_cert = etree.SubElement(x509_data, f"{{{ds_ns}}}X509Certificate")
                # Strip PEM headers and whitespace for the XML element
                cert_body = (
                    self.sp_cert_pem.replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .strip()
                )
                x509_cert.text = cert_body

        # Single Logout Service (optional but recommended for session management)
        if self.slo_url:
            etree.SubElement(
                sp_sso,
                f"{{{md_ns}}}SingleLogoutService",
                attrib={
                    "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                    "Location": self.slo_url,
                },
            )

        # NameID Format - specifies how the SP wants the user to be identified.
        # emailAddress is standard for Azure AD integration.
        name_id_format = etree.SubElement(sp_sso, f"{{{md_ns}}}NameIDFormat")
        name_id_format.text = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

        # Assertion Consumer Service - the endpoint that receives the SAML response.
        # HTTP-POST binding means the response is delivered as a form POST.
        etree.SubElement(
            sp_sso,
            f"{{{md_ns}}}AssertionConsumerService",
            attrib={
                "Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "Location": self.acs_url,
                "index": "0",
                "isDefault": "true",
            },
        )

        return etree.tostring(
            entity_descriptor, pretty_print=True, xml_declaration=True, encoding="UTF-8"
        ).decode("utf-8")

    def parse_assertion(self, saml_response_b64: str) -> etree._Element:
        """Parse and decode a SAML response from the IdP.

        The SAML response arrives as a Base64-encoded XML document in the
        HTTP POST body (SAMLResponse form parameter). This method:
        1. Base64-decodes the response
        2. Parses the XML
        3. Returns the parsed XML tree for further validation

        Args:
            saml_response_b64: Base64-encoded SAML response from the IdP.

        Returns:
            Parsed XML element tree of the SAML response.

        Raises:
            SAMLValidationError: If the response cannot be decoded or parsed.
        """
        try:
            # Decode the Base64-encoded SAML response
            xml_bytes = base64.b64decode(saml_response_b64)
        except Exception as exc:
            raise SAMLValidationError(f"Failed to Base64-decode SAML response: {exc}")

        try:
            # Parse the XML with security-safe parser (no entity expansion)
            parser = etree.XMLParser(
                resolve_entities=False,  # Prevent XXE attacks
                no_network=True,  # Prevent external entity fetching
                dtd_validation=False,
            )
            root = etree.fromstring(xml_bytes, parser=parser)
        except etree.XMLSyntaxError as exc:
            raise SAMLValidationError(f"Invalid SAML response XML: {exc}")

        # Verify this is actually a SAML Response element
        expected_tag = f"{{{SAML_NAMESPACES['samlp']}}}Response"
        if root.tag != expected_tag:
            raise SAMLValidationError(
                f"Expected SAML Response element, got: {root.tag}"
            )

        # Check the top-level status code
        status_code_elem = root.find(
            ".//samlp:Status/samlp:StatusCode", SAML_NAMESPACES
        )
        if status_code_elem is not None:
            status = status_code_elem.get("Value", "")
            if status != "urn:oasis:names:tc:SAML:2.0:status:Success":
                raise SAMLValidationError(f"SAML response indicates failure: {status}")

        logger.info("SAML response parsed successfully")
        return root

    def validate_signature(self, saml_response_xml: etree._Element) -> bool:
        """Validate the XML digital signature on the SAML response.

        SAML responses are signed by the IdP using XML Signature (XMLDSig).
        Signature validation proves:
        1. The response was issued by the trusted IdP (authenticity)
        2. The response has not been modified in transit (integrity)

        The IdP signs the response with its private key. We validate
        using the IdP's public certificate (idp_cert_pem).

        In HIPAA environments, signature validation is MANDATORY.
        Accepting unsigned or invalidly signed assertions would allow
        an attacker to forge user identities and gain unauthorized
        access to PHI.

        Args:
            saml_response_xml: Parsed SAML response XML element.

        Returns:
            True if the signature is valid.

        Raises:
            SAMLValidationError: If signature validation fails.
        """
        if not self.idp_cert_pem:
            raise SAMLValidationError(
                "IdP certificate not configured. Cannot validate SAML signature. "
                "Signature validation is mandatory in HIPAA environments."
            )

        try:
            # XMLVerifier validates the XML digital signature using the
            # IdP's X.509 certificate. It checks:
            # - The signature algorithm and digest are valid
            # - The signed content matches the actual XML content
            # - The certificate matches the one we trust
            verified_data = XMLVerifier().verify(
                saml_response_xml,
                x509_cert=self.idp_cert_pem,
            )
            logger.info("SAML response signature validated successfully")
            return True

        except InvalidSignature as exc:
            raise SAMLValidationError(
                f"SAML response signature validation failed: {exc}. "
                "This could indicate a tampered response, wrong IdP certificate, "
                "or a man-in-the-middle attack."
            )
        except Exception as exc:
            raise SAMLValidationError(
                f"Unexpected error during signature validation: {exc}"
            )

    def extract_claims(self, saml_response_xml: etree._Element) -> SAMLUserClaims:
        """Extract user claims from the SAML assertion.

        The SAML assertion's AttributeStatement contains name-value pairs
        (claims) about the authenticated user. Azure AD maps these from
        the user directory and any claims mapping policies.

        Standard Azure AD SAML claims:
            http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name
            http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
            http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname
            http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname
            http://schemas.microsoft.com/ws/2008/06/identity/claims/groups
            http://schemas.microsoft.com/ws/2008/06/identity/claims/role

        Custom claims (configured via claims mapping policy):
            employeeid - HR system identifier for HIPAA audit
            department - Organizational unit for access control

        Args:
            saml_response_xml: Parsed and signature-validated SAML response.

        Returns:
            SAMLUserClaims with extracted user attributes.

        Raises:
            SAMLValidationError: If the assertion or required claims are missing.
        """
        # Find the Assertion element within the Response
        assertion = saml_response_xml.find(".//saml:Assertion", SAML_NAMESPACES)
        if assertion is None:
            raise SAMLValidationError("No SAML Assertion found in response")

        # Validate assertion conditions (time validity, audience)
        self._validate_conditions(assertion)

        # Extract the NameID (primary subject identifier)
        name_id_elem = assertion.find(".//saml:Subject/saml:NameID", SAML_NAMESPACES)
        name_id = name_id_elem.text.strip() if name_id_elem is not None and name_id_elem.text else ""

        # Extract all attributes into a dictionary
        raw_attributes: Dict[str, List[str]] = {}
        attr_statement = assertion.find(".//saml:AttributeStatement", SAML_NAMESPACES)

        if attr_statement is not None:
            for attr in attr_statement.findall("saml:Attribute", SAML_NAMESPACES):
                attr_name = attr.get("Name", "")
                values = []
                for attr_value in attr.findall("saml:AttributeValue", SAML_NAMESPACES):
                    if attr_value.text:
                        values.append(attr_value.text.strip())
                if attr_name and values:
                    raw_attributes[attr_name] = values

        # Map well-known claim URIs to structured fields
        claims = SAMLUserClaims(
            name_id=name_id,
            email=self._get_claim(
                raw_attributes,
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            ),
            display_name=self._get_claim(
                raw_attributes,
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
            ),
            first_name=self._get_claim(
                raw_attributes,
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
            ),
            last_name=self._get_claim(
                raw_attributes,
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
            ),
            groups=self._get_claim_list(
                raw_attributes,
                "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
            ),
            roles=self._get_claim_list(
                raw_attributes,
                "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
            ),
            employee_id=self._get_claim(raw_attributes, "employeeid"),
            department=self._get_claim(raw_attributes, "department"),
            raw_attributes=raw_attributes,
        )

        logger.info(
            "Extracted SAML claims for user: name_id=%s, email=%s, groups=%d",
            claims.name_id,
            claims.email,
            len(claims.groups),
        )
        return claims

    def _validate_conditions(self, assertion: etree._Element) -> None:
        """Validate the assertion's Conditions element.

        Conditions specify:
        - NotBefore / NotOnOrAfter: The time window the assertion is valid
        - AudienceRestriction: Which SP entity IDs the assertion is intended for

        Failing to validate conditions would allow:
        - Replay attacks (using an expired assertion)
        - Audience confusion (assertion meant for a different SP)
        """
        conditions = assertion.find(".//saml:Conditions", SAML_NAMESPACES)
        if conditions is None:
            logger.warning("No Conditions element in assertion (less secure)")
            return

        now = datetime.now(timezone.utc)

        # Validate time window with a 5-minute clock skew tolerance
        not_before = conditions.get("NotBefore")
        if not_before:
            nb_time = datetime.fromisoformat(not_before.replace("Z", "+00:00"))
            skew_seconds = 300  # 5 minutes tolerance for clock drift
            if now < nb_time.replace(tzinfo=timezone.utc) and (
                nb_time.replace(tzinfo=timezone.utc) - now
            ).total_seconds() > skew_seconds:
                raise SAMLValidationError(
                    f"Assertion not yet valid. NotBefore={not_before}, now={now.isoformat()}"
                )

        not_on_or_after = conditions.get("NotOnOrAfter")
        if not_on_or_after:
            noa_time = datetime.fromisoformat(not_on_or_after.replace("Z", "+00:00"))
            if now >= noa_time.replace(tzinfo=timezone.utc):
                raise SAMLValidationError(
                    f"Assertion has expired. NotOnOrAfter={not_on_or_after}, now={now.isoformat()}"
                )

        # Validate audience restriction
        audience_elem = conditions.find(
            ".//saml:AudienceRestriction/saml:Audience", SAML_NAMESPACES
        )
        if audience_elem is not None and audience_elem.text:
            if audience_elem.text.strip() != self.entity_id:
                raise SAMLValidationError(
                    f"Audience mismatch. Expected={self.entity_id}, "
                    f"Got={audience_elem.text.strip()}"
                )

    @staticmethod
    def _get_claim(attributes: Dict[str, List[str]], claim_uri: str) -> str:
        """Get a single-valued claim from the attributes dictionary."""
        values = attributes.get(claim_uri, [])
        return values[0] if values else ""

    @staticmethod
    def _get_claim_list(attributes: Dict[str, List[str]], claim_uri: str) -> List[str]:
        """Get a multi-valued claim from the attributes dictionary."""
        return attributes.get(claim_uri, [])


class SAMLValidationError(Exception):
    """Raised when SAML response validation fails."""
    pass
