"""The external, privileged owner-authority boundary.

The audit verdict ``CANARY_OWNER_ROOTED_WITNESS_AUDIT_FAIL`` was returned
because one ordinary caller could choose a phrase, compute its digest, create
the authorization state, retain the expected digest, mint a receipt and pass
the pre-effect gate.  Every one of those steps lived on the same side of the
trust boundary as the attacker, so reopening the state proved nothing.

This package moves the root of trust outside the caller entirely, and splits it
into two capabilities that the ordinary preparation process, controller,
backend and coding agent all lack:

``installation`` / ``provisioning``
    Root-only.  Creates the fixed directories, the Ed25519 signing identity and
    the immutable pending-authorization records.  No RPC surface.

``runtime verify-and-consume``
    The privileged broker.  It can verify one preprovisioned payload against
    the owner phrase, atomically consume it, and sign exactly one receipt.  It
    cannot provision, cannot change a payload, cannot pick a key or a state
    root, cannot sign arbitrary caller bytes and cannot reset a consumption.

An ordinary caller can still fabricate witness evidence, a preparation, a seal,
a phrase and a digest.  None of that helps: it cannot write the root-owned
state, cannot provision through the broker, cannot use the signing key, and
therefore cannot produce a receipt whose Ed25519 signature verifies against the
public key in the root-owned installation record.
"""

from admissible.capsule.owner_authority.broker import (
    ATTEST_INSTALLATION,
    AUTHORIZATION_STATUS,
    BROKER_OPERATIONS,
    FORBIDDEN_BROKER_OPERATIONS,
    OwnerAuthorityBroker,
    OwnerAuthorityBrokerClient,
    OwnerAuthorityBrokerError,
    RECORD_LAUNCH_RESULT,
    VERIFY_AND_CONSUME,
    broker_protocol_schema,
    peer_credentials,
)
from admissible.capsule.owner_authority.installation import (
    OwnerAuthorityInstallation,
    OwnerAuthorityInstallationError,
    attest_production_installation,
    attest_synthetic_non_production_installation,
    build_installation_record,
    production_installation_is_present,
)
from admissible.capsule.owner_authority.installer import (
    BROKER_UNIT_NAME,
    INSTALLED_OBJECTS,
    OwnerAuthorityInstallerError,
    broker_unit_definition,
    installation_plan,
    perform_installation,
    preinstall_conflict_checks,
    render_installation_plan,
    require_privileged_identity,
    verify_installation,
)
from admissible.capsule.owner_authority.layout import (
    AUTHORIZATION_STATES,
    BROKER_PROTOCOL_VERSION,
    COMMITTED_STATES,
    CONSUMED_LAUNCH_COMMITTED,
    EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
    LAUNCH_RESULT_RECORDED,
    LAUNCHABLE_STATE,
    OwnerAuthorityError,
    OwnerAuthorityLayout,
    PHRASE_VERIFIED,
    PRODUCTION_CONFIGURATION_ROOT,
    PRODUCTION_LAYOUT,
    PRODUCTION_RUNTIME_ROOT,
    PRODUCTION_STATE_ROOT,
    PROVISIONED_PENDING,
    RECEIPT_ISSUED,
    RECEIPT_SIGNATURE_CONSTRUCTION,
    SIGNED_RECEIPT_SCHEMA_VERSION,
    SYNTHETIC_LAYOUT,
    describe_state_machine,
    production_layout,
    require_production_layout,
    synthetic_non_production_layout,
)
from admissible.capsule.owner_authority.provisioner import (
    OwnerAuthorityProvisioningError,
    owner_payload_summary,
    provision_authorization,
    render_owner_payload_summary,
)
from admissible.capsule.owner_authority.records import (
    OwnerAuthorityRecordError,
    SignedOwnerAuthorizationReceipt,
    authorization_consumption_identity,
    external_owner_authorization_digest,
    new_authorization_record_id,
    verify_signed_receipt,
)
from admissible.capsule.owner_authority.signing import (
    SIGNING_ALGORITHM,
    OwnerAuthoritySigningError,
    discover_system_openssl,
    executable_identity,
    verify_signature,
)
from admissible.capsule.owner_authority.state import (
    AUTHORIZATION_ABSENT,
    AuthorizationStateDirectory,
    OwnerAuthorityStateError,
)

__all__ = [
    "ATTEST_INSTALLATION",
    "AUTHORIZATION_ABSENT",
    "AUTHORIZATION_STATES",
    "AUTHORIZATION_STATUS",
    "AuthorizationStateDirectory",
    "BROKER_OPERATIONS",
    "BROKER_PROTOCOL_VERSION",
    "BROKER_UNIT_NAME",
    "COMMITTED_STATES",
    "CONSUMED_LAUNCH_COMMITTED",
    "EXTERNAL_OWNER_DIGEST_CONSTRUCTION",
    "FORBIDDEN_BROKER_OPERATIONS",
    "INSTALLED_OBJECTS",
    "LAUNCHABLE_STATE",
    "LAUNCH_RESULT_RECORDED",
    "OwnerAuthorityBroker",
    "OwnerAuthorityBrokerClient",
    "OwnerAuthorityBrokerError",
    "OwnerAuthorityError",
    "OwnerAuthorityInstallation",
    "OwnerAuthorityInstallationError",
    "OwnerAuthorityInstallerError",
    "OwnerAuthorityLayout",
    "OwnerAuthorityProvisioningError",
    "OwnerAuthorityRecordError",
    "OwnerAuthoritySigningError",
    "OwnerAuthorityStateError",
    "PHRASE_VERIFIED",
    "PRODUCTION_CONFIGURATION_ROOT",
    "PRODUCTION_LAYOUT",
    "PRODUCTION_RUNTIME_ROOT",
    "PRODUCTION_STATE_ROOT",
    "PROVISIONED_PENDING",
    "RECEIPT_ISSUED",
    "RECEIPT_SIGNATURE_CONSTRUCTION",
    "RECORD_LAUNCH_RESULT",
    "SIGNED_RECEIPT_SCHEMA_VERSION",
    "SIGNING_ALGORITHM",
    "SYNTHETIC_LAYOUT",
    "SignedOwnerAuthorizationReceipt",
    "VERIFY_AND_CONSUME",
    "attest_production_installation",
    "attest_synthetic_non_production_installation",
    "authorization_consumption_identity",
    "broker_protocol_schema",
    "broker_unit_definition",
    "build_installation_record",
    "describe_state_machine",
    "discover_system_openssl",
    "executable_identity",
    "external_owner_authorization_digest",
    "installation_plan",
    "new_authorization_record_id",
    "owner_payload_summary",
    "peer_credentials",
    "perform_installation",
    "preinstall_conflict_checks",
    "production_installation_is_present",
    "production_layout",
    "provision_authorization",
    "render_installation_plan",
    "render_owner_payload_summary",
    "require_privileged_identity",
    "require_production_layout",
    "synthetic_non_production_layout",
    "verify_installation",
    "verify_signature",
    "verify_signed_receipt",
]
