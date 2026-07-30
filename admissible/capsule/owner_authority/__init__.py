"""The external, privileged owner-authority boundary.

Eager imports are limited to the layout and error types so importing this
package never triggers a RuntimeWarning from circular installer/provisioner
loading.  Concrete subsystems are imported lazily through ``__getattr__``.
"""

from __future__ import annotations

from typing import Any

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

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "ATTEST_INSTALLATION": (".broker", "ATTEST_INSTALLATION"),
    "AUTHORIZATION_ABSENT": (".state", "AUTHORIZATION_ABSENT"),
    "AUTHORIZATION_STATUS": (".broker", "AUTHORIZATION_STATUS"),
    "AuthorizationStateDirectory": (".state", "AuthorizationStateDirectory"),
    "BROKER_OPERATIONS": (".broker", "BROKER_OPERATIONS"),
    "BROKER_UNIT_NAME": (".installer", "BROKER_UNIT_NAME"),
    "DEPLOYMENT_ARTIFACT_PATH": (".deployment_artifact", "DEPLOYMENT_ARTIFACT_PATH"),
    "FORBIDDEN_BROKER_OPERATIONS": (".broker", "FORBIDDEN_BROKER_OPERATIONS"),
    "INITIAL_CRYPTO_ATTESTATION_REVISION": (
        ".installation",
        "INITIAL_CRYPTO_ATTESTATION_REVISION",
    ),
    "INSTALLED_OBJECTS": (".installer", "INSTALLED_OBJECTS"),
    "OwnerAuthorityBroker": (".broker", "OwnerAuthorityBroker"),
    "OwnerAuthorityBrokerClient": (".broker", "OwnerAuthorityBrokerClient"),
    "OwnerAuthorityBrokerError": (".broker", "OwnerAuthorityBrokerError"),
    "OwnerAuthorityInstallation": (".installation", "OwnerAuthorityInstallation"),
    "OwnerAuthorityInstallationError": (
        ".installation",
        "OwnerAuthorityInstallationError",
    ),
    "OwnerAuthorityInstallerError": (".installer", "OwnerAuthorityInstallerError"),
    "OwnerAuthorityProvisioningError": (
        ".provisioner",
        "OwnerAuthorityProvisioningError",
    ),
    "OwnerAuthorityRecordError": (".records", "OwnerAuthorityRecordError"),
    "OwnerAuthoritySigningError": (".signing", "OwnerAuthoritySigningError"),
    "OwnerAuthorityStateError": (".state", "OwnerAuthorityStateError"),
    "RECOMMENDED_LAUNCHER_USERNAME": (
        ".launcher_account",
        "RECOMMENDED_LAUNCHER_USERNAME",
    ),
    "RECORD_LAUNCH_RESULT": (".broker", "RECORD_LAUNCH_RESULT"),
    "SIGNING_ALGORITHM": (".signing", "SIGNING_ALGORITHM"),
    "SignedOwnerAuthorizationReceipt": (
        ".records",
        "SignedOwnerAuthorizationReceipt",
    ),
    "VERIFY_AND_CONSUME": (".broker", "VERIFY_AND_CONSUME"),
    "attest_production_installation": (
        ".installation",
        "attest_production_installation",
    ),
    "attest_synthetic_non_production_installation": (
        ".installation",
        "attest_synthetic_non_production_installation",
    ),
    "auth_boundary_identity_integration_note": (
        ".launcher_account",
        "auth_boundary_identity_integration_note",
    ),
    "authorization_consumption_identity": (
        ".records",
        "authorization_consumption_identity",
    ),
    "broker_protocol_schema": (".broker", "broker_protocol_schema"),
    "broker_unit_definition": (".installer", "broker_unit_definition"),
    "build_broker_deployment_artifact": (
        ".deployment_artifact",
        "build_broker_deployment_artifact",
    ),
    "build_installation_record": (".installation", "build_installation_record"),
    "discover_system_openssl": (".signing", "discover_system_openssl"),
    "executable_identity": (".signing", "executable_identity"),
    "external_owner_authorization_digest": (
        ".records",
        "external_owner_authorization_digest",
    ),
    "host_readiness_report": (".host_readiness", "host_readiness_report"),
    "installation_plan": (".installer", "installation_plan"),
    "launcher_account_creation_commands": (
        ".launcher_account",
        "launcher_account_creation_commands",
    ),
    "new_authorization_record_id": (".records", "new_authorization_record_id"),
    "owner_payload_summary": (".provisioner", "owner_payload_summary"),
    "peer_credentials": (".broker", "peer_credentials"),
    "perform_installation": (".installer", "perform_installation"),
    "perform_rollback_failed_install": (
        ".installer",
        "perform_rollback_failed_install",
    ),
    "perform_uninstall": (".installer", "perform_uninstall"),
    "preinstall_conflict_checks": (".installer", "preinstall_conflict_checks"),
    "production_installation_is_present": (
        ".installation",
        "production_installation_is_present",
    ),
    "provision_authorization": (".provisioner", "provision_authorization"),
    "refuse_symlink_or_special_targets": (
        ".installer",
        "refuse_symlink_or_special_targets",
    ),
    "render_installation_plan": (".installer", "render_installation_plan"),
    "render_owner_payload_summary": (".provisioner", "render_owner_payload_summary"),
    "require_privileged_identity": (".installer", "require_privileged_identity"),
    "validate_authorized_launcher": (
        ".launcher_account",
        "validate_authorized_launcher",
    ),
    "validate_launcher_username": (".launcher_account", "validate_launcher_username"),
    "validate_service_unit_text": (".installer", "validate_service_unit_text"),
    "verify_deployment_artifact": (
        ".deployment_artifact",
        "verify_deployment_artifact",
    ),
    "verify_installation": (".installer", "verify_installation"),
    "verify_signature": (".signing", "verify_signature"),
    "verify_signed_receipt": (".records", "verify_signed_receipt"),
}

__all__ = [
    "AUTHORIZATION_STATES",
    "BROKER_PROTOCOL_VERSION",
    "COMMITTED_STATES",
    "CONSUMED_LAUNCH_COMMITTED",
    "EXTERNAL_OWNER_DIGEST_CONSTRUCTION",
    "LAUNCH_RESULT_RECORDED",
    "LAUNCHABLE_STATE",
    "OwnerAuthorityError",
    "OwnerAuthorityLayout",
    "PHRASE_VERIFIED",
    "PRODUCTION_CONFIGURATION_ROOT",
    "PRODUCTION_LAYOUT",
    "PRODUCTION_RUNTIME_ROOT",
    "PRODUCTION_STATE_ROOT",
    "PROVISIONED_PENDING",
    "RECEIPT_ISSUED",
    "RECEIPT_SIGNATURE_CONSTRUCTION",
    "SIGNED_RECEIPT_SCHEMA_VERSION",
    "SYNTHETIC_LAYOUT",
    "describe_state_machine",
    "production_layout",
    "require_production_layout",
    "synthetic_non_production_layout",
    *sorted(_LAZY_EXPORTS),
]


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    from importlib import import_module

    module = import_module(module_name, __name__)
    value = getattr(module, attribute)
    globals()[name] = value
    return value
