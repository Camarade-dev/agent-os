"""The external, privileged owner-authority boundary.

These tests cover the parts of the repair that do not need a candidate witness:
the fixed production layout, the root-only installer and provisioner, the
closed broker protocol, the signed receipt schema, the one-time state machine,
and --- the point of the whole exercise --- the complete fake-owner world run
from an ordinary unprivileged process.

Tests that need a genuine privileged installer identity are marked and skip
honestly outside the disposable namespace; the same properties are additionally
demonstrated end to end by the synthetic privilege witness.

Nothing here contacts a public provider, model or API, and no real Codex
authentication content is opened, copied, displayed or hashed.
"""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path

import pytest

from admissible.capsule.common import canonical_bytes, fingerprint
from admissible.capsule.owner_authority import (
    BROKER_OPERATIONS,
    BROKER_PROTOCOL_VERSION,
    EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
    FORBIDDEN_BROKER_OPERATIONS,
    OwnerAuthorityBroker,
    OwnerAuthorityBrokerClient,
    OwnerAuthorityError,
    PRODUCTION_CONFIGURATION_ROOT,
    PRODUCTION_RUNTIME_ROOT,
    PRODUCTION_STATE_ROOT,
    SIGNED_RECEIPT_SCHEMA_VERSION,
    attest_production_installation,
    attest_synthetic_non_production_installation,
    broker_protocol_schema,
    describe_state_machine,
    discover_system_openssl,
    installation_plan,
    preinstall_conflict_checks,
    production_installation_is_present,
    production_layout,
    provision_authorization,
    render_installation_plan,
    synthetic_non_production_layout,
    verify_signature,
    verify_signed_receipt,
)
from admissible.capsule.owner_authority.installer import (
    BROKER_UNIT_NAME,
    broker_unit_definition,
    perform_installation,
    require_privileged_identity,
)
from admissible.capsule.owner_authority.layout import (
    AUTHORIZATION_STATES,
    CONSUMED_LAUNCH_COMMITTED,
    LAUNCHABLE_STATE,
    LAUNCH_RESULT_RECORDED,
    PHRASE_VERIFIED,
    PROVISIONED_PENDING,
    RECEIPT_ISSUED,
    require_production_layout,
)
from admissible.capsule.owner_authority.provisioner import (
    owner_payload_summary,
    render_owner_payload_summary,
)
from admissible.capsule.owner_authority.records import (
    SignedOwnerAuthorizationReceipt,
    external_owner_authorization_digest,
    new_authorization_record_id,
)
from admissible.capsule.owner_authority.signing import (
    generate_signing_identity,
    sign_message,
)
from admissible.capsule.owner_authority.state import AuthorizationStateDirectory
from admissible.capsule.owner_authorization import zero_retry_policy
from tests._candidate_canary_binding import PRIVILEGED_IDENTITY_REASON

PHRASE = "synthetic-external-owner-authority-phrase"

PAYLOAD = {
    "schema_version": "synthetic_external_owner_authority_payload_v1",
    "repository_head": "a" * 40,
    "repository_canonical_path_sha256": "0" * 64,
    "implementation_head": "b" * 40,
    "run_id": "external-owner-authority-run-1",
    "preparation_id": "external-owner-authority-preparation-1",
    "mission_fingerprint": "c" * 64,
    "model_binding_policy": {
        "configured_model": "gpt-5.3-codex",
        "configured_reasoning_effort": "high",
    },
    "destination_manifest_identity": "d" * 64,
    "tool_authority_identity": "e" * 64,
    "budgets": {"wall_clock_seconds": 600, "capsule_pids": 64},
    "zero_retry_policy": zero_retry_policy(),
}

privileged = pytest.mark.skipif(
    os.geteuid() != 0, reason=PRIVILEGED_IDENTITY_REASON
)


@pytest.fixture()
def world(tmp_path: Path):
    """A disposable synthetic owner-authority world with a running broker."""

    root = Path(tempfile.mkdtemp(prefix="oa-test-"))
    layout = synthetic_non_production_layout(root)
    perform_installation(
        layout=layout,
        installation_id="externaltest0001",
        authorized_launcher_uid=os.getuid(),
        authorized_launcher_gid=os.getgid(),
        install_unit=False,
    )
    installation = attest_synthetic_non_production_installation(layout)
    broker = OwnerAuthorityBroker(installation)
    broker.bind()
    import threading

    thread = threading.Thread(target=broker.serve_forever, daemon=True)
    thread.start()
    client = OwnerAuthorityBrokerClient(installation)
    try:
        yield {
            "layout": layout,
            "installation": installation,
            "broker": broker,
            "client": client,
        }
    finally:
        broker.close()
        shutil.rmtree(root, ignore_errors=True)


def _provision(world, payload=None):
    return provision_authorization(
        installation=world["installation"],
        owner_payload=payload or PAYLOAD,
        owner_phrase=PHRASE,
    )


# --------------------------------------------------------------------------
# A. the fixed, non-caller-selectable production layout
# --------------------------------------------------------------------------


def test_the_production_layout_is_fixed_and_takes_no_caller_arguments():
    import inspect

    assert inspect.signature(production_layout).parameters == {}
    assert inspect.signature(attest_production_installation).parameters == {}
    layout = production_layout()
    assert layout.configuration_root == PRODUCTION_CONFIGURATION_ROOT
    assert layout.state_root == PRODUCTION_STATE_ROOT
    assert layout.runtime_root == PRODUCTION_RUNTIME_ROOT
    assert layout.broker_socket_path == PRODUCTION_RUNTIME_ROOT / "broker.sock"
    assert layout.is_production is True


def test_a_synthetic_layout_is_never_accepted_as_production(tmp_path: Path):
    synthetic = synthetic_non_production_layout(tmp_path / "synthetic")
    assert synthetic.is_production is False
    with pytest.raises(OwnerAuthorityError) as failure:
        require_production_layout(synthetic, "test")
    assert failure.value.classification == (
        "OWNER_AUTHORITY_NON_PRODUCTION_LAYOUT_REFUSED"
    )


def test_the_production_layout_cannot_be_redirected(tmp_path: Path):
    from admissible.capsule.owner_authority.layout import (
        OwnerAuthorityLayout,
        PRODUCTION_LAYOUT,
    )

    forged = OwnerAuthorityLayout(
        classification=PRODUCTION_LAYOUT,
        configuration_root=tmp_path / "etc",
        state_root=tmp_path / "var",
        runtime_root=tmp_path / "run",
    )
    with pytest.raises(OwnerAuthorityError) as failure:
        forged.validated()
    assert failure.value.classification == "OWNER_AUTHORITY_LAYOUT_REFUSED"


# --------------------------------------------------------------------------
# B. the cryptographic primitive
# --------------------------------------------------------------------------


def test_the_cryptographic_primitive_is_a_content_attested_system_executable():
    executable = discover_system_openssl()
    assert executable["file_type"] == "regular"
    assert len(executable["sha256"]) == 64
    # Not group- or world-writable: anyone who can write it can sign anything.
    assert executable["mode"] & 0o022 == 0


def test_a_copy_of_the_cryptographic_executable_is_a_different_identity(
    tmp_path: Path,
):
    from admissible.capsule.owner_authority.signing import (
        executable_identity,
        reattest_executable,
    )

    executable = discover_system_openssl()
    copied = tmp_path / "openssl-copy"
    shutil.copy2(executable["path"], copied)
    copied.chmod(0o755)
    observed = executable_identity(copied)
    # Same bytes, different inode and path: not the attested executable.
    assert observed["sha256"] == executable["sha256"]
    assert observed["inode"] != executable["inode"]
    with pytest.raises(OwnerAuthorityError) as failure:
        reattest_executable({**executable, "inode": executable["inode"] + 1})
    assert failure.value.classification == (
        "OWNER_AUTHORITY_CRYPTO_EXECUTABLE_CHANGED"
    )


def test_signature_verification_refuses_a_foreign_key(tmp_path: Path):
    executable = discover_system_openssl()
    first = generate_signing_identity(
        executable=executable,
        private_key_path=tmp_path / "one.pem",
        public_key_path=tmp_path / "one.pub.pem",
    )
    generate_signing_identity(
        executable=executable,
        private_key_path=tmp_path / "two.pem",
        public_key_path=tmp_path / "two.pub.pem",
    )
    assert first["algorithm"] == "ed25519"
    message = b"exact canonical receipt payload"
    signature = sign_message(
        executable=executable,
        private_key_path=tmp_path / "one.pem",
        message=message,
    )
    assert verify_signature(
        executable=executable,
        public_key_pem=(tmp_path / "one.pub.pem").read_bytes(),
        message=message,
        signature=signature,
    )
    # Another key, a changed message and a corrupted signature all refuse.
    assert not verify_signature(
        executable=executable,
        public_key_pem=(tmp_path / "two.pub.pem").read_bytes(),
        message=message,
        signature=signature,
    )
    assert not verify_signature(
        executable=executable,
        public_key_pem=(tmp_path / "one.pub.pem").read_bytes(),
        message=message + b"!",
        signature=signature,
    )
    assert not verify_signature(
        executable=executable,
        public_key_pem=(tmp_path / "one.pub.pem").read_bytes(),
        message=message,
        signature=bytes(64),
    )


# --------------------------------------------------------------------------
# C-D. the root-only installer and provisioner
# --------------------------------------------------------------------------


@pytest.mark.skipif(
    os.geteuid() == 0, reason="this asserts the unprivileged refusal path"
)
def test_the_installer_and_provisioner_refuse_an_unprivileged_identity():
    with pytest.raises(OwnerAuthorityError) as failure:
        require_privileged_identity("owner-authority installation")
    assert failure.value.classification == "OWNER_AUTHORITY_NOT_PRIVILEGED"


@pytest.mark.skipif(
    os.geteuid() == 0, reason="this asserts the unprivileged refusal path"
)
def test_an_unprivileged_process_cannot_provision_production_state(tmp_path: Path):
    """An unprivileged copy of the provisioner fails on identity and on state."""

    layout = production_layout()
    directory = AuthorizationStateDirectory(layout, new_authorization_record_id())
    with pytest.raises((OwnerAuthorityError, OSError)):
        directory.provision({"schema_version": "forged"})
    # The production authorizations root is not writable from here at all.
    assert not os.access(layout.authorizations_root, os.W_OK)


def test_the_installation_plan_is_generated_but_not_executed():
    plan = installation_plan(
        authorized_launcher_uid=1000,
        authorized_launcher_gid=1000,
        launcher_username="launcher",
        launcher_group="launcher",
    )
    assert plan["not_executed_by_implementation_task"] is True
    assert plan["layout"]["configuration_root"] == str(
        PRODUCTION_CONFIGURATION_ROOT
    )
    paths = {item["path"] for item in plan["objects"]}
    assert f"{PRODUCTION_CONFIGURATION_ROOT}/installation-v1.json" in paths
    assert (
        f"{PRODUCTION_STATE_ROOT}/private/owner-authority-signing-key.v1.pem"
        in paths
    )
    modes = {item["path"]: item["mode"] for item in plan["objects"]}
    assert (
        modes[
            f"{PRODUCTION_STATE_ROOT}/private/owner-authority-signing-key.v1.pem"
        ]
        == 0o600
    )
    rendered = render_installation_plan(plan)
    assert "NOT executed" in rendered
    for section in ("Uninstall / rollback", "Post-install verification"):
        assert section in rendered


def test_the_broker_unit_is_a_definition_that_starts_nothing_here():
    unit = broker_unit_definition(production_layout())
    assert "ExecStart=" in unit and "NoNewPrivileges=yes" in unit
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert BROKER_UNIT_NAME.endswith(".service")
    # Nothing in this repository starts it.
    assert not Path("/etc/systemd/system", BROKER_UNIT_NAME).exists()


def test_preinstall_conflict_checks_are_safe_to_run_unprivileged():
    checks = preinstall_conflict_checks()
    assert checks["layout"]["configuration_root"] == str(
        PRODUCTION_CONFIGURATION_ROOT
    )
    assert checks["cryptographic_primitive"]["resolved"] is True
    assert isinstance(checks["conflicts"], list)


def test_the_owner_payload_summary_shows_everything_the_owner_must_confirm():
    summary = owner_payload_summary(PAYLOAD)
    assert summary["repository_head"] == PAYLOAD["repository_head"]
    assert summary["run_id"] == PAYLOAD["run_id"]
    assert summary["model"] == "gpt-5.3-codex"
    assert summary["reasoning_effort"] == "high"
    assert summary["destination_authority"] == PAYLOAD[
        "destination_manifest_identity"
    ]
    assert summary["effect_authority"] == PAYLOAD["tool_authority_identity"]
    assert summary["retries_authorized"] == 0
    assert summary["repairs_authorized"] == 0
    assert summary["launches_authorized"] == 1
    assert summary["payload_fingerprint"] == fingerprint(PAYLOAD)
    rendered = render_owner_payload_summary(summary)
    for expected in (
        "repository HEAD",
        "run identity",
        "mission",
        "model",
        "reasoning effort",
        "destination authority",
        "effect authority",
        "retries",
        "repairs",
        "payload fingerprint",
    ):
        assert expected in rendered
    assert "exactly one launch" in rendered


# --------------------------------------------------------------------------
# E. the closed broker protocol
# --------------------------------------------------------------------------


def test_the_broker_protocol_is_closed_and_has_no_provisioning_operation():
    schema = broker_protocol_schema()
    assert schema["protocol"] == BROKER_PROTOCOL_VERSION
    assert set(schema["operations"]) == set(BROKER_OPERATIONS)
    assert schema["provisioning_rpc"] is False
    assert schema["caller_selectable_paths"] is False
    assert schema["signs_caller_supplied_messages"] is False
    assert schema["peer_credential_check"] == (
        "SO_PEERCRED_UID_EQUALS_AUTHORIZED_LAUNCHER"
    )
    # Every forbidden operation is absent from the implemented vocabulary.
    assert not (FORBIDDEN_BROKER_OPERATIONS & BROKER_OPERATIONS)
    for forbidden in (
        "PROVISION_AUTHORIZATION",
        "SET_EXPECTED_DIGEST",
        "CHANGE_PAYLOAD",
        "SELECT_STATE_ROOT",
        "SELECT_SIGNING_KEY",
        "SIGN_MESSAGE",
        "RESET_CONSUMED_AUTHORIZATION",
        "AUTHORIZE_RETRY",
        "AUTHORIZE_REPAIR",
    ):
        assert forbidden in FORBIDDEN_BROKER_OPERATIONS
        assert forbidden not in BROKER_OPERATIONS


def test_the_broker_client_has_no_socket_or_key_parameter():
    import inspect

    parameters = inspect.signature(OwnerAuthorityBrokerClient.__init__).parameters
    assert set(parameters) == {"self", "installation"}
    consume = inspect.signature(
        OwnerAuthorityBrokerClient.verify_and_consume
    ).parameters
    assert set(consume) == {
        "self",
        "authorization_record_id",
        "owner_payload_fingerprint",
        "owner_phrase",
    }


@privileged
def test_the_broker_refuses_operations_outside_its_vocabulary(world):
    for operation in sorted(FORBIDDEN_BROKER_OPERATIONS):
        with pytest.raises(OwnerAuthorityError) as failure:
            world["client"]._call({"operation": operation})
        assert failure.value.classification == (
            "OWNER_AUTHORITY_BROKER_OPERATION_REFUSED"
        )


@privileged
def test_the_broker_refuses_another_protocol(world):
    from admissible.capsule.owner_authority.broker import _receive_frame, _send_frame

    connection = world["client"]._connect(30.0)
    try:
        _send_frame(
            connection,
            {"protocol": "some_other_protocol_v9", "operation": "ATTEST_INSTALLATION"},
        )
        response = _receive_frame(connection)
    finally:
        connection.close()
    assert response["status"] == "REFUSED"
    assert response["classification"] == "OWNER_AUTHORITY_BROKER_PROTOCOL_REFUSED"


@privileged
def test_the_broker_socket_is_root_owned_and_restricted(world):
    info = world["layout"].broker_socket_path.stat()
    assert stat.S_ISSOCK(info.st_mode)
    assert info.st_uid == 0
    assert stat.S_IMODE(info.st_mode) == 0o660


@privileged
def test_a_replaced_socket_that_is_not_a_socket_is_refused(world):
    world["broker"].close()
    path = world["layout"].broker_socket_path
    path.write_bytes(b"not a socket")
    with pytest.raises(OwnerAuthorityError) as failure:
        world["client"].attest_installation()
    assert failure.value.classification == (
        "OWNER_AUTHORITY_BROKER_SOCKET_REFUSED"
    )


# --------------------------------------------------------------------------
# F. the signed production receipt
# --------------------------------------------------------------------------


@privileged
def test_the_signed_receipt_binds_every_required_identity(world):
    provisioned = _provision(world)
    receipt = world["client"].verify_and_consume(
        authorization_record_id=provisioned["authorization_record_id"],
        owner_payload_fingerprint=provisioned["owner_payload_fingerprint"],
        owner_phrase=PHRASE,
    )
    payload = dict(receipt.payload)
    assert payload["schema_version"] == SIGNED_RECEIPT_SCHEMA_VERSION
    assert payload["broker_protocol"] == BROKER_PROTOCOL_VERSION
    assert payload["digest_construction"] == EXTERNAL_OWNER_DIGEST_CONSTRUCTION
    assert payload["installation_identity"] == (
        world["installation"].installation_identity
    )
    assert payload["signing_key_fingerprint"] == (
        world["installation"].signing_key_fingerprint
    )
    assert payload["authorization_record_id"] == (
        provisioned["authorization_record_id"]
    )
    assert payload["owner_payload"] == PAYLOAD
    assert payload["consumption_state"] == CONSUMED_LAUNCH_COMMITTED
    assert payload["launches_authorized"] == 1
    assert payload["retries_authorized"] == 0
    assert payload["repairs_authorized"] == 0
    evidence = payload["broker_terminal_evidence"]
    assert evidence["commit_rule"] == (
        "CONSUMPTION_IS_DURABLE_BEFORE_ANY_SIGNATURE_IS_PRODUCED"
    )
    assert evidence["peer_uid"] == os.getuid()
    assert len(receipt.signature) == 64


@privileged
def test_signature_substitution_and_payload_tampering_are_refused(world):
    provisioned = _provision(world)
    receipt = world["client"].verify_and_consume(
        authorization_record_id=provisioned["authorization_record_id"],
        owner_payload_fingerprint=provisioned["owner_payload_fingerprint"],
        owner_phrase=PHRASE,
    )
    body = receipt.to_dict()

    # A zeroed signature over an otherwise perfect receipt.
    zeroed = SignedOwnerAuthorizationReceipt.from_dict(
        {**body, "signature_hex": "00" * 64}
    )
    with pytest.raises(OwnerAuthorityError) as failure:
        verify_signed_receipt(receipt=zeroed, installation=world["installation"])
    assert failure.value.classification == "OWNER_AUTHORITY_SIGNATURE_REFUSED"

    # A tampered payload with the original signature, re-fingerprinted so the
    # receipt is internally consistent.  The signature covers the payload bytes.
    tampered_payload = {
        **body["payload"],
        "owner_payload": {**PAYLOAD, "run_id": "some-other-run"},
    }
    tampered = SignedOwnerAuthorizationReceipt.from_dict(
        {
            "payload": tampered_payload,
            "signature_hex": body["signature_hex"],
            "receipt_identity": fingerprint(tampered_payload),
        }
    )
    with pytest.raises(OwnerAuthorityError) as tamper:
        verify_signed_receipt(receipt=tampered, installation=world["installation"])
    assert tamper.value.classification in {
        "OWNER_AUTHORITY_SIGNATURE_REFUSED",
        "OWNER_AUTHORITY_RECEIPT_INVALID",
    }


@privileged
def test_a_receipt_replayed_for_another_authorization_record_is_refused(world):
    first = _provision(world)
    second = _provision(world)
    receipt = world["client"].verify_and_consume(
        authorization_record_id=first["authorization_record_id"],
        owner_payload_fingerprint=first["owner_payload_fingerprint"],
        owner_phrase=PHRASE,
    )
    body = receipt.to_dict()
    substituted_payload = {
        **body["payload"],
        "authorization_record_id": second["authorization_record_id"],
    }
    substituted = SignedOwnerAuthorizationReceipt.from_dict(
        {
            "payload": substituted_payload,
            "signature_hex": body["signature_hex"],
            "receipt_identity": fingerprint(substituted_payload),
        }
    )
    with pytest.raises(OwnerAuthorityError) as failure:
        verify_signed_receipt(
            receipt=substituted, installation=world["installation"]
        )
    assert failure.value.classification in {
        "OWNER_AUTHORITY_SIGNATURE_REFUSED",
        "OWNER_AUTHORITY_RECEIPT_INVALID",
    }
    # The second authorization is untouched by the attempt.
    assert world["client"].authorization_status(
        second["authorization_record_id"]
    )["state"] == PROVISIONED_PENDING


@privileged
def test_a_tampered_installation_record_invalidates_the_attestation(world):
    record_path = world["layout"].installation_record_path
    original = record_path.read_bytes()
    record_path.chmod(0o644)
    record_path.write_bytes(original.replace(b"externaltest0001", b"externaltest0002"))
    with pytest.raises(OwnerAuthorityError) as failure:
        attest_synthetic_non_production_installation(world["layout"])
    assert failure.value.classification in {
        "OWNER_AUTHORITY_INSTALLATION_RECORD_INVALID",
        "OWNER_AUTHORITY_INSTALLATION_PATHS_DIFFER",
    }
    # A previously attested installation notices the drift when re-attested.
    with pytest.raises(OwnerAuthorityError):
        world["installation"].reattested()


# --------------------------------------------------------------------------
# H. the one-time state machine
# --------------------------------------------------------------------------


def test_the_state_machine_is_forward_only_and_commits_before_signing():
    machine = describe_state_machine()
    assert machine["states"] == [
        PROVISIONED_PENDING,
        PHRASE_VERIFIED,
        CONSUMED_LAUNCH_COMMITTED,
        RECEIPT_ISSUED,
        LAUNCH_RESULT_RECORDED,
    ]
    assert machine["launchable_state"] == LAUNCHABLE_STATE == PROVISIONED_PENDING
    assert machine["launchable_after_commit"] is False
    assert machine["commit_rule"] == (
        "CONSUMPTION_IS_DURABLE_BEFORE_ANY_SIGNATURE_IS_PRODUCED"
    )
    # Every state after the commit point refuses a launch.
    assert set(machine["committed_states"]) == {
        CONSUMED_LAUNCH_COMMITTED,
        RECEIPT_ISSUED,
        LAUNCH_RESULT_RECORDED,
    }
    assert AUTHORIZATION_STATES[0] == PROVISIONED_PENDING


@privileged
def test_the_state_machine_advances_exactly_once_through_a_launch(world):
    provisioned = _provision(world)
    record_id = provisioned["authorization_record_id"]
    directory = AuthorizationStateDirectory(world["layout"], record_id)
    assert directory.current_state() == PROVISIONED_PENDING
    receipt = world["client"].verify_and_consume(
        authorization_record_id=record_id,
        owner_payload_fingerprint=provisioned["owner_payload_fingerprint"],
        owner_phrase=PHRASE,
    )
    assert directory.current_state() == RECEIPT_ISSUED
    world["client"].record_launch_result(
        authorization_record_id=record_id,
        receipt_identity=receipt.receipt_identity,
        outcome="SYNTHETIC_TEST",
    )
    assert directory.current_state() == LAUNCH_RESULT_RECORDED
    # No transition may be repeated.
    with pytest.raises(OwnerAuthorityError) as failure:
        world["client"].record_launch_result(
            authorization_record_id=record_id,
            receipt_identity=receipt.receipt_identity,
            outcome="SYNTHETIC_TEST",
        )
    assert failure.value.classification == "OWNER_AUTHORITY_STATE_NOT_ELIGIBLE"


@privileged
def test_a_pending_record_is_immutable_and_retains_only_the_digest(world):
    provisioned = _provision(world)
    directory = AuthorizationStateDirectory(
        world["layout"], provisioned["authorization_record_id"]
    )
    record = directory.pending_record()
    assert record["launches_authorized"] == 1
    assert record["retries_authorized"] == 0
    assert record["repairs_authorized"] == 0
    assert record["expected_owner_authorization_digest"] == (
        external_owner_authorization_digest(
            phrase=PHRASE,
            payload_bytes=canonical_bytes(PAYLOAD),
            authorization_record_id=provisioned["authorization_record_id"],
        )
    )
    # The phrase itself appears nowhere in durable state.
    rendered = canonical_bytes(record).decode("utf-8")
    assert PHRASE not in rendered
    pending_path = directory.root / "pending.json"
    assert stat.S_IMODE(pending_path.stat().st_mode) == 0o400
    assert pending_path.stat().st_uid == 0
    # Re-provisioning the same record identity is refused.
    with pytest.raises(OwnerAuthorityError) as failure:
        directory.provision(record)
    assert failure.value.classification == "OWNER_AUTHORITY_ALREADY_PROVISIONED"


# --------------------------------------------------------------------------
# I. the complete fake-owner world, from an ordinary unprivileged process
# --------------------------------------------------------------------------


def test_the_complete_fake_owner_world_produces_no_production_authority(
    tmp_path: Path,
):
    """The exact audit attack, reproduced through public interfaces.

    Every step the attacker *can* perform succeeds, and the world still yields
    nothing: no production state, no provisioning path, no signing key, and
    therefore no receipt that verifies under the production installation.
    """

    executable = discover_system_openssl()

    # 1-2. fabricate candidate-shaped evidence and a preparation seal.  Both are
    #      just bytes the attacker wrote; that was never in dispute.
    fabricated_evidence = {"candidate": "fabricated", "seal": "fabricated"}
    assert fingerprint(fabricated_evidence)

    # 3-4. choose a phrase and compute a matching digest.
    chosen_phrase = "attacker-chosen-owner-phrase"
    invented_record_id = new_authorization_record_id()
    digest = external_owner_authorization_digest(
        phrase=chosen_phrase,
        payload_bytes=canonical_bytes(PAYLOAD),
        authorization_record_id=invented_record_id,
    )
    assert len(digest) == 64  # the attacker really can compute this

    # 5. create arbitrary local state.  The attacker owns this directory.
    attacker_state = tmp_path / "attacker-state"
    attacker_state.mkdir()
    (attacker_state / "expected-digest.json").write_bytes(
        canonical_bytes({"expected_owner_authorization_digest": digest})
    )

    # 6. attempt to provision production authorization.  The privileged state
    #    root is not writable, and the entry point refuses the identity.
    production = production_layout()
    directory = AuthorizationStateDirectory(production, invented_record_id)
    with pytest.raises((OwnerAuthorityError, OSError)):
        directory.provision({"schema_version": "forged"})
    assert directory.current_state() == "AUTHORIZATION_ABSENT"

    # 7. attempt to issue a production receipt with the attacker's own key.
    attacker_private = tmp_path / "attacker.pem"
    attacker_public = tmp_path / "attacker.pub.pem"
    generate_signing_identity(
        executable=executable,
        private_key_path=attacker_private,
        public_key_path=attacker_public,
    )
    forged_payload = {
        "schema_version": SIGNED_RECEIPT_SCHEMA_VERSION,
        "broker_protocol": BROKER_PROTOCOL_VERSION,
        "signature_construction": (
            "admissible_owner_authority_ed25519_over_canonical_receipt_payload_v1"
        ),
        "digest_construction": EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
        "installation_id": "forgedinstallation",
        "installation_identity": fingerprint({"forged": "installation"}),
        "signing_key_fingerprint": fingerprint({"forged": "key"}),
        "crypto_attestation_revision": "crypto-attestation-revision-v1-initial",
        "authorization_record_id": invented_record_id,
        "authorization_record_identity": fingerprint({"forged": "record"}),
        "owner_payload": dict(PAYLOAD),
        "owner_payload_fingerprint": fingerprint(dict(PAYLOAD)),
        "authorization_consumption_identity": digest,
        "consumption_state": CONSUMED_LAUNCH_COMMITTED,
        "consumption_record_identity": digest,
        "launches_authorized": 1,
        "retries_authorized": 0,
        "repairs_authorized": 0,
        "broker_terminal_evidence": {
            "schema_version": (
                "admissible_owner_authority_broker_terminal_evidence_v1"
            ),
            "commit_rule": (
                "CONSUMPTION_IS_DURABLE_BEFORE_ANY_SIGNATURE_IS_PRODUCED"
            ),
            "observed_state_sequence": [PROVISIONED_PENDING],
            "consumption_marker_identity": {
                "path": "/forged",
                "sha256": digest,
                "device": 1,
                "inode": 1,
                "owner_uid": 0,
                "owner_gid": 0,
                "mode": 0o400,
                "size": 1,
                "file_type": "regular",
                "link_count": 1,
            },
            "cryptographic_executable_identity": dict(executable),
            "broker_protocol": BROKER_PROTOCOL_VERSION,
            "peer_uid": os.getuid(),
        },
    }
    forged_receipt = SignedOwnerAuthorizationReceipt.create(
        payload=forged_payload,
        signature=sign_message(
            executable=executable,
            private_key_path=attacker_private,
            message=canonical_bytes(forged_payload),
        ),
    )
    # It is a structurally perfect receipt, validly signed --- by the wrong key.
    assert forged_receipt.structurally_validated() is forged_receipt
    assert verify_signature(
        executable=executable,
        public_key_pem=attacker_public.read_bytes(),
        message=forged_receipt.signed_bytes(),
        signature=forged_receipt.signature,
    )

    # 8. attempt the production gate.  There is no production installation to
    #    verify against on this host, and if there were, the attacker's key is
    #    not the key its root-owned record names.
    with pytest.raises(OwnerAuthorityError) as failure:
        verify_signed_receipt(
            receipt=forged_receipt,
            installation=attest_production_installation(),
        )
    assert failure.value.classification in {
        "OWNER_AUTHORITY_NOT_INSTALLED",
        "OWNER_AUTHORITY_INSTALLATION_NOT_ROOT_OWNED",
        "OWNER_AUTHORITY_RECEIPT_FOREIGN_INSTALLATION",
        "OWNER_AUTHORITY_SIGNATURE_REFUSED",
    }


@privileged
def test_the_fake_owner_world_also_fails_against_a_running_installation(world):
    """With a real installation present, the failure is cryptographic."""

    executable = discover_system_openssl()
    attacker_root = Path(tempfile.mkdtemp(prefix="oa-attacker-"))
    try:
        generate_signing_identity(
            executable=executable,
            private_key_path=attacker_root / "attacker.pem",
            public_key_path=attacker_root / "attacker.pub.pem",
        )
        provisioned = _provision(world)
        genuine = world["client"].verify_and_consume(
            authorization_record_id=provisioned["authorization_record_id"],
            owner_payload_fingerprint=provisioned["owner_payload_fingerprint"],
            owner_phrase=PHRASE,
        )
        # Re-sign the *exact* genuine payload with the attacker key.
        resigned = SignedOwnerAuthorizationReceipt.create(
            payload=dict(genuine.payload),
            signature=sign_message(
                executable=executable,
                private_key_path=attacker_root / "attacker.pem",
                message=genuine.signed_bytes(),
            ),
        )
        assert resigned.receipt_identity == genuine.receipt_identity
        with pytest.raises(OwnerAuthorityError) as failure:
            verify_signed_receipt(
                receipt=resigned, installation=world["installation"]
            )
        assert failure.value.classification == "OWNER_AUTHORITY_SIGNATURE_REFUSED"
    finally:
        shutil.rmtree(attacker_root, ignore_errors=True)


# --------------------------------------------------------------------------
# the production installation is deliberately absent on this host
# --------------------------------------------------------------------------


def test_the_production_installation_has_not_been_performed():
    """The implementation task must not install the real owner authority."""

    assert production_installation_is_present() is False
    with pytest.raises(OwnerAuthorityError) as failure:
        attest_production_installation()
    assert failure.value.classification == "OWNER_AUTHORITY_NOT_INSTALLED"
    for path in (
        PRODUCTION_CONFIGURATION_ROOT,
        PRODUCTION_STATE_ROOT,
        PRODUCTION_RUNTIME_ROOT,
    ):
        assert not path.exists(), f"{path} was created by the implementation task"
