"""Adversarial tests: only an externally rooted owner authority is production.

Every candidate store here is created locally, every phrase is synthetic, and
the only executable ever run is the pinned Codex 0.145.0 binary inside the
private routeless witness namespace, plus the content-attested system OpenSSL
the owner authority signs with.  No public provider, model or API is reachable
from this module, and no real authentication content is opened.

The trust root under test is no longer self-rooted.  A caller may still
fabricate stores, packs, receipts, tails, preparations, seals, phrases and
digests; the tests below show that none of it produces a signed receipt, and
that a signed receipt still refuses the moment reality differs from what the
owner authorized.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from admissible.capsule.backend import CapsuleAuthority
from admissible.capsule.common import canonical_bytes, fingerprint, sha256_bytes
from admissible.capsule.docker_controller import (
    DockerCapsuleController,
    DockerCapsuleLimits,
)
from admissible.capsule.execution_authority import BackendExecutionAuthority
from admissible.capsule.host_codex_backend import (
    HostCodexAppServerCapsuleBackend,
    NonProductionWitnessMode,
    ScriptedCodexAppServerConnection,
    ScriptedCodexConnectionFactory,
    SyntheticOwnerAuthorityWitness,
    dynamic_tools_grammar,
)
from admissible.capsule.host_control import AuthenticatedControlAuthority
from admissible.capsule.model_authority import (
    ModelBindingPolicy,
    ModelConfigurationError,
)
from admissible.capsule.owner_authority.broker import OwnerAuthorityBrokerError
from admissible.capsule.owner_authority.gate import (
    OwnerAuthorityGateError,
    revalidate_signed_owner_authority,
)
from admissible.capsule.owner_authority.layout import OwnerAuthorityError
from admissible.capsule.owner_authority.layout import (
    EXTERNAL_OWNER_DIGEST_CONSTRUCTION,
    LAUNCH_RESULT_RECORDED,
    PROVISIONED_PENDING,
    RECEIPT_ISSUED,
)
from admissible.capsule.owner_authority.records import (
    SignedOwnerAuthorizationReceipt,
    external_owner_authorization_digest,
    new_authorization_record_id,
)
from admissible.capsule.owner_authorization import (
    OwnerAuthorizationError,
    OwnerAuthorizationPayload,
    classify_local_chatgpt_login,
    read_owner_phrase_from_descriptor,
)
from admissible.capsule.preflight_seal import FuturePreflightSealError
from admissible.capsule.serialization_witness import (
    CANDIDATE_WITNESS_TRUST_STATE,
    ZERO_FINGERPRINT,
    CandidateSerializationWitnessStore,
    SerializationWitnessError,
    _durability_identity_from_receipt,
    trusted_witness_verifier_identity,
)
from admissible.capsule.session_store import DurableCapsuleSessionStore
from tests._candidate_canary_binding import (
    PRIVILEGED_IDENTITY_REASON,
    SYNTHETIC_OWNER_PHRASE,
    build_owner_payload,
    build_sealed_candidate_preparation,
    consume_synthetic_authorization,
    create_candidate_canary_binding,
    create_owner_bound_canary_binding,
    owner_phrase_descriptor,
    privileged_identity_available,
    provision_synthetic_authorization,
    synthetic_owner_authority_world,
)


SYNTHETIC_MISSION_PROMPT = "synthetic owner-rooted witness trust mission"

#: The capsule runs as a fixed non-root identity.  Pinning it here keeps the
#: suite identical whether or not it runs inside the disposable privilege
#: namespace, where the test process itself is uid 0.
CAPSULE_UID = 1000
CAPSULE_GID = 1000


# --------------------------------------------------------------------------
# module-scoped real-binary candidate bindings
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def primary(tmp_path_factory):
    root = tmp_path_factory.mktemp("primary-candidate")
    return create_candidate_canary_binding(root / "evidence")


@pytest.fixture(scope="module")
def secondary(tmp_path_factory):
    root = tmp_path_factory.mktemp("secondary-candidate")
    return create_candidate_canary_binding(root / "evidence")


@pytest.fixture()
def owner_bound(tmp_path: Path, primary):
    if not privileged_identity_available():
        pytest.skip(PRIVILEGED_IDENTITY_REASON)
    return create_owner_bound_canary_binding(tmp_path / "run", binding=primary)


def _gate(bound, **overrides):
    """Run the production pre-effect gate over a synthetic owner-authority world."""

    world = overrides.pop("world", None) or bound["owner_authority_world"]
    arguments = {
        "signed_receipt": bound["signed_receipt"],
        "installation": world["installation"],
        "broker_client": world["client"],
        "candidate_witness_store": bound["store"],
        "preparation_root": bound["preparation_root"],
        "retained_seal_identity": bound["retained_seal_identity"],
        "expected_model_binding_policy": bound["policy"],
    }
    arguments.update(overrides)
    return revalidate_signed_owner_authority(**arguments)


# --------------------------------------------------------------------------
# fabricating a complete, internally self-consistent candidate store
# --------------------------------------------------------------------------


def fabricate_candidate_store(root: Path, donor) -> dict:
    """Build a complete self-consistent candidate store without running Codex.

    Everything an ordinary caller can compute is computed here: a fresh store
    anchor minted by the real store code, a run anchor, an evidence pack, a
    receipt and a tail, all mutually consistent and all carrying the correct
    expected model, executable, namespace and terminal values.
    """

    store = CandidateSerializationWitnessStore(root)
    anchor = json.loads(
        (store.trusted_anchor_root / "store-anchor.json").read_text("utf-8")
    )
    donor_receipt = donor["receipt"].to_dict()
    donor_pack = json.loads(
        (
            donor["store"].root / donor_receipt["evidence_pack_relative_path"]
        ).read_text("utf-8")
    )
    run_identity = "codex-witness-fabricated0000000000000000"
    policy = donor["policy"]
    run_anchor_body = {
        "schema_version": "admissible_codex_candidate_witness_run_anchor_v2",
        "trust_state": CANDIDATE_WITNESS_TRUST_STATE,
        "store_anchor_fingerprint": anchor["store_anchor_fingerprint"],
        "witness_run_identity": run_identity,
        "witness_run_nonce": donor_pack["witness_run_nonce"],
        "sequence": 1,
        "previous_tail_identity": ZERO_FINGERPRINT,
        "model_binding_policy_fingerprint": policy.policy_fingerprint,
        "trusted_verifier_identity": trusted_witness_verifier_identity(),
        "codex_executable_identity": dict(policy.codex_executable_identity),
        "configuration_fingerprint": policy.configuration_fingerprint,
        "state": "ANCHORED_BEFORE_EXECUTION",
    }
    run_anchor = {
        **run_anchor_body,
        "run_anchor_fingerprint": fingerprint(run_anchor_body),
    }
    (store.trusted_anchor_root / "run-anchors" / f"{run_identity}.json").write_bytes(
        canonical_bytes(run_anchor)
    )
    pack_body = {
        **{
            key: value
            for key, value in donor_pack.items()
            if key != "evidence_pack_fingerprint"
        },
        "store_anchor_fingerprint": anchor["store_anchor_fingerprint"],
        "run_anchor_fingerprint": run_anchor["run_anchor_fingerprint"],
        "witness_run_identity": run_identity,
        "sequence": 1,
        "previous_tail_identity": ZERO_FINGERPRINT,
    }
    pack = {**pack_body, "evidence_pack_fingerprint": fingerprint(pack_body)}
    pack_path = store.root / "evidence-packs" / f"{run_identity}.json"
    pack_path.write_bytes(canonical_bytes(pack))
    pack_bytes = pack_path.read_bytes()
    receipt_body = {
        **{
            key: value
            for key, value in donor_receipt.items()
            if key != "receipt_identity"
        },
        "store_anchor_fingerprint": anchor["store_anchor_fingerprint"],
        "run_anchor_fingerprint": run_anchor["run_anchor_fingerprint"],
        "witness_run_identity": run_identity,
        "sequence": 1,
        "evidence_pack_relative_path": f"evidence-packs/{run_identity}.json",
        "evidence_pack_sha256": sha256_bytes(pack_bytes),
        "evidence_pack_size": len(pack_bytes),
        "evidence_pack_fingerprint": pack["evidence_pack_fingerprint"],
        "complete_witness_evidence_pack_fingerprint": (
            pack["evidence_pack_fingerprint"]
        ),
    }
    receipt_body["durable_evidence_receipt_identity"] = (
        _durability_identity_from_receipt(receipt_body)
    )
    receipt = {
        **receipt_body,
        "receipt_identity": fingerprint(receipt_body),
    }
    (store.root / "receipts" / f"{run_identity}.json").write_bytes(
        canonical_bytes(receipt)
    )
    tail_body = {
        "schema_version": "admissible_codex_candidate_witness_store_tail_v2",
        "trust_state": CANDIDATE_WITNESS_TRUST_STATE,
        "store_anchor_fingerprint": anchor["store_anchor_fingerprint"],
        "sequence": 1,
        "witness_run_identity": run_identity,
        "receipt_identity": receipt["receipt_identity"],
        "evidence_pack_fingerprint": pack["evidence_pack_fingerprint"],
        "previous_tail_identity": ZERO_FINGERPRINT,
    }
    (store.trusted_anchor_root / "tail.json").write_bytes(
        canonical_bytes({**tail_body, "tail_identity": fingerprint(tail_body)})
    )
    return {"store": store, "run_identity": run_identity}


# --------------------------------------------------------------------------
# 1-2. fabricated candidate stores, packs, receipts and tails
# --------------------------------------------------------------------------


def test_fully_fabricated_candidate_store_yields_no_production_authority(
    tmp_path: Path, primary
):
    """A complete fabrication may load as candidate evidence and still be inert."""

    fabricated = fabricate_candidate_store(tmp_path / "fabricated", primary)
    store = fabricated["store"]
    candidate = store.load_current_candidate_receipt(
        expected_policy=primary["policy"],
        expected_executable_identity=primary["identity"].to_dict(),
    )
    # It loads: nothing in the store can distinguish it from a genuine one.
    assert candidate.trust_state == CANDIDATE_WITNESS_TRUST_STATE
    # It is still not authority: it is not a signed receipt and cannot become
    # one, because becoming one requires a private key this process cannot read.
    assert not isinstance(candidate, SignedOwnerAuthorizationReceipt)


def test_fabricated_store_substituted_under_an_owner_binding_is_refused(
    tmp_path: Path, primary, owner_bound
):
    fabricated = fabricate_candidate_store(tmp_path / "swapped", primary)
    with pytest.raises(
        (SerializationWitnessError, OwnerAuthorityGateError)
    ) as failure:
        _gate(owner_bound, candidate_witness_store=fabricated["store"])
    assert failure.value.classification in {
        "WITNESS_TAIL_SUBSTITUTED",
        "OWNER_AUTHORITY_CANDIDATE_EVIDENCE_CHANGED",
    }


def test_fabricated_pack_receipt_and_tail_in_a_real_store_are_refused(
    tmp_path: Path, primary
):
    """Hand-written evidence with a mismatched anchor is refused outright."""

    store = CandidateSerializationWitnessStore(tmp_path / "half-fabricated")
    donor = primary["receipt"].to_dict()
    forged_body = {
        key: value for key, value in donor.items() if key != "receipt_identity"
    }
    forged = {**forged_body, "receipt_identity": fingerprint(forged_body)}
    (store.root / "receipts" / "forged.json").write_bytes(canonical_bytes(forged))
    with pytest.raises(SerializationWitnessError, match="no candidate witness"):
        store.load_current_candidate_receipt(
            expected_policy=primary["policy"],
            expected_executable_identity=primary["identity"].to_dict(),
        )


# --------------------------------------------------------------------------
# 3. production backend invoked with candidate evidence only
# --------------------------------------------------------------------------


class _ProductionModeScriptedFactory(ScriptedCodexConnectionFactory):
    """A scripted factory that claims a production connection mode."""

    @property
    def connection_mode(self) -> str:
        return "production_bwrap"


def _backend_inputs(tmp_path: Path, binding, image_identity: str = "sha256:" + "b" * 64):
    limits = DockerCapsuleLimits(
        image_identity=image_identity,
        command_timeout_seconds=5.0,
        session_timeout_seconds=10.0,
        output_limit_bytes=4096,
       uid=CAPSULE_UID,
        gid=CAPSULE_GID,
    )
    try:
        controller = DockerCapsuleController(
            workspace_root=tmp_path / "capsules",
            frozen_output_root=tmp_path / "provider-output",
            limits=limits,
        )
    except FileNotFoundError as error:  # pragma: no cover - host without Docker
        pytest.skip(f"the capsule controller requires a local Docker runtime: {error}")
    session_store = DurableCapsuleSessionStore(
        tmp_path / "session-store",
        candidate_witness_store=binding["store"],
    )
    capsule_authority = CapsuleAuthority.create(
        backend_kind="host_codex_app_server_capsule_v1",
        capsule_image_identity=image_identity,
        mission_fingerprint=sha256_bytes(
            SYNTHETIC_MISSION_PROMPT.encode("utf-8")
        ),
    )
    return controller, session_store, capsule_authority


def test_production_backend_with_a_candidate_receipt_only_is_refused(
    tmp_path: Path, primary
):
    controller, session_store, capsule_authority = _backend_inputs(tmp_path, primary)
    factory = _ProductionModeScriptedFactory(
        ScriptedCodexAppServerConnection(()),
        codex_component_identity=primary["identity"].to_dict(),
    )
    control_authority = AuthenticatedControlAuthority.create(
        codex_protocol_version="0.145.0",
        executable_identity=factory.codex_component_identity,
        policy_fingerprint=factory.host_policy_fingerprint,
        authentication_boundary_state=factory.authentication_boundary_state,
    )
    with pytest.raises(ValueError, match="impossible under a production"):
        HostCodexAppServerCapsuleBackend(
            authority=capsule_authority,
            control_authority=control_authority,
            controller=controller,
            session_store=session_store,
            connection_factory=factory,
            mission_prompt=SYNTHETIC_MISSION_PROMPT,
            witness_authority=NonProductionWitnessMode(primary["receipt"]),
        )


def test_production_backend_refuses_a_synthetic_owner_authority_witness(
    tmp_path: Path, primary, owner_bound
):
    """The synthetic privilege witness can never stand in for production."""

    controller, session_store, capsule_authority = _backend_inputs(
        tmp_path / "synthetic-under-production", primary
    )
    factory = _ProductionModeScriptedFactory(
        ScriptedCodexAppServerConnection(()),
        codex_component_identity=primary["identity"].to_dict(),
    )
    control_authority = AuthenticatedControlAuthority.create(
        codex_protocol_version="0.145.0",
        executable_identity=factory.codex_component_identity,
        policy_fingerprint=factory.host_policy_fingerprint,
        authentication_boundary_state=factory.authentication_boundary_state,
    )
    with pytest.raises(ValueError, match="synthetic owner-authority witness"):
        HostCodexAppServerCapsuleBackend(
            authority=capsule_authority,
            control_authority=control_authority,
            controller=controller,
            session_store=session_store,
            connection_factory=factory,
            mission_prompt=SYNTHETIC_MISSION_PROMPT,
            witness_authority=owner_bound["owner_authority_witness"],
        )


def test_backend_refuses_a_raw_candidate_receipt_as_witness_authority(
    tmp_path: Path, primary
):
    controller, session_store, capsule_authority = _backend_inputs(tmp_path, primary)
    factory = ScriptedCodexConnectionFactory(
        ScriptedCodexAppServerConnection(()),
        codex_component_identity=primary["identity"].to_dict(),
    )
    control_authority = AuthenticatedControlAuthority.create(
        codex_protocol_version="0.145.0",
        executable_identity=factory.codex_component_identity,
        policy_fingerprint=factory.host_policy_fingerprint,
        authentication_boundary_state=factory.authentication_boundary_state,
    )
    with pytest.raises(ValueError, match="requires either a broker-signed"):
        HostCodexAppServerCapsuleBackend(
            authority=capsule_authority,
            control_authority=control_authority,
            controller=controller,
            session_store=session_store,
            connection_factory=factory,
            mission_prompt=SYNTHETIC_MISSION_PROMPT,
            witness_authority=primary["receipt"],
        )


def test_production_execution_authority_requires_a_signed_receipt(primary):
    with pytest.raises(ValueError, match="requires a broker-signed owner"):
        BackendExecutionAuthority.create(
            capsule_authority_fingerprint=fingerprint({"synthetic": True}),
            generic_mission_fingerprint=sha256_bytes(b"mission"),
            codex_executable_identity=primary["identity"].to_dict(),
            model_authority=primary["authority"],
            candidate_witness_receipt=primary["receipt"],
            candidate_witness_store=primary["store"],
            host_control_policy_fingerprint=fingerprint({"host": True}),
            bwrap_executable_identity=primary["identity"].to_dict(),
            bwrap_argv_policy_fingerprint=fingerprint({"argv": True}),
            controller_identity=fingerprint({"controller": True}),
            capsule_image_content_id="sha256:" + "c" * 64,
            docker_executable_identity=primary["identity"].to_dict(),
            dynamic_tools_schema_identity=fingerprint(dynamic_tools_grammar()),
            protocol_request_policy_fingerprint=fingerprint({"request": True}),
            mission_bytes=b"mission",
            prompt_bytes=b"prompt",
            backend_session_id="capsule-session-owner-gate",
            run_id="capsule-run-owner-gate",
            connection_mode="production_bwrap",
            connection_factory_identity=primary["identity"].to_dict(),
            authentication_boundary_state="OS_ENFORCED",
            budgets={"event_timeout_ms": 1000},
            terminal_policy={"post_terminal_drain": "BOUNDED_UNTIL_PROCESS_CLOSED"},
        )


# --------------------------------------------------------------------------
# 4-8. signed receipts that target another store, pack, policy, root or run
# --------------------------------------------------------------------------


def test_owner_receipt_for_another_store_is_refused(
    tmp_path: Path, primary, secondary, owner_bound
):
    with pytest.raises(
        (SerializationWitnessError, OwnerAuthorityGateError)
    ) as failure:
        _gate(owner_bound, candidate_witness_store=secondary["store"])
    assert failure.value.classification in {
        "WITNESS_TAIL_SUBSTITUTED",
        "OWNER_AUTHORITY_CANDIDATE_EVIDENCE_CHANGED",
    }


def test_owner_payload_for_another_evidence_pack_is_refused(
    tmp_path: Path, primary
):
    """The broker signs what the owner provisioned; the gate checks reality."""

    if not privileged_identity_available():
        pytest.skip(PRIVILEGED_IDENTITY_REASON)
    prepared = build_sealed_candidate_preparation(
        tmp_path / "pack-swap", binding=primary
    )
    payload = build_owner_payload(prepared)
    substituted = OwnerAuthorizationPayload.from_dict(
        {
            **payload.to_dict(),
            "candidate_evidence_pack_fingerprint": "e" * 64,
            "payload_fingerprint": None,
        }
    )
    world = synthetic_owner_authority_world(tmp_path / "pack-swap")
    provisioned = provision_synthetic_authorization(world, substituted)
    signed = consume_synthetic_authorization(world, provisioned)
    with pytest.raises(OwnerAuthorityGateError) as failure:
        revalidate_signed_owner_authority(
            signed_receipt=signed,
            installation=world["installation"],
            broker_client=world["client"],
            candidate_witness_store=prepared["store"],
            preparation_root=prepared["preparation_root"],
            retained_seal_identity=prepared["retained_seal_identity"],
            expected_model_binding_policy=prepared["policy"],
        )
    assert failure.value.classification == (
        "OWNER_AUTHORITY_CANDIDATE_EVIDENCE_CHANGED"
    )


def test_owner_payload_for_another_model_policy_is_refused(
    tmp_path: Path, primary
):
    prepared = build_sealed_candidate_preparation(
        tmp_path / "policy-swap", binding=primary
    )
    payload = build_owner_payload(prepared)
    other = ModelBindingPolicy.create(
        policy_kind="another_explicit_mission_policy_v1",
        configured_model="gpt-5.3-codex",
        configured_reasoning_effort="medium",
        allow_provider_model_fallback=False,
        codex_executable_identity=primary["identity"].to_dict(),
    )
    with pytest.raises(ModelConfigurationError, match="not the closed canary"):
        OwnerAuthorizationPayload.from_dict(
            {
                **payload.to_dict(),
                "model_binding_policy": other.to_dict(),
                "model_binding_policy_fingerprint": other.policy_fingerprint,
                "payload_fingerprint": None,
            }
        )


def test_signed_receipt_for_another_model_policy_is_refused(
    tmp_path: Path, primary, owner_bound
):
    other = ModelBindingPolicy.create(
        policy_kind="another_explicit_mission_policy_v1",
        configured_model="gpt-5.3-codex",
        configured_reasoning_effort="high",
        allow_provider_model_fallback=False,
        codex_executable_identity=primary["identity"].to_dict(),
    )
    with pytest.raises(ModelConfigurationError, match="not the closed canary"):
        _gate(owner_bound, expected_model_binding_policy=other)


def test_signed_receipt_for_another_preparation_root_is_refused(
    tmp_path: Path, primary, owner_bound
):
    other = create_owner_bound_canary_binding(
        tmp_path / "other-root", binding=primary
    )
    with pytest.raises(
        (OwnerAuthorityGateError, FuturePreflightSealError)
    ) as failure:
        _gate(owner_bound, preparation_root=other["preparation_root"])
    assert (
        "copied, moved or re-created" in str(failure.value)
        or "final seal differs" in str(failure.value)
        or getattr(failure.value, "classification", "")
        == "OWNER_AUTHORITY_PREPARATION_ROOT_CHANGED"
    )


def test_owner_payload_whose_run_differs_from_its_root_identity_is_refused(
    tmp_path: Path, primary
):
    prepared = build_sealed_candidate_preparation(
        tmp_path / "run-swap", binding=primary
    )
    payload = build_owner_payload(prepared)
    with pytest.raises(OwnerAuthorizationError) as failure:
        OwnerAuthorizationPayload.from_dict(
            {
                **payload.to_dict(),
                "run_id": "canary-run-substituted",
                "payload_fingerprint": None,
            }
        )
    assert failure.value.classification == "OWNER_PAYLOAD_INVALID"


def test_signed_receipt_for_another_run_is_refused(tmp_path: Path, primary):
    """A receipt from one run cannot be presented against another run's world."""

    if not privileged_identity_available():
        pytest.skip(PRIVILEGED_IDENTITY_REASON)
    first = create_owner_bound_canary_binding(tmp_path / "run-one", binding=primary)
    second = create_owner_bound_canary_binding(tmp_path / "run-two", binding=primary)
    assert first["signed_receipt"].run_id != second["signed_receipt"].run_id
    with pytest.raises(OwnerAuthorityError) as failure:
        _gate(first, world=second["owner_authority_world"])
    assert failure.value.classification in {
        "OWNER_AUTHORITY_RECEIPT_FOREIGN_INSTALLATION",
        "OWNER_AUTHORITY_ALREADY_CONSUMED",
    }


def test_owner_phrase_not_matching_the_provisioned_digest_is_refused(
    tmp_path: Path, primary
):
    if not privileged_identity_available():
        pytest.skip(PRIVILEGED_IDENTITY_REASON)
    prepared = build_sealed_candidate_preparation(
        tmp_path / "wrong-phrase", binding=primary
    )
    payload = build_owner_payload(prepared)
    world = synthetic_owner_authority_world(tmp_path / "wrong-phrase")
    provisioned = provision_synthetic_authorization(world, payload)
    with pytest.raises(OwnerAuthorityBrokerError) as failure:
        consume_synthetic_authorization(
            world, provisioned, phrase="a-different-synthetic-phrase"
        )
    assert failure.value.classification == "OWNER_AUTHORITY_PHRASE_REFUSED"
    # A refused phrase does not spend the authorization.
    assert world["client"].authorization_status(
        provisioned["authorization_record_id"]
    )["state"] == PROVISIONED_PENDING


# --------------------------------------------------------------------------
# 9-12. copied and extended preparation trees under the owner gate
# --------------------------------------------------------------------------


def test_copied_preparation_directory_under_the_owner_gate_is_refused(
    tmp_path: Path, owner_bound
):
    copied = tmp_path / "copied-preparation"
    shutil.copytree(owner_bound["preparation_root"], copied)
    with pytest.raises(FuturePreflightSealError, match="copied, moved or re-created"):
        _gate(owner_bound, preparation_root=copied)


@pytest.mark.parametrize(
    "mutation",
    ["added_file", "added_directory", "unexpected_empty_directory"],
)
def test_extended_preparation_tree_under_the_owner_gate_is_refused(
    owner_bound, mutation: str
):
    root = owner_bound["preparation_root"]
    if mutation == "added_file":
        (root / "extra.txt").write_bytes(b"unlisted\n")
    elif mutation == "added_directory":
        (root / "extra-directory").mkdir()
    else:
        (root / "evidence" / "empty").mkdir()
    with pytest.raises(FuturePreflightSealError, match="closed authorized entry set"):
        _gate(owner_bound)


# --------------------------------------------------------------------------
# 13-14. stale tails and authorization reuse
# --------------------------------------------------------------------------


def test_stale_candidate_tail_after_owner_authorization_is_refused(
    tmp_path: Path, secondary
):
    if not privileged_identity_available():
        pytest.skip(PRIVILEGED_IDENTITY_REASON)
    bound = create_owner_bound_canary_binding(
        tmp_path / "tail-advance", binding=secondary
    )
    # A second candidate witness advances the store tail past the authorized one.
    secondary["store"].record_candidate_witness(
        policy=secondary["policy"],
        codex_executable=secondary["codex"],
    )
    with pytest.raises(SerializationWitnessError, match="not the externally"):
        _gate(bound)


def test_owner_authorization_is_consumable_exactly_once(owner_bound):
    """The broker transaction is the only consumption, and it happens once."""

    world = owner_bound["owner_authority_world"]
    record_id = owner_bound["provisioned"]["authorization_record_id"]
    assert world["client"].authorization_status(record_id)["state"] == RECEIPT_ISSUED
    with pytest.raises(OwnerAuthorityBrokerError) as failure:
        consume_synthetic_authorization(world, owner_bound["provisioned"])
    assert failure.value.classification == "OWNER_AUTHORITY_ALREADY_CONSUMED"


def test_reconsuming_a_spent_authorization_is_refused(owner_bound):
    world = owner_bound["owner_authority_world"]
    world["client"].record_launch_result(
        authorization_record_id=owner_bound["provisioned"][
            "authorization_record_id"
        ],
        receipt_identity=owner_bound["signed_receipt"].receipt_identity,
        outcome="SYNTHETIC_TEST_LAUNCH",
    )
    with pytest.raises(OwnerAuthorityBrokerError) as failure:
        consume_synthetic_authorization(world, owner_bound["provisioned"])
    assert failure.value.classification == "OWNER_AUTHORITY_ALREADY_CONSUMED"
    # And the gate refuses the stale receipt afterwards.
    with pytest.raises(OwnerAuthorityGateError) as stale:
        _gate(owner_bound)
    assert stale.value.classification == "OWNER_AUTHORITY_ALREADY_CONSUMED"


# --------------------------------------------------------------------------
# 15-16. mode separation and pre-effect ordering
# --------------------------------------------------------------------------


def test_non_production_mode_never_produces_a_signed_receipt(primary):
    mode = NonProductionWitnessMode(primary["receipt"]).validated()
    assert not isinstance(
        mode.candidate_witness_receipt, SignedOwnerAuthorizationReceipt
    )
    assert not hasattr(mode, "signed_receipt")
    assert "NO_OWNER_BINDING" in mode.acknowledgement


def test_non_production_mode_must_acknowledge_that_it_is_not_production(primary):
    with pytest.raises(ValueError, match="must acknowledge"):
        NonProductionWitnessMode(
            primary["receipt"], acknowledgement="PRODUCTION"
        ).validated()


def test_a_receipt_rebuilt_from_its_own_fields_has_no_valid_signature(owner_bound):
    """Reconstructing every field is exactly what the audit attack did."""

    world = owner_bound["owner_authority_world"]
    body = owner_bound["signed_receipt"].to_dict()
    forged = SignedOwnerAuthorizationReceipt.from_dict(
        {
            **body,
            "signature_hex": "00" * 64,
            "receipt_identity": body["receipt_identity"],
        }
    )
    with pytest.raises(OwnerAuthorityError) as failure:
        _gate(owner_bound, signed_receipt=forged)
    assert failure.value.classification == "OWNER_AUTHORITY_SIGNATURE_REFUSED"


def test_the_pre_effect_gate_refuses_without_a_signed_receipt(owner_bound):
    with pytest.raises(OwnerAuthorityGateError) as failure:
        _gate(owner_bound, signed_receipt=owner_bound["receipt"])
    assert failure.value.classification == "OWNER_AUTHORITY_RECEIPT_ABSENT"


def _owner_bound_backend(tmp_path: Path, owner_bound):
    image_identity = "sha256:" + "d" * 64
    controller, session_store, capsule_authority = _backend_inputs(
        tmp_path / "backend", owner_bound, image_identity=image_identity
    )
    factory = ScriptedCodexConnectionFactory(
        ScriptedCodexAppServerConnection(()),
        codex_component_identity=owner_bound["identity"].to_dict(),
    )
    control_authority = AuthenticatedControlAuthority.create(
        codex_protocol_version="0.145.0",
        executable_identity=factory.codex_component_identity,
        policy_fingerprint=factory.host_policy_fingerprint,
        authentication_boundary_state=factory.authentication_boundary_state,
    )
    return HostCodexAppServerCapsuleBackend(
        authority=capsule_authority,
        control_authority=control_authority,
        controller=controller,
        session_store=session_store,
        connection_factory=factory,
        mission_prompt=SYNTHETIC_MISSION_PROMPT,
        witness_authority=owner_bound["owner_authority_witness"],
    )


def test_no_effect_is_prepared_after_the_preparation_tree_grows(
    tmp_path: Path, owner_bound
):
    """The pre-effect gate refuses before the capsule is prepared at all."""

    backend = _owner_bound_backend(tmp_path, owner_bound)
    (owner_bound["preparation_root"] / "late-addition.txt").write_bytes(b"late\n")
    with pytest.raises(FuturePreflightSealError, match="closed authorized entry set"):
        backend.prepare_workspace()
    # No capsule was created and the launch was never committed.
    assert backend._workspace_sessions == {}
    assert owner_bound["owner_authority_world"]["client"].authorization_status(
        owner_bound["provisioned"]["authorization_record_id"]
    )["state"] == RECEIPT_ISSUED


def test_a_second_backend_on_a_committed_launch_is_refused(
    tmp_path: Path, owner_bound
):
    backend = _owner_bound_backend(tmp_path, owner_bound)
    consumption = backend.consume_owner_authorization_once()
    assert consumption["consumed"] is True
    assert consumption["state"] == LAUNCH_RESULT_RECORDED
    with pytest.raises(OwnerAuthorityGateError) as failure:
        _owner_bound_backend(tmp_path / "second", owner_bound)
    assert failure.value.classification == "OWNER_AUTHORITY_ALREADY_CONSUMED"


def test_owner_authority_witness_refuses_a_candidate_receipt_in_its_slot(
    owner_bound,
):
    world = owner_bound["owner_authority_world"]
    with pytest.raises(ValueError, match="broker-signed owner"):
        SyntheticOwnerAuthorityWitness(
            signed_receipt=owner_bound["receipt"],
            installation=world["installation"],
            broker_client=world["client"],
            preparation_root=owner_bound["preparation_root"],
            retained_seal_identity=owner_bound["retained_seal_identity"],
        ).validated()


# --------------------------------------------------------------------------
# owner phrase channel and local login classification
# --------------------------------------------------------------------------


def test_the_owner_phrase_arrives_only_on_a_private_descriptor(tmp_path: Path):
    descriptor = owner_phrase_descriptor()
    try:
        assert read_owner_phrase_from_descriptor(descriptor) == SYNTHETIC_OWNER_PHRASE
    finally:
        os.close(descriptor)
    with pytest.raises(OwnerAuthorizationError) as failure:
        read_owner_phrase_from_descriptor(2**30)
    assert failure.value.classification == "OWNER_PHRASE_CHANNEL_REFUSED"


def test_the_owner_digest_binds_the_payload_and_the_root_chosen_record(
    tmp_path: Path, primary
):
    """The caller cannot precompute the digest: it binds a root-chosen identity."""

    prepared = build_sealed_candidate_preparation(
        tmp_path / "digest", binding=primary
    )
    payload = build_owner_payload(prepared)
    record_id = new_authorization_record_id()
    exact = external_owner_authorization_digest(
        phrase=SYNTHETIC_OWNER_PHRASE,
        payload_bytes=payload.canonical_payload_bytes(),
        authorization_record_id=record_id,
    )
    # A single byte of payload drift changes the digest.
    assert exact != external_owner_authorization_digest(
        phrase=SYNTHETIC_OWNER_PHRASE,
        payload_bytes=payload.canonical_payload_bytes() + b" ",
        authorization_record_id=record_id,
    )
    # And so does the record identity the privileged provisioner chose.
    assert exact != external_owner_authorization_digest(
        phrase=SYNTHETIC_OWNER_PHRASE,
        payload_bytes=payload.canonical_payload_bytes(),
        authorization_record_id=new_authorization_record_id(),
    )
    assert "v3" in EXTERNAL_OWNER_DIGEST_CONSTRUCTION
    assert payload.body["digest_construction"] == EXTERNAL_OWNER_DIGEST_CONSTRUCTION


def test_local_login_classification_reads_no_credential_bytes(tmp_path: Path):
    synthetic = tmp_path / "synthetic-auth.json"
    synthetic.write_text('{"synthetic": "not-a-real-credential"}', encoding="utf-8")
    synthetic.chmod(0o600)
    observed = classify_local_chatgpt_login(synthetic)
    assert observed["classification"] == "LOCAL_CHATGPT_LOGIN_PRESENT_METADATA_ONLY"
    assert observed["credential_bytes_read"] == 0
    assert observed["credential_content_observed"] is False
    assert "sha256" not in observed and "content" not in observed
    absent = classify_local_chatgpt_login(tmp_path / "absent.json")
    assert absent["classification"] == "LOCAL_CHATGPT_LOGIN_ABSENT"


def test_owner_payload_binds_every_required_witness_and_preparation_identity(
    owner_bound,
):
    body = owner_bound["payload"].to_dict()
    for key in (
        "repository_head",
        "implementation_head",
        "run_id",
        "preparation_id",
        "preparation_root_identity",
        "candidate_store_root_identity",
        "candidate_store_anchor_fingerprint",
        "candidate_evidence_pack_fingerprint",
        "candidate_receipt_identity",
        "candidate_witness_run_identity",
        "candidate_witness_run_nonce",
        "candidate_store_tail_identity",
        "model_binding_policy",
        "canonical_configuration_fingerprint",
        "codex_executable_identity",
        "protocol_schema_identity",
        "boundary_launcher_identity",
        "destination_manifest_identity",
        "mission_fingerprint",
        "tool_authority_identity",
        "budgets",
        "preflight_manifest_fingerprint",
        "preflight_seal_fingerprint",
        "retained_seal_identity",
        "zero_retry_policy",
    ):
        assert body[key], key
    assert body["zero_retry_policy"]["retries"] == 0
    assert body["zero_retry_policy"]["repairs"] == 0
    assert body["zero_retry_policy"]["launches_per_authorization"] == 1


def test_no_owner_phrase_material_appears_in_the_signed_receipt(owner_bound):
    rendered = canonical_bytes(
        owner_bound["signed_receipt"].to_dict()
    ).decode("utf-8")
    assert SYNTHETIC_OWNER_PHRASE not in rendered
    for denied in ("credential", "prompt_text", "authorization_header"):
        assert denied not in rendered.lower()
    # Every occurrence of "phrase" belongs to the construction label, never to
    # phrase material: removing the label leaves no occurrence behind.
    assert EXTERNAL_OWNER_DIGEST_CONSTRUCTION in rendered
    assert "phrase" not in rendered.replace(
        EXTERNAL_OWNER_DIGEST_CONSTRUCTION, ""
    )
    # The expected digest itself never leaves the root-owned state.
    assert "expected_owner_authorization_digest" not in rendered
