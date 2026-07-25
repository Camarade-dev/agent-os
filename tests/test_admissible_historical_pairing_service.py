"""Step 5C2C2: the bounded product-layer historical pairing service.

Every confirmation tag used here is produced by an independent oracle that
re-implements the documented construction with the standard library, starting
from the public confirmation-message bytes the accepted owner review encodes.
The product is never asked to produce a credential it is then verified against,
and no test in this module calls the accepted tag helper.
"""

from __future__ import annotations

import ast
import base64
import builtins
from collections.abc import Mapping as AbstractMapping
import hashlib
import hmac
import json
import os
from pathlib import Path
from types import FunctionType, ModuleType

import pytest

from admissible.delegated_gate.historical_evaluation_store import (
    load_historical_evaluation_pairing,
)
from admissible.delegated_gate.historical_pairing_review import (
    HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES,
    HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS,
    PREPARATION_STATE_CONSUMED,
    PREPARATION_STATE_READY_FOR_CONFIRMATION,
)
from admissible.delegated_gate.historical_pairing_workflow import (
    CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE,
    HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS,
    HistoricalEvaluationPairingCoordinator,
    HistoricalPairingWorkflowError,
    InvalidPairingCoordinatorConfiguration,
    InvalidPairingPreparationRequest,
    MalformedPairingConfirmationTag,
    PairingArchiveConflict,
    PairingArchiveContentMismatch,
    PairingArchiveDurabilityUncertain,
    PairingArchiveReloadFailed,
    PairingArchiveWriteFailed,
    PairingConfirmationRejected,
    PairingPreparationCapacityExhausted,
    PairingPreparationConsumed,
    PairingPreparationExpired,
    PairingPreparationIdentifierUnavailable,
    PairingPreparationInUse,
    PairingPreparationNotFound,
    StalePairingAuthorityFingerprint,
)
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V5,
)
from admissible.delegated_gate.native_canary import (
    EVIDENCE_DIRECTORY_NAME,
    NATIVE_SIDECAR_DIRECTORY_NAME,
    WORKSPACE_DIRECTORY_NAME,
    NativeCanaryAuthorizationPayloadV4,
    load_historical_native_canary_authorization_payload_v4,
)
from admissible.product_launcher import historical_pairing_service as service_module
from admissible.product_launcher.historical_pairing_registry import (
    HistoricalPairingConfiguration,
    HistoricalPayloadEntry,
    HistoricalPayloadRegistry,
    MalformedHistoricalPayloadDocument,
)
from admissible.product_launcher.historical_pairing_service import (
    CONFIRMATION_ERROR_MAPPING,
    PREPARATION_ERROR_MAPPING,
    REVIEW_ERROR_MAPPING,
    HistoricalPairingFeatureConfigurationError,
    HistoricalPairingService,
    build_historical_pairing_service,
)
from test_admissible_historical_evaluation_pairing import _refingerprint_payload
from test_admissible_historical_pairing_confirmation import _fragments_of
from test_admissible_historical_v5_derivation import (
    _owner_bindings,
    _owner_claims,
    _owner_plan,
    _runtime_v2_profile,
)
from test_admissible_workflow_recovery_profile import _payload_harness


# ---------------------------------------------------------------------------
# Fixture material.
#
# Both secrets are deliberately structureless printable ASCII so the derived
# forbidden-fragment sets stay small, deterministic, and impossible to match by
# accident inside ordinary source text or a canonical document.  They are
# fixture material and no real secret.
# ---------------------------------------------------------------------------

PAIRING_SECRET = b"Kw3Yp6Bn9Zt2Qs5Rd8Lf1Gh4Mv7Xc0Ju3Ei6Ab9Ty2"
OTHER_SECRET = b"Nz5Hd8Kq1Vw4Rb7Ts0Ga3Mp6Cy9Lx2Ju5Fo8Ie1Sd4"
ACTOR_ID = "owner.asserted-actor"
OTHER_ACTOR_ID = "owner.other-asserted-actor"
PAYLOAD_ID = "alpha-historical-run"
OTHER_PAYLOAD_ID = "bravo-historical-run"

# The exact four route-visible payload metadata fields.  Nothing configured --
# no document path and no archive root -- may ever join them.
EXPECTED_PAYLOAD_FIELDS = frozenset(
    {
        "payload_id",
        "payload_fingerprint",
        "document_sha256",
        "document_byte_length",
    }
)

EXPECTED_CONFIRMATION_FIELDS = frozenset(
    {
        "outcome",
        "preparation_id",
        "asserted_actor_id",
        "pairing_authority_fingerprint",
        "evaluation_profile_fingerprint",
        "target_authorization_payload_fingerprint",
        "archived_pairing_document_count",
        "limitations",
    }
)


def _oracle_canonical_bytes(mapping: dict) -> bytes:
    """Re-implement the documented canonical rule with the standard library."""

    return json.dumps(
        mapping, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def build_historical_payload(
    fixture_root: Path,
) -> NativeCanaryAuthorizationPayloadV4:
    """One exact historical V4 payload whose every carried path is absent."""

    runtime_profile = _runtime_v2_profile()
    live = _payload_harness(fixture_root, runtime_profile).payload.to_dict()
    absent = fixture_root / "absent-original-material"
    live["source_repository"] = str(absent / "source")
    live["executable"] = str(absent / "bin" / "agent.exe")
    live["launcher_prefix"] = [
        str(absent / "bin" / f"launcher-{index}.exe")
        for index, _value in enumerate(live["launcher_prefix"])
    ]
    run_root = absent / runtime_profile.run_id
    live["run_root"] = str(run_root)
    live["workspace_root"] = str(run_root / WORKSPACE_DIRECTORY_NAME)
    live["evidence_root"] = str(run_root / EVIDENCE_DIRECTORY_NAME)
    live["native_sidecar_root"] = str(
        run_root / EVIDENCE_DIRECTORY_NAME / NATIVE_SIDECAR_DIRECTORY_NAME
    )
    payload = load_historical_native_canary_authorization_payload_v4(
        _refingerprint_payload(live)
    )
    assert not absent.exists()
    return payload


def build_second_historical_payload(
    fixture_root: Path,
) -> NativeCanaryAuthorizationPayloadV4:
    """A second, genuinely distinct payload for ordering and duplicate proofs."""

    from test_admissible_historical_evaluation_pairing import (
        _payload_for_runtime_profile,
        _refingerprint_profile,
    )
    from admissible.delegated_gate.mission_profile import NativeMissionProfile

    first = build_historical_payload(fixture_root)
    profile = first.mission_profile.to_dict()
    profile["mission_text"] = profile["mission_text"] + "\nSecond mission."
    variant = NativeMissionProfile.from_dict(_refingerprint_profile(profile))
    second = _payload_for_runtime_profile(first, variant)
    assert second.payload_fingerprint != first.payload_fingerprint
    return second


@pytest.fixture(scope="module")
def historical_payload(
    tmp_path_factory: pytest.TempPathFactory,
) -> NativeCanaryAuthorizationPayloadV4:
    return build_historical_payload(tmp_path_factory.mktemp("s5c2c2-a"))


@pytest.fixture(scope="module")
def other_payload(
    tmp_path_factory: pytest.TempPathFactory,
) -> NativeCanaryAuthorizationPayloadV4:
    return build_second_historical_payload(tmp_path_factory.mktemp("s5c2c2-b"))


def owner_material(payload: NativeCanaryAuthorizationPayloadV4) -> dict:
    """Fresh owner-authored member arrays for one preparation request."""

    return {
        "result_claims": _owner_claims(),
        "claim_verification_plan": _owner_plan(),
        "verification_evidence_bindings": _owner_bindings(
            payload.mission_profile.verification.verifier_source_sha256
        ),
    }


def write_document(path: Path, payload: NativeCanaryAuthorizationPayloadV4) -> Path:
    path.write_bytes(_oracle_canonical_bytes(payload.to_dict()))
    return path


def pairing_configuration(
    root: Path,
    entries: tuple[HistoricalPayloadEntry, ...],
    **overrides,
) -> HistoricalPairingConfiguration:
    values = dict(
        archive_root=(root / "archive").resolve(),
        payload_entries=entries,
    )
    values.update(overrides)
    return HistoricalPairingConfiguration(**values)


def single_entry_configuration(
    root: Path,
    payload: NativeCanaryAuthorizationPayloadV4,
    *,
    payload_id: str = PAYLOAD_ID,
    **overrides,
) -> HistoricalPairingConfiguration:
    documents = root / "documents"
    documents.mkdir(parents=True, exist_ok=True)
    document = write_document(documents / f"{payload_id}.json", payload)
    return pairing_configuration(
        root,
        (
            HistoricalPayloadEntry(
                payload_id=payload_id, document_path=document.resolve()
            ),
        ),
        **overrides,
    )


def independent_confirmation_tag(secret: bytes, review: dict) -> str:
    """Compute one tag the way a trusted caller outside the product would.

    Only the public confirmation-message bytes carried by the owner review and
    the caller's own copy of the shared secret are used.  The accepted product
    tag helper is deliberately never called.
    """

    message = base64.b64decode(
        review["pairing_identity"]["confirmation_message_base64"], validate=True
    )
    return hmac.new(key=secret, msg=message, digestmod=hashlib.sha256).hexdigest()


@pytest.fixture()
def service(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
) -> HistoricalPairingService:
    return HistoricalPairingService(
        configuration=single_entry_configuration(tmp_path, historical_payload),
        configured_secret=PAIRING_SECRET,
    )


def prepared(
    service: HistoricalPairingService,
    payload: NativeCanaryAuthorizationPayloadV4,
    *,
    payload_id: str = PAYLOAD_ID,
    actor_id: str = ACTOR_ID,
) -> tuple[int, dict]:
    return service.prepare(
        payload_id=payload_id,
        actor_id=actor_id,
        **owner_material(payload),
    )


# ---------------------------------------------------------------------------
# A. Feature construction and absence.
# ---------------------------------------------------------------------------


def test_both_optional_inputs_absent_disables_the_feature_entirely():
    assert (
        build_historical_pairing_service(
            configuration=None, configured_secret=None
        )
        is None
    )


def test_only_configuration_supplied_refuses_construction(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    configuration = single_entry_configuration(tmp_path, historical_payload)
    with pytest.raises(HistoricalPairingFeatureConfigurationError):
        build_historical_pairing_service(
            configuration=configuration, configured_secret=None
        )


def test_only_secret_supplied_refuses_construction():
    with pytest.raises(HistoricalPairingFeatureConfigurationError):
        build_historical_pairing_service(
            configuration=None, configured_secret=PAIRING_SECRET
        )


def test_partial_configuration_error_discloses_nothing(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """The bounded refusal names no secret, length, root, path, or payload."""

    configuration = single_entry_configuration(tmp_path, historical_payload)
    document_path = str(configuration.payload_entries[0].document_path)
    archive_root = str(configuration.archive_root)
    with pytest.raises(HistoricalPairingFeatureConfigurationError) as first:
        build_historical_pairing_service(
            configuration=configuration, configured_secret=None
        )
    with pytest.raises(HistoricalPairingFeatureConfigurationError) as second:
        build_historical_pairing_service(
            configuration=None, configured_secret=PAIRING_SECRET
        )
    fragments = _fragments_of(PAIRING_SECRET, "0" * 64)
    for info in (first, second):
        rendered = f"{info.value} {info.value.args!r} {info.value!r}"
        assert document_path not in rendered
        assert archive_root not in rendered
        assert str(len(PAIRING_SECRET)) not in rendered
        assert historical_payload.payload_fingerprint not in rendered
        assert not [item for item in fragments if item in rendered]


def test_zero_payload_entries_is_a_configuration_defect_not_a_disable(
    tmp_path: Path,
):
    configuration = pairing_configuration(tmp_path, ())
    with pytest.raises(HistoricalPairingFeatureConfigurationError):
        build_historical_pairing_service(
            configuration=configuration, configured_secret=PAIRING_SECRET
        )


def test_invalid_payload_document_aborts_service_construction(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    documents = tmp_path / "documents"
    documents.mkdir()
    document = documents / "broken.json"
    document.write_bytes(b'{"schema_version": "wrong"}')
    configuration = pairing_configuration(
        tmp_path,
        (
            HistoricalPayloadEntry(
                payload_id=PAYLOAD_ID, document_path=document.resolve()
            ),
        ),
    )
    with pytest.raises(MalformedHistoricalPayloadDocument):
        build_historical_pairing_service(
            configuration=configuration, configured_secret=PAIRING_SECRET
        )


def test_non_exact_configuration_and_secret_types_are_refused(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    configuration = single_entry_configuration(tmp_path, historical_payload)
    with pytest.raises(HistoricalPairingFeatureConfigurationError):
        HistoricalPairingService(
            configuration=object(), configured_secret=PAIRING_SECRET
        )
    with pytest.raises(HistoricalPairingFeatureConfigurationError):
        HistoricalPairingService(
            configuration=configuration,
            configured_secret=bytearray(PAIRING_SECRET),
        )
    with pytest.raises(HistoricalPairingFeatureConfigurationError):
        HistoricalPairingService(
            configuration=configuration,
            configured_secret=PAIRING_SECRET.decode("ascii"),
        )


def test_configured_secret_reaches_the_coordinator_as_the_exact_same_bytes(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """No textual conversion, copy, trim, or re-encoding happens in this slice."""

    built = HistoricalPairingService(
        configuration=single_entry_configuration(tmp_path, historical_payload),
        configured_secret=PAIRING_SECRET,
    )
    assert built._coordinator._configured_secret is PAIRING_SECRET


def test_service_owns_exactly_one_registry_and_one_coordinator(
    service: HistoricalPairingService,
):
    owned = dict(vars(service))
    assert set(owned) == {"_registry", "_coordinator"}
    assert isinstance(owned["_registry"], HistoricalPayloadRegistry)
    assert isinstance(owned["_coordinator"], HistoricalEvaluationPairingCoordinator)


def test_service_repr_is_fixed_and_bounded(
    service: HistoricalPairingService,
    tmp_path: Path,
):
    rendered = repr(service)
    assert rendered == "<HistoricalPairingService>"
    assert str(tmp_path) not in rendered
    assert "0x" not in rendered
    assert not any(character.isdigit() for character in rendered)


# ---------------------------------------------------------------------------
# B. Independent credential production.
# ---------------------------------------------------------------------------


def _module_imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
            names.update(alias.name for alias in node.names)
    return names


def test_service_module_imports_no_credential_generation_machinery():
    path = Path(service_module.__file__)
    imported = _module_imported_names(path)
    assert "hmac" not in imported
    assert "hashlib" not in imported
    assert "compute_historical_pairing_confirmation_tag" not in imported
    assert not hasattr(service_module, "hmac")
    assert not hasattr(service_module, "hashlib")


def _code_identifiers(path: Path) -> set[str]:
    """Every identifier a module actually uses, ignoring prose and comments.

    Docstrings are deliberately excluded: a module documenting that it never
    imports the tag helper is stating the law, not breaking it.  Imports,
    names, attributes, keywords, and string constants used as code are all
    inspected.
    """

    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        )
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.keyword) and node.arg:
            names.add(node.arg)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.update({alias.name, alias.asname or alias.name})
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
            for alias in node.names:
                names.update({alias.name, alias.asname or alias.name})
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in docstrings:
                names.add(node.value)
    return names


def test_no_product_module_references_the_tag_helper():
    """The product may never compute a confirmation credential anywhere."""

    root = Path(__file__).resolve().parents[1] / "admissible"
    scanned = 0
    offenders = []
    for tree in ("product_launcher", "product_service", "product_ui"):
        for path in sorted((root / tree).rglob("*.py")):
            scanned += 1
            if "compute_historical_pairing_confirmation_tag" in _code_identifiers(
                path
            ):
                offenders.append(str(path))
    assert scanned > 0
    assert offenders == []
    # The guard is not vacuous: a real code reference is detected.
    probe = root / "product_launcher" / "historical_pairing_service.py"
    assert "HistoricalEvaluationPairingCoordinator" in _code_identifiers(probe)


def test_service_exposes_no_tag_computer_or_expected_tag_surface():
    public = {name for name in dir(HistoricalPairingService) if not name.startswith("_")}
    assert public == {"confirm", "payloads", "prepare", "review"}
    for name in dir(service_module):
        assert "compute" not in name
        assert "expected_tag" not in name


# ---------------------------------------------------------------------------
# C. Payload listing.
# ---------------------------------------------------------------------------


def test_payload_listing_preserves_declaration_order_and_exact_fields(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    other_payload: NativeCanaryAuthorizationPayloadV4,
):
    documents = tmp_path / "documents"
    documents.mkdir()
    # Declared second-then-first on purpose: nothing may sort the answer.
    second = write_document(documents / "second.json", other_payload)
    first = write_document(documents / "first.json", historical_payload)
    configuration = pairing_configuration(
        tmp_path,
        (
            HistoricalPayloadEntry(
                payload_id=OTHER_PAYLOAD_ID, document_path=second.resolve()
            ),
            HistoricalPayloadEntry(
                payload_id=PAYLOAD_ID, document_path=first.resolve()
            ),
        ),
    )
    built = HistoricalPairingService(
        configuration=configuration, configured_secret=PAIRING_SECRET
    )
    status, body = built.payloads()
    assert status == 200
    assert set(body) == {"payloads"}
    listed = body["payloads"]
    assert [item["payload_id"] for item in listed] == [OTHER_PAYLOAD_ID, PAYLOAD_ID]
    assert [item["payload_fingerprint"] for item in listed] == [
        other_payload.payload_fingerprint,
        historical_payload.payload_fingerprint,
    ]
    for record, path, payload in (
        (listed[0], second, other_payload),
        (listed[1], first, historical_payload),
    ):
        assert set(record) == EXPECTED_PAYLOAD_FIELDS
        raw = path.read_bytes()
        assert record["document_sha256"] == hashlib.sha256(raw).hexdigest()
        assert record["document_byte_length"] == len(raw)
        assert record["payload_fingerprint"] == payload.payload_fingerprint


def test_payload_listing_exposes_no_document_path_or_archive_root(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    configuration = single_entry_configuration(tmp_path, historical_payload)
    built = HistoricalPairingService(
        configuration=configuration, configured_secret=PAIRING_SECRET
    )
    _status, body = built.payloads()
    rendered = json.dumps(body, sort_keys=True)
    assert str(configuration.payload_entries[0].document_path) not in rendered
    assert str(configuration.archive_root) not in rendered
    assert str(tmp_path) not in rendered
    for forbidden in ("path", "root", "directory", "document_path"):
        assert not any(forbidden in key for key in body["payloads"][0])


def test_payload_listing_and_preparation_touch_no_filesystem(
    monkeypatch: pytest.MonkeyPatch,
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """Documents are opened during construction only, never per request."""

    touches: list[str] = []

    def recorder(name, original):
        def observed(*args, **kwargs):
            touches.append(name)
            return original(*args, **kwargs)

        return observed

    monkeypatch.setattr(builtins, "open", recorder("open", builtins.open))
    for name in ("lstat", "stat", "open", "listdir", "scandir", "walk"):
        monkeypatch.setattr(os, name, recorder(f"os.{name}", getattr(os, name)))
    monkeypatch.setattr(Path, "open", recorder("Path.open", Path.open))

    listed = service.payloads()
    created = prepared(service, historical_payload)
    monkeypatch.undo()

    assert touches == []
    assert listed[0] == 200
    assert created[0] == 201


# ---------------------------------------------------------------------------
# D. Preparation and the complete owner review.
# ---------------------------------------------------------------------------


def test_preparation_answers_with_the_complete_coordinator_review(
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    status, body = prepared(service, historical_payload)
    assert status == 201
    assert set(body) == {
        "pairing_identity",
        "claim_authority",
        "verification_plan_authority",
        "verification_evidence_binding_authority",
        "historical_mission_context",
        "historical_authority_context",
        "compatibility_revalidation",
        "withheld_fields",
        "notices",
    }
    identity = body["pairing_identity"]
    assert identity["preparation_state"] == PREPARATION_STATE_READY_FOR_CONFIRMATION
    assert identity["asserted_actor_id"] == ACTOR_ID
    assert identity["evaluation_profile_is_launchable"] is False
    assert identity["evaluation_profile_schema_version"] == (
        MISSION_PROFILE_SCHEMA_VERSION_V5
    )
    assert identity["target_authorization_payload_fingerprint"] == (
        historical_payload.payload_fingerprint
    )
    assert body["withheld_fields"] == list(
        HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS
    )
    assert body["notices"] == list(HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES)


def test_preparation_obtains_the_review_through_the_coordinator_review_api(
    monkeypatch: pytest.MonkeyPatch,
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """The answering review is refreshed, never assembled by the service."""

    calls: list[dict] = []
    original = service._coordinator.get_historical_evaluation_pairing_review

    def spy(**kwargs):
        calls.append(dict(kwargs))
        return original(**kwargs)

    monkeypatch.setattr(
        service._coordinator,
        "get_historical_evaluation_pairing_review",
        spy,
    )
    status, body = prepared(service, historical_payload)
    assert status == 201
    assert len(calls) == 1
    assert set(calls[0]) == {"preparation_id", "expected_authority_fingerprint"}
    assert calls[0]["preparation_id"] == body["pairing_identity"]["preparation_id"]
    assert calls[0]["expected_authority_fingerprint"] == (
        body["pairing_identity"]["pairing_authority_fingerprint"]
    )


def test_owner_material_is_delegated_unchanged_and_later_mutation_is_inert(
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    material = owner_material(historical_payload)
    status, body = service.prepare(
        payload_id=PAYLOAD_ID, actor_id=ACTOR_ID, **material
    )
    assert status == 201
    claims_before = [
        claim["claim_id"] for claim in body["claim_authority"]["claims"]
    ]
    # Mutating the very containers the request carried must not reach the
    # pinned preparation: the derivation already copied everything it needs.
    material["result_claims"].append(
        {
            "claim_id": "claim.injected",
            "statement": "Injected after preparation.",
            "obligation_level": "MANDATORY",
            "depends_on": [],
            "non_claims": [],
        }
    )
    material["result_claims"][0]["statement"] = "Rewritten after preparation."
    identity = body["pairing_identity"]
    status, refreshed = service.review(
        preparation_id=identity["preparation_id"],
        expected_authority_fingerprint=identity["pairing_authority_fingerprint"],
    )
    assert status == 200
    assert [
        claim["claim_id"] for claim in refreshed["claim_authority"]["claims"]
    ] == claims_before
    assert refreshed["claim_authority"]["claims"][0]["statement"] != (
        "Rewritten after preparation."
    )


def test_unknown_and_malformed_payload_identifiers_share_one_refusal(
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    tmp_path: Path,
):
    material = owner_material(historical_payload)
    answers = []
    for candidate in (
        "unregistered-payload",
        "NOT-LOWERCASE",
        "a",
        "../escape",
        str(tmp_path / "documents" / f"{PAYLOAD_ID}.json"),
        "",
        None,
        123,
        {"payload_id": PAYLOAD_ID},
    ):
        answers.append(
            service.prepare(payload_id=candidate, actor_id=ACTOR_ID, **material)
        )
    assert answers == [(404, {"error": "PAYLOAD_NOT_ALLOWLISTED"})] * len(answers)


def test_invalid_owner_material_is_a_bounded_unprocessable_refusal(
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    material = owner_material(historical_payload)
    assert service.prepare(
        payload_id=PAYLOAD_ID, actor_id=ACTOR_ID, **{**material, "result_claims": []}
    ) == (422, {"error": "PAIRING_INPUTS_INVALID"})
    assert service.prepare(
        payload_id=PAYLOAD_ID, actor_id="", **material
    ) == (422, {"error": "PAIRING_INPUTS_INVALID"})
    assert service.prepare(
        payload_id=PAYLOAD_ID, actor_id=object(), **material
    ) == (422, {"error": "PAIRING_INPUTS_INVALID"})


def test_preparation_capacity_is_a_bounded_refusal(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    built = HistoricalPairingService(
        configuration=single_entry_configuration(
            tmp_path, historical_payload, max_preparations=1
        ),
        configured_secret=PAIRING_SECRET,
    )
    assert prepared(built, historical_payload)[0] == 201
    assert prepared(built, historical_payload, actor_id=OTHER_ACTOR_ID) == (
        429,
        {"error": "PREPARATION_CAPACITY"},
    )


# ---------------------------------------------------------------------------
# E. Review.
# ---------------------------------------------------------------------------


def test_review_is_freshly_generated_and_independent_of_earlier_answers(
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, first = prepared(service, historical_payload)
    identity = first["pairing_identity"]
    locator = dict(
        preparation_id=identity["preparation_id"],
        expected_authority_fingerprint=identity["pairing_authority_fingerprint"],
    )
    _status, second = service.review(**locator)
    assert second == first
    assert second is not first
    assert second["claim_authority"] is not first["claim_authority"]
    # Mutating one answer can never reach the coordinator or a later answer.
    second["notices"].append("injected")
    second["pairing_identity"]["asserted_actor_id"] = "impostor"
    second["claim_authority"]["claims"].clear()
    _status, third = service.review(**locator)
    assert third == first


def test_review_requires_the_complete_exact_fingerprint(
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, body = prepared(service, historical_payload)
    identity = body["pairing_identity"]
    fingerprint = identity["pairing_authority_fingerprint"]
    preparation_id = identity["preparation_id"]
    assert service.review(
        preparation_id=preparation_id,
        expected_authority_fingerprint=fingerprint[:63],
    ) == (400, {"error": "PAIRING_LOCATOR_INVALID"})
    assert service.review(
        preparation_id=preparation_id,
        expected_authority_fingerprint=fingerprint.upper(),
    ) == (400, {"error": "PAIRING_LOCATOR_INVALID"})
    assert service.review(
        preparation_id=preparation_id,
        expected_authority_fingerprint="f" * 64,
    ) == (409, {"error": "STALE_AUTHORITY_FINGERPRINT"})
    assert service.review(
        preparation_id="unknown-preparation-id",
        expected_authority_fingerprint=fingerprint,
    ) == (404, {"error": "PREPARATION_NOT_FOUND"})
    assert service.review(
        preparation_id="!!", expected_authority_fingerprint=fingerprint
    ) == (400, {"error": "PAIRING_LOCATOR_INVALID"})


def test_review_answers_for_a_consumed_record_and_never_extends_ttl(
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, body = prepared(service, historical_payload)
    identity = body["pairing_identity"]
    locator = dict(
        preparation_id=identity["preparation_id"],
        expected_authority_fingerprint=identity["pairing_authority_fingerprint"],
    )
    created_at = service._coordinator._preparations[
        identity["preparation_id"]
    ].created_at
    assert service.review(**locator)[0] == 200
    assert (
        service._coordinator._preparations[identity["preparation_id"]].created_at
        == created_at
    )
    status, _result = service.confirm(
        **locator,
        presented_confirmation_tag=independent_confirmation_tag(
            PAIRING_SECRET, body
        ),
    )
    assert status == 200
    status, consumed = service.review(**locator)
    assert status == 200
    assert consumed["pairing_identity"]["preparation_state"] == (
        PREPARATION_STATE_CONSUMED
    )


def test_expired_preparation_is_reported_as_expired_not_missing(
    tmp_path: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    built = HistoricalPairingService(
        configuration=single_entry_configuration(tmp_path, historical_payload),
        configured_secret=PAIRING_SECRET,
    )
    ticks = iter([0.0, 0.0, 10_000.0, 10_000.0, 10_000.0, 10_000.0, 10_000.0])
    built._coordinator._clock = lambda: next(ticks)
    _status, body = prepared(built, historical_payload)
    identity = body["pairing_identity"]
    locator = dict(
        preparation_id=identity["preparation_id"],
        expected_authority_fingerprint=identity["pairing_authority_fingerprint"],
    )
    assert built.review(**locator) == (410, {"error": "PREPARATION_EXPIRED"})


# ---------------------------------------------------------------------------
# F. Confirmation.
# ---------------------------------------------------------------------------


def test_correct_independent_tag_is_accepted_with_a_bounded_result(
    tmp_path: Path,
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, body = prepared(service, historical_payload)
    identity = body["pairing_identity"]
    status, result = service.confirm(
        preparation_id=identity["preparation_id"],
        expected_authority_fingerprint=identity["pairing_authority_fingerprint"],
        presented_confirmation_tag=independent_confirmation_tag(
            PAIRING_SECRET, body
        ),
    )
    assert status == 200
    assert set(result) == EXPECTED_CONFIRMATION_FIELDS
    assert result["outcome"] == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    assert result["asserted_actor_id"] == ACTOR_ID
    assert result["archived_pairing_document_count"] == 3
    assert result["limitations"] == list(HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS)
    assert result["target_authorization_payload_fingerprint"] == (
        historical_payload.payload_fingerprint
    )
    # The single accepted outcome meaning: no CREATED/REPLAY distinction, no
    # signature, no authenticated actor, and no durable-confirmation claim.
    # The honest disclaimers themselves are pinned by the limitations equality
    # above, so the overclaim scan is applied to the keys and the outcome only.
    assert "CREATED" not in result["outcome"]
    assert "REPLAY" not in result["outcome"]
    for key in result:
        for forbidden in (
            "receipt",
            "signature",
            "signed",
            "authenticated",
            "durable",
            "possession",
            "proof",
            "created",
            "replay",
        ):
            assert forbidden not in key


def test_confirmation_result_never_serializes_the_reloaded_bundle(
    tmp_path: Path,
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, body = prepared(service, historical_payload)
    identity = body["pairing_identity"]
    _status, result = service.confirm(
        preparation_id=identity["preparation_id"],
        expected_authority_fingerprint=identity["pairing_authority_fingerprint"],
        presented_confirmation_tag=independent_confirmation_tag(
            PAIRING_SECRET, body
        ),
    )
    # Every value is a bounded scalar or a flat string list: no canonical
    # mapping, store object, archive path, or nested document can hide here.
    assert set(result) == EXPECTED_CONFIRMATION_FIELDS
    for value in result.values():
        assert isinstance(value, (str, int))or (
            isinstance(value, list) and all(isinstance(item, str) for item in value)
        )
    assert isinstance(result["archived_pairing_document_count"], int)
    rendered = json.dumps(result, sort_keys=True)
    for forbidden in (
        "admissible_native_mission_profile_v5",
        "admissible_native_canary_authorization_v4",
        "admissible_historical_evaluation_pairing_v1",
        "mission_text",
        "runtime_prompt",
        "checkpoint_commands",
        "initialized_workspace",
        historical_payload.mission_profile.mission_text,
        historical_payload.source_repository,
        str(tmp_path),
    ):
        assert forbidden not in rendered


def test_every_wrong_credential_shape_reaches_one_fixed_code(
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """A public fingerprint, a foreign tag and a wrong-secret tag look alike."""

    _status, body = prepared(service, historical_payload)
    identity = body["pairing_identity"]
    locator = dict(
        preparation_id=identity["preparation_id"],
        expected_authority_fingerprint=identity["pairing_authority_fingerprint"],
    )
    correct = independent_confirmation_tag(PAIRING_SECRET, body)
    wrong_secret = independent_confirmation_tag(OTHER_SECRET, body)
    rejected = [
        identity["pairing_authority_fingerprint"],
        identity["evaluation_profile_fingerprint"],
        identity["target_authorization_payload_fingerprint"],
        identity["confirmation_message_sha256"],
        historical_payload.payload_fingerprint,
        hashlib.sha256(b"runtime-owner-authorization-phrase").hexdigest(),
        wrong_secret,
        "0" * 64,
    ]
    for candidate in rejected:
        assert len(candidate) == 64
        assert service.confirm(**locator, presented_confirmation_tag=candidate) == (
            403,
            {"error": "CONFIRMATION_REJECTED"},
        )
    for malformed in (
        correct.upper(),
        correct + " ",
        " " + correct,
        correct[:63],
        correct + "0",
        "",
        None,
        123,
    ):
        assert service.confirm(
            **locator, presented_confirmation_tag=malformed
        ) == (400, {"error": "CONFIRMATION_TAG_MALFORMED"})
    # The preparation survives every refusal and the correct tag still works.
    assert service.confirm(**locator, presented_confirmation_tag=correct)[0] == 200


def test_retry_after_a_successful_confirmation_reports_consumed(
    tmp_path: Path,
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, body = prepared(service, historical_payload)
    identity = body["pairing_identity"]
    locator = dict(
        preparation_id=identity["preparation_id"],
        expected_authority_fingerprint=identity["pairing_authority_fingerprint"],
    )
    tag = independent_confirmation_tag(PAIRING_SECRET, body)
    assert service.confirm(**locator, presented_confirmation_tag=tag)[0] == 200
    assert service.confirm(**locator, presented_confirmation_tag=tag) == (
        409,
        {"error": "PREPARATION_CONSUMED"},
    )
    archive = tmp_path / "archive"
    documents = sorted(
        path.relative_to(archive).as_posix()
        for path in archive.rglob("*")
        if path.is_file()
    )
    assert len(documents) == 3


def test_confirmed_archive_reloads_with_exactly_three_non_launchable_documents(
    tmp_path: Path,
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, body = prepared(service, historical_payload)
    identity = body["pairing_identity"]
    status, result = service.confirm(
        preparation_id=identity["preparation_id"],
        expected_authority_fingerprint=identity["pairing_authority_fingerprint"],
        presented_confirmation_tag=independent_confirmation_tag(
            PAIRING_SECRET, body
        ),
    )
    assert status == 200
    bundle = load_historical_evaluation_pairing(
        archive_root=(tmp_path / "archive").resolve(),
        authority_fingerprint=result["pairing_authority_fingerprint"],
    )
    assert bundle.evaluation_profile.schema_version == (
        MISSION_PROFILE_SCHEMA_VERSION_V5
    )
    assert bundle.evaluation_profile.is_launchable_runtime_profile is False
    assert bundle.target_authorization_payload.payload_fingerprint == (
        historical_payload.payload_fingerprint
    )


# ---------------------------------------------------------------------------
# G. Error mapping by exception type only.
# ---------------------------------------------------------------------------


class _UnexpectedWorkflowError(HistoricalPairingWorkflowError):
    """A workflow failure the mapping has deliberately never heard of."""


class _RaisingCoordinator:
    """Stand-in coordinator raising one chosen bounded domain failure."""

    def __init__(self, error: BaseException) -> None:
        self._error = error
        self.calls: list[str] = []

    def prepare_historical_evaluation_pairing(self, **_kwargs):
        self.calls.append("prepare")
        raise self._error

    def get_historical_evaluation_pairing_review(self, **_kwargs):
        self.calls.append("review")
        raise self._error

    def confirm_historical_evaluation_pairing(self, **_kwargs):
        self.calls.append("confirm")
        raise self._error


LEAK_SENTINEL = "SENTINEL-LEAKABLE-EXCEPTION-TEXT"


def _leaky(kind: type) -> BaseException:
    """One domain failure whose message and cause both carry a sentinel."""

    cause = RuntimeError(f"{LEAK_SENTINEL}-CAUSE")
    error = kind(f"{LEAK_SENTINEL}-MESSAGE")
    error.__cause__ = cause
    error.__context__ = cause
    return error


PREPARE_EXPECTATIONS = (
    (InvalidPairingPreparationRequest, 422, "PAIRING_INPUTS_INVALID"),
    (PairingPreparationCapacityExhausted, 429, "PREPARATION_CAPACITY"),
    (
        PairingPreparationIdentifierUnavailable,
        503,
        "PREPARATION_IDENTIFIER_UNAVAILABLE",
    ),
    (InvalidPairingCoordinatorConfiguration, 500, "HISTORICAL_PAIRING_UNAVAILABLE"),
    (_UnexpectedWorkflowError, 500, "HISTORICAL_PAIRING_UNAVAILABLE"),
)

REVIEW_EXPECTATIONS = (
    (InvalidPairingPreparationRequest, 400, "PAIRING_LOCATOR_INVALID"),
    (PairingPreparationNotFound, 404, "PREPARATION_NOT_FOUND"),
    (PairingPreparationExpired, 410, "PREPARATION_EXPIRED"),
    (PairingPreparationConsumed, 409, "PREPARATION_CONSUMED"),
    (PairingPreparationInUse, 409, "PREPARATION_IN_USE"),
    (StalePairingAuthorityFingerprint, 409, "STALE_AUTHORITY_FINGERPRINT"),
    (_UnexpectedWorkflowError, 500, "HISTORICAL_PAIRING_UNAVAILABLE"),
)

CONFIRM_EXPECTATIONS = REVIEW_EXPECTATIONS + (
    (MalformedPairingConfirmationTag, 400, "CONFIRMATION_TAG_MALFORMED"),
    (PairingConfirmationRejected, 403, "CONFIRMATION_REJECTED"),
    (PairingArchiveConflict, 409, "ARCHIVE_CONFLICT"),
    (PairingArchiveWriteFailed, 500, "ARCHIVE_WRITE_FAILED"),
    (PairingArchiveDurabilityUncertain, 500, "ARCHIVE_DURABILITY_UNCERTAIN"),
    (PairingArchiveReloadFailed, 500, "ARCHIVE_RELOAD_FAILED"),
    (PairingArchiveContentMismatch, 500, "ARCHIVE_CONTENT_MISMATCH"),
)


@pytest.mark.parametrize("kind,status,code", PREPARE_EXPECTATIONS)
def test_preparation_error_mapping_is_exact_and_silent(
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    kind,
    status,
    code,
):
    service._coordinator = _RaisingCoordinator(_leaky(kind))
    assert prepared(service, historical_payload) == (status, {"error": code})


@pytest.mark.parametrize("kind,status,code", REVIEW_EXPECTATIONS)
def test_review_error_mapping_is_exact_and_silent(
    service: HistoricalPairingService,
    kind,
    status,
    code,
):
    service._coordinator = _RaisingCoordinator(_leaky(kind))
    assert service.review(
        preparation_id="preparation-identifier",
        expected_authority_fingerprint="a" * 64,
    ) == (status, {"error": code})


@pytest.mark.parametrize("kind,status,code", CONFIRM_EXPECTATIONS)
def test_confirmation_error_mapping_is_exact_and_silent(
    service: HistoricalPairingService,
    kind,
    status,
    code,
):
    service._coordinator = _RaisingCoordinator(_leaky(kind))
    assert service.confirm(
        preparation_id="preparation-identifier",
        expected_authority_fingerprint="a" * 64,
        presented_confirmation_tag="b" * 64,
    ) == (status, {"error": code})


def test_no_mapped_refusal_ever_carries_message_cause_or_context(
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    observed = []
    for kind, _status, _code in CONFIRM_EXPECTATIONS + PREPARE_EXPECTATIONS:
        service._coordinator = _RaisingCoordinator(_leaky(kind))
        observed.append(prepared(service, historical_payload)[1])
        observed.append(
            service.review(
                preparation_id="preparation-identifier",
                expected_authority_fingerprint="a" * 64,
            )[1]
        )
        observed.append(
            service.confirm(
                preparation_id="preparation-identifier",
                expected_authority_fingerprint="a" * 64,
                presented_confirmation_tag="b" * 64,
            )[1]
        )
    for body in observed:
        assert set(body) == {"error"}
        rendered = json.dumps(body, sort_keys=True)
        assert LEAK_SENTINEL not in rendered
        for forbidden in ("message", "detail", "cause", "context", "Traceback"):
            assert forbidden not in rendered


def test_error_mappings_are_read_only_and_complete():
    for mapping in (
        PREPARATION_ERROR_MAPPING,
        REVIEW_ERROR_MAPPING,
        CONFIRMATION_ERROR_MAPPING,
    ):
        with pytest.raises(TypeError):
            mapping[RuntimeError] = (200, "NOPE")
    assert set(CONFIRMATION_ERROR_MAPPING) >= set(REVIEW_ERROR_MAPPING)
    # Every mapped code is a fixed uppercase identifier, never owner text.
    for mapping in (
        PREPARATION_ERROR_MAPPING,
        REVIEW_ERROR_MAPPING,
        CONFIRMATION_ERROR_MAPPING,
    ):
        for status, code in mapping.values():
            assert 400 <= status <= 599
            assert code == code.upper()
            assert set(code) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ_")


# ---------------------------------------------------------------------------
# H. Confidentiality of the service object graph.
# ---------------------------------------------------------------------------


def object_graph(root: object, *, max_nodes: int = 40_000):
    """Yield (path, node) for one bounded traversal of an object graph."""

    seen: set[int] = set()
    stack: list[tuple[str, object]] = [("<root>", root)]
    while stack and len(seen) < max_nodes:
        path, node = stack.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        yield path, node
        if isinstance(node, (str, bytes, bytearray, int, float, bool, type(None))):
            continue
        if isinstance(node, (ModuleType, type, FunctionType)):
            continue
        if isinstance(node, AbstractMapping):
            for key, value in list(node.items()):
                stack.append((f"{path}[{key!r}]", key))
                stack.append((f"{path}[{key!r}]", value))
        elif isinstance(node, (list, tuple, set, frozenset)):
            for index, value in enumerate(list(node)):
                stack.append((f"{path}[{index}]", value))
        namespace = getattr(node, "__dict__", None)
        if isinstance(namespace, dict):
            for key, value in list(namespace.items()):
                stack.append((f"{path}.{key}", value))
        for slot in getattr(type(node), "__slots__", ()) or ():
            if isinstance(slot, str) and hasattr(node, slot):
                stack.append((f"{path}.{slot}", getattr(node, slot)))


def graph_disclosures(root: object, fragments: frozenset[str]) -> list[tuple[str, str]]:
    """Every graph slot whose text carries one forbidden fragment."""

    ordered = sorted(fragments, key=lambda item: (-len(item), item))
    found: list[tuple[str, str]] = []
    for path, node in object_graph(root):
        if isinstance(node, str):
            texts = (node,)
        elif isinstance(node, (bytes, bytearray)):
            raw = bytes(node)
            texts = (raw.decode("latin-1"), raw.hex(), repr(raw))
        else:
            continue
        for fragment in ordered:
            if any(fragment in text for text in texts):
                found.append((path, fragment))
                break
    return found


def test_configured_secret_lives_only_in_the_owned_coordinator(
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """The secret is reachable at exactly one documented slot and nowhere else."""

    _status, body = prepared(service, historical_payload)
    identity = body["pairing_identity"]
    tag = independent_confirmation_tag(PAIRING_SECRET, body)
    assert (
        service.confirm(
            preparation_id=identity["preparation_id"],
            expected_authority_fingerprint=identity["pairing_authority_fingerprint"],
            presented_confirmation_tag=tag,
        )[0]
        == 200
    )
    secret_fragments = _fragments_of(PAIRING_SECRET, tag)
    tag_only = frozenset(
        fragment
        for fragment in secret_fragments
        if fragment in _fragments_of(OTHER_SECRET, tag)
    )
    # The fragment sets are non-vacuous, so neither assertion below is empty.
    assert len(tag_only) > 8
    assert len(secret_fragments) > len(tag_only)
    # The presented tag must appear nowhere at all in the graph.
    assert graph_disclosures(service, tag_only) == []
    # The configured secret may appear only where the coordinator documents it.
    slots = {path for path, _fragment in graph_disclosures(service, secret_fragments)}
    assert slots == {"<root>._coordinator._configured_secret"}


def test_a_complete_service_workflow_writes_nothing_to_any_output_sink(
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    from test_admissible_historical_pairing_confirmation import (
        _disclosures,
        _observed_sinks,
    )

    _status, body = prepared(service, historical_payload)
    identity = body["pairing_identity"]
    tag = independent_confirmation_tag(PAIRING_SECRET, body)
    fragments = _fragments_of(PAIRING_SECRET, tag)
    locator = dict(
        preparation_id=identity["preparation_id"],
        expected_authority_fingerprint=identity["pairing_authority_fingerprint"],
    )
    with _observed_sinks() as observation:
        service.payloads()
        service.review(**locator)
        service.confirm(**locator, presented_confirmation_tag="0" * 64)
        service.confirm(**locator, presented_confirmation_tag=tag)
        service.confirm(**locator, presented_confirmation_tag=tag)
        repr(service)
    assert _disclosures(observation, fragments) == []
    assert observation.warnings == []


def test_archive_filenames_and_bytes_carry_no_secret_or_tag(
    tmp_path: Path,
    service: HistoricalPairingService,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    _status, body = prepared(service, historical_payload)
    identity = body["pairing_identity"]
    tag = independent_confirmation_tag(PAIRING_SECRET, body)
    assert (
        service.confirm(
            preparation_id=identity["preparation_id"],
            expected_authority_fingerprint=identity["pairing_authority_fingerprint"],
            presented_confirmation_tag=tag,
        )[0]
        == 200
    )
    fragments = sorted(
        _fragments_of(PAIRING_SECRET, tag), key=lambda item: (-len(item), item)
    )
    archive = tmp_path / "archive"
    for path in archive.rglob("*"):
        if not path.is_file():
            continue
        rendered = path.read_bytes().decode("utf-8")
        name = path.as_posix()
        for fragment in fragments:
            assert fragment not in rendered
            assert fragment not in name
