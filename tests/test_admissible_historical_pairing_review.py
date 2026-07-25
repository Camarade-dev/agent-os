"""Step 5C2C1: complete server-derived owner review for one pinned pairing.

Every expectation here is built from independently declared fixture material or
from an independent canonical-JSON oracle.  The review under test is never asked
to produce an expectation it is then compared against.

The owner-authored fixtures are deliberately hostile: whitespace that would not
survive stripping, non-ASCII punctuation, non-breaking spaces, mixed case, and
non-alphabetical member ordering.  Any silent trim, normalization, collapse,
sort, or truncation therefore changes an asserted value.
"""

from __future__ import annotations

import base64
from dataclasses import FrozenInstanceError, fields, is_dataclass
import hashlib
import itertools
import json
from pathlib import Path
import re
import threading
from typing import Mapping
from unittest import mock

import pytest

from admissible.delegated_gate import historical_pairing_review as review_module
from admissible.delegated_gate import historical_pairing_workflow as workflow
from admissible.delegated_gate.canonical import (
    canonical_bytes,
    canonical_json,
    require_identifier,
)
from admissible.delegated_gate.historical_evaluation import (
    HistoricalEvaluationPairingAuthority,
)
from admissible.delegated_gate.historical_pairing_confirmation import (
    HISTORICAL_PAIRING_CONFIRMATION_DOMAIN,
    HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS,
)
from admissible.delegated_gate.historical_pairing_review import (
    CONFIRMATION_MESSAGE_RECIPE,
    EXACT_CANONICAL_MATCH_REVALIDATED,
    HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES,
    HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS,
    HISTORICAL_PAIRING_PREPARATION_STATES,
    PREPARATION_STATE_CONFIRMATION_IN_PROGRESS,
    PREPARATION_STATE_CONSUMED,
    PREPARATION_STATE_READY_FOR_CONFIRMATION,
    HistoricalEvaluationPairingOwnerReview,
    HistoricalPairingOwnerReviewError,
    ReviewedClaimAuthority,
    ReviewedEvidenceBinding,
    ReviewedEvidenceBindingAuthority,
    ReviewedIndependenceRequirements,
    ReviewedNegativeControl,
    ReviewedResultClaim,
    ReviewedVerificationObligation,
    ReviewedVerificationPlanAuthority,
    build_historical_evaluation_pairing_owner_review,
)
from admissible.delegated_gate.historical_pairing_workflow import (
    HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS,
    HistoricalEvaluationPairingCoordinator,
    PairingPreparationExpired,
    PairingPreparationNotFound,
    StalePairingAuthorityFingerprint,
)
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    ClaimAuthority,
    ClaimVerificationPlanAuthority,
    NativeMissionProfile,
    ResultClaim,
    VerificationEvidenceBinding,
    VerificationEvidenceBindingAuthority,
    VerificationIndependenceRequirements,
    VerificationNegativeControl,
    VerificationObligation,
    WorkspaceSourceAuthority,
    WorkspaceSourceKind,
)
from admissible.delegated_gate.native_canary import (
    EVIDENCE_DIRECTORY_NAME,
    NATIVE_SIDECAR_DIRECTORY_NAME,
    WORKSPACE_DIRECTORY_NAME,
    NativeCanaryAuthorizationPayloadV4,
    load_historical_native_canary_authorization_payload_v4,
)
from admissible.product_launcher.historical_pairing_registry import (
    HistoricalPairingConfiguration,
    HistoricalPayloadEntry,
    HistoricalPayloadRegistry,
)
from test_admissible_historical_evaluation_pairing import (
    _payload_for_runtime_profile,
    _refingerprint_payload,
    _refingerprint_profile,
)
from test_admissible_historical_pairing_confirmation import (
    _disclosures_in_text,
    _fragments_of,
)
from test_admissible_historical_v5_derivation import (
    HOSTILE_COMPLETION_CONDITIONS_TEXT,
    HOSTILE_GATE_OBJECTIVE,
    HOSTILE_MISSION_TEXT,
    HOSTILE_STOP_CLAUSE,
    _runtime_v2_profile,
)
from test_admissible_workflow_recovery_profile import _payload_harness


# ---------------------------------------------------------------------------
# Fixture material.
# ---------------------------------------------------------------------------

REVIEW_SECRET = b"Kp3Xw7Zs1Vq9Bn5Mt2Rf8Dj4Hg6Ly0Cu3Ai7Ne5Ov"
ACTOR_ID = "owner.review-asserted-actor"

# One token that appears in every local locator carried by the historical
# payload.  Nothing derived from those locators may ever reach the review.
PATH_MARKER = "zqxjleakmarker7731"

HOSTILE_CLAIM_STATEMENTS = (
    "  Zulu\tbehavior \u2014 \u201cquoted\u201d, \u00bd done\u2026\nsecond  line  ",
    "\tAlpha builds\u00a0on zulu; NOT the reverse.  \n",
    " mike   OBSERVATION  \u2013 recorded, un-adjudicated.\t",
)
HOSTILE_NON_CLAIMS = (
    "\tDoes NOT assert the \u03b1 behavior.\n",
    "  Says nothing about  \u201celigibility\u201d.  ",
    "No\u00a0verdict \u2014 ever.\t\n",
)
HOSTILE_COVERAGE = (
    " Covers\u00a0one  bounded slice \u2014 no more.\t",
    "\tExercises  the ECHO path only.\n",
    "  Frozen  behavioral  slice \u2013 \u00bd coverage.  ",
    "\nHuman  rubric  observation  only.  ",
)
HOSTILE_CONTROL_DESCRIPTIONS = (
    "Rejects  a known-bad  recorded result: \u2717\n\t",
    "  Rejects an EMPTY  workspace \u2014 \u201cnothing done\u201d.  ",
)
HOSTILE_OBLIGATION_NON_CLAIM = "  Does NOT adjudicate  the claim.\u00a0\t\n"


def _hostile_claims() -> list[dict]:
    """Fresh owner-authored claim members, deliberately non-alphabetical."""

    return [
        {
            "claim_id": "claim.zulu",
            "statement": HOSTILE_CLAIM_STATEMENTS[0],
            "obligation_level": "MANDATORY",
            "depends_on": [],
            "non_claims": [HOSTILE_NON_CLAIMS[0]],
        },
        {
            "claim_id": "claim.alpha",
            "statement": HOSTILE_CLAIM_STATEMENTS[1],
            "obligation_level": "OPTIONAL",
            "depends_on": ["claim.zulu"],
            "non_claims": [],
        },
        {
            "claim_id": "claim.mike",
            "statement": HOSTILE_CLAIM_STATEMENTS[2],
            "obligation_level": "ADVISORY",
            "depends_on": [],
            # Deliberately reverse order so any sort is visible.
            "non_claims": [HOSTILE_NON_CLAIMS[2], HOSTILE_NON_CLAIMS[1]],
        },
    ]


# Six deliberately different independence vectors, one per obligation, so a
# dropped or duplicated requirement cannot hide behind a uniform fixture.
INDEPENDENCE_VECTORS = (
    (True, True, True, False, True, True),
    (False, True, False, False, True, False),
    (True, False, True, False, False, True),
    (False, False, False, False, False, False),
)

_INDEPENDENCE_NAMES = (
    "temporal",
    "artifact",
    "process",
    "information",
    "model",
    "organizational",
)


def _independence(index: int) -> dict:
    return dict(zip(_INDEPENDENCE_NAMES, INDEPENDENCE_VECTORS[index]))


def _hostile_plan() -> list[dict]:
    return [
        {
            "obligation_id": "verify.zulu",
            "claim_ids": ["claim.zulu"],
            "strategy": "CHECKPOINT_COMMAND",
            "procedure_reference": "checkpoint.zeta",
            "acceptance_predicate": "EXIT_CODE_ZERO",
            "declared_coverage": HOSTILE_COVERAGE[0],
            "non_claims": [HOSTILE_OBLIGATION_NON_CLAIM],
            "oracle_disclosed_to_subject": False,
            "independence_requirements": _independence(0),
            "negative_controls": [
                {
                    "control_id": "negative.zulu",
                    "description": HOSTILE_CONTROL_DESCRIPTIONS[0],
                },
                {
                    "control_id": "negative.alpha",
                    "description": HOSTILE_CONTROL_DESCRIPTIONS[1],
                },
            ],
            "reference_cases": ["case.zulu", "case.alpha"],
        },
        {
            "obligation_id": "verify.echo",
            "claim_ids": ["claim.zulu", "claim.alpha"],
            "strategy": "CHECKPOINT_COMMAND",
            "procedure_reference": "procedure.echo",
            "acceptance_predicate": "EXIT_CODE_ZERO",
            "declared_coverage": HOSTILE_COVERAGE[1],
            "non_claims": [],
            "oracle_disclosed_to_subject": True,
            "independence_requirements": _independence(1),
            "negative_controls": [],
            "reference_cases": [],
        },
        {
            "obligation_id": "verify.alpha",
            "claim_ids": ["claim.alpha"],
            "strategy": "FROZEN_BEHAVIORAL_VERIFIER",
            "procedure_reference": "procedure.alpha",
            "acceptance_predicate": "EXIT_CODE_ZERO",
            "declared_coverage": HOSTILE_COVERAGE[2],
            "non_claims": [HOSTILE_NON_CLAIMS[1]],
            "oracle_disclosed_to_subject": False,
            "independence_requirements": _independence(2),
            "negative_controls": [
                {
                    "control_id": "negative.echo",
                    "description": HOSTILE_CONTROL_DESCRIPTIONS[1],
                }
            ],
            "reference_cases": ["case.mike"],
        },
        {
            "obligation_id": "verify.human",
            "claim_ids": ["claim.mike"],
            "strategy": "HUMAN_RUBRIC_OBSERVATION",
            "procedure_reference": "rubric.mike",
            "acceptance_predicate": "HUMAN_RUBRIC_PASS",
            "declared_coverage": HOSTILE_COVERAGE[3],
            "non_claims": [],
            "oracle_disclosed_to_subject": False,
            "independence_requirements": _independence(3),
            "negative_controls": [],
            "reference_cases": [],
        },
    ]


def _hostile_bindings(verifier_digest: str) -> list[dict]:
    return [
        {
            "binding_id": "binding.zulu",
            "obligation_id": "verify.zulu",
            "source_authority_type": "CHECKPOINT_COMMAND_AUTHORITY",
            "source_authority_reference": "checkpoint.alpha",
        },
        {
            "binding_id": "binding.alpha",
            "obligation_id": "verify.alpha",
            "source_authority_type": "FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY",
            "source_authority_reference": verifier_digest,
        },
        {
            "binding_id": "binding.echo",
            "obligation_id": "verify.echo",
            "source_authority_type": "CHECKPOINT_COMMAND_AUTHORITY",
            "source_authority_reference": "checkpoint.zeta",
        },
    ]


@pytest.fixture(scope="module")
def historical_payload(
    tmp_path_factory: pytest.TempPathFactory,
) -> NativeCanaryAuthorizationPayloadV4:
    """One historical V4 payload whose every local locator carries the marker."""

    fixture_root = tmp_path_factory.mktemp("s5c2c1-rev")
    runtime_profile = _runtime_v2_profile()
    live = _payload_harness(fixture_root, runtime_profile).payload.to_dict()
    absent = fixture_root / f"absent-{PATH_MARKER}-material"
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


@pytest.fixture(scope="module")
def local_locators(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
) -> tuple[str, ...]:
    values = (
        historical_payload.source_repository,
        historical_payload.run_root,
        historical_payload.workspace_root,
        historical_payload.evidence_root,
        historical_payload.native_sidecar_root,
        historical_payload.executable,
        *historical_payload.launcher_prefix,
    )
    for value in values:
        assert PATH_MARKER in value
    return values


class _FakeClock:
    def __init__(self, start: float = 10_000.0) -> None:
        self.value = float(start)

    def __call__(self) -> float:
        return self.value

    def advance(self, delta: float) -> None:
        self.value += float(delta)


def _sequential_identifiers(prefix: str = "prep"):
    counter = itertools.count(1)
    return lambda: f"{prefix}-{next(counter):06d}"


@pytest.fixture()
def archive_root(tmp_path: Path) -> Path:
    return tmp_path / "historical-archive"


@pytest.fixture()
def clock() -> _FakeClock:
    return _FakeClock()


@pytest.fixture()
def coordinator(
    archive_root: Path, clock: _FakeClock
) -> HistoricalEvaluationPairingCoordinator:
    return HistoricalEvaluationPairingCoordinator(
        configured_secret=REVIEW_SECRET,
        archive_root=archive_root,
        preparation_ttl_seconds=600,
        max_preparations=8,
        clock=clock,
        preparation_id_factory=_sequential_identifiers(),
    )


def _owner_material(payload: NativeCanaryAuthorizationPayloadV4) -> dict:
    return {
        "result_claims": _hostile_claims(),
        "claim_verification_plan": _hostile_plan(),
        "verification_evidence_bindings": _hostile_bindings(
            payload.mission_profile.verification.verifier_source_sha256
        ),
    }


@pytest.fixture()
def prepared(
    coordinator: HistoricalEvaluationPairingCoordinator,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    return coordinator.prepare_historical_evaluation_pairing(
        target_authorization_payload=historical_payload,
        actor_id=ACTOR_ID,
        **_owner_material(historical_payload),
    )


@pytest.fixture()
def review(
    coordinator: HistoricalEvaluationPairingCoordinator, prepared
) -> HistoricalEvaluationPairingOwnerReview:
    return coordinator.get_historical_evaluation_pairing_review(
        preparation_id=prepared.preparation_id,
        expected_authority_fingerprint=prepared.authority_fingerprint,
    )


# ---------------------------------------------------------------------------
# Recursive inspection helpers.
# ---------------------------------------------------------------------------


def _walk(value):
    """Yield every leaf reachable from one review or presentation structure."""

    if is_dataclass(value) and not isinstance(value, type):
        for field in fields(value):
            yield from _walk(getattr(value, field.name))
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield key
            yield from _walk(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _walk(item)
    else:
        yield value


def _texts(value) -> list[str]:
    return [leaf for leaf in _walk(value) if isinstance(leaf, str)]


def _dataclass_instances(value):
    if is_dataclass(value) and not isinstance(value, type):
        yield value
        for field in fields(value):
            yield from _dataclass_instances(getattr(value, field.name))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _dataclass_instances(item)


def _stored_mutable_containers(value):
    if is_dataclass(value) and not isinstance(value, type):
        for field in fields(value):
            yield from _stored_mutable_containers(getattr(value, field.name))
    elif isinstance(value, tuple):
        for item in value:
            yield from _stored_mutable_containers(item)
    elif isinstance(value, (dict, list, set, bytearray)):
        yield value


def _keyed_values(value, prefix: str = ""):
    """Yield (dotted key path, leaf) pairs from a presentation mapping."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _keyed_values(item, f"{prefix}.{key}" if prefix else key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _keyed_values(item, f"{prefix}[{index}]")
    else:
        yield prefix, value


# ---------------------------------------------------------------------------
# Q. Notices.
# ---------------------------------------------------------------------------


def test_owner_review_notices_are_exactly_fourteen_and_ordered():
    assert isinstance(HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES, tuple)
    assert len(HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES) == 14
    assert len(set(HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES)) == 14
    expected_order = (
        ("post-run evaluation only", "no execution"),
        ("separately authorized earlier",),
        ("did not receive",),
        ("not produced specifically for these claims",),
        ("no runtime evidence has been read",),
        ("no source, path, artifact, or workspace existence",),
        ("no eligibility", "ProductVerdict"),
        ("actor_id", "not authenticated"),
        ("no nonce", "fresh secret possession"),
        ("symmetric shared-secret", "not a digital signature"),
        ("archive alone never proves",),
        ("callable\n            directly".replace("\n            ", " "),),
        ("multiple distinct pairings", "no revocation or supersession"),
        ("in-memory process state", "launcher restart", "archive existence"),
    )
    for notice, fragments in zip(
        HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES, expected_order, strict=True
    ):
        for fragment in fragments:
            assert fragment in notice, (notice, fragment)


def test_owner_review_notices_do_not_replace_the_accepted_limitation_tuples():
    assert HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES != (
        HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS
    )
    assert HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES != (
        HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS
    )
    assert len(HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS) == 9
    assert len(HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS) == 11


def test_review_carries_the_exact_notices_and_withheld_tuples(review):
    assert review.notices is HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES
    assert review.withheld_fields is HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS
    presented = review.to_presentation_dict()
    assert presented["notices"] == list(HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES)
    assert presented["withheld_fields"] == list(
        HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS
    )


def test_withheld_fields_name_every_required_local_locator():
    required = (
        "source_repository",
        "source_repository_identity",
        "run_root",
        "workspace_root",
        "evidence_root",
        "native_sidecar_root",
        "executable",
        "launcher_prefix",
        "local_repository_path",
        "configured_document_path",
        "archive_root",
    )
    joined = "\n".join(HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS)
    for name in required:
        assert name in joined, name
    assert len(set(HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS)) == len(
        HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS
    )


# ---------------------------------------------------------------------------
# I/K/L/M. Complete presentation coverage of the current schema.
# ---------------------------------------------------------------------------


def test_reviewed_types_cover_every_current_schema_field():
    """Field-for-field coverage, so a future schema field cannot be dropped."""

    for reviewed, canonical in (
        (ReviewedResultClaim, ResultClaim),
        (ReviewedVerificationObligation, VerificationObligation),
        (ReviewedNegativeControl, VerificationNegativeControl),
        (
            ReviewedIndependenceRequirements,
            VerificationIndependenceRequirements,
        ),
        (ReviewedEvidenceBinding, VerificationEvidenceBinding),
    ):
        assert {field.name for field in fields(reviewed)} == {
            field.name for field in fields(canonical)
        }, reviewed


def test_every_claim_field_and_non_claim_appears_exactly(review):
    owner = _hostile_claims()
    reviewed = review.claim_authority
    assert reviewed.authorship == "OWNER_AUTHORED"
    assert reviewed.coverage_status == "NOT_ASSESSED"
    assert len(reviewed.claims) == len(owner)
    for claim, expected in zip(reviewed.claims, owner, strict=True):
        assert claim.claim_id == expected["claim_id"]
        assert claim.statement == expected["statement"]
        assert claim.obligation_level == expected["obligation_level"]
        assert claim.depends_on == tuple(expected["depends_on"])
        assert claim.non_claims == tuple(expected["non_claims"])
        assert claim.to_presentation_dict() == expected


def test_owner_prose_is_not_normalized_trimmed_or_collapsed(review):
    for statement in HOSTILE_CLAIM_STATEMENTS + HOSTILE_NON_CLAIMS:
        assert statement != statement.strip()
        assert statement != " ".join(statement.split())
    texts = _texts(review)
    for statement in HOSTILE_CLAIM_STATEMENTS:
        assert statement in texts
    for statement in HOSTILE_NON_CLAIMS:
        assert statement in texts
    for coverage in HOSTILE_COVERAGE:
        assert coverage in texts
    for description in HOSTILE_CONTROL_DESCRIPTIONS:
        assert description in texts


def test_every_obligation_field_predicate_and_independence_appears_exactly(review):
    owner = _hostile_plan()
    reviewed = review.verification_plan_authority
    assert reviewed.authorship == "OWNER_AUTHORED"
    assert reviewed.coverage_status == "NOT_ASSESSED"
    assert len(reviewed.verification_obligations) == len(owner)
    for obligation, expected in zip(
        reviewed.verification_obligations, owner, strict=True
    ):
        assert obligation.obligation_id == expected["obligation_id"]
        assert obligation.claim_ids == tuple(expected["claim_ids"])
        assert obligation.strategy == expected["strategy"]
        assert obligation.procedure_reference == expected["procedure_reference"]
        assert obligation.acceptance_predicate == expected["acceptance_predicate"]
        assert obligation.declared_coverage == expected["declared_coverage"]
        assert obligation.non_claims == tuple(expected["non_claims"])
        assert obligation.oracle_disclosed_to_subject == (
            expected["oracle_disclosed_to_subject"]
        )
        independence = expected["independence_requirements"]
        for name in _INDEPENDENCE_NAMES:
            assert (
                getattr(obligation.independence_requirements, name)
                is independence[name]
            )
        assert obligation.reference_cases == tuple(expected["reference_cases"])
        assert len(obligation.negative_controls) == len(
            expected["negative_controls"]
        )
        for control, control_expected in zip(
            obligation.negative_controls,
            expected["negative_controls"],
            strict=True,
        ):
            assert control.control_id == control_expected["control_id"]
            assert control.description == control_expected["description"]
        assert obligation.to_presentation_dict() == expected


def test_all_six_independence_vectors_are_distinct_and_preserved(review):
    observed = tuple(
        tuple(
            getattr(obligation.independence_requirements, name)
            for name in _INDEPENDENCE_NAMES
        )
        for obligation in review.verification_plan_authority.verification_obligations
    )
    assert observed == INDEPENDENCE_VECTORS
    assert len(set(observed)) == len(INDEPENDENCE_VECTORS)


def test_every_binding_field_appears_exactly(
    review, historical_payload: NativeCanaryAuthorizationPayloadV4
):
    owner = _hostile_bindings(
        historical_payload.mission_profile.verification.verifier_source_sha256
    )
    reviewed = review.verification_evidence_binding_authority
    assert reviewed.authorship == "OWNER_AUTHORED"
    assert reviewed.coverage_status == "NOT_ASSESSED"
    for binding, expected in zip(reviewed.bindings, owner, strict=True):
        assert binding.binding_id == expected["binding_id"]
        assert binding.obligation_id == expected["obligation_id"]
        assert binding.source_authority_type == expected["source_authority_type"]
        assert binding.source_authority_reference == (
            expected["source_authority_reference"]
        )
        assert binding.to_presentation_dict() == expected


def test_review_invents_no_resolution_or_result_field(review):
    presented = review.to_presentation_dict()
    keys = {key for key, _value in _keyed_values(presented)}
    rendered = json.dumps(presented, ensure_ascii=False)
    for invented in (
        "required_evidence_method",
        "declared_limitations",
        "resolved_source",
        "source_exists",
        "eligibility",
        "obligation_result",
        "satisfaction",
        "claim_support",
        "coverage_rollup",
        "admitted",
        "product_verdict",
        "method",
    ):
        assert not [key for key in keys if key.endswith(f".{invented}")], invented
        assert f'"{invented}"' not in rendered, invented


# ---------------------------------------------------------------------------
# N. Human-readable historical mission context.
# ---------------------------------------------------------------------------


def test_exact_historical_mission_context_appears_verbatim(
    review, historical_payload: NativeCanaryAuthorizationPayloadV4
):
    profile = historical_payload.mission_profile
    context = review.historical_mission_context
    assert context.mission_text == HOSTILE_MISSION_TEXT == profile.mission_text
    assert context.gate_objective == HOSTILE_GATE_OBJECTIVE
    assert context.completion_conditions_text == (
        HOSTILE_COMPLETION_CONDITIONS_TEXT
    )
    assert context.stop_clause == HOSTILE_STOP_CLAUSE
    assert context.stop_clause == profile.runtime_prompt.stop_clause
    assert context.permitted_effects == tuple(
        profile.runtime_prompt.permitted_effects
    )
    assert context.forbidden_effects == tuple(
        profile.runtime_prompt.forbidden_effects
    )
    assert tuple(
        (clause.clause_id, clause.text) for clause in context.gate_clauses
    ) == profile.gate_clauses
    assert [clause.clause_id for clause in context.gate_clauses] == [
        "clause.zulu",
        "clause.alpha",
    ]
    assert context.required_material_paths == profile.required_material_paths
    assert context.required_evidence_kinds == profile.required_evidence_kinds
    assert tuple(
        (command.command_id, command.argv, command.timeout_seconds,
         command.max_capture_bytes)
        for command in context.checkpoint_commands
    ) == tuple(
        (command.command_id, command.argv, command.timeout_seconds,
         command.max_capture_bytes)
        for command in profile.checkpoint_commands
    )
    assert [command.command_id for command in context.checkpoint_commands] == [
        "checkpoint.zeta",
        "checkpoint.alpha",
    ]
    policy = profile.effective_git_end_state_policy
    assert context.required_complete_commit_message == (
        policy.required_complete_commit_message
    )
    assert context.required_commits_added == policy.required_commits_added
    assert context.final_worktree_clean is policy.final_worktree_clean
    assert context.final_index_clean is policy.final_index_clean
    assert context.final_remotes_absent is policy.final_remotes_absent


def test_mission_context_is_never_replaced_by_a_hash_only(review):
    context = review.historical_mission_context
    for value in (
        context.mission_text,
        context.gate_objective,
        context.completion_conditions_text,
        context.stop_clause,
    ):
        assert len(value) > 8
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        assert value != digest
        assert digest not in _texts(review)


def test_behavioral_verifier_source_body_is_absent_while_identity_remains(
    review, historical_payload: NativeCanaryAuthorizationPayloadV4
):
    verification = historical_payload.mission_profile.verification
    disclosure = review.historical_mission_context.behavioral_verifier
    assert disclosure.mode == verification.mode.value
    assert disclosure.verifier_source_sha256 == verification.verifier_source_sha256
    assert disclosure.verifier_source_byte_length == len(
        verification.verifier_source.encode("utf-8")
    )
    assert disclosure.verifier_timeout_seconds == (
        verification.verifier_timeout_seconds
    )
    assert disclosure.verifier_output_limit_bytes == (
        verification.verifier_output_limit_bytes
    )
    assert disclosure.disclose_complete_source is (
        verification.disclose_complete_source
    )

    source = verification.verifier_source
    assert source and len(source) > 16
    rendered = json.dumps(review.to_presentation_dict(), ensure_ascii=False)
    assert source not in rendered
    for text in _texts(review):
        assert source not in text
    # No fragment of the body survives either.
    for start in range(0, len(source) - 12):
        assert source[start : start + 12] not in rendered


# ---------------------------------------------------------------------------
# O. Historical authority context and path withholding.
# ---------------------------------------------------------------------------


def test_historical_authority_allowlist_is_complete_and_exact(
    review, historical_payload: NativeCanaryAuthorizationPayloadV4
):
    profile = historical_payload.mission_profile
    context = review.historical_authority_context
    assert context.authorization_schema_version == historical_payload.schema_version
    assert context.target_authorization_payload_fingerprint == (
        historical_payload.payload_fingerprint
    )
    assert context.run_id == historical_payload.run_id == profile.run_id
    assert context.session_id == historical_payload.session_id
    assert context.profile_id == profile.profile_id
    assert context.gate_id == profile.gate_id
    assert context.mission_id == profile.mission_id
    assert context.historical_profile_fingerprint == profile.profile_fingerprint
    assert context.mission_fingerprint == historical_payload.mission_fingerprint
    assert context.gate_plan_fingerprint == (
        historical_payload.gate_plan_fingerprint
    )
    assert context.gate_contract_fingerprint == (
        historical_payload.gate_contract_fingerprint
    )
    source = profile.effective_workspace_source
    assert context.workspace_source_kind == source.kind.value
    assert context.workspace_source_identity_fingerprint == (
        source.identity_fingerprint
    )
    assert context.fixture_id == source.fixture_id
    assert context.fixture_version == source.fixture_version
    assert context.fixture_version_label == historical_payload.fixture_version
    assert context.selected_model == historical_payload.selected_model
    assert context.budgets == tuple(historical_payload.budgets)
    assert context.timeout_seconds == historical_payload.timeout_seconds
    assert context.stdout_byte_limit == historical_payload.stdout_byte_limit
    assert context.stderr_byte_limit == historical_payload.stderr_byte_limit
    assert context.clean_worktree_required is True
    assert context.source_head == historical_payload.source_head
    assert context.backend_attestation_class == (
        historical_payload.backend_attestation_class
    )
    assert context.backend_readiness_reason == (
        historical_payload.backend_readiness_reason
    )
    assert context.backend_attestation_fingerprint == (
        historical_payload.backend_attestation_fingerprint
    )
    assert context.attestation_non_claims == (
        historical_payload.attestation_non_claims
    )
    assert context.canary_non_claims == historical_payload.canary_non_claims
    workspace = historical_payload.initialized_workspace
    assert context.initialized_workspace.initial_git_head == (
        workspace.initial_git_head
    )
    assert context.initialized_workspace.initial_material_tree_hash == (
        workspace.initial_material_tree_hash
    )
    assert context.initialized_workspace.initial_commit_count == (
        workspace.initial_commit_count
    )
    assert context.initialized_workspace.initial_commit_message == (
        workspace.initial_commit_message
    )
    assert context.initialized_workspace.source_kind == workspace.source_kind
    assert context.initialized_workspace.source_identity == (
        workspace.source_identity
    )


def test_no_local_path_marker_reaches_the_review_or_its_presentation(
    review, local_locators: tuple[str, ...]
):
    presented = review.to_presentation_dict()
    rendered = json.dumps(presented, ensure_ascii=False)
    assert PATH_MARKER not in rendered
    for text in _texts(review):
        assert PATH_MARKER not in text
    for key, value in _keyed_values(presented):
        assert PATH_MARKER not in key
        if isinstance(value, str):
            assert PATH_MARKER not in value
    marker_directory = f"absent-{PATH_MARKER}-material"
    for locator in local_locators:
        assert locator not in rendered
        assert marker_directory in locator
        assert marker_directory not in rendered
        for text in _texts(review):
            assert locator not in text


def test_review_exposes_no_source_repository_identity_or_drive_shaped_value(
    review, archive_root: Path
):
    presented = review.to_presentation_dict()
    keys = {key.rsplit(".", 1)[-1] for key, _value in _keyed_values(presented)}
    for withheld in (
        "source_repository",
        "source_repository_identity",
        "run_root",
        "workspace_root",
        "evidence_root",
        "native_sidecar_root",
        "executable",
        "launcher_prefix",
        "local_repository_path",
        "archive_root",
        "device",
        "inode",
        "mtime_ns",
        "file_attributes",
        "verifier_source",
    ):
        assert withheld not in keys, withheld
    for _key, value in _keyed_values(presented):
        if not isinstance(value, str):
            continue
        # Fixture-scoped, and deliberately not a universal law: this fixture's
        # authored prose carries no absolute-path-looking text, so nothing
        # presented from it is path-shaped.  The general rule -- structured
        # locators withheld, exact prose and argv reproduced even when they do
        # look like paths -- is pinned by the Step 5C2C1.1 disclosure tests.
        assert not Path(value).is_absolute() or "/" not in value
        assert str(archive_root) not in value


def test_local_repository_workspace_source_path_is_never_projected():
    """The projection reads only kind, fixture identity, and a fingerprint."""

    marker = f"C:\\{PATH_MARKER}\\local-repo"
    source = WorkspaceSourceAuthority(
        kind=WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY,
        local_repository_path=marker,
    ).validated()
    projected = (
        source.kind.value,
        source.fixture_id,
        source.fixture_version,
        source.identity_fingerprint,
    )
    for value in projected:
        assert PATH_MARKER not in str(value)
    # The canonical authority does carry the path; the projection never does.
    assert source.to_dict()["local_repository_path"] == marker
    assert (
        "target_authorization_payload.mission_profile.workspace_source"
        ".local_repository_path"
    ) in HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS


def test_review_contains_no_secret_expected_tag_archive_root_or_document_path(
    coordinator: HistoricalEvaluationPairingCoordinator,
    prepared,
    review,
    archive_root: Path,
    tmp_path: Path,
):
    from admissible.delegated_gate.historical_pairing_confirmation import (
        compute_historical_pairing_confirmation_tag,
    )

    expected_tag = compute_historical_pairing_confirmation_tag(
        secret=REVIEW_SECRET,
        pairing_authority=coordinator._preparations[
            prepared.preparation_id
        ].pairing_authority,
    )
    fragments = _fragments_of(REVIEW_SECRET, expected_tag)
    rendered = json.dumps(review.to_presentation_dict(), ensure_ascii=False)
    assert _disclosures_in_text(rendered, fragments) == []
    assert _disclosures_in_text(repr(review), fragments) == []
    for value in (str(archive_root), str(tmp_path), archive_root.name):
        assert value not in rendered


# ---------------------------------------------------------------------------
# J. Confirmation identity.
# ---------------------------------------------------------------------------


def test_confirmation_message_decodes_to_the_exact_pinned_bytes(prepared, review):
    identity = review.pairing_identity
    decoded = base64.b64decode(identity.confirmation_message_base64.encode("ascii"))
    assert decoded == prepared.confirmation_message
    assert identity.confirmation_message_byte_length == len(
        prepared.confirmation_message
    )
    assert identity.confirmation_message_sha256 == hashlib.sha256(
        prepared.confirmation_message
    ).hexdigest()
    assert decoded.startswith(HISTORICAL_PAIRING_CONFIRMATION_DOMAIN + b"\x00")
    assert identity.confirmation_message_recipe == CONFIRMATION_MESSAGE_RECIPE
    assert (
        HISTORICAL_PAIRING_CONFIRMATION_DOMAIN.decode("ascii")
        in identity.confirmation_message_recipe
    )
    assert "NUL" in identity.confirmation_message_recipe


def test_pairing_identity_exposes_the_complete_authority_facts(
    prepared, review, historical_payload: NativeCanaryAuthorizationPayloadV4
):
    identity = review.pairing_identity
    assert identity.preparation_id == prepared.preparation_id
    assert identity.preparation_state == PREPARATION_STATE_READY_FOR_CONFIRMATION
    assert identity.asserted_actor_id == ACTOR_ID
    assert identity.pairing_authority_schema_version == (
        "admissible_historical_evaluation_pairing_authority_v1"
    )
    assert identity.pairing_authority_fingerprint == prepared.authority_fingerprint
    assert identity.evaluation_profile_schema_version == (
        MISSION_PROFILE_SCHEMA_VERSION_V5
    )
    assert identity.evaluation_profile_fingerprint == (
        prepared.evaluation_profile_fingerprint
    )
    assert identity.target_authorization_payload_fingerprint == (
        historical_payload.payload_fingerprint
    )
    assert identity.evaluation_profile_is_launchable is False


def test_no_second_canonical_authority_representation_is_presented(
    coordinator: HistoricalEvaluationPairingCoordinator, prepared, review
):
    authority = coordinator._preparations[prepared.preparation_id].pairing_authority
    canonical = canonical_bytes(authority.to_dict())
    authority_base64 = base64.b64encode(canonical).decode("ascii")
    presented = review.to_presentation_dict()

    carriers = [
        key
        for key, value in _keyed_values(presented)
        if isinstance(value, str) and authority_base64 in value
    ]
    assert carriers == ["pairing_identity.confirmation_message_base64"]
    assert presented["pairing_identity"]["confirmation_message_base64"] == (
        base64.b64encode(
            HISTORICAL_PAIRING_CONFIRMATION_DOMAIN + b"\x00" + canonical
        ).decode("ascii")
    )
    # No value is a bare second encoding, and no key advertises one.
    for key, value in _keyed_values(presented):
        assert value != authority_base64
        assert value != canonical_json(authority.to_dict())
        assert value != canonical.hex()
        assert "canonical_json" not in key
        assert "canonical_json_base64" not in key
    assert "pairing_authority_canonical_json_base64" not in json.dumps(presented)


def test_serializer_does_not_reinterpret_the_confirmation_message(
    coordinator: HistoricalEvaluationPairingCoordinator, prepared
):
    """Authority facts come from the pinned authority, never from the bytes."""

    pinned = coordinator._preparations[prepared.preparation_id]
    unrelated = b"these bytes are not a confirmation message at all"
    built = build_historical_evaluation_pairing_owner_review(
        preparation_id=prepared.preparation_id,
        preparation_state=PREPARATION_STATE_READY_FOR_CONFIRMATION,
        evaluation_profile=pinned.evaluation_profile,
        target_authorization_payload=pinned.target_authorization_payload,
        pairing_authority=pinned.pairing_authority,
        confirmation_message=unrelated,
    )
    identity = built.pairing_identity
    assert identity.pairing_authority_fingerprint == (
        pinned.pairing_authority.authority_fingerprint
    )
    assert identity.asserted_actor_id == pinned.pairing_authority.actor_id
    assert base64.b64decode(identity.confirmation_message_base64) == unrelated
    assert identity.confirmation_message_byte_length == len(unrelated)


# ---------------------------------------------------------------------------
# P. Compatibility revalidation.
# ---------------------------------------------------------------------------


def test_compatibility_is_freshly_revalidated_and_reported_bounded(
    coordinator: HistoricalEvaluationPairingCoordinator,
    prepared,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    with mock.patch.object(
        review_module,
        "require_exact_v5_v2_runtime_authority_compatibility",
        wraps=review_module.require_exact_v5_v2_runtime_authority_compatibility,
    ) as revalidation:
        built = coordinator.get_historical_evaluation_pairing_review(
            preparation_id=prepared.preparation_id,
            expected_authority_fingerprint=prepared.authority_fingerprint,
        )
    assert revalidation.call_count == 1
    assert built.compatibility_revalidation.result == (
        EXACT_CANONICAL_MATCH_REVALIDATED
    )
    assert built.compatibility_revalidation.projected_runtime_profile_fingerprint == (
        historical_payload.mission_profile.profile_fingerprint
    )


def test_review_module_import_graph_reaches_no_execution_or_evidence_module():
    """The review module's complete direct import graph, pinned exactly."""

    import ast
    import inspect

    source = Path(inspect.getfile(review_module)).read_text(encoding="utf-8")
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            imported.add(node.module)
    assert imported == {
        "__future__",
        "base64",
        "dataclasses",
        "hashlib",
        "typing",
        "admissible.delegated_gate.canonical",
        "admissible.delegated_gate.historical_evaluation",
        "admissible.delegated_gate.historical_pairing_confirmation",
        "admissible.delegated_gate.mission_profile",
        "admissible.delegated_gate.native_canary",
    }
    for forbidden in (
        "admissible.product_service",
        "admissible.product_read_model",
        "admissible.product_launcher",
        "admissible.review_surface",
        "admissible.browser_runtime",
        "admissible.delegated_gate.native_executor",
        "admissible.delegated_gate.native_acceptance",
        "admissible.delegated_gate.store",
        "admissible.delegated_gate.checkpoint",
        "admissible.delegated_gate.historical_evaluation_store",
        "os",
        "pathlib",
        "subprocess",
    ):
        assert forbidden not in imported, forbidden
    # Outside the withheld-fields declaration itself, no local locator name and
    # no filesystem, environment, or archive verb appears in the module at all.
    stripped = source
    for withheld in sorted(
        HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS, key=len, reverse=True
    ):
        stripped = stripped.replace(withheld, "")
    for forbidden in (
        "open(",
        "environ",
        "getenv",
        "subprocess",
        "persist_",
        "load_historical_evaluation_pairing",
        "source_repository",
        "run_root",
        "evidence_root",
        "workspace_root",
        "native_sidecar_root",
        "launcher_prefix",
        "executable",
    ):
        assert forbidden not in stripped, forbidden


def test_review_module_creates_no_fingerprint_and_defines_no_to_dict(review):
    assert not hasattr(review_module, "fingerprint")
    assert not hasattr(review_module, "canonical_bytes")
    assert not hasattr(review_module, "canonical_json")
    for instance in _dataclass_instances(review):
        assert not hasattr(instance, "to_dict"), type(instance)
        assert hasattr(instance, "to_presentation_dict"), type(instance)
        names = {field.name for field in fields(instance)}
        assert not (
            names
            & {
                "fingerprint",
                "review_fingerprint",
                "identity_fingerprint",
                "presentation_fingerprint",
            }
        ), type(instance)
        assert not hasattr(instance, "identity_fingerprint")


# ---------------------------------------------------------------------------
# I. Deep immutability and fresh serialization.
# ---------------------------------------------------------------------------


def test_review_stores_only_immutable_scalars_tuples_and_frozen_dataclasses(review):
    assert list(_stored_mutable_containers(review)) == []
    for instance in _dataclass_instances(review):
        with pytest.raises(FrozenInstanceError):
            setattr(instance, fields(instance)[0].name, "injected")


def test_serializer_returns_fresh_containers_and_never_mutates_the_review(review):
    first = review.to_presentation_dict()
    second = review.to_presentation_dict()
    assert first == second
    assert first is not second
    assert first["claim_authority"] is not second["claim_authority"]
    assert (
        first["claim_authority"]["claims"]
        is not second["claim_authority"]["claims"]
    )
    assert first["notices"] is not second["notices"]

    first["claim_authority"]["claims"][0]["statement"] = "MUTATED"
    first["notices"].clear()
    first["withheld_fields"].append("injected")
    del first["pairing_identity"]

    third = review.to_presentation_dict()
    assert third == second
    assert review.notices is HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES
    assert review.claim_authority.claims[0].statement == (
        HOSTILE_CLAIM_STATEMENTS[0]
    )
    assert "MUTATED" not in json.dumps(third, ensure_ascii=False)


def test_presentation_keys_match_the_reviewed_dataclass_fields(review):
    for instance in _dataclass_instances(review):
        presented = instance.to_presentation_dict()
        assert set(presented) == {field.name for field in fields(instance)}, (
            type(instance)
        )
        assert isinstance(presented, dict)


# ---------------------------------------------------------------------------
# R/S. Derivation from pinned objects, byte invariance, refresh semantics.
# ---------------------------------------------------------------------------


def test_review_is_derived_from_pinned_objects_not_mutated_owner_arrays(
    coordinator: HistoricalEvaluationPairingCoordinator,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    claims = _hostile_claims()
    plan = _hostile_plan()
    bindings = _hostile_bindings(
        historical_payload.mission_profile.verification.verifier_source_sha256
    )
    view = coordinator.prepare_historical_evaluation_pairing(
        target_authorization_payload=historical_payload,
        result_claims=claims,
        claim_verification_plan=plan,
        verification_evidence_bindings=bindings,
        actor_id=ACTOR_ID,
    )
    first = coordinator.get_historical_evaluation_pairing_review(
        preparation_id=view.preparation_id,
        expected_authority_fingerprint=view.authority_fingerprint,
    )

    claims[0]["statement"] = "MUTATED STATEMENT"
    claims[0]["non_claims"].append("MUTATED NON-CLAIM")
    claims.pop()
    plan[0]["negative_controls"].clear()
    plan[0]["independence_requirements"]["temporal"] = False
    plan.pop()
    bindings[0]["source_authority_reference"] = "checkpoint.mutated"
    bindings.clear()

    second = coordinator.get_historical_evaluation_pairing_review(
        preparation_id=view.preparation_id,
        expected_authority_fingerprint=view.authority_fingerprint,
    )
    assert second == first
    rendered = json.dumps(second.to_presentation_dict(), ensure_ascii=False)
    assert "MUTATED" not in rendered
    assert "checkpoint.mutated" not in rendered
    assert len(second.claim_authority.claims) == 3
    assert len(second.verification_plan_authority.verification_obligations) == 4
    assert len(second.verification_evidence_binding_authority.bindings) == 3


def test_repeated_review_builds_leave_every_canonical_byte_unchanged(
    coordinator: HistoricalEvaluationPairingCoordinator, prepared
):
    pinned = coordinator._preparations[prepared.preparation_id]
    before = (
        canonical_bytes(pinned.evaluation_profile.to_dict()),
        canonical_bytes(pinned.target_authorization_payload.to_dict()),
        canonical_bytes(pinned.pairing_authority.to_dict()),
        bytes(pinned.confirmation_message),
    )
    reviews = []
    for _round in range(3):
        built = coordinator.get_historical_evaluation_pairing_review(
            preparation_id=prepared.preparation_id,
            expected_authority_fingerprint=prepared.authority_fingerprint,
        )
        built.to_presentation_dict()
        reviews.append(built)
    after = (
        canonical_bytes(pinned.evaluation_profile.to_dict()),
        canonical_bytes(pinned.target_authorization_payload.to_dict()),
        canonical_bytes(pinned.pairing_authority.to_dict()),
        bytes(pinned.confirmation_message),
    )
    assert after == before
    assert reviews[0] == reviews[1] == reviews[2]
    assert pinned.pairing_authority.authority_fingerprint == (
        prepared.authority_fingerprint
    )


def test_review_never_creates_an_archive_document(
    coordinator: HistoricalEvaluationPairingCoordinator,
    prepared,
    archive_root: Path,
):
    assert not archive_root.exists()
    coordinator.get_historical_evaluation_pairing_review(
        preparation_id=prepared.preparation_id,
        expected_authority_fingerprint=prepared.authority_fingerprint,
    )
    assert not archive_root.exists()


def test_stale_fingerprint_is_refused_before_any_review_construction(
    coordinator: HistoricalEvaluationPairingCoordinator, prepared
):
    def _never(*args, **kwargs):
        raise AssertionError("review construction started before the fingerprint check")

    with mock.patch.object(
        workflow, "build_historical_evaluation_pairing_owner_review", _never
    ):
        with pytest.raises(StalePairingAuthorityFingerprint):
            coordinator.get_historical_evaluation_pairing_review(
                preparation_id=prepared.preparation_id,
                expected_authority_fingerprint="0" * 64,
            )


def test_authority_fingerprint_is_compared_completely_and_never_by_prefix(
    coordinator: HistoricalEvaluationPairingCoordinator, prepared
):
    complete = prepared.authority_fingerprint
    for candidate in (
        complete[:-1] + ("0" if complete[-1] != "0" else "1"),
        ("0" if complete[0] != "0" else "1") + complete[1:],
        complete[:32] + "0" * 32,
        "0" * 32 + complete[32:],
    ):
        assert candidate != complete
        with pytest.raises(StalePairingAuthorityFingerprint):
            coordinator.get_historical_evaluation_pairing_review(
                preparation_id=prepared.preparation_id,
                expected_authority_fingerprint=candidate,
            )
    for malformed in (complete[:63], complete.upper(), complete + "0", "", None, 7):
        with pytest.raises(workflow.InvalidPairingPreparationRequest):
            coordinator.get_historical_evaluation_pairing_review(
                preparation_id=prepared.preparation_id,
                expected_authority_fingerprint=malformed,
            )


def test_review_never_extends_the_preparation_lifetime(
    coordinator: HistoricalEvaluationPairingCoordinator,
    prepared,
    clock: _FakeClock,
):
    created_at = coordinator._preparations[prepared.preparation_id].created_at
    for _round in range(5):
        clock.advance(100.0)
        coordinator.get_historical_evaluation_pairing_review(
            preparation_id=prepared.preparation_id,
            expected_authority_fingerprint=prepared.authority_fingerprint,
        )
        assert (
            coordinator._preparations[prepared.preparation_id].created_at
            == created_at
        )
    # 500 s elapsed against a 600 s TTL; one more step crosses it exactly.
    clock.advance(100.0)
    with pytest.raises(PairingPreparationExpired):
        coordinator.get_historical_evaluation_pairing_review(
            preparation_id=prepared.preparation_id,
            expected_authority_fingerprint=prepared.authority_fingerprint,
        )


def test_expired_is_never_degraded_into_not_found(
    coordinator: HistoricalEvaluationPairingCoordinator,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    clock: _FakeClock,
):
    first = coordinator.prepare_historical_evaluation_pairing(
        target_authorization_payload=historical_payload,
        actor_id=ACTOR_ID,
        **_owner_material(historical_payload),
    )
    second = coordinator.prepare_historical_evaluation_pairing(
        target_authorization_payload=historical_payload,
        actor_id="owner.second-actor",
        **_owner_material(historical_payload),
    )
    clock.advance(601.0)
    # The accepted ``keep`` law protects exactly the preparation being resolved,
    # so the sweep running alongside it can never turn its expiry into
    # not-found -- even though it does reclaim the other expired entry.
    with pytest.raises(PairingPreparationExpired):
        coordinator.get_historical_evaluation_pairing_review(
            preparation_id=second.preparation_id,
            expected_authority_fingerprint=second.authority_fingerprint,
        )
    with pytest.raises(PairingPreparationNotFound):
        coordinator.get_historical_evaluation_pairing_review(
            preparation_id=first.preparation_id,
            expected_authority_fingerprint=first.authority_fingerprint,
        )
    with pytest.raises(PairingPreparationNotFound):
        coordinator.get_historical_evaluation_pairing_review(
            preparation_id="prep-999999",
            expected_authority_fingerprint=first.authority_fingerprint,
        )


def test_review_reads_no_secret_and_verifies_no_tag(
    coordinator: HistoricalEvaluationPairingCoordinator, prepared
):
    def _never(*args, **kwargs):
        raise AssertionError("review reached the confirmation verifier")

    with mock.patch.object(
        workflow, "verify_historical_pairing_confirmation_tag", _never
    ):
        built = coordinator.get_historical_evaluation_pairing_review(
            preparation_id=prepared.preparation_id,
            expected_authority_fingerprint=prepared.authority_fingerprint,
        )
    assert built.pairing_identity.preparation_state == (
        PREPARATION_STATE_READY_FOR_CONFIRMATION
    )


def test_review_is_built_completely_outside_the_registry_lock(
    coordinator: HistoricalEvaluationPairingCoordinator, prepared, clock: _FakeClock
):
    observed: list[str] = []
    real_builder = workflow.build_historical_evaluation_pairing_owner_review

    def probing_builder(**kwargs):
        acquired = coordinator._lock.acquire(blocking=False)
        observed.append("builder-free" if acquired else "builder-blocked")
        if acquired:
            coordinator._lock.release()
        return real_builder(**kwargs)

    class _ProbingClock:
        def __call__(self) -> float:
            acquired = coordinator._lock.acquire(blocking=False)
            observed.append("clock-free" if acquired else "clock-blocked")
            if acquired:
                coordinator._lock.release()
            return clock()

    coordinator._clock = _ProbingClock()
    with mock.patch.object(
        workflow,
        "build_historical_evaluation_pairing_owner_review",
        probing_builder,
    ):
        coordinator.get_historical_evaluation_pairing_review(
            preparation_id=prepared.preparation_id,
            expected_authority_fingerprint=prepared.authority_fingerprint,
        )
    assert observed == ["clock-free", "builder-free"]


def test_review_does_not_block_a_concurrent_preparation(
    coordinator: HistoricalEvaluationPairingCoordinator,
    prepared,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """A slow review build must not hold the lock against another caller."""

    entered = threading.Event()
    release = threading.Event()
    real_builder = workflow.build_historical_evaluation_pairing_owner_review

    def slow_builder(**kwargs):
        entered.set()
        assert release.wait(timeout=10.0)
        return real_builder(**kwargs)

    outcome: dict[str, object] = {}

    def reviewer():
        with mock.patch.object(
            workflow,
            "build_historical_evaluation_pairing_owner_review",
            slow_builder,
        ):
            outcome["review"] = coordinator.get_historical_evaluation_pairing_review(
                preparation_id=prepared.preparation_id,
                expected_authority_fingerprint=prepared.authority_fingerprint,
            )

    thread = threading.Thread(target=reviewer)
    thread.start()
    try:
        assert entered.wait(timeout=10.0)
        second = coordinator.prepare_historical_evaluation_pairing(
            target_authorization_payload=historical_payload,
            actor_id="owner.concurrent-actor",
            **_owner_material(historical_payload),
        )
        assert second.preparation_id != prepared.preparation_id
    finally:
        release.set()
        thread.join(timeout=10.0)
    assert not thread.is_alive()
    assert isinstance(
        outcome["review"], HistoricalEvaluationPairingOwnerReview
    )


# ---------------------------------------------------------------------------
# R. Preparation-state snapshot semantics.
# ---------------------------------------------------------------------------


def test_in_progress_and_consumed_preparations_stay_reviewable(
    coordinator: HistoricalEvaluationPairingCoordinator, prepared
):
    from admissible.delegated_gate.historical_pairing_confirmation import (
        compute_historical_pairing_confirmation_tag,
    )

    authority = coordinator._preparations[
        prepared.preparation_id
    ].pairing_authority
    tag = compute_historical_pairing_confirmation_tag(
        secret=REVIEW_SECRET, pairing_authority=authority
    )
    observed: list[str] = []
    real_persist = workflow.persist_historical_evaluation_pairing

    def observing_persist(**kwargs):
        # Confirmation holds no lock here, so the reserved state is observable.
        mid = coordinator.get_historical_evaluation_pairing_review(
            preparation_id=prepared.preparation_id,
            expected_authority_fingerprint=prepared.authority_fingerprint,
        )
        observed.append(mid.pairing_identity.preparation_state)
        return real_persist(**kwargs)

    with mock.patch.object(
        workflow, "persist_historical_evaluation_pairing", observing_persist
    ):
        result = coordinator.confirm_historical_evaluation_pairing(
            preparation_id=prepared.preparation_id,
            expected_authority_fingerprint=prepared.authority_fingerprint,
            presented_confirmation_tag=tag,
        )
    assert result.outcome == workflow.CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    assert observed == [PREPARATION_STATE_CONFIRMATION_IN_PROGRESS]

    after = coordinator.get_historical_evaluation_pairing_review(
        preparation_id=prepared.preparation_id,
        expected_authority_fingerprint=prepared.authority_fingerprint,
    )
    assert after.pairing_identity.preparation_state == PREPARATION_STATE_CONSUMED
    assert after.claim_authority == (
        coordinator.get_historical_evaluation_pairing_review(
            preparation_id=prepared.preparation_id,
            expected_authority_fingerprint=prepared.authority_fingerprint,
        ).claim_authority
    )


def test_preparation_states_are_exactly_the_three_documented_values():
    assert HISTORICAL_PAIRING_PREPARATION_STATES == (
        PREPARATION_STATE_READY_FOR_CONFIRMATION,
        PREPARATION_STATE_CONFIRMATION_IN_PROGRESS,
        PREPARATION_STATE_CONSUMED,
    )
    assert PREPARATION_STATE_READY_FOR_CONFIRMATION == "READY_FOR_CONFIRMATION"
    assert PREPARATION_STATE_CONFIRMATION_IN_PROGRESS == (
        "CONFIRMATION_IN_PROGRESS"
    )
    assert PREPARATION_STATE_CONSUMED == "CONSUMED"


# ---------------------------------------------------------------------------
# Builder input validation.
# ---------------------------------------------------------------------------


def test_builder_refuses_malformed_inputs(
    coordinator: HistoricalEvaluationPairingCoordinator, prepared
):
    pinned = coordinator._preparations[prepared.preparation_id]
    base = dict(
        preparation_id=prepared.preparation_id,
        preparation_state=PREPARATION_STATE_READY_FOR_CONFIRMATION,
        evaluation_profile=pinned.evaluation_profile,
        target_authorization_payload=pinned.target_authorization_payload,
        pairing_authority=pinned.pairing_authority,
        confirmation_message=pinned.confirmation_message,
    )
    assert isinstance(
        build_historical_evaluation_pairing_owner_review(**base),
        HistoricalEvaluationPairingOwnerReview,
    )
    for overrides in (
        {"preparation_id": ""},
        {"preparation_id": 7},
        {"preparation_state": "SOMETHING_ELSE"},
        {"evaluation_profile": object()},
        {"evaluation_profile": pinned.target_authorization_payload.mission_profile},
        {"target_authorization_payload": object()},
        {"pairing_authority": object()},
        {"confirmation_message": ""},
        {"confirmation_message": b""},
        {"confirmation_message": bytearray(b"abc")},
        {"confirmation_message": b"x" * (review_module.MAX_CONFIRMATION_MESSAGE_BYTES + 1)},
    ):
        with pytest.raises(HistoricalPairingOwnerReviewError):
            build_historical_evaluation_pairing_owner_review(**{**base, **overrides})


def test_review_type_is_frozen_and_carries_the_documented_sections(review):
    assert {field.name for field in fields(HistoricalEvaluationPairingOwnerReview)} == {
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
    with pytest.raises(FrozenInstanceError):
        review.notices = ()


# ---------------------------------------------------------------------------
# Step 5C2C1.1 C. Structured locators versus exact free text.
#
# Two deliberately different marker classes are planted at once:
#
# * structured locator markers, planted into canonical locator FIELDS, none of
#   which may ever reach the review; and
# * exact free-text and command markers -- Windows-flavoured and
#   POSIX-flavoured absolute-path-looking strings -- planted into owner-authored
#   and mission-authored TEXT and into checkpoint argv, every one of which must
#   be reproduced without rewriting.
#
# Every assertion below is exact marker membership or exact field equality.  No
# platform-dependent path predicate is used, so the meaning is identical on
# Windows and on POSIX.
# ---------------------------------------------------------------------------

# One token per independently settable canonical locator field.  The four
# authorization roots are structurally derived from one another (the workspace,
# evidence and sidecar roots are the committed deterministic children of the run
# root), so they necessarily share one chain token; each complete root value is
# additionally asserted absent on its own.
LOCATOR_MARKERS = {
    "source_repository": "zlocsrcrepo5c2c11",
    "run_root_chain": "zlocrunchain5c2c11",
    "program_path": "zlocprogram5c2c11",
    "launcher_prefix": "zloclauncher5c2c11",
    "local_repository_path": "zloclocalrepo5c2c11",
    "configured_document_path": "zlocdocument5c2c11",
    "archive_root": "zlocarchive5c2c11",
}

# Free-text slots whose exact planted text must survive verbatim.
TEXT_MARKER_SLOTS = (
    "mission_text",
    "gate_objective",
    "completion_conditions_text",
    "stop_clause",
    "gate_clause",
    "claim_statement",
    "claim_non_claim",
    "declared_coverage",
    "negative_control",
    "checkpoint_argv",
)

# Slots the canonical identifier grammar constrains, so a complete absolute
# path cannot be planted there at all.
IDENTIFIER_MARKER_SLOTS = ("procedure_reference", "reference_case")


def _windows_text_marker(slot: str) -> str:
    return f"C:\\s5c2c11\\{slot}\\windows-absolute.txt"


def _posix_text_marker(slot: str) -> str:
    return f"/s5c2c11/{slot}/posix-absolute.txt"


def _text_markers(slot: str) -> tuple[str, str]:
    return _windows_text_marker(slot), _posix_text_marker(slot)


def _decorated(base: str, slot: str) -> str:
    """Append both absolute-path-looking flavours to one authored string."""

    windows, posix = _text_markers(slot)
    return f"{base}\n{windows}\n{posix}\n"


def _identifier_marker(slot: str) -> str:
    """The most path-looking value the canonical identifier grammar permits."""

    return f"C:s5c2c11.{slot}.absolute-like"


def _serialized(value: str) -> str:
    """Return one string exactly as it appears inside serialized JSON.

    A Windows-flavoured marker carries a separator that JSON escapes, so a raw
    substring test against serialized output would be silently vacuous.
    """

    return json.dumps(value, ensure_ascii=False)[1:-1]


def _disclosure_profile(
    profile: NativeMissionProfile, local_repository: Path
) -> NativeMissionProfile:
    """One historical V2 profile whose authored prose carries both flavours."""

    data = profile.to_dict()
    data["mission_text"] = _decorated(data["mission_text"], "mission_text")
    data["gate_objective"] = _decorated(data["gate_objective"], "gate_objective")
    data["completion_conditions_text"] = _decorated(
        data["completion_conditions_text"], "completion_conditions_text"
    )
    data["runtime_prompt"]["stop_clause"] = _decorated(
        data["runtime_prompt"]["stop_clause"], "stop_clause"
    )
    clause_id, clause_text = data["gate_clauses"][0]
    data["gate_clauses"][0] = [clause_id, _decorated(clause_text, "gate_clause")]
    windows, posix = _text_markers("checkpoint_argv")
    data["checkpoint_commands"][0]["argv"] = [
        *data["checkpoint_commands"][0]["argv"],
        windows,
        posix,
    ]
    data["workspace_source"] = {
        "kind": WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY.value,
        "fixture_id": None,
        "fixture_version": None,
        "local_repository_path": str(local_repository),
    }
    return NativeMissionProfile.from_dict(_refingerprint_profile(data))


def _disclosure_owner_material(
    payload: NativeCanaryAuthorizationPayloadV4,
) -> dict:
    """Owner-authored material whose prose carries both flavours."""

    claims = _hostile_claims()
    claims[0]["statement"] = _decorated(claims[0]["statement"], "claim_statement")
    claims[0]["non_claims"] = [
        _decorated(claims[0]["non_claims"][0], "claim_non_claim")
    ]
    plan = _hostile_plan()
    plan[0]["procedure_reference"] = _identifier_marker("procedure_reference")
    plan[0]["declared_coverage"] = _decorated(
        plan[0]["declared_coverage"], "declared_coverage"
    )
    plan[0]["negative_controls"][0]["description"] = _decorated(
        plan[0]["negative_controls"][0]["description"], "negative_control"
    )
    plan[0]["reference_cases"] = [
        _identifier_marker("reference_case"),
        *plan[0]["reference_cases"],
    ]
    return {
        "result_claims": claims,
        "claim_verification_plan": plan,
        "verification_evidence_bindings": _hostile_bindings(
            payload.mission_profile.verification.verifier_source_sha256
        ),
    }


@pytest.fixture(scope="module")
def disclosure_payload(
    tmp_path_factory: pytest.TempPathFactory,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
) -> NativeCanaryAuthorizationPayloadV4:
    """One payload carrying both marker classes at once."""

    fixture_root = tmp_path_factory.mktemp("s5c2c11")
    local_repository = (
        fixture_root / f"absent-{LOCATOR_MARKERS['local_repository_path']}" / "repo"
    )
    variant = _disclosure_profile(
        historical_payload.mission_profile, local_repository
    )
    live = _payload_for_runtime_profile(historical_payload, variant).to_dict()
    assert live["launcher_prefix"], "the fixture must exercise launcher_prefix"
    chain = fixture_root / f"absent-{LOCATOR_MARKERS['run_root_chain']}"
    run_root = chain / live["run_id"]
    live["source_repository"] = str(
        fixture_root / f"absent-{LOCATOR_MARKERS['source_repository']}" / "source"
    )
    live["executable"] = str(
        fixture_root / f"absent-{LOCATOR_MARKERS['program_path']}" / "agent.exe"
    )
    live["launcher_prefix"] = [
        str(
            fixture_root
            / f"absent-{LOCATOR_MARKERS['launcher_prefix']}-{index}"
            / "launcher.exe"
        )
        for index, _value in enumerate(live["launcher_prefix"])
    ]
    live["run_root"] = str(run_root)
    live["workspace_root"] = str(run_root / WORKSPACE_DIRECTORY_NAME)
    live["evidence_root"] = str(run_root / EVIDENCE_DIRECTORY_NAME)
    live["native_sidecar_root"] = str(
        run_root / EVIDENCE_DIRECTORY_NAME / NATIVE_SIDECAR_DIRECTORY_NAME
    )
    payload = load_historical_native_canary_authorization_payload_v4(
        _refingerprint_payload(live)
    )
    assert not chain.exists()
    assert not local_repository.exists()
    return payload


@pytest.fixture(scope="module")
def registered_disclosure_payload(
    tmp_path_factory: pytest.TempPathFactory,
    disclosure_payload: NativeCanaryAuthorizationPayloadV4,
) -> NativeCanaryAuthorizationPayloadV4:
    """The same payload, delivered through a marker-bearing configured path."""

    root = tmp_path_factory.mktemp("s5c2c11-reg")
    document = root / f"{LOCATOR_MARKERS['configured_document_path']}.json"
    document.write_bytes(canonical_bytes(disclosure_payload.to_dict()))
    registry = HistoricalPayloadRegistry(
        configuration=HistoricalPairingConfiguration(
            archive_root=root / "registry-archive",
            payload_entries=(
                HistoricalPayloadEntry(
                    payload_id="disclosure-payload", document_path=document
                ),
            ),
        )
    )
    loaded = registry.get(payload_id="disclosure-payload")
    assert loaded.payload_fingerprint == disclosure_payload.payload_fingerprint
    assert LOCATOR_MARKERS["configured_document_path"] in str(document)
    return loaded


@pytest.fixture()
def disclosure_archive_root(tmp_path: Path) -> Path:
    return tmp_path / f"{LOCATOR_MARKERS['archive_root']}-archive"


@pytest.fixture()
def disclosure_coordinator(
    disclosure_archive_root: Path, clock: _FakeClock
) -> HistoricalEvaluationPairingCoordinator:
    return HistoricalEvaluationPairingCoordinator(
        configured_secret=REVIEW_SECRET,
        archive_root=disclosure_archive_root,
        preparation_ttl_seconds=600,
        max_preparations=8,
        clock=clock,
        preparation_id_factory=_sequential_identifiers("disclosure"),
    )


@pytest.fixture()
def disclosure_review(
    disclosure_coordinator: HistoricalEvaluationPairingCoordinator,
    registered_disclosure_payload: NativeCanaryAuthorizationPayloadV4,
) -> HistoricalEvaluationPairingOwnerReview:
    prepared = disclosure_coordinator.prepare_historical_evaluation_pairing(
        target_authorization_payload=registered_disclosure_payload,
        actor_id=ACTOR_ID,
        **_disclosure_owner_material(registered_disclosure_payload),
    )
    return disclosure_coordinator.get_historical_evaluation_pairing_review(
        preparation_id=prepared.preparation_id,
        expected_authority_fingerprint=prepared.authority_fingerprint,
    )


def test_every_structured_locator_marker_is_actually_planted(
    registered_disclosure_payload: NativeCanaryAuthorizationPayloadV4,
    disclosure_archive_root: Path,
):
    """A marker that was never planted would prove nothing about withholding."""

    payload = registered_disclosure_payload
    source = payload.mission_profile.effective_workspace_source
    assert LOCATOR_MARKERS["source_repository"] in payload.source_repository
    assert LOCATOR_MARKERS["program_path"] in payload.executable
    assert payload.launcher_prefix
    for value in payload.launcher_prefix:
        assert LOCATOR_MARKERS["launcher_prefix"] in value
    for value in (
        payload.run_root,
        payload.workspace_root,
        payload.evidence_root,
        payload.native_sidecar_root,
    ):
        assert LOCATOR_MARKERS["run_root_chain"] in value
    assert source.kind is WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY
    assert LOCATOR_MARKERS["local_repository_path"] in source.local_repository_path
    assert LOCATOR_MARKERS["archive_root"] in str(disclosure_archive_root)
    # The four roots really are structurally derived, which is why they share
    # one chain token rather than carrying four independent ones.
    assert payload.workspace_root == str(
        Path(payload.run_root) / WORKSPACE_DIRECTORY_NAME
    )
    assert payload.evidence_root == str(
        Path(payload.run_root) / EVIDENCE_DIRECTORY_NAME
    )
    assert payload.native_sidecar_root == str(
        Path(payload.evidence_root) / NATIVE_SIDECAR_DIRECTORY_NAME
    )


def test_no_structured_locator_marker_or_value_reaches_the_review(
    disclosure_review: HistoricalEvaluationPairingOwnerReview,
    registered_disclosure_payload: NativeCanaryAuthorizationPayloadV4,
    disclosure_archive_root: Path,
):
    review = disclosure_review
    payload = registered_disclosure_payload
    presented = review.to_presentation_dict()
    rendered = json.dumps(presented, ensure_ascii=False)
    rendered_repr = repr(review)
    texts = _texts(review)
    keyed = list(_keyed_values(presented))

    for name, marker in LOCATOR_MARKERS.items():
        assert marker not in rendered, name
        assert marker not in rendered_repr, name
        for text in texts:
            assert marker not in text, name
        for key, value in keyed:
            assert marker not in key, name
            if isinstance(value, str):
                assert marker not in value, name

    complete_values = (
        payload.source_repository,
        payload.run_root,
        payload.workspace_root,
        payload.evidence_root,
        payload.native_sidecar_root,
        payload.executable,
        *payload.launcher_prefix,
        payload.mission_profile.effective_workspace_source.local_repository_path,
        str(disclosure_archive_root),
    )
    assert len(set(complete_values)) == len(complete_values)
    for value in complete_values:
        assert value
        # Both the raw value and its serialized form, because JSON escapes the
        # separator a Windows-flavoured locator carries.
        assert value not in rendered
        assert _serialized(value) not in rendered
        assert value not in rendered_repr
        for text in texts:
            assert value not in text
        for _key, presented_value in keyed:
            if isinstance(presented_value, str):
                assert value not in presented_value


def test_the_source_repository_identity_is_not_path_bearing(
    disclosure_review: HistoricalEvaluationPairingOwnerReview,
    registered_disclosure_payload: NativeCanaryAuthorizationPayloadV4,
):
    """The withheld identity carries no path at all, and never appears.

    ``source_repository_identity`` is a filesystem identity of pure integers,
    so it is not path-bearing in the first place; what is proven here is that
    the complete object is withheld anyway.
    """

    identity = registered_disclosure_payload.source_repository_identity.to_dict()
    assert identity
    assert all(isinstance(value, int) for value in identity.values())
    for key in identity:
        assert "path" not in key, key
        assert LOCATOR_MARKERS["source_repository"] not in str(identity[key])
    presented = disclosure_review.to_presentation_dict()
    rendered = json.dumps(presented, ensure_ascii=False)
    assert canonical_json(identity) not in rendered
    for key, _value in _keyed_values(presented):
        assert "source_repository_identity" not in key, key
        # ``mode`` is deliberately not banned: the behavioral-verifier
        # disclosure owns an unrelated field of that name.
        assert key.rsplit(".", 1)[-1] not in {
            "device",
            "inode",
            "size",
            "mtime_ns",
            "file_attributes",
        }, key
    assert (
        "target_authorization_payload.source_repository_identity"
        in HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS
    )


# The exact review field and the exact presentation key that must carry each
# planted marker -- and nothing else may carry it.
MARKER_CARRIERS = {
    "mission_text": "historical_mission_context.mission_text",
    "gate_objective": "historical_mission_context.gate_objective",
    "completion_conditions_text": (
        "historical_mission_context.completion_conditions_text"
    ),
    "stop_clause": "historical_mission_context.stop_clause",
    "gate_clause": "historical_mission_context.gate_clauses[0].text",
    "claim_statement": "claim_authority.claims[0].statement",
    "claim_non_claim": "claim_authority.claims[0].non_claims[0]",
    "declared_coverage": (
        "verification_plan_authority.verification_obligations[0]"
        ".declared_coverage"
    ),
    "negative_control": (
        "verification_plan_authority.verification_obligations[0]"
        ".negative_controls[0].description"
    ),
    "procedure_reference": (
        "verification_plan_authority.verification_obligations[0]"
        ".procedure_reference"
    ),
    "reference_case": (
        "verification_plan_authority.verification_obligations[0]"
        ".reference_cases[0]"
    ),
}


def test_every_exact_prose_marker_is_reproduced_in_its_own_field_only(
    disclosure_review: HistoricalEvaluationPairingOwnerReview,
):
    """Each planted string appears exactly once, at exactly the right key."""

    presented = disclosure_review.to_presentation_dict()
    keyed = list(_keyed_values(presented))
    for slot in TEXT_MARKER_SLOTS:
        if slot == "checkpoint_argv":
            continue
        for marker in _text_markers(slot):
            carriers = sorted(
                key
                for key, value in keyed
                if isinstance(value, str) and marker in value
            )
            assert carriers == [MARKER_CARRIERS[slot]], (slot, marker, carriers)
    for slot in IDENTIFIER_MARKER_SLOTS:
        marker = _identifier_marker(slot)
        carriers = sorted(
            key for key, value in keyed if isinstance(value, str) and marker in value
        )
        assert carriers == [MARKER_CARRIERS[slot]], (slot, carriers)


def test_exact_authored_prose_is_reproduced_without_rewriting(
    disclosure_review: HistoricalEvaluationPairingOwnerReview,
    registered_disclosure_payload: NativeCanaryAuthorizationPayloadV4,
):
    """Field-by-field equality against the pinned canonical source values."""

    review = disclosure_review
    profile = registered_disclosure_payload.mission_profile
    context = review.historical_mission_context
    presented = review.to_presentation_dict()
    mission = presented["historical_mission_context"]
    owner = _disclosure_owner_material(registered_disclosure_payload)

    for slot, stored, shown, authored in (
        ("mission_text", context.mission_text, mission["mission_text"],
         profile.mission_text),
        ("gate_objective", context.gate_objective, mission["gate_objective"],
         profile.gate_objective),
        ("completion_conditions_text", context.completion_conditions_text,
         mission["completion_conditions_text"],
         profile.completion_conditions_text),
        ("stop_clause", context.stop_clause, mission["stop_clause"],
         profile.runtime_prompt.stop_clause),
        ("gate_clause", context.gate_clauses[0].text,
         mission["gate_clauses"][0]["text"], profile.gate_clauses[0][1]),
        ("claim_statement", review.claim_authority.claims[0].statement,
         presented["claim_authority"]["claims"][0]["statement"],
         owner["result_claims"][0]["statement"]),
        ("claim_non_claim", review.claim_authority.claims[0].non_claims[0],
         presented["claim_authority"]["claims"][0]["non_claims"][0],
         owner["result_claims"][0]["non_claims"][0]),
        ("declared_coverage",
         review.verification_plan_authority.verification_obligations[0]
         .declared_coverage,
         presented["verification_plan_authority"]["verification_obligations"][0]
         ["declared_coverage"],
         owner["claim_verification_plan"][0]["declared_coverage"]),
        ("negative_control",
         review.verification_plan_authority.verification_obligations[0]
         .negative_controls[0].description,
         presented["verification_plan_authority"]["verification_obligations"][0]
         ["negative_controls"][0]["description"],
         owner["claim_verification_plan"][0]["negative_controls"][0]
         ["description"]),
    ):
        windows, posix = _text_markers(slot)
        assert windows in authored and posix in authored, slot
        # Exact reproduction: no strip, collapse, escape, or rewrite.
        assert stored == authored, slot
        assert shown == authored, slot
        assert windows in stored and posix in stored, slot
        assert stored != stored.strip(), slot
        assert stored != " ".join(stored.split()), slot


def test_exact_checkpoint_command_arguments_are_reproduced_without_rewriting(
    disclosure_review: HistoricalEvaluationPairingOwnerReview,
    registered_disclosure_payload: NativeCanaryAuthorizationPayloadV4,
):
    profile = registered_disclosure_payload.mission_profile
    command = disclosure_review.historical_mission_context.checkpoint_commands[0]
    presented = disclosure_review.to_presentation_dict()
    shown = presented["historical_mission_context"]["checkpoint_commands"][0]
    windows, posix = _text_markers("checkpoint_argv")

    assert command.argv == profile.checkpoint_commands[0].argv
    assert shown["argv"] == list(profile.checkpoint_commands[0].argv)
    assert command.argv[-2:] == (windows, posix)
    assert shown["argv"][-2:] == [windows, posix]

    keyed = list(_keyed_values(presented))
    for offset, marker in ((2, windows), (1, posix)):
        index = len(command.argv) - offset
        carriers = sorted(
            key for key, value in keyed if isinstance(value, str) and marker in value
        )
        assert carriers == [
            f"historical_mission_context.checkpoint_commands[0].argv[{index}]"
        ], (marker, carriers)


def test_identifier_fields_cannot_carry_a_complete_absolute_path(
    disclosure_review: HistoricalEvaluationPairingOwnerReview,
):
    """The limitation on identifier-typed fields is pinned, not glossed over.

    ``procedure_reference`` and every reference case are canonical identifiers.
    The grammar admits ``:`` but neither separator flavour, so the most
    path-looking value the schema permits is planted there instead -- and the
    review still reproduces that value exactly.
    """

    obligation = (
        disclosure_review.verification_plan_authority.verification_obligations[0]
    )
    for slot, value in (
        ("procedure_reference", obligation.procedure_reference),
        ("reference_case", obligation.reference_cases[0]),
    ):
        assert value == _identifier_marker(slot)
        assert require_identifier(value, slot) == value
        assert ":" in value
        for refused in _text_markers(slot):
            with pytest.raises(ValueError):
                require_identifier(refused, slot)


def test_the_documented_distinction_is_stated_exactly(
    disclosure_review: HistoricalEvaluationPairingOwnerReview,
):
    """Structured locator fields withheld versus exact text reproduced."""

    documentation = " ".join(review_module.__doc__.split()).lower()
    assert (
        "every structured local locator field carried by the historical "
        "authorization is deliberately withheld" in documentation
    )
    assert (
        "exact owner-authored and mission-authored text is reproduced without "
        "rewriting, and such text may itself contain path-like or "
        "absolute-path-looking content" in documentation
    )
    assert (
        "the exact profile-authored checkpoint command arguments are reproduced"
        in documentation
    )
    # The two halves describe different material: no withheld field name is a
    # presented mission-context field, and vice versa.
    presented_mission_keys = set(
        disclosure_review.historical_mission_context.to_presentation_dict()
    )
    withheld_leaves = {
        field.rsplit(".", 1)[-1]
        for field in HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS
    }
    assert not (presented_mission_keys & withheld_leaves)
    assert {"mission_text", "checkpoint_commands"} <= presented_mission_keys


# ---------------------------------------------------------------------------
# Step 5C2C1.1 E. Authority-wrapper schema fidelity.
#
# The source field inventory is read from the real canonical types, so adding a
# wrapper field upstream without an explicit reviewed representation fails here.
# ---------------------------------------------------------------------------

AUTHORITY_WRAPPER_SCHEMAS = (
    (
        ClaimAuthority,
        ReviewedClaimAuthority,
        {
            "authorship": "authorship",
            "coverage_status": "coverage_status",
            "claims": "claims",
        },
        "claims",
        "claim_id",
        ResultClaim,
        ReviewedResultClaim,
    ),
    (
        ClaimVerificationPlanAuthority,
        ReviewedVerificationPlanAuthority,
        {
            "authorship": "authorship",
            "coverage_status": "coverage_status",
            "verification_obligations": "verification_obligations",
        },
        "verification_obligations",
        "obligation_id",
        VerificationObligation,
        ReviewedVerificationObligation,
    ),
    (
        VerificationEvidenceBindingAuthority,
        ReviewedEvidenceBindingAuthority,
        {
            "authorship": "authorship",
            "coverage_status": "coverage_status",
            "bindings": "bindings",
        },
        "bindings",
        "binding_id",
        VerificationEvidenceBinding,
        ReviewedEvidenceBinding,
    ),
)

# A reviewed wrapper may never invent an authority result or assessment.
INVENTED_AUTHORITY_RESULT_NAMES = frozenset(
    {
        "result",
        "results",
        "assessment",
        "assessed",
        "satisfaction",
        "satisfied",
        "verdict",
        "product_verdict",
        "admitted",
        "admission",
        "eligibility",
        "support",
        "claim_support",
        "coverage_rollup",
        "outcome",
        "score",
        "conclusion",
        "obligation_result",
    }
)


@pytest.mark.parametrize(
    "source_type,reviewed_type,mapping,member_field,id_field,"
    "source_member_type,reviewed_member_type",
    AUTHORITY_WRAPPER_SCHEMAS,
    ids=[schema[0].__name__ for schema in AUTHORITY_WRAPPER_SCHEMAS],
)
def test_every_authority_wrapper_field_has_an_explicit_reviewed_mapping(
    source_type,
    reviewed_type,
    mapping,
    member_field,
    id_field,
    source_member_type,
    reviewed_member_type,
):
    source_fields = {field.name for field in fields(source_type)}
    reviewed_fields = {field.name for field in fields(reviewed_type)}
    # Inventoried from the real source type: a new wrapper field upstream
    # without an explicit reviewed mapping fails right here.
    assert source_fields == set(mapping), source_type
    # No source field is silently omitted and no reviewed field is invented.
    assert reviewed_fields == set(mapping.values()), reviewed_type
    assert not (reviewed_fields & INVENTED_AUTHORITY_RESULT_NAMES), reviewed_type
    assert member_field in mapping.values()
    # The ordered member collection keeps its field-for-field member schema.
    assert {field.name for field in fields(reviewed_member_type)} == {
        field.name for field in fields(source_member_type)
    }
    assert id_field in {field.name for field in fields(reviewed_member_type)}
    # The wrappers carry no schema version of their own: the accepted design
    # states it exactly once, on the pairing identity.
    assert "schema_version" not in reviewed_fields
    assert "schema_version" not in source_fields


def test_reviewed_wrappers_preserve_authorship_coverage_and_owner_order(
    review: HistoricalEvaluationPairingOwnerReview,
    coordinator: HistoricalEvaluationPairingCoordinator,
    prepared,
):
    profile = coordinator._preparations[prepared.preparation_id].evaluation_profile
    pairs = (
        ("claim_authority", "claim_authority"),
        ("claim_verification_plan_authority", "verification_plan_authority"),
        (
            "verification_evidence_binding_authority",
            "verification_evidence_binding_authority",
        ),
    )
    for (source_attribute, reviewed_attribute), schema in zip(
        pairs, AUTHORITY_WRAPPER_SCHEMAS, strict=True
    ):
        _source_type, _reviewed_type, mapping, member_field, id_field = schema[:5]
        source = getattr(profile, source_attribute)
        reviewed = getattr(review, reviewed_attribute)
        assert reviewed.authorship == source.authorship.value
        assert reviewed.coverage_status == source.coverage_status.value
        # Coverage remains exactly what the authority carries.
        assert reviewed.coverage_status == "NOT_ASSESSED"
        members = getattr(reviewed, member_field)
        source_members = getattr(source, member_field)
        assert isinstance(members, tuple)
        # Owner ordering is preserved: nothing sorts, dedupes, or regroups.
        assert [getattr(member, id_field) for member in members] == [
            getattr(member, id_field) for member in source_members
        ]
        presented = reviewed.to_presentation_dict()
        assert set(presented) == set(mapping.values())
        assert len(presented[member_field]) == len(source_members)
    assert review.pairing_identity.evaluation_profile_schema_version == (
        profile.schema_version
    )
    assert profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5


# ---------------------------------------------------------------------------
# Step 5C2C1.1 F. Documentation wording.
#
# The audit distinguishes an explicit limitation from a positive overclaim: a
# sentence may name a hazard as long as it also bounds it, and a sentence that
# names the hazard while asserting immunity is refused.
# ---------------------------------------------------------------------------

_REVIEW_LIMITATION_CUES = frozenset(
    {
        "no",
        "not",
        "never",
        "cannot",
        "nothing",
        "neither",
        "nor",
        "may",
        "without",
        "inert",
        "deliberately",
    }
)

# The exact bounded claims the module is allowed to state.
REVIEW_REQUIRED_BOUNDED_CLAIMS = (
    "every structured local locator field carried by the historical "
    "authorization is deliberately withheld",
    "that is a field-level guarantee about exactly those named fields and it "
    "is nothing wider.",
    "exact owner-authored and mission-authored text is reproduced without "
    "rewriting, and such text may itself contain path-like or "
    "absolute-path-looking content",
    "the exact profile-authored checkpoint command arguments are reproduced "
    "as well, and one of those arguments may be, or may contain, a program "
    "name or a path-like string.",
    "no claim is made that every string resembling a path has been removed.",
    "it is never evidence that a filesystem entry exists, and a displayed "
    "path has been neither resolved nor accessed.",
    "the review continues to assert no path, source, artifact, or workspace "
    "existence.",
)

# Positive overclaims the module must never make.
REVIEW_FORBIDDEN_OVERCLAIMS = (
    "no absolute local path",
    "absolute local path value",
    "ever appears in the review",
    "never appears in the review",
    "no path-looking text",
    "no path-like text",
    "contains no path",
    "cannot contain a path",
    "cannot contain paths",
    "argv cannot contain",
    "arguments cannot contain a path",
    "every string resembling a path is removed",
    "all path-like text is removed",
    "prose is sanitized",
    "arbitrary prose is sanitized",
)

# Hazards that may be named only inside a sentence that also bounds them.
REVIEW_BOUNDED_TOPICS = (
    "path-like",
    "absolute-path-looking",
    "resembling a path",
)

# The exact false universal sentence this slice removed.
REMOVED_FALSE_UNIVERSAL_SENTENCE = (
    "No absolute local path value from the payload ever appears in the review "
    "or in its presentation mapping."
)


def _review_documentation() -> str:
    return " ".join(review_module.__doc__.split()).lower()


def test_review_states_the_bounded_disclosure_claim():
    documentation = _review_documentation()
    for claim in REVIEW_REQUIRED_BOUNDED_CLAIMS:
        assert claim in documentation, claim


def test_review_makes_no_universal_path_disclosure_claim():
    documentation = _review_documentation()
    for overclaim in REVIEW_FORBIDDEN_OVERCLAIMS:
        assert overclaim not in documentation, overclaim
    source = " ".join(
        Path(review_module.__file__).read_text(encoding="utf-8").split()
    ).lower()
    assert " ".join(REMOVED_FALSE_UNIVERSAL_SENTENCE.split()).lower() not in source


def test_every_review_hazard_sentence_bounds_the_hazard_it_names():
    normalized = " ".join(review_module.__doc__.split())
    sentences = [
        sentence.strip()
        for sentence in re.split(r"(?<=\.)\s+", normalized)
        if sentence.strip()
    ]
    for topic in REVIEW_BOUNDED_TOPICS:
        carrying = [
            sentence for sentence in sentences if topic in sentence.lower()
        ]
        assert carrying, topic
        for sentence in carrying:
            words = set(re.findall(r"[a-z]+", sentence.lower()))
            assert _REVIEW_LIMITATION_CUES & words, (topic, sentence)


def test_the_bounded_wording_matches_the_behavior_that_exists(
    disclosure_review: HistoricalEvaluationPairingOwnerReview,
    registered_disclosure_payload: NativeCanaryAuthorizationPayloadV4,
):
    """Documentation and behavior are checked against each other, both ways."""

    rendered = json.dumps(
        disclosure_review.to_presentation_dict(), ensure_ascii=False
    )
    # The withholding half is true.
    for marker in LOCATOR_MARKERS.values():
        assert marker not in rendered
    # The reproduction half is true, and is exactly why the universal claim
    # would have been false.  A Windows-flavoured marker is compared in its
    # serialized form, because JSON escapes the separator it contains.
    for slot in TEXT_MARKER_SLOTS:
        for marker in _text_markers(slot):
            assert _serialized(marker) in rendered, slot
    assert (
        "no source, path, artifact, or workspace existence"
        in "\n".join(HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES)
    )


def test_existing_preparation_view_and_projection_are_unchanged(prepared):
    """Step 5C2B's accepted surfaces keep their exact shape."""

    assert {
        field.name
        for field in fields(workflow.HistoricalEvaluationPairingPreparationView)
    } == {
        "preparation_id",
        "asserted_actor_id",
        "authority_fingerprint",
        "evaluation_profile_fingerprint",
        "target_authorization_payload_fingerprint",
        "confirmation_message",
        "review_projection",
        "limitations",
    }
    assert prepared.limitations is HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS
    projection = prepared.review_projection
    assert projection.result_claim_ids == ("claim.zulu", "claim.alpha", "claim.mike")
    assert projection.verification_obligation_ids == (
        "verify.zulu",
        "verify.echo",
        "verify.alpha",
        "verify.human",
    )
    assert projection.verification_evidence_binding_ids == (
        "binding.zulu",
        "binding.alpha",
        "binding.echo",
    )
    assert projection.evaluation_profile_is_launchable is False
