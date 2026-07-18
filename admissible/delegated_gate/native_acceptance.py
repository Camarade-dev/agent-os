"""Write-once committed-review binding and human acceptance of a captured canary.

Execution success, the committed evidence review, human checkpoint acceptance,
and archive are four separate facts.  Execution success lives exclusively in
the immutable lifecycle/checkpoint graph.  The committed review is recorded by
one immutable, canonically fingerprinted, write-once review-binding record
that states which exact reviewed code HEAD and which exact review verdict
adjudicated which exact persisted execution evidence.  Human acceptance is a
second write-once record that binds the review-binding fingerprint and an
owner statement in one exact canonical grammar.  Archive remains a third,
unimplemented decision that neither record grants.

Neither record is an execution-state transition: no delegated reducer event
exists for them, no delegated-state CAS replacement is performed, and the
generic final-review ``HumanDisposition`` (legal only from ``AWAITING_HUMAN``
with the ``final_review`` boundary) is deliberately not reused.  The delegated
execution phase remains exactly ``CHECKPOINT_CAPTURED``.

The prior review is immutable evidence, never caller prose: the exact review
verdict and reviewed code HEAD for a registered run are pinned by a committed
review specification inside this module and compared by byte equality at
review-binding creation, review-binding loading, acceptance creation, and
acceptance loading.  Substring, prefix, suffix, case-folded, trimmed, or
normalized matching is never used.  The owner statement follows one exact
ASCII one-line grammar parsed by a dedicated parser; presence of an expected
value somewhere in free text is never sufficient.

The execution source HEAD (from the persisted owner authorization payload) is
semantically distinct from the historical workspace final HEAD (the run's
committed output), from the evidence-review code HEAD (the committed code the
review passed under), and from the acceptance-protocol code HEAD (the
committed code observed at acceptance-write time).  Each role is bound to its
own authoritative source; two roles carrying the same object ID is not
inherently invalid, but any value contradicting its authoritative source is
fail-closed.

Recording or loading either record grants no native invocation, retry,
repair, continuation, provider, checkpoint-rerun, or archive authority and
asserts no production suitability.  Absence of both records never invalidates
the historical execution success; an invalid record never rewrites execution
history, but blocks any claim that the checkpoint is reviewed or
human-accepted.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable, Mapping

from admissible.delegated_gate.canonical import (
    canonical_bytes,
    fingerprint,
    require_exact_keys,
    require_identifier,
    require_nonempty_text,
    require_sha256,
    require_strict_int,
    require_string_list,
)
from admissible.delegated_gate.native_canary import (
    AUTHORIZATION_SCHEMA_VERSION,
    CANARY_CLASSIFICATION,
    CANARY_GATE_ID,
    NativeCanaryAuthorizationPayload,
    NativeCanaryStatus,
    reconstruct_completed_canary_success,
    _git_source_preflight,
)
from admissible.delegated_gate.native_executor import (
    AtomicNativeExecutionStore,
    NativeEvidenceInvalid,
    NativeEvidenceNotFound,
    NativeExecutionStoreError,
    _publish_native_bytes,
    _safe_directory,
    _utc_now,
    _validate_timestamp,
)
from admissible.delegated_gate.state import Phase
from admissible.delegated_gate.store import AtomicDelegatedSessionStore, DelegatedGateStoreError


NATIVE_CHECKPOINT_ACCEPTANCE_SCHEMA_VERSION = "admissible_native_checkpoint_acceptance_v1"
NATIVE_CHECKPOINT_REVIEW_BINDING_SCHEMA_VERSION = "admissible_native_checkpoint_review_binding_v1"
NATIVE_COMMITTED_REVIEW_SPECIFICATION_SCHEMA_VERSION = "admissible_native_committed_review_specification_v1"
ACCEPTANCE_RECORD_KIND = "checkpoint-acceptance"
REVIEW_BINDING_RECORD_KIND = "checkpoint-review-binding"
ACCEPTANCE_DECISION = "ACCEPTED"
ACCEPTANCE_PERSISTED_PHASE = "CHECKPOINT_CAPTURED"
RUN_METADATA_FILE_NAME = "canary-preflight.json"
OWNER_STATEMENT_GRAMMAR_PREFIX = "NATIVE_CHECKPOINT_ACCEPTANCE_V1"
# Structural token bound only — never an acceptance mechanism.  Verdict
# exactness is always byte equality against the committed review specification
# or the persisted review-binding record.
_REVIEW_VERDICT_PATTERN = re.compile(r"\A[A-Z0-9][A-Z0-9_]{0,255}\Z")
# The one exact, ASCII-only, one-line owner-statement grammar.  Field order,
# separators, labels, lowercase hexadecimal, and the terminal decision are all
# fixed; anything else — prose, whitespace, reordering, duplication, extra or
# missing fields, case changes, lookalikes — fails to parse.
_OWNER_STATEMENT_PATTERN = re.compile(
    r"\ANATIVE_CHECKPOINT_ACCEPTANCE_V1"
    r";run_id=(?P<run_id>[A-Za-z0-9][A-Za-z0-9_.:-]{0,127})"
    r";execution_source_head=(?P<execution_source_head>[0-9a-f]{40})"
    r";workspace_final_head=(?P<workspace_final_head>[0-9a-f]{40})"
    r";evidence_review_code_head=(?P<evidence_review_code_head>[0-9a-f]{40})"
    r";acceptance_protocol_code_head=(?P<acceptance_protocol_code_head>[0-9a-f]{40})"
    r";review_binding_fingerprint=(?P<review_binding_fingerprint>[0-9a-f]{64})"
    r";decision=ACCEPTED\Z"
)
# Exact ordered non-authority semantics.  They are bound into every record and
# its fingerprint; any omission, addition, reordering, or rewording is invalid.
NATIVE_CHECKPOINT_ACCEPTANCE_NON_AUTHORITY: tuple[str, ...] = (
    "acceptance grants no native invocation authority",
    "acceptance grants no retry authority",
    "acceptance grants no repair authority",
    "acceptance grants no continuation authority",
    "acceptance grants no provider authority",
    "acceptance grants no checkpoint rerun authority",
    "acceptance grants no archive authority",
    "acceptance asserts no production suitability",
    "the delegated execution phase remains CHECKPOINT_CAPTURED",
)
NATIVE_CHECKPOINT_REVIEW_BINDING_NON_AUTHORITY: tuple[str, ...] = (
    "committed review binding grants no native invocation authority",
    "committed review binding grants no retry authority",
    "committed review binding grants no repair authority",
    "committed review binding grants no continuation authority",
    "committed review binding grants no provider authority",
    "committed review binding grants no checkpoint rerun authority",
    "committed review binding grants no human acceptance authority",
    "committed review binding grants no archive authority",
    "committed review binding asserts no production suitability",
    "the delegated execution phase remains CHECKPOINT_CAPTURED",
)
_ONE_SHOT_LIFECYCLE = (1, 1, 1, 1, 1)
# Every review-specification field that must be byte-identical between a
# committed specification and any review-binding record claiming its run.
_SPEC_BOUND_FIELDS: tuple[str, ...] = (
    "session_id",
    "gate_id",
    "execution_attempt_index",
    "execution_source_head",
    "workspace_final_git_head",
    "request_fingerprint",
    "result_fingerprint",
    "behavioral_evidence_fingerprint",
    "capture_attempt_fingerprint",
    "checkpoint_fingerprint",
    "delegated_state_revision",
    "delegated_state_fingerprint",
    "persisted_phase",
    "reviewed_code_head",
    "review_verdict",
)


class NativeCheckpointAcceptanceInvalid(NativeEvidenceInvalid):
    """A precondition, binding, or persisted acceptance record is invalid."""


class NativeCheckpointAcceptanceConflict(NativeExecutionStoreError):
    """A differing acceptance already exists; the disposition is write-once."""


class NativeCheckpointReviewBindingInvalid(NativeEvidenceInvalid):
    """A precondition, binding, or persisted review binding is invalid."""


class NativeCheckpointReviewBindingConflict(NativeExecutionStoreError):
    """A differing review binding already exists; the record is write-once."""


class NativeCheckpointAcceptanceStatus(str, Enum):
    ACCEPTANCE_CREATED = "ACCEPTANCE_CREATED"
    ACCEPTANCE_IDEMPOTENT_EXISTING = "ACCEPTANCE_IDEMPOTENT_EXISTING"


class NativeCheckpointAcceptancePresence(str, Enum):
    ABSENT = "ABSENT"
    PRESENT_VALID = "PRESENT_VALID"
    PRESENT_INVALID = "PRESENT_INVALID"


class NativeCheckpointReviewBindingStatus(str, Enum):
    REVIEW_BINDING_CREATED = "REVIEW_BINDING_CREATED"
    REVIEW_BINDING_IDEMPOTENT_EXISTING = "REVIEW_BINDING_IDEMPOTENT_EXISTING"


class NativeCheckpointReviewBindingPresence(str, Enum):
    ABSENT = "ABSENT"
    PRESENT_VALID = "PRESENT_VALID"
    PRESENT_INVALID = "PRESENT_INVALID"


def _require_git_oid(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) not in {40, 64}
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{label} must be a lowercase Git object ID")
    return value


def _require_review_verdict(value: Any, label: str) -> str:
    require_nonempty_text(value, label, max_bytes=256)
    if not _REVIEW_VERDICT_PATTERN.fullmatch(value):
        raise ValueError(f"{label} is not a canonical uppercase verdict token")
    return value


@dataclass(frozen=True)
class NativeCommittedReviewSpecification:
    """One immutable statement of which exact committed-code review passed.

    It binds the run/session/gate/attempt identity, the reviewed code HEAD,
    the exact review verdict, and every persisted evidence identity the review
    adjudicated.  For a registered run the module-level committed constant is
    the only authority; a caller-selected variant is fail-closed.
    """

    schema_version: str
    run_id: str
    session_id: str
    gate_id: str
    execution_attempt_index: int
    execution_source_head: str
    workspace_final_git_head: str
    request_fingerprint: str
    result_fingerprint: str
    behavioral_evidence_fingerprint: str
    capture_attempt_fingerprint: str
    checkpoint_fingerprint: str
    delegated_state_revision: int
    delegated_state_fingerprint: str
    persisted_phase: str
    reviewed_code_head: str
    review_verdict: str
    specification_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        data.pop("specification_fingerprint")
        return data

    def validated(self) -> "NativeCommittedReviewSpecification":
        if self.schema_version != NATIVE_COMMITTED_REVIEW_SPECIFICATION_SCHEMA_VERSION:
            raise ValueError("unsupported committed review specification schema")
        require_identifier(self.run_id, "specification run_id")
        require_identifier(self.session_id, "specification session_id")
        require_identifier(self.gate_id, "specification gate_id")
        require_strict_int(self.execution_attempt_index, "specification attempt", minimum=0, maximum=0)
        for label, value in (
            ("execution_source_head", self.execution_source_head),
            ("workspace_final_git_head", self.workspace_final_git_head),
            ("reviewed_code_head", self.reviewed_code_head),
        ):
            _require_git_oid(value, f"specification {label}")
        for label, value in (
            ("request_fingerprint", self.request_fingerprint),
            ("result_fingerprint", self.result_fingerprint),
            ("behavioral_evidence_fingerprint", self.behavioral_evidence_fingerprint),
            ("capture_attempt_fingerprint", self.capture_attempt_fingerprint),
            ("checkpoint_fingerprint", self.checkpoint_fingerprint),
            ("delegated_state_fingerprint", self.delegated_state_fingerprint),
            ("specification_fingerprint", self.specification_fingerprint),
        ):
            require_sha256(value, f"specification {label}")
        require_strict_int(
            self.delegated_state_revision, "specification state revision", minimum=0, maximum=2**63 - 1
        )
        if self.persisted_phase != ACCEPTANCE_PERSISTED_PHASE:
            raise ValueError("specification persisted phase must be exactly CHECKPOINT_CAPTURED")
        _require_review_verdict(self.review_verdict, "specification review verdict")
        if fingerprint(self._body()) != self.specification_fingerprint:
            raise ValueError("committed review specification fingerprint mismatch")
        return self


def committed_review_specification(**values: Any) -> NativeCommittedReviewSpecification:
    """Build one canonically fingerprinted, validated review specification."""

    provisional = NativeCommittedReviewSpecification(
        schema_version=NATIVE_COMMITTED_REVIEW_SPECIFICATION_SCHEMA_VERSION,
        specification_fingerprint="0" * 64,
        **values,
    )
    return NativeCommittedReviewSpecification(
        **{**provisional.__dict__, "specification_fingerprint": fingerprint(provisional._body())}
    ).validated()


# The committed review specification for the real, immutable canary-004 run.
# Every value below is persisted execution truth independently re-derived from
# the run's canonical evidence; the reviewed code HEAD and exact verdict are
# the Act-2A.4F committed-evidence review.  For this protocol version this is
# the only review that can ground a canary-004 review binding.
CANARY_004_COMMITTED_REVIEW_SPECIFICATION = committed_review_specification(
    run_id="native-cursor-canary-004",
    session_id="native-cursor-canary-004",
    gate_id=CANARY_GATE_ID,
    execution_attempt_index=0,
    execution_source_head="c239f97c03cc5ddc0dbd3c80f201ec890760ef3d",
    workspace_final_git_head="c4863fc5ab2aed0878e80d82b58b1735feb4de7b",
    request_fingerprint="3d55c898c03de3bf6db167e99fa7af119f511bb60f9bcab8f9d1aaedc2ebdad5",
    result_fingerprint="753bbd25e70c71c3e6306a81465958e1f26a4bc5d810ad0bd84741e6227408a2",
    behavioral_evidence_fingerprint="827dfbe7880a419ad8f539a9ff695cb45d029c55551b9da70ac69147eca79e1c",
    capture_attempt_fingerprint="2d70557687ce085f4648cef84d87ef5ba42819da213339521c651f32560daee8",
    checkpoint_fingerprint="053c2f2ed291e7c3d595c8ea93d6253ff7fcf090f20f0347d2b596c8b717d603",
    delegated_state_revision=2,
    delegated_state_fingerprint="5423d02b12d905e58272e4a538eabad8db02454b20918d7775d7f46cc0791a23",
    persisted_phase="CHECKPOINT_CAPTURED",
    reviewed_code_head="48054798aa3be73194097ad96821702b31499a29",
    review_verdict="ACT_2A_4F_CANARY_004_COMMITTED_REVIEW_PASS_READY_FOR_OWNER_ACCEPTANCE",
)
COMMITTED_REVIEW_SPECIFICATIONS: Mapping[str, NativeCommittedReviewSpecification] = {
    CANARY_004_COMMITTED_REVIEW_SPECIFICATION.run_id: CANARY_004_COMMITTED_REVIEW_SPECIFICATION,
}


@dataclass(frozen=True)
class NativeCheckpointReviewBinding:
    """One immutable committed-review adjudication over persisted evidence."""

    schema_version: str
    review_binding_id: str
    reviewer_identity: str
    run_id: str
    session_id: str
    gate_id: str
    execution_attempt_index: int
    execution_source_head: str
    workspace_final_git_head: str
    request_fingerprint: str
    result_fingerprint: str
    behavioral_evidence_fingerprint: str
    capture_attempt_fingerprint: str
    checkpoint_fingerprint: str
    delegated_state_revision: int
    delegated_state_fingerprint: str
    persisted_phase: str
    reviewed_code_head: str
    review_verdict: str
    note: str
    non_authority_claims: tuple[str, ...]
    created_at: str
    review_binding_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        data["non_authority_claims"] = list(self.non_authority_claims)
        data.pop("review_binding_fingerprint")
        return data

    def validated(self) -> "NativeCheckpointReviewBinding":
        if self.schema_version != NATIVE_CHECKPOINT_REVIEW_BINDING_SCHEMA_VERSION:
            raise ValueError("unsupported native checkpoint review binding schema")
        require_identifier(self.reviewer_identity, "review binding reviewer_identity")
        require_identifier(self.run_id, "review binding run_id")
        require_identifier(self.session_id, "review binding session_id")
        require_identifier(self.gate_id, "review binding gate_id")
        require_strict_int(self.execution_attempt_index, "review binding attempt", minimum=0, maximum=0)
        expected_id = f"review:{self.session_id}:{self.gate_id}:{self.execution_attempt_index}"
        if self.review_binding_id != expected_id:
            raise ValueError("review binding ID differs from its deterministic derivation")
        for label, value in (
            ("execution_source_head", self.execution_source_head),
            ("workspace_final_git_head", self.workspace_final_git_head),
            ("reviewed_code_head", self.reviewed_code_head),
        ):
            _require_git_oid(value, f"review binding {label}")
        for label, value in (
            ("request_fingerprint", self.request_fingerprint),
            ("result_fingerprint", self.result_fingerprint),
            ("behavioral_evidence_fingerprint", self.behavioral_evidence_fingerprint),
            ("capture_attempt_fingerprint", self.capture_attempt_fingerprint),
            ("checkpoint_fingerprint", self.checkpoint_fingerprint),
            ("delegated_state_fingerprint", self.delegated_state_fingerprint),
            ("review_binding_fingerprint", self.review_binding_fingerprint),
        ):
            require_sha256(value, f"review binding {label}")
        require_strict_int(
            self.delegated_state_revision, "review binding state revision", minimum=0, maximum=2**63 - 1
        )
        if self.persisted_phase != ACCEPTANCE_PERSISTED_PHASE:
            raise ValueError("review binding persisted phase must be exactly CHECKPOINT_CAPTURED")
        _require_review_verdict(self.review_verdict, "review binding verdict")
        if not isinstance(self.note, str) or "\x00" in self.note or len(self.note.encode("utf-8")) > 1024:
            raise ValueError("review binding note is invalid")
        if tuple(self.non_authority_claims) != NATIVE_CHECKPOINT_REVIEW_BINDING_NON_AUTHORITY:
            raise ValueError("review binding non-authority claims differ from the exact committed set")
        _validate_timestamp(self.created_at, "review binding created_at")
        if fingerprint(self._body()) != self.review_binding_fingerprint:
            raise ValueError("native checkpoint review binding fingerprint mismatch")
        committed = COMMITTED_REVIEW_SPECIFICATIONS.get(self.run_id)
        if committed is not None:
            for name in _SPEC_BOUND_FIELDS:
                if getattr(self, name) != getattr(committed, name):
                    raise ValueError(
                        f"review binding {name} contradicts the committed review specification"
                    )
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["review_binding_fingerprint"] = self.review_binding_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeCheckpointReviewBinding":
        require_exact_keys(data, set(cls.__dataclass_fields__), "native checkpoint review binding")
        values = dict(data)
        values["non_authority_claims"] = require_string_list(
            data["non_authority_claims"], "review binding non-authority claims"
        )
        return cls(**values).validated()


@dataclass(frozen=True)
class NativeCheckpointReviewBindingOutcome:
    status: NativeCheckpointReviewBindingStatus
    review_binding: NativeCheckpointReviewBinding


@dataclass(frozen=True)
class NativeCheckpointAcceptance:
    """One immutable, evidence-bound owner acceptance of a captured checkpoint."""

    schema_version: str
    acceptance_id: str
    actor_identity: str
    decision: str
    run_id: str
    session_id: str
    gate_id: str
    execution_attempt_index: int
    execution_source_head: str
    workspace_final_git_head: str
    request_fingerprint: str
    result_fingerprint: str
    behavioral_evidence_fingerprint: str
    capture_attempt_fingerprint: str
    checkpoint_fingerprint: str
    delegated_state_revision: int
    delegated_state_fingerprint: str
    persisted_phase: str
    evidence_review_code_head: str
    evidence_review_verdict: str
    review_binding_fingerprint: str
    acceptance_protocol_code_head: str
    owner_statement_sha256: str
    note: str
    non_authority_claims: tuple[str, ...]
    created_at: str
    acceptance_fingerprint: str

    def _body(self) -> dict[str, Any]:
        data = dict(self.__dict__)
        data["non_authority_claims"] = list(self.non_authority_claims)
        data.pop("acceptance_fingerprint")
        return data

    def validated(self) -> "NativeCheckpointAcceptance":
        if self.schema_version != NATIVE_CHECKPOINT_ACCEPTANCE_SCHEMA_VERSION:
            raise ValueError("unsupported native checkpoint acceptance schema")
        require_identifier(self.acceptance_id, "acceptance_id")
        require_identifier(self.actor_identity, "acceptance actor_identity")
        if self.decision != ACCEPTANCE_DECISION:
            raise ValueError("native checkpoint acceptance defines exactly the ACCEPTED decision")
        require_identifier(self.run_id, "acceptance run_id")
        require_identifier(self.session_id, "acceptance session_id")
        require_identifier(self.gate_id, "acceptance gate_id")
        require_strict_int(self.execution_attempt_index, "acceptance attempt", minimum=0, maximum=0)
        # Each HEAD role is bound to its own authoritative source at creation
        # and loading; numerical equality between two roles is not itself
        # invalid, but any value contradicting its source is fail-closed.
        for label, value in (
            ("execution_source_head", self.execution_source_head),
            ("workspace_final_git_head", self.workspace_final_git_head),
            ("evidence_review_code_head", self.evidence_review_code_head),
            ("acceptance_protocol_code_head", self.acceptance_protocol_code_head),
        ):
            _require_git_oid(value, f"acceptance {label}")
        for label, value in (
            ("request_fingerprint", self.request_fingerprint),
            ("result_fingerprint", self.result_fingerprint),
            ("behavioral_evidence_fingerprint", self.behavioral_evidence_fingerprint),
            ("capture_attempt_fingerprint", self.capture_attempt_fingerprint),
            ("checkpoint_fingerprint", self.checkpoint_fingerprint),
            ("delegated_state_fingerprint", self.delegated_state_fingerprint),
            ("review_binding_fingerprint", self.review_binding_fingerprint),
            ("owner_statement_sha256", self.owner_statement_sha256),
            ("acceptance_fingerprint", self.acceptance_fingerprint),
        ):
            require_sha256(value, f"acceptance {label}")
        require_strict_int(self.delegated_state_revision, "acceptance state revision", minimum=0, maximum=2**63 - 1)
        if self.persisted_phase != ACCEPTANCE_PERSISTED_PHASE:
            raise ValueError("acceptance persisted phase must be exactly CHECKPOINT_CAPTURED")
        _require_review_verdict(self.evidence_review_verdict, "acceptance review verdict")
        if not isinstance(self.note, str) or "\x00" in self.note or len(self.note.encode("utf-8")) > 1024:
            raise ValueError("acceptance note is invalid")
        if tuple(self.non_authority_claims) != NATIVE_CHECKPOINT_ACCEPTANCE_NON_AUTHORITY:
            raise ValueError("acceptance non-authority claims differ from the exact committed set")
        _validate_timestamp(self.created_at, "acceptance created_at")
        if fingerprint(self._body()) != self.acceptance_fingerprint:
            raise ValueError("native checkpoint acceptance fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["acceptance_fingerprint"] = self.acceptance_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeCheckpointAcceptance":
        require_exact_keys(data, set(cls.__dataclass_fields__), "native checkpoint acceptance")
        values = dict(data)
        values["non_authority_claims"] = require_string_list(
            data["non_authority_claims"], "acceptance non-authority claims"
        )
        return cls(**values).validated()


@dataclass(frozen=True)
class NativeCheckpointAcceptanceOutcome:
    status: NativeCheckpointAcceptanceStatus
    acceptance: NativeCheckpointAcceptance


@dataclass(frozen=True)
class NativeRunAuthorizationBinding:
    """Inert structural facts from the run's persisted authorization payload.

    No path inside the payload is opened and no source, backend, or wrapper
    authority is re-derived: this is read-only historical run identity.
    """

    run_id: str
    session_id: str
    source_head: str
    mission_fingerprint: str
    gate_plan_fingerprint: str
    gate_contract_fingerprint: str
    run_root: str
    evidence_root: str
    native_sidecar_root: str
    payload_fingerprint: str


def load_run_authorization_binding(*, evidence_directory: str | Path) -> NativeRunAuthorizationBinding:
    """Structurally parse the run's persisted, fingerprinted authorization."""

    evidence, _ = _safe_directory(evidence_directory, "acceptance evidence directory")
    path = evidence / RUN_METADATA_FILE_NAME
    if not path.is_file():
        raise NativeEvidenceNotFound("canary run authorization metadata not found")
    raw = path.read_bytes()
    try:
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, Mapping) or raw != canonical_bytes(parsed) + b"\n":
            raise ValueError("run metadata bytes are not canonical")
        if parsed.get("classification") != CANARY_CLASSIFICATION:
            raise ValueError("run metadata classification differs from the committed canary")
        payload = parsed.get("authorization_payload")
        if not isinstance(payload, Mapping):
            raise ValueError("run metadata authorization payload is not an object")
        require_exact_keys(
            payload,
            set(NativeCanaryAuthorizationPayload.__dataclass_fields__),
            "native canary authorization payload",
        )
        if payload.get("schema_version") != AUTHORIZATION_SCHEMA_VERSION:
            raise ValueError("unsupported authorization payload schema for acceptance")
        body = dict(payload)
        claimed = body.pop("payload_fingerprint", None)
        require_sha256(claimed, "authorization payload fingerprint")
        if fingerprint(body) != claimed:
            raise ValueError("authorization payload fingerprint mismatch")
        require_identifier(payload["run_id"], "authorization run ID")
        require_identifier(payload["session_id"], "authorization session ID")
        _require_git_oid(payload["source_head"], "authorization source HEAD")
        for key in ("mission_fingerprint", "gate_plan_fingerprint", "gate_contract_fingerprint"):
            require_sha256(payload[key], f"authorization {key}")
        for key in ("run_root", "evidence_root", "native_sidecar_root"):
            require_nonempty_text(payload[key], f"authorization {key}", max_bytes=4096)
        if Path(payload["run_root"]).name != payload["run_id"]:
            raise ValueError("authorization run root basename differs from the run ID")
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NativeCheckpointAcceptanceInvalid(f"canary run authorization metadata is invalid: {exc}") from exc
    return NativeRunAuthorizationBinding(
        run_id=payload["run_id"],
        session_id=payload["session_id"],
        source_head=payload["source_head"],
        mission_fingerprint=payload["mission_fingerprint"],
        gate_plan_fingerprint=payload["gate_plan_fingerprint"],
        gate_contract_fingerprint=payload["gate_contract_fingerprint"],
        run_root=payload["run_root"],
        evidence_root=payload["evidence_root"],
        native_sidecar_root=payload["native_sidecar_root"],
        payload_fingerprint=claimed,
    )


def _structural_self_fingerprint(path: Path, key: str, label: str) -> str:
    """Validate one canonical persisted record's self-fingerprint as data only."""

    if not path.is_file():
        raise NativeEvidenceNotFound(f"native {label} not found")
    raw = path.read_bytes()
    try:
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, Mapping) or raw != canonical_bytes(parsed) + b"\n":
            raise ValueError("record bytes are not canonical")
        body = dict(parsed)
        claimed = body.pop(key, None)
        require_sha256(claimed, f"{label} {key}")
        if fingerprint(body) != claimed:
            raise ValueError(f"{label} {key} mismatch")
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NativeEvidenceInvalid(f"native {label} is invalid: {exc}") from exc
    return claimed


def _parse_owner_statement(statement: Any) -> Mapping[str, str]:
    """Parse the exact canonical one-line owner-statement grammar.

    The grammar admits exactly one byte representation per value tuple.  This
    parser is the only owner-statement recognition mechanism; no containment,
    prefix, suffix, case-folded, trimmed, or normalized matching exists.
    """

    if not isinstance(statement, str) or not statement:
        raise NativeCheckpointAcceptanceInvalid("owner statement must be non-empty text")
    if len(statement) > 1024:
        raise NativeCheckpointAcceptanceInvalid("owner statement exceeds its byte bound")
    try:
        statement.encode("ascii")
    except UnicodeEncodeError as exc:
        raise NativeCheckpointAcceptanceInvalid("owner statement must be ASCII only") from exc
    match = _OWNER_STATEMENT_PATTERN.fullmatch(statement)
    if match is None:
        raise NativeCheckpointAcceptanceInvalid(
            "owner statement does not follow the exact canonical acceptance grammar"
        )
    return match.groupdict()


def _owner_statement_sha256(statement: Any, *, required_fields: Mapping[str, str]) -> str:
    """Hash the exact fresh owner statement; the text itself is never persisted.

    Every parsed role value must equal its authoritative value exactly.  The
    hash is SHA-256 over the raw ASCII bytes of the exact statement, computed
    only after grammar validation, with no trimming or normalization.
    """

    parsed = _parse_owner_statement(statement)
    for label, value in required_fields.items():
        if parsed[label] != value:
            raise NativeCheckpointAcceptanceInvalid(
                f"owner statement {label} differs from its authoritative value"
            )
    return hashlib.sha256(statement.encode("ascii")).hexdigest()


def _acceptance_path(execution_store: AtomicNativeExecutionStore, session_id: str, gate_id: str) -> Path:
    return execution_store._path(ACCEPTANCE_RECORD_KIND, session_id, gate_id, 0)


def _review_binding_path(execution_store: AtomicNativeExecutionStore, session_id: str, gate_id: str) -> Path:
    return execution_store._path(REVIEW_BINDING_RECORD_KIND, session_id, gate_id, 0)


def has_native_checkpoint_acceptance(
    *, execution_store: AtomicNativeExecutionStore, session_id: str, gate_id: str
) -> bool:
    return _acceptance_path(execution_store, session_id, gate_id).is_file()


def has_native_checkpoint_review_binding(
    *, execution_store: AtomicNativeExecutionStore, session_id: str, gate_id: str
) -> bool:
    return _review_binding_path(execution_store, session_id, gate_id).is_file()


def _load_acceptance_record(
    execution_store: AtomicNativeExecutionStore, session_id: str, gate_id: str
) -> NativeCheckpointAcceptance:
    """Structural load: canonical bytes, exact keys, fingerprint, identity."""

    return execution_store._load(
        ACCEPTANCE_RECORD_KIND, session_id, gate_id, 0, NativeCheckpointAcceptance.from_dict
    )


def _load_review_binding_record(
    execution_store: AtomicNativeExecutionStore, session_id: str, gate_id: str
) -> NativeCheckpointReviewBinding:
    return execution_store._load(
        REVIEW_BINDING_RECORD_KIND, session_id, gate_id, 0, NativeCheckpointReviewBinding.from_dict
    )


def _equivalence_body(record: NativeCheckpointAcceptance) -> dict[str, Any]:
    data = record.to_dict()
    data.pop("created_at")
    data.pop("acceptance_fingerprint")
    return data


def _review_equivalence_body(record: NativeCheckpointReviewBinding) -> dict[str, Any]:
    data = record.to_dict()
    data.pop("created_at")
    data.pop("review_binding_fingerprint")
    return data


def _require_persisted_execution_bindings(
    record: Any,
    *,
    session_store: AtomicDelegatedSessionStore,
    execution_store: AtomicNativeExecutionStore,
    evidence_directory: str | Path,
    session_id: str,
    gate_id: str,
    invalid: type[NativeEvidenceInvalid],
    label: str,
) -> None:
    """Compare one record's execution bindings to persisted truth, read-only."""

    state = session_store.load(session_id)
    if state.phase is not Phase.CHECKPOINT_CAPTURED:
        raise invalid(f"{label} is bound to a state no longer at CHECKPOINT_CAPTURED")
    if state.current_gate.gate_id != record.gate_id:
        raise invalid(f"{label} gate differs from the persisted delegated state")
    if state.revision != record.delegated_state_revision or state.state_fingerprint != record.delegated_state_fingerprint:
        raise invalid(f"{label} state binding differs from the persisted delegated state")
    if not state.checkpoint_history or state.checkpoint_history[-1].checkpoint_fingerprint != record.checkpoint_fingerprint:
        raise invalid(f"{label} checkpoint binding differs from the persisted checkpoint")
    if state.checkpoint_history[-1].git_head != record.workspace_final_git_head:
        raise invalid(f"{label} workspace HEAD differs from the persisted checkpoint")
    if execution_store.has_terminal(session_id, gate_id, 0):
        raise invalid(f"{label} coexists with a contradictory terminal record")
    binding = execution_store.load_request_structural(session_id, gate_id, 0)
    if binding.request_fingerprint != record.request_fingerprint:
        raise invalid(f"{label} request binding differs from the durable request")
    result_fingerprint = _structural_self_fingerprint(
        execution_store._path("result", session_id, gate_id, 0), "result_fingerprint", "result"
    )
    if result_fingerprint != record.result_fingerprint:
        raise invalid(f"{label} result binding differs from the durable result")
    behavioral_fingerprint = _structural_self_fingerprint(
        execution_store._path("behavioral", session_id, gate_id, 0), "evidence_fingerprint", "behavioral evidence"
    )
    if behavioral_fingerprint != record.behavioral_evidence_fingerprint:
        raise invalid(f"{label} behavioral binding differs from the durable evidence")
    attempt = execution_store.load_capture_attempt(session_id, gate_id, 0)
    if attempt.attempt_fingerprint != record.capture_attempt_fingerprint:
        raise invalid(f"{label} capture binding differs from the durable capture attempt")
    authorization = load_run_authorization_binding(evidence_directory=evidence_directory)
    if authorization.session_id != record.session_id or authorization.run_id != record.run_id:
        raise invalid(f"{label} run identity differs from the persisted authorization")
    if authorization.source_head != record.execution_source_head:
        raise invalid(f"{label} execution source HEAD differs from the persisted authorization")


def load_native_checkpoint_review_binding(
    *,
    session_store: AtomicDelegatedSessionStore,
    execution_store: AtomicNativeExecutionStore,
    evidence_directory: str | Path,
    session_id: str,
    gate_id: str,
) -> NativeCheckpointReviewBinding:
    """Load one review binding and validate every persisted-evidence binding.

    For a registered run, schema validation already requires byte equality
    with the committed review specification; this loader additionally compares
    every execution binding to persisted truth as read-only data.
    """

    record = _load_review_binding_record(execution_store, session_id, gate_id)
    _require_persisted_execution_bindings(
        record,
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence_directory,
        session_id=session_id,
        gate_id=gate_id,
        invalid=NativeCheckpointReviewBindingInvalid,
        label="review binding",
    )
    return record


def classify_native_checkpoint_review_binding(
    *,
    session_store: AtomicDelegatedSessionStore,
    execution_store: AtomicNativeExecutionStore,
    evidence_directory: str | Path,
    session_id: str,
    gate_id: str,
) -> NativeCheckpointReviewBindingPresence:
    """Read-only committed-review surface next to evidence-only reconstruction."""

    if not has_native_checkpoint_review_binding(
        execution_store=execution_store, session_id=session_id, gate_id=gate_id
    ):
        return NativeCheckpointReviewBindingPresence.ABSENT
    try:
        load_native_checkpoint_review_binding(
            session_store=session_store,
            execution_store=execution_store,
            evidence_directory=evidence_directory,
            session_id=session_id,
            gate_id=gate_id,
        )
    except (NativeExecutionStoreError, DelegatedGateStoreError, OSError, ValueError):
        return NativeCheckpointReviewBindingPresence.PRESENT_INVALID
    return NativeCheckpointReviewBindingPresence.PRESENT_VALID


def load_native_checkpoint_acceptance(
    *,
    session_store: AtomicDelegatedSessionStore,
    execution_store: AtomicNativeExecutionStore,
    evidence_directory: str | Path,
    session_id: str,
    gate_id: str,
) -> NativeCheckpointAcceptance:
    """Load one acceptance and validate every persisted-evidence binding.

    This is read-only data validation: it opens no payload path, consults no
    backend, and grants no execution capability.  The persisted review binding
    is loaded and compared by exact equality; an acceptance without a valid
    matching review binding is invalid.
    """

    record = _load_acceptance_record(execution_store, session_id, gate_id)
    _require_persisted_execution_bindings(
        record,
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence_directory,
        session_id=session_id,
        gate_id=gate_id,
        invalid=NativeCheckpointAcceptanceInvalid,
        label="acceptance",
    )
    review_binding = load_native_checkpoint_review_binding(
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence_directory,
        session_id=session_id,
        gate_id=gate_id,
    )
    if record.review_binding_fingerprint != review_binding.review_binding_fingerprint:
        raise NativeCheckpointAcceptanceInvalid(
            "acceptance review-binding fingerprint differs from the persisted review binding"
        )
    if record.evidence_review_code_head != review_binding.reviewed_code_head:
        raise NativeCheckpointAcceptanceInvalid(
            "acceptance evidence-review code HEAD differs from the persisted review binding"
        )
    if record.evidence_review_verdict != review_binding.review_verdict:
        raise NativeCheckpointAcceptanceInvalid(
            "acceptance review verdict differs from the persisted review binding"
        )
    return record


def classify_native_checkpoint_acceptance(
    *,
    session_store: AtomicDelegatedSessionStore,
    execution_store: AtomicNativeExecutionStore,
    evidence_directory: str | Path,
    session_id: str,
    gate_id: str,
) -> NativeCheckpointAcceptancePresence:
    """Read-only adjudication surface next to evidence-only reconstruction.

    Execution truth stays in the immutable lifecycle/checkpoint graph; this
    classification never rewrites it and is never required to reconstruct it.
    """

    if not has_native_checkpoint_acceptance(
        execution_store=execution_store, session_id=session_id, gate_id=gate_id
    ):
        return NativeCheckpointAcceptancePresence.ABSENT
    try:
        load_native_checkpoint_acceptance(
            session_store=session_store,
            execution_store=execution_store,
            evidence_directory=evidence_directory,
            session_id=session_id,
            gate_id=gate_id,
        )
    except (NativeExecutionStoreError, DelegatedGateStoreError, OSError, ValueError):
        return NativeCheckpointAcceptancePresence.PRESENT_INVALID
    return NativeCheckpointAcceptancePresence.PRESENT_VALID


def _require_completed_run_context(
    *,
    session_store: AtomicDelegatedSessionStore,
    execution_store: AtomicNativeExecutionStore,
    evidence_directory: str | Path,
    session_id: str,
    gate_id: str,
    invalid: type[NativeEvidenceInvalid],
) -> tuple[Any, Any, Any, Any, NativeRunAuthorizationBinding]:
    """Evidence-only preconditions shared by both write-once record creators."""

    state = session_store.load(session_id)
    if state.phase is not Phase.CHECKPOINT_CAPTURED:
        raise invalid(f"recording requires persisted phase CHECKPOINT_CAPTURED, found {state.phase.value}")
    gate = state.current_gate
    if gate_id != gate.gate_id:
        raise invalid("recording gate differs from the persisted delegated state")
    binding = execution_store.load_request_structural(session_id, gate.gate_id, 0)
    outcome = reconstruct_completed_canary_success(
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence_directory,
        session_id=session_id,
    )
    if outcome.status is not NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS:
        raise invalid(f"recording requires the reconstructed completed success, found {outcome.status.value}")
    if (
        outcome.native_attempts_reserved,
        outcome.native_processes_started,
        outcome.native_processes_completed,
        outcome.process_observations_published,
        outcome.accepted_native_results_published,
    ) != _ONE_SHOT_LIFECYCLE:
        raise invalid("recording requires truthful one-shot lifecycle counts")
    authorization = load_run_authorization_binding(evidence_directory=evidence_directory)
    evidence_root, _ = _safe_directory(evidence_directory, "acceptance evidence directory")
    if (
        authorization.session_id != session_id
        or Path(authorization.evidence_root) != evidence_root
        or Path(authorization.native_sidecar_root) != execution_store.directory
        or authorization.mission_fingerprint != state.mission.mission_fingerprint
        or authorization.gate_plan_fingerprint != state.gate_plan.plan_fingerprint
        or authorization.gate_contract_fingerprint != gate.contract_fingerprint
    ):
        raise invalid("persisted authorization does not bind this exact session, plan, gate, and evidence root")
    return state, gate, binding, outcome, authorization


def record_native_checkpoint_review_binding(
    *,
    session_store: AtomicDelegatedSessionStore,
    execution_store: AtomicNativeExecutionStore,
    evidence_directory: str | Path,
    protocol_repository: str | Path,
    protocol_code_head: str,
    session_id: str,
    gate_id: str,
    run_id: str,
    reviewer_identity: str,
    reviewed_code_head: str,
    review_verdict: str,
    specification: NativeCommittedReviewSpecification,
    note: str = "",
    clock: Callable[[], str] = _utc_now,
) -> NativeCheckpointReviewBindingOutcome:
    """Atomically create exactly one committed-review binding record.

    Every execution value is derived from persisted truth; the reviewed code
    HEAD and exact verdict are compared by byte equality against the validated
    review specification, and for a registered run the module-committed
    specification is the only acceptable one.  The record may only be created
    from a clean committed protocol checkout.  No live backend attestation,
    wrapper or command discovery, Cursor installation, owner execution
    authorization, runner, provider, behavioral verifier, npm, or checkpoint
    executor is reachable from this call, and the delegated state is never
    transitioned.
    """

    state, gate, binding, outcome, authorization = _require_completed_run_context(
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence_directory,
        session_id=session_id,
        gate_id=gate_id,
        invalid=NativeCheckpointReviewBindingInvalid,
    )
    if run_id != authorization.run_id:
        raise NativeCheckpointReviewBindingInvalid("review binding run ID differs from the persisted authorization")
    try:
        spec = specification.validated()
    except (ValueError, TypeError, AttributeError) as exc:
        raise NativeCheckpointReviewBindingInvalid(f"review specification is invalid: {exc}") from exc
    committed = COMMITTED_REVIEW_SPECIFICATIONS.get(authorization.run_id)
    if committed is not None and spec != committed:
        raise NativeCheckpointReviewBindingInvalid(
            "supplied specification differs from the committed review specification for this run"
        )
    checkpoint = state.checkpoint_history[-1]
    for label, persisted, specified in (
        ("run ID", authorization.run_id, spec.run_id),
        ("session ID", session_id, spec.session_id),
        ("gate ID", gate.gate_id, spec.gate_id),
        ("execution source HEAD", authorization.source_head, spec.execution_source_head),
        ("workspace final HEAD", outcome.workspace_final_git_head, spec.workspace_final_git_head),
        ("request fingerprint", binding.request_fingerprint, spec.request_fingerprint),
        ("result fingerprint", outcome.result_fingerprint, spec.result_fingerprint),
        ("behavioral evidence fingerprint", outcome.behavioral_evidence_fingerprint, spec.behavioral_evidence_fingerprint),
        ("capture attempt fingerprint", outcome.capture_attempt_fingerprint, spec.capture_attempt_fingerprint),
        ("checkpoint fingerprint", checkpoint.checkpoint_fingerprint, spec.checkpoint_fingerprint),
        ("delegated state revision", state.revision, spec.delegated_state_revision),
        ("delegated state fingerprint", state.state_fingerprint, spec.delegated_state_fingerprint),
    ):
        if persisted != specified:
            raise NativeCheckpointReviewBindingInvalid(
                f"persisted {label} differs from the committed review specification"
            )
    if outcome.request_fingerprint != spec.request_fingerprint or outcome.checkpoint_fingerprint != spec.checkpoint_fingerprint:
        raise NativeCheckpointReviewBindingInvalid("reconstructed evidence contradicts the durable request or checkpoint")
    # The caller's claimed review facts must equal the specification exactly.
    if reviewed_code_head != spec.reviewed_code_head:
        raise NativeCheckpointReviewBindingInvalid(
            "claimed reviewed code HEAD differs from the committed review specification"
        )
    if review_verdict != spec.review_verdict:
        raise NativeCheckpointReviewBindingInvalid(
            "claimed review verdict differs from the committed review specification"
        )
    protocol_root, _ = _safe_directory(protocol_repository, "acceptance protocol repository")
    ready, detail = _git_source_preflight(protocol_root, protocol_code_head)
    if not ready:
        raise NativeCheckpointReviewBindingInvalid(
            f"acceptance-protocol repository is not at the exact clean committed HEAD: {detail}"
        )
    provisional = NativeCheckpointReviewBinding(
        schema_version=NATIVE_CHECKPOINT_REVIEW_BINDING_SCHEMA_VERSION,
        review_binding_id=f"review:{session_id}:{gate.gate_id}:0",
        reviewer_identity=reviewer_identity,
        run_id=run_id,
        session_id=session_id,
        gate_id=gate.gate_id,
        execution_attempt_index=0,
        execution_source_head=spec.execution_source_head,
        workspace_final_git_head=spec.workspace_final_git_head,
        request_fingerprint=spec.request_fingerprint,
        result_fingerprint=spec.result_fingerprint,
        behavioral_evidence_fingerprint=spec.behavioral_evidence_fingerprint,
        capture_attempt_fingerprint=spec.capture_attempt_fingerprint,
        checkpoint_fingerprint=spec.checkpoint_fingerprint,
        delegated_state_revision=spec.delegated_state_revision,
        delegated_state_fingerprint=spec.delegated_state_fingerprint,
        persisted_phase=ACCEPTANCE_PERSISTED_PHASE,
        reviewed_code_head=spec.reviewed_code_head,
        review_verdict=spec.review_verdict,
        note=note,
        non_authority_claims=NATIVE_CHECKPOINT_REVIEW_BINDING_NON_AUTHORITY,
        created_at=clock(),
        review_binding_fingerprint="0" * 64,
    )
    try:
        record = NativeCheckpointReviewBinding(
            **{**provisional.__dict__, "review_binding_fingerprint": fingerprint(provisional._body())}
        ).validated()
    except ValueError as exc:
        raise NativeCheckpointReviewBindingInvalid(str(exc)) from exc
    path = _review_binding_path(execution_store, session_id, gate.gate_id)
    with execution_store._lock(session_id, gate.gate_id, 0):
        if path.is_file():
            existing = _load_review_binding_record(execution_store, session_id, gate.gate_id)
            if _review_equivalence_body(existing) == _review_equivalence_body(record):
                return NativeCheckpointReviewBindingOutcome(
                    NativeCheckpointReviewBindingStatus.REVIEW_BINDING_IDEMPOTENT_EXISTING, existing
                )
            raise NativeCheckpointReviewBindingConflict(
                "a differing native checkpoint review binding already exists; the record is write-once"
            )
        execution_store._assert_root_identity()
        try:
            _publish_native_bytes(
                execution_store.durability_adapter,
                path,
                canonical_bytes(record.to_dict()) + b"\n",
                operation="native checkpoint review binding",
            )
        except FileExistsError:
            existing = _load_review_binding_record(execution_store, session_id, gate.gate_id)
            if _review_equivalence_body(existing) == _review_equivalence_body(record):
                return NativeCheckpointReviewBindingOutcome(
                    NativeCheckpointReviewBindingStatus.REVIEW_BINDING_IDEMPOTENT_EXISTING, existing
                )
            raise NativeCheckpointReviewBindingConflict(
                "a differing native checkpoint review binding already exists; the record is write-once"
            ) from None
    reloaded = load_native_checkpoint_review_binding(
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence_directory,
        session_id=session_id,
        gate_id=gate.gate_id,
    )
    if reloaded != record:
        raise NativeCheckpointReviewBindingInvalid("reloaded review binding differs from the intended record")
    return NativeCheckpointReviewBindingOutcome(
        NativeCheckpointReviewBindingStatus.REVIEW_BINDING_CREATED, reloaded
    )


def record_native_checkpoint_acceptance(
    *,
    session_store: AtomicDelegatedSessionStore,
    execution_store: AtomicNativeExecutionStore,
    evidence_directory: str | Path,
    protocol_repository: str | Path,
    session_id: str,
    gate_id: str,
    run_id: str,
    acceptance_id: str,
    actor_identity: str,
    execution_source_head: str,
    workspace_final_git_head: str,
    request_fingerprint: str,
    result_fingerprint: str,
    behavioral_evidence_fingerprint: str,
    capture_attempt_fingerprint: str,
    checkpoint_fingerprint: str,
    delegated_state_revision: int,
    delegated_state_fingerprint: str,
    evidence_review_code_head: str,
    evidence_review_verdict: str,
    review_binding_fingerprint: str,
    acceptance_protocol_code_head: str,
    owner_statement: str,
    note: str = "",
    clock: Callable[[], str] = _utc_now,
) -> NativeCheckpointAcceptanceOutcome:
    """Atomically create exactly one evidence-bound owner acceptance record.

    Preconditions are evidence-only: the immutable request is structurally
    loaded, the completed success is reconstructed exclusively from persisted
    records, every caller-supplied binding is compared to persisted truth, and
    the review facts are compared by exact equality against the persisted
    write-once review binding — an acceptance is impossible without one.  The
    owner statement must parse under the exact canonical grammar with every
    role equal to its authoritative value.  No live backend attestation,
    wrapper or command discovery, Cursor installation, owner execution
    authorization, runner, provider, behavioral verifier, npm, or checkpoint
    executor is reachable from this call, and the delegated state is never
    transitioned: the phase remains ``CHECKPOINT_CAPTURED``.
    """

    state, gate, binding, outcome, authorization = _require_completed_run_context(
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence_directory,
        session_id=session_id,
        gate_id=gate_id,
        invalid=NativeCheckpointAcceptanceInvalid,
    )
    if run_id != authorization.run_id:
        raise NativeCheckpointAcceptanceInvalid("acceptance run ID differs from the persisted authorization")
    if execution_source_head != authorization.source_head:
        raise NativeCheckpointAcceptanceInvalid(
            "acceptance execution source HEAD differs from the persisted authorization source HEAD"
        )
    checkpoint = state.checkpoint_history[-1]
    for label, supplied, persisted in (
        ("request fingerprint", request_fingerprint, binding.request_fingerprint),
        ("result fingerprint", result_fingerprint, outcome.result_fingerprint),
        ("behavioral evidence fingerprint", behavioral_evidence_fingerprint, outcome.behavioral_evidence_fingerprint),
        ("capture attempt fingerprint", capture_attempt_fingerprint, outcome.capture_attempt_fingerprint),
        ("checkpoint fingerprint", checkpoint_fingerprint, checkpoint.checkpoint_fingerprint),
        ("workspace final HEAD", workspace_final_git_head, outcome.workspace_final_git_head),
        ("delegated state fingerprint", delegated_state_fingerprint, state.state_fingerprint),
    ):
        if supplied != persisted:
            raise NativeCheckpointAcceptanceInvalid(f"acceptance {label} differs from persisted truth")
    if outcome.request_fingerprint != request_fingerprint or outcome.checkpoint_fingerprint != checkpoint_fingerprint:
        raise NativeCheckpointAcceptanceInvalid("reconstructed evidence contradicts the durable request or checkpoint")
    if delegated_state_revision != state.revision:
        raise NativeCheckpointAcceptanceInvalid("acceptance state revision differs from persisted truth")
    # The committed review is immutable evidence, never caller prose: without
    # a valid persisted review binding no acceptance can exist, and every
    # supplied review fact must equal the persisted record exactly.
    review_binding = load_native_checkpoint_review_binding(
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence_directory,
        session_id=session_id,
        gate_id=gate.gate_id,
    )
    for label, supplied, persisted in (
        ("review-binding fingerprint", review_binding_fingerprint, review_binding.review_binding_fingerprint),
        ("evidence-review code HEAD", evidence_review_code_head, review_binding.reviewed_code_head),
        ("review verdict", evidence_review_verdict, review_binding.review_verdict),
    ):
        if supplied != persisted:
            raise NativeCheckpointAcceptanceInvalid(
                f"acceptance {label} differs from the persisted review binding"
            )
    protocol_root, _ = _safe_directory(protocol_repository, "acceptance protocol repository")
    ready, detail = _git_source_preflight(protocol_root, acceptance_protocol_code_head)
    if not ready:
        raise NativeCheckpointAcceptanceInvalid(
            f"acceptance-protocol repository is not at the exact clean committed HEAD: {detail}"
        )
    statement_sha256 = _owner_statement_sha256(
        owner_statement,
        required_fields={
            "run_id": run_id,
            "execution_source_head": execution_source_head,
            "workspace_final_head": workspace_final_git_head,
            "evidence_review_code_head": evidence_review_code_head,
            "acceptance_protocol_code_head": acceptance_protocol_code_head,
            "review_binding_fingerprint": review_binding_fingerprint,
        },
    )
    provisional = NativeCheckpointAcceptance(
        schema_version=NATIVE_CHECKPOINT_ACCEPTANCE_SCHEMA_VERSION,
        acceptance_id=acceptance_id,
        actor_identity=actor_identity,
        decision=ACCEPTANCE_DECISION,
        run_id=run_id,
        session_id=session_id,
        gate_id=gate_id,
        execution_attempt_index=0,
        execution_source_head=execution_source_head,
        workspace_final_git_head=workspace_final_git_head,
        request_fingerprint=request_fingerprint,
        result_fingerprint=result_fingerprint,
        behavioral_evidence_fingerprint=behavioral_evidence_fingerprint,
        capture_attempt_fingerprint=capture_attempt_fingerprint,
        checkpoint_fingerprint=checkpoint_fingerprint,
        delegated_state_revision=delegated_state_revision,
        delegated_state_fingerprint=delegated_state_fingerprint,
        persisted_phase=ACCEPTANCE_PERSISTED_PHASE,
        evidence_review_code_head=evidence_review_code_head,
        evidence_review_verdict=evidence_review_verdict,
        review_binding_fingerprint=review_binding_fingerprint,
        acceptance_protocol_code_head=acceptance_protocol_code_head,
        owner_statement_sha256=statement_sha256,
        note=note,
        non_authority_claims=NATIVE_CHECKPOINT_ACCEPTANCE_NON_AUTHORITY,
        created_at=clock(),
        acceptance_fingerprint="0" * 64,
    )
    try:
        record = NativeCheckpointAcceptance(
            **{**provisional.__dict__, "acceptance_fingerprint": fingerprint(provisional._body())}
        ).validated()
    except ValueError as exc:
        raise NativeCheckpointAcceptanceInvalid(str(exc)) from exc
    path = _acceptance_path(execution_store, session_id, gate_id)
    with execution_store._lock(session_id, gate_id, 0):
        if path.is_file():
            existing = _load_acceptance_record(execution_store, session_id, gate_id)
            if _equivalence_body(existing) == _equivalence_body(record):
                return NativeCheckpointAcceptanceOutcome(
                    NativeCheckpointAcceptanceStatus.ACCEPTANCE_IDEMPOTENT_EXISTING, existing
                )
            raise NativeCheckpointAcceptanceConflict(
                "a differing native checkpoint acceptance already exists; the disposition is write-once"
            )
        execution_store._assert_root_identity()
        try:
            _publish_native_bytes(
                execution_store.durability_adapter,
                path,
                canonical_bytes(record.to_dict()) + b"\n",
                operation="native checkpoint acceptance",
            )
        except FileExistsError:
            existing = _load_acceptance_record(execution_store, session_id, gate_id)
            if _equivalence_body(existing) == _equivalence_body(record):
                return NativeCheckpointAcceptanceOutcome(
                    NativeCheckpointAcceptanceStatus.ACCEPTANCE_IDEMPOTENT_EXISTING, existing
                )
            raise NativeCheckpointAcceptanceConflict(
                "a differing native checkpoint acceptance already exists; the disposition is write-once"
            ) from None
    reloaded = load_native_checkpoint_acceptance(
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence_directory,
        session_id=session_id,
        gate_id=gate_id,
    )
    if reloaded != record:
        raise NativeCheckpointAcceptanceInvalid("reloaded acceptance differs from the intended record")
    return NativeCheckpointAcceptanceOutcome(NativeCheckpointAcceptanceStatus.ACCEPTANCE_CREATED, reloaded)


__all__ = [
    "ACCEPTANCE_DECISION",
    "ACCEPTANCE_PERSISTED_PHASE",
    "ACCEPTANCE_RECORD_KIND",
    "CANARY_004_COMMITTED_REVIEW_SPECIFICATION",
    "COMMITTED_REVIEW_SPECIFICATIONS",
    "NATIVE_CHECKPOINT_ACCEPTANCE_NON_AUTHORITY",
    "NATIVE_CHECKPOINT_ACCEPTANCE_SCHEMA_VERSION",
    "NATIVE_CHECKPOINT_REVIEW_BINDING_NON_AUTHORITY",
    "NATIVE_CHECKPOINT_REVIEW_BINDING_SCHEMA_VERSION",
    "NATIVE_COMMITTED_REVIEW_SPECIFICATION_SCHEMA_VERSION",
    "OWNER_STATEMENT_GRAMMAR_PREFIX",
    "REVIEW_BINDING_RECORD_KIND",
    "RUN_METADATA_FILE_NAME",
    "NativeCheckpointAcceptance",
    "NativeCheckpointAcceptanceConflict",
    "NativeCheckpointAcceptanceInvalid",
    "NativeCheckpointAcceptanceOutcome",
    "NativeCheckpointAcceptancePresence",
    "NativeCheckpointAcceptanceStatus",
    "NativeCheckpointReviewBinding",
    "NativeCheckpointReviewBindingConflict",
    "NativeCheckpointReviewBindingInvalid",
    "NativeCheckpointReviewBindingOutcome",
    "NativeCheckpointReviewBindingPresence",
    "NativeCheckpointReviewBindingStatus",
    "NativeCommittedReviewSpecification",
    "NativeRunAuthorizationBinding",
    "classify_native_checkpoint_acceptance",
    "classify_native_checkpoint_review_binding",
    "committed_review_specification",
    "has_native_checkpoint_acceptance",
    "has_native_checkpoint_review_binding",
    "load_native_checkpoint_acceptance",
    "load_native_checkpoint_review_binding",
    "load_run_authorization_binding",
    "record_native_checkpoint_acceptance",
    "record_native_checkpoint_review_binding",
]
