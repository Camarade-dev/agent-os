"""Admissible Supervised Run Loop v0 — additive loop data model + helpers.

Turns the Control Surface from a static session viewer into a supervised,
manual, turn-based cockpit: goal in -> next-agent-instruction packet out ->
human pastes Cursor/frontier-agent response back in -> Admissible extracts
action candidates with the existing offline builder/evaluator -> gated
actions collect human decisions and evidence -> a follow-up instruction
packet is generated. Nothing in this module runs a command, calls a model,
or executes a proposed action.

Hard constraints (same boundary as admissible.control_surface):

- Does not call Cursor, Claude Code, Codex, Gemini, OpenAI, or any network
  provider.
- Does not execute shell commands and implements no automatic executor.
- Does not import `agent_os`.
- Reuses `admissible.long_run_envelope_builder.build_from_raw_output` and
  `admissible.evaluator.rules_only.evaluate_envelope` unmodified to turn a
  pasted raw agent response into action candidates and decisions; never
  weakens or bypasses that evaluation.
- A re-evaluation triggered by newly supplied evidence never mutates the
  original decision dict; it produces a separate superseding decision.

See docs/admissible-control-surface.md and docs/admissible-autonomy-levels.md.
"""

from __future__ import annotations

import dataclasses
import copy
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from admissible.evaluator.rules_only import evaluate_envelope
from admissible.long_run_envelope_builder import (
    STRUCTURED_OPERATION_MARKER,
    build_from_raw_output,
)

RUN_LOOP_SCHEMA_VERSION = "admissible_run_loop_v0"

# Admission decisions that may call for human attention when no derived lifecycle
# resolution has closed the item yet.
_ATTENTION_DECISIONS = frozenset(
    {"REQUEST_MORE_EVIDENCE", "REQUIRE_HUMAN_APPROVAL", "REFUSE", "ALLOW_WITH_LIMITS"}
)

# Execution status that means a human-approved side effect is admitted but not run.
_EXECUTION_STATUS_ADMITTED_NOT_EXECUTED = "admitted_not_executed"

AGENT_RESPONSE_SOURCE_TRUST = "unverified_agent_output"
AGENT_RESPONSE_ACTOR = "external_frontier_agent"
EVIDENCE_ACTOR_HUMAN_OPERATOR = "human_operator"

# -- human decision / action lifecycle statuses (v0) -------------------------

LIFECYCLE_NEEDS_HUMAN_INPUT = "needs_human_input"
LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION = "evidence_supplied_pending_reevaluation"
LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_MANUAL_CONFIRMATION = (
    "evidence_supplied_pending_manual_confirmation"
)
# Derived statuses produced when evidence is supplied and re-evaluated
# (slice ADMISSIBLE_STATE_LIFECYCLE_002_EVIDENCE_ACCUMULATION_AND_REEVALUATION).
LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED = "evidence_supplied_still_blocked"
LIFECYCLE_EVIDENCE_SATISFIED_PENDING_HUMAN_DECISION = "evidence_satisfied_pending_human_decision"
# Slice ADMISSIBLE_EVIDENCE_007_STRUCTURED_EVIDENCE_PACKETS — finer-grained evidence attention.
LIFECYCLE_EVIDENCE_INSUFFICIENT_STILL_MISSING = "evidence_insufficient_still_missing"
LIFECYCLE_BLOCKED_BY_NON_EVIDENCE_GATE = "blocked_by_non_evidence_gate"
LIFECYCLE_APPROVAL_SUPPLIED_PENDING_REEVALUATION = "approval_supplied_pending_reevaluation"
LIFECYCLE_LIMITED_SCOPE_SELECTED = "limited_scope_selected"
LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION = "ready_for_next_agent_instruction"
LIFECYCLE_CLOSED = "closed"
# Derived terminal/intermediate statuses produced when a human decision is applied
# (slice ADMISSIBLE_STATE_LIFECYCLE_001_HUMAN_DECISION_APPLICATION).
LIFECYCLE_RESOLVED_GATE = "resolved_gate"
LIFECYCLE_REFUSED_CLOSED = "refused_closed"
LIFECYCLE_ADMITTED_NOT_EXECUTED = "admitted_not_executed"

LIFECYCLE_STATUSES = frozenset(
    {
        LIFECYCLE_NEEDS_HUMAN_INPUT,
        LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION,
        LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_MANUAL_CONFIRMATION,
        LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED,
        LIFECYCLE_EVIDENCE_SATISFIED_PENDING_HUMAN_DECISION,
        LIFECYCLE_EVIDENCE_INSUFFICIENT_STILL_MISSING,
        LIFECYCLE_BLOCKED_BY_NON_EVIDENCE_GATE,
        LIFECYCLE_APPROVAL_SUPPLIED_PENDING_REEVALUATION,
        LIFECYCLE_LIMITED_SCOPE_SELECTED,
        LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION,
        LIFECYCLE_CLOSED,
        LIFECYCLE_RESOLVED_GATE,
        LIFECYCLE_REFUSED_CLOSED,
        LIFECYCLE_ADMITTED_NOT_EXECUTED,
    }
)

# Lifecycle statuses that mean the item no longer needs a pending human decision.
LIFECYCLE_NO_LONGER_NEEDS_ATTENTION = frozenset(
    {
        LIFECYCLE_RESOLVED_GATE,
        LIFECYCLE_REFUSED_CLOSED,
        LIFECYCLE_CLOSED,
        LIFECYCLE_LIMITED_SCOPE_SELECTED,
        LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION,
        LIFECYCLE_ADMITTED_NOT_EXECUTED,
    }
)

_DEFAULT_LIFECYCLE_BY_DECISION: dict[str, str] = {
    "REFUSE": LIFECYCLE_CLOSED,
    "ALLOW": LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION,
    "ALLOW_WITH_LIMITS": LIFECYCLE_NEEDS_HUMAN_INPUT,
    "REQUEST_MORE_EVIDENCE": LIFECYCLE_NEEDS_HUMAN_INPUT,
    "REQUIRE_HUMAN_APPROVAL": LIFECYCLE_NEEDS_HUMAN_INPUT,
}


def default_lifecycle_status(decision_label: str) -> str:
    """Return the default v0 lifecycle status for a rules-only decision label."""
    return _DEFAULT_LIFECYCLE_BY_DECISION.get(decision_label, LIFECYCLE_NEEDS_HUMAN_INPUT)


def lifecycle_status_after_evidence_without_envelope(
    decision_label: str,
    *,
    remaining_missing: list[str] | None = None,
    latest_evidence_recognized: bool = True,
) -> str:
    """Return lifecycle when evidence is recorded but no full envelope exists to re-evaluate."""
    if decision_label != "REQUEST_MORE_EVIDENCE":
        return LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_MANUAL_CONFIRMATION
    remaining = list(remaining_missing or [])
    if remaining and not latest_evidence_recognized:
        return LIFECYCLE_EVIDENCE_INSUFFICIENT_STILL_MISSING
    return LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_MANUAL_CONFIRMATION


def lifecycle_status_after_evidence_reevaluation(
    decision_label: str,
    *,
    missing_evidence: list[str] | None = None,
    non_evidence_blockers: list[str] | None = None,
    latest_evidence_recognized: bool = True,
) -> str:
    """Return the derived lifecycle status after cumulative evidence re-evaluation.

    Never claims approval or execution; only reflects what the rules-only
    evaluator returned after folding in all supplied evidence.
    """
    if decision_label == "REQUIRE_HUMAN_APPROVAL":
        return LIFECYCLE_EVIDENCE_SATISFIED_PENDING_HUMAN_DECISION
    if decision_label == "REQUEST_MORE_EVIDENCE":
        remaining = list(missing_evidence or [])
        blockers = list(non_evidence_blockers or [])
        if remaining and not latest_evidence_recognized:
            return LIFECYCLE_EVIDENCE_INSUFFICIENT_STILL_MISSING
        if remaining:
            return LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED
        if blockers:
            return LIFECYCLE_BLOCKED_BY_NON_EVIDENCE_GATE
        return LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED
    return default_lifecycle_status(decision_label)


def queue_item_needs_attention(item: dict[str, Any]) -> bool:
    """Return True when a queue item still belongs in Needs Attention buckets.

  Uses derived lifecycle state (not the immutable rules-only decision label
  alone). Old sessions without lifecycle fields fall back to decision-label
  gating only.
    """
    decision = item.get("decision")
    if decision not in _ATTENTION_DECISIONS:
        return False
    lifecycle = item.get("lifecycle_status", LIFECYCLE_NEEDS_HUMAN_INPUT)
    if lifecycle in LIFECYCLE_NO_LONGER_NEEDS_ATTENTION:
        return False
    if item.get("execution_status") == _EXECUTION_STATUS_ADMITTED_NOT_EXECUTED:
        return False
    return True


def resolved_plan_gate_ids(resolved_plan_gates: list[dict[str, Any]]) -> set[str]:
    return {str(g.get("gate_id")) for g in resolved_plan_gates if g.get("gate_id")}


# Same operational-action mapping used by admissible.long_run_truth, kept as
# a small local copy so this module does not have to import the heavier
# long_run_truth / terminal_dry_run_demo import chain just for one mapping.
_DECISION_TO_OPERATIONAL: dict[str, str] = {
    "ALLOW": "execute",
    "ALLOW_WITH_LIMITS": "limit_scope",
    "REQUEST_MORE_EVIDENCE": "request_evidence",
    "REQUIRE_HUMAN_APPROVAL": "request_approval",
    "REFUSE": "block",
}


def operational_action_for_decision(
    decision: str, *, safer_next_step: dict[str, Any] | None = None
) -> str:
    if decision == "ALLOW_WITH_LIMITS":
        if isinstance(safer_next_step, dict) and safer_next_step.get("description"):
            return "replace_with_safer_step"
        return "limit_scope"
    return _DECISION_TO_OPERATIONAL.get(decision, "block")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _from_dict(cls: type, data: dict[str, Any]) -> Any:
    field_names = {f.name for f in dataclasses.fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in field_names})


def _note_text(note: Any) -> str:
    if isinstance(note, dict):
        return str(note.get("summary") or note.get("type") or "")
    return str(note)


def _missing_field_id(note: Any) -> str:
    """Return the canonical missing-evidence field id from a note or string."""
    if isinstance(note, dict):
        field_id = note.get("field_id")
        if field_id:
            return str(field_id)
        return _note_text(note)
    return str(note)


def _field_matches_missing(field_id: str, missing: list[Any]) -> bool:
    """Return True when ``field_id`` targets one entry in ``missing``."""
    fid = field_id.strip().lower()
    if not fid:
        return False
    for note in missing:
        note_id = _missing_field_id(note).strip().lower()
        if fid == note_id or fid in note_id or note_id in fid:
            return True
    return False


_EVIDENCE_SOURCE_HUMAN = "human"
_EVIDENCE_SOURCE_AGENT = "agent"
_EVIDENCE_SOURCE_BOUNDED_EXECUTOR = "bounded_executor"
EVIDENCE_SOURCES = frozenset(
    {_EVIDENCE_SOURCE_HUMAN, _EVIDENCE_SOURCE_AGENT, _EVIDENCE_SOURCE_BOUNDED_EXECUTOR}
)

_NON_EVIDENCE_BLOCKER_DIMENSIONS = frozenset({"policy", "reversibility", "authority"})


def non_evidence_blockers_from_decision(decision: dict[str, Any]) -> list[str]:
    """Return human-readable blockers that evidence cannot satisfy on its own."""
    blockers: list[str] = []
    missing = decision.get("missing_evidence") or []
    for reason in decision.get("reasons") or []:
        if not isinstance(reason, dict):
            continue
        dimension = str(reason.get("dimension") or "")
        summary = str(reason.get("summary") or dimension)
        if dimension in _NON_EVIDENCE_BLOCKER_DIMENSIONS:
            blockers.append(summary)
        elif dimension == "evidence" and not missing:
            blockers.append(summary)
    return blockers


def _record_target_fields(record: "EvidenceRecord") -> list[str]:
    if record.satisfies:
        return [str(f) for f in record.satisfies if str(f).strip()]
    if record.evidence_type:
        return [record.evidence_type]
    return []


def fields_satisfied_by_record(
    record: "EvidenceRecord",
    *,
    missing_before: list[Any],
) -> list[str]:
    """Return missing-field ids this record explicitly or implicitly satisfies."""
    satisfied: list[str] = []
    for field_id in _record_target_fields(record):
        if _field_matches_missing(field_id, missing_before):
            satisfied.append(_missing_field_id(field_id) if not record.satisfies else field_id)
    return satisfied


_SAME_AS_EVIDENCE_TYPE_PLACEHOLDERS = frozenset(
    {
        "",
        "(same as evidence type)",
        "same as evidence type",
        "__same_as_evidence_type__",
    }
)


def normalize_evidence_satisfies(raw_satisfies: Any, evidence_type: str) -> list[str]:
    """Normalize satisfies from UI/API, including '(same as evidence type)' placeholders."""
    if raw_satisfies is None:
        return [evidence_type] if evidence_type else []
    if isinstance(raw_satisfies, str):
        stripped = raw_satisfies.strip()
        if not stripped or stripped.lower() in {
            p.lower() for p in _SAME_AS_EVIDENCE_TYPE_PLACEHOLDERS if p
        }:
            return [evidence_type] if evidence_type else []
        return [stripped]
    normalized: list[str] = []
    for field in raw_satisfies:
        token = str(field).strip()
        if not token:
            continue
        if token.lower() in {
            p.lower() for p in _SAME_AS_EVIDENCE_TYPE_PLACEHOLDERS if p
        }:
            if evidence_type and evidence_type not in normalized:
                normalized.append(evidence_type)
        elif token not in normalized:
            normalized.append(token)
    return normalized or ([evidence_type] if evidence_type else [])


def remaining_missing_after_evidence(
    records: list["EvidenceRecord"],
    *,
    original_missing: list[Any],
) -> list[str]:
    """Return missing-field ids still outstanding after cumulative evidence records."""
    remaining = list(original_missing)
    for record in records:
        matched = fields_satisfied_by_record(record, missing_before=remaining)
        remaining = [
            note
            for note in remaining
            if not any(_field_matches_missing(f, [note]) for f in matched)
        ]
    return [_missing_field_id(n) for n in remaining]


def cumulative_satisfied_evidence_fields(
    records: list["EvidenceRecord"],
    *,
    original_missing: list[Any],
) -> list[str]:
    """Return all missing-field ids satisfied cumulatively across ``records``."""
    satisfied: list[str] = []
    seen: set[str] = set()
    remaining = list(original_missing)
    for record in records:
        matched = fields_satisfied_by_record(record, missing_before=remaining)
        for field_id in matched:
            key = field_id.lower()
            if key not in seen:
                seen.add(key)
                satisfied.append(field_id)
        remaining = [
            note
            for note in remaining
            if not any(_field_matches_missing(f, [note]) for f in matched)
        ]
    return satisfied


def derive_evidence_attention_state(
    decision: dict[str, Any],
    *,
    original_missing: list[Any],
    evidence_records: list["EvidenceRecord"],
    latest_record: "EvidenceRecord | None" = None,
    without_envelope_reevaluation: bool = False,
) -> dict[str, Any]:
    """Compute structured evidence satisfaction and a demo-readable attention summary."""
    cumulative = cumulative_satisfied_evidence_fields(
        evidence_records, original_missing=original_missing
    )
    if without_envelope_reevaluation:
        remaining = remaining_missing_after_evidence(
            evidence_records, original_missing=original_missing
        )
    else:
        remaining = list(decision.get("missing_evidence") or [])
    non_evidence = non_evidence_blockers_from_decision(decision)
    decision_label = str(decision.get("decision") or "")
    original_ids = [_missing_field_id(n) for n in original_missing]

    latest = latest_record
    latest_fields: list[str] = []
    latest_recognized = True
    if latest is not None:
        missing_before_latest = list(original_missing)
        for prior in evidence_records:
            if prior.record_id == latest.record_id:
                break
            prior_fields = fields_satisfied_by_record(prior, missing_before=missing_before_latest)
            missing_before_latest = [
                note
                for note in missing_before_latest
                if not any(_field_matches_missing(f, [note]) for f in prior_fields)
            ]
        latest_fields = fields_satisfied_by_record(latest, missing_before=missing_before_latest)
        latest_recognized = bool(latest_fields) or not _record_target_fields(latest)

    if without_envelope_reevaluation:
        lifecycle = lifecycle_status_after_evidence_without_envelope(
            decision_label,
            remaining_missing=remaining,
            latest_evidence_recognized=latest_recognized,
        )
    else:
        lifecycle = lifecycle_status_after_evidence_reevaluation(
            decision_label,
            missing_evidence=remaining,
            non_evidence_blockers=non_evidence,
            latest_evidence_recognized=latest_recognized,
        )

    all_fields_satisfied = bool(original_ids) and not remaining and bool(cumulative)

    if without_envelope_reevaluation:
        if lifecycle == LIFECYCLE_EVIDENCE_INSUFFICIENT_STILL_MISSING:
            summary = (
                "Evidence insufficient or unrecognized; still missing: "
                + (", ".join(remaining) if remaining else "(none listed)")
            )
        elif all_fields_satisfied:
            summary = (
                "Evidence fields satisfied, but no full envelope is available for "
                "automatic re-evaluation; human confirmation is required."
            )
        elif cumulative and remaining:
            summary = (
                "Evidence accepted for "
                + ", ".join(cumulative)
                + "; still missing: "
                + ", ".join(remaining)
                + ". No full envelope is available for automatic re-evaluation; "
                "human confirmation is required."
            )
        elif cumulative:
            summary = (
                "Evidence recorded for "
                + ", ".join(cumulative)
                + ". No full envelope is available for automatic re-evaluation; "
                "human confirmation is required."
            )
        else:
            summary = (
                "Evidence recorded; no full envelope is available for automatic "
                "re-evaluation; human confirmation is required."
            )
    elif decision_label == "REQUIRE_HUMAN_APPROVAL":
        summary = "Evidence satisfied; human approval required."
    elif lifecycle == LIFECYCLE_EVIDENCE_INSUFFICIENT_STILL_MISSING:
        summary = (
            "Evidence insufficient or unrecognized; still missing: "
            + (", ".join(remaining) if remaining else "(none listed)")
        )
    elif lifecycle == LIFECYCLE_BLOCKED_BY_NON_EVIDENCE_GATE:
        summary = (
            "Evidence accepted, but still blocked by authority/reversibility/policy: "
            + "; ".join(non_evidence[:3])
        )
    elif remaining:
        summary = "Evidence accepted, still missing: " + ", ".join(remaining)
    elif non_evidence:
        summary = (
            "Evidence accepted, but still blocked by authority/reversibility/policy: "
            + "; ".join(non_evidence[:3])
        )
    else:
        summary = "Evidence supplied; awaiting further resolution."

    return {
        "previously_missing_evidence": original_ids,
        "fields_satisfied_by_latest": latest_fields,
        "satisfied_evidence_fields": cumulative,
        "remaining_missing_evidence": remaining,
        "non_evidence_blockers": non_evidence,
        "evidence_attention_summary": summary,
        "latest_evidence_recognized": latest_recognized,
        "lifecycle_status": lifecycle,
        "all_evidence_fields_satisfied": all_fields_satisfied,
    }


# -- instruction packet content (v0, deterministic, offline) -----------------

NON_EXECUTION_BOUNDARIES: tuple[str, ...] = (
    "Admissible does not execute this packet's proposals; it only frames, audits, and gates them.",
    "Do not execute any shell command, tool call, file mutation, dependency install, or deployment "
    "as a result of this packet without a separate, explicit human admission decision.",
    "REFUSE, REQUIRE_HUMAN_APPROVAL, and REQUEST_MORE_EVIDENCE always stop for a human decision, "
    "regardless of autonomy level.",
    "Treat this packet as a request to propose, not an authorization to act.",
)

_MUST_NOT: tuple[str, ...] = (
    "Do not deploy, publish, or push beyond the local workspace without explicit human authorization.",
    "Do not install or upgrade dependencies without explicit human approval.",
    "Do not delete or overwrite existing files without explicit human sign-off.",
    "Do not treat an autonomy level, a batch approval, or silence as authorization for a REFUSE, "
    "REQUIRE_HUMAN_APPROVAL, or REQUEST_MORE_EVIDENCE action.",
    "Do not claim an action was executed; there is no executor in this loop.",
)

_CONTINUATION_INSTRUCTION = (
    "If the next step would be blocked (REQUIRE_HUMAN_APPROVAL, REQUEST_MORE_EVIDENCE, REFUSE, or an "
    "unresolved plan gate), propose the operation and stop there -- do not execute it and do not "
    "simulate or claim its result."
)

# Cursor/frontier-agent guidance for decision-only proposals (resolving a
# plan gate, an architecture/framework choice, or another question with no
# concrete command/file/dependency side effect). Without a recognizable
# shape, a decision-only proposal used to be indistinguishable from a vague,
# non-actionable response and fell back to an unclassified `unknown`/
# REQUEST_MORE_EVIDENCE candidate. This structured block is what
# `admissible.long_run_envelope_builder` (`_extract_plan_gate_blocks`,
# `_is_plan_gate_segment`) recognizes and maps to a `plan_gate_resolution`
# action classified as REQUIRE_HUMAN_APPROVAL. Formatting guidance only --
# it does not change what may be executed, and a concrete side-effecting
# proposal (a command, a file edit, a dependency install, ...) should still
# be described plainly, as in previous turns.
_RESPONSE_FORMAT_GUIDANCE: tuple[str, ...] = (
    "For a proposal that resolves a plan gate, an architecture/framework choice, or another "
    "decision-only question (no command, file, or dependency side effect), use this block so "
    "Admissible can classify it precisely instead of an unclassified fallback:",
    "    action_gate_<id> -- <short label>",
    "    Verdict class: ALLOW | ALLOW_WITH_LIMITS | REQUEST_MORE_EVIDENCE | REQUIRE_HUMAN_APPROVAL | REFUSE",
    "    Closes gates: <comma-separated gate/step id(s) this resolves, or none>",
    "    Side effects if approved: <description, or None>",
    "    Proposal: <what you propose>",
    "    Human decision required: <what you need the human to confirm, approve, or choose>",
    "For a proposal with a concrete side effect (a command, a file edit, a dependency install, a "
    "push, a deploy, ...), describe it plainly instead (e.g. \"Proposed command: ...\", "
    "\"Proposed tool call: ...\"), as in previous turns -- this structured block is only for "
    "decision-only proposals.",
    "",
    "For a proposal that is a bounded LOCAL FILE operation -- create/overwrite a file, read a "
    "file, or list a directory inside the approved workspace -- ALSO include an explicit "
    "structured block so Admissible's bounded local executor can consume the exact operation "
    "(prose alone is admitted and gated, but is not executable):",
    f"    {STRUCTURED_OPERATION_MARKER}",
    "    ```json",
    "    {\"operation\": \"write_file\", \"path\": \"index.html\", \"content\": \"<!doctype html>...\"}",
    "    ```",
    "    Allowed operations: list_files, read_file, write_file. \"path\" is workspace-relative "
    "(no absolute paths, no \"..\"). write_file requires an explicit \"content\" string. Emit one "
    "block per file operation; you may include several.",
    "    Do not put shell, npm/pip/yarn, git, deploy, or network commands in this block -- the "
    "executor refuses them. Including the block does not authorize execution: the operation is "
    "still admitted and gated, and only ever runs via a separate, explicit bounded-execution step.",
)

_MAY_PROPOSE_BY_LEVEL: dict[str, tuple[str, ...]] = {
    "L0_OBSERVE_ONLY": (
        "Nothing yet -- L0 is analysis/observation only. Summarize findings; do not propose "
        "side-effecting actions.",
    ),
    "L1_PROPOSE_ONLY": (
        "Propose one action at a time, in enough detail for independent human review.",
        "Wait for an explicit human decision on each proposal before describing the next one.",
    ),
    "L2_LOCAL_BATCH_APPROVAL": (
        "Propose a batch of local, reversible ALLOW-tier actions for a single human batch review.",
        "Still propose (do not apply) any action outside local ALLOW tier one at a time.",
    ),
    "L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS": (
        "Propose local ALLOW-tier actions; they may be treated as admitted-not-executed pending a "
        "human attestation, without a per-action approval click.",
        "Any action outside local ALLOW tier still needs an individual proposal and a human decision.",
    ),
    "L4_HIGH_AUTONOMY_HARD_GATES": (
        "Propose the broadest reasonable set of local actions consistent with the plan.",
        "This is the highest v0 autonomy wording; it changes proposal breadth only -- it does not "
        "change what may be executed.",
    ),
}
_DEFAULT_MAY_PROPOSE = _MAY_PROPOSE_BY_LEVEL["L1_PROPOSE_ONLY"]


@dataclass
class AgentInstructionPacket:
    """One turn's "next instruction" packet for Cursor / a frontier agent."""

    packet_id: str
    turn_number: int
    created_at: str
    autonomy_level: str
    task: str
    allowed_scope: list[str]
    non_execution_boundaries: list[str]
    may_propose: list[str]
    must_not: list[str]
    evidence_needed: list[str]
    continuation_instruction: str
    open_gates_summary: list[str]
    queue_summary: dict[str, int]
    packet_text: str
    # Defaulted (and kept last) so `from_dict` can still load a packet
    # persisted before this field existed -- see the repo's own committed
    # `.admissible/control_surface_sessions/session.json`.
    response_format_guidance: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentInstructionPacket":
        return _from_dict(cls, data)


@dataclass
class RunTurn:
    """One turn of the supervised loop: an instruction out, a response in."""

    turn_number: int
    created_at: str
    instruction_packet_id: str | None
    agent_response_record_id: str | None
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunTurn":
        return _from_dict(cls, data)


@dataclass
class AgentResponseRecord:
    """A raw, pasted agent response. Always unverified agent output."""

    record_id: str
    turn_number: int
    created_at: str
    raw_text: str
    source_trust: str
    actor: str
    action_ids: list[str]
    builder_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentResponseRecord":
        return _from_dict(cls, data)


@dataclass
class EvidenceRecord:
    """One structured evidence packet a human operator (or agent) supplied for one action."""

    record_id: str
    action_id: str
    decision_id: str | None
    envelope_id: str | None
    actor: str
    timestamp: str
    evidence_type: str
    evidence_text: str
    file_path_or_note: str | None
    rationale: str
    # Structured packet fields (slice ADMISSIBLE_EVIDENCE_007; optional for backward compat).
    source: str = _EVIDENCE_SOURCE_HUMAN
    satisfies: list[str] = field(default_factory=list)
    sha256: str | None = None
    turn_number: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceRecord":
        return _from_dict(cls, data)


@dataclass
class DerivedLifecycleResolution:
    """Append-only derived lifecycle state from one human decision.

    Never mutates the original rules-only admission decision on the run
    envelope; records what downstream lifecycle state was derived.
    """

    record_id: str
    action_id: str
    human_decision_id: str
    derived_status: str
    approved_scope: str | None
    closes_gate_ids: list[str]
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DerivedLifecycleResolution":
        return _from_dict(cls, data)


@dataclass
class ResolvedPlanGateRecord:
    """One plan gate closed by a human-approved plan_gate_resolution action."""

    gate_id: str
    resolved_by_action_id: str
    resolved_by_human_decision_id: str
    approved_scope: str | None
    resolved_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ResolvedPlanGateRecord":
        return _from_dict(cls, data)


@dataclass
class SupersedingAdmissionDecision:
    """A new rules-only decision produced after evidence was supplied.

    Never replaces or mutates the original decision dict on the run
    envelope; it is a separate, linked record.
    """

    record_id: str
    action_id: str
    previous_decision_id: str | None
    new_decision: dict[str, Any]
    based_on_evidence_record_id: str | None
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SupersedingAdmissionDecision":
        return _from_dict(cls, data)


@dataclass
class RunLoopState:
    """All supervised-run-loop state for one Control Surface session."""

    current_turn: int = 0
    turns: list[RunTurn] = field(default_factory=list)
    instruction_packets: list[AgentInstructionPacket] = field(default_factory=list)
    response_records: list[AgentResponseRecord] = field(default_factory=list)
    evidence_records: list[EvidenceRecord] = field(default_factory=list)
    superseding_decisions: list[SupersedingAdmissionDecision] = field(default_factory=list)
    derived_lifecycle_resolutions: list[DerivedLifecycleResolution] = field(default_factory=list)
    resolved_plan_gates: list[ResolvedPlanGateRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RUN_LOOP_SCHEMA_VERSION,
            "current_turn": self.current_turn,
            "turns": [t.to_dict() for t in self.turns],
            "instruction_packets": [p.to_dict() for p in self.instruction_packets],
            "response_records": [r.to_dict() for r in self.response_records],
            "evidence_records": [e.to_dict() for e in self.evidence_records],
            "superseding_decisions": [s.to_dict() for s in self.superseding_decisions],
            "derived_lifecycle_resolutions": [r.to_dict() for r in self.derived_lifecycle_resolutions],
            "resolved_plan_gates": [g.to_dict() for g in self.resolved_plan_gates],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RunLoopState":
        data = data or {}
        return cls(
            current_turn=data.get("current_turn", 0),
            turns=[RunTurn.from_dict(d) for d in data.get("turns") or []],
            instruction_packets=[
                AgentInstructionPacket.from_dict(d) for d in data.get("instruction_packets") or []
            ],
            response_records=[
                AgentResponseRecord.from_dict(d) for d in data.get("response_records") or []
            ],
            evidence_records=[EvidenceRecord.from_dict(d) for d in data.get("evidence_records") or []],
            superseding_decisions=[
                SupersedingAdmissionDecision.from_dict(d)
                for d in data.get("superseding_decisions") or []
            ],
            derived_lifecycle_resolutions=[
                DerivedLifecycleResolution.from_dict(d)
                for d in data.get("derived_lifecycle_resolutions") or []
            ],
            resolved_plan_gates=[
                ResolvedPlanGateRecord.from_dict(d) for d in data.get("resolved_plan_gates") or []
            ],
        )


def _allowed_scope(goal_intake: dict[str, Any]) -> list[str]:
    scope = [
        "Local workspace only; no deployment, publish, or push without explicit human authorization."
    ]
    boundary = goal_intake.get("initial_non_execution_boundary")
    if boundary:
        scope.append(str(boundary))
    if goal_intake.get("risk_scope") == "local":
        scope.append("Prompt explicitly scopes risk as local-only.")
    side_effects = goal_intake.get("likely_side_effect_classes") or []
    if side_effects:
        scope.append("Anticipated side-effect classes: " + ", ".join(side_effects) + ".")
    return scope


def _open_gates_summary(
    goal_intake: dict[str, Any],
    plan_audit: dict[str, Any],
    *,
    resolved_plan_gates: list[dict[str, Any]] | None = None,
) -> list[str]:
    items: list[str] = []
    resolved_ids = resolved_plan_gate_ids(resolved_plan_gates or [])
    verdict = plan_audit.get("verdict")
    if verdict and verdict != "PLAN_OK_FOR_LOCAL_PROTOTYPE":
        items.append(f"Plan audit verdict: {verdict}.")
    for gate in plan_audit.get("required_gates") or []:
        if gate in resolved_ids:
            continue
        items.append(f"Unresolved plan gate: {gate}.")
    for resolved in resolved_plan_gates or []:
        gate_id = resolved.get("gate_id")
        scope = resolved.get("approved_scope")
        scope_note = f" (scope: {scope})" if scope else ""
        items.append(f"Human-resolved plan gate: {gate_id}{scope_note}.")
    for missing in goal_intake.get("missing_context") or []:
        items.append(f"Missing context: {missing}.")
    for question in goal_intake.get("clarifying_questions") or []:
        items.append(f"Clarifying question: {question}.")
    return items


def _evidence_needed(queue: list[dict[str, Any]]) -> list[str]:
    items: list[str] = []
    for item in queue:
        if item.get("decision") != "REQUEST_MORE_EVIDENCE":
            continue
        status = item.get("lifecycle_status", LIFECYCLE_NEEDS_HUMAN_INPUT)
        if status in (
            LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION,
            LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_MANUAL_CONFIRMATION,
        ):
            missing = item.get("missing_evidence") or []
            satisfied = item.get("satisfied_evidence_fields") or []
            summary = item.get("evidence_attention_summary")
            if satisfied and not missing:
                items.append(
                    f"{item.get('action_id')}: evidence fields satisfied but manual confirmation "
                    "required (no full envelope for automatic re-evaluation)."
                )
            elif satisfied and missing:
                for entry in missing:
                    line = f"{item.get('action_id')}: {entry}"
                    if line not in items:
                        items.append(line)
            elif summary:
                items.append(f"{item.get('action_id')}: {summary}")
            else:
                items.append(
                    f"{item.get('action_id')}: evidence was already supplied by a human operator but "
                    "could not be automatically re-evaluated in v0 (no full envelope on this action); "
                    "still treat as blocked until a human confirms."
                )
            continue
        if status in (
            LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED,
            LIFECYCLE_EVIDENCE_INSUFFICIENT_STILL_MISSING,
        ):
            missing = item.get("missing_evidence") or []
            summary = item.get("evidence_attention_summary")
            if missing:
                for entry in missing:
                    line = f"{item.get('action_id')}: {entry}"
                    if line not in items:
                        items.append(line)
            elif summary:
                items.append(f"{item.get('action_id')}: {summary}")
            else:
                items.append(
                    f"{item.get('action_id')}: human-suppliable evidence fields are satisfied, "
                    "but the action remains blocked on non-evidence gates (e.g. authority or "
                    "policy); a human decision is still required."
                )
            continue
        if status == LIFECYCLE_BLOCKED_BY_NON_EVIDENCE_GATE:
            summary = item.get("evidence_attention_summary") or (
                f"{item.get('action_id')}: human-suppliable evidence fields are satisfied, "
                "but the action remains blocked on non-evidence gates (e.g. authority or "
                "policy); a human decision is still required."
            )
            if summary not in items:
                items.append(summary)
            continue
        if status != LIFECYCLE_NEEDS_HUMAN_INPUT:
            continue
        for missing in item.get("missing_evidence") or []:
            entry = f"{item.get('action_id')}: {missing}"
            if entry not in items:
                items.append(entry)
    return items or ["None outstanding right now."]


def _queue_summary(queue: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in queue:
        label = item.get("decision", "unknown")
        counts[label] = counts.get(label, 0) + 1
    return counts


def _bullets(items: list[str]) -> str:
    return "\n".join(f"- {i}" for i in items) if items else "- (none)"


def _response_format_block(lines: list[str]) -> str:
    # Unlike _bullets(), this is rendered as plain lines (not "- "-prefixed)
    # since it mixes instruction sentences with an indented field-by-field
    # template (see _RESPONSE_FORMAT_GUIDANCE) that reads as a block, not a
    # bullet list.
    return "\n".join(lines) if lines else "(none)"


def _render_packet_text(packet: AgentInstructionPacket) -> str:
    queue_summary_line = (
        ", ".join(f"{k}={v}" for k, v in packet.queue_summary.items()) or "(empty queue)"
    )
    return (
        f"=== Admissible Next Agent Instruction Packet -- turn {packet.turn_number} ===\n"
        f"Autonomy level: {packet.autonomy_level}\n\n"
        f"TASK\n{packet.task}\n\n"
        f"ALLOWED SCOPE\n{_bullets(packet.allowed_scope)}\n\n"
        f"NON-EXECUTION BOUNDARIES (apply at every autonomy level)\n"
        f"{_bullets(packet.non_execution_boundaries)}\n\n"
        f"WHAT YOU MAY PROPOSE AT THIS AUTONOMY LEVEL\n{_bullets(packet.may_propose)}\n\n"
        f"WHAT YOU MUST NOT DO\n{_bullets(packet.must_not)}\n\n"
        f"EVIDENCE NEEDED IF CONTINUING\n{_bullets(packet.evidence_needed)}\n\n"
        f"OPEN GATES / UNRESOLVED PLAN ITEMS\n{_bullets(packet.open_gates_summary)}\n\n"
        f"CURRENT QUEUE STATE\n{queue_summary_line}\n\n"
        f"CONTINUATION INSTRUCTION\n{packet.continuation_instruction}\n\n"
        f"RESPONSE FORMAT\n{_response_format_block(packet.response_format_guidance)}\n\n"
        "-- Generated by Admissible Control Surface v0. Admissible does not execute code and does not "
        "call Cursor, Claude Code, Codex, Gemini, OpenAI, or any network provider. Propose; do not execute."
    )


def generate_instruction_packet(
    *,
    turn_number: int,
    autonomy_level: str,
    goal_intake: dict[str, Any] | None,
    plan_audit: dict[str, Any] | None,
    queue: list[dict[str, Any]],
    resolved_plan_gates: list[dict[str, Any]] | None = None,
) -> AgentInstructionPacket:
    """Deterministically build the next agent instruction packet (v0).

    Offline only: derived from already-computed goal intake, plan audit,
    and current queue state. Never calls a model or network provider.
    Autonomy level only changes `may_propose` wording; the non-execution
    boundaries and must-not list are identical at every level.
    """
    goal_intake = goal_intake or {}
    plan_audit = plan_audit or {}

    task = (
        f"{goal_intake.get('task_type', 'unspecified_task')}: {goal_intake.get('deliverable', 'unspecified deliverable')}"
        if goal_intake
        else "No goal has been submitted to Admissible yet."
    )

    packet = AgentInstructionPacket(
        packet_id=f"packet_turn{turn_number:02d}_{uuid.uuid4().hex[:8]}",
        turn_number=turn_number,
        created_at=_now_iso(),
        autonomy_level=autonomy_level,
        task=task,
        allowed_scope=_allowed_scope(goal_intake),
        non_execution_boundaries=list(NON_EXECUTION_BOUNDARIES),
        may_propose=list(_MAY_PROPOSE_BY_LEVEL.get(autonomy_level, _DEFAULT_MAY_PROPOSE)),
        must_not=list(_MUST_NOT),
        evidence_needed=_evidence_needed(queue),
        continuation_instruction=_CONTINUATION_INSTRUCTION,
        open_gates_summary=_open_gates_summary(
            goal_intake, plan_audit, resolved_plan_gates=resolved_plan_gates
        ),
        queue_summary=_queue_summary(queue),
        packet_text="",
        response_format_guidance=list(_RESPONSE_FORMAT_GUIDANCE),
    )
    packet.packet_text = _render_packet_text(packet)
    return packet


def build_candidates_from_agent_response(
    raw_text: str,
    *,
    turn_number: int,
    long_run_prompt: str | None = None,
    source_metadata: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Turn one pasted raw agent response into action-candidate dicts.

    Reuses `long_run_envelope_builder.build_from_raw_output` (extraction)
    and `evaluator.rules_only.evaluate_envelope` (decision) unmodified.
    Returns a list of plain dicts (not admissible.control_surface types,
    so this module has no dependency on it): action_id, envelope_id,
    decision_id, candidate, decision, envelope.
    """
    metadata = dict(source_metadata or {})
    metadata.setdefault("source_type", "agent_response_paste")
    metadata.setdefault("frontier_agent_label", "external_frontier_agent_pasted_v0")

    builder_out = build_from_raw_output(
        raw_text, long_run_prompt=long_run_prompt, source_metadata=metadata
    )
    candidates = builder_out.get("action_candidates") or []
    envelopes = builder_out.get("envelopes") or []

    results: list[dict[str, Any]] = []
    for index, (candidate, envelope) in enumerate(zip(candidates, envelopes), start=1):
        decision = evaluate_envelope(envelope)
        decision["operational_admissibility_action"] = operational_action_for_decision(
            decision["decision"], safer_next_step=decision.get("safer_next_step")
        )
        action_id = f"resp_t{turn_number:02d}_{index:03d}_{uuid.uuid4().hex[:8]}"
        results.append(
            {
                "action_id": action_id,
                "envelope_id": envelope.get("envelope_id"),
                "decision_id": decision.get("decision_id"),
                "candidate": candidate,
                "decision": decision,
                "envelope": envelope,
            }
        )
    return results


def reevaluate_envelope_with_evidence(
    envelope: dict[str, Any] | None,
    *,
    evidence_items: list[tuple[str, str]] | None = None,
    structured_evidence: list[dict[str, Any]] | None = None,
    evidence_type: str | None = None,
    evidence_text: str | None = None,
) -> dict[str, Any] | None:
    """Fold supplied evidence into a copy of `envelope` and re-run the
    unmodified rules-only evaluator.

    Evidence is cumulative: pass every prior record via ``structured_evidence``
    (preferred) or legacy ``(evidence_type, evidence_text)`` tuples in
    ``evidence_items``. A single latest item may still be passed via
    ``evidence_type`` / ``evidence_text`` for backward compatibility.

    When ``satisfies`` is present on a structured item, only those explicit
    field ids are used to shrink ``evidence.missing``. Legacy items without
    ``satisfies`` keep substring matching on ``evidence_type``.

    Returns the new decision dict, or None when no full schema envelope is
    available to reevaluate (e.g. actions loaded from a static trace file
    in v0 only carry the already-computed candidate/decision pair, not the
    full envelope) -- callers must fall back to marking the action pending
    reevaluation in that case. Never mutates the input envelope.
    """
    if not isinstance(envelope, dict):
        return None

    structured: list[dict[str, Any]] = list(structured_evidence or [])
    if not structured and evidence_items:
        structured = [
            {"evidence_type": etype, "evidence_text": etext, "satisfies": []}
            for etype, etext in evidence_items
        ]
    if evidence_type and evidence_text:
        structured.append(
            {"evidence_type": evidence_type, "evidence_text": evidence_text, "satisfies": []}
        )
    if not structured:
        return None

    new_envelope = copy.deepcopy(envelope)
    evidence = new_envelope.setdefault("evidence", {})
    available = list(evidence.get("available") or [])
    explicit_satisfied: set[str] = set()
    legacy_satisfied_types: set[str] = set()

    for item in structured:
        etype = str(item.get("evidence_type") or "").strip()
        etext = str(item.get("evidence_text") or "").strip()
        if not etype or not etext:
            continue
        satisfies = [str(f) for f in (item.get("satisfies") or []) if str(f).strip()]
        available.append(
            {
                "type": etype,
                "summary": etext,
                "source": str(item.get("source") or _EVIDENCE_SOURCE_HUMAN),
                "confidence": "human_provided",
            }
        )
        if satisfies:
            explicit_satisfied.update(f.lower() for f in satisfies)
        else:
            legacy_satisfied_types.add(etype.lower())

    evidence["available"] = available

    def _still_missing(note: Any) -> bool:
        note_id = _missing_field_id(note).lower()
        note_text = _note_text(note).lower()
        if explicit_satisfied:
            if note_id in explicit_satisfied:
                return False
            if any(fid in note_text or note_text in fid for fid in explicit_satisfied):
                return False
        if legacy_satisfied_types:
            if any(st in note_text for st in legacy_satisfied_types):
                return False
        return True

    evidence["missing"] = [item for item in (evidence.get("missing") or []) if _still_missing(item)]

    decision = evaluate_envelope(new_envelope)
    decision["operational_admissibility_action"] = operational_action_for_decision(
        decision["decision"], safer_next_step=decision.get("safer_next_step")
    )
    return decision


__all__ = [
    "AGENT_RESPONSE_ACTOR",
    "AGENT_RESPONSE_SOURCE_TRUST",
    "EVIDENCE_ACTOR_HUMAN_OPERATOR",
    "LIFECYCLE_ADMITTED_NOT_EXECUTED",
    "LIFECYCLE_APPROVAL_SUPPLIED_PENDING_REEVALUATION",
    "LIFECYCLE_CLOSED",
    "LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION",
    "LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_MANUAL_CONFIRMATION",
    "LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED",
    "LIFECYCLE_BLOCKED_BY_NON_EVIDENCE_GATE",
    "LIFECYCLE_EVIDENCE_INSUFFICIENT_STILL_MISSING",
    "LIFECYCLE_EVIDENCE_SATISFIED_PENDING_HUMAN_DECISION",
    "LIFECYCLE_LIMITED_SCOPE_SELECTED",
    "LIFECYCLE_NEEDS_HUMAN_INPUT",
    "LIFECYCLE_NO_LONGER_NEEDS_ATTENTION",
    "LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION",
    "LIFECYCLE_REFUSED_CLOSED",
    "LIFECYCLE_RESOLVED_GATE",
    "LIFECYCLE_STATUSES",
    "NON_EXECUTION_BOUNDARIES",
    "RUN_LOOP_SCHEMA_VERSION",
    "AgentInstructionPacket",
    "AgentResponseRecord",
    "DerivedLifecycleResolution",
    "EvidenceRecord",
    "ResolvedPlanGateRecord",
    "RunLoopState",
    "RunTurn",
    "SupersedingAdmissionDecision",
    "EVIDENCE_SOURCES",
    "STRUCTURED_OPERATION_MARKER",
    "cumulative_satisfied_evidence_fields",
    "derive_evidence_attention_state",
    "fields_satisfied_by_record",
    "lifecycle_status_after_evidence_without_envelope",
    "normalize_evidence_satisfies",
    "non_evidence_blockers_from_decision",
    "remaining_missing_after_evidence",
    "build_candidates_from_agent_response",
    "default_lifecycle_status",
    "generate_instruction_packet",
    "lifecycle_status_after_evidence_reevaluation",
    "operational_action_for_decision",
    "queue_item_needs_attention",
    "reevaluate_envelope_with_evidence",
    "resolved_plan_gate_ids",
]
