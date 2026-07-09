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
from admissible.long_run_envelope_builder import build_from_raw_output

RUN_LOOP_SCHEMA_VERSION = "admissible_run_loop_v0"

AGENT_RESPONSE_SOURCE_TRUST = "unverified_agent_output"
AGENT_RESPONSE_ACTOR = "external_frontier_agent"
EVIDENCE_ACTOR_HUMAN_OPERATOR = "human_operator"

# -- human decision / action lifecycle statuses (v0) -------------------------

LIFECYCLE_NEEDS_HUMAN_INPUT = "needs_human_input"
LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION = "evidence_supplied_pending_reevaluation"
LIFECYCLE_APPROVAL_SUPPLIED_PENDING_REEVALUATION = "approval_supplied_pending_reevaluation"
LIFECYCLE_LIMITED_SCOPE_SELECTED = "limited_scope_selected"
LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION = "ready_for_next_agent_instruction"
LIFECYCLE_CLOSED = "closed"

LIFECYCLE_STATUSES = frozenset(
    {
        LIFECYCLE_NEEDS_HUMAN_INPUT,
        LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION,
        LIFECYCLE_APPROVAL_SUPPLIED_PENDING_REEVALUATION,
        LIFECYCLE_LIMITED_SCOPE_SELECTED,
        LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION,
        LIFECYCLE_CLOSED,
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
    """One piece of evidence a human operator supplied for one action."""

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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceRecord":
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RUN_LOOP_SCHEMA_VERSION,
            "current_turn": self.current_turn,
            "turns": [t.to_dict() for t in self.turns],
            "instruction_packets": [p.to_dict() for p in self.instruction_packets],
            "response_records": [r.to_dict() for r in self.response_records],
            "evidence_records": [e.to_dict() for e in self.evidence_records],
            "superseding_decisions": [s.to_dict() for s in self.superseding_decisions],
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


def _open_gates_summary(goal_intake: dict[str, Any], plan_audit: dict[str, Any]) -> list[str]:
    items: list[str] = []
    verdict = plan_audit.get("verdict")
    if verdict and verdict != "PLAN_OK_FOR_LOCAL_PROTOTYPE":
        items.append(f"Plan audit verdict: {verdict}.")
    for gate in plan_audit.get("required_gates") or []:
        items.append(f"Unresolved plan gate: {gate}.")
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
        if status == LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION:
            items.append(
                f"{item.get('action_id')}: evidence was already supplied by a human operator but "
                "could not be automatically re-evaluated in v0 (no full envelope on this action); "
                "still treat as blocked until a human confirms."
            )
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
        open_gates_summary=_open_gates_summary(goal_intake, plan_audit),
        queue_summary=_queue_summary(queue),
        packet_text="",
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
    evidence_type: str,
    evidence_text: str,
) -> dict[str, Any] | None:
    """Fold one supplied evidence item into a copy of `envelope` and re-run
    the unmodified rules-only evaluator.

    Returns the new decision dict, or None when no full schema envelope is
    available to reevaluate (e.g. actions loaded from a static trace file
    in v0 only carry the already-computed candidate/decision pair, not the
    full envelope) -- callers must fall back to marking the action pending
    reevaluation in that case. Never mutates the input envelope.
    """
    if not isinstance(envelope, dict):
        return None

    new_envelope = copy.deepcopy(envelope)
    evidence = new_envelope.setdefault("evidence", {})
    available = list(evidence.get("available") or [])
    available.append(
        {
            "type": evidence_type,
            "summary": evidence_text,
            "confidence": "human_provided",
        }
    )
    evidence["available"] = available
    evidence["missing"] = [
        item for item in (evidence.get("missing") or []) if evidence_type.lower() not in _note_text(item).lower()
    ]

    decision = evaluate_envelope(new_envelope)
    decision["operational_admissibility_action"] = operational_action_for_decision(
        decision["decision"], safer_next_step=decision.get("safer_next_step")
    )
    return decision


__all__ = [
    "AGENT_RESPONSE_ACTOR",
    "AGENT_RESPONSE_SOURCE_TRUST",
    "EVIDENCE_ACTOR_HUMAN_OPERATOR",
    "LIFECYCLE_APPROVAL_SUPPLIED_PENDING_REEVALUATION",
    "LIFECYCLE_CLOSED",
    "LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION",
    "LIFECYCLE_LIMITED_SCOPE_SELECTED",
    "LIFECYCLE_NEEDS_HUMAN_INPUT",
    "LIFECYCLE_READY_FOR_NEXT_AGENT_INSTRUCTION",
    "LIFECYCLE_STATUSES",
    "NON_EXECUTION_BOUNDARIES",
    "RUN_LOOP_SCHEMA_VERSION",
    "AgentInstructionPacket",
    "AgentResponseRecord",
    "EvidenceRecord",
    "RunLoopState",
    "RunTurn",
    "SupersedingAdmissionDecision",
    "build_candidates_from_agent_response",
    "default_lifecycle_status",
    "generate_instruction_packet",
    "operational_action_for_decision",
    "reevaluate_envelope_with_evidence",
]
