"""Admitted Execution Protocol v0 — attestation only, no automatic executor.

Records that admitted local ALLOW actions were executed externally after
admission. Does not run shell commands, call providers, or mutate workspaces.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

ATTESTATION_SCHEMA_VERSION = "admitted_execution_attestation_v0"

EXECUTION_STATUS_PROPOSED_ONLY = "proposed_only"
EXECUTION_STATUS_ADMITTED_NOT_EXECUTED = "admitted_not_executed"
EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION = "executed_after_admission"
EXECUTION_STATUS_BLOCKED = "blocked"

EXECUTION_STATUSES = frozenset(
    {
        EXECUTION_STATUS_PROPOSED_ONLY,
        EXECUTION_STATUS_ADMITTED_NOT_EXECUTED,
        EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION,
        EXECUTION_STATUS_BLOCKED,
    }
)

EXECUTION_ACTOR_HUMAN_OPERATOR = "human_operator"
EXECUTION_ACTOR_EXTERNAL_FRONTIER = "external_frontier_agent_after_admission"

EXECUTION_ACTORS = frozenset(
    {
        EXECUTION_ACTOR_HUMAN_OPERATOR,
        EXECUTION_ACTOR_EXTERNAL_FRONTIER,
    }
)

EXECUTION_SCOPE_LOCAL_WORKSPACE_ONLY = "local_workspace_only"

FORBIDDEN_EXECUTED_DECISIONS = frozenset(
    {
        "REQUEST_MORE_EVIDENCE",
        "REQUIRE_HUMAN_APPROVAL",
        "REFUSE",
        "ALLOW_WITH_LIMITS",
    }
)


class AdmittedExecutionValidationError(ValueError):
    """Raised when an execution attestation violates v0 protocol rules."""


def load_execution_attestation(path: str | Path) -> dict[str, Any]:
    """Load and minimally validate an execution attestation fixture."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AdmittedExecutionValidationError(
            f"{path}: invalid JSON execution attestation: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise AdmittedExecutionValidationError(
            f"{path}: execution attestation must be a JSON object"
        )
    if data.get("schema_version") != ATTESTATION_SCHEMA_VERSION:
        raise AdmittedExecutionValidationError(
            f"{path}: unsupported schema_version {data.get('schema_version')!r}; "
            f"expected {ATTESTATION_SCHEMA_VERSION!r}"
        )
    records = data.get("records")
    if not isinstance(records, list):
        raise AdmittedExecutionValidationError(f"{path}: records must be a list")
    return data


def _decision_by_action_id(trace: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {d["action_id"]: d for d in trace.get("decisions") or []}


def _candidate_by_action_id(trace: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {c["action_id"]: c for c in trace.get("action_candidates") or []}


def is_local_allow_without_missing_evidence(
    decision: dict[str, Any],
    candidate: dict[str, Any] | None = None,
) -> bool:
    """Return True when v0 permits admitted-not-executed or executed-after-admission."""
    if decision.get("decision") != "ALLOW":
        return False
    if decision.get("operational_admissibility_action") != "execute":
        return False
    if decision.get("risk_level") != "local":
        return False
    missing = decision.get("missing_evidence")
    if missing:
        return False
    if candidate is not None:
        blast = (decision.get("audit_trace") or {}).get("blast_radius") or ""
        if "blast_radius=local" not in blast:
            return False
    return True


def _validate_execution_basis(
    basis: Any,
    *,
    decision: dict[str, Any],
    action_id: str,
) -> None:
    if not isinstance(basis, dict):
        raise AdmittedExecutionValidationError(
            f"{action_id}: execution_basis must be an object"
        )
    decision_id = basis.get("decision_id")
    envelope_id = basis.get("envelope_id")
    if not decision_id and not envelope_id:
        raise AdmittedExecutionValidationError(
            f"{action_id}: execution_basis must include decision_id and/or envelope_id"
        )
    if decision_id and decision_id != decision.get("decision_id"):
        raise AdmittedExecutionValidationError(
            f"{action_id}: execution_basis.decision_id {decision_id!r} does not match "
            f"admission decision {decision.get('decision_id')!r}"
        )
    if envelope_id and envelope_id != decision.get("envelope_id"):
        raise AdmittedExecutionValidationError(
            f"{action_id}: execution_basis.envelope_id {envelope_id!r} does not match "
            f"admission envelope {decision.get('envelope_id')!r}"
        )


def validate_executed_after_admission_record(
    record: dict[str, Any],
    trace: dict[str, Any],
) -> None:
    """Validate that a record may mark an action executed_after_admission in v0."""
    action_id = record.get("action_id")
    if not action_id:
        raise AdmittedExecutionValidationError("record missing action_id")

    if record.get("execution_status") != EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION:
        raise AdmittedExecutionValidationError(
            f"{action_id}: validate_executed_after_admission_record requires "
            f"execution_status={EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION!r}"
        )

    decisions = _decision_by_action_id(trace)
    candidates = _candidate_by_action_id(trace)

    if action_id not in decisions:
        raise AdmittedExecutionValidationError(
            f"{action_id}: no admission decision in trace"
        )
    if action_id not in candidates:
        raise AdmittedExecutionValidationError(
            f"{action_id}: no action candidate in trace"
        )

    decision = decisions[action_id]
    candidate = candidates[action_id]
    decision_label = decision.get("decision")

    if decision_label in FORBIDDEN_EXECUTED_DECISIONS:
        raise AdmittedExecutionValidationError(
            f"{action_id}: decision {decision_label!r} cannot be marked "
            f"executed_after_admission in v0"
        )

    if not is_local_allow_without_missing_evidence(decision, candidate):
        raise AdmittedExecutionValidationError(
            f"{action_id}: only ALLOW local actions with operational execute and "
            f"no missing evidence may be executed_after_admission in v0"
        )

    actor = record.get("execution_actor")
    if actor not in EXECUTION_ACTORS:
        raise AdmittedExecutionValidationError(
            f"{action_id}: execution_actor must be one of {sorted(EXECUTION_ACTORS)}"
        )

    scope = record.get("execution_scope")
    if scope != EXECUTION_SCOPE_LOCAL_WORKSPACE_ONLY:
        raise AdmittedExecutionValidationError(
            f"{action_id}: execution_scope must be {EXECUTION_SCOPE_LOCAL_WORKSPACE_ONLY!r}"
        )

    if not record.get("execution_timestamp"):
        raise AdmittedExecutionValidationError(
            f"{action_id}: execution_timestamp is required"
        )

    _validate_execution_basis(record.get("execution_basis"), decision=decision, action_id=action_id)
    validate_execution_evidence_traceability(record, candidate)


def _significant_terms_from_tool_or_command(tool_or_command: str) -> list[str]:
    terms: list[str] = []
    for part in re.split(r"[\s/.,;:()]+", tool_or_command.lower()):
        part = part.strip()
        if not part:
            continue
        if part.startswith(".") or "." in part:
            terms.append(part)
        elif len(part) >= 4:
            terms.append(part)
    return terms


def validate_execution_evidence_traceability(
    record: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    """Require execution evidence to refer to the same operation as the action candidate."""
    action_id = record.get("action_id") or candidate.get("action_id") or "?"
    tool_or_command = str(candidate.get("tool_or_command") or "")
    terms = _significant_terms_from_tool_or_command(tool_or_command)
    if not terms:
        return

    evidence = record.get("execution_evidence") or {}
    evidence_text = " ".join(
        str(evidence.get(key) or "") for key in ("notes", "verification")
    ).lower()

    matched = sum(1 for term in terms if term in evidence_text)
    required_matches = min(2, len(terms))
    if matched < required_matches:
        raise AdmittedExecutionValidationError(
            f"{action_id}: execution evidence does not trace to action candidate "
            f"{tool_or_command!r} (matched {matched}/{len(terms)} significant terms)"
        )


def validate_attestation_fixture(
    attestation: dict[str, Any],
    trace: dict[str, Any],
) -> None:
    """Validate all records in an attestation fixture against a truth trace."""
    records = attestation.get("records") or []
    seen_action_ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise AdmittedExecutionValidationError("each record must be an object")
        action_id = record.get("action_id")
        if not action_id:
            raise AdmittedExecutionValidationError("record missing action_id")
        if action_id in seen_action_ids:
            raise AdmittedExecutionValidationError(
                f"{action_id}: duplicate attestation record"
            )
        seen_action_ids.add(action_id)

        status = record.get("execution_status")
        if status not in EXECUTION_STATUSES:
            raise AdmittedExecutionValidationError(
                f"{action_id}: invalid execution_status {status!r}"
            )
        if status == EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION:
            validate_executed_after_admission_record(record, trace)


def _build_execution_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "execution_status": record["execution_status"],
        "execution_basis": copy.deepcopy(record.get("execution_basis") or {}),
        "execution_actor": record.get("execution_actor"),
        "execution_evidence": copy.deepcopy(record.get("execution_evidence") or {}),
        "execution_scope": record.get("execution_scope"),
        "execution_timestamp": record.get("execution_timestamp"),
    }


def _append_execution_log_event(
    execution_log: list[dict[str, Any]],
    *,
    action_id: str,
    event: str,
    decision: dict[str, Any],
    record: dict[str, Any] | None = None,
    step_id: str | None = None,
) -> None:
    entry: dict[str, Any] = {
        "action_id": action_id,
        "step_id": step_id,
        "event": event,
        "decision": decision.get("decision"),
        "operational_admissibility_action": decision.get("operational_admissibility_action"),
        "side_effect_executed": False,
        "attested_external_execution": event == "executed_after_admission",
        "timestamp": (record or {}).get("execution_timestamp")
        or decision.get("timestamp"),
    }
    if record is not None:
        entry["execution_basis"] = copy.deepcopy(record.get("execution_basis") or {})
        entry["execution_actor"] = record.get("execution_actor")
        entry["execution_evidence"] = copy.deepcopy(record.get("execution_evidence") or {})
        entry["execution_scope"] = record.get("execution_scope")
        entry["execution_timestamp"] = record.get("execution_timestamp")
    execution_log.append(entry)


def apply_execution_attestations(
    trace: dict[str, Any],
    attestation: dict[str, Any],
) -> dict[str, Any]:
    """Return a new trace with execution statuses and log events from attestations.

    Does not execute anything. Trace root side_effect_executed remains false.
    """
    validate_attestation_fixture(attestation, trace)

    updated = copy.deepcopy(trace)
    decisions = _decision_by_action_id(updated)
    candidates_by_id = {c["action_id"]: c for c in updated.get("action_candidates") or []}
    execution_log: list[dict[str, Any]] = list(updated.get("execution_log") or [])

    executed_action_ids: set[str] = set()
    for record in attestation.get("records") or []:
        action_id = record["action_id"]
        status = record.get("execution_status")
        if status != EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION:
            continue
        validate_executed_after_admission_record(record, updated)
        executed_action_ids.add(action_id)

        candidate = candidates_by_id[action_id]
        decision = decisions[action_id]
        candidate["execution_status"] = EXECUTION_STATUS_EXECUTED_AFTER_ADMISSION
        candidate["execution_record"] = _build_execution_record(record)

        _append_execution_log_event(
            execution_log,
            action_id=action_id,
            event="executed_after_admission",
            decision=decision,
            record=record,
            step_id=candidate.get("proposed_by_step_id"),
        )

    for action_id, decision in decisions.items():
        candidate = candidates_by_id.get(action_id)
        if candidate is None:
            continue
        if action_id in executed_action_ids:
            continue
        if is_local_allow_without_missing_evidence(decision, candidate):
            candidate["execution_status"] = EXECUTION_STATUS_ADMITTED_NOT_EXECUTED
            _append_execution_log_event(
                execution_log,
                action_id=action_id,
                event="admitted_not_executed",
                decision=decision,
                step_id=candidate.get("proposed_by_step_id"),
            )

    updated["execution_log"] = execution_log
    updated["side_effect_executed"] = False
    updated["execution_attestation"] = {
        "schema_version": attestation.get("schema_version"),
        "attestation_note": attestation.get("attestation_note"),
        "applied_record_count": len(attestation.get("records") or []),
        "executed_after_admission_count": len(executed_action_ids),
    }
    return updated
