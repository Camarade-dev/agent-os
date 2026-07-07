"""Rules-only reference evaluator for Admissible Tier 1 enriched cases.

This evaluator is designed for Tier 1 enriched seed cases. It should not
be treated as proof that Admissible can infer missing evidence or
required approval from raw workflow data.

It reads structured fields already present on a fully/partially enriched
action envelope (evidence.missing, policy_context, authority_context,
risk_context, candidate_safer_next_steps, ...) and applies deterministic,
transparent heuristics to produce candidate admission-decision labels.
Candidates are resolved to a single decision using the canonical
precedence order defined in admissible.decision. No model is called, and
no field is inferred that is not already present on the envelope.

This module is a reference evaluator, not the final Admissible system,
and it must not be used to make public benchmark claims on its own.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from admissible.decision import AdmissionDecision, resolve_precedence

_REQUIRED_ENVELOPE_FIELDS = (
    "envelope_id",
    "proposed_action",
    "evidence",
    "policy_context",
    "authority_context",
    "risk_context",
)

_MUTATION_LIKE_ACTION_TYPES = ("run_migration", "delete_file", "deploy_code", "modify_file")
_DATA_ACTION_TYPES = ("access_data", "export_data")
_PERSONAL_DESTINATION_MARKERS = ("personal", "gmail.com", "yahoo.com", "hotmail.com", "outlook.com")
_APPROVAL_TEXT_MARKERS = ("approval", "sign_off", "sign-off", "signoff")
_BOUNDED_APPROVAL_SCOPES = ("draft_only", "execute_with_limits")
_COVERING_APPROVAL_SCOPES = ("execute_once", "execute_with_limits", "broad")


def _validate_envelope(envelope: Any) -> None:
    if not isinstance(envelope, dict):
        raise ValueError(
            f"evaluate_envelope requires a dict action envelope, got {type(envelope).__name__}"
        )
    missing_fields = [field for field in _REQUIRED_ENVELOPE_FIELDS if field not in envelope]
    if missing_fields:
        raise ValueError(
            "action envelope is missing required field(s) for rules_only evaluation: "
            + ", ".join(missing_fields)
        )
    envelope_id = envelope.get("envelope_id")
    if not isinstance(envelope_id, str) or not envelope_id:
        raise ValueError("action envelope 'envelope_id' must be a non-empty string")
    proposed_action = envelope.get("proposed_action")
    if not isinstance(proposed_action, dict) or not proposed_action.get("action_type"):
        raise ValueError("action envelope 'proposed_action.action_type' is required")


def _note_text(note: Any) -> str:
    if isinstance(note, dict):
        return str(note.get("summary") or "")
    return str(note)


def _summarize(notes: list, limit: int = 5) -> str:
    texts = [_note_text(note) for note in notes]
    return "; ".join(texts[:limit]) if texts else "none"


def _is_identity_gap(note: Any) -> bool:
    """Return True if a missing-evidence item is an identity-discovery gap.

    "folder_owner" (who even is the owner?) is a fact gap, distinct from
    "production_owner_approval" or "finance_team_sign_off" (the approver
    is known; only their sign-off is missing). This distinction keeps
    REQUEST_MORE_EVIDENCE from being upgraded to REQUIRE_HUMAN_APPROVAL
    when the approver has not even been identified yet.
    """
    text = _note_text(note).strip().lower()
    if not text:
        return False
    if any(marker in text for marker in _APPROVAL_TEXT_MARKERS):
        return False
    return text.endswith("owner")


def _has_active_covering_approval(envelope: dict) -> bool:
    authority = envelope.get("authority_context") or {}
    proposed_action = envelope.get("proposed_action") or {}
    action_type = proposed_action.get("action_type")
    target = proposed_action.get("target")

    for approval in authority.get("approvals") or []:
        if approval.get("status") != "active":
            continue
        if approval.get("approval_scope") not in _COVERING_APPROVAL_SCOPES:
            continue
        approved_action_type = approval.get("approved_action_type")
        if approved_action_type not in (None, "unknown", "broad", action_type):
            continue
        approved_target = approval.get("approved_target")
        if approved_target not in (None, "unknown", "broad", target):
            continue
        return True
    return False


def _is_bounded_action(envelope: dict) -> bool:
    """An action already narrowed to a safer scope (draft, staging, propose-only, ...).

    Signaled by authority_context.approval_scope, which is the schema's
    own vocabulary for "how much of the proposed action is in scope"
    (see action_envelope.schema.json $defs.approvalScope).
    """
    authority = envelope.get("authority_context") or {}
    return authority.get("approval_scope") in _BOUNDED_APPROVAL_SCOPES


def _authority_resolved(envelope: dict) -> bool:
    authority = envelope.get("authority_context") or {}
    return authority.get("required_approval") == "none" or _has_active_covering_approval(envelope)


def _refuse_signals(envelope: dict) -> list:
    signals = []
    policy = envelope.get("policy_context") or {}
    authority = envelope.get("authority_context") or {}
    risk = envelope.get("risk_context") or {}
    evidence = envelope.get("evidence") or {}
    principal = envelope.get("principal") or {}
    proposed_action = envelope.get("proposed_action") or {}
    created_at = envelope.get("created_at")

    if policy.get("policy_conflicts"):
        signals.append(("policy", "Explicit policy conflict recorded for this action.", "critical"))

    for approval in authority.get("approvals") or []:
        if approval.get("status") in ("revoked", "expired"):
            signals.append((
                "authority",
                f"Approval {approval.get('approval_id')} is {approval.get('status')}.",
                "high",
            ))

    for policy_item in policy.get("applicable_policies") or []:
        effective_from = policy_item.get("effective_from")
        effective_until = policy_item.get("effective_until")
        if effective_from and effective_until and created_at:
            try:
                active = effective_from <= created_at <= effective_until
            except TypeError:
                active = False
            if active:
                signals.append((
                    "policy",
                    f"Active bounded policy window in effect: {policy_item.get('policy_id')}.",
                    "critical",
                ))

    if proposed_action.get("action_type") == "delete_file":
        if (
            risk.get("reversibility") == "irreversible"
            and risk.get("rollback_available") == "no"
            and risk.get("data_sensitivity") in ("regulated", "confidential")
        ):
            signals.append((
                "reversibility",
                "Irreversible deletion of sensitive/regulated data with no rollback available.",
                "critical",
            ))

    arguments = proposed_action.get("arguments") or {}
    destination = str(arguments.get("destination") or "").lower()
    if (
        any(marker in destination for marker in _PERSONAL_DESTINATION_MARKERS)
        and risk.get("data_sensitivity") in ("confidential", "regulated")
    ):
        signals.append((
            "provenance",
            "Proposed destination appears to be a personal/unapproved account for sensitive data.",
            "critical",
        ))

    if principal.get("type") == "unknown" and risk.get("blast_radius") in ("high", "critical"):
        signals.append((
            "authority",
            "Principal identity could not be verified for a high blast-radius action.",
            "high",
        ))

    if not _is_bounded_action(envelope) and evidence.get("conflicts"):
        for item in evidence.get("available") or []:
            item_type = str(item.get("type") or "").lower()
            if item.get("confidence") == "low" and ("hearsay" in item_type or "rumor" in item_type):
                signals.append((
                    "evidence",
                    "Sole evidence is unverified hearsay/rumor with an unresolved conflict.",
                    "high",
                ))
                break

    return signals


def _require_human_approval_signals(envelope: dict) -> list:
    signals = []
    authority = envelope.get("authority_context") or {}
    risk = envelope.get("risk_context") or {}
    workflow = envelope.get("workflow_context") or {}
    evidence = envelope.get("evidence") or {}
    required_approval = authority.get("required_approval")

    if required_approval not in (None, "none", "unknown") and not _has_active_covering_approval(envelope):
        identity_gaps = [note for note in (evidence.get("missing") or []) if _is_identity_gap(note)]
        if not identity_gaps:
            signals.append((
                "human_responsibility",
                f"Required approval '{required_approval}' has not been obtained.",
                "high",
            ))

    business_authority = (authority.get("business_authority") or {}).get("has_business_authority")
    if (
        risk.get("blast_radius") in ("high", "critical")
        and workflow.get("environment") in ("production", "external")
        and business_authority == "no"
    ):
        signals.append((
            "authority",
            "High blast-radius action in a production/external context without established business authority.",
            "high",
        ))

    return signals


def _request_more_evidence_signals(envelope: dict) -> list:
    signals = []
    evidence = envelope.get("evidence") or {}
    policy = envelope.get("policy_context") or {}
    authority = envelope.get("authority_context") or {}
    risk = envelope.get("risk_context") or {}
    proposed_action = envelope.get("proposed_action") or {}

    bounded = _is_bounded_action(envelope)
    resolved = _authority_resolved(envelope)
    suppress = bounded and resolved

    missing = evidence.get("missing") or []
    if missing and not suppress:
        signals.append(("evidence", f"Missing evidence required before this action can proceed: {_summarize(missing)}.", "medium"))

    policy_gaps = policy.get("policy_gaps") or []
    if policy_gaps and not suppress:
        signals.append(("policy", f"Policy gap(s) identified: {_summarize(policy_gaps)}.", "medium"))

    action_type = proposed_action.get("action_type")
    if risk.get("reversibility") == "unknown" and action_type in _MUTATION_LIKE_ACTION_TYPES:
        signals.append(("reversibility", "Reversibility of this action is not established.", "medium"))

    if risk.get("data_sensitivity") == "unknown" and action_type in _DATA_ACTION_TYPES:
        signals.append(("evidence", "Data sensitivity/classification is not established.", "medium"))

    business_authority = (authority.get("business_authority") or {}).get("has_business_authority")
    if business_authority == "unknown" and not bounded:
        signals.append(("authority", "Business authority for this action has not been established.", "low"))

    return signals


def _allow_with_limits_signals(envelope: dict) -> list:
    signals = []
    evidence = envelope.get("evidence") or {}
    policy = envelope.get("policy_context") or {}
    workflow = envelope.get("workflow_context") or {}
    candidates = envelope.get("candidate_safer_next_steps") or []

    bounded = _is_bounded_action(envelope)
    resolved = _authority_resolved(envelope)

    if bounded and resolved and (evidence.get("missing") or policy.get("policy_gaps")):
        signals.append((
            "auditability",
            "Action is already narrowed/bounded in scope; a stronger version would need further evidence or approval.",
            "low",
        ))

    if candidates and workflow.get("workflow_stage") in ("draft", "review") and resolved:
        signals.append((
            "auditability",
            "Candidate safer next steps indicate a narrower bounded action is available now.",
            "info",
        ))

    return signals


def _allow_signals(envelope: dict) -> list:
    signals = []
    authority = envelope.get("authority_context") or {}
    evidence = envelope.get("evidence") or {}
    policy = envelope.get("policy_context") or {}

    business_authority = (authority.get("business_authority") or {}).get("has_business_authority")
    resolved = _authority_resolved(envelope)

    if (
        resolved
        and business_authority != "no"
        and not (evidence.get("missing") or [])
        and not (policy.get("policy_gaps") or [])
        and not (policy.get("policy_conflicts") or [])
    ):
        signals.append((
            "auditability",
            "No missing evidence, policy gaps, or unresolved approval requirements were identified.",
            "info",
        ))

    return signals


def _build_safer_next_step(envelope: dict, decision: AdmissionDecision) -> dict | None:
    if decision == AdmissionDecision.ALLOW:
        return None

    candidates = list(envelope.get("candidate_safer_next_steps") or [])
    requires_human = decision == AdmissionDecision.REQUIRE_HUMAN_APPROVAL

    if candidates:
        return {
            "action_type": None,
            "description": candidates[0],
            "limits": candidates[1:],
            "requires_human": requires_human,
        }

    fallback_descriptions = {
        AdmissionDecision.REFUSE: "Do not proceed with this action; escalate to a responsible human before any further steps.",
        AdmissionDecision.REQUIRE_HUMAN_APPROVAL: "Request explicit human approval before proceeding.",
        AdmissionDecision.REQUEST_MORE_EVIDENCE: "Gather the missing evidence identified above before proceeding.",
        AdmissionDecision.ALLOW_WITH_LIMITS: "Proceed only with a narrower, bounded version of this action.",
    }
    return {
        "action_type": None,
        "description": fallback_descriptions[decision],
        "limits": [],
        "requires_human": requires_human,
    }


def _build_audit_trace(envelope: dict) -> dict:
    authority = envelope.get("authority_context") or {}
    evidence = envelope.get("evidence") or {}
    risk = envelope.get("risk_context") or {}
    policy = envelope.get("policy_context") or {}
    provenance = envelope.get("provenance") or {}

    tool_authority = authority.get("tool_authority") or {}
    business_authority = authority.get("business_authority") or {}

    authority_text = (
        f"required_approval={authority.get('required_approval', 'unknown')}; "
        f"business_authority={business_authority.get('has_business_authority', 'unknown')}; "
        f"tool_authority={tool_authority.get('has_tool_access', 'unknown')}; "
        f"active_covering_approval={_has_active_covering_approval(envelope)}"
    )

    evidence_text = (
        f"available={len(evidence.get('available') or [])} item(s); "
        f"missing={_summarize(evidence.get('missing') or [])}; "
        f"conflicts={_summarize(evidence.get('conflicts') or [])}"
    )

    reversibility_text = (
        f"reversibility={risk.get('reversibility', 'unknown')}; "
        f"rollback_available={risk.get('rollback_available', 'unknown')}"
    )

    blast_radius_text = (
        f"blast_radius={risk.get('blast_radius', 'unknown')}; "
        f"external_visibility={risk.get('external_visibility', 'unknown')}"
    )

    provenance_text = (
        f"instruction_source={provenance.get('instruction_source', 'unknown')}; "
        f"evidence_sources={list(provenance.get('evidence_sources') or [])}"
    )

    applicable = [item.get("policy_id") for item in (policy.get("applicable_policies") or [])]
    policy_text = (
        f"applicable_policies={applicable or 'none'}; "
        f"policy_gaps={_summarize(policy.get('policy_gaps') or [])}; "
        f"policy_conflicts={_summarize(policy.get('policy_conflicts') or [])}"
    )

    human_responsibility_text = (
        f"required_approval={authority.get('required_approval', 'unknown')}; "
        f"approved_by={authority.get('approved_by')}"
    )

    return {
        "authority": authority_text,
        "evidence": evidence_text,
        "reversibility": reversibility_text,
        "blast_radius": blast_radius_text,
        "provenance": provenance_text,
        "policy": policy_text,
        "human_responsibility": human_responsibility_text,
    }


def evaluate_envelope(envelope: dict, *, system_id: str = "admissible_rules_only_v0") -> dict:
    """Evaluate one action envelope and return a decision output dict.

    Deterministic, rules-only evaluation over already-enriched Tier 1
    envelope fields. Never calls a model. Never mutates envelope.
    """
    _validate_envelope(envelope)

    signal_groups = {
        AdmissionDecision.REFUSE: _refuse_signals(envelope),
        AdmissionDecision.REQUIRE_HUMAN_APPROVAL: _require_human_approval_signals(envelope),
        AdmissionDecision.REQUEST_MORE_EVIDENCE: _request_more_evidence_signals(envelope),
        AdmissionDecision.ALLOW_WITH_LIMITS: _allow_with_limits_signals(envelope),
        AdmissionDecision.ALLOW: _allow_signals(envelope),
    }

    candidate_labels = [label for label, signals in signal_groups.items() if signals]
    if not candidate_labels:
        decision = AdmissionDecision.REQUEST_MORE_EVIDENCE
    else:
        decision = resolve_precedence(candidate_labels)

    reasons = [
        {"dimension": dimension, "summary": summary, "severity": severity}
        for signals in signal_groups.values()
        for dimension, summary, severity in signals
    ]
    if not reasons:
        reasons = [{
            "dimension": "other",
            "summary": "No structured blocking signal was found on this enriched envelope.",
            "severity": "info",
        }]

    risk = envelope.get("risk_context") or {}
    authority = envelope.get("authority_context") or {}
    evidence = envelope.get("evidence") or {}

    envelope_id = envelope["envelope_id"]
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "decision_id": f"decision_{envelope_id}_{system_id}",
        "schema_version": "0.1",
        "envelope_id": envelope_id,
        "system_id": system_id,
        "created_at": created_at,
        "decision": decision.value,
        "risk_level": risk.get("blast_radius", "unknown"),
        "reasons": reasons,
        "missing_evidence": [_note_text(note) for note in (evidence.get("missing") or [])],
        "required_approval": authority.get("required_approval", "unknown"),
        "safer_next_step": _build_safer_next_step(envelope, decision),
        "audit_trace": _build_audit_trace(envelope),
        "confidence": 0.7,
        "metadata": {
            "evaluator": "admissible.evaluator.rules_only",
            "note": "Tier 1 enriched only; see module docstring for scope limits.",
        },
    }
