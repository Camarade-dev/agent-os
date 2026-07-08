"""Rule-based envelope builder for long-run Cursor-class agent output (v0).

Parses a narrow set of deterministic action patterns from raw terminal/agent
transcripts and produces action candidates plus schema-shaped envelopes suitable
for rules_only evaluation. No provider calls, no command execution, no agent_os.

See docs/admissible-cursor-long-run-composition.md for the cross-layer contract.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BUILDER_VERSION = "0.2"
BUILDER_CLAIM_BOUNDARY = (
    "Offline rule-based extraction only; raw agent output is unverified."
)
EXTRACTION_METHOD = "rule_based_v0"
DEFAULT_SOURCE_TYPE = "fixture"
DEFAULT_SOURCE_TRUST = "unverified_agent_output"
DEFAULT_EXECUTION_STATUS = "proposed_only"

_USER_LINE_RE = re.compile(r"^User:\s*(.+)$", re.MULTILINE)
_TOOL_CALL_RE = re.compile(
    r"Proposed tool call:\s*\n\s*([\w.-]+)\(\s*(\{[\s\S]*?\})\s*\)",
    re.MULTILINE,
)
_SHELL_COMMAND_RE = re.compile(
    r"(?:Proposed (?:command|shell call)|Command):\s*\n\s*(.+?)(?:\n\n|\nStatus:|\Z)",
    re.MULTILINE | re.IGNORECASE,
)
_NOTE_LINES_RE = re.compile(r"^Note:\s*(.+)$", re.MULTILINE)

_ACTION_PATTERNS: tuple[tuple[re.Pattern[str], str, str, str], ...] = (
    (re.compile(r"deploy\.production|deploy\s+to\s+production", re.I), "deploy_code", "deployment", "REQUIRE_HUMAN_APPROVAL"),
    (re.compile(r"prepare\s+(?:a\s+)?deployment|prepare_deploy", re.I), "prepare_deploy", "deployment", "REQUIRE_HUMAN_APPROVAL"),
    (re.compile(r"\bnpm\s+install\b|\bpip\s+install\b|\bpnpm\s+add\b|\byarn\s+add\b", re.I), "install_dependency", "code_change", "REQUEST_MORE_EVIDENCE"),
    (re.compile(r"drive\.delete|\bpermanent(?:ly)?\s+delet", re.I), "delete_file", "data_mutation", "ALLOW_WITH_LIMITS"),
    (re.compile(r"\bdelete\s+(?:the\s+)?(?:old\s+)?(?:client\s+)?folder\b", re.I), "delete_folder", "data_mutation", "ALLOW_WITH_LIMITS"),
    (re.compile(r"\brm\s+-rf\b|\bunlink\s*\(", re.I), "delete_file", "data_mutation", "REQUIRE_HUMAN_APPROVAL"),
    (re.compile(r"\bgit\s+push\b", re.I), "git_push", "code_change", "REQUIRE_HUMAN_APPROVAL"),
    (re.compile(r"\bgit\s+commit\b", re.I), "git_commit", "code_change", "REQUEST_MORE_EVIDENCE"),
    (re.compile(r"\bedit_file\b|\bwrite\s+(?:to\s+)?(?:file|local)\b|\bStrReplace\b|\bsafe\s+local\s+(?:file\s+)?edit", re.I), "edit_file", "code_change", "ALLOW"),
)

_PRODUCTION_READINESS_MARKER_RE = re.compile(
    r"proposed operations|production[- ]readiness assessment",
    re.I,
)
_TABLE_ROW_RE = re.compile(
    r"^\|\s*(\d+[a-z]?)\s*\|\s*(.+?)\s*\|\s*.+?\s*\|$",
    re.MULTILINE,
)
_PHASE_HEADING_RE = re.compile(
    r"^###\s+Phase\s+\d+[^—\n]*(?:—\s*(.+?))?\s*$",
    re.MULTILINE,
)
_NEGATIVE_SECTION_RE = re.compile(
    r"##\s+What I would\s+\*?\*?not\*?\*?\s+do yet[\s\S]*?(?=\n##\s|\Z)",
    re.I,
)

_DEFAULT_MISSING_EVIDENCE: dict[str, list[str]] = {
    "deploy_code": ["rollback_plan", "production_owner_approval", "integration_test_results"],
    "prepare_deploy": ["rollback_plan", "production_owner_approval", "deployment_checklist"],
    "install_dependency": ["package_trust_review", "license_compatibility", "dependency_lockfile_review"],
    "delete_file": ["folder_owner_sign_off"],
    "delete_folder": ["folder_owner_sign_off"],
    "git_push": ["branch_protection_review", "remote_push_approval", "ci_status"],
    "git_commit": ["diff_review", "test_results"],
    "claim_status": ["build_verification", "manual_test_results", "deployment_readiness_check"],
    "edit_file": [],
    "local_code_change": [],
    "create_file": [],
    "document_hosting_options": ["hosting_choice_authorization"],
    "verification_plan": ["test_results", "manual_test_results"],
    "unknown": ["action_classification", "side_effect_scope"],
}

_ARCHIVE_HINT_RE = re.compile(r"archive|reversible|pending[- ]deletion", re.I)
_APPROVAL_HINT_RE = re.compile(r"owner\s+sign[- ]?off|approval|rollback", re.I)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha12(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def _extract_user_request(raw_output: str) -> str | None:
    match = _USER_LINE_RE.search(raw_output)
    return match.group(1).strip() if match else None


def _extract_tool_call(raw_output: str) -> tuple[str | None, dict[str, Any]]:
    match = _TOOL_CALL_RE.search(raw_output)
    if not match:
        return None, {}
    tool = match.group(1).strip()
    args_text = match.group(2).strip()
    try:
        args = json.loads(args_text)
    except json.JSONDecodeError:
        args = {"raw_arguments": args_text}
    if not isinstance(args, dict):
        args = {"value": args}
    return tool, args


def _extract_shell_command(raw_output: str) -> str | None:
    match = _SHELL_COMMAND_RE.search(raw_output)
    return match.group(1).strip() if match else None


def _extract_notes(raw_output: str) -> list[str]:
    return [line.strip() for line in _NOTE_LINES_RE.findall(raw_output) if line.strip()]


def _is_production_readiness_report(raw_output: str) -> bool:
    return bool(_PRODUCTION_READINESS_MARKER_RE.search(raw_output))


def _strip_negative_sections(text: str) -> str:
    return _NEGATIVE_SECTION_RE.sub("", text)


def _has_positive_production_ready_claim(text: str) -> bool:
    if re.search(r"not\s+(?:yet\s+)?production[- ]ready", text, re.I):
        return False
    if re.search(
        r"(?:is|are|status:\s*)ready\b|ready\s+for\s+production|production[- ]ready\s+as",
        text,
        re.I,
    ):
        return True
    if re.search(r"tests\s+pass(?:ed)?(?:\s+and\s+ready)?", text, re.I):
        return True
    return False


def _extract_production_readiness_operations(raw_output: str) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    current_phase: str | None = None
    for line in raw_output.splitlines():
        phase_match = _PHASE_HEADING_RE.match(line)
        if phase_match:
            current_phase = (
                phase_match.group(1).strip()
                if phase_match.group(1)
                else line.strip("# ").strip()
            )
            continue
        row_match = _TABLE_ROW_RE.match(line)
        if not row_match:
            continue
        row_id, op_cell = row_match.group(1), row_match.group(2).strip()
        if row_id == "#" or op_cell.startswith("---"):
            continue
        if re.fullmatch(r"operation", op_cell, re.I):
            continue
        op_text = re.sub(r"\*\*", "", op_cell)
        op_text = re.sub(r"`([^`]+)`", r"\1", op_text)
        op_text = re.sub(r"\s*—\s*.+$", "", op_text).strip()
        if not op_text:
            continue
        operations.append(
            {
                "row_id": row_id,
                "phase": current_phase,
                "operation_text": op_text,
            }
        )
    return operations


def _extract_assessment_claims(raw_output: str) -> list[dict[str, str]]:
    claims: list[dict[str, str]] = []
    if re.search(r"not\s+(?:yet\s+)?production[- ]ready", raw_output, re.I):
        claims.append(
            {
                "claim_text": "Assessment: not production-ready",
                "claim_kind": "negative_readiness",
            }
        )
    if re.search(r"ready to commit\s*/\s*host", raw_output, re.I):
        claims.append(
            {
                "claim_text": "Conditional readiness: ready to commit/host",
                "claim_kind": "conditional_readiness",
            }
        )
    return claims


def _operation_tool_label(operation_text: str, action_type: str) -> str:
    compact = re.sub(r"\s+", " ", operation_text).strip()
    if action_type == "install_dependency":
        if re.search(r"vitest|jest", compact, re.I):
            return "dev test tooling (Vitest/Jest)"
        if re.search(r"eslint", compact, re.I):
            return "dev lint tooling (ESLint)"
        return "install dev dependencies"
    if len(compact) > 72:
        return compact[:69] + "..."
    return compact


def _classify_proposed_operation(
    operation_text: str,
    *,
    phase: str | None,
) -> tuple[str, str, str, str] | None:
    text = operation_text.lower()
    phase_l = (phase or "").lower()

    if re.search(
        r"\bnpm\s+install\b|installing dev dependencies|dev-only tooling|\bvitest\b|\bjest\b|\beslint\b",
        text,
        re.I,
    ):
        return ("install_dependency", "code_change", "REQUEST_MORE_EVIDENCE", "medium")

    if re.search(r"\bdeploy\b", text, re.I) and not re.search(
        r"without deploy|no deploy|not deploy", text, re.I
    ):
        return ("deploy_code", "deployment", "REQUIRE_HUMAN_APPROVAL", "high")
    if re.search(r"\bgit\s+push\b", text, re.I):
        return ("git_push", "code_change", "REQUIRE_HUMAN_APPROVAL", "high")
    if re.search(r"\bgit\s+commit\b", text, re.I):
        return ("git_commit", "code_change", "REQUEST_MORE_EVIDENCE", "medium")

    if re.search(
        r"github pages|netlify|\bs3\b|hosting options|document static hosting|404\.html",
        text,
        re.I,
    ):
        return ("document_hosting_options", "code_change", "ALLOW_WITH_LIMITS", "medium")

    if re.search(r"manual test checklist", text, re.I):
        return ("verification_plan", "internal_state_change", "ALLOW_WITH_LIMITS", "medium")
    if re.search(
        r"test strategy|automated test|smoke-test|smoke test|test runner",
        text,
        re.I,
    ):
        return ("verification_plan", "internal_state_change", "REQUEST_MORE_EVIDENCE", "medium")

    if re.search(r"\blicense\b", text, re.I):
        return ("create_file", "code_change", "REQUEST_MORE_EVIDENCE", "medium")

    if re.search(r"\.gitignore|readme\.md|contributing|development section", text, re.I):
        return ("create_file", "code_change", "ALLOW", "high")

    if re.search(r"ci workflow|validation script|cache-busting", text, re.I):
        return ("create_file", "code_change", "ALLOW_WITH_LIMITS", "medium")

    if "accessibility" in phase_l or re.search(
        r"tabindex|aria-|role=|focus style|reduced.motion|touch control|pause state",
        text,
        re.I,
    ):
        return ("local_code_change", "code_change", "ALLOW_WITH_LIMITS", "high")

    return ("local_code_change", "code_change", "ALLOW", "high")


def _infer_target(tool: str | None, args: dict[str, Any], shell_command: str | None) -> str | None:
    for key in ("path", "target", "service", "environment", "file", "package"):
        value = args.get(key)
        if isinstance(value, str) and value:
            return value
    if shell_command:
        return shell_command.split()[0] if shell_command.split() else shell_command
    return tool


def _classify_action(
    raw_output: str,
    *,
    tool: str | None,
    shell_command: str | None,
    user_request: str | None,
) -> tuple[str, str, str, str]:
    haystack = _strip_negative_sections(
        "\n".join(
            part
            for part in (raw_output, tool or "", shell_command or "", user_request or "")
            if part
        )
    )
    for pattern, action_type, side_effect_type, tendency in _ACTION_PATTERNS:
        if pattern.search(haystack):
            return action_type, side_effect_type, tendency, "high"
    if _has_positive_production_ready_claim(haystack):
        return "claim_status", "internal_state_change", "REQUEST_MORE_EVIDENCE", "medium"
    if tool or shell_command:
        return "unknown", "unknown", "REQUEST_MORE_EVIDENCE", "low"
    return "unknown", "unknown", "REQUEST_MORE_EVIDENCE", "low"


def _missing_evidence_for_action(
    action_type: str,
    notes: list[str],
) -> list[str]:
    missing = list(_DEFAULT_MISSING_EVIDENCE.get(action_type, _DEFAULT_MISSING_EVIDENCE["unknown"]))
    note_text = " ".join(notes).lower()
    if action_type in ("delete_file", "delete_folder"):
        if "owner" in note_text and "folder_owner_sign_off" not in missing:
            missing.append("folder_owner_sign_off")
    if action_type in ("deploy_code", "prepare_deploy"):
        if "rollback" in note_text and "rollback_plan" not in missing:
            missing.append("rollback_plan")
        if "owner" in note_text and "production_owner_approval" not in missing:
            missing.append("production_owner_approval")
    deduped: list[str] = []
    for item in missing:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _safer_next_steps(action_type: str, target: str | None, notes: list[str]) -> list[str]:
    if action_type not in ("delete_file", "delete_folder"):
        if action_type in ("deploy_code", "prepare_deploy"):
            return [
                "Prepare a deployment checklist.",
                "Request production owner approval.",
                "Create a rollback plan.",
            ]
        return []
    archive_hint = any(_ARCHIVE_HINT_RE.search(note) for note in notes)
    if not archive_hint and not target:
        return ["Identify owner and obtain sign-off before permanent deletion."]
    archive_target = (
        f"/Projects/Archive/_pending_deletion/{target.lstrip('/')}"
        if target
        else "/Projects/Archive/_pending_deletion/"
    )
    return [
        f"Move target to {archive_target} instead of permanent deletion.",
        "Identify the folder owner and obtain sign-off before permanent deletion.",
    ]


def _field_provenance(
    *,
    user_request: str | None,
    tool: str | None,
    args: dict[str, Any],
    notes: list[str],
    missing_evidence: list[str],
) -> dict[str, list[str]]:
    observed: list[str] = []
    if user_request:
        observed.append("user_request.raw")
    if tool:
        observed.append("proposed_action.tool")
    if args:
        observed.append("proposed_action.arguments")
    if notes:
        observed.extend(f"note:{idx}" for idx, _ in enumerate(notes, start=1))

    inferred = [
        "proposed_action.action_type",
        "proposed_action.side_effect_type",
        "expected_admission_tendency",
    ]
    if missing_evidence:
        inferred.append("evidence.missing")

    return {
        "observed": observed,
        "inferred": inferred,
        "missing": [
            "actor",
            "principal",
            "workflow_context.organization_context",
            "authority_context.approved_by",
        ],
        "defaulted": [
            "actor",
            "principal",
            "workflow_context",
            "authority_context.requested_by",
            "risk_context defaults",
        ],
    }


def _build_action_candidate(
    *,
    raw_output: str,
    action_index: int,
    source_metadata: dict[str, Any],
    long_run_prompt: str | None,
    operation_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    user_request = _extract_user_request(raw_output)
    tool, args = _extract_tool_call(raw_output)
    shell_command = _extract_shell_command(raw_output)
    notes = _extract_notes(raw_output)
    if operation_context:
        action_type = str(operation_context["action_type"])
        side_effect_type = str(operation_context["side_effect_type"])
        expected_tendency = str(operation_context["expected_admission_tendency"])
        confidence = str(operation_context.get("extraction_confidence", "medium"))
        tool_or_command = str(
            operation_context.get("tool_or_command")
            or operation_context.get("operation_text")
            or "proposed_operation"
        )
        target = operation_context.get("target")
        hash_source = str(operation_context.get("operation_text") or tool_or_command)
    else:
        action_type, side_effect_type, expected_tendency, confidence = _classify_action(
            raw_output,
            tool=tool,
            shell_command=shell_command,
            user_request=user_request,
        )
        target = _infer_target(tool, args, shell_command)
        tool_or_command = tool or shell_command or "unknown"
        hash_source = raw_output
    missing_evidence = _missing_evidence_for_action(action_type, notes)
    safer_steps = _safer_next_steps(action_type, target, notes)

    candidate: dict[str, Any] = {
        "candidate_id": f"candidate_{action_index:03d}_{_sha12(hash_source)}",
        "action_type": action_type,
        "tool_or_command": tool_or_command,
        "target": target,
        "side_effect_type": side_effect_type,
        "execution_status": DEFAULT_EXECUTION_STATUS,
        "extracted_from_raw_output": True,
        "source_type": source_metadata.get("source_type", DEFAULT_SOURCE_TYPE),
        "source_trust": DEFAULT_SOURCE_TRUST,
        "extraction_method": EXTRACTION_METHOD,
        "extraction_confidence": confidence,
        "expected_admission_tendency": expected_tendency,
        "user_request_raw": user_request,
        "notes_observed": notes,
        "missing_evidence_hints": missing_evidence,
        "candidate_safer_next_steps": safer_steps,
        "field_provenance": _field_provenance(
            user_request=user_request,
            tool=tool,
            args=args,
            notes=notes,
            missing_evidence=missing_evidence,
        ),
        "long_run_prompt": long_run_prompt,
        "workspace_context": source_metadata.get("workspace_context"),
        "frontier_agent_label": source_metadata.get("frontier_agent_label"),
        "builder_version": BUILDER_VERSION,
    }
    if operation_context:
        if operation_context.get("row_id") is not None:
            candidate["operation_row_id"] = operation_context["row_id"]
        if operation_context.get("phase"):
            candidate["operation_phase"] = operation_context["phase"]
        if operation_context.get("operation_text"):
            candidate["operation_text"] = operation_context["operation_text"]
        if operation_context.get("claim_kind"):
            candidate["claim_kind"] = operation_context["claim_kind"]
    return candidate


def _authority_for_action(action_type: str, notes: list[str]) -> dict[str, Any]:
    archive_available = any(_ARCHIVE_HINT_RE.search(note) for note in notes)
    if action_type in ("deploy_code", "prepare_deploy", "git_push"):
        return {
            "requested_by": "agent_session_user",
            "approved_by": None,
            "approval_scope": "none",
            "required_approval": "owner",
            "authority_notes": [
                "Production-impacting actions require explicit owner approval in v0 builder defaults."
            ],
            "approvals": [],
            "tool_authority": {
                "has_tool_access": "yes",
                "summary": "Tool access observed in agent output.",
            },
            "business_authority": {
                "has_business_authority": "no",
                "summary": "No organizational release authority recorded in raw output.",
            },
        }
    if action_type in ("delete_file", "delete_folder") and archive_available:
        return {
            "requested_by": "agent_session_user",
            "approved_by": None,
            "approval_scope": "execute_with_limits",
            "required_approval": "none",
            "authority_notes": [
                "Reversible archive path noted in raw output; permanent deletion still needs owner sign-off."
            ],
            "approvals": [],
            "tool_authority": {"has_tool_access": "yes", "summary": "Delete tool access observed."},
            "business_authority": {
                "has_business_authority": "yes",
                "summary": "Reversible relocation may proceed under limited scope.",
            },
        }
    if action_type in ("edit_file", "local_code_change", "create_file", "document_hosting_options"):
        return {
            "requested_by": "agent_session_user",
            "approved_by": None,
            "approval_scope": "execute_with_limits",
            "required_approval": "none",
            "authority_notes": ["Local file edit within user-authorized workspace scope."],
            "approvals": [],
            "tool_authority": {
                "has_tool_access": "yes",
                "summary": "File edit tool access assumed for local workspace.",
            },
            "business_authority": {
                "has_business_authority": "yes",
                "summary": "Local-only code change within stated task scope.",
            },
        }
    return {
        "requested_by": "agent_session_user",
        "approved_by": None,
        "approval_scope": "none",
        "required_approval": "unknown",
        "authority_notes": ["Authority not established from raw agent output alone."],
        "approvals": [],
        "tool_authority": {"has_tool_access": "unknown", "summary": "Tool access not verified."},
        "business_authority": {
            "has_business_authority": "unknown",
            "summary": "Business authority not established from raw output.",
        },
    }


def _risk_for_action(action_type: str) -> dict[str, Any]:
    if action_type in ("deploy_code", "prepare_deploy", "git_push"):
        return {
            "reversibility": "partially_reversible",
            "rollback_available": "unknown",
            "blast_radius": "critical",
            "external_visibility": "external",
            "financial_impact": {"amount": None, "currency": None, "impact_known": "unknown"},
            "data_sensitivity": "confidential",
            "safety_impact": "unknown",
            "reputation_impact": "high",
        }
    if action_type in ("delete_file", "delete_folder"):
        return {
            "reversibility": "irreversible",
            "rollback_available": "unknown",
            "blast_radius": "low",
            "external_visibility": "internal_only",
            "financial_impact": {"amount": None, "currency": None, "impact_known": "no"},
            "data_sensitivity": "confidential",
            "safety_impact": "none",
            "reputation_impact": "none",
        }
    if action_type == "install_dependency":
        return {
            "reversibility": "partially_reversible",
            "rollback_available": "unknown",
            "blast_radius": "local",
            "external_visibility": "internal_only",
            "financial_impact": {"amount": None, "currency": None, "impact_known": "no"},
            "data_sensitivity": "internal",
            "safety_impact": "none",
            "reputation_impact": "none",
        }
    if action_type in ("edit_file", "local_code_change", "create_file", "document_hosting_options"):
        return {
            "reversibility": "reversible",
            "rollback_available": "yes",
            "blast_radius": "local",
            "external_visibility": "internal_only",
            "financial_impact": {"amount": None, "currency": None, "impact_known": "no"},
            "data_sensitivity": "internal",
            "safety_impact": "none",
            "reputation_impact": "none",
        }
    if action_type == "verification_plan":
        return {
            "reversibility": "reversible",
            "rollback_available": "yes",
            "blast_radius": "local",
            "external_visibility": "internal_only",
            "financial_impact": {"amount": None, "currency": None, "impact_known": "no"},
            "data_sensitivity": "internal",
            "safety_impact": "none",
            "reputation_impact": "none",
        }
    return {
        "reversibility": "unknown",
        "rollback_available": "unknown",
        "blast_radius": "unknown",
        "external_visibility": "unknown",
        "financial_impact": {"amount": None, "currency": None, "impact_known": "unknown"},
        "data_sensitivity": "unknown",
        "safety_impact": "unknown",
        "reputation_impact": "unknown",
    }


def _workflow_for_action(action_type: str, source_metadata: dict[str, Any]) -> dict[str, Any]:
    domain_map = {
        "deploy_code": "software_engineering",
        "prepare_deploy": "software_engineering",
        "install_dependency": "software_engineering",
        "delete_file": "file_management",
        "delete_folder": "file_management",
        "git_commit": "software_engineering",
        "git_push": "software_engineering",
        "claim_status": "software_engineering",
        "edit_file": "software_engineering",
        "local_code_change": "software_engineering",
        "create_file": "software_engineering",
        "document_hosting_options": "software_engineering",
        "verification_plan": "software_engineering",
        "unknown": "unknown",
    }
    environment = "production" if action_type in ("deploy_code", "prepare_deploy", "git_push") else "local"
    if action_type in ("edit_file", "local_code_change", "create_file", "document_hosting_options", "verification_plan"):
        environment = "local"
    return {
        "domain": domain_map.get(action_type, "unknown"),
        "environment": environment,
        "organization_context": source_metadata.get("workspace_context", "local workspace"),
        "stakeholders": ["developer"],
        "workflow_stage": "execution",
    }


def build_envelope_from_raw_output(
    raw_output: str,
    *,
    long_run_prompt: str | None = None,
    source_metadata: dict[str, Any] | None = None,
    action_index: int = 1,
    benchmark_case_id: str | None = None,
    candidate: dict[str, Any] | None = None,
    operation_snippet: str | None = None,
) -> dict[str, Any]:
    """Build a single action envelope dict from raw long-run agent output."""
    metadata = dict(source_metadata or {})
    if candidate is None:
        candidate = _build_action_candidate(
            raw_output=raw_output,
            action_index=action_index,
            source_metadata=metadata,
            long_run_prompt=long_run_prompt,
        )
    user_request = candidate.get("user_request_raw") or ""
    tool, args = _extract_tool_call(raw_output)
    shell_command = _extract_shell_command(raw_output)
    notes = candidate.get("notes_observed") or []
    action_type = candidate["action_type"]
    missing_evidence = list(candidate.get("missing_evidence_hints") or [])
    safer_steps = list(candidate.get("candidate_safer_next_steps") or [])
    target = candidate.get("target")
    envelope_hash_source = operation_snippet or candidate.get("operation_text") or raw_output
    envelope_id = f"env_lr_{_sha12(envelope_hash_source)}"

    policy_gaps: list[str] = []
    if action_type in ("deploy_code", "prepare_deploy"):
        policy_gaps = ["Production deployment policy not fully satisfied from raw output."]
    elif action_type == "unknown":
        policy_gaps = ["Action type could not be classified confidently from raw output."]

    envelope: dict[str, Any] = {
        "envelope_id": envelope_id,
        "schema_version": "0.1",
        "envelope_tier": "fully_enriched",
        "construction_mode": "system_assembled",
        "created_at": _utc_now_iso(),
        "actor": {
            "type": "agent",
            "id": metadata.get("frontier_agent_label", "cursor_class_agent_v0"),
            "role": "software_engineering_agent",
            "technical_authority_level": "assistant",
            "organization_unit": "engineering",
        },
        "principal": {
            "type": "human",
            "id": "session_user",
            "role": "developer",
            "authority_basis": "session instruction",
        },
        "user_request": {
            "raw": user_request,
            "interpreted_intent": user_request or "Unspecified user intent from raw output.",
        },
        "proposed_action": {
            "action_type": action_type,
            "tool": tool or shell_command or candidate.get("tool_or_command"),
            "target": target,
            "arguments": args if args else {"shell_command": shell_command} if shell_command else {},
            "side_effect_type": candidate.get("side_effect_type", "unknown"),
        },
        "workflow_context": _workflow_for_action(action_type, metadata),
        "evidence": {
            "available": [],
            "missing": missing_evidence,
            "assumptions": ["Raw agent output treated as unverified interpretation input."],
            "conflicts": [],
        },
        "policy_context": {
            "applicable_policies": [],
            "policy_gaps": policy_gaps,
            "policy_conflicts": [],
        },
        "authority_context": _authority_for_action(action_type, notes),
        "risk_context": _risk_for_action(action_type),
        "provenance": {
            "instruction_source": "terminal_agent_output",
            "evidence_sources": [],
            "tool_sources": [tool] if tool else [],
            "memory_sources": [],
            "retrieval_sources": [],
        },
        "expected_side_effect": {
            "description": (
                f"Proposed {action_type} side effect derived from unverified agent output."
                + (f" Operation: {operation_snippet}" if operation_snippet else "")
            ),
            "affected_systems": [target] if target else [],
            "affected_people": ["developer"],
            "persistence": "unknown",
        },
        "metadata": {
            "scenario_domain": _workflow_for_action(action_type, metadata)["domain"],
            "benchmark_case_id": benchmark_case_id or f"case_lr_{_sha12(raw_output)}",
            "notes": [
                BUILDER_CLAIM_BOUNDARY,
                f"builder_version={BUILDER_VERSION}",
                f"extraction_method={EXTRACTION_METHOD}",
                f"extraction_confidence={candidate.get('extraction_confidence')}",
            ],
        },
    }
    if safer_steps:
        envelope["candidate_safer_next_steps"] = safer_steps
    if long_run_prompt:
        envelope["metadata"]["long_run_prompt"] = long_run_prompt
    return envelope


def _fixture_stem_from_metadata(metadata: dict[str, Any]) -> str | None:
    fixture_path = metadata.get("fixture_path")
    if not isinstance(fixture_path, str) or not fixture_path:
        return None
    return Path(fixture_path).stem


def _build_from_production_readiness_report(
    raw_output: str,
    *,
    long_run_prompt: str | None,
    source_metadata: dict[str, Any],
) -> dict[str, Any]:
    operations = _extract_production_readiness_operations(raw_output)
    fixture_stem = _fixture_stem_from_metadata(source_metadata)
    candidates: list[dict[str, Any]] = []
    envelopes: list[dict[str, Any]] = []
    action_index = 0

    for operation in operations:
        classified = _classify_proposed_operation(
            operation["operation_text"],
            phase=operation.get("phase"),
        )
        if classified is None:
            continue
        action_type, side_effect_type, expected_tendency, confidence = classified
        action_index += 1
        operation_context = {
            "action_type": action_type,
            "side_effect_type": side_effect_type,
            "expected_admission_tendency": expected_tendency,
            "extraction_confidence": confidence,
            "operation_text": operation["operation_text"],
            "tool_or_command": _operation_tool_label(operation["operation_text"], action_type),
            "row_id": operation["row_id"],
            "phase": operation.get("phase"),
        }
        candidate = _build_action_candidate(
            raw_output=raw_output,
            action_index=action_index,
            source_metadata=source_metadata,
            long_run_prompt=long_run_prompt,
            operation_context=operation_context,
        )
        case_id = (
            f"{fixture_stem}__op_{operation['row_id']}"
            if fixture_stem
            else f"case_lr_{_sha12(operation['operation_text'])}"
        )
        envelope = build_envelope_from_raw_output(
            raw_output,
            long_run_prompt=long_run_prompt,
            source_metadata=source_metadata,
            action_index=action_index,
            benchmark_case_id=case_id,
            candidate=candidate,
            operation_snippet=operation["operation_text"],
        )
        candidates.append(candidate)
        envelopes.append(envelope)

    for claim in _extract_assessment_claims(raw_output):
        action_index += 1
        operation_context = {
            "action_type": "claim_status",
            "side_effect_type": "internal_state_change",
            "expected_admission_tendency": "REQUEST_MORE_EVIDENCE",
            "extraction_confidence": "medium",
            "operation_text": claim["claim_text"],
            "tool_or_command": claim["claim_text"],
            "claim_kind": claim["claim_kind"],
        }
        candidate = _build_action_candidate(
            raw_output=raw_output,
            action_index=action_index,
            source_metadata=source_metadata,
            long_run_prompt=long_run_prompt,
            operation_context=operation_context,
        )
        claim_suffix = claim["claim_kind"]
        case_id = (
            f"{fixture_stem}__claim_{claim_suffix}"
            if fixture_stem
            else f"case_lr_{_sha12(claim['claim_text'])}"
        )
        envelope = build_envelope_from_raw_output(
            raw_output,
            long_run_prompt=long_run_prompt,
            source_metadata=source_metadata,
            action_index=action_index,
            benchmark_case_id=case_id,
            candidate=candidate,
            operation_snippet=claim["claim_text"],
        )
        candidates.append(candidate)
        envelopes.append(envelope)

    return {
        "builder_version": BUILDER_VERSION,
        "claim_boundary": BUILDER_CLAIM_BOUNDARY,
        "action_candidates": candidates,
        "envelopes": envelopes,
    }


def build_from_raw_output(
    raw_output: str,
    *,
    long_run_prompt: str | None = None,
    source_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Parse raw agent output into action candidates and evaluable envelopes."""
    metadata = dict(source_metadata or {})
    if _is_production_readiness_report(raw_output):
        return _build_from_production_readiness_report(
            raw_output,
            long_run_prompt=long_run_prompt,
            source_metadata=metadata,
        )

    candidate = _build_action_candidate(
        raw_output=raw_output,
        action_index=1,
        source_metadata=metadata,
        long_run_prompt=long_run_prompt,
    )
    fixture_stem = _fixture_stem_from_metadata(metadata)
    benchmark_case_id = fixture_stem or f"case_lr_{_sha12(raw_output)}"
    envelope = build_envelope_from_raw_output(
        raw_output,
        long_run_prompt=long_run_prompt,
        source_metadata=metadata,
        action_index=1,
        benchmark_case_id=benchmark_case_id,
        candidate=candidate,
    )
    return {
        "builder_version": BUILDER_VERSION,
        "claim_boundary": BUILDER_CLAIM_BOUNDARY,
        "action_candidates": [candidate],
        "envelopes": [envelope],
    }
