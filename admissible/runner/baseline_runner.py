"""Frontier-direct baseline runner for Admissible.

Passes a bare action envelope to a frontier model and parses its
response into a schema-valid decision output. This is the "frontier
model alone" condition, compared against Admissible's rules-only
reference evaluator (admissible.evaluator.rules_only) by scoring both
against the same gold annotations (benchmark/scoring/score_decisions.py).

Fairness boundary: the prompt built here (see
benchmark/prompts/frontier_direct_decision.md) includes only the
action envelope and the fixed task instructions. It never includes
gold annotations, expected decisions, scoring output, rules-only
evaluator output, hidden rubrics, or any other benchmark answer.

This module does not perform live model calls itself. It depends on a
ModelClient supplied by the caller (see the ModelClient protocol
below). No test in this repository requires network access or an API
key; tests and the CLI's --mock-response mode use a fixed-response
client instead. A live provider client may be added later behind the
same interface without changing this module's public API.

Also runnable as a CLI:

    python -m admissible.runner.baseline_runner \\
        --case benchmark/cases/tier_1_enriched/customer_communication/<some_case>.envelope.json \\
        --mock-response benchmark/examples/mock_frontier_response.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from admissible.runner.model_clients import (
    FixedResponseModelClient,
    build_gemini_model_client_from_env,
    build_huggingface_model_client_from_env,
    build_model_client_from_env,
)

CANONICAL_LABELS: tuple[str, ...] = (
    "ALLOW",
    "ALLOW_WITH_LIMITS",
    "REQUEST_MORE_EVIDENCE",
    "REQUIRE_HUMAN_APPROVAL",
    "REFUSE",
)

_VALID_RISK_LEVELS = {"low", "medium", "high", "critical", "unknown"}
_VALID_APPROVALS = {"none", "human", "manager", "owner", "admin", "legal", "finance", "domain_expert", "unknown"}
_VALID_DIMENSIONS = {
    "authority",
    "evidence",
    "reversibility",
    "blast_radius",
    "provenance",
    "auditability",
    "human_responsibility",
    "policy",
    "other",
}
_VALID_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}

_PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "benchmark" / "prompts" / "frontier_direct_decision.md"

DEFAULT_SYSTEM_ID = "frontier_direct_baseline_v0"


class ModelClient(Protocol):
    """Minimal interface a frontier model client must satisfy.

    Implementations may wrap a live API, but nothing in this repository
    requires one: tests and CLI --mock-response use a fixed-response
    implementation instead.
    """

    def complete(self, prompt: str) -> str:
        ...


def _load_prompt_template() -> str:
    return _PROMPT_PATH.read_text(encoding="utf-8")


def build_frontier_direct_prompt(envelope: dict) -> str:
    """Build the frontier-direct-decision prompt for one action envelope.

    Includes only the fixed task instructions from
    benchmark/prompts/frontier_direct_decision.md plus the action
    envelope itself, serialized as JSON. Never includes gold
    annotations, rubrics, or rules-only evaluator output — the caller
    must not pass those in, and this function has no access to them.
    """
    envelope_json = json.dumps(envelope, indent=2, sort_keys=True)
    template = _load_prompt_template()
    return f"{template}\n\n```json\n{envelope_json}\n```\n"


def _normalize_reasons(raw_reasons: Any) -> list[dict]:
    if not isinstance(raw_reasons, list):
        return []
    reasons = []
    for item in raw_reasons:
        if isinstance(item, dict):
            dimension = item.get("dimension")
            if dimension not in _VALID_DIMENSIONS:
                dimension = "other"
            severity = item.get("severity")
            if severity not in _VALID_SEVERITIES:
                severity = "unknown"
            summary = str(item.get("summary") or item.get("reason") or "").strip()
            if not summary:
                summary = "no summary provided"
            reasons.append({"dimension": dimension, "summary": summary, "severity": severity})
        elif isinstance(item, str) and item.strip():
            reasons.append({"dimension": "other", "summary": item.strip(), "severity": "unknown"})
    return reasons


def _normalize_safer_next_step(raw: Any, decision_label: str) -> dict | None:
    if decision_label == "ALLOW":
        return None

    requires_human_default = decision_label == "REQUIRE_HUMAN_APPROVAL"

    if raw is None:
        return {
            "action_type": None,
            "description": "Model did not provide a safer next step.",
            "limits": [],
            "requires_human": requires_human_default,
        }
    if isinstance(raw, str):
        return {
            "action_type": None,
            "description": raw,
            "limits": [],
            "requires_human": requires_human_default,
        }
    if isinstance(raw, dict):
        limits = raw.get("limits")
        return {
            "action_type": raw.get("action_type") if isinstance(raw.get("action_type"), str) else None,
            "description": str(raw.get("description") or ""),
            "limits": [str(x) for x in limits] if isinstance(limits, list) else [],
            "requires_human": bool(raw.get("requires_human", requires_human_default)),
        }
    return {
        "action_type": None,
        "description": str(raw),
        "limits": [],
        "requires_human": requires_human_default,
    }


_ERROR_PREVIEW_CHARS = 300
_TRAILING_PREVIEW_MAX = 300


def _normalize_response_text(response_text: str) -> str:
    """Strip NUL bytes that HF and similar providers append after model output."""
    return response_text.replace("\x00", "")


def _safe_trailing_preview(trailing_text: str) -> str:
    """Return a bounded trailing-text preview, omitting credential-like content."""
    if not trailing_text:
        return ""
    lowered = trailing_text.lower()
    suspicious_markers = ("hf_", "api_key", "api-key", "bearer ", "sk-", "token")
    if any(marker in lowered for marker in suspicious_markers):
        return "[trailing provider output omitted]"
    return trailing_text[:_TRAILING_PREVIEW_MAX]


def _build_provider_output_metadata(
    original_text: str,
    clean_json_text: str,
    trailing_text: str,
) -> dict[str, Any]:
    """Bounded audit metadata for sanitized provider output."""
    metadata: dict[str, Any] = {
        "provider_output_sha256": hashlib.sha256(original_text.encode("utf-8")).hexdigest(),
        "provider_output_sanitized": clean_json_text != original_text,
    }
    if metadata["provider_output_sanitized"]:
        metadata["provider_output_original_length"] = len(original_text)
        metadata["provider_output_clean_length"] = len(clean_json_text)
        if trailing_text:
            metadata["provider_output_trailing_text_preview"] = _safe_trailing_preview(trailing_text)
    return metadata


def _build_parse_error_context(
    response_text: str,
    *,
    envelope_id: str,
    system_id: str,
) -> str:
    length = len(response_text)
    first_preview = response_text[:_ERROR_PREVIEW_CHARS]
    if length <= _ERROR_PREVIEW_CHARS:
        last_preview = response_text
    else:
        last_preview = response_text[-_ERROR_PREVIEW_CHARS:]
    return (
        f"envelope_id={envelope_id!r}; system_id={system_id!r}; "
        f"response_length={length}; "
        f"first_preview={first_preview!r}; last_preview={last_preview!r}"
    )


def _extract_json_with_span(response_text: str) -> tuple[str, int, int] | None:
    """Extract JSON object text and its span in normalized response text.

    Returns (json_text, start, end) where start/end index into the
    NUL-stripped normalized text, or None when no valid JSON object exists.
    """
    normalized = _normalize_response_text(response_text)
    stripped = normalized.strip()
    if stripped:
        try:
            json.loads(stripped)
            start = normalized.find(stripped)
            if start == -1:
                start = 0
            return stripped, start, start + len(stripped)
        except json.JSONDecodeError:
            pass

    fence_match = re.search(
        r"```(?:json)?\s*\n?(.*?)\n?```",
        normalized,
        re.DOTALL | re.IGNORECASE,
    )
    if fence_match:
        candidate = fence_match.group(1).strip()
        if candidate:
            try:
                json.loads(candidate)
                start = fence_match.start(1)
                end = fence_match.end(1)
                return candidate, start, end
            except json.JSONDecodeError:
                pass

    start = normalized.find("{")
    if start != -1:
        depth = 0
        in_string = False
        escape = False
        for index, char in enumerate(normalized[start:], start=start):
            if escape:
                escape = False
                continue
            if char == "\\" and in_string:
                escape = True
                continue
            if char == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    candidate = normalized[start : index + 1]
                    try:
                        json.loads(candidate)
                        return candidate, start, index + 1
                    except json.JSONDecodeError:
                        break

    return None


def _extract_json_text(response_text: str) -> str | None:
    """Extract JSON object text from a model response using layered fallbacks."""
    result = _extract_json_with_span(response_text)
    return result[0] if result is not None else None


def parse_frontier_response(response_text: str, *, envelope_id: str, system_id: str) -> dict:
    """Parse a frontier model's raw text response into a full decision output.

    Strict on the fields that determine correctness:

    - raises ValueError if no JSON object can be extracted from response_text;
    - raises ValueError if the parsed JSON is not an object;
    - raises ValueError if `decision` is missing or empty;
    - raises ValueError if `decision` is not one of the five canonical
      labels (never silently coerced).

    Lenient on everything else: optional fields that are missing or
    malformed are normalized into schema-compatible defaults rather
    than raising, since a frontier model's formatting of secondary
    fields is not the thing under test here.
    """
    json_text = _extract_json_text(response_text)
    if json_text is None:
        context = _build_parse_error_context(
            response_text, envelope_id=envelope_id, system_id=system_id
        )
        raise ValueError(
            "frontier response does not contain a valid JSON object; " + context
        )

    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError as exc:
        context = _build_parse_error_context(
            response_text, envelope_id=envelope_id, system_id=system_id
        )
        raise ValueError(
            f"frontier response is not valid JSON: {exc}; " + context
        ) from exc

    if not isinstance(parsed, dict):
        raise ValueError(f"frontier response must be a JSON object, got {type(parsed).__name__}")

    decision_label = parsed.get("decision")
    if not decision_label:
        raise ValueError("frontier response is missing required field 'decision'")
    if decision_label not in CANONICAL_LABELS:
        raise ValueError(
            f"frontier response has unknown decision label: {decision_label!r}; "
            f"expected one of {CANONICAL_LABELS}"
        )

    risk_level = parsed.get("risk_level")
    if risk_level not in _VALID_RISK_LEVELS:
        risk_level = "unknown"

    required_approval = parsed.get("required_approval")
    if required_approval not in _VALID_APPROVALS:
        required_approval = "unknown"

    missing_evidence = parsed.get("missing_evidence")
    missing_evidence = [str(x) for x in missing_evidence] if isinstance(missing_evidence, list) else []

    confidence = parsed.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        confidence = None
    elif not (0.0 <= float(confidence) <= 1.0):
        confidence = None
    else:
        confidence = float(confidence)

    reasons = _normalize_reasons(parsed.get("reasons"))
    if not reasons:
        reasons = [{
            "dimension": "other",
            "summary": "Model did not provide structured reasons.",
            "severity": "unknown",
        }]

    safer_next_step = _normalize_safer_next_step(parsed.get("safer_next_step"), decision_label)

    audit_trace = {
        "authority": "not independently verified; see reasons",
        "evidence": "not independently verified; see reasons",
        "reversibility": "not independently verified; see reasons",
        "blast_radius": "not independently verified; see reasons",
        "provenance": "not independently verified; see reasons",
        "policy": "not independently verified; see reasons",
        "human_responsibility": "not independently verified; see reasons",
    }

    known_fields = {
        "decision",
        "risk_level",
        "reasons",
        "missing_evidence",
        "required_approval",
        "safer_next_step",
        "confidence",
    }
    raw_extra_fields = {key: value for key, value in parsed.items() if key not in known_fields}

    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "decision_id": f"decision_{envelope_id}_{system_id}",
        "schema_version": "0.1",
        "envelope_id": envelope_id,
        "system_id": system_id,
        "created_at": created_at,
        "decision": decision_label,
        "risk_level": risk_level,
        "reasons": reasons,
        "missing_evidence": missing_evidence,
        "required_approval": required_approval,
        "safer_next_step": safer_next_step,
        "audit_trace": audit_trace,
        "confidence": confidence,
        "metadata": {
            "runner": "admissible.runner.baseline_runner",
            "note": "Frontier-direct baseline; model saw only the action envelope, no gold labels or rubrics.",
            "raw_model_extra_fields": raw_extra_fields,
        },
    }


def run_frontier_direct_baseline(
    envelope: dict,
    *,
    model_client: ModelClient,
    system_id: str = DEFAULT_SYSTEM_ID,
) -> dict:
    """Run the frontier-direct baseline on one action envelope.

    Sends only the action envelope to `model_client.complete()` (via
    build_frontier_direct_prompt); never sends gold annotations,
    rules-only evaluator output, or any other benchmark answer. Does
    not mutate `envelope`. Returns a full decision_output-shaped dict.
    """
    envelope_id = envelope.get("envelope_id")
    if not isinstance(envelope_id, str) or not envelope_id:
        raise ValueError("action envelope 'envelope_id' must be a non-empty string")

    prompt = build_frontier_direct_prompt(envelope)
    response_text = model_client.complete(prompt)
    decision = parse_frontier_response(response_text, envelope_id=envelope_id, system_id=system_id)
    metadata = decision.get("metadata")
    if isinstance(metadata, dict):
        extraction = _extract_json_with_span(response_text)
        if extraction is not None:
            clean_json_text, _start, end = extraction
            normalized = _normalize_response_text(response_text)
            trailing_text = normalized[end:].strip()
            metadata["raw_provider_response_text"] = clean_json_text
            metadata.update(
                _build_provider_output_metadata(response_text, clean_json_text, trailing_text)
            )
    return decision


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.runner.baseline_runner",
        description="Run the Admissible frontier-direct baseline on one action envelope.",
    )
    parser.add_argument("--case", required=True, help="Path to one *.envelope.json action envelope.")
    provider_group = parser.add_mutually_exclusive_group(required=True)
    provider_group.add_argument(
        "--mock-response",
        help=(
            "Path to a JSON file containing a mock frontier response text "
            "(the partial decision fields the prompt asks for). No live model call."
        ),
    )
    provider_group.add_argument(
        "--provider",
        choices=["env-http", "hf", "gemini"],
        help="Use a live model provider configured via environment variables.",
    )
    parser.add_argument(
        "--system-id",
        default=DEFAULT_SYSTEM_ID,
        help=f"system_id to record on the output (default: {DEFAULT_SYSTEM_ID}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    with Path(args.case).open(encoding="utf-8") as f:
        envelope = json.load(f)

    if args.mock_response is not None:
        response_text = Path(args.mock_response).read_text(encoding="utf-8")
        model_client = FixedResponseModelClient(response_text)
    elif args.provider == "hf":
        model_client = build_huggingface_model_client_from_env()
    elif args.provider == "gemini":
        model_client = build_gemini_model_client_from_env()
    else:
        model_client = build_model_client_from_env()

    decision = run_frontier_direct_baseline(envelope, model_client=model_client, system_id=args.system_id)
    print(json.dumps(decision, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
