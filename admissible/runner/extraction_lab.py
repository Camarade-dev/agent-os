"""Admissible Agent Response Extraction Lab v0.

A regression harness for `admissible.long_run_envelope_builder` against
pasted-agent-response fixtures. It answers one narrow question: for a given
raw pasted response, does extraction produce (at least) the action
candidates and rules-only decisions we expect, and does it avoid producing
the ones we've declared forbidden (e.g. a negated "I will not push" must
never surface as a positive `git_push` candidate, and nothing may become a
silent `ALLOW` that shouldn't)?

Pipeline, per fixture: raw text -> `build_from_raw_output` (extraction,
unmodified) -> `evaluate_envelope` (rules-only decision, unmodified) ->
compare action types / decisions against an `expected_extractions.json`
spec -> pass/fail summary.

Hard constraints (same boundary as the rest of `admissible`):

- Does not call Cursor, Claude Code, Codex, Gemini, OpenAI, or any network
  provider.
- Does not execute any shell command proposed in a fixture.
- Does not import `agent_os`.
- Never mutates the underlying builder/evaluator outputs; only reads them.

Also runnable as a CLI:

    python -m admissible.runner.extraction_lab \\
        --fixtures-dir benchmark/long_run_scenarios/cursor_slither_demo/fixtures/pasted_agent_responses \\
        --expected benchmark/long_run_scenarios/cursor_slither_demo/fixtures/pasted_agent_responses/expected_extractions.json \\
        --out benchmark/reports/admissible_agent_response_extraction_lab.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from admissible.evaluator.rules_only import evaluate_envelope
from admissible.long_run_envelope_builder import build_from_raw_output

LAB_CLAIM_BOUNDARY = (
    "Offline rule-based extraction regression harness for pasted agent "
    "responses; not a benchmark result."
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_fixture(path: str | Path) -> str:
    """Read one raw pasted-agent-response fixture as text."""
    return Path(path).read_text(encoding="utf-8")


def load_expected_spec(path: str | Path) -> dict[str, Any]:
    """Load the `expected_extractions.json` regression spec."""
    with Path(path).open(encoding="utf-8") as f:
        return json.load(f)


def extract_and_decide(
    raw_text: str,
    *,
    fixture_name: str,
    source_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the unmodified builder + rules-only evaluator over one raw response.

    Returns the builder output plus a parallel list of rules-only decisions,
    one per envelope, in the same order as `action_candidates`/`envelopes`.
    """
    metadata = dict(source_metadata or {})
    metadata.setdefault("fixture_path", fixture_name)
    built = build_from_raw_output(raw_text, source_metadata=metadata)
    decisions = [evaluate_envelope(envelope) for envelope in built.get("envelopes") or []]
    return {
        "action_candidates": built.get("action_candidates") or [],
        "envelopes": built.get("envelopes") or [],
        "decisions": decisions,
    }


def evaluate_fixture(
    fixture_name: str,
    raw_text: str,
    expected: dict[str, Any],
    *,
    source_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compare one fixture's extraction against its expected spec entry.

    `expected` follows the `expected_extractions.json` per-fixture shape:
    `min_candidate_count`, `expected_action_types`, `expected_decisions`,
    `forbidden_action_types`, `forbidden_decisions`, `notes`. Every expected/
    forbidden check is a membership check against the full set of action
    types (or decisions) extracted from the fixture -- not a 1:1 pairing --
    matching the spec's own "expected action types" / "expected decisions"
    wording.
    """
    result = extract_and_decide(raw_text, fixture_name=fixture_name, source_metadata=source_metadata)
    action_types = [c.get("action_type") for c in result["action_candidates"]]
    decision_labels = [d.get("decision") for d in result["decisions"]]

    failures: list[str] = []

    min_count = expected.get("min_candidate_count", 0)
    if len(result["action_candidates"]) < min_count:
        failures.append(
            f"expected at least {min_count} candidate(s), got {len(result['action_candidates'])}"
        )

    for expected_type in expected.get("expected_action_types", []) or []:
        if expected_type not in action_types:
            failures.append(f"expected action type {expected_type!r} not found in {action_types}")

    for expected_decision in expected.get("expected_decisions", []) or []:
        if expected_decision not in decision_labels:
            failures.append(
                f"expected decision {expected_decision!r} not found in {decision_labels}"
            )

    for forbidden_type in expected.get("forbidden_action_types", []) or []:
        if forbidden_type in action_types:
            failures.append(f"forbidden action type {forbidden_type!r} was present")

    for forbidden_decision in expected.get("forbidden_decisions", []) or []:
        if forbidden_decision in decision_labels:
            failures.append(f"forbidden decision {forbidden_decision!r} was present")

    return {
        "fixture": fixture_name,
        "description": expected.get("description", ""),
        "candidate_count": len(result["action_candidates"]),
        "action_types": action_types,
        "decisions": decision_labels,
        "notes": expected.get("notes", ""),
        "passed": not failures,
        "failures": failures,
    }


def run_extraction_lab(
    fixtures_dir: str | Path,
    expected_path: str | Path,
) -> dict[str, Any]:
    """Run every fixture named in `expected_extractions.json` and summarize.

    Fixtures are looked up by name (the JSON keys) inside `fixtures_dir`,
    not by directory glob -- this keeps the spec authoritative about which
    fixtures are in scope for the lab.
    """
    fixtures_dir = Path(fixtures_dir)
    expected_path = Path(expected_path)
    spec = load_expected_spec(expected_path)
    fixture_specs: dict[str, Any] = spec.get("fixtures") or {}

    results: list[dict[str, Any]] = []
    for fixture_name in sorted(fixture_specs):
        fixture_path = fixtures_dir / fixture_name
        if not fixture_path.is_file():
            results.append(
                {
                    "fixture": fixture_name,
                    "description": fixture_specs[fixture_name].get("description", ""),
                    "candidate_count": 0,
                    "action_types": [],
                    "decisions": [],
                    "notes": fixture_specs[fixture_name].get("notes", ""),
                    "passed": False,
                    "failures": [f"fixture file not found: {fixture_path}"],
                }
            )
            continue
        raw_text = load_fixture(fixture_path)
        results.append(
            evaluate_fixture(
                fixture_name,
                raw_text,
                fixture_specs[fixture_name],
                source_metadata={"fixture_path": str(fixture_path.as_posix())},
            )
        )

    pass_count = sum(1 for r in results if r["passed"])
    return {
        "schema_version": "0.1",
        "claim_boundary": spec.get("claim_boundary", LAB_CLAIM_BOUNDARY),
        "fixtures_dir": str(fixtures_dir),
        "expected_spec_path": str(expected_path),
        "generated_at": _utc_now_iso(),
        "fixture_count": len(results),
        "pass_count": pass_count,
        "fail_count": len(results) - pass_count,
        "overall_passed": pass_count == len(results),
        "results": results,
    }


def render_markdown_report(summary: dict[str, Any]) -> str:
    """Render a concise Markdown table + failure detail for one lab run."""
    status = "PASS" if summary["overall_passed"] else "FAIL"
    lines = [
        "# Admissible Agent Response Extraction Lab",
        "",
        f"Overall: **{status}** ({summary['pass_count']}/{summary['fixture_count']} fixtures)",
        "",
        f"_{summary.get('claim_boundary', LAB_CLAIM_BOUNDARY)}_",
        "",
        "| Fixture | Candidates | Action types | Decisions | Result |",
        "|---|---|---|---|---|",
    ]
    for r in summary["results"]:
        row_status = "PASS" if r["passed"] else "FAIL"
        action_types = ", ".join(t for t in r["action_types"] if t) or "(none)"
        decisions = ", ".join(d for d in r["decisions"] if d) or "(none)"
        lines.append(
            f"| {r['fixture']} | {r['candidate_count']} | {action_types} | {decisions} | {row_status} |"
        )

    failing = [r for r in summary["results"] if not r["passed"]]
    if failing:
        lines.append("")
        lines.append("## Failures")
        for r in failing:
            lines.append("")
            lines.append(f"### {r['fixture']}")
            for failure in r["failures"]:
                lines.append(f"- {failure}")

    return "\n".join(lines) + "\n"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.runner.extraction_lab",
        description=(
            "Run admissible.long_run_envelope_builder + rules_only over the pasted-agent-"
            "response fixtures and compare against expected_extractions.json. Offline, "
            "deterministic; calls no provider and executes nothing."
        ),
    )
    parser.add_argument(
        "--fixtures-dir",
        required=True,
        help="Directory containing pasted-agent-response *.txt fixtures.",
    )
    parser.add_argument(
        "--expected",
        required=True,
        help="Path to expected_extractions.json.",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Optional path to write the JSON summary. Always printed to stdout too.",
    )
    parser.add_argument(
        "--markdown-out",
        default=None,
        help="Optional path to write a Markdown report alongside the JSON summary.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    summary = run_extraction_lab(args.fixtures_dir, args.expected)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, sort_keys=True)
            f.write("\n")

    if args.markdown_out:
        markdown_path = Path(args.markdown_out)
        markdown_path.parent.mkdir(parents=True, exist_ok=True)
        markdown_path.write_text(render_markdown_report(summary), encoding="utf-8")

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["overall_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
