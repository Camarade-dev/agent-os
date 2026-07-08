"""Terminal Agent Dry-Run Demo v0 — fixture-based, no side effects.

Pipeline (dry-run only):

    raw terminal-agent output fixture
    → proposed action / action envelope
    → Admissible rules-only decision
    → trace JSON
    → readable static HTML trace

Does not call Claude Code, Codex, Cursor CLI, Gemini, or any network
provider. No API keys, no secrets, no workspace mutation.

CLI:

    python -m admissible.runner.terminal_dry_run_demo \\
        --demo-pack benchmark/terminal_agent_dry_run/demo-pack.json \\
        --trace-out benchmark/reports/terminal_agent_dry_run_trace.json \\
        --html-out benchmark/reports/terminal_agent_dry_run_trace.html
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from admissible.evaluator.rules_only import evaluate_envelope
from admissible.harness.viewer import write_trace_html
from admissible.trace import build_run_trace
from benchmark.scoring.score_decisions import score_case, score_decisions

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

TERMINAL_DRY_RUN_CLAIM_BOUNDARY = (
    "Terminal-agent dry-run demonstration only; not a benchmark result."
)
TERMINAL_DRY_RUN_SOURCE_SYSTEM = "terminal_agent_dry_run_v0"
TERMINAL_DRY_RUN_DECISION_SYSTEM = "admissible_rules_only_v0"
TERMINAL_DRY_RUN_GENERATED_BY = "admissible.runner.terminal_dry_run_demo"

_MIN_SELECTED_CASES = 3
_MAX_SELECTED_CASES = 3


def load_terminal_dry_run_pack(path: str | Path) -> dict:
    """Load and validate benchmark/terminal_agent_dry_run/demo-pack.json."""
    path = Path(path)
    try:
        demo_pack = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON demo pack file: {exc}") from exc

    if not isinstance(demo_pack, dict):
        raise ValueError(
            f"{path}: demo pack must be a JSON object, got {type(demo_pack).__name__}"
        )

    claim_boundary = demo_pack.get("claim_boundary")
    if claim_boundary != TERMINAL_DRY_RUN_CLAIM_BOUNDARY:
        raise ValueError(
            f"{path}: demo pack 'claim_boundary' must be exactly "
            f"{TERMINAL_DRY_RUN_CLAIM_BOUNDARY!r}, got {claim_boundary!r}"
        )

    selected_cases = demo_pack.get("selected_cases")
    if not isinstance(selected_cases, list):
        raise ValueError(f"{path}: demo pack 'selected_cases' must be a list")
    if not (_MIN_SELECTED_CASES <= len(selected_cases) <= _MAX_SELECTED_CASES):
        raise ValueError(
            f"{path}: terminal dry-run demo pack must contain exactly "
            f"{_MIN_SELECTED_CASES} cases, got {len(selected_cases)}"
        )

    return demo_pack


def _load_fixture_text(repo_root: Path, fixture_path: str) -> str:
    resolved = (repo_root / fixture_path).resolve()
    if not resolved.is_file():
        raise ValueError(f"terminal fixture does not exist: {fixture_path}")
    return resolved.read_text(encoding="utf-8")


def _load_envelope(repo_root: Path, envelope_path: str) -> dict:
    resolved = (repo_root / envelope_path).resolve()
    if not resolved.is_file():
        raise ValueError(f"envelope path does not exist: {envelope_path}")
    envelope = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(envelope, dict):
        raise ValueError(f"{envelope_path}: envelope must be a JSON object")
    return envelope


def _minimal_gold(case: dict, envelope: dict) -> dict:
    envelope_id = envelope["envelope_id"]
    benchmark_case_id = case.get("benchmark_case_id") or case.get("case_id")
    expected = case["expected_decision"]
    return {
        "annotation_id": f"gold_{benchmark_case_id}",
        "schema_version": "0.1",
        "benchmark_case_id": benchmark_case_id,
        "envelope_id": envelope_id,
        "gold_decision": expected,
        "gold_risk_level": "unknown",
        "gold_failure_modes_if_incorrectly_allowed": [],
        "gold_required_missing_evidence": [],
        "gold_required_approval": "unknown",
        "gold_safer_next_step": "",
        "rubric": {},
        "annotator_metadata": {"source": "terminal_agent_dry_run_demo_pack"},
        "quality_flags": {"ambiguous": False},
    }


def load_terminal_dry_run_cases(
    demo_pack: dict, *, repo_root: str | Path = REPO_ROOT
) -> list[dict]:
    """Load fixture text, envelope, and metadata for each demo-pack case."""
    repo_root = Path(repo_root)
    loaded: list[dict] = []
    for case in demo_pack["selected_cases"]:
        for field in ("fixture_path", "envelope_path", "expected_decision"):
            if field not in case:
                raise ValueError(
                    f"demo pack case {case.get('case_id')!r} missing required field {field!r}"
                )

        fixture_path = case["fixture_path"]
        envelope_path = case["envelope_path"]
        raw_output = _load_fixture_text(repo_root, fixture_path)
        envelope = _load_envelope(repo_root, envelope_path)

        loaded.append(
            {
                "case": case,
                "raw_terminal_output": raw_output,
                "envelope": envelope,
                "gold": _minimal_gold(case, envelope),
            }
        )
    return loaded_cases if (loaded_cases := loaded) else loaded


def build_terminal_dry_run_trace(
    *,
    demo_pack_path: str | Path,
    repo_root: str | Path = REPO_ROOT,
) -> dict:
    """Build a terminal-agent dry-run trace (rules-only, no side effects)."""
    demo_pack_path = Path(demo_pack_path)
    demo_pack = load_terminal_dry_run_pack(demo_pack_path)
    cases = load_terminal_dry_run_cases(demo_pack, repo_root=repo_root)

    envelopes = [item["envelope"] for item in cases]
    gold_by_envelope_id = {item["gold"]["envelope_id"]: item["gold"] for item in cases}

    decisions = [
        evaluate_envelope(envelope, system_id=TERMINAL_DRY_RUN_DECISION_SYSTEM)
        for envelope in envelopes
    ]
    decisions_by_system = {"rules_only": decisions}

    summary = score_decisions(decisions, gold_by_envelope_id)
    comparison = {
        "systems": ["rules_only"],
        "case_count": len(envelopes),
        "claim_boundary": TERMINAL_DRY_RUN_CLAIM_BOUNDARY,
        "results": {"rules_only": summary},
        "notes": "Terminal-agent dry-run; rules-only evaluation; no side effects executed.",
        "source_system": TERMINAL_DRY_RUN_SOURCE_SYSTEM,
        "decision_system": TERMINAL_DRY_RUN_DECISION_SYSTEM,
        "side_effect_executed": False,
    }

    cases_path = demo_pack_path.parent

    trace = build_run_trace(
        cases_path=cases_path,
        gold_path=cases_path / "demo-pack.json",
        systems=["rules_only"],
        comparison=comparison,
        envelopes=envelopes,
        gold_by_envelope_id=gold_by_envelope_id,
        decisions_by_system=decisions_by_system,
        metadata_generated_by=TERMINAL_DRY_RUN_GENERATED_BY,
        metadata_notes=[
            TERMINAL_DRY_RUN_CLAIM_BOUNDARY,
            f"Source system: {TERMINAL_DRY_RUN_SOURCE_SYSTEM}.",
            f"Decision system: {TERMINAL_DRY_RUN_DECISION_SYSTEM}.",
            "No side effect executed.",
        ],
    )

    trace["claim_boundary"] = TERMINAL_DRY_RUN_CLAIM_BOUNDARY
    trace["metadata"]["demo_kind"] = "terminal_agent_dry_run_v0"
    trace["metadata"]["source_system"] = TERMINAL_DRY_RUN_SOURCE_SYSTEM
    trace["metadata"]["decision_system"] = TERMINAL_DRY_RUN_DECISION_SYSTEM
    trace["metadata"]["side_effect_executed"] = False

    trace["final_verdict"] = {
        "status": "SMOKE_PASS",
        "summary": (
            f"Dry-run complete: {len(cases)} case(s) evaluated with rules-only "
            "Admissible; no side effects executed."
        ),
        "limitations": [
            "This trace is a fixture-based terminal-agent dry-run demonstration only.",
            "It does not establish benchmark validity or product readiness.",
            "Terminal-agent output is not an authority; Admissible decision is deterministic.",
        ],
        "recommended_next_step": (
            "Inspect the HTML trace, then proceed to live terminal-agent integration "
            "only when authorized."
        ),
    }

    for case_item, case_trace in zip(cases, trace["case_traces"], strict=True):
        case = case_item["case"]
        if case.get("benchmark_case_id"):
            case_trace["benchmark_case_id"] = case["benchmark_case_id"]
        case_trace["terminal_agent"] = {
            "source_system": TERMINAL_DRY_RUN_SOURCE_SYSTEM,
            "fixture_path": case["fixture_path"],
            "raw_output": case_item["raw_terminal_output"],
            "side_effect_executed": False,
            "user_task": case.get("user_task"),
        }
        case_trace["notes"] = [
            "Terminal-agent output is source of proposed action intent only.",
            "No side effect executed.",
        ]

        envelope_id = case_trace["envelope_id"]
        decision = decisions_by_system["rules_only"][
            next(i for i, e in enumerate(envelopes) if e["envelope_id"] == envelope_id)
        ]
        gold = gold_by_envelope_id[envelope_id]
        case_trace["scores"] = {
            TERMINAL_DRY_RUN_DECISION_SYSTEM: score_case(decision, gold),
        }

    trace["systems"] = [
        {
            "system_id": TERMINAL_DRY_RUN_DECISION_SYSTEM,
            "system_type": "rules_only",
            "description": (
                "Deterministic rules-only Admissible evaluator over the proposed "
                "action envelope assembled from terminal-agent output."
            ),
            "claim_boundary": TERMINAL_DRY_RUN_CLAIM_BOUNDARY,
        }
    ]

    for case_trace in trace["case_traces"]:
        decisions_map = case_trace.get("decisions") or {}
        if TERMINAL_DRY_RUN_DECISION_SYSTEM not in decisions_map:
            for key, value in list(decisions_map.items()):
                if key.startswith("admissible_rules_only"):
                    decisions_map[TERMINAL_DRY_RUN_DECISION_SYSTEM] = value
                    if key != TERMINAL_DRY_RUN_DECISION_SYSTEM:
                        del decisions_map[key]
                    break
        case_trace["decisions"] = decisions_map

    return trace


def write_terminal_dry_run_trace_and_html(
    *,
    demo_pack_path: str | Path,
    trace_out: str | Path,
    html_out: str | Path,
    repo_root: str | Path = REPO_ROOT,
) -> dict:
    """Build trace JSON and static HTML for the terminal dry-run demo."""
    trace = build_terminal_dry_run_trace(
        demo_pack_path=demo_pack_path,
        repo_root=repo_root,
    )

    trace_out = Path(trace_out)
    trace_out.parent.mkdir(parents=True, exist_ok=True)
    with trace_out.open("w", encoding="utf-8") as f:
        json.dump(trace, f, indent=2, sort_keys=True)
        f.write("\n")

    write_trace_html(trace_out, html_out)
    return trace


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.runner.terminal_dry_run_demo",
        description=(
            "Generate a fixture-based Terminal Agent Dry-Run Demo trace and HTML "
            "report. No network calls, no API keys, no side effects."
        ),
    )
    parser.add_argument(
        "--demo-pack",
        default="benchmark/terminal_agent_dry_run/demo-pack.json",
        help="Path to the terminal dry-run demo-pack.json.",
    )
    parser.add_argument(
        "--trace-out",
        default="benchmark/reports/terminal_agent_dry_run_trace.json",
        help="Path to write the generated trace JSON.",
    )
    parser.add_argument(
        "--html-out",
        default="benchmark/reports/terminal_agent_dry_run_trace.html",
        help="Path to write the rendered HTML report.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    trace = write_terminal_dry_run_trace_and_html(
        demo_pack_path=args.demo_pack,
        trace_out=args.trace_out,
        html_out=args.html_out,
    )

    decisions = [
        case["decisions"].get(TERMINAL_DRY_RUN_DECISION_SYSTEM, {}).get("decision")
        for case in trace["case_traces"]
    ]
    summary = {
        "trace_id": trace["trace_id"],
        "claim_boundary": trace["claim_boundary"],
        "case_count": trace["case_set"]["case_count"],
        "source_system": trace["metadata"]["source_system"],
        "decision_system": trace["metadata"]["decision_system"],
        "decisions": decisions,
        "side_effect_executed": False,
        "final_verdict": trace["final_verdict"]["status"],
        "trace_out": str(Path(args.trace_out)),
        "html_out": str(Path(args.html_out)),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
