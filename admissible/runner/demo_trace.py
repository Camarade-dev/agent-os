"""Deterministic demo-trace generator for the curated Admissible demo pack (Slice L).

Takes the curated 8-case demo scenario pack (benchmark/reports/demo-pack.json,
see Slice K) and produces a run trace + static HTML viewer artifact scoped to
exactly those selected cases. This is still a mock/plumbing demo layer: it
runs only `rules_only` and `frontier_direct_mock` (the latter using a fixed
mock model response, see benchmark/examples/mock_frontier_response.json), it
never calls a live model or network, and it makes no benchmark claims.

Reuses existing modules rather than duplicating their logic:

- admissible.runner.compare_runner.run_system_on_envelopes for running each
  system;
- benchmark.scoring.score_decisions for scoring;
- admissible.trace.build_run_trace for the run trace shape;
- admissible.harness.viewer.write_trace_html for rendering the static HTML
  report.

Also runnable as a CLI:

    python -m admissible.runner.demo_trace \\
        --demo-pack benchmark/reports/demo-pack.json \\
        --gold benchmark/annotations/gold_labels.jsonl \\
        --mock-response benchmark/examples/mock_frontier_response.json \\
        --trace-out benchmark/reports/demo_trace.json \\
        --html-out benchmark/reports/demo_trace.html
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from admissible.harness.viewer import write_trace_html
from admissible.runner.compare_runner import FRONTIER_MOCK_NOTE, run_system_on_envelopes
from admissible.trace import build_run_trace
from benchmark.scoring.score_decisions import (
    TIER_1_CLAIM_BOUNDARY,
    load_gold_annotations,
    score_decisions,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CASES_ROOT = (REPO_ROOT / "benchmark" / "cases" / "tier_1_enriched").resolve()

DEMO_PACK_CLAIM_BOUNDARY = "Curated Tier 1 enriched demo pack; not a benchmark result."
DEMO_TRACE_DISCLAIMER_NOTE = (
    "Curated demo trace using frontier_direct_mock; not a live frontier-model result."
)
DEMO_TRACE_GENERATED_BY = "admissible.runner.demo_trace"
DEMO_SYSTEMS: tuple[str, ...] = ("rules_only", "frontier_direct_mock")

_MIN_SELECTED_CASES = 5
_MAX_SELECTED_CASES = 8


def load_demo_pack(path: str | Path) -> dict:
    """Load and validate benchmark/reports/demo-pack.json (or an equivalent).

    Raises ValueError if the file is not valid JSON, if the parsed JSON is
    not an object, if `claim_boundary` is not exactly
    DEMO_PACK_CLAIM_BOUNDARY, if `selected_cases` is not a list, or if it
    does not contain between 5 and 8 entries. Does not validate individual
    case entries; see load_demo_envelopes for that.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    try:
        demo_pack = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON demo pack file: {exc}") from exc

    if not isinstance(demo_pack, dict):
        raise ValueError(
            f"{path}: demo pack must be a JSON object, got {type(demo_pack).__name__}"
        )

    claim_boundary = demo_pack.get("claim_boundary")
    if claim_boundary != DEMO_PACK_CLAIM_BOUNDARY:
        raise ValueError(
            f"{path}: demo pack 'claim_boundary' must be exactly "
            f"{DEMO_PACK_CLAIM_BOUNDARY!r}, got {claim_boundary!r}"
        )

    selected_cases = demo_pack.get("selected_cases")
    if not isinstance(selected_cases, list):
        raise ValueError(f"{path}: demo pack 'selected_cases' must be a list")
    if not (_MIN_SELECTED_CASES <= len(selected_cases) <= _MAX_SELECTED_CASES):
        raise ValueError(
            f"{path}: demo pack must select between {_MIN_SELECTED_CASES} and "
            f"{_MAX_SELECTED_CASES} cases, got {len(selected_cases)}"
        )

    return demo_pack


def load_demo_envelopes(demo_pack: dict, *, repo_root: str | Path = REPO_ROOT) -> list[dict]:
    """Load the action envelope for every case in demo_pack['selected_cases'].

    Returned in the same order as `selected_cases`, one envelope per entry.
    For each entry, raises ValueError if `case_path` is missing/empty, if it
    does not stay under benchmark/cases/tier_1_enriched, if the resolved
    file does not exist, or if the loaded envelope's
    `metadata.benchmark_case_id` does not match the entry's
    `benchmark_case_id`.
    """
    repo_root = Path(repo_root)
    cases_root = (repo_root / "benchmark" / "cases" / "tier_1_enriched").resolve()

    envelopes: list[dict] = []
    for case in demo_pack["selected_cases"]:
        expected_case_id = case.get("benchmark_case_id")
        case_path_value = case.get("case_path")
        if not isinstance(case_path_value, str) or not case_path_value:
            raise ValueError(
                f"demo pack case {expected_case_id!r} has no valid 'case_path'"
            )

        normalized = case_path_value.replace("\\", "/")
        if not normalized.startswith("benchmark/cases/tier_1_enriched/"):
            raise ValueError(
                f"demo pack case_path {case_path_value!r} must stay under "
                "benchmark/cases/tier_1_enriched"
            )

        resolved = (repo_root / case_path_value).resolve()
        if cases_root != resolved and cases_root not in resolved.parents:
            raise ValueError(
                f"demo pack case_path {case_path_value!r} resolves outside "
                "benchmark/cases/tier_1_enriched"
            )
        if not resolved.is_file():
            raise ValueError(
                f"demo pack case_path {case_path_value!r} does not exist"
            )

        with resolved.open(encoding="utf-8") as f:
            envelope = json.load(f)

        envelope_case_id = (envelope.get("metadata") or {}).get("benchmark_case_id")
        if envelope_case_id != expected_case_id:
            raise ValueError(
                f"demo pack case {expected_case_id!r} does not match loaded "
                f"envelope's metadata.benchmark_case_id {envelope_case_id!r} "
                f"({case_path_value})"
            )

        envelopes.append(envelope)

    return envelopes


def _relative_note_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def build_demo_trace(
    *,
    demo_pack_path: str | Path,
    gold_path: str | Path,
    mock_response_path: str | Path,
) -> dict:
    """Build a run trace scoped to exactly the curated demo pack's cases.

    Runs `rules_only` and `frontier_direct_mock` over the selected case
    envelopes only, scores both against gold, and returns a run trace via
    admissible.trace.build_run_trace. Raises ValueError if selection
    integrity checks fail (see load_demo_pack / load_demo_envelopes) or if
    any selected case has no matching gold annotation by envelope_id.
    """
    demo_pack_path = Path(demo_pack_path)
    demo_pack = load_demo_pack(demo_pack_path)
    envelopes = load_demo_envelopes(demo_pack)

    gold_by_envelope_id = load_gold_annotations(gold_path)
    for envelope in envelopes:
        envelope_id = envelope["envelope_id"]
        if envelope_id not in gold_by_envelope_id:
            benchmark_case_id = (envelope.get("metadata") or {}).get("benchmark_case_id")
            raise ValueError(
                f"no gold annotation found for envelope_id {envelope_id!r} "
                f"(benchmark_case_id={benchmark_case_id!r})"
            )

    with Path(mock_response_path).open(encoding="utf-8") as f:
        mock_response = json.load(f)

    decisions_by_system: dict[str, list[dict]] = {}
    results: dict[str, dict] = {}
    for system in DEMO_SYSTEMS:
        decisions = run_system_on_envelopes(system, envelopes, mock_response=mock_response)
        decisions_by_system[system] = decisions
        summary = score_decisions(decisions, gold_by_envelope_id)
        summary["claim_boundary"] = TIER_1_CLAIM_BOUNDARY
        if system == "frontier_direct_mock":
            summary["notes"] = FRONTIER_MOCK_NOTE
        results[system] = summary

    comparison = {
        "systems": list(DEMO_SYSTEMS),
        "case_count": len(envelopes),
        "claim_boundary": TIER_1_CLAIM_BOUNDARY,
        "results": results,
        "notes": FRONTIER_MOCK_NOTE,
    }

    cases_path = demo_pack.get("source_case_set") or str(CASES_ROOT)

    return build_run_trace(
        cases_path=cases_path,
        gold_path=gold_path,
        systems=list(DEMO_SYSTEMS),
        comparison=comparison,
        envelopes=envelopes,
        gold_by_envelope_id=gold_by_envelope_id,
        decisions_by_system=decisions_by_system,
        metadata_generated_by=DEMO_TRACE_GENERATED_BY,
        metadata_notes=[
            DEMO_TRACE_DISCLAIMER_NOTE,
            f"Selected from {_relative_note_path(demo_pack_path)}.",
        ],
    )


def write_demo_trace_and_html(
    *,
    demo_pack_path: str | Path,
    gold_path: str | Path,
    mock_response_path: str | Path,
    trace_out: str | Path,
    html_out: str | Path,
) -> dict:
    """Build a demo trace and write both the trace JSON and rendered HTML.

    Returns the built trace dict. Reuses
    admissible.harness.viewer.write_trace_html for rendering, so the HTML
    output is produced by the same code path as any other run trace.
    """
    trace = build_demo_trace(
        demo_pack_path=demo_pack_path,
        gold_path=gold_path,
        mock_response_path=mock_response_path,
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
        prog="python -m admissible.runner.demo_trace",
        description=(
            "Generate a deterministic demo run trace and static HTML viewer report "
            "scoped to the curated Admissible demo pack (benchmark/reports/demo-pack.json). "
            "Mock/plumbing demo only: no live model call, no live model provider, no "
            "network access, no benchmark claim."
        ),
    )
    parser.add_argument(
        "--demo-pack",
        required=True,
        help="Path to demo-pack.json (see benchmark/reports/demo-pack.json).",
    )
    parser.add_argument(
        "--gold",
        required=True,
        help="Path to a gold_labels.jsonl file.",
    )
    parser.add_argument(
        "--mock-response",
        required=True,
        help="Path to a JSON file containing a fixed mock frontier response.",
    )
    parser.add_argument(
        "--trace-out",
        required=True,
        help="Path to write the generated demo run trace JSON.",
    )
    parser.add_argument(
        "--html-out",
        required=True,
        help="Path to write the rendered demo trace HTML report.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    trace = write_demo_trace_and_html(
        demo_pack_path=args.demo_pack,
        gold_path=args.gold,
        mock_response_path=args.mock_response,
        trace_out=args.trace_out,
        html_out=args.html_out,
    )

    summary = {
        "trace_id": trace["trace_id"],
        "claim_boundary": trace["claim_boundary"],
        "case_count": trace["case_set"]["case_count"],
        "systems": [descriptor["system_id"] for descriptor in trace["systems"]],
        "final_verdict": trace["final_verdict"]["status"],
        "notes": trace["metadata"]["notes"],
        "trace_out": str(Path(args.trace_out)),
        "html_out": str(Path(args.html_out)),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
