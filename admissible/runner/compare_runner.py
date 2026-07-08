"""Baseline scoring comparison harness for Admissible (Slice H).

Runs multiple systems over the same Tier 1 enriched action envelopes and
reports their benchmark.scoring.score_decisions summaries side by side.
This is still a Tier 1 enriched smoke-test layer: it does not make public
benchmark claims, does not call a live model by default, does not build a
UI, and does not build long-run traces by default (use --trace-out to emit one).

Supported systems:

- rules_only: admissible.evaluator.rules_only.evaluate_envelope, a
  deterministic reference evaluator over already-enriched envelope
  fields.
- frontier_direct_mock: admissible.runner.baseline_runner
  .run_frontier_direct_baseline, called with a fixed mock model response
  for every case. This is a plumbing/mock baseline for exercising the
  comparison harness, not a measurement of any real frontier model's
  performance.
- frontier_direct_live: admissible.runner.baseline_runner
  .run_frontier_direct_baseline, called with a live model client built from
  environment variables. Opt-in only; not used by default or in tests.
- frontier_direct_hf: admissible.runner.baseline_runner
  .run_frontier_direct_baseline, called with a Hugging Face Inference Providers
  client built from ADMISSIBLE_HF_* environment variables. Opt-in only.
- frontier_direct_gemini: admissible.runner.baseline_runner
  .run_frontier_direct_baseline, called with a Google Gemini generateContent
  client built from ADMISSIBLE_GEMINI_* environment variables. Opt-in only.

Also runnable as a CLI:

    python -m admissible.runner.compare_runner \\
        --cases benchmark/cases/tier_1_enriched \\
        --gold benchmark/annotations/gold_labels.jsonl \\
        --systems rules_only frontier_direct_mock \\
        --mock-response benchmark/examples/mock_frontier_response.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from admissible.evaluator.rules_only import evaluate_envelope
from admissible.runner.baseline_runner import ModelClient, run_frontier_direct_baseline
from admissible.runner.model_clients import (
    FixedResponseModelClient,
    build_gemini_model_client_from_env,
    build_huggingface_model_client_from_env,
    build_model_client_from_env,
)
from admissible.trace import build_run_trace
from benchmark.scoring.score_decisions import TIER_1_CLAIM_BOUNDARY, load_gold_annotations, score_decisions

SUPPORTED_SYSTEMS: tuple[str, ...] = (
    "rules_only",
    "frontier_direct_mock",
    "frontier_direct_live",
    "frontier_direct_hf",
    "frontier_direct_gemini",
)

FRONTIER_MOCK_NOTE = "frontier_direct_mock is a plumbing/mock baseline, not a model-performance result."
FRONTIER_LIVE_NOTE = (
    "frontier_direct_live uses an externally configured model provider; "
    "results are not stable benchmark claims."
)
FRONTIER_HF_NOTE = (
    "frontier_direct_hf uses Hugging Face Inference Providers; "
    "results are not stable benchmark claims."
)
FRONTIER_GEMINI_NOTE = (
    "frontier_direct_gemini uses Google Gemini generateContent; "
    "results are not stable benchmark claims."
)

DEFAULT_FRONTIER_MOCK_SYSTEM_ID = "frontier_direct_mock_v0"
DEFAULT_FRONTIER_LIVE_SYSTEM_ID = "frontier_direct_live_v0"
DEFAULT_FRONTIER_HF_SYSTEM_ID = "frontier_direct_hf_v0"
DEFAULT_FRONTIER_GEMINI_SYSTEM_ID = "frontier_direct_gemini_v0"


def _envelope_id(envelope: dict) -> str:
    envelope_id = envelope.get("envelope_id")
    return envelope_id if isinstance(envelope_id, str) else "<unknown>"


def _run_with_envelope_context(
    system: str,
    case_index: int,
    envelope: dict,
    run_fn,
) -> dict:
    try:
        return run_fn(envelope)
    except Exception as exc:
        raise type(exc)(
            f"{exc}; system_id={system!r}, envelope_id={_envelope_id(envelope)!r}, "
            f"case_index={case_index}"
        ) from exc


def _envelope_sort_key(envelope: dict) -> str:
    metadata = envelope.get("metadata") or {}
    benchmark_case_id = metadata.get("benchmark_case_id")
    if isinstance(benchmark_case_id, str) and benchmark_case_id:
        return benchmark_case_id
    envelope_id = envelope.get("envelope_id")
    return envelope_id if isinstance(envelope_id, str) else ""


def load_envelopes(cases_path: str | Path) -> list[dict]:
    """Load all *.envelope.json action envelopes under cases_path.

    Returned in a deterministic order: sorted by metadata.benchmark_case_id
    when present, falling back to envelope_id. This is independent of
    filesystem glob order so results are stable across platforms.
    """
    cases_path = Path(cases_path)
    envelopes = []
    for path in sorted(cases_path.glob("**/*.envelope.json")):
        with path.open(encoding="utf-8") as f:
            envelopes.append(json.load(f))
    envelopes.sort(key=_envelope_sort_key)
    return envelopes


def _mock_response_text(mock_response: dict | str) -> str:
    if isinstance(mock_response, str):
        return mock_response
    if isinstance(mock_response, dict):
        return json.dumps(mock_response)
    raise ValueError(
        f"mock_response must be a dict or str, got {type(mock_response).__name__}"
    )


def _run_frontier_direct_mock(
    envelopes: list[dict],
    *,
    mock_response: dict | str | None,
    model_client: ModelClient | None = None,
) -> list[dict]:
    if model_client is None:
        if mock_response is None:
            raise ValueError(
                "system 'frontier_direct_mock' requires a mock_response (dict or JSON string)"
            )
        model_client = FixedResponseModelClient(_mock_response_text(mock_response))

    return [
        _run_with_envelope_context(
            "frontier_direct_mock",
            case_index,
            envelope,
            lambda env, mc=model_client: run_frontier_direct_baseline(
                env, model_client=mc, system_id=DEFAULT_FRONTIER_MOCK_SYSTEM_ID
            ),
        )
        for case_index, envelope in enumerate(envelopes)
    ]


def _run_frontier_direct_live(
    envelopes: list[dict],
    *,
    model_client: ModelClient | None = None,
) -> list[dict]:
    if model_client is None:
        model_client = build_model_client_from_env()

    return [
        _run_with_envelope_context(
            "frontier_direct_live",
            case_index,
            envelope,
            lambda env, mc=model_client: run_frontier_direct_baseline(
                env, model_client=mc, system_id=DEFAULT_FRONTIER_LIVE_SYSTEM_ID
            ),
        )
        for case_index, envelope in enumerate(envelopes)
    ]


def _run_frontier_direct_hf(
    envelopes: list[dict],
    *,
    model_client: ModelClient | None = None,
) -> list[dict]:
    if model_client is None:
        model_client = build_huggingface_model_client_from_env()

    return [
        _run_with_envelope_context(
            "frontier_direct_hf",
            case_index,
            envelope,
            lambda env, mc=model_client: run_frontier_direct_baseline(
                env, model_client=mc, system_id=DEFAULT_FRONTIER_HF_SYSTEM_ID
            ),
        )
        for case_index, envelope in enumerate(envelopes)
    ]


def _run_frontier_direct_gemini(
    envelopes: list[dict],
    *,
    model_client: ModelClient | None = None,
) -> list[dict]:
    if model_client is None:
        model_client = build_gemini_model_client_from_env()

    return [
        _run_with_envelope_context(
            "frontier_direct_gemini",
            case_index,
            envelope,
            lambda env, mc=model_client: run_frontier_direct_baseline(
                env, model_client=mc, system_id=DEFAULT_FRONTIER_GEMINI_SYSTEM_ID
            ),
        )
        for case_index, envelope in enumerate(envelopes)
    ]


def run_system_on_envelopes(
    system: str,
    envelopes: list[dict],
    *,
    mock_response: dict | str | None = None,
) -> list[dict]:
    """Run one named system over a list of action envelopes.

    `rules_only` calls admissible.evaluator.rules_only.evaluate_envelope
    directly; it takes no mock_response. `frontier_direct_mock` calls
    admissible.runner.baseline_runner.run_frontier_direct_baseline with a
    single fixed mock response reused for every envelope; mock_response is
    required for it and raises ValueError if omitted. `frontier_direct_live`
    calls the same baseline runner with a live model client from environment
    variables. Raises ValueError for any other system name.
    """
    if system == "rules_only":
        return [
            _run_with_envelope_context(system, case_index, envelope, evaluate_envelope)
            for case_index, envelope in enumerate(envelopes)
        ]
    if system == "frontier_direct_mock":
        return _run_frontier_direct_mock(envelopes, mock_response=mock_response)
    if system == "frontier_direct_live":
        return _run_frontier_direct_live(envelopes)
    if system == "frontier_direct_hf":
        return _run_frontier_direct_hf(envelopes)
    if system == "frontier_direct_gemini":
        return _run_frontier_direct_gemini(envelopes)
    raise ValueError(
        f"unknown system: {system!r}; supported systems: {SUPPORTED_SYSTEMS}"
    )


def gather_comparison_data(
    cases_path: str | Path,
    gold_path: str | Path,
    systems: list[str],
    *,
    mock_response_path: str | Path | None = None,
) -> tuple[dict, list[dict], dict[str, dict], dict[str, list[dict]]]:
    """Run each system and return comparison plus trace-building inputs.

    Returns ``(comparison, envelopes, gold_by_envelope_id, decisions_by_system)``.
    """
    envelopes = load_envelopes(cases_path)
    gold_by_envelope_id = load_gold_annotations(gold_path)

    mock_response: dict | str | None = None
    if mock_response_path is not None:
        with Path(mock_response_path).open(encoding="utf-8") as f:
            mock_response = json.load(f)

    decisions_by_system: dict[str, list[dict]] = {}
    results: dict[str, dict] = {}
    for system in systems:
        decisions = run_system_on_envelopes(system, envelopes, mock_response=mock_response)
        decisions_by_system[system] = decisions
        summary = score_decisions(decisions, gold_by_envelope_id)
        summary["claim_boundary"] = TIER_1_CLAIM_BOUNDARY
        if system == "frontier_direct_mock":
            summary["notes"] = FRONTIER_MOCK_NOTE
        if system == "frontier_direct_live":
            summary["notes"] = FRONTIER_LIVE_NOTE
        if system == "frontier_direct_hf":
            summary["notes"] = FRONTIER_HF_NOTE
        if system == "frontier_direct_gemini":
            summary["notes"] = FRONTIER_GEMINI_NOTE
        results[system] = summary

    comparison = {
        "systems": list(systems),
        "case_count": len(envelopes),
        "claim_boundary": TIER_1_CLAIM_BOUNDARY,
        "results": results,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    comparison_notes: list[str] = []
    if "frontier_direct_mock" in systems:
        comparison_notes.append(FRONTIER_MOCK_NOTE)
    if "frontier_direct_live" in systems:
        comparison_notes.append(FRONTIER_LIVE_NOTE)
    if "frontier_direct_hf" in systems:
        comparison_notes.append(FRONTIER_HF_NOTE)
    if "frontier_direct_gemini" in systems:
        comparison_notes.append(FRONTIER_GEMINI_NOTE)
    if comparison_notes:
        comparison["notes"] = " ".join(comparison_notes)
    return comparison, envelopes, gold_by_envelope_id, decisions_by_system


def compare_systems(
    cases_path: str | Path,
    gold_path: str | Path,
    systems: list[str],
    *,
    mock_response_path: str | Path | None = None,
) -> dict:
    """Run each system in `systems` over the same envelope set and score it.

    Loads envelopes once (via load_envelopes) and gold annotations once
    (via benchmark.scoring.score_decisions.load_gold_annotations), then
    scores each system's output against the same gold set with
    score_decisions. Every result, and the comparison as a whole, carries
    the Tier 1 enriched seed smoke-test claim boundary; the
    frontier_direct_mock result additionally carries an explicit
    plumbing/mock-only note so it is never read as a model-performance
    result.
    """
    comparison, _, _, _ = gather_comparison_data(
        cases_path,
        gold_path,
        systems,
        mock_response_path=mock_response_path,
    )
    return comparison


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.runner.compare_runner",
        description=(
            "Run multiple Admissible systems over the same Tier 1 enriched case set "
            "and print their scoring metrics side by side. Tier 1 enriched seed smoke "
            "test only; not a benchmark result."
        ),
    )
    parser.add_argument(
        "--cases",
        required=True,
        help="Directory containing *.envelope.json action envelopes (searched recursively).",
    )
    parser.add_argument(
        "--gold",
        required=True,
        help="Path to a gold_labels.jsonl file.",
    )
    parser.add_argument(
        "--systems",
        required=True,
        nargs="+",
        choices=SUPPORTED_SYSTEMS,
        help="One or more systems to compare.",
    )
    parser.add_argument(
        "--mock-response",
        default=None,
        help=(
            "Path to a JSON file containing a fixed mock frontier response, reused for "
            "every case. Required if 'frontier_direct_mock' is among --systems."
        ),
    )
    parser.add_argument(
        "--trace-out",
        default=None,
        help=(
            "Optional path to write a durable run trace JSON file. The comparison "
            "summary is still printed to stdout."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if args.trace_out:
        comparison, envelopes, gold_by_envelope_id, decisions_by_system = gather_comparison_data(
            args.cases,
            args.gold,
            args.systems,
            mock_response_path=args.mock_response,
        )
        trace = build_run_trace(
            cases_path=args.cases,
            gold_path=args.gold,
            systems=args.systems,
            comparison=comparison,
            envelopes=envelopes,
            gold_by_envelope_id=gold_by_envelope_id,
            decisions_by_system=decisions_by_system,
        )
        trace_path = Path(args.trace_out)
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        with trace_path.open("w", encoding="utf-8") as f:
            json.dump(trace, f, indent=2, sort_keys=True)
            f.write("\n")
    else:
        comparison = compare_systems(
            args.cases,
            args.gold,
            args.systems,
            mock_response_path=args.mock_response,
        )

    print(json.dumps(comparison, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
