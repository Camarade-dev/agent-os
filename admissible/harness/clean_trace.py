"""Offline sanitizer for Admissible run traces with dirty provider output.

Loads an existing run_trace.json, walks
``case_traces[*].decisions[*].metadata.raw_provider_response_text``,
and replaces dirty frontier provider text with the first valid JSON object
using the same extraction logic as admissible.runner.baseline_runner.

This is a post-run, read-only repair tool:

- it does not call a model or any network API;
- it does not require Hugging Face or other provider environment variables;
- it does not mutate scoring, decision labels, envelopes, gold annotations,
  aggregate results, trace_id, or claim_boundary;
- it only sanitizes stored provider response text and adds bounded audit
  metadata when sanitization occurs.

Also runnable as a CLI:

    python -m admissible.harness.clean_trace \\
        --trace benchmark/reports/hf_demo_trace.json \\
        --out benchmark/reports/hf_demo_trace.cleaned.json \\
        --html-out benchmark/reports/hf_demo_trace.cleaned.html
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

from admissible.harness.viewer import load_trace, render_trace_html
from admissible.runner.baseline_runner import (
    _build_provider_output_metadata,
    _extract_json_with_span,
    _normalize_response_text,
)


def sanitize_provider_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Return metadata with sanitized raw_provider_response_text when dirty."""
    original_text = metadata.get("raw_provider_response_text")
    if not isinstance(original_text, str):
        return metadata

    extraction = _extract_json_with_span(original_text)
    if extraction is None:
        return metadata

    clean_json_text, _start, end = extraction
    normalized = _normalize_response_text(original_text)
    trailing_text = normalized[end:].strip()

    updated = dict(metadata)
    updated["raw_provider_response_text"] = clean_json_text
    updated.update(
        _build_provider_output_metadata(original_text, clean_json_text, trailing_text)
    )
    return updated


def clean_trace(trace: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of trace with sanitized provider response metadata."""
    cleaned = copy.deepcopy(trace)
    case_traces = cleaned.get("case_traces")
    if not isinstance(case_traces, list):
        return cleaned

    for case_trace in case_traces:
        if not isinstance(case_trace, dict):
            continue
        decisions = case_trace.get("decisions")
        if not isinstance(decisions, dict):
            continue
        for decision in decisions.values():
            if not isinstance(decision, dict):
                continue
            metadata = decision.get("metadata")
            if isinstance(metadata, dict) and "raw_provider_response_text" in metadata:
                decision["metadata"] = sanitize_provider_metadata(metadata)
    return cleaned


def write_cleaned_trace(
    trace_path: str | Path,
    out_path: str | Path,
    *,
    html_out: str | Path | None = None,
) -> Path:
    """Load, sanitize, and write a run trace JSON file.

    When html_out is supplied, also writes a static HTML report using the
    existing viewer. Does not modify the source trace file.
    """
    trace = load_trace(trace_path)
    cleaned = clean_trace(trace)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(cleaned, f, indent=2, sort_keys=True)
        f.write("\n")

    if html_out is not None:
        html_path = Path(html_out)
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_trace_html(cleaned), encoding="utf-8")

    return out_path


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.harness.clean_trace",
        description=(
            "Sanitize dirty provider output in an existing Admissible run trace "
            "JSON file. Offline only: no model calls, no network access."
        ),
    )
    parser.add_argument(
        "--trace",
        required=True,
        help="Path to an existing run_trace.json file.",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Path to write the sanitized run trace JSON.",
    )
    parser.add_argument(
        "--html-out",
        help="Optional path to write a static HTML report from the cleaned trace.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    out_path = write_cleaned_trace(args.trace, args.out, html_out=args.html_out)
    print(str(out_path))
    if args.html_out:
        print(str(Path(args.html_out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
