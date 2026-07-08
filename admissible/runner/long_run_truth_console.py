"""Admissible Long-Run Truth Console v0 — fixture-backed, no side effects.

Builds a TruthTrace from terminal dry-run fixtures embedded in a
long-run Slither-like game scenario context, then renders a static HTML
truth console for local inspection.

Does not call Cursor, Claude Code, Codex, Gemini, or any network
provider. No API keys, no secrets, no workspace mutation.

CLI:

    python -m admissible.runner.long_run_truth_console \\
        --out benchmark/reports/admissible_long_run_truth_console.html
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from admissible.harness.truth_console import write_truth_console_html
from admissible.long_run_truth import (
    LONG_RUN_CLAIM_BOUNDARY,
    LONG_RUN_FRONTIER_AGENT_LABEL,
    build_truth_trace,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

DEFAULT_DEMO_PACK = "benchmark/terminal_agent_dry_run/demo-pack.json"
DEFAULT_HTML_OUT = "benchmark/reports/admissible_long_run_truth_console.html"
DEFAULT_TRACE_OUT = "benchmark/reports/admissible_long_run_truth_console_trace.json"


def write_long_run_truth_console(
    *,
    demo_pack_path: str | Path,
    html_out: str | Path,
    trace_out: str | Path | None = None,
    repo_root: str | Path = REPO_ROOT,
) -> dict:
    """Build truth trace and write HTML console (and optional JSON trace)."""
    trace = build_truth_trace(
        demo_pack_path=str(demo_pack_path),
        repo_root=str(repo_root),
    )

    if trace_out is not None:
        trace_out = Path(trace_out)
        trace_out.parent.mkdir(parents=True, exist_ok=True)
        with trace_out.open("w", encoding="utf-8") as f:
            json.dump(trace, f, indent=2, sort_keys=True)
            f.write("\n")

    write_truth_console_html(trace, html_out)
    return trace


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.runner.long_run_truth_console",
        description=(
            "Generate the Admissible Long-Run Truth Console HTML from "
            "fixture-backed terminal dry-run cases. No network, no side effects."
        ),
    )
    parser.add_argument(
        "--demo-pack",
        default=DEFAULT_DEMO_PACK,
        help="Path to terminal dry-run demo-pack.json.",
    )
    parser.add_argument(
        "--out",
        default=DEFAULT_HTML_OUT,
        help="Path to write the truth console HTML.",
    )
    parser.add_argument(
        "--trace-out",
        default=DEFAULT_TRACE_OUT,
        help="Path to write the truth trace JSON (for inspection/reuse).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    trace = write_long_run_truth_console(
        demo_pack_path=args.demo_pack,
        html_out=args.out,
        trace_out=args.trace_out,
    )

    decisions = [d["decision"] for d in trace["decisions"]]
    operational = [d["operational_admissibility_action"] for d in trace["decisions"]]

    summary = {
        "run_id": trace["long_run"]["run_id"],
        "claim_boundary": LONG_RUN_CLAIM_BOUNDARY,
        "frontier_agent_label": LONG_RUN_FRONTIER_AGENT_LABEL,
        "action_count": len(trace["action_candidates"]),
        "decisions": decisions,
        "operational_admissibility_actions": operational,
        "side_effect_executed": False,
        "html_out": str(Path(args.out)),
        "trace_out": str(Path(args.trace_out)),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
