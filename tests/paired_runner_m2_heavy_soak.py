"""The explicit Milestone 2 output soak driver.

Two levels exist:

* the *regression* soak, small enough to run in the normal automated suite but
  large enough that an unbounded queue or an unbounded retention buffer would be
  obvious;
* the *heavy* soak, which meets the governing target of at least 1,000,000
  output lines **and** at least 1 GiB of combined stdout/stderr.

Run the heavy soak directly:

    python3 tests/paired_runner_m2_heavy_soak.py --report implementation/M2_OUTPUT_SOAK_REPORT.json

The soak is provider-free.  The child is this interpreter running an inline
generator; no network, provider, model, or authority is involved, and every byte
is produced and consumed inside a disposable temporary workspace.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from _paired_runner_m2_fixtures import (  # noqa: E402
    PYTHON,
    DisposableWorkspace,
    build_proposal,
    build_specification,
    decision_for,
)
from admissible.paired_runner.canonical import canonical_bytes  # noqa: E402
from admissible.paired_runner.durable_store import DurableObjectStore  # noqa: E402
from admissible.paired_runner.effect_ledger import RunEffectLedger  # noqa: E402
from admissible.paired_runner.effects import SharedEffectSubstrate, WorkspaceBinding  # noqa: E402
from admissible.paired_runner.process_supervision import controller_memory_bound  # noqa: E402
from admissible.paired_runner.tool_schemas import RunCommandRequest  # noqa: E402


#: The controller-memory acceptance threshold declared in
#: implementation/M2_PLATFORM_AND_DURABILITY_CONTRACT.md.
CONTROLLER_RSS_GROWTH_LIMIT_BYTES = 64 * 1024 * 1024

GENERATOR = """
import sys
lines = {lines}
line_bytes = {line_bytes}
stderr_share = {stderr_share}
block_lines = max(1, 65536 // line_bytes)
payload = ('a' * (line_bytes - 1) + '\\n')
block = (payload * block_lines).encode('ascii')
out = sys.stdout.buffer
err = sys.stderr.buffer
written = 0
toggle = 0
while written < lines:
    count = min(block_lines, lines - written)
    chunk = block if count == block_lines else (payload * count).encode('ascii')
    if stderr_share and toggle % 2 == 1:
        err.write(chunk)
    else:
        out.write(chunk)
    toggle += 1
    written += count
out.flush()
err.flush()
"""


def _proc_status_kib(field: str) -> int | None:
    try:
        text = Path("/proc/self/status").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith(f"{field}:"):
            return int(line.split()[1])
    return None


def run_soak(
    *,
    lines: int,
    line_bytes: int,
    max_output_bytes: int,
    split_stderr: bool,
    timeout_ms: int,
) -> dict[str, object]:
    """Run one soak and return a fully explicit measurement record."""

    specification = build_specification("DIRECT", run_id="run-soak")
    script = GENERATOR.format(
        lines=lines, line_bytes=line_bytes, stderr_share="True" if split_stderr else "False"
    )
    argv = [PYTHON, "-c", script]
    baseline_rss_kib = _proc_status_kib("VmRSS")
    baseline_peak_kib = _proc_status_kib("VmHWM")

    with DisposableWorkspace(prefix="admissible-m2-soak-") as disposable:
        binding = WorkspaceBinding.bind(
        disposable.workspace, specification, evidence_root=disposable.store_root
    )
        try:
            store = DurableObjectStore(disposable.store_root)
            substrate = SharedEffectSubstrate(
                binding=binding, store=store, ledger=RunEffectLedger("run-soak")
            )
            request = RunCommandRequest.create(
                tool_grammar_fingerprint=specification.tool_grammar.grammar_fingerprint,
                argv=argv,
                timeout_ms=timeout_ms,
                max_output_bytes=max_output_bytes,
            )
            proposal = build_proposal(specification, request, proposal_id="proposal-soak")
            started = time.monotonic_ns()
            outcome = substrate.execute(
                specification=specification,
                proposal=proposal,
                decision=decision_for(proposal),
                reservation_id="reservation-soak",
                receipt_id="receipt-soak",
            )
            wall_ns = time.monotonic_ns() - started
            stdout = store.load("stdout-observation", "proposal-soak")
            stderr = store.load("stderr-observation", "proposal-soak")
            process = store.load("process-observation", "proposal-soak")
            resource = store.load("resource-observation", "proposal-soak")
        finally:
            binding.close()

    peak_rss_kib = _proc_status_kib("VmHWM")
    final_rss_kib = _proc_status_kib("VmRSS")
    growth_bytes = None
    if peak_rss_kib is not None and baseline_rss_kib is not None:
        growth_bytes = max(0, (peak_rss_kib - baseline_rss_kib) * 1024)

    total_bytes = stdout["total_bytes"] + stderr["total_bytes"]
    return {
        "command": argv[:2] + ["<inline generator>"],
        "generator_parameters": {
            "lines": lines,
            "line_bytes": line_bytes,
            "split_stderr": split_stderr,
            "max_output_bytes": max_output_bytes,
            "timeout_ms": timeout_ms,
        },
        "receipt_status": outcome.receipt.status,
        "exit_code": process["exit_code"],
        "total_output_bytes": total_bytes,
        "total_output_lines": total_bytes // line_bytes,
        "stdout_total_bytes": stdout["total_bytes"],
        "stderr_total_bytes": stderr["total_bytes"],
        "stdout_retained_bytes": stdout["retained_bytes"],
        "stderr_retained_bytes": stderr["retained_bytes"],
        "stdout_truncated": stdout["retained_truncated"],
        "stderr_truncated": stderr["retained_truncated"],
        "stdout_stream_fingerprint": stdout["stream_fingerprint"]["value"],
        "stderr_stream_fingerprint": stderr["stream_fingerprint"]["value"],
        "stdout_text_decode_status": stdout["text_decode_status"],
        "stderr_text_decode_status": stderr["text_decode_status"],
        "wall_time_ms": wall_ns // 1_000_000,
        "controller_baseline_rss_bytes": None if baseline_rss_kib is None else baseline_rss_kib * 1024,
        "controller_baseline_peak_rss_bytes": None if baseline_peak_kib is None else baseline_peak_kib * 1024,
        "controller_peak_rss_bytes": None if peak_rss_kib is None else peak_rss_kib * 1024,
        "controller_final_rss_bytes": None if final_rss_kib is None else final_rss_kib * 1024,
        "controller_rss_growth_bytes": growth_bytes,
        "controller_rss_growth_availability": "OBSERVED" if growth_bytes is not None else "UNAVAILABLE_ON_PLATFORM",
        "controller_rss_growth_limit_bytes": CONTROLLER_RSS_GROWTH_LIMIT_BYTES,
        "controller_retention_bound_bytes": controller_memory_bound(max_output_bytes),
        "controller_peak_retained_output_bytes": resource["controller_peak_retained_output_bytes"],
        "child_cleanup": {
            "descendants_reaped": process["descendants_reaped"],
            "termination_escalation": process["termination_escalation"],
            "timed_out": process["timed_out"],
            "cancelled": process["cancelled"],
        },
        "reconciliation_classification": outcome.reconciliation.classification,
    }


def regression_soak() -> dict[str, object]:
    """The soak that runs inside the ordinary automated suite."""

    return run_soak(lines=200_000, line_bytes=128, max_output_bytes=65_536, split_stderr=True, timeout_ms=60_000)


def heavy_soak() -> dict[str, object]:
    """The governing soak: >= 1,000,000 lines and >= 1 GiB combined output."""

    return run_soak(
        lines=1_048_576, line_bytes=1_024, max_output_bytes=1_048_576, split_stderr=True, timeout_ms=60_000
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Milestone 2 provider-free output soak")
    parser.add_argument("--level", choices=("regression", "heavy"), default="heavy")
    parser.add_argument("--report", type=Path, default=None)
    arguments = parser.parse_args()

    measurement = heavy_soak() if arguments.level == "heavy" else regression_soak()
    target_met = (
        measurement["total_output_lines"] >= 1_000_000 or measurement["total_output_bytes"] >= 1 << 30
    )
    growth = measurement["controller_rss_growth_bytes"]
    within_limit = growth is None or growth <= CONTROLLER_RSS_GROWTH_LIMIT_BYTES
    measurement["governing_target_met"] = bool(target_met) if arguments.level == "heavy" else None
    measurement["controller_memory_within_threshold"] = bool(within_limit)
    measurement["level"] = arguments.level

    # Repository JSON artifacts use the same canonical encoding as Milestone 1.
    if arguments.report is not None:
        arguments.report.write_bytes(canonical_bytes(measurement))
    print(json.dumps(measurement, indent=1, sort_keys=True))
    if arguments.level == "heavy" and not target_met:
        print("HEAVY SOAK TARGET NOT MET", file=sys.stderr)
        return 1
    if not within_limit:
        print("CONTROLLER MEMORY THRESHOLD EXCEEDED", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
