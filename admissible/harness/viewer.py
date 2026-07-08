"""Static HTML viewer for Admissible run traces (Slice J).

Consumes one run_trace.json file (see benchmark/schemas/run_trace.schema.json
and admissible.trace.build_run_trace) and renders it as a single static,
self-contained HTML report for local inspection and demos.

This is a read-only, post-run inspection tool:

- it does not call a model;
- it does not build prompts;
- it does not pass gold annotations anywhere except onto the rendered
  page (the trace already carries gold annotations for scoring/audit;
  see run_trace.schema.json);
- it does not mutate the trace it reads;
- it does not score anything beyond what the trace already recorded;
- it requires no backend server and no third-party package -- stdlib
  only, and the rendered page loads no external network assets.

Also runnable as a CLI:

    python -m admissible.harness.viewer \\
        --trace benchmark/reports/latest_trace.json \\
        --out benchmark/reports/latest_trace.html
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any

_TEMPLATE_PATH = Path(__file__).resolve().parent / "viewer.html"

_REQUIRED_TOP_LEVEL_FIELDS = (
    "trace_id",
    "schema_version",
    "created_at",
    "claim_boundary",
    "case_set",
    "systems",
    "case_traces",
    "aggregate_results",
    "final_verdict",
    "metadata",
)

_AGGREGATE_METRIC_FIELDS: tuple[tuple[str, str], ...] = (
    ("label_accuracy", "Label accuracy"),
    ("correct_count", "Correct"),
    ("incorrect_count", "Incorrect"),
    ("false_allow_rate_broad", "False allow (broad)"),
    ("missing_escalation_rate", "Missing escalation"),
    ("missing_evidence_rate", "Missing evidence"),
    ("overblock_rate", "Overblock"),
    ("safe_throughput", "Safe throughput"),
)

_RATE_FIELDS = {
    "label_accuracy",
    "false_allow_rate_broad",
    "missing_escalation_rate",
    "missing_evidence_rate",
    "overblock_rate",
    "safe_throughput",
}


def load_trace(path: str | Path) -> dict:
    """Load and minimally validate a run trace JSON file.

    Raises ValueError if the file is not valid JSON, if the parsed JSON
    is not an object, or if it is missing any required top-level field
    (see benchmark/schemas/run_trace.schema.json). Does not otherwise
    validate against the full schema and does not mutate the loaded data.
    """
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    try:
        trace = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON trace file: {exc}") from exc

    if not isinstance(trace, dict):
        raise ValueError(
            f"{path}: run trace must be a JSON object, got {type(trace).__name__}"
        )

    missing = [field for field in _REQUIRED_TOP_LEVEL_FIELDS if field not in trace]
    if missing:
        raise ValueError(
            f"{path}: run trace missing required top-level field(s): {missing}"
        )

    return trace


def _esc(value: Any) -> str:
    if value is None:
        return "—"
    return html.escape(str(value))


def _fmt_rate(value: Any) -> str:
    if value is None:
        return "N/A"
    return f"{float(value) * 100:.1f}%"


def _fmt_metric(field: str, value: Any) -> str:
    if field in _RATE_FIELDS:
        return _fmt_rate(value)
    if value is None:
        return "N/A"
    return str(value)


def _fmt_list(items: Any) -> str:
    if not isinstance(items, list) or not items:
        return "None"
    return ", ".join(_esc(item) for item in items)


def _system_label(system_name: str, systems: list[dict]) -> str:
    for descriptor in systems:
        if descriptor.get("system_type") == system_name:
            return f"{descriptor.get('system_id')} ({system_name})"
    return system_name


def _is_terminal_dry_run_trace(trace: dict) -> bool:
    metadata = trace.get("metadata") or {}
    return metadata.get("demo_kind") == "terminal_agent_dry_run_v0"


def _render_dry_run_banner(trace: dict) -> str:
    if not _is_terminal_dry_run_trace(trace):
        return ""

    metadata = trace.get("metadata") or {}
    return f"""
    <div class="dry-run-banner">
      <strong>No side effect executed.</strong>
      This is a fixture-based terminal-agent dry-run demonstration only.
      <dl class="dry-run-grid">
        <dt>Source system</dt><dd><code>{_esc(metadata.get('source_system'))}</code></dd>
        <dt>Decision system</dt><dd><code>{_esc(metadata.get('decision_system'))}</code></dd>
        <dt>Side effect executed</dt><dd>{_esc(metadata.get('side_effect_executed'))}</dd>
      </dl>
    </div>
    """


def _render_header(trace: dict) -> str:
    final_verdict = trace.get("final_verdict") or {}
    status = final_verdict.get("status", "UNKNOWN")
    status_class = {
        "SMOKE_PASS": "verdict-pass",
        "SMOKE_FAIL": "verdict-fail",
        "INCONCLUSIVE": "verdict-inconclusive",
    }.get(status, "verdict-unknown")

    title = (
        "Terminal Agent Dry-Run Trace"
        if _is_terminal_dry_run_trace(trace)
        else "Admissible Run Trace"
    )

    return f"""
    <header class="trace-header">
      <h1>{title}</h1>
      <dl class="header-grid">
        <dt>Trace ID</dt><dd><code>{_esc(trace.get('trace_id'))}</code></dd>
        <dt>Created at</dt><dd>{_esc(trace.get('created_at'))}</dd>
      </dl>
      <div class="claim-boundary">
        <strong>Claim boundary:</strong> {_esc(trace.get('claim_boundary'))}
      </div>
      {_render_dry_run_banner(trace)}
      <div class="final-verdict {status_class}">
        <div class="verdict-status">Final verdict: {_esc(status)}</div>
        <div class="verdict-summary">{_esc(final_verdict.get('summary'))}</div>
      </div>
    </header>
    """


def _render_case_set_summary(trace: dict) -> str:
    case_set = trace.get("case_set") or {}
    systems = trace.get("systems") or []
    system_items = "".join(
        f"<li><code>{_esc(descriptor.get('system_id'))}</code> "
        f"<span class=\"system-type\">({_esc(descriptor.get('system_type'))})</span>"
        f"<div class=\"system-desc\">{_esc(descriptor.get('description'))}</div></li>"
        for descriptor in systems
    )
    return f"""
    <section class="case-set-summary">
      <h2>Case Set Summary</h2>
      <dl class="case-set-grid">
        <dt>Case count</dt><dd>{_esc(case_set.get('case_count'))}</dd>
        <dt>Benchmark tier</dt><dd>{_esc(case_set.get('benchmark_tier'))}</dd>
        <dt>Envelope tier</dt><dd>{_esc(case_set.get('envelope_tier'))}</dd>
      </dl>
      <h3>Systems compared</h3>
      <ul class="system-list">{system_items}</ul>
    </section>
    """


def _render_aggregate_table(trace: dict) -> str:
    aggregate_results = trace.get("aggregate_results") or {}
    results = aggregate_results.get("results") or {}
    systems = trace.get("systems") or []

    header_cells = "".join(
        f"<th>{_esc(_system_label(name, systems))}</th>" for name in results
    )
    rows = []
    for field, label in _AGGREGATE_METRIC_FIELDS:
        cells = "".join(
            f"<td>{_esc(_fmt_metric(field, results[name].get(field)))}</td>"
            for name in results
        )
        rows.append(f"<tr><th scope=\"row\">{_esc(label)}</th>{cells}</tr>")

    return f"""
    <section class="aggregate-metrics">
      <h2>Aggregate Metrics</h2>
      <table>
        <thead><tr><th>Metric</th>{header_cells}</tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </section>
    """


def _gold_decision_label(case_trace: dict) -> str | None:
    gold = case_trace.get("gold_annotation")
    if isinstance(gold, dict):
        return gold.get("gold_decision")
    return None


def _render_case_table(trace: dict) -> str:
    systems = trace.get("systems") or []
    case_traces = trace.get("case_traces") or []

    header_cells = "".join(
        f"<th>{_esc(descriptor.get('system_id'))}</th>" for descriptor in systems
    )
    rows = []
    for case_trace in case_traces:
        benchmark_case_id = case_trace.get("benchmark_case_id")
        gold_label = _gold_decision_label(case_trace)
        decisions = case_trace.get("decisions") or {}
        scores = case_trace.get("scores") or {}

        cells = []
        for descriptor in systems:
            system_id = descriptor.get("system_id")
            decision = decisions.get(system_id)
            if decision is None:
                cells.append("<td class=\"no-decision\">—</td>")
                continue

            score = scores.get(system_id)
            correct = score.get("correct") if isinstance(score, dict) else None
            match_class = (
                "match-yes" if correct else ("match-no" if correct is False else "match-unknown")
            )
            match_symbol = "✓" if correct else ("✗" if correct is False else "?")

            reasons = decision.get("reasons") or []
            reason_summary = ""
            if reasons and isinstance(reasons[0], dict):
                reason_summary = reasons[0].get("summary", "")

            cells.append(
                f"<td class=\"{match_class}\">"
                f"<span class=\"decision-label\">{_esc(decision.get('decision'))}</span> "
                f"<span class=\"match-symbol\">{match_symbol}</span>"
                f"<div class=\"reason-summary\">{_esc(reason_summary)}</div></td>"
            )

        rows.append(
            f"<tr><td>{_esc(benchmark_case_id)}</td>"
            f"<td>{_esc(gold_label)}</td>{''.join(cells)}</tr>"
        )

    return f"""
    <section class="per-case-table">
      <h2>Per-case Comparison</h2>
      <table>
        <thead><tr><th>Case ID</th><th>Gold decision</th>{header_cells}</tr></thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </section>
    """


def _proposed_action_summary(envelope: dict) -> str:
    action = envelope.get("proposed_action") or {}
    parts = [
        f"action_type={action.get('action_type')}",
        f"tool={action.get('tool')}",
        f"target={action.get('target')}",
    ]
    return "; ".join(parts)


def _risk_summary(envelope: dict) -> str:
    risk = envelope.get("risk_context") or {}
    parts = [
        f"reversibility={risk.get('reversibility')}",
        f"blast_radius={risk.get('blast_radius')}",
        f"external_visibility={risk.get('external_visibility')}",
        f"safety_impact={risk.get('safety_impact')}",
        f"reputation_impact={risk.get('reputation_impact')}",
    ]
    return "; ".join(parts)


def _gold_summary(gold: dict | None) -> str:
    if not isinstance(gold, dict):
        return "No gold annotation available for this case."
    parts = [
        f"gold_decision={gold.get('gold_decision')}",
        f"gold_risk_level={gold.get('gold_risk_level')}",
        f"gold_required_approval={gold.get('gold_required_approval')}",
    ]
    safer = gold.get("gold_safer_next_step")
    if safer:
        parts.append(f"gold_safer_next_step={safer}")
    return "; ".join(parts)


def _render_system_decision_block(
    system_id: str, decision: dict | None, score: dict | None
) -> str:
    if decision is None:
        return (
            f"<div class=\"system-decision\"><h4>{_esc(system_id)}</h4>"
            "<p>No decision recorded.</p></div>"
        )

    correct = score.get("correct") if isinstance(score, dict) else None
    correct_text = "Correct" if correct else ("Incorrect" if correct is False else "Not scored")

    reasons = decision.get("reasons") or []
    reason_items = "".join(
        f"<li><strong>{_esc(reason.get('dimension'))}</strong> "
        f"({_esc(reason.get('severity'))}): {_esc(reason.get('summary'))}</li>"
        for reason in reasons
        if isinstance(reason, dict)
    )

    safer_next_step = decision.get("safer_next_step")
    safer_desc = (
        safer_next_step.get("description") if isinstance(safer_next_step, dict) else None
    )

    metadata = decision.get("metadata") if isinstance(decision.get("metadata"), dict) else {}
    raw_provider_text = metadata.get("raw_provider_response_text")
    provider_response_block = ""
    if isinstance(raw_provider_text, str) and raw_provider_text:
        provider_response_block = (
            f'<p class="provider-response-label"><strong>Provider response (parsed JSON):</strong></p>'
            f'<pre class="provider-response">{_esc(raw_provider_text)}</pre>'
        )
        if metadata.get("provider_output_sanitized"):
            provider_response_block += (
                '<p class="provider-sanitized-note">'
                "Provider output sanitized; original SHA-256 available in metadata."
                "</p>"
            )

    return f"""
    <div class="system-decision">
      <h4>{_esc(system_id)} &mdash; {_esc(decision.get('decision'))} ({_esc(correct_text)})</h4>
      <p>Risk level: {_esc(decision.get('risk_level'))} |
         Required approval: {_esc(decision.get('required_approval'))}</p>
      <p>Missing evidence: {_fmt_list(decision.get('missing_evidence'))}</p>
      <p>Safer next step: {_esc(safer_desc)}</p>
      <ul class="reasons">{reason_items}</ul>
      {provider_response_block}
    </div>
    """


def _render_terminal_agent_block(case_trace: dict) -> str:
    terminal_agent = case_trace.get("terminal_agent")
    if not isinstance(terminal_agent, dict):
        return ""

    raw_output = terminal_agent.get("raw_output")
    if not isinstance(raw_output, str) or not raw_output:
        return ""

    return f"""
    <div class="terminal-agent-block">
      <p><strong>Raw terminal-agent output</strong>
         (source: <code>{_esc(terminal_agent.get('source_system'))}</code>;
         fixture: <code>{_esc(terminal_agent.get('fixture_path'))}</code>)</p>
      <p class="no-side-effect-note"><strong>No side effect executed.</strong></p>
      <pre class="terminal-agent-output">{_esc(raw_output)}</pre>
    </div>
    """


def _render_case_detail(case_trace: dict, systems: list[dict]) -> str:
    envelope = case_trace.get("envelope") or {}
    user_request = envelope.get("user_request") or {}
    evidence = envelope.get("evidence") or {}
    authority_context = envelope.get("authority_context") or {}
    gold = case_trace.get("gold_annotation")
    decisions = case_trace.get("decisions") or {}
    scores = case_trace.get("scores") or {}

    system_blocks = "".join(
        _render_system_decision_block(
            descriptor.get("system_id"),
            decisions.get(descriptor.get("system_id")),
            scores.get(descriptor.get("system_id")),
        )
        for descriptor in systems
    )

    benchmark_case_id = case_trace.get("benchmark_case_id")
    terminal_block = _render_terminal_agent_block(case_trace)

    return f"""
    <details class="case-detail">
      <summary>{_esc(benchmark_case_id)}</summary>
      <div class="case-detail-body">
        {terminal_block}
        <p><strong>User task:</strong> {_esc(user_request.get('raw'))}</p>
        <p><strong>Proposed action:</strong> {_esc(_proposed_action_summary(envelope))}</p>
        <p><strong>Risk summary:</strong> {_esc(_risk_summary(envelope))}</p>
        <p><strong>Evidence missing:</strong> {_fmt_list(evidence.get('missing'))}</p>
        <p><strong>Required approval:</strong> {_esc(authority_context.get('required_approval'))}</p>
        <p><strong>Candidate safer next steps:</strong> {_fmt_list(envelope.get('candidate_safer_next_steps'))}</p>
        <p><strong>Gold annotation:</strong> {_esc(_gold_summary(gold))}</p>
        <h4>Admissible decision</h4>
        {system_blocks}
      </div>
    </details>
    """


def render_trace_html(trace: dict) -> str:
    """Render one run trace dict as a static, self-contained HTML report.

    Reads admissible/harness/viewer.html as a static page shell (stdlib
    only: no template engine) and fills in the title and body content.
    Does not mutate `trace`. Every trace-derived text value is passed
    through html.escape before being written into the page.
    """
    systems = trace.get("systems") or []
    case_traces = trace.get("case_traces") or []

    case_detail_sections = "".join(
        _render_case_detail(case_trace, systems) for case_trace in case_traces
    )

    body = "".join(
        [
            _render_header(trace),
            _render_case_set_summary(trace),
            _render_aggregate_table(trace),
            _render_case_table(trace),
            '<section class="case-details"><h2>Case Details</h2>',
            case_detail_sections,
            "</section>",
        ]
    )

    template = _TEMPLATE_PATH.read_text(encoding="utf-8")
    title = _esc(trace.get("trace_id") or "Admissible Run Trace")
    return template.replace("{{TITLE}}", title).replace("{{CONTENT}}", body)


def write_trace_html(trace_path: str | Path, out_path: str | Path) -> Path:
    """Load a run trace, render it, and write the HTML report to out_path.

    Creates parent directories of out_path if needed. Does not modify
    the source trace file. Returns the written path.
    """
    trace = load_trace(trace_path)
    rendered = render_trace_html(trace)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    return out_path


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.harness.viewer",
        description=(
            "Render a static, read-only HTML report from an Admissible run trace "
            "JSON file. Local inspection/demo tool only: does not call a model, "
            "does not modify the trace, and needs no backend server."
        ),
    )
    parser.add_argument(
        "--trace",
        required=True,
        help="Path to a run_trace.json file (see benchmark/schemas/run_trace.schema.json).",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Path to write the rendered static HTML report.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    out_path = write_trace_html(args.trace, args.out)
    print(str(out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
