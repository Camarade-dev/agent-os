"""Static HTML truth console for Admissible long-run traces (v0).

Renders a TruthTrace dict as a self-contained local HTML page. Every
visible field is sourced from trace data or a deterministic derivation
defined in admissible.long_run_truth.

Does not call models, execute shell commands, or require a server.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path
from typing import Any

_TEMPLATE_PATH = Path(__file__).resolve().parent / "truth_console.html"

_REQUIRED_FIELDS = (
    "schema_version",
    "long_run",
    "agent_steps",
    "action_candidates",
    "decisions",
    "execution_log",
)


def load_truth_trace(path: str | Path) -> dict:
    """Load and minimally validate a truth trace JSON file."""
    path = Path(path)
    try:
        trace = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON truth trace: {exc}") from exc

    if not isinstance(trace, dict):
        raise ValueError(f"{path}: truth trace must be a JSON object")

    missing = [field for field in _REQUIRED_FIELDS if field not in trace]
    if missing:
        raise ValueError(f"{path}: truth trace missing required field(s): {missing}")

    return trace


def _esc(value: Any) -> str:
    if value is None:
        return "—"
    return html.escape(str(value))


def _fmt_list(items: Any) -> str:
    if not isinstance(items, list) or not items:
        return "None"
    return ", ".join(_esc(item) for item in items)


def _step_by_id(trace: dict) -> dict[str, dict]:
    return {step["step_id"]: step for step in trace.get("agent_steps") or []}


def _decision_by_action_id(trace: dict) -> dict[str, dict]:
    return {d["action_id"]: d for d in trace.get("decisions") or []}


def _render_header(trace: dict) -> str:
    long_run = trace.get("long_run") or {}
    return f"""
    <header class="truth-header">
      <h1>Admissible Long-Run Truth Console</h1>
      <div class="claim-boundary">
        <strong>Claim boundary:</strong> {_esc(long_run.get("claim_boundary"))}
      </div>
      <div class="execution-banner">No side effect executed.</div>
      <dl class="header-grid">
        <dt>Frontier agent</dt>
        <dd>{_esc(long_run.get("frontier_agent_label"))}</dd>
        <dt>Run ID</dt>
        <dd><code>{_esc(long_run.get("run_id"))}</code></dd>
        <dt>Created at</dt>
        <dd>{_esc(long_run.get("created_at"))}</dd>
        <dt>Workspace</dt>
        <dd>{_esc(long_run.get("workspace_context"))}</dd>
        <dt>Source system</dt>
        <dd><code>{_esc(trace.get("source_system"))}</code></dd>
        <dt>Decision system</dt>
        <dd><code>{_esc(trace.get("decision_system"))}</code></dd>
      </dl>
      <div class="truth-boundary">
        <strong>Truth boundaries:</strong>
        <ul>
          {''.join(f'<li>{_esc(note)}</li>' for note in (trace.get("truth_boundary_notes") or []))}
        </ul>
      </div>
    </header>
    """


def _render_prompt_panel(trace: dict) -> str:
    long_run = trace.get("long_run") or {}
    return f"""
    <section class="prompt-panel">
      <h2>Long-Run Prompt</h2>
      <p>What the user asked the frontier agent to do across this run:</p>
      <blockquote>{_esc(long_run.get("prompt"))}</blockquote>
    </section>
    """


def _render_timeline(trace: dict) -> str:
    decisions_by_action = _decision_by_action_id(trace)
    rows = []
    for candidate in trace.get("action_candidates") or []:
        action_id = candidate.get("action_id")
        decision = decisions_by_action.get(action_id, {})
        decision_label = decision.get("decision", "—")
        decision_class = f"decision-{decision_label}" if decision_label != "—" else ""
        rows.append(
            f"<tr>"
            f"<td><code>{_esc(action_id)}</code></td>"
            f"<td>{_esc(candidate.get('benchmark_case_id'))}</td>"
            f"<td>{_esc(candidate.get('tool_or_command'))}</td>"
            f"<td class=\"{decision_class}\">{_esc(decision_label)}</td>"
            f"<td>{_esc(decision.get('risk_level'))}</td>"
            f"<td><code>{_esc(decision.get('operational_admissibility_action'))}</code></td>"
            f"<td><code>{_esc(candidate.get('execution_status'))}</code></td>"
            f"</tr>"
        )
    return f"""
    <section class="timeline-section">
      <h2>Admission Timeline</h2>
      <p>Action candidates encountered during the long run (fixture-backed in v0):</p>
      <div class="timeline-wrapper">
      <table class="timeline">
        <thead>
          <tr>
            <th>Action</th>
            <th>Case</th>
            <th>Tool / command</th>
            <th>Decision</th>
            <th>Risk</th>
            <th>Operational action</th>
            <th>Execution status</th>
          </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
      </div>
    </section>
    """


def _render_tab_nav(tab_ids: list[tuple[str, str]]) -> str:
    buttons = "".join(
        f'<button type="button" class="tab-btn" data-tab="{tid}">{_esc(label)}</button>'
        for tid, label in tab_ids
    )
    return f'<nav class="tab-nav">{buttons}</nav>'


def _render_tab_panel(tab_id: str, content: str, *, active: bool = False) -> str:
    active_class = " active" if active else ""
    return f'<div class="tab-panel{active_class}" data-panel="{tab_id}">{content}</div>'


def _render_action_detail(
    candidate: dict,
    step: dict | None,
    decision: dict,
) -> str:
    action_id = candidate.get("action_id")
    decision_label = decision.get("decision", "—")
    safer = decision.get("safer_next_step")
    safer_desc = safer.get("description") if isinstance(safer, dict) else None
    proposed = decision.get("proposed_action") or {}
    auth = decision.get("authorization_summary") or {}
    evidence = decision.get("evidence_summary") or {}
    policy = decision.get("policy_summary") or {}
    audit = decision.get("audit_trace") or {}
    reasons = decision.get("reasons") or []

    reason_items = "".join(
        f"<li><strong>{_esc(r.get('dimension'))}</strong> "
        f"({_esc(r.get('severity'))}): {_esc(r.get('summary'))}</li>"
        for r in reasons
        if isinstance(r, dict)
    )

    tab_ids = [
        ("overview", "Overview"),
        ("raw", "Raw Agent Output"),
        ("proposed", "Proposed Action"),
        ("risk", "Risk"),
        ("authorization", "Authorization"),
        ("evidence", "Evidence"),
        ("policy", "Policy"),
        ("decision", "Admission Decision"),
        ("operational", "Operational Action"),
        ("safer", "Safer Next Step"),
        ("metadata", "Trace Metadata"),
    ]

    overview = f"""
      <p><strong>Long-run boundary:</strong> {_esc(candidate.get('long_run_boundary'))}</p>
      <p><strong>User task in step:</strong> {_esc(step.get('user_task_in_step') if step else None)}</p>
      <p><strong>Decision:</strong> <span class="decision-{decision_label}">{_esc(decision_label)}</span></p>
      <p><strong>Operational admissibility action:</strong>
         <code>{_esc(decision.get('operational_admissibility_action'))}</code></p>
      <p><strong>Execution status:</strong> <code>{_esc(candidate.get('execution_status'))}</code></p>
      <p><strong>No side effect executed.</strong></p>
    """

    raw_output = step.get("raw_output", "") if step else ""
    raw_panel = f"""
      <p class="unverified-note">
        <strong>Raw agent output is unverified.</strong>
        Agent output is not authority. Source trust:
        <code>{_esc(step.get('source_trust') if step else None)}</code>;
        source type: <code>{_esc(step.get('source_type') if step else None)}</code>.
      </p>
      <pre class="raw-output">{_esc(raw_output)}</pre>
    """

    proposed_panel = f"""
      <p class="unverified-note">
        <strong>Generated envelope is an interpretation, not ground truth.</strong>
        The envelope below is constructed deterministically from unverified raw agent output.
        It may omit context or misclassify intent. Treat it as conservative, offline extraction.
      </p>
      <p><strong>Admissible action candidate</strong> (extracted from raw output:
      {_esc(candidate.get('extracted_from_raw_output'))})</p>
      <dl class="meta-grid">
        <dt>action_type</dt><dd><code>{_esc(proposed.get('action_type'))}</code></dd>
        <dt>tool_or_command</dt><dd><code>{_esc(proposed.get('tool'))}</code></dd>
        <dt>target</dt><dd><code>{_esc(proposed.get('target'))}</code></dd>
        <dt>side_effect_type</dt><dd><code>{_esc(candidate.get('side_effect_type'))}</code></dd>
        <dt>envelope_id</dt><dd><code>{_esc(candidate.get('envelope_id'))}</code></dd>
      </dl>
    """

    risk_panel = f"""
      <p><strong>Risk boundary crossed:</strong> {_esc(decision.get('risk_boundary'))}</p>
      <p><strong>Risk level:</strong> {_esc(decision.get('risk_level'))}</p>
      <p><strong>Audit (reversibility):</strong> {_esc(audit.get('reversibility'))}</p>
      <p><strong>Audit (blast radius):</strong> {_esc(audit.get('blast_radius'))}</p>
    """

    auth_panel = f"""
      <p><strong>Required approval (decision):</strong> {_esc(decision.get('required_approval'))}</p>
      <dl class="meta-grid">
        <dt>requested_by</dt><dd>{_esc(auth.get('requested_by'))}</dd>
        <dt>approved_by</dt><dd>{_esc(auth.get('approved_by'))}</dd>
        <dt>approval_scope</dt><dd>{_esc(auth.get('approval_scope'))}</dd>
        <dt>required_approval (envelope)</dt><dd>{_esc(auth.get('required_approval'))}</dd>
      </dl>
      <p><strong>Authority notes:</strong> {_fmt_list(auth.get('authority_notes'))}</p>
      <p><strong>Audit (authority):</strong> {_esc(audit.get('authority'))}</p>
      <p><strong>Audit (human responsibility):</strong> {_esc(audit.get('human_responsibility'))}</p>
    """

    evidence_panel = f"""
      <p><strong>Missing evidence (decision):</strong> {_fmt_list(decision.get('missing_evidence'))}</p>
      <p><strong>Missing (envelope):</strong> {_fmt_list(evidence.get('missing'))}</p>
      <p><strong>Available:</strong> {len(evidence.get('available') or [])} item(s)</p>
      <p><strong>Audit (evidence):</strong> {_esc(audit.get('evidence'))}</p>
    """

    policy_panel = f"""
      <p><strong>Applicable policies:</strong> {_fmt_list(policy.get('applicable_policies'))}</p>
      <p><strong>Policy gaps:</strong> {_fmt_list(policy.get('policy_gaps'))}</p>
      <p><strong>Policy conflicts:</strong> {_fmt_list(policy.get('policy_conflicts'))}</p>
      <p><strong>Audit (policy):</strong> {_esc(audit.get('policy'))}</p>
    """

    decision_panel = f"""
      <p><strong>Admission decision:</strong>
         <span class="decision-{decision_label}">{_esc(decision_label)}</span></p>
      <p>Derived from the action envelope and rules-only evaluator — not from raw agent output.</p>
      <ul class="reasons">{reason_items}</ul>
    """

    operational_panel = f"""
      <p><strong>Operational admissibility action:</strong>
         <code>{_esc(decision.get('operational_admissibility_action'))}</code></p>
      <p>Mapping: ALLOW→execute; ALLOW_WITH_LIMITS→limit_scope or replace_with_safer_step;
         REQUEST_MORE_EVIDENCE→request_evidence; REQUIRE_HUMAN_APPROVAL→request_approval;
         REFUSE→block.</p>
      <p><strong>Execution status:</strong> <code>{_esc(candidate.get('execution_status'))}</code></p>
      <p><strong>No side effect executed.</strong></p>
    """

    safer_panel = f"""
      <p><strong>Safer next step:</strong> {_esc(safer_desc)}</p>
      {f'<p><strong>Additional limits:</strong> {_fmt_list(safer.get("limits"))}</p>' if isinstance(safer, dict) and safer.get('limits') else ''}
    """

    metadata_panel = f"""
      <dl class="meta-grid">
        <dt>action_id</dt><dd><code>{_esc(action_id)}</code></dd>
        <dt>step_id</dt><dd><code>{_esc(candidate.get('proposed_by_step_id'))}</code></dd>
        <dt>decision_id</dt><dd><code>{_esc(decision.get('decision_id'))}</code></dd>
        <dt>benchmark_case_id</dt><dd><code>{_esc(candidate.get('benchmark_case_id'))}</code></dd>
        <dt>step timestamp</dt><dd>{_esc(step.get('timestamp') if step else None)}</dd>
        <dt>boundary context</dt><dd>{_esc(step.get('boundary_context') if step else None)}</dd>
        <dt>extraction_method</dt><dd><code>{_esc(candidate.get('extraction_method'))}</code></dd>
        <dt>extraction_confidence</dt><dd><code>{_esc(candidate.get('extraction_confidence'))}</code></dd>
      </dl>
      <p><strong>Field provenance</strong> (observed vs inferred vs missing/defaulted):</p>
      <pre class="raw-output">{_esc(json.dumps(candidate.get("field_provenance") or {}, indent=2, sort_keys=True))}</pre>
      <p><strong>Audit (provenance):</strong> {_esc(audit.get('provenance'))}</p>
    """

    panels = "".join(
        [
            _render_tab_panel("overview", overview, active=True),
            _render_tab_panel("raw", raw_panel),
            _render_tab_panel("proposed", proposed_panel),
            _render_tab_panel("risk", risk_panel),
            _render_tab_panel("authorization", auth_panel),
            _render_tab_panel("evidence", evidence_panel),
            _render_tab_panel("policy", policy_panel),
            _render_tab_panel("decision", decision_panel),
            _render_tab_panel("operational", operational_panel),
            _render_tab_panel("safer", safer_panel),
            _render_tab_panel("metadata", metadata_panel),
        ]
    )

    summary = (
        f"{_esc(action_id)} — {_esc(candidate.get('tool_or_command'))} → "
        f"{_esc(decision_label)} / {_esc(decision.get('operational_admissibility_action'))}"
    )

    return f"""
    <details class="action-detail" open>
      <summary>{summary}</summary>
      <div class="action-detail-body">
        {_render_tab_nav(tab_ids)}
        {panels}
      </div>
    </details>
    """


def _render_action_details(trace: dict) -> str:
    steps = _step_by_id(trace)
    decisions_by_action = _decision_by_action_id(trace)
    sections = []
    for candidate in trace.get("action_candidates") or []:
        action_id = candidate.get("action_id")
        step_id = candidate.get("proposed_by_step_id")
        sections.append(
            _render_action_detail(
                candidate,
                steps.get(step_id),
                decisions_by_action.get(action_id, {}),
            )
        )
    return f"""
    <section class="action-details">
      <h2>Action Detail</h2>
      {''.join(sections)}
    </section>
    """


def render_truth_console_html(trace: dict) -> str:
    """Render a TruthTrace dict as a static HTML truth console."""
    body = "".join(
        [
            _render_header(trace),
            _render_prompt_panel(trace),
            _render_timeline(trace),
            _render_action_details(trace),
        ]
    )
    template = _TEMPLATE_PATH.read_text(encoding="utf-8")
    title = _esc(
        (trace.get("long_run") or {}).get("run_id") or "Admissible Long-Run Truth Console"
    )
    return template.replace("{{TITLE}}", title).replace("{{CONTENT}}", body)


def write_truth_console_html(trace: dict, out_path: str | Path) -> Path:
    """Write the truth console HTML to out_path."""
    rendered = render_truth_console_html(trace)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(rendered, encoding="utf-8")
    return out_path


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.harness.truth_console",
        description="Render a static truth console from a truth trace JSON file.",
    )
    parser.add_argument("--trace", required=True, help="Path to truth trace JSON.")
    parser.add_argument("--out", required=True, help="Path to write HTML console.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    trace = load_truth_trace(args.trace)
    out_path = write_truth_console_html(trace, args.out)
    print(str(out_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
