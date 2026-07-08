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


def _truncate(text: Any, max_len: int = 48) -> str:
    if text is None:
        return "—"
    s = str(text)
    if len(s) <= max_len:
        return s
    return s[: max_len - 1] + "…"


def _count_by_key(items: list[dict], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key) or "—")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _action_type_for_candidate(candidate: dict, decision: dict) -> str:
    proposed = decision.get("proposed_action") or {}
    return str(candidate.get("action_type") or proposed.get("action_type") or "—")


def _compute_summary(trace: dict) -> dict[str, Any]:
    candidates = trace.get("action_candidates") or []
    decisions = trace.get("decisions") or []
    decisions_by_action = _decision_by_action_id(trace)
    action_types: dict[str, int] = {}
    for candidate in candidates:
        action_id = candidate.get("action_id")
        decision = decisions_by_action.get(action_id, {})
        atype = _action_type_for_candidate(candidate, decision)
        action_types[atype] = action_types.get(atype, 0) + 1
    execution_log = trace.get("execution_log") or []
    side_effects_in_log = sum(1 for e in execution_log if e.get("side_effect_executed"))
    return {
        "total_candidates": len(candidates),
        "by_decision": _count_by_key(decisions, "decision"),
        "by_operational_action": _count_by_key(decisions, "operational_admissibility_action"),
        "by_action_type": dict(sorted(action_types.items())),
        "side_effect_executed": bool(trace.get("side_effect_executed")),
        "side_effects_in_log": side_effects_in_log,
    }


_DEMO_HIGHLIGHT_SPECS: tuple[tuple[str, str, str, str], ...] = (
    ("local_safe_edit", "ALLOW", "local_code_change", "Local safe edit"),
    ("create_file_doc", "ALLOW", "create_file", "Create file / documentation"),
    ("verification_strategy", "REQUEST_MORE_EVIDENCE", "verification_plan", "Verification / test strategy"),
    ("dependency_tooling", "REQUEST_MORE_EVIDENCE", "install_dependency", "Dependency / tooling"),
    ("hosting_adjacent", "ALLOW_WITH_LIMITS", "document_hosting_options", "Hosting / deployment-adjacent"),
    ("production_readiness_claim", "REQUEST_MORE_EVIDENCE", "claim_status", "Production-readiness claim"),
)


def _select_demo_highlights(trace: dict) -> list[dict[str, Any]]:
    """Pick one representative action per demo category (deterministic, first match)."""
    decisions_by_action = _decision_by_action_id(trace)
    highlights: list[dict[str, Any]] = []
    used_action_ids: set[str] = set()

    for key, target_decision, target_action_type, label in _DEMO_HIGHLIGHT_SPECS:
        for candidate in trace.get("action_candidates") or []:
            action_id = candidate.get("action_id")
            if not action_id or action_id in used_action_ids:
                continue
            decision = decisions_by_action.get(action_id, {})
            if decision.get("decision") != target_decision:
                continue
            if _action_type_for_candidate(candidate, decision) != target_action_type:
                continue
            used_action_ids.add(action_id)
            highlights.append(
                {
                    "key": key,
                    "label": label,
                    "action_id": action_id,
                    "decision": target_decision,
                    "action_type": target_action_type,
                    "tool_or_command": candidate.get("tool_or_command"),
                    "operational_admissibility_action": decision.get("operational_admissibility_action"),
                }
            )
            break

    return highlights


def _render_count_list(counts: dict[str, int], *, css_class: str = "count-list") -> str:
    if not counts:
        return "<p>None</p>"
    items = "".join(
        f'<li><span class="count-label">{_esc(k)}</span> '
        f'<span class="count-value">{v}</span></li>'
        for k, v in counts.items()
    )
    return f'<ul class="{css_class}">{items}</ul>'


def _render_executive_summary(trace: dict) -> str:
    summary = _compute_summary(trace)
    side_effect_label = "false" if not summary["side_effect_executed"] else "true"
    return f"""
    <section class="executive-summary" id="executive-summary">
      <h2>Executive Summary</h2>
      <p class="summary-intro">At-a-glance counts for this long-run trace (demo-friendly; full detail below).</p>
      <div class="summary-grid">
        <div class="summary-card">
          <h3>Action candidates</h3>
          <p class="summary-stat">{summary['total_candidates']}</p>
        </div>
        <div class="summary-card">
          <h3>Side effects executed</h3>
          <p class="summary-stat">{_esc(side_effect_label)} / {summary['side_effects_in_log']}</p>
          <span class="badge badge-no-side-effect">No side effect executed</span>
        </div>
        <div class="summary-card">
          <h3>By admission decision</h3>
          {_render_count_list(summary["by_decision"])}
        </div>
        <div class="summary-card">
          <h3>By operational action</h3>
          {_render_count_list(summary["by_operational_action"])}
        </div>
        <div class="summary-card summary-card-wide">
          <h3>By action type</h3>
          {_render_count_list(summary["by_action_type"])}
        </div>
      </div>
    </section>
    """


def _render_demo_highlights(trace: dict) -> str:
    highlights = _select_demo_highlights(trace)
    if not highlights:
        return ""

    cards = []
    for h in highlights:
        action_id = h["action_id"]
        cards.append(
            f'<li class="highlight-card">'
            f'<a class="highlight-link" href="#action-{_esc(action_id)}">'
            f'<span class="highlight-label">{_esc(h["label"])}</span>'
            f'<span class="decision-{_esc(h["decision"])}">{_esc(h["decision"])}</span>'
            f'<code class="highlight-action-id">{_esc(action_id)}</code>'
            f'<span class="highlight-tool" title="{_esc(h.get("tool_or_command"))}">'
            f'{_esc(_truncate(h.get("tool_or_command"), 56))}</span>'
            f'</a></li>'
        )

    return f"""
    <section class="demo-highlights" id="demo-highlights">
      <h2>Demo Highlights</h2>
      <p>Representative actions across admission outcomes — click to jump to full detail.</p>
      <ul class="highlight-list">{''.join(cards)}</ul>
    </section>
    """


def _render_filters(trace: dict) -> str:
    summary = _compute_summary(trace)
    decision_opts = "".join(
        f'<option value="{_esc(d)}">{_esc(d)} ({c})</option>'
        for d, c in summary["by_decision"].items()
    )
    op_opts = "".join(
        f'<option value="{_esc(d)}">{_esc(d)} ({c})</option>'
        for d, c in summary["by_operational_action"].items()
    )
    type_opts = "".join(
        f'<option value="{_esc(d)}">{_esc(d)} ({c})</option>'
        for d, c in summary["by_action_type"].items()
    )
    return f"""
    <section class="filter-bar" id="filter-bar">
      <h2>Filters</h2>
      <div class="filter-controls">
        <label>Decision
          <select id="filter-decision" data-filter="decision">
            <option value="">All</option>
            {decision_opts}
          </select>
        </label>
        <label>Action type
          <select id="filter-action-type" data-filter="action_type">
            <option value="">All</option>
            {type_opts}
          </select>
        </label>
        <label>Operational action
          <select id="filter-operational" data-filter="operational_admissibility_action">
            <option value="">All</option>
            {op_opts}
          </select>
        </label>
        <button type="button" id="filter-reset" class="filter-reset">Reset filters</button>
      </div>
      <p class="filter-status" id="filter-status" aria-live="polite"></p>
    </section>
    """


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
        action_type = _action_type_for_candidate(candidate, decision)
        tool_full = candidate.get("tool_or_command") or ""
        tool_short = _truncate(tool_full, 48)
        operational = decision.get("operational_admissibility_action", "—")
        rows.append(
            f"<tr class=\"timeline-row\" data-action-id=\"{_esc(action_id)}\" "
            f"data-decision=\"{_esc(decision_label)}\" "
            f"data-action-type=\"{_esc(action_type)}\" "
            f"data-operational-admissibility-action=\"{_esc(operational)}\">"
            f"<td><a href=\"#action-{_esc(action_id)}\"><code>{_esc(action_id)}</code></a></td>"
            f"<td>{_esc(candidate.get('benchmark_case_id'))}</td>"
            f"<td class=\"tool-cell\" title=\"{_esc(tool_full)}\">{_esc(tool_short)}</td>"
            f"<td class=\"{decision_class}\">{_esc(decision_label)}</td>"
            f"<td>{_esc(decision.get('risk_level'))}</td>"
            f"<td><code>{_esc(operational)}</code></td>"
            f"<td><code>{_esc(candidate.get('execution_status'))}</code></td>"
            f"</tr>"
        )
    return f"""
    <section class="timeline-section" id="admission-timeline">
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
    *,
    open_default: bool = False,
    is_highlight: bool = False,
    highlight_label: str | None = None,
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
    execution_status = candidate.get("execution_status") or "proposed_only"
    action_type = _action_type_for_candidate(candidate, decision)

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
      <p><strong>Execution status:</strong> <code>{_esc(execution_status)}</code>
         <span class="badge badge-proposed-only">proposed_only</span></p>
      <p><strong>No side effect executed.</strong>
         <span class="badge badge-no-side-effect">no side effect executed</span></p>
    """

    raw_output = step.get("raw_output", "") if step else ""
    raw_panel = f"""
      <p class="unverified-note">
        <span class="badge badge-unverified">unverified raw output</span>
        <strong>Raw agent output is unverified.</strong>
        Agent output is not authority. Source trust:
        <code>{_esc(step.get('source_trust') if step else None)}</code>;
        source type: <code>{_esc(step.get('source_type') if step else None)}</code>.
      </p>
      <details class="raw-output-collapsible">
        <summary>Show raw agent output ({len(raw_output)} chars)</summary>
        <pre class="raw-output">{_esc(raw_output)}</pre>
      </details>
    """

    proposed_panel = f"""
      <p class="unverified-note">
        <span class="badge badge-generated-envelope">generated envelope</span>
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
        f"{_esc(action_id)} — {_esc(_truncate(candidate.get('tool_or_command'), 64))} → "
        f"{_esc(decision_label)} / {_esc(decision.get('operational_admissibility_action'))}"
    )
    highlight_badge = (
        f'<span class="badge badge-highlight">Demo: {_esc(highlight_label)}</span>'
        if is_highlight and highlight_label
        else ""
    )
    open_attr = " open" if open_default else ""
    highlight_class = " action-highlight" if is_highlight else ""

    return f"""
    <details class="action-detail{highlight_class}" id="action-{_esc(action_id)}"{open_attr}
             data-action-id="{_esc(action_id)}"
             data-decision="{_esc(decision_label)}"
             data-action-type="{_esc(action_type)}"
             data-operational-admissibility-action="{_esc(decision.get('operational_admissibility_action'))}">
      <summary>{highlight_badge}{summary}</summary>
      <div class="action-detail-body">
        {_render_tab_nav(tab_ids)}
        {panels}
      </div>
    </details>
    """


def _render_action_details(trace: dict) -> str:
    steps = _step_by_id(trace)
    decisions_by_action = _decision_by_action_id(trace)
    highlights = _select_demo_highlights(trace)
    highlight_by_action = {h["action_id"]: h["label"] for h in highlights}
    highlight_ids = set(highlight_by_action)
    sections = []
    for candidate in trace.get("action_candidates") or []:
        action_id = candidate.get("action_id")
        step_id = candidate.get("proposed_by_step_id")
        is_highlight = action_id in highlight_ids
        sections.append(
            _render_action_detail(
                candidate,
                steps.get(step_id),
                decisions_by_action.get(action_id, {}),
                open_default=is_highlight,
                is_highlight=is_highlight,
                highlight_label=highlight_by_action.get(action_id),
            )
        )
    return f"""
    <section class="action-details" id="action-details">
      <h2>Action Detail</h2>
      <p class="action-details-note">Collapsed by default except demo highlights. Raw output and field provenance remain in each block.</p>
      {''.join(sections)}
    </section>
    """


def render_truth_console_html(trace: dict) -> str:
    """Render a TruthTrace dict as a static HTML truth console."""
    body = "".join(
        [
            _render_header(trace),
            _render_prompt_panel(trace),
            _render_executive_summary(trace),
            _render_demo_highlights(trace),
            _render_filters(trace),
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
