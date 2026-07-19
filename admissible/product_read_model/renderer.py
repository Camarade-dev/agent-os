"""Refused / incomplete result renderers: one JSON-ready, one self-contained HTML.

Both renderers are pure functions of a :class:`RunDetail`. Neither performs I/O
nor is ever persisted as execution authority. The HTML document is fully
self-contained: no iframe, no script, no remote assets, no arbitrary file
serving. Every persisted string is HTML-escaped. Missing verifier/checkpoint
render as ``ABSENT`` (never ``PASSED``/``FAILED``); malformed evidence renders as
``INCONSISTENT`` and is never silently dropped.
"""

from __future__ import annotations

import html

from .presentation_types import RunDetail

RESULT_SCHEMA_VERSION = "admissible_product_read_model_result_v1"

_NON_AUTHORITY_NOTICE = (
    "Presentation only. This view reconstructs persisted evidence and does not "
    "itself decide whether the run succeeded. A product admission verdict is "
    "authoritative only when supplied by the audited reconstruction seam."
)


def render_result_json(detail: RunDetail) -> dict:
    """Return a focused, JSON-ready structure of the layered result.

    The layers are kept explicitly separate; a provider exit code of 0 never
    upgrades the product verdict, which stays ``UNKNOWN`` unless authoritative.
    """

    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "non_authority_notice": _NON_AUTHORITY_NOTICE,
        "run_id": detail.identity.run_id,
        "run_root": detail.run_root,
        "presentation_status": detail.presentation_status.value,
        "execution_state": {
            "state": detail.process.execution_state.value,
            "provider_exit_code": detail.process.exit_code,
            "timed_out": detail.process.timed_out,
            "termination_reason": detail.process.termination_reason,
        },
        "result_admission_state": detail.product_verdict.to_json(),
        "canonical_classification": {
            "value": detail.canonical_classification,
            "kind": detail.canonical_classification_kind.value,
            "detail": detail.final_status_detail,
            "canary_success": detail.canary_success,
        },
        "failing_boundary": detail.failing_boundary.to_json(),
        "material_git_result": {
            "material": detail.material.to_json(),
            "git": detail.workspace_git.to_json(),
        },
        "behavioral_verifier_result": detail.behavioral.to_json(),
        "checkpoint_result": detail.checkpoint.to_json(),
        "evidence_completeness": detail.evidence_completeness.to_json(),
        "human_disposition": detail.human_disposition.to_json(),
        "timeline": [entry.to_json() for entry in detail.timeline],
        "artifacts": [artifact.to_json() for artifact in detail.artifacts],
        "diagnostics": [excerpt.to_json() for excerpt in detail.diagnostics],
        "read_notes": list(detail.read_notes),
    }


# --- HTML rendering ----------------------------------------------------------


def _esc(value: object) -> str:
    if value is None:
        return "<span class=\"muted\">—</span>"
    if isinstance(value, bool):
        return "true" if value else "false"
    return html.escape(str(value), quote=True)


def _plain(value: object) -> str:
    if value is None:
        return "(none)"
    return html.escape(str(value), quote=True)


def _row(label: str, value: object) -> str:
    return f"<tr><th>{html.escape(label)}</th><td>{_esc(value)}</td></tr>"


def _badge(text: str, kind: str) -> str:
    return f'<span class="badge badge-{html.escape(kind)}">{html.escape(text)}</span>'


def _status_kind(status_value: str) -> str:
    return {
        "ADMITTED": "ok",
        "REFUSED": "bad",
        "INCONSISTENT": "warn",
        "INCOMPLETE": "warn",
        "UNKNOWN": "unknown",
    }.get(status_value, "unknown")


def _outcome_kind(outcome_value: str) -> str:
    return {
        "PASSED": "ok",
        "FAILED": "bad",
        "ABSENT": "absent",
        "INCONSISTENT": "warn",
    }.get(outcome_value, "unknown")


_STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
  margin: 0; padding: 1.5rem; line-height: 1.45; }
h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
h2 { font-size: 1.05rem; margin: 1.5rem 0 .5rem; border-bottom: 1px solid #8884; padding-bottom: .2rem; }
.notice { border: 1px solid #b8860b; background: #b8860b22; padding: .6rem .8rem; border-radius: 6px;
  font-size: .85rem; margin: .8rem 0 1rem; }
table { border-collapse: collapse; width: 100%; max-width: 60rem; margin: .3rem 0; }
th, td { text-align: left; vertical-align: top; padding: .25rem .5rem; border-bottom: 1px solid #8882;
  font-size: .9rem; }
th { width: 16rem; font-weight: 600; color: #666; }
.muted { color: #999; }
pre { background: #8881; padding: .6rem; border-radius: 6px; overflow-x: auto; font-size: .8rem;
  max-width: 60rem; white-space: pre-wrap; word-break: break-word; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 999px; font-size: .78rem;
  font-weight: 700; letter-spacing: .02em; }
.badge-ok { background: #1a7f3722; color: #1a7f37; border: 1px solid #1a7f3766; }
.badge-bad { background: #b4232322; color: #d34141; border: 1px solid #b4232366; }
.badge-warn { background: #b8860b22; color: #b8860b; border: 1px solid #b8860b66; }
.badge-absent { background: #6b6b6b22; color: #888; border: 1px solid #6b6b6b66; }
.badge-unknown { background: #3b5bdb22; color: #6b8bff; border: 1px solid #3b5bdb66; }
.trunc { color: #b8860b; font-size: .78rem; }
.list { margin: .2rem 0; padding-left: 1.2rem; font-size: .88rem; }
""".strip()


def render_run_html(detail: RunDetail) -> str:
    """Render a self-contained HTML document for a refused/incomplete run."""

    pv = detail.product_verdict
    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
    parts.append(
        f"<title>Admissible run {_plain(detail.identity.run_id)}</title>"
    )
    parts.append(f"<style>{_STYLE}</style></head><body>")

    parts.append(f"<h1>Admissible run: {_esc(detail.identity.run_id)}</h1>")
    parts.append(
        "<div>"
        + _badge(f"presentation: {detail.presentation_status.value}", _status_kind(detail.presentation_status.value))
        + " "
        + _badge(f"product verdict: {pv.verdict.value}", _status_kind({"ADMITTED_OBSERVED": "ADMITTED", "ADMITTED_VERIFIED": "ADMITTED", "REFUSED": "REFUSED"}.get(pv.verdict.value, "UNKNOWN")))
        + "</div>"
    )
    parts.append(f'<div class="notice">{html.escape(_NON_AUTHORITY_NOTICE)}</div>')

    # Execution state
    parts.append("<h2>Execution state</h2><table>")
    parts.append(_row("execution state", detail.process.execution_state.value))
    parts.append(_row("provider exit code", detail.process.exit_code))
    parts.append(_row("timed out", detail.process.timed_out))
    parts.append(_row("termination reason", detail.process.termination_reason))
    parts.append(_row("output truncation occurred", detail.process.output_truncation_occurred))
    if detail.process.observation_matches_result is False:
        parts.append(_row("observation vs result", "MISMATCH (harness observation authoritative)"))
    parts.append("</table>")

    # Result admission state
    parts.append("<h2>Result admission state</h2><table>")
    parts.append(_row("product verdict", pv.verdict.value + (f" (raw {pv.raw_verdict})" if pv.raw_verdict else "")))
    parts.append(_row("verification mode", pv.verification_mode.value + (f" (raw {pv.raw_verification_mode})" if pv.raw_verification_mode else "")))
    parts.append(_row("verdict source", pv.source.value))
    parts.append(_row("verdict consistent", pv.consistent))
    parts.append(_row("behavioral non-claim", pv.behavioral_non_claim))
    parts.append("</table>")

    # Canonical classification
    parts.append("<h2>Exact canonical classification</h2><table>")
    parts.append(_row("classification", detail.canonical_classification))
    parts.append(_row("classification kind", detail.canonical_classification_kind.value))
    parts.append(_row("canary success (self-test only)", detail.canary_success))
    parts.append(_row("final-status detail", detail.final_status_detail))
    parts.append("</table>")

    # Failing boundary
    fb = detail.failing_boundary
    parts.append("<h2>Exact failing boundary</h2><table>")
    parts.append(_row("boundary", fb.boundary.value))
    parts.append(_row("failure category", fb.failure_category))
    parts.append(_row("detail", fb.detail))
    parts.append("</table>")
    if fb.reasons:
        parts.append("<ul class=\"list\">" + "".join(f"<li>{_esc(r)}</li>" for r in fb.reasons) + "</ul>")

    # Material / Git
    mv = detail.material
    gv = detail.workspace_git
    parts.append("<h2>Material / Git result</h2><table>")
    parts.append(_row("material eligibility", _badge(mv.result.value, _outcome_kind(mv.result.value))))
    parts.append(_row("eligible", mv.eligible))
    parts.append(_row("material paths compliant", mv.material_paths_compliant))
    parts.append(_row("workspace clean", mv.workspace_clean))
    parts.append(_row("remotes absent", mv.remotes_absent))
    parts.append(_row("exactly one commit", mv.exactly_one_commit))
    parts.append(_row("commit message compliant", mv.commit_message_compliant))
    parts.append(_row("initial git head", gv.initial_git_head))
    parts.append(_row("final git head", gv.final_git_head))
    parts.append(_row("commits added", gv.commits_added))
    parts.append(_row("source repository mutated", gv.source_repository_mutated))
    parts.append("</table>")
    if mv.ineligibility_reasons:
        parts.append("<ul class=\"list\">" + "".join(f"<li>{_esc(r)}</li>" for r in mv.ineligibility_reasons) + "</ul>")
    if gv.changed_material_files:
        parts.append("<ul class=\"list\">" + "".join(f"<li>{_esc(f)}</li>" for f in gv.changed_material_files) + "</ul>")

    # Behavioral verifier
    bv = detail.behavioral
    parts.append("<h2>Behavioral-verifier result</h2><table>")
    parts.append(_row("verifier result", _badge(bv.result.value, _outcome_kind(bv.result.value))))
    parts.append(_row("exit code", bv.exit_code))
    parts.append(_row("timed out", bv.timed_out))
    parts.append(_row("evidence fingerprint", bv.evidence_fingerprint))
    parts.append("</table>")

    # Checkpoint
    cp = detail.checkpoint
    parts.append("<h2>Checkpoint result</h2><table>")
    parts.append(_row("checkpoint", _badge(cp.result.value, _outcome_kind(cp.result.value))))
    parts.append(_row("attempted", cp.attempted))
    parts.append(_row("checkpoint fingerprint", cp.checkpoint_fingerprint))
    parts.append("</table>")

    # Evidence completeness
    ec = detail.evidence_completeness
    parts.append("<h2>Evidence completeness</h2><table>")
    parts.append(_row("completeness", _badge(ec.state.value, _status_kind({"COMPLETE": "ADMITTED", "INCOMPLETE": "INCOMPLETE", "INCONSISTENT": "INCONSISTENT"}.get(ec.state.value, "UNKNOWN")))))
    parts.append("</table>")
    if ec.missing_required:
        parts.append("<div>Missing required records:</div>")
        parts.append("<ul class=\"list\">" + "".join(f"<li>{_esc(r)}</li>" for r in ec.missing_required) + "</ul>")
    if ec.inconsistent_records:
        parts.append("<div>Inconsistent records:</div>")
        parts.append("<ul class=\"list\">" + "".join(f"<li>{_esc(r)}</li>" for r in ec.inconsistent_records) + "</ul>")

    # Human disposition
    hd = detail.human_disposition
    parts.append("<h2>Human disposition</h2><table>")
    parts.append(_row("disposition", hd.disposition.value))
    parts.append(_row("reason", hd.reason))
    parts.append("</table>")

    # Timeline
    parts.append("<h2>Timeline</h2><table>")
    parts.append("<tr><th>event</th><td>timestamp / state</td></tr>")
    for entry in detail.timeline:
        ts = entry.timestamp if entry.timestamp else f"[{entry.presence.value}]"
        suffix = " <span class=\"trunc\">(out of order)</span>" if entry.out_of_order else ""
        parts.append(f"<tr><th>{html.escape(entry.label)}</th><td>{_esc(ts)}{suffix}</td></tr>")
    parts.append("</table>")

    # Artifacts
    if detail.artifacts:
        parts.append("<h2>Artifacts</h2><table>")
        parts.append("<tr><th>artifact</th><td>bytes / sha256 / present</td></tr>")
        for artifact in detail.artifacts:
            desc = f"{artifact.byte_count} bytes &middot; {_plain(artifact.sha256)} &middot; {artifact.file_presence.value}"
            trunc = " <span class=\"trunc\">(truncated)</span>" if artifact.truncated else ""
            parts.append(f"<tr><th>{_esc(artifact.artifact_id)}</th><td>{desc}{trunc}</td></tr>")
        parts.append("</table>")

    # Diagnostics
    if detail.diagnostics:
        parts.append("<h2>Diagnostics (bounded)</h2>")
        for excerpt in detail.diagnostics:
            parts.append(f"<div><strong>{_esc(excerpt.label)}</strong>")
            if excerpt.total_byte_count is not None:
                parts.append(f' <span class="muted">({_esc(excerpt.total_byte_count)} bytes total)</span>')
            parts.append("</div>")
            parts.append(f"<pre>{html.escape(excerpt.excerpt)}</pre>")
            if excerpt.truncated:
                parts.append('<div class="trunc">… excerpt truncated …</div>')

    if detail.read_notes:
        parts.append("<h2>Read notes</h2>")
        parts.append("<ul class=\"list\">" + "".join(f"<li>{_esc(n)}</li>" for n in detail.read_notes) + "</ul>")

    parts.append("</body></html>")
    return "".join(parts)
