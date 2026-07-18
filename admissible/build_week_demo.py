"""Read-only Build Week demo surface over one frozen captured canary run.

This module renders one self-contained HTML replay of the canonical
``CHECKPOINT_CAPTURED_CANARY_SUCCESS`` native canary.  It is a presentation
artifact generator, not a protocol layer: every authoritative fact is resolved
through the committed read-only loaders, classifiers, and the evidence-only
reconstruction, and the generator fails closed when any required fact is
missing or invalid.  The generated page is never execution evidence and never
an authority record.

No live capability is reachable from this module: it never invokes Cursor, a
provider, npm, a native process, the behavioral verifier, or checkpoint
capture; it never reserves an attempt, writes a review binding or acceptance,
transitions delegated state, or contacts a network.  The only write it
performs is the explicitly supplied output file, which must live outside the
run root.  A process-local, non-persisted Git ``safe.directory`` overlay is
applied only when the sandbox process identity cannot otherwise perform the
committed read-only evidence reconstruction.

Rendering is deterministic: the same immutable run evidence and the same
committed source produce byte-identical UTF-8 HTML with exactly one terminal
newline.  No wall-clock time, random value, environment value, or absolute
local path is included in the page.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import subprocess
import sys
import webbrowser
from dataclasses import dataclass, fields
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from admissible.delegated_gate.models import CommandEvidence, EvidenceStatus
from admissible.delegated_gate.native_acceptance import (
    COMMITTED_REVIEW_SPECIFICATIONS,
    NativeCheckpointAcceptancePresence,
    NativeCheckpointReviewBindingPresence,
    classify_native_checkpoint_acceptance,
    classify_native_checkpoint_review_binding,
    load_native_checkpoint_acceptance,
    load_native_checkpoint_review_binding,
    load_run_authorization_binding,
)
from admissible.delegated_gate.native_canary import (
    EVIDENCE_DIRECTORY_NAME,
    NATIVE_SIDECAR_DIRECTORY_NAME,
    WORKSPACE_DIRECTORY_NAME,
    NativeCanaryStatus,
    load_behavioral_verifier,
    reconstruct_completed_canary_success,
)
from admissible.delegated_gate.native_executor import (
    AtomicNativeExecutionStore,
    NativeEvidenceInvalid,
    NativeExecutionStoreError,
)
from admissible.delegated_gate.store import (
    AtomicDelegatedSessionStore,
    DelegatedGateStoreError,
)


DELEGATED_STATE_DIRECTORY_NAME = "delegated-state"
CHECKPOINT_ARTIFACT_DIRECTORY_NAME = "checkpoint-artifacts"
ARCHIVE_ABSENT = "ABSENT"
RUN_METADATA_FILE_NAME = "canary-preflight.json"
# The one authorized one-shot budget shape this surface presents:
# (provider invocations, native attempts, repair rounds, auditors, retries).
CANARY_ONE_SHOT_BUDGETS = (1, 1, 0, 0, 0)
_ONE_SHOT_LIFECYCLE = (1, 1, 1, 1, 1)
# Every persisted attempt-record kind the frozen protocol can produce.  An
# archive record kind does not exist; archive absence is resolved by proving
# no such record is present rather than by assuming it.
_KNOWN_ATTEMPT_RECORD_KINDS = frozenset(
    {
        "request",
        "attempt-reserved",
        "process-started",
        "process-observation",
        "execution-eligibility",
        "result",
        "behavioral",
        "capture-attempt",
        "terminal",
        "checkpoint-review-binding",
        "checkpoint-acceptance",
    }
)
# A drive-letter or UNC prefix anywhere in the rendered page is a privacy
# defect; generation fails closed instead of publishing a local path.
_ABSOLUTE_PATH_PATTERN = re.compile(r"(?:[A-Za-z]:[\\/]|\\\\[A-Za-z0-9._-]+\\|/(?:home|Users|tmp|var|mnt)/)")
_CHECKPOINT_STDOUT_TAIL_LINES = 12
_CHECKPOINT_STDOUT_MAX_CHARS = 1200
_LOAD_ERRORS = (
    NativeExecutionStoreError,
    DelegatedGateStoreError,
    OSError,
    ValueError,
    TypeError,
    KeyError,
)


class BuildWeekDemoError(Exception):
    """The demo surface refuses to render; no success page is produced."""


@dataclass(frozen=True)
class ChainNode:
    """One evidence-chain entry: a human label bound to one stable identity."""

    label: str
    status: str
    identity_label: str
    identity: str
    recorded_at: str | None


@dataclass(frozen=True)
class DemoFacts:
    """Render-safe facts extracted from validated evidence.

    Deliberately contains no filesystem path: everything here may appear in
    the published page.
    """

    run_id: str
    session_id: str
    gate_id: str
    execution_status: str
    review_presence: str
    acceptance_presence: str
    archive_presence: str
    mission_text: str
    gate_objective: str
    gate_clauses: tuple[tuple[str, str], ...]
    budgets: tuple[int, int, int, int, int]
    native_invocations: int
    attempts: int
    process_starts: int
    process_completions: int
    native_exit_code: int
    timed_out: bool
    cleanup_observation: str
    retries: int
    repairs: int
    providers_used: int
    auditors: int
    started_at: str
    ended_at: str
    duration_text: str
    execution_source_head: str
    workspace_initial_head: str
    workspace_final_head: str
    evidence_review_code_head: str
    acceptance_protocol_code_head: str
    commit_message: str
    commits_added: int
    worktree_clean: bool
    remotes: tuple[str, ...]
    changed_files: tuple[str, ...]
    behavioral_exit_code: int
    behavioral_timed_out: bool
    checkpoint_command: str
    checkpoint_exit_code: int
    checkpoint_timed_out: bool
    checkpoint_stdout_excerpt: str
    chain: tuple[ChainNode, ...]
    review_reviewer: str
    review_note: str
    review_created_at: str
    review_fingerprint: str
    review_specification_fingerprint: str | None
    review_verdict: str
    acceptance_actor: str
    acceptance_created_at: str
    acceptance_fingerprint: str
    owner_statement_sha256: str
    acceptance_review_binding_fingerprint: str
    acceptance_non_authority: tuple[str, ...]
    review_non_authority: tuple[str, ...]
    checkpoint_fingerprint: str
    state_fingerprint: str
    state_revision: int


def _require_existing_directory(path: Path, label: str) -> Path:
    """Fail closed on a missing layout directory instead of creating it."""

    if not path.is_dir():
        raise BuildWeekDemoError(f"{label} does not exist; the demo surface never creates run-root state")
    return path


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _enable_process_local_git_safe_directory(workspace: Path) -> None:
    """Apply the sandbox-only, process-local ``safe.directory`` overlay.

    Only when Git refuses the immutable workspace under the current process
    identity; the overlay lives in this process environment alone and is
    never written to any Git configuration file.
    """

    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    try:
        probe = subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "--show-toplevel"],
            env=environment,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return
    if probe.returncode == 0:
        return
    stderr = probe.stderr or ""
    if "dubious ownership" not in stderr and "safe.directory" not in stderr:
        return
    try:
        count = int(os.environ.get("GIT_CONFIG_COUNT", "0") or "0")
    except ValueError:
        return
    os.environ[f"GIT_CONFIG_KEY_{count}"] = "safe.directory"
    os.environ[f"GIT_CONFIG_VALUE_{count}"] = str(workspace)
    os.environ["GIT_CONFIG_COUNT"] = str(count + 1)


def _load_validated_budgets(evidence_directory: Path) -> tuple[int, int, int, int, int]:
    """Read the authorized budgets from the fingerprint-validated payload.

    ``load_run_authorization_binding`` has already validated the canonical
    bytes and payload fingerprint; this reads the same validated bytes for the
    one field the binding type does not expose.
    """

    raw = json.loads((evidence_directory / RUN_METADATA_FILE_NAME).read_text(encoding="utf-8"))
    budgets = raw["authorization_payload"]["budgets"]
    if not isinstance(budgets, list) or len(budgets) != 5 or any(isinstance(v, bool) or not isinstance(v, int) for v in budgets):
        raise BuildWeekDemoError("persisted authorization budgets are malformed")
    return tuple(budgets)  # type: ignore[return-value]


def _classify_archive(execution_store: AtomicNativeExecutionStore, session_id: str, gate_id: str) -> str:
    """Resolve archive absence from the persisted record inventory.

    The frozen protocol defines no archive record kind; ABSENT is proven by
    enumerating every attempt record and finding only known non-archive kinds
    for exactly attempt zero.
    """

    prefix = f"{session_id}.{gate_id}.attempt-0.native-"
    for path in sorted(execution_store.directory.glob(f"{session_id}.{gate_id}.attempt-*.native-*.json")):
        name = path.name
        if not name.startswith(prefix) or not name.endswith(".json"):
            raise BuildWeekDemoError(f"unexpected native record outside attempt zero: {name}")
        kind = name[len(prefix) : -len(".json")]
        if "archive" in kind:
            raise BuildWeekDemoError(
                "an archive-like record exists; this surface presents only the archive-absent canonical state"
            )
        if kind not in _KNOWN_ATTEMPT_RECORD_KINDS:
            raise BuildWeekDemoError(f"unknown native record kind {kind!r}; refusing to summarize it")
    return ARCHIVE_ABSENT


def _parse_utc(value: str, label: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise BuildWeekDemoError(f"{label} is not a valid persisted timestamp") from exc


def _format_duration(started_at: str, ended_at: str) -> str:
    total = (_parse_utc(ended_at, "ended_at") - _parse_utc(started_at, "started_at")).total_seconds()
    if total < 0:
        raise BuildWeekDemoError("persisted end timestamp precedes the start timestamp")
    minutes = int(total // 60)
    seconds = total - minutes * 60
    if minutes:
        return f"{minutes} min {seconds:.1f} s"
    return f"{seconds:.1f} s"


def _checkpoint_stdout_excerpt(checkpoint: Any, artifact_root: Path, command: CommandEvidence) -> str:
    """Short excerpt of the persisted checkpoint stdout, hash-verified first."""

    reference = None
    for candidate in checkpoint.artifact_references:
        if candidate.artifact_id == command.stdout_artifact_id:
            reference = candidate
            break
    if reference is None:
        return ""
    path = artifact_root / reference.relative_path
    if not path.is_file():
        raise BuildWeekDemoError("persisted checkpoint stdout artifact is missing")
    data = path.read_bytes()
    if len(data) != reference.byte_count or hashlib.sha256(data).hexdigest() != reference.sha256:
        raise BuildWeekDemoError("persisted checkpoint stdout artifact hash mismatch")
    text = data.decode("utf-8", errors="replace")
    tail = [line.rstrip() for line in text.splitlines()][-_CHECKPOINT_STDOUT_TAIL_LINES:]
    return "\n".join(tail)[:_CHECKPOINT_STDOUT_MAX_CHARS]


def _single_passed_checkpoint_command(checkpoint: Any) -> CommandEvidence:
    commands = tuple(record for record in checkpoint.evidence_records if isinstance(record, CommandEvidence))
    if len(commands) != 1:
        raise BuildWeekDemoError("the canonical canary has exactly one checkpoint verification command")
    command = commands[0]
    if (
        command.status is not EvidenceStatus.PASSED
        or command.exit_code != 0
        or command.timed_out
        or command.output_truncated
        or not command.cleanup_proven
    ):
        raise BuildWeekDemoError("the persisted checkpoint command evidence is not a clean pass")
    return command


def _assert_render_safe(facts: DemoFacts) -> None:
    """No fact routed to the page may carry an absolute local path."""

    def _walk(value: Any, name: str) -> None:
        if isinstance(value, str):
            if _ABSOLUTE_PATH_PATTERN.search(value):
                raise BuildWeekDemoError(f"fact {name} carries an absolute local path and cannot be rendered")
        elif isinstance(value, tuple):
            for index, item in enumerate(value):
                _walk(item, f"{name}[{index}]")
        elif isinstance(value, ChainNode):
            for field in fields(value):
                _walk(getattr(value, field.name), f"{name}.{field.name}")

    for field in fields(facts):
        _walk(getattr(facts, field.name), field.name)


def load_demo_facts(run_root: str | Path) -> DemoFacts:
    """Resolve every displayed fact through the committed read-only protocol.

    Fails closed unless the run independently reconstructs to the canonical
    final state: completed execution success, PRESENT_VALID review binding,
    PRESENT_VALID acceptance, and a proven-absent archive.
    """

    root = Path(os.path.abspath(os.fspath(run_root)))
    _require_existing_directory(root, "run root")
    evidence = _require_existing_directory(root / EVIDENCE_DIRECTORY_NAME, "evidence directory")
    workspace = _require_existing_directory(root / WORKSPACE_DIRECTORY_NAME, "work workspace")
    session_directory = _require_existing_directory(
        evidence / DELEGATED_STATE_DIRECTORY_NAME, "delegated-state directory"
    )
    sidecar = _require_existing_directory(evidence / NATIVE_SIDECAR_DIRECTORY_NAME, "native execution sidecar")
    _require_existing_directory(sidecar / "artifacts", "native artifact directory")
    checkpoint_artifacts = _require_existing_directory(
        evidence / CHECKPOINT_ARTIFACT_DIRECTORY_NAME, "checkpoint artifact directory"
    )

    _enable_process_local_git_safe_directory(workspace)

    authorization = load_run_authorization_binding(evidence_directory=evidence)
    if Path(authorization.run_root) != root:
        raise BuildWeekDemoError("persisted authorization run root differs from the supplied run root")
    if Path(authorization.evidence_root) != evidence:
        raise BuildWeekDemoError("persisted authorization evidence root differs from the run layout")
    budgets = _load_validated_budgets(evidence)
    if budgets != CANARY_ONE_SHOT_BUDGETS:
        raise BuildWeekDemoError("persisted authorization budgets differ from the one-shot canary bounds")

    session_store = AtomicDelegatedSessionStore(session_directory)
    execution_store = AtomicNativeExecutionStore(sidecar)
    if Path(authorization.native_sidecar_root) != execution_store.directory:
        raise BuildWeekDemoError("persisted authorization sidecar root differs from the run layout")

    session_id = authorization.session_id
    outcome = reconstruct_completed_canary_success(
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence,
        session_id=session_id,
    )
    if outcome.status is not NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS or not outcome.canary_success:
        raise BuildWeekDemoError(
            f"execution did not reconstruct to the completed canary success: {outcome.status.value}"
        )
    lifecycle = (
        outcome.native_attempts_reserved,
        outcome.native_processes_started,
        outcome.native_processes_completed,
        outcome.process_observations_published,
        outcome.accepted_native_results_published,
    )
    if lifecycle != _ONE_SHOT_LIFECYCLE or outcome.provider_invocations != 1:
        raise BuildWeekDemoError("reconstructed lifecycle counts are not the one-shot canary counts")

    state = session_store.load(session_id)
    gate = state.current_gate
    gate_id = gate.gate_id

    review_presence = classify_native_checkpoint_review_binding(
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence,
        session_id=session_id,
        gate_id=gate_id,
    )
    if review_presence is not NativeCheckpointReviewBindingPresence.PRESENT_VALID:
        raise BuildWeekDemoError(f"review binding classification is {review_presence.value}, not PRESENT_VALID")
    review = load_native_checkpoint_review_binding(
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence,
        session_id=session_id,
        gate_id=gate_id,
    )

    acceptance_presence = classify_native_checkpoint_acceptance(
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence,
        session_id=session_id,
        gate_id=gate_id,
    )
    if acceptance_presence is not NativeCheckpointAcceptancePresence.PRESENT_VALID:
        raise BuildWeekDemoError(f"acceptance classification is {acceptance_presence.value}, not PRESENT_VALID")
    acceptance = load_native_checkpoint_acceptance(
        session_store=session_store,
        execution_store=execution_store,
        evidence_directory=evidence,
        session_id=session_id,
        gate_id=gate_id,
    )

    archive_presence = _classify_archive(execution_store, session_id, gate_id)

    binding = execution_store.load_request_structural(session_id, gate_id, 0)
    reservation = execution_store.load_attempt_reserved(session_id, gate_id, 0)
    started = execution_store.load_process_started(session_id, gate_id, 0)
    observation = execution_store.load_process_observation(session_id, gate_id, 0)
    eligibility = execution_store.load_execution_eligibility(session_id, gate_id, 0)
    result = execution_store.load_result(session_id, gate_id, 0)
    behavioral = load_behavioral_verifier(request=binding, execution_store=execution_store)
    capture = execution_store.load_capture_attempt(session_id, gate_id, 0)
    checkpoint = state.checkpoint_history[-1]

    if result.process_exit_code != 0 or result.timed_out or result.final_git_porcelain_status != "":
        raise BuildWeekDemoError("accepted result is not the clean canonical success")
    if result.final_git_remotes or result.commits_added != 1 or result.final_commit_message is None:
        raise BuildWeekDemoError("accepted result Git facts are not the canonical one-commit shape")
    if result.initial_git_head is None or result.final_git_head is None:
        raise BuildWeekDemoError("accepted result is missing persisted Git heads")

    command = _single_passed_checkpoint_command(checkpoint)
    stdout_excerpt = _checkpoint_stdout_excerpt(checkpoint, checkpoint_artifacts, command)

    committed_specification = COMMITTED_REVIEW_SPECIFICATIONS.get(authorization.run_id)
    specification_fingerprint = (
        committed_specification.validated().specification_fingerprint
        if committed_specification is not None
        else None
    )

    chain = (
        ChainNode("Request", "recorded", "request fingerprint", binding.request_fingerprint, None),
        ChainNode("Reservation", "recorded", "reservation fingerprint", reservation.reservation_fingerprint, reservation.reserved_at),
        ChainNode("Process start", "recorded", "start fingerprint", started.process_started_fingerprint, started.process_started_at),
        ChainNode("Process observation", "completed", "observation fingerprint", observation.observation_fingerprint, str(observation.process["ended_at"])),
        ChainNode("Eligibility", "eligible", "eligibility fingerprint", eligibility.eligibility_fingerprint, eligibility.evaluated_at),
        ChainNode("Result", "accepted", "result fingerprint", result.result_fingerprint, result.ended_at),
        ChainNode("Behavioral evidence", "PASS", "evidence fingerprint", behavioral.evidence_fingerprint, None),
        ChainNode("Capture", "recorded", "capture fingerprint", capture.attempt_fingerprint, capture.started_at),
        ChainNode("npm checkpoint", "PASS", "checkpoint fingerprint", checkpoint.checkpoint_fingerprint, None),
        ChainNode("Delegated state", state.phase.value, "state fingerprint", state.state_fingerprint, None),
    )

    facts = DemoFacts(
        run_id=authorization.run_id,
        session_id=session_id,
        gate_id=gate_id,
        execution_status=outcome.status.value,
        review_presence=review_presence.value,
        acceptance_presence=acceptance_presence.value,
        archive_presence=archive_presence,
        mission_text=state.mission.specification,
        gate_objective=gate.objective,
        gate_clauses=tuple((clause.clause_id, clause.text) for clause in gate.clauses),
        budgets=budgets,
        native_invocations=outcome.provider_invocations,
        attempts=outcome.native_attempts_reserved,
        process_starts=outcome.native_processes_started,
        process_completions=outcome.native_processes_completed,
        native_exit_code=result.process_exit_code,
        timed_out=result.timed_out,
        cleanup_observation=result.cleanup_observation.replace("_", " "),
        retries=outcome.native_attempts_reserved - 1,
        repairs=len(state.audit_history) if state.repair_authority is not None else 0,
        providers_used=outcome.provider_invocations,
        auditors=len(state.audit_history),
        started_at=result.started_at,
        ended_at=result.ended_at,
        duration_text=_format_duration(result.started_at, result.ended_at),
        execution_source_head=authorization.source_head,
        workspace_initial_head=result.initial_git_head,
        workspace_final_head=result.final_git_head,
        evidence_review_code_head=review.reviewed_code_head,
        acceptance_protocol_code_head=acceptance.acceptance_protocol_code_head,
        commit_message=result.final_commit_message,
        commits_added=result.commits_added,
        worktree_clean=result.final_git_porcelain_status == "",
        remotes=result.final_git_remotes,
        changed_files=result.changed_material_files,
        behavioral_exit_code=behavioral.exit_code if behavioral.exit_code is not None else -1,
        behavioral_timed_out=behavioral.timed_out,
        checkpoint_command=" ".join(command.argv),
        checkpoint_exit_code=command.exit_code,
        checkpoint_timed_out=command.timed_out,
        checkpoint_stdout_excerpt=stdout_excerpt,
        chain=chain,
        review_reviewer=review.reviewer_identity,
        review_note=review.note,
        review_created_at=review.created_at,
        review_fingerprint=review.review_binding_fingerprint,
        review_specification_fingerprint=specification_fingerprint,
        review_verdict=review.review_verdict,
        acceptance_actor=acceptance.actor_identity,
        acceptance_created_at=acceptance.created_at,
        acceptance_fingerprint=acceptance.acceptance_fingerprint,
        owner_statement_sha256=acceptance.owner_statement_sha256,
        acceptance_review_binding_fingerprint=acceptance.review_binding_fingerprint,
        acceptance_non_authority=acceptance.non_authority_claims,
        review_non_authority=review.non_authority_claims,
        checkpoint_fingerprint=checkpoint.checkpoint_fingerprint,
        state_fingerprint=state.state_fingerprint,
        state_revision=state.revision,
    )
    _assert_render_safe(facts)
    return facts


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _abbr(value: str) -> str:
    return f"{value[:12]}…" if len(value) > 16 else value


def _identity(label: str, value: str) -> str:
    """Abbreviated identity with the full value in a native disclosure."""

    return (
        f'<span class="fp mono">{_e(_abbr(value))}</span>'
        f'<details class="full"><summary>{_e(label)}</summary>'
        f'<code class="mono">{_e(value)}</code></details>'
    )


def _status_card(card_id: str, tone: str, eyebrow: str, label: str, value: str, footnote: str | None = None) -> str:
    note = f'<p class="card-note">{_e(footnote)}</p>' if footnote else ""
    return (
        f'<article class="status-card {tone}" id="{card_id}">'
        f'<p class="card-eyebrow">{_e(eyebrow)}</p>'
        f'<h2 class="card-label">{_e(label)}</h2>'
        f'<p class="card-value mono">{_e(value)}</p>'
        f"{note}</article>"
    )


def _metric(term: str, value: str) -> str:
    return f'<div class="metric"><dt>{_e(term)}</dt><dd class="mono">{_e(value)}</dd></div>'


_WHAT_CHANGED = (
    "The committed diff adds high-score persistence through the package&#x27;s storage "
    "interface: <code>src/score.js</code> gains <code>loadHighScore</code> and "
    "<code>persistHighScore</code>, which read the stored value, keep only the maximum, "
    "and reject non-integer stored values; <code>src/game-state.js</code> threads that "
    "storage through <code>createGameState</code> and <code>finishRound</code> so every "
    "state carries the current high score; <code>test/game-state.test.js</code> covers "
    "persistence across rounds and reloads; <code>README.md</code> documents the feature."
)

_WHY_REPLAY_COPY = (
    "The live agent is not being called again. Admissible reconstructs the outcome "
    "from immutable evidence produced during the original authorized execution. "
    "Current model availability, wrapper state, or provider access is not required "
    "to prove what happened."
)

_PROVES = (
    "one bounded native execution occurred",
    "the process completed successfully",
    "the expected workspace commit exists",
    "the npm checkpoint passed",
    "execution success can be reconstructed from evidence",
    "a committed review was bound to that evidence",
    "a human accepted the checkpoint",
)

_DOES_NOT_AUTHORIZE = (
    "another model invocation",
    "a retry or repair",
    "execution continuation",
    "another checkpoint run",
    "production deployment",
    "archive",
    "push",
)

_GUIDED_STEPS = (
    ("Mission", ("group-mission",)),
    ("Native execution", ("group-execution",)),
    ("Evidence and checkpoint", ("group-evidence",)),
    ("Review and human acceptance", ("group-adjudication",)),
    ("Authority boundary", ("group-authority",)),
)


_STYLE = """
:root {
  --bg: #0b0f14; --surface: #121821; --surface-2: #0e141b; --line: #22303f;
  --text: #e8edf4; --muted: #93a1b3; --verified: #46d190; --human: #e5b455;
  --neutral: #8fa0b3;
  --serif: Georgia, 'Times New Roman', serif;
  --sans: 'Segoe UI', system-ui, -apple-system, Arial, sans-serif;
  --mono: 'Cascadia Mono', Consolas, 'SF Mono', Menlo, monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
  * { transition: none !important; }
}
body {
  background: var(--bg); color: var(--text); font-family: var(--sans);
  font-size: 16px; line-height: 1.55;
}
.mono { font-family: var(--mono); }
.wrap { max-width: 1180px; margin: 0 auto; padding: 0 40px; }
a { color: inherit; }

.hero { padding: 64px 0 36px; border-bottom: 1px solid var(--line); }
.brand {
  font-family: var(--serif); font-size: 20px; letter-spacing: 0.28em;
  text-transform: uppercase; color: var(--human); margin-bottom: 26px;
}
.thesis {
  font-family: var(--serif); font-size: 40px; line-height: 1.22;
  max-width: 21em; font-weight: 400;
}
.thesis .quiet { color: var(--muted); }
.badge {
  display: inline-block; margin-top: 24px; padding: 6px 14px;
  border: 1px solid var(--line); border-radius: 999px;
  color: var(--muted); font-size: 13px; letter-spacing: 0.04em;
}

.status-strip { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; padding: 28px 0; }
.status-card {
  background: var(--surface); border: 1px solid var(--line); border-radius: 10px;
  padding: 16px 18px 14px; border-top-width: 3px;
}
.status-card.verified { border-top-color: var(--verified); }
.status-card.human { border-top-color: var(--human); }
.status-card.neutral { border-top-color: var(--neutral); border-top-style: dashed; }
.card-eyebrow { font-size: 11px; letter-spacing: 0.18em; text-transform: uppercase; color: var(--muted); }
.card-label { font-size: 15px; font-weight: 600; margin: 6px 0 8px; }
.card-value { font-size: 13px; word-break: break-word; }
.verified .card-value { color: var(--verified); }
.human .card-value { color: var(--human); }
.neutral .card-value { color: var(--neutral); }
.card-note { margin-top: 8px; font-size: 12px; color: var(--muted); }

.step-group { border-left: 2px solid transparent; }
.step-group.guided-on { border-left-color: var(--human); background: var(--surface-2); }
.step-group.guided-on .panel { border-color: var(--human); }

.panel { border: 1px solid var(--line); border-radius: 10px; background: var(--surface); padding: 28px 32px; margin: 22px 0; }
.eyebrow { font-size: 11px; letter-spacing: 0.2em; text-transform: uppercase; color: var(--muted); margin-bottom: 14px; }
.panel h2 { font-family: var(--serif); font-size: 26px; font-weight: 400; margin-bottom: 14px; }
.panel h3 { font-size: 15px; font-weight: 600; margin: 18px 0 8px; }
.panel p { max-width: 72ch; }
.panel p + p { margin-top: 10px; }
.lede { color: var(--muted); }

.mission-text {
  font-family: var(--serif); font-size: 19px; line-height: 1.5;
  white-space: pre-line; border-left: 3px solid var(--human);
  padding: 6px 0 6px 20px; margin: 10px 0 18px; max-width: 62em;
}
.chips { display: flex; flex-wrap: wrap; gap: 8px; list-style: none; }
.chips li {
  border: 1px solid var(--line); border-radius: 999px; padding: 4px 12px;
  font-size: 13px; color: var(--muted);
}

.metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px 18px; margin-top: 8px; }
.metric { background: var(--surface-2); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }
.metric dt { font-size: 12px; color: var(--muted); }
.metric dd { font-size: 15px; margin-top: 2px; }
.duration { margin-top: 14px; color: var(--muted); font-size: 14px; }
.duration .mono { color: var(--text); }

.kv { display: grid; grid-template-columns: 230px 1fr; gap: 8px 18px; margin: 10px 0; }
.kv dt { color: var(--muted); font-size: 14px; padding-top: 1px; }
.kv dd { font-size: 14px; word-break: break-word; }
.head-value { font-size: 14px; letter-spacing: 0.02em; }

.filelist { list-style: none; display: grid; gap: 6px; margin: 8px 0 14px; }
.filelist li { font-size: 14px; }
.filelist li::before { content: "+ "; color: var(--verified); }

.verify-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.verify-card { background: var(--surface-2); border: 1px solid var(--line); border-radius: 8px; padding: 16px 18px; }
.pass { color: var(--verified); font-weight: 600; }
.stdout {
  background: var(--bg); border: 1px solid var(--line); border-radius: 6px;
  padding: 12px 14px; font-size: 12px; line-height: 1.5; overflow-x: auto;
  white-space: pre; margin-top: 10px; max-height: 260px;
}
.capture-note { margin-top: 10px; font-size: 13px; color: var(--muted); }

.chain { list-style: none; margin-top: 6px; }
.chain li { position: relative; padding: 0 0 16px 26px; border-left: 1px solid var(--line); margin-left: 7px; }
.chain li:last-child { padding-bottom: 2px; border-left-color: transparent; }
.chain li::before {
  content: ""; position: absolute; left: -5px; top: 5px; width: 9px; height: 9px;
  border-radius: 50%; background: var(--verified); border: 2px solid var(--bg);
}
.chain .node-row { display: flex; flex-wrap: wrap; align-items: baseline; gap: 10px; }
.chain .node-label { font-weight: 600; font-size: 15px; }
.chain .node-status {
  font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase;
  color: var(--verified); border: 1px solid var(--line); border-radius: 999px; padding: 1px 8px;
}
.chain .node-time { color: var(--muted); font-size: 12px; }
.fp { color: var(--muted); font-size: 13px; }
details.full { font-size: 12px; color: var(--muted); margin-top: 2px; }
details.full summary { cursor: pointer; }
details.full code { display: block; margin-top: 4px; word-break: break-all; color: var(--text); }

.heads { display: grid; gap: 10px; margin-top: 8px; }
.head-row { display: grid; grid-template-columns: 210px 1fr; gap: 4px 18px; background: var(--surface-2); border: 1px solid var(--line); border-radius: 8px; padding: 12px 14px; }
.head-role { font-size: 13px; font-weight: 600; }
.head-row .why { grid-column: 2; color: var(--muted); font-size: 13px; }

.boundary { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.boundary .col { border: 1px solid var(--line); border-radius: 8px; padding: 16px 18px; background: var(--surface-2); }
.boundary h3 { margin-top: 0; }
.boundary ul { list-style: none; display: grid; gap: 6px; font-size: 14px; }
.boundary .yes li::before { content: "\\2713\\0020"; color: var(--verified); }
.boundary .no li::before { content: "\\2715\\0020"; color: var(--human); }

.why-replay { border-left: 3px solid var(--verified); }
.why-replay .big { font-family: var(--serif); font-size: 21px; line-height: 1.45; max-width: 44em; }

footer { padding: 30px 0 60px; color: var(--muted); font-size: 13px; }
footer p { max-width: 84ch; }

.guided {
  position: fixed; right: 22px; bottom: 22px; display: none; z-index: 10;
  background: var(--surface); border: 1px solid var(--line); border-radius: 10px;
  padding: 10px 12px; box-shadow: 0 6px 24px rgba(0, 0, 0, 0.45);
  align-items: center; gap: 10px; font-size: 13px;
}
.guided button {
  background: var(--surface-2); border: 1px solid var(--line); color: var(--text);
  border-radius: 6px; padding: 5px 10px; font: inherit; cursor: pointer;
}
.guided button:hover { border-color: var(--human); }
.guided button:focus-visible, details.full summary:focus-visible { outline: 2px solid var(--human); outline-offset: 2px; }
.guided .g-step { color: var(--muted); min-width: 15em; text-align: center; }

@media (max-width: 1100px) {
  .status-strip, .verify-grid, .boundary { grid-template-columns: 1fr 1fr; }
  .metrics { grid-template-columns: repeat(3, 1fr); }
  .thesis { font-size: 32px; }
}
@media (max-width: 720px) {
  .wrap { padding: 0 18px; }
  .status-strip, .verify-grid, .boundary, .metrics { grid-template-columns: 1fr; }
  .kv, .head-row { grid-template-columns: 1fr; }
  .head-row .why { grid-column: 1; }
}
"""


_SCRIPT = """
(function () {
  'use strict';
  var steps = __STEPS__;
  var current = -1;
  var bar = document.getElementById('guided');
  var nav = document.getElementById('g-nav');
  var toggle = document.getElementById('g-toggle');
  var label = document.getElementById('g-step');
  if (!bar || !toggle) { return; }
  bar.style.display = 'flex';
  function clearHighlight() {
    var groups = document.querySelectorAll('.step-group.guided-on');
    for (var i = 0; i < groups.length; i += 1) { groups[i].classList.remove('guided-on'); }
  }
  function exitGuided() {
    current = -1;
    clearHighlight();
    if (nav) { nav.style.display = 'none'; }
    toggle.style.display = 'inline-block';
  }
  function show(index) {
    if (index < 0 || index >= steps.length) { return; }
    current = index;
    clearHighlight();
    var ids = steps[index][1];
    var first = null;
    for (var i = 0; i < ids.length; i += 1) {
      var group = document.getElementById(ids[i]);
      if (group) {
        group.classList.add('guided-on');
        if (!first) { first = group; }
      }
    }
    if (label) { label.textContent = (index + 1) + ' \\u00b7 ' + steps.length + ' \\u2014 ' + steps[index][0]; }
    if (first) {
      var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      first.scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
    }
    if (nav) { nav.style.display = 'flex'; }
    toggle.style.display = 'none';
  }
  toggle.addEventListener('click', function () { show(0); });
  var prev = document.getElementById('g-prev');
  var next = document.getElementById('g-next');
  var close = document.getElementById('g-close');
  if (prev) { prev.addEventListener('click', function () { show(Math.max(0, current - 1)); }); }
  if (next) { next.addEventListener('click', function () { show(Math.min(steps.length - 1, current + 1)); }); }
  if (close) { close.addEventListener('click', exitGuided); }
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') { exitGuided(); }
  });
}());
"""


def render_demo_html(facts: DemoFacts) -> str:
    """Render the deterministic, self-contained success page."""

    _assert_render_safe(facts)
    parts: list[str] = []
    add = parts.append

    add("<!DOCTYPE html>")
    add('<html lang="en">')
    add("<head>")
    add('<meta charset="utf-8">')
    add('<meta name="viewport" content="width=device-width, initial-scale=1">')
    add("<title>Admissible</title>")
    add(f"<style>{_STYLE}</style>")
    add("</head>")
    add("<body>")

    # Hero -----------------------------------------------------------------
    add('<header class="hero"><div class="wrap">')
    add('<p class="brand">Admissible</p>')
    add(
        '<h1 class="thesis">A native agent completed a real coding task.<br>'
        '<span class="quiet">Admissible proves what ran, what changed, what passed, '
        "and what a human accepted.</span></h1>"
    )
    add('<p class="badge">Evidence-only replay · no live model or provider consulted</p>')
    add("</div></header>")

    add('<main class="wrap">')

    # Status strip ---------------------------------------------------------
    add('<section class="status-strip" aria-label="Canonical run state">')
    add(_status_card("status-execution", "verified", "Execution", "Execution verified", facts.execution_status))
    add(_status_card("status-review", "human", "Committed review", "Review bound to evidence", facts.review_presence))
    add(_status_card("status-acceptance", "human", "Human checkpoint", "Human accepted", facts.acceptance_presence))
    add(
        _status_card(
            "status-archive",
            "neutral",
            "Archive",
            "Archive",
            f"{facts.archive_presence} — intentionally outside this demo",
            "Not an error: archiving is a separate decision this replay does not make.",
        )
    )
    add("</section>")

    # 1. Mission -----------------------------------------------------------
    add('<div class="step-group" id="group-mission">')
    add('<section class="panel" id="mission">')
    add('<p class="eyebrow">1 · Mission</p>')
    add("<h2>One immutable mission, handed to a native agent</h2>")
    add(f'<p class="mission-text">{_e(facts.mission_text)}</p>')
    add("<h3>Bounds the owner authorized</h3>")
    add('<ul class="chips">')
    for constraint in (
        f"{facts.budgets[0]} native provider invocation",
        f"{facts.budgets[1]} attempt",
        "no retry",
        "no repair",
        "no push",
        "stop after the local commit",
    ):
        add(f"<li>{_e(constraint)}</li>")
    add("</ul>")
    add("</section></div>")

    # 2. Execution ---------------------------------------------------------
    add('<div class="step-group" id="group-execution">')
    add('<section class="panel" id="execution">')
    add('<p class="eyebrow">2 · Native execution</p>')
    add("<h2>Exactly one bounded invocation, measured end to end</h2>")
    add('<dl class="metrics">')
    add(_metric("native invocations", str(facts.native_invocations)))
    add(_metric("attempts", str(facts.attempts)))
    add(_metric("process starts", str(facts.process_starts)))
    add(_metric("process completions", str(facts.process_completions)))
    add(_metric("native exit code", str(facts.native_exit_code)))
    add(_metric("timeout", "yes" if facts.timed_out else "no"))
    add(_metric("cleanup", facts.cleanup_observation))
    add(_metric("retries", str(facts.retries)))
    add(_metric("repairs", str(facts.repairs)))
    add(_metric("providers used", str(facts.providers_used)))
    add(_metric("auditors during execution", str(facts.auditors)))
    add("</dl>")
    add(
        f'<p class="duration">Elapsed execution: <span class="mono">{_e(facts.duration_text)}</span> '
        f'— persisted timestamps <span class="mono">{_e(facts.started_at)}</span> to '
        f'<span class="mono">{_e(facts.ended_at)}</span>.</p>'
    )
    add("</section>")

    # Resulting workspace --------------------------------------------------
    add('<section class="panel" id="workspace">')
    add('<p class="eyebrow">2 · Resulting workspace</p>')
    add("<h2>One concrete local commit</h2>")
    add('<dl class="kv">')
    add(f'<dt>Workspace final HEAD</dt><dd class="mono head-value">{_e(facts.workspace_final_head)}</dd>')
    add(f'<dt>Exact commit message</dt><dd class="mono">{_e(facts.commit_message)}</dd>')
    add(
        f"<dt>Git facts</dt><dd>exactly {_e(facts.commits_added)} local commit created by the task · "
        f'{"clean final workspace" if facts.worktree_clean else "workspace not clean"} · '
        f'{"no configured remotes" if not facts.remotes else "remotes present"} · no push</dd>'
    )
    add("</dl>")
    add("<h3>Changed files</h3>")
    add('<ul class="filelist mono">')
    for path in facts.changed_files:
        add(f"<li>{_e(path)}</li>")
    add("</ul>")
    add("<h3>What changed</h3>")
    add(f"<p>{_WHAT_CHANGED}</p>")
    add("</section></div>")

    # 3. Verification + chain + replay explanation ---------------------------
    add('<div class="step-group" id="group-evidence">')
    add('<section class="panel" id="verification">')
    add('<p class="eyebrow">3 · Verification</p>')
    add("<h2>Two independent verification results</h2>")
    add('<div class="verify-grid">')
    add('<article class="verify-card">')
    add(f'<h3>Behavioral evidence — <span class="pass">PASS</span></h3>')
    add(
        "<p>A harness-owned Node script, persisted with the evidence, imported the "
        "committed modules and asserted the feature actually works: a fresh state "
        "starts at zero, the high score persists across rounds, a lower score never "
        "lowers it, it survives reloads, and invalid stored values are rejected. "
        f"Recorded exit code <span class=\"mono\">{_e(facts.behavioral_exit_code)}</span>, "
        f"timeout {_e('yes' if facts.behavioral_timed_out else 'no')}.</p>"
    )
    add('<p class="capture-note">Captured during the original authorized execution.</p>')
    add("</article>")
    add('<article class="verify-card">')
    add(f'<h3>Checkpoint — <span class="pass">PASS</span></h3>')
    add(
        f'<p>Command <span class="mono">{_e(facts.checkpoint_command)}</span> · '
        f'exit code <span class="mono">{_e(facts.checkpoint_exit_code)}</span> · '
        f"timeout {_e('yes' if facts.checkpoint_timed_out else 'no')}.</p>"
    )
    if facts.checkpoint_stdout_excerpt:
        add(f'<pre class="stdout mono">{_e(facts.checkpoint_stdout_excerpt)}</pre>')
    add('<p class="capture-note">Captured during the original authorized execution — this page did not rerun the tests.</p>')
    add("</article>")
    add("</div>")
    add("</section>")

    # Evidence chain ---------------------------------------------------------
    add('<section class="panel" id="chain">')
    add('<p class="eyebrow">3 · Evidence chain</p>')
    add("<h2>Every step is a write-once, fingerprinted record</h2>")
    add('<ol class="chain">')
    for node in facts.chain:
        add("<li>")
        add('<div class="node-row">')
        add(f'<span class="node-label">{_e(node.label)}</span>')
        add(f'<span class="node-status">{_e(node.status)}</span>')
        add(_identity(node.identity_label, node.identity))
        if node.recorded_at:
            add(f'<span class="node-time mono">{_e(node.recorded_at)}</span>')
        add("</div>")
        add("</li>")
    add("</ol>")
    add("</section>")

    # Why this replay matters ------------------------------------------------
    add('<section class="panel why-replay" id="why-replay">')
    add('<p class="eyebrow">3 · Why this replay matters</p>')
    add(f'<p class="big">{_e(_WHY_REPLAY_COPY)}</p>')
    add(
        "<p>The guarantees are exactly the implemented ones: SHA-256 fingerprinting "
        "of canonical records and write-once evidence semantics. No further "
        "cryptographic property is claimed.</p>"
    )
    add("</section></div>")

    # 4. Review binding + acceptance + four heads ----------------------------
    add('<div class="step-group" id="group-adjudication">')
    add('<section class="panel" id="review-binding">')
    add('<p class="eyebrow">4 · Committed review</p>')
    add("<h2>A committed review, bound to this exact evidence</h2>")
    add('<dl class="kv">')
    add(f'<dt>Classification</dt><dd class="mono">{_e(facts.review_presence)}</dd>')
    add(f"<dt>Reviewer</dt><dd>{_e(facts.review_reviewer)}</dd>")
    add(f"<dt>Note</dt><dd>{_e(facts.review_note) if facts.review_note else '—'}</dd>")
    add(f'<dt>Created at</dt><dd class="mono">{_e(facts.review_created_at)}</dd>')
    add(f"<dt>Review-binding fingerprint</dt><dd>{_identity('full review-binding fingerprint', facts.review_fingerprint)}</dd>")
    if facts.review_specification_fingerprint is not None:
        add(
            "<dt>Committed review-specification fingerprint</dt>"
            f"<dd>{_identity('full specification fingerprint', facts.review_specification_fingerprint)}</dd>"
        )
    else:
        add(
            "<dt>Committed review-specification fingerprint</dt>"
            "<dd>no committed specification is registered for this run ID</dd>"
        )
    add(f'<dt>Reviewed code HEAD</dt><dd class="mono head-value">{_e(facts.evidence_review_code_head)}</dd>')
    add(f'<dt>Review verdict</dt><dd class="mono">{_e(facts.review_verdict)}</dd>')
    add("</dl>")
    add(
        "<p>The review binding records that a specific committed review examined this "
        "specific execution evidence. It is not human checkpoint acceptance and grants "
        "no execution authority.</p>"
    )
    add("</section>")

    add('<section class="panel" id="acceptance">')
    add('<p class="eyebrow">4 · Human acceptance</p>')
    add("<h2>A human accepted this checkpoint, on the record</h2>")
    add('<dl class="kv">')
    add(f'<dt>Classification</dt><dd class="mono">{_e(facts.acceptance_presence)}</dd>')
    add(f"<dt>Actor</dt><dd>{_e(facts.acceptance_actor)}</dd>")
    add(f'<dt>Created at</dt><dd class="mono">{_e(facts.acceptance_created_at)}</dd>')
    add(f"<dt>Acceptance-record fingerprint</dt><dd>{_identity('full acceptance fingerprint', facts.acceptance_fingerprint)}</dd>")
    add(f"<dt>Owner-statement SHA-256</dt><dd>{_identity('full owner-statement SHA-256', facts.owner_statement_sha256)}</dd>")
    add(
        "<dt>Linked review-binding fingerprint</dt>"
        f"<dd>{_identity('full linked review-binding fingerprint', facts.acceptance_review_binding_fingerprint)}</dd>"
    )
    add(f'<dt>Acceptance-protocol HEAD</dt><dd class="mono head-value">{_e(facts.acceptance_protocol_code_head)}</dd>')
    add("</dl>")
    add(
        "<p>The complete owner statement is not stored. Only its SHA-256 is persisted "
        "after exact canonical parsing.</p>"
    )
    add(
        "<p>Human acceptance did not rerun or alter the execution and did not "
        "transition the delegated execution phase.</p>"
    )
    add("</section>")

    # Four-head binding ------------------------------------------------------
    add('<section class="panel" id="four-heads">')
    add('<p class="eyebrow">4 · Four-head binding</p>')
    add("<h2>Four distinct roles, four committed identities</h2>")
    add('<div class="heads">')
    for role, head, why in (
        ("Execution source", facts.execution_source_head, "The committed protocol code that ran the bounded native execution."),
        ("Workspace result", facts.workspace_final_head, "The single local commit the native agent created inside the assigned workspace."),
        ("Evidence-review code", facts.evidence_review_code_head, "The committed code the evidence review passed under."),
        ("Acceptance-protocol code", facts.acceptance_protocol_code_head, "The committed code observed when the human acceptance record was written."),
    ):
        add('<div class="head-row">')
        add(f'<span class="head-role">{_e(role)}</span>')
        add(f'<span class="mono head-value">{_e(head)}</span>')
        add(f'<span class="why">{_e(why)}</span>')
        add("</div>")
    add("</div>")
    add("</section></div>")

    # 5. Authority boundary ---------------------------------------------------
    add('<div class="step-group" id="group-authority">')
    add('<section class="panel" id="authority">')
    add('<p class="eyebrow">5 · Authority boundary</p>')
    add("<h2>What this proves — and what it does not authorize</h2>")
    add('<div class="boundary">')
    add('<div class="col"><h3>Proves</h3><ul class="yes">')
    for item in _PROVES:
        add(f"<li>{_e(item)}</li>")
    add("</ul></div>")
    add('<div class="col"><h3>Does not authorize</h3><ul class="no">')
    for item in _DOES_NOT_AUTHORIZE:
        add(f"<li>{_e(item)}</li>")
    add("</ul></div>")
    add("</div>")
    add('<details class="full"><summary>Persisted non-authority claims (acceptance record)</summary>')
    add('<code class="mono">')
    add("<br>".join(_e(claim) for claim in facts.acceptance_non_authority))
    add("</code></details>")
    add("</section></div>")

    add("</main>")

    # Footer -------------------------------------------------------------------
    add('<footer><div class="wrap">')
    add(
        f"<p>Generated read-only from the persisted evidence of run "
        f'<span class="mono">{_e(facts.run_id)}</span>. This page is a presentation '
        "artifact: it is not new execution evidence and not an authority record. "
        "The protocol that produced the evidence is frozen for this demo.</p>"
    )
    add("</div></footer>")

    # Guided replay (presentation-only) ---------------------------------------
    add('<div class="guided" id="guided">')
    add('<button type="button" id="g-toggle">Guided replay</button>')
    add('<div class="g-nav" id="g-nav" style="display:none; align-items:center; gap:10px;">')
    add('<button type="button" id="g-prev" aria-label="Previous step">◀</button>')
    add('<span class="g-step" id="g-step"></span>')
    add('<button type="button" id="g-next" aria-label="Next step">▶</button>')
    add('<button type="button" id="g-close" aria-label="Exit guided replay">Esc</button>')
    add("</div></div>")

    steps_json = json.dumps([[title, list(ids)] for title, ids in _GUIDED_STEPS], sort_keys=False)
    add(f"<script>{_SCRIPT.replace('__STEPS__', steps_json)}</script>")

    add("</body>")
    add("</html>")

    return "\n".join(parts) + "\n"


def render_validation_error_html(category: str, detail: str) -> str:
    """A deliberately status-free page for an invalid-evidence invocation."""

    return "\n".join(
        (
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            "<title>Admissible — evidence validation failed</title>",
            f"<style>{_STYLE}</style>",
            "</head>",
            "<body>",
            '<header class="hero"><div class="wrap">',
            '<p class="brand">Admissible</p>',
            '<h1 class="thesis">Evidence validation failed.</h1>',
            '<p class="badge">No execution, review, acceptance, or archive status is claimed</p>',
            "</div></header>",
            '<main class="wrap"><section class="panel">',
            f"<h2>{_e(category)}</h2>",
            f"<p>{_e(detail)}</p>",
            "<p>The demo surface fails closed: it renders a success page only when the "
            "run independently reconstructs to the canonical captured-canary state.</p>",
            "</section></main>",
            "</body>",
            "</html>",
        )
    ) + "\n"


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


def _resolved_output_path(output: str | Path, run_root: str | Path) -> Path:
    destination = Path(os.path.abspath(os.fspath(output)))
    root = Path(os.path.abspath(os.fspath(run_root)))
    if _is_within(destination, root):
        raise BuildWeekDemoError("the output path must live outside the run root")
    return destination


def _write_page(destination: Path, text: str) -> tuple[int, str]:
    data = text.encode("utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return len(data), hashlib.sha256(data).hexdigest()


def generate_build_week_demo(run_root: str | Path, output: str | Path) -> tuple[Path, int, str]:
    """Load, validate, render, and write the demo page; returns (path, size, sha256)."""

    destination = _resolved_output_path(output, run_root)
    facts = load_demo_facts(run_root)
    text = render_demo_html(facts)
    if _ABSOLUTE_PATH_PATTERN.search(text):
        raise BuildWeekDemoError("rendered page unexpectedly carries an absolute local path")
    size, digest = _write_page(destination, text)
    return destination, size, digest


def _redacted_detail(message: str, run_root: str | Path) -> str:
    root = str(Path(os.path.abspath(os.fspath(run_root))))
    for variant in (root, root.replace("\\", "/"), root.replace("\\", "\\\\")):
        if variant:
            message = message.replace(variant, "‹run-root›")
    if _ABSOLUTE_PATH_PATTERN.search(message):
        return "evidence validation failed; details withheld because they carry a local path"
    return message


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m admissible.build_week_demo",
        description=(
            "Render the read-only Build Week demo page from one frozen captured "
            "canary run. Presentation only: no live capability is invoked and "
            "only the explicit output path is written."
        ),
    )
    parser.add_argument("--run-root", required=True, help="canonical canary run root (read-only)")
    parser.add_argument("--output", required=True, help="output HTML path, outside the run root")
    parser.add_argument(
        "--open",
        action="store_true",
        help="open the generated page with the standard webbrowser module after success",
    )
    args = parser.parse_args(argv)

    try:
        destination, size, digest = generate_build_week_demo(args.run_root, args.output)
    except (BuildWeekDemoError, *_LOAD_ERRORS) as exc:
        detail = _redacted_detail(str(exc), args.run_root)
        print(f"build-week demo blocked: {type(exc).__name__}: {detail}", file=sys.stderr)
        try:
            destination = _resolved_output_path(args.output, args.run_root)
            _write_page(destination, render_validation_error_html(type(exc).__name__, detail))
        except (BuildWeekDemoError, OSError):
            pass
        return 2

    print(f"generated {destination}")
    print(f"bytes={size}")
    print(f"sha256={digest}")
    if args.open:
        webbrowser.open(destination.as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
