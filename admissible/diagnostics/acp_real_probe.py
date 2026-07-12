"""Real, budgeted Cursor ACP vs one-shot model-probe harness (RUN_048).

Diagnostic-only. **Never imported by production code.** Drives the RUN_047
`CursorAcpBackend` and one-shot `CursorCliAgentBackend` against the *real*
installed Cursor CLI, records a sanitized live ACP transcript, and enforces the
RUN_048 hard constraints:

- a hard budget of **four** real model-bearing invocations (non-model handshake
  is free);
- serial execution only, no concurrency;
- **no** automatic retry — each ``run_*`` call is exactly one attempt;
- no silent transport fallback;
- every real invocation's process tree is cleaned up and *verified*.

The normal unit suite must never import this module against a real provider;
the deterministic RUN_048 tests exercise the budget/serial/no-retry/redaction
logic with fakes only.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from admissible.agent_backend import (
    BACKEND_ID_CURSOR_ONESHOT,
    AgentInvocationRequest,
    CursorCliAgentBackend,
    CursorCliConfig,
    build_cursor_agent_safe_environment,
)
from admissible.cursor_acp_transport import (
    ACP_METHOD_INITIALIZE,
    BACKEND_ID_CURSOR_ACP,
    AcpConnection,
    AcpTimeouts,
    CursorAcpBackend,
    CursorAcpConfig,
    MSG_JSON,
    _extract_protocol_version,
)
from admissible.managed_process import ManagedProcess, READ_TIMEOUT, pid_alive
from admissible.transport_health import TransportHealth
from admissible.long_run_envelope_builder import extract_structured_operation_blocks

DEFAULT_MAX_MODEL_CALLS = 4
_PREVIEW_MAX = 240


class ModelBudgetExceeded(RuntimeError):
    """Raised when a probe would exceed the hard four-call model budget."""


class ProbeAlreadyRunning(RuntimeError):
    """Raised on any attempted concurrent/re-entrant probe (serial-only)."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Target-workspace mutation audit (RUN_049 PART D.25)
# ---------------------------------------------------------------------------

# Admissible's own controlled metadata (e.g. the mission-contract artifact
# written under the *agent* workspace) is excluded -- this snapshot audits the
# *target* workspace, which a proposal-only ACP turn must never mutate at all
# before Admissible's own bounded execution runs.
DEFAULT_WORKSPACE_SNAPSHOT_EXCLUDE_PREFIXES = (".admissible",)


def snapshot_workspace(
    root: str | Path,
    *,
    exclude_prefixes: tuple[str, ...] = DEFAULT_WORKSPACE_SNAPSHOT_EXCLUDE_PREFIXES,
) -> dict[str, str]:
    """Sha256 snapshot of every file under ``root`` (POSIX-relative path -> hash).

    Read-only; never creates, modifies, or deletes anything. Missing roots
    snapshot as empty (never an error) so a probe can snapshot a target
    workspace before it necessarily exists.
    """
    root_path = Path(root)
    if not root_path.exists():
        return {}
    snapshot: dict[str, str] = {}
    for path in sorted(root_path.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root_path).as_posix()
        if any(rel == prefix or rel.startswith(prefix + "/") for prefix in exclude_prefixes):
            continue
        snapshot[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


def diff_workspace_snapshots(before: dict[str, str], after: dict[str, str]) -> dict[str, Any]:
    """Added/removed/modified paths between two ``snapshot_workspace`` results.

    ``clean`` is True only when the target workspace is byte-for-byte
    unchanged -- any application mutation before Admissible's own bounded
    execution fails the proposal-only gate (PART D.25).
    """
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    modified = sorted(p for p in (set(before) & set(after)) if before[p] != after[p])
    return {
        "paths_added": added,
        "paths_removed": removed,
        "paths_modified": modified,
        "clean": not added and not removed and not modified,
    }


# ---------------------------------------------------------------------------
# Sanitization (PART J.32)
# ---------------------------------------------------------------------------

_SENSITIVE_KEY_RE = re.compile(r"token|auth|secret|key|cookie|email|bearer|credential", re.I)
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_WINPATH_RE = re.compile(r"[A-Za-z]:\\\\?(?:Users|Documents)\\\\?[^\"\s]*", re.I)
_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9_\-]{40,}\.?[A-Za-z0-9_\-.]*")


def sanitize_text(text: str, *, max_len: int = _PREVIEW_MAX) -> str:
    """Redact emails, host paths, and long token-like blobs; bound the length."""
    text = _EMAIL_RE.sub("<email>", text)
    text = _WINPATH_RE.sub("<path>", text)
    text = _LONG_TOKEN_RE.sub("<token>", text)
    if len(text) > max_len:
        text = text[:max_len] + f"…[+{len(text) - max_len}]"
    return text


def sanitize_json_line(line: str) -> Any:
    """Parse one JSON-RPC line and redact sensitive fields recursively; fall back
    to plain text sanitization when the line is not JSON."""
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return {"_raw": sanitize_text(line)}

    def _redact(node: Any) -> Any:
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                if _SENSITIVE_KEY_RE.search(str(k)):
                    out[k] = "<redacted>"
                else:
                    out[k] = _redact(v)
            return out
        if isinstance(node, list):
            return [_redact(x) for x in node]
        if isinstance(node, str):
            return sanitize_text(node)
        return node

    return _redact(obj)


# ---------------------------------------------------------------------------
# Verdict gate + response-deviation classifier (PART G / D)
# ---------------------------------------------------------------------------

VERDICT_PROMOTE = "PROMOTE_CURSOR_ACP_TO_DEFAULT"
VERDICT_KEEP = "KEEP_CURSOR_ONESHOT_DEFAULT_ACP_EXPERIMENTAL"
VERDICT_NOT_USABLE = "CURSOR_ACP_NOT_CURRENTLY_USABLE"
VERDICT_INSUFFICIENT = "INSUFFICIENT_EVIDENCE_FOR_DEFAULT_DECISION"

# Every condition that must be true to PROMOTE ACP to default (PART G.21), plus
# the RUN_048 addition that BOTH real ACP calls must have exercised the
# promotable (plan-mode-enforced) configuration.
_PROMOTE_CONDITIONS = (
    "handshake_ok",
    "both_acp_terminal",
    "both_acp_usable",
    "structured_extraction_ok",
    "identities_stable",
    "no_duplicate_ingest",
    "no_uncertain_completion",
    "no_orphan_or_cleanup_failure",
    "no_silent_fallback",
    "health_healthy",
    "both_acp_calls_in_promotable_config",
    "full_suite_passes",
)


def compute_default_transport_verdict(evidence: dict[str, Any]) -> str:
    """Deterministic default-transport verdict from evidence (PART G.20/21).

    PROMOTE only when *every* condition holds; a proven hard failure yields
    NOT_USABLE; a viable-but-incomplete picture yields KEEP (experimental);
    otherwise INSUFFICIENT.
    """
    if all(bool(evidence.get(c)) for c in _PROMOTE_CONDITIONS):
        return VERDICT_PROMOTE
    if evidence.get("acp_hard_failure"):
        return VERDICT_NOT_USABLE
    if evidence.get("handshake_ok") and evidence.get("any_acp_usable"):
        return VERDICT_KEEP
    return VERDICT_INSUFFICIENT


# ---------------------------------------------------------------------------
# RUN_049 PART H -- durable promotion decision
# ---------------------------------------------------------------------------

RUN049_VERDICT_PROMOTE = "PROMOTE_CURSOR_ACP_TO_DEFAULT"
RUN049_VERDICT_KEEP = "KEEP_CURSOR_ONESHOT_DEFAULT_ACP_EXPERIMENTAL"
RUN049_VERDICT_UNSAFE = "CURSOR_ACP_UNSAFE_FOR_PROPOSAL_ONLY"
RUN049_VERDICT_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"

# Every named condition PART H.38 requires to hold for PROMOTE. Each key maps
# to a plain bool the caller supplies in ``evidence`` -- this function only
# ever mechanically ANDs them together; it never re-derives or guesses at any
# of them from raw transcripts (that derivation belongs to the caller, close
# to the actual evidence).
RUN049_PROMOTE_CONDITIONS = (
    "run048_structured_call_passed_in_plan_mode",
    "both_new_direct_probes_pass",
    "repair_rehearsal_completes",
    "plan_mode_confirmed_before_every_prompt",
    "zero_tool_or_write_events",
    "zero_pre_execution_workspace_mutation",
    "all_terminal_responses_unambiguous",
    "exactly_once_behavior_passes",
    "no_uncertain_completion",
    "no_transport_fallback",
    "no_cleanup_failure",
    "zero_orphan_processes",
    "transport_health_healthy",
    "deterministic_non_transport_fixes_pass",
    "full_admissible_suite_passes",
)


@dataclass
class CursorAcpPromotionDecision:
    """Durable RUN_049 PART H.36 promotion-gate record.

    A mechanical AND of named, independently-supplied evidence booleans --
    never a re-derivation from raw transcripts, and never weakened to force a
    particular verdict. ``confidence``/``limitations`` document that this is
    never a statistical long-run reliability proof (PART H.39), regardless of
    which way the verdict falls.
    """

    run048_evidence_refs: list[str]
    plan_mode_probe_results: dict[str, Any]
    repair_rehearsal_result: dict[str, Any]
    proposal_only_safety_result: dict[str, Any]
    workspace_mutation_result: dict[str, Any]
    tool_event_result: dict[str, Any]
    exactly_once_result: dict[str, Any]
    cleanup_result: dict[str, Any]
    transport_health_result: dict[str, Any]
    regression_suite_result: dict[str, Any]
    verdict: str
    failed_conditions: list[str]
    confidence: str
    limitations: list[str]
    generated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def compute_run049_promotion_decision(
    evidence: dict[str, bool],
    *,
    run048_evidence_refs: list[str],
    plan_mode_probe_results: dict[str, Any],
    repair_rehearsal_result: dict[str, Any],
    proposal_only_safety_result: dict[str, Any],
    workspace_mutation_result: dict[str, Any],
    tool_event_result: dict[str, Any],
    exactly_once_result: dict[str, Any],
    cleanup_result: dict[str, Any],
    transport_health_result: dict[str, Any],
    regression_suite_result: dict[str, Any],
    limitations: list[str] | None = None,
) -> CursorAcpPromotionDecision:
    """Compute the RUN_049 PART H promotion decision from independently-supplied evidence.

    ``evidence`` must supply every key in ``RUN049_PROMOTE_CONDITIONS``.
    PROMOTE only when every one is True. A confirmed proposal-only violation
    that was nonetheless caught cleanly (zero mutation, cleanup proven) is
    ``KEEP`` (viable but not yet promotable), never silently reclassified as
    ``PROMOTE`` -- and never ``UNSAFE`` either, since nothing was actually
    unsafe: the invariant held. ``UNSAFE`` is reserved for evidence of an
    actual uncaught mutation or a cleanup failure the circuit breaker did not
    catch.
    """
    failed = [cond for cond in RUN049_PROMOTE_CONDITIONS if not evidence.get(cond)]
    unsafe_signal = bool(
        (workspace_mutation_result or {}).get("any_pre_execution_mutation")
        or (cleanup_result or {}).get("any_unproven_cleanup")
    )
    if not failed:
        verdict = RUN049_VERDICT_PROMOTE
    elif unsafe_signal:
        verdict = RUN049_VERDICT_UNSAFE
    elif evidence.get("plan_mode_confirmed_before_every_prompt") and evidence.get(
        "zero_pre_execution_workspace_mutation"
    ):
        verdict = RUN049_VERDICT_KEEP
    else:
        verdict = RUN049_VERDICT_INSUFFICIENT

    return CursorAcpPromotionDecision(
        run048_evidence_refs=list(run048_evidence_refs),
        plan_mode_probe_results=dict(plan_mode_probe_results),
        repair_rehearsal_result=dict(repair_rehearsal_result),
        proposal_only_safety_result=dict(proposal_only_safety_result),
        workspace_mutation_result=dict(workspace_mutation_result),
        tool_event_result=dict(tool_event_result),
        exactly_once_result=dict(exactly_once_result),
        cleanup_result=dict(cleanup_result),
        transport_health_result=dict(transport_health_result),
        regression_suite_result=dict(regression_suite_result),
        verdict=verdict,
        failed_conditions=failed,
        confidence=(
            "n=3 real serial calls this slice (plus n=4 from RUN_048); "
            "not a statistical long-run reliability estimate"
        ),
        limitations=list(
            limitations
            or [
                "Evidence count is not a statistical long-run reliability proof (PART H.39).",
                "Promotion, if granted, would mean ACP is the safest/most observable "
                "available Cursor transport -- not that failure probability has been "
                "precisely measured.",
            ]
        ),
    )


def classify_response_deviation(*, expected: str, actual: str, terminal_ok: bool) -> str:
    """Distinguish a model *formatting* deviation from a *protocol* failure
    (PART D.11). A usable terminal response with imperfect text is NOT a protocol
    failure."""
    if not terminal_ok:
        return "protocol_failure"
    if actual.strip() == expected.strip():
        return "exact_match"
    if expected.strip() in actual:
        return "formatting_deviation"
    return "content_deviation"


# ---------------------------------------------------------------------------
# Transcript-recording process wrapper (managed-process consumer contract)
# ---------------------------------------------------------------------------


class TranscriptRecordingProcess:
    """Wraps a real ``ManagedProcess`` and records a sanitized JSON-RPC transcript
    of everything the ACP client sends and receives."""

    def __init__(self, inner: ManagedProcess) -> None:
        self._inner = inner
        self.transcript: list[dict[str, Any]] = []
        self._t0 = time.perf_counter()

    def _record(self, direction: str, payload: Any) -> None:
        self.transcript.append(
            {
                "at_ms": round((time.perf_counter() - self._t0) * 1000, 1),
                "direction": direction,
                "message": payload,
            }
        )

    # -- consumer contract --------------------------------------------------
    @property
    def pid(self):
        return self._inner.pid

    def start(self) -> None:
        self._t0 = time.perf_counter()
        self._inner.start()

    def send_stdin(self, text: str) -> None:
        for line in text.splitlines():
            if line.strip():
                self._record("client_to_server", sanitize_json_line(line))
        self._inner.send_stdin(text)

    def close_stdin(self) -> None:
        self._inner.close_stdin()

    def read_stdout_line(self, timeout):
        line = self._inner.read_stdout_line(timeout)
        if line is None:
            self._record("server_to_client", {"_eof": True})
        elif line == READ_TIMEOUT:
            pass
        elif line.strip():
            self._record("server_to_client", sanitize_json_line(line))
        return line

    def poll(self):
        return self._inner.poll()

    def wait(self, timeout=None):
        return self._inner.wait(timeout=timeout)

    def terminate(self, *, reason: str = "cancelled"):
        return self._inner.terminate(reason=reason)

    def finish(self, *, reason: str = "completed") -> None:
        self._inner.finish(reason=reason)

    def result(self):
        return self._inner.result()

    def captured_stderr(self) -> str:
        return self._inner.captured_stderr()


# ---------------------------------------------------------------------------
# Per-call record (PART B.6)
# ---------------------------------------------------------------------------


@dataclass
class ProbeCallRecord:
    label: str
    transport: str
    backend_id: str
    model_selector: str
    instruction_id: str
    instruction_sha256: str
    request_id: str | None = None
    session_id: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    handshake_ms: float | None = None
    accepted_at: str | None = None
    first_progress_at: str | None = None
    last_progress_at: str | None = None
    total_duration_ms: float | None = None
    progress_event_count: int = 0
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    response_bytes: int = 0
    response_sha256: str | None = None
    response_preview: str | None = None
    exit_code: int | None = None
    invoke_status: str | None = None
    acp_invocation_state: str | None = None
    parse_status: str | None = None
    structured_operation_count: int = 0
    cleanup_complete: bool | None = None
    remaining_process_ids: list[int] = field(default_factory=list)
    transport_health_state: str | None = None
    transcript: list[dict[str, Any]] = field(default_factory=list)
    error_message: str | None = None
    # RUN_049 PART D.25 -- target-workspace mutation audit (proposal-only gate).
    workspace_paths_added: list[str] = field(default_factory=list)
    workspace_paths_removed: list[str] = field(default_factory=list)
    workspace_paths_modified: list[str] = field(default_factory=list)
    workspace_mutation_clean: bool | None = None
    # RUN_049 PART D.24 -- tool-call / policy-violation audit.
    tool_event_count: int = 0
    policy_violation_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class AcpRealProbeHarness:
    def __init__(self, *, max_model_calls: int = DEFAULT_MAX_MODEL_CALLS) -> None:
        self.max_model_calls = max_model_calls
        self.used_model_calls = 0
        self._running = False
        self.calls: list[ProbeCallRecord] = []
        self.handshake_record: dict[str, Any] | None = None
        self.preflight: dict[str, Any] = {}
        # shared health per transport so cross-call transitions are visible
        self._acp_health = TransportHealth(backend_id=BACKEND_ID_CURSOR_ACP)
        self._oneshot_health = TransportHealth(backend_id=BACKEND_ID_CURSOR_ONESHOT)

    # -- guards -------------------------------------------------------------
    def _begin(self, *, consumes_budget: bool) -> None:
        if self._running:
            raise ProbeAlreadyRunning("Probes must run serially.")
        if consumes_budget and self.used_model_calls >= self.max_model_calls:
            raise ModelBudgetExceeded(
                f"Model budget exhausted ({self.used_model_calls}/{self.max_model_calls})."
            )
        self._running = True

    def _end(self, *, consumes_budget: bool) -> None:
        self._running = False
        if consumes_budget:
            self.used_model_calls += 1

    # -- preflight (free) ---------------------------------------------------
    def record_preflight(self, extra: dict[str, Any]) -> dict[str, Any]:
        acp_cfg = CursorAcpConfig.from_env()
        self.preflight = {
            "generated_at": _now_iso(),
            "resolved_command": acp_cfg.resolved_command(),
            "acp_timeouts": acp_cfg.timeouts.to_dict(),
            "default_transport": "oneshot",
            "model_selector": "cursor-agent default (unpinned)",
            **extra,
        }
        return self.preflight

    def run_non_model_handshake(self, *, workspace: str, timeout: float = 15.0) -> dict[str, Any]:
        """Free (non-model) initialize handshake + cleanup verification."""
        self._begin(consumes_budget=False)
        try:
            cfg = CursorAcpConfig.from_env()
            argv = cfg.acp_argv()
            env, _diag = build_cursor_agent_safe_environment()
            record: dict[str, Any] = {"started_at": _now_iso(), "command": cfg.resolved_command()}
            if not argv or env is None:
                record.update({"handshake_ok": False, "error": "argv/env unavailable"})
                self.handshake_record = record
                return record
            mp = ManagedProcess(argv, cwd=workspace, env=env, want_stdin=True,
                                grace_seconds=3.0, force_seconds=3.0)
            t0 = time.perf_counter()
            mp.start()
            pid = mp.pid
            descendants = list(mp._observed_descendants)
            conn = AcpConnection(mp)
            conn.send(ACP_METHOD_INITIALIZE, {"protocolVersion": 1, "clientCapabilities": {}}, request_id=1)
            protocol_version = None
            matched = False
            deadline = time.perf_counter() + timeout
            while time.perf_counter() < deadline:
                kind, payload = conn.read_message(deadline - time.perf_counter())
                if kind == MSG_JSON and payload.get("id") == 1:
                    matched = True
                    protocol_version = _extract_protocol_version(payload.get("result") or {})
                    record["capabilities"] = sanitize_json_line(json.dumps(payload.get("result") or {}))
                    break
                if kind in ("eof", "timeout"):
                    break
            handshake_ms = round((time.perf_counter() - t0) * 1000, 1)
            result = mp.terminate(reason="cancelled")
            time.sleep(0.3)
            lingering = [p for p in [pid, *descendants] if pid_alive(p)]
            record.update(
                {
                    "handshake_ok": matched,
                    "protocol_version": protocol_version,
                    "handshake_ms": handshake_ms,
                    "platform_strategy": result.platform_strategy,
                    "cleanup_complete": result.cleanup_complete,
                    "remaining_process_ids": result.remaining_process_ids,
                    "lingering_owned_pids": lingering,
                    "process_exited": mp.poll() is not None,
                }
            )
            self.handshake_record = record
            return record
        finally:
            self._end(consumes_budget=False)

    # -- real model probes --------------------------------------------------
    def run_acp_probe(self, *, label, instruction, workspace, timeouts: AcpTimeouts | None = None,
                      process_factory=None) -> ProbeCallRecord:
        """Run one real ACP model probe. ``process_factory`` is injectable so the
        deterministic RUN_048 tests drive the whole harness path with a fake ACP
        server (no real subprocess, no model call)."""
        self._begin(consumes_budget=True)
        try:
            instruction_id = f"run048_{label}_{uuid.uuid4().hex[:8]}"
            recorders: list[TranscriptRecordingProcess] = []

            def default_factory(argv, cwd, env):
                inner = ManagedProcess(argv, cwd=cwd, env=env, want_stdin=True)
                rec = TranscriptRecordingProcess(inner)
                recorders.append(rec)
                return rec

            factory = process_factory or default_factory
            backend = CursorAcpBackend(
                process_factory=factory,
                health=self._acp_health,
                timeouts=timeouts or AcpTimeouts(
                    handshake_seconds=20.0, request_acceptance_seconds=60.0,
                    idle_no_progress_seconds=90.0, absolute_request_seconds=180.0,
                    cancellation_seconds=8.0, cleanup_seconds=8.0,
                ),
            )
            request = AgentInvocationRequest(
                instruction_text=instruction, session_id="run048", turn_number=1,
                instruction_id=instruction_id,
                target_workspace_path=str(Path(workspace) / "target"),
                agent_workspace_path=str(Path(workspace) / "agent"),
            )
            target_ws = Path(workspace) / "target"
            target_ws.mkdir(parents=True, exist_ok=True)
            (Path(workspace) / "agent").mkdir(parents=True, exist_ok=True)
            snapshot_before = snapshot_workspace(target_ws)
            t0 = time.perf_counter()
            result = backend.invoke(request)
            total_ms = round((time.perf_counter() - t0) * 1000, 1)
            snapshot_after = snapshot_workspace(target_ws)
            transcript = recorders[0].transcript if recorders else []
            return self._finalize_record(
                label, BACKEND_ID_CURSOR_ACP, result, instruction, instruction_id,
                total_ms, transcript, self._acp_health,
                workspace_diff=diff_workspace_snapshots(snapshot_before, snapshot_after),
            )
        finally:
            self._end(consumes_budget=True)

    def run_oneshot_probe(self, *, label, instruction, workspace) -> ProbeCallRecord:
        self._begin(consumes_budget=True)
        try:
            instruction_id = f"run048_{label}_{uuid.uuid4().hex[:8]}"
            config = CursorCliConfig.cursor_agent_preset()
            backend = CursorCliAgentBackend(config=config)  # managed path (no runner)
            (Path(workspace) / "target").mkdir(parents=True, exist_ok=True)
            (Path(workspace) / "agent").mkdir(parents=True, exist_ok=True)
            request = AgentInvocationRequest(
                instruction_text=instruction, session_id="run048", turn_number=1,
                instruction_id=instruction_id,
                target_workspace_path=str(Path(workspace) / "target"),
                agent_workspace_path=str(Path(workspace) / "agent"),
                timeout_seconds=180.0,
            )
            t0 = time.perf_counter()
            result = backend.invoke(request)
            total_ms = round((time.perf_counter() - t0) * 1000, 1)
            return self._finalize_record(
                label, BACKEND_ID_CURSOR_ONESHOT, result, instruction, instruction_id,
                total_ms, [], self._oneshot_health,
            )
        finally:
            self._end(consumes_budget=True)

    # -- shared finalization ------------------------------------------------
    def _finalize_record(self, label, backend_id, result, instruction, instruction_id,
                         total_ms, transcript, health, *, workspace_diff: dict[str, Any] | None = None) -> ProbeCallRecord:
        response_text = result.response_text or ""
        blocks = extract_structured_operation_blocks(response_text) if response_text else []
        parse_status = "usable" if response_text.strip() else "empty"
        telemetry = result.acp_telemetry or {}
        mpr = result.managed_process_result or {}
        progress_events = telemetry.get("progress_events") or []
        tool_event_count = sum(1 for e in progress_events if e.get("event_type") == "tool_call")
        diff = workspace_diff or {}
        rec = ProbeCallRecord(
            label=label,
            transport=backend_id,
            backend_id=backend_id,
            model_selector="cursor-agent default (unpinned)",
            instruction_id=instruction_id,
            instruction_sha256=_sha256(instruction),
            request_id=result.acp_request_id,
            session_id=result.acp_session_id,
            started_at=result.started_at,
            completed_at=result.completed_at,
            handshake_ms=telemetry.get("handshake_duration_ms"),
            accepted_at=telemetry.get("accepted_at"),
            first_progress_at=telemetry.get("first_progress_at"),
            last_progress_at=telemetry.get("last_progress_at"),
            total_duration_ms=total_ms,
            progress_event_count=telemetry.get("progress_event_count", 0),
            stdout_bytes=len((result.raw_stdout or "").encode("utf-8")),
            stderr_bytes=len((result.raw_stderr or "").encode("utf-8")),
            response_bytes=len(response_text.encode("utf-8")),
            response_sha256=_sha256(response_text) if response_text else None,
            response_preview=sanitize_text(response_text) if response_text else None,
            exit_code=result.exit_code,
            invoke_status=result.status,
            acp_invocation_state=result.acp_invocation_state,
            parse_status=parse_status,
            structured_operation_count=len(blocks),
            cleanup_complete=mpr.get("cleanup_complete"),
            remaining_process_ids=mpr.get("remaining_process_ids", []),
            transport_health_state=health.state,
            transcript=transcript,
            error_message=result.error_message,
            workspace_paths_added=list(diff.get("paths_added") or []),
            workspace_paths_removed=list(diff.get("paths_removed") or []),
            workspace_paths_modified=list(diff.get("paths_modified") or []),
            workspace_mutation_clean=diff.get("clean") if workspace_diff is not None else None,
            tool_event_count=tool_event_count,
            policy_violation_reason=telemetry.get("policy_violation_reason"),
        )
        self.calls.append(rec)
        return rec

    # -- reporting ----------------------------------------------------------
    def to_report(self) -> dict[str, Any]:
        return {
            "generated_at": _now_iso(),
            "budget": {"max_model_calls": self.max_model_calls, "used_model_calls": self.used_model_calls},
            "preflight": self.preflight,
            "handshake": self.handshake_record,
            "calls": [c.to_dict() for c in self.calls],
        }

    def write_report(self, path: str | Path) -> Path:
        out = Path(str(path))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(self.to_report(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return out


__all__ = [
    "DEFAULT_MAX_MODEL_CALLS",
    "ModelBudgetExceeded",
    "ProbeAlreadyRunning",
    "AcpRealProbeHarness",
    "ProbeCallRecord",
    "TranscriptRecordingProcess",
    "sanitize_text",
    "sanitize_json_line",
    "compute_default_transport_verdict",
    "classify_response_deviation",
    "VERDICT_PROMOTE",
    "VERDICT_KEEP",
    "VERDICT_NOT_USABLE",
    "VERDICT_INSUFFICIENT",
    "snapshot_workspace",
    "diff_workspace_snapshots",
    "DEFAULT_WORKSPACE_SNAPSHOT_EXCLUDE_PREFIXES",
    "RUN049_VERDICT_PROMOTE",
    "RUN049_VERDICT_KEEP",
    "RUN049_VERDICT_UNSAFE",
    "RUN049_VERDICT_INSUFFICIENT",
    "RUN049_PROMOTE_CONDITIONS",
    "CursorAcpPromotionDecision",
    "compute_run049_promotion_decision",
]
