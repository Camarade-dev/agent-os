"""Bounded browser-runtime verification for the isolated V0 line (Slice 5A).

This is a thin, bounded wrapper over the existing Chromium/CDP browser-runtime
machinery (:mod:`admissible.browser_runtime.chromium_provider`,
:mod:`admissible.browser_runtime.runner`). It performs *exactly one*
deterministic browser verification attempt against a previously materialized,
governed V0 target and produces one durable, typed
:class:`V0RuntimeVerificationResult`.

It is deliberately narrow. The verifier:

* reads a persisted V0 :class:`~admissible.v0_controller.state.SessionState`;
* refuses to run unless the strict runtime entry conditions hold;
* hashes the target tree before and after;
* runs one bounded plan (navigate, wait for load, observe, screenshot);
* collects a serialized DOM document snapshot;
* derives a single verdict (``PASS`` / ``FAIL`` / ``INCONCLUSIVE``); and
* returns a fully typed, round-trippable result.

It **never** modifies the target, invokes a model provider, executes a repair,
retries, navigates off loopback, allows successful external network access,
reuses a personal profile, or converts uncertainty into success. Persisting the
result and enforcing exactly-one-attempt is the job of
:mod:`admissible.browser_runtime.v0_runtime_store`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol

from admissible.browser_runtime.models import (
    BrowserRuntimeVerificationPlan,
    new_id,
    now_iso,
)
from admissible.browser_runtime import limits as _limits
from admissible.v0_controller.state import Phase, SessionState

V0_RUNTIME_SCHEMA_VERSION = "admissible_v0_runtime_verification_v1"

# The single fixed runtime entry point for a governed web target.
RUNTIME_ENTRY_POINT = "index.html"

# Bounded ceilings for the one attempt. Each is at or under the shared absolute
# ceiling in :mod:`admissible.browser_runtime.limits`; none may be raised here.
MAX_RUNTIME_DURATION_MS = 20_000
MAX_LOAD_WAIT_MS = 10_000
SETTLE_WAIT_MS = 400


class V0RuntimeVerdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"


class RuntimeReason(str, Enum):
    """Explicit reason codes attached to every verdict."""

    # PASS
    RUNTIME_PASS = "runtime_pass"
    # Entry-gate refusals (INCONCLUSIVE, no browser launched)
    ENTRY_NOT_AWAITING_HUMAN = "entry_not_awaiting_human"
    ENTRY_STRUCTURAL_NOT_PASSED = "entry_structural_not_passed"
    ENTRY_MANDATORY_PATH_MISSING = "entry_mandatory_path_missing"
    ENTRY_ENTRY_POINT_MISSING = "entry_entry_point_missing"
    ENTRY_RECEIPTS_NOT_DURABLE = "entry_receipts_not_durable"
    ENTRY_INVOCATION_IN_FLIGHT = "entry_invocation_in_flight"
    ENTRY_TARGET_UNREADABLE = "entry_target_unreadable"
    # Runtime INCONCLUSIVE
    BROWSER_UNAVAILABLE = "browser_runtime_unavailable"
    PROVIDER_ERROR = "provider_error"
    NAVIGATION_NOT_REACHED = "navigation_not_reached"
    LOAD_TIMED_OUT = "load_timed_out"
    MISSING_SCREENSHOT_EVIDENCE = "missing_screenshot_evidence"
    MISSING_DOM_EVIDENCE = "missing_dom_evidence"
    CLEANUP_UNCERTAIN = "cleanup_uncertain"
    # Runtime FAIL (positively observed contract violation)
    UNCAUGHT_EXCEPTION = "uncaught_javascript_exception"
    EXTERNAL_REQUEST_ATTEMPTED = "external_network_request_attempted"
    TARGET_TREE_MUTATED = "target_tree_mutated"


# --------------------------------------------------------------------------
# Provider protocol (duck-typed; the real provider is ChromiumCdpRuntimeProvider)
# --------------------------------------------------------------------------
class RuntimeProvider(Protocol):
    def detect_capability(self) -> Any: ...
    def create_session(self, plan: BrowserRuntimeVerificationPlan) -> Any: ...
    def execute_step(self, session: Any, step: dict[str, Any]) -> dict[str, Any]: ...
    def collect_evidence(self, session: Any) -> dict[str, Any]: ...
    def close_session(self, session: Any) -> dict[str, Any]: ...


# --------------------------------------------------------------------------
# Deterministic target tree hashing
# --------------------------------------------------------------------------
def hash_target_tree(target_workspace: str | Path) -> dict[str, Any]:
    """Return a deterministic hash of every file under the target workspace.

    The digest is over a canonical, sorted ``path\x00sha256\x00size`` manifest,
    so the tree hash is stable across platforms and independent of directory
    iteration order. Symlinks are recorded as such and never followed.
    """

    root = Path(target_workspace)
    entries: list[tuple[str, str, int]] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        rel = path.relative_to(root).as_posix()
        data = path.read_bytes()
        entries.append((rel, hashlib.sha256(data).hexdigest(), len(data)))
    manifest = "\n".join(f"{rel}\x00{sha}\x00{size}" for rel, sha, size in entries)
    tree_sha256 = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
    return {
        "tree_sha256": tree_sha256,
        "file_count": len(entries),
        "files": [{"path": rel, "sha256": sha, "byte_count": size} for rel, sha, size in entries],
    }


# --------------------------------------------------------------------------
# Entry conditions
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class EntryDecision:
    permitted: bool
    reason: RuntimeReason | None
    detail: str


def evaluate_entry_conditions(state: SessionState, target_workspace: str | Path) -> EntryDecision:
    """Decide whether a bounded runtime verification may begin.

    A refusal is never a failure of the target: it yields ``INCONCLUSIVE`` with
    an explicit reason and no browser is ever launched.
    """

    if state.phase != Phase.AWAITING_HUMAN:
        return EntryDecision(False, RuntimeReason.ENTRY_NOT_AWAITING_HUMAN, f"phase is {state.phase.value}")
    sv = state.structural_verification
    if sv is None or not sv.passed:
        return EntryDecision(False, RuntimeReason.ENTRY_STRUCTURAL_NOT_PASSED, "structural verification not passed")
    if RUNTIME_ENTRY_POINT not in state.mandatory_paths:
        return EntryDecision(
            False, RuntimeReason.ENTRY_ENTRY_POINT_MISSING, f"{RUNTIME_ENTRY_POINT} is not a mandatory path"
        )
    # No provider invocation may be in flight.
    inv = state.current_invocation
    if inv is not None and inv.lifecycle.value in ("prepared", "dispatched"):
        return EntryDecision(False, RuntimeReason.ENTRY_INVOCATION_IN_FLIGHT, f"invocation {inv.lifecycle.value}")
    # Governed execution receipts must be durable for every mandatory path.
    if not state.execution_receipt_history:
        return EntryDecision(False, RuntimeReason.ENTRY_RECEIPTS_NOT_DURABLE, "no durable execution receipts")
    if state.remaining_paths():
        return EntryDecision(
            False, RuntimeReason.ENTRY_MANDATORY_PATH_MISSING, f"missing evidence for {state.remaining_paths()}"
        )
    root = Path(target_workspace)
    if not root.is_dir():
        return EntryDecision(False, RuntimeReason.ENTRY_TARGET_UNREADABLE, "target workspace is not a directory")
    for rel in state.mandatory_paths:
        candidate = root / Path(rel)
        if not candidate.is_file():
            return EntryDecision(
                False, RuntimeReason.ENTRY_MANDATORY_PATH_MISSING, f"mandatory path not present on disk: {rel}"
            )
    entry = root / RUNTIME_ENTRY_POINT
    if not entry.is_file():
        return EntryDecision(False, RuntimeReason.ENTRY_ENTRY_POINT_MISSING, f"{RUNTIME_ENTRY_POINT} not present on disk")
    return EntryDecision(True, None, "entry conditions satisfied")


# --------------------------------------------------------------------------
# Fixed bounded plan
# --------------------------------------------------------------------------
def build_runtime_plan(target_workspace: str | Path, *, mission_contract_sha256: str = "") -> BrowserRuntimeVerificationPlan:
    """One fixed, minimal, allowlisted plan. No app-specific assertions."""

    steps: list[dict[str, Any]] = [
        {"type": "navigate_local", "path": RUNTIME_ENTRY_POINT},
        {"type": "wait_for_load", "timeout_ms": MAX_LOAD_WAIT_MS},
        {"type": "wait_bounded", "duration_ms": SETTLE_WAIT_MS},
        {"type": "assert_no_page_exceptions"},
        {"type": "assert_no_external_requests"},
        {"type": "capture_screenshot", "name": "runtime_verification"},
    ]
    return BrowserRuntimeVerificationPlan(
        plan_version=_limits.BROWSER_RUNTIME_PLAN_VERSION,
        mission_contract_sha256=mission_contract_sha256,
        workspace_root=str(Path(target_workspace)),
        entrypoint_path=RUNTIME_ENTRY_POINT,
        entrypoint_query="",
        target_origin_policy="loopback_only",
        debug_interface=None,
        max_duration_ms=MAX_RUNTIME_DURATION_MS,
        max_steps=len(steps) + 2,
        max_input_events=0,
        max_snapshots=0,
        max_screenshots=1,
        max_console_entries=_limits.DEFAULT_MAX_CONSOLE_ENTRIES,
        max_network_events=_limits.DEFAULT_MAX_NETWORK_EVENTS,
        criteria=[],
        steps=steps,
    )


# --------------------------------------------------------------------------
# Result schema
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class V0RuntimeVerificationResult:
    """The complete, durable, typed evidence of one bounded verification attempt."""

    schema_version: str
    session_id: str
    attempt_id: str
    entry_point: str
    verdict: str
    reason_codes: tuple[str, ...]
    started_at: str
    completed_at: str
    # Bounds actually enforced.
    bounds: Mapping[str, int]
    # Runtime observations.
    loopback_origin: str | None
    final_url: str | None
    navigation_ok: bool
    dom_content_loaded: bool
    page_loaded: bool
    ready_state: str | None
    uncaught_exceptions: tuple[Mapping[str, Any], ...]
    console_errors: tuple[Mapping[str, Any], ...]
    external_request_attempts: tuple[Mapping[str, Any], ...]
    # Browser identity.
    browser_available: bool
    browser_executable: str | None
    browser_version: str | None
    provider_id: str
    provider_error: str | None
    # Serialized document + screenshot references.
    dom_document_sha256: str | None
    dom_document_byte_count: int | None
    screenshot_sha256: str | None
    screenshot_byte_count: int | None
    # Termination.
    browser_exit: Mapping[str, Any]
    server_exit: Mapping[str, Any]
    orphan_processes: tuple[int, ...]
    termination_reason: str
    # Target integrity.
    tree_hash_before: str
    tree_hash_after: str
    tree_byte_identical: bool
    # Invariants of this slice.
    provider_invoked: bool = False
    repair_attempted: bool = False
    retry_attempted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "attempt_id": self.attempt_id,
            "entry_point": self.entry_point,
            "verdict": self.verdict,
            "reason_codes": list(self.reason_codes),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "bounds": dict(self.bounds),
            "loopback_origin": self.loopback_origin,
            "final_url": self.final_url,
            "navigation_ok": self.navigation_ok,
            "dom_content_loaded": self.dom_content_loaded,
            "page_loaded": self.page_loaded,
            "ready_state": self.ready_state,
            "uncaught_exceptions": [dict(e) for e in self.uncaught_exceptions],
            "console_errors": [dict(e) for e in self.console_errors],
            "external_request_attempts": [dict(e) for e in self.external_request_attempts],
            "browser_available": self.browser_available,
            "browser_executable": self.browser_executable,
            "browser_version": self.browser_version,
            "provider_id": self.provider_id,
            "provider_error": self.provider_error,
            "dom_document_sha256": self.dom_document_sha256,
            "dom_document_byte_count": self.dom_document_byte_count,
            "screenshot_sha256": self.screenshot_sha256,
            "screenshot_byte_count": self.screenshot_byte_count,
            "browser_exit": dict(self.browser_exit),
            "server_exit": dict(self.server_exit),
            "orphan_processes": list(self.orphan_processes),
            "termination_reason": self.termination_reason,
            "tree_hash_before": self.tree_hash_before,
            "tree_hash_after": self.tree_hash_after,
            "tree_byte_identical": self.tree_byte_identical,
            "provider_invoked": self.provider_invoked,
            "repair_attempted": self.repair_attempted,
            "retry_attempted": self.retry_attempted,
        }

    def canonical_bytes(self) -> bytes:
        import json

        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "V0RuntimeVerificationResult":
        if data.get("schema_version") != V0_RUNTIME_SCHEMA_VERSION:
            raise ValueError("unsupported V0 runtime verification schema")
        return cls(
            schema_version=data["schema_version"],
            session_id=data["session_id"],
            attempt_id=data["attempt_id"],
            entry_point=data["entry_point"],
            verdict=data["verdict"],
            reason_codes=tuple(data["reason_codes"]),
            started_at=data["started_at"],
            completed_at=data["completed_at"],
            bounds=dict(data["bounds"]),
            loopback_origin=data["loopback_origin"],
            final_url=data["final_url"],
            navigation_ok=data["navigation_ok"],
            dom_content_loaded=data["dom_content_loaded"],
            page_loaded=data["page_loaded"],
            ready_state=data["ready_state"],
            uncaught_exceptions=tuple(dict(e) for e in data["uncaught_exceptions"]),
            console_errors=tuple(dict(e) for e in data["console_errors"]),
            external_request_attempts=tuple(dict(e) for e in data["external_request_attempts"]),
            browser_available=data["browser_available"],
            browser_executable=data["browser_executable"],
            browser_version=data["browser_version"],
            provider_id=data["provider_id"],
            provider_error=data["provider_error"],
            dom_document_sha256=data["dom_document_sha256"],
            dom_document_byte_count=data["dom_document_byte_count"],
            screenshot_sha256=data["screenshot_sha256"],
            screenshot_byte_count=data["screenshot_byte_count"],
            browser_exit=dict(data["browser_exit"]),
            server_exit=dict(data["server_exit"]),
            orphan_processes=tuple(data["orphan_processes"]),
            termination_reason=data["termination_reason"],
            tree_hash_before=data["tree_hash_before"],
            tree_hash_after=data["tree_hash_after"],
            tree_byte_identical=data["tree_byte_identical"],
            provider_invoked=data["provider_invoked"],
            repair_attempted=data["repair_attempted"],
            retry_attempted=data["retry_attempted"],
        )


# --------------------------------------------------------------------------
# Verdict derivation (pure)
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class _Observation:
    """The bounded facts a verdict is derived from."""

    browser_available: bool
    provider_error: str | None
    navigation_ok: bool
    page_loaded: bool
    uncaught_exceptions: int
    external_attempts: int
    tree_byte_identical: bool
    has_screenshot: bool
    has_dom: bool
    cleanup_clean: bool


def derive_verdict(obs: _Observation) -> tuple[V0RuntimeVerdict, tuple[RuntimeReason, ...]]:
    """Map bounded observations to a single verdict and explicit reason codes.

    Precedence is deliberate. Anything that prevents a *justified* pass or fail
    is ``INCONCLUSIVE``; a positively observed violation is ``FAIL``; only a
    fully clean, fully evidenced, byte-identical run is ``PASS``. Uncertainty is
    never converted into success.
    """

    # 1. Could not run a justified attempt at all -> INCONCLUSIVE.
    if not obs.browser_available:
        return V0RuntimeVerdict.INCONCLUSIVE, (RuntimeReason.BROWSER_UNAVAILABLE,)
    if obs.provider_error:
        return V0RuntimeVerdict.INCONCLUSIVE, (RuntimeReason.PROVIDER_ERROR,)
    if not obs.navigation_ok:
        return V0RuntimeVerdict.INCONCLUSIVE, (RuntimeReason.NAVIGATION_NOT_REACHED,)
    if not obs.page_loaded:
        return V0RuntimeVerdict.INCONCLUSIVE, (RuntimeReason.LOAD_TIMED_OUT,)

    # 2. Positively observed contract violations -> FAIL.
    fail_reasons: list[RuntimeReason] = []
    if not obs.tree_byte_identical:
        fail_reasons.append(RuntimeReason.TARGET_TREE_MUTATED)
    if obs.uncaught_exceptions > 0:
        fail_reasons.append(RuntimeReason.UNCAUGHT_EXCEPTION)
    if obs.external_attempts > 0:
        fail_reasons.append(RuntimeReason.EXTERNAL_REQUEST_ATTEMPTED)
    if fail_reasons:
        return V0RuntimeVerdict.FAIL, tuple(fail_reasons)

    # 3. Missing mandatory evidence or cleanup uncertainty -> INCONCLUSIVE.
    inconclusive_reasons: list[RuntimeReason] = []
    if not obs.has_screenshot:
        inconclusive_reasons.append(RuntimeReason.MISSING_SCREENSHOT_EVIDENCE)
    if not obs.has_dom:
        inconclusive_reasons.append(RuntimeReason.MISSING_DOM_EVIDENCE)
    if not obs.cleanup_clean:
        inconclusive_reasons.append(RuntimeReason.CLEANUP_UNCERTAIN)
    if inconclusive_reasons:
        return V0RuntimeVerdict.INCONCLUSIVE, tuple(inconclusive_reasons)

    # 4. Fully clean, fully evidenced, byte-identical -> PASS.
    return V0RuntimeVerdict.PASS, (RuntimeReason.RUNTIME_PASS,)


# --------------------------------------------------------------------------
# The bounded driver
# --------------------------------------------------------------------------
@dataclass
class RuntimeVerificationRun:
    """The result plus the (never-serialized) raw screenshot/DOM blobs."""

    result: V0RuntimeVerificationResult
    screenshot_blob: bytes | None = None
    dom_document_bytes: bytes | None = None


def _cleanup_is_clean(cleanup: Mapping[str, Any]) -> bool:
    return (
        bool(cleanup.get("browser_process_terminated"))
        and bool(cleanup.get("http_server_stopped"))
        and bool(cleanup.get("temporary_profile_removed"))
        and not list(cleanup.get("orphan_processes") or [])
    )


def _entry_refusal_result(
    *,
    session_id: str,
    decision: EntryDecision,
    tree_hash_before: str,
    started_at: str,
) -> RuntimeVerificationRun:
    result = V0RuntimeVerificationResult(
        schema_version=V0_RUNTIME_SCHEMA_VERSION,
        session_id=session_id,
        attempt_id=new_id("v0_runtime_attempt"),
        entry_point=RUNTIME_ENTRY_POINT,
        verdict=V0RuntimeVerdict.INCONCLUSIVE.value,
        reason_codes=(decision.reason.value,) if decision.reason else (),
        started_at=started_at,
        completed_at=now_iso(),
        bounds={"max_duration_ms": MAX_RUNTIME_DURATION_MS, "max_load_wait_ms": MAX_LOAD_WAIT_MS},
        loopback_origin=None,
        final_url=None,
        navigation_ok=False,
        dom_content_loaded=False,
        page_loaded=False,
        ready_state=None,
        uncaught_exceptions=(),
        console_errors=(),
        external_request_attempts=(),
        browser_available=False,
        browser_executable=None,
        browser_version=None,
        provider_id="",
        provider_error=None,
        dom_document_sha256=None,
        dom_document_byte_count=None,
        screenshot_sha256=None,
        screenshot_byte_count=None,
        browser_exit={"reason": "browser_never_launched"},
        server_exit={"reason": "server_never_started"},
        orphan_processes=(),
        termination_reason="entry_conditions_refused",
        tree_hash_before=tree_hash_before,
        tree_hash_after=tree_hash_before,
        tree_byte_identical=True,
    )
    return RuntimeVerificationRun(result=result)


def run_bounded_runtime_verification(
    *,
    state: SessionState,
    target_workspace: str | Path,
    provider: RuntimeProvider,
) -> RuntimeVerificationRun:
    """Perform exactly one bounded runtime verification attempt.

    ``provider`` is injected (the real one is ``ChromiumCdpRuntimeProvider``)
    so tests can drive deterministic scenarios without a real browser. This
    function never invokes a model provider, never repairs, and never retries.
    """

    started_at = now_iso()
    target_workspace = Path(target_workspace)
    tree_before = hash_target_tree(target_workspace)
    tree_hash_before = tree_before["tree_sha256"]

    decision = evaluate_entry_conditions(state, target_workspace)
    if not decision.permitted:
        return _entry_refusal_result(
            session_id=state.session_id,
            decision=decision,
            tree_hash_before=tree_hash_before,
            started_at=started_at,
        )

    capability = provider.detect_capability()
    plan = build_runtime_plan(
        target_workspace, mission_contract_sha256=_contract_sha256(state)
    )

    if not getattr(capability, "available", False):
        tree_after = hash_target_tree(target_workspace)
        result = _assemble_result(
            state=state,
            started_at=started_at,
            capability=capability,
            collected={},
            cleanup={"reason": "browser_never_launched", "browser_process_terminated": False,
                     "http_server_stopped": False, "temporary_profile_removed": False, "orphan_processes": []},
            document=None,
            screenshot=None,
            provider_error=None,
            termination_reason="browser_capability_gap",
            tree_hash_before=tree_hash_before,
            tree_hash_after=tree_after["tree_sha256"],
        )
        return RuntimeVerificationRun(result=result)

    session = None
    provider_error: str | None = None
    document: dict[str, Any] | None = None
    collected: dict[str, Any] = {}
    cleanup: dict[str, Any] = {}
    termination_reason = "completed"
    try:
        session = provider.create_session(plan)
        for step in plan.steps:
            if session.elapsed_ms() >= plan.max_duration_ms:
                termination_reason = "duration_exceeded"
                break
            provider.execute_step(session, step)
        # Bounded, read-only serialized-document capture before teardown.
        capture = getattr(provider, "capture_document", None)
        if callable(capture):
            document = capture(session)
    except Exception as exc:  # noqa: BLE001 - always terminates cleanly, never propagates
        provider_error = f"{type(exc).__name__}: {exc}"
        termination_reason = "provider_error"
    finally:
        if session is not None:
            collected = provider.collect_evidence(session)
            cleanup = provider.close_session(session)

    screenshot = _first_screenshot(collected, session)
    tree_after = hash_target_tree(target_workspace)
    result = _assemble_result(
        state=state,
        started_at=started_at,
        capability=capability,
        collected=collected,
        cleanup=cleanup,
        document=document,
        screenshot=screenshot,
        provider_error=provider_error,
        termination_reason=termination_reason,
        tree_hash_before=tree_hash_before,
        tree_hash_after=tree_after["tree_sha256"],
    )
    return RuntimeVerificationRun(
        result=result,
        screenshot_blob=screenshot["blob"] if screenshot else None,
        dom_document_bytes=(document.get("outer_html", "").encode("utf-8") if document and document.get("captured") else None),
    )


def _contract_sha256(state: SessionState) -> str:
    import json

    payload = json.dumps(state.contract.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _first_screenshot(collected: Mapping[str, Any], session: Any) -> dict[str, Any] | None:
    shots = list(collected.get("screenshots") or [])
    if not shots:
        return None
    record = shots[0]
    blob = None
    blobs = getattr(session, "screenshot_blobs", None)
    if isinstance(blobs, Mapping):
        blob = blobs.get(record.get("screenshot_id"))
    return {"record": record, "blob": blob}


def _assemble_result(
    *,
    state: SessionState,
    started_at: str,
    capability: Any,
    collected: Mapping[str, Any],
    cleanup: Mapping[str, Any],
    document: Mapping[str, Any] | None,
    screenshot: Mapping[str, Any] | None,
    provider_error: str | None,
    termination_reason: str,
    tree_hash_before: str,
    tree_hash_after: str,
) -> V0RuntimeVerificationResult:
    page_load = dict(collected.get("page_load") or {})
    navigation_ok = bool(page_load.get("ok"))
    page_loaded = bool(collected.get("page_load")) and navigation_ok and termination_reason not in (
        "duration_exceeded",
        "provider_error",
    )
    # A load that fired at all is treated as loaded; a duration_exceeded run
    # that never fired the load event is not.
    if collected.get("page_load") is not None and page_load.get("loaded") is False:
        page_loaded = False
    exceptions = tuple(dict(e) for e in (collected.get("page_exceptions") or []))
    console_errors = tuple(
        dict(e) for e in (collected.get("console_entries") or []) if e.get("level") == "error"
    )
    external_attempts = tuple(dict(e) for e in (collected.get("external_request_attempts") or []))

    final_url = None
    ready_state = None
    dom_sha = None
    dom_bytes = None
    dom_present = False
    if document and document.get("captured"):
        dom_present = True
        html = document.get("outer_html", "")
        blob = html.encode("utf-8")
        dom_sha = hashlib.sha256(blob).hexdigest()
        dom_bytes = len(blob)
        final_url = document.get("final_url")
        ready_state = document.get("ready_state")
    if final_url is None:
        final_url = page_load.get("url")

    loopback_origin = _origin_of(final_url)
    dom_content_loaded = ready_state in ("interactive", "complete") if ready_state is not None else page_loaded

    screenshot_sha = None
    screenshot_bytes = None
    if screenshot and screenshot.get("record"):
        screenshot_sha = screenshot["record"].get("sha256")
        screenshot_bytes = screenshot["record"].get("byte_length")

    tree_identical = tree_hash_before == tree_hash_after

    obs = _Observation(
        browser_available=bool(getattr(capability, "available", False)),
        provider_error=provider_error,
        navigation_ok=navigation_ok,
        page_loaded=page_loaded,
        uncaught_exceptions=len(exceptions),
        external_attempts=len(external_attempts),
        tree_byte_identical=tree_identical,
        has_screenshot=screenshot_sha is not None,
        has_dom=dom_present,
        cleanup_clean=_cleanup_is_clean(cleanup),
    )
    verdict, reasons = derive_verdict(obs)

    return V0RuntimeVerificationResult(
        schema_version=V0_RUNTIME_SCHEMA_VERSION,
        session_id=state.session_id,
        attempt_id=new_id("v0_runtime_attempt"),
        entry_point=RUNTIME_ENTRY_POINT,
        verdict=verdict.value,
        reason_codes=tuple(r.value for r in reasons),
        started_at=started_at,
        completed_at=now_iso(),
        bounds={
            "max_duration_ms": MAX_RUNTIME_DURATION_MS,
            "max_load_wait_ms": MAX_LOAD_WAIT_MS,
            "settle_wait_ms": SETTLE_WAIT_MS,
        },
        loopback_origin=loopback_origin,
        final_url=final_url,
        navigation_ok=navigation_ok,
        dom_content_loaded=bool(dom_content_loaded),
        page_loaded=page_loaded,
        ready_state=ready_state,
        uncaught_exceptions=exceptions,
        console_errors=console_errors,
        external_request_attempts=external_attempts,
        browser_available=bool(getattr(capability, "available", False)),
        browser_executable=getattr(capability, "executable_path", None),
        browser_version=getattr(capability, "browser_version", None),
        provider_id=str(getattr(capability, "provider_id", "") or ""),
        provider_error=provider_error,
        dom_document_sha256=dom_sha,
        dom_document_byte_count=dom_bytes,
        screenshot_sha256=screenshot_sha,
        screenshot_byte_count=screenshot_bytes,
        browser_exit={
            "terminated": bool(cleanup.get("browser_process_terminated")),
            "method": cleanup.get("termination_method"),
            "profile_removed": bool(cleanup.get("temporary_profile_removed")),
        },
        server_exit={
            "stopped": bool(cleanup.get("http_server_stopped")),
            "requests_served": cleanup.get("requests_served"),
        },
        orphan_processes=tuple(int(pid) for pid in (cleanup.get("orphan_processes") or [])),
        termination_reason=termination_reason,
        tree_hash_before=tree_hash_before,
        tree_hash_after=tree_hash_after,
        tree_byte_identical=tree_identical,
    )


def _origin_of(url: str | None) -> str | None:
    if not url:
        return None
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"
