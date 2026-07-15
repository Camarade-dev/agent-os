"""Slice 5A: deterministic acceptance tests for bounded browser verification.

These exercise the bounded V0 runtime verifier with an injected fake provider,
so every verdict path (PASS / FAIL / INCONCLUSIVE), the byte-identity guarantee,
the single-attempt store, and the no-provider/no-repair/no-retry/no-orphan
invariants are proven without launching a real browser. A separate module-level
live test drives one real bounded attempt against the archived neon-serpents
target when Chrome is available.
"""

from __future__ import annotations

import dataclasses
import hashlib
from pathlib import Path

import pytest

from admissible.browser_runtime.v0_runtime_verification import (
    RUNTIME_ENTRY_POINT,
    V0RuntimeVerdict,
    hash_target_tree,
    run_bounded_runtime_verification,
)
from admissible.browser_runtime.v0_runtime_store import (
    RuntimeAttemptExists,
    V0RuntimeVerificationStore,
)
from admissible.v0_controller.invariants import validate_state
from admissible.v0_controller.state import (
    V0_SCHEMA_VERSION,
    BatchRecord,
    BatchStatus,
    Counters,
    FileEvidence,
    InvocationLifecycle,
    InvocationRecord,
    MissionContract,
    Phase,
    ProposedOperation,
    SessionState,
    StructuralFileCheck,
    StructuralVerification,
    V0ExecutionReceipt,
    WaitKind,
    WaitToken,
)

INDEX_HTML = b"<!doctype html><html><head><title>Fixture</title></head><body>ok</body></html>"


# --------------------------------------------------------------------------
# A minimal but fully valid AWAITING_HUMAN V0 state (single mandatory path).
# --------------------------------------------------------------------------
def build_awaiting_human_state(*, session_id: str = "slice5a-fixture") -> SessionState:
    path = "index.html"
    sha = hashlib.sha256(INDEX_HTML).hexdigest()
    op_id = "op-index"
    batch_id = "inv-1:batch:1"
    inv_id = "inv-1"
    receipt_id = "receipt-index"
    contract = MissionContract(
        contract_id="slice5a",
        target_workspace="/nonexistent/target",
        mandatory_paths=(path,),
    )
    evidence = FileEvidence(
        path=path,
        resolved_target="/nonexistent/target/index.html",
        physical_identity_key="phys-index",
        sha256=sha,
        byte_count=len(INDEX_HTML),
        action_id=op_id,
        execution_command_id="exec-cmd-1",
        batch_id=batch_id,
        invocation_id=inv_id,
        execution_receipt_id=receipt_id,
    )
    receipt = V0ExecutionReceipt(
        schema_version="admissible_v0_execution_receipt_v1",
        receipt_id=receipt_id,
        session_id=session_id,
        issued_revision=1,
        execution_command_id="exec-cmd-1",
        batch_id=batch_id,
        invocation_id=inv_id,
        action_id=op_id,
        operation_kind="write_file",
        path=path,
        resolved_target="/nonexistent/target/index.html",
        physical_identity_key="phys-index",
        sha256=sha,
        byte_count=len(INDEX_HTML),
        success=True,
    )
    batch = BatchRecord(
        batch_id=batch_id,
        invocation_id=inv_id,
        proposed_operations=(
            ProposedOperation.from_operation(
                operation_id=op_id, operation={"kind": "write_file", "path": path}
            ),
        ),
        admitted_operation_ids=(op_id,),
        executed_operation_ids=(op_id,),
        materialized_evidence=(evidence,),
        remaining_mandatory_paths=(),
        status=BatchStatus.COMPLETED,
    )
    invocation = InvocationRecord(
        invocation_id=inv_id,
        lifecycle=InvocationLifecycle.CONSUMED,
        request_at="t0",
    )
    verification = StructuralVerification(
        checks=(
            StructuralFileCheck(
                path=path, exists=True, non_empty=True, inside_workspace=True, sha256=sha
            ),
        ),
        passed=True,
        completed_at="t1",
    )
    state = SessionState(
        schema_version=V0_SCHEMA_VERSION,
        session_id=session_id,
        revision=8,
        semantic_state_version=8,
        phase=Phase.AWAITING_HUMAN,
        contract=contract,
        mandatory_paths=(path,),
        materialized_evidence=(evidence,),
        execution_receipt_history=(receipt,),
        current_invocation=None,
        invocation_history=(invocation,),
        current_batch=None,
        batch_history=(batch,),
        pending_command=None,
        completed_command_ids=("c1", "c2", "c3", "c4"),
        wait_token=WaitToken(
            kind=WaitKind.HUMAN_DECISION,
            owner_id="human_operator",
            command_id=None,
            expected_event="operator_resume",
        ),
        structural_verification=verification,
        counters=Counters(invocations=1, batches=1, commands=4),
    )
    validate_state(state)
    return state


def write_target(tmp_path: Path, *, contents: bytes = INDEX_HTML) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / RUNTIME_ENTRY_POINT).write_bytes(contents)
    return target


# --------------------------------------------------------------------------
# Fake provider
# --------------------------------------------------------------------------
class FakeCapability:
    def __init__(self, available: bool = True) -> None:
        self.available = available
        self.executable_path = "/fake/chrome" if available else None
        self.browser_version = "Fake/1.0" if available else None
        self.provider_id = "fake_provider"
        self.unavailable_reason = None if available else "no_browser"

    def to_dict(self):
        return {"available": self.available, "provider_id": self.provider_id}


class FakeSession:
    def __init__(self) -> None:
        self.screenshot_blobs: dict[str, bytes] = {}
        self._elapsed = 0

    def elapsed_ms(self) -> int:
        return self._elapsed


class FakeProvider:
    """A scripted provider producing controlled evidence for one scenario."""

    def __init__(
        self,
        *,
        available: bool = True,
        navigation_ok: bool = True,
        loaded: bool = True,
        exceptions: int = 0,
        external_attempts: int = 0,
        console_errors: int = 0,
        with_screenshot: bool = True,
        document_captured: bool = True,
        cleanup_clean: bool = True,
        orphan: bool = False,
        raise_on_step: bool = False,
        mutate_target: Path | None = None,
    ) -> None:
        self.capability = FakeCapability(available)
        self.navigation_ok = navigation_ok
        self.loaded = loaded
        self.exceptions = exceptions
        self.external_attempts = external_attempts
        self.console_errors = console_errors
        self.with_screenshot = with_screenshot
        self.document_captured = document_captured
        self.cleanup_clean = cleanup_clean
        self.orphan = orphan
        self.raise_on_step = raise_on_step
        self.mutate_target = mutate_target
        self.detect_calls = 0
        self.create_calls = 0
        self.close_calls = 0
        self._screenshot_id = "screenshot_deadbeef"
        self._shot = b"\x89PNG\r\n\x1a\nFAKE"

    def detect_capability(self):
        self.detect_calls += 1
        return self.capability

    def create_session(self, plan):
        self.create_calls += 1
        if self.mutate_target is not None:
            (self.mutate_target / "injected.txt").write_bytes(b"mutation")
        session = FakeSession()
        if self.with_screenshot:
            session.screenshot_blobs[self._screenshot_id] = self._shot
        return session

    def execute_step(self, session, step):
        if self.raise_on_step and step["type"] == "assert_no_page_exceptions":
            raise RuntimeError("boom")
        return {"status": "pass"}

    def capture_document(self, session):
        if not self.document_captured:
            return {"captured": False, "reason": "unavailable"}
        return {
            "captured": True,
            "outer_html": "<html><body>ok</body></html>",
            "outer_html_truncated": False,
            "ready_state": "complete",
            "title": "Fixture",
            "final_url": "http://127.0.0.1:54321/index.html",
        }

    def collect_evidence(self, session):
        screenshots = []
        if self.with_screenshot:
            screenshots = [
                {
                    "screenshot_id": self._screenshot_id,
                    "sha256": hashlib.sha256(self._shot).hexdigest(),
                    "byte_length": len(self._shot),
                    "width": 100,
                    "height": 100,
                }
            ]
        return {
            "page_load": {"ok": self.navigation_ok, "loaded": self.loaded, "url": "http://127.0.0.1:54321/index.html"},
            "page_exceptions": [{"text": f"err{i}"} for i in range(self.exceptions)],
            "external_request_attempts": [{"url": f"http://evil{i}"} for i in range(self.external_attempts)],
            "console_entries": [{"level": "error", "text": f"c{i}"} for i in range(self.console_errors)],
            "screenshots": screenshots,
        }

    def close_session(self, session):
        self.close_calls += 1
        return {
            "browser_process_terminated": True,
            "termination_method": "graceful",
            "http_server_stopped": True,
            "temporary_profile_removed": self.cleanup_clean,
            "requests_served": 3,
            "orphan_processes": [4242] if self.orphan else [],
        }


def run(state, target, provider):
    return run_bounded_runtime_verification(state=state, target_workspace=target, provider=provider)


# --------------------------------------------------------------------------
# 1. valid fixture -> PASS
# --------------------------------------------------------------------------
def test_valid_fixture_produces_pass(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    provider = FakeProvider()
    result = run(state, target, provider).result
    assert result.verdict == V0RuntimeVerdict.PASS.value
    assert result.reason_codes == ("runtime_pass",)
    assert result.screenshot_sha256 is not None
    assert result.dom_document_sha256 is not None
    assert result.loopback_origin == "http://127.0.0.1:54321"


# 2. uncaught exception -> FAIL
def test_uncaught_exception_produces_fail(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    result = run(state, target, FakeProvider(exceptions=1)).result
    assert result.verdict == V0RuntimeVerdict.FAIL.value
    assert "uncaught_javascript_exception" in result.reason_codes


# 3. attempted forbidden external dependency cannot PASS
def test_external_request_cannot_pass(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    result = run(state, target, FakeProvider(external_attempts=1)).result
    assert result.verdict != V0RuntimeVerdict.PASS.value
    assert result.verdict == V0RuntimeVerdict.FAIL.value
    assert "external_network_request_attempted" in result.reason_codes


# 4. bounded timeout -> INCONCLUSIVE
def test_timeout_produces_inconclusive(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    result = run(state, target, FakeProvider(loaded=False)).result
    assert result.verdict == V0RuntimeVerdict.INCONCLUSIVE.value
    assert "load_timed_out" in result.reason_codes


# 5. missing screenshot cannot PASS
def test_missing_screenshot_cannot_pass(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    result = run(state, target, FakeProvider(with_screenshot=False)).result
    assert result.verdict == V0RuntimeVerdict.INCONCLUSIVE.value
    assert "missing_screenshot_evidence" in result.reason_codes


def test_missing_dom_cannot_pass(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    result = run(state, target, FakeProvider(document_captured=False)).result
    assert result.verdict == V0RuntimeVerdict.INCONCLUSIVE.value
    assert "missing_dom_evidence" in result.reason_codes


# 6. target byte-identical before and after
def test_target_byte_identical(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    before = hash_target_tree(target)["tree_sha256"]
    result = run(state, target, FakeProvider()).result
    after = hash_target_tree(target)["tree_sha256"]
    assert before == after
    assert result.tree_byte_identical is True
    assert result.tree_hash_before == result.tree_hash_after == before


def test_target_mutation_detected_as_fail(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    result = run(state, target, FakeProvider(mutate_target=target)).result
    assert result.verdict == V0RuntimeVerdict.FAIL.value
    assert "target_tree_mutated" in result.reason_codes


# 7. exactly one verification attempt is persisted
def test_exactly_one_attempt_persisted(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    store = V0RuntimeVerificationStore(tmp_path / "runtime-store")
    run1 = run(state, target, FakeProvider())
    store.attach(run1)
    run2 = run(state, target, FakeProvider())
    with pytest.raises(RuntimeAttemptExists):
        store.attach(run2)
    files = list((tmp_path / "runtime-store").glob("*.runtime.json"))
    assert len(files) == 1


# 8. no provider invocation occurs
def test_no_provider_invocation(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    result = run(state, target, FakeProvider()).result
    assert result.provider_invoked is False


# 9. no retry or repair occurs
def test_no_retry_or_repair(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    provider = FakeProvider()
    result = run(state, target, provider).result
    assert result.retry_attempted is False
    assert result.repair_attempted is False
    assert provider.create_calls == 1  # exactly one browser session, never retried


# 10. no orphan / clean termination for PASS; orphan -> INCONCLUSIVE
def test_no_orphan_processes_on_pass(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    result = run(state, target, FakeProvider()).result
    assert result.orphan_processes == ()
    assert result.browser_exit["terminated"] is True
    assert result.server_exit["stopped"] is True


def test_orphan_process_is_inconclusive(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    result = run(state, target, FakeProvider(orphan=True)).result
    assert result.verdict == V0RuntimeVerdict.INCONCLUSIVE.value
    assert "cleanup_uncertain" in result.reason_codes
    assert result.orphan_processes == (4242,)


# 11. reconstructing the persisted run preserves the same result byte-for-byte
def test_reconstruction_is_byte_identical(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    store = V0RuntimeVerificationStore(tmp_path / "runtime-store")
    original = run(state, target, FakeProvider())
    store.attach(original)
    reloaded = store.load(state.session_id)
    assert reloaded.result.canonical_bytes() == original.result.canonical_bytes()
    assert store.verify_artifacts(state.session_id) is True


# --------------------------------------------------------------------------
# Entry-gate refusals never launch a browser.
# --------------------------------------------------------------------------
def test_entry_refused_when_not_awaiting_human(tmp_path):
    state = dataclasses.replace(build_awaiting_human_state(), phase=Phase.PLAN)
    target = write_target(tmp_path)
    provider = FakeProvider()
    result = run(state, target, provider).result
    assert result.verdict == V0RuntimeVerdict.INCONCLUSIVE.value
    assert "entry_not_awaiting_human" in result.reason_codes
    assert provider.detect_calls == 0  # no browser was ever launched


def test_entry_refused_when_structural_not_passed(tmp_path):
    base = build_awaiting_human_state()
    failed_sv = dataclasses.replace(base.structural_verification, passed=False)
    state = dataclasses.replace(base, structural_verification=failed_sv)
    target = write_target(tmp_path)
    provider = FakeProvider()
    result = run(state, target, provider).result
    assert result.verdict == V0RuntimeVerdict.INCONCLUSIVE.value
    assert "entry_structural_not_passed" in result.reason_codes
    assert provider.detect_calls == 0


def test_entry_refused_when_entry_point_missing_on_disk(tmp_path):
    state = build_awaiting_human_state()
    target = tmp_path / "target"
    target.mkdir()  # empty: index.html absent
    provider = FakeProvider()
    result = run(state, target, provider).result
    assert result.verdict == V0RuntimeVerdict.INCONCLUSIVE.value
    assert "entry_mandatory_path_missing" in result.reason_codes
    assert provider.detect_calls == 0


def test_browser_unavailable_is_inconclusive(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    result = run(state, target, FakeProvider(available=False)).result
    assert result.verdict == V0RuntimeVerdict.INCONCLUSIVE.value
    assert "browser_runtime_unavailable" in result.reason_codes


# --------------------------------------------------------------------------
# F1: normal save/load never leaves a lock file inside the evidence directory.
# --------------------------------------------------------------------------
def test_store_leaves_no_lock_inside_evidence_directory(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    store_dir = tmp_path / "runtime-store"
    store = V0RuntimeVerificationStore(store_dir)
    attach = run(state, target, FakeProvider())
    store.attach(attach)
    store.load(state.session_id)
    assert store.verify_artifacts(state.session_id) is True
    # The advisory lock is machine-local: it must never materialize anywhere
    # inside the canonical evidence directory.
    stray_locks = list(store_dir.rglob("*.lock")) + list(store_dir.rglob("*.runtime.lock"))
    assert stray_locks == []


# --------------------------------------------------------------------------
# F3: a tampered evidence artifact fails verification and never reads as valid.
# --------------------------------------------------------------------------
def test_tampered_artifact_fails_verification(tmp_path):
    state = build_awaiting_human_state()
    target = write_target(tmp_path)
    store = V0RuntimeVerificationStore(tmp_path / "runtime-store")
    attach = run(state, target, FakeProvider())
    attachment = store.attach(attach)
    assert store.verify_artifacts(state.session_id) is True

    # Flip one byte of one persisted evidence artifact on disk.
    artifact_path = attachment.directory / attachment.artifacts[0].relative_path
    raw = bytearray(artifact_path.read_bytes())
    raw[0] ^= 0xFF
    artifact_path.write_bytes(bytes(raw))

    assert store.verify_artifacts(state.session_id) is False
    # After reload the recorded digest still describes the original bytes, so the
    # altered artifact cannot be treated as verified.
    reloaded = store.load(state.session_id)
    tampered = reloaded.directory / reloaded.artifacts[0].relative_path
    assert hashlib.sha256(tampered.read_bytes()).hexdigest() != reloaded.artifacts[0].sha256
    assert store.verify_artifacts(state.session_id) is False


# --------------------------------------------------------------------------
# F2: the umbrella archive manifest matches the committed canonical archive.
# --------------------------------------------------------------------------
def test_umbrella_manifest_matches_archive():
    from admissible.browser_runtime.archive_integrity import verify_manifest

    archive_root = (
        Path(__file__).resolve().parents[1]
        / "_agent-runs"
        / "neon-serpents-live-002"
    )
    if not archive_root.is_dir():
        pytest.skip("canonical archive not present in this checkout")
    ok, problems = verify_manifest(archive_root)
    assert ok, f"umbrella manifest does not match archive: {problems}"
