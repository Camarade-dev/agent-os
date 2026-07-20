"""Act-2A.4J: write-once committed-review binding and evidence-bound acceptance.

Every native process is deterministic fake code from the sibling executor test
harness; no live Cursor, provider, or backend attestation is reachable from any
test, and every blocked case proves it created nothing and mutated nothing.
The three Act-2A.4I failure modes — substring review verdicts, substring owner
statements, and a caller-trusted review HEAD — are exercised directly against
the production predicates, never behind mocks.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import threading
from typing import Callable

import pytest

from test_admissible_delegated_gate_native_executor import (
    Harness,
    _command,
    _commit,
    _eligibility_recorded_false,
    _harness,
    _repository_internals,
    _rewrite_record,
    _trap_capability,
    _tree_hashes,
)

from admissible.delegated_gate.canonical import canonical_bytes, fingerprint
from admissible.delegated_gate.events import HumanDispositionRecorded
from admissible.delegated_gate.native_acceptance import (
    ACCEPTANCE_DECISION,
    ACCEPTANCE_PERSISTED_PHASE,
    CANARY_004_COMMITTED_REVIEW_SPECIFICATION,
    NATIVE_CHECKPOINT_ACCEPTANCE_NON_AUTHORITY,
    NATIVE_CHECKPOINT_ACCEPTANCE_SCHEMA_VERSION,
    NATIVE_CHECKPOINT_REVIEW_BINDING_NON_AUTHORITY,
    NATIVE_CHECKPOINT_REVIEW_BINDING_SCHEMA_VERSION,
    RUN_METADATA_FILE_NAME,
    NativeCheckpointAcceptance,
    NativeCheckpointAcceptanceConflict,
    NativeCheckpointAcceptanceInvalid,
    NativeCheckpointAcceptancePresence,
    NativeCheckpointAcceptanceStatus,
    NativeCheckpointReviewBinding,
    NativeCheckpointReviewBindingConflict,
    NativeCheckpointReviewBindingInvalid,
    NativeCheckpointReviewBindingPresence,
    NativeCheckpointReviewBindingStatus,
    classify_native_checkpoint_acceptance,
    classify_native_checkpoint_review_binding,
    committed_review_specification,
    has_native_checkpoint_acceptance,
    has_native_checkpoint_review_binding,
    load_native_checkpoint_acceptance,
    load_native_checkpoint_review_binding,
    load_run_authorization_binding,
    record_native_checkpoint_acceptance,
    record_native_checkpoint_review_binding,
    _parse_owner_statement,
)
from admissible.delegated_gate import native_canary as native_canary_module
from admissible.delegated_gate.native_canary import (
    CANARY_CLASSIFICATION,
    CANARY_GATE_ID,
    build_authorization_payload,
    reconstruct_completed_canary_success,
    _git_source_preflight,
    _git_source_preflight_run,
)
from admissible.delegated_gate.native_executor import (
    NativeCaptureTerminalStatus,
    NativeDelegatedExecutor,
    NativeExecutionStoreError,
)
from admissible.delegated_gate.reducer import IllegalTransition, reduce
from admissible.delegated_gate.state import HumanDisposition, Phase
from admissible.delegated_gate.store import DelegatedGateStoreError


_REVIEW_HEAD = "b" * 40
_REVIEW_PASS_VERDICT = "ACT_TEST_COMMITTED_REVIEW_PASS_READY_FOR_OWNER_ACCEPTANCE"
_BLOCKED_ERRORS = (NativeExecutionStoreError, DelegatedGateStoreError)


def _install_traps(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every live capability is a trap while acceptance code runs."""

    monkeypatch.setattr("admissible.delegated_gate.native_canary.run_behavioral_verifier", _trap_capability("behavioral verifier"))
    monkeypatch.setattr("admissible.delegated_gate.native_canary.capture_checkpoint", _trap_capability("checkpoint capture"))
    monkeypatch.setattr("admissible.delegated_gate.native_executor.preflight_native_cursor", _trap_capability("cursor preflight"))
    monkeypatch.setattr("admissible.delegated_gate.native_executor._attest_local_backend", _trap_capability("local backend attestor"))
    monkeypatch.setattr(NativeDelegatedExecutor, "execute", _trap_capability("native executor"))
    monkeypatch.setattr(NativeDelegatedExecutor, "attest_local_backend", _trap_capability("live attestation"))


def _source_head(h: Harness) -> str:
    return _command(["git", "rev-parse", "HEAD"], cwd=h.source).stdout.strip().lower()


def _write_run_metadata(h: Harness, *, run_id: str = "run", mutate: Callable[[dict], None] | None = None) -> None:
    payload = build_authorization_payload(
        source_repository=h.source, source_head=_source_head(h), run_id=run_id,
        session_id=h.session_id, attestation=h.attestation, run_root=h.root, timeout_seconds=30,
    )
    metadata = {
        "classification": CANARY_CLASSIFICATION,
        "authorization_payload": payload.to_dict(),
        "attestation": h.attestation.to_dict(),
        "local_capability_status": "PREFLIGHT_READY",
        "durability_capability": {"ready": True},
    }
    if mutate is not None:
        mutate(metadata)
        body = {key: value for key, value in metadata["authorization_payload"].items() if key != "payload_fingerprint"}
        metadata["authorization_payload"]["payload_fingerprint"] = fingerprint(body)
    (h.evidence / RUN_METADATA_FILE_NAME).write_bytes(canonical_bytes(metadata) + b"\n")


def _protocol_repository(tmp_path: Path) -> tuple[Path, str]:
    root = tmp_path / "protocol-repo"
    root.mkdir()
    _command(["git", "init", "--quiet", "--initial-branch=main"], cwd=root)
    _command(["git", "config", "core.autocrlf", "false"], cwd=root)
    _command(["git", "config", "commit.gpgsign", "false"], cwd=root)
    (root / "protocol.md").write_text("bound checkpoint acceptance protocol\n", encoding="utf-8")
    _commit(root, "feat: bound checkpoint acceptance protocol")
    head = _command(["git", "rev-parse", "HEAD"], cwd=root).stdout.strip().lower()
    return root, head


def _record_fingerprint(h: Harness, kind: str, key: str) -> str:
    return json.loads(h.store._path(kind, h.session_id, CANARY_GATE_ID, 0).read_text(encoding="utf-8"))[key]


def _synthetic_specification(
    h: Harness,
    *,
    run_id: str = "run",
    reviewed_code_head: str = _REVIEW_HEAD,
    review_verdict: str = _REVIEW_PASS_VERDICT,
    override: dict | None = None,
):
    state = h.session_store.load(h.session_id)
    checkpoint = state.checkpoint_history[-1]
    values = dict(
        run_id=run_id,
        session_id=h.session_id,
        gate_id=CANARY_GATE_ID,
        execution_attempt_index=0,
        execution_source_head=_source_head(h),
        workspace_final_git_head=checkpoint.git_head,
        request_fingerprint=_record_fingerprint(h, "request", "request_fingerprint"),
        result_fingerprint=_record_fingerprint(h, "result", "result_fingerprint"),
        behavioral_evidence_fingerprint=_record_fingerprint(h, "behavioral", "evidence_fingerprint"),
        capture_attempt_fingerprint=_record_fingerprint(h, "capture-attempt", "attempt_fingerprint"),
        checkpoint_fingerprint=checkpoint.checkpoint_fingerprint,
        delegated_state_revision=state.revision,
        delegated_state_fingerprint=state.state_fingerprint,
        persisted_phase="CHECKPOINT_CAPTURED",
        reviewed_code_head=reviewed_code_head,
        review_verdict=review_verdict,
    )
    values.update(override or {})
    return committed_review_specification(**values)


def _review_args(h: Harness, spec=None, **overrides) -> dict:
    spec = spec if spec is not None else h.review_spec
    base = dict(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        protocol_repository=h.protocol_root, protocol_code_head=h.protocol_head,
        session_id=h.session_id, gate_id=CANARY_GATE_ID, run_id=spec.run_id,
        reviewer_identity="test-reviewer", reviewed_code_head=spec.reviewed_code_head,
        review_verdict=spec.review_verdict, specification=spec,
    )
    base.update(overrides)
    return base


def _owner_statement(args: dict) -> str:
    return (
        "NATIVE_CHECKPOINT_ACCEPTANCE_V1"
        f";run_id={args['run_id']}"
        f";execution_source_head={args['execution_source_head']}"
        f";workspace_final_head={args['workspace_final_git_head']}"
        f";evidence_review_code_head={args['evidence_review_code_head']}"
        f";acceptance_protocol_code_head={args['acceptance_protocol_code_head']}"
        f";review_binding_fingerprint={args['review_binding_fingerprint']}"
        ";decision=ACCEPTED"
    )


def _acceptance_context(tmp_path: Path, *, run: bool = True, bind_review: bool = True) -> tuple[Harness, dict]:
    h = _harness(tmp_path)
    if run:
        assert h.coordinator.run(session_id=h.session_id).canary_success
    _write_run_metadata(h)
    h.protocol_root, h.protocol_head = _protocol_repository(tmp_path)
    state = h.session_store.load(h.session_id)
    review_binding_fingerprint = "0" * 64
    if run:
        h.review_spec = _synthetic_specification(h)
        if bind_review:
            review_outcome = record_native_checkpoint_review_binding(**_review_args(h))
            assert review_outcome.status is NativeCheckpointReviewBindingStatus.REVIEW_BINDING_CREATED
            review_binding_fingerprint = review_outcome.review_binding.review_binding_fingerprint
        checkpoint = state.checkpoint_history[-1]
        bindings = dict(
            workspace_final_git_head=checkpoint.git_head,
            request_fingerprint=_record_fingerprint(h, "request", "request_fingerprint"),
            result_fingerprint=_record_fingerprint(h, "result", "result_fingerprint"),
            behavioral_evidence_fingerprint=_record_fingerprint(h, "behavioral", "evidence_fingerprint"),
            capture_attempt_fingerprint=_record_fingerprint(h, "capture-attempt", "attempt_fingerprint"),
            checkpoint_fingerprint=checkpoint.checkpoint_fingerprint,
        )
    else:
        bindings = dict(
            workspace_final_git_head="e" * 40, request_fingerprint="0" * 64, result_fingerprint="0" * 64,
            behavioral_evidence_fingerprint="0" * 64, capture_attempt_fingerprint="0" * 64,
            checkpoint_fingerprint="0" * 64,
        )
    args = dict(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        protocol_repository=h.protocol_root,
        session_id=h.session_id, gate_id=CANARY_GATE_ID, run_id="run",
        acceptance_id="acceptance-001", actor_identity="test-owner",
        execution_source_head=_source_head(h),
        delegated_state_revision=state.revision, delegated_state_fingerprint=state.state_fingerprint,
        evidence_review_code_head=_REVIEW_HEAD, evidence_review_verdict=_REVIEW_PASS_VERDICT,
        review_binding_fingerprint=review_binding_fingerprint,
        acceptance_protocol_code_head=h.protocol_head,
        **bindings,
    )
    args["owner_statement"] = _owner_statement(args)
    return h, args


def _acceptance_path(h: Harness) -> Path:
    return h.store._path("checkpoint-acceptance", h.session_id, CANARY_GATE_ID, 0)


def _review_path(h: Harness) -> Path:
    return h.store._path("checkpoint-review-binding", h.session_id, CANARY_GATE_ID, 0)


def _assert_blocked(
    h: Harness,
    args: dict,
    monkeypatch: pytest.MonkeyPatch,
    *,
    errors: tuple = _BLOCKED_ERRORS,
    terminal_expected: bool = False,
) -> None:
    before = _tree_hashes(h.root)
    _install_traps(monkeypatch)
    with pytest.raises(errors):
        record_native_checkpoint_acceptance(**args)
    assert _tree_hashes(h.root) == before
    assert not has_native_checkpoint_acceptance(execution_store=h.store, session_id=h.session_id, gate_id=CANARY_GATE_ID)
    assert h.store.has_terminal(h.session_id, CANARY_GATE_ID, 0) is terminal_expected
    assert not tuple(h.store.directory.glob("*.attempt-1.*"))
    assert len(h.runner.invocations) <= 1


def _assert_review_blocked(
    h: Harness,
    rargs: dict,
    monkeypatch: pytest.MonkeyPatch,
    *,
    match: str | None = None,
    errors: tuple = _BLOCKED_ERRORS,
    terminal_expected: bool = False,
) -> None:
    before = _tree_hashes(h.root)
    _install_traps(monkeypatch)
    with pytest.raises(errors, match=match):
        record_native_checkpoint_review_binding(**rargs)
    assert _tree_hashes(h.root) == before
    assert not has_native_checkpoint_review_binding(execution_store=h.store, session_id=h.session_id, gate_id=CANARY_GATE_ID)
    assert h.store.has_terminal(h.session_id, CANARY_GATE_ID, 0) is terminal_expected
    assert not tuple(h.store.directory.glob("*.attempt-1.*"))
    assert len(h.runner.invocations) <= 1


# ---------------------------------------------------------------------------
# Review binding: creation, idempotence, conflicts, storage
# ---------------------------------------------------------------------------


def test_valid_review_binding_creation_with_exact_write_accounting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    _install_traps(monkeypatch)
    monkeypatch.delenv("GIT_OPTIONAL_LOCKS", raising=False)
    source_before = _tree_hashes(h.source)
    run_before = _tree_hashes(h.root)
    work_before = _repository_internals(h.work)
    protocol_before = _repository_internals(h.protocol_root)
    outcome = record_native_checkpoint_review_binding(**_review_args(h))
    assert outcome.status is NativeCheckpointReviewBindingStatus.REVIEW_BINDING_CREATED
    record = outcome.review_binding
    assert record.schema_version == NATIVE_CHECKPOINT_REVIEW_BINDING_SCHEMA_VERSION
    assert record.review_binding_id == f"review:{h.session_id}:{CANARY_GATE_ID}:0"
    assert record.reviewed_code_head == _REVIEW_HEAD
    assert record.review_verdict == _REVIEW_PASS_VERDICT
    assert record.non_authority_claims == NATIVE_CHECKPOINT_REVIEW_BINDING_NON_AUTHORITY
    run_after = _tree_hashes(h.root)
    added = set(run_after) - set(run_before)
    assert added == {str(_review_path(h).relative_to(h.root))}
    assert {key: run_after[key] for key in run_before} == run_before
    assert _tree_hashes(h.source) == source_before
    assert _repository_internals(h.work) == work_before
    assert _repository_internals(h.protocol_root) == protocol_before
    assert "GIT_OPTIONAL_LOCKS" not in os.environ
    state = h.session_store.load(h.session_id)
    assert state.phase is Phase.CHECKPOINT_CAPTURED and state.human_disposition is None
    raw = _review_path(h).read_bytes()
    assert raw == canonical_bytes(record.to_dict()) + b"\n"
    for forbidden in (b"authorization_digest", b"OWNER_AUTHORIZATION", b"owner_statement", b"Immutable mission:"):
        assert forbidden not in raw
    loaded = load_native_checkpoint_review_binding(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    )
    assert loaded == record
    assert classify_native_checkpoint_review_binding(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    ) is NativeCheckpointReviewBindingPresence.PRESENT_VALID
    assert len(h.runner.invocations) == 1
    # Idempotent retry preserves both the record and the protocol repository.
    path = _review_path(h)
    record_stat = (path.read_bytes(), path.stat().st_mtime_ns)
    second = record_native_checkpoint_review_binding(**_review_args(h))
    assert second.status is NativeCheckpointReviewBindingStatus.REVIEW_BINDING_IDEMPOTENT_EXISTING
    assert (path.read_bytes(), path.stat().st_mtime_ns) == record_stat
    assert _repository_internals(h.protocol_root) == protocol_before


def test_review_binding_exact_duplicate_idempotent_without_rewrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    path = _review_path(h)
    stat_before = (path.read_bytes(), path.stat().st_mtime_ns)
    second = record_native_checkpoint_review_binding(**_review_args(h))
    assert second.status is NativeCheckpointReviewBindingStatus.REVIEW_BINDING_IDEMPOTENT_EXISTING
    assert (path.read_bytes(), path.stat().st_mtime_ns) == stat_before
    third = record_native_checkpoint_review_binding(**_review_args(h, clock=lambda: "2027-01-01T00:00:00.000000Z"))
    assert third.status is NativeCheckpointReviewBindingStatus.REVIEW_BINDING_IDEMPOTENT_EXISTING
    assert (path.read_bytes(), path.stat().st_mtime_ns) == stat_before


@pytest.mark.parametrize("mutate", [
    {"reviewer_identity": "other-reviewer"},
    {"note": "a different concise review note"},
], ids=["reviewer", "note"])
def test_review_binding_conflicting_second_blocked_write_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutate: dict):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    path = _review_path(h)
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    with pytest.raises(NativeCheckpointReviewBindingConflict):
        record_native_checkpoint_review_binding(**_review_args(h, **mutate))
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_review_binding_malformed_existing_blocked_and_never_replaced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    path = _review_path(h)
    path.write_bytes(b"{not a canonical review binding\n")
    with pytest.raises(_BLOCKED_ERRORS):
        record_native_checkpoint_review_binding(**_review_args(h))
    assert path.read_bytes() == b"{not a canonical review binding\n"
    assert classify_native_checkpoint_review_binding(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    ) is NativeCheckpointReviewBindingPresence.PRESENT_INVALID


def test_review_binding_concurrent_duplicate_is_create_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    _install_traps(monkeypatch)
    rargs = _review_args(h, clock=lambda: "2026-07-18T00:00:00.000000Z")
    outcomes: list = [None, None]

    def _attempt(index: int) -> None:
        outcomes[index] = record_native_checkpoint_review_binding(**rargs)

    threads = [threading.Thread(target=_attempt, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    statuses = sorted(outcome.status for outcome in outcomes)
    assert statuses.count(NativeCheckpointReviewBindingStatus.REVIEW_BINDING_CREATED) == 1
    matches = tuple(h.store.directory.glob("*checkpoint-review-binding*"))
    assert matches == (_review_path(h),)
    assert outcomes[0].review_binding == outcomes[1].review_binding


# ---------------------------------------------------------------------------
# Review binding: exact verdict and reviewed-HEAD predicates (A4I-F-001/003)
# ---------------------------------------------------------------------------


_FRAUDULENT_VERDICTS = [
    ("bare-marker", "REVIEW_PASS"),
    ("fake-prefix", "FAKE_REVIEW_PASS"),
    ("wrong-act-short", "ACT_2A_4F_REVIEW_PASS"),
    ("prefixed-exact", "X_" + _REVIEW_PASS_VERDICT),
    ("suffixed-exact", _REVIEW_PASS_VERDICT + "_X"),
    ("leading-space", " " + _REVIEW_PASS_VERDICT),
    ("trailing-space", _REVIEW_PASS_VERDICT + " "),
    ("embedded-newline", _REVIEW_PASS_VERDICT[:8] + "\n" + _REVIEW_PASS_VERDICT[8:]),
    ("lowercase", _REVIEW_PASS_VERDICT.lower()),
    ("other-act", "ACT_9Z_COMMITTED_REVIEW_PASS_READY_FOR_OWNER_ACCEPTANCE"),
    ("other-classification", "ACT_TEST_COMMITTED_REVIEW_BLOCKED"),
    ("cyrillic-lookalike", _REVIEW_PASS_VERDICT.replace("REVIEW_PASS", "RЕVIEW_PASS")),
    ("lookalike-plus-marker", _REVIEW_PASS_VERDICT.replace("REVIEW_PASS", "RЕVIEW_PASS") + "_REVIEW_PASS"),
]


@pytest.mark.parametrize(("case", "verdict"), _FRAUDULENT_VERDICTS, ids=[case for case, _ in _FRAUDULENT_VERDICTS])
def test_review_binding_fraudulent_verdicts_rejected_by_exact_equality(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str, verdict: str):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    _assert_review_blocked(
        h, _review_args(h, review_verdict=verdict), monkeypatch,
        match="claimed review verdict differs from the committed review specification",
    )


def test_review_binding_wrong_reviewed_head_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    one_off = _REVIEW_HEAD[:-1] + "c"
    _assert_review_blocked(
        h, _review_args(h, reviewed_code_head=one_off), monkeypatch,
        match="claimed reviewed code HEAD differs from the committed review specification",
    )
    _assert_review_blocked(
        h, _review_args(h, reviewed_code_head="f" * 40), monkeypatch,
        match="claimed reviewed code HEAD differs from the committed review specification",
    )


@pytest.mark.parametrize(("case", "override"), [
    ("wrong-result-fingerprint", {"result_fingerprint": "2" * 64}),
    ("wrong-capture-fingerprint", {"capture_attempt_fingerprint": "4" * 64}),
    ("wrong-state-revision", {"delegated_state_revision": 7}),
    ("wrong-source-head", {"execution_source_head": "f" * 40}),
    ("wrong-workspace-head", {"workspace_final_git_head": "e" * 40}),
], ids=["result", "capture", "revision", "source-head", "workspace-head"])
def test_review_binding_wrong_evidence_specification_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str, override: dict):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    spec = _synthetic_specification(h, override=override)
    _assert_review_blocked(
        h, _review_args(h, spec=spec), monkeypatch,
        match="differs from the committed review specification",
    )


def test_review_binding_wrong_run_session_gate_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    _assert_review_blocked(h, _review_args(h, run_id="other-run"), monkeypatch)
    spec = _synthetic_specification(h, override={"session_id": "other-session"})
    _assert_review_blocked(h, _review_args(h, spec=spec, run_id="run"), monkeypatch)
    spec = _synthetic_specification(h, override={"gate_id": "substituted-gate"})
    _assert_review_blocked(h, _review_args(h, spec=spec, run_id="run"), monkeypatch)


def test_review_binding_requires_completed_success_phase(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, run=False)
    spec = committed_review_specification(
        run_id="run", session_id=h.session_id, gate_id=CANARY_GATE_ID, execution_attempt_index=0,
        execution_source_head="e" * 40, workspace_final_git_head="d" * 40,
        request_fingerprint="0" * 64, result_fingerprint="0" * 64,
        behavioral_evidence_fingerprint="0" * 64, capture_attempt_fingerprint="0" * 64,
        checkpoint_fingerprint="0" * 64, delegated_state_revision=0,
        delegated_state_fingerprint="0" * 64, persisted_phase="CHECKPOINT_CAPTURED",
        reviewed_code_head=_REVIEW_HEAD, review_verdict=_REVIEW_PASS_VERDICT,
    )
    before = _tree_hashes(h.root)
    _install_traps(monkeypatch)
    with pytest.raises(NativeCheckpointReviewBindingInvalid, match="CHECKPOINT_CAPTURED"):
        record_native_checkpoint_review_binding(**_review_args(h, spec=spec))
    assert _tree_hashes(h.root) == before
    assert not has_native_checkpoint_review_binding(execution_store=h.store, session_id=h.session_id, gate_id=CANARY_GATE_ID)
    assert h.runner.invocations == []


def test_review_binding_contradictory_terminal_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    h.store.create_terminal(
        request=h.store.load_request_structural(h.session_id, CANARY_GATE_ID, 0),
        result=h.store.load_result(h.session_id, CANARY_GATE_ID, 0),
        status=NativeCaptureTerminalStatus.CAPTURE_FAILED,
        failure_category="checkpoint_capture",
        diagnostic="synthetic contradictory terminal for review-binding fail-closed testing",
    )
    _assert_review_blocked(h, _review_args(h), monkeypatch, terminal_expected=True)


def test_review_binding_dirty_workspace_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    (h.work / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    _assert_review_blocked(h, _review_args(h), monkeypatch)


def test_review_binding_protocol_repository_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    (h.protocol_root / "uncommitted.txt").write_text("dirty\n", encoding="utf-8")
    _assert_review_blocked(
        h, _review_args(h), monkeypatch,
        match="acceptance-protocol repository is not at the exact clean committed HEAD",
    )
    (h.protocol_root / "uncommitted.txt").unlink()
    (h.protocol_root / "protocol.md").write_text("advanced protocol\n", encoding="utf-8")
    _commit(h.protocol_root, "feat: later protocol change")
    _assert_review_blocked(
        h, _review_args(h), monkeypatch,
        match="acceptance-protocol repository is not at the exact clean committed HEAD",
    )


def test_committed_specification_enforced_for_canary_004_run_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, bind_review=False)

    def masquerade(metadata: dict) -> None:
        payload = metadata["authorization_payload"]
        payload["run_id"] = "native-cursor-canary-004"
        payload["run_root"] = str(Path(payload["run_root"]).parent / "native-cursor-canary-004")

    _write_run_metadata(h, mutate=masquerade)
    # A caller-selected specification for a registered run is fail-closed.
    synthetic = _synthetic_specification(h, run_id="native-cursor-canary-004")
    _assert_review_blocked(
        h, _review_args(h, spec=synthetic), monkeypatch,
        match="differs from the committed review specification for this run",
    )
    # The committed specification itself cannot bind foreign synthetic evidence.
    committed = CANARY_004_COMMITTED_REVIEW_SPECIFICATION
    _assert_review_blocked(
        h,
        _review_args(h, spec=committed, run_id=committed.run_id,
                     reviewed_code_head=committed.reviewed_code_head,
                     review_verdict=committed.review_verdict),
        monkeypatch,
        match="differs from the committed review specification",
    )


def test_review_binding_schema_bounds_and_forged_registered_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    record = load_native_checkpoint_review_binding(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    )
    round_trip = NativeCheckpointReviewBinding.from_dict(record.to_dict())
    assert round_trip == record
    for mutate in (
        lambda raw: raw.__setitem__("review_binding_id", "review:other:gate:0"),
        lambda raw: raw.__setitem__("execution_attempt_index", 1),
        lambda raw: raw.__setitem__("persisted_phase", "COMPLETED"),
        lambda raw: raw.__setitem__("non_authority_claims", list(reversed(raw["non_authority_claims"]))),
        lambda raw: raw.__setitem__("review_verdict", raw["review_verdict"].lower()),
        lambda raw: raw.__setitem__("review_verdict", "ACT TEST WITH SPACES"),
        lambda raw: raw.__setitem__("reviewer_identity", ""),
        lambda raw: raw.pop("note"),
        lambda raw: raw.__setitem__("extra_field", 1),
    ):
        raw = record.to_dict()
        mutate(raw)
        raw["review_binding_fingerprint"] = fingerprint({key: value for key, value in raw.items() if key != "review_binding_fingerprint"})
        with pytest.raises(ValueError):
            NativeCheckpointReviewBinding.from_dict(raw)
    # A forged, refingerprinted record claiming the registered canary-004 run
    # is schema-invalid: its evidence contradicts the committed specification.
    forged = record.to_dict()
    forged["run_id"] = "native-cursor-canary-004"
    forged["session_id"] = "native-cursor-canary-004"
    forged["review_binding_id"] = f"review:native-cursor-canary-004:{CANARY_GATE_ID}:0"
    forged["review_binding_fingerprint"] = fingerprint({key: value for key, value in forged.items() if key != "review_binding_fingerprint"})
    with pytest.raises(ValueError, match="contradicts the committed review specification"):
        NativeCheckpointReviewBinding.from_dict(forged)


# ---------------------------------------------------------------------------
# Acceptance: creation, write order, idempotence, conflicts
# ---------------------------------------------------------------------------


def test_valid_acceptance_after_evidence_only_success_with_exact_write_accounting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    monkeypatch.delenv("GIT_OPTIONAL_LOCKS", raising=False)
    source_before = _tree_hashes(h.source)
    run_before = _tree_hashes(h.root)
    work_before = _repository_internals(h.work)
    protocol_before = _repository_internals(h.protocol_root)
    outcome = record_native_checkpoint_acceptance(**args)
    assert outcome.status is NativeCheckpointAcceptanceStatus.ACCEPTANCE_CREATED
    record = outcome.acceptance
    assert record.decision == ACCEPTANCE_DECISION and record.persisted_phase == ACCEPTANCE_PERSISTED_PHASE
    assert record.schema_version == NATIVE_CHECKPOINT_ACCEPTANCE_SCHEMA_VERSION
    assert record.non_authority_claims == NATIVE_CHECKPOINT_ACCEPTANCE_NON_AUTHORITY
    assert record.execution_attempt_index == 0
    assert record.review_binding_fingerprint == args["review_binding_fingerprint"]
    assert record.evidence_review_code_head == _REVIEW_HEAD
    assert record.evidence_review_verdict == _REVIEW_PASS_VERDICT
    assert record.owner_statement_sha256 == hashlib.sha256(args["owner_statement"].encode("ascii")).hexdigest()
    # Exactly one new file: the acceptance record.  Everything else is
    # byte-identical, including the workspace Git internals, the source, and
    # the protocol repository (including .git/index bytes and mtime_ns).
    run_after = _tree_hashes(h.root)
    added = set(run_after) - set(run_before)
    assert added == {str(_acceptance_path(h).relative_to(h.root))}
    assert {key: run_after[key] for key in run_before} == run_before
    assert _tree_hashes(h.source) == source_before
    assert _repository_internals(h.work) == work_before
    assert _repository_internals(h.protocol_root) == protocol_before
    assert "GIT_OPTIONAL_LOCKS" not in os.environ
    # Delegated state remains untouched at CHECKPOINT_CAPTURED.
    state = h.session_store.load(h.session_id)
    assert state.phase is Phase.CHECKPOINT_CAPTURED
    assert state.revision == record.delegated_state_revision
    assert state.human_disposition is None
    # The record is canonical, loadable, valid, and carries no secret material.
    raw = _acceptance_path(h).read_bytes()
    assert raw == canonical_bytes(record.to_dict()) + b"\n"
    for forbidden in (b"authorization_digest", b"OWNER_AUTHORIZATION", b"Immutable mission:", args["owner_statement"].encode("ascii")):
        assert forbidden not in raw
    loaded = load_native_checkpoint_acceptance(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    )
    assert loaded == record
    assert classify_native_checkpoint_acceptance(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    ) is NativeCheckpointAcceptancePresence.PRESENT_VALID
    assert len(h.runner.invocations) == 1
    path = _acceptance_path(h)
    record_stat = (path.read_bytes(), path.stat().st_mtime_ns)
    second = record_native_checkpoint_acceptance(**args)
    assert second.status is NativeCheckpointAcceptanceStatus.ACCEPTANCE_IDEMPOTENT_EXISTING
    assert (path.read_bytes(), path.stat().st_mtime_ns) == record_stat
    assert _repository_internals(h.protocol_root) == protocol_before
    assert h.session_store.load(h.session_id).phase is Phase.CHECKPOINT_CAPTURED


def test_review_binding_then_acceptance_write_order_accounting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    _install_traps(monkeypatch)
    snapshot_zero = _tree_hashes(h.root)
    review_outcome = record_native_checkpoint_review_binding(**_review_args(h))
    snapshot_one = _tree_hashes(h.root)
    assert set(snapshot_one) - set(snapshot_zero) == {str(_review_path(h).relative_to(h.root))}
    args = dict(args)
    args["review_binding_fingerprint"] = review_outcome.review_binding.review_binding_fingerprint
    args["owner_statement"] = _owner_statement(args)
    outcome = record_native_checkpoint_acceptance(**args)
    assert outcome.status is NativeCheckpointAcceptanceStatus.ACCEPTANCE_CREATED
    snapshot_two = _tree_hashes(h.root)
    assert set(snapshot_two) - set(snapshot_one) == {str(_acceptance_path(h).relative_to(h.root))}
    assert {key: snapshot_two[key] for key in snapshot_one} == snapshot_one


def test_acceptance_is_not_execution_and_reducer_still_rejects_generic_disposition(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    before = reconstruct_completed_canary_success(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence, session_id=h.session_id,
    )
    record_native_checkpoint_acceptance(**args)
    # Execution truth is unchanged and reconstruction never requires acceptance.
    after = reconstruct_completed_canary_success(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence, session_id=h.session_id,
    )
    assert after == before and after.canary_success
    # The generic final-review disposition remains illegal from CHECKPOINT_CAPTURED.
    state = h.session_store.load(h.session_id)
    disposition = HumanDisposition.accept(disposition_id="generic-disposition", actor_identity="test-owner")
    with pytest.raises(IllegalTransition):
        reduce(state, HumanDispositionRecorded(disposition))
    assert h.session_store.load(h.session_id).phase is Phase.CHECKPOINT_CAPTURED
    assert len(h.runner.invocations) == 1


def test_exact_duplicate_is_idempotent_without_rewrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    first = record_native_checkpoint_acceptance(**args)
    path = _acceptance_path(h)
    stat_before = (path.read_bytes(), path.stat().st_mtime_ns)
    second = record_native_checkpoint_acceptance(**args)
    assert first.status is NativeCheckpointAcceptanceStatus.ACCEPTANCE_CREATED
    assert second.status is NativeCheckpointAcceptanceStatus.ACCEPTANCE_IDEMPOTENT_EXISTING
    assert second.acceptance == first.acceptance
    assert (path.read_bytes(), path.stat().st_mtime_ns) == stat_before
    # A different creation clock alone is still the same disposition.
    third = record_native_checkpoint_acceptance(**{**args, "clock": lambda: "2027-01-01T00:00:00.000000Z"})
    assert third.status is NativeCheckpointAcceptanceStatus.ACCEPTANCE_IDEMPOTENT_EXISTING
    assert (path.read_bytes(), path.stat().st_mtime_ns) == stat_before


@pytest.mark.parametrize("mutate", [
    {"actor_identity": "other-owner"},
    {"acceptance_id": "acceptance-002"},
    {"note": "a different concise note"},
], ids=["actor", "acceptance-id", "note"])
def test_conflicting_second_acceptance_blocked_write_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutate: dict):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    record_native_checkpoint_acceptance(**args)
    path = _acceptance_path(h)
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    with pytest.raises(NativeCheckpointAcceptanceConflict):
        record_native_checkpoint_acceptance(**{**args, **mutate})
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_tampered_statement_hash_conflicts_write_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    record_native_checkpoint_acceptance(**args)
    path = _acceptance_path(h)
    _rewrite_record(path, lambda raw: raw.__setitem__("owner_statement_sha256", "9" * 64), self_fingerprint="acceptance_fingerprint")
    tampered = path.read_bytes()
    with pytest.raises(NativeCheckpointAcceptanceConflict):
        record_native_checkpoint_acceptance(**args)
    assert path.read_bytes() == tampered


def test_malformed_existing_acceptance_blocked_and_never_replaced(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    record_native_checkpoint_acceptance(**args)
    path = _acceptance_path(h)
    path.write_bytes(b"{not canonical acceptance\n")
    with pytest.raises(_BLOCKED_ERRORS):
        record_native_checkpoint_acceptance(**args)
    assert path.read_bytes() == b"{not canonical acceptance\n"
    assert classify_native_checkpoint_acceptance(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    ) is NativeCheckpointAcceptancePresence.PRESENT_INVALID


def test_acceptance_fingerprint_mismatch_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    record_native_checkpoint_acceptance(**args)
    path = _acceptance_path(h)
    _rewrite_record(path, lambda raw: raw.__setitem__("acceptance_fingerprint", "0" * 64), self_fingerprint=None)
    tampered = path.read_bytes()
    with pytest.raises(_BLOCKED_ERRORS):
        load_native_checkpoint_acceptance(
            session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
            session_id=h.session_id, gate_id=CANARY_GATE_ID,
        )
    with pytest.raises(_BLOCKED_ERRORS):
        record_native_checkpoint_acceptance(**args)
    assert path.read_bytes() == tampered
    assert classify_native_checkpoint_acceptance(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    ) is NativeCheckpointAcceptancePresence.PRESENT_INVALID


def test_tampered_refingerprinted_record_conflicts_with_the_original_request(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    record_native_checkpoint_acceptance(**args)
    path = _acceptance_path(h)
    _rewrite_record(path, lambda raw: raw.__setitem__("actor_identity", "substituted-owner"), self_fingerprint="acceptance_fingerprint")
    tampered = path.read_bytes()
    with pytest.raises(NativeCheckpointAcceptanceConflict):
        record_native_checkpoint_acceptance(**args)
    assert path.read_bytes() == tampered


# ---------------------------------------------------------------------------
# Acceptance: wrong or conflated bindings (fail-closed before any write)
# ---------------------------------------------------------------------------


_WRONG_BINDING_CASES = [
    ("wrong-run-id", {"run_id": "other-run"}),
    ("wrong-gate", {"gate_id": "substituted-gate"}),
    ("wrong-source-head", {"execution_source_head": "f" * 40}),
    ("review-head-substituted-for-source-head", {"execution_source_head": _REVIEW_HEAD}),
    ("wrong-workspace-head", {"workspace_final_git_head": "e" * 40}),
    ("wrong-request-fingerprint", {"request_fingerprint": "1" * 64}),
    ("wrong-result-fingerprint", {"result_fingerprint": "2" * 64}),
    ("wrong-behavioral-fingerprint", {"behavioral_evidence_fingerprint": "3" * 64}),
    ("wrong-capture-fingerprint", {"capture_attempt_fingerprint": "4" * 64}),
    ("wrong-checkpoint-fingerprint", {"checkpoint_fingerprint": "5" * 64}),
    ("wrong-state-revision", {"delegated_state_revision": 7}),
    ("wrong-state-fingerprint", {"delegated_state_fingerprint": "6" * 64}),
    ("non-pass-review-verdict", {"evidence_review_verdict": "ACT_TEST_COMMITTED_REVIEW_BLOCKED"}),
    ("fake-review-verdict", {"evidence_review_verdict": "FAKE_REVIEW_PASS"}),
    ("suffixed-review-verdict", {"evidence_review_verdict": _REVIEW_PASS_VERDICT + "_FABRICATED"}),
    ("review-head-conflated-with-source-head", {"evidence_review_code_head": None}),
    ("review-head-one-char-off", {"evidence_review_code_head": _REVIEW_HEAD[:-1] + "c"}),
    ("wrong-review-binding-fingerprint", {"review_binding_fingerprint": "7" * 64}),
    ("stale-protocol-head", {"acceptance_protocol_code_head": "a" * 40}),
]


@pytest.mark.parametrize(("case", "mutate"), _WRONG_BINDING_CASES, ids=[case for case, _ in _WRONG_BINDING_CASES])
def test_wrong_or_conflated_bindings_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str, mutate: dict):
    h, args = _acceptance_context(tmp_path)
    if mutate == {"evidence_review_code_head": None}:
        mutate = {"evidence_review_code_head": args["execution_source_head"]}
    args.update(mutate)
    args["owner_statement"] = _owner_statement(args)
    _assert_blocked(h, args, monkeypatch)


def test_wrong_session_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    args["session_id"] = "other-session"
    _assert_blocked(h, args, monkeypatch)


def test_phase_other_than_checkpoint_captured_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, run=False)
    before = _tree_hashes(h.root)
    _install_traps(monkeypatch)
    with pytest.raises(NativeCheckpointAcceptanceInvalid, match="CHECKPOINT_CAPTURED"):
        record_native_checkpoint_acceptance(**args)
    assert _tree_hashes(h.root) == before
    assert not has_native_checkpoint_acceptance(execution_store=h.store, session_id=h.session_id, gate_id=CANARY_GATE_ID)
    assert h.runner.invocations == []


def test_contradictory_terminal_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    h.store.create_terminal(
        request=h.store.load_request_structural(h.session_id, CANARY_GATE_ID, 0),
        result=h.store.load_result(h.session_id, CANARY_GATE_ID, 0),
        status=NativeCaptureTerminalStatus.CAPTURE_FAILED,
        failure_category="checkpoint_capture",
        diagnostic="synthetic contradictory terminal for acceptance fail-closed testing",
    )
    _assert_blocked(h, args, monkeypatch, terminal_expected=True)


@pytest.mark.parametrize("kind", ["request", "result", "behavioral", "capture-attempt"])
def test_missing_evidence_stage_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str):
    h, args = _acceptance_context(tmp_path)
    h.store._path(kind, h.session_id, CANARY_GATE_ID, 0).unlink()
    _assert_blocked(h, args, monkeypatch)


def test_eligibility_false_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _rewrite_record(
        h.store._path("execution-eligibility", h.session_id, CANARY_GATE_ID, 0),
        _eligibility_recorded_false, self_fingerprint="eligibility_fingerprint",
    )
    _assert_blocked(h, args, monkeypatch)


def test_dirty_workspace_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    (h.work / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    _assert_blocked(h, args, monkeypatch)


def test_advanced_workspace_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    (h.work / "advance.js").write_text("// post-success mutation\n", encoding="utf-8")
    _commit(h.work, "chore: post-success mutation")
    _assert_blocked(h, args, monkeypatch)


def test_missing_run_metadata_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    (h.evidence / RUN_METADATA_FILE_NAME).unlink()
    _assert_blocked(h, args, monkeypatch)


def test_tampered_authorization_payload_fingerprint_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    raw = json.loads((h.evidence / RUN_METADATA_FILE_NAME).read_text(encoding="utf-8"))
    raw["authorization_payload"]["payload_fingerprint"] = "0" * 64
    (h.evidence / RUN_METADATA_FILE_NAME).write_bytes(canonical_bytes(raw) + b"\n")
    _assert_blocked(h, args, monkeypatch)


def test_authorization_run_root_basename_mismatch_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _write_run_metadata(h, mutate=lambda metadata: metadata["authorization_payload"].__setitem__("run_id", "other-run"))
    args["run_id"] = "other-run"
    args["owner_statement"] = _owner_statement(args)
    _assert_blocked(h, args, monkeypatch)


def test_dirty_protocol_repository_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    (Path(args["protocol_repository"]) / "uncommitted.txt").write_text("dirty\n", encoding="utf-8")
    _assert_blocked(h, args, monkeypatch)


def test_advanced_protocol_head_after_declaration_blocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    protocol_root = Path(args["protocol_repository"])
    (protocol_root / "protocol.md").write_text("advanced protocol\n", encoding="utf-8")
    _commit(protocol_root, "feat: later protocol change")
    _assert_blocked(h, args, monkeypatch)


def test_concurrent_duplicate_attempt_is_create_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    args["clock"] = lambda: "2026-07-18T00:00:00.000000Z"
    outcomes: list = [None, None]

    def _attempt(index: int) -> None:
        outcomes[index] = record_native_checkpoint_acceptance(**args)

    threads = [threading.Thread(target=_attempt, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    statuses = sorted(outcome.status for outcome in outcomes)
    assert statuses.count(NativeCheckpointAcceptanceStatus.ACCEPTANCE_CREATED) == 1
    matches = tuple(h.store.directory.glob("*checkpoint-acceptance*"))
    assert matches == (_acceptance_path(h),)
    assert outcomes[0].acceptance == outcomes[1].acceptance


def test_loader_rejects_non_canonical_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    record_native_checkpoint_acceptance(**args)
    path = _acceptance_path(h)
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(_BLOCKED_ERRORS):
        load_native_checkpoint_acceptance(
            session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
            session_id=h.session_id, gate_id=CANARY_GATE_ID,
        )


def test_classification_is_read_only_and_absent_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    _install_traps(monkeypatch)
    before = _tree_hashes(h.root)
    assert classify_native_checkpoint_acceptance(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    ) is NativeCheckpointAcceptancePresence.ABSENT
    assert classify_native_checkpoint_review_binding(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    ) is NativeCheckpointReviewBindingPresence.ABSENT
    binding = load_run_authorization_binding(evidence_directory=h.evidence)
    assert binding.run_id == "run" and binding.session_id == h.session_id
    assert binding.source_head == args["execution_source_head"]
    assert _tree_hashes(h.root) == before


def test_invalid_acceptance_never_rewrites_execution_history(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    record_native_checkpoint_acceptance(**args)
    path = _acceptance_path(h)
    _rewrite_record(path, lambda raw: raw.__setitem__("checkpoint_fingerprint", "7" * 64), self_fingerprint="acceptance_fingerprint")
    assert classify_native_checkpoint_acceptance(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    ) is NativeCheckpointAcceptancePresence.PRESENT_INVALID
    outcome = reconstruct_completed_canary_success(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence, session_id=h.session_id,
    )
    assert outcome.canary_success
    assert h.session_store.load(h.session_id).phase is Phase.CHECKPOINT_CAPTURED


def test_record_schema_bounds_attempt_decision_phase_and_non_authority(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    record = record_native_checkpoint_acceptance(**args).acceptance
    round_trip = NativeCheckpointAcceptance.from_dict(record.to_dict())
    assert round_trip == record
    for mutate in (
        lambda raw: raw.__setitem__("execution_attempt_index", 1),
        lambda raw: raw.__setitem__("decision", "REJECTED"),
        lambda raw: raw.__setitem__("persisted_phase", "COMPLETED"),
        lambda raw: raw.__setitem__("non_authority_claims", list(reversed(raw["non_authority_claims"]))),
        lambda raw: raw.__setitem__("evidence_review_verdict", raw["evidence_review_verdict"].lower()),
        lambda raw: raw.__setitem__("evidence_review_verdict", "ACT TEST WITH SPACES"),
        lambda raw: raw.__setitem__("review_binding_fingerprint", ""),
        lambda raw: raw.__setitem__("created_at", "2026-07-18T00:00:00"),
        lambda raw: raw.__setitem__("extra_field", 1),
        lambda raw: raw.pop("note"),
    ):
        raw = record.to_dict()
        mutate(raw)
        raw["acceptance_fingerprint"] = fingerprint({key: value for key, value in raw.items() if key != "acceptance_fingerprint"})
        with pytest.raises(ValueError):
            NativeCheckpointAcceptance.from_dict(raw)


# ---------------------------------------------------------------------------
# Acceptance requires the persisted review binding (A4I-F-001/003)
# ---------------------------------------------------------------------------


def test_acceptance_blocked_without_review_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    _assert_blocked(h, args, monkeypatch)


def test_acceptance_blocked_on_malformed_review_binding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _review_path(h).write_bytes(b"{not a canonical review binding\n")
    before = _tree_hashes(h.root)
    _install_traps(monkeypatch)
    with pytest.raises(_BLOCKED_ERRORS):
        record_native_checkpoint_acceptance(**args)
    assert _tree_hashes(h.root) == before
    assert not has_native_checkpoint_acceptance(execution_store=h.store, session_id=h.session_id, gate_id=CANARY_GATE_ID)
    assert classify_native_checkpoint_review_binding(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    ) is NativeCheckpointReviewBindingPresence.PRESENT_INVALID


def test_acceptance_blocked_when_tampered_binding_carries_fraudulent_verdict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _rewrite_record(
        _review_path(h),
        lambda raw: raw.__setitem__("review_verdict", "FAKE_REVIEW_PASS"),
        self_fingerprint="review_binding_fingerprint",
    )
    _assert_blocked(h, args, monkeypatch)


def test_acceptance_load_validates_review_binding_after_the_fact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    record_native_checkpoint_acceptance(**args)
    _review_path(h).write_bytes(b"{corrupted after acceptance\n")
    with pytest.raises(_BLOCKED_ERRORS):
        load_native_checkpoint_acceptance(
            session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
            session_id=h.session_id, gate_id=CANARY_GATE_ID,
        )
    assert classify_native_checkpoint_acceptance(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence,
        session_id=h.session_id, gate_id=CANARY_GATE_ID,
    ) is NativeCheckpointAcceptancePresence.PRESENT_INVALID
    # Execution truth remains reconstructible regardless.
    assert reconstruct_completed_canary_success(
        session_store=h.session_store, execution_store=h.store, evidence_directory=h.evidence, session_id=h.session_id,
    ).canary_success


# ---------------------------------------------------------------------------
# Four HEAD roles: authoritative bindings, not numerical inequality
# ---------------------------------------------------------------------------


def test_equal_source_and_review_heads_valid_for_synthetic_future_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path, bind_review=False)
    source = _source_head(h)
    # A future run legitimately reviewed at its own execution commit: the two
    # roles carry the same object ID and both bind to their own sources.
    spec = _synthetic_specification(h, reviewed_code_head=source)
    review_outcome = record_native_checkpoint_review_binding(**_review_args(h, spec=spec))
    _install_traps(monkeypatch)
    args = dict(args)
    args["evidence_review_code_head"] = source
    args["review_binding_fingerprint"] = review_outcome.review_binding.review_binding_fingerprint
    args["owner_statement"] = _owner_statement(args)
    outcome = record_native_checkpoint_acceptance(**args)
    assert outcome.status is NativeCheckpointAcceptanceStatus.ACCEPTANCE_CREATED
    record = outcome.acceptance
    assert record.execution_source_head == record.evidence_review_code_head == source
    assert record.workspace_final_git_head != source


def test_swapped_authoritative_bindings_still_fail_with_equal_roles_allowed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    # Swapping two authoritative values remains fail-closed even though the
    # schema no longer imposes numerical inequality between roles.
    swapped = dict(args)
    swapped["execution_source_head"], swapped["workspace_final_git_head"] = (
        swapped["workspace_final_git_head"], swapped["execution_source_head"],
    )
    swapped["owner_statement"] = _owner_statement(swapped)
    _assert_blocked(h, swapped, monkeypatch)


# ---------------------------------------------------------------------------
# Canonical owner-statement grammar (A4I-F-002)
# ---------------------------------------------------------------------------


def test_owner_statement_parser_extracts_exact_role_mapping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    parsed = _parse_owner_statement(args["owner_statement"])
    assert dict(parsed) == {
        "run_id": args["run_id"],
        "execution_source_head": args["execution_source_head"],
        "workspace_final_head": args["workspace_final_git_head"],
        "evidence_review_code_head": args["evidence_review_code_head"],
        "acceptance_protocol_code_head": args["acceptance_protocol_code_head"],
        "review_binding_fingerprint": args["review_binding_fingerprint"],
    }


def _adversarial_statements(args: dict) -> list[tuple[str, str]]:
    s = _owner_statement(args)
    source = args["execution_source_head"]
    workspace = args["workspace_final_git_head"]
    review = args["evidence_review_code_head"]
    protocol = args["acceptance_protocol_code_head"]
    swapped_labels = s.replace(
        f";execution_source_head={source};workspace_final_head={workspace}",
        f";workspace_final_head={workspace};execution_source_head={source}",
    )
    swapped_review_protocol_labels = s.replace(
        f";evidence_review_code_head={review};acceptance_protocol_code_head={protocol}",
        f";acceptance_protocol_code_head={protocol};evidence_review_code_head={review}",
    )
    swapped_values = s.replace(
        f";execution_source_head={source};workspace_final_head={workspace}",
        f";execution_source_head={workspace};workspace_final_head={source}",
    )
    review_protocol_values_crossed = s.replace(
        f";evidence_review_code_head={review};acceptance_protocol_code_head={protocol}",
        f";evidence_review_code_head={protocol};acceptance_protocol_code_head={review}",
    )
    return [
        ("missing-role", s.replace(f";evidence_review_code_head={review}", "")),
        ("swapped-source-workspace-labels", swapped_labels),
        ("swapped-review-protocol-labels", swapped_review_protocol_labels),
        ("swapped-source-workspace-values", swapped_values),
        ("review-protocol-values-crossed", review_protocol_values_crossed),
        ("old-incorrect-source-claim", s.replace(
            f";execution_source_head={source}",
            ";execution_source_head=48054798aa3be73194097ad96821702b31499a29")),
        ("heads-only-in-unrelated-prose", "please accept " + " ".join((source, workspace, review, protocol))),
        ("duplicated-role-appended", s + f";execution_source_head={source}"),
        ("contradictory-extra-role", s.replace(";decision=", f";execution_source_head={'f' * 40};decision=")),
        ("workspace-duplicates-source-value", s.replace(
            f";workspace_final_head={workspace}", f";workspace_final_head={source}")),
        ("partial-head", s.replace(f";execution_source_head={source}", f";execution_source_head={source[:20]}")),
        ("uppercase-hex", s.replace(f";execution_source_head={source}", f";execution_source_head={source.upper()}")),
        ("one-char-head-change", s.replace(
            f";workspace_final_head={workspace}",
            f";workspace_final_head={workspace[:-1] + ('0' if workspace[-1] != '0' else '1')}")),
        ("leading-whitespace", " " + s),
        ("trailing-whitespace", s + " "),
        ("whitespace-around-separator", s.replace(";workspace_final_head", "; workspace_final_head")),
        ("carriage-return", s + "\r"),
        ("embedded-newline", s.replace(";decision", "\n;decision")),
        ("extra-prose-before", "I hereby accept " + s),
        ("extra-prose-after", s + " with thanks"),
        ("extra-field", s.replace(";decision=", ";extra=1;decision=")),
        ("reordered-fields", s.replace(
            f";review_binding_fingerprint={args['review_binding_fingerprint']};decision=ACCEPTED",
            f";decision=ACCEPTED;review_binding_fingerprint={args['review_binding_fingerprint']}")),
        ("case-modified-label", s.replace(";run_id=", ";Run_id=")),
        ("case-modified-prefix", s.replace("NATIVE_CHECKPOINT_ACCEPTANCE_V1", "native_checkpoint_acceptance_v1")),
        ("lookalike-separator", s.replace(";decision", "；decision")),
        ("lookalike-label", s.replace("execution_source_head", "executiоn_source_head")),
        ("changed-binding-fingerprint", s.replace(
            f";review_binding_fingerprint={args['review_binding_fingerprint']}",
            f";review_binding_fingerprint={'c' * 64}")),
        ("missing-binding-fingerprint", s.replace(
            f";review_binding_fingerprint={args['review_binding_fingerprint']}", "")),
        ("decision-rejected", s.replace("decision=ACCEPTED", "decision=REJECTED")),
        ("wrong-run-id", s.replace(";run_id=run;", ";run_id=other-run;")),
        ("empty-statement", "   "),
    ]


def test_owner_statement_adversarial_matrix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, args = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    before = _tree_hashes(h.root)
    cases = _adversarial_statements(args)
    assert len(cases) == 31
    for label, statement in cases:
        with pytest.raises(_BLOCKED_ERRORS):
            record_native_checkpoint_acceptance(**{**args, "owner_statement": statement})
        assert not has_native_checkpoint_acceptance(
            execution_store=h.store, session_id=h.session_id, gate_id=CANARY_GATE_ID
        ), label
    assert _tree_hashes(h.root) == before
    assert len(h.runner.invocations) == 1
    # The one exact canonical statement still succeeds afterwards.
    outcome = record_native_checkpoint_acceptance(**args)
    assert outcome.status is NativeCheckpointAcceptanceStatus.ACCEPTANCE_CREATED
    assert outcome.acceptance.owner_statement_sha256 == hashlib.sha256(
        args["owner_statement"].encode("ascii")
    ).hexdigest()


# ---------------------------------------------------------------------------
# Act 2A.4L: protocol-repository preflight Git read-only child environment
# ---------------------------------------------------------------------------


def _disposable_clean_git_repository(root: Path) -> str:
    root.mkdir(parents=True, exist_ok=True)
    _command(["git", "init", "--quiet", "--initial-branch=main"], cwd=root)
    _command(["git", "config", "core.autocrlf", "false"], cwd=root)
    _command(["git", "config", "core.filemode", "false"], cwd=root)
    _command(["git", "config", "commit.gpgsign", "false"], cwd=root)
    tracked = root / "tracked.txt"
    tracked.write_text("unchanged\n", encoding="utf-8")
    _commit(root, "chore: initialize disposable preflight repository")
    return _command(["git", "rev-parse", "HEAD"], cwd=root).stdout.strip().lower()


def _touch_tracked_stat_only(repository: Path) -> None:
    tracked = repository / "tracked.txt"
    old = tracked.stat()
    os.utime(tracked, ns=(old.st_atime_ns, old.st_mtime_ns + 2_000_000_000))


def test_git_source_preflight_run_forces_optional_locks_when_parent_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = tmp_path / "repository"
    repository.mkdir()
    observed: dict[str, object] = {}

    def capture(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["command"] = args[0]
        observed.update(kwargs)
        return subprocess.CompletedProcess(args[0], 0, "ok\n", "")

    monkeypatch.delenv("GIT_OPTIONAL_LOCKS", raising=False)
    monkeypatch.setenv("NATIVE_PREFLIGHT_INHERITED_TEST", "preserved")
    monkeypatch.setattr(native_canary_module.subprocess, "run", capture)
    result = _git_source_preflight_run(repository, "status", "--porcelain=v1", timeout=17)
    assert result.stdout == "ok\n"
    assert observed["env"]["GIT_OPTIONAL_LOCKS"] == "0"
    assert observed["env"]["NATIVE_PREFLIGHT_INHERITED_TEST"] == "preserved"
    assert "GIT_OPTIONAL_LOCKS" not in os.environ
    # The hardened read-only Git argv pins fsmonitor off and disables the
    # pager; the observation arguments follow that committed prefix.
    assert observed["command"] == ["git", "-c", "core.fsmonitor=false", "--no-pager", "status", "--porcelain=v1"]
    assert observed["cwd"] == repository and observed["timeout"] == 17
    assert observed["shell"] is False and observed["capture_output"] is True
    assert observed["text"] is True and observed["encoding"] == "utf-8"
    assert observed["check"] is False


def test_git_source_preflight_run_overrides_parent_optional_locks_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = tmp_path / "repository"
    repository.mkdir()
    observed: dict[str, object] = {}

    def capture(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["env"] = kwargs["env"]
        return subprocess.CompletedProcess(args[0], 0, "ok\n", "")

    monkeypatch.setenv("GIT_OPTIONAL_LOCKS", "1")
    monkeypatch.setenv("NATIVE_PREFLIGHT_INHERITED_TEST", "still-here")
    monkeypatch.setattr(native_canary_module.subprocess, "run", capture)
    _git_source_preflight_run(repository, "rev-parse", "HEAD")
    assert observed["env"]["GIT_OPTIONAL_LOCKS"] == "0"
    assert observed["env"]["NATIVE_PREFLIGHT_INHERITED_TEST"] == "still-here"
    assert os.environ["GIT_OPTIONAL_LOCKS"] == "1"


def test_git_source_preflight_run_preserves_unrelated_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repository = tmp_path / "repository"
    repository.mkdir()
    observed: dict[str, object] = {}
    before = dict(os.environ)

    def capture(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        observed["env"] = kwargs["env"]
        return subprocess.CompletedProcess(args[0], 0, "ok\n", "")

    monkeypatch.setenv("NATIVE_PREFLIGHT_MARKER", "alpha")
    monkeypatch.delenv("GIT_OPTIONAL_LOCKS", raising=False)
    monkeypatch.setattr(native_canary_module.subprocess, "run", capture)
    _git_source_preflight_run(repository, "status")
    assert observed["env"]["NATIVE_PREFLIGHT_MARKER"] == "alpha"
    assert observed["env"]["GIT_OPTIONAL_LOCKS"] == "0"
    assert dict(os.environ) == {**before, "NATIVE_PREFLIGHT_MARKER": "alpha"}
    assert "GIT_OPTIONAL_LOCKS" not in os.environ


def test_ordinary_git_status_may_refresh_disposable_index(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GIT_OPTIONAL_LOCKS", raising=False)
    refreshed = False
    for attempt in range(5):
        repository = tmp_path / f"ordinary-{attempt}"
        _disposable_clean_git_repository(repository)
        _touch_tracked_stat_only(repository)
        before = _repository_internals(repository)
        env = {key: value for key, value in os.environ.items() if key != "GIT_OPTIONAL_LOCKS"}
        result = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=repository,
            env=env,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        assert result.returncode == 0 and result.stdout == ""
        after = _repository_internals(repository)
        if after != before:
            refreshed = True
            assert after[".git/index"] != before[".git/index"]
            break
    # Reproduction of ordinary Git index refresh is informative for the act
    # report; failure to reproduce is not independently blocking.
    print(f"ORDINARY_GIT_INDEX_REFRESHED={refreshed}")


def test_git_source_preflight_does_not_refresh_disposable_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("GIT_OPTIONAL_LOCKS", raising=False)
    repository = tmp_path / "production-preflight"
    head = _disposable_clean_git_repository(repository)
    _touch_tracked_stat_only(repository)
    before = _repository_internals(repository)
    observed_envs: list[dict[str, str]] = []
    real_run = native_canary_module.subprocess.run

    def instrumented(*args: object, **kwargs: object):
        env = kwargs.get("env")
        if env is not None:
            observed_envs.append(dict(env))
        return real_run(*args, **kwargs)

    monkeypatch.setattr(native_canary_module.subprocess, "run", instrumented)
    ready, detail = _git_source_preflight(repository, head)
    assert ready is True and "clean authorized source HEAD" in detail
    assert _repository_internals(repository) == before
    assert observed_envs
    assert all(env.get("GIT_OPTIONAL_LOCKS") == "0" for env in observed_envs)
    assert "GIT_OPTIONAL_LOCKS" not in os.environ


def test_git_source_preflight_behavior_matrix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("GIT_OPTIONAL_LOCKS", raising=False)
    clean = tmp_path / "clean"
    head = _disposable_clean_git_repository(clean)
    assert _git_source_preflight(clean, head)[0] is True
    assert _git_source_preflight(clean, "f" * 40)[0] is False

    advanced = tmp_path / "advanced"
    advanced_head = _disposable_clean_git_repository(advanced)
    (advanced / "tracked.txt").write_text("advanced\n", encoding="utf-8")
    _commit(advanced, "chore: advance head")
    assert _git_source_preflight(advanced, advanced_head)[0] is False

    dirty_tracked = tmp_path / "dirty-tracked"
    dirty_head = _disposable_clean_git_repository(dirty_tracked)
    (dirty_tracked / "tracked.txt").write_text("mutated\n", encoding="utf-8")
    assert _git_source_preflight(dirty_tracked, dirty_head)[0] is False

    untracked = tmp_path / "untracked"
    untracked_head = _disposable_clean_git_repository(untracked)
    (untracked / "extra.txt").write_text("untracked\n", encoding="utf-8")
    assert _git_source_preflight(untracked, untracked_head)[0] is False

    staged = tmp_path / "staged"
    staged_head = _disposable_clean_git_repository(staged)
    (staged / "tracked.txt").write_text("staged\n", encoding="utf-8")
    _command(["git", "add", "--", "tracked.txt"], cwd=staged)
    assert _git_source_preflight(staged, staged_head)[0] is False

    unborn = tmp_path / "unborn"
    unborn.mkdir()
    _command(["git", "init", "--quiet", "--initial-branch=main"], cwd=unborn)
    assert _git_source_preflight(unborn, "a" * 40)[0] is False

    non_repo = tmp_path / "non-repo"
    non_repo.mkdir()
    assert _git_source_preflight(non_repo, "a" * 40)[0] is False

    nested = tmp_path / "nested-root"
    nested_head = _disposable_clean_git_repository(nested)
    nested_child = nested / "child"
    nested_child.mkdir()
    assert _git_source_preflight(nested_child, nested_head)[0] is False

    missing_git = tmp_path / "missing-git"
    missing_head = _disposable_clean_git_repository(missing_git)
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    (tmp_path / "empty-bin").mkdir()
    try:
        ready, detail = _git_source_preflight(missing_git, missing_head)
        assert ready is False and detail
    except FileNotFoundError:
        # Existing fail-closed behavior: missing Git surfaces before a ready tuple.
        pass


@pytest.mark.parametrize(
    ("setup", "path"),
    [
        ("dirty", "review"),
        ("wrong-head", "review"),
        ("advanced", "review"),
        ("untracked", "review"),
        ("unborn", "review"),
        ("invalid-root", "review"),
        ("dirty", "acceptance"),
        ("wrong-head", "acceptance"),
        ("advanced", "acceptance"),
        ("untracked", "acceptance"),
        ("unborn", "acceptance"),
        ("invalid-root", "acceptance"),
    ],
)
def test_failed_protocol_preflight_write_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, setup: str, path: str
):
    bind_review = path == "acceptance"
    h, args = _acceptance_context(tmp_path, bind_review=bind_review)
    _install_traps(monkeypatch)
    monkeypatch.delenv("GIT_OPTIONAL_LOCKS", raising=False)
    protocol = h.protocol_root
    if setup == "dirty":
        (protocol / "protocol.md").write_text("dirty protocol\n", encoding="utf-8")
    elif setup == "advanced":
        (protocol / "protocol.md").write_text("advanced protocol\n", encoding="utf-8")
        _commit(protocol, "feat: later protocol change")
    elif setup == "untracked":
        (protocol / "uncommitted.txt").write_text("dirty\n", encoding="utf-8")
    elif setup == "unborn":
        unborn = tmp_path / "unborn-protocol"
        unborn.mkdir()
        _command(["git", "init", "--quiet", "--initial-branch=main"], cwd=unborn)
        protocol = unborn
        h.protocol_root = unborn
    elif setup == "invalid-root":
        protocol = tmp_path / "not-a-git-repo"
        protocol.mkdir()
        h.protocol_root = protocol
    protocol_before = _repository_internals(protocol)
    run_before = _tree_hashes(h.root)
    if path == "review":
        rargs = _review_args(h)
        if setup == "wrong-head":
            rargs["protocol_code_head"] = "f" * 40
        if setup in {"unborn", "invalid-root"}:
            rargs["protocol_repository"] = protocol
        with pytest.raises(_BLOCKED_ERRORS):
            record_native_checkpoint_review_binding(**rargs)
        assert not has_native_checkpoint_review_binding(
            execution_store=h.store, session_id=h.session_id, gate_id=CANARY_GATE_ID
        )
    else:
        aargs = dict(args)
        if setup == "wrong-head":
            aargs["acceptance_protocol_code_head"] = "f" * 40
            aargs["owner_statement"] = _owner_statement(aargs)
        if setup in {"unborn", "invalid-root"}:
            aargs["protocol_repository"] = protocol
        with pytest.raises(_BLOCKED_ERRORS):
            record_native_checkpoint_acceptance(**aargs)
        assert not has_native_checkpoint_acceptance(
            execution_store=h.store, session_id=h.session_id, gate_id=CANARY_GATE_ID
        )
    assert _tree_hashes(h.root) == run_before
    assert _repository_internals(protocol) == protocol_before
    assert len(h.runner.invocations) <= 1
