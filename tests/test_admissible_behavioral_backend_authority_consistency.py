"""FROZEN_BEHAVIORAL cross-lane backend-authority consistency regressions.

One coherent law is exercised end to end with deterministic fake providers:
strict wrapper-chain attestation equality before provider spawn, the persisted
post-run eligibility decision as the only backend-drift authority afterwards.
The provider's own ``.running`` marker inside the selected Cursor version root
is the exact real-world condition these regressions pin: it changes only the
selected-version-root directory mtime, the eligibility lane admits it as
``METADATA_ONLY_DRIFT``, and the behavioral verifier must not re-refuse it
with a stale strict live re-attestation.  Every blocking backend-drift class
must remain admission-blocking, and the isolated-mtime carve-out must never
widen into a general metadata exemption.
"""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import shutil
import stat

import pytest

from admissible.delegated_gate.canonical import fingerprint
from admissible.delegated_gate.native_canary import (
    CANARY_GATE_ID,
    EXPECTED_MATERIAL_PATHS,
    NativeCanaryStatus,
    REQUIRED_COMMIT_MESSAGE,
    load_behavioral_verifier,
    run_behavioral_verifier,
)
from admissible.delegated_gate.native_executor import (
    NativeEvidenceInvalid,
    NativeFilesystemIdentity,
    NativeResultIneligible,
)
from admissible.product_launcher.recovery import (
    CLASSIFICATION_NOT_RECOVERABLE,
    CLASSIFICATION_REAUTHORIZATION_REQUIRED,
    classify_recovery,
)

from test_admissible_delegated_gate_native_executor import (
    FakeNativeProcessRunner,
    _bump_directory_mtime,
    _mutate_without_feature,
    _request,
    _wrapper_chain_harness,
)


def _create_running_marker(selected_root: Path) -> None:
    """Reproduce the observed provider behavior: a ``.running`` marker file."""

    (selected_root / ".running").write_bytes(b"pid: 4242\n")


def _classifier_envelope(eligibility) -> dict:
    """REFUSED result envelope carrying the run's real persisted reasons.

    ``failing_boundary.reasons`` in the product read model is exactly the
    persisted eligibility ``ineligibility_reasons`` list; the committed
    governed-rerun classifier consumes that envelope shape.  Only the reasons
    themselves come from live run evidence here.
    """

    return {
        "result_admission_state": {"verdict": "REFUSED", "verdict_is_authoritative": True},
        "failing_boundary": {"reasons": list(eligibility.ineligibility_reasons)},
    }


def test_provider_running_marker_is_isolated_mtime_only_and_admits_behavioral_and_checkpoint(tmp_path: Path):
    h, _ = _wrapper_chain_harness(tmp_path)
    selected = Path(h.attestation.selected_version_root)
    before = NativeFilesystemIdentity.from_stat(os.lstat(selected))
    h.runner.after_start = lambda: _create_running_marker(selected)
    outcome = h.coordinator.run(session_id=h.session_id)
    after = NativeFilesystemIdentity.from_stat(os.lstat(selected))
    # Direct physical proof of the isolated class: the marker changed only the
    # directory mtime, never device, inode, mode, or file attributes.
    assert (after.device, after.inode, after.mode, after.file_attributes) == (
        before.device, before.inode, before.mode, before.file_attributes,
    )
    assert after.mtime_ns != before.mtime_ns
    eligibility = h.store.load_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)
    assert eligibility.eligible and eligibility.ineligibility_reasons == ()
    assert eligibility.selected_version_validation == "METADATA_ONLY_DRIFT"
    assert "selected_version:METADATA_ONLY_DRIFT" in eligibility.backend_drift_diagnostics
    assert (
        "selected_version:METADATA_ONLY_DRIFT:FUTURE_ATTESTATION_REFRESH_REQUIRED"
        in eligibility.backend_drift_diagnostics
    )
    assert eligibility.pinned_executable_validation == "NO_DRIFT"
    assert eligibility.pinned_launcher_validation == ("NO_DRIFT",)
    assert eligibility.catalog_validation == "NO_DRIFT"
    assert all(value in {"NO_DRIFT", "NOT_APPLICABLE"} for value in eligibility.wrapper_chain_drift)
    # The behavioral verifier actually ran, its evidence is durable, and the
    # checkpoint followed: no ValueError from the stale selected-root mtime.
    assert outcome.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS
    binding = h.store.load_request_structural(h.session_id, CANARY_GATE_ID, 0)
    behavioral = load_behavioral_verifier(request=binding, execution_store=h.store)
    assert behavioral.exit_code == 0 and not behavioral.timed_out
    assert h.store.has_behavioral_evidence(h.session_id, CANARY_GATE_ID, 0)
    assert h.store.has_capture_attempt(h.session_id, CANARY_GATE_ID, 0)
    assert outcome.checkpoint_fingerprint is not None
    assert len(h.runner.invocations) == 1
    replay = h.coordinator.run(session_id=h.session_id)
    assert replay.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS
    assert len(h.runner.invocations) == 1


def test_running_marker_before_spawn_still_blocks_exact_strict_attestation(tmp_path: Path):
    h, _ = _wrapper_chain_harness(tmp_path)
    request, prompt = _request(h)
    h.store.create_request(request)
    _create_running_marker(Path(h.attestation.selected_version_root))
    with pytest.raises(NativeEvidenceInvalid):
        h.executor.execute(
            request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
            allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
            artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
            required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
        )
    assert h.runner.invocations == []
    assert not h.store.has_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)


def test_behavioral_entry_without_persisted_eligibility_fails_closed(tmp_path: Path):
    h, _ = _wrapper_chain_harness(tmp_path)
    request, _ = _request(h)
    h.store.create_request(request)
    with pytest.raises(NativeEvidenceInvalid, match="persisted post-run eligibility decision"):
        run_behavioral_verifier(request=request, execution_store=h.store)
    assert not h.store.has_behavioral_evidence(h.session_id, CANARY_GATE_ID, 0)


def test_behavioral_entry_rejects_request_unbound_to_durable_canonical_bytes(tmp_path: Path):
    h, _ = _wrapper_chain_harness(tmp_path)
    request, _ = _request(h)
    h.store.create_request(request)
    lying = replace(request, timeout_seconds=31)
    with pytest.raises((NativeEvidenceInvalid, ValueError), match="fingerprint mismatch"):
        run_behavioral_verifier(request=lying, execution_store=h.store)
    refingerprinted = replace(lying, request_fingerprint="0" * 64)
    refingerprinted = replace(refingerprinted, request_fingerprint=fingerprint(refingerprinted._body()))
    with pytest.raises(NativeEvidenceInvalid, match="differs from the durable native request"):
        run_behavioral_verifier(request=refingerprinted, execution_store=h.store)
    assert not h.store.has_behavioral_evidence(h.session_id, CANARY_GATE_ID, 0)


def test_behavioral_entry_rejects_tampered_eligibility_proof(tmp_path: Path):
    h, _ = _wrapper_chain_harness(tmp_path)
    selected = Path(h.attestation.selected_version_root)
    h.runner.after_start = lambda: _create_running_marker(selected)
    request, prompt = _request(h)
    h.store.create_request(request)
    issued = h.executor.execute(
        request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
        allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
        artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
        required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
    )
    h.store.write_result(issued)
    path = h.store.directory / f"{h.session_id}.{CANARY_GATE_ID}.attempt-0.native-execution-eligibility.json"
    assert path.is_file()
    payload = json.loads(path.read_bytes().decode("utf-8"))
    payload["eligible"] = False
    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
    path.write_bytes(json.dumps(payload, sort_keys=True).encode("utf-8"))
    with pytest.raises(NativeEvidenceInvalid):
        run_behavioral_verifier(request=request, execution_store=h.store)
    assert not h.store.has_behavioral_evidence(h.session_id, CANARY_GATE_ID, 0)


def test_behavioral_entry_defers_to_persisted_post_run_rejection(tmp_path: Path):
    h, _ = _wrapper_chain_harness(tmp_path)
    launcher = Path(h.attestation.launcher_prefix[0].canonical_path)
    original = launcher.read_bytes()
    h.runner.after_start = lambda: launcher.write_bytes(original + b"// drift\n")
    request, prompt = _request(h)
    h.store.create_request(request)
    with pytest.raises(NativeResultIneligible):
        h.executor.execute(
            request=request, prompt=prompt, source_repository=h.source, canary_parent=h.root,
            allowed_parent_children=frozenset({h.work.name}), evidence_store_root=h.store.directory,
            artifact_directory=h.store.artifact_directory, required_commit_message=REQUIRED_COMMIT_MESSAGE,
            required_material_paths=EXPECTED_MATERIAL_PATHS, execution_store=h.store,
        )
    eligibility = h.store.load_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)
    assert not eligibility.eligible and "post_run_backend_drift" in eligibility.ineligibility_reasons
    # Restore the launcher bytes so a stale strict live re-attestation would
    # now pass again: only the persisted rejection may decide.
    launcher.write_bytes(original)
    with pytest.raises(NativeEvidenceInvalid, match="persisted post-run eligibility rejects"):
        run_behavioral_verifier(request=request, execution_store=h.store)
    assert not h.store.has_behavioral_evidence(h.session_id, CANARY_GATE_ID, 0)


@pytest.mark.parametrize(
    "drift_kind",
    [
        "non_isolated_marker_plus_wrapper_mtime",
        "non_isolated_marker_plus_manifest_mtime",
        "inventory_only_change",
        "selected_root_identity",
        "missing_node_component",
    ],
)
def test_blocking_backend_drift_classes_remain_refused_with_truthful_terminal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, drift_kind: str):
    h, _ = _wrapper_chain_harness(tmp_path)
    root = Path(h.attestation.command_resolution.wrapper_root)
    selected = Path(h.attestation.selected_version_root)

    def mutate() -> None:
        if drift_kind == "non_isolated_marker_plus_wrapper_mtime":
            _create_running_marker(selected)
            _bump_directory_mtime(root / "cursor-agent.cmd")
        elif drift_kind == "non_isolated_marker_plus_manifest_mtime":
            _create_running_marker(selected)
            _bump_directory_mtime(selected / "package.json")
        elif drift_kind == "inventory_only_change":
            (root / "versions" / "2020.01.01-00000000").mkdir()
        elif drift_kind == "selected_root_identity":
            duplicate = root / "versions" / "duplicate-holding"
            shutil.copytree(selected, duplicate)
            shutil.rmtree(selected)
            os.replace(duplicate, selected)
        else:
            (selected / "node.exe").unlink()

    h.runner.after_start = mutate
    calls = {"behavioral": 0, "capture": 0}
    monkeypatch.setattr(
        "admissible.delegated_gate.native_canary.run_behavioral_verifier",
        lambda **_: calls.__setitem__("behavioral", calls["behavioral"] + 1) or (_ for _ in ()).throw(AssertionError("behavioral verifier must be unreachable")),
    )
    monkeypatch.setattr(
        "admissible.delegated_gate.native_canary.capture_checkpoint",
        lambda **_: calls.__setitem__("capture", calls["capture"] + 1) or (_ for _ in ()).throw(AssertionError("checkpoint must be unreachable")),
    )
    outcome = h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED
    eligibility = h.store.load_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)
    assert not eligibility.eligible and "post_run_backend_drift" in eligibility.ineligibility_reasons
    if drift_kind == "non_isolated_marker_plus_wrapper_mtime":
        assert eligibility.selected_version_validation == "METADATA_ONLY_DRIFT"
        assert eligibility.wrapper_chain_drift[0] == "METADATA_ONLY_DRIFT"
        assert (
            "selected_version:METADATA_ONLY_DRIFT:FUTURE_ATTESTATION_REFRESH_REQUIRED"
            not in eligibility.backend_drift_diagnostics
        )
    elif drift_kind == "non_isolated_marker_plus_manifest_mtime":
        # The sharpest non-widening case: a second metadata-only slot inside
        # the selected version root must defeat the carve-out even though the
        # command resolution and every content hash remain untouched.
        assert eligibility.selected_version_validation == "METADATA_ONLY_DRIFT"
        assert eligibility.wrapper_chain_drift[2] == "METADATA_ONLY_DRIFT"
        assert (
            "selected_version:METADATA_ONLY_DRIFT:FUTURE_ATTESTATION_REFRESH_REQUIRED"
            not in eligibility.backend_drift_diagnostics
        )
    elif drift_kind == "inventory_only_change":
        assert eligibility.catalog_validation == "VERSION_INVENTORY_DRIFT"
        assert eligibility.selected_version_validation == "NO_DRIFT"
    elif drift_kind == "selected_root_identity":
        assert eligibility.selected_version_validation == "IDENTITY_ONLY_DRIFT"
    else:
        # A deleted component is observed through the safe-file boundary, so
        # it is recorded as MISSING or UNREADABLE; both remain blocking.
        assert eligibility.pinned_executable_validation in {"MISSING", "UNREADABLE"}
    terminal = h.store.load_terminal(h.session_id, CANARY_GATE_ID, 0)
    assert terminal.failure_category == "result_ineligible"
    assert "post_run_backend_drift" in terminal.diagnostic
    assert calls == {"behavioral": 0, "capture": 0}
    assert not h.store.has_behavioral_evidence(h.session_id, CANARY_GATE_ID, 0)
    assert not h.store.has_result(h.session_id, CANARY_GATE_ID, 0)
    assert classify_recovery(_classifier_envelope(eligibility), control_state="TERMINAL") == CLASSIFICATION_REAUTHORIZATION_REQUIRED


def test_ordinary_behavioral_failure_stays_ordinary_and_not_backend_recoverable(tmp_path: Path):
    h, _ = _wrapper_chain_harness(tmp_path)
    selected = Path(h.attestation.selected_version_root)
    h.runner.mutation = _mutate_without_feature
    h.runner.after_start = lambda: _create_running_marker(selected)
    outcome = h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED
    eligibility = h.store.load_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)
    assert eligibility.eligible and eligibility.ineligibility_reasons == ()
    assert eligibility.selected_version_validation == "METADATA_ONLY_DRIFT"
    binding = h.store.load_request_structural(h.session_id, CANARY_GATE_ID, 0)
    behavioral = load_behavioral_verifier(request=binding, execution_store=h.store)
    assert behavioral.exit_code not in (0, None)
    terminal = h.store.load_terminal(h.session_id, CANARY_GATE_ID, 0)
    assert terminal.failure_category == "pre_capture_eligibility"
    assert "behavioral verifier did not pass" in terminal.diagnostic
    assert classify_recovery(_classifier_envelope(eligibility), control_state="TERMINAL") == CLASSIFICATION_NOT_RECOVERABLE


def test_post_run_backend_drift_terminal_remains_governed_rerun_recoverable(tmp_path: Path):
    h, _ = _wrapper_chain_harness(tmp_path)
    executable = Path(h.attestation.executable.canonical_path)
    h.runner.after_start = lambda: executable.write_bytes(executable.read_bytes() + b"x")
    outcome = h.coordinator.run(session_id=h.session_id)
    assert outcome.status is NativeCanaryStatus.PRECAPTURE_ELIGIBILITY_FAILED
    eligibility = h.store.load_execution_eligibility(h.session_id, CANARY_GATE_ID, 0)
    assert eligibility.pinned_executable_validation == "CONTENT_DRIFT"
    assert "post_run_backend_drift" in eligibility.ineligibility_reasons
    envelope = _classifier_envelope(eligibility)
    assert classify_recovery(envelope, control_state="TERMINAL") == CLASSIFICATION_REAUTHORIZATION_REQUIRED
    assert classify_recovery(envelope, control_state="TERMINAL", parent_is_recovery_child=True) == CLASSIFICATION_NOT_RECOVERABLE
