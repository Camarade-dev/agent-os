"""Provider-free lifecycle/reducer tests covering the capsule acceptance boundary.

This exercises the full CAPSULE_READY -> ... -> ACCEPTED/REFUSED/FAILED
reducer with real (but fake/disposable) intake trees, verification results,
and Git finalizer repositories. No provider, model, Docker, or network
transport is ever invoked.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from admissible.capsule.backend import CapsuleAuthority
from admissible.capsule.events import (
    BehaviorVerified,
    CapsuleExecutionStarted,
    CheckpointVerificationStarted,
    CheckpointVerified,
    FailureCode,
    FinalizationCompleted,
    FinalizationStarted,
    IntakeEvaluated,
    IntakeStarted,
    ProviderOutputFrozen,
    RefusalReason,
    SessionFailed,
)
from admissible.capsule.finalizer import (
    AcceptedBlob,
    AdmissibleFinalizer,
    FinalizationOutcome,
    initialize_disposable_repository,
)
from admissible.capsule.intake import NEON_RELAY_AUTHORITY, RejectionCode, validate_and_copy
from admissible.capsule.models import (
    ByteTreeObservation,
    CleanupResult,
    ObservedEntry,
    ProcessResult,
    ProviderCompletionClaim,
    ProviderOutput,
    TransportResult,
    WorkspaceReference,
)
from admissible.capsule.reducer import IllegalTransition, reduce
from admissible.capsule.state import Phase, new_session_state
from admissible.capsule.verification import (
    BehavioralVerifierIdentity,
    BehaviorRefusalCode,
    BehaviorResult,
    ByteHashPair,
    CheckpointIdentity,
    CheckpointRefusalCode,
    CheckpointResult,
    CommandCapture,
    VerificationCopy,
)


ZERO = "0" * 64
ONE = "1" * 64
PARENT_IDENTITY = {
    "author_name": "Capsule Fixture",
    "author_email": "capsule-fixture@example.invalid",
    "author_date": "1999-12-31T00:00:00+00:00",
    "committer_name": "Capsule Fixture",
    "committer_email": "capsule-fixture@example.invalid",
    "committer_date": "1999-12-31T00:00:00+00:00",
}
MESSAGE = "feat: build playable Neon Relay browser game\n"


def _authority() -> CapsuleAuthority:
    return CapsuleAuthority.create(
        backend_kind="linux_capsule_v1",
        capsule_image_identity="sha256:" + "a" * 64,
        mission_fingerprint="b" * 64,
    )


def _provider_output(authority: CapsuleAuthority) -> ProviderOutput:
    workspace = WorkspaceReference.create(
        workspace_id="workspace-001",
        capsule_authority_fingerprint=authority.authority_fingerprint,
        host_owned=False,
    )
    observation = ByteTreeObservation.create(
        entries=(ObservedEntry(relative_path="index.html", kind="regular", size=12, sha256="c" * 64),)
    )
    return ProviderOutput.create(
        capsule_authority_fingerprint=authority.authority_fingerprint,
        workspace=workspace,
        observation=observation,
        process_result=ProcessResult(
            schema_version="admissible_capsule_process_result_v1", exit_code=0, timed_out=False, signal=None
        ),
        transport_result=TransportResult(
            schema_version="admissible_capsule_transport_result_v1",
            transport_kind="loopback_relay_v1",
            connected=True,
            closed_cleanly=True,
        ),
        cleanup_result=CleanupResult(
            schema_version="admissible_capsule_cleanup_result_v1", workspace_removed=True, processes_reaped=True
        ),
        completion_claim=ProviderCompletionClaim(
            schema_version="admissible_capsule_provider_completion_claim_v1",
            claimed_complete=True,
            claim_text="provider claims completion",
        ),
    )


def _healthy_intake_tree(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "LOCAL_DEV.md").write_bytes(b"# dev notes\n")
    (root / "index.html").write_bytes(b"<html></html>\n")
    (root / "package.json").write_bytes(b'{"name": "neon-relay"}\n')
    (root / "style.css").write_bytes(b"body {}\n")
    for name in NEON_RELAY_AUTHORITY.authority_paths:
        if name.startswith("src/") or name.startswith("test/"):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"// {name}\n".encode())


def _capture(*, exit_code=0, timed_out=False) -> CommandCapture:
    return CommandCapture.create(
        argv=("./verify.sh",),
        exit_code=exit_code,
        timed_out=timed_out,
        stdout_sha256=ZERO,
        stderr_sha256=ZERO,
        stdout_truncated=False,
        stderr_truncated=False,
    )


def _checkpoint(*, passed: bool, copy_id: str = "checkpoint-copy") -> CheckpointResult:
    if passed:
        return CheckpointResult(
            identity=CheckpointIdentity.create(tree_hash=ZERO),
            copy=VerificationCopy.create(copy_id=copy_id, purpose="checkpoint", root_fingerprint=ZERO),
            capture=_capture(),
            byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ZERO).validated(),
            passed=True,
            refusal_code=None,
        ).validated()
    return CheckpointResult(
        identity=CheckpointIdentity.create(tree_hash=ZERO),
        copy=VerificationCopy.create(copy_id=copy_id, purpose="checkpoint", root_fingerprint=ZERO),
        capture=_capture(exit_code=1),
        byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ZERO).validated(),
        passed=False,
        refusal_code=CheckpointRefusalCode.NONZERO_EXIT,
    ).validated()


def _behavior(*, passed: bool, copy_id: str = "behavior-copy") -> BehaviorResult:
    if passed:
        return BehaviorResult(
            identity=BehavioralVerifierIdentity.create(verifier_source_sha256=ONE),
            copy=VerificationCopy.create(copy_id=copy_id, purpose="behavior", root_fingerprint=ZERO),
            capture=_capture(),
            byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ZERO).validated(),
            passed=True,
            refusal_code=None,
        ).validated()
    return BehaviorResult(
        identity=BehavioralVerifierIdentity.create(verifier_source_sha256=ONE),
        copy=VerificationCopy.create(copy_id=copy_id, purpose="behavior", root_fingerprint=ZERO),
        capture=_capture(exit_code=1),
        byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ZERO).validated(),
        passed=False,
        refusal_code=BehaviorRefusalCode.ASSERTION_FAILED,
    ).validated()


def _drive_to_finalization_ready(tmp_path: Path):
    authority = _authority()
    state = new_session_state(session_id="capsule-session-001", capsule_authority=authority)
    state = reduce(state, CapsuleExecutionStarted())
    state = reduce(state, ProviderOutputFrozen(provider_output=_provider_output(authority)))
    state = reduce(state, IntakeStarted())

    source = tmp_path / "provider-workspace"
    _healthy_intake_tree(source)
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "ACCEPTED"
    state = reduce(state, IntakeEvaluated(intake_evidence=evidence))
    state = reduce(state, CheckpointVerificationStarted())
    state = reduce(state, CheckpointVerified(checkpoint_result=_checkpoint(passed=True)))
    state = reduce(state, BehaviorVerified(behavior_result=_behavior(passed=True)))
    assert state.phase == Phase.FINALIZATION_READY
    return state, evidence


def test_happy_path_reaches_accepted_and_publishes_exactly_one_commit(tmp_path: Path):
    state, evidence = _drive_to_finalization_ready(tmp_path)

    repository = tmp_path / "disposable.git"
    parent = initialize_disposable_repository(repository, parent_identity=PARENT_IDENTITY)
    finalizer = AdmissibleFinalizer(repository)

    state = reduce(state, FinalizationStarted())
    assert state.phase == Phase.FINALIZING
    # No durable accepted effect exists yet: the ref is still the parent.
    assert finalizer.current_ref() == parent

    blobs = tuple(
        AcceptedBlob.create(relative_path=record.relative_path, data=(tmp_path / "accepted" / record.relative_path).read_bytes())
        for record in evidence.files
    )
    result = finalizer.finalize(
        parent=parent,
        accepted_blobs=blobs,
        private_index=tmp_path / "private-index",
        message=MESSAGE,
        evidence_is_durable=evidence.published and state.behavior_result.passed,
    )
    assert result.outcome == FinalizationOutcome.PUBLISHED
    state = reduce(state, FinalizationCompleted(finalization_result=result))
    assert state.phase == Phase.ACCEPTED
    assert finalizer.current_ref() == result.commit

    # Evidence-only reconstruction: the durable state dict fully round-trips.
    reconstructed = type(state).from_dict(state.to_dict())
    assert reconstructed == state
    assert reconstructed.phase == Phase.ACCEPTED


def test_terminal_phase_blocks_further_events(tmp_path: Path):
    state, evidence = _drive_to_finalization_ready(tmp_path)
    repository = tmp_path / "disposable.git"
    parent = initialize_disposable_repository(repository, parent_identity=PARENT_IDENTITY)
    finalizer = AdmissibleFinalizer(repository)
    state = reduce(state, FinalizationStarted())

    blobs = tuple(
        AcceptedBlob.create(
            relative_path=record.relative_path, data=(tmp_path / "accepted" / record.relative_path).read_bytes()
        )
        for record in evidence.files
    )
    result = finalizer.finalize(
        parent=parent,
        accepted_blobs=blobs,
        private_index=tmp_path / "term-index",
        message=MESSAGE,
        evidence_is_durable=True,
    )
    state = reduce(state, FinalizationCompleted(finalization_result=result))
    assert state.phase == Phase.ACCEPTED
    with pytest.raises(IllegalTransition):
        reduce(state, FinalizationStarted())


def test_provider_failure_reaches_failed_with_no_evidence(tmp_path: Path):
    authority = _authority()
    state = new_session_state(session_id="capsule-session-002", capsule_authority=authority)
    state = reduce(state, CapsuleExecutionStarted())
    state = reduce(state, SessionFailed(code=FailureCode.PROVIDER_FAILED, detail="provider process crashed"))
    assert state.phase == Phase.FAILED
    assert state.failure_code == FailureCode.PROVIDER_FAILED
    assert state.provider_output is None
    assert state.refusal_reason is None


def test_cleanup_failure_reaches_failed(tmp_path: Path):
    authority = _authority()
    state = new_session_state(session_id="capsule-session-003", capsule_authority=authority)
    state = reduce(state, CapsuleExecutionStarted())
    state = reduce(
        state, SessionFailed(code=FailureCode.CLEANUP_UNCONFIRMED, detail="workspace teardown could not be confirmed")
    )
    assert state.phase == Phase.FAILED
    assert state.failure_code == FailureCode.CLEANUP_UNCONFIRMED


def test_checkpoint_refusal_reaches_refused(tmp_path: Path):
    authority = _authority()
    state = new_session_state(session_id="capsule-session-004", capsule_authority=authority)
    state = reduce(state, CapsuleExecutionStarted())
    state = reduce(state, ProviderOutputFrozen(provider_output=_provider_output(authority)))
    state = reduce(state, IntakeStarted())
    source = tmp_path / "provider-workspace"
    _healthy_intake_tree(source)
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    state = reduce(state, IntakeEvaluated(intake_evidence=evidence))
    state = reduce(state, CheckpointVerificationStarted())
    state = reduce(state, CheckpointVerified(checkpoint_result=_checkpoint(passed=False)))
    assert state.phase == Phase.REFUSED
    assert state.refusal_reason == RefusalReason.CHECKPOINT_REFUSED
    assert state.behavior_result is None


def test_behavioral_refusal_after_checkpoint_pass_reaches_refused_not_accepted(tmp_path: Path):
    authority = _authority()
    state = new_session_state(session_id="capsule-session-005", capsule_authority=authority)
    state = reduce(state, CapsuleExecutionStarted())
    state = reduce(state, ProviderOutputFrozen(provider_output=_provider_output(authority)))
    state = reduce(state, IntakeStarted())
    source = tmp_path / "provider-workspace"
    _healthy_intake_tree(source)
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    state = reduce(state, IntakeEvaluated(intake_evidence=evidence))
    state = reduce(state, CheckpointVerificationStarted())
    state = reduce(state, CheckpointVerified(checkpoint_result=_checkpoint(passed=True)))
    assert state.phase == Phase.VERIFYING_BEHAVIOR
    state = reduce(state, BehaviorVerified(behavior_result=_behavior(passed=False)))
    assert state.phase == Phase.REFUSED
    assert state.refusal_reason == RefusalReason.BEHAVIOR_REFUSED
    assert state.checkpoint_result.passed is True
    assert state.finalization_result is None


def test_intake_rejection_reaches_refused_before_any_verification(tmp_path: Path):
    authority = _authority()
    state = new_session_state(session_id="capsule-session-006", capsule_authority=authority)
    state = reduce(state, CapsuleExecutionStarted())
    state = reduce(state, ProviderOutputFrozen(provider_output=_provider_output(authority)))
    state = reduce(state, IntakeStarted())
    source = tmp_path / "provider-workspace"
    _healthy_intake_tree(source)
    (source / "extra.txt").write_bytes(b"not authorized")
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    state = reduce(state, IntakeEvaluated(intake_evidence=evidence))
    assert state.phase == Phase.REFUSED
    assert state.refusal_reason == RefusalReason.INTAKE_REJECTED
    assert state.checkpoint_result is None
    assert state.behavior_result is None


def test_provider_created_git_state_is_refused_by_canonical_intake(tmp_path: Path):
    """A provider cannot smuggle its own Git repository into acceptance:
    canonical intake's exact authority set has no `.git` entry, so a
    provider-created `.git` directory is refused as an extra path."""

    source = tmp_path / "provider-workspace"
    _healthy_intake_tree(source)
    git_dir = source / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_bytes(b"ref: refs/heads/main\n")
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    codes = {reason.code for reason in evidence.rejection_reasons}
    assert RejectionCode.EXTRA_DIRECTORY in codes or RejectionCode.EXTRA_PATH in codes
    assert not (tmp_path / "accepted").exists()


def test_finalizer_cas_refusal_reaches_failed_not_accepted(tmp_path: Path):
    state, evidence = _drive_to_finalization_ready(tmp_path)
    repository = tmp_path / "disposable.git"
    parent = initialize_disposable_repository(repository, parent_identity=PARENT_IDENTITY)
    finalizer = AdmissibleFinalizer(repository)
    state = reduce(state, FinalizationStarted())

    from admissible.capsule.common import git
    from admissible.capsule.finalizer import _git_environment

    unexpected_tree = git(repository, "show", "-s", "--format=%T", parent).stdout.decode().strip()
    unexpected_identity = dict(PARENT_IDENTITY)
    unexpected_identity["author_date"] = "1999-12-31T00:00:01+00:00"
    unexpected_identity["committer_date"] = "1999-12-31T00:00:01+00:00"
    unexpected_commit = (
        git(
            repository,
            "commit-tree",
            unexpected_tree,
            "-p",
            parent,
            env=_git_environment(unexpected_identity),
            input_bytes=b"unexpected concurrent parent\n",
        )
        .stdout.decode()
        .strip()
    )
    git(repository, "update-ref", finalizer.target_ref, unexpected_commit, parent)

    blobs = tuple(
        AcceptedBlob.create(relative_path=record.relative_path, data=(tmp_path / "accepted" / record.relative_path).read_bytes())
        for record in evidence.files
    )
    result = finalizer.finalize(
        parent=parent,
        accepted_blobs=blobs,
        private_index=tmp_path / "private-index",
        message=MESSAGE,
        evidence_is_durable=True,
    )
    assert result.outcome == FinalizationOutcome.COMPARE_AND_SWAP_REFUSED
    state = reduce(state, FinalizationCompleted(finalization_result=result))
    assert state.phase == Phase.FAILED
    assert state.failure_code == FailureCode.COMPARE_AND_SWAP_REFUSED
    assert finalizer.current_ref() == unexpected_commit


def test_finalizer_crash_before_update_ref_reaches_failed_with_ref_untouched(tmp_path: Path):
    state, evidence = _drive_to_finalization_ready(tmp_path)
    repository = tmp_path / "disposable.git"
    parent = initialize_disposable_repository(repository, parent_identity=PARENT_IDENTITY)
    finalizer = AdmissibleFinalizer(repository)
    state = reduce(state, FinalizationStarted())

    blobs = tuple(
        AcceptedBlob.create(relative_path=record.relative_path, data=(tmp_path / "accepted" / record.relative_path).read_bytes())
        for record in evidence.files
    )
    from admissible.capsule.common import CrashInjected

    with pytest.raises(CrashInjected):
        finalizer.finalize(
            parent=parent,
            accepted_blobs=blobs,
            private_index=tmp_path / "private-index",
            message=MESSAGE,
            evidence_is_durable=True,
            crash_before_update_ref=True,
        )
    assert finalizer.current_ref() == parent
    state = reduce(
        state,
        SessionFailed(
            code=FailureCode.FINALIZER_CRASHED_BEFORE_UPDATE_REF,
            detail="finalizer process crashed before update-ref",
        ),
    )
    assert state.phase == Phase.FAILED
    assert finalizer.current_ref() == parent


def test_idempotent_duplicate_finalization_still_reaches_accepted(tmp_path: Path):
    state, evidence = _drive_to_finalization_ready(tmp_path)
    repository = tmp_path / "disposable.git"
    parent = initialize_disposable_repository(repository, parent_identity=PARENT_IDENTITY)
    finalizer = AdmissibleFinalizer(repository)
    state = reduce(state, FinalizationStarted())

    blobs = tuple(
        AcceptedBlob.create(relative_path=record.relative_path, data=(tmp_path / "accepted" / record.relative_path).read_bytes())
        for record in evidence.files
    )
    first = finalizer.finalize(
        parent=parent, accepted_blobs=blobs, private_index=tmp_path / "index-1", message=MESSAGE, evidence_is_durable=True
    )
    state = reduce(state, FinalizationCompleted(finalization_result=first))
    assert state.phase == Phase.ACCEPTED

    # A second, independent finalizer call against the same repository (as
    # if the transaction were retried) is idempotent at the Git layer.
    second = finalizer.finalize(
        parent=parent, accepted_blobs=blobs, private_index=tmp_path / "index-2", message=MESSAGE, evidence_is_durable=True
    )
    assert second.outcome == FinalizationOutcome.IDEMPOTENT_SAME_ACCEPTED_IDENTITY
    assert second.commit == first.commit
    assert finalizer.current_ref() == first.commit
