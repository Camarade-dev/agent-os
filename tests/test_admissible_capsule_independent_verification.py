"""Provider-free tests for independent checkpoint/behavioral verification.

These construct `CheckpointResult`/`BehaviorResult` values directly; no
subprocess, provider, or Docker container is invoked.
"""

from __future__ import annotations

import pytest

from admissible.capsule.verification import (
    BehavioralVerifierIdentity,
    BehaviorRefusalCode,
    BehaviorResult,
    ByteHashPair,
    CheckpointIdentity,
    CheckpointRefusalCode,
    CheckpointResult,
    CommandCapture,
    IndependentVerificationResult,
    VerificationCopy,
    require_independent_copies,
)


ZERO = "0" * 64
ONE = "1" * 64


def _capture(*, exit_code=0, timed_out=False, truncated=False) -> CommandCapture:
    return CommandCapture.create(
        argv=("./verify.sh",),
        exit_code=exit_code,
        timed_out=timed_out,
        stdout_sha256=ZERO,
        stderr_sha256=ZERO,
        stdout_truncated=truncated,
        stderr_truncated=False,
    )


def _checkpoint_copy(copy_id: str = "checkpoint-copy-1", root: str = ZERO) -> VerificationCopy:
    return VerificationCopy.create(copy_id=copy_id, purpose="checkpoint", root_fingerprint=root)


def _behavior_copy(copy_id: str = "behavior-copy-1", root: str = ZERO) -> VerificationCopy:
    return VerificationCopy.create(copy_id=copy_id, purpose="behavior", root_fingerprint=root)


def _checkpoint_pass() -> CheckpointResult:
    return CheckpointResult(
        identity=CheckpointIdentity.create(tree_hash=ZERO),
        copy=_checkpoint_copy(),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ZERO).validated(),
        passed=True,
        refusal_code=None,
    ).validated()


def _behavior_pass() -> BehaviorResult:
    return BehaviorResult(
        identity=BehavioralVerifierIdentity.create(verifier_source_sha256=ONE),
        copy=_behavior_copy(),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ZERO).validated(),
        passed=True,
        refusal_code=None,
    ).validated()


def test_checkpoint_pass_requires_consistent_process_evidence():
    with pytest.raises(ValueError):
        CheckpointResult(
            identity=CheckpointIdentity.create(tree_hash=ZERO),
            copy=_checkpoint_copy(),
            capture=_capture(exit_code=1),
            byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ZERO).validated(),
            passed=True,
            refusal_code=None,
        ).validated()


def test_checkpoint_refusal_requires_a_refusal_code():
    with pytest.raises(ValueError):
        CheckpointResult(
            identity=CheckpointIdentity.create(tree_hash=ZERO),
            copy=_checkpoint_copy(),
            capture=_capture(exit_code=1),
            byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ZERO).validated(),
            passed=False,
            refusal_code=None,
        ).validated()


def test_checkpoint_refused_on_tree_mutation():
    result = CheckpointResult(
        identity=CheckpointIdentity.create(tree_hash=ZERO),
        copy=_checkpoint_copy(),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ONE).validated(),
        passed=False,
        refusal_code=CheckpointRefusalCode.TREE_MUTATED,
    ).validated()
    assert result.passed is False
    assert result.refusal_code == CheckpointRefusalCode.TREE_MUTATED


def test_behavior_refused_after_checkpoint_pass_does_not_flip_admissibility():
    checkpoint = _checkpoint_pass()
    behavior = BehaviorResult(
        identity=BehavioralVerifierIdentity.create(verifier_source_sha256=ONE),
        copy=_behavior_copy(),
        capture=_capture(exit_code=1),
        byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ZERO).validated(),
        passed=False,
        refusal_code=BehaviorRefusalCode.ASSERTION_FAILED,
    ).validated()
    result = IndependentVerificationResult(checkpoint=checkpoint, behavior=behavior).validated()
    assert result.checkpoint.passed is True
    assert result.behavior.passed is False
    assert result.admissible is False


def test_checkpoint_pass_alone_is_never_admissible():
    result = IndependentVerificationResult(checkpoint=_checkpoint_pass(), behavior=None).validated()
    assert result.admissible is False


def test_both_passing_is_admissible():
    result = IndependentVerificationResult(checkpoint=_checkpoint_pass(), behavior=_behavior_pass()).validated()
    assert result.admissible is True


def test_shared_copy_identity_between_checkpoint_and_behavior_is_rejected():
    checkpoint_copy = _checkpoint_copy(copy_id="shared-id")
    behavior_copy = VerificationCopy.create(copy_id="shared-id", purpose="behavior", root_fingerprint=ZERO)
    with pytest.raises(ValueError):
        require_independent_copies(checkpoint_copy, behavior_copy)


def test_independent_verification_result_enforces_copy_independence():
    checkpoint = CheckpointResult(
        identity=CheckpointIdentity.create(tree_hash=ZERO),
        copy=_checkpoint_copy(copy_id="dup"),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ZERO).validated(),
        passed=True,
        refusal_code=None,
    ).validated()
    behavior = BehaviorResult(
        identity=BehavioralVerifierIdentity.create(verifier_source_sha256=ONE),
        copy=VerificationCopy.create(copy_id="dup", purpose="behavior", root_fingerprint=ZERO),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ZERO).validated(),
        passed=True,
        refusal_code=None,
    ).validated()
    with pytest.raises(ValueError):
        IndependentVerificationResult(checkpoint=checkpoint, behavior=behavior).validated()


def test_checkpoint_result_round_trips_through_evidence_only_dict():
    checkpoint = _checkpoint_pass()
    reconstructed = CheckpointResult.from_dict(checkpoint.to_dict())
    assert reconstructed == checkpoint


def test_behavior_result_round_trips_through_evidence_only_dict():
    behavior = _behavior_pass()
    reconstructed = BehaviorResult.from_dict(behavior.to_dict())
    assert reconstructed == behavior


def test_behavior_result_rejects_a_checkpoint_purpose_copy():
    with pytest.raises(ValueError):
        BehaviorResult(
            identity=BehavioralVerifierIdentity.create(verifier_source_sha256=ONE),
            copy=_checkpoint_copy(),
            capture=_capture(),
            byte_hashes=ByteHashPair(before_hash=ZERO, after_hash=ZERO).validated(),
            passed=True,
            refusal_code=None,
        ).validated()
