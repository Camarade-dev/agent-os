"""Provider-free tests for independent checkpoint/behavioral verification.

These construct `CheckpointResult`/`BehaviorResult` values directly; no
subprocess, provider, or Docker container is invoked.
"""

from __future__ import annotations

import pytest

from admissible.capsule.common import fingerprint
from admissible.capsule.intake import (
    AcceptedMaterialIdentity,
    IntakeEvidence,
    IntakeFileRecord,
    IntakePublicationState,
)
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


def _material(content_hash: str = ONE) -> AcceptedMaterialIdentity:
    record = IntakeFileRecord(
        relative_path="index.html",
        size=12,
        sha256=content_hash,
        git_mode="100644",
    ).validated()
    evidence = IntakeEvidence.create(
        authority_fingerprint="a" * 64,
        ruling="ACCEPTED",
        rejection_reasons=(),
        files=(record,),
        aggregate_fingerprint=fingerprint([record.to_dict()]),
        publication_state=IntakePublicationState.ACCEPTED_INTAKE_PUBLISHED,
    )
    return AcceptedMaterialIdentity.from_intake_evidence(evidence)


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


def _checkpoint_copy(copy_id: str = "checkpoint-copy-1", root: str | None = None) -> VerificationCopy:
    root = root or _material().canonical_manifest_fingerprint
    return VerificationCopy.create(copy_id=copy_id, purpose="checkpoint", root_fingerprint=root)


def _behavior_copy(copy_id: str = "behavior-copy-1", root: str | None = None) -> VerificationCopy:
    root = root or _material().canonical_manifest_fingerprint
    return VerificationCopy.create(copy_id=copy_id, purpose="behavior", root_fingerprint=root)


def _checkpoint_pass() -> CheckpointResult:
    material = _material()
    root = material.canonical_manifest_fingerprint
    return CheckpointResult(
        accepted_material=material,
        identity=CheckpointIdentity.create(tree_hash=root),
        copy=_checkpoint_copy(root=root),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=root, after_hash=root).validated(),
        passed=True,
        refusal_code=None,
    ).validated()


def _behavior_pass() -> BehaviorResult:
    material = _material()
    root = material.canonical_manifest_fingerprint
    return BehaviorResult(
        accepted_material=material,
        identity=BehavioralVerifierIdentity.create(verifier_source_sha256=ONE),
        copy=_behavior_copy(root=root),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=root, after_hash=root).validated(),
        passed=True,
        refusal_code=None,
    ).validated()


def test_checkpoint_pass_requires_consistent_process_evidence():
    material = _material()
    root = material.canonical_manifest_fingerprint
    with pytest.raises(ValueError):
        CheckpointResult(
            accepted_material=material,
            identity=CheckpointIdentity.create(tree_hash=root),
            copy=_checkpoint_copy(root=root),
            capture=_capture(exit_code=1),
            byte_hashes=ByteHashPair(before_hash=root, after_hash=root).validated(),
            passed=True,
            refusal_code=None,
        ).validated()


def test_checkpoint_refusal_requires_a_refusal_code():
    material = _material()
    root = material.canonical_manifest_fingerprint
    with pytest.raises(ValueError):
        CheckpointResult(
            accepted_material=material,
            identity=CheckpointIdentity.create(tree_hash=root),
            copy=_checkpoint_copy(root=root),
            capture=_capture(exit_code=1),
            byte_hashes=ByteHashPair(before_hash=root, after_hash=root).validated(),
            passed=False,
            refusal_code=None,
        ).validated()


def test_checkpoint_refused_on_tree_mutation():
    material = _material()
    root = material.canonical_manifest_fingerprint
    result = CheckpointResult(
        accepted_material=material,
        identity=CheckpointIdentity.create(tree_hash=root),
        copy=_checkpoint_copy(root=root),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=root, after_hash=ONE).validated(),
        passed=False,
        refusal_code=CheckpointRefusalCode.TREE_MUTATED,
    ).validated()
    assert result.passed is False
    assert result.refusal_code == CheckpointRefusalCode.TREE_MUTATED


def test_behavior_refused_after_checkpoint_pass_does_not_flip_admissibility():
    checkpoint = _checkpoint_pass()
    root = checkpoint.accepted_material.canonical_manifest_fingerprint
    behavior = BehaviorResult(
        accepted_material=checkpoint.accepted_material,
        identity=BehavioralVerifierIdentity.create(verifier_source_sha256=ONE),
        copy=_behavior_copy(root=root),
        capture=_capture(exit_code=1),
        byte_hashes=ByteHashPair(before_hash=root, after_hash=root).validated(),
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
    root = _material().canonical_manifest_fingerprint
    checkpoint_copy = _checkpoint_copy(copy_id="shared-id", root=root)
    behavior_copy = VerificationCopy.create(copy_id="shared-id", purpose="behavior", root_fingerprint=root)
    with pytest.raises(ValueError):
        require_independent_copies(checkpoint_copy, behavior_copy)


def test_independent_verification_result_enforces_copy_independence():
    material = _material()
    root = material.canonical_manifest_fingerprint
    checkpoint = CheckpointResult(
        accepted_material=material,
        identity=CheckpointIdentity.create(tree_hash=root),
        copy=_checkpoint_copy(copy_id="dup", root=root),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=root, after_hash=root).validated(),
        passed=True,
        refusal_code=None,
    ).validated()
    behavior = BehaviorResult(
        accepted_material=material,
        identity=BehavioralVerifierIdentity.create(verifier_source_sha256=ONE),
        copy=VerificationCopy.create(copy_id="dup", purpose="behavior", root_fingerprint=root),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=root, after_hash=root).validated(),
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
    material = _material()
    root = material.canonical_manifest_fingerprint
    with pytest.raises(ValueError):
        BehaviorResult(
            accepted_material=material,
            identity=BehavioralVerifierIdentity.create(verifier_source_sha256=ONE),
            copy=_checkpoint_copy(root=root),
            capture=_capture(),
            byte_hashes=ByteHashPair(before_hash=root, after_hash=root).validated(),
            passed=True,
            refusal_code=None,
        ).validated()


def test_checkpoint_copy_identity_mismatch_is_reachable_and_refused():
    material = _material()
    wrong_root = "f" * 64
    result = CheckpointResult(
        accepted_material=material,
        identity=CheckpointIdentity.create(tree_hash=wrong_root),
        copy=_checkpoint_copy(root=wrong_root),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=wrong_root, after_hash=wrong_root).validated(),
        passed=False,
        refusal_code=CheckpointRefusalCode.COPY_IDENTITY_MISMATCH,
    ).validated()
    assert result.refusal_code is CheckpointRefusalCode.COPY_IDENTITY_MISMATCH


def test_behavior_copy_with_different_root_is_refused():
    material = _material()
    wrong_root = "e" * 64
    result = BehaviorResult(
        accepted_material=material,
        identity=BehavioralVerifierIdentity.create(verifier_source_sha256=ONE),
        copy=_behavior_copy(root=wrong_root),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=wrong_root, after_hash=wrong_root).validated(),
        passed=False,
        refusal_code=BehaviorRefusalCode.COPY_IDENTITY_MISMATCH,
    ).validated()
    assert result.passed is False


def test_behavior_mutation_after_verification_is_refused():
    material = _material()
    root = material.canonical_manifest_fingerprint
    result = BehaviorResult(
        accepted_material=material,
        identity=BehavioralVerifierIdentity.create(verifier_source_sha256=ONE),
        copy=_behavior_copy(root=root),
        capture=_capture(),
        byte_hashes=ByteHashPair(before_hash=root, after_hash="d" * 64).validated(),
        passed=False,
        refusal_code=BehaviorRefusalCode.TREE_MUTATED,
    ).validated()
    assert result.byte_hashes.mutated is True
