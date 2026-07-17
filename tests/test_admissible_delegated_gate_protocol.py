"""Act 1 deterministic tests for the independent delegated-gate protocol core."""

from __future__ import annotations

import ast
import copy
import dataclasses
from dataclasses import FrozenInstanceError
import gc
import hashlib
import json
import os
from pathlib import Path
import pickle
import stat
import subprocess
import sys
import weakref

import pytest

import admissible.delegated_gate as delegated_gate_package
from admissible.delegated_gate.durability import (
    PlatformDurabilityAdapter,
    PublicationMetadataDurability,
    PublicationVisibleButMetadataUncertain,
)

from admissible.delegated_gate import (
    ArtifactReference,
    AtomicDelegatedSessionStore,
    AuditFinding,
    AuditStarted,
    AuditVerdict,
    AuditVerdictRecorded,
    Checkpoint,
    CheckpointCaptureError,
    CheckpointRecorded,
    CommittedButDurabilityUncertain,
    EvidenceKind,
    EvidenceStatus,
    FindingSeverity,
    FixtureAuditor,
    GateAdvanced,
    GateClause,
    GateContract,
    GateExecutionStarted,
    GatePlan,
    GitEvidence,
    HumanBoundaryReason,
    HumanDisposition,
    HumanDispositionRecorded,
    IllegalTransition,
    InvalidSuccessorError,
    Mission,
    PersistedStateInvalid,
    Phase,
    RepairExecutionStarted,
    StaleRevisionError,
    TreeEvidence,
    Verdict,
    VerificationCommand,
    capture_checkpoint,
    new_session_state,
    reduce,
    validate_state,
)
from admissible.delegated_gate.canonical import fingerprint
from admissible.delegated_gate import checkpoint as checkpoint_module


def sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def mission() -> Mission:
    return Mission.create(
        mission_id="build-week",
        specification="Build the approved local feature through three independent gates.",
    )


def gate(
    gate_id: str,
    *,
    repair_budget: int = 1,
    command: VerificationCommand | None = None,
) -> GateContract:
    required = (EvidenceKind.TARGET_TREE, EvidenceKind.GIT_STATE)
    commands: tuple[VerificationCommand, ...] = ()
    if command is not None:
        required += (EvidenceKind.VERIFICATION_COMMAND,)
        commands = (command,)
    return GateContract.create(
        gate_id=gate_id,
        objective=f"Complete objective for {gate_id}",
        clauses=(
            GateClause(clause_id=f"{gate_id}.c1", text="The material output is correct."),
            GateClause(clause_id=f"{gate_id}.c2", text="Required verification passes."),
        ),
        required_evidence_kinds=required,
        checkpoint_verification_commands=commands,
        repair_budget=repair_budget,
    )


def plan(count: int = 3, *, build_week: bool = True) -> GatePlan:
    gates = tuple(gate(f"gate-{index}") for index in range(1, count + 1))
    if build_week:
        return GatePlan.create_build_week(mission=mission(), ordered_gate_contracts=gates)
    return GatePlan.create(mission=mission(), ordered_gate_contracts=gates)


def state_with_plan(gate_plan: GatePlan | None = None, *, session_id: str = "session-1"):
    selected = gate_plan or plan()
    return new_session_state(session_id=session_id, mission=mission(), gate_plan=selected)


def state_for_gate(*, session_id: str, gate_contract: GateContract):
    selected_mission = mission()
    return new_session_state(
        session_id=session_id,
        mission=selected_mission,
        gate_plan=GatePlan.create(
            mission=selected_mission,
            ordered_gate_contracts=(gate_contract,),
        ),
    )


def plain_checkpoint_for(state, *, attempt: int = 0, gate_id: str | None = None, seed: str = "tree"):
    """Test-only model fixture; production reducer admission must reject it."""

    selected_gate = gate_id or state.current_gate.gate_id
    tree_hash = sha(seed)
    head = "a" * 40
    provisional = Checkpoint(
        schema_version="admissible_delegated_checkpoint_v1",
        session_id=state.session_id,
        gate_id=selected_gate,
        execution_attempt_index=attempt,
        material_tree_hash=tree_hash,
        git_head=head,
        git_worktree_status="",
        evidence_records=(
            TreeEvidence(
                evidence_id="target-tree",
                kind=EvidenceKind.TARGET_TREE,
                status=EvidenceStatus.OBSERVED,
                tree_hash=tree_hash,
                file_count=1,
            ).validated(),
            GitEvidence(
                evidence_id="git-state",
                kind=EvidenceKind.GIT_STATE,
                status=EvidenceStatus.OBSERVED,
                head=head,
                porcelain_status="",
            ).validated(),
        ),
        artifact_references=(),
        checkpoint_fingerprint="0" * 64,
    )
    return dataclasses.replace(
        provisional,
        checkpoint_fingerprint=fingerprint(provisional._body()),
    ).validated()


def capture_result_for(
    state,
    tmp_path: Path,
    *,
    attempt: int = 0,
    gate_id: str | None = None,
    seed: str = "tree",
):
    selected_gate_id = gate_id or state.current_gate.gate_id
    selected_gate = next(
        gate_contract
        for gate_contract in state.gate_plan.ordered_gate_contracts
        if gate_contract.gate_id == selected_gate_id
    )
    root = tmp_path / f"capture-{len(list(tmp_path.iterdir()))}"
    root.mkdir()
    repo = _init_git_repo(root)
    (repo / "material-marker.txt").write_text(seed, encoding="utf-8")
    return capture_checkpoint(
        repository=repo,
        artifact_directory=root / "artifacts",
        session_id=state.session_id,
        gate_contract=selected_gate,
        execution_attempt_index=attempt,
    )


def finding(
    checkpoint: Checkpoint,
    *,
    finding_id: str = "finding-1",
    clause_id: str | None = None,
    human: bool = False,
) -> AuditFinding:
    return AuditFinding(
        finding_id=finding_id,
        gate_id=checkpoint.gate_id,
        checkpoint_fingerprint=checkpoint.checkpoint_fingerprint,
        cited_gate_clause_id=clause_id or f"{checkpoint.gate_id}.c1",
        severity=FindingSeverity.BLOCKING,
        observed_defect="Observed output does not satisfy the cited clause.",
        supporting_evidence_references=("target-tree",),
        bounded_repair_surface=() if human else ("src/approved-surface.py",),
        requires_human_escalation=human,
    ).validated()


def verdict_for(
    checkpoint: Checkpoint,
    verdict: Verdict,
    *,
    findings: tuple[AuditFinding, ...] = (),
) -> AuditVerdict:
    return AuditVerdict.create(
        session_id=checkpoint.session_id,
        gate_id=checkpoint.gate_id,
        checkpoint_fingerprint=checkpoint.checkpoint_fingerprint,
        auditor_invocation_identity=f"audit-{checkpoint.gate_id}-{checkpoint.execution_attempt_index}",
        verdict=verdict,
        findings=findings,
    )


def start_audit(state, tmp_path: Path, capture_result=None):
    result = capture_result or capture_result_for(state, tmp_path)
    state = reduce(state, GateExecutionStarted(state.current_gate.gate_id))
    state = reduce(state, CheckpointRecorded(result))
    cp = state.checkpoint_history[-1]
    state = reduce(state, AuditStarted())
    return state, cp


def pass_current_gate(state, tmp_path: Path):
    state, cp = start_audit(state, tmp_path)
    state = reduce(state, AuditVerdictRecorded(verdict_for(cp, Verdict.PASS)))
    return state, cp


def authorize_repair(state, tmp_path: Path):
    state, cp = start_audit(state, tmp_path)
    fix = verdict_for(cp, Verdict.FIX_REQUIRED, findings=(finding(cp),))
    return reduce(state, AuditVerdictRecorded(fix)), cp


# 1. GatePlan round-trip and fingerprint stability.
def test_gate_plan_round_trip_and_fingerprint_stability():
    original = plan()
    reconstructed = GatePlan.from_dict(json.loads(json.dumps(original.to_dict())))
    assert reconstructed == original
    assert reconstructed.plan_fingerprint == original.plan_fingerprint
    assert [g.contract_fingerprint for g in reconstructed.ordered_gate_contracts] == [
        g.contract_fingerprint for g in original.ordered_gate_contracts
    ]


# 2. Mission and gate order cannot be mutated after session creation.
def test_plan_and_gate_order_are_immutable_after_session_creation():
    gate_plan = plan()
    session = state_with_plan(gate_plan)
    with pytest.raises(FrozenInstanceError):
        gate_plan.ordered_gate_contracts = tuple(reversed(gate_plan.ordered_gate_contracts))
    tampered = session.to_dict()
    tampered["gate_plan"]["ordered_gate_contracts"].reverse()
    with pytest.raises(ValueError, match="fingerprint"):
        type(session).from_dict(tampered)


# 3. More than four gates is rejected, and Build Week is exactly three.
def test_gate_count_limits_are_closed():
    with pytest.raises(ValueError, match="one and four"):
        plan(5, build_week=False)
    with pytest.raises(ValueError, match="exactly three"):
        plan(2, build_week=True)


# 4. Duplicate gate IDs or clause IDs are rejected.
def test_duplicate_gate_and_clause_ids_are_rejected():
    duplicate = gate("same")
    with pytest.raises(ValueError, match="duplicate gate IDs"):
        GatePlan.create(mission=mission(), ordered_gate_contracts=(duplicate, duplicate))
    with pytest.raises(ValueError, match="duplicate clause IDs"):
        GateContract.create(
            gate_id="dup-clauses",
            objective="Reject duplicate clauses.",
            clauses=(GateClause("c1", "One."), GateClause("c1", "Two.")),
            required_evidence_kinds=(EvidenceKind.TARGET_TREE,),
        )


# 5. Straight PASS lifecycle reaches the next predefined gate.
def test_straight_pass_reaches_only_the_next_predefined_gate(tmp_path: Path):
    state, _ = pass_current_gate(state_with_plan(), tmp_path)
    assert state.phase == Phase.GATE_PASSED
    state = reduce(state, GateAdvanced())
    assert state.phase == Phase.READY_FOR_GATE
    assert state.current_gate_index == 1
    assert state.current_gate.gate_id == "gate-2"


# 6. Final gate PASS reaches human review, not automatic acceptance.
def test_final_gate_pass_reaches_human_review_not_completion(tmp_path: Path):
    state = state_with_plan()
    for index in range(3):
        state, _ = pass_current_gate(state, tmp_path)
        state = reduce(state, GateAdvanced())
        if index < 2:
            assert state.phase == Phase.READY_FOR_GATE
    assert state.phase == Phase.AWAITING_HUMAN
    assert state.human_boundary_reason == HumanBoundaryReason.FINAL_REVIEW
    assert state.human_disposition is None


# 7. INCONCLUSIVE never advances.
def test_inconclusive_never_advances(tmp_path: Path):
    state, cp = start_audit(state_with_plan(), tmp_path)
    state = reduce(state, AuditVerdictRecorded(verdict_for(cp, Verdict.INCONCLUSIVE)))
    assert state.phase == Phase.AWAITING_HUMAN
    assert state.current_gate_index == 0
    assert state.human_boundary_reason == HumanBoundaryReason.INCONCLUSIVE
    with pytest.raises(IllegalTransition):
        reduce(state, GateAdvanced())


# 8. BLOCKED reaches human review.
def test_blocked_reaches_human_boundary(tmp_path: Path):
    state, cp = start_audit(state_with_plan(), tmp_path)
    blocked = verdict_for(cp, Verdict.BLOCKED, findings=(finding(cp, human=True),))
    state = reduce(state, AuditVerdictRecorded(blocked))
    assert state.phase == Phase.AWAITING_HUMAN
    assert state.human_boundary_reason == HumanBoundaryReason.BLOCKED


# 9. Unknown-clause findings are refused as repair authority.
def test_unknown_clause_finding_cannot_become_repair_authority(tmp_path: Path):
    state, cp = start_audit(state_with_plan(), tmp_path)
    unknown = finding(cp, clause_id="gate-1.unknown")
    typed = verdict_for(cp, Verdict.FIX_REQUIRED, findings=(unknown,))
    with pytest.raises(IllegalTransition, match="unknown gate-contract clause"):
        reduce(state, AuditVerdictRecorded(typed))


# 10. PASS with blocking findings is refused.
def test_pass_with_blocking_findings_is_refused():
    cp = plain_checkpoint_for(state_with_plan())
    with pytest.raises(ValueError, match="PASS cannot contain blocking"):
        verdict_for(cp, Verdict.PASS, findings=(finding(cp),))


# 11. FIX_REQUIRED without at least one enforceable finding is refused.
def test_fix_required_without_valid_finding_is_refused():
    cp = plain_checkpoint_for(state_with_plan())
    with pytest.raises(ValueError, match="requires enforceable"):
        verdict_for(cp, Verdict.FIX_REQUIRED)


# 12. Exactly one repair can be authorized and it is finding-bounded.
def test_exactly_one_repair_is_authorized_from_exact_findings(tmp_path: Path):
    state, cp = authorize_repair(state_with_plan(), tmp_path)
    assert state.phase == Phase.REPAIR_AUTHORIZED
    assert state.repair_authority is not None
    assert state.repair_authority.checkpoint_fingerprint == cp.checkpoint_fingerprint
    assert state.repair_authority.accepted_finding_ids == ("finding-1",)
    assert state.repair_authority.bounded_repair_surface == ("src/approved-surface.py",)
    state = reduce(state, RepairExecutionStarted())
    assert state.phase == Phase.REPAIR_EXECUTING
    with pytest.raises(IllegalTransition):
        reduce(state, RepairExecutionStarted())


# 13 & 15. A second repair is impossible; failed re-audit reaches human review.
def test_failed_reaudit_reaches_human_and_cannot_authorize_second_repair(tmp_path: Path):
    state, _ = authorize_repair(state_with_plan(), tmp_path)
    state = reduce(state, RepairExecutionStarted())
    repaired_result = capture_result_for(state, tmp_path, attempt=1, seed="repaired")
    state = reduce(state, CheckpointRecorded(repaired_result))
    repaired = state.checkpoint_history[-1]
    state = reduce(state, AuditStarted())
    assert state.phase == Phase.REAUDITING
    second_fix = verdict_for(
        repaired,
        Verdict.FIX_REQUIRED,
        findings=(finding(repaired, finding_id="finding-2"),),
    )
    state = reduce(state, AuditVerdictRecorded(second_fix))
    assert state.phase == Phase.AWAITING_HUMAN
    assert state.human_boundary_reason == HumanBoundaryReason.FAILED_REAUDIT
    with pytest.raises(IllegalTransition):
        reduce(state, RepairExecutionStarted())


# 14. Exactly one re-audit can occur.
def test_exactly_one_reaudit_can_occur(tmp_path: Path):
    state, _ = authorize_repair(state_with_plan(), tmp_path)
    state = reduce(state, RepairExecutionStarted())
    repaired_result = capture_result_for(state, tmp_path, attempt=1, seed="repair-pass")
    state = reduce(state, CheckpointRecorded(repaired_result))
    repaired = state.checkpoint_history[-1]
    state = reduce(state, AuditStarted())
    state = reduce(state, AuditVerdictRecorded(verdict_for(repaired, Verdict.PASS)))
    assert state.phase == Phase.GATE_PASSED
    gate_audits = [v for v in state.audit_history if v.gate_id == "gate-1"]
    assert len(gate_audits) == 2
    with pytest.raises(IllegalTransition):
        reduce(state, AuditStarted())


# 16. Checkpoint identity is bound to the correct gate and attempt.
@pytest.mark.parametrize(
    ("gate_id", "attempt"),
    [("gate-2", 0), ("gate-1", 1)],
)
def test_checkpoint_identity_must_match_current_gate_and_attempt(
    gate_id: str, attempt: int, tmp_path: Path
):
    state = state_with_plan()
    state = reduce(state, GateExecutionStarted("gate-1"))
    wrong = capture_result_for(state, tmp_path, gate_id=gate_id, attempt=attempt)
    with pytest.raises(IllegalTransition, match="checkpoint"):
        reduce(state, CheckpointRecorded(wrong))


# 17. A verdict for another checkpoint cannot be applied.
def test_verdict_for_another_checkpoint_cannot_be_applied(tmp_path: Path):
    state, current = start_audit(state_with_plan(), tmp_path)
    other = plain_checkpoint_for(state, seed="other")
    assert other.checkpoint_fingerprint != current.checkpoint_fingerprint
    with pytest.raises(IllegalTransition, match="another checkpoint"):
        reduce(state, AuditVerdictRecorded(verdict_for(other, Verdict.PASS)))


def test_checkpoint_from_capture_is_not_a_public_model_factory():
    assert not hasattr(Checkpoint, "from_capture")


def test_capture_authority_is_opaque_and_absent_from_package_exports(tmp_path: Path):
    state = reduce(state_with_plan(), GateExecutionStarted("gate-1"))
    capture_result = capture_result_for(state, tmp_path)
    assert not hasattr(delegated_gate_package, "CapturedCheckpoint")
    assert "CapturedCheckpoint" not in delegated_gate_package.__all__
    for private_boundary_name in (
        "_CapturedCheckpoint",
        "_CAPTURE_ISSUANCE_REGISTRY",
        "_issue_captured_checkpoint",
        "_issued_capture_for",
        "_consume_issued_checkpoint",
        "_ArtifactRootAnchor",
        "_OwnedArtifact",
    ):
        assert private_boundary_name not in delegated_gate_package.__all__
    assert not hasattr(checkpoint_module, "_CAPTURE_ISSUANCE_MARKER")
    assert type(capture_result).__slots__ == ("__weakref__",)
    assert not any("marker" in name or "sentinel" in name for name in dir(capture_result))


def test_plain_or_deserialized_checkpoint_cannot_reach_auditing(tmp_path: Path):
    state = reduce(state_with_plan(), GateExecutionStarted("gate-1"))
    invented = plain_checkpoint_for(state, seed="invented-observations")
    reconstructed = Checkpoint.from_dict(invented.to_dict())
    with pytest.raises(IllegalTransition, match="boundary-issued"):
        reduce(state, CheckpointRecorded(reconstructed))
    assert state.phase == Phase.GATE_EXECUTING
    assert state.checkpoint_history == ()


def test_constructed_or_object_new_capture_lookalikes_are_not_authority(tmp_path: Path):
    state = reduce(state_with_plan(), GateExecutionStarted("gate-1"))
    genuine = capture_result_for(state, tmp_path)
    lookalike = checkpoint_module._CapturedCheckpoint()
    object_new_lookalike = object.__new__(checkpoint_module._CapturedCheckpoint)
    assert genuine is not lookalike
    assert lookalike is not object_new_lookalike
    for candidate in (lookalike, object_new_lookalike):
        with pytest.raises(IllegalTransition, match="issuance authority"):
            reduce(state, CheckpointRecorded(candidate))
    accepted = reduce(state, CheckpointRecorded(genuine))
    assert accepted.phase == Phase.CHECKPOINT_CAPTURED


def test_equality_overriding_subclass_cannot_consume_genuine_capture(tmp_path: Path):
    state = reduce(state_with_plan(), GateExecutionStarted("gate-1"))
    genuine = capture_result_for(state, tmp_path)

    class EqualityOverridingSubclass(checkpoint_module._CapturedCheckpoint):
        def __hash__(self):
            return hash(genuine)

        def __eq__(self, other):
            return True

    malicious = EqualityOverridingSubclass()
    assert malicious is not genuine
    assert malicious == genuine
    with pytest.raises(IllegalTransition, match="boundary-issued"):
        reduce(state, CheckpointRecorded(malicious))
    accepted = reduce(state, CheckpointRecorded(genuine))
    assert accepted.phase == Phase.CHECKPOINT_CAPTURED


def test_only_single_use_boundary_capture_result_can_record_a_checkpoint(tmp_path: Path):
    initial = state_with_plan()
    executing = reduce(initial, GateExecutionStarted("gate-1"))
    capture_result = capture_result_for(executing, tmp_path)
    captured = reduce(executing, CheckpointRecorded(capture_result))
    assert captured.phase == Phase.CHECKPOINT_CAPTURED
    assert len(captured.checkpoint_history) == 1
    with pytest.raises(IllegalTransition, match="issuance authority"):
        reduce(reduce(initial, GateExecutionStarted("gate-1")), CheckpointRecorded(capture_result))


def test_capture_is_not_copyable_serializable_or_authority_equivalent(tmp_path: Path):
    state = reduce(state_with_plan(), GateExecutionStarted("gate-1"))
    capture_result = capture_result_for(state, tmp_path)
    for operation in (
        lambda: copy.copy(capture_result),
        lambda: copy.deepcopy(capture_result),
        lambda: pickle.dumps(capture_result),
    ):
        with pytest.raises(TypeError):
            operation()
    second_object = checkpoint_module._CapturedCheckpoint()
    with pytest.raises(IllegalTransition, match="issuance authority"):
        reduce(state, CheckpointRecorded(second_object))
    reduce(state, CheckpointRecorded(capture_result))


def test_unused_capture_registry_entry_is_weak_and_disappears(tmp_path: Path):
    state = reduce(state_with_plan(), GateExecutionStarted("gate-1"))
    baseline = len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY)
    capture_result = capture_result_for(state, tmp_path)
    reference = weakref.ref(capture_result)
    capture_identity = id(capture_result)
    issuance = checkpoint_module._CAPTURE_ISSUANCE_REGISTRY[capture_identity]
    assert issuance.capture_ref() is capture_result
    assert len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY) == baseline + 1
    del capture_result
    gc.collect()
    assert reference() is None
    assert capture_identity not in checkpoint_module._CAPTURE_ISSUANCE_REGISTRY
    assert len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY) == baseline


def test_stale_weak_identity_entry_cannot_grant_authority_to_another_exact_type_object(tmp_path: Path):
    state = reduce(state_with_plan(), GateExecutionStarted("gate-1"))
    issued = capture_result_for(state, tmp_path)
    issued_identity = id(issued)
    reference = weakref.ref(issued)
    del issued
    gc.collect()
    assert reference() is None
    assert issued_identity not in checkpoint_module._CAPTURE_ISSUANCE_REGISTRY
    distinct = checkpoint_module._CapturedCheckpoint()
    with pytest.raises(IllegalTransition, match="issuance authority"):
        reduce(state, CheckpointRecorded(distinct))


def test_capture_result_is_bound_to_session_gate_and_attempt(tmp_path: Path):
    source = state_with_plan(session_id="source-session")
    source_executing = reduce(source, GateExecutionStarted("gate-1"))
    result = capture_result_for(source_executing, tmp_path)

    other_session = reduce(
        state_with_plan(session_id="other-session"), GateExecutionStarted("gate-1")
    )
    with pytest.raises(IllegalTransition, match="another session or gate"):
        reduce(other_session, CheckpointRecorded(result))

    other_gate = reduce(
        state_for_gate(session_id="source-session", gate_contract=gate("gate-2")),
        GateExecutionStarted("gate-2"),
    )
    with pytest.raises(IllegalTransition, match="another session or gate"):
        reduce(other_gate, CheckpointRecorded(result))

    repair_state, _ = authorize_repair(state_with_plan(session_id="repair-session"), tmp_path)
    repair_state = reduce(repair_state, RepairExecutionStarted())
    wrong_attempt = capture_result_for(
        reduce(state_with_plan(session_id="repair-session"), GateExecutionStarted("gate-1")),
        tmp_path,
    )
    with pytest.raises(IllegalTransition, match="execution attempt"):
        reduce(repair_state, CheckpointRecorded(wrong_attempt))

    accepted = reduce(source_executing, CheckpointRecorded(result))
    assert accepted.phase == Phase.CHECKPOINT_CAPTURED


def test_invalid_checkpoint_event_does_not_consume_genuine_capture(tmp_path: Path):
    state = reduce(state_with_plan(), GateExecutionStarted("gate-1"))
    genuine = capture_result_for(state, tmp_path)
    with pytest.raises(IllegalTransition, match="boundary-issued"):
        reduce(state, CheckpointRecorded(plain_checkpoint_for(state, seed="not-issued")))
    accepted = reduce(state, CheckpointRecorded(genuine))
    assert accepted.phase == Phase.CHECKPOINT_CAPTURED


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=True,
    )


def _init_git_repo(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    repo = root / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.email", "fixture@example.invalid")
    _git(repo, "config", "user.name", "Delegated Gate Fixture")
    (repo / "tracked.txt").write_bytes(b"tracked\n")
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "--quiet", "-m", "fixture")
    (repo / "untracked.txt").write_bytes(b"material\n")
    return repo


def _expected_tree_hash(repo: Path) -> str:
    entries: list[tuple[str, str, int]] = []
    for path in repo.rglob("*"):
        if not path.is_file() or ".git" in path.relative_to(repo).parts:
            continue
        data = path.read_bytes()
        entries.append((path.relative_to(repo).as_posix(), hashlib.sha256(data).hexdigest(), len(data)))
    digest = hashlib.sha256()
    for rel, file_hash, size in sorted(entries):
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(file_hash.encode("ascii"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _material_bytes(repo: Path) -> dict[str, bytes]:
    return {
        path.relative_to(repo).as_posix(): path.read_bytes()
        for path in repo.rglob("*")
        if path.is_file() and ".git" not in path.relative_to(repo).parts
    }


# 18 & 19. Capture exact Git/tree/command evidence and remains read-only.
def test_checkpoint_capture_is_exact_bounded_and_read_only(tmp_path: Path):
    repo = _init_git_repo(tmp_path)
    artifacts = tmp_path / "artifacts"
    command = VerificationCommand(
        command_id="fixed-check",
        argv=(
            sys.executable,
            "-c",
            "import sys; print('verified'); print('diagnostic', file=sys.stderr)",
        ),
        timeout_seconds=20,
        max_capture_bytes=4096,
    ).validated()
    contract = gate("capture-gate", command=command)
    before_files = _material_bytes(repo)
    before_head = _git(repo, "rev-parse", "HEAD").stdout.strip()
    before_status = _git(repo, "status", "--porcelain=v1", "--untracked-files=all").stdout

    capture_result = capture_checkpoint(
        repository=repo,
        artifact_directory=artifacts,
        session_id="capture-session",
        gate_contract=contract,
        execution_attempt_index=0,
    )
    state = state_for_gate(session_id="capture-session", gate_contract=contract)
    state = reduce(state, GateExecutionStarted(contract.gate_id))
    state = reduce(state, CheckpointRecorded(capture_result))
    cp = state.checkpoint_history[-1]

    assert cp.material_tree_hash == _expected_tree_hash(repo)
    assert cp.git_head == before_head
    assert cp.git_worktree_status == before_status
    assert cp.execution_attempt_index == 0
    command_evidence = next(record for record in cp.evidence_records if record.kind == EvidenceKind.VERIFICATION_COMMAND)
    assert command_evidence.command_id == command.command_id
    assert command_evidence.argv == command.argv
    assert command_evidence.status == EvidenceStatus.PASSED
    assert command_evidence.exit_code == 0
    assert command_evidence.cleanup_proven is True
    assert len(cp.artifact_references) == 2
    for reference in cp.artifact_references:
        data = (artifacts / reference.relative_path).read_bytes()
        assert hashlib.sha256(data).hexdigest() == reference.sha256
        assert len(data) == reference.byte_count
    assert b"verified" in (artifacts / cp.artifact_references[0].relative_path).read_bytes()
    assert b"diagnostic" in (artifacts / cp.artifact_references[1].relative_path).read_bytes()
    assert _material_bytes(repo) == before_files
    assert _git(repo, "rev-parse", "HEAD").stdout.strip() == before_head
    assert _git(repo, "status", "--porcelain=v1", "--untracked-files=all").stdout == before_status


def test_checkpoint_capture_rejects_a_declared_command_that_mutates_repository(tmp_path: Path):
    repo = _init_git_repo(tmp_path)
    mutator = VerificationCommand(
        command_id="mutator",
        argv=(sys.executable, "-c", "from pathlib import Path; Path('mutation.txt').write_text('x')"),
        timeout_seconds=20,
        max_capture_bytes=4096,
    ).validated()
    with pytest.raises(CheckpointCaptureError, match="mutated"):
        capture_checkpoint(
            repository=repo,
            artifact_directory=tmp_path / "artifacts",
            session_id="mutation-session",
            gate_contract=gate("mutation-gate", command=mutator),
            execution_attempt_index=0,
        )


def test_checkpoint_capture_refuses_artifacts_inside_target_repository(tmp_path: Path):
    repo = _init_git_repo(tmp_path)
    with pytest.raises(CheckpointCaptureError, match="outside"):
        capture_checkpoint(
            repository=repo,
            artifact_directory=repo / "evidence",
            session_id="bad-artifacts",
            gate_contract=gate("artifact-gate"),
            execution_attempt_index=0,
        )


def test_capture_preflight_rejects_symlinked_artifact_root_without_side_effects(
    tmp_path: Path, monkeypatch
):
    external = tmp_path / "external"
    external.mkdir()
    lexical_root = tmp_path / "artifact-link"
    try:
        lexical_root.symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"ordinary symlink fixture is unavailable: {exc}")
    calls: list[object] = []
    registry_size = len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY)

    def forbidden_run(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("redirecting artifact roots must fail before commands")

    monkeypatch.setattr(checkpoint_module, "_run", forbidden_run)
    with pytest.raises(CheckpointCaptureError, match="redirecting"):
        capture_checkpoint(
            repository=tmp_path / "not-a-repository",
            artifact_directory=lexical_root,
            session_id="symlink-root-session",
            gate_contract=gate("symlink-root-gate"),
            execution_attempt_index=0,
        )
    assert calls == []
    assert list(external.iterdir()) == []
    assert not (external / "symlink-root-session.symlink-root-gate.attempt-0").exists()
    assert len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY) == registry_size


def test_capture_preflight_rejects_symlinked_artifact_parent_without_side_effects(
    tmp_path: Path, monkeypatch
):
    external = tmp_path / "external"
    external.mkdir()
    lexical_parent = tmp_path / "parent-link"
    try:
        lexical_parent.symlink_to(external, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"ordinary symlink fixture is unavailable: {exc}")
    calls: list[object] = []
    monkeypatch.setattr(checkpoint_module, "_run", lambda *args, **kwargs: calls.append(args))
    with pytest.raises(CheckpointCaptureError, match="redirecting"):
        capture_checkpoint(
            repository=tmp_path / "not-a-repository",
            artifact_directory=lexical_parent / "new-artifacts",
            session_id="symlink-parent-session",
            gate_contract=gate("symlink-parent-gate"),
            execution_attempt_index=0,
        )
    assert calls == []
    assert list(external.iterdir()) == []


def test_reparse_file_attribute_is_treated_as_redirecting_without_a_junction_fixture(monkeypatch):
    class ReparseDirectoryMetadata:
        st_mode = stat.S_IFDIR
        st_file_attributes = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)

    monkeypatch.setattr(os.path, "isjunction", lambda _: False, raising=False)
    assert checkpoint_module._is_redirecting_path(Path("reparse-fixture"), ReparseDirectoryMetadata())


@pytest.mark.skipif(os.name != "nt", reason="real junction fixture is Windows-specific")
def test_capture_preflight_rejects_real_windows_junction_without_side_effects(tmp_path: Path, monkeypatch):
    external = tmp_path / "junction-target"
    external.mkdir()
    junction = tmp_path / "junction-root"
    try:
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", os.fspath(junction), os.fspath(external)],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"real Windows junction fixture unavailable: {exc}")
    if created.returncode != 0:
        pytest.skip(
            "real Windows junction fixture unavailable: "
            f"mklink /J exited {created.returncode}: {created.stderr.strip() or created.stdout.strip()}"
        )
    if not os.path.isjunction(junction):
        pytest.skip("real Windows junction fixture unavailable: os.path.isjunction did not recognize it")
    calls: list[object] = []
    registry_size = len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY)
    monkeypatch.setattr(checkpoint_module, "_run", lambda *args, **kwargs: calls.append(args))
    try:
        with pytest.raises(CheckpointCaptureError, match="redirecting"):
            capture_checkpoint(
                repository=tmp_path / "not-a-repository",
                artifact_directory=junction,
                session_id="junction-root-session",
                gate_contract=gate("junction-root-gate"),
                execution_attempt_index=0,
            )
        assert calls == []
        assert list(external.iterdir()) == []
        assert len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY) == registry_size
    finally:
        if junction.exists() or junction.is_symlink():
            junction.rmdir()


def test_capture_accepts_existing_normal_or_new_artifact_root(tmp_path: Path):
    repo = _init_git_repo(tmp_path / "normal-root")
    command = VerificationCommand("normal-check", (sys.executable, "-c", "print('ok')")).validated()
    contract = gate("normal-root-gate", command=command)
    existing = tmp_path / "existing-artifacts"
    existing.mkdir()
    capture_checkpoint(
        repository=repo,
        artifact_directory=existing,
        session_id="normal-existing-session",
        gate_contract=contract,
        execution_attempt_index=0,
    )
    assert len(list(existing.iterdir())) == 2
    created = tmp_path / "new-artifacts"
    capture_checkpoint(
        repository=repo,
        artifact_directory=created,
        session_id="normal-created-session",
        gate_contract=contract,
        execution_attempt_index=0,
    )
    assert len(list(created.iterdir())) == 2


@pytest.mark.parametrize(
    ("identity_kind", "invalid_value"),
    [
        ("session", "../escaped"),
        ("gate", "../escaped"),
        ("session", "C:\\escaped"),
        ("session", "/escaped"),
        ("session", "alternate\\separator"),
        ("session", "nul\x00identity"),
    ],
)
def test_capture_preflight_rejects_invalid_path_identities_without_side_effects(
    tmp_path: Path,
    monkeypatch,
    identity_kind: str,
    invalid_value: str,
):
    calls: list[object] = []

    def forbidden_run(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("preflight must reject before any command invocation")

    monkeypatch.setattr(checkpoint_module, "_run", forbidden_run)
    contract = gate("valid-gate")
    if identity_kind == "gate":
        contract = dataclasses.replace(contract, gate_id=invalid_value)
    artifacts = tmp_path / "artifacts"
    with pytest.raises(CheckpointCaptureError):
        capture_checkpoint(
            repository=tmp_path / "not-yet-a-repository",
            artifact_directory=artifacts,
            session_id=invalid_value if identity_kind == "session" else "valid-session",
            gate_contract=contract,
            execution_attempt_index=0,
        )
    assert calls == []
    assert not artifacts.exists()
    assert not list(tmp_path.glob("escaped*"))


def test_preexisting_artifact_destination_rejects_before_any_command_or_overwrite(
    tmp_path: Path,
    monkeypatch,
):
    calls: list[object] = []

    def forbidden_run(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("preflight must reject before any command invocation")

    monkeypatch.setattr(checkpoint_module, "_run", forbidden_run)
    command = VerificationCommand("fixed-check", (sys.executable, "-c", "print('unused')")).validated()
    contract = gate("pre-gate", command=command)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    destination = artifacts / "pre-session.pre-gate.attempt-0.fixed-check.stdout.txt"
    destination.write_bytes(b"existing evidence")
    with pytest.raises(CheckpointCaptureError, match="already exists"):
        capture_checkpoint(
            repository=tmp_path / "not-yet-a-repository",
            artifact_directory=artifacts,
            session_id="pre-session",
            gate_contract=contract,
            execution_attempt_index=0,
        )
    assert calls == []
    assert destination.read_bytes() == b"existing evidence"
    assert list(artifacts.iterdir()) == [destination]


def test_artifact_collisions_fail_before_writes_and_checkpoint_validation_rejects_duplicates(
    tmp_path: Path,
):
    artifact_root = tmp_path / "artifacts"
    destination = artifact_root / "same.txt"
    stdout = checkpoint_module._ArtifactPlan("one", "stdout", "same.txt", destination)
    stderr = checkpoint_module._ArtifactPlan("two", "stderr", "same.txt", destination)
    with pytest.raises(CheckpointCaptureError, match="collision"):
        checkpoint_module._write_artifacts(
            artifact_root=artifact_root,
            planned_outputs=((stdout, "stdout", False), (stderr, "stderr", False)),
        )
    assert not artifact_root.exists()

    command = VerificationCommand("command-one", (sys.executable, "-c", "print('unused')")).validated()
    duplicate_contract = dataclasses.replace(
        gate("collision-gate", command=command),
        checkpoint_verification_commands=(command, command),
    )
    with pytest.raises(CheckpointCaptureError, match="collision"):
        checkpoint_module._preflight_artifact_plan(
            artifact_root=tmp_path / "second-artifacts",
            session_id="collision-session",
            gate_contract=duplicate_contract,
            execution_attempt_index=0,
        )

    repo = _init_git_repo(tmp_path / "artifact-model")
    valid_contract = gate(
        "artifact-model-gate",
        command=VerificationCommand("check", (sys.executable, "-c", "print('ok')")).validated(),
    )
    result = capture_checkpoint(
        repository=repo,
        artifact_directory=tmp_path / "artifact-model-artifacts",
        session_id="artifact-model-session",
        gate_contract=valid_contract,
        execution_attempt_index=0,
    )
    state = state_for_gate(session_id="artifact-model-session", gate_contract=valid_contract)
    state = reduce(state, GateExecutionStarted(valid_contract.gate_id))
    state = reduce(state, CheckpointRecorded(result))
    checkpoint = state.checkpoint_history[-1]
    first, second = checkpoint.artifact_references
    with pytest.raises(ValueError, match="artifact IDs"):
        dataclasses.replace(
            checkpoint,
            artifact_references=(first, dataclasses.replace(second, artifact_id=first.artifact_id)),
        ).validated()
    with pytest.raises(ValueError, match="relative paths"):
        dataclasses.replace(
            checkpoint,
            artifact_references=(first, dataclasses.replace(second, relative_path=first.relative_path)),
        ).validated()
    with pytest.raises(ValueError, match="canonical relative"):
        ArtifactReference(
            artifact_id="normalization-check",
            purpose="stdout",
            relative_path="nested//same.txt",
            sha256=sha("normalization"),
            byte_count=1,
            truncated=False,
        ).validated()


def _single_artifact_plan(root: Path, *, name: str = "output.txt"):
    return checkpoint_module._ArtifactPlan("output", "stdout", name, root / name)


class _WriteStageFailure:
    def __init__(self, handle, *, stage: str):
        self._handle = handle
        self._stage = stage

    def __enter__(self):
        if self._stage == "after-open":
            self._handle.close()
            raise OSError("injected failure after exclusive creation")
        return self

    def __exit__(self, *args):
        self._handle.close()

    def write(self, data):
        if self._stage == "partial-write":
            self._handle.write(data[:1])
            raise OSError("injected partial write failure")
        return self._handle.write(data)

    def flush(self):
        if self._stage == "flush":
            raise OSError("injected flush failure")
        return self._handle.flush()

    def fileno(self):
        return self._handle.fileno()


def _stage_failure_open(original_open, *, stage: str):
    def open_with_failure(path, *args, **kwargs):
        mode = kwargs.get("mode", args[0] if args else "r")
        handle = original_open(path, *args, **kwargs)
        return _WriteStageFailure(handle, stage=stage) if mode == "xb" else handle

    return open_with_failure


@pytest.mark.parametrize("stage", ("after-open", "partial-write", "flush"))
def test_capture_created_artifacts_are_cleaned_after_write_stage_failures(
    tmp_path: Path, monkeypatch, stage: str
):
    artifact_root = tmp_path / f"{stage}-artifacts"
    plan = _single_artifact_plan(artifact_root)
    original_open = Path.open

    monkeypatch.setattr(Path, "open", _stage_failure_open(original_open, stage=stage))
    with pytest.raises(CheckpointCaptureError, match="write failed"):
        checkpoint_module._write_artifacts(
            artifact_root=artifact_root,
            planned_outputs=((plan, "output", False),),
        )
    assert not plan.destination.exists()
    assert not artifact_root.exists()


def test_capture_created_artifacts_are_cleaned_after_fsync_failure(tmp_path: Path, monkeypatch):
    artifact_root = tmp_path / "fsync-artifacts"
    plan = _single_artifact_plan(artifact_root)
    monkeypatch.setattr(checkpoint_module.os, "fsync", lambda _: (_ for _ in ()).throw(OSError("fsync")))
    with pytest.raises(CheckpointCaptureError, match="write failed"):
        checkpoint_module._write_artifacts(
            artifact_root=artifact_root,
            planned_outputs=((plan, "output", False),),
        )
    assert not plan.destination.exists()
    assert not artifact_root.exists()


def test_partial_artifact_cleanup_preserves_preexisting_root_and_unrelated_file(tmp_path: Path, monkeypatch):
    artifact_root = tmp_path / "preexisting-artifacts"
    artifact_root.mkdir()
    unrelated = artifact_root / "unrelated.txt"
    unrelated.write_bytes(b"keep")
    plan = _single_artifact_plan(artifact_root)
    original_open = Path.open
    monkeypatch.setattr(
        Path,
        "open",
        _stage_failure_open(original_open, stage="partial-write"),
    )
    with pytest.raises(CheckpointCaptureError, match="write failed"):
        checkpoint_module._write_artifacts(
            artifact_root=artifact_root,
            planned_outputs=((plan, "output", False),),
        )
    assert artifact_root.is_dir()
    assert unrelated.read_bytes() == b"keep"
    assert not plan.destination.exists()


def test_exclusive_create_race_preserves_the_winning_existing_destination(tmp_path: Path, monkeypatch):
    artifact_root = tmp_path / "race-artifacts"
    artifact_root.mkdir()
    plan = _single_artifact_plan(artifact_root)
    plan.destination.write_bytes(b"winner")
    original_exists = checkpoint_module._path_exists_without_following

    def race_blind_exists(path: Path) -> bool:
        return False if path == plan.destination else original_exists(path)

    monkeypatch.setattr(checkpoint_module, "_path_exists_without_following", race_blind_exists)
    with pytest.raises(CheckpointCaptureError, match="overwrite"):
        checkpoint_module._write_artifacts(
            artifact_root=artifact_root,
            planned_outputs=((plan, "candidate", False),),
        )
    assert plan.destination.read_bytes() == b"winner"
    assert list(artifact_root.iterdir()) == [plan.destination]


def test_capture_assembly_failure_cleans_artifacts_and_issues_no_authority(tmp_path: Path, monkeypatch):
    repo = _init_git_repo(tmp_path / "assembly-failure")
    command = VerificationCommand("assembly-check", (sys.executable, "-c", "print('ok')")).validated()
    contract = gate("assembly-gate", command=command)
    artifacts = tmp_path / "assembly-artifacts"
    registry_size = len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY)
    monkeypatch.setattr(
        checkpoint_module,
        "_checkpoint_from_observations",
        lambda **kwargs: (_ for _ in ()).throw(ValueError("injected assembly failure")),
    )
    with pytest.raises(CheckpointCaptureError, match="assembly failed"):
        capture_checkpoint(
            repository=repo,
            artifact_directory=artifacts,
            session_id="assembly-session",
            gate_contract=contract,
            execution_attempt_index=0,
        )
    assert not artifacts.exists()
    assert len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY) == registry_size


def test_capture_write_failure_cleans_artifacts_and_issues_no_authority(tmp_path: Path, monkeypatch):
    repo = _init_git_repo(tmp_path / "write-failure")
    command = VerificationCommand("write-check", (sys.executable, "-c", "print('ok')")).validated()
    contract = gate("write-gate", command=command)
    artifacts = tmp_path / "write-artifacts"
    registry_size = len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY)
    original_open = Path.open
    monkeypatch.setattr(
        Path,
        "open",
        _stage_failure_open(original_open, stage="partial-write"),
    )
    with pytest.raises(CheckpointCaptureError, match="write failed"):
        capture_checkpoint(
            repository=repo,
            artifact_directory=artifacts,
            session_id="write-session",
            gate_contract=contract,
            execution_attempt_index=0,
        )
    assert not artifacts.exists()
    assert len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY) == registry_size


def test_cleanup_failure_is_explicit_and_fails_closed(tmp_path: Path, monkeypatch):
    artifact_root = tmp_path / "cleanup-failure-artifacts"
    plan = _single_artifact_plan(artifact_root)
    original_open = Path.open
    original_unlink = Path.unlink
    monkeypatch.setattr(
        Path,
        "open",
        _stage_failure_open(original_open, stage="partial-write"),
    )
    monkeypatch.setattr(
        Path,
        "unlink",
        lambda path, *args, **kwargs: (_ for _ in ()).throw(OSError("injected cleanup failure"))
        if path == plan.destination
        else original_unlink(path, *args, **kwargs),
    )
    with pytest.raises(CheckpointCaptureError, match="cleanup failed"):
        checkpoint_module._write_artifacts(
            artifact_root=artifact_root,
            planned_outputs=((plan, "output", False),),
        )
    assert plan.destination.exists()
    assert artifact_root.exists()


def test_assembly_cleanup_rejects_redirected_root_and_preserves_external_sentinel(
    tmp_path: Path, monkeypatch
):
    repo = _init_git_repo(tmp_path / "redirected-root")
    command = VerificationCommand("redirected-root-check", (sys.executable, "-c", "print('ok')")).validated()
    contract = gate("redirected-root-gate", command=command)
    artifacts = tmp_path / "redirected-root-artifacts"
    external = tmp_path / "external-target"
    external.mkdir()
    sentinel = external / "sentinel.bin"
    sentinel.write_bytes(b"external bytes must survive")
    registry_size = len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY)

    def replace_root_then_fail(**kwargs):
        for artifact in artifacts.iterdir():
            artifact.unlink()
        artifacts.rmdir()
        artifacts.symlink_to(external, target_is_directory=True)
        raise ValueError("injected assembly failure after root replacement")

    monkeypatch.setattr(checkpoint_module, "_checkpoint_from_observations", replace_root_then_fail)
    try:
        with pytest.raises(CheckpointCaptureError, match="assembly failed and cleanup failed"):
            capture_checkpoint(
                repository=repo,
                artifact_directory=artifacts,
                session_id="redirected-root-session",
                gate_contract=contract,
                execution_attempt_index=0,
            )
        assert sentinel.read_bytes() == b"external bytes must survive"
        assert artifacts.is_symlink()
        assert len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY) == registry_size
    finally:
        if artifacts.is_symlink():
            artifacts.unlink()


def test_assembly_cleanup_rejects_replaced_owned_file_and_preserves_replacement(
    tmp_path: Path, monkeypatch
):
    repo = _init_git_repo(tmp_path / "replacement-file")
    command = VerificationCommand("replacement-file-check", (sys.executable, "-c", "print('ok')")).validated()
    contract = gate("replacement-file-gate", command=command)
    artifacts = tmp_path / "replacement-file-artifacts"
    registry_size = len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY)

    def replace_file_then_fail(**kwargs):
        replacement = next(path for path in artifacts.iterdir() if path.name.endswith("stdout.txt"))
        replacement.unlink()
        replacement.write_bytes(b"replacement bytes must survive")
        raise ValueError("injected assembly failure after file replacement")

    monkeypatch.setattr(checkpoint_module, "_checkpoint_from_observations", replace_file_then_fail)
    with pytest.raises(CheckpointCaptureError, match="assembly failed and cleanup failed"):
        capture_checkpoint(
            repository=repo,
            artifact_directory=artifacts,
            session_id="replacement-file-session",
            gate_contract=contract,
            execution_attempt_index=0,
        )
    replacement = next(path for path in artifacts.iterdir() if path.name.endswith("stdout.txt"))
    assert replacement.read_bytes() == b"replacement bytes must survive"
    assert len(list(artifacts.iterdir())) == 1
    assert len(checkpoint_module._CAPTURE_ISSUANCE_REGISTRY) == registry_size


def test_write_cleanup_rejects_redirected_intermediate_parent_and_preserves_external_sentinel(
    tmp_path: Path, monkeypatch
):
    artifact_root = tmp_path / "intermediate-root"
    intermediate = artifact_root / "nested"
    intermediate.mkdir(parents=True)
    plan = _single_artifact_plan(intermediate)
    external = tmp_path / "intermediate-external"
    external.mkdir()
    sentinel = external / plan.destination.name
    sentinel.write_bytes(b"intermediate external bytes must survive")
    original_open = Path.open
    original_cleanup = checkpoint_module._cleanup_capture_artifacts

    def replace_parent_then_cleanup(**kwargs):
        plan.destination.unlink()
        intermediate.rmdir()
        intermediate.symlink_to(external, target_is_directory=True)
        return original_cleanup(**kwargs)

    monkeypatch.setattr(Path, "open", _stage_failure_open(original_open, stage="partial-write"))
    monkeypatch.setattr(checkpoint_module, "_cleanup_capture_artifacts", replace_parent_then_cleanup)
    try:
        with pytest.raises(CheckpointCaptureError, match="cleanup failed"):
            checkpoint_module._write_artifacts(
                artifact_root=artifact_root,
                planned_outputs=((plan, "output", False),),
            )
        assert sentinel.read_bytes() == b"intermediate external bytes must survive"
        assert intermediate.is_symlink()
    finally:
        if intermediate.is_symlink():
            intermediate.unlink()


@pytest.mark.skipif(os.name != "nt", reason="real junction fixture is Windows-specific")
def test_assembly_cleanup_rejects_root_replaced_by_real_windows_junction(tmp_path: Path, monkeypatch):
    repo = _init_git_repo(tmp_path / "junction-cleanup")
    command = VerificationCommand("junction-cleanup-check", (sys.executable, "-c", "print('ok')")).validated()
    contract = gate("junction-cleanup-gate", command=command)
    artifacts = tmp_path / "junction-cleanup-artifacts"
    external = tmp_path / "junction-cleanup-external"
    external.mkdir()
    sentinel = external / "sentinel.bin"
    sentinel.write_bytes(b"junction external bytes must survive")

    def replace_root_with_junction_then_fail(**kwargs):
        for artifact in artifacts.iterdir():
            artifact.unlink()
        artifacts.rmdir()
        try:
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", os.fspath(artifacts), os.fspath(external)],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            pytest.skip(f"real Windows junction cleanup fixture unavailable: {exc}")
        if created.returncode != 0 or not os.path.isjunction(artifacts):
            pytest.skip(
                "real Windows junction cleanup fixture unavailable: "
                f"mklink /J exited {created.returncode}: {created.stderr.strip() or created.stdout.strip()}"
            )
        raise ValueError("injected assembly failure after junction replacement")

    monkeypatch.setattr(checkpoint_module, "_checkpoint_from_observations", replace_root_with_junction_then_fail)
    try:
        with pytest.raises(CheckpointCaptureError, match="assembly failed and cleanup failed"):
            capture_checkpoint(
                repository=repo,
                artifact_directory=artifacts,
                session_id="junction-cleanup-session",
                gate_contract=contract,
                execution_attempt_index=0,
            )
        assert sentinel.read_bytes() == b"junction external bytes must survive"
        assert os.path.isjunction(artifacts)
    finally:
        if artifacts.exists() or artifacts.is_symlink():
            artifacts.rmdir()


def test_tree_snapshot_excludes_git_metadata_for_normal_and_linked_worktrees(tmp_path: Path):
    repo = _init_git_repo(tmp_path / "normal")
    (repo / ".gitattributes").write_bytes(b"* -text\n")
    (repo / ".gitignore").write_text("ignored-output\n", encoding="utf-8")
    (repo / "git-notes.txt").write_text("material\n", encoding="utf-8")
    _git(repo, "add", ".gitattributes", ".gitignore", "git-notes.txt")
    _git(repo, "commit", "--quiet", "-m", "material-files")
    _git(repo, "checkout", "--", "tracked.txt")
    normal = checkpoint_module._tree_snapshot(repo)

    linked = tmp_path / "linked-worktree"
    _git(repo, "worktree", "add", "--quiet", "--detach", str(linked), "HEAD")
    assert (linked / ".git").is_file()
    (linked / "untracked.txt").write_bytes(b"material\n")
    linked_snapshot = checkpoint_module._tree_snapshot(linked)
    assert linked_snapshot == normal
    assert normal.file_count == 5

    (linked / "git-notes.txt").write_text("changed material\n", encoding="utf-8")
    assert checkpoint_module._tree_snapshot(linked).tree_hash != normal.tree_hash


# 20. Restart reconstruction preserves every authoritative value.
def test_restart_reconstruction_preserves_every_authoritative_value(tmp_path: Path):
    store = AtomicDelegatedSessionStore(tmp_path / "sessions")
    initial = state_with_plan(session_id="restart-session")
    store.create(initial)
    advanced = reduce(initial, GateExecutionStarted("gate-1"))
    store.replace(advanced, expected_revision=0)
    capture_result = capture_result_for(advanced, tmp_path)
    captured = reduce(advanced, CheckpointRecorded(capture_result))
    store.replace(captured, expected_revision=1)
    reconstructed = AtomicDelegatedSessionStore(tmp_path / "sessions").load("restart-session")
    assert reconstructed == captured
    assert reconstructed.canonical_bytes() == captured.canonical_bytes()
    validate_state(reconstructed)


def test_post_replace_durability_uncertainty_is_typed_and_visible(tmp_path: Path, monkeypatch):
    class UncertainAfterPublication(PlatformDurabilityAdapter):
        def publish(self, final_path, data, *, mode, replacement_authority=None):
            super().publish(
                final_path,
                data,
                mode=mode,
                replacement_authority=replacement_authority,
            )
            raise PublicationVisibleButMetadataUncertain(
                "injected directory durability failure",
                path=Path(final_path),
                file_content_durable=True,
                publication_visible=True,
                metadata_status=PublicationMetadataDurability.PUBLICATION_METADATA_UNCERTAIN,
            )

    store = AtomicDelegatedSessionStore(
        tmp_path / "sessions", durability_adapter=UncertainAfterPublication()
    )
    initial = state_with_plan(session_id="uncertain-session")
    with pytest.raises(CommittedButDurabilityUncertain) as raised:
        store.create(initial)
    assert raised.value.committed_revision == 0
    assert raised.value.visibility_confirmed is True
    assert store.load("uncertain-session") == initial


def test_store_compare_and_swap_rejects_stale_revision(tmp_path: Path):
    store = AtomicDelegatedSessionStore(tmp_path / "sessions")
    initial = state_with_plan(session_id="cas-session")
    store.create(initial)
    next_state = reduce(initial, GateExecutionStarted("gate-1"))
    store.replace(next_state, expected_revision=0)
    with pytest.raises(StaleRevisionError):
        store.replace(next_state, expected_revision=0)


def test_store_refuses_forged_valid_plan_replacement(tmp_path: Path):
    from admissible.delegated_gate.state import mint_state

    store = AtomicDelegatedSessionStore(tmp_path / "sessions")
    initial = state_with_plan(session_id="immutable-plan-session")
    store.create(initial)
    alternate = GatePlan.create_build_week(
        mission=initial.mission,
        ordered_gate_contracts=(gate("alternate-1"), gate("alternate-2"), gate("alternate-3")),
    )
    forged = mint_state(
        schema_version=initial.schema_version,
        session_id=initial.session_id,
        revision=1,
        phase=Phase.GATE_EXECUTING,
        mission=initial.mission,
        gate_plan=alternate,
        current_gate_index=0,
        checkpoint_history=(),
        audit_history=(),
        repair_authority=None,
        human_boundary_reason=None,
        human_disposition=None,
    )
    validate_state(forged)
    with pytest.raises(InvalidSuccessorError, match="immutable"):
        store.replace(forged, expected_revision=0)


# 21. Malformed persisted state fails closed.
def test_malformed_persisted_state_fails_closed(tmp_path: Path):
    store = AtomicDelegatedSessionStore(tmp_path / "sessions")
    initial = state_with_plan(session_id="malformed-session")
    store.create(initial)
    path = tmp_path / "sessions" / "malformed-session.delegated-gate.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["gate_plan"]["ordered_gate_contracts"].reverse()
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(PersistedStateInvalid):
        store.load("malformed-session")


# 22. No agent_os import exists anywhere in the new package.
def test_delegated_gate_package_has_no_agent_os_import():
    root = Path(__file__).resolve().parents[1] / "admissible" / "delegated_gate"
    hits: list[str] = []
    for source_path in sorted(root.glob("*.py")):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                hits.extend(
                    f"{source_path.name}:{node.lineno}:{alias.name}"
                    for alias in node.names
                    if alias.name == "agent_os" or alias.name.startswith("agent_os.")
                )
            elif isinstance(node, ast.ImportFrom) and node.module and (
                node.module == "agent_os" or node.module.startswith("agent_os.")
            ):
                hits.append(f"{source_path.name}:{node.lineno}:{node.module}")
    assert hits == []


def test_fixture_auditor_has_only_constitutional_inputs():
    session = state_with_plan()
    cp = plain_checkpoint_for(session)
    adapter = FixtureAuditor(invocation_identity="fixture-audit-1")
    result = adapter.audit(
        mission=session.mission,
        gate_contract=session.current_gate,
        checkpoint=cp,
        required_evidence_kinds=session.current_gate.required_evidence_kinds,
        verdict=Verdict.PASS,
    )
    assert result.verdict == Verdict.PASS
    assert "transcript" not in adapter.audit.__annotations__


def test_final_human_disposition_is_required_and_write_once(tmp_path: Path):
    state = state_with_plan()
    for _ in range(3):
        state, _ = pass_current_gate(state, tmp_path)
        state = reduce(state, GateAdvanced())
    disposition = HumanDisposition.accept(
        disposition_id="human-acceptance-1",
        actor_identity="human-owner",
        note="Accepted after durable review.",
    )
    state = reduce(state, HumanDispositionRecorded(disposition))
    assert state.phase == Phase.COMPLETED
    assert state.human_disposition == disposition
    with pytest.raises(IllegalTransition):
        reduce(state, HumanDispositionRecorded(disposition))


def test_persisted_completed_disposition_has_no_successor(tmp_path: Path):
    from admissible.delegated_gate.state import mint_state

    store = AtomicDelegatedSessionStore(tmp_path / "sessions")
    state = state_with_plan(session_id="terminal-session")
    store.create(state)

    def persist(event):
        nonlocal state
        next_state = reduce(state, event)
        store.replace(next_state, expected_revision=state.revision)
        state = next_state

    for _ in range(3):
        persist(GateExecutionStarted(state.current_gate.gate_id))
        capture_result = capture_result_for(state, tmp_path)
        persist(CheckpointRecorded(capture_result))
        cp = state.checkpoint_history[-1]
        persist(AuditStarted())
        persist(AuditVerdictRecorded(verdict_for(cp, Verdict.PASS)))
        persist(GateAdvanced())
    assert state.phase == Phase.AWAITING_HUMAN
    disposition = HumanDisposition.accept(
        disposition_id="terminal-acceptance",
        actor_identity="human-owner",
    )
    persist(HumanDispositionRecorded(disposition))
    completed = state
    forged_successor = mint_state(
        **{
            "schema_version": completed.schema_version,
            "session_id": completed.session_id,
            "revision": completed.revision + 1,
            "phase": completed.phase,
            "mission": completed.mission,
            "gate_plan": completed.gate_plan,
            "current_gate_index": completed.current_gate_index,
            "checkpoint_history": completed.checkpoint_history,
            "audit_history": completed.audit_history,
            "repair_authority": completed.repair_authority,
            "human_boundary_reason": completed.human_boundary_reason,
            "human_disposition": completed.human_disposition,
        }
    )
    with pytest.raises(InvalidSuccessorError):
        store.replace(forged_successor, expected_revision=completed.revision)
