"""Assemble a :class:`RunDetail` from persisted evidence and an optional truth provider.

This module reads persisted records read-only, prefers harness observations over
agent-authored claims, and calls the truth-provider seam (never the native
provider / verifier / checkpoint). It NEVER infers a product admission verdict
from a provider exit code, a clean Git state or a final-status filename: the
product verdict stays ``UNKNOWN`` unless authoritative data supplies it.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path

from . import evidence_reader
from .enums import (
    ClassificationKind,
    CompletenessState,
    ExecutionState,
    FailingBoundary,
    OutcomeState,
    PresentationStatus,
    PresenceState,
    ProductVerdict,
    TruthStatus,
    VerdictSource,
    classify_classification,
    coerce_human_disposition,
)
from .evidence_reader import EvidenceRead
from .presentation_types import (
    ArtifactView,
    AuthorizationView,
    BehavioralVerificationView,
    CheckpointView,
    DiagnosticExcerpt,
    EvidenceCompletenessView,
    FailingBoundaryView,
    HumanDispositionView,
    MaterialView,
    ProcessView,
    ProductVerdictView,
    RunDetail,
    RunIdentityView,
    RunSummary,
    WorkspaceGitView,
)
from .product_extractor import TruthProviderOutcome, extract_product_verdict
from .timeline import TimelineInput, build_timeline
from .truth_provider import RunTruthProvider

_NATIVE_DIR = "evidence/native-execution"
_DELEGATED_DIR = "evidence/delegated-state"
_CHECKPOINT_ARTIFACT_DIR = "evidence/checkpoint-artifacts"

_NATIVE_SUFFIXES = {
    "request": ".native-request.json",
    "attempt_reserved": ".native-attempt-reserved.json",
    "process_started": ".native-process-started.json",
    "process_observation": ".native-process-observation.json",
    "result": ".native-result.json",
    "eligibility": ".native-execution-eligibility.json",
    "behavioral": ".native-behavioral.json",
    "capture_attempt": ".native-capture-attempt.json",
    "terminal": ".native-terminal.json",
}

# Bounded hashing of persisted checkpoint artefacts. A declared artefact larger
# than this is treated as unresolvable (never as a silent pass).
_MAX_CHECKPOINT_ARTIFACT_BYTES = 64 * 1024 * 1024
_CHECKPOINT_HASH_CHUNK_BYTES = 1024 * 1024

# Optional forward-compatible persisted product block location. This is a
# persisted *claim* only: it is never treated as authoritative (see
# ``product_extractor``). ``_authorization_view`` lifts a small, explicit set of
# safe authorization fields directly; there is no separate allow-list constant.
_PERSISTED_PRODUCT_PATH = "evidence/product-verdict.json"


# --- typed accessors ---------------------------------------------------------


def _data(read: EvidenceRead) -> Mapping | None:
    if read.ok and isinstance(read.data, Mapping):
        return read.data
    return None


def _mstr(mapping: Mapping | None, key: str) -> str | None:
    if mapping is None:
        return None
    value = mapping.get(key)
    return value if isinstance(value, str) else None


def _mint(mapping: Mapping | None, key: str) -> int | None:
    if mapping is None:
        return None
    value = mapping.get(key)
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def _mbool(mapping: Mapping | None, key: str) -> bool | None:
    if mapping is None:
        return None
    value = mapping.get(key)
    return value if isinstance(value, bool) else None


def _mlist_str(mapping: Mapping | None, key: str) -> tuple[str, ...]:
    if mapping is None:
        return ()
    value = mapping.get(key)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _mlist_int(mapping: Mapping | None, key: str) -> tuple[int, ...]:
    if mapping is None:
        return ()
    value = mapping.get(key)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, int) and not isinstance(item, bool))
    return ()


def _msub(mapping: Mapping | None, key: str) -> Mapping | None:
    if mapping is None:
        return None
    value = mapping.get(key)
    return value if isinstance(value, Mapping) else None


def _first_present(*reads: EvidenceRead) -> PresenceState:
    saw_inconsistent = False
    for read in reads:
        if read.presence is PresenceState.PRESENT:
            return PresenceState.PRESENT
        if read.presence is PresenceState.INCONSISTENT:
            saw_inconsistent = True
    return PresenceState.INCONSISTENT if saw_inconsistent else PresenceState.ABSENT


# --- native record discovery -------------------------------------------------


def _scan_native_files(root_real: Path) -> dict[str, list[str]]:
    """Map each native suffix to the sorted relative paths of matching records."""

    matches: dict[str, list[str]] = {key: [] for key in _NATIVE_SUFFIXES}
    native_dir = evidence_reader.safe_child_path(root_real, _NATIVE_DIR)
    if native_dir is None or not native_dir.is_dir():
        return matches
    names: list[str] = []
    with os.scandir(native_dir) as entries:
        for entry in entries:
            try:
                st = os.lstat(entry.path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            names.append(entry.name)
    for name in sorted(names):
        for key, suffix in _NATIVE_SUFFIXES.items():
            if name.endswith(suffix):
                matches[key].append(f"{_NATIVE_DIR}/{name}")
    return matches


def _read_native(root_real: Path, matches: dict[str, list[str]], key: str, max_bytes: int) -> EvidenceRead:
    paths = matches.get(key) or []
    if not paths:
        return EvidenceRead(f"{_NATIVE_DIR}/*{_NATIVE_SUFFIXES[key]}", PresenceState.ABSENT, None, None, None)
    chosen = paths[-1]
    return evidence_reader.read_json(root_real, chosen, max_bytes=max_bytes)


def _find_delegated_gate(root_real: Path, max_bytes: int) -> EvidenceRead:
    delegated_dir = evidence_reader.safe_child_path(root_real, _DELEGATED_DIR)
    if delegated_dir is None or not delegated_dir.is_dir():
        return EvidenceRead(f"{_DELEGATED_DIR}/*.delegated-gate.json", PresenceState.ABSENT, None, None, None)
    candidates: list[str] = []
    with os.scandir(delegated_dir) as entries:
        for entry in entries:
            if entry.name.endswith(".delegated-gate.json"):
                candidates.append(entry.name)
    if not candidates:
        return EvidenceRead(f"{_DELEGATED_DIR}/*.delegated-gate.json", PresenceState.ABSENT, None, None, None)
    chosen = sorted(candidates)[-1]
    return evidence_reader.read_json(root_real, f"{_DELEGATED_DIR}/{chosen}", max_bytes=max_bytes)


# --- artifact helpers --------------------------------------------------------


def _artifact_view(root_real: Path, record: Mapping | None) -> ArtifactView | None:
    if record is None:
        return None
    relative_path = _mstr(record, "relative_path")
    file_presence = PresenceState.ABSENT
    if relative_path:
        file_presence = evidence_reader.file_presence(root_real, f"evidence/native-execution/{relative_path}")
    return ArtifactView(
        artifact_id=_mstr(record, "artifact_id"),
        purpose=_mstr(record, "purpose"),
        relative_path=relative_path,
        byte_count=_mint(record, "byte_count"),
        sha256=_mstr(record, "sha256"),
        truncated=_mbool(record, "truncated"),
        schema_version=_mstr(record, "schema_version"),
        file_presence=file_presence,
    )


# --- view builders -----------------------------------------------------------


def _identity_view(
    root_real: Path,
    final_status: EvidenceRead,
    request: EvidenceRead,
    delegated: EvidenceRead,
) -> RunIdentityView:
    fs = _data(final_status)
    rq = _data(request)
    dg = _data(delegated)
    mission = _msub(dg, "mission")
    session_id = _mstr(fs, "session_id") or _mstr(rq, "session_id")
    return RunIdentityView(
        run_id=session_id or root_real.name,
        session_id=session_id,
        run_root=str(root_real),
        gate_id=_mstr(rq, "gate_id"),
        mission_id=_mstr(mission, "mission_id"),
        mission_fingerprint=_mstr(rq, "mission_fingerprint") or _mstr(mission, "mission_fingerprint"),
        request_fingerprint=_mstr(fs, "request_fingerprint") or _mstr(rq, "request_fingerprint"),
        final_status_presence=final_status.presence,
    )


def _authorization_view(preflight: EvidenceRead, delegated: EvidenceRead, request: EvidenceRead) -> AuthorizationView:
    pf = _data(preflight)
    payload = _msub(pf, "authorization_payload")
    dg = _data(delegated)
    rq = _data(request)
    objective = None
    plan = _msub(dg, "gate_plan")
    if plan is not None:
        contracts = plan.get("ordered_gate_contracts")
        if isinstance(contracts, list) and contracts and isinstance(contracts[0], Mapping):
            candidate = contracts[0].get("objective")
            objective = candidate if isinstance(candidate, str) else None
    mission = _msub(dg, "mission")
    budgets_raw = _msub(payload, "budgets")
    budgets = None
    if budgets_raw is not None:
        budgets = {str(k): v for k, v in budgets_raw.items() if isinstance(v, int) and not isinstance(v, bool)}
    non_claims = _mlist_str(payload, "canary_non_claims") + _mlist_str(payload, "attestation_non_claims")
    return AuthorizationView(
        present=preflight.presence,
        run_id=_mstr(payload, "run_id"),
        session_id=_mstr(payload, "session_id"),
        mission_id=_mstr(mission, "mission_id"),
        mission_fingerprint=_mstr(payload, "mission_fingerprint"),
        gate_id=_mstr(rq, "gate_id"),
        gate_contract_fingerprint=_mstr(payload, "gate_contract_fingerprint"),
        required_commit_message=_mstr(payload, "required_commit_message"),
        authorized_model=_mstr(payload, "selected_model") or _mstr(rq, "authorized_model"),
        backend_identity=_mstr(rq, "backend_identity"),
        classification=_mstr(pf, "classification"),
        clean_worktree_required=_mbool(payload, "clean_worktree_required"),
        timeout_seconds=_mint(payload, "timeout_seconds"),
        budgets=budgets,
        objective=objective,
        non_claims=non_claims,
    )


def _process_view(
    started: EvidenceRead,
    observation: EvidenceRead,
    result: EvidenceRead,
    attempt_reserved: EvidenceRead,
) -> ProcessView:
    st = _data(started)
    ob = _data(observation)
    ob_proc = _msub(ob, "process")
    rs = _data(result)
    ar = _data(attempt_reserved)

    present = _first_present(started, observation, result)

    process_id = _mint(ob_proc, "process_id") or _mint(st, "process_id")
    executable = _mstr(ob_proc, "executable") or _mstr(rs, "executable") or _mstr(st, "executable")

    exit_ob = _mint(ob_proc, "exit_code")
    exit_rs = _mint(rs, "process_exit_code")
    exit_code = exit_ob if exit_ob is not None else exit_rs
    observation_matches_result: bool | None = None
    notes: list[str] = []
    if exit_ob is not None and exit_rs is not None:
        observation_matches_result = exit_ob == exit_rs
        if not observation_matches_result:
            notes.append(
                f"harness observation exit_code={exit_ob} outranks agent result exit_code={exit_rs}"
            )

    termination_reason = _mstr(ob_proc, "termination_reason") or _mstr(rs, "termination_reason")
    timed_out = _mbool(ob_proc, "timed_out")
    if timed_out is None:
        timed_out = _mbool(rs, "timed_out")
    started_at = _mstr(ob_proc, "started_at") or _mstr(st, "process_started_at") or _mstr(rs, "started_at")
    ended_at = _mstr(ob_proc, "ended_at") or _mstr(rs, "ended_at")
    output_truncation = _mbool(ob_proc, "output_truncation_occurred")
    if output_truncation is None:
        output_truncation = _mbool(rs, "output_truncation_occurred")
    orphans = _mlist_int(ob_proc, "orphan_process_ids") or _mlist_int(rs, "orphan_process_ids")
    cleanup_confirmed = _mbool(ob_proc, "cleanup_confirmed")
    if cleanup_confirmed is None:
        cleanup_confirmed = _mbool(rs, "cleanup_confirmed")
    cleanup_observation = _mstr(ob_proc, "cleanup_observation") or _mstr(rs, "cleanup_observation")

    completion_observed = _mbool(ob, "process_completion_observed")
    if completion_observed or ended_at is not None or rs is not None:
        execution_state = ExecutionState.COMPLETED
    elif st is not None:
        execution_state = ExecutionState.STARTED
    else:
        execution_state = ExecutionState.UNOBSERVED

    return ProcessView(
        present=present,
        execution_state=execution_state,
        process_id=process_id,
        executable=executable,
        exit_code=exit_code,
        termination_reason=termination_reason,
        timed_out=timed_out,
        started_at=started_at,
        ended_at=ended_at,
        timeout_seconds=_mint(ar, "timeout_seconds"),
        output_truncation_occurred=output_truncation,
        orphan_process_ids=orphans,
        cleanup_confirmed=cleanup_confirmed,
        cleanup_observation=cleanup_observation,
        observation_matches_result=observation_matches_result,
        notes=tuple(notes),
    )


def _workspace_git_view(result: EvidenceRead, observation: EvidenceRead) -> WorkspaceGitView:
    rs = _data(result)
    ob = _data(observation)
    ob_final = _msub(ob, "final_workspace")
    ob_initial = _msub(ob, "initial_workspace")
    ob_source = _msub(ob, "source_observation")
    return WorkspaceGitView(
        present=_first_present(result, observation),
        initial_git_head=_mstr(rs, "initial_git_head") or _mstr(ob_initial, "git_head"),
        final_git_head=_mstr(rs, "final_git_head") or _mstr(ob_final, "git_head"),
        initial_material_tree_hash=_mstr(rs, "initial_material_tree_hash") or _mstr(ob_initial, "material_tree_hash"),
        final_material_tree_hash=_mstr(rs, "final_material_tree_hash") or _mstr(ob_final, "material_tree_hash"),
        final_git_porcelain_status=_mstr(rs, "final_git_porcelain_status") or _mstr(ob_final, "git_status"),
        git_remotes=_mlist_str(rs, "final_git_remotes") or _mlist_str(ob_final, "git_remotes"),
        commits_added=_mint(rs, "commits_added"),
        workspace_material_changed=_mbool(rs, "workspace_material_changed"),
        source_repository_mutated=(
            _mbool(rs, "source_repository_mutated")
            if _mbool(rs, "source_repository_mutated") is not None
            else _mbool(ob_source, "mutated")
        ),
        changed_material_files=_mlist_str(rs, "changed_material_files"),
    )


def _material_view(eligibility: EvidenceRead) -> MaterialView:
    el = _data(eligibility)
    eligible = _mbool(el, "eligible")
    if eligibility.presence is PresenceState.ABSENT:
        result = OutcomeState.ABSENT
    elif eligibility.presence is PresenceState.INCONSISTENT:
        result = OutcomeState.INCONSISTENT
    elif eligible is True:
        result = OutcomeState.PASSED
    elif eligible is False:
        result = OutcomeState.FAILED
    else:
        result = OutcomeState.INCONSISTENT
    notes = () if result is not OutcomeState.INCONSISTENT or eligibility.presence is not PresenceState.PRESENT else ("eligibility record present without a boolean 'eligible' field",)
    return MaterialView(
        present=eligibility.presence,
        result=result,
        eligible=eligible,
        material_paths_compliant=_mbool(el, "material_paths_compliant"),
        workspace_clean=_mbool(el, "workspace_clean"),
        remotes_absent=_mbool(el, "remotes_absent"),
        exactly_one_commit=_mbool(el, "exactly_one_commit"),
        commit_message_compliant=_mbool(el, "commit_message_compliant"),
        source_and_root_integrity=_mbool(el, "source_and_root_integrity"),
        ineligibility_reasons=_mlist_str(el, "ineligibility_reasons"),
        notes=notes,
    )


def _behavioral_view(root_real: Path, behavioral: EvidenceRead) -> BehavioralVerificationView:
    bh = _data(behavioral)
    exit_code = _mint(bh, "exit_code")
    if behavioral.presence is PresenceState.ABSENT:
        result = OutcomeState.ABSENT
    elif behavioral.presence is PresenceState.INCONSISTENT:
        result = OutcomeState.INCONSISTENT
    elif exit_code == 0:
        result = OutcomeState.PASSED
    elif exit_code is not None:
        result = OutcomeState.FAILED
    else:
        result = OutcomeState.INCONSISTENT
    notes: tuple[str, ...] = ()
    if behavioral.presence is PresenceState.ABSENT:
        notes = ("behavioral verifier did not run (ABSENT); this is not a pass",)
    return BehavioralVerificationView(
        present=behavioral.presence,
        result=result,
        exit_code=exit_code,
        timed_out=_mbool(bh, "timed_out"),
        evidence_fingerprint=_mstr(bh, "evidence_fingerprint"),
        stdout_artifact=_artifact_view(root_real, _msub(bh, "stdout")),
        stderr_artifact=_artifact_view(root_real, _msub(bh, "stderr")),
        notes=notes,
    )


def _hash_persisted_file(root_real: Path, relative: str) -> str | None:
    """Return the SHA-256 of a persisted file, or ``None`` when unresolvable.

    ``None`` covers every unsafe or unreadable case (containment refusal, absent
    file, non-regular file, oversize, I/O error). Callers must treat ``None`` as
    an unresolved condition, never as a match.
    """

    target = evidence_reader.safe_child_path(root_real, relative)
    if target is None:
        return None
    try:
        st = os.lstat(target)
        if not stat.S_ISREG(st.st_mode):
            return None
        if st.st_size > _MAX_CHECKPOINT_ARTIFACT_BYTES:
            return None
        digest = hashlib.sha256()
        with open(target, "rb") as handle:
            while True:
                chunk = handle.read(_CHECKPOINT_HASH_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _checkpoint_command_definitions(raw: object) -> tuple[tuple[str, tuple[str, ...]], ...] | None:
    """Normalise a persisted checkpoint-command list to ``(command_id, argv)`` pairs."""

    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return None
    pairs: list[tuple[str, tuple[str, ...]]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            return None
        command_id = item.get("command_id")
        argv = item.get("argv")
        if not isinstance(command_id, str) or not command_id:
            return None
        if not isinstance(argv, list) or not argv:
            return None
        if not all(isinstance(part, str) for part in argv):
            return None
        pairs.append((command_id, tuple(argv)))
    if not pairs:
        return None
    if len({command_id for command_id, _ in pairs}) != len(pairs):
        return None
    return tuple(pairs)


def _expected_checkpoint_commands(
    preflight: EvidenceRead, delegated: EvidenceRead, gate_id: str | None
) -> tuple[tuple[str, tuple[str, ...]], ...] | None:
    """Resolve the expected checkpoint commands from persisted authority.

    The canonical preflight authorization payload is preferred; the persisted
    delegated gate contract is the fallback. ``None`` means no authority could be
    resolved, which keeps the checkpoint unresolved rather than trusting the
    executor's own evidence records to define what was required.
    """

    payload = _msub(_data(preflight), "authorization_payload")
    profile = _msub(payload, "mission_profile")
    if profile is not None:
        pairs = _checkpoint_command_definitions(profile.get("checkpoint_commands"))
        if pairs is not None:
            return pairs

    plan = _msub(_data(delegated), "gate_plan")
    if plan is not None:
        contracts = plan.get("ordered_gate_contracts")
        if isinstance(contracts, list):
            candidates = [item for item in contracts if isinstance(item, Mapping)]
            chosen: Mapping | None = None
            if gate_id is not None:
                matching = [item for item in candidates if item.get("gate_id") == gate_id]
                if len(matching) == 1:
                    chosen = matching[0]
            if chosen is None and len(candidates) == 1:
                chosen = candidates[0]
            if chosen is not None:
                pairs = _checkpoint_command_definitions(
                    chosen.get("checkpoint_verification_commands")
                )
                if pairs is not None:
                    return pairs
    return None


def _artifact_reference_index(entry: Mapping) -> dict[str, Mapping] | None:
    """Index a checkpoint-history entry's artefact references by artifact id."""

    references = entry.get("artifact_references")
    if not isinstance(references, list):
        return None
    index: dict[str, Mapping] = {}
    for reference in references:
        if not isinstance(reference, Mapping):
            return None
        artifact_id = reference.get("artifact_id")
        if not isinstance(artifact_id, str) or artifact_id in index:
            return None
        index[artifact_id] = reference
    return index


def _checkpoint_artifact_resolved(
    root_real: Path, references: dict[str, Mapping], artifact_id: object
) -> bool:
    """True only when the referenced artefact exists and its declared hash matches."""

    if not isinstance(artifact_id, str) or artifact_id not in references:
        return False
    reference = references[artifact_id]
    if reference.get("truncated") is not False:
        return False
    relative_path = reference.get("relative_path")
    declared = reference.get("sha256")
    if not isinstance(relative_path, str) or not relative_path:
        return False
    if not isinstance(declared, str) or not declared:
        return False
    actual = _hash_persisted_file(root_real, f"{_CHECKPOINT_ARTIFACT_DIR}/{relative_path}")
    if actual is None:
        return False
    return actual == declared


def _verification_command_records(entry: Mapping) -> tuple[Mapping, ...] | None:
    """Return the ``verification_command`` evidence records of one history entry.

    ``command_id`` lives inside each evidence record, not on the history entry.
    """

    records = entry.get("evidence_records")
    if not isinstance(records, list):
        return None
    selected: list[Mapping] = []
    for record in records:
        if not isinstance(record, Mapping):
            return None
        if record.get("kind") == "verification_command":
            selected.append(record)
    return tuple(selected)


def _checkpoint_command_resolved(
    root_real: Path,
    record: Mapping,
    expected_argv: tuple[str, ...],
    references: dict[str, Mapping],
) -> bool:
    """True only when every required condition for one command is independently met."""

    argv = record.get("argv")
    if not isinstance(argv, list) or tuple(argv) != expected_argv:
        return False
    if record.get("status") != "passed":
        return False
    exit_code = record.get("exit_code")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int) or exit_code != 0:
        return False
    if record.get("timed_out") is not False:
        return False
    if record.get("output_truncated") is not False:
        return False
    if record.get("cleanup_proven") is not True:
        return False
    if not _checkpoint_artifact_resolved(root_real, references, record.get("stdout_artifact_id")):
        return False
    if not _checkpoint_artifact_resolved(root_real, references, record.get("stderr_artifact_id")):
        return False
    return True


def _checkpoint_view(
    root_real: Path,
    final_status: EvidenceRead,
    terminal: EvidenceRead,
    delegated: EvidenceRead,
    preflight: EvidenceRead,
) -> CheckpointView:
    """Reconstruct the checkpoint outcome from persisted evidence only.

    ``PASSED`` requires that every command named by persisted preflight/contract
    authority is independently resolved from persisted checkpoint evidence and
    that the persisted final status agrees. Every other shape stays
    ``INCONSISTENT``: a later manual command never implies a pass.
    """

    fs = _data(final_status)
    tm = _data(terminal)
    dg = _data(delegated)
    checkpoint_fingerprint = _mstr(fs, "checkpoint_fingerprint") or _mstr(tm, "capture_attempt_fingerprint")
    history = dg.get("checkpoint_history") if isinstance(dg, Mapping) else None
    history_entries = [entry for entry in history if isinstance(entry, Mapping)] if isinstance(history, list) else []
    malformed_history = isinstance(history, list) and len(history_entries) != len(history)
    attempted = bool(history_entries) or checkpoint_fingerprint is not None

    if not attempted:
        return CheckpointView(
            present=PresenceState.ABSENT,
            result=OutcomeState.ABSENT,
            attempted=False,
            checkpoint_fingerprint=None,
            verification_command_ids=(),
            notes=("no checkpoint was attempted (ABSENT); this is not a failure",),
        )

    entry = history_entries[-1] if history_entries else None
    records = _verification_command_records(entry) if entry is not None else None
    command_ids = tuple(
        record["command_id"]
        for record in (records or ())
        if isinstance(record.get("command_id"), str)
    )

    def inconsistent(reason: str) -> CheckpointView:
        return CheckpointView(
            present=PresenceState.PRESENT,
            result=OutcomeState.INCONSISTENT,
            attempted=True,
            checkpoint_fingerprint=checkpoint_fingerprint,
            verification_command_ids=command_ids,
            notes=(reason,),
        )

    if malformed_history:
        return inconsistent("checkpoint history contains malformed entries; outcome not resolved")
    if entry is None or records is None:
        return inconsistent("checkpoint evidence records are absent or malformed; outcome not resolved")

    expected = _expected_checkpoint_commands(preflight, delegated, _mstr(entry, "gate_id"))
    if expected is None:
        return inconsistent("no persisted authority defines the expected checkpoint commands; outcome not resolved")

    by_id: dict[str, Mapping] = {}
    for record in records:
        command_id = record.get("command_id")
        if not isinstance(command_id, str) or command_id in by_id:
            return inconsistent("checkpoint command evidence is malformed or duplicated; outcome not resolved")
        by_id[command_id] = record

    expected_ids = {command_id for command_id, _ in expected}
    if set(by_id) != expected_ids:
        return inconsistent("persisted checkpoint commands do not match the authorized command set; outcome not resolved")

    references = _artifact_reference_index(entry)
    if references is None:
        return inconsistent("checkpoint artefact references are malformed; outcome not resolved")

    for command_id, expected_argv in expected:
        if not _checkpoint_command_resolved(root_real, by_id[command_id], expected_argv, references):
            return inconsistent(
                f"checkpoint command {command_id!r} is not independently resolved from persisted evidence"
            )

    if _mstr(fs, "checkpoint_status") != "PASSED":
        return inconsistent("persisted final checkpoint_status does not agree with the resolved commands")

    return CheckpointView(
        present=PresenceState.PRESENT,
        result=OutcomeState.PASSED,
        attempted=True,
        checkpoint_fingerprint=checkpoint_fingerprint,
        verification_command_ids=command_ids,
        notes=(
            "every authorized checkpoint command is independently resolved from persisted evidence",
        ),
    )


def _failing_boundary_view(
    final_status: EvidenceRead,
    terminal: EvidenceRead,
    material: MaterialView,
    behavioral: BehavioralVerificationView,
    checkpoint: CheckpointView,
    process: ProcessView,
    classification_kind: ClassificationKind,
) -> FailingBoundaryView:
    fs = _data(final_status)
    tm = _data(terminal)
    failure_category = _mstr(tm, "failure_category")
    detail = _mstr(fs, "detail") or _mstr(tm, "diagnostic")
    reasons = material.ineligibility_reasons

    process_failed = bool(
        process.timed_out
        or (process.exit_code is not None and process.exit_code != 0)
        or (failure_category in ("process_spawn_failure", "process_observation_publication"))
    )

    if process_failed:
        boundary = FailingBoundary.PROCESS
    elif material.result is OutcomeState.FAILED:
        boundary = FailingBoundary.MATERIAL_ELIGIBILITY
    elif behavioral.result is OutcomeState.FAILED:
        boundary = FailingBoundary.BEHAVIORAL_VERIFIER
    elif checkpoint.result is OutcomeState.FAILED:
        boundary = FailingBoundary.CHECKPOINT
    elif classification_kind is ClassificationKind.SUCCESS:
        boundary = FailingBoundary.NONE
    elif classification_kind is ClassificationKind.NON_SUCCESS:
        boundary = FailingBoundary.OTHER
    else:
        boundary = FailingBoundary.UNKNOWN

    return FailingBoundaryView(
        boundary=boundary,
        failure_category=failure_category,
        detail=detail,
        reasons=reasons,
    )


def _human_disposition_view(delegated: EvidenceRead) -> HumanDispositionView:
    dg = _data(delegated)
    raw = dg.get("human_disposition") if isinstance(dg, Mapping) else None
    disposition, unsupported = coerce_human_disposition(raw)
    reason = _mstr(dg, "human_boundary_reason")
    return HumanDispositionView(
        present=delegated.presence,
        disposition=disposition,
        raw_disposition=unsupported,
        reason=reason,
    )


# --- completeness ------------------------------------------------------------

_SLOT_LABELS = {
    "final_status": "evidence/final-status.json",
    "delegated_gate": "evidence/delegated-state/*.delegated-gate.json",
    "canary_preflight": "evidence/canary-preflight.json",
    "request": "native-request.json",
    "attempt_reserved": "native-attempt-reserved.json",
    "process_started": "native-process-started.json",
    "process_observation": "native-process-observation.json",
    "eligibility": "native-execution-eligibility.json",
    "result": "native-result.json",
    "behavioral": "native-behavioral.json",
    "capture_attempt": "native-capture-attempt.json",
    "terminal": "native-terminal.json",
}

# Required in every lane. The lane-specific native terminal record is added by
# ``_completeness_view`` from the resolved evidence lane.
_BASE_REQUIRED = (
    "final_status",
    "request",
    "attempt_reserved",
    "process_started",
    "process_observation",
    "eligibility",
)


def _evidence_lane(final_status: EvidenceRead, classification_kind: ClassificationKind) -> str:
    """Resolve which native terminal record this run's lane must carry.

    The success lane is entered only on *positive* persisted evidence: a present
    final status carrying a canonical SUCCESS classification together with an
    explicit ``canary_success`` of ``True``. The success lane deliberately never
    writes ``native-terminal.json``; it writes ``native-capture-attempt.json``
    instead, so that record becomes the required one.

    Every other shape - failure, contradictory, unsupported, absent or
    unreadable final status - stays in the terminal-requiring lane. Absence of
    ``native-terminal.json`` alone never selects the success lane.
    """

    if final_status.presence is not PresenceState.PRESENT:
        return "OTHER"
    if classification_kind is not ClassificationKind.SUCCESS:
        return "OTHER"
    if _mbool(_data(final_status), "canary_success") is not True:
        return "OTHER"
    return "SUCCESS"


def _completeness_view(
    reads: dict[str, EvidenceRead],
    material: MaterialView,
    behavioral: BehavioralVerificationView,
    lane: str,
) -> EvidenceCompletenessView:
    present: list[str] = []
    absent: list[str] = []
    inconsistent: list[str] = []
    for slot, label in _SLOT_LABELS.items():
        read = reads.get(slot)
        if read is None:
            absent.append(label)
            continue
        if read.presence is PresenceState.PRESENT:
            present.append(label)
        elif read.presence is PresenceState.INCONSISTENT:
            inconsistent.append(label)
        else:
            absent.append(label)

    required = set(_BASE_REQUIRED)
    # Lane-specific native terminal record. Exactly one of the two is required;
    # neither lane may pass without its own positive terminal evidence.
    required.add("capture_attempt" if lane == "SUCCESS" else "terminal")
    if material.result is OutcomeState.PASSED:
        # Material eligibility passing means the behavioral verifier and an
        # accepted result are expected to exist.
        required.add("result")
        required.add("behavioral")

    missing_required: list[str] = []
    for slot in sorted(required):
        read = reads.get(slot)
        if read is None or read.presence is PresenceState.ABSENT:
            missing_required.append(_SLOT_LABELS[slot])

    if inconsistent:
        state = CompletenessState.INCONSISTENT
    elif missing_required:
        state = CompletenessState.INCOMPLETE
    else:
        state = CompletenessState.COMPLETE

    return EvidenceCompletenessView(
        state=state,
        present_records=tuple(present),
        absent_records=tuple(absent),
        inconsistent_records=tuple(inconsistent),
        missing_required=tuple(missing_required),
    )


# --- presentation status -----------------------------------------------------


def _presentation_status(
    product: ProductVerdictView,
    classification_kind: ClassificationKind,
    completeness: EvidenceCompletenessView,
    final_status_presence: PresenceState,
) -> PresentationStatus:
    """Derive the top-level status. ``ADMITTED`` requires authoritative truth.

    ``ADMITTED`` is reachable only when the *effective* verdict is an authoritative
    admission (``truth_status == AUTHORITATIVE`` and source is the reconstruction
    seam). A persisted product claim never reaches this branch: under no provider
    and under provider failure the effective verdict stays ``UNKNOWN`` and the
    status falls back to the persisted canonical *execution* classification, which
    is kept distinct from an authoritative product verdict.
    """

    # 1) A provider failure with a persisted product claim cannot be reconciled:
    #    the claim is unverifiable, so surface it as inconsistent, never admitted.
    if product.truth_status in (TruthStatus.ERROR, TruthStatus.UNAVAILABLE) and product.claim_present:
        return PresentationStatus.INCONSISTENT
    # 2) An authoritative verdict that contradicts a persisted claim.
    if not product.consistent:
        return PresentationStatus.INCONSISTENT
    # 3) Malformed evidence set.
    if completeness.state is CompletenessState.INCONSISTENT:
        return PresentationStatus.INCONSISTENT
    # 4) The ONLY admission path: an authoritative admitted verdict.
    if (
        product.verdict in (ProductVerdict.ADMITTED_OBSERVED, ProductVerdict.ADMITTED_VERIFIED)
        and product.source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION
        and product.truth_status is TruthStatus.AUTHORITATIVE
    ):
        return PresentationStatus.ADMITTED
    # 5) An authoritative product refusal (distinct from a canonical execution refusal).
    if (
        product.verdict is ProductVerdict.REFUSED
        and product.source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION
        and product.truth_status is TruthStatus.AUTHORITATIVE
    ):
        return PresentationStatus.REFUSED
    # 6) Authoritative but not understood: never guessed into a success/refusal.
    if product.verdict is ProductVerdict.UNSUPPORTED:
        return PresentationStatus.UNKNOWN
    # 7) verdict is UNKNOWN: fall back to the persisted canonical classification
    #    ONLY. A persisted product claim never drives the status here.
    if final_status_presence is PresenceState.ABSENT:
        return PresentationStatus.INCOMPLETE
    if final_status_presence is PresenceState.INCONSISTENT:
        return PresentationStatus.INCONSISTENT
    if completeness.state is CompletenessState.INCOMPLETE:
        return PresentationStatus.INCOMPLETE
    if classification_kind is ClassificationKind.NON_SUCCESS:
        return PresentationStatus.REFUSED
    # SUCCESS canary or unsupported/absent classification -> product still UNKNOWN.
    return PresentationStatus.UNKNOWN


# --- diagnostics -------------------------------------------------------------


def _diagnostics(
    root_real: Path,
    final_status: EvidenceRead,
    terminal: EvidenceRead,
    behavioral: BehavioralVerificationView,
    process: ProcessView,
    result: EvidenceRead,
    excerpt_bytes: int,
) -> tuple[DiagnosticExcerpt, ...]:
    excerpts: list[DiagnosticExcerpt] = []

    detail = _mstr(_data(final_status), "detail") or _mstr(_data(terminal), "diagnostic")
    if detail is not None:
        excerpts.append(
            DiagnosticExcerpt(
                label="final-status detail",
                source_relative_path="evidence/final-status.json",
                total_byte_count=len(detail.encode("utf-8")),
                excerpt=detail[:excerpt_bytes],
                truncated=len(detail) > excerpt_bytes,
                sha256=None,
                encoding_note=None,
            )
        )

    # Behavioral stderr excerpt (the most useful refusal diagnostic).
    if behavioral.stderr_artifact and behavioral.stderr_artifact.relative_path:
        rel = f"evidence/native-execution/{behavioral.stderr_artifact.relative_path}"
        read = evidence_reader.read_text_excerpt(root_real, rel, max_bytes=excerpt_bytes)
        if read.presence is PresenceState.PRESENT and read.excerpt:
            excerpts.append(
                DiagnosticExcerpt(
                    label="behavioral verifier stderr",
                    source_relative_path=rel,
                    total_byte_count=read.source_byte_size,
                    excerpt=read.excerpt,
                    truncated=read.truncated,
                    sha256=behavioral.stderr_artifact.sha256,
                    encoding_note=read.encoding_note,
                )
            )

    return tuple(excerpts)


# --- public API --------------------------------------------------------------


def load_run_detail(
    run_root: Path | str,
    *,
    truth_provider: RunTruthProvider | None = None,
    max_bytes: int = evidence_reader.DEFAULT_MAX_JSON_BYTES,
    excerpt_bytes: int = evidence_reader.DEFAULT_MAX_EXCERPT_BYTES,
) -> RunDetail:
    """Build a :class:`RunDetail` for one run root, read-only.

    ``truth_provider`` supplies an authoritative reconstruction through the seam.
    When omitted, the product verdict remains ``UNKNOWN``; it is never inferred
    from persisted execution facts.
    """

    root_real = evidence_reader.resolve_root(run_root)
    read_notes: list[str] = []

    final_status = evidence_reader.read_json(root_real, "evidence/final-status.json", max_bytes=max_bytes)
    preflight = evidence_reader.read_json(root_real, "evidence/canary-preflight.json", max_bytes=max_bytes)
    delegated = _find_delegated_gate(root_real, max_bytes)

    matches = _scan_native_files(root_real)
    for key, paths in matches.items():
        if len(paths) > 1:
            read_notes.append(f"multiple {key} records found; using {paths[-1]}")
    request = _read_native(root_real, matches, "request", max_bytes)
    attempt_reserved = _read_native(root_real, matches, "attempt_reserved", max_bytes)
    process_started = _read_native(root_real, matches, "process_started", max_bytes)
    process_observation = _read_native(root_real, matches, "process_observation", max_bytes)
    result = _read_native(root_real, matches, "result", max_bytes)
    eligibility = _read_native(root_real, matches, "eligibility", max_bytes)
    behavioral = _read_native(root_real, matches, "behavioral", max_bytes)
    capture_attempt = _read_native(root_real, matches, "capture_attempt", max_bytes)
    terminal = _read_native(root_real, matches, "terminal", max_bytes)

    reads = {
        "final_status": final_status,
        "delegated_gate": delegated,
        "canary_preflight": preflight,
        "request": request,
        "attempt_reserved": attempt_reserved,
        "process_started": process_started,
        "process_observation": process_observation,
        "eligibility": eligibility,
        "result": result,
        "behavioral": behavioral,
        "capture_attempt": capture_attempt,
        "terminal": terminal,
    }

    identity = _identity_view(root_real, final_status, request, delegated)
    authorization = _authorization_view(preflight, delegated, request)
    process_view = _process_view(process_started, process_observation, result, attempt_reserved)
    workspace_git = _workspace_git_view(result, process_observation)
    material = _material_view(eligibility)
    behavioral_view = _behavioral_view(root_real, behavioral)
    checkpoint = _checkpoint_view(root_real, final_status, terminal, delegated, preflight)

    canonical_classification = _mstr(_data(final_status), "status")
    classification_kind = classify_classification(canonical_classification)
    canary_success = _mbool(_data(final_status), "canary_success")
    final_status_detail = _mstr(_data(final_status), "detail")

    failing_boundary = _failing_boundary_view(
        final_status, terminal, material, behavioral_view, checkpoint, process_view, classification_kind
    )
    human_disposition = _human_disposition_view(delegated)
    completeness = _completeness_view(
        reads, material, behavioral_view, _evidence_lane(final_status, classification_kind)
    )

    # Authoritative product verdict via the truth-provider seam. Provider absence,
    # provider failure (exception), and a provider that returns invalid authority
    # are kept distinct so a persisted claim can never fill an authority vacuum.
    authoritative: Mapping | None = None
    truth_outcome = TruthProviderOutcome.NOT_CONFIGURED
    if truth_provider is not None:
        try:
            reconstructed = truth_provider.reconstruct(root_real)
        except Exception as exc:  # truth-provider failure: fail closed, never fatal.
            # Bounded diagnostic only; the exception message/traceback is not
            # exposed (it may carry workspace or provider output).
            truth_outcome = TruthProviderOutcome.RAISED
            read_notes.append(f"truth provider failed: {type(exc).__name__}")
        else:
            if isinstance(reconstructed, Mapping):
                truth_outcome = TruthProviderOutcome.RETURNED_MAPPING
                authoritative = reconstructed
            else:
                truth_outcome = TruthProviderOutcome.RETURNED_INVALID
                read_notes.append(
                    f"truth provider returned non-mapping: {type(reconstructed).__name__}"
                )

    persisted_product_read = evidence_reader.read_json(root_real, _PERSISTED_PRODUCT_PATH, max_bytes=max_bytes)
    persisted_product: Mapping | None = _data(persisted_product_read)
    if persisted_product_read.presence is PresenceState.INCONSISTENT:
        read_notes.append(f"persisted product block inconsistent: {persisted_product_read.reason}")

    product_verdict = extract_product_verdict(
        authoritative, persisted_product, outcome=truth_outcome
    )

    presentation_status = _presentation_status(
        product_verdict, classification_kind, completeness, final_status.presence
    )

    timeline = build_timeline(
        [
            TimelineInput("authorization_materialized", "authorization materialized", None, "evidence/canary-preflight.json", preflight.presence),
            TimelineInput("attempt_reserved", "attempt reserved", _mstr(_data(attempt_reserved), "reserved_at"), attempt_reserved.relative_path, attempt_reserved.presence),
            TimelineInput("process_started", "process started", _mstr(_data(process_started), "process_started_at"), process_started.relative_path, process_started.presence),
            TimelineInput("process_completed", "process completed", process_view.ended_at, process_observation.relative_path, _first_present(result, process_observation)),
            TimelineInput("eligibility_evaluated", "eligibility evaluated", _mstr(_data(eligibility), "evaluated_at"), eligibility.relative_path, eligibility.presence),
            TimelineInput("behavioral_verifier_completed", "behavioral verifier completed", None, behavioral.relative_path, behavioral.presence),
            TimelineInput("checkpoint_attempted", "checkpoint attempted", None, None, PresenceState.PRESENT if checkpoint.attempted else PresenceState.ABSENT),
            TimelineInput("checkpoint_completed", "checkpoint completed", None, None, PresenceState.PRESENT if checkpoint.result is OutcomeState.PASSED else PresenceState.ABSENT),
            TimelineInput("terminal_status_persisted", "terminal status persisted", _mstr(_data(terminal), "created_at"), terminal.relative_path, terminal.presence),
            TimelineInput("review_persisted", "review persisted", None, None, PresenceState.PRESENT if human_disposition.raw_disposition or human_disposition.disposition.value in ("ACCEPTED", "REJECTED") else PresenceState.ABSENT),
            TimelineInput("acceptance_persisted", "acceptance persisted", None, None, PresenceState.PRESENT if human_disposition.disposition.value == "ACCEPTED" else PresenceState.ABSENT),
        ]
    )

    artifacts = _collect_artifacts(root_real, result, behavioral_view)
    diagnostics = _diagnostics(root_real, final_status, terminal, behavioral_view, process_view, result, excerpt_bytes)

    return RunDetail(
        run_root=str(root_real),
        identity=identity,
        authorization=authorization,
        canonical_classification=canonical_classification,
        canonical_classification_kind=classification_kind,
        canary_success=canary_success,
        final_status_detail=final_status_detail,
        failing_boundary=failing_boundary,
        process=process_view,
        workspace_git=workspace_git,
        material=material,
        behavioral=behavioral_view,
        checkpoint=checkpoint,
        product_verdict=product_verdict,
        human_disposition=human_disposition,
        evidence_completeness=completeness,
        presentation_status=presentation_status,
        timeline=timeline,
        artifacts=artifacts,
        diagnostics=diagnostics,
        read_notes=tuple(read_notes),
    )


def _collect_artifacts(root_real: Path, result: EvidenceRead, behavioral: BehavioralVerificationView) -> tuple[ArtifactView, ...]:
    artifacts: list[ArtifactView] = []
    rs = _data(result)
    for key in ("stdout_artifact", "stderr_artifact"):
        view = _artifact_view(root_real, _msub(rs, key))
        if view is not None:
            artifacts.append(view)
    if behavioral.stdout_artifact is not None:
        artifacts.append(behavioral.stdout_artifact)
    if behavioral.stderr_artifact is not None:
        artifacts.append(behavioral.stderr_artifact)
    return tuple(artifacts)


def load_run_summary(
    run_root: Path | str,
    *,
    truth_provider: RunTruthProvider | None = None,
    max_bytes: int = evidence_reader.DEFAULT_MAX_JSON_BYTES,
) -> RunSummary:
    """Load a run and project it to a compact :class:`RunSummary`."""

    return load_run_detail(
        run_root, truth_provider=truth_provider, max_bytes=max_bytes
    ).summary()
