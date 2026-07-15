"""Operator-only runner for the first complete real V0 Cursor trajectory (Slice 4).

This module drives *one* full V0 mission -- proposal, admission, bounded write,
and a single deterministic structural check -- to its terminal ``AWAITING_HUMAN``
state, using only components that already exist:

- the isolated V0 controller/reducer (:class:`V0ControllerEngine`);
- :class:`AtomicSessionStore`;
- :class:`V0OfflineOrchestrator` (the reconstruct-from-disk driver);
- :class:`CursorCallableProposalBackend` (store-backed persisted dispatch);
- :class:`BoundedLocalExecutorV0Adapter` (the only writer);
- :class:`V0StructuralChecker` (deterministic, one check);
- :class:`WorkspaceIntegrationPolicy` / ``WorkspaceAuthorityDescriptor``;
- durable receipts and materialized ``FileEvidence``.

It creates **no** new controller or state machine, does **not** touch the normal
Control Surface, and adds **no** automatic repair, runtime verification, retry, or
browser path.  Its only additions over the offline orchestrator are: an operator
double-confirmation gate, a preflight that fails *before* any durable session
exists, and an **independent budget layer** that fails closed the instant any
hard limit would be exceeded.

It is **inert** by default.  A real run requires the conjunction of ``--execute``
*and* ``--confirm-real-run``; either flag alone performs dry-run/config
validation only.  No real Cursor process is started by dry-run, by tests, or by
importing this module.

Example (dry-run, the default) -- every live-contract input made explicit::

    python -m admissible.diagnostics.v0_cursor_live_run \
        --executable node.exe \
        --executable-prefix-arg /path/to/cursor/index.js \
        --target-workspace /tmp/neon-serpents \
        --agent-workspace /tmp/neon-agent-ws \
        --store-directory /tmp/neon-sessions \
        --allowed-workspace-root /tmp \
        --session-id neon-serpents-live-001 \
        --model auto \
        --timeout-seconds 900 \
        --mission-file /path/to/neon_serpents_mission.txt \
        --invocation-limit 2 \
        --operation-limit 4 \
        --write-limit 8

The eight mandatory paths (index.html, style.css, src/main.js, src/game.js,
src/entities.js, src/bots.js, src/render.js, LOCAL_DEV.md) are fixed by the
mission contract.  Add ``--execute --confirm-real-run`` to perform the real run.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from admissible.v0_controller.adapters import (
    MAX_PROPOSAL_OPERATIONS,
    BoundedLocalExecutorV0Adapter,
)
from admissible.v0_controller.cursor_backend import (
    BACKEND_IDENTITY,
    BACKEND_PROTOCOL_VERSION,
    TRANSPORT_IDENTITY,
    CursorBackendConfig,
    CursorCallableProposalBackend,
    V0ProcessRunner,
)
from admissible.v0_controller.integration_policy import (
    WorkspaceIntegrationError,
    WorkspaceIntegrationPolicy,
)
from admissible.v0_controller.orchestrator import (
    CLI008_MANDATORY_PATHS,
    OrchestratorStepResult,
    V0OfflineIntegrationConfig,
    V0OfflineOrchestrator,
    cli008_contract,
)
from admissible.v0_controller.state import Phase, SessionState
from admissible.v0_controller.store import AtomicSessionStore
from admissible.v0_controller.structural_checker import V0StructuralChecker

# --------------------------------------------------------------------------
# The whole bounded LIVE RUN CONTRACT, as constants an auditor reads in one place.
# --------------------------------------------------------------------------
MAX_CURSOR_INVOCATIONS = 2
MAX_OPERATIONS_PER_RESULT = MAX_PROPOSAL_OPERATIONS  # 4
MAX_ADMITTED_OPERATIONS = 8
MAX_TARGET_WRITES = 8
MAX_AUTOMATIC_RETRIES = 0
MAX_REPAIR_ROUNDS = 0
MAX_RUNTIME_ATTEMPTS = 0
MAX_STRUCTURAL_CHECKS = 1
POST_TERMINAL_STABILITY_CHECKS = 20
EXPECTED_FINAL_PHASE = Phase.AWAITING_HUMAN

# A hard ceiling on logical ticks.  The nominal two-turn trajectory is well under
# this; exceeding it is itself a fail-closed condition.
MAX_LOGICAL_STEPS = 48

# The eight-file first live mission.
MISSION_MANDATORY_PATHS: tuple[str, ...] = CLI008_MANDATORY_PATHS
DEFAULT_CONTRACT_ID = "cli008-neon-serpents-live"

# The bounded size of a persisted mission specification, mirrored by
# ``MissionContract.MAX_MISSION_SPECIFICATION_BYTES`` so the runner rejects an
# oversized mission before any session exists rather than at construction.
MAX_MISSION_BYTES = 8192

# The default, fully-specified Neon Serpents mission.  It is deterministic text;
# ``normalize_mission`` leaves already-normalized input unchanged.
DEFAULT_MISSION_SUMMARY = (
    'Build "Neon Serpents": a self-contained plain HTML/CSS/JavaScript browser game.\n'
    "Requirements:\n"
    "- no external dependencies\n"
    "- no CDN or network references\n"
    "- local assets only\n"
    "- keyboard controls documented\n"
    "- deterministic local opening through index.html\n"
    "- complete final contents for every proposed file\n"
    "- exactly the eight mandatory paths declared in this contract\n"
    "- no runtime or browser claims"
)

# Terminal states at which no automatic loop may continue.
TERMINAL_PHASES = frozenset({Phase.AWAITING_HUMAN, Phase.COMPLETED, Phase.FAILED, Phase.TECHNICAL_PAUSE})

WINDOWS_SHELL_WRAPPER_SUFFIXES = (".ps1", ".cmd", ".bat")


class LiveRunPreflightError(ValueError):
    """A configuration fault found *before* any durable session can exist."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class LiveRunBudgetExceeded(RuntimeError):
    """A hard live-run budget would be (or was) exceeded: the driver fails closed."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


class LiveRunMissionMismatch(RuntimeError):
    """Resuming a persisted session with a different mission: reject, no dispatch."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


def normalize_mission(raw: str) -> str:
    """Deterministically normalize an operator mission; reject an invalid one.

    Normalization is pure text hygiene: CRLF/CR become LF, trailing whitespace is
    stripped per line, and surrounding blank lines are removed.  Two inputs that
    differ only in line endings or trailing whitespace normalize byte-identically,
    so they persist and instruct identically.
    """

    if raw is None:
        raise LiveRunPreflightError("empty_mission", "a mission specification is required")
    if "\x00" in raw:
        raise LiveRunPreflightError("nul_in_mission", "the mission specification contains NUL characters")
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n")]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    normalized = "\n".join(lines)
    if not normalized.strip():
        raise LiveRunPreflightError("empty_mission", "the mission specification is empty or whitespace-only")
    if len(normalized.encode("utf-8")) > MAX_MISSION_BYTES:
        raise LiveRunPreflightError(
            "oversized_mission", f"the mission specification exceeds {MAX_MISSION_BYTES} bytes"
        )
    return normalized


@dataclass(frozen=True)
class LiveRunPreflight:
    """Everything validated before a session that looks active is ever created."""

    executable: str
    resolved_executable: str
    executable_prefix_args: tuple[str, ...]
    config: CursorBackendConfig
    target_workspace: Path
    agent_workspace: Path
    store_directory: Path
    session_id: str
    contract_id: str
    mission_specification: str
    allowed_workspace_roots: tuple[str, ...]
    rejected_workspace_roots: tuple[str, ...]
    mandatory_paths: tuple[str, ...]
    model: str
    timeout_seconds: float


@dataclass(frozen=True)
class StabilityTick:
    """One reconstructed post-terminal NoEvent poll."""

    revision: int
    phase: str
    canonical_sha256: str
    byte_stable: bool


@dataclass(frozen=True)
class TransitionRecord:
    """One logical transition, for the revision-by-revision report."""

    step_index: int
    step_kind: str
    revision: int
    phase: str
    selected_command: str | None


@dataclass(frozen=True)
class TargetFile:
    path: str
    present: bool
    sha256: str | None
    byte_count: int | None


@dataclass(frozen=True)
class LiveRunOutcome:
    """The bounded, typed summary of one real (or fake-driven) trajectory."""

    dry_run: bool
    session_id: str
    transitions: tuple[TransitionRecord, ...]
    invocation_count: int
    result_count: int
    admitted_operations: int
    physical_writes: int
    durable_receipts: int
    evidence_count: int
    remaining_mandatory_paths: tuple[str, ...]
    structural_checks: int
    final_phase: str
    technical_failure: str
    stability_ticks: tuple[StabilityTick, ...]
    target_manifest: tuple[TargetFile, ...]
    remaining_cursor_process_ids: tuple[int, ...]
    budget_breach: str = ""

    @property
    def stability_byte_stable(self) -> bool:
        return all(tick.byte_stable for tick in self.stability_ticks)


# --------------------------------------------------------------------------
# Preflight
# --------------------------------------------------------------------------


def _reject_windows_shell_wrapper(executable: str) -> None:
    if os.name != "nt":
        return
    suffix = Path(executable).suffix.lower()
    if suffix in WINDOWS_SHELL_WRAPPER_SUFFIXES:
        raise LiveRunPreflightError(
            "shell_wrapper_executable",
            f"the configured executable {executable!r} is a {suffix} shell-script wrapper; "
            "name a native executable (for example node.exe) and pass the launcher script "
            "with --executable-prefix-arg instead, so no shell interpreter is invoked",
        )


def _resolve_executable(executable: str) -> str:
    _reject_windows_shell_wrapper(executable)
    candidate = Path(executable)
    if candidate.is_absolute() or candidate.parent != Path("."):
        if not candidate.is_file():
            raise LiveRunPreflightError(
                "executable_unavailable", f"the configured executable {executable!r} is not a file"
            )
        return str(candidate)
    resolved = shutil.which(executable)
    if resolved is None:
        raise LiveRunPreflightError(
            "executable_unavailable", f"the configured executable {executable!r} is not on PATH"
        )
    return resolved


def _resolve_launcher_file(value: str, *, target_workspace: Path) -> str:
    candidate = Path(value)
    if not candidate.exists():
        raise LiveRunPreflightError(
            "launcher_file_missing", f"the required launcher file {value!r} does not exist"
        )
    if not candidate.is_file():
        raise LiveRunPreflightError(
            "launcher_file_not_a_file", f"the required launcher file {value!r} is not a regular file"
        )
    resolved = candidate.resolve()
    if resolved == target_workspace or target_workspace in resolved.parents:
        raise LiveRunPreflightError(
            "launcher_file_in_target_workspace",
            f"the required launcher file {value!r} resolves inside the target application workspace",
        )
    return str(resolved)


def _disjoint(a: Path, b: Path) -> bool:
    """True iff neither path is the other and neither contains the other."""

    return not (a == b or a in b.parents or b in a.parents)


def _validate_mandatory_paths(paths: tuple[str, ...]) -> None:
    """Every mandatory path must be canonical, unique, and non-escaping."""

    if not paths:
        raise LiveRunPreflightError("no_mandatory_paths", "the mission declares no mandatory paths")
    if len(set(paths)) != len(paths):
        raise LiveRunPreflightError("duplicate_mandatory_path", "mandatory paths are not a unique set")
    alias_keys: dict[str, str] = {}
    for path in paths:
        candidate = Path(path)
        if candidate.is_absolute() or path != os.path.normpath(path).replace(os.sep, "/"):
            raise LiveRunPreflightError(
                "non_canonical_mandatory_path", f"mandatory path {path!r} is not canonical/relative"
            )
        if ".." in candidate.parts or path.startswith("/"):
            raise LiveRunPreflightError(
                "escaping_mandatory_path", f"mandatory path {path!r} escapes the workspace"
            )
        key = path.casefold() if os.name == "nt" else path
        if key in alias_keys:
            raise LiveRunPreflightError(
                "aliased_mandatory_path",
                f"mandatory path {path!r} aliases {alias_keys[key]!r} on this filesystem",
            )
        alias_keys[key] = path


def _read_mission_source(args: argparse.Namespace) -> str:
    """The raw mission text, from ``--mission-file`` if given, else the summary."""

    if args.mission_file:
        candidate = Path(args.mission_file)
        if not candidate.is_file():
            raise LiveRunPreflightError(
                "mission_file_missing", f"the mission file {args.mission_file!r} does not exist or is not a file"
            )
        try:
            return candidate.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise LiveRunPreflightError("mission_file_unreadable", f"the mission file cannot be read: {exc}") from exc
    return args.mission_summary


def _session_persisted(store_directory: Path, session_id: str) -> bool:
    """True iff a durable V0 session file already exists for this id (a resume).

    This is a pure filesystem probe: it must never create the store directory
    (constructing :class:`AtomicSessionStore` would), or it could pollute a target
    workspace whose overlap with the store is exactly what preflight checks next.
    """

    return (Path(store_directory) / f"{session_id}.v0.json").is_file()


def preflight(args: argparse.Namespace) -> LiveRunPreflight:
    """Validate everything before any durable, active-looking state exists."""

    resolved_executable = _resolve_executable(args.executable)

    # Resolve and normalize the operator mission *before* anything durable.  A
    # ``--mission-file`` (if given) is the mission source; otherwise the
    # ``--mission-summary`` value is.  The normalized text is the only mission
    # authority that will be persisted.
    mission_source = _read_mission_source(args)
    mission_specification = normalize_mission(mission_source)

    target = Path(args.target_workspace)
    if not target.is_dir():
        raise LiveRunPreflightError("invalid_target_workspace", "the target workspace must be an existing directory")
    target = target.resolve()
    # A *clean* target: no already-present files.  A first live run always starts
    # from an empty target so nothing can be silently clobbered.  A resume of an
    # already-persisted session is exempt: its effects are the prior run's.
    if not _session_persisted(Path(args.store_directory), args.session_id) and any(target.iterdir()):
        raise LiveRunPreflightError(
            "unclean_target_workspace",
            "the target workspace must be empty for a first live run; it already contains entries",
        )

    agent = Path(args.agent_workspace)
    agent.parent.mkdir(parents=True, exist_ok=True)
    agent.mkdir(parents=True, exist_ok=True)
    agent = agent.resolve()
    if not _disjoint(agent, target):
        raise LiveRunPreflightError(
            "workspace_overlap",
            "the isolated agent workspace must be physically separate from the target workspace",
        )

    store_directory = Path(args.store_directory)
    if store_directory.exists() and not store_directory.is_dir():
        raise LiveRunPreflightError("invalid_store_path", "the store path exists and is not a directory")
    resolved_store = store_directory.resolve() if store_directory.exists() else (store_directory.parent.resolve() / store_directory.name)
    if not _disjoint(resolved_store, target) or not _disjoint(resolved_store, agent):
        raise LiveRunPreflightError(
            "store_overlap",
            "the session store must be separate from both the target and the isolated agent workspace",
        )

    policy = WorkspaceIntegrationPolicy(
        allowed_live_workspace_roots=tuple(args.allowed_workspace_root),
        rejected_workspace_roots=tuple(args.rejected_workspace_root),
    )
    try:
        # Allowed-root containment and rejected artifact-root policy are both
        # exercised here, before any session exists.
        policy.capture_workspace_authority(target)
    except WorkspaceIntegrationError as exc:
        raise LiveRunPreflightError("invalid_target_policy", str(exc)) from exc

    mandatory_paths = MISSION_MANDATORY_PATHS
    _validate_mandatory_paths(mandatory_paths)

    prefix_args = tuple(
        _resolve_launcher_file(value, target_workspace=target) for value in args.executable_prefix_arg
    )

    if args.invocation_limit != MAX_CURSOR_INVOCATIONS:
        raise LiveRunPreflightError(
            "invalid_invocation_limit",
            f"the live invocation limit must be exactly {MAX_CURSOR_INVOCATIONS}",
        )
    if args.operation_limit != MAX_OPERATIONS_PER_RESULT:
        raise LiveRunPreflightError(
            "invalid_operation_limit",
            f"the per-result operation limit must be exactly {MAX_OPERATIONS_PER_RESULT}",
        )
    if args.write_limit != MAX_TARGET_WRITES:
        raise LiveRunPreflightError(
            "invalid_write_limit", f"the target write limit must be exactly {MAX_TARGET_WRITES}"
        )

    try:
        config = CursorBackendConfig(
            executable=args.executable,
            agent_workspace=agent,
            executable_prefix_args=prefix_args,
            model=args.model,
            timeout_seconds=args.timeout_seconds,
            max_operations=MAX_OPERATIONS_PER_RESULT,
        )
    except ValueError as exc:
        raise LiveRunPreflightError("invalid_backend_config", str(exc)) from exc

    return LiveRunPreflight(
        executable=args.executable,
        resolved_executable=resolved_executable,
        executable_prefix_args=prefix_args,
        config=config,
        target_workspace=target,
        agent_workspace=agent,
        store_directory=store_directory,
        session_id=args.session_id,
        contract_id=args.contract_id,
        mission_specification=mission_specification,
        allowed_workspace_roots=tuple(args.allowed_workspace_root),
        rejected_workspace_roots=tuple(args.rejected_workspace_root),
        mandatory_paths=mandatory_paths,
        model=args.model,
        timeout_seconds=args.timeout_seconds,
    )


# --------------------------------------------------------------------------
# Bounded-contract description and expected trajectory
# --------------------------------------------------------------------------


def _expected_trajectory() -> tuple[str, ...]:
    return (
        "session_created (PLAN -> READY_TO_INVOKE)",
        "invocation 1 requested -> dispatch prepared -> Cursor call #1 (<=4 ops)",
        "admit batch 1 -> execute batch 1 (4 bounded writes) -> READY_TO_INVOKE",
        "invocation 2 requested -> dispatch prepared -> Cursor call #2 (<=4 ops)",
        "admit batch 2 -> execute batch 2 (4 bounded writes) -> CHECKING_FILES",
        "exactly one structural check (all 8 mandatory paths present) -> AWAITING_HUMAN",
        f"{POST_TERMINAL_STABILITY_CHECKS} reconstructed NoEvent polls: byte-stable, no effects",
    )


def describe(pre: LiveRunPreflight, *, real: bool) -> str:
    config = pre.config
    lines = [
        "=== Admissible V0 Slice 4: first complete real two-turn Cursor trajectory ===",
        "persisted mission (exact text that will be sent to Cursor):",
    ]
    lines.extend(f"    {line}" if line.strip() else "" for line in pre.mission_specification.split("\n"))
    lines.extend([
        f"contract id                   : {pre.contract_id}",
        f"executable                    : {pre.executable}",
        f"resolved executable           : {pre.resolved_executable}",
        f"executable prefix arguments   : {list(config.executable_prefix_args) or '(none)'}",
        f"effective argv template       : {' '.join(config.fixed_arguments())}",
        f"target workspace              : {pre.target_workspace}",
        f"isolated agent workspace      : {pre.agent_workspace}",
        f"durable session store         : {pre.store_directory}",
        f"session id                    : {pre.session_id}",
        f"allowed live workspace roots  : {list(pre.allowed_workspace_roots)}",
        f"rejected artifact roots       : {list(pre.rejected_workspace_roots) or '(none)'}",
        f"mandatory paths ({len(pre.mandatory_paths)})            : {list(pre.mandatory_paths)}",
        f"backend identity              : {BACKEND_IDENTITY} ({BACKEND_PROTOCOL_VERSION})",
        f"transport identity            : {TRANSPORT_IDENTITY}",
        f"model                         : {config.model}",
        f"timeout (seconds)             : {config.timeout_seconds}",
        "--- hard bounded contract ---",
        f"maximum Cursor invocations    : {MAX_CURSOR_INVOCATIONS}",
        f"operations per result         : {MAX_OPERATIONS_PER_RESULT}",
        f"admitted operations           : {MAX_ADMITTED_OPERATIONS}",
        f"target writes                 : {MAX_TARGET_WRITES}",
        f"automatic retries             : {MAX_AUTOMATIC_RETRIES} (every uncertain completion fails closed)",
        f"repair rounds                 : {MAX_REPAIR_ROUNDS} (DISABLED)",
        f"runtime / browser attempts    : {MAX_RUNTIME_ATTEMPTS} (DISABLED)",
        f"structural checks             : {MAX_STRUCTURAL_CHECKS} (only after all mandatory paths exist)",
        f"expected final phase          : {EXPECTED_FINAL_PHASE.value}",
        f"post-terminal stability polls : {POST_TERMINAL_STABILITY_CHECKS}",
        "proposal-only mode            : yes (Cursor never writes the target workspace)",
        "automatic repair              : DISABLED",
        "runtime verification          : DISABLED",
        "--- expected state trajectory ---",
    ])
    lines.extend(f"  {index}. {step}" for index, step in enumerate(_expected_trajectory(), start=1))
    lines.append(f"this invocation               : {'REAL (up to two process calls)' if real else 'DRY RUN (no process)'}")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# The real driver
# --------------------------------------------------------------------------


def _admitted_operation_count(state: SessionState) -> int:
    total = sum(len(batch.admitted_operation_ids) for batch in state.batch_history)
    if state.current_batch is not None:
        total += len(state.current_batch.admitted_operation_ids)
    return total


def _selected_command(state: SessionState) -> str | None:
    command = state.pending_command
    return None if command is None else command.kind.value


def _enforce_budget(
    state: SessionState,
    *,
    backend: CursorCallableProposalBackend,
    executor: BoundedLocalExecutorV0Adapter,
    checker: V0StructuralChecker,
) -> None:
    """The independent budget layer: fail closed if any hard limit is breached."""

    if backend.invocation_count > MAX_CURSOR_INVOCATIONS:
        raise LiveRunBudgetExceeded(
            "invocation_budget", f"{backend.invocation_count} Cursor invocations exceed {MAX_CURSOR_INVOCATIONS}"
        )
    if executor.write_count > MAX_TARGET_WRITES:
        raise LiveRunBudgetExceeded(
            "write_budget", f"{executor.write_count} target writes exceed {MAX_TARGET_WRITES}"
        )
    if _admitted_operation_count(state) > MAX_ADMITTED_OPERATIONS:
        raise LiveRunBudgetExceeded(
            "admission_budget",
            f"{_admitted_operation_count(state)} admitted operations exceed {MAX_ADMITTED_OPERATIONS}",
        )
    if checker.check_count > MAX_STRUCTURAL_CHECKS:
        raise LiveRunBudgetExceeded(
            "structural_budget", f"{checker.check_count} structural checks exceed {MAX_STRUCTURAL_CHECKS}"
        )
    # Each admitted/proposed batch may carry at most the per-result operation limit.
    batches = list(state.batch_history)
    if state.current_batch is not None:
        batches.append(state.current_batch)
    for batch in batches:
        if len(batch.proposed_operations) > MAX_OPERATIONS_PER_RESULT:
            raise LiveRunBudgetExceeded(
                "operation_budget",
                f"a batch proposed {len(batch.proposed_operations)} operations, above {MAX_OPERATIONS_PER_RESULT}",
            )
    # A structural check may be prepared only once every mandatory path exists.
    command = state.pending_command
    if (
        command is not None
        and command.kind.value == "run_structural_check"
        and state.remaining_paths()
    ):
        raise LiveRunBudgetExceeded(
            "premature_structural_check",
            "a structural check was prepared while mandatory paths remain outstanding",
        )


def build_integration_config(
    pre: LiveRunPreflight,
    *,
    runner: V0ProcessRunner | None = None,
) -> tuple[V0OfflineIntegrationConfig, CursorCallableProposalBackend, BoundedLocalExecutorV0Adapter, V0StructuralChecker]:
    """Assemble the exact existing offline integration around the real backend.

    The ``max_invocations=2`` bound on the backend makes a third Cursor call
    structurally impossible; the bounded executor is the only writer; the
    structural checker runs at most once.  Nothing here is a new state machine.
    """

    store = AtomicSessionStore(pre.store_directory)
    backend = CursorCallableProposalBackend(
        config=pre.config,
        target_workspace=pre.target_workspace,
        store=store,
        max_invocations=MAX_CURSOR_INVOCATIONS,
    )
    if runner is not None:
        backend.runner = runner
    executor = BoundedLocalExecutorV0Adapter()
    checker = V0StructuralChecker()
    config = V0OfflineIntegrationConfig(
        store_directory=pre.store_directory,
        session_id=pre.session_id,
        contract=cli008_contract(
            target_workspace=pre.target_workspace,
            contract_id=pre.contract_id,
            mission_specification=pre.mission_specification,
        ),
        proposal_backend=backend,
        bounded_executor_adapter=executor,
        structural_checker=checker,
        workspace_integration_policy=WorkspaceIntegrationPolicy(
            allowed_live_workspace_roots=pre.allowed_workspace_roots,
            rejected_workspace_roots=pre.rejected_workspace_roots,
        ),
        occurred_at="v0-cursor-live-run",
    )
    return config, backend, executor, checker


def run_live_trajectory(
    pre: LiveRunPreflight,
    *,
    runner: V0ProcessRunner | None = None,
) -> LiveRunOutcome:
    """Drive one full real trajectory through the existing offline orchestrator.

    Every logical tick reconstructs the engine/orchestrator from disk (a fresh
    :class:`V0OfflineOrchestrator` per step), so no in-memory state carries the
    session forward.  The loop stops the instant a terminal phase is reached, a
    budget would be exceeded, or a technical pause occurs -- there is no
    automatic continuation past any of those.
    """

    config, backend, executor, checker = build_integration_config(pre, runner=runner)

    def fresh() -> V0OfflineOrchestrator:
        return V0OfflineOrchestrator(config)

    transitions: list[TransitionRecord] = []
    budget_breach = ""

    # Resume-or-create is decided from persisted state only.  A session that
    # already exists is never re-created; if its immutable persisted mission
    # differs from the operator-approved mission for this run, reject *before*
    # any dispatch -- the runner never invokes a provider on a mission conflict.
    store = AtomicSessionStore(pre.store_directory)
    try:
        existing = store.load(pre.session_id)
    except Exception:
        existing = None
    if existing is not None:
        if existing.contract.mission_specification != pre.mission_specification:
            raise LiveRunMissionMismatch(
                f"session {pre.session_id!r} already exists with a different persisted mission; "
                "refusing to resume it under a changed mission (no Cursor process was started)"
            )
        loaded = existing
        transitions.append(
            TransitionRecord(
                step_index=0,
                step_kind="resumed_from_disk",
                revision=loaded.revision,
                phase=loaded.phase.value,
                selected_command=_selected_command(loaded),
            )
        )
    else:
        creation = fresh().create_session()
        transitions.append(
            TransitionRecord(
                step_index=0,
                step_kind=creation.step_kind.value,
                revision=creation.tick.state.revision,
                phase=creation.tick.state.phase.value,
                selected_command=_selected_command(creation.tick.state),
            )
        )

    step_index = 0
    while True:
        state = fresh().load_state()
        if state.phase in TERMINAL_PHASES:
            break
        step_index += 1
        if step_index > MAX_LOGICAL_STEPS:
            budget_breach = f"logical_step_budget: exceeded {MAX_LOGICAL_STEPS} logical steps"
            break
        # Independent budget gate *before* selecting the next external command.
        try:
            _enforce_budget(state, backend=backend, executor=executor, checker=checker)
        except LiveRunBudgetExceeded as exc:
            budget_breach = str(exc)
            _fail_closed(fresh(), pre.session_id, exc)
            break

        step: OrchestratorStepResult = fresh().run_logical_tick()
        after = step.tick.state
        transitions.append(
            TransitionRecord(
                step_index=step_index,
                step_kind=step.step_kind.value,
                revision=after.revision,
                phase=after.phase.value,
                selected_command=_selected_command(after),
            )
        )
        # Independent budget gate *after* the effect is durable.
        try:
            _enforce_budget(fresh().load_state(), backend=backend, executor=executor, checker=checker)
        except LiveRunBudgetExceeded as exc:
            budget_breach = str(exc)
            _fail_closed(fresh(), pre.session_id, exc)
            break

    # Twenty reconstructed NoEvent polls after the terminal state.
    stability = _stability_ticks(fresh, pre.session_id)

    final_state = fresh().load_state()
    technical_failure = ""
    if final_state.outcome_reason is not None:
        technical_failure = f"{final_state.outcome_reason.code.value}: {final_state.outcome_reason.message}"

    return LiveRunOutcome(
        dry_run=False,
        session_id=pre.session_id,
        transitions=tuple(transitions),
        invocation_count=backend.invocation_count,
        result_count=backend.results_consumed,
        admitted_operations=_admitted_operation_count(final_state),
        physical_writes=executor.write_count,
        durable_receipts=len(final_state.execution_receipt_history),
        evidence_count=len(final_state.materialized_evidence),
        remaining_mandatory_paths=tuple(final_state.remaining_paths()),
        structural_checks=checker.check_count,
        final_phase=final_state.phase.value,
        technical_failure=technical_failure,
        stability_ticks=stability,
        target_manifest=_target_manifest(pre.target_workspace, pre.mandatory_paths),
        remaining_cursor_process_ids=(),  # cleanup is proven by the backend before any result is trusted
        budget_breach=budget_breach,
    )


def _fail_closed(orchestrator: V0OfflineOrchestrator, session_id: str, exc: LiveRunBudgetExceeded) -> None:
    """Persist a fail-closed technical pause when a budget is breached.

    This reuses the engine's existing ``TechnicalFault`` path; it never invents a
    new terminal transition.  If the session is already terminal, the NoEvent
    tick is a stable no-op.
    """

    from admissible.v0_controller.events import TechnicalFault
    from admissible.v0_controller.state import OutcomeReason, ReasonCode

    engine = orchestrator.fresh_engine()
    state = orchestrator.load_state()
    if state.phase in {Phase.COMPLETED, Phase.FAILED, Phase.TECHNICAL_PAUSE, Phase.AWAITING_HUMAN}:
        return
    engine.tick(
        session_id,
        TechnicalFault(
            OutcomeReason(
                ReasonCode.COMMAND_OUTCOME_UNCERTAIN,
                f"live_run_budget_exceeded: {exc}",
                "The live runner refused to continue because a hard budget would be exceeded. "
                "Inspect the persisted session and start a new one if needed.",
            )
        ),
    )


def _stability_ticks(fresh, session_id: str) -> tuple[StabilityTick, ...]:
    baseline = fresh().load_state().canonical_bytes()
    baseline_sha = hashlib.sha256(baseline).hexdigest()
    ticks: list[StabilityTick] = []
    for _ in range(POST_TERMINAL_STABILITY_CHECKS):
        step = fresh().run_no_event_tick()
        state = step.tick.state
        current = state.canonical_bytes()
        ticks.append(
            StabilityTick(
                revision=state.revision,
                phase=state.phase.value,
                canonical_sha256=hashlib.sha256(current).hexdigest(),
                byte_stable=current == baseline,
            )
        )
    return tuple(ticks)


def _target_manifest(target_workspace: Path, mandatory_paths: tuple[str, ...]) -> tuple[TargetFile, ...]:
    manifest: list[TargetFile] = []
    for path in mandatory_paths:
        candidate = target_workspace / Path(path)
        if candidate.is_file():
            data = candidate.read_bytes()
            manifest.append(
                TargetFile(path=path, present=True, sha256=hashlib.sha256(data).hexdigest(), byte_count=len(data))
            )
        else:
            manifest.append(TargetFile(path=path, present=False, sha256=None, byte_count=None))
    return tuple(manifest)


def _git_status() -> str:
    try:
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover - environment dependent
        return f"(git status unavailable: {exc})"
    if result.returncode != 0:
        return f"(git status exit {result.returncode})"
    return result.stdout.strip() or "(clean)"


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def _print_report(outcome: LiveRunOutcome) -> None:
    print(f"\nsession id            : {outcome.session_id}")
    print("--- logical transitions (revision / phase / selected command) ---")
    for record in outcome.transitions:
        print(
            f"  step {record.step_index:>2}: rev={record.revision:<3} "
            f"phase={record.phase:<16} kind={record.step_kind:<22} "
            f"command={record.selected_command or '(none)'}"
        )
    print("--- totals ---")
    print(f"cursor invocations    : {outcome.invocation_count} (maximum {MAX_CURSOR_INVOCATIONS})")
    print(f"consumed results      : {outcome.result_count}")
    print(f"admitted operations   : {outcome.admitted_operations} (maximum {MAX_ADMITTED_OPERATIONS})")
    print(f"physical writes       : {outcome.physical_writes} (maximum {MAX_TARGET_WRITES})")
    print(f"durable receipts      : {outcome.durable_receipts}")
    print(f"materialized evidence : {outcome.evidence_count}")
    print(f"remaining mandatory   : {list(outcome.remaining_mandatory_paths) or '(none)'}")
    print(f"structural checks     : {outcome.structural_checks} (maximum {MAX_STRUCTURAL_CHECKS})")
    print(f"final phase           : {outcome.final_phase} (expected {EXPECTED_FINAL_PHASE.value})")
    print(f"technical failure     : {outcome.technical_failure or 'none'}")
    print(f"budget breach         : {outcome.budget_breach or 'none'}")
    print(
        f"stability polls       : {len(outcome.stability_ticks)} "
        f"(byte-stable: {outcome.stability_byte_stable})"
    )
    print("--- target file manifest (sha256 / bytes) ---")
    for item in outcome.target_manifest:
        if item.present:
            print(f"  {item.path:<18} present sha256={item.sha256} bytes={item.byte_count}")
        else:
            print(f"  {item.path:<18} MISSING")
    print(f"remaining cursor procs: {list(outcome.remaining_cursor_process_ids) or '(none, cleanup proven)'}")
    print(f"git status            :\n{_git_status()}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="v0_cursor_live_run", description=__doc__)
    parser.add_argument("--executable", help="Native Cursor CLI executable, e.g. node.exe or cursor-agent")
    parser.add_argument(
        "--executable-prefix-arg",
        action="append",
        default=[],
        help=(
            "An explicit operator-trusted launcher argument inserted between the executable and the "
            "fixed Cursor arguments (repeatable, order preserved). Each value is a required launcher file."
        ),
    )
    parser.add_argument("--target-workspace", help="The real, empty application workspace (never written by Cursor)")
    parser.add_argument("--agent-workspace", help="The isolated proposal workspace handed to Cursor")
    parser.add_argument("--store-directory", help="Directory for the durable V0 session state")
    parser.add_argument("--session-id", default="v0-cursor-live-run")
    parser.add_argument("--contract-id", default=DEFAULT_CONTRACT_ID)
    parser.add_argument(
        "--mission-summary",
        default=DEFAULT_MISSION_SUMMARY,
        help="The operator mission text (normalized and persisted immutably; the sole mission authority)",
    )
    parser.add_argument(
        "--mission-file",
        default="",
        help="A UTF-8 file whose contents are the mission (overrides --mission-summary when given)",
    )
    parser.add_argument("--model", default="auto")
    parser.add_argument("--timeout-seconds", type=float, default=900.0)
    parser.add_argument(
        "--allowed-workspace-root",
        action="append",
        default=[],
        help="Explicit allowed root for the target workspace (repeatable, required)",
    )
    parser.add_argument(
        "--rejected-workspace-root",
        action="append",
        default=[],
        help="Explicit rejected artifact-output root (repeatable, optional)",
    )
    parser.add_argument("--invocation-limit", type=int, default=MAX_CURSOR_INVOCATIONS)
    parser.add_argument("--operation-limit", type=int, default=MAX_OPERATIONS_PER_RESULT)
    parser.add_argument("--write-limit", type=int, default=MAX_TARGET_WRITES)
    parser.add_argument("--execute", action="store_true", help="Attempt the REAL two-turn Cursor trajectory")
    parser.add_argument(
        "--confirm-real-run",
        action="store_true",
        help="Second, independent acknowledgement required alongside --execute",
    )
    return parser


def _missing(args: argparse.Namespace) -> list[str]:
    required = {
        "--executable": args.executable,
        "--target-workspace": args.target_workspace,
        "--agent-workspace": args.agent_workspace,
        "--store-directory": args.store_directory,
        "--allowed-workspace-root": args.allowed_workspace_root,
    }
    return [name for name, value in required.items() if not value]


def main(argv: list[str] | None = None, *, runner: V0ProcessRunner | None = None) -> int:
    args = build_parser().parse_args(argv)
    missing = _missing(args)
    if missing:
        print("Live runner is inert: missing required configuration: " + ", ".join(missing))
        print("Nothing was invoked. Supply every option above to validate a real configuration.")
        return 2

    real = bool(args.execute and args.confirm_real_run)
    try:
        pre = preflight(args)
    except LiveRunPreflightError as exc:
        print(f"Live-run preflight failed: {exc}")
        print("No V0 session was created and no process was started.")
        return 2

    print(describe(pre, real=real))
    if not real:
        print("\nDRY RUN: configuration validated. No session was created and no Cursor process was started.")
        print("Pass BOTH --execute and --confirm-real-run to perform the real two-turn trajectory.")
        return 0

    print("\nREAL RUN: creating (or resuming) the V0 session and driving the two-turn trajectory ...")
    try:
        outcome = run_live_trajectory(pre, runner=runner)
    except LiveRunMissionMismatch as exc:
        print(f"\nMISSION MISMATCH: {exc}")
        return 2
    _print_report(outcome)

    ok = (
        not outcome.technical_failure
        and not outcome.budget_breach
        and outcome.final_phase == EXPECTED_FINAL_PHASE.value
        and outcome.invocation_count <= MAX_CURSOR_INVOCATIONS
        and outcome.physical_writes <= MAX_TARGET_WRITES
        and outcome.structural_checks <= MAX_STRUCTURAL_CHECKS
        and not outcome.remaining_mandatory_paths
        and outcome.stability_byte_stable
    )
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover - operator entry point
    sys.exit(main())
