"""Operator-driven one-call canary for the V0 Cursor callable backend (Slice 3).

The canary exists for exactly one purpose: prove that **one** real Cursor
proposal invocation happens and that its typed result can be inspected.  It is
not a run, not a demo, and not an execution path.

By construction it never:

- admits a proposal;
- constructs or calls the bounded executor;
- writes one byte of the target workspace;
- runs a structural check, runtime, repair, or continuation;
- makes a second provider invocation;
- retries anything.

It is **inert** unless the operator supplies every required piece of
configuration, and it **defaults to dry-run**.  A real invocation requires the
conjunction of ``--execute`` *and* ``--confirm-real-invocation``; either flag
alone stays a dry run.  Nothing here is imported by the controller, the
orchestrator, or any offline test of them.

Example (dry-run, the default)::

    python -m admissible.diagnostics.v0_cursor_canary \
        --executable cursor-agent \
        --target-workspace /path/to/app \
        --agent-workspace /path/to/isolated-agent-ws \
        --store-directory /path/to/sessions \
        --allowed-workspace-root /path/to
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from admissible.v0_controller.cursor_backend import (
    BACKEND_IDENTITY,
    BACKEND_PROTOCOL_VERSION,
    TRANSPORT_IDENTITY,
    CursorBackendConfig,
    CursorCallableProposalBackend,
    V0ProcessRunner,
)
from admissible.v0_controller.cursor_dispatch import PersistedCursorDispatchRequest
from admissible.v0_controller.cursor_failures import V0ProposalBackendFailure
from admissible.v0_controller.cursor_instruction import expected_batch_id
from admissible.v0_controller.commands import CommandKind
from admissible.v0_controller.engine import V0ControllerEngine
from admissible.v0_controller.events import CommandDispatchStarted, TechnicalFault
from admissible.v0_controller.integration_policy import (
    WorkspaceIntegrationError,
    WorkspaceIntegrationPolicy,
)
from admissible.v0_controller.orchestrator import cli008_contract
from admissible.v0_controller.state import OutcomeReason, Phase, ReasonCode, new_session_state
from admissible.v0_controller.store import AtomicSessionStore

# The canary's whole contract, as constants an auditor can read in one place.
MAX_INVOCATIONS = 1
MAX_OPERATIONS = 4
MAX_TARGET_WRITES = 0
MAX_EXECUTOR_CALLS = 0
MAX_STRUCTURAL_CHECKS = 0
MAX_AUTOMATIC_RETRIES = 0

CANARY_PAUSE_CODE = "canary_complete_no_execution"

# Filename extensions that name a shell-script wrapper rather than a native
# executable.  On Windows these are launched through a shell interpreter, so the
# canary refuses them as the configured executable and asks the operator to name
# a native executable plus explicit prefix arguments instead.  This is a bounded
# canary/preflight guard, not a universal claim that a filename extension is an
# executable-security mechanism.
WINDOWS_SHELL_WRAPPER_SUFFIXES = (".ps1", ".cmd", ".bat")


class CanaryPreflightError(ValueError):
    """A configuration fault found *before* any durable session can exist."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class CanaryPreflight:
    """Everything validated before a session that looks active is ever created."""

    executable: str
    resolved_executable: str
    config: CursorBackendConfig
    target_workspace: Path
    agent_workspace: Path
    store_directory: Path
    session_id: str
    allowed_workspace_roots: tuple[str, ...]
    executable_prefix_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class CanaryOutcome:
    """The bounded, typed summary of one canary run."""

    dry_run: bool
    invocations: int
    operations: int
    target_writes: int = 0
    executor_calls: int = 0
    structural_checks: int = 0
    proposed_paths: tuple[str, ...] = ()
    final_phase: str = ""
    failure: str = ""


def _reject_windows_shell_wrapper(executable: str) -> None:
    """On Windows, refuse a shell-script wrapper as the configured executable."""

    if os.name != "nt":
        return
    suffix = Path(executable).suffix.lower()
    if suffix in WINDOWS_SHELL_WRAPPER_SUFFIXES:
        raise CanaryPreflightError(
            "shell_wrapper_executable",
            f"the configured executable {executable!r} is a {suffix} shell-script wrapper; "
            "name a native executable (for example node.exe) and pass the launcher script "
            "with --executable-prefix-arg instead, so no shell interpreter is invoked",
        )


def _resolve_launcher_file(value: str, *, target_workspace: Path) -> str:
    """Validate one operator prefix argument declared as a required launcher file."""

    candidate = Path(value)
    if not candidate.exists():
        raise CanaryPreflightError(
            "launcher_file_missing", f"the required launcher file {value!r} does not exist"
        )
    if not candidate.is_file():
        raise CanaryPreflightError(
            "launcher_file_not_a_file", f"the required launcher file {value!r} is not a regular file"
        )
    resolved = candidate.resolve()
    if resolved == target_workspace or target_workspace in resolved.parents:
        raise CanaryPreflightError(
            "launcher_file_in_target_workspace",
            f"the required launcher file {value!r} resolves inside the target application workspace",
        )
    return str(resolved)


def _resolve_executable(executable: str) -> str:
    _reject_windows_shell_wrapper(executable)
    candidate = Path(executable)
    if candidate.is_absolute() or candidate.parent != Path("."):
        if not candidate.is_file():
            raise CanaryPreflightError(
                "executable_unavailable", f"the configured executable {executable!r} is not a file"
            )
        return str(candidate)
    resolved = shutil.which(executable)
    if resolved is None:
        raise CanaryPreflightError(
            "executable_unavailable", f"the configured executable {executable!r} is not on PATH"
        )
    return resolved


def preflight(args: argparse.Namespace) -> CanaryPreflight:
    """Validate everything before creating any durable, active-looking state.

    A missing executable, an invalid or overlapping workspace, a rejected live
    root, or an invalid limit must fail *here* -- never after a session exists
    that appears active or in-flight.
    """

    resolved_executable = _resolve_executable(args.executable)

    target = Path(args.target_workspace)
    if not target.is_dir():
        raise CanaryPreflightError("invalid_target_workspace", "the target workspace must be an existing directory")
    target = target.resolve()
    agent = Path(args.agent_workspace)
    agent.parent.mkdir(parents=True, exist_ok=True)
    agent.mkdir(parents=True, exist_ok=True)
    agent = agent.resolve()
    if agent == target or target in agent.parents or agent in target.parents:
        raise CanaryPreflightError(
            "workspace_overlap",
            "the isolated agent workspace must not be, contain, or sit inside the target workspace",
        )

    policy = WorkspaceIntegrationPolicy(allowed_live_workspace_roots=tuple(args.allowed_workspace_root))
    try:
        policy.capture_workspace_authority(target)
    except WorkspaceIntegrationError as exc:
        raise CanaryPreflightError("invalid_target_policy", str(exc)) from exc

    store_directory = Path(args.store_directory)
    if store_directory.exists() and not store_directory.is_dir():
        raise CanaryPreflightError("invalid_store_path", "the store path exists and is not a directory")

    # Every operator prefix argument is a required launcher file: it must exist,
    # be a regular file, resolve canonically, and never live inside the target
    # workspace.  The resolved paths are what enter the fingerprinted config.
    prefix_args = tuple(
        _resolve_launcher_file(value, target_workspace=target)
        for value in args.executable_prefix_arg
    )

    try:
        config = CursorBackendConfig(
            executable=args.executable,
            agent_workspace=agent,
            executable_prefix_args=prefix_args,
            model=args.model,
            timeout_seconds=args.timeout_seconds,
            max_operations=MAX_OPERATIONS,
        )
    except ValueError as exc:
        raise CanaryPreflightError("invalid_backend_config", str(exc)) from exc

    return CanaryPreflight(
        executable=args.executable,
        resolved_executable=resolved_executable,
        config=config,
        target_workspace=target,
        agent_workspace=agent,
        store_directory=store_directory,
        session_id=args.session_id,
        allowed_workspace_roots=tuple(args.allowed_workspace_root),
        executable_prefix_args=prefix_args,
    )


def describe(pre: CanaryPreflight, *, real: bool) -> str:
    config = pre.config
    lines = [
        "=== Admissible V0 Slice 3: one-call Cursor proposal canary ===",
        f"executable                    : {pre.executable}",
        f"resolved executable           : {pre.resolved_executable}",
        f"executable prefix arguments   : {list(config.executable_prefix_args) or '(none)'}",
        f"fixed cursor arguments        : {' '.join(config.fixed_cursor_arguments())}",
        f"effective argv template       : {' '.join(config.fixed_arguments())}",
        f"target workspace              : {pre.target_workspace}",
        f"isolated agent workspace      : {pre.agent_workspace}",
        f"durable session store         : {pre.store_directory}",
        f"session id                    : {pre.session_id}",
        f"backend identity              : {BACKEND_IDENTITY} ({BACKEND_PROTOCOL_VERSION})",
        f"transport identity            : {TRANSPORT_IDENTITY}",
        f"model                         : {config.model}",
        f"timeout (seconds)             : {config.timeout_seconds}",
        f"raw diagnostic retention cap  : {config.max_capture_bytes} bytes",
        f"total stdout stream limit     : {config.max_total_stream_bytes} bytes",
        f"stderr limit                  : {config.max_stderr_bytes} bytes",
        f"canonical result limit        : {config.max_canonical_result_bytes} bytes",
        f"maximum Cursor invocations    : {MAX_INVOCATIONS}",
        f"maximum parsed operations     : {MAX_OPERATIONS}",
        f"target writes                 : {MAX_TARGET_WRITES} (DISABLED)",
        f"executor calls                : {MAX_EXECUTOR_CALLS} (trusted executor is never constructed)",
        f"structural checks             : {MAX_STRUCTURAL_CHECKS} (DISABLED)",
        f"automatic retries             : {MAX_AUTOMATIC_RETRIES} (every uncertain completion fails closed)",
        "proposal-only mode            : yes (Cursor never writes the target workspace)",
        "runtime verification          : DISABLED",
        "automatic repair              : DISABLED",
        "continuation / admission      : DISABLED",
        f"this invocation               : {'REAL (one process call)' if real else 'DRY RUN (no process)'}",
    ]
    return "\n".join(lines)


def run_one_call_canary(
    pre: CanaryPreflight,
    *,
    runner: V0ProcessRunner | None = None,
) -> CanaryOutcome:
    """The whole real flow: one persisted dispatch, one process, then stop.

    This is a dedicated canary method on purpose.  It never calls the general
    ``run_logical_tick()`` loop, so there is no driver that could carry the
    session on into admission or execution.
    """

    store = AtomicSessionStore(pre.store_directory)
    backend = CursorCallableProposalBackend(
        config=pre.config,
        target_workspace=pre.target_workspace,
        store=store,
        max_invocations=MAX_INVOCATIONS,
    )
    if runner is not None:
        backend.runner = runner
    engine = V0ControllerEngine(
        store,
        bounded_executor_adapter=None,  # the executor is never even constructed
        dispatch_backend_fingerprint=backend.config_fingerprint,
    )
    policy = WorkspaceIntegrationPolicy(allowed_live_workspace_roots=pre.allowed_workspace_roots)

    # 1) the dedicated canary session
    engine.create_session(
        new_session_state(
            session_id=pre.session_id,
            contract=cli008_contract(target_workspace=pre.target_workspace),
            workspace_authority=policy.capture_workspace_authority(pre.target_workspace),
        ),
        occurred_at="v0-cursor-canary",
    )
    # 2) exactly one persisted invocation command
    engine.tick(pre.session_id)
    state = store.load(pre.session_id)
    command = state.pending_command
    if command is None or command.kind != CommandKind.DISPATCH_AGENT or command.command_id is None:
        raise CanaryPreflightError("no_dispatch_command", "the canary session did not persist a dispatch command")
    # 3) persisted dispatch start
    started = engine.tick(pre.session_id, CommandDispatchStarted(command.command_id))
    dispatched = started.state
    if dispatched.phase != Phase.WAITING_FOR_AGENT or dispatched.pending_command is None:
        raise CanaryPreflightError("no_dispatch_state", "the canary session is not persistently waiting for the agent")

    failure = ""
    operations: tuple[str, ...] = ()
    result = None
    try:
        # 4) exactly one Cursor invocation, through store-backed persisted authority
        result = backend.invoke_persisted(
            request=PersistedCursorDispatchRequest(
                session_id=pre.session_id,
                command_id=command.command_id,
                invocation_id=command.owner_id,
                batch_id=expected_batch_id(dispatched, command.owner_id),
                expected_revision=dispatched.revision,
                backend_fingerprint=backend.config_fingerprint,
            )
        )
        # 5) parse and validate exactly one typed V0ProposalResult
        operations = tuple(item.path for item in result.operations)
        # 6) inspect it only.  The result is never turned into an AgentResultReceived
        #    fact, so no ADMIT_PROPOSAL command can ever be created.
        backend.mark_result_consumed(result)
    except V0ProposalBackendFailure as exc:
        failure = str(exc)

    # 7) settle immediately into a stable, non-executing operator state
    backend.close(reason=CANARY_PAUSE_CODE)
    paused = engine.tick(
        pre.session_id,
        TechnicalFault(
            OutcomeReason(
                ReasonCode.COMMAND_OUTCOME_UNCERTAIN,
                f"{CANARY_PAUSE_CODE}: the canary observed one Cursor proposal and stopped. "
                f"{'Failure: ' + failure if failure else 'A typed proposal result was inspected only.'}",
                "This session is a canary. It must never be resumed: it can neither admit nor execute. "
                "Inspect the printed result and start a real V0 session if you want execution.",
            )
        ),
    )
    # 8) stop.
    return CanaryOutcome(
        dry_run=False,
        invocations=backend.invocation_count,
        operations=len(result.operations) if result is not None else 0,
        proposed_paths=operations,
        final_phase=paused.state.phase.value,
        failure=failure,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="v0_cursor_canary", description=__doc__)
    parser.add_argument("--executable", help="Cursor CLI executable, e.g. cursor-agent")
    parser.add_argument(
        "--executable-prefix-arg",
        action="append",
        default=[],
        help=(
            "An explicit operator-trusted launcher argument inserted between the executable "
            "and the fixed Cursor arguments (repeatable, order preserved). Each value is treated "
            "as a required launcher file and must exist. Example: the Cursor index.js for a native "
            "node.exe launch."
        ),
    )
    parser.add_argument("--target-workspace", help="The real application workspace (never written by the canary)")
    parser.add_argument("--agent-workspace", help="The isolated proposal workspace handed to Cursor")
    parser.add_argument("--store-directory", help="Directory for the durable V0 canary session state")
    parser.add_argument("--session-id", default="v0-cursor-canary")
    parser.add_argument("--model", default="auto")
    parser.add_argument("--timeout-seconds", type=float, default=900.0)
    parser.add_argument(
        "--allowed-workspace-root",
        action="append",
        default=[],
        help="Explicit allowed root for the target workspace (repeatable, required)",
    )
    parser.add_argument("--execute", action="store_true", help="Attempt the single REAL Cursor invocation")
    parser.add_argument(
        "--confirm-real-invocation",
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
        print("Canary is inert: missing required configuration: " + ", ".join(missing))
        print("Nothing was invoked. Supply every option above to validate a real configuration.")
        return 2

    real = bool(args.execute and args.confirm_real_invocation)
    try:
        pre = preflight(args)
    except CanaryPreflightError as exc:
        # No session, no store entry, nothing in-flight: the fault is pre-durable.
        print(f"Canary preflight failed: {exc}")
        print("No V0 session was created and no process was started.")
        return 2

    print(describe(pre, real=real))
    if not real:
        print("\nDRY RUN: configuration validated. No session was created and no Cursor process was started.")
        print("Pass BOTH --execute and --confirm-real-invocation to perform the single real invocation.")
        return 0

    print("\nREAL INVOCATION: creating the dedicated canary session (one call, no execution) ...")
    outcome = run_one_call_canary(pre, runner=runner)
    print(f"\ncursor invocations    : {outcome.invocations} (maximum {MAX_INVOCATIONS})")
    print(f"parsed operations     : {outcome.operations} (maximum {MAX_OPERATIONS})")
    print(f"proposed paths        : {list(outcome.proposed_paths)}")
    print(f"target writes         : {outcome.target_writes}")
    print(f"executor calls        : {outcome.executor_calls}")
    print(f"structural checks     : {outcome.structural_checks}")
    print(f"final phase           : {outcome.final_phase}")
    print(f"failure               : {outcome.failure or 'none'}")
    print(f"\nThe canary session is now {CANARY_PAUSE_CODE!r}: it cannot admit, execute, or continue.")
    return 0 if not outcome.failure and outcome.invocations == MAX_INVOCATIONS else 1


if __name__ == "__main__":  # pragma: no cover - operator entry point
    sys.exit(main())
