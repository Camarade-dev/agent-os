"""The minimal real Cursor callable proposal backend (V0 Slice 3).

This backend implements the same ``V0ProposalBackend`` protocol as
``FixtureProposalBackend``.  It receives one *already persisted, already
in-flight* dispatch command, invokes the configured ``cursor-agent`` process
exactly once, observes its bounded NDJSON stdout, and extracts exactly one typed
``V0ProposalResult``.

What it is not allowed to do, by construction:

- it never writes the target application workspace (Cursor is given an isolated
  agent workspace; the bounded executor is the only writer);
- it never executes shell, package, server, browser, network, deploy, or
  arbitrary project commands -- the only executable it can start is the one
  named in its explicit configuration, spawned as an argument vector with
  ``shell=False``;
- it never creates or repairs lifecycle state, and never retries.

The only new authority is the typed backend result.  Raw stdout, stderr,
terminal text, Cursor status text, and diagnostics are bounded evidence only.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from admissible.managed_process import ManagedProcessError, run_managed_oneshot
from admissible.v0_controller.adapters import (
    MAX_PROPOSAL_OPERATIONS,
    V0ProposalResult,
)
from admissible.v0_controller.commands import Command
from admissible.v0_controller.cursor_context import (
    DEFAULT_MAX_CONTEXT_BYTES,
    build_persisted_context,
    reattest_materialized_targets,
)
from admissible.v0_controller.cursor_dispatch import (
    AuthorizedCursorDispatch,
    CursorDispatchAuthority,
    PersistedCursorDispatchRequest,
)
from admissible.v0_controller.cursor_envelope import parse_proposal_envelope
from admissible.v0_controller.cursor_failures import (
    V0BackendFailureKind,
    V0ProposalBackendFailure,
)
from admissible.v0_controller.cursor_instruction import (
    build_governed_instruction,
    render_governed_prompt,
)
from admissible.v0_controller.cursor_ndjson import (
    DEFAULT_MALFORMED_LINE_TOLERANCE,
    DEFAULT_MAX_CANONICAL_RESULT_BYTES,
    TERMINAL_CANONICAL_TOO_LARGE,
    TERMINAL_DUPLICATE,
    TERMINAL_FAILURE,
    TERMINAL_MALFORMED,
    TERMINAL_MISSING,
    TERMINAL_SUCCESS,
    IncrementalNdjsonAccumulator,
    NdjsonObservation,
)
from admissible.v0_controller.cursor_workspace import V0AgentWorkspace
from admissible.v0_controller.store import AtomicSessionStore

BACKEND_IDENTITY = "v0-cursor-callable-proposal-backend"
BACKEND_PROTOCOL_VERSION = "cursor-callable-proposal-v1"
TRANSPORT_IDENTITY = "cursor-agent-oneshot-stream-json"

DEFAULT_TIMEOUT_SECONDS = 900.0
DEFAULT_MAX_CAPTURE_BYTES = 512 * 1024
DEFAULT_MAX_TOTAL_STREAM_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_STDERR_BYTES = 64 * 1024

DEFAULT_ENVIRONMENT_ALLOWLIST: tuple[str, ...] = (
    "APPDATA",
    "COMSPEC",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "LANG",
    "LC_ALL",
    "LOCALAPPDATA",
    "PATH",
    "PATHEXT",
    "SHELL",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "USERPROFILE",
)


# ---------------------------------------------------------------------------
# Process boundary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class V0ProcessInvocation:
    """Everything the process boundary is allowed to know."""

    argv: tuple[str, ...]
    cwd: str
    env: Mapping[str, str]
    timeout_seconds: float
    max_capture_bytes: int


@dataclass(frozen=True)
class V0ProcessOutcome:
    """Bounded facts about one completed (or terminated) process."""

    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    output_truncated: bool
    cleanup_proven: bool
    remaining_process_ids: tuple[int, ...] = ()
    observed_stdout_bytes: int = 0
    observed_stderr_bytes: int = 0


class V0ProcessRunner(Protocol):
    """The one seam through which a V0 backend may start an external process."""

    def run(
        self,
        invocation: V0ProcessInvocation,
        *,
        on_stdout_line: Callable[[str], None],
    ) -> V0ProcessOutcome:
        ...


@dataclass
class ManagedCursorProcessRunner:
    """The real runner: an argument vector, ``shell=False``, owned process tree.

    Cleanup is delegated to ``admissible.managed_process``, which contains the
    whole ``.CMD -> powershell -> node`` chain in a Job Object (Windows) or a
    process session (POSIX) so no orphan survives success, timeout, malformed
    output, or cancellation -- and *proves* it with a liveness re-check.
    """

    def run(
        self,
        invocation: V0ProcessInvocation,
        *,
        on_stdout_line: Callable[[str], None],
    ) -> V0ProcessOutcome:
        executable = invocation.argv[0]
        if not self._executable_available(executable):
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.EXECUTABLE_UNAVAILABLE,
                f"The configured Cursor executable {executable!r} was not found on this host.",
            )
        try:
            outcome = run_managed_oneshot(
                list(invocation.argv),
                cwd=invocation.cwd,
                env=dict(invocation.env),
                timeout_seconds=invocation.timeout_seconds,
                max_capture_bytes=invocation.max_capture_bytes,
                on_stdout_line=on_stdout_line,
            )
        except ManagedProcessError as exc:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.PROCESS_START_FAILED,
                f"The Cursor process could not be started: {exc}",
            ) from exc
        process = outcome.process_result
        return V0ProcessOutcome(
            returncode=outcome.returncode,
            stdout=outcome.stdout,
            stderr=outcome.stderr,
            timed_out=outcome.timed_out,
            output_truncated=process.output_truncated,
            cleanup_proven=process.cleanup_proven,
            remaining_process_ids=tuple(process.remaining_process_ids),
            observed_stdout_bytes=process.stdout_bytes,
            observed_stderr_bytes=process.stderr_bytes,
        )

    @staticmethod
    def _executable_available(executable: str) -> bool:
        candidate = Path(executable)
        if candidate.is_absolute() or candidate.parent != Path("."):
            return candidate.is_file()
        return shutil.which(executable) is not None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CursorBackendConfig:
    """Explicit configuration.  No owner path or executable is ever inferred."""

    executable: str
    agent_workspace: Path
    executable_prefix_args: tuple[str, ...] = ()
    model: str = "auto"
    mode: str = "ask"
    trust: bool = True
    stream_partial_output: bool = True
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_capture_bytes: int = DEFAULT_MAX_CAPTURE_BYTES
    max_total_stream_bytes: int = DEFAULT_MAX_TOTAL_STREAM_BYTES
    max_stderr_bytes: int = DEFAULT_MAX_STDERR_BYTES
    max_canonical_result_bytes: int = DEFAULT_MAX_CANONICAL_RESULT_BYTES
    malformed_line_tolerance: int = DEFAULT_MALFORMED_LINE_TOLERANCE
    max_operations: int = MAX_PROPOSAL_OPERATIONS
    max_context_bytes: int | None = None
    include_materialized_content: bool = True
    environment_allowlist: tuple[str, ...] = DEFAULT_ENVIRONMENT_ALLOWLIST
    extra_environment: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.executable:
            raise ValueError("an explicit Cursor executable is required")
        object.__setattr__(self, "executable_prefix_args", tuple(self.executable_prefix_args))
        for arg in self.executable_prefix_args:
            if not isinstance(arg, str) or arg == "":
                raise ValueError("every executable prefix argument must be a non-empty string")
            if "\x00" in arg:
                raise ValueError("executable prefix arguments may not contain null bytes")
        if self.max_operations < 1 or self.max_operations > MAX_PROPOSAL_OPERATIONS:
            raise ValueError(f"max_operations must be between 1 and {MAX_PROPOSAL_OPERATIONS}")
        if min(
            self.timeout_seconds,
            self.max_capture_bytes,
            self.max_total_stream_bytes,
            self.max_stderr_bytes,
            self.max_canonical_result_bytes,
        ) <= 0:
            raise ValueError("all Cursor backend limits must be positive")

    def argv(self, *, agent_workspace: Path, prompt: str) -> tuple[str, ...]:
        """The fixed argument vector.  Nothing here comes from agent output."""

        argv = [self.executable, *self.executable_prefix_args, "--print", "--output-format", "stream-json"]
        if self.stream_partial_output:
            argv.append("--stream-partial-output")
        argv.extend(["--mode", self.mode, "--model", self.model, "--workspace", str(agent_workspace)])
        if self.trust:
            argv.append("--trust")
        argv.append(prompt)
        return tuple(argv)

    def fixed_arguments(self) -> tuple[str, ...]:
        """The complete argv template with the prompt and workspace elided.

        This is the full effective argv shape (executable, operator prefix
        arguments, fixed Cursor arguments, prompt placeholder) as it would be
        spawned -- suitable for a canary dry-run summary.
        """

        return self.argv(agent_workspace=Path("{agent_workspace}"), prompt="{prompt}")

    def fixed_cursor_arguments(self) -> tuple[str, ...]:
        """Only the fixed Cursor arguments, without the executable or the operator prefix."""

        prefix_len = len(self.executable_prefix_args)
        return self.fixed_arguments()[1 + prefix_len :]

    def build_environment(self, *, base: Mapping[str, str] | None = None) -> dict[str, str]:
        """Bounded inherited environment: an explicit allowlist plus explicit extras."""

        source = os.environ if base is None else base
        allowed = {name.upper() for name in self.environment_allowlist}
        env = {key: value for key, value in source.items() if key.upper() in allowed}
        env.update(dict(self.extra_environment))
        return env

    def fingerprint(self) -> str:
        """Stable identity of the backend configuration for result correlation."""

        identity = {
            "backend": BACKEND_IDENTITY,
            "protocol_version": BACKEND_PROTOCOL_VERSION,
            "transport": TRANSPORT_IDENTITY,
            "executable": self.executable,
            "executable_prefix_args": list(self.executable_prefix_args),
            "model": self.model,
            "mode": self.mode,
            "trust": self.trust,
            "stream_partial_output": self.stream_partial_output,
            "agent_workspace": str(self.agent_workspace),
            "limits": {
                "timeout_seconds": self.timeout_seconds,
                "max_capture_bytes": self.max_capture_bytes,
                "max_total_stream_bytes": self.max_total_stream_bytes,
                "max_stderr_bytes": self.max_stderr_bytes,
                "max_canonical_result_bytes": self.max_canonical_result_bytes,
                "max_operations": self.max_operations,
            },
        }
        blob = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Exact-once correlation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CursorResultBinding:
    """What a Cursor result must correlate to before it can be consumed once."""

    session_id: str
    invocation_id: str
    command_id: str
    batch_id: str
    config_fingerprint: str
    dispatch_nonce: str
    issued_revision: int

    @classmethod
    def from_authorized(cls, authorized: AuthorizedCursorDispatch) -> "CursorResultBinding":
        capability = authorized.capability
        return cls(
            session_id=capability.session_id,
            invocation_id=capability.invocation_id,
            command_id=capability.command_id,
            batch_id=capability.batch_id,
            config_fingerprint=capability.backend_fingerprint,
            dispatch_nonce=authorized.dispatch_authority_nonce,
            issued_revision=capability.issued_revision,
        )


# ---------------------------------------------------------------------------
# Backend
# ---------------------------------------------------------------------------


@dataclass
class CursorCallableProposalBackend:
    """Proposal-only Cursor backend implementing the ``V0ProposalBackend`` protocol.

    The real process runner is reachable through exactly one path:
    :meth:`invoke_persisted`, which accepts stable identifiers only and then
    *independently reloads* the session from the authoritative store through
    :class:`CursorDispatchAuthority`.  A caller-supplied ``Command`` -- however
    in-flight it looks -- is never dispatch authority.
    """

    config: CursorBackendConfig
    target_workspace: Path
    store: AtomicSessionStore
    runner: V0ProcessRunner = field(default_factory=ManagedCursorProcessRunner)
    max_invocations: int | None = None
    identity: str = BACKEND_IDENTITY
    protocol_version: str = BACKEND_PROTOCOL_VERSION
    transport_identity: str = TRANSPORT_IDENTITY
    retained_diagnostic_total_bytes: int = 0

    _invocation_count: int = 0
    _results_consumed: int = 0
    _closed: bool = False
    _active_binding: CursorResultBinding | None = None
    _bindings: dict[str, CursorResultBinding] = field(default_factory=dict)
    _consumed_result_ids: set[str] = field(default_factory=set)
    _last_observation: NdjsonObservation | None = None
    _last_agent_workspace: Path | None = None
    _agent_workspace: V0AgentWorkspace | None = None
    _closed_reason: str = ""

    def __post_init__(self) -> None:
        # The operator prefix is trusted launcher configuration; it must never
        # smuggle the real application workspace path in as a Cursor argument.
        candidates = {str(self.target_workspace)}
        try:
            candidates.add(str(Path(self.target_workspace).resolve()))
        except OSError:
            pass
        for arg in self.config.executable_prefix_args:
            for target in candidates:
                if target and target in arg:
                    raise ValueError(
                        "an executable prefix argument may not contain the target application workspace path; "
                        "the prefix is launcher configuration only."
                    )

    # -- protocol surface ----------------------------------------------------

    @property
    def invocation_count(self) -> int:
        return self._invocation_count

    @property
    def results_consumed(self) -> int:
        return self._results_consumed

    @property
    def config_fingerprint(self) -> str:
        return self.config.fingerprint()

    @property
    def last_observation(self) -> NdjsonObservation | None:
        return self._last_observation

    @property
    def last_agent_workspace(self) -> Path | None:
        return self._last_agent_workspace

    @property
    def authority(self) -> CursorDispatchAuthority:
        return CursorDispatchAuthority(store=self.store, backend_fingerprint=self.config_fingerprint)

    @property
    def agent_workspace(self) -> V0AgentWorkspace:
        if self._agent_workspace is None:
            self._agent_workspace = V0AgentWorkspace(
                root=Path(self.config.agent_workspace),
                include_materialized_content=self.config.include_materialized_content,
                **(
                    {"max_context_bytes": self.config.max_context_bytes}
                    if self.config.max_context_bytes is not None
                    else {}
                ),
            )
        return self._agent_workspace

    def close(self, *, reason: str = "terminal") -> None:
        """Refuse every later result: the session is paused, cancelled, or terminal."""

        self._closed = True
        self._active_binding = None
        self._closed_reason = reason

    def invoke(self, *, command: Command, instruction: Mapping[str, Any]) -> V0ProposalResult:
        """Refused by construction: a Command object is not dispatch authority.

        The ``V0ProposalBackend`` protocol keeps this method so a fixture and the
        real backend stay substitutable, but the real backend will not start a
        process from caller-supplied objects.  ``invoke_persisted`` is the only
        path to the process runner.
        """

        raise V0ProposalBackendFailure(
            V0BackendFailureKind.PERSISTED_DISPATCH_REJECTED,
            "The real Cursor backend dispatches only through store-backed persisted authority; "
            "a caller-supplied Command and instruction are not dispatch authority.",
        )

    def invoke_persisted(self, *, request: PersistedCursorDispatchRequest) -> V0ProposalResult:
        """Invoke ``cursor-agent`` exactly once for one *persisted* dispatch.

        Every check below happens before the process runner is reachable.  If any
        of them fails, the runner invocation count stays where it was, no process
        starts, and no output is parsed.
        """

        self._guard_backend_state(request)
        authorized = self.authority.authorize(request)
        binding = CursorResultBinding.from_authorized(authorized)
        if binding.invocation_id in self._bindings:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.DISPATCH_ORDER_VIOLATION,
                f"Invocation {binding.invocation_id!r} was already dispatched to Cursor by this backend; "
                "it is never invoked twice.",
            )

        state = authorized.state
        # Persisted facts are the only instruction authority; the live target is
        # re-attested, never read for content.
        reattest_materialized_targets(state)
        snapshot = build_persisted_context(
            state,
            include_materialized_content=self.config.include_materialized_content,
            max_context_bytes=(
                self.config.max_context_bytes
                if self.config.max_context_bytes is not None
                else DEFAULT_MAX_CONTEXT_BYTES
            ),
        )
        instruction = build_governed_instruction(
            state=state,
            command=authorized.command,
            materialized_context={
                item.path: item.content_bytes.decode("utf-8") for item in snapshot.files
            },
        )
        if instruction["batch_id"] != binding.batch_id or instruction["invocation_id"] != binding.invocation_id:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.PERSISTED_DISPATCH_REJECTED,
                "The governed instruction does not carry the authorized persisted dispatch identity.",
            )
        prompt = render_governed_prompt(instruction)
        agent_workspace = self.agent_workspace.materialize(
            target_workspace=Path(self.target_workspace),
            instruction=instruction,
            prompt=prompt,
            snapshot=snapshot,
        )
        self._last_agent_workspace = agent_workspace

        accumulator = IncrementalNdjsonAccumulator(
            malformed_line_tolerance=self.config.malformed_line_tolerance,
            max_canonical_result_bytes=self.config.max_canonical_result_bytes,
        )
        process = V0ProcessInvocation(
            argv=self.config.argv(agent_workspace=agent_workspace, prompt=prompt),
            cwd=str(agent_workspace),
            env=self.config.build_environment(),
            timeout_seconds=self.config.timeout_seconds,
            max_capture_bytes=self.config.max_capture_bytes,
        )
        self._invocation_count += 1
        self._bindings[binding.invocation_id] = binding
        self._active_binding = binding

        outcome = self.runner.run(process, on_stdout_line=accumulator.feed_line)
        observation = accumulator.finalize(raw_capture_truncated=outcome.output_truncated)
        self._last_observation = observation

        self._classify_process_outcome(outcome, observation)
        canonical = self._require_terminal_success(observation)
        envelope = parse_proposal_envelope(
            canonical,
            expected_invocation_id=binding.invocation_id,
            expected_batch_id=binding.batch_id,
            max_operations=self.config.max_operations,
        )
        return self._build_result(
            binding=binding,
            envelope_operations=envelope.operations,
            observation=observation,
            outcome=outcome,
        )

    def mark_result_consumed(self, result: V0ProposalResult | None = None) -> None:
        """Consume one correlated result exactly once."""

        if result is None:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.STALE_RESULT,
                "The Cursor backend consumes only an explicit typed result.",
            )
        if self._closed:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.TERMINAL_STATE_REJECTED,
                "A Cursor result arrived after technical pause, cancellation, or a terminal state.",
            )
        if result.result_id in self._consumed_result_ids:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.DUPLICATE_RESULT_CONSUMPTION,
                f"Result {result.result_id!r} was already consumed; a result is consumable exactly once.",
            )
        active = self._active_binding
        binding = self._bindings.get(result.invocation_id)
        if binding is None or active is None or binding != active:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.STALE_RESULT,
                f"Result for invocation {result.invocation_id!r} does not correlate to the active "
                "dispatched Cursor invocation.",
            )
        if result.config_fingerprint != binding.config_fingerprint:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.BACKEND_FINGERPRINT_MISMATCH,
                "The result was not produced under the dispatched backend configuration fingerprint.",
            )
        if result.dispatch_nonce != binding.dispatch_nonce:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.STALE_RESULT,
                "The result does not carry the independently correlated dispatch nonce.",
            )
        if result.batch_id != binding.batch_id:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.INVOCATION_MISMATCH,
                f"Result batch {result.batch_id!r} does not match the expected turn batch "
                f"{binding.batch_id!r}.",
            )
        self._consumed_result_ids.add(result.result_id)
        self._results_consumed += 1
        self._active_binding = None

    def retain_diagnostic_stream(self, stream: str) -> tuple[str, bool]:
        """Bound the retained raw diagnostic text; truncation is always explicit."""

        encoded = stream.encode("utf-8")
        cap = self.config.max_capture_bytes
        if len(encoded) > cap:
            retained = encoded[:cap].decode("utf-8", errors="ignore")
            self.retained_diagnostic_total_bytes += len(retained.encode("utf-8"))
            return retained, True
        self.retained_diagnostic_total_bytes += len(encoded)
        return stream, False

    # -- internals -----------------------------------------------------------

    def _guard_backend_state(self, request: PersistedCursorDispatchRequest) -> None:
        """Backend-instance guards that precede the store-backed authority check."""

        if self._closed:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.TERMINAL_STATE_REJECTED,
                "The Cursor backend is closed; a paused, cancelled, or terminal session is never redispatched.",
            )
        if self._active_binding is not None:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.DISPATCH_ORDER_VIOLATION,
                "A previous Cursor result has not been consumed; the backend never runs two invocations at once.",
            )
        if self.max_invocations is not None and self._invocation_count >= self.max_invocations:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.DISPATCH_ORDER_VIOLATION,
                f"The configured maximum of {self.max_invocations} Cursor invocation(s) is already reached.",
            )
        if request.backend_fingerprint != self.config_fingerprint:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.BACKEND_FINGERPRINT_MISMATCH,
                "The dispatch request does not name this backend's configuration fingerprint.",
            )

    def _classify_process_outcome(self, outcome: V0ProcessOutcome, observation: NdjsonObservation) -> None:
        if not outcome.cleanup_proven:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.PROCESS_CLEANUP_FAILED,
                "The Cursor process tree could not be proven terminated; refusing to trust its output. "
                f"Remaining process ids: {list(outcome.remaining_process_ids)}.",
                diagnostics=observation.diagnostic_facts(),
            )
        if outcome.timed_out:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.TIMEOUT,
                f"The Cursor process exceeded its {self.config.timeout_seconds}-second bounded timeout.",
                diagnostics=observation.diagnostic_facts(),
            )
        observed = max(outcome.observed_stdout_bytes, observation.diagnostics.get("observed_stdout_bytes", 0))
        if observed > self.config.max_total_stream_bytes:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.OUTPUT_LIMIT_EXCEEDED,
                f"Cursor produced {observed} stdout bytes, above the "
                f"{self.config.max_total_stream_bytes}-byte total stream limit.",
                diagnostics=observation.diagnostic_facts(),
            )
        if outcome.observed_stderr_bytes > self.config.max_stderr_bytes:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.OUTPUT_LIMIT_EXCEEDED,
                f"Cursor produced {outcome.observed_stderr_bytes} stderr bytes, above the "
                f"{self.config.max_stderr_bytes}-byte stderr limit.",
                diagnostics=observation.diagnostic_facts(),
            )
        if outcome.returncode != 0:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.NONZERO_EXIT,
                f"The Cursor process exited with code {outcome.returncode!r}.",
                diagnostics=observation.diagnostic_facts(),
            )

    def _require_terminal_success(self, observation: NdjsonObservation) -> str:
        kinds = {
            TERMINAL_DUPLICATE: V0BackendFailureKind.DUPLICATE_TERMINAL_RESULT,
            TERMINAL_FAILURE: V0BackendFailureKind.TERMINAL_FAILURE,
            TERMINAL_MISSING: V0BackendFailureKind.MISSING_TERMINAL_RESULT,
            TERMINAL_MALFORMED: V0BackendFailureKind.MALFORMED_NDJSON,
            TERMINAL_CANONICAL_TOO_LARGE: V0BackendFailureKind.CANONICAL_RESULT_TOO_LARGE,
        }
        if observation.classification != TERMINAL_SUCCESS:
            raise V0ProposalBackendFailure(
                kinds.get(observation.classification, V0BackendFailureKind.MALFORMED_NDJSON),
                observation.message or "Cursor produced no authoritative terminal result.",
                diagnostics=observation.diagnostic_facts(),
            )
        canonical = observation.canonical_result or ""
        if not canonical.strip():
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.MALFORMED_NDJSON,
                "The authoritative terminal result carried no text.",
                diagnostics=observation.diagnostic_facts(),
            )
        return canonical

    def _build_result(
        self,
        *,
        binding: CursorResultBinding,
        envelope_operations: tuple[Any, ...],
        observation: NdjsonObservation,
        outcome: V0ProcessOutcome,
    ) -> V0ProposalResult:
        terminal = observation.terminal_event or {}
        raw_result_id = terminal.get("id") or terminal.get("session_id")
        diagnostic_identity = str(raw_result_id) if isinstance(raw_result_id, (str, int)) else "unnamed"
        diagnostics = (
            *observation.diagnostic_facts(),
            f"cursor_raw_result_identity:{diagnostic_identity[:128]}",
            f"cursor_exit_code:{outcome.returncode}",
            f"cursor_stderr_bytes:{outcome.observed_stderr_bytes}",
            f"backend_config_fingerprint:{binding.config_fingerprint}",
            f"dispatch_issued_revision:{binding.issued_revision}",
        )
        return V0ProposalResult(
            invocation_id=binding.invocation_id,
            # Lifecycle authority is the persisted invocation/command correlation;
            # the raw Cursor id above is retained only as diagnostic identity.
            result_id=f"{binding.invocation_id}:{binding.command_id}:cursor-result",
            batch_id=binding.batch_id,
            response_reference=f"cursor://{self.transport_identity}/{binding.invocation_id}",
            operations=envelope_operations,
            diagnostics=diagnostics,
            retained_diagnostic_stream=outcome.stdout,
            output_truncated=outcome.output_truncated,
            backend_identity=self.identity,
            model_identity=self.config.model,
            transport_identity=self.transport_identity,
            config_fingerprint=binding.config_fingerprint,
            dispatch_nonce=binding.dispatch_nonce,
        )


def cursor_backend_from_config(
    *,
    executable: str,
    agent_workspace: Path,
    target_workspace: Path,
    store_directory: Path,
    runner: V0ProcessRunner | None = None,
    max_invocations: int | None = None,
    **overrides: Any,
) -> CursorCallableProposalBackend:
    """Explicit construction helper; no owner path or default executable is implied.

    The store directory is required: without the authoritative store there is no
    persisted dispatch authority, and therefore no legal way to start Cursor.
    """

    config = CursorBackendConfig(executable=executable, agent_workspace=Path(agent_workspace), **overrides)
    backend = CursorCallableProposalBackend(
        config=config,
        target_workspace=Path(target_workspace),
        store=AtomicSessionStore(Path(store_directory)),
        max_invocations=max_invocations,
    )
    if runner is not None:
        backend.runner = runner
    return backend


__all__ = [
    "BACKEND_IDENTITY",
    "BACKEND_PROTOCOL_VERSION",
    "DEFAULT_ENVIRONMENT_ALLOWLIST",
    "DEFAULT_MAX_CAPTURE_BYTES",
    "DEFAULT_MAX_STDERR_BYTES",
    "DEFAULT_MAX_TOTAL_STREAM_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "TRANSPORT_IDENTITY",
    "CursorBackendConfig",
    "CursorCallableProposalBackend",
    "CursorDispatchAuthority",
    "CursorResultBinding",
    "ManagedCursorProcessRunner",
    "PersistedCursorDispatchRequest",
    "V0ProcessInvocation",
    "V0ProcessOutcome",
    "V0ProcessRunner",
    "cursor_backend_from_config",
]
