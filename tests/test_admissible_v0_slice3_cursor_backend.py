"""V0 Slice 3: the minimal real Cursor callable proposal backend.

Every test here is offline.  No Cursor process, no provider, and no browser is
ever started: the process boundary is driven by ``FakeCursorProcessRunner``,
which replays saved NDJSON fixtures through the same incremental observation
path the real ``ManagedCursorProcessRunner`` uses.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import tempfile
import unittest
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

from admissible.v0_controller.adapters import (
    BoundedLocalExecutorV0Adapter,
    V0ProposalResult,
    proposal_backend_to_agent_result,
    sha256_file,
)
from admissible.v0_controller.commands import Command, CommandKind, CommandStatus
from admissible.v0_controller.cursor_backend import (
    BACKEND_IDENTITY,
    TRANSPORT_IDENTITY,
    CursorBackendConfig,
    CursorCallableProposalBackend,
    ManagedCursorProcessRunner,
    V0ProcessInvocation,
    V0ProcessOutcome,
)
from admissible.v0_controller.cursor_context import build_persisted_context
from admissible.v0_controller.cursor_dispatch import PersistedCursorDispatchRequest
from admissible.v0_controller.cursor_envelope import (
    ENVELOPE_BEGIN,
    ENVELOPE_END,
    ENVELOPE_SCHEMA_VERSION,
)
from admissible.v0_controller.cursor_failures import V0BackendFailureKind, V0ProposalBackendFailure
from admissible.v0_controller.cursor_instruction import (
    build_governed_instruction,
    expected_batch_id,
    render_governed_prompt,
)
from admissible.v0_controller.cursor_workspace import (
    CONTEXT_DIRECTORY,
    CONTEXT_MANIFEST_FILE,
    INSTRUCTION_FILE,
)
from admissible.v0_controller.events import CommandDispatchStarted
from admissible.v0_controller.integration_policy import WorkspaceIntegrationPolicy
from admissible.v0_controller.orchestrator import (
    CLI008_MANDATORY_PATHS,
    OrchestratorStepKind,
    V0OfflineIntegrationConfig,
    V0OfflineOrchestrator,
    cli008_contract,
)
from admissible.v0_controller.state import InvocationLifecycle, Phase, ProposedOperation, ReasonCode
from admissible.v0_controller.store import AtomicSessionStore
from admissible.v0_controller.structural_checker import V0StructuralChecker

NOW = "2026-07-13T10:00:00Z"


# ---------------------------------------------------------------------------
# NDJSON fixture builders
# ---------------------------------------------------------------------------


def envelope_text(
    *,
    invocation_id: str,
    batch_id: str,
    operations: list[dict[str, Any]],
    schema_version: str = ENVELOPE_SCHEMA_VERSION,
) -> str:
    payload = {
        "schema_version": schema_version,
        "invocation_id": invocation_id,
        "batch_id": batch_id,
        "operations": operations,
    }
    return "\n".join(
        [
            "Here is the proposal.",
            ENVELOPE_BEGIN,
            json.dumps(payload, indent=2, sort_keys=True),
            ENVELOPE_END,
        ]
    )


def event_line(payload: dict[str, Any]) -> str:
    return json.dumps(payload) + "\n"


def assistant_line(text: str) -> str:
    return event_line({"type": "assistant", "message": {"content": [{"type": "text", "text": text}]}})


def result_line(text: str, *, subtype: str = "success", is_error: bool = False, event_id: str = "cur-1") -> str:
    return event_line(
        {"type": "result", "subtype": subtype, "is_error": is_error, "id": event_id, "result": text}
    )


def write_ops(paths: list[str], *, prefix: str) -> list[dict[str, Any]]:
    return [
        {
            "action_id": f"{prefix}-{index}",
            "kind": "write_file",
            "path": path,
            "content": f"// {path}\nexport const generated = {index};\n",
        }
        for index, path in enumerate(paths, start=1)
    ]


def successful_stream(instruction: dict[str, Any], *, padding_lines: int = 0) -> list[str]:
    remaining = list(instruction["remaining_mandatory_paths"])[:4]
    text = envelope_text(
        invocation_id=instruction["invocation_id"],
        batch_id=instruction["batch_id"],
        operations=write_ops(remaining, prefix=instruction["batch_id"].split(":")[-1]),
    )
    lines = [event_line({"type": "system", "subtype": "init"})]
    lines.extend(assistant_line("x" * 4096) for _ in range(padding_lines))
    lines.append(result_line(text))
    return lines


# ---------------------------------------------------------------------------
# Fake process boundary
# ---------------------------------------------------------------------------


@dataclass
class FakeCursorProcessRunner:
    """Replay NDJSON fixtures through the real incremental observation path."""

    stream_builder: Callable[[dict[str, Any]], list[str]] = successful_stream
    returncode: int = 0
    timed_out: bool = False
    cleanup_proven: bool = True
    remaining_process_ids: tuple[int, ...] = ()
    stderr: str = ""
    raise_failure: V0ProposalBackendFailure | None = None

    invocations: list[V0ProcessInvocation] = field(default_factory=list)
    instructions: list[dict[str, Any]] = field(default_factory=list)
    started: int = 0
    cleaned_up: int = 0

    def run(
        self,
        invocation: V0ProcessInvocation,
        *,
        on_stdout_line: Callable[[str], None],
    ) -> V0ProcessOutcome:
        self.started += 1
        self.invocations.append(invocation)
        try:
            if self.raise_failure is not None:
                raise self.raise_failure
            instruction = json.loads((Path(invocation.cwd) / "instruction.json").read_text(encoding="utf-8"))
            self.instructions.append(instruction)
            lines = self.stream_builder(instruction)

            retained: list[str] = []
            total = 0
            truncated = False
            for line in lines:
                total += len(line.encode("utf-8"))
                if total > invocation.max_capture_bytes:
                    truncated = True
                else:
                    retained.append(line)
                on_stdout_line(line)
            return V0ProcessOutcome(
                returncode=self.returncode,
                stdout="".join(retained),
                stderr=self.stderr,
                timed_out=self.timed_out,
                output_truncated=truncated,
                cleanup_proven=self.cleanup_proven,
                remaining_process_ids=self.remaining_process_ids,
                observed_stdout_bytes=total,
                observed_stderr_bytes=len(self.stderr.encode("utf-8")),
            )
        finally:
            # The real runner terminates and *verifies* the owned tree on every
            # exit path — success, timeout, malformed output, or exception.
            self.cleaned_up += 1


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


class CursorBackendHarness:
    def __init__(
        self,
        testcase: unittest.TestCase,
        *,
        runner: FakeCursorProcessRunner | None = None,
        **config_overrides: Any,
    ) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        testcase.addCleanup(self._tmp.cleanup)
        root = Path(self._tmp.name)
        self.root = root
        self.workspace = root / "live_workspace"
        self.workspace.mkdir()
        self.agent_workspace = root / "agent_workspace"
        self.store_dir = root / "sessions"
        self.runner = runner or FakeCursorProcessRunner()
        self.config = CursorBackendConfig(
            executable="cursor-agent",
            agent_workspace=self.agent_workspace,
            **config_overrides,
        )
        self.store = AtomicSessionStore(self.store_dir)
        self.backend = CursorCallableProposalBackend(
            config=self.config,
            target_workspace=self.workspace,
            store=self.store,
            runner=self.runner,
        )
        self.executor = BoundedLocalExecutorV0Adapter()
        self.checker = V0StructuralChecker()
        self.integration_config = V0OfflineIntegrationConfig(
            store_directory=self.store_dir,
            session_id="cli008-cursor-two-batch",
            contract=cli008_contract(target_workspace=self.workspace),
            proposal_backend=self.backend,
            bounded_executor_adapter=self.executor,
            structural_checker=self.checker,
            workspace_integration_policy=WorkspaceIntegrationPolicy(
                allowed_live_workspace_roots=(str(root),),
            ),
            occurred_at=NOW,
        )
        self.orchestrator = V0OfflineOrchestrator(self.integration_config)

    def fresh_orchestrator(self) -> V0OfflineOrchestrator:
        return V0OfflineOrchestrator(self.integration_config)

    def state(self):
        return self.orchestrator.load_state()

    def workspace_snapshot(self) -> dict[str, str]:
        return {
            str(item.relative_to(self.workspace)).replace("\\", "/"): sha256_file(str(item))
            for item in sorted(self.workspace.rglob("*"))
            if item.is_file()
        }

    def prepared_command(self) -> Command:
        """Drive the session to a persisted, *prepared* dispatch command."""

        self.orchestrator.create_session()
        self.fresh_orchestrator().run_logical_tick()  # -> prepared dispatch command
        prepared = self.state().pending_command
        assert prepared is not None and prepared.command_id is not None
        return prepared

    def dispatch_command(self) -> Command:
        """Drive a fresh session to a *durably persisted, in-flight* dispatch command."""

        self.prepared_command()
        return self.dispatch_command_for_current_invocation()

    def dispatch_command_for_current_invocation(self) -> Command:
        """Persist the dispatch start of the session's current invocation."""

        if self.state().pending_command is None:
            self.fresh_orchestrator().run_logical_tick()
        prepared = self.state().pending_command
        assert prepared is not None and prepared.command_id is not None
        if prepared.status == CommandStatus.PREPARED:
            self.fresh_orchestrator().fresh_engine().tick(
                self.integration_config.session_id, CommandDispatchStarted(prepared.command_id)
            )
        in_flight = self.state().pending_command
        assert in_flight is not None and in_flight.status == CommandStatus.IN_FLIGHT
        return in_flight

    def request_for(self, command: Command, **overrides: Any) -> PersistedCursorDispatchRequest:
        state = self.state()
        fields: dict[str, Any] = {
            "session_id": self.integration_config.session_id,
            "command_id": command.command_id or "",
            "invocation_id": command.owner_id,
            "batch_id": expected_batch_id(state, command.owner_id),
            "expected_revision": state.revision,
            "backend_fingerprint": self.backend.config_fingerprint,
        }
        fields.update(overrides)
        return PersistedCursorDispatchRequest(**fields)

    def tamper(self, state) -> None:
        """Write persisted bytes directly, bypassing the store's own validation.

        A tampered session must be *refused* -- either because the store cannot
        even load it, or because the dispatch authority rejects it. Both outcomes
        are the same fact: zero runner calls.
        """

        path = self.store_dir / f"{self.integration_config.session_id}.v0.json"
        path.write_bytes(state.canonical_bytes() + b"\n")

    def instruction_for(self, command: Command) -> dict[str, Any]:
        return build_governed_instruction(state=self.state(), command=command)

    def invoke_once(self) -> V0ProposalResult:
        command = self.dispatch_command()
        return self.backend.invoke_persisted(request=self.request_for(command))

    def advance_to_second_invocation(self) -> None:
        """Run turn 1 to completion and stop just before turn 2 is dispatched."""

        self.orchestrator.create_session()
        for _ in range(32):
            state = self.state()
            if state.phase == Phase.READY_TO_INVOKE and state.materialized_evidence:
                return
            if state.phase in {Phase.AWAITING_HUMAN, Phase.TECHNICAL_PAUSE, Phase.FAILED}:
                break
            self.fresh_orchestrator().run_logical_tick()
        raise AssertionError("the session never reached a second invocation")

    def context_bytes(self, relative: str) -> bytes:
        return (self.agent_workspace.resolve() / CONTEXT_DIRECTORY / Path(relative)).read_bytes()

    def run_to_awaiting_human(self) -> list:
        self.orchestrator.create_session()
        steps = []
        for _ in range(64):
            if self.state().phase in {Phase.AWAITING_HUMAN, Phase.TECHNICAL_PAUSE, Phase.FAILED}:
                break
            steps.append(self.fresh_orchestrator().run_logical_tick())
        return steps


# ---------------------------------------------------------------------------
# Successful proposals
# ---------------------------------------------------------------------------


class TestCursorBackendSuccess(unittest.TestCase):
    def test_successful_four_operation_proposal(self) -> None:
        harness = CursorBackendHarness(self)
        result = harness.invoke_once()
        self.assertEqual(len(result.operations), 4)
        self.assertEqual({item.operation_kind for item in result.operations}, {"write_file"})
        self.assertEqual([item.path for item in result.operations], list(CLI008_MANDATORY_PATHS[:4]))
        self.assertEqual(result.backend_identity, BACKEND_IDENTITY)
        self.assertEqual(result.transport_identity, TRANSPORT_IDENTITY)
        self.assertEqual(result.model_identity, "auto")
        self.assertFalse(result.output_truncated)
        self.assertEqual(harness.backend.invocation_count, 1)
        self.assertEqual(harness.runner.started, 1)

    def test_backend_result_carries_no_execution_evidence(self) -> None:
        harness = CursorBackendHarness(self)
        result = harness.invoke_once()
        blob = json.dumps(
            {
                "diagnostics": list(result.diagnostics),
                "response_reference": result.response_reference,
                "result_id": result.result_id,
            }
        )
        for forbidden in ("receipt", "physical_identity_key", "resolved_target"):
            self.assertNotIn(forbidden, blob)

    def test_successful_second_turn_proposal(self) -> None:
        harness = CursorBackendHarness(self)
        harness.run_to_awaiting_human()
        self.assertEqual(harness.backend.invocation_count, 2)
        self.assertEqual(len(harness.runner.instructions), 2)
        first, second = harness.runner.instructions
        self.assertEqual(first["remaining_mandatory_paths"], list(CLI008_MANDATORY_PATHS))
        self.assertEqual(second["remaining_mandatory_paths"], list(CLI008_MANDATORY_PATHS[4:]))
        self.assertEqual([item["path"] for item in second["materialized_paths"]], list(CLI008_MANDATORY_PATHS[:4]))
        self.assertNotEqual(first["batch_id"], second["batch_id"])

    def test_process_boundary_is_an_argument_vector_in_the_agent_workspace(self) -> None:
        harness = CursorBackendHarness(self)
        harness.invoke_once()
        invocation = harness.runner.invocations[0]
        self.assertEqual(invocation.argv[0], "cursor-agent")
        self.assertIn("--print", invocation.argv)
        self.assertIn("--output-format", invocation.argv)
        self.assertIn("stream-json", invocation.argv)
        self.assertIn("--mode", invocation.argv)
        self.assertIn("ask", invocation.argv)
        self.assertIn("--trust", invocation.argv)
        workspace_arg = invocation.argv[invocation.argv.index("--workspace") + 1]
        self.assertEqual(Path(workspace_arg), harness.agent_workspace.resolve())
        self.assertEqual(Path(invocation.cwd), harness.agent_workspace.resolve())
        # The real target workspace is never handed to Cursor, in any argument.
        self.assertNotIn(str(harness.workspace.resolve()), " ".join(invocation.argv))

    def test_environment_is_a_bounded_allowlist(self) -> None:
        harness = CursorBackendHarness(self, extra_environment={"CURSOR_API_KEY": "token"})
        env = harness.config.build_environment(base={"PATH": "/usr/bin", "SECRET_TOKEN": "leak", "HOME": "/home/x"})
        self.assertEqual(env, {"PATH": "/usr/bin", "HOME": "/home/x", "CURSOR_API_KEY": "token"})

    def test_agent_workspace_receives_only_bounded_proposal_context(self) -> None:
        harness = CursorBackendHarness(self)
        harness.run_to_awaiting_human()
        resolved = harness.agent_workspace.resolve()
        self.assertTrue((resolved / INSTRUCTION_FILE).is_file())
        context_root = resolved / CONTEXT_DIRECTORY
        copied = sorted(str(p.relative_to(context_root)).replace("\\", "/") for p in context_root.rglob("*") if p.is_file())
        self.assertEqual(copied, sorted(CLI008_MANDATORY_PATHS[:4]))
        for relative in copied:
            self.assertEqual(
                sha256_file(str(context_root / relative)),
                sha256_file(str(harness.workspace / relative)),
            )


# ---------------------------------------------------------------------------
# Governed instruction
# ---------------------------------------------------------------------------


class TestGovernedInstruction(unittest.TestCase):
    def test_instruction_is_deterministic_for_equivalent_state(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        first = harness.instruction_for(command)
        second = harness.instruction_for(command)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        self.assertEqual(render_governed_prompt(first), render_governed_prompt(second))

    def test_instruction_states_every_required_boundary(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        instruction = harness.instruction_for(command)
        prompt = render_governed_prompt(instruction)
        self.assertEqual(instruction["operation_limit"], 4)
        self.assertTrue(instruction["proposal_only"])
        self.assertEqual(instruction["batch_id"], expected_batch_id(harness.state(), command.owner_id))
        for path in CLI008_MANDATORY_PATHS:
            self.assertIn(path, prompt)
        for boundary in ("shell", "browser", "network", "deploy", "git", "package_install", "server"):
            self.assertIn(boundary, prompt)
        self.assertIn("COMPLETE final content", prompt)
        self.assertIn("Do not claim runtime", prompt)
        self.assertIn(ENVELOPE_BEGIN, prompt)
        self.assertIn(ENVELOPE_SCHEMA_VERSION, prompt)


# ---------------------------------------------------------------------------
# Output limits
# ---------------------------------------------------------------------------


class TestOutputLimits(unittest.TestCase):
    def test_stream_above_512_kib_still_yields_the_structured_proposal(self) -> None:
        harness = CursorBackendHarness(self, runner=FakeCursorProcessRunner(
            stream_builder=lambda instruction: successful_stream(instruction, padding_lines=160),
        ))
        result = harness.invoke_once()
        observation = harness.backend.last_observation
        assert observation is not None
        self.assertGreater(observation.diagnostics["observed_stdout_bytes"], 512 * 1024)
        self.assertEqual(len(result.operations), 4)

    def test_output_above_diagnostic_cap_truncates_only_diagnostics(self) -> None:
        harness = CursorBackendHarness(self, runner=FakeCursorProcessRunner(
            stream_builder=lambda instruction: successful_stream(instruction, padding_lines=200),
        ))
        command = harness.dispatch_command()
        result = harness.backend.invoke_persisted(request=harness.request_for(command))
        observation = harness.backend.last_observation
        assert observation is not None
        self.assertTrue(observation.diagnostics["raw_capture_truncated"])
        self.assertTrue(result.output_truncated)
        # The terminal event arrives last and still survives a truncated capture.
        self.assertEqual(len(result.operations), 4)
        self.assertNotIn(ENVELOPE_BEGIN, result.retained_diagnostic_stream)
        agent_event = proposal_backend_to_agent_result(
            backend=harness.backend, command=command, result=result
        )
        self.assertIn("diagnostic_stream_truncated", agent_event.diagnostics)
        self.assertLessEqual(
            len(result.retained_diagnostic_stream.encode("utf-8")), harness.config.max_capture_bytes
        )

    def test_total_stream_above_its_limit_fails_closed(self) -> None:
        harness = CursorBackendHarness(
            self,
            runner=FakeCursorProcessRunner(
                stream_builder=lambda instruction: successful_stream(instruction, padding_lines=40),
            ),
            max_total_stream_bytes=64 * 1024,
        )
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.invoke_once()
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.OUTPUT_LIMIT_EXCEEDED)

    def test_canonical_result_over_its_limit_fails_closed(self) -> None:
        def oversized(instruction: dict[str, Any]) -> list[str]:
            return [result_line("x" * 5000)]

        harness = CursorBackendHarness(
            self,
            runner=FakeCursorProcessRunner(stream_builder=oversized),
            max_canonical_result_bytes=1024,
        )
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.invoke_once()
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.CANONICAL_RESULT_TOO_LARGE)

    def test_stderr_above_its_limit_fails_closed(self) -> None:
        harness = CursorBackendHarness(
            self,
            runner=FakeCursorProcessRunner(stderr="e" * 4096),
            max_stderr_bytes=1024,
        )
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.invoke_once()
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.OUTPUT_LIMIT_EXCEEDED)


# ---------------------------------------------------------------------------
# NDJSON and terminal-event authority
# ---------------------------------------------------------------------------


class TestTerminalEventAuthority(unittest.TestCase):
    def _failing(self, builder: Callable[[dict[str, Any]], list[str]], **runner_kwargs: Any) -> V0ProposalBackendFailure:
        harness = CursorBackendHarness(
            self, runner=FakeCursorProcessRunner(stream_builder=builder, **runner_kwargs)
        )
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.invoke_once()
        self.assertEqual(harness.runner.cleaned_up, harness.runner.started)
        self.assertEqual(harness.workspace_snapshot(), {})
        return failure.exception

    def test_malformed_lines_before_success_reject(self) -> None:
        def stream(instruction: dict[str, Any]) -> list[str]:
            return ["this is not json\n", *successful_stream(instruction)]

        self.assertEqual(self._failing(stream).kind, V0BackendFailureKind.MALFORMED_NDJSON)

    def test_duplicate_terminal_success_rejects(self) -> None:
        def stream(instruction: dict[str, Any]) -> list[str]:
            lines = successful_stream(instruction)
            return [*lines, lines[-1]]

        self.assertEqual(self._failing(stream).kind, V0BackendFailureKind.DUPLICATE_TERMINAL_RESULT)

    def test_terminal_failure_rejects(self) -> None:
        def stream(instruction: dict[str, Any]) -> list[str]:
            return [result_line("model error", subtype="error", is_error=True)]

        self.assertEqual(self._failing(stream).kind, V0BackendFailureKind.TERMINAL_FAILURE)

    def test_exit_without_terminal_result_rejects(self) -> None:
        def stream(instruction: dict[str, Any]) -> list[str]:
            return [assistant_line("thinking out loud")]

        self.assertEqual(self._failing(stream).kind, V0BackendFailureKind.MISSING_TERMINAL_RESULT)

    def test_nonzero_exit_rejects(self) -> None:
        self.assertEqual(
            self._failing(successful_stream, returncode=3).kind, V0BackendFailureKind.NONZERO_EXIT
        )

    def test_timeout_rejects(self) -> None:
        self.assertEqual(
            self._failing(successful_stream, timed_out=True, returncode=None).kind,
            V0BackendFailureKind.TIMEOUT,
        )

    def test_unproven_process_cleanup_rejects(self) -> None:
        failure = self._failing(successful_stream, cleanup_proven=False, remaining_process_ids=(4321,))
        self.assertEqual(failure.kind, V0BackendFailureKind.PROCESS_CLEANUP_FAILED)

    def test_malformed_ndjson_with_unproven_cleanup_reports_cleanup_first(self) -> None:
        failure = self._failing(
            lambda instruction: ["{malformed\n"],
            cleanup_proven=False,
            remaining_process_ids=(4321,),
        )
        self.assertEqual(failure.kind, V0BackendFailureKind.PROCESS_CLEANUP_FAILED)

    def test_missing_executable_rejects_without_spawning(self) -> None:
        harness = CursorBackendHarness(self, runner=None)
        harness.backend.runner = ManagedCursorProcessRunner()
        harness.backend.config = CursorBackendConfig(
            executable="cursor-agent-that-does-not-exist-on-this-host",
            agent_workspace=harness.agent_workspace,
        )
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.invoke_once()
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.EXECUTABLE_UNAVAILABLE)
        self.assertEqual(harness.workspace_snapshot(), {})


# ---------------------------------------------------------------------------
# Structured proposal contract
# ---------------------------------------------------------------------------


class TestProposalContract(unittest.TestCase):
    def _reject(self, builder: Callable[[dict[str, Any]], list[str]]) -> V0ProposalBackendFailure:
        harness = CursorBackendHarness(self, runner=FakeCursorProcessRunner(stream_builder=builder))
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.invoke_once()
        self.assertEqual(harness.workspace_snapshot(), {})
        return failure.exception

    def test_prose_without_typed_proposal_rejects(self) -> None:
        def stream(instruction: dict[str, Any]) -> list[str]:
            return [result_line("I have created all the files. The game is done and works great.")]

        self.assertEqual(self._reject(stream).kind, V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA)

    def test_markdown_fence_without_envelope_rejects(self) -> None:
        def stream(instruction: dict[str, Any]) -> list[str]:
            body = json.dumps({"operations": [{"path": "index.html", "content": "<html></html>"}]})
            return [result_line(f"```json\n{body}\n```")]

        self.assertEqual(self._reject(stream).kind, V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA)

    def test_malformed_envelope_json_rejects(self) -> None:
        def stream(instruction: dict[str, Any]) -> list[str]:
            return [result_line(f"{ENVELOPE_BEGIN}\n{{not json,,,}}\n{ENVELOPE_END}")]

        self.assertEqual(self._reject(stream).kind, V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA)

    def test_multiple_authoritative_envelopes_reject(self) -> None:
        def stream(instruction: dict[str, Any]) -> list[str]:
            one = envelope_text(
                invocation_id=instruction["invocation_id"],
                batch_id=instruction["batch_id"],
                operations=write_ops(["index.html"], prefix="a"),
            )
            two = envelope_text(
                invocation_id=instruction["invocation_id"],
                batch_id=instruction["batch_id"],
                operations=write_ops(["style.css"], prefix="b"),
            )
            return [result_line(f"{one}\n{two}")]

        self.assertEqual(self._reject(stream).kind, V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA)

    def test_mismatched_invocation_id_rejects(self) -> None:
        def stream(instruction: dict[str, Any]) -> list[str]:
            return [
                result_line(
                    envelope_text(
                        invocation_id="v0inv:someone-else:1:1",
                        batch_id=instruction["batch_id"],
                        operations=write_ops(["index.html"], prefix="x"),
                    )
                )
            ]

        self.assertEqual(self._reject(stream).kind, V0BackendFailureKind.INVOCATION_MISMATCH)

    def test_mismatched_batch_id_rejects(self) -> None:
        def stream(instruction: dict[str, Any]) -> list[str]:
            return [
                result_line(
                    envelope_text(
                        invocation_id=instruction["invocation_id"],
                        batch_id="some-other-batch",
                        operations=write_ops(["index.html"], prefix="x"),
                    )
                )
            ]

        self.assertEqual(self._reject(stream).kind, V0BackendFailureKind.INVOCATION_MISMATCH)

    def test_unsupported_operation_kinds_reject_and_are_never_normalized(self) -> None:
        for kind in ("shell", "command", "network", "browser", "deploy", "package_install", "WRITE_FILE", "run"):
            with self.subTest(kind=kind):

                def stream(instruction: dict[str, Any], kind: str = kind) -> list[str]:
                    return [
                        result_line(
                            envelope_text(
                                invocation_id=instruction["invocation_id"],
                                batch_id=instruction["batch_id"],
                                operations=[
                                    {
                                        "action_id": "op-1",
                                        "kind": kind,
                                        "path": "index.html",
                                        "content": "<html></html>",
                                    }
                                ],
                            )
                        )
                    ]

                failure = self._reject(stream)
                self.assertEqual(failure.kind, V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA)
                self.assertIn(repr(kind), str(failure))

    def test_fifth_operation_rejects(self) -> None:
        def stream(instruction: dict[str, Any]) -> list[str]:
            return [
                result_line(
                    envelope_text(
                        invocation_id=instruction["invocation_id"],
                        batch_id=instruction["batch_id"],
                        operations=write_ops(list(CLI008_MANDATORY_PATHS[:5]), prefix="over"),
                    )
                )
            ]

        self.assertEqual(self._reject(stream).kind, V0BackendFailureKind.PROPOSAL_OPERATION_LIMIT_EXCEEDED)

    def test_duplicate_action_ids_and_paths_reject(self) -> None:
        def duplicate_ids(instruction: dict[str, Any]) -> list[str]:
            operations = [
                {"action_id": "same", "kind": "write_file", "path": "index.html", "content": "a"},
                {"action_id": "same", "kind": "write_file", "path": "style.css", "content": "b"},
            ]
            return [
                result_line(
                    envelope_text(
                        invocation_id=instruction["invocation_id"],
                        batch_id=instruction["batch_id"],
                        operations=operations,
                    )
                )
            ]

        def duplicate_paths(instruction: dict[str, Any]) -> list[str]:
            operations = [
                {"action_id": "one", "kind": "write_file", "path": "index.html", "content": "a"},
                {"action_id": "two", "kind": "write_file", "path": "index.html", "content": "b"},
            ]
            return [
                result_line(
                    envelope_text(
                        invocation_id=instruction["invocation_id"],
                        batch_id=instruction["batch_id"],
                        operations=operations,
                    )
                )
            ]

        self.assertEqual(self._reject(duplicate_ids).kind, V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA)
        self.assertEqual(self._reject(duplicate_paths).kind, V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA)

    def test_missing_identifiers_and_bad_schema_version_reject(self) -> None:
        def missing_ids(instruction: dict[str, Any]) -> list[str]:
            payload = {"schema_version": ENVELOPE_SCHEMA_VERSION, "operations": []}
            return [result_line(f"{ENVELOPE_BEGIN}\n{json.dumps(payload)}\n{ENVELOPE_END}")]

        def bad_schema(instruction: dict[str, Any]) -> list[str]:
            return [
                result_line(
                    envelope_text(
                        invocation_id=instruction["invocation_id"],
                        batch_id=instruction["batch_id"],
                        operations=write_ops(["index.html"], prefix="x"),
                        schema_version="something_else_v9",
                    )
                )
            ]

        self.assertEqual(self._reject(missing_ids).kind, V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA)
        self.assertEqual(self._reject(bad_schema).kind, V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA)

    def test_escaping_path_rejects(self) -> None:
        def stream(instruction: dict[str, Any]) -> list[str]:
            return [
                result_line(
                    envelope_text(
                        invocation_id=instruction["invocation_id"],
                        batch_id=instruction["batch_id"],
                        operations=[
                            {
                                "action_id": "op-1",
                                "kind": "write_file",
                                "path": "../../etc/passwd",
                                "content": "x",
                            }
                        ],
                    )
                )
            ]

        self.assertEqual(self._reject(stream).kind, V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA)


# ---------------------------------------------------------------------------
# Durable dispatch order and exact-once results
# ---------------------------------------------------------------------------


class TestPersistedDispatchAuthority(unittest.TestCase):
    """BLOCKER 1 — only a *reloaded persisted* lifecycle may start a process."""

    def _rejects(self, harness: CursorBackendHarness, request: PersistedCursorDispatchRequest) -> V0ProposalBackendFailure:
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.backend.invoke_persisted(request=request)
        # The whole point: the runner was never reached.
        self.assertEqual(harness.runner.started, 0)
        self.assertEqual(harness.backend.invocation_count, 0)
        self.assertEqual(harness.workspace_snapshot(), {})
        return failure.exception

    def test_a_caller_supplied_command_is_never_dispatch_authority(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.backend.invoke(command=command, instruction=harness.instruction_for(command))
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.PERSISTED_DISPATCH_REJECTED)
        self.assertEqual(harness.runner.started, 0)

    def test_synthetic_never_persisted_command_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        harness.orchestrator.create_session()
        synthetic = Command(
            command_id="v0cmd:forged:1:1:dispatch_agent:v0inv:forged:1:1",
            kind=CommandKind.DISPATCH_AGENT,
            owner_id="v0inv:forged:1:1",
            status=CommandStatus.IN_FLIGHT,
            payload_json='{"invocation_id": "v0inv:forged:1:1", "mandatory_paths": []}',
        )
        failure = self._rejects(
            harness,
            PersistedCursorDispatchRequest(
                session_id=harness.integration_config.session_id,
                command_id=synthetic.command_id or "",
                invocation_id=synthetic.owner_id,
                batch_id=f"{synthetic.owner_id}:batch:1",
                expected_revision=harness.state().revision,
                backend_fingerprint=harness.backend.config_fingerprint,
            ),
        )
        self.assertEqual(failure.kind, V0BackendFailureKind.PERSISTED_DISPATCH_REJECTED)

    def test_persisted_prepared_command_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        prepared = harness.prepared_command()
        self.assertEqual(prepared.status, CommandStatus.PREPARED)
        failure = self._rejects(harness, harness.request_for(prepared))
        self.assertEqual(failure.kind, V0BackendFailureKind.PERSISTED_DISPATCH_REJECTED)

    def test_wrong_command_id_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        failure = self._rejects(harness, harness.request_for(command, command_id="v0cmd:not-this-one"))
        self.assertEqual(failure.kind, V0BackendFailureKind.PERSISTED_DISPATCH_REJECTED)

    def test_wrong_invocation_id_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        self._rejects(harness, harness.request_for(command, invocation_id="v0inv:someone-else:1:1"))

    def test_wrong_session_id_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        self._rejects(harness, harness.request_for(command, session_id="another-session"))

    def test_stale_revision_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        failure = self._rejects(harness, harness.request_for(command, expected_revision=1))
        self.assertIn("Stale dispatch revision", str(failure))

    def test_wrong_batch_identity_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        self._rejects(harness, harness.request_for(command, batch_id=f"{command.owner_id}:batch:7"))

    def test_mismatched_backend_fingerprint_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        failure = self._rejects(harness, harness.request_for(command, backend_fingerprint="0" * 64))
        self.assertEqual(failure.kind, V0BackendFailureKind.BACKEND_FINGERPRINT_MISMATCH)

    def test_a_differently_configured_backend_cannot_consume_the_dispatch(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        other = CursorCallableProposalBackend(
            config=CursorBackendConfig(
                executable="some-other-agent",
                agent_workspace=harness.agent_workspace,
            ),
            target_workspace=harness.workspace,
            store=harness.store,
            runner=harness.runner,
        )
        request = PersistedCursorDispatchRequest(
            session_id=harness.integration_config.session_id,
            command_id=command.command_id or "",
            invocation_id=command.owner_id,
            batch_id=expected_batch_id(harness.state(), command.owner_id),
            expected_revision=harness.state().revision,
            backend_fingerprint=other.config_fingerprint,
        )
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            other.invoke_persisted(request=request)
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.BACKEND_FINGERPRINT_MISMATCH)
        self.assertEqual(harness.runner.started, 0)

    def test_missing_wait_token_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        request = harness.request_for(command)
        harness.tamper(replace(harness.state(), wait_token=None))
        failure = self._rejects(harness, request)
        self.assertEqual(failure.kind, V0BackendFailureKind.PERSISTED_DISPATCH_REJECTED)

    def test_wrong_wait_token_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        request = harness.request_for(command)
        state = harness.state()
        assert state.wait_token is not None
        harness.tamper(replace(state, wait_token=replace(state.wait_token, owner_id="v0inv:someone-else:1:1")))
        self._rejects(harness, request)

    def test_terminal_and_paused_sessions_do_not_start_a_process(self) -> None:
        for phase in (Phase.TECHNICAL_PAUSE, Phase.FAILED, Phase.COMPLETED):
            with self.subTest(phase=phase):
                harness = CursorBackendHarness(self)
                command = harness.dispatch_command()
                request = harness.request_for(command)
                harness.tamper(replace(harness.state(), phase=phase))
                failure = self._rejects(harness, request)
                self.assertEqual(failure.kind, V0BackendFailureKind.PERSISTED_DISPATCH_REJECTED)

    def test_consumed_failed_cancelled_or_uncertain_invocation_does_not_start_a_process(self) -> None:
        for lifecycle in (
            InvocationLifecycle.PREPARED,
            InvocationLifecycle.RESULT_RECEIVED,
            InvocationLifecycle.CONSUMED,
            InvocationLifecycle.FAILED,
            InvocationLifecycle.CANCELLED,
            InvocationLifecycle.UNCERTAIN,
        ):
            with self.subTest(lifecycle=lifecycle):
                harness = CursorBackendHarness(self)
                command = harness.dispatch_command()
                request = harness.request_for(command)
                state = harness.state()
                assert state.current_invocation is not None
                harness.tamper(
                    replace(state, current_invocation=replace(state.current_invocation, lifecycle=lifecycle))
                )
                self._rejects(harness, request)

    def test_a_dispatch_command_without_a_persisted_capability_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        request = harness.request_for(command)
        state = harness.state()
        assert state.pending_command is not None
        payload = state.pending_command.payload
        payload.pop("dispatch_capability")
        harness.tamper(replace(state, pending_command=state.pending_command.with_payload(payload)))
        failure = self._rejects(harness, request)
        self.assertEqual(failure.kind, V0BackendFailureKind.PERSISTED_DISPATCH_REJECTED)

    def test_mutating_only_capability_nonce_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        request = harness.request_for(command)
        state = harness.state()
        assert state.pending_command is not None
        payload = state.pending_command.payload
        capability = dict(payload["dispatch_capability"])
        capability["nonce"] = "forged-capability-nonce"
        payload["dispatch_capability"] = capability
        harness.tamper(replace(state, pending_command=state.pending_command.with_payload(payload)))
        self._rejects(harness, request)

    def test_mutating_only_invocation_dispatch_nonce_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        request = harness.request_for(command)
        state = harness.state()
        assert state.current_invocation is not None
        assert state.current_invocation.dispatch_authority is not None
        authority = replace(state.current_invocation.dispatch_authority, nonce="forged-invocation-nonce")
        harness.tamper(
            replace(state, current_invocation=replace(state.current_invocation, dispatch_authority=authority))
        )
        self._rejects(harness, request)

    def test_mutating_only_wait_nonce_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        request = harness.request_for(command)
        state = harness.state()
        assert state.wait_token is not None
        harness.tamper(
            replace(state, wait_token=replace(state.wait_token, correlation_nonce="forged-wait-nonce"))
        )
        self._rejects(harness, request)

    def test_nonce_from_another_valid_session_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        request = harness.request_for(command)
        other = CursorBackendHarness(self)
        other_command = other.dispatch_command()
        other_state = other.state()
        assert other_state.current_invocation is not None
        assert other_state.current_invocation.dispatch_authority is not None
        state = harness.state()
        assert state.pending_command is not None
        payload = state.pending_command.payload
        capability = dict(payload["dispatch_capability"])
        capability["nonce"] = other_state.current_invocation.dispatch_authority.nonce
        payload["dispatch_capability"] = capability
        harness.tamper(replace(state, pending_command=state.pending_command.with_payload(payload)))
        self._rejects(harness, request)

    def test_nonce_from_earlier_invocation_does_not_start_a_process(self) -> None:
        harness = CursorBackendHarness(self)
        harness.advance_to_second_invocation()
        first = harness.state().invocation_history[0]
        assert first.dispatch_authority is not None
        command = harness.dispatch_command_for_current_invocation()
        request = harness.request_for(command)
        state = harness.state()
        assert state.pending_command is not None
        payload = state.pending_command.payload
        capability = dict(payload["dispatch_capability"])
        capability["nonce"] = first.dispatch_authority.nonce
        payload["dispatch_capability"] = capability
        harness.tamper(replace(state, pending_command=state.pending_command.with_payload(payload)))
        started = harness.runner.started
        with self.assertRaises(V0ProposalBackendFailure):
            harness.backend.invoke_persisted(request=request)
        self.assertEqual(harness.runner.started, started)

    def test_legitimate_persisted_state_dispatches_exactly_once(self) -> None:
        harness = CursorBackendHarness(self)
        result = harness.invoke_once()
        self.assertEqual(harness.runner.started, 1)
        self.assertEqual(harness.backend.invocation_count, 1)
        self.assertEqual(len(result.operations), 4)
        self.assertEqual(result.config_fingerprint, harness.backend.config_fingerprint)

    def test_a_fresh_backend_after_an_uncertain_restart_never_reinvokes(self) -> None:
        harness = CursorBackendHarness(self)
        harness.orchestrator.create_session()
        harness.fresh_orchestrator().run_logical_tick()
        prepared = harness.state().pending_command
        assert prepared is not None and prepared.command_id is not None
        # Crash *after* the command was durably marked in-flight, before a result.
        harness.fresh_orchestrator().fresh_engine().tick(
            harness.integration_config.session_id, CommandDispatchStarted(prepared.command_id)
        )
        self.assertEqual(harness.state().pending_command.status, CommandStatus.IN_FLIGHT)

        # A brand-new backend instance (empty in-memory dedup set) must not be
        # able to bypass the restart pause.
        fresh_runner = FakeCursorProcessRunner()
        fresh_backend = CursorCallableProposalBackend(
            config=harness.config,
            target_workspace=harness.workspace,
            store=AtomicSessionStore(harness.store_dir),
            runner=fresh_runner,
        )
        harness.integration_config = replace(harness.integration_config, proposal_backend=fresh_backend)
        step = V0OfflineOrchestrator(harness.integration_config).run_logical_tick()
        self.assertEqual(step.step_kind, OrchestratorStepKind.RESTART_PAUSE)
        self.assertEqual(harness.state().phase, Phase.TECHNICAL_PAUSE)
        self.assertEqual(harness.state().outcome_reason.code, ReasonCode.COMMAND_OUTCOME_UNCERTAIN)
        self.assertEqual(fresh_runner.started, 0)
        self.assertEqual(fresh_backend.invocation_count, 0)
        self.assertEqual(harness.runner.started, 0)


class TestExactOnceResults(unittest.TestCase):
    def test_result_is_consumable_exactly_once(self) -> None:
        harness = CursorBackendHarness(self)
        result = harness.invoke_once()
        harness.backend.mark_result_consumed(result)
        self.assertEqual(harness.backend.results_consumed, 1)
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.backend.mark_result_consumed(result)
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.DUPLICATE_RESULT_CONSUMPTION)
        self.assertEqual(harness.backend.results_consumed, 1)

    def test_a_result_with_a_mismatched_fingerprint_is_rejected(self) -> None:
        harness = CursorBackendHarness(self)
        result = harness.invoke_once()
        forged = replace(result, config_fingerprint="0" * 64)
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.backend.mark_result_consumed(forged)
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.BACKEND_FINGERPRINT_MISMATCH)
        self.assertEqual(harness.backend.results_consumed, 0)

    def test_a_result_with_a_mismatched_dispatch_nonce_is_rejected(self) -> None:
        harness = CursorBackendHarness(self)
        result = harness.invoke_once()
        forged = replace(result, dispatch_nonce="forged-result-nonce")
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.backend.mark_result_consumed(forged)
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.STALE_RESULT)
        self.assertEqual(harness.backend.results_consumed, 0)

    def test_stale_result_from_another_invocation_rejects(self) -> None:
        harness = CursorBackendHarness(self)
        result = harness.invoke_once()
        stale = V0ProposalResult(
            invocation_id="v0inv:stale:1:1",
            result_id="stale-result",
            batch_id=result.batch_id,
            response_reference=result.response_reference,
            operations=result.operations,
        )
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.backend.mark_result_consumed(stale)
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.STALE_RESULT)

    def test_result_after_technical_pause_rejects(self) -> None:
        harness = CursorBackendHarness(self)
        result = harness.invoke_once()
        harness.backend.close(reason="technical_pause")
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.backend.mark_result_consumed(result)
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.TERMINAL_STATE_REJECTED)

    def test_the_same_invocation_is_never_dispatched_twice(self) -> None:
        harness = CursorBackendHarness(self)
        command = harness.dispatch_command()
        request = harness.request_for(command)
        result = harness.backend.invoke_persisted(request=request)
        harness.backend.mark_result_consumed(result)
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.backend.invoke_persisted(request=request)
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.DISPATCH_ORDER_VIOLATION)
        self.assertEqual(harness.runner.started, 1)


# ---------------------------------------------------------------------------
# Native launcher executable prefix (node.exe + index.js)
# ---------------------------------------------------------------------------


class TestExecutablePrefixArgs(unittest.TestCase):
    """The operator prefix inserted between the executable and fixed arguments."""

    def _argv(self, config: CursorBackendConfig) -> list[str]:
        return list(config.argv(agent_workspace=Path("/agent/ws"), prompt="PROMPT"))

    def test_empty_prefix_preserves_the_previous_argv_exactly(self) -> None:
        config = CursorBackendConfig(executable="cursor-agent", agent_workspace=Path("/agent/ws"))
        argv = self._argv(config)
        self.assertEqual(
            argv,
            [
                "cursor-agent",
                "--print",
                "--output-format",
                "stream-json",
                "--stream-partial-output",
                "--mode",
                "ask",
                "--model",
                "auto",
                "--workspace",
                str(Path("/agent/ws")),
                "--trust",
                "PROMPT",
            ],
        )
        self.assertEqual(config.executable_prefix_args, ())

    def test_one_prefix_argument_produces_node_index_print(self) -> None:
        config = CursorBackendConfig(
            executable="node.exe",
            agent_workspace=Path("/agent/ws"),
            executable_prefix_args=("index.js",),
        )
        argv = self._argv(config)
        self.assertEqual(argv[:3], ["node.exe", "index.js", "--print"])

    def test_multiple_prefix_arguments_preserve_exact_order(self) -> None:
        config = CursorBackendConfig(
            executable="node.exe",
            agent_workspace=Path("/agent/ws"),
            executable_prefix_args=("--enable-x", "index.js", "--flag"),
        )
        argv = self._argv(config)
        self.assertEqual(argv[:5], ["node.exe", "--enable-x", "index.js", "--flag", "--print"])

    def test_prefix_argument_with_spaces_stays_one_argv_element(self) -> None:
        spaced = r"C:\Program Files\cursor\index.js"
        config = CursorBackendConfig(
            executable="node.exe",
            agent_workspace=Path("/agent/ws"),
            executable_prefix_args=(spaced,),
        )
        argv = self._argv(config)
        self.assertEqual(argv[1], spaced)  # never split on the space
        self.assertEqual(argv.count(spaced), 1)

    def test_prefix_is_never_shell_interpolated(self) -> None:
        # A value that a shell would expand must survive verbatim as one element.
        hostile = "index.js && rm -rf / ; $(whoami)"
        config = CursorBackendConfig(
            executable="node.exe",
            agent_workspace=Path("/agent/ws"),
            executable_prefix_args=(hostile,),
        )
        argv = self._argv(config)
        self.assertEqual(argv[1], hostile)

    def test_empty_or_null_prefix_entries_reject(self) -> None:
        with self.assertRaises(ValueError):
            CursorBackendConfig(
                executable="node.exe", agent_workspace=Path("/agent/ws"), executable_prefix_args=("",)
            )
        with self.assertRaises(ValueError):
            CursorBackendConfig(
                executable="node.exe",
                agent_workspace=Path("/agent/ws"),
                executable_prefix_args=("index\x00.js",),
            )

    def test_a_prefix_containing_the_target_workspace_rejects(self) -> None:
        harness = CursorBackendHarness(self)
        config = replace(
            harness.config,
            executable="node.exe",
            executable_prefix_args=(str(harness.workspace / "index.js"),),
        )
        with self.assertRaises(ValueError):
            CursorCallableProposalBackend(
                config=config,
                target_workspace=harness.workspace,
                store=harness.store,
                runner=harness.runner,
            )

    def test_prefix_cannot_originate_from_model_output(self) -> None:
        # The prefix is a frozen config field; a proposal envelope cannot set it.
        # Even after a full successful invocation, the argv prefix is exactly the
        # configured one, never anything derived from the returned proposal.
        harness = CursorBackendHarness(self, executable_prefix_args=("index.js",))
        harness.invoke_once()
        argv = list(harness.runner.invocations[0].argv)
        self.assertEqual(argv[:2], ["cursor-agent", "index.js"])
        # No proposed path (model output) leaked into the launcher prefix.
        for element in argv[:2]:
            self.assertNotIn("cli008", element)

    def test_prefix_change_changes_the_fingerprint(self) -> None:
        base = CursorBackendConfig(executable="node.exe", agent_workspace=Path("/agent/ws"))
        with_index = replace(base, executable_prefix_args=("index.js",))
        other_path = replace(base, executable_prefix_args=("other.js",))
        reordered = replace(base, executable_prefix_args=("a.js", "b.js"))
        reordered_2 = replace(base, executable_prefix_args=("b.js", "a.js"))
        extra = replace(base, executable_prefix_args=("index.js", "extra"))
        fps = {
            base.fingerprint(),
            with_index.fingerprint(),
            other_path.fingerprint(),
            reordered.fingerprint(),
            reordered_2.fingerprint(),
            extra.fingerprint(),
        }
        # All six configurations must have distinct fingerprints.
        self.assertEqual(len(fps), 6)

    def test_persisted_dispatch_for_prefix_a_rejects_configured_prefix_b(self) -> None:
        harness = CursorBackendHarness(self, executable_prefix_args=("a.js",))
        command = harness.dispatch_command()
        other = CursorCallableProposalBackend(
            config=replace(harness.config, executable_prefix_args=("b.js",)),
            target_workspace=harness.workspace,
            store=harness.store,
            runner=harness.runner,
        )
        request = PersistedCursorDispatchRequest(
            session_id=harness.integration_config.session_id,
            command_id=command.command_id or "",
            invocation_id=command.owner_id,
            batch_id=expected_batch_id(harness.state(), command.owner_id),
            expected_revision=harness.state().revision,
            backend_fingerprint=other.config_fingerprint,
        )
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            other.invoke_persisted(request=request)
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.BACKEND_FINGERPRINT_MISMATCH)
        self.assertEqual(harness.runner.started, 0)

    def test_a_forged_result_fingerprint_under_a_prefix_rejects(self) -> None:
        harness = CursorBackendHarness(self, executable_prefix_args=("index.js",))
        result = harness.invoke_once()
        forged = replace(result, config_fingerprint="0" * 64)
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            harness.backend.mark_result_consumed(forged)
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.BACKEND_FINGERPRINT_MISMATCH)
        self.assertEqual(harness.backend.results_consumed, 0)


# ---------------------------------------------------------------------------
# Fail-closed orchestration
# ---------------------------------------------------------------------------


class TestFailClosedOrchestration(unittest.TestCase):
    def test_backend_failure_pauses_the_session_and_never_retries(self) -> None:
        harness = CursorBackendHarness(self, runner=FakeCursorProcessRunner(
            stream_builder=lambda instruction: [result_line("all done, trust me")],
        ))
        harness.run_to_awaiting_human()
        state = harness.state()
        self.assertEqual(state.phase, Phase.TECHNICAL_PAUSE)
        self.assertEqual(state.outcome_reason.code, ReasonCode.INVALID_EXTERNAL_RESULT)
        self.assertIn("invalid_proposal_schema", state.outcome_reason.message)
        self.assertEqual(harness.runner.started, 1)
        self.assertEqual(harness.executor.write_count, 0)
        self.assertEqual(harness.workspace_snapshot(), {})

    def test_transport_failure_pauses_with_an_invocation_failed_reason(self) -> None:
        harness = CursorBackendHarness(self, runner=FakeCursorProcessRunner(timed_out=True, returncode=None))
        harness.run_to_awaiting_human()
        state = harness.state()
        self.assertEqual(state.phase, Phase.TECHNICAL_PAUSE)
        self.assertEqual(state.outcome_reason.code, ReasonCode.INVOCATION_FAILED)
        self.assertIn("timeout", state.outcome_reason.message)
        self.assertEqual(harness.executor.write_count, 0)


# ---------------------------------------------------------------------------
# The fake-process two-batch integration
# ---------------------------------------------------------------------------


class TestCursorBackendTwoBatchIntegration(unittest.TestCase):
    def test_two_batch_totals_match_the_fixture_backend_run(self) -> None:
        harness = CursorBackendHarness(self)
        steps = harness.run_to_awaiting_human()
        self.assertGreater(len(steps), 0)

        projection = harness.orchestrator.projection()
        self.assertEqual(projection.phase, Phase.AWAITING_HUMAN.value)
        self.assertEqual(projection.backend_invocations, 2)
        self.assertEqual(projection.proposal_results_consumed, 2)
        self.assertEqual(projection.admitted_operations, 8)
        self.assertEqual(projection.bounded_writes, 8)
        self.assertEqual(projection.structural_checks, 1)
        self.assertEqual(projection.completed_batches, 2)
        self.assertEqual(projection.interrupted_batches, 0)
        self.assertEqual(projection.remaining_paths, ())
        self.assertEqual(sorted(projection.materialized_paths), sorted(CLI008_MANDATORY_PATHS))

        state = harness.state()
        self.assertEqual(len(state.execution_receipt_history), 8)
        self.assertEqual(harness.executor.write_count, 8)
        self.assertEqual(harness.runner.started, 2)
        for path in CLI008_MANDATORY_PATHS:
            self.assertTrue((harness.workspace / Path(path)).is_file())

    def test_twenty_no_event_polls_are_byte_stable(self) -> None:
        harness = CursorBackendHarness(self)
        harness.run_to_awaiting_human()
        baseline = harness.orchestrator.session_bytes()
        hashes = harness.workspace_snapshot()
        for _ in range(20):
            step = harness.fresh_orchestrator().run_no_event_tick()
            self.assertEqual(step.step_kind, OrchestratorStepKind.NO_EVENT)
            self.assertEqual(step.tick.state.phase, Phase.AWAITING_HUMAN)
            self.assertEqual(step.session_bytes, baseline)
        self.assertEqual(harness.workspace_snapshot(), hashes)
        self.assertEqual(harness.backend.invocation_count, 2)
        self.assertEqual(harness.runner.started, 2)
        self.assertEqual(harness.executor.write_count, 8)


# ---------------------------------------------------------------------------
# Persisted-fact-only governed context
# ---------------------------------------------------------------------------


def crlf_stream(instruction: dict[str, Any]) -> list[str]:
    """Turn-1 proposals whose content carries CRLF and a trailing bare LF."""

    remaining = list(instruction["remaining_mandatory_paths"])[:4]
    operations = [
        {
            "action_id": f"crlf-{index}",
            "kind": "write_file",
            "path": path,
            "content": f"// {path}\r\nexport const generated = {index};\r\n\n",
        }
        for index, path in enumerate(remaining, start=1)
    ]
    return [
        result_line(
            envelope_text(
                invocation_id=instruction["invocation_id"],
                batch_id=instruction["batch_id"],
                operations=operations,
            )
        )
    ]


class TestPersistedFactContext(unittest.TestCase):
    """BLOCKER 4 — the instruction derives from persisted facts, never live reads."""

    def _drift_pauses(self, harness: CursorBackendHarness, mutate) -> None:
        harness.advance_to_second_invocation()
        self.assertEqual(harness.runner.started, 1)
        mutate()
        harness.fresh_orchestrator().run_logical_tick()  # prepare turn 2
        harness.fresh_orchestrator().run_logical_tick()  # would dispatch turn 2
        state = harness.state()
        self.assertEqual(state.phase, Phase.TECHNICAL_PAUSE)
        self.assertEqual(state.outcome_reason.code, ReasonCode.PHYSICAL_ATTESTATION_FAILED)
        self.assertIn("materialized_context_drift", state.outcome_reason.message)
        # No second process, and the instruction was never rebuilt differently.
        self.assertEqual(harness.runner.started, 1)
        self.assertEqual(harness.backend.invocation_count, 1)
        self.assertEqual(len(harness.runner.instructions), 1)
        baseline = harness.orchestrator.session_bytes()
        for _ in range(20):
            step = harness.fresh_orchestrator().run_no_event_tick()
            self.assertEqual(step.step_kind, OrchestratorStepKind.NO_EVENT)
            self.assertEqual(step.session_bytes, baseline)

    def test_equivalent_persisted_state_yields_identical_instruction_and_context(self) -> None:
        harness = CursorBackendHarness(self)
        harness.advance_to_second_invocation()
        command = harness.dispatch_command_for_current_invocation()
        request = harness.request_for(command)

        first = harness.backend.invoke_persisted(request=request)
        first_instruction = json.dumps(harness.runner.instructions[-1], sort_keys=True)
        workspace = harness.agent_workspace.resolve()
        first_files = {
            str(item.relative_to(workspace)).replace("\\", "/"): item.read_bytes()
            for item in sorted(workspace.rglob("*"))
            if item.is_file()
        }

        # Same persisted state, a brand-new backend: byte-identical preparation.
        harness.backend.mark_result_consumed(first)
        rerun_backend = CursorCallableProposalBackend(
            config=harness.config,
            target_workspace=harness.workspace,
            store=AtomicSessionStore(harness.store_dir),
            runner=harness.runner,
        )
        rerun_backend.invoke_persisted(request=request)
        second_instruction = json.dumps(harness.runner.instructions[-1], sort_keys=True)
        second_files = {
            str(item.relative_to(workspace)).replace("\\", "/"): item.read_bytes()
            for item in sorted(workspace.rglob("*"))
            if item.is_file()
        }
        self.assertEqual(first_instruction, second_instruction)
        self.assertEqual(first_files, second_files)
        self.assertIn(CONTEXT_MANIFEST_FILE, first_files)

    def test_context_bytes_come_from_persisted_content_not_a_live_read(self) -> None:
        harness = CursorBackendHarness(self)
        harness.advance_to_second_invocation()
        command = harness.dispatch_command_for_current_invocation()
        harness.backend.invoke_persisted(request=harness.request_for(command))
        state = harness.state()
        for evidence in state.materialized_evidence:
            copied = harness.context_bytes(evidence.path)
            target = (harness.workspace / Path(evidence.path)).read_bytes()
            # Identical to the target *because* the persisted content is what the
            # bounded executor wrote -- and identical to the durable receipt hash.
            self.assertEqual(copied, target)
            self.assertEqual(sha256_file(str(harness.workspace / Path(evidence.path))), evidence.sha256)

    def test_crlf_bytes_are_preserved_exactly(self) -> None:
        harness = CursorBackendHarness(self, runner=FakeCursorProcessRunner(stream_builder=crlf_stream))
        harness.advance_to_second_invocation()
        command = harness.dispatch_command_for_current_invocation()
        harness.backend.invoke_persisted(request=harness.request_for(command))
        for evidence in harness.state().materialized_evidence:
            copied = harness.context_bytes(evidence.path)
            self.assertIn(b"\r\n", copied)
            self.assertTrue(copied.endswith(b"\r\n\n"))
            self.assertEqual(len(copied), evidence.byte_count)

    def test_drifted_target_content_pauses_instead_of_changing_the_instruction(self) -> None:
        harness = CursorBackendHarness(self)
        drifted = harness.workspace / "index.html"
        self._drift_pauses(harness, lambda: drifted.write_bytes(b"<html>tampered</html>"))

    def test_deleted_target_file_pauses(self) -> None:
        harness = CursorBackendHarness(self)
        deleted = harness.workspace / "index.html"
        self._drift_pauses(harness, lambda: deleted.unlink())

    def test_target_replaced_by_a_directory_pauses(self) -> None:
        harness = CursorBackendHarness(self)
        path = harness.workspace / "index.html"

        def replace_with_directory() -> None:
            path.unlink()
            path.mkdir()

        self._drift_pauses(harness, replace_with_directory)

    def test_parent_symlink_to_same_byte_external_tree_pauses_before_runner(self) -> None:
        harness = CursorBackendHarness(self)
        harness.advance_to_second_invocation()
        source = harness.workspace / "src"
        external = harness.root / "external-src"
        shutil.copytree(source, external)
        shutil.rmtree(source)
        try:
            os.symlink(external, source, target_is_directory=True)
        except OSError as exc:  # pragma: no cover - restricted Windows hosts
            self.skipTest(f"directory symlinks unavailable: {exc}")
        harness.fresh_orchestrator().run_logical_tick()
        harness.fresh_orchestrator().run_logical_tick()
        state = harness.state()
        self.assertEqual(state.phase, Phase.TECHNICAL_PAUSE)
        self.assertEqual(state.outcome_reason.code, ReasonCode.PHYSICAL_ATTESTATION_FAILED)
        self.assertEqual(harness.runner.started, 1)
        self.assertEqual(harness.backend.invocation_count, 1)
        self.assertEqual(len(harness.runner.instructions), 1)
        baseline = harness.orchestrator.session_bytes()
        for _ in range(20):
            step = harness.fresh_orchestrator().run_no_event_tick()
            self.assertEqual(step.step_kind, OrchestratorStepKind.NO_EVENT)
            self.assertEqual(step.session_bytes, baseline)

    def test_target_file_symlink_to_external_content_pauses_before_runner(self) -> None:
        harness = CursorBackendHarness(self)
        target = harness.workspace / "index.html"
        external = harness.root / "external-index.html"
        self._drift_pauses(
            harness,
            lambda: (
                external.write_bytes(target.read_bytes()),
                target.unlink(),
                os.symlink(external, target),
            ),
        )

    def test_rebound_logical_workspace_pauses_before_runner(self) -> None:
        harness = CursorBackendHarness(self)
        harness.advance_to_second_invocation()
        original = harness.workspace
        rebound = harness.root / "rebound-live-workspace"
        shutil.copytree(original, rebound)
        shutil.rmtree(original)
        try:
            os.symlink(rebound, original, target_is_directory=True)
        except OSError as exc:  # pragma: no cover - restricted Windows hosts
            self.skipTest(f"directory symlinks unavailable: {exc}")
        harness.fresh_orchestrator().run_logical_tick()
        harness.fresh_orchestrator().run_logical_tick()
        state = harness.state()
        self.assertEqual(state.phase, Phase.TECHNICAL_PAUSE)
        self.assertEqual(harness.runner.started, 1)
        self.assertEqual(harness.backend.invocation_count, 1)

    def test_persisted_content_that_cannot_be_reconstructed_fails_closed(self) -> None:
        harness = CursorBackendHarness(self)
        harness.advance_to_second_invocation()
        state = harness.state()
        # The receipt exists but its originating admitted operation is gone.
        stripped = replace(state, batch_history=())
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            build_persisted_context(stripped)
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.PERSISTED_CONTEXT_UNAVAILABLE)

    def test_persisted_content_hash_mismatch_fails_closed(self) -> None:
        harness = CursorBackendHarness(self)
        harness.advance_to_second_invocation()
        state = harness.state()
        batch = state.batch_history[0]
        rewritten = tuple(
            ProposedOperation.from_operation(
                operation_id=item.operation_id,
                operation={**item.operation, "content": "not what was written"},
            )
            for item in batch.proposed_operations
        )
        tampered = replace(
            state, batch_history=(replace(batch, proposed_operations=rewritten),) + state.batch_history[1:]
        )
        with self.assertRaises(V0ProposalBackendFailure) as failure:
            build_persisted_context(tampered)
        self.assertEqual(failure.exception.kind, V0BackendFailureKind.PERSISTED_CONTEXT_UNAVAILABLE)

    def test_the_instruction_never_names_the_target_workspace(self) -> None:
        harness = CursorBackendHarness(self)
        harness.advance_to_second_invocation()
        blob = json.dumps(harness.runner.instructions[0], sort_keys=True)
        prompt = (harness.agent_workspace.resolve() / INSTRUCTION_FILE).read_text(encoding="utf-8")
        target = str(harness.workspace.resolve())
        self.assertNotIn(target, blob)
        self.assertNotIn(target, prompt)
        self.assertNotIn(target.replace("\\", "\\\\"), blob)

    def test_preparation_imports_no_clock_random_or_ui_source(self) -> None:
        package = Path(__file__).parents[1] / "admissible" / "v0_controller"
        forbidden = {"time", "datetime", "random", "secrets", "uuid"}
        for name in ("cursor_context.py", "cursor_instruction.py", "cursor_workspace.py"):
            imports: list[str] = []
            tree = ast.parse((package / name).read_text(encoding="utf-8"), filename=name)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.append(node.module.split(".")[0])
            self.assertEqual(sorted(forbidden.intersection(imports)), [], name)


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


class TestSlice3Isolation(unittest.TestCase):
    def test_cursor_backend_imports_no_legacy_high_autonomy_state(self) -> None:
        forbidden = (
            "admissible.high_autonomy_controller",
            "admissible.high_autonomy_policy",
            "admissible.high_autonomy_state_invariants",
            "admissible.control_surface",
            "admissible.governed_run",
            "admissible.long_run_truth",
            "admissible.long_run_envelope_builder",
            "admissible.run_loop",
            "admissible.agent_backend",
            "admissible.cursor_stream_json",
            "admissible.cursor_acp_transport",
            "admissible.browser_runtime",
        )
        package = Path(__file__).parents[1] / "admissible" / "v0_controller"
        imports: list[str] = []
        for source in sorted(package.glob("*.py")):
            tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.append(node.module)
        offenders = [
            name for name in imports for item in forbidden if name == item or name.startswith(f"{item}.")
        ]
        self.assertEqual(offenders, [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
