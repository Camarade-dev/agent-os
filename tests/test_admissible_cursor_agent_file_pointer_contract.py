"""Regression tests for the Cursor Agent file-pointer/stdout contract."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.agent_backend import (
    AGENT_INVOKE_MALFORMED,
    AGENT_INVOKE_SUCCESS,
    INPUT_MODE_FILE_POINTER_ALWAYS,
    INVOCATION_STATUS_MALFORMED,
    PROMPT_MODE_FILE_POINTER,
    AgentInvocationRecord,
    AgentInvocationRequest,
    CursorCliAgentBackend,
    CursorCliConfig,
    build_invocation_record,
)
from admissible.control_surface import ControlSurfaceController
from admissible.runner.extraction_lab import load_fixture


REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "admissible" / "tiny_game_turn_1_agent_response.md"


class _FakeCompleted:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _no_real_subprocess(*args, **kwargs):
    raise AssertionError("tests must not invoke a real Cursor Agent process")


class TestCursorAgentFilePointerContract(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        command_dir = self.root / "Cursor Agent Bin"
        command_dir.mkdir()
        self.command = command_dir / "cursor-agent"
        self.command.write_text("fixture executable", encoding="utf-8")
        self.target = self.root / "Target Workspace"
        self.target.mkdir()
        self.agent_workspace = self.root / "Isolated Agent Workspace"
        self.agent_workspace.mkdir()
        self.config = CursorCliConfig.cursor_agent_preset(command=str(self.command))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _request(self, instruction: str) -> AgentInvocationRequest:
        return AgentInvocationRequest(
            instruction_text=instruction,
            target_workspace_path=str(self.target),
            agent_workspace_path=str(self.agent_workspace),
            timeout_seconds=10,
        )

    def test_medium_and_long_instructions_use_the_same_stable_pointer_adapter(self) -> None:
        captures: list[dict] = []

        def runner(argv, **kwargs):
            instruction_file = self.agent_workspace / ".admissible" / "next-agent-instruction.md"
            captures.append(
                {
                    "argv": argv,
                    "kwargs": kwargs,
                    "instruction": instruction_file.read_text(encoding="utf-8"),
                }
            )
            return _FakeCompleted(stdout="complete proposal")

        backend = CursorCliAgentBackend(config=self.config, runner=runner)
        medium = "M" * 1200
        long = "L" * 12000
        first = backend.invoke(self._request(medium))
        second = backend.invoke(self._request(long))

        self.assertEqual((first.status, second.status), (AGENT_INVOKE_SUCCESS,) * 2)
        self.assertEqual([c["instruction"] for c in captures], [medium, long])
        self.assertEqual(captures[0]["argv"][-1], captures[1]["argv"][-1])
        self.assertNotIn(medium, captures[0]["argv"])
        self.assertNotIn(long, captures[1]["argv"])
        self.assertEqual(self.config.input_mode, INPUT_MODE_FILE_POINTER_ALWAYS)

    def test_adapter_requires_stdout_forbids_writes_and_keeps_space_path_one_argv(self) -> None:
        captured: dict = {}

        def runner(argv, **kwargs):
            captured.update(argv=argv, kwargs=kwargs)
            return _FakeCompleted(stdout="proposal")

        instruction = "Build the bounded local files."
        result = CursorCliAgentBackend(config=self.config, runner=runner).invoke(
            self._request(instruction)
        )

        adapter = captured["argv"][-1]
        instruction_path = (
            self.agent_workspace / ".admissible" / "next-agent-instruction.md"
        ).resolve()
        self.assertFalse(captured["kwargs"]["shell"])
        self.assertIn(str(instruction_path), adapter)
        self.assertEqual(sum(str(instruction_path) in arg for arg in captured["argv"]), 1)
        self.assertIn("directly to stdout", adapter)
        self.assertIn("Do not write or modify any file", adapter)
        self.assertIn("Do not write .admissible/agent-response.md", adapter)
        self.assertIn("ADMISSIBLE_STRUCTURED_OPERATION", adapter)
        self.assertNotIn(instruction, adapter)
        self.assertEqual(result.prompt_mode, PROMPT_MODE_FILE_POINTER)

    def test_diagnostics_persist_on_the_exactly_once_invocation_record(self) -> None:
        output = "structured stdout response"
        instruction = "governed instruction"
        backend = CursorCliAgentBackend(
            config=self.config,
            runner=lambda argv, **kwargs: _FakeCompleted(stdout=output, returncode=0),
        )
        result = backend.invoke(self._request(instruction))
        record = build_invocation_record(
            result,
            backend_id=backend.backend_id,
            instruction_id="packet_1",
            session_id="session_1",
            turn_number=1,
            invocation_id="invoke_1",
        )

        self.assertEqual(record.prompt_mode, PROMPT_MODE_FILE_POINTER)
        self.assertEqual(record.instruction_file_path, result.instruction_file_path)
        self.assertEqual(record.instruction_sha256, result.instruction_sha256)
        self.assertEqual(record.adapter_prompt_length, result.adapter_prompt_length)
        self.assertEqual(record.full_instruction_length, len(instruction))
        self.assertEqual(record.stdout_length, len(output))
        self.assertEqual(record.exit_code, 0)
        self.assertIsNotNone(record.invocation_duration_ms)
        self.assertGreaterEqual(record.invocation_duration_ms or -1, 0)
        restored = AgentInvocationRecord.from_dict(record.to_dict())
        self.assertEqual(restored.to_dict(), record.to_dict())

    def test_stdout_enters_existing_ingest_and_admission_flow(self) -> None:
        response = load_fixture(FIXTURE)
        backend = CursorCliAgentBackend(
            config=self.config,
            runner=lambda argv, **kwargs: _FakeCompleted(stdout=response),
        )
        controller = ControlSurfaceController(session_dir=self.root / "sessions")
        with mock.patch.object(subprocess, "run", side_effect=_no_real_subprocess):
            controller.submit_goal(
                "Build a local-only browser game with plain HTML/CSS/JavaScript and zero "
                "dependencies. Do not deploy."
            )
            controller.start_high_autonomy_run(
                workspace_path=str(self.target), backend=backend, max_turns=4
            )
            controller.tick_high_autonomy_run()
            state = controller.tick_high_autonomy_run()

        self.assertTrue((state.get("high_autonomy_tick") or {}).get("ingested"))
        self.assertEqual(len(controller._session.run_loop.response_records), 1)
        self.assertGreaterEqual(len(controller._session.queue), 3)

    def test_empty_stdout_pauses_with_diagnostics_and_does_not_reinvoke(self) -> None:
        calls = {"count": 0}

        def runner(argv, **kwargs):
            calls["count"] += 1
            return _FakeCompleted(stdout="\n", stderr="", returncode=0)

        backend = CursorCliAgentBackend(config=self.config, runner=runner)
        controller = ControlSurfaceController(session_dir=self.root / "empty-sessions")
        with mock.patch.object(subprocess, "run", side_effect=_no_real_subprocess):
            controller.submit_goal(
                "Build a local-only browser game with plain HTML/CSS/JavaScript and zero "
                "dependencies. Do not deploy."
            )
            controller.start_high_autonomy_run(
                workspace_path=str(self.target), backend=backend, max_turns=4
            )
            first = controller.tick_high_autonomy_run()
            second = controller.tick_high_autonomy_run()

        pending = AgentInvocationRecord.from_dict(
            controller._session.high_autonomy_run.get("pending_agent_invocation")
        )
        self.assertEqual(calls["count"], 1)
        self.assertEqual(first["high_autonomy_summary"]["mode"], "paused")
        self.assertEqual(second["high_autonomy_summary"]["mode"], "paused")
        self.assertEqual(pending.status, INVOCATION_STATUS_MALFORMED)
        self.assertEqual(pending.stdout_length, 1)
        self.assertEqual(pending.exit_code, 0)
        self.assertEqual(backend.status_snapshot()["last_result"]["status"], AGENT_INVOKE_MALFORMED)


if __name__ == "__main__":
    unittest.main()
