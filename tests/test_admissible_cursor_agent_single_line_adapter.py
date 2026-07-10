"""Slice ADMISSIBLE_RUN_037 — Cursor Agent single-line file-pointer adapter.

Live evidence showed Admissible's multiline ``{prompt}`` adapter was split or
dropped across the Windows ``cursor-agent.CMD -> PowerShell -File -> node $args``
chain, yielding exit 0 with newline-only stdout. The stable contract is one
argv line with no CR/LF/TAB/NUL.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from admissible.agent_backend import (
    AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
    AGENT_INVOKE_SUCCESS,
    PROMPT_MODE_FILE_POINTER,
    AgentInvocationRequest,
    CursorCliAgentBackend,
    CursorCliConfig,
    build_cursor_agent_file_pointer_adapter,
    cursor_agent_adapter_diagnostics,
    validate_cursor_agent_file_pointer_adapter,
)


class _FakeCompleted:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class TestCursorAgentSingleLineAdapter(unittest.TestCase):
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

    def _instruction_file(self) -> Path:
        return (self.agent_workspace / ".admissible" / "next-agent-instruction.md").resolve()

    def test_generated_adapter_is_single_line_without_forbidden_chars(self) -> None:
        instruction_file = self._instruction_file()
        instruction_file.parent.mkdir(parents=True, exist_ok=True)
        instruction_file.write_text("governed", encoding="utf-8")
        adapter = build_cursor_agent_file_pointer_adapter(instruction_file)

        self.assertNotIn("\r", adapter)
        self.assertNotIn("\n", adapter)
        self.assertNotIn("\t", adapter)
        self.assertNotIn("\x00", adapter)
        self.assertEqual(len(adapter.splitlines()), 1)
        self.assertIsNone(validate_cursor_agent_file_pointer_adapter(adapter))
        diag = cursor_agent_adapter_diagnostics(adapter)
        self.assertEqual(diag["adapter_line_count"], 1)
        self.assertFalse(diag["adapter_contains_crlf"])
        self.assertEqual(diag["adapter_prompt_length"], len(adapter))
        self.assertIsNotNone(diag["adapter_sha256"])

    def test_instruction_not_in_argv_and_path_stays_one_element(self) -> None:
        captured: dict = {}

        def runner(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return _FakeCompleted(stdout="proposal")

        instruction = "Build the bounded local files with ADMISSIBLE_STRUCTURED_OPERATION blocks."
        backend = CursorCliAgentBackend(config=self.config, runner=runner)
        result = backend.invoke(self._request(instruction))

        adapter = captured["argv"][-1]
        instruction_path = self._instruction_file()
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertFalse(captured["kwargs"]["shell"])
        self.assertIn(str(instruction_path), adapter)
        self.assertEqual(sum(str(instruction_path) in arg for arg in captured["argv"]), 1)
        self.assertNotIn(instruction, captured["argv"])
        self.assertNotIn(instruction, adapter)
        self.assertEqual(result.prompt_mode, PROMPT_MODE_FILE_POINTER)
        self.assertEqual(result.adapter_line_count, 1)
        self.assertFalse(result.adapter_contains_crlf)

    def test_medium_and_long_instructions_share_identical_one_line_adapter(self) -> None:
        captures: list[str] = []

        def runner(argv, **kwargs):
            captures.append(argv[-1])
            return _FakeCompleted(stdout="proposal")

        backend = CursorCliAgentBackend(config=self.config, runner=runner)
        backend.invoke(self._request("M" * 1200))
        backend.invoke(self._request("L" * 12000))

        self.assertEqual(len(captures), 2)
        self.assertEqual(captures[0], captures[1])
        self.assertNotIn("\n", captures[0])
        self.assertNotIn("\r", captures[0])

    def test_multiline_adapter_blocked_before_runner_invocation(self) -> None:
        calls = {"count": 0}

        def runner(argv, **kwargs):
            calls["count"] += 1
            return _FakeCompleted(stdout="proposal")

        backend = CursorCliAgentBackend(config=self.config, runner=runner)

        def multiline_prompt(self, request, *, instruction_file):
            return "line one\nline two", PROMPT_MODE_FILE_POINTER

        backend._prompt_value = multiline_prompt.__get__(backend, CursorCliAgentBackend)
        result = backend.invoke(self._request("instruction"))

        self.assertEqual(calls["count"], 0)
        self.assertEqual(result.status, AGENT_INVOKE_BLOCKED_BY_CONFIGURATION)
        self.assertIn("one argv line", (result.error_message or "").lower())
        self.assertTrue(result.adapter_contains_crlf)

    def test_validate_rejects_cr_lf_tab_and_nul(self) -> None:
        base = 'Read the complete governed instruction from the file at "/tmp/x". Done.'
        for forbidden, label in (("\r", "CR"), ("\n", "LF"), ("\t", "TAB"), ("\x00", "NUL")):
            error = validate_cursor_agent_file_pointer_adapter(base.replace(". Done", f"{forbidden}. Done"))
            self.assertIsNotNone(error)
            self.assertIn(label, error or "")

    def test_invoke_persists_adapter_diagnostics(self) -> None:
        backend = CursorCliAgentBackend(
            config=self.config,
            runner=lambda argv, **kwargs: _FakeCompleted(stdout="ok"),
        )
        result = backend.invoke(self._request("instruction"))
        self.assertEqual(result.adapter_line_count, 1)
        self.assertFalse(result.adapter_contains_crlf)
        self.assertIsNotNone(result.adapter_sha256)
        self.assertGreater(result.adapter_prompt_length or 0, 0)


if __name__ == "__main__":
    unittest.main()
