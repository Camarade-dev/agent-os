"""Slice ADMISSIBLE_RUN_033 tests — Cursor Agent CLI backend configuration.

Configures the model-agnostic Cursor CLI backend for the real local Cursor Agent
CLI (`cursor-agent`) in read-only planning mode. Verifies the safe preset, the
safety validation that rejects write/execute-granting flags, the subprocess
mechanics, and a two-turn high-autonomy loop driven by a mocked Cursor Agent CLI.

Constraints exercised: no provider calls, **no real Cursor Agent invocation**
(subprocess is injected/mocked), no arbitrary shell execution, backend never
writes the target workspace, model output always routed through ingest/admission.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
from admissible.agent_backend import (
    AGENT_AVAILABILITY_AVAILABLE,
    AGENT_AVAILABILITY_UNSUPPORTED,
    AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
    AGENT_INVOKE_SUCCESS,
    CURSOR_AGENT_CLI_COMMAND,
    CURSOR_CLI_ARGS_ENV,
    CURSOR_CLI_COMMAND_ENV,
    PROMPT_ARG_MAX_CHARS,
    AgentInvocationRequest,
    CursorCliAgentBackend,
    CursorCliConfig,
    assess_cursor_cli_safety,
    cursor_agent_cli_preset_env,
    cursor_agent_cli_safe_args_template,
    describe_available_backends,
    is_cursor_agent_command,
)
from admissible.control_surface import ControlSurfaceController
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "admissible"

TURN_1_FIXTURE = "tiny_game_turn_1_agent_response.md"
TURN_2_FIXTURE = "tiny_game_turn_2_agent_response.md"
TURN_1_FILES = ("index.html", "style.css", "game.js")
TURN_2_NEW_FILE = "README.md"

CANONICAL_GOAL_PROMPT = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)


class _FakeCompleted:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _make_fake_cursor_agent(tmp: Path) -> Path:
    """Create a fake ``cursor-agent`` file so command_exists() is env-independent."""
    fake = tmp / "cursor-agent"
    fake.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    fake.chmod(0o755)
    return fake


class TestCursorAgentPresetAndSafety(unittest.TestCase):
    def test_preset_uses_cursor_agent_command_not_cursor_subcommand(self) -> None:
        env = cursor_agent_cli_preset_env()
        self.assertEqual(env[CURSOR_CLI_COMMAND_ENV], "cursor-agent")
        # Must not drive the IDE wrapper as `cursor agent ...`.
        self.assertNotIn("cursor agent", env[CURSOR_CLI_ARGS_ENV])
        self.assertTrue(is_cursor_agent_command("cursor-agent"))
        self.assertFalse(is_cursor_agent_command("cursor"))

    def test_preset_has_required_read_only_flags(self) -> None:
        args = cursor_agent_cli_safe_args_template()
        self.assertIn("--print", args)
        self.assertIn("--mode", args)
        self.assertIn("plan", args)
        self.assertIn("--workspace", args)
        self.assertIn("{agent_workspace}", args)
        self.assertIn("{prompt}", args)
        # The preset itself must pass its own safety validation.
        blocking, _ = assess_cursor_cli_safety(CURSOR_AGENT_CLI_COMMAND, args)
        self.assertEqual(blocking, [])

    def test_rejects_force_yolo_and_sandbox_disabled(self) -> None:
        base = cursor_agent_cli_safe_args_template()
        for unsafe in (base + ["--force"], base + ["--yolo"]):
            blocking, _ = assess_cursor_cli_safety(CURSOR_AGENT_CLI_COMMAND, unsafe)
            self.assertTrue(blocking)
        sandbox = ["--print", "--mode", "plan", "--sandbox", "disabled",
                   "--workspace", "{agent_workspace}", "{prompt}"]
        blocking, _ = assess_cursor_cli_safety(CURSOR_AGENT_CLI_COMMAND, sandbox)
        self.assertTrue(any("sandbox" in b.lower() for b in blocking))

    def test_missing_plan_mode_blocks_configuration(self) -> None:
        no_plan = ["--print", "--workspace", "{agent_workspace}", "{prompt}"]
        blocking, _ = assess_cursor_cli_safety(CURSOR_AGENT_CLI_COMMAND, no_plan)
        self.assertTrue(any("plan" in b.lower() for b in blocking))
        # --plan (short form) is accepted.
        with_plan = ["--print", "--plan", "--workspace", "{agent_workspace}", "{prompt}"]
        blocking2, _ = assess_cursor_cli_safety(CURSOR_AGENT_CLI_COMMAND, with_plan)
        self.assertFalse(any("plan" in b.lower() for b in blocking2))

    def test_missing_print_blocks_configuration(self) -> None:
        no_print = ["--mode", "plan", "--workspace", "{agent_workspace}", "{prompt}"]
        blocking, _ = assess_cursor_cli_safety(CURSOR_AGENT_CLI_COMMAND, no_print)
        self.assertTrue(any("--print" in b for b in blocking))

    def test_cursor_ide_with_agent_subcommand_blocked(self) -> None:
        blocking, _ = assess_cursor_cli_safety(
            "cursor", ["agent", "--print", "--mode", "plan", "--workspace", "{agent_workspace}", "{prompt}"]
        )
        self.assertTrue(any("cursor-agent" in b for b in blocking))

    def test_workspace_must_use_agent_workspace_placeholder(self) -> None:
        hardcoded = ["--print", "--mode", "plan", "--workspace", "/tmp/target", "{prompt}"]
        blocking, _ = assess_cursor_cli_safety(CURSOR_AGENT_CLI_COMMAND, hardcoded)
        self.assertTrue(any("agent_workspace" in b for b in blocking))

    def test_no_model_is_visible_warning_not_block(self) -> None:
        blocking, warnings = assess_cursor_cli_safety(
            CURSOR_AGENT_CLI_COMMAND, cursor_agent_cli_safe_args_template()
        )
        self.assertEqual(blocking, [])
        self.assertTrue(any("model" in w.lower() for w in warnings))


class TestCursorAgentInvocation(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.fake = _make_fake_cursor_agent(self.tmp)
        self.target = self.tmp / "project"
        self.target.mkdir()
        self.agent_ws = self.target / ".admissible" / "agent_workspace"
        self.agent_ws.mkdir(parents=True)
        self.config = CursorCliConfig.cursor_agent_preset(command=str(self.fake))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _request(self, text: str = "scaffold the game") -> AgentInvocationRequest:
        return AgentInvocationRequest(
            instruction_text=text,
            agent_workspace_path=str(self.agent_ws),
            target_workspace_path=str(self.target),
            timeout_seconds=30.0,
        )

    def test_configured_preset_is_available(self) -> None:
        backend = CursorCliAgentBackend(config=self.config, runner=lambda *a, **k: _FakeCompleted("ok"))
        self.assertTrue(self.config.ready())
        self.assertEqual(backend.availability().status, AGENT_AVAILABILITY_AVAILABLE)

    def test_subprocess_shell_false_cwd_agent_workspace_and_prompt_arg(self) -> None:
        captured: dict = {}

        def runner(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return _FakeCompleted(stdout="ADMISSIBLE PROPOSAL: write_file game.js")

        backend = CursorCliAgentBackend(config=self.config, runner=runner)
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("no real cursor")):
            result = backend.invoke(self._request())

        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertFalse(captured["kwargs"]["shell"])
        self.assertIsInstance(captured["argv"], list)
        self.assertEqual(
            Path(captured["kwargs"]["cwd"]).resolve(), self.agent_ws.resolve()
        )
        self.assertNotEqual(
            Path(captured["kwargs"]["cwd"]).resolve(), self.target.resolve()
        )
        # Read-only plan-mode flags are present, and the prompt is a single argv
        # element (never shell-interpreted).
        self.assertIn("--print", captured["argv"])
        self.assertIn("plan", captured["argv"])
        self.assertIn("scaffold the game", captured["argv"])
        # The --workspace value resolves to the agent workspace, not target.
        ws_idx = captured["argv"].index("--workspace")
        self.assertEqual(
            Path(captured["argv"][ws_idx + 1]).resolve(), self.agent_ws.resolve()
        )

    def test_long_prompt_uses_instruction_file_pointer(self) -> None:
        captured: dict = {}

        def runner(argv, **kwargs):
            captured["argv"] = argv
            return _FakeCompleted(stdout="proposal")

        backend = CursorCliAgentBackend(config=self.config, runner=runner)
        backend.invoke(self._request("Z" * (PROMPT_ARG_MAX_CHARS + 50)))
        self.assertTrue(any("Read the instruction file at" in a for a in captured["argv"]))
        instr = self.agent_ws / ".admissible" / "next-agent-instruction.md"
        self.assertTrue(instr.is_file())
        self.assertTrue(instr.read_text(encoding="utf-8").startswith("Z"))

    def test_stdout_is_returned_as_response_text_not_executed(self) -> None:
        def runner(argv, **kwargs):
            # A dangerous-looking proposal must be returned, never executed.
            return _FakeCompleted(stdout="Proposed: rm -rf / ; write_file game.js")

        backend = CursorCliAgentBackend(config=self.config, runner=runner)
        before = {p.name for p in self.target.iterdir() if p.is_file()}
        result = backend.invoke(self._request())
        after = {p.name for p in self.target.iterdir() if p.is_file()}
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertIn("write_file", result.response_text)
        self.assertEqual(before, after)  # backend wrote no target files

    def test_unsafe_config_is_unsupported_and_never_runs(self) -> None:
        unsafe = CursorCliConfig.from_env(
            {
                CURSOR_CLI_COMMAND_ENV: str(self.fake),
                CURSOR_CLI_ARGS_ENV: (
                    "--print --mode plan --workspace {agent_workspace} --yolo {prompt}"
                ),
            }
        )
        self.assertEqual(
            CursorCliAgentBackend(config=unsafe).availability().status,
            AGENT_AVAILABILITY_UNSUPPORTED,
        )

        def runner(argv, **kwargs):
            raise AssertionError("unsafe config must never invoke the CLI")

        backend = CursorCliAgentBackend(config=unsafe, runner=runner)
        result = backend.invoke(self._request())
        self.assertEqual(result.status, AGENT_INVOKE_BLOCKED_BY_CONFIGURATION)


class TestCursorAgentBackendDiscovery(unittest.TestCase):
    def test_describe_backends_shows_cursor_agent_label_and_safety_mode(self) -> None:
        env = cursor_agent_cli_preset_env(command="cursor-agent")
        backends = {b["backend_id"]: b for b in describe_available_backends(env)}
        cursor = backends["cursor_cli"]
        self.assertIn("Cursor Agent CLI", cursor["label"])
        self.assertTrue(cursor["proposal_only"])
        self.assertIsNotNone(cursor["safety_mode"])
        self.assertIn("--mode plan", cursor["safety_mode"])


def _cursor_agent_runner(responses: list[str]):
    """A fake subprocess runner that returns queued fixture stdout per call."""
    queue = list(responses)

    def runner(argv, **kwargs):
        text = queue.pop(0) if queue else ""
        return _FakeCompleted(stdout=text, returncode=0)

    return runner


class TestCursorAgentHighAutonomyLoop(unittest.TestCase):
    def test_two_turns_with_mocked_cursor_agent_backend(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        fake = _make_fake_cursor_agent(tmp)
        workspace = tmp / "workspace"
        workspace.mkdir()
        controller = ControlSurfaceController(session_dir=tmp / "sessions")
        config = CursorCliConfig.cursor_agent_preset(command=str(fake))
        runner = _cursor_agent_runner(
            [
                load_fixture(FIXTURES_DIR / TURN_1_FIXTURE),
                load_fixture(FIXTURES_DIR / TURN_2_FIXTURE),
            ]
        )
        backend = CursorCliAgentBackend(config=config, runner=runner)

        # Guarantee no real Cursor Agent process is ever spawned.
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("no real cursor")):
            controller.submit_goal(CANONICAL_GOAL_PROMPT)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace), backend=backend, max_turns=8
            )
            for _ in range(16):
                state = controller.tick_high_autonomy_run()
                if state["high_autonomy_summary"]["mode"] in ("stopped", "failed"):
                    break

        # Two full turns ran with no manual file bridge; files were written only by
        # Admissible's bounded executor.
        self.assertEqual(len(controller._session.run_loop.response_records), 2)
        for name in TURN_1_FILES:
            self.assertTrue((workspace / name).is_file())
        self.assertTrue((workspace / TURN_2_NEW_FILE).is_file())
        view = controller.state_view()
        executed = [
            item
            for item in view["queue"]
            if item["execution_status"] == EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
        ]
        self.assertGreaterEqual(len(executed), 3)
        # Agent workspace is isolated from the target workspace.
        self.assertTrue((workspace / ".admissible" / "agent_workspace").is_dir())


class TestCursorAgentUi(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = (REPO_ROOT / "admissible" / "harness" / "control_surface.html").read_text(
            encoding="utf-8"
        )

    def test_ui_displays_cursor_agent_safety_mode(self) -> None:
        # The backend note renders the dynamic safety_mode from the backend list.
        self.assertIn("safety_mode", self.html)
        # And a static hint states the read-only, proposal-only plan mode.
        self.assertIn("Cursor Agent CLI runs read-only", self.html)
        self.assertIn("--print --mode plan", self.html)
        self.assertIn("proposal-only", self.html)


if __name__ == "__main__":
    unittest.main()
