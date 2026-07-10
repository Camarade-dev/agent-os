"""Slice ADMISSIBLE_RUN_032 tests — model-agnostic agent transport/backends.

Exercises the backend abstraction and callable-backend high-autonomy loop:

- FixtureAgentBackend returns scripted responses deterministically (no subprocess).
- CursorCliAgentBackend is unavailable/blocked_by_configuration until configured,
  and — when configured — runs subprocess.run with shell=False, a timeout, and
  cwd set to the *agent* workspace (never the target workspace), with a sanitized
  environment. A real Cursor CLI is never spawned (subprocess is mocked).
- Cursor CLI output is ingested through admission, never executed directly, and a
  backend never writes application files into the target workspace.
- The callable-backend high-autonomy loop runs >= 2 turns without any manual
  file-bridge waiting; low-risk local writes are auto-executed only by
  Admissible's bounded executor; npm/deploy and human-critical proposals still
  recover / pause per policy.

Constraints exercised: no provider calls, no real Cursor invocation, no arbitrary
shell execution, admission/content guards never weakened, human-critical never
auto-approved, backends never write the target workspace directly.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
from admissible.agent_backend import (
    AGENT_AVAILABILITY_AVAILABLE,
    AGENT_AVAILABILITY_NOT_CONFIGURED,
    AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
    AGENT_INVOKE_SUCCESS,
    AGENT_INVOKE_UNAVAILABLE,
    CURSOR_CLI_ARGS_ENV,
    CURSOR_CLI_COMMAND_ENV,
    AgentInvocationRequest,
    CallableBackendTransport,
    CursorCliAgentBackend,
    CursorCliConfig,
    FixtureAgentBackend,
    assess_workspace_safety,
    default_agent_workspace_path,
    describe_available_backends,
)
from admissible.control_surface import ControlSurfaceController
from admissible.high_autonomy_controller import (
    HA_MODE_HUMAN_REQUIRED,
    HA_MODE_PAUSED,
)
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "admissible"

TURN_1_FIXTURE = "tiny_game_turn_1_agent_response.md"
TURN_2_FIXTURE = "tiny_game_turn_2_agent_response.md"
TURN_3_FIXTURE = "tiny_game_turn_3_blocked_agent_response.md"
TURN_4_FIXTURE = "tiny_game_turn_4_recovery_agent_response.md"

TURN_1_FILES = ("index.html", "style.css", "game.js")
TURN_2_NEW_FILE = "README.md"

CANONICAL_GOAL_PROMPT = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)

GIT_PUSH_RESPONSE = (
    "Cursor Agent — publish request (nothing executed)\n\n"
    "User: Publish the game so others can play it.\n\n"
    "Thinking...\n"
    "I will send the local commits to the remote so it is visible online.\n\n"
    "Proposed command:\n"
    "    git push origin main\n\n"
    "Status: PROPOSED — awaiting the admission gate.\n"
    "Note: Nothing was executed.\n"
)


class _FakeCompleted:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _cursor_cli_config(**overrides: str) -> CursorCliConfig:
    # Use a real executable path (the test interpreter) so command_exists() is
    # true via is_file(); the injected runner means it is never actually run.
    env = {
        CURSOR_CLI_COMMAND_ENV: sys.executable,
        CURSOR_CLI_ARGS_ENV: '["agent", "--instructions", "{instruction_file}"]',
    }
    env.update(overrides)
    return CursorCliConfig.from_env(env)


class TestFixtureAgentBackend(unittest.TestCase):
    def test_scripted_responses_are_deterministic(self) -> None:
        backend = FixtureAgentBackend(["one", "two"])
        r1 = backend.invoke(AgentInvocationRequest(instruction_text="i1"))
        r2 = backend.invoke(AgentInvocationRequest(instruction_text="i2"))
        self.assertEqual((r1.status, r1.response_text), (AGENT_INVOKE_SUCCESS, "one"))
        self.assertEqual((r2.status, r2.response_text), (AGENT_INVOKE_SUCCESS, "two"))
        self.assertEqual(len(backend.invocations), 2)

    def test_exhausted_backend_reports_unavailable_not_crash(self) -> None:
        backend = FixtureAgentBackend(["only"])
        backend.invoke(AgentInvocationRequest(instruction_text="i1"))
        exhausted = backend.invoke(AgentInvocationRequest(instruction_text="i2"))
        self.assertEqual(exhausted.status, AGENT_INVOKE_UNAVAILABLE)
        self.assertFalse(exhausted.ok)

    def test_no_subprocess_used(self) -> None:
        backend = FixtureAgentBackend(["x"])
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("no subprocess")):
            result = backend.invoke(AgentInvocationRequest(instruction_text="i"))
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)


class TestCursorCliBackendConfiguration(unittest.TestCase):
    def test_unavailable_when_not_configured(self) -> None:
        backend = CursorCliAgentBackend(config=CursorCliConfig.from_env({}))
        availability = backend.availability()
        self.assertEqual(availability.status, AGENT_AVAILABILITY_NOT_CONFIGURED)
        self.assertFalse(availability.available)
        result = backend.invoke(
            AgentInvocationRequest(instruction_text="hi", agent_workspace_path="x")
        )
        self.assertEqual(result.status, AGENT_INVOKE_BLOCKED_BY_CONFIGURATION)
        self.assertIn(CURSOR_CLI_COMMAND_ENV, result.error_message or "")

    def test_blocked_when_args_template_missing(self) -> None:
        config = CursorCliConfig.from_env({CURSOR_CLI_COMMAND_ENV: "cursor-agent"})
        # command configured but no argv template -> refuse to guess syntax.
        self.assertFalse(config.ready())
        self.assertIn("argv template", config.missing_reason() or "")

    def test_does_not_run_when_not_configured(self) -> None:
        backend = CursorCliAgentBackend(config=CursorCliConfig.from_env({}))
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("no cursor run")):
            result = backend.invoke(
                AgentInvocationRequest(instruction_text="hi", agent_workspace_path="x")
            )
        self.assertEqual(result.status, AGENT_INVOKE_BLOCKED_BY_CONFIGURATION)


class TestCursorCliBackendInvocation(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.target = Path(self._tmp.name) / "project"
        self.target.mkdir()
        self.agent_ws = self.target / ".admissible" / "agent_workspace"
        self.agent_ws.mkdir(parents=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _configured_backend(self, runner) -> CursorCliAgentBackend:
        return CursorCliAgentBackend(config=_cursor_cli_config(), runner=runner)

    def test_uses_subprocess_shell_false_timeout_and_agent_cwd(self) -> None:
        captured: dict = {}

        def runner(argv, **kwargs):
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return _FakeCompleted(stdout="Proposed: write_file game.js")

        backend = self._configured_backend(runner)
        request = AgentInvocationRequest(
            instruction_text="scaffold the game",
            agent_workspace_path=str(self.agent_ws),
            target_workspace_path=str(self.target),
            timeout_seconds=42.0,
        )
        result = backend.invoke(request)

        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertFalse(captured["kwargs"]["shell"])
        self.assertEqual(captured["kwargs"]["timeout"], 42.0)
        # cwd is the agent workspace, never the target workspace.
        self.assertEqual(Path(captured["kwargs"]["cwd"]).resolve(), self.agent_ws.resolve())
        self.assertNotEqual(Path(captured["kwargs"]["cwd"]).resolve(), self.target.resolve())
        # argv is a fixed list (no shell string), instruction handed via a file.
        self.assertIsInstance(captured["argv"], list)
        self.assertTrue(any("next-agent-instruction.md" in a for a in captured["argv"]))

    def test_environment_is_sanitized_no_secret_leak(self) -> None:
        captured: dict = {}

        def runner(argv, **kwargs):
            captured["kwargs"] = kwargs
            return _FakeCompleted(stdout="ok")

        backend = self._configured_backend(runner)
        with mock.patch.dict(
            "os.environ", {"OPENAI_API_KEY": "sk-secret", "ANTHROPIC_API_KEY": "sk-2"}, clear=False
        ):
            backend.invoke(
                AgentInvocationRequest(
                    instruction_text="go",
                    agent_workspace_path=str(self.agent_ws),
                    target_workspace_path=str(self.target),
                )
            )
        env = captured["kwargs"]["env"]
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertNotIn(CURSOR_CLI_COMMAND_ENV, env)

    def test_output_is_returned_not_executed_and_target_untouched(self) -> None:
        def runner(argv, **kwargs):
            # A malicious-looking proposal must NOT be executed by the backend.
            return _FakeCompleted(stdout="Proposed command: rm -rf / ; write_file game.js")

        backend = self._configured_backend(runner)
        before = {p.name for p in self.target.iterdir() if p.is_file()}
        result = backend.invoke(
            AgentInvocationRequest(
                instruction_text="go",
                agent_workspace_path=str(self.agent_ws),
                target_workspace_path=str(self.target),
            )
        )
        after = {p.name for p in self.target.iterdir() if p.is_file()}
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertIn("write_file", result.response_text)
        # The backend only returns text; it wrote no application files in target.
        self.assertEqual(before, after)

    def test_timeout_is_reported_not_raised(self) -> None:
        def runner(argv, **kwargs):
            raise subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout"))

        backend = self._configured_backend(runner)
        result = backend.invoke(
            AgentInvocationRequest(
                instruction_text="go",
                agent_workspace_path=str(self.agent_ws),
                target_workspace_path=str(self.target),
            )
        )
        self.assertEqual(result.status, "timeout")

    def test_refuses_when_agent_workspace_equals_target(self) -> None:
        def runner(argv, **kwargs):
            raise AssertionError("must not run when agent workspace == target")

        backend = self._configured_backend(runner)
        result = backend.invoke(
            AgentInvocationRequest(
                instruction_text="go",
                agent_workspace_path=str(self.target),
                target_workspace_path=str(self.target),
            )
        )
        self.assertEqual(result.status, AGENT_INVOKE_BLOCKED_BY_CONFIGURATION)


class TestWorkspaceSafety(unittest.TestCase):
    def test_missing_target_blocks(self) -> None:
        assessment = assess_workspace_safety(target_workspace_path=None)
        self.assertFalse(assessment.safe_to_start)
        self.assertIn("No target workspace configured.", assessment.blocking_reasons)

    def test_agent_os_repo_target_blocks(self) -> None:
        assessment = assess_workspace_safety(
            target_workspace_path=str(REPO_ROOT), repo_root=str(REPO_ROOT)
        )
        self.assertTrue(assessment.target_is_agent_os_repo)
        self.assertFalse(assessment.safe_to_start)

    def test_default_agent_workspace_differs_from_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            agent_ws = default_agent_workspace_path(target)
            self.assertNotEqual(agent_ws.resolve(), target.resolve())
            assessment = assess_workspace_safety(
                target_workspace_path=str(target), high_autonomy=True
            )
            self.assertTrue(assessment.safe_to_start)
            self.assertFalse(assessment.agent_equals_target)

    def test_high_autonomy_blocks_agent_equals_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            assessment = assess_workspace_safety(
                target_workspace_path=tmp,
                agent_workspace_path=tmp,
                high_autonomy=True,
            )
            self.assertTrue(assessment.agent_equals_target)
            self.assertFalse(assessment.safe_to_start)

    def test_describe_backends_lists_all_with_availability(self) -> None:
        backends = {b["backend_id"]: b for b in describe_available_backends({})}
        self.assertIn("file_bridge", backends)
        self.assertIn("cursor_cli", backends)
        self.assertIn("fixture", backends)
        self.assertFalse(backends["cursor_cli"]["availability"]["available"])
        self.assertTrue(backends["file_bridge"]["availability"]["available"])


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("callable-backend loop must never spawn a real subprocess")


class TestCallableBackendHighAutonomyLoop(unittest.TestCase):
    """The callable-backend loop drives multiple turns with no manual bridge wait."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, backend, *, max_ticks: int = 16):
        states = []
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace), backend=backend, max_turns=8
            )
            for _ in range(max_ticks):
                state = self.controller.tick_high_autonomy_run()
                states.append(state)
                mode = state["high_autonomy_summary"]["mode"]
                if mode in ("stopped", "failed", HA_MODE_HUMAN_REQUIRED, HA_MODE_PAUSED):
                    if mode in ("stopped", "failed"):
                        break
        return states

    def test_two_turns_without_manual_file_bridge_waiting(self) -> None:
        backend = FixtureAgentBackend(
            [
                load_fixture(FIXTURES_DIR / TURN_1_FIXTURE),
                load_fixture(FIXTURES_DIR / TURN_2_FIXTURE),
            ]
        )
        self._run(backend)
        # Both turns were invoked directly on the backend (no waiting for a human
        # to drive an external editor); two full turns were ingested + executed.
        self.assertGreaterEqual(len(backend.invocations), 2)
        response_records = self.controller._session.run_loop.response_records
        self.assertEqual(len(response_records), 2)
        for name in TURN_1_FILES:
            self.assertTrue((self.workspace / name).is_file())
        self.assertTrue((self.workspace / TURN_2_NEW_FILE).is_file())

    def test_low_risk_writes_executed_only_by_bounded_executor(self) -> None:
        backend = FixtureAgentBackend([load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)])
        self._run(backend)
        view = self.controller.state_view()
        executed = [
            item
            for item in view["queue"]
            if item["execution_status"] == EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
        ]
        self.assertGreaterEqual(len(executed), 3)
        # No side_effect_executed_by_admissible flag flips true.
        self.assertFalse(view["mission_summary"]["side_effect_executed_by_admissible"])

    def test_ingest_does_not_write_target_before_bounded_execution(self) -> None:
        # A single-turn backend: after the first invoke+ingest tick, before the
        # auto-execute tick fires, no target files exist yet.
        backend = FixtureAgentBackend([load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)])
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace), backend=backend, max_turns=8
            )
            self.controller.tick_high_autonomy_run()  # write + invoke
            self.controller.tick_high_autonomy_run()  # ingest
            files_after_ingest = {p.name for p in self.workspace.iterdir() if p.is_file()}
        self.assertEqual(files_after_ingest, set())

    def test_agent_workspace_created_and_separate_from_target(self) -> None:
        backend = FixtureAgentBackend([load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)])
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            view = self.controller.start_high_autonomy_run(
                workspace_path=str(self.workspace), backend=backend, max_turns=8
            )
        summary = view["high_autonomy_summary"]
        self.assertEqual(summary["transport_kind"], "callable_backend")
        self.assertTrue((self.workspace / ".admissible" / "agent_workspace").is_dir())
        self.assertNotEqual(summary["agent_workspace_path"], summary["workspace_path"])

    def test_npm_deploy_blocked_proposals_recover_not_executed(self) -> None:
        backend = FixtureAgentBackend(
            [
                load_fixture(FIXTURES_DIR / TURN_1_FIXTURE),
                load_fixture(FIXTURES_DIR / TURN_3_FIXTURE),  # npm + deploy blockers
                load_fixture(FIXTURES_DIR / TURN_4_FIXTURE),  # local-only recovery
            ]
        )
        self._run(backend, max_ticks=24)
        view = self.controller.state_view()
        # The npm/deploy proposals were admitted-blocked and never executed by the
        # bounded executor, regardless of which loop turn they landed on.
        npm_deploy = [
            item
            for item in view["queue"]
            if item["action_type"] in ("install_dependency", "deploy_code")
        ]
        self.assertTrue(npm_deploy)
        for item in npm_deploy:
            self.assertNotEqual(
                item["execution_status"], EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
            )
            self.assertNotEqual(item["decision"], "ALLOW")
        # A recovery instruction was issued to the backend (3rd invocation).
        self.assertGreaterEqual(len(backend.invocations), 3)

    def test_human_critical_git_push_pauses_and_is_not_auto_approved(self) -> None:
        backend = FixtureAgentBackend(
            [load_fixture(FIXTURES_DIR / TURN_1_FIXTURE), GIT_PUSH_RESPONSE]
        )
        states = self._run(backend, max_ticks=24)
        modes = [s["high_autonomy_summary"]["mode"] for s in states]
        self.assertIn(HA_MODE_HUMAN_REQUIRED, modes)
        final = self.controller.state_view()["high_autonomy_summary"]
        self.assertTrue(final["human_action_required"])

    def test_backend_block_pauses_loop_without_spinning(self) -> None:
        # A backend that yields one turn then goes unavailable must pause the loop
        # with a clear reason rather than spin re-planning forever.
        backend = FixtureAgentBackend([load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)])
        states = self._run(backend, max_ticks=20)
        final = states[-1]["high_autonomy_summary"]
        self.assertEqual(final["mode"], HA_MODE_PAUSED)
        self.assertTrue(final["backend_block_reason"])


class TestCallableBackendTransportAdapter(unittest.TestCase):
    def test_write_then_read_round_trips_backend_response(self) -> None:
        backend = FixtureAgentBackend(["structured proposal"])
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "t"
            target.mkdir()
            agent_ws = target / ".admissible" / "agent_workspace"
            transport = CallableBackendTransport(
                backend,
                target_workspace_path=str(target),
                agent_workspace_path=str(agent_ws),
            )
            result = transport.write_instruction("do it", turn_number=1, session_id="s")
            self.assertEqual(result["invoke_status"], AGENT_INVOKE_SUCCESS)
            read = transport.read_response_if_changed()
            self.assertTrue(read.changed)
            self.assertEqual(read.text, "structured proposal")

    def test_terminal_block_surfaces_last_result(self) -> None:
        backend = CursorCliAgentBackend(config=CursorCliConfig.from_env({}))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "t"
            target.mkdir()
            transport = CallableBackendTransport(
                backend,
                target_workspace_path=str(target),
                agent_workspace_path=str(target / "agent"),
            )
            transport.write_instruction("do it", turn_number=1)
            self.assertIsNotNone(transport.last_invocation_result)
            self.assertTrue(transport.last_invocation_result.is_terminal_block)
            read = transport.read_response_if_changed()
            self.assertFalse(read.changed)


if __name__ == "__main__":
    unittest.main()
