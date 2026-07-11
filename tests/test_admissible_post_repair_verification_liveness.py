"""RUN_045 PART J — post-repair verification liveness (PART C/E integration).

After a repair write has executed (``repair_phase`` in
``repair_executing``/``repair_verifying``), the run must schedule a static or
runtime re-verification on the very next tick -- never return to
``next_action=none`` and never spin waiting for a response that will never
arrive. This is a general state-machine/liveness fix, exercised here against
both a callable backend and the legacy file-bridge transport so it is clear
the fix is not specific to any one transport.

No real model/Cursor CLI/browser-provider calls -- fixture doubles only.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_backend import FixtureAgentBackend
from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController
from admissible.governed_run import FINAL_OUTCOMES
from admissible.high_autonomy_controller import (
    HA_MODE_WAITING_FOR_AGENT,
    HA_NEXT_START_RUNTIME_VERIFICATION,
    HA_NEXT_VERIFY,
    REPAIR_PHASE_REPAIR_VERIFYING,
    _plan_next_action,
    HighAutonomyPolicy,
)

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_002_regression.json"
)


def _response(operations: list[dict]) -> str:
    return "\n".join(
        "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
        + json.dumps(operation, ensure_ascii=False)
        + "\n```"
        for operation in operations
    )


class TestPostRepairVerificationLiveness(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def _initial_ops(self, game_js: str) -> list[dict]:
        return [
            {
                "operation": "write_file",
                "path": "index.html",
                "content": '<!doctype html><link rel="stylesheet" href="style.css"><canvas id="game"></canvas><span id="score">0</span><script src="game.js"></script>\n',
            },
            {"operation": "write_file", "path": "style.css", "content": "body{margin:0;}\n"},
            {"operation": "write_file", "path": "game.js", "content": game_js},
            {
                "operation": "write_file",
                "path": "LOCAL_DEV.md",
                "content": "To run locally, open index.html in your browser.\n",
            },
        ]

    def test_callable_backend_repair_does_not_livelock_and_completes(self) -> None:
        goal = self.fixture["goal_text"]
        missing_restart_js = self.fixture["game_js_cli002_missing_restart_content"]
        fixed_js = missing_restart_js.replace(
            "  window.addEventListener('keydown', (e) => {\n    keys[e.key] = true;\n  });",
            "  window.addEventListener('keydown', (e) => {\n    keys[e.key] = true;\n"
            "    if (e.key === 'r' || e.key === 'R') init();\n  });",
        )
        self.assertNotEqual(fixed_js, missing_restart_js, "test setup must actually change the content")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            backend = FixtureAgentBackend(
                [
                    _response(self._initial_ops(missing_restart_js)),
                    _response([{"operation": "write_file", "path": "game.js", "content": fixed_js}]),
                ]
            )
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(goal)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace), backend=backend, max_turns=12, closure_reserve_turns=2
            )
            stuck_ticks = 0
            for _ in range(40):
                state = controller.tick_high_autonomy_run()
                summary = state["high_autonomy_summary"]
                self.assertNotEqual(summary.get("current_step"), "internal_livelock")
                if summary.get("mode") == HA_MODE_WAITING_FOR_AGENT and summary.get("next_action") == "none":
                    stuck_ticks += 1
                    self.assertLess(
                        stuck_ticks, 3,
                        "must never repeat a reasonless waiting_for_agent/next_action=none tick "
                        "more than the bounded technical-pause threshold",
                    )
                if summary.get("outcome") in FINAL_OUTCOMES:
                    break
            summary = state["high_autonomy_summary"]
            self.assertEqual(summary["outcome"], "completed")
            # Exactly one repair invocation, never re-billed just to escape the wait.
            self.assertEqual(len(backend.invocations), 2)

    def test_file_bridge_repair_still_completes_without_livelock(self) -> None:
        goal = self.fixture["goal_text"]
        missing_restart_js = self.fixture["game_js_cli002_missing_restart_content"]
        fixed_js = missing_restart_js.replace(
            "  window.addEventListener('keydown', (e) => {\n    keys[e.key] = true;\n  });",
            "  window.addEventListener('keydown', (e) => {\n    keys[e.key] = true;\n"
            "    if (e.key === 'r' || e.key === 'R') init();\n  });",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            transport = FixtureAgentTransport()
            transport.set_responses(
                [_response([{"operation": "write_file", "path": "game.js", "content": fixed_js}])]
            )
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(goal)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace), transport=transport, max_turns=12, closure_reserve_turns=2
            )
            controller.ingest_agent_response(_response(self._initial_ops(missing_restart_js)))
            for _ in range(40):
                state = controller.tick_high_autonomy_run()
                summary = state["high_autonomy_summary"]
                self.assertNotEqual(summary.get("current_step"), "internal_livelock")
                if summary.get("outcome") in FINAL_OUTCOMES:
                    break
            summary = state["high_autonomy_summary"]
            self.assertEqual(summary["outcome"], "completed")
            self.assertEqual(len(transport.written_instructions), 1)

    def test_runtime_sourced_repair_kind_routes_to_runtime_verification_not_static(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal("Create result.txt locally.")
            controller.start_high_autonomy_run(workspace_path=str(workspace), max_turns=8)
            ha = controller._high_autonomy_state()
            ha.repair_phase = REPAIR_PHASE_REPAIR_VERIFYING
            ha.runtime_repair_kind = "runtime_verification_failure"
            ha.mode = "verifying"
            controller._set_high_autonomy_state(ha)
            transport = controller._high_autonomy_transport
            planned = _plan_next_action(controller, ha, HighAutonomyPolicy(), transport)
            self.assertEqual(planned, HA_NEXT_START_RUNTIME_VERIFICATION)

    def test_static_repair_kind_routes_to_bounded_verification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal("Create result.txt locally.")
            controller.start_high_autonomy_run(workspace_path=str(workspace), max_turns=8)
            ha = controller._high_autonomy_state()
            ha.repair_phase = REPAIR_PHASE_REPAIR_VERIFYING
            ha.runtime_repair_kind = None
            ha.mode = "verifying"
            controller._set_high_autonomy_state(ha)
            transport = controller._high_autonomy_transport
            planned = _plan_next_action(controller, ha, HighAutonomyPolicy(), transport)
            self.assertEqual(planned, HA_NEXT_VERIFY)


if __name__ == "__main__":
    unittest.main()
