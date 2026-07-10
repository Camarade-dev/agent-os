from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import (
    ControlSurfaceController,
    DecisionQueueItem,
    HumanDecisionRecord,
    _repair_stale_negated_non_actions,
)
from admissible.governed_run import FINAL_OUTCOMES, count_genuine_human_interventions
from admissible.long_run_envelope_builder import CLI_011_NEGATED_CONSTRAINT_SENTENCE

FIXTURE_011 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_011_regression.json"
)
FIXTURE_010 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_010_regression.json"
)
FIXTURE_007 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_007_regression.json"
)
FIXTURE_006 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_006_regression.json"
)


def _response(operations: list[dict], *, negative_prose: str | None = None) -> str:
    blocks = "\n".join(
        "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
        + json.dumps(operation, ensure_ascii=False)
        + "\n```"
        for operation in operations
    )
    if negative_prose:
        return f"{blocks}\n\n- {negative_prose}"
    return blocks


class TestAdmissibleLiveRun011Regression(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE_011.read_text(encoding="utf-8"))

    def test_fixture_documents_cli011_defect_surface(self) -> None:
        self.assertEqual(self.fixture["source_session"], "pixel-wanderer-cli-011")
        gate = self.fixture["false_git_push_candidate"]
        self.assertEqual(gate["action_type"], "git_push")
        self.assertTrue(gate["human_decision_recorded"])
        self.assertEqual(self.fixture["final_state_before_fix"]["outcome"], "incomplete")

    def test_cli011_replay_completes_without_phantom_blocker_or_repair_turn(self) -> None:
        goal = self.fixture["goal_text"]
        game_js = self.fixture["game_js_cli011_content"]
        initial = [
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
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            transport = FixtureAgentTransport()
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(goal)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace),
                transport=transport,
                max_turns=12,
                closure_reserve_turns=2,
            )
            controller.ingest_agent_response(
                _response(initial, negative_prose=CLI_011_NEGATED_CONSTRAINT_SENTENCE)
            )
            built_types = [item.action_type for item in controller._session.queue]
            self.assertEqual(built_types.count("git_push"), 0)
            for _ in range(30):
                state = controller.tick_high_autonomy_run()
                summary = state["high_autonomy_summary"]
                if summary.get("outcome") in FINAL_OUTCOMES:
                    break
            summary = state["high_autonomy_summary"]
            metrics = summary.get("metrics") or {}
            self.assertEqual(summary["outcome"], "completed")
            self.assertEqual(summary["acceptance_verified_count"], 8)
            self.assertEqual(metrics.get("active_blocked_count"), 0)
            self.assertEqual(metrics.get("genuine_human_intervention_count"), 0)
            self.assertEqual(len(transport.written_instructions), 0)

    def test_cli011_missing_restart_repair_path(self) -> None:
        goal = self.fixture["goal_text"]
        missing_restart_js = self.fixture["game_js_cli011_content"].replace(
            "if (e.key === 'r' || e.key === 'R') init();",
            "// restart handler removed for repair test",
        )
        initial = [
            {
                "operation": "write_file",
                "path": "index.html",
                "content": '<!doctype html><link rel="stylesheet" href="style.css"><canvas id="game"></canvas><span id="score">0</span><script src="game.js"></script>\n',
            },
            {"operation": "write_file", "path": "style.css", "content": "body{margin:0;}\n"},
            {"operation": "write_file", "path": "game.js", "content": missing_restart_js},
            {
                "operation": "write_file",
                "path": "LOCAL_DEV.md",
                "content": "To run locally, open index.html in your browser.\n",
            },
        ]
        repair_ops = [
            {
                "operation": "write_file",
                "path": "game.js",
                "content": self.fixture["game_js_cli011_content"],
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            transport = FixtureAgentTransport()
            transport.set_responses([_response(repair_ops)])
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(goal)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace),
                transport=transport,
                max_turns=10,
                closure_reserve_turns=2,
            )
            controller.ingest_agent_response(_response(initial))
            for _ in range(35):
                state = controller.tick_high_autonomy_run()
                summary = state["high_autonomy_summary"]
                if summary.get("outcome") in FINAL_OUTCOMES:
                    break
            summary = state["high_autonomy_summary"]
            self.assertEqual(summary["outcome"], "completed")
            self.assertEqual(len(transport.written_instructions), 1)

    def test_stale_false_git_push_repair_restores_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            controller = ControlSurfaceController(session_dir=Path(tmp) / "sessions")
            session = controller._session
            gate = self.fixture["false_git_push_candidate"]
            session.queue.append(
                DecisionQueueItem(
                    action_id="false_git_push",
                    tool_or_command=gate["prose"],
                    action_type="git_push",
                    decision="REQUIRE_HUMAN_APPROVAL",
                    operational_admissibility_action=None,
                    risk_level="high",
                    required_approval=None,
                    missing_evidence=[],
                    execution_status="admitted_not_executed",
                    attestation_eligible=False,
                    lifecycle_status="admitted_not_executed",
                )
            )
            session.human_decisions.append(
                HumanDecisionRecord(
                    record_id="hd_1",
                    action_id="false_git_push",
                    actor="operator",
                    timestamp="2026-01-01T00:00:00Z",
                    decision_type="approve",
                    scope="high_autonomy_human_approved_local_only",
                    rationale="approved false constraint",
                    linked_decision_id=None,
                    linked_envelope_id=None,
                )
            )
            _repair_stale_negated_non_actions(session)
            self.assertEqual(
                count_genuine_human_interventions(
                    session.human_decisions, session.governance_records
                ),
                0,
            )

    def test_cli006_cli007_cli010_fixtures_still_present(self) -> None:
        for path in (FIXTURE_006, FIXTURE_007, FIXTURE_010, FIXTURE_011):
            self.assertTrue(path.exists(), msg=str(path))


if __name__ == "__main__":
    unittest.main()
