from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController
from admissible.execution.bounded_local_executor import execute_bounded_local_action
from admissible.execution.bounded_local_verification import (
    VerificationRequest,
    run_bounded_verification,
)
from admissible.governed_run import build_proposal_coverage_report, classify_optional_write_paths

FIXTURE_010 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_010_regression.json"
)


class TestAdmissibleProposalCoverage(unittest.TestCase):
    def test_readme_does_not_satisfy_local_dev_requirement(self) -> None:
        goal = json.loads(FIXTURE_010.read_text(encoding="utf-8"))["goal_text"]
        operations = [
            {"operation": "write_file", "path": "index.html", "content": "<html></html>\n"},
            {"operation": "write_file", "path": "style.css", "content": "body{}\n"},
            {"operation": "write_file", "path": "game.js", "content": "let score=0;\n"},
            {"operation": "write_file", "path": "README.md", "content": "# readme\n"},
        ]
        report = build_proposal_coverage_report(goal_text=goal, structured_operations=operations)
        self.assertFalse(report["coverage_complete"])
        self.assertEqual(report["missing_required_paths"], ["LOCAL_DEV.md"])
        self.assertEqual(report["additional_paths"], ["README.md"])
        self.assertCountEqual(
            report["proposed_required_paths"], ["index.html", "style.css", "game.js"]
        )

    def test_safe_partial_batch_executes_but_required_files_still_fails(self) -> None:
        goal = json.loads(FIXTURE_010.read_text(encoding="utf-8"))["goal_text"]
        operations = [
            {"operation": "write_file", "path": "index.html", "content": "<html></html>\n"},
            {"operation": "write_file", "path": "style.css", "content": "body{}\n"},
            {"operation": "write_file", "path": "game.js", "content": "let score=0;\n"},
            {"operation": "write_file", "path": "README.md", "content": "# readme\n"},
        ]
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            controller = ControlSurfaceController(session_dir=Path(tmp) / "sessions")
            controller.set_bounded_executor_workspace(str(workspace))
            for index, operation in enumerate(operations):
                execute_bounded_local_action(
                    workspace_path=workspace,
                    operations=[operation],
                    action_id=f"test_{index}",
                )
            result = run_bounded_verification(
                workspace_path=workspace,
                requests=[
                    VerificationRequest(
                        check_id="all_required_files_present",
                        target_paths=["index.html", "style.css", "game.js", "LOCAL_DEV.md"],
                        criterion_id="required_files",
                    )
                ],
            )
            self.assertEqual(result.overall_status, "fail")
            self.assertIn("LOCAL_DEV.md", result.results[0].message)

    def test_optional_polish_classifies_unmatched_writes(self) -> None:
        goal = json.loads(FIXTURE_010.read_text(encoding="utf-8"))["goal_text"]
        operations = [
            {"operation": "write_file", "path": "index.html", "content": "<html></html>\n"},
            {"operation": "write_file", "path": "README.md", "content": "# readme\n"},
        ]
        report = build_proposal_coverage_report(
            goal_text=goal,
            structured_operations=operations,
            avoid_optional_polish=True,
        )
        classified = classify_optional_write_paths(report)
        self.assertEqual(classified.get("README.md"), "deferred_optional")

    def test_coverage_persisted_on_ingest(self) -> None:
        goal = json.loads(FIXTURE_010.read_text(encoding="utf-8"))["goal_text"]
        response = (
            "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
            + json.dumps({"operation": "write_file", "path": "README.md", "content": "# x\n"})
            + "\n```"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal(goal)
            controller.start_high_autonomy_run(
                workspace_path=str(workspace),
                transport=FixtureAgentTransport(),
                max_turns=4,
            )
            controller.ingest_agent_response(response)
            report = (controller._session.high_autonomy_run or {}).get(
                "last_proposal_coverage_report"
            )
            self.assertIsNotNone(report)
            self.assertIn("LOCAL_DEV.md", report["missing_required_paths"])


if __name__ == "__main__":
    unittest.main()
