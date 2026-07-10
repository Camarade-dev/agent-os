from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import ControlSurfaceController
from admissible.governed_run import (
    DEFAULT_OUTCOME_IN_PROGRESS,
    migrate_high_autonomy_projection,
    migrate_session_projection_fields,
)


class TestAdmissibleNonNullRunProjection(unittest.TestCase):
    def test_migrate_null_legacy_fields_to_canonical_defaults(self) -> None:
        legacy = {
            "high_autonomy_run": {
                "outcome": None,
                "pending_useful_operation_count": None,
                "active_blocked_count": None,
                "blocking_reason": None,
                "verification_readiness": None,
                "next_action": None,
                "active": True,
            }
        }
        migrated = migrate_session_projection_fields(legacy)
        ha = migrated["high_autonomy_run"]
        self.assertEqual(ha["outcome"], DEFAULT_OUTCOME_IN_PROGRESS)
        self.assertEqual(ha["pending_useful_operation_count"], 0)
        self.assertEqual(ha["active_blocked_count"], 0)
        self.assertEqual(ha["blocking_reason"], "")
        self.assertEqual(ha["verification_readiness"], "not_run")
        self.assertIsNotNone(ha["next_action"])

    def test_high_autonomy_summary_never_serializes_null_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal("Projection defaults test")
            controller.start_high_autonomy_run(
                workspace_path=str(workspace),
                max_turns=4,
            )
            summary = controller.state_view()["high_autonomy_summary"]
            self.assertEqual(summary["outcome"], DEFAULT_OUTCOME_IN_PROGRESS)
            self.assertIsInstance(summary["pending_useful_operation_count"], int)
            self.assertIsInstance(summary["active_blocked_count"], int)
            self.assertIsNotNone(summary["blocking_reason"])

    def test_cli010_fixture_null_fields_migrate(self) -> None:
        fixture = json.loads(
            (
                Path(__file__).resolve().parent
                / "fixtures"
                / "admissible"
                / "pixel_wanderer_cli_010_regression.json"
            ).read_text(encoding="utf-8")
        )
        before = fixture["final_state_before_fix"]
        migrated = migrate_high_autonomy_projection(
            {
                "outcome": before["outcome"],
                "pending_useful_operation_count": before["pending_useful_operation_count"],
                "active_blocked_count": before["active_blocked_count"],
                "blocking_reason": before["blocking_reason"],
            }
        )
        self.assertEqual(migrated["outcome"], DEFAULT_OUTCOME_IN_PROGRESS)
        self.assertEqual(migrated["pending_useful_operation_count"], 0)
        self.assertEqual(migrated["active_blocked_count"], 0)


if __name__ == "__main__":
    unittest.main()
