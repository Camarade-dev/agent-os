from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.execution.bounded_local_verification import (
    VerificationRequest,
    run_single_verification_check,
)

FIXTURE_011 = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "pixel_wanderer_cli_011_regression.json"
)


class TestAdmissibleRestartVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads(FIXTURE_011.read_text(encoding="utf-8"))

    def test_cli011_game_js_restart_present_under_bounded_subchecks(self) -> None:
        audit = self.fixture["game_restart_audit"]
        self.assertEqual(audit["classification"], "present_matcher_missed")
        workspace = Path(tempfile.mkdtemp())
        game_path = workspace / "game.js"
        game_path.write_text(self.fixture["game_js_cli011_content"], encoding="utf-8")
        result = run_single_verification_check(
            workspace_path=workspace,
            request=VerificationRequest(
                check_id="game_restart_check",
                target_paths=["game.js"],
                criterion_id="game_restart",
            ),
        )
        self.assertEqual(result.status, "pass")
        payload = result.evidence_payload
        for key in (
            "r_key_binding_present",
            "restart_handler_present",
            "player_state_reset_present",
            "score_reset_present",
            "collectible_or_game_state_reset_present",
        ):
            self.assertEqual(payload["subchecks"][key], "pass")

    def test_restart_diagnostics_expose_all_bounded_subchecks(self) -> None:
        workspace = Path(tempfile.mkdtemp())
        (workspace / "game.js").write_text("let score=0;\n", encoding="utf-8")
        result = run_single_verification_check(
            workspace_path=workspace,
            request=VerificationRequest(
                check_id="game_restart_check",
                target_paths=["game.js"],
                criterion_id="game_restart",
            ),
        )
        self.assertEqual(result.status, "fail")
        payload = result.evidence_payload
        self.assertIn("subchecks", payload)
        self.assertIn("failed_subchecks", payload)
        self.assertIn("repair_hint", payload)
        self.assertEqual(payload["path"], "game.js")

    def test_missing_restart_produces_targeted_repair_hint(self) -> None:
        workspace = Path(tempfile.mkdtemp())
        (workspace / "game.js").write_text(
            "let score=0; const collectibles=[]; function update(){}",
            encoding="utf-8",
        )
        result = run_single_verification_check(
            workspace_path=workspace,
            request=VerificationRequest(
                check_id="game_restart_check",
                target_paths=["game.js"],
                criterion_id="game_restart",
            ),
        )
        self.assertEqual(result.status, "fail")
        self.assertIn("game.js", result.evidence_payload.get("repair_hint") or "")


if __name__ == "__main__":
    unittest.main()
