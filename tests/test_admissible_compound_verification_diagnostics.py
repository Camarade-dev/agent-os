from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from admissible.execution.bounded_local_verification import (
    VerificationRequest,
    run_single_verification_check,
)


def _cli010_game_js() -> str:
    return (
        "(function(){'use strict'; var keys={};"
        "window.addEventListener('keydown',function(e){keys[e.key]=true;});"
        "function update(){"
        "if(keys.ArrowUp||keys.w||keys.W){}"
        "if(keys.ArrowDown||keys.s||keys.S){}"
        "if(keys.ArrowLeft||keys.a||keys.A){}"
        "if(keys.ArrowRight||keys.d||keys.D){}"
        "}"
        "let score=0; const collectibles=[]; function restart(){score=0;}"
        "document.addEventListener('keydown',e=>{if(e.key==='r'||e.key==='R')restart();});"
        "update();})();"
    )


class TestAdmissibleCompoundVerificationDiagnostics(unittest.TestCase):
    def test_cli010_game_js_wasd_present_under_property_access(self) -> None:
        """WASD in cli-010 game.js is present via keys.w style bindings (matcher-missed in live run)."""
        workspace = Path(tempfile.mkdtemp())
        (workspace / "game.js").write_text(_cli010_game_js(), encoding="utf-8")
        result = run_single_verification_check(
            workspace_path=workspace,
            request=VerificationRequest(
                check_id="game_controls_check",
                target_paths=["game.js"],
                criterion_id="game_controls",
            ),
        )
        self.assertEqual(result.status, "pass")
        payload = result.evidence_payload
        self.assertEqual(payload["subchecks"]["arrow_up"], "pass")
        self.assertEqual(payload["subchecks"]["w"], "pass")
        self.assertEqual(payload["subchecks"]["d"], "pass")
        self.assertEqual(payload["failed_subchecks"], {})

    def test_game_controls_exposes_arrow_and_wasd_groups(self) -> None:
        workspace = Path(tempfile.mkdtemp())
        (workspace / "game.js").write_text(
            "document.addEventListener('keydown', e => { if (e.key === 'ArrowUp') {} });",
            encoding="utf-8",
        )
        result = run_single_verification_check(
            workspace_path=workspace,
            request=VerificationRequest(
                check_id="game_controls_check",
                target_paths=["game.js"],
                criterion_id="game_controls",
            ),
        )
        self.assertEqual(result.status, "fail")
        payload = result.evidence_payload
        self.assertEqual(payload["subchecks"]["arrow_up"], "pass")
        self.assertEqual(payload["failed_subchecks"].get("wasd_controls"), "fail")
        self.assertEqual(payload["failed_subchecks"].get("arrow_controls"), "fail")
        self.assertIn("w", payload["missing"])

    def test_local_usage_distinguishes_file_missing_from_content_missing(self) -> None:
        workspace = Path(tempfile.mkdtemp())
        missing = run_single_verification_check(
            workspace_path=workspace,
            request=VerificationRequest(
                check_id="local_usage_check",
                target_paths=["LOCAL_DEV.md"],
                criterion_id="local_usage",
            ),
        )
        self.assertEqual(missing.status, "fail")
        self.assertEqual(missing.evidence_payload["failure_class"], "file_missing")

        (workspace / "LOCAL_DEV.md").write_text("placeholder\n", encoding="utf-8")
        content_missing = run_single_verification_check(
            workspace_path=workspace,
            request=VerificationRequest(
                check_id="local_usage_check",
                target_paths=["LOCAL_DEV.md"],
                criterion_id="local_usage",
            ),
        )
        self.assertEqual(content_missing.status, "fail")
        self.assertEqual(content_missing.evidence_payload["failure_class"], "content_missing")


if __name__ == "__main__":
    unittest.main()
