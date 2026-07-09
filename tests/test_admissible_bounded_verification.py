"""Slice ADMISSIBLE_EXECUTION_025_BOUNDED_VERIFICATION_COMMANDS tests.

Proves explicit bounded verification after governed local writes:

    - allowlisted read-only checks only (no shell/npm/network/deploy)
    - verification evidence stored separately from write evidence
    - sha256 tampering and external references fail clearly
    - four-turn blocker/recovery demo passes verification after execution

Hard constraints: no provider calls, no arbitrary command execution.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.control_surface import ControlSurfaceController
from admissible.execution.bounded_local_verification import (
    ALLOWED_VERIFICATION_CHECKS,
    BoundedVerificationError,
    VerificationRequest,
    run_bounded_verification,
    run_single_verification_check,
    validate_verification_request,
)
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "admissible"
TURN_1_FIXTURE = "tiny_game_turn_1_agent_response.md"
TURN_2_FIXTURE = "tiny_game_turn_2_agent_response.md"
TURN_3_FIXTURE = "tiny_game_turn_3_blocked_agent_response.md"
TURN_4_FIXTURE = "tiny_game_turn_4_recovery_agent_response.md"

CANONICAL_GOAL_PROMPT = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)

_EXPECTED_CHECKS = (
    "files_exist",
    "files_non_empty",
    "sha256_matches_write_evidence",
    "html_local_asset_references",
    "no_external_references",
)


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("bounded verification demo must not spawn a subprocess")


class TestBoundedVerificationChecks(unittest.TestCase):
    """Unit-level checks for the allowlisted verification runner."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_rejects_arbitrary_command_strings(self) -> None:
        with self.assertRaises(BoundedVerificationError) as ctx:
            validate_verification_request(VerificationRequest("npm install"))
        self.assertEqual(ctx.exception.diagnostic, "unsupported_verification_check")

        with self.assertRaises(BoundedVerificationError):
            validate_verification_request(VerificationRequest("curl https://example.com"))

        with self.assertRaises(BoundedVerificationError):
            validate_verification_request(VerificationRequest("deploy production"))

    def test_allowlisted_checks_are_fixed(self) -> None:
        self.assertIn("files_exist", ALLOWED_VERIFICATION_CHECKS)
        self.assertIn("sha256_matches_write_evidence", ALLOWED_VERIFICATION_CHECKS)
        self.assertNotIn("run_shell_command", ALLOWED_VERIFICATION_CHECKS)

    def test_missing_file_check_fails_clearly(self) -> None:
        result = run_single_verification_check(
            workspace_path=self.workspace,
            request=VerificationRequest("files_exist", ["index.html"]),
        )
        self.assertEqual(result.status, "fail")
        self.assertIn("Missing expected files", result.message)
        self.assertEqual(result.check_id, "files_exist")

    def test_non_empty_check_fails_for_empty_file(self) -> None:
        target = self.workspace / "game.js"
        target.write_text("", encoding="utf-8")
        result = run_single_verification_check(
            workspace_path=self.workspace,
            request=VerificationRequest("files_non_empty", ["game.js"]),
        )
        self.assertEqual(result.status, "fail")
        self.assertIn("empty", result.message.lower())

    def test_external_reference_check_fails_for_cdn_url(self) -> None:
        (self.workspace / "index.html").write_text(
            '<script src="https://cdn.example.com/lib.js"></script>',
            encoding="utf-8",
        )
        (self.workspace / "style.css").write_text("body {}", encoding="utf-8")
        (self.workspace / "game.js").write_text("const x = 1;", encoding="utf-8")

        result = run_single_verification_check(
            workspace_path=self.workspace,
            request=VerificationRequest("no_external_references", ["index.html", "style.css", "game.js"]),
        )
        self.assertEqual(result.status, "fail")
        self.assertIn("external", result.message.lower())
        self.assertIn("index.html", result.evidence_payload["findings"])

    def test_html_local_asset_reference_check_fails_for_remote_script(self) -> None:
        (self.workspace / "index.html").write_text(
            '<script src="//cdn.example.com/app.js"></script>',
            encoding="utf-8",
        )
        result = run_single_verification_check(
            workspace_path=self.workspace,
            request=VerificationRequest("html_local_asset_references", ["index.html"]),
        )
        self.assertEqual(result.status, "fail")
        self.assertIn("Non-local", result.message)


class TestBoundedVerificationAfterRecoveryDemo(unittest.TestCase):
    """Verification passes after the four-turn blocker/recovery governed loop."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.turn_1_raw = load_fixture(FIXTURES_DIR / TURN_1_FIXTURE)
        self.turn_2_raw = load_fixture(FIXTURES_DIR / TURN_2_FIXTURE)
        self.turn_3_raw = load_fixture(FIXTURES_DIR / TURN_3_FIXTURE)
        self.turn_4_raw = load_fixture(FIXTURES_DIR / TURN_4_FIXTURE)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _run_four_turn_recovery_demo(self) -> dict:
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
            self.controller.generate_next_instruction_packet()
            self.controller.ingest_agent_response(self.turn_1_raw)
            self.controller.set_bounded_executor_workspace(self.workspace)
            self.controller.execute_bounded_local_batch({"workspace_path": str(self.workspace)})
            self.controller.generate_next_instruction_packet()
            self.controller.ingest_agent_response(self.turn_2_raw)
            self.controller.execute_bounded_local_batch({"workspace_path": str(self.workspace)})
            self.controller.generate_next_instruction_packet()
            self.controller.ingest_agent_response(self.turn_3_raw)
            self.controller.generate_next_instruction_packet()
            self.controller.ingest_agent_response(self.turn_4_raw)
            return self.controller.execute_bounded_local_batch(
                {"workspace_path": str(self.workspace)}
            )

    def test_verification_passes_after_four_turn_recovery_demo(self) -> None:
        final_state = self._run_four_turn_recovery_demo()
        self.assertEqual(final_state["run_timeline"]["evidence_count"], 8)

        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            verify_state = self.controller.verify_bounded_local_workspace(
                {"workspace_path": str(self.workspace), "profile": "tiny_game_demo"}
            )

        summary = verify_state["verification_summary"]
        self.assertEqual(summary["verification_count"], 1)
        self.assertEqual(summary["readiness"], "pass")
        self.assertEqual(summary["latest_overall_status"], "pass")

        result = verify_state["bounded_local_verification_result"]
        self.assertEqual(result["overall_status"], "pass")
        check_ids = [entry["check_id"] for entry in result["results"]]
        self.assertEqual(check_ids, list(_EXPECTED_CHECKS))
        self.assertTrue(all(entry["status"] == "pass" for entry in result["results"]))

        stored = verify_state["run_loop"]["verification_records"]
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]["overall_status"], "pass")
        self.assertEqual(verify_state["run_timeline"]["evidence_count"], 8)

    def test_sha256_match_check_catches_tampering_after_execution(self) -> None:
        self._run_four_turn_recovery_demo()
        game_js = self.workspace / "game.js"
        game_js.write_text(game_js.read_text(encoding="utf-8") + "\n// tampered\n", encoding="utf-8")

        evidence = run_bounded_verification(
            workspace_path=self.workspace,
            profile="tiny_game_demo",
            write_evidence_records=self.controller._session.run_loop.evidence_records,
        )
        sha_result = next(
            result for result in evidence.results if result.check_id == "sha256_matches_write_evidence"
        )
        self.assertEqual(sha_result.status, "fail")
        self.assertIn("mismatch", sha_result.message.lower())

        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            verify_state = self.controller.verify_bounded_local_workspace(
                {"workspace_path": str(self.workspace)}
            )
        self.assertEqual(verify_state["verification_summary"]["readiness"], "fail")
        failed = [
            entry
            for entry in verify_state["bounded_local_verification_result"]["results"]
            if entry["status"] == "fail"
        ]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["check_id"], "sha256_matches_write_evidence")

    def test_verification_does_not_add_write_evidence_records(self) -> None:
        self._run_four_turn_recovery_demo()
        write_count_before = len(self.controller._session.run_loop.evidence_records)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.verify_bounded_local_workspace({"workspace_path": str(self.workspace)})
        self.assertEqual(len(self.controller._session.run_loop.evidence_records), write_count_before)
        self.assertEqual(len(self.controller._session.run_loop.verification_records), 1)


if __name__ == "__main__":
    unittest.main()
