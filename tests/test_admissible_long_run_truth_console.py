"""Tests for Admissible Long-Run Truth Console v0."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.harness.truth_console import render_truth_console_html
from admissible.long_run_truth import (
    LONG_RUN_CLAIM_BOUNDARY,
    LONG_RUN_PROMPT,
    build_truth_trace,
    map_operational_admissibility_action,
)
from admissible.runner.long_run_truth_console import main, write_long_run_truth_console
from admissible.runner.terminal_dry_run_demo import (
    build_terminal_dry_run_trace,
    main as dry_run_main,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_PACK_PATH = REPO_ROOT / "benchmark" / "terminal_agent_dry_run" / "demo-pack.json"


class TestOperationalMapping(unittest.TestCase):
    def test_require_human_approval_maps_to_request_approval(self) -> None:
        self.assertEqual(
            map_operational_admissibility_action("REQUIRE_HUMAN_APPROVAL"),
            "request_approval",
        )

    def test_allow_with_limits_with_safer_step_maps_to_replace(self) -> None:
        self.assertEqual(
            map_operational_admissibility_action(
                "ALLOW_WITH_LIMITS",
                safer_next_step={"description": "Archive instead."},
            ),
            "replace_with_safer_step",
        )


class TestTruthTrace(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = build_truth_trace(
            demo_pack_path=str(DEMO_PACK_PATH),
            repo_root=str(REPO_ROOT),
        )

    def test_has_three_action_candidates(self) -> None:
        self.assertEqual(len(self.trace["action_candidates"]), 3)
        self.assertEqual(len(self.trace["agent_steps"]), 3)
        self.assertEqual(len(self.trace["decisions"]), 3)

    def test_long_run_prompt_and_claim_boundary(self) -> None:
        long_run = self.trace["long_run"]
        self.assertEqual(long_run["prompt"], LONG_RUN_PROMPT)
        self.assertEqual(long_run["claim_boundary"], LONG_RUN_CLAIM_BOUNDARY)
        self.assertIn("Cursor Composer 2.5", long_run["frontier_agent_label"])

    def test_expected_decisions_and_operational_actions(self) -> None:
        decisions = [d["decision"] for d in self.trace["decisions"]]
        operational = [d["operational_admissibility_action"] for d in self.trace["decisions"]]
        self.assertEqual(
            decisions,
            ["REQUIRE_HUMAN_APPROVAL", "REQUIRE_HUMAN_APPROVAL", "ALLOW_WITH_LIMITS"],
        )
        self.assertEqual(
            operational,
            ["request_approval", "request_approval", "replace_with_safer_step"],
        )

    def test_no_side_effects(self) -> None:
        self.assertFalse(self.trace["side_effect_executed"])
        for candidate in self.trace["action_candidates"]:
            self.assertEqual(candidate["execution_status"], "proposed_only")
        for event in self.trace["execution_log"]:
            self.assertFalse(event["side_effect_executed"])

    def test_raw_agent_output_present(self) -> None:
        for step in self.trace["agent_steps"]:
            self.assertEqual(step["source_trust"], "unverified_agent_output")
            self.assertIn("Proposed tool call", step["raw_output"])


class TestTruthConsoleHtml(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = build_truth_trace(
            demo_pack_path=str(DEMO_PACK_PATH),
            repo_root=str(REPO_ROOT),
        )
        self.html = render_truth_console_html(self.trace)

    def test_contains_required_truth_language(self) -> None:
        self.assertIn("Admissible Long-Run Truth Console", self.html)
        self.assertIn(LONG_RUN_PROMPT, self.html)
        self.assertIn(LONG_RUN_CLAIM_BOUNDARY, self.html)
        self.assertIn("No side effect executed", self.html)
        self.assertIn("Raw agent output is unverified", self.html)
        self.assertIn("Agent output is not authority", self.html)

    def test_contains_all_three_actions(self) -> None:
        self.assertIn("deploy.production", self.html)
        self.assertIn("gmail.send", self.html)
        self.assertIn("drive.delete", self.html)

    def test_contains_operational_and_admission_fields(self) -> None:
        self.assertIn("request_approval", self.html)
        self.assertIn("replace_with_safer_step", self.html)
        self.assertIn("REQUIRE_HUMAN_APPROVAL", self.html)
        self.assertIn("ALLOW_WITH_LIMITS", self.html)
        self.assertIn("Operational admissibility action", self.html)
        self.assertIn("Missing evidence", self.html)
        self.assertIn("Safer next step", self.html)

    def test_write_console_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            html_out = Path(tmpdir) / "console.html"
            trace_out = Path(tmpdir) / "trace.json"
            trace = write_long_run_truth_console(
                demo_pack_path=DEMO_PACK_PATH,
                html_out=html_out,
                trace_out=trace_out,
            )
            self.assertTrue(html_out.is_file())
            self.assertTrue(trace_out.is_file())
            loaded = json.loads(trace_out.read_text(encoding="utf-8"))
            self.assertEqual(loaded["long_run"]["run_id"], trace["long_run"]["run_id"])


class TestTruthConsoleCli(unittest.TestCase):
    def test_main_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            html_out = Path(tmpdir) / "console.html"
            trace_out = Path(tmpdir) / "trace.json"
            exit_code = main(
                [
                    "--demo-pack",
                    str(DEMO_PACK_PATH),
                    "--out",
                    str(html_out),
                    "--trace-out",
                    str(trace_out),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertTrue(html_out.is_file())


class TestTerminalDryRunStillWorks(unittest.TestCase):
    def test_dry_run_trace_unchanged(self) -> None:
        trace = build_terminal_dry_run_trace(demo_pack_path=DEMO_PACK_PATH)
        self.assertEqual(trace["case_set"]["case_count"], 3)

    def test_dry_run_cli_still_works(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_out = Path(tmpdir) / "trace.json"
            html_out = Path(tmpdir) / "trace.html"
            exit_code = dry_run_main(
                [
                    "--demo-pack",
                    str(DEMO_PACK_PATH),
                    "--trace-out",
                    str(trace_out),
                    "--html-out",
                    str(html_out),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertTrue(trace_out.is_file())


if __name__ == "__main__":
    unittest.main()
