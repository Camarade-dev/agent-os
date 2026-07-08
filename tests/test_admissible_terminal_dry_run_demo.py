"""Tests for admissible.runner.terminal_dry_run_demo (Terminal Agent Dry-Run Demo v0)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.harness.viewer import render_trace_html
from admissible.runner.terminal_dry_run_demo import (
    TERMINAL_DRY_RUN_CLAIM_BOUNDARY,
    TERMINAL_DRY_RUN_DECISION_SYSTEM,
    TERMINAL_DRY_RUN_SOURCE_SYSTEM,
    build_terminal_dry_run_trace,
    load_terminal_dry_run_pack,
    main,
    write_terminal_dry_run_trace_and_html,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_PACK_PATH = REPO_ROOT / "benchmark" / "terminal_agent_dry_run" / "demo-pack.json"


class TestTerminalDryRunPack(unittest.TestCase):
    def test_loads_valid_demo_pack(self) -> None:
        demo_pack = load_terminal_dry_run_pack(DEMO_PACK_PATH)
        self.assertEqual(demo_pack["claim_boundary"], TERMINAL_DRY_RUN_CLAIM_BOUNDARY)
        self.assertEqual(len(demo_pack["selected_cases"]), 3)
        self.assertEqual(demo_pack["source_system"], TERMINAL_DRY_RUN_SOURCE_SYSTEM)

    def test_rejects_wrong_claim_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_path = Path(tmpdir) / "bad-pack.json"
            bad_path.write_text(
                json.dumps(
                    {
                        "claim_boundary": "wrong",
                        "selected_cases": [{}, {}, {}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_terminal_dry_run_pack(bad_path)


class TestTerminalDryRunTrace(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = build_terminal_dry_run_trace(demo_pack_path=DEMO_PACK_PATH)

    def test_has_three_cases(self) -> None:
        self.assertEqual(self.trace["case_set"]["case_count"], 3)
        self.assertEqual(len(self.trace["case_traces"]), 3)

    def test_claim_boundary_and_metadata(self) -> None:
        self.assertEqual(self.trace["claim_boundary"], TERMINAL_DRY_RUN_CLAIM_BOUNDARY)
        metadata = self.trace["metadata"]
        self.assertEqual(metadata["demo_kind"], "terminal_agent_dry_run_v0")
        self.assertEqual(metadata["source_system"], TERMINAL_DRY_RUN_SOURCE_SYSTEM)
        self.assertEqual(metadata["decision_system"], TERMINAL_DRY_RUN_DECISION_SYSTEM)
        self.assertFalse(metadata["side_effect_executed"])

    def test_expected_decisions(self) -> None:
        decisions = [
            case["decisions"][TERMINAL_DRY_RUN_DECISION_SYSTEM]["decision"]
            for case in self.trace["case_traces"]
        ]
        self.assertEqual(
            decisions,
            ["REQUIRE_HUMAN_APPROVAL", "REQUIRE_HUMAN_APPROVAL", "ALLOW_WITH_LIMITS"],
        )

    def test_each_case_has_raw_terminal_output(self) -> None:
        for case_trace in self.trace["case_traces"]:
            terminal = case_trace["terminal_agent"]
            self.assertEqual(terminal["source_system"], TERMINAL_DRY_RUN_SOURCE_SYSTEM)
            self.assertFalse(terminal["side_effect_executed"])
            self.assertIn("Proposed tool call", terminal["raw_output"])
            self.assertIn("dry-run", terminal["raw_output"].lower())

    def test_all_scores_correct(self) -> None:
        for case_trace in self.trace["case_traces"]:
            score = case_trace["scores"][TERMINAL_DRY_RUN_DECISION_SYSTEM]
            self.assertTrue(score["correct"])

    def test_html_renders_dry_run_claims(self) -> None:
        html = render_trace_html(self.trace)
        self.assertIn(TERMINAL_DRY_RUN_CLAIM_BOUNDARY, html)
        self.assertIn("No side effect executed", html)
        self.assertIn("Raw terminal-agent output", html)
        self.assertIn("Terminal Agent Dry-Run Trace", html)
        self.assertIn("deploy.production", html)
        self.assertIn("gmail.send", html)
        self.assertIn("drive.delete", html)

    def test_write_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_out = Path(tmpdir) / "trace.json"
            html_out = Path(tmpdir) / "trace.html"
            trace = write_terminal_dry_run_trace_and_html(
                demo_pack_path=DEMO_PACK_PATH,
                trace_out=trace_out,
                html_out=html_out,
            )
            self.assertTrue(trace_out.is_file())
            self.assertTrue(html_out.is_file())
            loaded = json.loads(trace_out.read_text(encoding="utf-8"))
            self.assertEqual(loaded["trace_id"], trace["trace_id"])


class TestTerminalDryRunCli(unittest.TestCase):
    def test_main_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            trace_out = Path(tmpdir) / "trace.json"
            html_out = Path(tmpdir) / "trace.html"
            exit_code = main(
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
            self.assertTrue(html_out.is_file())


if __name__ == "__main__":
    unittest.main()
