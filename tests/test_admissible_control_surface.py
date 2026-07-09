"""Tests for the Admissible Control Surface v0.

Covers admissible.control_surface (pure session/decision model),
admissible.runner.control_surface (stdlib HTTP adapter), and the
control_surface.html harness content.
"""

from __future__ import annotations

import json
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from admissible.admitted_execution import AdmittedExecutionValidationError
from admissible.control_surface import (
    AUTONOMY_LEVEL_ORDER,
    AUTONOMY_PROFILES,
    AutonomyLevel,
    ControlSession,
    ControlSurfaceController,
    DecisionQueueItem,
    InvalidSessionFileError,
    SAMPLE_SLITHER_PROMPT,
    available_human_actions,
)
from admissible.run_loop import LIFECYCLE_RESOLVED_GATE, queue_item_needs_attention

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_TRACE_PATH = (
    REPO_ROOT / "benchmark" / "reports" / "admissible_cursor_admitted_execution_truth_console_trace.json"
)
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"

EXPECTED_AUTONOMY_LEVELS = (
    "L0_OBSERVE_ONLY",
    "L1_PROPOSE_ONLY",
    "L2_LOCAL_BATCH_APPROVAL",
    "L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS",
    "L4_HIGH_AUTONOMY_HARD_GATES",
)


def _queue_item(
    *,
    decision: str,
    execution_status: str = "proposed_only",
    attestation_eligible: bool = False,
) -> DecisionQueueItem:
    return DecisionQueueItem(
        action_id="synthetic_001",
        tool_or_command="do a thing",
        action_type="local_code_change",
        decision=decision,
        operational_admissibility_action="execute",
        risk_level="local",
        required_approval="none",
        missing_evidence=[],
        execution_status=execution_status,
        attestation_eligible=attestation_eligible,
    )


class TestAutonomyLevels(unittest.TestCase):
    def test_stable_level_names_and_order(self) -> None:
        self.assertEqual(AUTONOMY_LEVEL_ORDER, EXPECTED_AUTONOMY_LEVELS)
        self.assertEqual(tuple(level.value for level in AutonomyLevel), EXPECTED_AUTONOMY_LEVELS)

    def test_every_level_has_a_profile(self) -> None:
        for level in AUTONOMY_LEVEL_ORDER:
            profile = AUTONOMY_PROFILES[level]
            self.assertEqual(profile.level, level)
            self.assertTrue(profile.label)
            self.assertTrue(profile.description)
            self.assertTrue(profile.default_stopping_points)

    def test_every_level_has_a_short_operational_explanation(self) -> None:
        # UX requirement: "what this level allows / what still stops" in one
        # concise sentence, distinct from the longer `description`.
        for level in AUTONOMY_LEVEL_ORDER:
            profile = AUTONOMY_PROFILES[level]
            self.assertTrue(profile.operational_explanation)
            self.assertLess(len(profile.operational_explanation), 160)
            self.assertIn("operational_explanation", profile.to_dict())


class TestAvailableHumanActions(unittest.TestCase):
    def test_refuse_has_no_human_actions_at_any_level(self) -> None:
        item = _queue_item(decision="REFUSE")
        for level in AUTONOMY_LEVEL_ORDER:
            self.assertEqual(available_human_actions(item, level), [])

    def test_require_human_approval_unaffected_by_autonomy(self) -> None:
        item = _queue_item(decision="REQUIRE_HUMAN_APPROVAL")
        for level in AUTONOMY_LEVEL_ORDER:
            self.assertEqual(available_human_actions(item, level), ["approve", "refuse"])

    def test_request_more_evidence_unaffected_by_autonomy(self) -> None:
        item = _queue_item(decision="REQUEST_MORE_EVIDENCE")
        for level in AUTONOMY_LEVEL_ORDER:
            self.assertEqual(available_human_actions(item, level), ["request_evidence", "refuse"])

    def test_allow_with_limits_unaffected_by_autonomy(self) -> None:
        item = _queue_item(decision="ALLOW_WITH_LIMITS")
        for level in AUTONOMY_LEVEL_ORDER:
            self.assertEqual(available_human_actions(item, level), ["limit_scope", "refuse"])

    def test_allow_attestation_gated_by_autonomy_level(self) -> None:
        item = _queue_item(decision="ALLOW", attestation_eligible=True, execution_status="admitted_not_executed")
        self.assertEqual(available_human_actions(item, "L0_OBSERVE_ONLY"), ["refuse"])
        self.assertEqual(available_human_actions(item, "L1_PROPOSE_ONLY"), ["refuse"])
        self.assertEqual(available_human_actions(item, "L2_LOCAL_BATCH_APPROVAL"), ["refuse", "attest_executed"])
        self.assertEqual(
            available_human_actions(item, "L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS"), ["refuse", "attest_executed"]
        )
        self.assertEqual(available_human_actions(item, "L4_HIGH_AUTONOMY_HARD_GATES"), ["refuse", "attest_executed"])

    def test_allow_not_attestation_eligible_never_offers_attest(self) -> None:
        item = _queue_item(decision="ALLOW", attestation_eligible=False)
        for level in AUTONOMY_LEVEL_ORDER:
            self.assertEqual(available_human_actions(item, level), ["refuse"])

    def test_allow_already_executed_does_not_offer_attest_again(self) -> None:
        item = _queue_item(
            decision="ALLOW", attestation_eligible=True, execution_status="executed_after_admission"
        )
        for level in AUTONOMY_LEVEL_ORDER:
            self.assertEqual(available_human_actions(item, level), ["refuse"])


class TestControllerWithSampleSession(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = ControlSurfaceController(
            session_dir=Path(self._tmpdir.name) / "sessions",
            sample_trace_path=SAMPLE_TRACE_PATH,
        )

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_load_sample_session_populates_transcript_and_queue(self) -> None:
        state = self.controller.load_sample_session()
        # Regression: the sample admitted-execution trace has 31 actions.
        self.assertEqual(len(state["queue"]), 31)
        self.assertTrue(state["goal_intake"])
        self.assertTrue(state["plan_candidate"])
        self.assertTrue(state["plan_audit"])
        types = [entry["type"] for entry in state["transcript"]]
        self.assertIn("user_prompt", types)
        self.assertIn("goal_intake", types)
        self.assertIn("plan_proposal", types)
        self.assertIn("plan_audit", types)
        self.assertIn("admissible_message", types)

    def test_mission_summary_matches_queue_contents(self) -> None:
        state = self.controller.load_sample_session()
        summary = state["mission_summary"]
        self.assertEqual(summary["total_actions"], len(state["queue"]))
        self.assertEqual(summary["task_type"], state["goal_intake"]["task_type"])
        self.assertEqual(summary["recommended_autonomy_ceiling"], state["goal_intake"]["recommended_autonomy_ceiling"])
        self.assertEqual(summary["plan_audit_verdict"], state["plan_audit"]["verdict"])
        self.assertFalse(summary["side_effect_executed_by_admissible"])

        counted_allow = sum(1 for item in state["queue"] if item["decision"] == "ALLOW")
        self.assertEqual(summary["counts_by_decision"]["ALLOW"], counted_allow)

        expected_attention = sum(1 for item in state["queue"] if queue_item_needs_attention(item))
        self.assertEqual(summary["needs_attention_count"], expected_attention)
        self.assertGreater(summary["needs_attention_count"], 0)

    def test_needs_attention_lists_only_gated_decisions(self) -> None:
        state = self.controller.load_sample_session()
        attention = state["needs_attention"]
        attention_action_ids = {a["action_id"] for a in attention["actions"]}
        for item in state["queue"]:
            if queue_item_needs_attention(item):
                self.assertIn(item["action_id"], attention_action_ids)
            elif item["decision"] == "ALLOW":
                self.assertNotIn(item["action_id"], attention_action_ids)
        self.assertEqual(attention["missing_context"], state["goal_intake"]["missing_context"])
        self.assertEqual(attention["unresolved_plan_gates"], state["plan_audit"]["required_gates"])

    def test_needs_attention_buckets_are_populated_for_sample_session(self) -> None:
        """Regression: the Needs Attention panel renders from the bucketed
        fields (evidence_needed/approval_needed/scope_limits_needed/...),
        not just the flat 'actions' list. If those buckets ever went empty
        while mission_summary/queue still reported gated actions, the panel
        would wrongly render "Nothing needs attention right now."."""
        state = self.controller.load_sample_session()
        summary = state["mission_summary"]
        attention = state["needs_attention"]

        self.assertEqual(summary["needs_attention_count"], 9)
        self.assertEqual(len(attention["actions"]), 9)

        bucket_action_count = (
            len(attention["evidence_needed"])
            + len(attention["approval_needed"])
            + len(attention["scope_limits_needed"])
        )
        self.assertEqual(bucket_action_count, 9)
        self.assertTrue(any(a["decision"] == "REQUEST_MORE_EVIDENCE" for a in attention["evidence_needed"]))

        # Mirrors the UI's renderNeedsAttention() "hasAnything" check.
        has_anything = bool(
            attention["evidence_needed"]
            or attention["approval_needed"]
            or attention["scope_limits_needed"]
            or attention["plan_clarifications"]
            or attention["ready_to_continue"]
        )
        self.assertTrue(has_anything)

    def test_mission_summary_and_needs_attention_excluded_from_canonical_export(self) -> None:
        # These are derived UI-only views (not part of the round-trippable
        # session state) -- session_dict()/export must not carry them.
        self.controller.load_sample_session()
        exported = self.controller.session_dict()
        self.assertNotIn("mission_summary", exported)
        self.assertNotIn("needs_attention", exported)
        self.assertNotIn("session_diagnostics", exported)
        self.assertNotIn("lifecycle_overview", exported)

    def test_state_view_exposes_session_diagnostics_and_lifecycle_overview(self) -> None:
        state = self.controller.load_sample_session()
        diag = state["session_diagnostics"]
        self.assertEqual(diag["session_file"], str(self.controller.session_file))
        self.assertFalse(diag["session_loaded_from_disk"])
        self.assertEqual(diag["session_id"], state["session_id"])
        self.assertEqual(diag["current_turn"], state["run_loop"]["current_turn"])
        self.assertIn("bridge_awaiting_response", diag)
        self.assertIn("evidence_record_count", diag)

        overview = state["lifecycle_overview"]
        self.assertEqual(
            len(overview["pending_human_decision"]),
            state["mission_summary"]["needs_attention_count"],
        )
        self.assertIsInstance(overview["resolved_plan_gates"], list)
        self.assertIsInstance(overview["admitted_not_executed"], list)
        self.assertIsInstance(overview["refused_closed"], list)

    def test_resolved_plan_gates_not_in_plan_clarifications(self) -> None:
        from admissible.runner.extraction_lab import load_fixture

        fixtures_dir = (
            REPO_ROOT
            / "benchmark"
            / "long_run_scenarios"
            / "cursor_slither_demo"
            / "fixtures"
            / "pasted_agent_responses"
        )
        self.controller.submit_goal(SAMPLE_SLITHER_PROMPT)
        self.controller.ingest_agent_response(load_fixture(fixtures_dir / "cursor_plan_gate_resolution_request.txt"))
        item = self.controller.state_view()["queue"][-1]
        updated = self.controller.decide(
            item["action_id"],
            {"decision_type": "approve", "scope": "local_workspace_only", "rationale": "ok"},
        )
        clarifications = updated["needs_attention"]["plan_clarifications"]
        self.assertFalse(any("Human-resolved plan gate:" in c for c in clarifications))
        self.assertTrue(updated["lifecycle_overview"]["resolved_plan_gates"])
        self.assertNotIn(
            item["action_id"],
            {a["action_id"] for a in updated["lifecycle_overview"]["pending_human_decision"]},
        )

    def test_bridge_awaiting_response_after_instruction_without_ingest(self) -> None:
        self.controller.submit_goal("Build a tiny local CLI rename tool.")
        self.controller.generate_next_instruction_packet()
        diag = self.controller.state_view()["session_diagnostics"]
        self.assertTrue(diag["bridge_awaiting_response"])
        self.assertIn(1, diag["bridge_awaiting_turns"])

    def test_submit_goal_runs_intake_and_plan_audit(self) -> None:
        state = self.controller.submit_goal("Build a small local CLI tool to rename files.")
        self.assertEqual(state["goal_intake"]["task_type"], "software_build")
        self.assertIn(state["plan_audit"]["verdict"], (
            "PLAN_OK_FOR_LOCAL_PROTOTYPE",
            "PLAN_NEEDS_CLARIFICATION",
            "PLAN_NEEDS_HUMAN_APPROVAL",
            "PLAN_BLOCKED",
        ))

    def test_human_decision_does_not_rewrite_admissible_decision(self) -> None:
        state = self.controller.load_sample_session()
        self.controller.set_autonomy(AutonomyLevel.L2_LOCAL_BATCH_APPROVAL.value)
        state = self.controller.state_view()

        item = next(
            i for i in state["queue"] if "attest_executed" in i["available_actions"]
        )
        original_decision = item["decision"]
        rationale = f"Manually verified: {item['tool_or_command']}"

        updated = self.controller.decide(
            item["action_id"],
            {"decision_type": "attest_executed", "rationale": rationale, "verification": rationale},
        )
        updated_item = next(i for i in updated["queue"] if i["action_id"] == item["action_id"])

        self.assertEqual(updated_item["decision"], original_decision)
        self.assertEqual(updated_item["execution_status"], "executed_after_admission")
        self.assertEqual(len(updated["human_decisions"]), 1)
        record = updated["human_decisions"][0]
        self.assertEqual(record["actor"], "human_operator")
        self.assertEqual(record["action_id"], item["action_id"])
        self.assertEqual(record["decision_type"], "attest_executed")
        self.assertIsNotNone(record["linked_decision_id"])

    def test_invalid_execution_attestation_is_rejected_and_does_not_mutate_state(self) -> None:
        state = self.controller.load_sample_session()
        self.controller.set_autonomy(AutonomyLevel.L2_LOCAL_BATCH_APPROVAL.value)
        state = self.controller.state_view()

        # REQUEST_MORE_EVIDENCE actions must never become executed_after_admission.
        item = next(i for i in state["queue"] if i["decision"] == "REQUEST_MORE_EVIDENCE")
        with self.assertRaises(ValueError):
            self.controller.decide(item["action_id"], {"decision_type": "attest_executed"})

        # An ALLOW action with evidence that doesn't trace to its tool/command
        # must also be rejected (admitted_execution traceability check).
        allow_item = next(
            i for i in state["queue"] if "attest_executed" in i["available_actions"]
        )
        with self.assertRaises(AdmittedExecutionValidationError):
            self.controller.decide(
                allow_item["action_id"],
                {"decision_type": "attest_executed", "rationale": "totally unrelated evidence text"},
            )

        # State must be unchanged after the rejected attempt.
        after = self.controller.state_view()
        after_item = next(i for i in after["queue"] if i["action_id"] == allow_item["action_id"])
        self.assertEqual(after_item["execution_status"], allow_item["execution_status"])
        self.assertEqual(len(after["human_decisions"]), 0)

    def test_unknown_decision_type_rejected(self) -> None:
        state = self.controller.load_sample_session()
        item = state["queue"][0]
        with self.assertRaises(ValueError):
            self.controller.decide(item["action_id"], {"decision_type": "not_a_real_decision"})

    def test_unknown_action_id_rejected(self) -> None:
        self.controller.load_sample_session()
        with self.assertRaises(ValueError):
            self.controller.decide("does_not_exist", {"decision_type": "refuse"})

    def test_autonomy_change_is_recorded_in_transcript(self) -> None:
        self.controller.load_sample_session()
        state = self.controller.set_autonomy(AutonomyLevel.L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS.value)
        self.assertEqual(state["autonomy_level"], "L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS")
        last = state["transcript"][-1]
        self.assertEqual(last["type"], "autonomy_change")

    def test_invalid_autonomy_level_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.controller.set_autonomy("L99_NOT_REAL")

    def test_reset_clears_session(self) -> None:
        self.controller.load_sample_session()
        state = self.controller.reset_session()
        self.assertEqual(state["queue"], [])
        self.assertEqual(state["transcript"], [])
        self.assertIsNone(state["goal_intake"])

    def test_export_import_round_trip_preserves_decisions(self) -> None:
        self.controller.load_sample_session()
        self.controller.set_autonomy(AutonomyLevel.L2_LOCAL_BATCH_APPROVAL.value)
        state = self.controller.state_view()
        item = next(i for i in state["queue"] if "attest_executed" in i["available_actions"])
        rationale = f"Manually verified: {item['tool_or_command']}"
        self.controller.decide(
            item["action_id"],
            {"decision_type": "attest_executed", "rationale": rationale, "verification": rationale},
        )

        exported = self.controller.session_dict()
        json.dumps(exported)  # must be plain-JSON serializable

        other = ControlSurfaceController(
            session_dir=Path(self._tmpdir.name) / "sessions2",
            sample_trace_path=SAMPLE_TRACE_PATH,
        )
        imported = other.import_session(exported)
        self.assertEqual(len(imported["queue"]), len(exported["queue"]))
        self.assertEqual(len(imported["human_decisions"]), 1)
        self.assertEqual(imported["session_id"], exported["session_id"])

    def test_import_rejects_wrong_schema_version(self) -> None:
        with self.assertRaises(ValueError):
            ControlSession.from_dict({"schema_version": "not_a_real_schema"})

    def test_missing_trace_falls_back_to_builder_fixtures_without_shell(self) -> None:
        controller = ControlSurfaceController(
            session_dir=Path(self._tmpdir.name) / "sessions3",
            sample_trace_path=Path(self._tmpdir.name) / "does_not_exist.json",
        )
        state = controller.load_sample_session()
        self.assertGreater(len(state["queue"]), 0)
        self.assertIn("builder-fixtures", state["source_trace_path"])


class TestSyntheticRequireApprovalAndRefuse(unittest.TestCase):
    """Uses a small synthetic trace (not the real sample) via the public load_trace API."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        trace = {
            "action_candidates": [
                {
                    "action_id": "synthetic_approval",
                    "tool_or_command": "publish release notes",
                    "action_type": "publish",
                    "execution_status": "proposed_only",
                    "envelope_id": "env_synthetic_approval",
                },
                {
                    "action_id": "synthetic_refuse",
                    "tool_or_command": "rm -rf /important",
                    "action_type": "destructive_command",
                    "execution_status": "proposed_only",
                    "envelope_id": "env_synthetic_refuse",
                },
            ],
            "decisions": [
                {
                    "action_id": "synthetic_approval",
                    "decision": "REQUIRE_HUMAN_APPROVAL",
                    "operational_admissibility_action": "request_approval",
                    "risk_level": "local",
                    "missing_evidence": [],
                    "required_approval": "explicit_scope_required",
                    "decision_id": "decision_synthetic_approval",
                    "envelope_id": "env_synthetic_approval",
                },
                {
                    "action_id": "synthetic_refuse",
                    "decision": "REFUSE",
                    "operational_admissibility_action": "block",
                    "risk_level": "high",
                    "missing_evidence": [],
                    "required_approval": "none",
                    "decision_id": "decision_synthetic_refuse",
                    "envelope_id": "env_synthetic_refuse",
                },
            ],
        }
        self.trace_path = Path(self._tmpdir.name) / "synthetic_trace.json"
        self.trace_path.write_text(json.dumps(trace), encoding="utf-8")
        self.controller = ControlSurfaceController(session_dir=Path(self._tmpdir.name) / "sessions")
        self.controller.load_trace(self.trace_path)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_approve_requires_explicit_scope(self) -> None:
        with self.assertRaises(ValueError):
            self.controller.decide("synthetic_approval", {"decision_type": "approve"})
        state = self.controller.decide(
            "synthetic_approval",
            {"decision_type": "approve", "scope": "local_workspace_only; read-only preview", "rationale": "ok"},
        )
        item = next(i for i in state["queue"] if i["action_id"] == "synthetic_approval")
        self.assertEqual(item["decision"], "REQUIRE_HUMAN_APPROVAL")
        record = state["human_decisions"][0]
        self.assertEqual(record["scope"], "local_workspace_only; read-only preview")

    def test_refuse_decision_has_no_available_human_actions(self) -> None:
        state = self.controller.state_view()
        item = next(i for i in state["queue"] if i["action_id"] == "synthetic_refuse")
        self.assertEqual(item["available_actions"], [])
        with self.assertRaises(ValueError):
            self.controller.decide("synthetic_refuse", {"decision_type": "approve"})
        with self.assertRaises(ValueError):
            self.controller.decide("synthetic_refuse", {"decision_type": "refuse"})


class TestSessionPersistenceParity(unittest.TestCase):
    """ADMISSIBLE_CONTROL_SURFACE_004_SESSION_PERSISTENCE_PARITY.

    HTTP Control Surface startup must resume persisted session.json the same
    way the CLI cursor_bridge build_controller does.
    """

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.session_dir = Path(self._tmpdir.name) / "sessions"
        self.sample_trace = SAMPLE_TRACE_PATH

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _persist_sample_session(self) -> tuple[str, int]:
        from admissible.runner.control_surface import build_controller as build_http_controller

        writer = build_http_controller(
            session_dir=self.session_dir,
            sample_trace_path=self.sample_trace,
            fresh_session=True,
        )
        state = writer.load_sample_session()
        session_id = state["session_id"]
        queue_len = len(state["queue"])
        self.assertGreater(queue_len, 0)
        return session_id, queue_len

    def test_http_build_controller_resumes_persisted_session(self) -> None:
        from admissible.runner.control_surface import build_controller as build_http_controller

        session_id, queue_len = self._persist_sample_session()
        resumed = build_http_controller(session_dir=self.session_dir, sample_trace_path=self.sample_trace)
        state = resumed.state_view()
        self.assertEqual(state["session_id"], session_id)
        self.assertEqual(len(state["queue"]), queue_len)
        self.assertTrue(state["session_loaded_from_disk"])
        self.assertEqual(state["session_file"], str(self.session_dir / "session.json"))

    def test_http_startup_does_not_clobber_persisted_queue(self) -> None:
        from admissible.runner.control_surface import build_controller as build_http_controller

        session_id, queue_len = self._persist_sample_session()
        before = json.loads((self.session_dir / "session.json").read_text(encoding="utf-8"))

        build_http_controller(session_dir=self.session_dir, sample_trace_path=self.sample_trace)
        after = json.loads((self.session_dir / "session.json").read_text(encoding="utf-8"))

        self.assertEqual(after["session_id"], session_id)
        self.assertEqual(len(after["queue"]), queue_len)
        self.assertEqual(len(before["queue"]), queue_len)

    def test_cli_persisted_session_loads_via_http_build_controller(self) -> None:
        from admissible.runner.control_surface import build_controller as build_http_controller
        from admissible.runner.cursor_bridge import build_controller as build_cli_controller

        cli = build_cli_controller(session_dir=self.session_dir)
        cli.load_sample_session()
        session_id = cli.session_dict()["session_id"]

        http = build_http_controller(session_dir=self.session_dir, sample_trace_path=self.sample_trace)
        self.assertEqual(http.state_view()["session_id"], session_id)
        self.assertEqual(len(http.state_view()["queue"]), len(cli.state_view()["queue"]))

    def test_http_updated_session_reloads_via_cli_build_controller(self) -> None:
        from admissible.runner.control_surface import build_controller as build_http_controller
        from admissible.runner.cursor_bridge import build_controller as build_cli_controller

        http = build_http_controller(
            session_dir=self.session_dir,
            sample_trace_path=self.sample_trace,
            fresh_session=True,
        )
        http.set_autonomy("L2_LOCAL_BATCH_APPROVAL")
        http_session_id = http.session_dict()["session_id"]

        cli = build_cli_controller(session_dir=self.session_dir)
        self.assertEqual(cli.state_view()["session_id"], http_session_id)
        self.assertEqual(cli.state_view()["autonomy_level"], "L2_LOCAL_BATCH_APPROVAL")

    def test_invalid_session_file_raises_instead_of_silent_reset(self) -> None:
        from admissible.runner.control_surface import build_controller as build_http_controller

        self.session_dir.mkdir(parents=True)
        session_file = self.session_dir / "session.json"
        session_file.write_text("not valid json {{{", encoding="utf-8")
        with self.assertRaises(InvalidSessionFileError) as ctx:
            build_http_controller(session_dir=self.session_dir, sample_trace_path=self.sample_trace)
        self.assertIn("invalid session file", str(ctx.exception))
        self.assertEqual(ctx.exception.detail["session_file"], str(session_file))

    def test_fresh_session_skips_resume_when_file_exists(self) -> None:
        from admissible.runner.control_surface import build_controller as build_http_controller

        persisted_id, _ = self._persist_sample_session()
        fresh = build_http_controller(
            session_dir=self.session_dir,
            sample_trace_path=self.sample_trace,
            fresh_session=True,
        )
        state = fresh.state_view()
        self.assertNotEqual(state["session_id"], persisted_id)
        self.assertEqual(state["run_loop"]["current_turn"], 0)
        self.assertFalse(state["session_loaded_from_disk"])
        on_disk = json.loads((self.session_dir / "session.json").read_text(encoding="utf-8"))
        self.assertEqual(on_disk["session_id"], persisted_id)

    def test_state_view_exposes_session_path_diagnostics(self) -> None:
        from admissible.runner.control_surface import build_controller as build_http_controller

        self._persist_sample_session()
        controller = build_http_controller(session_dir=self.session_dir, sample_trace_path=self.sample_trace)
        state = controller.state_view()
        self.assertEqual(state["session_file"], str(self.session_dir / "session.json"))
        self.assertTrue(state["session_loaded_from_disk"])

    def test_resumed_session_preserves_derived_lifecycle_and_plan_gates(self) -> None:
        from admissible.runner.control_surface import build_controller as build_http_controller
        from admissible.runner.extraction_lab import load_fixture

        fixtures_dir = (
            REPO_ROOT
            / "benchmark"
            / "long_run_scenarios"
            / "cursor_slither_demo"
            / "fixtures"
            / "pasted_agent_responses"
        )
        plan_gate_fixture = fixtures_dir / "cursor_plan_gate_resolution_request.txt"
        slither_prompt = (
            "Build a small browser-based Slither-like game with a moving snake, "
            "collectible food, growth, collision handling, score display, restart "
            "behavior, and simple visual polish. Keep it local-only. Do not deploy. "
            "Ask before installing dependencies or deleting existing files."
        )

        writer = build_http_controller(session_dir=self.session_dir, sample_trace_path=self.sample_trace)
        writer.submit_goal(slither_prompt)
        writer.ingest_agent_response(load_fixture(plan_gate_fixture))
        item = writer.state_view()["queue"][-1]
        writer.decide(
            item["action_id"],
            {"decision_type": "approve", "scope": "local_workspace_only", "rationale": "ok"},
        )
        exported = writer.session_dict()

        resumed = build_http_controller(session_dir=self.session_dir, sample_trace_path=self.sample_trace)
        state = resumed.state_view()
        self.assertEqual(
            len(state["run_loop"]["derived_lifecycle_resolutions"]),
            len(exported["run_loop"]["derived_lifecycle_resolutions"]),
        )
        self.assertEqual(
            len(state["run_loop"]["resolved_plan_gates"]),
            len(exported["run_loop"]["resolved_plan_gates"]),
        )
        reloaded_item = next(i for i in state["queue"] if i["action_id"] == item["action_id"])
        self.assertEqual(reloaded_item["lifecycle_status"], LIFECYCLE_RESOLVED_GATE)

    def test_resumed_session_preserves_bridge_blocked_ingest_diagnostics(self) -> None:
        from admissible.runner.control_surface import build_controller as build_http_controller
        from admissible.runner.cursor_bridge import (
            DuplicateResponseError,
            ingest_response_file_with_controller,
            write_next_instruction_with_controller,
        )

        raw_response = (
            "User: Please add a helper dependency.\n\n"
            "Proposed command:\n"
            "    npm install left-pad\n"
        )
        workspace = Path(self._tmpdir.name) / "workspace"
        workspace.mkdir()

        writer = build_http_controller(session_dir=self.session_dir, sample_trace_path=self.sample_trace)
        # Bridge write is goal-first (ADMISSIBLE_UX_014); a packet only exists
        # once a goal has been submitted.
        writer.submit_goal("Build a tiny local-only page. Local only. Do not deploy.")
        write_next_instruction_with_controller(writer, workspace)
        (workspace / ".admissible" / "agent-response.md").write_text(raw_response, encoding="utf-8")
        ingest_response_file_with_controller(writer, workspace)
        with self.assertRaises(DuplicateResponseError):
            ingest_response_file_with_controller(writer, workspace)

        resumed = build_http_controller(session_dir=self.session_dir, sample_trace_path=self.sample_trace)
        blocked = [
            e for e in resumed.session_dict()["transcript"] if e["type"] == "bridge_ingest_blocked"
        ]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["payload"]["reason"], "duplicate_response")


class TestControlSurfaceHttpServer(unittest.TestCase):
    """End-to-end smoke test over the real stdlib HTTP server (ephemeral port)."""

    @classmethod
    def setUpClass(cls) -> None:
        from admissible.runner.control_surface import build_controller, make_server

        cls._tmpdir = tempfile.TemporaryDirectory()
        controller = build_controller(
            session_dir=Path(cls._tmpdir.name) / "sessions",
            sample_trace_path=SAMPLE_TRACE_PATH,
        )
        cls.server = make_server(controller, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls._tmpdir.cleanup()

    def _get(self, path: str):
        try:
            with urllib.request.urlopen(self.base_url + path) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _post(self, path: str, body: dict):
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_root_serves_html(self) -> None:
        with urllib.request.urlopen(self.base_url + "/") as response:
            self.assertEqual(response.status, 200)
            body = response.read().decode("utf-8")
            self.assertIn("Admissible Control Surface", body)

    def test_session_lifecycle_over_http(self) -> None:
        status, state = self._post("/api/session/load_sample", {})
        self.assertEqual(status, 200)
        self.assertEqual(len(state["queue"]), 31)
        self.assertEqual(state["mission_summary"]["total_actions"], 31)
        self.assertGreater(state["mission_summary"]["needs_attention_count"], 0)
        self.assertTrue(state["needs_attention"]["actions"])

        status, state = self._post("/api/session/autonomy", {"level": "L2_LOCAL_BATCH_APPROVAL"})
        self.assertEqual(status, 200)
        self.assertEqual(state["autonomy_level"], "L2_LOCAL_BATCH_APPROVAL")

        item = next(i for i in state["queue"] if "attest_executed" in i["available_actions"])
        rationale = f"Manually verified: {item['tool_or_command']}"
        status, state = self._post(
            f"/api/queue/{item['action_id']}/decide",
            {"decision_type": "attest_executed", "rationale": rationale, "verification": rationale},
        )
        self.assertEqual(status, 200)
        updated_item = next(i for i in state["queue"] if i["action_id"] == item["action_id"])
        self.assertEqual(updated_item["execution_status"], "executed_after_admission")

        status, error_body = self._post(f"/api/queue/{item['action_id']}/decide", {"decision_type": "attest_executed"})
        self.assertEqual(status, 400)
        self.assertIn("error", error_body)

        status, exported = self._get("/api/session/export")
        self.assertEqual(status, 200)
        self.assertIn("run_envelopes", exported)

    def test_unknown_route_is_404(self) -> None:
        status, body = self._get("/api/does-not-exist")
        self.assertEqual(status, 404)
        self.assertIn("error", body)


class TestControlSurfaceHtmlContent(unittest.TestCase):
    def setUp(self) -> None:
        raw = HTML_PATH.read_text(encoding="utf-8")
        self.raw = raw
        self.normalized = re.sub(r"\s+", " ", raw)

    def test_autonomy_selector_present(self) -> None:
        self.assertIn('id="autonomy-select"', self.raw)

    def test_goal_intake_panel_present(self) -> None:
        self.assertIn('id="goal-intake-panel"', self.raw)
        self.assertIn("Goal Intake", self.raw)

    def test_plan_audit_panel_present(self) -> None:
        self.assertIn('id="plan-audit-panel"', self.raw)
        self.assertIn("Plan", self.raw)
        self.assertIn("Audit", self.raw)

    def test_admissible_queue_panel_present(self) -> None:
        self.assertIn('id="admissible-queue-panel"', self.raw)

    def test_decision_records_panel_present(self) -> None:
        self.assertIn('id="decision-records-panel"', self.raw)

    def test_mission_summary_panel_present(self) -> None:
        self.assertIn('id="mission-summary-panel"', self.raw)
        self.assertIn("Mission Summary", self.raw)

    def test_needs_attention_panel_present(self) -> None:
        self.assertIn('id="needs-attention-panel"', self.raw)
        self.assertIn("Supervised Run State", self.raw)

    def test_session_diagnostics_panel_present(self) -> None:
        self.assertIn('id="session-diagnostics-panel"', self.raw)
        self.assertIn("Session Diagnostics", self.raw)
        self.assertIn("renderSessionDiagnostics", self.raw)
        self.assertIn("session_diagnostics", self.raw)

    def test_no_execution_banner_visible_without_collapsing(self) -> None:
        self.assertIn('id="no-execution-banner"', self.raw)
        banner_start = self.raw.index('id="no-execution-banner"')
        banner_region = self.raw[banner_start : banner_start + 400]
        self.assertIn("does not execute side effects", banner_region)
        self.assertNotIn("<details", banner_region)

    def test_lifecycle_buckets_rendered_in_supervised_run_state(self) -> None:
        for label in (
            "Needs attention — pending human decision",
            "Resolved plan gates — closed context",
            "Admitted, not executed",
            "Refused / closed",
            "Evidence supplied — still blocked",
            "Evidence satisfied — pending human decision",
        ):
            self.assertIn(label, self.raw)

    def test_bridge_blocked_banner_present(self) -> None:
        self.assertIn('id="bridge-blocked-banner"', self.raw)
        self.assertIn("renderBridgeBlockedBanner", self.raw)
        self.assertIn("duplicate_response", self.raw)

    def test_resolved_gates_not_rendered_as_unresolved_blockers(self) -> None:
        self.assertIn("resolvedGateRows", self.raw)
        self.assertIn('startsWith("Human-resolved plan gate:")', self.raw)

    def test_selected_action_panel_present(self) -> None:
        self.assertIn('id="selected-action-panel"', self.raw)
        self.assertIn("Selected Action", self.raw)

    def test_queue_has_no_per_row_decision_form(self) -> None:
        # UX requirement: one decision form at a time, in the Selected
        # Action panel -- never one per row in the action queue table.
        self.assertEqual(self.raw.count('<form class="decide-form"'), 1)
        self.assertIn("select-action-btn", self.raw)

    def test_truth_boundary_is_collapsible_but_not_removed(self) -> None:
        self.assertIn('id="truth-boundary-details"', self.raw)
        # A <details> element wrapping the boundary text, not a removal of it.
        details_start = self.raw.index('id="truth-boundary-details"')
        details_region = self.raw[details_start : details_start + 2000]
        self.assertIn("<summary>", details_region)
        self.assertIn("No side effect executed by Admissible.", details_region)

    def test_transcript_present_but_not_first_screen_content(self) -> None:
        self.assertIn('id="transcript-log"', self.raw)
        # Mission Summary / Supervised Run State / Queue must come before the
        # transcript in document order (progressive disclosure).
        transcript_index = self.raw.index('id="transcript-log"')
        self.assertLess(self.raw.index('id="mission-summary-panel"'), transcript_index)
        self.assertLess(self.raw.index('id="needs-attention-panel"'), transcript_index)
        self.assertLess(self.raw.index('id="admissible-queue-panel"'), transcript_index)
        # Transcript is inside a collapsible "advanced" details block.
        self.assertIn('id="advanced-transcript-details"', self.raw)

    def test_autonomy_explanation_is_short_and_present(self) -> None:
        self.assertIn('id="autonomy-explanation"', self.raw)
        self.assertIn("operational_explanation", self.raw)

    def test_decision_records_compact_with_full_history_available(self) -> None:
        self.assertIn('id="decision-records-full-details"', self.raw)
        self.assertIn(".slice(-3)", self.raw)

    def test_empty_state_explains_frame_audit_admit(self) -> None:
        self.assertIn("Frame", self.raw)
        self.assertIn("Audit", self.raw)
        self.assertIn("Admit", self.raw)

    def test_all_decision_controls_present(self) -> None:
        for decision_type in ("approve", "request_evidence", "refuse", "limit_scope", "attest_executed"):
            self.assertIn(decision_type, self.raw)

    def test_top_controls_present(self) -> None:
        self.assertIn('id="btn-export"', self.raw)
        self.assertIn('id="btn-reset"', self.raw)
        self.assertIn('id="import-file"', self.raw)
        self.assertIn('id="examples-drawer"', self.raw)
        self.assertIn('id="btn-load-sample"', self.raw)

    def test_truth_boundary_language_present(self) -> None:
        self.assertIn("No side effect executed by Admissible.", self.normalized)
        self.assertIn("does not execute shell commands", self.normalized)
        self.assertIn(
            "does not call Cursor, Claude Code, Codex, Gemini, OpenAI, or any network provider",
            self.normalized,
        )
        self.assertIn("no automatic executor", self.normalized.lower())

    def test_no_provider_network_calls_in_markup_or_script(self) -> None:
        # Only same-origin, relative fetch() calls are allowed.
        for match in re.finditer(r"fetch\(([^)]*)\)", self.raw):
            arg = match.group(1)
            self.assertTrue(
                "/api/" in arg or "url" in arg,
                f"unexpected fetch() call target: {arg!r}",
            )
        forbidden_hosts = ("openai.com", "anthropic.com", "cursor.sh", "googleapis.com")
        for host in forbidden_hosts:
            self.assertNotIn(host, self.raw)


class TestControlSurfaceNoForbiddenExecution(unittest.TestCase):
    """Static-source checks backing the NO_EXECUTOR / NO_AGENT_OS_IMPORT diagnostics."""

    _MODULE_PATHS = (
        "admissible/goal_intake.py",
        "admissible/plan_audit.py",
        "admissible/control_surface.py",
        "admissible/runner/control_surface.py",
        "admissible/run_loop.py",
    )

    def test_no_agent_os_import(self) -> None:
        # Matches the substring convention used by
        # test_admissible_admitted_execution.py: real import statements are
        # forbidden, but docstrings documenting the boundary (e.g. "Does not
        # import `agent_os`.") are expected and must not trip this check.
        # tests/test_admissible_boundary.py separately enforces this via AST
        # for every file under admissible/, including these.
        for rel_path in self._MODULE_PATHS:
            source = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
            self.assertNotIn("import agent_os", source, f"{rel_path} unexpectedly imports agent_os")
            self.assertNotIn("from agent_os", source, f"{rel_path} unexpectedly imports from agent_os")

    def test_no_subprocess_or_shell_execution(self) -> None:
        forbidden_tokens = ("import subprocess", "os.system(", "os.popen(", " eval(", " exec(")
        for rel_path in self._MODULE_PATHS:
            source = (REPO_ROOT / rel_path).read_text(encoding="utf-8")
            for token in forbidden_tokens:
                self.assertNotIn(token, source, f"{rel_path} unexpectedly contains {token!r}")

    def test_no_network_provider_sdk_imports(self) -> None:
        forbidden_tokens = ("import openai", "import anthropic", "google.generativeai", "requests.post", "import httpx")
        for rel_path in self._MODULE_PATHS:
            source = (REPO_ROOT / rel_path).read_text(encoding="utf-8").lower()
            for token in forbidden_tokens:
                self.assertNotIn(token, source, f"{rel_path} unexpectedly references {token!r}")


if __name__ == "__main__":
    unittest.main()
