"""Tests for the Admissible Supervised Run Loop v0.

Covers admissible.run_loop (pure packet/ingestion/evidence helpers),
the admissible.control_surface controller wiring (generate instruction,
ingest response, provide evidence), the new HTTP routes, and the
control_surface.html Run Loop / evidence-form additions.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from admissible.control_surface import AutonomyLevel, ControlSurfaceController
from admissible.run_loop import (
    LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION,
    LIFECYCLE_NEEDS_HUMAN_INPUT,
    NON_EXECUTION_BOUNDARIES,
    AgentInstructionPacket,
    generate_instruction_packet,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_TRACE_PATH = (
    REPO_ROOT / "benchmark" / "reports" / "admissible_cursor_admitted_execution_truth_console_trace.json"
)
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"

RAW_INSTALL_DEPENDENCY_RESPONSE = (
    "User: Please add a helper dependency.\n\n"
    "Proposed command:\n"
    "    npm install left-pad\n"
)

RAW_EDIT_FILE_RESPONSE = (
    "User: Add a comment to the header component.\n\n"
    "Proposed tool call:\n"
    '    edit_file({"path": "src/Header.tsx", "instructions": "add a comment"})\n'
)


def _make_controller(tmpdir: str, name: str = "sessions") -> ControlSurfaceController:
    return ControlSurfaceController(
        session_dir=Path(tmpdir) / name,
        sample_trace_path=SAMPLE_TRACE_PATH,
    )


class TestGenerateInstructionPacket(unittest.TestCase):
    """Pure function tests -- no controller/session involved."""

    def _packet(self, *, autonomy_level: str, **kwargs):
        base = dict(
            turn_number=1,
            autonomy_level=autonomy_level,
            goal_intake={"task_type": "software_build", "deliverable": "small tool"},
            plan_audit={"verdict": "PLAN_OK_FOR_LOCAL_PROTOTYPE", "required_gates": []},
            queue=[],
        )
        base.update(kwargs)
        return generate_instruction_packet(**base)

    def test_packet_contains_non_execution_boundaries(self) -> None:
        for level in (level.value for level in AutonomyLevel):
            packet = self._packet(autonomy_level=level)
            for boundary in NON_EXECUTION_BOUNDARIES:
                self.assertIn(boundary, packet.non_execution_boundaries)
                self.assertIn(boundary, packet.packet_text)

    def test_packet_text_never_authorizes_execution(self) -> None:
        packet = self._packet(autonomy_level=AutonomyLevel.L4_HIGH_AUTONOMY_HARD_GATES.value)
        self.assertIn("does not execute code", packet.packet_text)
        self.assertIn("Propose; do not execute.", packet.packet_text)

    def test_may_propose_varies_by_autonomy_but_hard_gates_are_constant(self) -> None:
        l0 = self._packet(autonomy_level=AutonomyLevel.L0_OBSERVE_ONLY.value)
        l4 = self._packet(autonomy_level=AutonomyLevel.L4_HIGH_AUTONOMY_HARD_GATES.value)

        self.assertNotEqual(l0.may_propose, l4.may_propose)
        self.assertIn("L0 is analysis/observation only", " ".join(l0.may_propose))

        # Hard-gate / must-not language is identical at every autonomy level.
        self.assertEqual(l0.non_execution_boundaries, l4.non_execution_boundaries)
        self.assertEqual(l0.must_not, l4.must_not)
        for text in (l0.packet_text, l4.packet_text):
            self.assertIn("REQUIRE_HUMAN_APPROVAL", text)
            self.assertIn("REQUEST_MORE_EVIDENCE", text)

    def test_response_format_guidance_present_and_constant_across_autonomy(self) -> None:
        l0 = self._packet(autonomy_level=AutonomyLevel.L0_OBSERVE_ONLY.value)
        l4 = self._packet(autonomy_level=AutonomyLevel.L4_HIGH_AUTONOMY_HARD_GATES.value)

        self.assertTrue(l0.response_format_guidance)
        self.assertEqual(l0.response_format_guidance, l4.response_format_guidance)

        for text in (l0.packet_text, l4.packet_text):
            self.assertIn("RESPONSE FORMAT", text)
            self.assertIn("action_gate_<id>", text)
            self.assertIn("Verdict class:", text)
            self.assertIn("Closes gates:", text)
            self.assertIn("Side effects if approved:", text)
            self.assertIn("Human decision required:", text)

    def test_agent_instruction_packet_from_dict_defaults_missing_response_format_guidance(self) -> None:
        # Backward compatibility: a packet persisted before this field
        # existed (e.g. the repo's own .admissible/control_surface_sessions
        # session.json) must still load, defaulting to an empty list rather
        # than raising.
        packet = self._packet(autonomy_level=AutonomyLevel.L1_PROPOSE_ONLY.value)
        old_shaped = packet.to_dict()
        del old_shaped["response_format_guidance"]

        reloaded = AgentInstructionPacket.from_dict(old_shaped)
        self.assertEqual(reloaded.response_format_guidance, [])
        self.assertEqual(reloaded.packet_id, packet.packet_id)

    def test_evidence_needed_reflects_gated_queue_items(self) -> None:
        queue = [
            {
                "action_id": "action_1",
                "decision": "REQUEST_MORE_EVIDENCE",
                "lifecycle_status": LIFECYCLE_NEEDS_HUMAN_INPUT,
                "missing_evidence": ["package_trust_review"],
            }
        ]
        packet = self._packet(autonomy_level=AutonomyLevel.L1_PROPOSE_ONLY.value, queue=queue)
        self.assertIn("action_1: package_trust_review", packet.evidence_needed)

    def test_no_evidence_needed_when_queue_empty(self) -> None:
        packet = self._packet(autonomy_level=AutonomyLevel.L1_PROPOSE_ONLY.value)
        self.assertEqual(packet.evidence_needed, ["None outstanding right now."])

    def test_open_gates_reflect_plan_audit_and_goal_intake(self) -> None:
        packet = self._packet(
            autonomy_level=AutonomyLevel.L1_PROPOSE_ONLY.value,
            goal_intake={
                "task_type": "software_build",
                "deliverable": "small tool",
                "missing_context": ["deployment boundary"],
                "clarifying_questions": ["Should this be local-only?"],
            },
            plan_audit={"verdict": "PLAN_NEEDS_CLARIFICATION", "required_gates": ["step_2"]},
        )
        joined = " | ".join(packet.open_gates_summary)
        self.assertIn("PLAN_NEEDS_CLARIFICATION", joined)
        self.assertIn("step_2", joined)
        self.assertIn("deployment boundary", joined)
        self.assertIn("Should this be local-only?", joined)


class TestControllerRunLoop(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _make_controller(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_generate_instruction_packet_advances_turn(self) -> None:
        self.controller.submit_goal("Build a small local CLI tool to rename files.")
        state = self.controller.generate_next_instruction_packet()
        self.assertEqual(state["run_loop"]["current_turn"], 1)
        self.assertEqual(len(state["run_loop"]["instruction_packets"]), 1)
        packet = state["run_loop"]["instruction_packets"][0]
        self.assertIn("TASK", packet["packet_text"])
        self.assertEqual(state["transcript"][-1]["type"], "instruction_packet_generated")

        state = self.controller.generate_next_instruction_packet()
        self.assertEqual(state["run_loop"]["current_turn"], 2)
        self.assertEqual(len(state["run_loop"]["instruction_packets"]), 2)

    def test_ingest_agent_response_creates_response_record_and_action_candidates(self) -> None:
        self.controller.submit_goal("Build a small local CLI tool to rename files.")
        state = self.controller.ingest_agent_response(RAW_INSTALL_DEPENDENCY_RESPONSE)

        self.assertEqual(len(state["run_loop"]["response_records"]), 1)
        record = state["run_loop"]["response_records"][0]
        self.assertEqual(record["raw_text"], RAW_INSTALL_DEPENDENCY_RESPONSE)
        self.assertEqual(record["source_trust"], "unverified_agent_output")
        self.assertEqual(record["actor"], "external_frontier_agent")
        self.assertEqual(len(record["action_ids"]), 1)

        self.assertEqual(len(state["queue"]), 1)
        item = state["queue"][0]
        self.assertEqual(item["action_id"], record["action_ids"][0])
        self.assertEqual(item["action_type"], "install_dependency")
        self.assertEqual(item["decision"], "REQUEST_MORE_EVIDENCE")
        self.assertEqual(state["transcript"][-1]["type"], "agent_response_ingested")

    def test_ingest_agent_response_rejects_empty_text(self) -> None:
        with self.assertRaises(ValueError):
            self.controller.ingest_agent_response("   ")

    def test_ingest_edit_file_response_produces_allow_action(self) -> None:
        state = self.controller.ingest_agent_response(RAW_EDIT_FILE_RESPONSE)
        item = state["queue"][0]
        self.assertEqual(item["action_type"], "edit_file")
        self.assertEqual(item["decision"], "ALLOW")

    def test_provide_evidence_links_action_decision_and_envelope(self) -> None:
        state = self.controller.ingest_agent_response(RAW_INSTALL_DEPENDENCY_RESPONSE)
        item = state["queue"][0]
        envelope = state["run_envelopes"][item["action_id"]]

        state2 = self.controller.provide_evidence(
            item["action_id"],
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Reviewed left-pad on npm; MIT license, no known vulnerabilities.",
                "rationale": "Checked npm audit output manually.",
            },
        )

        self.assertEqual(len(state2["run_loop"]["evidence_records"]), 1)
        record = state2["run_loop"]["evidence_records"][0]
        self.assertEqual(record["action_id"], item["action_id"])
        self.assertEqual(record["decision_id"], envelope["decision_id"])
        self.assertEqual(record["envelope_id"], envelope["envelope_id"])
        self.assertEqual(record["actor"], "human_operator")
        self.assertTrue(record["timestamp"])

    def test_provide_evidence_requires_type_and_text(self) -> None:
        state = self.controller.ingest_agent_response(RAW_INSTALL_DEPENDENCY_RESPONSE)
        item = state["queue"][0]
        with self.assertRaises(ValueError):
            self.controller.provide_evidence(item["action_id"], {"evidence_type": "", "evidence_text": ""})

    def test_provide_evidence_only_allowed_for_request_more_evidence(self) -> None:
        state = self.controller.ingest_agent_response(RAW_EDIT_FILE_RESPONSE)
        item = state["queue"][0]
        self.assertEqual(item["decision"], "ALLOW")
        with self.assertRaises(ValueError):
            self.controller.provide_evidence(
                item["action_id"], {"evidence_type": "x", "evidence_text": "y"}
            )

    def test_provide_evidence_does_not_mutate_original_decision(self) -> None:
        state = self.controller.ingest_agent_response(RAW_INSTALL_DEPENDENCY_RESPONSE)
        item = state["queue"][0]
        action_id = item["action_id"]
        original_envelope = state["run_envelopes"][action_id]
        original_missing = list(original_envelope["decision"]["missing_evidence"])
        original_decision_id = original_envelope["decision_id"]

        state2 = self.controller.provide_evidence(
            action_id,
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Reviewed left-pad on npm; MIT license, no known vulnerabilities.",
            },
        )

        # The original RunEnvelope.decision dict must be byte-for-byte
        # unchanged -- a re-evaluation produces a *separate* superseding
        # decision, never a mutation of the original.
        updated_envelope = state2["run_envelopes"][action_id]
        self.assertEqual(updated_envelope["decision"], original_envelope["decision"])
        self.assertEqual(updated_envelope["decision"]["missing_evidence"], original_missing)
        self.assertIn("package_trust_review", original_missing)

        self.assertEqual(len(state2["run_loop"]["superseding_decisions"]), 1)
        superseding = state2["run_loop"]["superseding_decisions"][0]
        self.assertEqual(superseding["action_id"], action_id)
        self.assertEqual(superseding["previous_decision_id"], original_decision_id)
        # The superseding decision reflects the supplied evidence (fewer
        # missing items) even though the original decision above did not.
        self.assertNotIn("package_trust_review", superseding["new_decision"]["missing_evidence"])

        updated_item = next(i for i in state2["queue"] if i["action_id"] == action_id)
        self.assertNotIn("package_trust_review", updated_item["missing_evidence"])

    def test_evidence_on_action_without_full_envelope_marks_pending_reevaluation(self) -> None:
        # Actions loaded from a static trace file only carry candidate +
        # decision, not the full schema envelope -- v0 cannot safely
        # re-run the evaluator for them, so it must say so explicitly.
        state = self.controller.load_sample_session()
        item = next(i for i in state["queue"] if i["decision"] == "REQUEST_MORE_EVIDENCE")
        original_decision = item["decision"]

        state2 = self.controller.provide_evidence(
            item["action_id"],
            {"evidence_type": "test_results", "evidence_text": "Ran full suite locally, all green."},
        )
        updated_item = next(i for i in state2["queue"] if i["action_id"] == item["action_id"])

        self.assertEqual(updated_item["decision"], original_decision)
        self.assertEqual(updated_item["lifecycle_status"], LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION)
        self.assertEqual(len(state2["run_loop"]["superseding_decisions"]), 0)
        self.assertEqual(len(state2["run_loop"]["evidence_records"]), 1)

    def test_unresolved_evidence_can_still_generate_follow_up_instruction(self) -> None:
        state = self.controller.load_sample_session()
        item = next(i for i in state["queue"] if i["decision"] == "REQUEST_MORE_EVIDENCE")
        self.controller.provide_evidence(
            item["action_id"],
            {"evidence_type": "test_results", "evidence_text": "Ran full suite locally, all green."},
        )

        state2 = self.controller.generate_next_instruction_packet()
        self.assertEqual(state2["run_loop"]["current_turn"], 1)
        packet = state2["run_loop"]["instruction_packets"][-1]
        # The still-unresolved action's own missing evidence is still
        # surfaced in the follow-up packet.
        joined = " ".join(packet["evidence_needed"])
        self.assertIn(item["action_id"], joined)

    def test_export_import_round_trip_preserves_run_loop_state(self) -> None:
        self.controller.submit_goal("Build a small local CLI tool to rename files.")
        self.controller.generate_next_instruction_packet()
        self.controller.ingest_agent_response(RAW_INSTALL_DEPENDENCY_RESPONSE)

        exported = self.controller.session_dict()
        json.dumps(exported)  # must be plain-JSON serializable

        other = _make_controller(self._tmpdir.name, name="sessions2")
        imported = other.import_session(exported)
        self.assertEqual(imported["run_loop"]["current_turn"], exported["run_loop"]["current_turn"])
        self.assertEqual(
            len(imported["run_loop"]["response_records"]), len(exported["run_loop"]["response_records"])
        )


class TestRunLoopHttpServer(unittest.TestCase):
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

    def test_run_loop_endpoints_over_http(self) -> None:
        status, state = self._post("/api/session/load_sample", {})
        self.assertEqual(status, 200)

        status, state = self._post("/api/session/run_loop/generate_instruction", {})
        self.assertEqual(status, 200)
        self.assertEqual(state["run_loop"]["current_turn"], 1)

        status, state = self._post(
            "/api/session/run_loop/ingest_response", {"raw_response": RAW_INSTALL_DEPENDENCY_RESPONSE}
        )
        self.assertEqual(status, 200)
        new_item = state["queue"][-1]
        self.assertEqual(new_item["decision"], "REQUEST_MORE_EVIDENCE")

        status, state = self._post(
            f"/api/queue/{new_item['action_id']}/evidence",
            {"evidence_type": "package_trust_review", "evidence_text": "Reviewed on npm; MIT, safe."},
        )
        self.assertEqual(status, 200)
        updated_item = next(i for i in state["queue"] if i["action_id"] == new_item["action_id"])
        self.assertNotIn("package_trust_review", updated_item["missing_evidence"])

        status, error_body = self._post("/api/session/run_loop/ingest_response", {"raw_response": ""})
        self.assertEqual(status, 400)
        self.assertIn("error", error_body)


class TestRunLoopHtmlContent(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = HTML_PATH.read_text(encoding="utf-8")

    def test_cursor_bridge_panel_present(self) -> None:
        # The Supervised Run Loop's canonical UI is now the single "Cursor
        # supervised file bridge" card -- there is no separate top-level
        # "Run Loop" panel any more.
        self.assertIn('id="cursor-bridge-panel"', self.raw)
        self.assertIn("Cursor supervised file bridge", self.raw)

    def test_turn_number_present(self) -> None:
        self.assertIn('id="bridge-turn"', self.raw)

    def test_manual_paste_controls_are_inside_collapsed_advanced_fallback(self) -> None:
        # Requirement: manual paste is a collapsed, non-default fallback --
        # its controls must appear textually after the <details> that hides
        # them, not before it (i.e. inside the collapsed section).
        details_index = self.raw.index('id="advanced-manual-fallback-details"')
        summary_index = self.raw.index("<summary>Advanced manual paste fallback</summary>")
        self.assertGreater(summary_index, details_index)
        for marker in (
            'id="instruction-packet-text"',
            'id="btn-copy-packet"',
            'id="btn-generate-instruction"',
            'id="agent-response-input"',
            'id="btn-ingest-response"',
        ):
            self.assertGreater(self.raw.index(marker), summary_index, f"{marker} must be inside the advanced fallback")
        details_close = self.raw.index("</details>", summary_index)
        self.assertLess(self.raw.index('id="btn-ingest-response"'), details_close)

    def test_instruction_packet_preview_and_copy_present(self) -> None:
        self.assertIn('id="instruction-packet-text"', self.raw)
        self.assertIn('id="btn-copy-packet"', self.raw)
        self.assertIn('id="btn-generate-instruction"', self.raw)

    def test_paste_response_textarea_and_ingest_button_present(self) -> None:
        self.assertIn('id="agent-response-input"', self.raw)
        self.assertIn('id="btn-ingest-response"', self.raw)

    def test_ingest_button_shows_error_on_empty_input(self) -> None:
        # Regression: clicking "Ingest response" with an empty/whitespace-only
        # textarea used to silently no-op with zero user feedback. The click
        # handler must call showError(...) in that case instead of just
        # returning.
        handler_start = self.raw.index('getElementById("btn-ingest-response").addEventListener')
        handler_end = self.raw.index("});", handler_start)
        handler_body = self.raw[handler_start:handler_end]
        self.assertIn("showError", handler_body)

    def test_last_ingestion_summary_present(self) -> None:
        self.assertIn('id="last-ingestion-summary"', self.raw)

    def test_evidence_form_present(self) -> None:
        self.assertIn('class="evidence-form"', self.raw)
        self.assertIn("evidence_type", self.raw)
        self.assertIn("evidence_text", self.raw)
        self.assertIn("file_path_or_note", self.raw)

    def test_needs_attention_categories_present(self) -> None:
        for label in (
            "Needs attention — pending human decision",
            "Resolved plan gates — closed context",
            "Admitted, not executed",
            "Evidence supplied — still blocked",
            "Evidence satisfied — pending human decision",
        ):
            self.assertIn(label, self.raw)

    def test_only_one_generic_decide_form_template(self) -> None:
        # UX requirement carried over from the base control surface: one
        # generic decision form template, in the Selected Action panel --
        # the evidence form is a separate, additional template.
        self.assertEqual(self.raw.count('<form class="decide-form"'), 1)
        self.assertEqual(self.raw.count('<form class="evidence-form"'), 1)

    def test_no_provider_network_calls_in_new_markup(self) -> None:
        forbidden_hosts = ("openai.com", "anthropic.com", "cursor.sh", "googleapis.com")
        for host in forbidden_hosts:
            self.assertNotIn(host, self.raw)


class TestRunLoopNoForbiddenExecution(unittest.TestCase):
    """Static-source checks backing the NO_EXECUTOR / NO_PROVIDER_CALLS / NO_AGENT_OS_IMPORT diagnostics."""

    _SOURCE_PATH = REPO_ROOT / "admissible" / "run_loop.py"

    def setUp(self) -> None:
        self.source = self._SOURCE_PATH.read_text(encoding="utf-8")

    def test_no_agent_os_import(self) -> None:
        self.assertNotIn("import agent_os", self.source)
        self.assertNotIn("from agent_os", self.source)

    def test_no_subprocess_or_shell_execution(self) -> None:
        forbidden_tokens = ("import subprocess", "os.system(", "os.popen(", " eval(", " exec(")
        for token in forbidden_tokens:
            self.assertNotIn(token, self.source, f"run_loop.py unexpectedly contains {token!r}")

    def test_no_network_provider_sdk_imports(self) -> None:
        forbidden_tokens = (
            "import openai",
            "import anthropic",
            "google.generativeai",
            "requests.post",
            "import httpx",
        )
        lowered = self.source.lower()
        for token in forbidden_tokens:
            self.assertNotIn(token, lowered, f"run_loop.py unexpectedly references {token!r}")


if __name__ == "__main__":
    unittest.main()
