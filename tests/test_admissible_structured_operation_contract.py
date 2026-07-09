"""Slice ADMISSIBLE_EXECUTION_010_STRUCTURED_OPERATION_PROPOSAL_CONTRACT tests.

Covers the offline structured-operation proposal contract: the
`ADMISSIBLE_STRUCTURED_OPERATION:` marker guidance in the next-agent
instruction packet, offline extraction of the block into
`candidate.structured_operations`, and the round-trip into the bounded local
executor. No provider calls, no command execution, fixtures/offline only.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import AutonomyLevel, RunEnvelope, _build_queue_item
from admissible.evaluator.rules_only import evaluate_envelope
from admissible.execution.bounded_local_executor import (
    DIAG_FORBIDDEN_OPERATION_CATEGORY,
    assess_bounded_execution_eligibility,
    execute_bounded_local_action,
)
from admissible.long_run_envelope_builder import (
    DEFAULT_EXECUTION_STATUS,
    STRUCTURED_OPERATION_MARKER,
    build_from_raw_output,
    extract_structured_operation_blocks,
)
from admissible.run_loop import (
    build_candidates_from_agent_response,
    generate_instruction_packet,
)


def _write_block(path: str, content: str) -> str:
    return (
        f"{STRUCTURED_OPERATION_MARKER}\n"
        "```json\n"
        f'{{"operation": "write_file", "path": "{path}", "content": "{content}"}}\n'
        "```\n"
    )


class TestStructuredOperationExtraction(unittest.TestCase):
    def test_extracts_single_fenced_write_operation(self) -> None:
        raw = "I will scaffold the page.\n\n" + _write_block("index.html", "<!doctype html>")
        blocks = extract_structured_operation_blocks(raw)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(
            blocks[0]["operations"],
            [{"operation": "write_file", "path": "index.html", "content": "<!doctype html>"}],
        )

    def test_braces_in_content_do_not_break_the_scanner(self) -> None:
        raw = (
            f"{STRUCTURED_OPERATION_MARKER}\n"
            "```json\n"
            '{"operation": "write_file", "path": "game.js", '
            '"content": "function f(){ return {a: [1,2]}; }"}\n'
            "```\n"
        )
        blocks = extract_structured_operation_blocks(raw)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(
            blocks[0]["operations"][0]["content"], "function f(){ return {a: [1,2]}; }"
        )

    def test_operations_list_payload_is_flattened(self) -> None:
        raw = (
            f"{STRUCTURED_OPERATION_MARKER}\n"
            "```json\n"
            '{"operations": [{"operation": "list_files", "path": "."}, '
            '{"operation": "read_file", "path": "README.md"}]}\n'
            "```\n"
        )
        blocks = extract_structured_operation_blocks(raw)
        self.assertEqual(len(blocks), 1)
        self.assertEqual([op["operation"] for op in blocks[0]["operations"]], ["list_files", "read_file"])

    def test_bare_unfenced_object_is_supported(self) -> None:
        raw = STRUCTURED_OPERATION_MARKER + ' {"operation": "read_file", "path": "a.txt"}'
        blocks = extract_structured_operation_blocks(raw)
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["operations"][0]["operation"], "read_file")

    def test_unparseable_payload_is_skipped(self) -> None:
        raw = f"{STRUCTURED_OPERATION_MARKER}\n```json\n{{not valid json}}\n```\n"
        self.assertEqual(extract_structured_operation_blocks(raw), [])

    def test_object_without_operation_key_is_skipped(self) -> None:
        raw = f'{STRUCTURED_OPERATION_MARKER}\n```json\n{{"path": "a.txt"}}\n```\n'
        self.assertEqual(extract_structured_operation_blocks(raw), [])

    def test_multiple_markers_yield_multiple_blocks(self) -> None:
        raw = _write_block("index.html", "x") + "\n" + _write_block("style.css", "y")
        blocks = extract_structured_operation_blocks(raw)
        self.assertEqual(len(blocks), 2)


class TestCandidatePopulation(unittest.TestCase):
    def test_write_block_populates_structured_operations_and_classifies_allow_local(self) -> None:
        raw = "Scaffold the local game.\n\n" + _write_block("index.html", "<!doctype html>")
        out = build_from_raw_output(raw, source_metadata={"workspace_context": "ws"})
        candidate = next(
            c for c in out["action_candidates"] if c.get("structured_operations")
        )
        self.assertEqual(candidate["action_type"], "create_file")
        self.assertEqual(
            candidate["structured_operations"],
            [{"operation": "write_file", "path": "index.html", "content": "<!doctype html>"}],
        )
        envelope = out["envelopes"][out["action_candidates"].index(candidate)]
        decision = evaluate_envelope(envelope)
        self.assertEqual(decision["decision"], "ALLOW")
        self.assertEqual(decision["risk_level"], "local")
        self.assertEqual(decision["missing_evidence"], [])

    def test_read_only_block_is_allow_local_observation(self) -> None:
        raw = (
            "Inspect first.\n\n"
            f"{STRUCTURED_OPERATION_MARKER}\n"
            "```json\n"
            '{"operations": [{"operation": "list_files", "path": "."}, '
            '{"operation": "read_file", "path": "README.md"}]}\n'
            "```\n"
        )
        out = build_from_raw_output(raw)
        candidate = out["action_candidates"][0]
        self.assertEqual(candidate["action_type"], "read_file")
        self.assertEqual(len(candidate["structured_operations"]), 2)
        decision = evaluate_envelope(out["envelopes"][0])
        self.assertEqual(decision["decision"], "ALLOW")
        self.assertEqual(decision["risk_level"], "local")

    def test_response_without_marker_has_no_structured_operations(self) -> None:
        raw = (
            "User: Add a comment to the header.\n\n"
            "Proposed tool call:\n"
            '    edit_file({"path": "src/Header.tsx", "instructions": "add a comment"})\n'
        )
        out = build_from_raw_output(raw)
        for candidate in out["action_candidates"]:
            self.assertNotIn("structured_operations", candidate)

    def test_marker_span_is_consumed_no_noisy_json_candidates(self) -> None:
        raw = "Do the scaffold.\n\n" + _write_block("index.html", "<!doctype html>")
        out = build_from_raw_output(raw)
        structured = [c for c in out["action_candidates"] if c.get("structured_operations")]
        self.assertEqual(len(structured), 1)
        # The raw JSON keys/braces must not leak into a separate candidate.
        for candidate in out["action_candidates"]:
            self.assertNotIn('"operation"', candidate.get("tool_or_command", ""))

    def test_extraction_does_not_auto_execute_or_mark_executed(self) -> None:
        raw = _write_block("index.html", "<!doctype html>")
        candidate = build_from_raw_output(raw)["action_candidates"][0]
        self.assertEqual(candidate["execution_status"], DEFAULT_EXECUTION_STATUS)


class TestExecutorRoundTrip(unittest.TestCase):
    def test_extracted_write_is_eligible_and_executes(self) -> None:
        raw = "Scaffold it.\n\n" + _write_block("game.js", "console.log(1);")
        built = build_candidates_from_agent_response(raw, turn_number=1)
        entry = built[0]
        self.assertEqual(entry["decision"]["decision"], "ALLOW")
        run_env = RunEnvelope(
            action_id=entry["action_id"],
            envelope_id=entry["envelope_id"],
            decision_id=entry["decision_id"],
            candidate=entry["candidate"],
            decision=entry["decision"],
            envelope=entry["envelope"],
        )
        item = _build_queue_item(run_env)
        assessment = assess_bounded_execution_eligibility(item=item, envelope=run_env)
        self.assertTrue(assessment["eligible"])
        self.assertEqual(len(assessment["operations"]), 1)

        with tempfile.TemporaryDirectory() as tmpdir:
            result = execute_bounded_local_action(
                workspace_path=tmpdir,
                operations=assessment["operations"],
                action_id=entry["action_id"],
            )
            self.assertTrue(result.success)
            self.assertTrue((Path(tmpdir) / "game.js").is_file())

    def test_forbidden_content_recorded_but_refused_at_execution(self) -> None:
        # Extraction is a pure recorder; the admission/execution gate is not
        # weakened -- forbidden shell/package content is still refused.
        raw = _write_block("x.sh", "npm install evil")
        candidate = build_from_raw_output(raw)["action_candidates"][0]
        operations = candidate["structured_operations"]
        self.assertEqual(operations[0]["content"], "npm install evil")
        with tempfile.TemporaryDirectory() as tmpdir:
            result = execute_bounded_local_action(
                workspace_path=tmpdir, operations=operations, action_id="bad"
            )
            self.assertFalse(result.success)
            self.assertEqual(result.diagnostic, DIAG_FORBIDDEN_OPERATION_CATEGORY)


class TestInstructionPacketGuidance(unittest.TestCase):
    def _packet(self, autonomy_level: str):
        return generate_instruction_packet(
            turn_number=1,
            autonomy_level=autonomy_level,
            goal_intake={"task_type": "software_build", "deliverable": "small tool"},
            plan_audit={"verdict": "PLAN_OK_FOR_LOCAL_PROTOTYPE", "required_gates": []},
            queue=[],
        )

    def test_packet_documents_structured_operation_marker(self) -> None:
        packet = self._packet(AutonomyLevel.L1_PROPOSE_ONLY.value)
        self.assertIn(STRUCTURED_OPERATION_MARKER, packet.packet_text)
        for token in ("list_files", "read_file", "write_file"):
            self.assertIn(token, packet.packet_text)

    def test_guidance_is_constant_across_autonomy_levels(self) -> None:
        l0 = self._packet(AutonomyLevel.L0_OBSERVE_ONLY.value)
        l4 = self._packet(AutonomyLevel.L4_HIGH_AUTONOMY_HARD_GATES.value)
        self.assertEqual(l0.response_format_guidance, l4.response_format_guidance)
        self.assertIn(STRUCTURED_OPERATION_MARKER, l0.packet_text)
        self.assertIn(STRUCTURED_OPERATION_MARKER, l4.packet_text)

    def test_guidance_does_not_authorize_execution(self) -> None:
        packet = self._packet(AutonomyLevel.L4_HIGH_AUTONOMY_HARD_GATES.value)
        self.assertIn("does not authorize execution", packet.packet_text)


if __name__ == "__main__":
    unittest.main()
