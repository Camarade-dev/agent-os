"""Tests for Admissible state lifecycle slices.

Slice 001 (ADMISSIBLE_STATE_LIFECYCLE_001_HUMAN_DECISION_APPLICATION):
human decisions append derived lifecycle state without mutating original
admission decisions.

Slice 002 (ADMISSIBLE_STATE_LIFECYCLE_002_EVIDENCE_ACCUMULATION_AND_REEVALUATION):
evidence provision is append-only and cumulative; re-evaluation never forgets
earlier evidence items.
"""

from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_ADMITTED_NOT_EXECUTED
from admissible.control_surface import ControlSurfaceController
from admissible.run_loop import (
    LIFECYCLE_ADMITTED_NOT_EXECUTED,
    LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_REEVALUATION,
    LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED,
    LIFECYCLE_EVIDENCE_SATISFIED_PENDING_HUMAN_DECISION,
    LIFECYCLE_NEEDS_HUMAN_INPUT,
    LIFECYCLE_REFUSED_CLOSED,
    LIFECYCLE_RESOLVED_GATE,
    lifecycle_status_after_evidence_reevaluation,
    reevaluate_envelope_with_evidence,
)
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = (
    REPO_ROOT
    / "benchmark"
    / "long_run_scenarios"
    / "cursor_slither_demo"
    / "fixtures"
    / "pasted_agent_responses"
)
PLAN_GATE_FIXTURE = FIXTURES_DIR / "cursor_plan_gate_resolution_request.txt"
MULTI_ACTION_FIXTURE = FIXTURES_DIR / "multi_action_install_push_local_claim.txt"
RAW_INSTALL_DEPENDENCY_RESPONSE = (
    "User: Please add a helper dependency.\n\n"
    "Proposed command:\n"
    "    npm install left-pad\n"
)
SAMPLE_SLITHER_PROMPT = (
    "Build a small browser-based Slither-like game with a moving snake, "
    "collectible food, growth, collision handling, score display, restart "
    "behavior, and simple visual polish. Keep it local-only. Do not deploy. "
    "Ask before installing dependencies or deleting existing files."
)


def _controller(tmpdir: str) -> ControlSurfaceController:
    return ControlSurfaceController(session_dir=Path(tmpdir) / "sessions")


def _session_with_plan_gate(controller: ControlSurfaceController) -> dict:
    controller.submit_goal(SAMPLE_SLITHER_PROMPT)
    controller.ingest_agent_response(load_fixture(PLAN_GATE_FIXTURE))
    return controller.state_view()


class TestPlanGateApprovalLifecycle(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _controller(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_approving_plan_gate_appends_resolved_record_and_preserves_original_decision(self) -> None:
        state = _session_with_plan_gate(self.controller)
        item = state["queue"][-1]
        self.assertEqual(item["action_type"], "plan_gate_resolution")
        original_decision = item["decision"]
        original_envelope_decision = state["run_envelopes"][item["action_id"]]["decision"]

        updated = self.controller.decide(
            item["action_id"],
            {"decision_type": "approve", "scope": "local_workspace_only", "rationale": "ok"},
        )
        updated_item = updated["queue"][-1]
        self.assertEqual(updated_item["decision"], original_decision)
        self.assertEqual(
            updated["run_envelopes"][item["action_id"]]["decision"],
            original_envelope_decision,
        )
        self.assertEqual(len(updated["human_decisions"]), 1)
        self.assertEqual(len(updated["run_loop"]["derived_lifecycle_resolutions"]), 1)
        derived = updated["run_loop"]["derived_lifecycle_resolutions"][0]
        self.assertEqual(derived["derived_status"], LIFECYCLE_RESOLVED_GATE)
        self.assertEqual(derived["human_decision_id"], updated["human_decisions"][0]["record_id"])

    def test_scoped_approval_stores_local_workspace_only(self) -> None:
        state = _session_with_plan_gate(self.controller)
        item = state["queue"][-1]
        updated = self.controller.decide(
            item["action_id"],
            {"decision_type": "approve", "scope": "local_workspace_only", "rationale": "scoped ok"},
        )
        record = updated["human_decisions"][0]
        derived = updated["run_loop"]["derived_lifecycle_resolutions"][0]
        self.assertEqual(record["scope"], "local_workspace_only")
        self.assertEqual(derived["approved_scope"], "local_workspace_only")
        resolved = updated["run_loop"]["resolved_plan_gates"]
        self.assertTrue(resolved)
        self.assertTrue(all(g["approved_scope"] == "local_workspace_only" for g in resolved))

    def test_approved_plan_gate_disappears_from_unresolved_gate_list(self) -> None:
        state = _session_with_plan_gate(self.controller)
        item = state["queue"][-1]
        before = set(state["needs_attention"]["unresolved_plan_gates"])
        self.assertTrue(before)

        updated = self.controller.decide(
            item["action_id"],
            {"decision_type": "approve", "scope": "local_workspace_only", "rationale": "ok"},
        )
        after = set(updated["needs_attention"]["unresolved_plan_gates"])
        self.assertTrue(after < before)
        self.assertNotIn(item["action_id"], {a["action_id"] for a in updated["needs_attention"]["approval_needed"]})
        self.assertEqual(updated["queue"][-1]["lifecycle_status"], LIFECYCLE_RESOLVED_GATE)

    def test_next_instruction_packet_does_not_repeat_resolved_plan_gate(self) -> None:
        state = _session_with_plan_gate(self.controller)
        item = state["queue"][-1]
        self.controller.decide(
            item["action_id"],
            {"decision_type": "approve", "scope": "local_workspace_only", "rationale": "ok"},
        )
        state2 = self.controller.generate_next_instruction_packet()
        packet = state2["run_loop"]["instruction_packets"][-1]
        joined = "\n".join(packet["open_gates_summary"])
        for gate in state["plan_audit"]["required_gates"]:
            if gate in {g["gate_id"] for g in state2["run_loop"]["resolved_plan_gates"]}:
                self.assertNotIn(f"Unresolved plan gate: {gate}.", joined)
        self.assertIn("Human-resolved plan gate:", joined)
        self.assertIn("local_workspace_only", joined)


class TestSideEffectApprovalLifecycle(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _controller(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_approved_side_effecting_local_edit_becomes_admitted_not_executed(self) -> None:
        self.controller.submit_goal(SAMPLE_SLITHER_PROMPT)
        self.controller.ingest_agent_response(load_fixture(MULTI_ACTION_FIXTURE))
        state = self.controller.state_view()
        item = next(i for i in state["queue"] if i.get("action_type") == "git_push")
        original_decision = item["decision"]
        self.assertEqual(original_decision, "REQUIRE_HUMAN_APPROVAL")

        updated = self.controller.decide(
            item["action_id"],
            {"decision_type": "approve", "scope": "local_workspace_only", "rationale": "approved push"},
        )
        updated_item = next(i for i in updated["queue"] if i["action_id"] == item["action_id"])
        self.assertEqual(updated_item["decision"], original_decision)
        self.assertEqual(updated_item["execution_status"], EXECUTION_STATUS_ADMITTED_NOT_EXECUTED)
        self.assertEqual(updated_item["lifecycle_status"], LIFECYCLE_ADMITTED_NOT_EXECUTED)
        self.assertGreater(
            updated["mission_summary"]["counts_by_execution_status"]["admitted_not_executed"],
            0,
        )


class TestRefusalAndNeedsAttention(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _controller(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_refused_item_leaves_needs_attention(self) -> None:
        state = _session_with_plan_gate(self.controller)
        item = state["queue"][-1]
        before_count = state["mission_summary"]["needs_attention_count"]
        self.assertGreater(before_count, 0)

        updated = self.controller.decide(
            item["action_id"],
            {"decision_type": "refuse", "rationale": "not now"},
        )
        updated_item = next(i for i in updated["queue"] if i["action_id"] == item["action_id"])
        self.assertEqual(updated_item["lifecycle_status"], LIFECYCLE_REFUSED_CLOSED)
        self.assertLess(updated["mission_summary"]["needs_attention_count"], before_count)
        self.assertNotIn(item["action_id"], {a["action_id"] for a in updated["needs_attention"]["approval_needed"]})

    def test_needs_attention_count_decreases_after_approval(self) -> None:
        state = _session_with_plan_gate(self.controller)
        before = state["mission_summary"]["needs_attention_count"]
        item = state["queue"][-1]
        updated = self.controller.decide(
            item["action_id"],
            {"decision_type": "approve", "scope": "local_workspace_only", "rationale": "ok"},
        )
        self.assertLess(updated["mission_summary"]["needs_attention_count"], before)


class TestSessionExportLifecycle(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _controller(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_session_export_includes_original_human_and_derived_state(self) -> None:
        state = _session_with_plan_gate(self.controller)
        item = state["queue"][-1]
        self.controller.decide(
            item["action_id"],
            {"decision_type": "approve", "scope": "local_workspace_only", "rationale": "ok"},
        )
        exported = self.controller.session_dict()
        self.assertIn("human_decisions", exported)
        self.assertEqual(len(exported["human_decisions"]), 1)
        self.assertIn("derived_lifecycle_resolutions", exported["run_loop"])
        self.assertIn("resolved_plan_gates", exported["run_loop"])
        queue_item = next(i for i in exported["queue"] if i["action_id"] == item["action_id"])
        self.assertEqual(queue_item["lifecycle_status"], LIFECYCLE_RESOLVED_GATE)
        self.assertEqual(
            exported["run_envelopes"][item["action_id"]]["decision"]["decision"],
            state["run_envelopes"][item["action_id"]]["decision"]["decision"],
        )

    def test_reload_session_preserves_derived_lifecycle_state(self) -> None:
        state = _session_with_plan_gate(self.controller)
        item = state["queue"][-1]
        self.controller.decide(
            item["action_id"],
            {"decision_type": "approve", "scope": "local_workspace_only", "rationale": "ok"},
        )
        exported = self.controller.session_dict()

        other = _controller(self._tmpdir.name + "_reload")
        imported = other.import_session(exported)
        self.assertEqual(
            len(imported["run_loop"]["derived_lifecycle_resolutions"]),
            len(exported["run_loop"]["derived_lifecycle_resolutions"]),
        )
        self.assertEqual(
            len(imported["run_loop"]["resolved_plan_gates"]),
            len(exported["run_loop"]["resolved_plan_gates"]),
        )
        reloaded_item = next(i for i in imported["queue"] if i["action_id"] == item["action_id"])
        self.assertEqual(reloaded_item["lifecycle_status"], LIFECYCLE_RESOLVED_GATE)
        json.dumps(imported)  # round-trip serializable


class TestAdmissibleBoundary(unittest.TestCase):
    def test_no_agent_os_import_in_admissible_modules(self) -> None:
        admissible_root = REPO_ROOT / "admissible"
        hits: list[str] = []
        for path in sorted(admissible_root.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "agent_os" or alias.name.startswith("agent_os."):
                            hits.append(f"{path}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module
                    if module and (module == "agent_os" or module.startswith("agent_os.")):
                        hits.append(f"{path}: from {module}")
        self.assertEqual(hits, [])


def _session_with_install_dependency(controller: ControlSurfaceController) -> tuple[dict, str]:
    controller.submit_goal(SAMPLE_SLITHER_PROMPT)
    state = controller.ingest_agent_response(RAW_INSTALL_DEPENDENCY_RESPONSE)
    item = state["queue"][0]
    return state, item["action_id"]


class TestEvidenceAccumulationLifecycle(unittest.TestCase):
    """Slice 002: cumulative evidence re-evaluation and derived lifecycle."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _controller(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_first_evidence_item_reduces_missing_evidence(self) -> None:
        state, action_id = _session_with_install_dependency(self.controller)
        original_missing = list(state["run_envelopes"][action_id]["decision"]["missing_evidence"])
        self.assertIn("package_trust_review", original_missing)

        updated = self.controller.provide_evidence(
            action_id,
            {"evidence_type": "package_trust_review", "evidence_text": "Package is from a trusted maintainer."},
        )
        item = next(i for i in updated["queue"] if i["action_id"] == action_id)
        self.assertNotIn("package_trust_review", item["missing_evidence"])
        self.assertEqual(item["lifecycle_status"], LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED)

    def test_second_evidence_preserves_first_during_reevaluation(self) -> None:
        state, action_id = _session_with_install_dependency(self.controller)
        self.controller.provide_evidence(
            action_id,
            {"evidence_type": "package_trust_review", "evidence_text": "Trusted package."},
        )
        updated = self.controller.provide_evidence(
            action_id,
            {"evidence_type": "license_compatibility", "evidence_text": "MIT license is compatible."},
        )
        item = next(i for i in updated["queue"] if i["action_id"] == action_id)
        self.assertNotIn("package_trust_review", item["missing_evidence"])
        self.assertNotIn("license_compatibility", item["missing_evidence"])
        self.assertIn("dependency_lockfile_review", item["missing_evidence"])

    def test_missing_evidence_does_not_regress_across_supplies(self) -> None:
        state, action_id = _session_with_install_dependency(self.controller)
        supplies = [
            ("package_trust_review", "Trusted."),
            ("license_compatibility", "MIT ok."),
            ("dependency_lockfile_review", "Lockfile reviewed."),
        ]
        satisfied: set[str] = set()
        for etype, etext in supplies:
            updated = self.controller.provide_evidence(
                action_id, {"evidence_type": etype, "evidence_text": etext}
            )
            item = next(i for i in updated["queue"] if i["action_id"] == action_id)
            current = set(item["missing_evidence"])
            for prev in satisfied:
                self.assertNotIn(prev, current, f"{prev} regressed after supplying {etype}")
            satisfied.add(etype)

    def test_evidence_records_are_append_only_and_export_round_trips(self) -> None:
        state, action_id = _session_with_install_dependency(self.controller)
        self.controller.provide_evidence(
            action_id, {"evidence_type": "package_trust_review", "evidence_text": "A"}
        )
        self.controller.provide_evidence(
            action_id, {"evidence_type": "license_compatibility", "evidence_text": "B"}
        )
        exported = self.controller.session_dict()
        records = [r for r in exported["run_loop"]["evidence_records"] if r["action_id"] == action_id]
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["evidence_type"], "package_trust_review")
        self.assertEqual(records[1]["evidence_type"], "license_compatibility")

        other = _controller(self._tmpdir.name + "_reload")
        imported = other.import_session(exported)
        reloaded = [r for r in imported["run_loop"]["evidence_records"] if r["action_id"] == action_id]
        self.assertEqual(len(reloaded), 2)
        json.dumps(imported)

    def test_original_decision_remains_immutable_after_evidence(self) -> None:
        state, action_id = _session_with_install_dependency(self.controller)
        original_decision = copy.deepcopy(state["run_envelopes"][action_id]["decision"])
        self.controller.provide_evidence(
            action_id, {"evidence_type": "package_trust_review", "evidence_text": "ok"}
        )
        self.controller.provide_evidence(
            action_id, {"evidence_type": "license_compatibility", "evidence_text": "ok"}
        )
        final = self.controller.state_view()
        self.assertEqual(final["run_envelopes"][action_id]["decision"], original_decision)

    def test_original_envelope_schema_remains_auditable(self) -> None:
        state, action_id = _session_with_install_dependency(self.controller)
        original_envelope = copy.deepcopy(state["run_envelopes"][action_id]["envelope"])
        self.assertIsNotNone(original_envelope)
        self.controller.provide_evidence(
            action_id, {"evidence_type": "package_trust_review", "evidence_text": "ok"}
        )
        final = self.controller.state_view()
        self.assertEqual(final["run_envelopes"][action_id]["envelope"], original_envelope)
        self.assertEqual(
            final["run_envelopes"][action_id]["envelope"]["evidence"]["missing"],
            original_envelope["evidence"]["missing"],
        )

    def test_request_more_evidence_stays_in_needs_attention_until_resolved(self) -> None:
        state, action_id = _session_with_install_dependency(self.controller)
        before = state["mission_summary"]["needs_attention_count"]
        self.assertGreater(before, 0)

        updated = self.controller.provide_evidence(
            action_id, {"evidence_type": "package_trust_review", "evidence_text": "partial"}
        )
        item = next(i for i in updated["queue"] if i["action_id"] == action_id)
        self.assertEqual(item["decision"], "REQUEST_MORE_EVIDENCE")
        self.assertEqual(item["lifecycle_status"], LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED)
        self.assertEqual(updated["mission_summary"]["needs_attention_count"], before)

    def test_insufficient_evidence_keeps_blocked_derived_status(self) -> None:
        _, action_id = _session_with_install_dependency(self.controller)
        updated = self.controller.provide_evidence(
            action_id, {"evidence_type": "package_trust_review", "evidence_text": "only one of three"}
        )
        item = next(i for i in updated["queue"] if i["action_id"] == action_id)
        self.assertEqual(item["decision"], "REQUEST_MORE_EVIDENCE")
        self.assertEqual(item["lifecycle_status"], LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED)
        self.assertTrue(item["missing_evidence"])

    def test_all_satisfiable_evidence_clears_missing_without_auto_execution(self) -> None:
        _, action_id = _session_with_install_dependency(self.controller)
        for etype, etext in [
            ("package_trust_review", "trusted"),
            ("license_compatibility", "MIT"),
            ("dependency_lockfile_review", "lock ok"),
        ]:
            self.controller.provide_evidence(action_id, {"evidence_type": etype, "evidence_text": etext})

        final = self.controller.state_view()
        item = next(i for i in final["queue"] if i["action_id"] == action_id)
        self.assertEqual(item["missing_evidence"], [])
        self.assertEqual(item["lifecycle_status"], LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED)
        self.assertEqual(item["decision"], "REQUEST_MORE_EVIDENCE")
        self.assertNotEqual(item.get("execution_status"), EXECUTION_STATUS_ADMITTED_NOT_EXECUTED)

    def test_request_evidence_human_decision_does_not_transition_lifecycle(self) -> None:
        state, action_id = _session_with_install_dependency(self.controller)
        updated = self.controller.decide(action_id, {"decision_type": "request_evidence", "rationale": "need more"})
        item = next(i for i in updated["queue"] if i["action_id"] == action_id)
        self.assertEqual(item["lifecycle_status"], LIFECYCLE_NEEDS_HUMAN_INPUT)
        self.assertEqual(len(updated["human_decisions"]), 1)

    def test_pure_reevaluation_accumulates_all_items(self) -> None:
        state, action_id = _session_with_install_dependency(self.controller)
        envelope = state["run_envelopes"][action_id]["envelope"]
        decision = reevaluate_envelope_with_evidence(
            envelope,
            evidence_items=[
                ("package_trust_review", "trusted"),
                ("license_compatibility", "MIT"),
            ],
        )
        self.assertIsNotNone(decision)
        assert decision is not None
        self.assertNotIn("package_trust_review", decision["missing_evidence"])
        self.assertNotIn("license_compatibility", decision["missing_evidence"])

    def test_lifecycle_mapping_after_evidence_reevaluation(self) -> None:
        self.assertEqual(
            lifecycle_status_after_evidence_reevaluation("REQUEST_MORE_EVIDENCE"),
            LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED,
        )
        self.assertEqual(
            lifecycle_status_after_evidence_reevaluation("REQUIRE_HUMAN_APPROVAL"),
            LIFECYCLE_EVIDENCE_SATISFIED_PENDING_HUMAN_DECISION,
        )


if __name__ == "__main__":
    unittest.main()
