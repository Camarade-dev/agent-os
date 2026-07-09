"""Canonical blank-session Admissible demo end-to-end regression.

Slice ADMISSIBLE_DEMO_005_CANONICAL_E2E_REGRESSION pins the offline demo
scenario from benchmark/reports/admissible_end_to_end_demo_audit.md as a
repeatable regression test.

Constraints exercised: no provider calls, no command execution, no agent_os
import, bridge file ingest only (not manual paste fallback), fixtures only.
"""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_ADMITTED_NOT_EXECUTED
from admissible.control_surface import ControlSurfaceController
from admissible.run_loop import (
    LIFECYCLE_ADMITTED_NOT_EXECUTED,
    LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED,
    LIFECYCLE_RESOLVED_GATE,
)
from admissible.runner.cursor_bridge import (
    DuplicateResponseError,
    ingest_response_file_with_controller,
    write_next_instruction_with_controller,
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

CANONICAL_GOAL_PROMPT = (
    "Build a small browser-based Slither-like game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)

PLAN_GATE_FIXTURE = "cursor_plan_gate_resolution_request.txt"
MULTI_ACTION_FIXTURE = "multi_action_install_push_local_claim.txt"
NEGATIVE_ONLY_FIXTURE = "negative_only_boundaries.txt"


def _controller(session_root: Path) -> ControlSurfaceController:
    return ControlSurfaceController(session_dir=session_root / "sessions")


def _workspace(root: Path) -> Path:
    path = root / "workspace"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _load_fixture(name: str) -> str:
    return load_fixture(FIXTURES_DIR / name)


def _bridge_dir(workspace: Path) -> Path:
    return workspace / ".admissible"


def _write_response(workspace: Path, text: str) -> Path:
    bridge = _bridge_dir(workspace)
    bridge.mkdir(parents=True, exist_ok=True)
    response_path = bridge / "agent-response.md"
    response_path.write_text(text, encoding="utf-8")
    return response_path


def _bridge_write(controller: ControlSurfaceController, workspace: Path) -> dict:
    return write_next_instruction_with_controller(controller, workspace)


def _bridge_ingest(controller: ControlSurfaceController, workspace: Path) -> dict:
    return ingest_response_file_with_controller(controller, workspace)


class TestCanonicalDemoEndToEnd(unittest.TestCase):
    """Single orchestrated walk of the canonical blank-session demo."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.controller = _controller(self.root)
        self.workspace = _workspace(self.root)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_blank_session_canonical_demo_end_to_end(self) -> None:
        # 1–2. Blank session, submit canonical goal, intake/plan/audit.
        state = self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        self.assertIn("goal_intake", state)
        self.assertIn("plan_audit", state)
        plan_audit = state["plan_audit"]
        self.assertTrue(plan_audit.get("required_gates"))
        unresolved_before = set(state["needs_attention"]["unresolved_plan_gates"])
        self.assertTrue(unresolved_before)

        # 3–4. Bridge write produces next-agent-instruction.md.
        write_result = _bridge_write(self.controller, self.workspace)
        instruction_path = Path(write_result["bridge"]["instruction_path"])
        self.assertTrue(instruction_path.is_file())
        self.assertEqual(
            instruction_path,
            self.workspace / ".admissible" / "next-agent-instruction.md",
        )
        self.assertIn("Admissible Next Agent Instruction Packet", instruction_path.read_text(encoding="utf-8"))

        # 5–6. Turn 1: plan-gate fixture via real bridge ingest.
        _write_response(self.workspace, _load_fixture(PLAN_GATE_FIXTURE))

        def _boom(*args, **kwargs):
            raise AssertionError("canonical demo must never execute subprocess")

        with mock.patch.object(subprocess, "run", _boom):
            turn1 = _bridge_ingest(self.controller, self.workspace)

        self.assertEqual(turn1["bridge"]["action_count"], 1)
        plan_gate_item = turn1["queue"][-1]
        self.assertEqual(plan_gate_item["action_type"], "plan_gate_resolution")
        self.assertEqual(plan_gate_item["decision"], "REQUIRE_HUMAN_APPROVAL")
        original_plan_gate_decision = copy.deepcopy(plan_gate_item["decision"])
        queue_len_after_turn1 = len(turn1["queue"])
        attention_after_plan_gate_ingest = turn1["mission_summary"]["needs_attention_count"]
        self.assertGreater(attention_after_plan_gate_ingest, 0)

        # 7–8. Human approves plan gate (scope local_workspace_only).
        after_plan_gate = self.controller.decide(
            plan_gate_item["action_id"],
            {
                "decision_type": "approve",
                "scope": "local_workspace_only",
                "rationale": "approve local-only architecture boundary",
            },
        )
        resolved_item = next(
            i for i in after_plan_gate["queue"] if i["action_id"] == plan_gate_item["action_id"]
        )
        self.assertEqual(resolved_item["decision"], original_plan_gate_decision)
        self.assertEqual(resolved_item["lifecycle_status"], LIFECYCLE_RESOLVED_GATE)
        self.assertTrue(after_plan_gate["run_loop"]["resolved_plan_gates"])
        self.assertTrue(after_plan_gate["run_loop"]["derived_lifecycle_resolutions"])
        unresolved_after = set(after_plan_gate["needs_attention"]["unresolved_plan_gates"])
        self.assertTrue(unresolved_after < unresolved_before)
        self.assertLess(
            after_plan_gate["mission_summary"]["needs_attention_count"],
            attention_after_plan_gate_ingest,
        )
        self.assertNotIn(
            plan_gate_item["action_id"],
            {a["action_id"] for a in after_plan_gate["needs_attention"]["approval_needed"]},
        )

        packet_state = self.controller.generate_next_instruction_packet()
        packet = packet_state["run_loop"]["instruction_packets"][-1]
        joined_gates = "\n".join(packet["open_gates_summary"])
        for gate in after_plan_gate["run_loop"]["resolved_plan_gates"]:
            self.assertNotIn(f"Unresolved plan gate: {gate['gate_id']}.", joined_gates)
        self.assertIn("Human-resolved plan gate:", joined_gates)
        self.assertIn("local_workspace_only", joined_gates)

        # 5 (negative-only) via bridge: boundary fixture must not surface ALLOW side effects.
        _bridge_write(self.controller, self.workspace)
        _write_response(self.workspace, _load_fixture(NEGATIVE_ONLY_FIXTURE))
        negative_turn = _bridge_ingest(self.controller, self.workspace)
        for item in negative_turn["queue"]:
            if item["action_type"] in ("install_dependency", "git_push", "deploy_code"):
                self.assertNotEqual(item["decision"], "ALLOW")

        # Turn 2: multi-action fixture (install, push, edit, claim).
        _bridge_write(self.controller, self.workspace)
        _write_response(self.workspace, _load_fixture(MULTI_ACTION_FIXTURE))
        turn2 = _bridge_ingest(self.controller, self.workspace)
        queue_after_turn2 = len(turn2["queue"])
        self.assertGreater(queue_after_turn2, queue_len_after_turn1)
        action_types = {i["action_type"] for i in turn2["queue"]}
        self.assertIn("install_dependency", action_types)
        self.assertIn("git_push", action_types)
        self.assertIn("edit_file", action_types)
        self.assertIn("claim_status", action_types)

        install_item = next(i for i in turn2["queue"] if i["action_type"] == "install_dependency")
        self.assertEqual(install_item["decision"], "REQUEST_MORE_EVIDENCE")
        install_action_id = install_item["action_id"]
        original_install_decision = copy.deepcopy(
            turn2["run_envelopes"][install_action_id]["decision"]
        )

        # 9–10. Human evidence A then B; cumulative, append-only, no regression.
        after_evidence_a = self.controller.provide_evidence(
            install_action_id,
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Trusted maintainer; package used in prior internal demos.",
            },
        )
        item_a = next(i for i in after_evidence_a["queue"] if i["action_id"] == install_action_id)
        self.assertNotIn("package_trust_review", item_a["missing_evidence"])
        self.assertEqual(item_a["lifecycle_status"], LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED)
        records_a = [
            r
            for r in after_evidence_a["run_loop"]["evidence_records"]
            if r["action_id"] == install_action_id
        ]
        self.assertEqual(len(records_a), 1)

        after_evidence_b = self.controller.provide_evidence(
            install_action_id,
            {
                "evidence_type": "license_compatibility",
                "evidence_text": "MIT license is compatible with this local-only demo.",
            },
        )
        item_b = next(i for i in after_evidence_b["queue"] if i["action_id"] == install_action_id)
        self.assertNotIn("package_trust_review", item_b["missing_evidence"])
        self.assertNotIn("license_compatibility", item_b["missing_evidence"])
        records_b = [
            r
            for r in after_evidence_b["run_loop"]["evidence_records"]
            if r["action_id"] == install_action_id
        ]
        self.assertEqual(len(records_b), 2)
        self.assertEqual(records_b[0]["evidence_type"], "package_trust_review")
        self.assertEqual(records_b[1]["evidence_type"], "license_compatibility")
        self.assertEqual(
            after_evidence_b["run_envelopes"][install_action_id]["decision"],
            original_install_decision,
        )

        # 11. Approve side-effecting action (git_push; edit_file is ALLOW in fixtures).
        push_item = next(i for i in after_evidence_b["queue"] if i["action_type"] == "git_push")
        original_push_decision = push_item["decision"]
        attention_before_push = after_evidence_b["mission_summary"]["needs_attention_count"]
        after_push = self.controller.decide(
            push_item["action_id"],
            {
                "decision_type": "approve",
                "scope": "local_workspace_only",
                "rationale": "approve local push gate only",
            },
        )
        push_resolved = next(i for i in after_push["queue"] if i["action_id"] == push_item["action_id"])
        self.assertEqual(push_resolved["decision"], original_push_decision)
        self.assertEqual(push_resolved["execution_status"], EXECUTION_STATUS_ADMITTED_NOT_EXECUTED)
        self.assertEqual(push_resolved["lifecycle_status"], LIFECYCLE_ADMITTED_NOT_EXECUTED)
        self.assertLess(after_push["mission_summary"]["needs_attention_count"], attention_before_push)
        self.assertNotIn(
            push_item["action_id"],
            {a["action_id"] for a in after_push["needs_attention"]["approval_needed"]},
        )
        self.assertFalse((self.workspace / "src" / "game.js").exists())

        # 13–14. Duplicate bridge ingest is blocked; no duplicate queue item; diagnostic recorded.
        queue_before_duplicate = len(after_push["queue"])
        with self.assertRaises(DuplicateResponseError):
            _bridge_ingest(self.controller, self.workspace)
        self.assertEqual(len(self.controller.state_view()["queue"]), queue_before_duplicate)
        blocked = [
            e
            for e in self.controller.session_dict()["transcript"]
            if e["type"] == "bridge_ingest_blocked"
        ]
        self.assertTrue(blocked)
        self.assertEqual(blocked[-1]["payload"]["reason"], "duplicate_response")

        # 15–16. Export and reload preserve append-only history.
        exported = self.controller.session_dict()
        self.assertEqual(exported["schema_version"], "admissible_control_surface_session_v0")
        self.assertTrue(exported["human_decisions"])
        self.assertTrue(exported["run_loop"]["derived_lifecycle_resolutions"])
        self.assertTrue(exported["run_loop"]["resolved_plan_gates"])
        self.assertTrue(exported["run_loop"]["evidence_records"])
        self.assertTrue(any(e["type"] == "bridge_ingest_blocked" for e in exported["transcript"]))

        reloaded_controller = _controller(self.root / "reload")
        imported = reloaded_controller.import_session(exported)
        self.assertEqual(
            len(imported["human_decisions"]),
            len(exported["human_decisions"]),
        )
        self.assertEqual(
            len(imported["run_loop"]["derived_lifecycle_resolutions"]),
            len(exported["run_loop"]["derived_lifecycle_resolutions"]),
        )
        self.assertEqual(
            len(imported["run_loop"]["resolved_plan_gates"]),
            len(exported["run_loop"]["resolved_plan_gates"]),
        )
        self.assertEqual(
            len(imported["run_loop"]["evidence_records"]),
            len(exported["run_loop"]["evidence_records"]),
        )
        reloaded_push = next(i for i in imported["queue"] if i["action_id"] == push_item["action_id"])
        self.assertEqual(reloaded_push["lifecycle_status"], LIFECYCLE_ADMITTED_NOT_EXECUTED)
        reloaded_plan_gate = next(
            i for i in imported["queue"] if i["action_id"] == plan_gate_item["action_id"]
        )
        self.assertEqual(reloaded_plan_gate["lifecycle_status"], LIFECYCLE_RESOLVED_GATE)
        self.assertEqual(
            imported["run_envelopes"][plan_gate_item["action_id"]]["decision"]["decision"],
            exported["run_envelopes"][plan_gate_item["action_id"]]["decision"]["decision"],
        )
        json.dumps(imported)

        final_view = self.controller.state_view()
        self.assertFalse(final_view["mission_summary"]["side_effect_executed_by_admissible"])
        self.assertFalse(any(i.get("execution_status") == "executed_after_admission" for i in final_view["queue"]))


class TestCanonicalDemoFixturesPinned(unittest.TestCase):
    """Guard that committed fixtures remain available for the demo regression."""

    def test_required_fixture_files_exist(self) -> None:
        for name in (
            PLAN_GATE_FIXTURE,
            MULTI_ACTION_FIXTURE,
            NEGATIVE_ONLY_FIXTURE,
            "evidence_response_for_request_more_evidence.txt",
        ):
            path = FIXTURES_DIR / name
            self.assertTrue(path.is_file(), f"missing fixture: {name}")
            self.assertTrue(_load_fixture(name).strip())


if __name__ == "__main__":
    unittest.main()
