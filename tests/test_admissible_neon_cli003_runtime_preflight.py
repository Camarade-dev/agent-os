"""ADMISSIBLE_NEON_RUNTIME_PLAN_OFFLINE_PREFLIGHT — cli-003 contract.

Offline proof that the corrected 15-criterion / 8-path Neon Serpents Mission
Contract schedules bounded browser runtime verification after static
verification, without any real provider or browser call.
"""

from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider
from admissible.browser_runtime.plan_builder import build_runtime_verification_plan
from admissible.high_autonomy_controller import (
    HA_NEXT_START_RUNTIME_VERIFICATION,
    _plan_next_action,
)
from admissible.mission_contract import (
    build_mission_contract,
    contract_acceptance_ledger,
    extract_runtime_observability_intent,
)
from admissible.runtime_verification_orchestrator import assess_runtime_need, prepare_runtime_attempt

from tests._run044_helpers import force_static_verification_final, make_controller, start_run

FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "admissible"
    / "neon_serpents_cli_003_contract_regression.json"
)

EXPECTED_MANDATORY_PATHS = [
    "index.html",
    "style.css",
    "src/main.js",
    "src/game.js",
    "src/entities.js",
    "src/bots.js",
    "src/render.js",
    "LOCAL_DEV.md",
]

EXPECTED_SNAPSHOT_FIELDS = [
    "phase",
    "player",
    "botCount",
    "pelletCount",
    "leaderboard",
    "respawnCount",
    "loopCount",
    "debugVisible",
]


def _goal() -> str:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["goal_text"]


def _contract_and_ledger():
    contract = build_mission_contract(_goal()).to_dict()
    ledger = contract_acceptance_ledger(contract)
    return contract, ledger


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("offline preflight must not spawn a real subprocess")


class TestNeonCli003RuntimePreflight(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract, cls.ledger = _contract_and_ledger()
        cls.by_number = {
            c.get("source_number"): c for c in cls.contract["explicit_acceptance_criteria"]
        }

    def test_exactly_fifteen_criteria_and_eight_paths(self) -> None:
        self.assertEqual(len(self.contract["explicit_acceptance_criteria"]), 15)
        self.assertEqual(self.contract["mandatory_paths"], EXPECTED_MANDATORY_PATHS)
        self.assertEqual(len(self.by_number[13].get("subrequirements") or []), 8)

    def test_runtime_verification_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            assessment = assess_runtime_need(self.contract, self.ledger, workspace_root=td)
        self.assertTrue(assessment.required)
        self.assertEqual(assessment.reason, "deterministic_runtime_criteria_unresolved")
        self.assertGreaterEqual(len(assessment.executable_now_criterion_ids), 1)

    def test_validated_runtime_plan_is_produced(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            assessment = assess_runtime_need(self.contract, self.ledger, workspace_root=td)
            plan = assessment.plan
            provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {field: 0 for field in EXPECTED_SNAPSHOT_FIELDS}})
            attempt, transition = prepare_runtime_attempt(
                session_id="preflight",
                mission_contract=self.contract,
                ledger=self.ledger,
                plan=plan,
                provider=provider,
            )
        self.assertIsNotNone(attempt)
        self.assertEqual(transition.next_step, "start")
        self.assertEqual(transition.semantic_status, "runtime_verification_pending")

    def test_debug_interface_and_eight_snapshot_fields_are_represented(self) -> None:
        intent = extract_runtime_observability_intent(self.contract)
        self.assertEqual(intent["declared_debug_interface"], "window.__NEON__")
        self.assertEqual(intent["required_snapshot_fields"], EXPECTED_SNAPSHOT_FIELDS)
        self.assertIn("?debug=1", intent["query_flags"])

        with tempfile.TemporaryDirectory() as td:
            plan, _ = build_runtime_verification_plan(
                self.contract, self.ledger, workspace_root=td, entrypoint_path="index.html"
            )
        self.assertEqual(plan.entrypoint_path, "index.html")
        self.assertEqual(plan.debug_interface, "window.__NEON__")
        debug_steps = [
            s
            for s in plan.steps
            if s.get("criterion_id") == self.ledger[12]["criterion_id"]
            and s.get("type") == "assert_json_path_present"
        ]
        self.assertEqual({s["path"] for s in debug_steps}, set(EXPECTED_SNAPSHOT_FIELDS))

    def test_bot_count_threshold_twelve_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            plan, _ = build_runtime_verification_plan(
                self.contract, self.ledger, workspace_root=td, entrypoint_path="index.html"
            )
        bot_steps = [
            s
            for s in plan.steps
            if s.get("type") == "assert_json_path_gte" and s.get("path") == "botCount" and s.get("expected") == 12
        ]
        self.assertEqual(len(bot_steps), 1)

    def test_loop_and_respawn_lifecycle_checks_where_supported(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            plan, _ = build_runtime_verification_plan(
                self.contract, self.ledger, workspace_root=td, entrypoint_path="index.html"
            )
        c13 = self.ledger[12]["criterion_id"]
        loop_increase = [
            s for s in plan.steps if s.get("criterion_id") == c13 and s.get("type") == "compare_snapshot_path_increased"
        ]
        respawn_present = [
            s
            for s in plan.steps
            if s.get("criterion_id") == c13 and s.get("type") == "assert_json_path_present" and s.get("path") == "respawnCount"
        ]
        self.assertEqual(len(loop_increase), 1)
        self.assertEqual(loop_increase[0]["path"], "loopCount")
        self.assertEqual(len(respawn_present), 1)

    def test_human_criteria_remain_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            plan, coverage = build_runtime_verification_plan(
                self.contract, self.ledger, workspace_root=td, entrypoint_path="index.html"
            )
        by_id = {c.criterion_id: c for c in plan.criteria}
        # RUN_053: criterion 5 ("visibly represented as a continuous
        # multi-segment serpent... body follows the head") is now also
        # correctly routed to human observation -- it names no numeric
        # threshold or control, so it stays inherently visual/experiential
        # rather than silently sitting as untouched "evidence_required".
        human_only = {
            self.ledger[4]["criterion_id"],
            self.ledger[13]["criterion_id"],
            self.ledger[14]["criterion_id"],
        }
        for cid in human_only:
            self.assertEqual(by_id[cid].disposition, "human_observation_required")
            self.assertTrue(by_id[cid].human_observation_required)
        # Criterion 4 keeps a subjective smoothness sub-aspect while also runtime-checkable.
        c4 = by_id[self.ledger[3]["criterion_id"]]
        self.assertEqual(c4.disposition, "deterministic_runtime")
        self.assertTrue(c4.human_observation_required)
        self.assertEqual(set(coverage["human_observation_criterion_ids"]), human_only | {self.ledger[3]["criterion_id"]})

    def test_controller_next_action_is_start_runtime_verification(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            workspace = root_path / "workspace"
            controller = make_controller(root_path)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                start_run(controller, _goal(), workspace, max_turns=8)
                controller.set_runtime_provider(FixtureBrowserRuntimeProvider({"initial_snapshot": {}}))
                force_static_verification_final(controller, workspace)
                ha_state = controller._high_autonomy_state()
                from admissible.high_autonomy_controller import HighAutonomyPolicy

                next_action = _plan_next_action(
                    controller,
                    ha_state,
                    HighAutonomyPolicy(),
                    controller._high_autonomy_transport,
                )
        self.assertEqual(next_action, HA_NEXT_START_RUNTIME_VERIFICATION)
        self.assertTrue(ha_state.runtime_verification_required)

    def test_no_real_provider_or_network_call(self) -> None:
        original_connect = socket.socket.connect

        def _blocked(self, *args, **kwargs):  # pragma: no cover
            raise AssertionError("offline preflight attempted a network call")

        socket.socket.connect = _blocked
        try:
            contract, ledger = _contract_and_ledger()
            with tempfile.TemporaryDirectory() as td:
                assessment = assess_runtime_need(contract, ledger, workspace_root=td)
                provider = FixtureBrowserRuntimeProvider({"initial_snapshot": {}})
                prepare_runtime_attempt(
                    session_id="preflight",
                    mission_contract=contract,
                    ledger=ledger,
                    plan=assessment.plan,
                    provider=provider,
                )
                self.assertEqual(provider.detect_capability().provider_id, "fixture")
        finally:
            socket.socket.connect = original_connect


if __name__ == "__main__":
    unittest.main()
