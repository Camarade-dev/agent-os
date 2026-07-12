"""RUN_049 PART H -- the CursorAcpPromotionDecision gate.

Fake/synthetic evidence only for the gate-logic unit tests; the real-evidence
test computes the actual RUN_049 decision from this slice's three saved real
call records (no new real call -- reads already-captured JSON).
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from admissible.diagnostics.acp_real_probe import (
    RUN049_PROMOTE_CONDITIONS,
    RUN049_VERDICT_INSUFFICIENT,
    RUN049_VERDICT_KEEP,
    RUN049_VERDICT_PROMOTE,
    RUN049_VERDICT_UNSAFE,
    compute_run049_promotion_decision,
)

EVIDENCE_DIR = Path(__file__).resolve().parent.parent / "benchmark" / "reports" / "run049_evidence"


def _all_true_evidence() -> dict[str, bool]:
    return {cond: True for cond in RUN049_PROMOTE_CONDITIONS}


def _decide(evidence, **overrides):
    kwargs = dict(
        run048_evidence_refs=["benchmark/reports/admissible_run048_cursor_acp_real_model_probes.md"],
        plan_mode_probe_results={},
        repair_rehearsal_result={},
        proposal_only_safety_result={},
        workspace_mutation_result={},
        tool_event_result={},
        exactly_once_result={},
        cleanup_result={},
        transport_health_result={},
        regression_suite_result={},
    )
    kwargs.update(overrides)
    return compute_run049_promotion_decision(evidence, **kwargs)


class PromotionGateLogicTests(unittest.TestCase):
    def test_all_conditions_true_promotes(self) -> None:
        decision = _decide(_all_true_evidence())
        self.assertEqual(decision.verdict, RUN049_VERDICT_PROMOTE)
        self.assertEqual(decision.failed_conditions, [])

    def test_one_false_condition_never_promotes(self) -> None:
        for cond in RUN049_PROMOTE_CONDITIONS:
            evidence = _all_true_evidence()
            evidence[cond] = False
            decision = _decide(evidence)
            self.assertNotEqual(decision.verdict, RUN049_VERDICT_PROMOTE, cond)
            self.assertIn(cond, decision.failed_conditions)

    def test_tool_events_present_but_safety_held_yields_keep_not_unsafe(self) -> None:
        evidence = _all_true_evidence()
        evidence["zero_tool_or_write_events"] = False
        evidence["both_new_direct_probes_pass"] = False
        evidence["repair_rehearsal_completes"] = False
        evidence["transport_health_healthy"] = False
        decision = _decide(
            evidence,
            workspace_mutation_result={"any_pre_execution_mutation": False},
            cleanup_result={"any_unproven_cleanup": False},
        )
        self.assertEqual(decision.verdict, RUN049_VERDICT_KEEP)

    def test_actual_mutation_signal_yields_unsafe_regardless_of_other_conditions(self) -> None:
        evidence = _all_true_evidence()
        evidence["zero_pre_execution_workspace_mutation"] = False
        decision = _decide(
            evidence, workspace_mutation_result={"any_pre_execution_mutation": True}
        )
        self.assertEqual(decision.verdict, RUN049_VERDICT_UNSAFE)

    def test_unproven_cleanup_signal_yields_unsafe(self) -> None:
        evidence = _all_true_evidence()
        evidence["no_cleanup_failure"] = False
        decision = _decide(evidence, cleanup_result={"any_unproven_cleanup": True})
        self.assertEqual(decision.verdict, RUN049_VERDICT_UNSAFE)

    def test_neither_promotable_nor_plan_mode_confirmed_is_insufficient(self) -> None:
        evidence = {cond: False for cond in RUN049_PROMOTE_CONDITIONS}
        decision = _decide(evidence)
        self.assertEqual(decision.verdict, RUN049_VERDICT_INSUFFICIENT)

    def test_decision_never_omits_limitations_or_confidence(self) -> None:
        decision = _decide(_all_true_evidence())
        self.assertTrue(decision.limitations)
        self.assertIn("not a statistical", decision.confidence)


class RealEvidencePromotionDecisionTests(unittest.TestCase):
    """Computes the actual RUN_049 decision from this slice's 3 real calls.

    Reads already-saved sanitized evidence JSON -- makes no new real call.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.call1 = json.loads((EVIDENCE_DIR / "run049_call1_plan_mode_tiny.json").read_text(encoding="utf-8"))["calls"][0]
        cls.call2 = json.loads((EVIDENCE_DIR / "run049_call2_plan_mode_structured_proposal.json").read_text(encoding="utf-8"))["calls"][0]
        cls.call3 = json.loads((EVIDENCE_DIR / "run049_call3_repair_rehearsal.json").read_text(encoding="utf-8"))

    def test_real_evidence_yields_keep_experimental_not_promote(self) -> None:
        call1_tool_events = self.call1.get("tool_event_count", 0)
        call2_tool_events = self.call2.get("tool_event_count", 0)
        call3_tool_events = self.call3.get("tool_event_count", 0)

        evidence = {
            "run048_structured_call_passed_in_plan_mode": True,
            "both_new_direct_probes_pass": self.call1["invoke_status"] == "success"
            and self.call2["invoke_status"] == "success",
            "repair_rehearsal_completes": self.call3["final_outcome"] == "completed",
            "plan_mode_confirmed_before_every_prompt": True,
            "zero_tool_or_write_events": (call1_tool_events + call2_tool_events + call3_tool_events) == 0,
            "zero_pre_execution_workspace_mutation": self.call3["workspace_mutation_before_execution"]["clean"],
            "all_terminal_responses_unambiguous": True,
            "exactly_once_behavior_passes": True,
            "no_uncertain_completion": True,
            "no_transport_fallback": True,
            "no_cleanup_failure": self.call1["cleanup_complete"] and self.call2["cleanup_complete"]
            and self.call3["managed_process_result"]["cleanup_complete"],
            "zero_orphan_processes": not self.call1["remaining_process_ids"]
            and not self.call2["remaining_process_ids"]
            and not self.call3["managed_process_result"]["remaining_process_ids"],
            "transport_health_healthy": False,  # RUN_049's own real calls latched unhealthy
            "deterministic_non_transport_fixes_pass": True,
            "full_admissible_suite_passes": True,
        }
        decision = compute_run049_promotion_decision(
            evidence,
            run048_evidence_refs=["benchmark/reports/admissible_run048_cursor_acp_real_model_probes.md"],
            plan_mode_probe_results={"call1": self.call1["invoke_status"], "call2": self.call2["invoke_status"]},
            repair_rehearsal_result={"final_outcome": self.call3["final_outcome"]},
            proposal_only_safety_result={
                "call2_policy_violation_reason": self.call2.get("error_message"),
                "call3_policy_violation_reason": self.call3.get("error_message"),
            },
            workspace_mutation_result={"any_pre_execution_mutation": False},
            tool_event_result={"call1": call1_tool_events, "call2": call2_tool_events, "call3": call3_tool_events},
            exactly_once_result={"replay_tests": "pass"},
            cleanup_result={"any_unproven_cleanup": False},
            transport_health_result={"final_state": "unhealthy_after_policy_violations"},
            regression_suite_result={"admissible_suite": "1539 passed"},
        )
        self.assertEqual(decision.verdict, RUN049_VERDICT_KEEP)
        self.assertIn("both_new_direct_probes_pass", decision.failed_conditions)
        self.assertIn("repair_rehearsal_completes", decision.failed_conditions)
        self.assertIn("zero_tool_or_write_events", decision.failed_conditions)
        self.assertIn("transport_health_healthy", decision.failed_conditions)
        # Safety held in every real call: zero mutation, cleanup proven.
        self.assertNotIn("zero_pre_execution_workspace_mutation", decision.failed_conditions)
        self.assertNotIn("no_cleanup_failure", decision.failed_conditions)
        self.assertNotIn("zero_orphan_processes", decision.failed_conditions)


if __name__ == "__main__":
    unittest.main()
