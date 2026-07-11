"""RUN_048 deterministic probe-harness tests (PART J.31/32, PART D exactly-once).

Every test is fully deterministic — the real-model harness paths are exercised
with the in-memory fake ACP server; no real subprocess, no provider call.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "admissible"
if str(FIXTURES_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURES_DIR))

import fake_acp_server as fake  # noqa: E402

from admissible.agent_backend import BACKEND_ID_CURSOR_ACP, build_invocation_record  # noqa: E402
from admissible.cursor_acp_transport import (  # noqa: E402
    AcpTimeouts,
    DEFAULT_TRANSPORT,
    TRANSPORT_ONESHOT,
    select_transport,
)
from admissible.diagnostics.acp_real_probe import (  # noqa: E402
    VERDICT_INSUFFICIENT,
    VERDICT_KEEP,
    VERDICT_NOT_USABLE,
    VERDICT_PROMOTE,
    AcpRealProbeHarness,
    ModelBudgetExceeded,
    ProbeAlreadyRunning,
    classify_response_deviation,
    compute_default_transport_verdict,
    sanitize_json_line,
    sanitize_text,
)


def _fast() -> AcpTimeouts:
    return AcpTimeouts(
        handshake_seconds=2.0, request_acceptance_seconds=2.0,
        idle_no_progress_seconds=0.3, absolute_request_seconds=2.0,
        cancellation_seconds=0.5, cleanup_seconds=0.5,
    )


class TestProbeBudgetAndSerial(unittest.TestCase):
    def _harness(self):
        return AcpRealProbeHarness(max_model_calls=4)

    def _acp(self, h, scenario=fake.SCENARIO_SUCCESS, **kw):
        ws = tempfile.mkdtemp(prefix="run048t_")
        return h.run_acp_probe(
            label="t", instruction="x", workspace=ws, timeouts=_fast(),
            process_factory=fake.fake_process_factory(scenario, response_text="ok", **kw),
        )

    def test_budget_cannot_exceed_four(self) -> None:
        h = self._harness()
        for _ in range(4):
            self._acp(h)
        self.assertEqual(h.used_model_calls, 4)
        with self.assertRaises(ModelBudgetExceeded):
            self._acp(h)
        self.assertEqual(h.used_model_calls, 4)  # a rejected probe consumes nothing

    def test_probes_are_serial(self) -> None:
        h = self._harness()
        h._begin(consumes_budget=True)  # simulate an in-flight probe
        try:
            with self.assertRaises(ProbeAlreadyRunning):
                self._acp(h)
        finally:
            h._end(consumes_budget=False)

    def test_no_automatic_retry_and_failed_probe_recorded(self) -> None:
        h = self._harness()
        rec = self._acp(h, scenario=fake.SCENARIO_PROVIDER_ERROR)
        # exactly one attempt was made and it is recorded, not retried away
        self.assertEqual(h.used_model_calls, 1)
        self.assertEqual(len(h.calls), 1)
        self.assertEqual(rec.invoke_status, "failed")

    def test_no_silent_fallback_failed_acp_stays_acp(self) -> None:
        h = self._harness()
        rec = self._acp(h, scenario=fake.SCENARIO_DISCONNECT_AFTER_ACCEPTANCE)
        # a failed ACP probe is never silently retried as one-shot
        self.assertEqual(rec.transport, BACKEND_ID_CURSOR_ACP)
        self.assertNotEqual(rec.invoke_status, "success")

    def test_default_transport_unchanged(self) -> None:
        self.assertEqual(DEFAULT_TRANSPORT, TRANSPORT_ONESHOT)
        self.assertEqual(select_transport({}), TRANSPORT_ONESHOT)


class TestVerdictGate(unittest.TestCase):
    def _all_true(self) -> dict:
        return {
            "handshake_ok": True, "both_acp_terminal": True, "both_acp_usable": True,
            "structured_extraction_ok": True, "identities_stable": True,
            "no_duplicate_ingest": True, "no_uncertain_completion": True,
            "no_orphan_or_cleanup_failure": True, "no_silent_fallback": True,
            "health_healthy": True, "both_acp_calls_in_promotable_config": True,
            "full_suite_passes": True, "any_acp_usable": True,
        }

    def test_all_conditions_true_promotes(self) -> None:
        self.assertEqual(compute_default_transport_verdict(self._all_true()), VERDICT_PROMOTE)

    def test_missing_promotable_config_keeps_experimental(self) -> None:
        ev = self._all_true()
        ev["both_acp_calls_in_promotable_config"] = False  # e.g. one call pre-fix
        self.assertEqual(compute_default_transport_verdict(ev), VERDICT_KEEP)

    def test_hard_failure_marks_not_usable(self) -> None:
        ev = {"acp_hard_failure": True}
        self.assertEqual(compute_default_transport_verdict(ev), VERDICT_NOT_USABLE)

    def test_no_evidence_is_insufficient(self) -> None:
        self.assertEqual(compute_default_transport_verdict({}), VERDICT_INSUFFICIENT)

    def test_run048_evidence_yields_keep(self) -> None:
        # The actual RUN_048 evidence: everything passed EXCEPT that A1 ran in
        # agent mode before the plan-mode fix, so only one real ACP call
        # exercised the promotable (plan-mode) config.
        ev = self._all_true()
        ev["both_acp_calls_in_promotable_config"] = False
        self.assertEqual(compute_default_transport_verdict(ev), VERDICT_KEEP)


class TestRedaction(unittest.TestCase):
    def test_text_redaction(self) -> None:
        out = sanitize_text("mail a@b.co token " + ("ab12cd34" * 6))
        self.assertNotIn("a@b.co", out)
        self.assertIn("<email>", out)
        self.assertIn("<token>", out)

    def test_json_key_redaction_and_bounding(self) -> None:
        line = json.dumps({"authMethods": ["x"], "token": "z" * 80, "nested": {"secret": "s"}})
        red = sanitize_json_line(line)
        self.assertEqual(red["token"], "<redacted>")
        self.assertEqual(red["nested"]["secret"], "<redacted>")

    def test_non_json_falls_back_to_text_sanitize(self) -> None:
        red = sanitize_json_line("not json a@b.co")
        self.assertIn("_raw", red)
        self.assertIn("<email>", red["_raw"])


class TestFormattingVsProtocol(unittest.TestCase):
    def test_exact_match(self) -> None:
        self.assertEqual(
            classify_response_deviation(expected="OK", actual="OK", terminal_ok=True), "exact_match"
        )

    def test_formatting_deviation_is_not_protocol_failure(self) -> None:
        # a usable terminal with extra whitespace/framing is a formatting deviation
        self.assertEqual(
            classify_response_deviation(expected="OK", actual="OK\n", terminal_ok=True),
            "exact_match",
        )
        self.assertEqual(
            classify_response_deviation(expected="OK", actual="Result: OK done", terminal_ok=True),
            "formatting_deviation",
        )

    def test_no_terminal_is_protocol_failure(self) -> None:
        self.assertEqual(
            classify_response_deviation(expected="OK", actual="", terminal_ok=False),
            "protocol_failure",
        )


class TestExactlyOnceOfflineReplay(unittest.TestCase):
    """PART D.12/13 — replaying a terminal must not duplicate ingest; identity is
    backend id + ACP request id + response hash."""

    def _result(self, request_id, response_text):
        from admissible.agent_backend import AGENT_INVOKE_SUCCESS, AgentInvocationResult

        return AgentInvocationResult(
            status=AGENT_INVOKE_SUCCESS,
            response_text=response_text,
            transport_kind=BACKEND_ID_CURSOR_ACP,
            acp_request_id=request_id,
        )

    def test_replayed_terminal_yields_same_identity(self) -> None:
        r1 = self._result("req-abc", "ADMISSIBLE_ACP_TINY_PROBE_OK")
        r2 = self._result("req-abc", "ADMISSIBLE_ACP_TINY_PROBE_OK")  # replay
        rec1 = build_invocation_record(r1, backend_id=BACKEND_ID_CURSOR_ACP,
                                       instruction_id="i", session_id="s", turn_number=1)
        rec2 = build_invocation_record(r2, backend_id=BACKEND_ID_CURSOR_ACP,
                                       instruction_id="i", session_id="s", turn_number=1)
        key1 = (rec1.backend_id, rec1.acp_request_id, rec1.response_sha256)
        key2 = (rec2.backend_id, rec2.acp_request_id, rec2.response_sha256)
        self.assertEqual(key1, key2)  # same identity -> dedup, no second ingest

    def test_different_request_id_is_distinct(self) -> None:
        r1 = self._result("req-abc", "same text")
        r2 = self._result("req-xyz", "same text")
        rec1 = build_invocation_record(r1, backend_id=BACKEND_ID_CURSOR_ACP,
                                       instruction_id="i", session_id="s", turn_number=1)
        rec2 = build_invocation_record(r2, backend_id=BACKEND_ID_CURSOR_ACP,
                                       instruction_id="i", session_id="s", turn_number=1)
        self.assertNotEqual(rec1.acp_request_id, rec2.acp_request_id)


class TestFourCallMatrixFixture(unittest.TestCase):
    def test_fixture_records_four_successful_probes(self) -> None:
        data = json.loads((FIXTURES_DIR / "run048_four_call_matrix.json").read_text(encoding="utf-8"))
        self.assertEqual(data["budget"], {"max_model_calls": 4, "used_model_calls": 4})
        calls = {c["label"]: c for c in data["calls"]}
        self.assertEqual(len(calls), 4)
        for c in calls.values():
            self.assertEqual(c["invoke_status"], "success")
            self.assertTrue(c["cleanup_complete"])
            self.assertEqual(c["remaining_process_ids"], [])
        # structured probes each extracted exactly one operation
        self.assertEqual(calls["B1_acp_struct"]["structured_operation_count"], 1)
        self.assertEqual(calls["B2_oneshot_struct"]["structured_operation_count"], 1)
        # the ACP structured probe's live transcript confirms session/set_mode
        methods = [s.get("method") for s in calls["B1_acp_struct"]["transcript_sequence"] if s.get("method")]
        self.assertIn("session/set_mode", methods)
        self.assertIn("session/prompt", methods)


if __name__ == "__main__":
    unittest.main()
