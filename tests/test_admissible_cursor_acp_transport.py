"""ACP transport tests (slice ADMISSIBLE_RUN_047, PART K, tests 5-19).

Every test drives the deterministic in-memory fake ACP server — no real
subprocess, no model call.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "admissible"
if str(FIXTURES_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURES_DIR))

import fake_acp_server as fake  # noqa: E402

from admissible.agent_backend import (  # noqa: E402
    AGENT_INVOKE_EMPTY_SUCCESS,
    AGENT_INVOKE_FAILED,
    AGENT_INVOKE_SUCCESS,
    AGENT_INVOKE_TIMEOUT,
    BACKEND_ID_CURSOR_ACP,
    AgentInvocationRequest,
    build_invocation_record,
    describe_available_backends,
)
from admissible.cursor_acp_transport import (  # noqa: E402
    DEFAULT_TRANSPORT,
    STATE_CLEANUP_FAILED,
    STATE_COMPLETED,
    STATE_PROTOCOL_ERROR,
    STATE_UNCERTAIN_COMPLETION,
    TRANSPORT_ACP,
    TRANSPORT_LABEL_ACP,
    TRANSPORT_ONESHOT,
    AcpTimeouts,
    CursorAcpBackend,
    select_transport,
)
from admissible.long_run_envelope_builder import extract_structured_operation_blocks
from admissible.transport_health import (
    HEALTH_DEGRADED,
    HEALTH_UNHEALTHY,
    TransportHealth,
)


def _fast_timeouts(**overrides) -> AcpTimeouts:
    base = dict(
        server_start_seconds=2.0,
        handshake_seconds=2.0,
        request_acceptance_seconds=2.0,
        idle_no_progress_seconds=0.25,
        absolute_request_seconds=2.0,
        cancellation_seconds=0.5,
        cleanup_seconds=0.5,
    )
    base.update(overrides)
    return AcpTimeouts(**base)


class _AcpTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        root = Path(self._tmp.name)
        self.target_ws = root / "target"
        self.agent_ws = root / "agent"
        self.target_ws.mkdir()
        self.agent_ws.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _request(self, instruction: str = "Do the task.") -> AgentInvocationRequest:
        return AgentInvocationRequest(
            instruction_text=instruction,
            session_id="acp_test",
            turn_number=1,
            instruction_id="instr-1",
            target_workspace_path=str(self.target_ws),
            agent_workspace_path=str(self.agent_ws),
        )

    def _backend(self, scenario: str, *, health: TransportHealth | None = None, timeouts=None, **kw):
        return CursorAcpBackend(
            process_factory=fake.fake_process_factory(scenario, **kw),
            health=health if health is not None else TransportHealth(backend_id=BACKEND_ID_CURSOR_ACP),
            timeouts=timeouts or _fast_timeouts(),
        )

    def _invoke(self, scenario: str, instruction: str = "Do the task.", **kw):
        backend = self._backend(scenario, **kw)
        result = backend.invoke(self._request(instruction))
        return backend, result


class TestAcpHappyPath(_AcpTestBase):
    def test_05_handshake_succeeds_against_fake_server(self) -> None:
        backend, result = self._invoke(
            fake.SCENARIO_SUCCESS, response_text="All good.", progress_count=2
        )
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertTrue(result.ok)
        self.assertEqual(result.response_text, "All good.")
        self.assertEqual(result.acp_protocol_version, 1)
        self.assertEqual(result.transport_kind, BACKEND_ID_CURSOR_ACP)
        self.assertIsNotNone(result.acp_request_id)
        self.assertEqual(result.acp_invocation_state, STATE_COMPLETED)

    def test_09_terminal_response_becomes_one_canonical_response(self) -> None:
        _backend, result = self._invoke(
            fake.SCENARIO_SUCCESS, response_text="Canonical body.", progress_count=3
        )
        # exactly one canonical response object, of the shared result type
        self.assertEqual(result.response_text, "Canonical body.")
        telemetry = result.acp_telemetry
        self.assertEqual(telemetry["counters"]["usable_responses"], 1)
        self.assertEqual(telemetry["counters"]["model_turns"], 1)
        # progress was persisted in bounded form (not an unbounded token stream)
        self.assertGreaterEqual(telemetry["progress_event_count"], 1)
        for event in telemetry["progress_events"]:
            self.assertLessEqual(len((event["summary"] or "")), 201)

    def test_10_duplicate_terminal_event_does_not_duplicate_ingest(self) -> None:
        _backend, result = self._invoke(
            fake.SCENARIO_DUPLICATE_TERMINAL, response_text="Once.", progress_count=1
        )
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        # response text is not doubled and only one usable response recorded
        self.assertEqual(result.response_text, "Once.")
        self.assertEqual(result.acp_telemetry["counters"]["usable_responses"], 1)
        # exactly-once ingest key: backend_id + acp_request_id + response hash
        record = build_invocation_record(
            result,
            backend_id=BACKEND_ID_CURSOR_ACP,
            instruction_id="instr-1",
            session_id="acp_test",
            turn_number=1,
        )
        self.assertEqual(record.acp_request_id, result.acp_request_id)
        self.assertIsNotNone(record.response_sha256)

    def test_16_acp_response_preserves_structured_operation_extraction(self) -> None:
        body = (
            "Here is the change.\n\n"
            "ADMISSIBLE_STRUCTURED_OPERATION:\n"
            "```json\n"
            '{"operation": "write_file", "path": "index.html", "content": "<html></html>"}\n'
            "```\n"
        )
        _backend, result = self._invoke(
            fake.SCENARIO_SUCCESS, response_text=body, progress_count=4
        )
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        blocks = extract_structured_operation_blocks(result.response_text)
        self.assertEqual(len(blocks), 1)


class TestAcpProtocolFailures(_AcpTestBase):
    def test_06_unsupported_protocol_version_fails_explicitly(self) -> None:
        _backend, result = self._invoke(fake.SCENARIO_UNSUPPORTED_PROTOCOL)
        self.assertEqual(result.status, AGENT_INVOKE_FAILED)
        self.assertEqual(result.acp_invocation_state, STATE_PROTOCOL_ERROR)
        self.assertIn("protocolVersion", result.error_message)
        self.assertEqual(result.acp_protocol_version, 999)

    def test_handshake_rejection_fails(self) -> None:
        _backend, result = self._invoke(fake.SCENARIO_HANDSHAKE_REJECT)
        self.assertEqual(result.status, AGENT_INVOKE_FAILED)

    def test_provider_error_is_terminal_failure(self) -> None:
        backend, result = self._invoke(fake.SCENARIO_PROVIDER_ERROR)
        self.assertEqual(result.status, AGENT_INVOKE_FAILED)
        self.assertEqual(backend.health.provider_errors, 1)


class TestAcpTimeoutSemantics(_AcpTestBase):
    def test_07_progress_events_refresh_idle_liveness(self) -> None:
        # idle (0.15s) << absolute (0.6s); progress drips every 0.03s. If idle
        # were NOT refreshed by progress it would fire at ~0.15s; instead the
        # run survives to the absolute deadline, proving idle liveness refresh.
        health = TransportHealth(backend_id=BACKEND_ID_CURSOR_ACP)
        backend, result = self._invoke(
            fake.SCENARIO_TOTAL_TIMEOUT_PROGRESS,
            health=health,
            timeouts=_fast_timeouts(idle_no_progress_seconds=0.15, absolute_request_seconds=0.6),
            drip_interval=0.03,
        )
        self.assertEqual(result.status, AGENT_INVOKE_TIMEOUT)
        self.assertEqual(health.idle_timeouts, 0)  # idle never fired
        self.assertEqual(health.total_timeouts, 1)  # absolute fired
        self.assertGreater(result.acp_telemetry["counters"]["progress_events_total"], 3)

    def test_08_absolute_timeout_remains_bounded_despite_progress(self) -> None:
        import time

        started = time.monotonic()
        _backend, result = self._invoke(
            fake.SCENARIO_TOTAL_TIMEOUT_PROGRESS,
            timeouts=_fast_timeouts(idle_no_progress_seconds=0.2, absolute_request_seconds=0.4),
            drip_interval=0.02,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(result.status, AGENT_INVOKE_TIMEOUT)
        self.assertEqual(result.acp_invocation_state, STATE_UNCERTAIN_COMPLETION)
        # bounded: absolute (0.4s) + cancellation/cleanup grace, well under 3s
        self.assertLess(elapsed, 3.0)

    def test_idle_timeout_when_no_progress(self) -> None:
        health = TransportHealth(backend_id=BACKEND_ID_CURSOR_ACP)
        _backend, result = self._invoke(
            fake.SCENARIO_IDLE_TIMEOUT,
            health=health,
            timeouts=_fast_timeouts(idle_no_progress_seconds=0.2, absolute_request_seconds=5.0),
        )
        self.assertEqual(result.status, AGENT_INVOKE_TIMEOUT)
        self.assertEqual(health.idle_timeouts, 1)


class TestAcpDisconnectSemantics(_AcpTestBase):
    def test_11_disconnect_before_acceptance_allows_one_bounded_retry(self) -> None:
        _backend, result = self._invoke(fake.SCENARIO_DISCONNECT_BEFORE_ACCEPTANCE)
        self.assertEqual(result.status, AGENT_INVOKE_FAILED)
        # provably not accepted -> the one bounded retry is permitted
        self.assertTrue(result.acp_telemetry["retry_safe"])

    def test_12_disconnect_after_acceptance_is_uncertain_completion(self) -> None:
        health = TransportHealth(backend_id=BACKEND_ID_CURSOR_ACP)
        _backend, result = self._invoke(fake.SCENARIO_DISCONNECT_AFTER_ACCEPTANCE, health=health)
        self.assertEqual(result.status, AGENT_INVOKE_TIMEOUT)
        self.assertEqual(result.acp_invocation_state, STATE_UNCERTAIN_COMPLETION)
        self.assertFalse(result.acp_telemetry["retry_safe"])
        self.assertEqual(health.uncertain_completions, 1)

    def test_13_uncertain_completion_never_auto_retries(self) -> None:
        health = TransportHealth(backend_id=BACKEND_ID_CURSOR_ACP)
        _backend, _result = self._invoke(fake.SCENARIO_DISCONNECT_AFTER_ACCEPTANCE, health=health)
        self.assertTrue(health.blocks_automatic_retry)
        self.assertEqual(health.state, HEALTH_DEGRADED)


class TestAcpCancellationAndCleanup(_AcpTestBase):
    def test_14_cancellation_terminates_request_and_process(self) -> None:
        factory = fake.fake_process_factory(fake.SCENARIO_IDLE_TIMEOUT)
        backend = CursorAcpBackend(
            process_factory=factory,
            timeouts=_fast_timeouts(idle_no_progress_seconds=0.15, absolute_request_seconds=5.0),
        )
        result = backend.invoke(self._request())
        proc = factory.created[0]
        self.assertEqual(result.status, AGENT_INVOKE_TIMEOUT)
        self.assertTrue(proc.cancel_received)  # session/cancel was sent
        self.assertTrue(proc.terminate_called)  # process tree terminated
        self.assertTrue(result.managed_process_result["cleanup_complete"])

    def test_03_cleanup_failure_trips_circuit_breaker(self) -> None:
        health = TransportHealth(backend_id=BACKEND_ID_CURSOR_ACP)
        _backend, result = self._invoke(
            fake.SCENARIO_SUCCESS,
            health=health,
            response_text="ok",
            leak_on_terminate=True,
        )
        # a leaked tree latches unhealthy and forbids automatic retry
        self.assertEqual(health.state, HEALTH_UNHEALTHY)
        self.assertTrue(health.blocks_automatic_retry)
        self.assertTrue(health.requires_operator_recovery)
        self.assertFalse(result.managed_process_result["cleanup_complete"])
        self.assertEqual(result.acp_invocation_state, STATE_CLEANUP_FAILED)


class TestAcpBudgetAndSelector(_AcpTestBase):
    def test_17_transport_failure_does_not_consume_repair_budget(self) -> None:
        for scenario in (
            fake.SCENARIO_PROVIDER_ERROR,
            fake.SCENARIO_DISCONNECT_AFTER_ACCEPTANCE,
            fake.SCENARIO_SUCCESS,
        ):
            _backend, result = self._invoke(scenario, response_text="x")
            counters = result.acp_telemetry["counters"]
            self.assertEqual(counters["semantic_repair_rounds"], 0)
            self.assertEqual(counters["transport_attempt_count"], 1)

    def test_18_transport_selector_never_silently_falls_back(self) -> None:
        self.assertEqual(select_transport({"ADMISSIBLE_CURSOR_TRANSPORT": "acp"}), TRANSPORT_ACP)
        self.assertEqual(
            select_transport({"ADMISSIBLE_CURSOR_TRANSPORT": "oneshot"}), TRANSPORT_ONESHOT
        )
        # an unrecognized value falls back to the compatibility default, never acp
        self.assertEqual(select_transport({"ADMISSIBLE_CURSOR_TRANSPORT": "bogus"}), DEFAULT_TRANSPORT)
        self.assertEqual(select_transport({}), TRANSPORT_ONESHOT)
        self.assertEqual(DEFAULT_TRANSPORT, TRANSPORT_ONESHOT)

    def test_18b_acp_capability_gap_raises_never_downgrades(self) -> None:
        # When ACP is selected but the backend is unavailable, run start must
        # raise a technical capability gap instead of silently building one-shot.
        import admissible.cursor_acp_transport as acp_mod
        from admissible.high_autonomy_controller import _build_backend_from_id

        class _UnavailableAcp:
            backend_id = BACKEND_ID_CURSOR_ACP

            def availability(self):
                from admissible.agent_backend import (
                    AGENT_AVAILABILITY_UNAVAILABLE,
                    AgentBackendAvailability,
                )

                return AgentBackendAvailability(
                    status=AGENT_AVAILABILITY_UNAVAILABLE,
                    configured=True,
                    message="cursor-agent not found",
                )

        original = acp_mod.CursorAcpBackend
        acp_mod.CursorAcpBackend = _UnavailableAcp  # type: ignore[assignment]
        try:
            with self.assertRaises(ValueError):
                _build_backend_from_id(
                    "cursor_cli",
                    str(self.target_ws),
                    apply_transport_selection=True,
                )
        finally:
            acp_mod.CursorAcpBackend = original  # type: ignore[assignment]

    def test_19_ui_identifies_exact_transport(self) -> None:
        acp_view = {b["backend_id"]: b for b in describe_available_backends({"ADMISSIBLE_CURSOR_TRANSPORT": "acp"})}
        oneshot_view = {b["backend_id"]: b for b in describe_available_backends({"ADMISSIBLE_CURSOR_TRANSPORT": "oneshot"})}
        # the UI names the exact transport cursor_cli will resolve to
        self.assertEqual(acp_view["cursor_cli"]["transport"], "acp")
        self.assertEqual(acp_view["cursor_cli"]["transport_label"], TRANSPORT_LABEL_ACP)
        self.assertEqual(oneshot_view["cursor_cli"]["transport"], "oneshot")
        self.assertEqual(oneshot_view["cursor_cli"]["transport_label"], "Cursor Agent one-shot")
        # the discovery list keeps its stable shape (no new selectable backend id)
        self.assertEqual(set(acp_view), {"file_bridge", "cursor_cli", "fixture"})


class TestAcpPlanModeEnforcement(_AcpTestBase):
    """RUN_048 finding: session/new defaults to agent (write-capable) mode; the
    backend must force read-only plan mode for the proposal-only invariant."""

    def test_agent_mode_is_forced_to_plan(self) -> None:
        factory = fake.fake_process_factory(
            fake.SCENARIO_SUCCESS, response_text="ok", session_mode="agent"
        )
        backend = CursorAcpBackend(process_factory=factory, timeouts=_fast_timeouts())
        result = backend.invoke(self._request())
        proc = factory.created[0]
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertEqual(proc.set_mode_requested, "plan")  # client requested plan mode
        self.assertTrue(result.acp_telemetry["plan_mode_enforced"])
        self.assertEqual(result.acp_telemetry["session_mode_before"], "agent")

    def test_unsupported_set_mode_is_graceful(self) -> None:
        factory = fake.fake_process_factory(
            fake.SCENARIO_SUCCESS, response_text="ok",
            session_mode="agent", set_mode_supported=False,
        )
        backend = CursorAcpBackend(process_factory=factory, timeouts=_fast_timeouts())
        result = backend.invoke(self._request())
        # still completes, but honestly records that plan mode was not enforced
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertFalse(result.acp_telemetry["plan_mode_enforced"])

    def test_already_plan_mode_skips_set_mode(self) -> None:
        factory = fake.fake_process_factory(
            fake.SCENARIO_SUCCESS, response_text="ok", session_mode="plan"
        )
        backend = CursorAcpBackend(process_factory=factory, timeouts=_fast_timeouts())
        result = backend.invoke(self._request())
        proc = factory.created[0]
        self.assertIsNone(proc.set_mode_requested)  # no redundant set_mode
        self.assertTrue(result.acp_telemetry["plan_mode_enforced"])


class TestAcpTranscriptFixture(unittest.TestCase):
    def test_confirmed_handshake_transcript_parses(self) -> None:
        import json

        from admissible.cursor_acp_transport import (
            _extract_protocol_version,
            _extract_session_id,
        )

        data = json.loads(
            (FIXTURES_DIR / "cursor_acp_transport_transcript.json").read_text(encoding="utf-8")
        )
        by_seq = {m["seq"]: m for m in data["messages"]}
        # the initialize response is the confirmed-live evidence
        init_response = by_seq[2]
        self.assertEqual(init_response["provenance"], "confirmed_live")
        result = init_response["payload"]["result"]
        self.assertEqual(_extract_protocol_version(result), 1)
        self.assertIn("cursor_login", result["authMethods"])
        # spec-derived session id extraction works against the documented shape
        self.assertEqual(_extract_session_id({"sessionId": "abc"}), "abc")
        # unknowns are recorded honestly rather than invented
        self.assertTrue(data["unknowns"])


if __name__ == "__main__":
    unittest.main()
