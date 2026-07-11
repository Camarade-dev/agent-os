"""Transport health / circuit-breaker tests (slice ADMISSIBLE_RUN_047, PART I)."""

from __future__ import annotations

import unittest

from admissible.transport_health import (
    HEALTH_COOLDOWN,
    HEALTH_DEGRADED,
    HEALTH_HEALTHY,
    HEALTH_UNHEALTHY,
    HEALTH_UNKNOWN,
    OUTCOME_ACCEPTED,
    OUTCOME_CLEANUP_FAILURE,
    OUTCOME_EMPTY_RESPONSE,
    OUTCOME_HANDSHAKE_OK,
    OUTCOME_PROTOCOL_ERROR,
    OUTCOME_UNCERTAIN_COMPLETION,
    OUTCOME_USABLE_COMPLETION,
    TransportHealth,
)


class TestTransportHealth(unittest.TestCase):
    def _health(self, **kw) -> TransportHealth:
        return TransportHealth(backend_id="cursor_acp", failure_threshold=3, **kw)

    def test_starts_unknown(self) -> None:
        h = self._health()
        self.assertEqual(h.state, HEALTH_UNKNOWN)
        self.assertFalse(h.blocks_automatic_retry)

    def test_handshake_alone_never_marks_model_healthy(self) -> None:
        h = self._health()
        h.record(OUTCOME_HANDSHAKE_OK)
        h.record(OUTCOME_ACCEPTED)
        # only a usable end-to-end completion may mark the model transport healthy
        self.assertNotEqual(h.state, HEALTH_HEALTHY)
        self.assertEqual(h.state, HEALTH_UNKNOWN)

    def test_usable_completion_marks_healthy(self) -> None:
        h = self._health()
        h.record(OUTCOME_HANDSHAKE_OK)
        h.record(OUTCOME_USABLE_COMPLETION)
        self.assertEqual(h.state, HEALTH_HEALTHY)
        self.assertFalse(h.blocks_automatic_retry)

    def test_cleanup_failure_latches_unhealthy_until_operator_recovery(self) -> None:
        h = self._health()
        h.record(OUTCOME_USABLE_COMPLETION)
        h.record(OUTCOME_CLEANUP_FAILURE)
        self.assertEqual(h.state, HEALTH_UNHEALTHY)
        self.assertTrue(h.blocks_automatic_retry)
        self.assertTrue(h.requires_operator_recovery)
        # a later good completion does NOT silently clear a leaked-process latch
        h.record(OUTCOME_USABLE_COMPLETION)
        self.assertEqual(h.state, HEALTH_UNHEALTHY)
        # only explicit operator recovery clears it
        h.operator_recover()
        self.assertFalse(h.requires_operator_recovery)
        self.assertNotEqual(h.state, HEALTH_UNHEALTHY)

    def test_uncertain_completion_degrades_and_blocks_retry(self) -> None:
        h = self._health()
        h.record(OUTCOME_UNCERTAIN_COMPLETION)
        self.assertEqual(h.state, HEALTH_DEGRADED)
        self.assertTrue(h.blocks_automatic_retry)

    def test_repeated_failures_trip_cooldown(self) -> None:
        h = self._health()
        h.record(OUTCOME_EMPTY_RESPONSE)
        h.record(OUTCOME_PROTOCOL_ERROR)
        self.assertNotEqual(h.state, HEALTH_COOLDOWN)  # below threshold
        h.record(OUTCOME_EMPTY_RESPONSE)  # 3rd consecutive
        self.assertEqual(h.state, HEALTH_COOLDOWN)
        self.assertTrue(h.blocks_automatic_retry)
        # a usable completion resets the consecutive-failure streak
        h.record(OUTCOME_USABLE_COMPLETION)
        self.assertEqual(h.state, HEALTH_HEALTHY)

    def test_rolling_history_is_bounded(self) -> None:
        h = TransportHealth(backend_id="x", max_history=5)
        for _ in range(20):
            h.record(OUTCOME_ACCEPTED)
        self.assertLessEqual(len(h.events), 5)
        snapshot = h.to_dict()
        self.assertIn("counters", snapshot)
        self.assertLessEqual(len(snapshot["recent_events"]), 5)


if __name__ == "__main__":
    unittest.main()
