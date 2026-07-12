"""Provider-neutral transport health + circuit breaker (slice ADMISSIBLE_RUN_047).

A *technical* transport state that sits above any concrete backend
(``cursor_cli_oneshot``, ``cursor_acp``, or a future provider). It answers one
question: "is this transport currently behaving well enough to auto-drive, or
must a human explicitly recover it?" It never decides *semantic* admissibility
and is never a human-authority gate (PART I.38) — it only ever gates
*automatic* transport retries.

Circuit-breaker rules (PART I.37):

- any cleanup failure -> immediately ``unhealthy`` and latched (a leaked
  process tree is never something to auto-retry through);
- any uncertain completion -> ``degraded`` with automatic retry prohibited;
- repeated transport failures above a bounded threshold -> ``cooldown``;
- successful handshakes alone never mark the *model* transport healthy — only a
  usable end-to-end completion does.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# -- health states (PART I.35) -----------------------------------------------
HEALTH_HEALTHY = "healthy"
HEALTH_DEGRADED = "degraded"
HEALTH_UNHEALTHY = "unhealthy"
HEALTH_COOLDOWN = "cooldown"
HEALTH_UNKNOWN = "unknown"

HEALTH_STATES = frozenset(
    {HEALTH_HEALTHY, HEALTH_DEGRADED, HEALTH_UNHEALTHY, HEALTH_COOLDOWN, HEALTH_UNKNOWN}
)

# -- recorded outcomes (PART I.36) -------------------------------------------
OUTCOME_ACCEPTED = "accepted"  # a request was accepted by the transport
OUTCOME_USABLE_COMPLETION = "usable_completion"
OUTCOME_EMPTY_RESPONSE = "empty_response"
OUTCOME_PROTOCOL_ERROR = "protocol_error"
OUTCOME_PROVIDER_ERROR = "provider_error"
OUTCOME_IDLE_TIMEOUT = "idle_timeout"
OUTCOME_TOTAL_TIMEOUT = "total_timeout"
OUTCOME_CLEANUP_FAILURE = "cleanup_failure"
OUTCOME_UNCERTAIN_COMPLETION = "uncertain_completion"
OUTCOME_HANDSHAKE_OK = "handshake_ok"  # non-model; never improves model health
OUTCOME_CANCELLED = "cancelled"
# RUN_049 PART D.24/26: a proposal-only safety-invariant violation (a tool-call/
# write/network event, or a mode change away from plan, observed before Admissible
# execution) -- distinct from an ordinary transport failure. Latches unhealthy
# immediately, the same severity as a cleanup failure, since this is a backend
# safety invariant rather than a best-effort transport hiccup.
OUTCOME_POLICY_VIOLATION = "policy_violation"

# Outcomes that count as a *transport* failure toward the cooldown threshold.
_TRANSPORT_FAILURE_OUTCOMES = frozenset(
    {
        OUTCOME_EMPTY_RESPONSE,
        OUTCOME_PROTOCOL_ERROR,
        OUTCOME_PROVIDER_ERROR,
        OUTCOME_IDLE_TIMEOUT,
        OUTCOME_TOTAL_TIMEOUT,
        OUTCOME_UNCERTAIN_COMPLETION,
        OUTCOME_CLEANUP_FAILURE,
        OUTCOME_POLICY_VIOLATION,
    }
)

_DEFAULT_HISTORY = 20
_DEFAULT_FAILURE_THRESHOLD = 3


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class TransportHealth:
    """Rolling, bounded technical health for one transport (by ``backend_id``).

    ``record`` folds one outcome in and re-derives ``state``. ``blocks_automatic_retry``
    is the load-bearing output the caller consults before *ever* auto-retrying.
    """

    backend_id: str
    max_history: int = _DEFAULT_HISTORY
    failure_threshold: int = _DEFAULT_FAILURE_THRESHOLD
    state: str = HEALTH_UNKNOWN

    # rolling counters (bounded window)
    accepted_requests: int = 0
    usable_completions: int = 0
    empty_responses: int = 0
    protocol_errors: int = 0
    provider_errors: int = 0
    idle_timeouts: int = 0
    total_timeouts: int = 0
    cleanup_failures: int = 0
    uncertain_completions: int = 0
    handshakes_ok: int = 0

    consecutive_failures: int = 0
    last_outcome: str | None = None
    last_updated_at: str | None = None
    cleanup_failure_latched: bool = False
    policy_violations: int = 0
    policy_violation_latched: bool = False
    events: deque = field(default_factory=lambda: deque(maxlen=_DEFAULT_HISTORY))
    _seq: int = 0

    def __post_init__(self) -> None:
        if self.events.maxlen != self.max_history:
            self.events = deque(self.events, maxlen=self.max_history)

    # -- recording ----------------------------------------------------------

    def record(self, outcome: str, *, detail: str | None = None) -> str:
        """Fold one outcome into the rolling window and re-derive ``state``."""
        self._seq += 1
        self.last_outcome = outcome
        self.last_updated_at = _now_iso()
        self.events.append(
            {"seq": self._seq, "outcome": outcome, "at": self.last_updated_at, "detail": detail}
        )

        if outcome == OUTCOME_ACCEPTED:
            self.accepted_requests += 1
        elif outcome == OUTCOME_USABLE_COMPLETION:
            self.usable_completions += 1
            self.consecutive_failures = 0
        elif outcome == OUTCOME_EMPTY_RESPONSE:
            self.empty_responses += 1
        elif outcome == OUTCOME_PROTOCOL_ERROR:
            self.protocol_errors += 1
        elif outcome == OUTCOME_PROVIDER_ERROR:
            self.provider_errors += 1
        elif outcome == OUTCOME_IDLE_TIMEOUT:
            self.idle_timeouts += 1
        elif outcome == OUTCOME_TOTAL_TIMEOUT:
            self.total_timeouts += 1
        elif outcome == OUTCOME_CLEANUP_FAILURE:
            self.cleanup_failures += 1
            self.cleanup_failure_latched = True
        elif outcome == OUTCOME_UNCERTAIN_COMPLETION:
            self.uncertain_completions += 1
        elif outcome == OUTCOME_HANDSHAKE_OK:
            self.handshakes_ok += 1  # deliberately does NOT touch model health
        elif outcome == OUTCOME_POLICY_VIOLATION:
            self.policy_violations += 1
            self.policy_violation_latched = True

        if outcome in _TRANSPORT_FAILURE_OUTCOMES:
            self.consecutive_failures += 1

        self.state = self._derive_state()
        return self.state

    def _derive_state(self) -> str:
        # 1) A leaked process tree, or a proposal-only policy violation,
        # latches unhealthy until explicit recovery.
        if self.cleanup_failure_latched or self.policy_violation_latched:
            return HEALTH_UNHEALTHY
        # 2) An uncertain completion degrades and forbids auto-retry.
        if self.last_outcome == OUTCOME_UNCERTAIN_COMPLETION:
            return HEALTH_DEGRADED
        # 3) Repeated transport failures trip a cooldown.
        if self.consecutive_failures >= self.failure_threshold:
            return HEALTH_COOLDOWN
        # 4) A usable completion is the only thing that proves model health.
        if self.last_outcome == OUTCOME_USABLE_COMPLETION:
            return HEALTH_HEALTHY
        if self.usable_completions > 0 and self.consecutive_failures == 0:
            return HEALTH_HEALTHY
        # 5) Handshakes / accepted requests alone stay 'unknown' for the model.
        if self.consecutive_failures > 0:
            return HEALTH_DEGRADED
        return HEALTH_UNKNOWN

    # -- circuit-breaker outputs -------------------------------------------

    @property
    def blocks_automatic_retry(self) -> bool:
        """True when the transport must NOT be auto-retried without operator action."""
        if self.cleanup_failure_latched or self.policy_violation_latched:
            return True
        if self.state in (HEALTH_UNHEALTHY, HEALTH_COOLDOWN):
            return True
        if self.last_outcome == OUTCOME_UNCERTAIN_COMPLETION:
            return True
        return False

    @property
    def requires_operator_recovery(self) -> bool:
        """A latched cleanup failure or policy violation requires explicit operator recovery (PART A.6, D.26)."""
        return self.cleanup_failure_latched or self.policy_violation_latched

    def operator_recover(self) -> None:
        """Explicit operator recovery: clear the cleanup/policy-violation latch and cooldown.

        This is a *technical* reset an operator triggers; it never approves any
        semantic action and never auto-fires.
        """
        self.cleanup_failure_latched = False
        self.policy_violation_latched = False
        self.consecutive_failures = 0
        self.state = self._derive_state()

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend_id": self.backend_id,
            "state": self.state,
            "blocks_automatic_retry": self.blocks_automatic_retry,
            "requires_operator_recovery": self.requires_operator_recovery,
            "counters": {
                "accepted_requests": self.accepted_requests,
                "usable_completions": self.usable_completions,
                "empty_responses": self.empty_responses,
                "protocol_errors": self.protocol_errors,
                "provider_errors": self.provider_errors,
                "idle_timeouts": self.idle_timeouts,
                "total_timeouts": self.total_timeouts,
                "cleanup_failures": self.cleanup_failures,
                "uncertain_completions": self.uncertain_completions,
                "handshakes_ok": self.handshakes_ok,
                "policy_violations": self.policy_violations,
            },
            "consecutive_failures": self.consecutive_failures,
            "failure_threshold": self.failure_threshold,
            "last_outcome": self.last_outcome,
            "last_updated_at": self.last_updated_at,
            "cleanup_failure_latched": self.cleanup_failure_latched,
            "policy_violation_latched": self.policy_violation_latched,
            "recent_events": list(self.events),
        }


__all__ = [
    "HEALTH_HEALTHY",
    "HEALTH_DEGRADED",
    "HEALTH_UNHEALTHY",
    "HEALTH_COOLDOWN",
    "HEALTH_UNKNOWN",
    "HEALTH_STATES",
    "OUTCOME_ACCEPTED",
    "OUTCOME_USABLE_COMPLETION",
    "OUTCOME_EMPTY_RESPONSE",
    "OUTCOME_PROTOCOL_ERROR",
    "OUTCOME_PROVIDER_ERROR",
    "OUTCOME_IDLE_TIMEOUT",
    "OUTCOME_TOTAL_TIMEOUT",
    "OUTCOME_CLEANUP_FAILURE",
    "OUTCOME_UNCERTAIN_COMPLETION",
    "OUTCOME_HANDSHAKE_OK",
    "OUTCOME_CANCELLED",
    "OUTCOME_POLICY_VIOLATION",
    "TransportHealth",
]
