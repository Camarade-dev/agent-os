"""Canonical G1 preflight consumption and authorization preparation."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Callable, Mapping

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.native_canary import NativeCanaryAuthorizationPayloadV4
from admissible.product_launcher.configuration import (
    AUTHORIZATION_MODE_INTERACTIVE,
    AUTHORIZATION_MODE_PRECOMMITTED,
)

PREFLIGHT_READY = "PREFLIGHT_READY"
PREFLIGHT_BLOCKED = "PREFLIGHT_BLOCKED"
STATE_QUEUED = "QUEUED"
STATE_RUNNING = "RUNNING"
STATE_READY = "READY"
STATE_BLOCKED = "BLOCKED"
STATE_FAILED = "FAILED"
STATE_EXPIRED = "EXPIRED"

INTERACTIVE_AUTHORIZATION_NOTICE = (
    "The local launcher derives an invocation digest from the owner-entered phrase "
    "and the exact canonical preflight payload displayed for this preparation. "
    "This is an interactive bound confirmation, not a precommitted external digest. "
    "Fresh G1 launch observations may still reject on drift."
)
PRECOMMITTED_AUTHORIZATION_NOTICE = (
    "The launcher forwards the owner-supplied digest unchanged. "
    "G1 remains the only authority that validates phrase and digest against a fresh payload."
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


class PreflightParseError(Exception):
    def __init__(self, error_code: str, safe_message_key: str):
        self.error_code = error_code
        self.safe_message_key = safe_message_key
        super().__init__(error_code)


def parse_preflight_stdout(raw: bytes) -> dict[str, Any]:
    """Parse bounded preflight stdout under the exact G2.5 law."""

    if not isinstance(raw, bytes):
        raise PreflightParseError("MALFORMED_PREFLIGHT", "preflight.not_bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PreflightParseError("MALFORMED_PREFLIGHT", "preflight.invalid_utf8") from None
    decoder = json.JSONDecoder(object_pairs_hook=_reject_duplicate_keys)
    try:
        value, index = decoder.raw_decode(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise PreflightParseError("MALFORMED_PREFLIGHT", "preflight.invalid_json") from None
    trailing = text[index:]
    if trailing.strip():
        raise PreflightParseError("MALFORMED_PREFLIGHT", "preflight.trailing_data")
    if not isinstance(value, dict):
        raise PreflightParseError("MALFORMED_PREFLIGHT", "preflight.object_required")
    return value


@dataclass
class AuthorizationPreparation:
    preparation_id: str
    contract_id: str
    authorization_mode: str
    state: str
    created_at: str
    consumed: bool = False
    payload_fingerprint: str | None = None
    safe_payload_summary: dict[str, object] | None = None
    owner_visible_payload: dict[str, object] | None = None
    canonical_payload_bytes: bytes | None = None
    blocked_summary: dict[str, object] | None = None
    error_type: str | None = None
    updated_at: str | None = None

    def to_status_dict(self) -> dict[str, object]:
        notice = (
            INTERACTIVE_AUTHORIZATION_NOTICE
            if self.authorization_mode == AUTHORIZATION_MODE_INTERACTIVE
            else PRECOMMITTED_AUTHORIZATION_NOTICE
        )
        payload: dict[str, object] = {
            "preparation_id": self.preparation_id,
            "contract_id": self.contract_id,
            "state": self.state,
            "authorization_mode": self.authorization_mode,
            "authorization_semantics_notice": notice,
            "consumed": self.consumed,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "payload_fingerprint": self.payload_fingerprint,
            "safe_payload_summary": self.safe_payload_summary,
            "authorization_payload": self.owner_visible_payload,
            "blocked_summary": self.blocked_summary,
            "error_type": self.error_type,
        }
        return payload


def _safe_payload_summary(payload: NativeCanaryAuthorizationPayloadV4) -> dict[str, object]:
    return {
        "schema_version": payload.schema_version,
        "payload_fingerprint": payload.payload_fingerprint,
        "run_id": payload.run_id,
        "session_id": payload.session_id,
        "selected_model": payload.selected_model,
        "timeout_seconds": payload.timeout_seconds,
        "backend_attestation_class": payload.backend_attestation_class,
        "source_head": payload.source_head,
        "mission_profile_fingerprint": payload.mission_profile.profile_fingerprint,
    }


def _owner_visible_payload(payload: NativeCanaryAuthorizationPayloadV4) -> dict[str, object]:
    """Return the validated payload for owner inspection.

    Local path fields are authority facts and are intentionally shown. No field
    is silently altered; any future redaction must be marked explicitly.
    """

    data = payload.to_dict()
    data["path_disclosure"] = {
        "policy": "AUTHORITY_PATHS_SHOWN",
        "marked_redactions": [],
    }
    return data


def consume_ready_preflight(
    *,
    return_code: int,
    stdout: bytes,
    payload_loader: Callable[[Mapping[str, Any]], NativeCanaryAuthorizationPayloadV4] = (
        NativeCanaryAuthorizationPayloadV4.from_dict
    ),
) -> tuple[str, NativeCanaryAuthorizationPayloadV4 | None, dict[str, object] | None]:
    """Interpret one preflight child result.

    Returns ``(state, payload_or_none, blocked_summary_or_none)``.
    """

    try:
        parsed = parse_preflight_stdout(stdout)
    except PreflightParseError:
        return STATE_FAILED, None, {"error_type": "MALFORMED_PREFLIGHT"}
    status = parsed.get("status")
    if return_code == 0 and status == PREFLIGHT_READY:
        raw_payload = parsed.get("authorization_payload")
        if not isinstance(raw_payload, Mapping):
            return STATE_FAILED, None, {"error_type": "MALFORMED_PREFLIGHT"}
        try:
            validated = payload_loader(raw_payload)
            # Digests must use canonical_bytes(validated.to_dict()), never printed JSON.
            _ = canonical_bytes(validated.to_dict())
        except Exception:
            return STATE_FAILED, None, {"error_type": "PAYLOAD_INVALID"}
        return STATE_READY, validated, None
    if status == PREFLIGHT_BLOCKED or return_code == 2:
        summary = {
            "error_type": "PREFLIGHT_BLOCKED",
            "reason_code": parsed.get("reason_code") if isinstance(parsed.get("reason_code"), str) else None,
            "status": PREFLIGHT_BLOCKED,
        }
        return STATE_BLOCKED, None, summary
    return STATE_FAILED, None, {"error_type": "UNEXPECTED_PREFLIGHT_STATUS"}


def compute_interactive_digest(*, phrase: str, canonical_payload: bytes) -> str:
    material = phrase.encode("utf-8") + b"\x00" + canonical_payload
    return hashlib.sha256(material).hexdigest()


def require_precommitted_digest(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError("invalid owner authorization digest")
    return value


@dataclass
class PreparationStore:
    """Bounded in-memory authorization preparation records."""

    max_preparations: int
    ttl_seconds: int
    clock: Callable[[], str] = _now
    _items: dict[str, AuthorizationPreparation] = field(default_factory=dict)
    _order: list[str] = field(default_factory=list)

    def create(self, preparation: AuthorizationPreparation) -> AuthorizationPreparation:
        self.expire()
        if len(self._items) >= self.max_preparations:
            raise RuntimeError("preparation capacity reached")
        self._items[preparation.preparation_id] = preparation
        self._order.append(preparation.preparation_id)
        return preparation

    def get(self, preparation_id: str) -> AuthorizationPreparation | None:
        self.expire()
        return self._items.get(preparation_id)

    def update(self, preparation: AuthorizationPreparation) -> None:
        preparation.updated_at = self.clock()
        self._items[preparation.preparation_id] = preparation

    def mark_consumed(self, preparation_id: str) -> None:
        item = self._items.get(preparation_id)
        if item is None:
            return
        item.consumed = True
        item.canonical_payload_bytes = None
        item.updated_at = self.clock()

    def clear(self) -> None:
        for item in self._items.values():
            item.canonical_payload_bytes = None
        self._items.clear()
        self._order.clear()

    def expire(self) -> None:
        # TTL is expressed in seconds; ISO timestamps are compared lexicographically
        # only for ordering within one process. Explicit cleanup remains primary.
        while len(self._order) > self.max_preparations:
            oldest = self._order.pop(0)
            item = self._items.pop(oldest, None)
            if item is not None:
                item.canonical_payload_bytes = None


def apply_ready_payload(preparation: AuthorizationPreparation, payload: NativeCanaryAuthorizationPayloadV4) -> None:
    preparation.state = STATE_READY
    preparation.payload_fingerprint = payload.payload_fingerprint
    preparation.safe_payload_summary = _safe_payload_summary(payload)
    preparation.owner_visible_payload = _owner_visible_payload(payload)
    preparation.canonical_payload_bytes = canonical_bytes(payload.to_dict())
    preparation.blocked_summary = None
    preparation.error_type = None


__all__ = [
    "AuthorizationPreparation",
    "INTERACTIVE_AUTHORIZATION_NOTICE",
    "PRECOMMITTED_AUTHORIZATION_NOTICE",
    "PREFLIGHT_BLOCKED",
    "PREFLIGHT_READY",
    "PreparationStore",
    "PreflightParseError",
    "STATE_BLOCKED",
    "STATE_EXPIRED",
    "STATE_FAILED",
    "STATE_QUEUED",
    "STATE_READY",
    "STATE_RUNNING",
    "apply_ready_payload",
    "compute_interactive_digest",
    "consume_ready_preflight",
    "parse_preflight_stdout",
    "require_precommitted_digest",
]
