"""Governed post-terminal backend-drift recovery (reauthorization) primitives.

This module supports exactly one recovery class: an authoritative terminal
``REFUSED`` product result whose failing boundary includes
``post_run_backend_drift``. It classifies eligibility from server-side result
truth, holds launcher-resident pending recovery state, and emits exactly one
durable write-once recovery record when a child control run is created.

The parent refusal stays authoritative and immutable: nothing here mutates the
parent run root, parent evidence, or the parent result. Recovery records and
views never carry the owner phrase, any authorization digest, the G2 control
token, the UI CSRF nonce, or canonical-payload custody.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import threading
from typing import Any, Mapping

from admissible.product_launcher.authoring import AuthoringError, _write_once

RECOVERY_SCHEMA_VERSION = "admissible_product_recovery_v1"

# The single supported refusal reason. Any other refusal reason, verdict,
# non-authoritative claim, or non-terminal state exposes no recovery.
RECOVERY_REASON_BACKEND_DRIFT = "post_run_backend_drift"

CLASSIFICATION_REAUTHORIZATION_REQUIRED = "REAUTHORIZATION_REQUIRED"
CLASSIFICATION_NOT_RECOVERABLE = "NOT_RECOVERABLE"

# Recovery lifecycle. AVAILABLE is a classification of the parent result, not a
# stored record; the remaining states are computed truthfully from the existing
# preparation lifecycle plus the child-run binding. Preparation BLOCKED, FAILED
# or EXPIRED terminates the recovery through the existing preparation error
# surface and is reported verbatim as the recovery state.
RECOVERY_STATE_AVAILABLE = "AVAILABLE"
RECOVERY_STATE_PREPARING = "PREPARING"
RECOVERY_STATE_AWAITING_OWNER_AUTHORIZATION = "AWAITING_OWNER_AUTHORIZATION"
RECOVERY_STATE_CHILD_RUN_CREATED = "CHILD_RUN_CREATED"
RECOVERY_STATE_COMPLETED = "COMPLETED"

# Terminal control-plane states. Only a terminal parent may classify as
# recoverable; the authoritative-result requirement then narrows this further.
TERMINAL_CONTROL_STATES = frozenset({"TERMINAL", "START_FAILED"})

OWNER_DECISION_AUTHORIZED_RERUN = "OWNER_AUTHORIZED_GOVERNED_RERUN"

# Fail-closed guard: no serialized recovery record may contain a key that even
# resembles secret custody. Key-substring match, lowercase.
_FORBIDDEN_RECORD_KEY_SUBSTRINGS = (
    "phrase",
    "digest",
    "token",
    "nonce",
    "secret",
    "cookie",
    "password",
    "canonical_payload",
    "owner_authorization",
)


class RecoveryPersistenceError(RuntimeError):
    """Bounded durable-record failure without internal diagnostics."""

    def __init__(self, error_code: str):
        self.error_code = error_code
        super().__init__(error_code)


@dataclass
class RecoveryRecord:
    """One governed recovery for one refused parent control run.

    The durable projection (:meth:`to_durable_json`) carries exactly the
    ``admissible_product_recovery_v1`` fields. Launcher-internal binding fields
    (``child_contract_id``, ``parent_backend_identity``, durable bookkeeping)
    stay out of the durable record.
    """

    recovery_id: str
    parent_control_run_id: str
    parent_session_id: str | None
    refusal_reason: str
    classification: str
    preparation_id: str
    created_at: str
    schema_version: str = RECOVERY_SCHEMA_VERSION
    owner_decision: str | None = None
    child_control_run_id: str | None = None
    authorized_at: str | None = None
    # Launcher-internal association (never part of the durable schema).
    child_contract_id: str | None = None
    parent_backend_identity: str | None = None
    durable_record_written: bool = False
    durable_record_error: str | None = None

    def to_durable_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "recovery_id": self.recovery_id,
            "parent_control_run_id": self.parent_control_run_id,
            "parent_session_id": self.parent_session_id,
            "refusal_reason": self.refusal_reason,
            "classification": self.classification,
            "owner_decision": self.owner_decision,
            "preparation_id": self.preparation_id,
            "child_control_run_id": self.child_control_run_id,
            "created_at": self.created_at,
            "authorized_at": self.authorized_at,
        }


class RecoveryStore:
    """Launcher-resident pending recoveries, keyed by parent control run.

    One parent has at most one recovery. Pending states survive browser refresh
    through launcher GET routes; they are NOT durable across launcher restart.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_parent: dict[str, RecoveryRecord] = {}

    def create(self, record: RecoveryRecord) -> RecoveryRecord:
        with self._lock:
            existing = self._by_parent.get(record.parent_control_run_id)
            if existing is not None:
                return existing
            self._by_parent[record.parent_control_run_id] = record
            return record

    def get_by_parent(self, parent_control_run_id: str) -> RecoveryRecord | None:
        with self._lock:
            return self._by_parent.get(parent_control_run_id)

    def get(self, recovery_id: str) -> RecoveryRecord | None:
        with self._lock:
            for record in self._by_parent.values():
                if record.recovery_id == recovery_id:
                    return record
            return None

    def get_by_child_contract(self, contract_id: str) -> RecoveryRecord | None:
        with self._lock:
            for record in self._by_parent.values():
                if record.child_contract_id == contract_id:
                    return record
            return None

    def is_recovery_child(self, control_run_id: str) -> bool:
        """True when this control run was itself created by a recovery.

        Such a run is a depth-one descendant and can never become a recovery
        parent through this slice.
        """

        with self._lock:
            return any(
                record.child_control_run_id == control_run_id
                for record in self._by_parent.values()
            )

    def values(self) -> list[RecoveryRecord]:
        with self._lock:
            return sorted(self._by_parent.values(), key=lambda r: r.created_at)

    def clear(self) -> None:
        with self._lock:
            self._by_parent.clear()


def classify_recovery(
    result_json: object,
    *,
    control_state: object = None,
    parent_is_recovery_child: bool = False,
) -> str:
    """Classify one parent result for governed-rerun eligibility.

    ``REAUTHORIZATION_REQUIRED`` is returned only when server-side truth proves
    every condition: terminal parent control state, authoritative ``REFUSED``
    product verdict, ``post_run_backend_drift`` in the failing boundary, and no
    recovery ancestry. Browser claims are never consulted.
    """

    if parent_is_recovery_child:
        return CLASSIFICATION_NOT_RECOVERABLE
    if control_state not in TERMINAL_CONTROL_STATES:
        return CLASSIFICATION_NOT_RECOVERABLE
    if not isinstance(result_json, Mapping):
        return CLASSIFICATION_NOT_RECOVERABLE
    admission = result_json.get("result_admission_state")
    boundary = result_json.get("failing_boundary")
    if not isinstance(admission, Mapping) or not isinstance(boundary, Mapping):
        return CLASSIFICATION_NOT_RECOVERABLE
    if admission.get("verdict") != "REFUSED":
        return CLASSIFICATION_NOT_RECOVERABLE
    if admission.get("verdict_is_authoritative") is not True:
        return CLASSIFICATION_NOT_RECOVERABLE
    reasons = boundary.get("reasons")
    if not isinstance(reasons, list) or RECOVERY_REASON_BACKEND_DRIFT not in reasons:
        return CLASSIFICATION_NOT_RECOVERABLE
    return CLASSIFICATION_REAUTHORIZATION_REQUIRED


def _require_secret_free(payload: Mapping[str, Any]) -> None:
    def scan(value: object) -> None:
        if isinstance(value, Mapping):
            for key, inner in value.items():
                lowered = str(key).lower()
                for forbidden in _FORBIDDEN_RECORD_KEY_SUBSTRINGS:
                    if forbidden in lowered:
                        raise RecoveryPersistenceError("RECOVERY_RECORD_FORBIDDEN_KEY")
                scan(inner)
        elif isinstance(value, (list, tuple)):
            for inner in value:
                scan(inner)

    scan(payload)


def _safe_record_name(recovery_id: str) -> str:
    if not recovery_id or any(char not in "0123456789abcdef" for char in recovery_id):
        raise RecoveryPersistenceError("RECOVERY_RECORD_UNSAFE_IDENTIFIER")
    return f"recovery-{recovery_id}.json"


def emit_recovery_record(record: RecoveryRecord, *, directory) -> str:
    """Durably write exactly one ``admissible_product_recovery_v1`` record.

    Reuses the existing write-once primitive: O_CREAT|O_EXCL, full write, fsync,
    close, with created-path cleanup on failure. A pre-existing record for the
    same recovery is a hard error, never an overwrite.
    """

    from pathlib import Path

    target_directory = Path(directory)
    if not target_directory.is_absolute():
        raise RecoveryPersistenceError("RECOVERY_DIRECTORY_INVALID")
    payload = record.to_durable_json()
    _require_secret_free(payload)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    target_directory.mkdir(parents=True, exist_ok=True)
    path = target_directory / _safe_record_name(record.recovery_id)
    try:
        _write_once(path, encoded)
    except AuthoringError as exc:
        raise RecoveryPersistenceError(exc.error_code) from None
    return str(path)


__all__ = [
    "CLASSIFICATION_NOT_RECOVERABLE",
    "CLASSIFICATION_REAUTHORIZATION_REQUIRED",
    "OWNER_DECISION_AUTHORIZED_RERUN",
    "RECOVERY_REASON_BACKEND_DRIFT",
    "RECOVERY_SCHEMA_VERSION",
    "RECOVERY_STATE_AVAILABLE",
    "RECOVERY_STATE_AWAITING_OWNER_AUTHORIZATION",
    "RECOVERY_STATE_CHILD_RUN_CREATED",
    "RECOVERY_STATE_COMPLETED",
    "RECOVERY_STATE_PREPARING",
    "RecoveryPersistenceError",
    "RecoveryRecord",
    "RecoveryStore",
    "TERMINAL_CONTROL_STATES",
    "classify_recovery",
    "emit_recovery_record",
]
