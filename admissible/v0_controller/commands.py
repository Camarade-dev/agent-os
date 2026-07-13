"""Typed durable command intents for the isolated V0 controller."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import json
from typing import Any, Mapping


class CommandKind(str, Enum):
    DISPATCH_AGENT = "dispatch_agent"
    ADMIT_PROPOSAL = "admit_proposal"
    EXECUTE_BOUNDED_OPERATIONS = "execute_bounded_operations"
    RUN_STRUCTURAL_CHECK = "run_structural_check"
    PAUSE_TECHNICALLY = "pause_technically"


class CommandStatus(str, Enum):
    PREPARED = "prepared"
    IN_FLIGHT = "in_flight"


def canonical_json(value: Mapping[str, Any]) -> str:
    """Encode command payloads without retaining mutable caller-owned data."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class Command:
    """An external-effect intent persisted before a dispatcher can execute it."""

    command_id: str | None
    kind: CommandKind
    owner_id: str
    status: CommandStatus
    payload_json: str

    @property
    def payload(self) -> dict[str, Any]:
        value = json.loads(self.payload_json)
        if not isinstance(value, dict):  # defensive for corrupted persisted data
            raise ValueError("command payload must decode to an object")
        return value

    def with_id(self, command_id: str) -> "Command":
        if self.command_id is not None:
            raise ValueError("command already has an id")
        return replace(self, command_id=command_id)

    def with_status(self, status: CommandStatus) -> "Command":
        return replace(self, status=status)

    def with_payload(self, payload: Mapping[str, Any]) -> "Command":
        """Return the same immutable command with an engine-issued payload."""

        return replace(self, payload_json=canonical_json(payload))

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "kind": self.kind.value,
            "owner_id": self.owner_id,
            "status": self.status.value,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Command":
        expected = {"command_id", "kind", "owner_id", "status", "payload"}
        if set(data) != expected:
            raise ValueError("invalid command fields")
        command_id = data["command_id"]
        if command_id is not None and (not isinstance(command_id, str) or not command_id):
            raise ValueError("command_id must be a non-empty string or null")
        if not isinstance(data["owner_id"], str) or not data["owner_id"]:
            raise ValueError("command owner_id must be non-empty")
        if not isinstance(data["payload"], dict):
            raise ValueError("command payload must be an object")
        return cls(
            command_id=command_id,
            kind=CommandKind(data["kind"]),
            owner_id=data["owner_id"],
            status=CommandStatus(data["status"]),
            payload_json=canonical_json(data["payload"]),
        )


def command_intent(
    kind: CommandKind,
    *,
    owner_id: str,
    payload: Mapping[str, Any],
) -> Command:
    """Create an unassigned command intent.  The engine assigns its id."""

    if not owner_id:
        raise ValueError("owner_id is required")
    return Command(
        command_id=None,
        kind=kind,
        owner_id=owner_id,
        status=CommandStatus.PREPARED,
        payload_json=canonical_json(payload),
    )
