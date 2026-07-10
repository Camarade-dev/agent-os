"""Agent transport abstraction v0 — instruction/response bridge boundary.

Wraps the existing Cursor file bridge without faking provider integration.
High-autonomy mode writes instructions and polls for response file changes.

Live-rehearsal hardening (slice ADMISSIBLE_RUN_030): the file-bridge transport
keeps run/session/turn metadata aligned with the high-autonomy controller,
detects only *changed* responses since the last consumed one (never ingesting
the same response twice and blocking responses that predate the current
instruction), and exposes an explicit ``status_snapshot`` for the UI. It never
calls a provider, never executes anything, and never weakens admission or
content guards.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# -- transport status codes surfaced to the UI (display-only) ----------------
TRANSPORT_STATUS_IDLE = "idle"
TRANSPORT_STATUS_INSTRUCTION_WRITTEN = "instruction_written"
TRANSPORT_STATUS_WAITING = "waiting_for_response"
TRANSPORT_STATUS_RESPONSE_DETECTED = "response_detected"
TRANSPORT_STATUS_RESPONSE_CONSUMED = "response_consumed"
TRANSPORT_STATUS_STALE_BLOCKED = "stale_response_blocked"
TRANSPORT_STATUS_MALFORMED_RETRY = "malformed_response_retry"
TRANSPORT_STATUS_ERROR = "error"

TRANSPORT_STATUS_CODES = frozenset(
    {
        TRANSPORT_STATUS_IDLE,
        TRANSPORT_STATUS_INSTRUCTION_WRITTEN,
        TRANSPORT_STATUS_WAITING,
        TRANSPORT_STATUS_RESPONSE_DETECTED,
        TRANSPORT_STATUS_RESPONSE_CONSUMED,
        TRANSPORT_STATUS_STALE_BLOCKED,
        TRANSPORT_STATUS_MALFORMED_RETRY,
        TRANSPORT_STATUS_ERROR,
    }
)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class AgentTransportReadResult:
    """Result of polling for a new agent response."""

    changed: bool
    text: str | None
    cursor: str | None
    metadata: dict[str, Any] = field(default_factory=dict)
    status: str = TRANSPORT_STATUS_WAITING

    def to_dict(self) -> dict[str, Any]:
        return {
            "changed": self.changed,
            "text": self.text,
            "cursor": self.cursor,
            "metadata": dict(self.metadata),
            "status": self.status,
        }


class AgentTransport(ABC):
    """Transport boundary for agent instruction dispatch and response detection."""

    @abstractmethod
    def write_instruction(
        self,
        text: str,
        *,
        turn_number: int | None = None,
        session_id: str | None = None,
        instruction_id: str | None = None,
    ) -> dict[str, Any]:
        """Write the next instruction packet to the agent bridge location.

        ``turn_number``/``session_id``/``instruction_id`` are optional run
        metadata used only to keep the bridge's turn accounting aligned with
        the high-autonomy controller; they never affect an admission decision.
        """

    @abstractmethod
    def read_response_if_changed(self) -> AgentTransportReadResult:
        """Return a new response when the agent bridge response file changes."""

    @property
    @abstractmethod
    def response_cursor(self) -> str | None:
        """Opaque cursor/token/mtime for the last observed response."""

    @abstractmethod
    def clear_or_archive_response(self) -> dict[str, Any] | None:
        """Archive or clear the response file when idiomatic for this transport."""

    def mark_response_consumed(self, *, turn_number: int, response_sha256: str) -> None:
        """Record a successful ingest so the same response is never ingested twice.

        Default implementation only updates status; concrete transports override
        to also persist bridge-state / cursor bookkeeping.
        """
        self.note_status(TRANSPORT_STATUS_RESPONSE_CONSUMED, turn=turn_number)

    # -- shared status plumbing (display-only) -------------------------------

    def note_status(self, status_code: str, **detail: Any) -> None:
        """Record the current transport status and optional structured detail."""
        self._status_code = status_code
        self._status_detail = dict(detail)

    def status_snapshot(self) -> dict[str, Any]:
        """Display-only transport status for the UI. Never an authority source."""
        return {
            "status": getattr(self, "_status_code", TRANSPORT_STATUS_IDLE),
            "detail": dict(getattr(self, "_status_detail", {}) or {}),
        }


class FileBridgeAgentTransport(AgentTransport):
    """Production transport: existing `.admissible/` file bridge in a workspace."""

    def __init__(self, workspace_path: str | Path) -> None:
        from admissible.runner import cursor_bridge

        self._cursor_bridge = cursor_bridge
        self.workspace = Path(str(workspace_path).strip())
        # Cursor of the last response we *detected* (returned changed=True for).
        self._last_cursor: str | None = None
        # Cursor of the last response the controller confirmed *consumed*.
        self._last_consumed_cursor: str | None = None
        # Turn/session metadata for the most recent instruction we wrote.
        self._current_turn: int | None = None
        self._session_id: str | None = None
        self._current_instruction_id: str | None = None
        self._instruction_written_at: str | None = None
        self._status_code: str = TRANSPORT_STATUS_IDLE
        self._status_detail: dict[str, Any] = {}

    # -- path helpers --------------------------------------------------------

    @property
    def instruction_path(self) -> Path:
        cb = self._cursor_bridge
        return self.workspace / cb.BRIDGE_SUBDIR / cb.INSTRUCTION_FILENAME

    @property
    def response_path(self) -> Path:
        cb = self._cursor_bridge
        return self.workspace / cb.BRIDGE_SUBDIR / cb.RESPONSE_FILENAME

    def write_instruction(
        self,
        text: str,
        *,
        turn_number: int | None = None,
        session_id: str | None = None,
        instruction_id: str | None = None,
    ) -> dict[str, Any]:
        cb = self._cursor_bridge
        bridge_dir = self.workspace / cb.BRIDGE_SUBDIR
        bridge_dir.mkdir(parents=True, exist_ok=True)
        instruction_path = self.instruction_path
        response_path = self.response_path

        prior_state = cb.read_bridge_state(self.workspace) or {}
        # Archive any leftover response for the *previous* turn so the live
        # response path is empty before this instruction awaits a fresh reply.
        archive_turn = prior_state.get("turn")
        if archive_turn is None:
            archive_turn = max((turn_number or 1) - 1, 1)
        archived_response_path = cb._archive_stale_response_file(self.workspace, turn=archive_turn)

        rendered = cb.render_instruction_file(text, workspace=self.workspace)
        instruction_path.write_text(rendered, encoding="utf-8")
        file_meta = cb._file_metadata(instruction_path)

        self._current_turn = turn_number if turn_number is not None else prior_state.get("turn")
        self._session_id = session_id if session_id is not None else prior_state.get("session_id")
        self._current_instruction_id = instruction_id
        self._instruction_written_at = file_meta.get("modified_at")

        # Bridge-state keys kept aligned with cursor_bridge.write_next_instruction_
        # with_controller so a live turn's metadata is consistent no matter which
        # write path (manual bridge button or high-autonomy tick) produced it.
        bridge_updates: dict[str, Any] = {
            "instruction_path": str(instruction_path),
            "instruction_sha256": file_meta.get("sha256"),
            "written_at": file_meta.get("modified_at"),
            "instruction_written_at": file_meta.get("modified_at"),
            "expected_response_path": str(response_path),
            "response_path": str(response_path),
            "awaiting_response": True,
            "response_ingested_for_turn": None,
            "ingested_response_sha256": None,
        }
        if turn_number is not None:
            bridge_updates["turn"] = turn_number
        if session_id is not None:
            bridge_updates["session_id"] = session_id
        if instruction_id is not None:
            bridge_updates["instruction_id"] = instruction_id
        cb.write_bridge_state(self.workspace, bridge_updates)

        self.note_status(
            TRANSPORT_STATUS_INSTRUCTION_WRITTEN,
            turn=self._current_turn,
            instruction_sha256=file_meta.get("sha256"),
        )
        return {
            "transport": "file_bridge",
            "instruction_path": str(instruction_path),
            "response_path": str(response_path),
            "instruction_sha256": file_meta.get("sha256"),
            "turn": self._current_turn,
            "session_id": self._session_id,
            "instruction_id": instruction_id,
            "archived_response_path": archived_response_path,
        }

    def read_response_if_changed(self) -> AgentTransportReadResult:
        cb = self._cursor_bridge
        response_path = self.response_path
        if not response_path.is_file():
            self.note_status(TRANSPORT_STATUS_WAITING, reason="no_response_file")
            return AgentTransportReadResult(
                changed=False,
                text=None,
                cursor=self._last_cursor,
                metadata={"response_path": str(response_path), "exists": False},
                status=TRANSPORT_STATUS_WAITING,
            )

        meta = cb._file_metadata(response_path)
        cursor = str(meta.get("sha256") or meta.get("modified_at") or "")
        base_meta = {"response_path": str(response_path), **meta}

        if not cursor:
            self.note_status(TRANSPORT_STATUS_WAITING, reason="unreadable_response")
            return AgentTransportReadResult(
                changed=False, text=None, cursor=self._last_cursor,
                metadata=base_meta, status=TRANSPORT_STATUS_WAITING,
            )

        # Already consumed exactly this response: never ingest it twice.
        if cursor == self._last_consumed_cursor:
            self.note_status(TRANSPORT_STATUS_STALE_BLOCKED, reason="already_consumed", cursor=cursor)
            return AgentTransportReadResult(
                changed=False, text=None, cursor=self._last_cursor,
                metadata={**base_meta, "stale_reason": "already_consumed"},
                status=TRANSPORT_STATUS_STALE_BLOCKED,
            )

        # Response predates the current instruction: it is a leftover, not a reply.
        modified_at = meta.get("modified_at")
        if (
            self._instruction_written_at
            and modified_at is not None
            and modified_at < self._instruction_written_at
        ):
            self.note_status(TRANSPORT_STATUS_STALE_BLOCKED, reason="predates_instruction", cursor=cursor)
            return AgentTransportReadResult(
                changed=False, text=None, cursor=self._last_cursor,
                metadata={**base_meta, "stale_reason": "predates_instruction"},
                status=TRANSPORT_STATUS_STALE_BLOCKED,
            )

        # Unchanged since the last time we already detected it.
        if cursor == self._last_cursor:
            self.note_status(TRANSPORT_STATUS_WAITING, reason="unchanged", cursor=cursor)
            return AgentTransportReadResult(
                changed=False, text=None, cursor=self._last_cursor,
                metadata=base_meta, status=TRANSPORT_STATUS_WAITING,
            )

        raw_text = response_path.read_text(encoding="utf-8")
        if not raw_text.strip():
            self.note_status(TRANSPORT_STATUS_WAITING, reason="empty_response")
            return AgentTransportReadResult(
                changed=False, text=None, cursor=self._last_cursor,
                metadata={**base_meta, "empty": True}, status=TRANSPORT_STATUS_WAITING,
            )

        self._last_cursor = cursor
        self.note_status(TRANSPORT_STATUS_RESPONSE_DETECTED, cursor=cursor)
        return AgentTransportReadResult(
            changed=True, text=raw_text, cursor=cursor,
            metadata=base_meta, status=TRANSPORT_STATUS_RESPONSE_DETECTED,
        )

    @property
    def response_cursor(self) -> str | None:
        return self._last_cursor

    def clear_or_archive_response(self) -> dict[str, Any] | None:
        cb = self._cursor_bridge
        state = cb.read_bridge_state(self.workspace) or {}
        turn = state.get("turn") or self._current_turn or 1
        archived = cb._archive_stale_response_file(self.workspace, turn=turn)
        if archived is None:
            return None
        return {"archived_path": str(archived)}

    def mark_response_consumed(self, *, turn_number: int, response_sha256: str) -> None:
        """Record a successful ingest so the same response is never ingested twice."""
        cb = self._cursor_bridge
        self._last_consumed_cursor = response_sha256 or self._last_cursor
        cb.write_bridge_state(
            self.workspace,
            {
                "awaiting_response": False,
                "last_ingested_turn": turn_number,
                "last_ingested_response_sha256": self._last_consumed_cursor,
                "response_ingested_for_turn": turn_number,
                "ingested_response_sha256": self._last_consumed_cursor,
            },
        )
        self.note_status(
            TRANSPORT_STATUS_RESPONSE_CONSUMED,
            turn=turn_number,
            cursor=self._last_consumed_cursor,
        )

    # Backwards-compatible alias for the prior method name.
    def mark_response_ingested(self, *, turn_number: int, response_sha256: str) -> None:
        self.mark_response_consumed(turn_number=turn_number, response_sha256=response_sha256)

    def status_snapshot(self) -> dict[str, Any]:
        base = super().status_snapshot()
        base.update(
            {
                "transport_kind": "file_bridge",
                "workspace_path": str(self.workspace),
                "instruction_path": str(self.instruction_path),
                "response_path": str(self.response_path),
                "current_turn": self._current_turn,
                "session_id": self._session_id,
                "instruction_id": self._current_instruction_id,
                "last_response_cursor": self._last_cursor,
                "last_consumed_cursor": self._last_consumed_cursor,
                "response_file_present": self.response_path.is_file(),
            }
        )
        return base


class FixtureAgentTransport(AgentTransport):
    """Deterministic test transport with scripted responses — no filesystem required."""

    def __init__(self) -> None:
        self._responses: list[str] = []
        self._response_index = 0
        self._last_cursor: str | None = None
        self._last_consumed_cursor: str | None = None
        self._pending_response: str | None = None
        self.written_instructions: list[str] = []
        # Turn/session metadata recorded per instruction for alignment tests.
        self.written_instruction_meta: list[dict[str, Any]] = []
        self._current_turn: int | None = None
        self._session_id: str | None = None
        self._status_code: str = TRANSPORT_STATUS_IDLE
        self._status_detail: dict[str, Any] = {}

    def enqueue_response(self, text: str) -> None:
        self._responses.append(text)

    def set_responses(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self._response_index = 0
        self._pending_response = None
        self._last_cursor = None
        self._last_consumed_cursor = None

    def write_instruction(
        self,
        text: str,
        *,
        turn_number: int | None = None,
        session_id: str | None = None,
        instruction_id: str | None = None,
    ) -> dict[str, Any]:
        self.written_instructions.append(text)
        self.written_instruction_meta.append(
            {
                "turn_number": turn_number,
                "session_id": session_id,
                "instruction_id": instruction_id,
            }
        )
        self._current_turn = turn_number
        self._session_id = session_id
        if self._response_index < len(self._responses):
            self._pending_response = self._responses[self._response_index]
            self._response_index += 1
        self.note_status(TRANSPORT_STATUS_INSTRUCTION_WRITTEN, turn=turn_number)
        return {
            "transport": "fixture",
            "instruction_index": len(self.written_instructions),
            "instruction_sha256": _sha256_text(text),
            "turn": turn_number,
            "session_id": session_id,
            "instruction_id": instruction_id,
        }

    def read_response_if_changed(self) -> AgentTransportReadResult:
        if self._pending_response is None:
            self.note_status(TRANSPORT_STATUS_WAITING)
            return AgentTransportReadResult(
                changed=False, text=None, cursor=self._last_cursor,
                status=TRANSPORT_STATUS_WAITING,
            )

        text = self._pending_response
        cursor = _sha256_text(text)
        if cursor == self._last_consumed_cursor or cursor == self._last_cursor:
            self.note_status(TRANSPORT_STATUS_STALE_BLOCKED, cursor=cursor)
            return AgentTransportReadResult(
                changed=False, text=None, cursor=self._last_cursor,
                status=TRANSPORT_STATUS_STALE_BLOCKED,
            )

        self._last_cursor = cursor
        self._pending_response = None
        self.note_status(TRANSPORT_STATUS_RESPONSE_DETECTED, cursor=cursor)
        return AgentTransportReadResult(
            changed=True, text=text, cursor=cursor,
            metadata={"transport": "fixture"}, status=TRANSPORT_STATUS_RESPONSE_DETECTED,
        )

    @property
    def response_cursor(self) -> str | None:
        return self._last_cursor

    def clear_or_archive_response(self) -> dict[str, Any] | None:
        self._pending_response = None
        return {"cleared": True}

    def mark_response_consumed(self, *, turn_number: int, response_sha256: str) -> None:
        self._last_consumed_cursor = response_sha256 or self._last_cursor
        self.note_status(TRANSPORT_STATUS_RESPONSE_CONSUMED, turn=turn_number)

    def mark_response_ingested(self, *, turn_number: int, response_sha256: str) -> None:
        self.mark_response_consumed(turn_number=turn_number, response_sha256=response_sha256)

    def status_snapshot(self) -> dict[str, Any]:
        base = super().status_snapshot()
        base.update(
            {
                "transport_kind": "fixture",
                "current_turn": self._current_turn,
                "session_id": self._session_id,
                "last_response_cursor": self._last_cursor,
                "last_consumed_cursor": self._last_consumed_cursor,
            }
        )
        return base
