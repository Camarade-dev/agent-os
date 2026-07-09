"""Agent transport abstraction v0 — instruction/response bridge boundary.

Wraps the existing Cursor file bridge without faking provider integration.
High-autonomy mode writes instructions and polls for response file changes.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class AgentTransportReadResult:
    """Result of polling for a new agent response."""

    changed: bool
    text: str | None
    cursor: str | None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "changed": self.changed,
            "text": self.text,
            "cursor": self.cursor,
            "metadata": dict(self.metadata),
        }


class AgentTransport(ABC):
    """Transport boundary for agent instruction dispatch and response detection."""

    @abstractmethod
    def write_instruction(self, text: str) -> dict[str, Any]:
        """Write the next instruction packet to the agent bridge location."""

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


class FileBridgeAgentTransport(AgentTransport):
    """Production transport: existing `.admissible/` file bridge in a workspace."""

    def __init__(self, workspace_path: str | Path) -> None:
        from admissible.runner import cursor_bridge

        self._cursor_bridge = cursor_bridge
        self.workspace = Path(str(workspace_path).strip())
        self._last_cursor: str | None = None

    def write_instruction(self, text: str) -> dict[str, Any]:
        cb = self._cursor_bridge
        bridge_dir = self.workspace / cb.BRIDGE_SUBDIR
        bridge_dir.mkdir(parents=True, exist_ok=True)
        instruction_path = self.workspace / cb.BRIDGE_SUBDIR / cb.INSTRUCTION_FILENAME
        response_path = self.workspace / cb.BRIDGE_SUBDIR / cb.RESPONSE_FILENAME

        prior_state = cb.read_bridge_state(self.workspace) or {}
        turn = prior_state.get("turn") or 1
        cb._archive_stale_response_file(self.workspace, turn=turn)

        rendered = cb.render_instruction_file(text, workspace=self.workspace)
        instruction_path.write_text(rendered, encoding="utf-8")
        file_meta = cb._file_metadata(instruction_path)
        cb.write_bridge_state(
            self.workspace,
            {
                "awaiting_response": True,
                "instruction_path": str(instruction_path),
                "response_path": str(response_path),
                "instruction_sha256": file_meta.get("sha256"),
                "instruction_written_at": file_meta.get("modified_at"),
            },
        )
        return {
            "transport": "file_bridge",
            "instruction_path": str(instruction_path),
            "response_path": str(response_path),
            "instruction_sha256": file_meta.get("sha256"),
        }

    def read_response_if_changed(self) -> AgentTransportReadResult:
        cb = self._cursor_bridge
        response_path = self.workspace / cb.BRIDGE_SUBDIR / cb.RESPONSE_FILENAME
        if not response_path.is_file():
            return AgentTransportReadResult(changed=False, text=None, cursor=self._last_cursor)

        meta = cb._file_metadata(response_path)
        cursor = str(meta.get("sha256") or meta.get("modified_at") or "")
        if not cursor or cursor == self._last_cursor:
            return AgentTransportReadResult(
                changed=False,
                text=None,
                cursor=self._last_cursor,
                metadata={"response_path": str(response_path), **meta},
            )

        raw_text = response_path.read_text(encoding="utf-8")
        if not raw_text.strip():
            return AgentTransportReadResult(
                changed=False,
                text=None,
                cursor=self._last_cursor,
                metadata={"response_path": str(response_path), "empty": True},
            )

        self._last_cursor = cursor
        return AgentTransportReadResult(
            changed=True,
            text=raw_text,
            cursor=cursor,
            metadata={"response_path": str(response_path), **meta},
        )

    @property
    def response_cursor(self) -> str | None:
        return self._last_cursor

    def clear_or_archive_response(self) -> dict[str, Any] | None:
        cb = self._cursor_bridge
        state = cb.read_bridge_state(self.workspace) or {}
        turn = state.get("turn") or 1
        archived = cb._archive_stale_response_file(self.workspace, turn=turn)
        if archived is None:
            return None
        return {"archived_path": str(archived)}

    def mark_response_ingested(self, *, turn_number: int, response_sha256: str) -> None:
        """Update bridge state after successful ingest (mirrors cursor_bridge hygiene)."""
        cb = self._cursor_bridge
        cb.write_bridge_state(
            self.workspace,
            {
                "awaiting_response": False,
                "last_ingested_turn": turn_number,
                "last_ingested_response_sha256": response_sha256,
            },
        )


class FixtureAgentTransport(AgentTransport):
    """Deterministic test transport with scripted responses — no filesystem required."""

    def __init__(self) -> None:
        self._responses: list[str] = []
        self._response_index = 0
        self._last_cursor: str | None = None
        self._pending_response: str | None = None
        self.written_instructions: list[str] = []

    def enqueue_response(self, text: str) -> None:
        self._responses.append(text)

    def set_responses(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self._response_index = 0
        self._pending_response = None
        self._last_cursor = None

    def write_instruction(self, text: str) -> dict[str, Any]:
        self.written_instructions.append(text)
        if self._response_index < len(self._responses):
            self._pending_response = self._responses[self._response_index]
            self._response_index += 1
        return {
            "transport": "fixture",
            "instruction_index": len(self.written_instructions),
            "instruction_sha256": _sha256_text(text),
        }

    def read_response_if_changed(self) -> AgentTransportReadResult:
        if self._pending_response is None:
            return AgentTransportReadResult(changed=False, text=None, cursor=self._last_cursor)

        text = self._pending_response
        cursor = _sha256_text(text)
        if cursor == self._last_cursor:
            return AgentTransportReadResult(changed=False, text=None, cursor=self._last_cursor)

        self._last_cursor = cursor
        self._pending_response = None
        return AgentTransportReadResult(
            changed=True,
            text=text,
            cursor=cursor,
            metadata={"transport": "fixture"},
        )

    @property
    def response_cursor(self) -> str | None:
        return self._last_cursor

    def clear_or_archive_response(self) -> dict[str, Any] | None:
        self._pending_response = None
        return {"cleared": True}
