"""Deterministic presentation timeline over persisted run events.

The timeline is emitted in a fixed canonical *logical* order supplied by the
caller. Persisted timestamps are attached where available and never invented
from file modification times. Absent timestamps stay visible (``None``);
conflicting timestamps (a later logical event carrying an earlier instant than an
earlier event) are flagged ``out_of_order`` rather than silently reordered.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from .enums import PresenceState
from .presentation_types import EvidenceTimelineEntry


@dataclass(frozen=True)
class TimelineInput:
    """One logical timeline event with its persisted timestamp (or ``None``)."""

    event_key: str
    label: str
    timestamp: str | None
    source_relative_path: str | None
    presence: PresenceState


def _parse(timestamp: str) -> datetime | None:
    text = timestamp.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def build_timeline(inputs: Sequence[TimelineInput]) -> tuple[EvidenceTimelineEntry, ...]:
    """Build timeline entries, flagging out-of-order persisted timestamps."""

    entries: list[EvidenceTimelineEntry] = []
    max_seen: datetime | None = None
    for item in inputs:
        out_of_order = False
        notes: tuple[str, ...] = ()
        parsed: datetime | None = None
        if item.timestamp is not None:
            parsed = _parse(item.timestamp)
            if parsed is None:
                notes = ("unparseable timestamp",)
        if parsed is not None:
            if max_seen is not None and parsed < max_seen:
                out_of_order = True
                notes = notes + ("timestamp precedes an earlier logged event",)
            if max_seen is None or parsed > max_seen:
                max_seen = parsed
        entries.append(
            EvidenceTimelineEntry(
                event_key=item.event_key,
                label=item.label,
                timestamp=item.timestamp,
                source_relative_path=item.source_relative_path,
                presence=item.presence,
                out_of_order=out_of_order,
                notes=notes,
            )
        )
    return tuple(entries)
