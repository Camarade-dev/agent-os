"""Immutable G2 control-plane records."""
from __future__ import annotations
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

class ControlState(str, Enum):
    VALIDATED="VALIDATED"; QUEUED="QUEUED"; STARTING="STARTING"; RUNNING="RUNNING"; TERMINAL="TERMINAL"; START_FAILED="START_FAILED"

@dataclass(frozen=True)
class ValidatedContract:
    contract_id: str
    profile: Any
    profile_document: str
    created_at: str
    consumed: bool=False
    def consumed_copy(self): return replace(self, consumed=True)

@dataclass(frozen=True)
class ControlRun:
    control_run_id: str
    contract_id: str
    control_state: ControlState
    authoritative_session_id: str|None
    run_root: str|None
    created_at: str
    started_at: str|None=None
    ended_at: str|None=None
    start_error_type: str|None=None
    def transition(self, state: ControlState, **changes: object):
        return replace(self, control_state=state, **changes)
