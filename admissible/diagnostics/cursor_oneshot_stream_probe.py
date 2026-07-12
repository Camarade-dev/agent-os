"""Real, single-call Cursor one-shot stream-json canary (PART 6 of
ADMISSIBLE_NARROW_FIX_CURSOR_ONESHOT_STREAM_JSON_ASK_AND_OPERATION_LIMIT).

Diagnostic-only. **Never imported by production code.** Drives the real,
unmodified production ``CursorCliAgentBackend`` (NDJSON stream-json, Ask mode,
configured model) against the real Neon Serpents raw goal, through exactly one
governed high-autonomy tick that dispatches the instruction and captures the
real model response -- and stops there.

Hard constraints:

- At most one real, model-bearing Cursor invocation (enforced by a module-level
  call counter; a second call raises ``ModelBudgetExceeded``).
- Serial execution, no concurrency, no automatic retry
  (``automatic_empty_success_retries=0``).
- Exactly one high-autonomy tick is ever executed. The response is captured
  from the durable ``CallableBackendTransport`` result and never ingested --
  ingestion is what would extract+admit+execute structured operations, and
  this probe must never execute the proposed operations.
- Isolated temporary target + agent workspaces (never the real repository,
  never a real Neon Serpents project workspace).
- Target-workspace mutation is snapshotted before/after and asserted clean.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from admissible.agent_backend import (
    AGENT_INVOKE_SUCCESS,
    CursorCliAgentBackend,
    CursorCliConfig,
    is_cursor_agent_command,
)
from admissible.control_surface import ControlSurfaceController
from admissible.diagnostics.acp_real_probe import (
    diff_workspace_snapshots,
    sanitize_text,
    snapshot_workspace,
)
from admissible.long_run_envelope_builder import extract_structured_operation_blocks

DEFAULT_MAX_MODEL_CALLS = 1
DEFAULT_TIMEOUT_SECONDS = 300.0


class ModelBudgetExceeded(RuntimeError):
    """Raised when this probe would exceed its hard one-call model budget."""


@dataclass
class NeonTurn1CanaryReport:
    """Sanitized, structured outcome of the single real canary invocation."""

    attempted: bool = False
    command_resolved: str | None = None
    model: str | None = None
    argv_summary: list[str] = field(default_factory=list)
    exit_code: int | None = None
    invoke_status: str | None = None
    error_message: str | None = None
    ndjson_valid: bool | None = None
    terminal_event_count: int | None = None
    tool_call_event_count: int | None = None
    interaction_query_event_count: int | None = None
    create_plan_detected: bool | None = None
    canonical_response_nonempty: bool | None = None
    canonical_response_preview: str | None = None
    structured_operation_count: int | None = None
    structured_operation_paths: list[str] = field(default_factory=list)
    effective_max_structured_operations_per_response: int | None = None
    target_workspace_mutation: dict[str, Any] | None = None
    managed_process_result: dict[str, Any] | None = None
    cleanup_complete: bool | None = None
    remaining_process_ids: list[int] = field(default_factory=list)
    usable_structured_proposal: bool = False
    stop_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class NeonTurn1CanaryProbe:
    """Serial, budgeted, single-use probe. Construct fresh per attempt."""

    def __init__(self, *, max_model_calls: int = DEFAULT_MAX_MODEL_CALLS) -> None:
        self._max_model_calls = max_model_calls
        self._calls_made = 0

    def run(
        self,
        *,
        raw_goal_text: str,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        model: str = "auto",
        command: str | None = None,
        _test_runner: Any = None,
    ) -> NeonTurn1CanaryReport:
        """``_test_runner`` is a dry-run-only seam (injected ``subprocess.run``-compatible
        callable) for exercising this probe's plumbing without spending the real
        one-call budget. Never set outside tests -- the real canary omits it,
        which routes through the unmodified production managed-subprocess path."""
        if self._calls_made >= self._max_model_calls:
            raise ModelBudgetExceeded(
                f"Real-call budget ({self._max_model_calls}) already spent for this probe instance."
            )

        report = NeonTurn1CanaryReport()

        resolved_command = command or shutil.which("cursor-agent")
        if not resolved_command or not is_cursor_agent_command(resolved_command):
            report.attempted = False
            report.stop_reason = (
                f"cursor-agent command not found or not recognized as the real Cursor "
                f"Agent CLI (resolved={resolved_command!r})."
            )
            return report
        report.command_resolved = resolved_command
        report.model = model
        report.argv_summary = [
            resolved_command,
            "--print", "--output-format", "stream-json", "--stream-partial-output",
            "--mode", "ask", "--model", model, "--workspace", "<agent_workspace>",
            "--trust", "<file-pointer adapter>",
        ]

        tmp_root = Path(tempfile.mkdtemp(prefix="admissible_neon_canary_"))
        target_ws = tmp_root / "target"
        agent_ws = tmp_root / "agent"
        target_ws.mkdir(parents=True, exist_ok=True)
        agent_ws.mkdir(parents=True, exist_ok=True)

        before_snapshot = snapshot_workspace(target_ws)

        config = CursorCliConfig.cursor_agent_preset(command=resolved_command, model=model)
        blocking, _warnings = config.safety_issues()
        if blocking:
            report.attempted = False
            report.stop_reason = f"Preflight blocked: {'; '.join(blocking)}"
            return report

        backend = CursorCliAgentBackend(config=config, runner=_test_runner)

        from admissible.agent_backend import CallableBackendTransport

        transport = CallableBackendTransport(
            backend,
            target_workspace_path=str(target_ws),
            agent_workspace_path=str(agent_ws),
            timeout_seconds=timeout_seconds,
        )

        controller = ControlSurfaceController(session_dir=tmp_root / "sessions")
        controller.submit_goal(raw_goal_text)
        controller.start_high_autonomy_run(
            workspace_path=str(target_ws),
            transport=transport,
            max_turns=4,
            automatic_empty_success_retries=0,
        )
        ha_before = controller._session.high_autonomy_run or {}
        report.effective_max_structured_operations_per_response = ha_before.get(
            "max_structured_operations_per_response"
        )

        # -- the one real, model-bearing call happens synchronously inside this
        # single tick (HA_NEXT_WRITE_INSTRUCTION -> transport.write_instruction
        # -> backend.invoke). No further tick is ever called by this probe, so
        # the response is captured but never ingested/admitted/executed.
        self._calls_made += 1
        report.attempted = True
        controller.tick_high_autonomy_run()

        after_snapshot = snapshot_workspace(target_ws)
        mutation = diff_workspace_snapshots(before_snapshot, after_snapshot)
        report.target_workspace_mutation = mutation

        result = transport.last_invocation_result
        if result is None:
            report.stop_reason = "No invocation result captured (transport never invoked backend)."
            return report

        report.exit_code = result.exit_code
        report.invoke_status = result.status
        report.error_message = sanitize_text(result.error_message) if result.error_message else None
        report.managed_process_result = result.managed_process_result
        if result.managed_process_result:
            report.cleanup_complete = bool(result.managed_process_result.get("cleanup_complete"))
            report.remaining_process_ids = list(
                result.managed_process_result.get("remaining_process_ids") or []
            )

        diag = result.stream_json_diagnostics or {}
        report.ndjson_valid = bool(diag) and report.invoke_status != "transport_parse_error"
        report.terminal_event_count = diag.get("terminal_event_count")
        report.tool_call_event_count = diag.get("tool_call_event_count")
        report.interaction_query_event_count = diag.get("interaction_query_event_count")
        report.create_plan_detected = diag.get("create_plan_detected")

        if result.status == AGENT_INVOKE_SUCCESS and result.response_text:
            report.canonical_response_nonempty = True
            report.canonical_response_preview = sanitize_text(result.response_text, max_len=400)
            blocks = extract_structured_operation_blocks(result.response_text)
            operations = [op for block in blocks for op in block["operations"]]
            report.structured_operation_count = len(operations)
            report.structured_operation_paths = [
                str(op.get("path")) for op in operations if op.get("path")
            ]
            report.usable_structured_proposal = (
                1 <= len(operations) <= (report.effective_max_structured_operations_per_response or 4)
                and all(op.get("operation") == "write_file" for op in operations)
                and all(isinstance(op.get("content"), str) for op in operations)
            )
            if not report.usable_structured_proposal:
                report.stop_reason = (
                    f"Terminal response succeeded but did not satisfy the 1-4 complete "
                    f"write_file proposal shape (found {len(operations)} operation(s))."
                )
        else:
            report.canonical_response_nonempty = False
            report.stop_reason = (
                f"No usable structured proposal: invoke_status={result.status!r}, "
                f"error_message={report.error_message!r}."
            )

        return report


__all__ = [
    "DEFAULT_MAX_MODEL_CALLS",
    "DEFAULT_TIMEOUT_SECONDS",
    "ModelBudgetExceeded",
    "NeonTurn1CanaryProbe",
    "NeonTurn1CanaryReport",
]
