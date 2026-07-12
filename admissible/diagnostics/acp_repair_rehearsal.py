"""Deterministic real-repair rehearsal harness (RUN_049 PART F).

Diagnostic-only. **Never imported by production code.** Builds a deterministic,
legitimate pre-repair ``ControlSurfaceController`` session (an authoritative
Mission Contract, four local application files on disk, bounded write evidence,
seven of eight acceptance criteria verified_pass, exactly one static criterion
verified_fail, run in ``repair_needed``, no blocker, repair budget remaining --
RUN_049 PART F.28) using only a scripted ``FixtureAgentBackend`` for the
*initial* implementation turn, then drives exactly one further callable-backend
turn (real ``CursorAcpBackend`` or, for deterministic tests, another
``FixtureAgentBackend``) through the *actual* production high-autonomy
controller lifecycle for the repair round:

    controller -> write_repair_instruction (invokes the backend once)
    -> ingest -> admission -> bounded write execution
    -> automatic post-repair static verification -> completion re-evaluation

The backend swap is an explicit, deliberate identity change (PART J.47): the
persisted ``backend_id`` is updated to the new backend's own id, and the
in-memory transport is replaced -- never a silent reinterpretation of the
initial (fixture) turn's identity.

Uses the exact acceptance-heading/verifier-selection fix from RUN_049 PART A/B
(an explicit ``MANDATORY ACCEPTANCE CRITERIA`` goal with 8 numbered items),
so this rehearsal doubles as an integration proof for that fix.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from admissible.agent_backend import AgentBackend, CallableBackendTransport, FixtureAgentBackend
from admissible.control_surface import ControlSurfaceController
from admissible.governed_run import FINAL_OUTCOMES
from admissible.high_autonomy_controller import REPAIR_PHASE_REPAIR_NEEDED

REHEARSAL_GOAL = (
    "Build a small local tool.\n\n"
    "MANDATORY ACCEPTANCE CRITERIA\n"
    "1. index.html exists.\n"
    "2. style.css exists.\n"
    "3. game.js exists.\n"
    "4. Arrow keys move the player.\n"
    "5. WASD keys move the player.\n"
    "6. Collecting an item increases the score.\n"
    "7. The R key restarts the game.\n"
    "8. LOCAL_DEV.md explains how to run it locally.\n"
)

# Deterministically complete except for the one targeted repair (RUN_049 PART
# F.29: "add missing WASD bindings ... or another existing deterministic
# criterion" -- this rehearsal uses the R-key restart criterion instead, since
# it maps 1:1 to its own dedicated verifier (game_restart_check) with no
# overlap with any other criterion's check, unlike arrow/WASD which currently
# share one combined check -- see the RUN_049 report's limitations section).
INITIAL_GAME_JS_MISSING_RESTART = (
    "const keys = {};\n"
    "window.addEventListener('keydown', e => { keys[e.key] = true; });\n"
    "window.addEventListener('keyup', e => { keys[e.key] = false; });\n"
    "let player = { x: 0, y: 0 };\n"
    "let score = 0;\n"
    "function update() {\n"
    "  if (keys['ArrowUp'] || keys['w'] || keys['W']) player.y -= 1;\n"
    "  if (keys['ArrowDown'] || keys['s'] || keys['S']) player.y += 1;\n"
    "  if (keys['ArrowLeft'] || keys['a'] || keys['A']) player.x -= 1;\n"
    "  if (keys['ArrowRight'] || keys['d'] || keys['D']) player.x += 1;\n"
    "}\n"
    "function collectItem() {\n"
    "  score += 10;\n"
    "}\n"
)

REPAIR_INSTRUCTION_TEMPLATE = (
    "Repair exactly one failing acceptance criterion in the existing local project.\n\n"
    "MANDATORY ACCEPTANCE CRITERIA\n"
    "1. index.html exists.\n"
    "2. style.css exists.\n"
    "3. game.js exists.\n"
    "4. Arrow keys move the player.\n"
    "5. WASD keys move the player.\n"
    "6. Collecting an item increases the score.\n"
    "7. The R key restarts the game.\n"
    "8. LOCAL_DEV.md explains how to run it locally.\n\n"
    "Criteria 1-6 and 8 already pass and must not be changed. Only criterion 7\n"
    "(\"The R key restarts the game.\") currently fails: game.js has no restart\n"
    "handling. Propose exactly one bounded write_file operation for the exact\n"
    "path `game.js` that ADDS a restart handler bound to the R key (accept\n"
    "either `event.key === 'r'`/`'R'` or `event.code === 'KeyR'`) which resets\n"
    "the score and player position, while PRESERVING every existing passing\n"
    "behavior (arrow/WASD movement, the score-increasing collectItem\n"
    "function). Do not touch any other file. Do not run any shell, network,\n"
    "dependency-install, or deploy operation -- propose the write only; do not\n"
    "execute it yourself.\n"
)


def _response(operations: list[dict[str, Any]]) -> str:
    return "\n".join(
        "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
        + json.dumps(operation, ensure_ascii=False)
        + "\n```"
        for operation in operations
    )


@dataclass
class PreRepairSession:
    controller: ControlSurfaceController
    workspace: Path
    session_root: Path

    def acceptance_statuses(self) -> dict[str, str]:
        ha = self.controller._high_autonomy_state()
        return {c["criterion_id"]: c["status"] for c in ha.acceptance_criteria}


def build_deterministic_pre_repair_session(
    session_root: str | Path,
    *,
    goal: str = REHEARSAL_GOAL,
    game_js: str = INITIAL_GAME_JS_MISSING_RESTART,
    max_turns: int = 10,
    closure_reserve_turns: int = 2,
) -> PreRepairSession:
    """Build the RUN_049 PART F.28 deterministic legitimate pre-repair state.

    Uses only a scripted ``FixtureAgentBackend`` for the initial implementation
    turn -- zero real model calls. Ticks forward until the run reaches
    ``repair_phase == repair_needed``; raises if that state is not reached
    (never silently returns a session in the wrong phase).
    """
    root = Path(str(session_root))
    workspace = root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    initial_ops = [
        {"operation": "write_file", "path": "index.html", "content": "<!doctype html><html></html>\n"},
        {"operation": "write_file", "path": "style.css", "content": "body { margin: 0; }\n"},
        {"operation": "write_file", "path": "game.js", "content": game_js},
        {
            "operation": "write_file",
            "path": "LOCAL_DEV.md",
            "content": "To run locally, open index.html directly in your browser.\n",
        },
    ]
    backend = FixtureAgentBackend(responses=[_response(initial_ops)])
    controller = ControlSurfaceController(session_dir=root / "sessions")
    controller.submit_goal(goal)
    controller.start_high_autonomy_run(
        workspace_path=str(workspace),
        backend=backend,
        max_turns=max_turns,
        closure_reserve_turns=closure_reserve_turns,
    )

    for _ in range(30):
        state = controller.tick_high_autonomy_run()
        summary = state["high_autonomy_summary"]
        if summary.get("repair_phase") == REPAIR_PHASE_REPAIR_NEEDED:
            return PreRepairSession(controller=controller, workspace=workspace, session_root=root)
        if summary.get("outcome") in FINAL_OUTCOMES:
            raise RuntimeError(
                f"Deterministic pre-repair fixture reached a terminal outcome "
                f"({summary.get('outcome')}) before repair_needed; expected exactly "
                "one static criterion to fail."
            )
    raise RuntimeError("Deterministic pre-repair fixture never reached repair_needed within budget.")


def _snapshot(root: Path) -> dict[str, str]:
    from admissible.diagnostics.acp_real_probe import snapshot_workspace

    return snapshot_workspace(root)


def _diff(before: dict[str, str], after: dict[str, str]) -> dict[str, Any]:
    from admissible.diagnostics.acp_real_probe import diff_workspace_snapshots

    return diff_workspace_snapshots(before, after)


@dataclass
class RepairRehearsalResult:
    """Durable record of one real (or fake, for tests) repair rehearsal."""

    backend_id: str
    pre_swap_backend_id: str | None
    ticks: list[dict[str, Any]] = field(default_factory=list)
    final_outcome: str | None = None
    final_acceptance_statuses: dict[str, str] = field(default_factory=dict)
    all_eight_pass: bool = False
    model_turn_count: int = 0
    workspace_mutation_before_execution: dict[str, Any] | None = None
    workspace_paths_added: list[str] = field(default_factory=list)
    workspace_paths_removed: list[str] = field(default_factory=list)
    workspace_paths_modified: list[str] = field(default_factory=list)
    tool_event_count: int = 0
    acp_invocation_state: str | None = None
    acp_request_id: str | None = None
    acp_session_id: str | None = None
    plan_mode_enforced: bool | None = None
    managed_process_result: dict[str, Any] | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def drive_repair_round(
    session: PreRepairSession,
    backend: "AgentBackend",
    *,
    instruction: str = REPAIR_INSTRUCTION_TEMPLATE,
    max_ticks: int = 15,
) -> RepairRehearsalResult:
    """Swap in ``backend`` for exactly one repair round and drive it to a terminal state.

    Snapshots the target workspace immediately before and after the repair
    round's *first* tick (the one that invokes the backend) to prove the model
    turn itself never mutated the target workspace (PART D.25/F.32: zero
    pre-execution mutation) -- the legitimate bounded write happens on a
    *later* tick, after admission.
    """
    controller = session.controller
    ha = controller._high_autonomy_state()
    pre_swap_backend_id = ha.backend_id
    ha.backend_id = backend.backend_id
    # The repair instruction is deterministic here (built by this harness, not
    # the controller's own generic repair-packet composer) -- the point of
    # this rehearsal is the real *model* repair response and lifecycle, not
    # exercising repair-instruction authoring.
    controller._set_high_autonomy_state(ha)
    controller._high_autonomy_transport = CallableBackendTransport(
        backend,
        target_workspace_path=str(session.workspace),
        agent_workspace_path=ha.agent_workspace_path or str(session.workspace),
    )
    controller._persist()

    result = RepairRehearsalResult(backend_id=backend.backend_id, pre_swap_backend_id=pre_swap_backend_id)
    before_snapshot: dict[str, str] | None = None
    first_tick_done = False

    for _ in range(max_ticks):
        if not first_tick_done:
            before_snapshot = _snapshot(session.workspace)
        t0 = time.perf_counter()
        state = controller.tick_high_autonomy_run()
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        summary = state["high_autonomy_summary"]
        result.ticks.append(
            {
                "elapsed_ms": elapsed_ms,
                "mode": summary.get("mode"),
                "next_action": summary.get("next_action"),
                "repair_phase": summary.get("repair_phase"),
                "outcome": summary.get("outcome"),
                "current_step": summary.get("current_step"),
            }
        )
        if not first_tick_done:
            after_snapshot = _snapshot(session.workspace)
            diff = _diff(before_snapshot or {}, after_snapshot)
            result.workspace_mutation_before_execution = diff
            first_tick_done = True

            ha_after = controller._high_autonomy_state()
            invocation = (ha_after.invocation_history or [None])[-1]
            if invocation:
                telemetry = invocation.get("acp_telemetry") or {}
                result.acp_invocation_state = invocation.get("acp_invocation_state")
                result.acp_request_id = invocation.get("acp_request_id")
                result.acp_session_id = invocation.get("acp_session_id")
                result.plan_mode_enforced = telemetry.get("plan_mode_enforced")
                result.managed_process_result = invocation.get("managed_process_result")
                result.error_message = invocation.get("error_message")
                progress_events = telemetry.get("progress_events") or []
                result.tool_event_count = sum(
                    1 for e in progress_events if e.get("event_type") == "tool_call"
                )
                result.model_turn_count = 1

        if summary.get("outcome") in FINAL_OUTCOMES:
            break

    ha_final = controller._high_autonomy_state()
    result.final_outcome = ha_final.outcome
    result.final_acceptance_statuses = {c["criterion_id"]: c["status"] for c in ha_final.acceptance_criteria}
    result.all_eight_pass = all(
        status in ("verified_pass", "waived") for status in result.final_acceptance_statuses.values()
    ) and len(result.final_acceptance_statuses) == 8
    diff = result.workspace_mutation_before_execution or {}
    result.workspace_paths_added = list(diff.get("paths_added") or [])
    result.workspace_paths_removed = list(diff.get("paths_removed") or [])
    result.workspace_paths_modified = list(diff.get("paths_modified") or [])
    return result


__all__ = [
    "REHEARSAL_GOAL",
    "INITIAL_GAME_JS_MISSING_RESTART",
    "REPAIR_INSTRUCTION_TEMPLATE",
    "PreRepairSession",
    "RepairRehearsalResult",
    "build_deterministic_pre_repair_session",
    "drive_repair_round",
]
