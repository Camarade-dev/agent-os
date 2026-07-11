"""Shared setup helpers for RUN_044 runtime-orchestration tests.

Not a test module itself (no ``test_`` prefix); imported by the
``test_admissible_runtime_*``/``test_admissible_neon_runtime_end_to_end``
modules that exercise the RUN_044 orchestration layer end to end through
``ControlSurfaceController``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController

COUNTER_GOAL = """Build a tiny counter app.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. Expose a read-only debugging interface: window.__APP__ with a snapshot returning at least: count.
"""

# Two independent deterministic-runtime criteria (debug interface + an
# external-network prohibition), so single-attempt/single-plan tests can
# assert on more than one criterion id without pulling in the full Neon goal.
TWO_CRITERIA_GOAL = """Build a tiny counter app.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. Expose a read-only debugging interface: window.__APP__ with a snapshot returning at least: count.
2. The app must make no external network requests.
"""

FORM_GOAL = """Build a small local form app.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. Expose a read-only debugging interface: window.__FORM__ with a snapshot returning at least: valid.
2. The app must make no external network requests.
"""

ANIMATION_LOOP_GOAL = """Build a tiny local animation demo.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. Press R to restart; the app must not create duplicate animation loops.
2. Expose a read-only debugging interface: window.__LOOP__ with a snapshot returning at least: loopStarts.
"""

POLICY_VIOLATION_GOAL = """Build a tiny local widget app.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. Expose a read-only debugging interface: window.__WIDGET__ with a snapshot returning at least: count.
2. The app must make no external network requests.
"""

UNOBSERVABLE_GOAL = """Build a tiny local mystery app.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. The active entity count must update live during play.
"""


def make_controller(tmp_path: Path, *, subdir: str = "sessions") -> ControlSurfaceController:
    return ControlSurfaceController(session_dir=tmp_path / subdir)


def write_index_html(workspace: Path) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "index.html").write_text("<html><body>hi</body></html>", encoding="utf-8")


def start_run(
    controller: ControlSurfaceController,
    goal_text: str,
    workspace: Path,
    *,
    max_turns: int = 8,
    transport: Any = None,
) -> dict[str, Any]:
    write_index_html(workspace)
    controller.submit_goal(goal_text)
    return controller.start_high_autonomy_run(
        workspace_path=str(workspace),
        transport=transport or FixtureAgentTransport(),
        max_turns=max_turns,
    )


def force_static_verification_final(controller: ControlSurfaceController, workspace: Path) -> dict[str, Any]:
    """Run the (possibly empty) static acceptance-ledger verification pass once.

    Mirrors what a real run already has by the time bounded writes and
    static checks are done, without needing to drive the full multi-turn
    agent-loop machinery for tests whose focus is the runtime orchestration
    layer itself (already covered by other RUN_029/033 test modules).
    """

    return controller.verify_bounded_local_workspace(
        {"workspace_path": str(workspace), "profile": "acceptance_ledger"}
    )


def tick_until(
    controller: ControlSurfaceController,
    *,
    max_ticks: int = 20,
    stop_modes: tuple[str, ...] = ("stopped", "failed"),
) -> dict[str, Any]:
    state = controller.state_view()
    for _ in range(max_ticks):
        state = controller.tick_high_autonomy_run()
        if state["high_autonomy_summary"]["mode"] in stop_modes:
            break
    return state


def tick_n(controller: ControlSurfaceController, n: int) -> dict[str, Any]:
    state = controller.state_view()
    for _ in range(n):
        state = controller.tick_high_autonomy_run()
    return state
