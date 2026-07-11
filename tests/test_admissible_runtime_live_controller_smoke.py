"""RUN_044 PART P: opt-in real-browser CONTROLLER smoke test.

Unlike tests/test_admissible_browser_runtime_live_smoke.py (RUN_043, which
calls ChromiumCdpRuntimeProvider directly), this exercises the real
end-to-end path: ControlSurfaceController.start_high_autonomy_run ->
tick_high_autonomy_run auto-triggering the runtime orchestrator -> a real
installed browser -> evidence applied to the acceptance ledger -> completion
eligibility. No provider is called directly.

Marked ``browser_runtime``; skipped honestly when no allowlisted browser is
installed (PART P.69). Never depends on network access; only ever serves the
local fixture over the loopback-only workspace server.
"""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

import pytest

from admissible.browser_runtime.chromium_provider import ChromiumCdpRuntimeProvider

from tests._run044_helpers import force_static_verification_final, make_controller

_CAPABILITY = ChromiumCdpRuntimeProvider().detect_capability()
_SKIP_REASON = None if _CAPABILITY.available else f"no allowlisted browser detected: {_CAPABILITY.unavailable_reason}"

pytestmark = pytest.mark.browser_runtime
_skip = pytest.mark.skipif(_SKIP_REASON is not None, reason=_SKIP_REASON or "")

COUNTER_FIXTURE_DIR = Path(__file__).parent / "fixtures" / "admissible" / "browser_runtime" / "counter"

COUNTER_CONTROLLER_GOAL = """Build a tiny counter app.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. Expose a read-only debugging interface: window.__COUNTER__ with a snapshot returning at least: count.
"""


def _copy_fixture(src: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        if item.is_file():
            (dest / item.name).write_bytes(item.read_bytes())


def _tick_with_real_timeout(controller, *, timeout_seconds: float = 45.0) -> dict[str, Any]:
    """A real Chromium launch is far slower than the fixture provider, so
    poll ticks need real wall-clock patience (with a short sleep between
    ticks) rather than a fixed small tick count."""

    deadline = time.monotonic() + timeout_seconds
    state = controller.state_view()
    while time.monotonic() < deadline:
        state = controller.tick_high_autonomy_run()
        if state["high_autonomy_summary"]["mode"] in ("stopped", "failed"):
            return state
        time.sleep(0.25)
    return state


@_skip
class TestRealBrowserControllerSmoke(unittest.TestCase):
    def test_controller_auto_triggers_real_runtime_verification_and_completes(self):
        """PART P.67."""
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            workspace = root / "workspace"
            _copy_fixture(COUNTER_FIXTURE_DIR, workspace)
            controller = make_controller(root)
            # No set_runtime_provider() call: this deliberately exercises the
            # controller's real default (admissible.runtime_verification_orchestrator.default_runtime_provider).
            controller.submit_goal(COUNTER_CONTROLLER_GOAL)
            controller.start_high_autonomy_run(workspace_path=str(workspace), max_turns=8)
            force_static_verification_final(controller, workspace)

            final = _tick_with_real_timeout(controller)
            summary = final["high_autonomy_summary"]

            self.assertEqual(summary["outcome"], "completed")
            criterion = summary["acceptance_criteria"][0]
            self.assertEqual(criterion["status"], "verified_pass")

            history = summary["runtime_attempt_history"]
            self.assertEqual(len(history), 1)
            evidence_id = history[0]["evidence_id"]

            from admissible.runtime_verification_orchestrator import find_persisted_evidence

            evidence = find_persisted_evidence(str(workspace), evidence_id)
            self.assertIsNotNone(evidence)
            self.assertFalse(evidence.external_request_attempts, "no external network")
            cleanup = evidence.resource_cleanup
            self.assertTrue(cleanup.get("browser_process_terminated"))
            self.assertTrue(cleanup.get("http_server_stopped"))
            self.assertTrue(cleanup.get("temporary_profile_removed"))
            self.assertEqual(cleanup.get("orphan_processes"), [], "no orphan process")

    # PART P.68 (policy-violation real-browser controller smoke) is
    # deliberately not included here. Both an immediate on-script-parse
    # fetch and a "press T to trigger a network request"-derived key_press
    # (plan_builder's only generic input-dispatch pattern outside a
    # snapshot-comparison loop) race the real browser's async event/CDP
    # round-trip: plan_builder never inserts a wait_bounded between a bare
    # named-control key_press and the next assertion unless the criterion
    # also declares a snapshot comparison, so `assert_no_external_requests`
    # can run before the fetch's Fetch.requestPaused event arrives. Forcing
    # this through the fully-automatic contract-derived plan path would
    # produce a flaky test; RUN_043's own real-browser policy-violation
    # coverage (test_admissible_browser_runtime_live_smoke.py, which
    # deliberately builds an explicit plan with a click_selector step) is
    # the validated, passing test for this exact scenario. The controller
    # auto-trigger and completion path itself is covered above.


if __name__ == "__main__":
    unittest.main()
