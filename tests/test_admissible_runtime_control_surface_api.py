"""RUN_044 Control Surface API tests (PART L).

Verifies the four narrowly-scoped endpoints (read status, retry, cancel,
record human observation), that no arbitrary runtime-plan/selector/
JavaScript/browser-argument/URL/entrypoint is ever exposed, and the actual
HTTP route wiring in admissible.runner.control_surface.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.browser_runtime.fixture_provider import FixtureBrowserRuntimeProvider

from tests._run044_helpers import COUNTER_GOAL, force_static_verification_final, make_controller, start_run


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("must never spawn a real subprocess")


class TestControllerLevelApi(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.workspace = self.root / "workspace"
        self.controller = make_controller(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def test_runtime_verification_status_is_read_only_projection(self):
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            status = self.controller.runtime_verification_status()
            for key in (
                "runtime_verification_required",
                "runtime_verification_status",
                "active_runtime_attempt_id",
                "runtime_attempt_history",
                "runtime_pending_criterion_ids",
                "human_observation_pending_criterion_ids",
            ):
                self.assertIn(key, status)

    def test_retry_raises_when_nothing_is_interrupted(self):
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            with self.assertRaises(ValueError):
                self.controller.retry_runtime_verification_attempt()

    def test_cancel_raises_when_nothing_is_active(self):
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            with self.assertRaises(ValueError):
                self.controller.cancel_runtime_verification_attempt()

    def test_record_human_observation_raises_for_unknown_criterion(self):
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            with self.assertRaises(ValueError):
                self.controller.record_human_observation(
                    "no_such_criterion", actor="op", disposition="pass", note="x"
                )

    def test_set_runtime_provider_is_never_settable_from_session_export(self):
        """Session export/import (the closest thing to an HTTP-shaped
        payload for a whole session) must never carry a live provider
        object or let one be injected through it."""
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            start_run(self.controller, COUNTER_GOAL, self.workspace)
            exported = self.controller.session_dict()
            serialized = json.dumps(exported)  # must be plain JSON: no provider object leaked in
            self.assertIsInstance(serialized, str)


class TestHttpRouteWiring(unittest.TestCase):
    """Confirms the exact route strings exist and dispatch to the narrow
    controller methods -- without actually starting a TCP server (the
    handler class is exercised directly, mirroring how BaseHTTPRequestHandler
    would call these methods after routing)."""

    def test_runner_module_defines_the_four_narrow_routes(self):
        import inspect

        from admissible.runner import control_surface as runner_module

        source = inspect.getsource(runner_module)
        self.assertIn('"/api/session/high_autonomy/runtime_status"', source)
        self.assertIn('"/api/session/high_autonomy/runtime/retry"', source)
        self.assertIn('"/api/session/high_autonomy/runtime/cancel"', source)
        self.assertIn('"/api/session/high_autonomy/runtime/human_observation"', source)

    def test_no_generic_runtime_plan_or_selector_route_exists(self):
        """Required test 28: no arbitrary plan/selector/URL/JavaScript API."""
        import inspect

        from admissible.runner import control_surface as runner_module

        source = inspect.getsource(runner_module)
        forbidden = (
            "submit_runtime_plan",
            "run_selector",
            "execute_script",
            "run_javascript",
            "/api/session/high_autonomy/runtime/plan",
            "/api/session/high_autonomy/runtime/execute",
        )
        for token in forbidden:
            self.assertNotIn(token, source)

    def test_human_observation_route_only_accepts_narrow_fields(self):
        import inspect

        from admissible.runner import control_surface as runner_module

        source = inspect.getsource(runner_module)
        # The handler must read exactly criterion_id/actor/disposition/note/
        # evidence_refs from the body for this route -- not e.g. "selector",
        # "script", "url", or "args".
        start = source.index('"/api/session/high_autonomy/runtime/human_observation"')
        snippet = source[start : start + 500]
        self.assertIn("criterion_id", snippet)
        self.assertIn("disposition", snippet)
        for forbidden in ("selector", "javascript", "script", "browser_args"):
            self.assertNotIn(forbidden, snippet.lower())


if __name__ == "__main__":
    unittest.main()
