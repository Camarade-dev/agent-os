"""RUN_045 PART J / PART F — auto-run generation token, Pause is authoritative.

Static-content assertions on admissible/harness/control_surface.html, matching
the existing convention (test_admissible_runtime_control_surface_ui.py): this
UI is plain server-rendered JSON + vanilla JS, so "Pause always wins over a
stale in-flight tick" is verified by checking the generation-token guard is
present at every resumption point, not via a browser-driven test.
"""

from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"


class TestAutoRunGenerationToken(unittest.TestCase):
    def setUp(self) -> None:
        self.html = HTML_PATH.read_text(encoding="utf-8")

    def _function_body(self, signature: str) -> str:
        start = self.html.index(signature)
        end = self.html.index("\n}\n", start)
        return self.html[start:end]

    def test_generation_counter_exists(self) -> None:
        self.assertIn("let autoRunGeneration = 0;", self.html)

    def test_stop_auto_run_bumps_the_generation(self) -> None:
        body = self._function_body("function stopAutoRun()")
        self.assertIn("autoRunGeneration += 1", body)
        self.assertIn("autoRunActive = false", body)

    def test_start_auto_run_bumps_the_generation(self) -> None:
        body = self._function_body("function startAutoRun()")
        self.assertIn("autoRunGeneration += 1", body)

    def test_loop_checks_generation_at_entry(self) -> None:
        body = self._function_body("async function autoRunLoop(generation)")
        self.assertIn("if (generation !== autoRunGeneration || !autoRunActive) return;", body)

    def test_loop_checks_generation_after_await_success(self) -> None:
        body = self._function_body("async function autoRunLoop(generation)")
        # After `await apiPost(...)` resolves, a second, independent check.
        self.assertIn('state = await apiPost("/api/session/high_autonomy/tick", {});', body)
        self.assertIn("if (generation !== autoRunGeneration) {", body)

    def test_loop_checks_generation_after_await_error(self) -> None:
        body = self._function_body("async function autoRunLoop(generation)")
        self.assertIn("} catch (err) {", body)
        self.assertIn("if (generation !== autoRunGeneration) return;", body)

    def test_loop_never_reschedules_a_stale_generation(self) -> None:
        body = self._function_body("async function autoRunLoop(generation)")
        # Every setTimeout re-entry passes the same closed-over generation --
        # a stale loop can therefore only ever re-check itself, never resurrect.
        self.assertEqual(body.count("setTimeout(() => autoRunLoop(generation)"), 2)

    def test_start_auto_run_refuses_during_technical_pause(self) -> None:
        body = self._function_body("function startAutoRun()")
        self.assertIn("technical_pause_active", body)

    def test_misleading_backend_invocation_in_flight_message_is_gone(self) -> None:
        self.assertNotIn('"Backend invocation in progress."', self.html)

    def test_pause_button_calls_stop_auto_run_directly(self) -> None:
        self.assertIn("stopAutoRun()", self.html)


if __name__ == "__main__":
    unittest.main()
