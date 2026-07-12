"""RUN_045 PART J / PART F — backend-progress banner truthfulness.

``computeProgressBanner`` must return one of six mutually exclusive labels,
and "BACKEND INVOCATION RUNNING" must require an actual queued/running
callable-backend invocation (``ha.backend_step === "invoking_agent"``), never
just "some HTTP request is in flight" -- that was the reported defect (an
ordinary tick, or a runtime-verification poll, showed the same misleading
"Backend invocation in progress" text as a real callable-agent call).

Static-content assertions, matching test_admissible_runtime_control_surface_ui.py.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"


class TestBackendProgressUiTruth(unittest.TestCase):
    def setUp(self) -> None:
        self.html = HTML_PATH.read_text(encoding="utf-8")
        start = self.html.index("function computeProgressBanner(ha)")
        end = self.html.index("\n}\n", start)
        self.banner_fn = self.html[start:end]

    def test_all_six_labels_present(self) -> None:
        for label in (
            "TECHNICAL PAUSE",
            "RUNTIME VERIFICATION RUNNING",
            "BACKEND INVOCATION RUNNING",
            "ADVANCING STATE",
            "AUTO-RUN ACTIVE",
            "AUTO-RUN PAUSED",
        ):
            self.assertIn(label, self.banner_fn)

    def test_backend_invocation_running_requires_invoking_agent_step(self) -> None:
        self.assertIn(
            'ha.is_callable_backend && ha.backend_step === "invoking_agent"', self.banner_fn
        )

    def test_backend_invocation_running_does_not_key_off_request_in_flight_alone(self) -> None:
        # The line that returns BACKEND INVOCATION RUNNING must not reference
        # requestInFlight -- that generic flag is true for *any* HTTP call
        # (an ordinary tick, a runtime poll, a plain refresh), not just a
        # real callable-backend invocation.
        line = next(
            line for line in self.banner_fn.splitlines() if "BACKEND INVOCATION RUNNING" in line
        )
        self.assertNotIn("requestInFlight", line)

    def test_technical_pause_takes_precedence_over_everything_else(self) -> None:
        lines = [l.strip() for l in self.banner_fn.splitlines() if "return" in l]
        self.assertTrue(lines[0].startswith("if (ha.technical_pause_active"))

    def test_advancing_state_uses_request_in_flight_generically(self) -> None:
        self.assertIn("if (requestInFlight) return \"ADVANCING STATE\";", self.banner_fn)

    def test_runtime_verification_running_keys_off_mode_not_request_in_flight(self) -> None:
        line = next(
            line for line in self.banner_fn.splitlines() if "RUNTIME VERIFICATION RUNNING" in line
        )
        self.assertIn('ha.mode === "runtime_verifying"', line)
        self.assertNotIn("requestInFlight", line)

    def test_render_auto_run_status_line_delegates_to_the_banner(self) -> None:
        self.assertIn("computeProgressBanner(ha)", self.html)
        # The old unconditional wording must not still exist alongside it.
        self.assertNotIn('parts.push("Backend invocation in progress")', self.html)

    def test_acp_specific_labels_present_and_gated_on_cursor_acp_backend(self) -> None:
        # RUN_049 PART K.48/51 -- four additional ACP-specific labels, plus
        # RUN COMPLETED, layered on top of (never replacing) the original six.
        for label in (
            "ACP SERVER STARTING",
            "ACP MODE CONFIRMATION",
            "ACP REQUEST RUNNING",
            "ACP RESPONSE READY",
            "RUN COMPLETED",
        ):
            self.assertIn(label, self.banner_fn)
        # Every ACP-specific branch is gated on the cursor_acp backend id, so
        # it never fires for file_bridge/fixture/cursor_cli one-shot runs.
        acp_lines = [
            line for line in self.banner_fn.splitlines()
            if any(lbl in line for lbl in ("ACP SERVER STARTING", "ACP MODE CONFIRMATION", "ACP REQUEST RUNNING", "ACP RESPONSE READY"))
        ]
        self.assertEqual(len(acp_lines), 4)
        for line in acp_lines:
            self.assertIn("acpState", line)

    def test_banner_function_is_a_pure_function_of_ha_and_module_flags(self) -> None:
        # Defense against regressions that thread request-specific args back in.
        signature = re.search(r"function computeProgressBanner\(([^)]*)\)", self.html)
        self.assertIsNotNone(signature)
        self.assertEqual(signature.group(1).strip(), "ha")


if __name__ == "__main__":
    unittest.main()
