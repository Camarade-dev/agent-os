"""RUN_044 Control Surface UI tests (PART K).

Static-content assertions on admissible/harness/control_surface.html,
matching the existing test_html_high_autonomy_panel_is_primary style
(test_admissible_high_autonomy_governed_loop.py): this UI is plain
server-rendered JSON + vanilla JS, so "the UI shows X" is verified by
checking the JS renders the right fields/banners and wires the right
endpoints, not via a browser-driven screenshot test.
"""

from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"


class TestControlSurfaceRuntimeUi(unittest.TestCase):
    def setUp(self):
        self.html = HTML_PATH.read_text(encoding="utf-8")

    def test_renders_runtime_banner_field(self):
        self.assertIn("runtime_banner", self.html)
        self.assertIn("ha.runtime_banner", self.html)

    def test_renders_active_attempt_details(self):
        self.assertIn("active_runtime_attempt", self.html)
        self.assertIn("provider_id", self.html)
        self.assertIn("cleanup_status", self.html)

    def test_renders_human_observation_pending_with_three_actions(self):
        self.assertIn("human_observation_pending_criterion_ids", self.html)
        self.assertIn("Record observed pass", self.html)
        self.assertIn("Record observed fail", self.html)
        self.assertIn("Waive", self.html)

    def test_retry_and_cancel_buttons_call_the_narrow_endpoints(self):
        self.assertIn("btn-ha-runtime-retry", self.html)
        self.assertIn("btn-ha-runtime-cancel", self.html)
        self.assertIn("/api/session/high_autonomy/runtime/retry", self.html)
        self.assertIn("/api/session/high_autonomy/runtime/cancel", self.html)

    def test_human_observation_buttons_call_the_narrow_endpoint(self):
        self.assertIn("/api/session/high_autonomy/runtime/human_observation", self.html)
        self.assertIn("btn-ha-observe", self.html)

    def test_waive_requires_a_rationale_prompt_client_side(self):
        # Defense in depth: the server also rejects an empty rationale, but
        # the UI should not even try without one.
        self.assertIn("rationale", self.html.lower())

    def test_no_generic_script_or_selector_input_field_exists(self):
        forbidden = ("id=\"ha-runtime-selector", "id=\"ha-runtime-script", "id=\"ha-runtime-url")
        for token in forbidden:
            self.assertNotIn(token, self.html)


if __name__ == "__main__":
    unittest.main()
