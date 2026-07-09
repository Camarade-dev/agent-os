"""Slice ADMISSIBLE_UX_016_SAMPLE_DEMOTION_AND_SAFE_RESET.

Executable checks that the historical Slither sample is demoted to a secondary
examples affordance and that loading a sample cannot silently replace a
non-empty session.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import (
    SESSION_NOT_EMPTY_REASON,
    ControlSurfaceController,
    SessionNotEmptyError,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"
_LOCAL_GOAL = "Build a tiny local game page. Local only. Do not deploy."


class _ControllerCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.controller = ControlSurfaceController(
            session_dir=base / "sessions", repo_root=REPO_ROOT
        )
        self.addCleanup(self._tmp.cleanup)


class TestSampleDemotionHtml(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML_PATH.read_text(encoding="utf-8")

    def test_blank_html_does_not_show_slither_primary_copy(self) -> None:
        self.assertNotIn("Load sample Slither session", self.html)
        self.assertNotIn("Load sample session", self.html)

    def test_sample_control_is_secondary_in_examples_section(self) -> None:
        self.assertIn('id="examples-drawer"', self.html)
        self.assertIn("<details", self.html[self.html.index('id="examples-drawer"') - 20 : self.html.index('id="examples-drawer"') + 20])
        self.assertIn("Load example session", self.html)
        sample_idx = self.html.index('id="btn-load-sample"')
        top_controls_end = self.html.index("</section>", self.html.index('id="top-controls"'))
        self.assertGreater(sample_idx, top_controls_end, "sample button must not live in top controls")
        btn_tag = self.html[self.html.rindex("<button", 0, sample_idx) : sample_idx + 60]
        self.assertIn("secondary", btn_tag)


class TestSafeSampleLoad(_ControllerCase):
    def test_blank_session_has_no_content_flag(self) -> None:
        view = self.controller.state_view()
        self.assertFalse(view["session_has_content"])
        self.assertFalse(view["has_goal"])

    def test_load_sample_succeeds_for_empty_session(self) -> None:
        state = self.controller.load_sample_session()
        self.assertTrue(state["is_sample_session"])
        self.assertGreater(len(state["queue"]), 0)
        self.assertIsNotNone(state["goal_intake"])

    def test_load_sample_without_force_rejects_non_empty_session(self) -> None:
        self.controller.submit_goal(_LOCAL_GOAL)
        with self.assertRaises(SessionNotEmptyError) as ctx:
            self.controller.load_sample_session()
        self.assertEqual(ctx.exception.detail.get("reason"), SESSION_NOT_EMPTY_REASON)

    def test_load_sample_without_force_does_not_wipe_goal(self) -> None:
        self.controller.submit_goal(_LOCAL_GOAL)
        before = self.controller.state_view()
        with self.assertRaises(SessionNotEmptyError):
            self.controller.load_sample_session()
        after = self.controller.state_view()
        self.assertEqual(after["goal_intake"], before["goal_intake"])
        self.assertEqual(after["queue"], before["queue"])
        self.assertFalse(after["is_sample_session"])

    def test_load_sample_with_force_succeeds_for_non_empty_session(self) -> None:
        self.controller.submit_goal(_LOCAL_GOAL)
        state = self.controller.load_sample_session(force=True)
        self.assertTrue(state["is_sample_session"])
        self.assertGreater(len(state["queue"]), 0)

    def test_load_sample_with_confirmed_alias_over_http(self) -> None:
        import json
        import threading
        import urllib.error
        import urllib.request

        from admissible.runner.control_surface import make_server

        self.controller.submit_goal(_LOCAL_GOAL)
        server = make_server(self.controller, port=0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        host, port = server.server_address
        base = f"http://{host}:{port}"

        def _post(path: str, body: dict) -> tuple[int, dict]:
            data = json.dumps(body).encode("utf-8")
            request = urllib.request.Request(
                base + path,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request) as response:
                    return response.status, json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read().decode("utf-8"))

        status, body = _post("/api/session/load_sample", {})
        self.assertEqual(status, 400)
        self.assertEqual(body.get("reason"), SESSION_NOT_EMPTY_REASON)

        status, state = _post("/api/session/load_sample", {"confirmed": True})
        self.assertEqual(status, 200)
        self.assertTrue(state["is_sample_session"])
        self.assertGreater(len(state["queue"]), 0)


if __name__ == "__main__":
    unittest.main()
