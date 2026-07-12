"""RUN_049 PART C -- Run Identity backend/transport projection tests.

RUN_046 root-caused control_surface.html's ``renderRunIdentity()`` reading
``state.high_autonomy``/``state.control`` (never set by the server) instead of
the real ``state.high_autonomy_summary``/``state.agent_backend_control`` keys
(see ``test_admissible_callable_transport_forensic_regression.py`` for the
fix's HTML-level assertions). This module tests the underlying Python data the
now-fixed frontend actually consumes: ``describe_available_backends()``'s
transport/model-label projection (pre-invocation identity, PART C.15-17) and
``ControlSurfaceController``'s persisted ``backend_id`` (post-invocation and
imported-session consistency, PART C.18).

Fake providers/transcripts only -- no real Cursor/model/browser process.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from admissible.agent_backend import FixtureAgentBackend, describe_available_backends
from admissible.control_surface import ControlSurfaceController
from admissible.cursor_acp_transport import TRANSPORT_LABEL_ACP, TRANSPORT_LABEL_ONESHOT

GOAL = """Build a tiny counter app.

Mandatory deliverables:
- index.html

Acceptance criteria:
1. Expose a read-only debugging interface: window.__APP__ with a snapshot returning at least: count.
"""


class PreInvocationBackendIdentityTests(unittest.TestCase):
    """PART C.15/C.18 -- exact backend+transport identity before any invocation.

    ``describe_available_backends()`` is a pure discovery function -- it never
    depends on a session or run having started, so these assertions hold
    identically before the first invocation.
    """

    def test_pre_invocation_acp_identity(self) -> None:
        backends = {b["backend_id"]: b for b in describe_available_backends({"ADMISSIBLE_CURSOR_TRANSPORT": "acp"})}
        cursor = backends["cursor_cli"]
        self.assertEqual(cursor["transport"], "acp")
        self.assertEqual(cursor["transport_label"], TRANSPORT_LABEL_ACP)
        self.assertEqual(cursor["transport_label"], "Cursor Agent ACP")
        self.assertIn("model_label", cursor)
        self.assertTrue(cursor["model_label"])
        # Backend family, transport, and model label are distinct fields (PART C.17).
        self.assertEqual(cursor["backend_id"], "cursor_cli")
        self.assertNotEqual(cursor["backend_id"], cursor["transport_label"])

    def test_pre_invocation_oneshot_identity(self) -> None:
        backends = {b["backend_id"]: b for b in describe_available_backends({"ADMISSIBLE_CURSOR_TRANSPORT": "oneshot"})}
        cursor = backends["cursor_cli"]
        self.assertEqual(cursor["transport"], "oneshot")
        self.assertEqual(cursor["transport_label"], TRANSPORT_LABEL_ONESHOT)
        self.assertEqual(cursor["transport_label"], "Cursor Agent one-shot")
        self.assertIn("model_label", cursor)

    def test_unavailable_transport_reports_capability_state_not_a_crash(self) -> None:
        # In this test environment cursor-agent's real availability depends on
        # host PATH configuration; either way, describe_available_backends
        # must always return a well-formed availability/status projection
        # instead of raising or silently claiming "healthy".
        backends = {b["backend_id"]: b for b in describe_available_backends({"ADMISSIBLE_CURSOR_TRANSPORT": "acp"})}
        cursor = backends["cursor_cli"]
        availability = cursor["availability"]
        self.assertIn("available", availability)
        self.assertIn("status", availability)
        self.assertIsInstance(availability["available"], bool)


class PostInvocationAndImportedSessionConsistencyTests(unittest.TestCase):
    """PART C.18 -- backend identity survives re-render and session import."""

    def _start_fixture_run(self, tmp_path: Path) -> ControlSurfaceController:
        controller = ControlSurfaceController(session_dir=tmp_path / "sessions")
        workspace = tmp_path / "workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / "index.html").write_text("<html></html>", encoding="utf-8")
        controller.submit_goal(GOAL)
        controller.start_high_autonomy_run(
            workspace_path=str(workspace),
            backend=FixtureAgentBackend(),
            max_turns=4,
        )
        return controller

    def test_post_invocation_backend_identity_is_stable_across_rerenders(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            controller = self._start_fixture_run(Path(tmp))
            first = controller.state_view()
            second = controller.state_view()
            self.assertEqual(first["high_autonomy_summary"]["backend_id"], "fixture")
            self.assertEqual(
                first["high_autonomy_summary"]["backend_id"],
                second["high_autonomy_summary"]["backend_id"],
            )
            # The backend actually governing the run is resolvable in the
            # same backends list Run Identity now reads.
            backend_ids = {b["backend_id"] for b in first["agent_backend_control"]["backends"]}
            self.assertIn(first["high_autonomy_summary"]["backend_id"], backend_ids)

    def test_imported_session_preserves_recorded_backend_identity(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            controller_a = self._start_fixture_run(Path(tmp) / "a")
            exported = controller_a.session_dict()
            original_backend_id = exported["high_autonomy_run"]["backend_id"]

            controller_b = ControlSurfaceController(session_dir=Path(tmp) / "b" / "sessions")
            controller_b.import_session(exported)
            imported_state = controller_b.state_view()

            self.assertEqual(
                imported_state["high_autonomy_summary"]["backend_id"], original_backend_id
            )
            # Import must never silently reinterpret the recorded backend/transport.
            self.assertEqual(original_backend_id, "fixture")


if __name__ == "__main__":
    unittest.main()
