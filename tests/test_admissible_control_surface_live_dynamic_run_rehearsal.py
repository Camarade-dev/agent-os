"""Slice ADMISSIBLE_DEMO_012_CONTROL_SURFACE_LIVE_DYNAMIC_RUN_REHEARSAL.

Rehearses the tiny local game dynamic run through the Control Surface HTTP
bridge path (same endpoints the browser UI calls), not only direct controller
unit tests.

Flow: fresh session -> goal -> bridge write instruction -> fixture as
agent-response.md -> bridge ingest -> verify structured ops eligible ->
explicit bounded local writes via HTTP -> verify files + sha256 evidence.

Hard constraints: no providers, no shell/npm/git/deploy/network execution,
no agent_os import, no auto-execute on ingest, gates unchanged.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import unittest
import unittest.mock as mock
import urllib.error
import urllib.request
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
from admissible.runner.control_surface import build_controller, make_server
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = (
    REPO_ROOT
    / "benchmark"
    / "long_run_scenarios"
    / "cursor_slither_demo"
    / "fixtures"
    / "pasted_agent_responses"
)
TINY_GAME_FIXTURE = "tiny_local_game_structured_scaffold.txt"
GAME_FILES = ("index.html", "style.css", "game.js")

CANONICAL_GOAL_PROMPT = (
    "Scaffold a tiny local-only browser game in a local workspace. "
    "Keep it local-only unless I explicitly approve otherwise."
)


def _raise_on_subprocess(*args, **kwargs):
    raise AssertionError("control surface live rehearsal must never spawn a subprocess")


class TestControlSurfaceLiveDynamicRunRehearsal(unittest.TestCase):
    """HTTP bridge rehearsal for the tiny local game structured fixture."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmpdir.name)
        cls.session_dir = cls.root / "sessions"
        cls.workspace = cls.root / "workspace"
        cls.workspace.mkdir()
        controller = build_controller(session_dir=cls.session_dir, fresh_session=True)
        cls.server = make_server(controller, host="127.0.0.1", port=0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls._tmpdir.cleanup()

    def _get(self, path: str) -> tuple[int, dict]:
        try:
            with urllib.request.urlopen(self.base_url + path, timeout=10) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _post(self, path: str, body: dict | None = None) -> tuple[int, dict]:
        payload = json.dumps(body or {}).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def _game_files_present(self) -> list[str]:
        return [name for name in GAME_FILES if (self.workspace / name).is_file()]

    def _game_action_ids(self, state: dict) -> list[str]:
        return [i["action_id"] for i in state["queue"] if i["action_type"] == "create_file"]

    def test_control_surface_bridge_path_tiny_local_game_dynamic_run(self) -> None:
        raw = load_fixture(FIXTURES_DIR / TINY_GAME_FIXTURE)

        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            status, state = self._post("/api/session/reset", {})
            self.assertEqual(status, 200)
            self.assertEqual(state["run_loop"]["current_turn"], 0)

            status, state = self._post("/api/session/goal", {"prompt": CANONICAL_GOAL_PROMPT})
            self.assertEqual(status, 200)
            self.assertIn("goal_intake", state)
            self.assertIn("plan_audit", state)

            status, write_state = self._post(
                "/api/session/run_loop/bridge/write_instruction",
                {"workspace_path": str(self.workspace)},
            )
            self.assertEqual(status, 200)
            instruction_path = Path(write_state["bridge"]["instruction_path"])
            self.assertTrue(instruction_path.is_file())
            self.assertIn("next-agent-instruction.md", instruction_path.name)

            bridge_dir = self.workspace / ".admissible"
            bridge_dir.mkdir(parents=True, exist_ok=True)
            (bridge_dir / "agent-response.md").write_text(raw, encoding="utf-8")
            self.assertEqual(self._game_files_present(), [])

            status, ingest_state = self._post(
                "/api/session/run_loop/bridge/ingest_response",
                {"workspace_path": str(self.workspace)},
            )
            self.assertEqual(status, 200)
            self.assertEqual(ingest_state["bridge"]["action_count"], 3)

        game_items = [i for i in ingest_state["queue"] if i["action_type"] == "create_file"]
        self.assertEqual(len(game_items), 3)
        for item in game_items:
            self.assertEqual(item["decision"], "ALLOW")
            self.assertTrue(item["bounded_execution_eligible"])
            self.assertIsNone(item["bounded_execution_diagnostic"])
            self.assertEqual(item["bounded_execution_message"], "Eligible for bounded local execution.")
            self.assertEqual(item["structured_operation_count"], 1)
            self.assertEqual(item["execution_status"], "proposed_only")

        self.assertEqual(self._game_files_present(), [])
        self.assertFalse(ingest_state["mission_summary"]["side_effect_executed_by_admissible"])

        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            for action_id in self._game_action_ids(ingest_state):
                status, exec_state = self._post(
                    f"/api/queue/{action_id}/execute_bounded_local",
                    {"workspace_path": str(self.workspace)},
                )
                self.assertEqual(status, 200, exec_state)
                item = next(i for i in exec_state["queue"] if i["action_id"] == action_id)
                self.assertEqual(item["execution_status"], EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR)

        self.assertEqual(self._game_files_present(), list(GAME_FILES))
        self.assertIn("<!doctype html>", (self.workspace / "index.html").read_text(encoding="utf-8").lower())
        self.assertIn("canvas", (self.workspace / "style.css").read_text(encoding="utf-8").lower())
        self.assertIn("requestanimationframe", (self.workspace / "game.js").read_text(encoding="utf-8").lower())

        status, exported = self._get("/api/session/export")
        self.assertEqual(status, 200)
        evidence = exported["run_loop"]["evidence_records"]
        write_records = [r for r in evidence if r["source"] == "bounded_executor"]
        self.assertEqual(len(write_records), 3)
        self.assertEqual({r["file_path_or_note"] for r in write_records}, set(GAME_FILES))
        for record in write_records:
            self.assertIn("local_file_written", record["satisfies"])
            self.assertIn("workspace_scope_attested", record["satisfies"])
            self.assertTrue(record["sha256"])


class TestControlSurfaceHtmlSupportsBoundedRehearsal(unittest.TestCase):
    """Static checks that the UI exposes the bridge + bounded execution path."""

    _HTML_PATH = REPO_ROOT / "admissible" / "harness" / "control_surface.html"

    def test_bridge_and_bounded_execute_controls_present(self) -> None:
        html = self._HTML_PATH.read_text(encoding="utf-8")
        for marker in (
            'id="bridge-workspace-path"',
            'id="btn-bridge-write-instruction"',
            'id="btn-bridge-ingest-response"',
            "bounded-execute-form",
            "/api/session/run_loop/bridge/write_instruction",
            "/api/session/run_loop/bridge/ingest_response",
            "/execute_bounded_local",
            "Ready to execute locally",
            "/api/queue/execute_bounded_local_batch",
        ):
            self.assertIn(marker, html, f"missing UI marker: {marker}")


if __name__ == "__main__":
    unittest.main()
