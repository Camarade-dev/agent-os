"""Slice ADMISSIBLE_UX_018_EXECUTION_REVIEW_AND_BATCH_RUN tests.

Execution review UX for admitted bounded local file operations: workspace
persistence, queue visibility, ready-to-execute review panel, and explicit
batch execution after admission.
"""

from __future__ import annotations

import ast
import copy
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
from admissible.control_surface import ControlSurfaceController, RunEnvelope, _build_queue_item
from admissible.execution.bounded_local_executor import (
    DIAG_FORBIDDEN_OPERATION_CATEGORY,
    DIAG_NOT_ADMITTED,
)
from admissible.runner.control_surface import build_controller, make_server
from admissible.runner.extraction_lab import load_fixture

REPO_ROOT = Path(__file__).resolve().parent.parent
ADMISSIBLE_ROOT = REPO_ROOT / "admissible"
HTML_PATH = ADMISSIBLE_ROOT / "harness" / "control_surface.html"
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
    raise AssertionError("execution review UX tests must never spawn a subprocess")


def _local_allow_decision(action_id: str) -> dict:
    return {
        "action_id": action_id,
        "decision_id": f"decision_{action_id}",
        "envelope_id": f"envelope_{action_id}",
        "decision": "ALLOW",
        "operational_admissibility_action": "execute",
        "risk_level": "local",
        "required_approval": "none",
        "missing_evidence": [],
        "audit_trace": {"blast_radius": "blast_radius=local"},
    }


def _inject_queue_item(
    controller: ControlSurfaceController,
    *,
    action_id: str = "action_write_001",
    decision: dict | None = None,
    candidate: dict | None = None,
    execution_status: str = "proposed_only",
) -> str:
    decision = decision or _local_allow_decision(action_id)
    candidate = candidate or {
        "action_id": action_id,
        "envelope_id": decision["envelope_id"],
        "action_type": "create_file",
        "tool_or_command": "write index.html",
        "execution_status": execution_status,
        "structured_operations": [
            {"operation": "write_file", "path": "index.html", "content": "<!doctype html><html></html>"}
        ],
    }
    envelope = RunEnvelope(
        action_id=action_id,
        envelope_id=decision.get("envelope_id"),
        decision_id=decision.get("decision_id"),
        candidate=candidate,
        decision=decision,
    )
    item = _build_queue_item(envelope)
    item.execution_status = execution_status
    controller._session.run_envelopes[action_id] = envelope
    controller._session.queue.append(item)
    return action_id


class TestExecutionReviewStateView(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_state_view_exposes_session_workspace_after_bridge_workspace_set(self) -> None:
        state = self.controller.set_bounded_executor_workspace(self.workspace)
        self.assertEqual(state["bounded_executor_workspace"], str(self.workspace.resolve()))

    def test_queue_projection_exposes_structured_operation_count(self) -> None:
        _inject_queue_item(self.controller)
        item = self.controller.state_view()["queue"][0]
        self.assertEqual(item["structured_operation_count"], 1)
        self.assertEqual(item["bounded_execution_operation_types"], ["write_file"])

    def test_queue_projection_exposes_target_path_for_write_file(self) -> None:
        _inject_queue_item(self.controller)
        item = self.controller.state_view()["queue"][0]
        self.assertEqual(item["bounded_execution_target_paths"], ["index.html"])

    def test_ready_list_includes_admitted_eligible_local_write_actions(self) -> None:
        _inject_queue_item(self.controller)
        self.controller.set_bounded_executor_workspace(self.workspace)
        ready = self.controller.state_view()["ready_to_execute_locally"]
        self.assertEqual(len(ready), 1)
        self.assertEqual(ready[0]["operation"], "write_file")
        self.assertEqual(ready[0]["path"], "index.html")

    def test_ready_list_excludes_non_admitted_actions(self) -> None:
        _inject_queue_item(
            self.controller,
            action_id="refused",
            decision={**_local_allow_decision("refused"), "decision": "REFUSE"},
        )
        self.controller.set_bounded_executor_workspace(self.workspace)
        ready = self.controller.state_view()["ready_to_execute_locally"]
        self.assertEqual(ready, [])

    def test_ready_list_excludes_already_executed_actions(self) -> None:
        action_id = _inject_queue_item(self.controller)
        self.controller.set_bounded_executor_workspace(self.workspace)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.execute_bounded_local(action_id, {"workspace_path": str(self.workspace)})
        ready = self.controller.state_view()["ready_to_execute_locally"]
        self.assertEqual(ready, [])

    def test_individual_execution_defaults_to_session_workspace(self) -> None:
        action_id = _inject_queue_item(self.controller)
        self.controller.set_bounded_executor_workspace(self.workspace)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            state = self.controller.execute_bounded_local(action_id, {})
        item = next(i for i in state["queue"] if i["action_id"] == action_id)
        self.assertEqual(item["execution_status"], EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR)
        self.assertTrue((self.workspace / "index.html").is_file())


class TestExecutionReviewBatch(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.root / "sessions")
        self.raw = load_fixture(FIXTURES_DIR / TINY_GAME_FIXTURE)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _ingest_tiny_game(self) -> dict:
        self.controller.submit_goal(CANONICAL_GOAL_PROMPT)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            return self.controller.ingest_agent_response(self.raw)

    def _game_files_present(self) -> list[str]:
        return [name for name in GAME_FILES if (self.workspace / name).is_file()]

    def test_batch_execution_writes_three_tiny_game_files(self) -> None:
        self._ingest_tiny_game()
        self.controller.set_bounded_executor_workspace(self.workspace)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            state = self.controller.execute_bounded_local_batch({"workspace_path": str(self.workspace)})
        self.assertEqual(self._game_files_present(), list(GAME_FILES))
        self.assertEqual(state["bounded_local_batch_result"]["succeeded_count"], 3)
        self.assertEqual(state["bounded_local_batch_result"]["failed_count"], 0)

    def test_batch_execution_emits_bounded_executor_evidence_per_file(self) -> None:
        self._ingest_tiny_game()
        self.controller.set_bounded_executor_workspace(self.workspace)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.execute_bounded_local_batch({"workspace_path": str(self.workspace)})
        evidence = self.controller.session_dict()["run_loop"]["evidence_records"]
        write_records = [r for r in evidence if r["source"] == "bounded_executor"]
        self.assertEqual(len(write_records), 3)
        self.assertEqual({r["file_path_or_note"] for r in write_records}, set(GAME_FILES))
        for record in write_records:
            self.assertTrue(record["sha256"])

    def test_batch_execution_does_not_run_on_ingest(self) -> None:
        state = self._ingest_tiny_game()
        self.assertEqual(self._game_files_present(), [])
        self.assertTrue(state["ready_to_execute_locally"] == [] or not state.get("bounded_local_batch_result"))
        self.assertFalse(state["mission_summary"]["side_effect_executed_by_admissible"])

    def test_batch_excludes_forbidden_shell_structured_operations(self) -> None:
        _inject_queue_item(
            self.controller,
            action_id="shell_action",
            candidate={
                "action_id": "shell_action",
                "envelope_id": "envelope_shell_action",
                "tool_or_command": "npm install",
                "execution_status": "proposed_only",
                "structured_operations": [{"operation": "npm", "path": "package.json"}],
            },
        )
        self.controller.set_bounded_executor_workspace(self.workspace)
        item = next(i for i in self.controller.state_view()["queue"] if i["action_id"] == "shell_action")
        self.assertFalse(item["bounded_execution_eligible"])
        self.assertEqual(item["bounded_execution_diagnostic"], DIAG_FORBIDDEN_OPERATION_CATEGORY)
        ready_ids = {entry["action_id"] for entry in self.controller.state_view()["ready_to_execute_locally"]}
        self.assertNotIn("shell_action", ready_ids)

    def test_batch_execution_reports_per_action_failures_clearly(self) -> None:
        good_id = _inject_queue_item(
            self.controller,
            action_id="good_write",
            candidate={
                "action_id": "good_write",
                "envelope_id": "envelope_good_write",
                "execution_status": "proposed_only",
                "structured_operations": [
                    {"operation": "write_file", "path": "ok.txt", "content": "ok"}
                ],
            },
        )
        bad_id = _inject_queue_item(
            self.controller,
            action_id="bad_write",
            candidate={
                "action_id": "bad_write",
                "envelope_id": "envelope_bad_write",
                "execution_status": "proposed_only",
                "structured_operations": [
                    {"operation": "write_file", "path": "../escape.txt", "content": "nope"}
                ],
            },
        )
        self.controller.set_bounded_executor_workspace(self.workspace)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            state = self.controller.execute_bounded_local_batch({"workspace_path": str(self.workspace)})
        results = {r["action_id"]: r for r in state["bounded_local_batch_result"]["action_results"]}
        self.assertTrue(results[good_id]["success"])
        self.assertFalse(results[bad_id]["success"])
        self.assertIn("diagnostic", results[bad_id])
        self.assertTrue((self.workspace / "ok.txt").is_file())
        self.assertTrue(state["bounded_local_batch_result"]["partial_success"])

    def test_export_import_preserves_batch_execution_evidence(self) -> None:
        self._ingest_tiny_game()
        self.controller.set_bounded_executor_workspace(self.workspace)
        with mock.patch.object(subprocess, "run", _raise_on_subprocess):
            self.controller.execute_bounded_local_batch({"workspace_path": str(self.workspace)})
        exported = self.controller.session_dict()
        reloaded = ControlSurfaceController(session_dir=self.root / "reload")
        imported = reloaded.import_session(exported)
        self.assertEqual(
            len(imported["run_loop"]["evidence_records"]),
            len(exported["run_loop"]["evidence_records"]),
        )
        self.assertEqual(
            exported["run_loop"]["evidence_records"][0]["sha256"],
            imported["run_loop"]["evidence_records"][0]["sha256"],
        )


class TestExecutionReviewHtmlAndHttp(unittest.TestCase):
    def test_html_contains_ready_to_execute_locally_section(self) -> None:
        html = HTML_PATH.read_text(encoding="utf-8")
        for marker in (
            "Ready to execute locally",
            'id="ready-to-execute-panel"',
            'id="btn-execute-bounded-batch"',
            "/api/queue/execute_bounded_local_batch",
            "Structured operations",
        ):
            self.assertIn(marker, html, f"missing HTML marker: {marker}")

    def test_http_batch_route_writes_files(self) -> None:
        tmpdir = tempfile.TemporaryDirectory()
        try:
            root = Path(tmpdir.name)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = build_controller(session_dir=root / "sessions", fresh_session=True)
            controller.submit_goal(CANONICAL_GOAL_PROMPT)
            raw = load_fixture(FIXTURES_DIR / TINY_GAME_FIXTURE)
            with mock.patch.object(subprocess, "run", _raise_on_subprocess):
                controller.ingest_agent_response(raw)
                controller.set_bounded_executor_workspace(workspace)
            server = make_server(controller, host="127.0.0.1", port=0)
            host, port = server.server_address
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                payload = json.dumps({"workspace_path": str(workspace)}).encode("utf-8")
                req = urllib.request.Request(
                    f"http://{host}:{port}/api/queue/execute_bounded_local_batch",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    state = json.loads(resp.read().decode("utf-8"))
                self.assertEqual(state["bounded_local_batch_result"]["succeeded_count"], 3)
            finally:
                server.shutdown()
                thread.join(timeout=2)
        finally:
            tmpdir.cleanup()

    def test_bridge_check_workspace_persists_session_workspace(self) -> None:
        tmpdir = tempfile.TemporaryDirectory()
        try:
            root = Path(tmpdir.name)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = build_controller(session_dir=root / "sessions", fresh_session=True)
            server = make_server(controller, host="127.0.0.1", port=0)
            host, port = server.server_address
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                payload = json.dumps({"workspace_path": str(workspace)}).encode("utf-8")
                req = urllib.request.Request(
                    f"http://{host}:{port}/api/session/run_loop/bridge/check_workspace",
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    result = json.loads(resp.read().decode("utf-8"))
                self.assertTrue(result["workspace_exists"])
                session = controller.state_view()
                self.assertEqual(session["bounded_executor_workspace"], str(workspace.resolve()))
            finally:
                server.shutdown()
                thread.join(timeout=2)
        finally:
            tmpdir.cleanup()


class TestExecutionReviewNoAgentOsImports(unittest.TestCase):
    def test_no_agent_os_imports_in_admissible_modules(self) -> None:
        violations: list[str] = []
        for path in sorted(ADMISSIBLE_ROOT.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "agent_os" or alias.name.startswith("agent_os."):
                            violations.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
                elif isinstance(node, ast.ImportFrom):
                    module = node.module
                    if module and (module == "agent_os" or module.startswith("agent_os.")):
                        violations.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
