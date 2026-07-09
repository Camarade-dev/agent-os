"""Slice ADMISSIBLE_EXECUTION_009_BOUNDED_LOCAL_EXECUTOR_V0 tests."""

from __future__ import annotations

import ast
import copy
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from admissible.admitted_execution import EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR
from admissible.control_surface import (
    ControlSurfaceController,
    DecisionQueueItem,
    RunEnvelope,
    _build_queue_item,
)
from admissible.execution.bounded_local_executor import (
    DIAG_FORBIDDEN_OPERATION_CATEGORY,
    DIAG_NOT_ADMITTED,
    DIAG_NOT_EXECUTABLE_WITHOUT_STRUCTURED_OPERATION,
    DIAG_NO_WORKSPACE_CONFIGURED,
    DIAG_PATH_OUTSIDE_WORKSPACE,
    DIAG_REFUSED_DECISION,
    BoundedExecutionError,
    BoundedLocalExecutor,
    assess_bounded_execution_eligibility,
    execute_bounded_local_action,
    validate_relative_path_inside_workspace,
    validate_workspace_path,
)
from admissible.run_loop import LIFECYCLE_ADMITTED_NOT_EXECUTED
from admissible.runner.control_surface import make_server

REPO_ROOT = Path(__file__).resolve().parent.parent
ADMISSIBLE_ROOT = REPO_ROOT / "admissible"
SAMPLE_SLITHER_PROMPT = (
    "Build a small browser-based Slither-like game. Keep it local-only. Do not deploy."
)


def _controller(tmpdir: str) -> ControlSurfaceController:
    return ControlSurfaceController(session_dir=Path(tmpdir) / "sessions")


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
    lifecycle_status: str | None = None,
    execution_status: str = "proposed_only",
) -> str:
    decision = decision or _local_allow_decision(action_id)
    candidate = candidate or {
        "action_id": action_id,
        "envelope_id": decision["envelope_id"],
        "action_type": "edit_file",
        "tool_or_command": "write index.html",
        "side_effect_type": "code_change",
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
    if lifecycle_status is not None:
        item.lifecycle_status = lifecycle_status
    item.execution_status = execution_status
    controller._session.run_envelopes[action_id] = envelope
    controller._session.queue.append(item)
    return action_id


class TestBoundedLocalExecutorCore(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.workspace = Path(self._tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_write_file_inside_workspace_succeeds_for_admitted_action(self) -> None:
        result = execute_bounded_local_action(
            workspace_path=self.workspace,
            operations=[
                {"operation": "write_file", "path": "index.html", "content": "<!doctype html>"}
            ],
            action_id="action_write_001",
        )
        self.assertTrue(result.success)
        self.assertTrue((self.workspace / "index.html").is_file())
        self.assertIn("<!doctype html>", (self.workspace / "index.html").read_text(encoding="utf-8"))

    def test_successful_write_produces_sha256_attestation_evidence(self) -> None:
        content = "body { color: red; }"
        result = execute_bounded_local_action(
            workspace_path=self.workspace,
            operations=[{"operation": "write_file", "path": "style.css", "content": content}],
            action_id="action_write_002",
            turn_number=3,
        )
        self.assertTrue(result.success)
        self.assertEqual(len(result.evidence_records), 1)
        record = result.evidence_records[0]
        self.assertEqual(record.source, "bounded_executor")
        self.assertIn("local_file_written", record.satisfies)
        self.assertIn("workspace_scope_attested", record.satisfies)
        self.assertEqual(record.file_path_or_note, "style.css")
        self.assertIsNotNone(record.sha256)
        self.assertEqual(record.turn_number, 3)

    def test_read_and_list_emit_observation_evidence(self) -> None:
        (self.workspace / "notes.txt").write_text("hello", encoding="utf-8")
        (self.workspace / "subdir").mkdir()
        result = execute_bounded_local_action(
            workspace_path=self.workspace,
            operations=[
                {"operation": "list_files", "path": "."},
                {"operation": "read_file", "path": "notes.txt"},
            ],
            action_id="action_read_001",
        )
        self.assertTrue(result.success)
        self.assertEqual(len(result.evidence_records), 2)
        for record in result.evidence_records:
            self.assertEqual(record.source, "bounded_executor")
            self.assertIn("workspace_scope_attested", record.satisfies)
            self.assertIn("local_file_observed", record.satisfies)
        self.assertIsNotNone(result.evidence_records[1].sha256)

    def test_path_traversal_refused(self) -> None:
        with self.assertRaises(BoundedExecutionError) as ctx:
            validate_relative_path_inside_workspace(self.workspace, "../outside.txt")
        self.assertEqual(ctx.exception.diagnostic, DIAG_PATH_OUTSIDE_WORKSPACE)

    def test_absolute_outside_path_refused(self) -> None:
        outside = Path(self._tmpdir.name) / "outside.txt"
        outside.write_text("nope", encoding="utf-8")
        with self.assertRaises(BoundedExecutionError) as ctx:
            validate_relative_path_inside_workspace(self.workspace, str(outside))
        self.assertEqual(ctx.exception.diagnostic, DIAG_PATH_OUTSIDE_WORKSPACE)

    def test_symlink_escape_refused_when_supported(self) -> None:
        outside = Path(self._tmpdir.name) / "secret.txt"
        outside.write_text("secret", encoding="utf-8")
        link = self.workspace / "escape-link"
        try:
            if os.name == "nt":
                os.symlink(str(outside), str(link))
            else:
                link.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation not supported on this platform")
        with self.assertRaises(BoundedExecutionError) as ctx:
            validate_relative_path_inside_workspace(self.workspace, "escape-link")
        self.assertEqual(ctx.exception.diagnostic, DIAG_PATH_OUTSIDE_WORKSPACE)

    def test_no_workspace_configured_refused(self) -> None:
        with self.assertRaises(BoundedExecutionError) as ctx:
            validate_workspace_path(None)
        self.assertEqual(ctx.exception.diagnostic, DIAG_NO_WORKSPACE_CONFIGURED)

    def test_natural_language_without_structured_operation_refused(self) -> None:
        item = DecisionQueueItem(
            action_id="nl_001",
            tool_or_command="Create a nice landing page",
            action_type="edit_file",
            decision="ALLOW",
            operational_admissibility_action="execute",
            risk_level="local",
            required_approval="none",
            missing_evidence=[],
            execution_status="proposed_only",
            attestation_eligible=True,
        )
        envelope = RunEnvelope(
            action_id="nl_001",
            envelope_id="env_nl",
            decision_id="dec_nl",
            candidate={"action_id": "nl_001", "tool_or_command": "Create a nice landing page"},
            decision=_local_allow_decision("nl_001"),
        )
        assessment = assess_bounded_execution_eligibility(item=item, envelope=envelope)
        self.assertFalse(assessment["eligible"])
        self.assertEqual(assessment["diagnostic"], DIAG_NOT_EXECUTABLE_WITHOUT_STRUCTURED_OPERATION)

    def test_shell_like_operation_strings_refused(self) -> None:
        result = execute_bounded_local_action(
            workspace_path=self.workspace,
            operations=[{"operation": "npm", "path": "install"}],
            action_id="forbidden_001",
        )
        self.assertFalse(result.success)
        self.assertEqual(result.diagnostic, DIAG_FORBIDDEN_OPERATION_CATEGORY)

    def test_forbidden_natural_language_tool_refused(self) -> None:
        item = DecisionQueueItem(
            action_id="npm_001",
            tool_or_command="npm install left-pad",
            action_type="install_dependency",
            decision="ALLOW",
            operational_admissibility_action="execute",
            risk_level="local",
            required_approval="none",
            missing_evidence=[],
            execution_status="proposed_only",
            attestation_eligible=True,
        )
        envelope = RunEnvelope(
            action_id="npm_001",
            envelope_id="env_npm",
            decision_id="dec_npm",
            candidate={"action_id": "npm_001", "tool_or_command": "npm install left-pad"},
            decision=_local_allow_decision("npm_001"),
        )
        assessment = assess_bounded_execution_eligibility(item=item, envelope=envelope)
        self.assertFalse(assessment["eligible"])
        self.assertEqual(assessment["diagnostic"], DIAG_FORBIDDEN_OPERATION_CATEGORY)


class TestBoundedExecutorAdmissionGates(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _controller(self._tmpdir.name)
        self.workspace = Path(self._tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _assess(self, decision_label: str, **kwargs: object) -> dict:
        action_id = "gate_action"
        decision = _local_allow_decision(action_id)
        decision["decision"] = decision_label
        if decision_label == "REQUEST_MORE_EVIDENCE":
            decision["missing_evidence"] = ["package_trust_review"]
        candidate = {
            "action_id": action_id,
            "structured_operations": [
                {"operation": "write_file", "path": "a.txt", "content": "x"}
            ],
        }
        envelope = RunEnvelope(
            action_id=action_id,
            envelope_id="env_gate",
            decision_id="dec_gate",
            candidate=candidate,
            decision=decision,
        )
        item = _build_queue_item(envelope)
        for key, value in kwargs.items():
            setattr(item, key, value)
        return assess_bounded_execution_eligibility(item=item, envelope=envelope)

    def test_request_more_evidence_cannot_execute(self) -> None:
        assessment = self._assess("REQUEST_MORE_EVIDENCE")
        self.assertFalse(assessment["eligible"])
        self.assertEqual(assessment["diagnostic"], DIAG_NOT_ADMITTED)

    def test_require_human_approval_cannot_execute_until_admitted(self) -> None:
        assessment = self._assess("REQUIRE_HUMAN_APPROVAL")
        self.assertFalse(assessment["eligible"])
        self.assertEqual(assessment["diagnostic"], DIAG_NOT_ADMITTED)

    def test_require_human_approval_can_execute_when_admitted_not_executed(self) -> None:
        assessment = self._assess(
            "REQUIRE_HUMAN_APPROVAL",
            execution_status="admitted_not_executed",
            lifecycle_status=LIFECYCLE_ADMITTED_NOT_EXECUTED,
        )
        self.assertTrue(assessment["eligible"])

    def test_refuse_cannot_execute(self) -> None:
        assessment = self._assess("REFUSE")
        self.assertFalse(assessment["eligible"])
        self.assertEqual(assessment["diagnostic"], DIAG_REFUSED_DECISION)


class TestBoundedExecutorControlSurface(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _controller(self._tmpdir.name)
        self.workspace = Path(self._tmpdir.name) / "workspace"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_successful_write_marks_derived_execution_status_without_mutating_decision(self) -> None:
        action_id = _inject_queue_item(self.controller)
        original_decision = copy.deepcopy(self.controller._session.run_envelopes[action_id].decision)
        state = self.controller.execute_bounded_local(
            action_id,
            {"workspace_path": str(self.workspace)},
        )
        item = next(i for i in state["queue"] if i["action_id"] == action_id)
        self.assertEqual(item["execution_status"], EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR)
        self.assertEqual(
            state["run_envelopes"][action_id]["decision"],
            original_decision,
        )

    def test_control_surface_exposes_blocked_execution_diagnostic(self) -> None:
        action_id = "action_nl"
        _inject_queue_item(
            self.controller,
            action_id=action_id,
            candidate={
                "action_id": action_id,
                "tool_or_command": "Polish the UI copy",
                "execution_status": "proposed_only",
            },
        )
        view = self.controller.state_view()
        item = next(i for i in view["queue"] if i["action_id"] == action_id)
        self.assertFalse(item["bounded_execution_eligible"])
        self.assertEqual(
            item["bounded_execution_diagnostic"],
            DIAG_NOT_EXECUTABLE_WITHOUT_STRUCTURED_OPERATION,
        )

    def test_structured_executor_evidence_export_import_round_trips(self) -> None:
        action_id = _inject_queue_item(self.controller)
        self.controller.execute_bounded_local(action_id, {"workspace_path": str(self.workspace)})
        exported = self.controller.session_dict()
        evidence = exported["run_loop"]["evidence_records"]
        self.assertTrue(any(r["source"] == "bounded_executor" for r in evidence))

        fresh = _controller(self._tmpdir.name)
        fresh.import_session(exported)
        imported = fresh.session_dict()
        self.assertEqual(
            len(imported["run_loop"]["evidence_records"]),
            len(exported["run_loop"]["evidence_records"]),
        )
        self.assertEqual(
            imported["run_loop"]["evidence_records"][0]["sha256"],
            exported["run_loop"]["evidence_records"][0]["sha256"],
        )

    def test_http_route_execute_bounded_local(self) -> None:
        action_id = _inject_queue_item(self.controller)
        server = make_server(self.controller, host="127.0.0.1", port=0)
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            payload = json.dumps({"workspace_path": str(self.workspace)}).encode("utf-8")
            req = urllib.request.Request(
                f"http://{host}:{port}/api/queue/{action_id}/execute_bounded_local",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                state = json.loads(resp.read().decode("utf-8"))
            item = next(i for i in state["queue"] if i["action_id"] == action_id)
            self.assertEqual(item["execution_status"], EXECUTION_STATUS_EXECUTED_BY_BOUNDED_EXECUTOR)
        finally:
            server.shutdown()
            thread.join(timeout=2)

    def test_http_route_returns_blocked_diagnostic(self) -> None:
        action_id = "blocked"
        _inject_queue_item(
            self.controller,
            action_id=action_id,
            decision={**_local_allow_decision(action_id), "decision": "REFUSE"},
        )
        server = make_server(self.controller, host="127.0.0.1", port=0)
        host, port = server.server_address
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            payload = json.dumps({"workspace_path": str(self.workspace)}).encode("utf-8")
            req = urllib.request.Request(
                f"http://{host}:{port}/api/queue/{action_id}/execute_bounded_local",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=5)
            body = json.loads(ctx.exception.read().decode("utf-8"))
            self.assertEqual(body.get("bounded_execution_diagnostic"), DIAG_REFUSED_DECISION)
        finally:
            server.shutdown()
            thread.join(timeout=2)

    def test_browser_scaffold_demo_writes_three_files(self) -> None:
        action_id = _inject_queue_item(
            self.controller,
            candidate={
                "action_id": "scaffold_001",
                "envelope_id": "envelope_scaffold_001",
                "tool_or_command": "write browser scaffold files",
                "execution_status": "proposed_only",
                "structured_operations": [
                    {"operation": "write_file", "path": "index.html", "content": "<!doctype html><html></html>"},
                    {"operation": "write_file", "path": "style.css", "content": "body { margin: 0; }"},
                    {"operation": "write_file", "path": "game.js", "content": "console.log('game');"},
                ],
            },
        )
        self.controller.execute_bounded_local(action_id, {"workspace_path": str(self.workspace)})
        self.assertTrue((self.workspace / "index.html").is_file())
        self.assertTrue((self.workspace / "style.css").is_file())
        self.assertTrue((self.workspace / "game.js").is_file())


class TestBoundedExecutorBoundary(unittest.TestCase):
    def test_no_agent_os_imports_in_admissible_modules(self) -> None:
        violations: list[str] = []
        for path in sorted((ADMISSIBLE_ROOT).rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
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
