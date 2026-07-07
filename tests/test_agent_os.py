"""Tests for Agent OS v0 CLI and validation."""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agent_os.cli import build_parser, main
from agent_os.orchestrator import (
    DRAFT_PREPARATION_PREFLIGHT_NON_AUTHORITY_FLAGS,
    GOAL_INTAKE_NON_AUTHORITY_FLAGS,
    GOAL_INTAKE_REQUIRED_FIELDS,
    OWNER_CLARIFICATION_NON_AUTHORITY_FLAGS,
    OWNER_CLARIFICATION_REQUIRED_FIELDS,
    OWNER_READINESS_DECISION_NON_AUTHORITY_FLAGS,
    OWNER_READINESS_DECISION_REQUIRED_FIELDS,
    READINESS_REVIEW_NON_AUTHORITY_FLAGS,
    build_goal_intake_artifact,
    build_owner_clarification_artifact,
    build_owner_readiness_decision_artifact,
    create_goal_intake,
    create_owner_clarification,
    create_owner_readiness_decision,
    create_requirements_extraction_owner_decision,
    create_requirements_validation_owner_decision,
    create_requirements_approval_owner_decision,
    check_requirements_extraction_execution_authorization,
    requirements_validation_execution_check,
    validate_requirements_draft,
    requirements_approval_preflight,
    extract_requirements_draft,
    requirements_draft_validation_preflight,
    build_requirements_extraction_owner_decision_artifact,
    build_requirements_validation_owner_decision_artifact,
    build_requirements_approval_owner_decision_artifact,
    load_requirements_extraction_owner_decision,
    load_requirements_validation_owner_decision,
    load_requirements_approval_owner_decision,
    list_requirements_extraction_owner_decisions,
    list_requirements_validation_owner_decisions,
    list_requirements_approval_owner_decisions,
    validate_requirements_extraction_owner_decision,
    validate_requirements_validation_owner_decision,
    validate_requirements_approval_owner_decision,
    REQUIREMENTS_EXTRACTION_OWNER_DECISION_NON_AUTHORITY_FLAGS,
    REQUIREMENTS_EXTRACTION_OWNER_DECISION_REQUIRED_FIELDS,
    REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_NON_AUTHORITY_FLAGS,
    REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_STATE,
    REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_NEXT_ACTION,
    REQUIREMENTS_DRAFT_STATUS,
    REQUIREMENTS_DRAFT_NON_AUTHORITY_FLAGS,
    REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_STATE,
    REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_NEXT_ACTION,
    REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_NON_AUTHORITY_FLAGS,
    REQUIREMENTS_VALIDATION_OWNER_DECISION_NON_AUTHORITY_FLAGS,
    REQUIREMENTS_VALIDATION_OWNER_DECISION_RECORDED_STATE,
    REQUIREMENTS_VALIDATION_AUTHORIZE_NEXT_ACTION,
    REQUIREMENTS_VALIDATION_REQUEST_NEXT_ACTION,
    REQUIREMENTS_VALIDATION_BLOCK_NEXT_ACTION,
    REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_STATE,
    REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_NEXT_ACTION,
    REQUIREMENTS_VALIDATION_EXECUTION_CHECK_NON_AUTHORITY_FLAGS,
    REQUIREMENTS_VALIDATION_EXECUTION_CHECK_CONFIRMED_STATE,
    REQUIREMENTS_VALIDATION_EXECUTION_CHECK_CONFIRMED_NEXT_ACTION,
    REQUIREMENTS_DRAFT_VALIDATION_REPORT_CREATED_STATE,
    REQUIREMENTS_DRAFT_VALIDATION_REPORT_CREATED_NEXT_ACTION,
    REQUIREMENTS_DRAFT_VALIDATION_REPORT_NON_AUTHORITY_FLAGS,
    REQUIREMENTS_DRAFT_VALIDATION_RESULT_PASS,
    REQUIREMENTS_DRAFT_VALIDATION_RESULT_NEEDS_REVISION,
    REQUIREMENTS_DRAFT_VALIDATION_RESULT_BLOCKED,
    REQUIREMENTS_APPROVAL_PREFLIGHT_CONFIRMED_STATE,
    REQUIREMENTS_APPROVAL_PREFLIGHT_CONFIRMED_NEXT_ACTION,
    REQUIREMENTS_APPROVAL_PREFLIGHT_NON_AUTHORITY_FLAGS,
    REQUIREMENTS_APPROVAL_OWNER_DECISION_NON_AUTHORITY_FLAGS,
    REQUIREMENTS_APPROVAL_OWNER_DECISION_RECORDED_STATE,
    REQUIREMENTS_APPROVAL_AUTHORIZE_NEXT_ACTION,
    REQUIREMENTS_APPROVAL_REQUEST_NEXT_ACTION,
    REQUIREMENTS_APPROVAL_BLOCK_NEXT_ACTION,
    REQUIREMENTS_APPROVAL_PREFLIGHT_NOT_REQUIRED_STATE,
    REQUIREMENTS_APPROVAL_PREFLIGHT_NOT_REQUIRED_NEXT_ACTION,
    DraftRequirementCandidate,
    DRAFT_REQUIREMENT_CANDIDATE_STATUS,
    _parse_requirements_draft_candidates_from_spec,
    _validate_single_draft_requirement_candidate,
    DRAFT_REQUIREMENT_SOURCE_BOUNDED_MARKER,
    goal_intake_status,
    list_owner_clarifications,
    list_owner_readiness_decisions,
    load_goal_intake,
    load_owner_clarification,
    load_owner_readiness_decision,
    normalize_goal,
    preflight_draft_preparation,
    prepare_planning_workspace_draft,
    review_goal_intake_readiness,
    validate_clarification_id,
    validate_goal_intake,
    validate_intake_id,
    validate_owner_clarification,
    validate_owner_readiness_decision,
    validate_readiness_decision_id,
)
from agent_os.paths import (
    CLARIFICATIONS_DIR,
    GOAL_INTAKE_FILE,
    READINESS_DECISIONS_DIR,
    TEMPLATE_FILES,
    orchestrator_clarification_path,
    orchestrator_intake_path,
    orchestrator_readiness_decision_path,
    orchestrator_requirements_extraction_decision_path,
    orchestrator_requirements_validation_decision_path,
    orchestrator_requirements_approval_decision_path,
    REQUIREMENTS_EXTRACTION_DECISIONS_DIR,
    REQUIREMENTS_VALIDATION_DECISIONS_DIR,
    REQUIREMENTS_APPROVAL_DECISIONS_DIR,
    planning_path,
    run_path,
)
from agent_os import planning as planning_module
from agent_os.planning import (
    init_planning_workspace,
    list_planning_owner_decisions,
    progress_planning_workspace,
    record_planning_owner_decision,
    status_planning_workspace,
    transition_planning_workspace,
    validate_planning_workspace,
    validate_plan_id,
)
from agent_os.validate import validate_run_for_closure
from agent_os.workspace import (
    GIT_SNAPSHOT_READONLY_ARGV,
    add_evidence,
    add_evidence_command_output,
    add_evidence_file,
    close_run,
    create_mission,
    init_workspace,
    list_evidence,
    list_runs,
    record_audit,
    snapshot_evidence_git,
)


def _fill_run_for_closure(base: Path) -> None:
    """Fill all required closure fields in a run directory."""
    mission = base / "mission.md"
    mission.write_text(
        "---\nrun_id: test\n---\n\n"
        "# Mission\n\nShip the widget.\n\n"
        "## Scope\n\nIn: widget. Out: billing.\n\n"
        "## Success criteria\n\nWidget ships.\n",
        encoding="utf-8",
    )

    preflight = base / "preflight.md"
    preflight.write_text(
        "---\nrun_id: test\nauthority: owner\nautonomy_level: L1\n---\n\n"
        "# Preflight\n\n## Authority\n\nOwner authorized.\n\n"
        "## Autonomy gates\n\nNo production deploys.\n\n"
        "## Context boundaries\n\nRepo only.\n",
        encoding="utf-8",
    )

    evidence = base / "evidence.md"
    evidence.write_text(
        "---\nrun_id: test\n---\n\n# Evidence\n\npytest passed.\n",
        encoding="utf-8",
    )

    audit = base / "audit.md"
    audit.write_text(
        "---\nrun_id: test\nverdict: pass\nrecorded_at: 2026-01-01T00:00:00+00:00\n---\n\n"
        "# Audit\n\nReview complete.\n",
        encoding="utf-8",
    )

    owner = base / "owner-decision.md"
    owner.write_text(
        "---\nrun_id: test\ndecision: accept\nowner: owner\nrecorded_at: 2026-01-01T00:00:00+00:00\n---\n\n"
        "# Owner decision\n\nAccepted.\n",
        encoding="utf-8",
    )

    closure = base / "closure.md"
    closure.write_text(
        "---\nrun_id: test\nverdict: CLOSED_SUCCESS\nrecorded_at: 2026-01-01T00:00:00+00:00\n---\n\n"
        "# Closure\n\nDone.\n",
        encoding="utf-8",
    )


def _init_git_repo(path: Path, *, with_commit: bool = True) -> None:
    """Create a minimal local git repo for snapshot-git tests."""
    subprocess.run(
        ["git", "init", str(path)],
        capture_output=True,
        check=True,
        shell=False,
    )
    readme = path / "README.md"
    readme.write_text("# test repo\n", encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(path), "add", "README.md"],
        capture_output=True,
        check=True,
        shell=False,
    )
    if with_commit:
        subprocess.run(
            [
                "git",
                "-C",
                str(path),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-m",
                "init",
            ],
            capture_output=True,
            check=True,
            shell=False,
        )


class AgentOsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_init_creates_workspace_structure(self) -> None:
        root = init_workspace(self.project)
        self.assertTrue(root.is_dir())
        self.assertTrue((root / "runs").is_dir())
        self.assertTrue((root / "workspace.json").is_file())

        meta = json.loads((root / "workspace.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["protocol"], "agent-os")

    def test_mission_creates_run_with_expected_files(self) -> None:
        run_id = create_mission(self.project, "20260704-001")
        base = run_path(self.project, run_id)
        self.assertTrue(base.is_dir())
        for name in TEMPLATE_FILES:
            self.assertTrue((base / name).is_file(), name)
        self.assertTrue((base / "run.json").is_file())

    def test_status_reports_open_run_and_unfilled_fields(self) -> None:
        run_id = create_mission(self.project, "20260704-002")
        runs = list_runs(self.project)
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["run_id"], run_id)
        self.assertEqual(runs[0]["status"], "open")
        missing = runs[0]["missing"]
        self.assertIn("mission statement is placeholder/unfilled", missing)
        self.assertIn("scope is placeholder/unfilled", missing)
        self.assertIn("authority field is placeholder", missing)

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["status", str(self.project)])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("open", output)
        self.assertIn("blocked:", output)
        self.assertNotIn("missing:", output)
        self.assertIn("mission statement is placeholder/unfilled", output)

    def test_close_fails_before_required_fields_filled(self) -> None:
        run_id = create_mission(self.project, "20260704-003")
        ok, errors = close_run(self.project, run_id)
        self.assertFalse(ok)
        self.assertTrue(errors)

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["close", run_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("closure blocked", buf.getvalue())

    def test_audit_records_verdict(self) -> None:
        run_id = create_mission(self.project, "20260704-004")
        record_audit(self.project, run_id, "pass", notes="looks good")
        audit_path = run_path(self.project, run_id) / "audit.md"
        text = audit_path.read_text(encoding="utf-8")
        self.assertIn("verdict: pass", text)
        self.assertRegex(text, r"recorded_at: \d{4}-\d{2}-\d{2}T")

    def test_close_succeeds_after_required_fields_filled(self) -> None:
        run_id = create_mission(self.project, "20260704-005")
        base = run_path(self.project, run_id)
        _fill_run_for_closure(base)

        result = validate_run_for_closure(self.project, run_id)
        self.assertTrue(result.ok, result.errors)

        ok, errors = close_run(self.project, run_id)
        self.assertTrue(ok, errors)
        self.assertEqual(errors, [])

        meta = json.loads((base / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["status"], "closed")
        self.assertIsNotNone(meta["closed_at"])

    def test_close_fails_when_run_already_closed(self) -> None:
        run_id = create_mission(self.project, "20260704-008")
        base = run_path(self.project, run_id)
        _fill_run_for_closure(base)

        ok, errors = close_run(self.project, run_id)
        self.assertTrue(ok, errors)

        ok, errors = close_run(self.project, run_id)
        self.assertFalse(ok)
        self.assertEqual(errors, ["run is already closed"])

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["close", run_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertEqual(
            buf.getvalue().strip(),
            f"closure blocked for run {run_id}: run is already closed",
        )

    def test_docs_do_not_reference_obsolete_root_templates_path(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        doc_paths = [
            repo_root / "README.md",
            repo_root / "docs" / "primitives.md",
            repo_root / "docs" / "operating-loop.md",
            repo_root / "docs" / "memory-hygiene.md",
            repo_root / "examples" / "toy-run-example.md",
            repo_root / "examples" / "manual-agent-workflow.md",
        ]
        obsolete = re.compile(r"(?<!agent_os/)`templates/`")
        for path in doc_paths:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(
                    obsolete.search(text),
                    f"{path.name} still references obsolete root templates/ path",
                )

    def test_validation_distinguishes_missing_file_from_placeholder(self) -> None:
        run_id = create_mission(self.project, "20260704-006")
        base = run_path(self.project, run_id)

        result = validate_run_for_closure(self.project, run_id)
        self.assertIn("mission statement is placeholder/unfilled", result.errors)
        self.assertNotIn("mission file missing", result.errors)

        (base / "mission.md").unlink()
        result = validate_run_for_closure(self.project, run_id)
        self.assertIn("mission file missing", result.errors)
        self.assertNotIn("mission statement is placeholder/unfilled", result.errors)

    def test_validation_distinguishes_missing_field_from_placeholder_field(self) -> None:
        run_id = create_mission(self.project, "20260704-007")
        base = run_path(self.project, run_id)

        result = validate_run_for_closure(self.project, run_id)
        self.assertIn("authority field is placeholder", result.errors)
        self.assertNotIn("authority field missing", result.errors)

        preflight = base / "preflight.md"
        text = preflight.read_text(encoding="utf-8").replace("authority: PLACEHOLDER\n", "")
        preflight.write_text(text, encoding="utf-8")

        result = validate_run_for_closure(self.project, run_id)
        self.assertIn("authority field missing", result.errors)
        self.assertNotIn("authority field is placeholder", result.errors)

    def test_evidence_add_appends_structured_block(self) -> None:
        run_id = create_mission(self.project, "20260704-010")
        add_evidence(self.project, run_id, "unittest passed", artifact_path="out.txt")
        text = (run_path(self.project, run_id) / "evidence.md").read_text(encoding="utf-8")
        self.assertIn("## Evidence Entry —", text)
        self.assertIn("type: note", text)
        self.assertIn("path: out.txt", text)
        self.assertIn("claim: unittest passed", text)
        self.assertRegex(text, r"## Evidence Entry — \d{4}-\d{2}-\d{2}T")

    def test_evidence_add_preserves_previous_evidence(self) -> None:
        run_id = create_mission(self.project, "20260704-011")
        evidence_path = run_path(self.project, run_id) / "evidence.md"
        original = evidence_path.read_text(encoding="utf-8")
        add_evidence(self.project, run_id, "first note")
        add_evidence(self.project, run_id, "second note", evidence_type="observation")
        text = evidence_path.read_text(encoding="utf-8")
        self.assertTrue(text.startswith(original.rstrip("\n")))
        self.assertIn("claim: first note", text)
        self.assertIn("claim: second note", text)
        self.assertIn("type: observation", text)

    def test_evidence_add_fails_for_missing_run(self) -> None:
        with self.assertRaises(FileNotFoundError):
            add_evidence(self.project, "missing-run", "note text")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                ["evidence", "add", "missing-run", str(self.project), "--note", "note text"]
            )
        self.assertEqual(code, 1)
        self.assertIn("run not found", buf.getvalue())

    def test_evidence_add_fails_for_missing_evidence_file(self) -> None:
        run_id = create_mission(self.project, "20260704-012")
        (run_path(self.project, run_id) / "evidence.md").unlink()
        with self.assertRaises(FileNotFoundError):
            add_evidence(self.project, run_id, "note text")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                ["evidence", "add", run_id, str(self.project), "--note", "note text"]
            )
        self.assertEqual(code, 1)
        self.assertIn("evidence file missing", buf.getvalue())

    def test_evidence_add_fails_for_empty_note(self) -> None:
        run_id = create_mission(self.project, "20260704-013")
        with self.assertRaises(ValueError):
            add_evidence(self.project, run_id, "   ")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                ["evidence", "add", run_id, str(self.project), "--note", "   "]
            )
        self.assertEqual(code, 1)
        self.assertIn("note must not be empty", buf.getvalue())

    def test_evidence_add_does_not_change_run_status(self) -> None:
        run_id = create_mission(self.project, "20260704-014")
        base = run_path(self.project, run_id)
        meta_before = (base / "run.json").read_text(encoding="utf-8")
        add_evidence(self.project, run_id, "status unchanged")
        meta_after = (base / "run.json").read_text(encoding="utf-8")
        self.assertEqual(meta_before, meta_after)
        meta = json.loads(meta_after)
        self.assertEqual(meta["status"], "open")

    def test_evidence_add_does_not_modify_audit_owner_closure(self) -> None:
        run_id = create_mission(self.project, "20260704-015")
        base = run_path(self.project, run_id)
        audit_before = (base / "audit.md").read_text(encoding="utf-8")
        owner_before = (base / "owner-decision.md").read_text(encoding="utf-8")
        closure_before = (base / "closure.md").read_text(encoding="utf-8")
        add_evidence(self.project, run_id, "audit untouched")
        self.assertEqual(audit_before, (base / "audit.md").read_text(encoding="utf-8"))
        self.assertEqual(owner_before, (base / "owner-decision.md").read_text(encoding="utf-8"))
        self.assertEqual(closure_before, (base / "closure.md").read_text(encoding="utf-8"))

    def test_closure_still_blocked_when_audit_owner_closure_missing(self) -> None:
        run_id = create_mission(self.project, "20260704-016")
        add_evidence(self.project, run_id, "evidence only is not enough")
        ok, errors = close_run(self.project, run_id)
        self.assertFalse(ok)
        self.assertIn("mission statement is placeholder/unfilled", errors)
        self.assertIn("audit verdict field is placeholder", errors)
        self.assertIn("owner decision field is placeholder", errors)
        self.assertIn("closure verdict field is placeholder", errors)

    def test_evidence_list_prints_structured_entries(self) -> None:
        run_id = create_mission(self.project, "20260704-020")
        add_evidence(
            self.project,
            run_id,
            "unittest: 18 passed",
            evidence_type="test",
        )
        add_evidence(
            self.project,
            run_id,
            "report generated",
            evidence_type="artifact",
            artifact_path="reports/report.md",
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["evidence", "list", run_id, str(self.project)])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn(f"Evidence for run {run_id}:", output)
        self.assertRegex(output, r"1\. \d{4}-\d{2}-\d{2}T.*\[test\] unittest: 18 passed")
        self.assertRegex(output, r"2\. \d{4}-\d{2}-\d{2}T.*\[artifact\] report generated")

    def test_evidence_list_includes_optional_path(self) -> None:
        run_id = create_mission(self.project, "20260704-021")
        add_evidence(
            self.project,
            run_id,
            "report generated",
            evidence_type="artifact",
            artifact_path="reports/report.md",
        )

        output = list_evidence(self.project, run_id)
        self.assertIn("path: reports/report.md", output)

    def test_evidence_list_handles_no_entries_gracefully(self) -> None:
        run_id = create_mission(self.project, "20260704-022")

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["evidence", "list", run_id, str(self.project)])
        self.assertEqual(code, 0)
        output = buf.getvalue().strip()
        self.assertEqual(output, f"Evidence for run {run_id}:")

    def test_evidence_list_fails_for_missing_run(self) -> None:
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["evidence", "list", "missing-run", str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("run not found", buf.getvalue())

    def test_evidence_list_fails_for_missing_evidence_file(self) -> None:
        run_id = create_mission(self.project, "20260704-023")
        (run_path(self.project, run_id) / "evidence.md").unlink()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["evidence", "list", run_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("evidence file missing", buf.getvalue())

    def test_evidence_list_does_not_modify_evidence_md(self) -> None:
        run_id = create_mission(self.project, "20260704-024")
        add_evidence(self.project, run_id, "immutable listing")
        evidence_path = run_path(self.project, run_id) / "evidence.md"
        before = evidence_path.read_text(encoding="utf-8")
        list_evidence(self.project, run_id)
        self.assertEqual(before, evidence_path.read_text(encoding="utf-8"))

    def test_evidence_list_does_not_modify_audit_owner_closure_or_run_json(self) -> None:
        run_id = create_mission(self.project, "20260704-025")
        base = run_path(self.project, run_id)
        add_evidence(self.project, run_id, "read-only index")
        snapshots = {
            "evidence.md": (base / "evidence.md").read_text(encoding="utf-8"),
            "audit.md": (base / "audit.md").read_text(encoding="utf-8"),
            "owner-decision.md": (base / "owner-decision.md").read_text(encoding="utf-8"),
            "closure.md": (base / "closure.md").read_text(encoding="utf-8"),
            "run.json": (base / "run.json").read_text(encoding="utf-8"),
        }
        list_evidence(self.project, run_id)
        self.assertEqual(snapshots["evidence.md"], (base / "evidence.md").read_text(encoding="utf-8"))
        self.assertEqual(snapshots["audit.md"], (base / "audit.md").read_text(encoding="utf-8"))
        self.assertEqual(
            snapshots["owner-decision.md"],
            (base / "owner-decision.md").read_text(encoding="utf-8"),
        )
        self.assertEqual(snapshots["closure.md"], (base / "closure.md").read_text(encoding="utf-8"))
        self.assertEqual(snapshots["run.json"], (base / "run.json").read_text(encoding="utf-8"))

    def test_closure_validation_unchanged_after_evidence_list(self) -> None:
        run_id = create_mission(self.project, "20260704-026")
        add_evidence(self.project, run_id, "listed but not closed")
        before = validate_run_for_closure(self.project, run_id)
        list_evidence(self.project, run_id)
        after = validate_run_for_closure(self.project, run_id)
        self.assertEqual(before.ok, after.ok)
        self.assertEqual(before.errors, after.errors)
        self.assertFalse(before.ok)
        self.assertIn("mission statement is placeholder/unfilled", before.errors)

    def test_evidence_add_file_appends_structured_block(self) -> None:
        run_id = create_mission(self.project, "20260704-030")
        ref_file = self.project / "report.txt"
        ref_file.write_text("report content\n", encoding="utf-8")
        add_evidence_file(self.project, run_id, str(ref_file), "build report")
        text = (run_path(self.project, run_id) / "evidence.md").read_text(encoding="utf-8")
        self.assertIn("## Evidence Entry —", text)
        self.assertIn("type: file", text)
        self.assertIn(f"path: {ref_file}", text)
        self.assertIn("claim: build report", text)
        self.assertRegex(text, r"## Evidence Entry — \d{4}-\d{2}-\d{2}T")

    def test_evidence_add_file_path_appears_in_list(self) -> None:
        run_id = create_mission(self.project, "20260704-031")
        ref_file = self.project / "output.log"
        ref_file.write_text("log line\n", encoding="utf-8")
        add_evidence_file(self.project, run_id, str(ref_file), "test output log")
        output = list_evidence(self.project, run_id)
        self.assertIn("[file] test output log", output)
        self.assertIn(f"path: {ref_file}", output)

    def test_evidence_add_file_preserves_previous_evidence(self) -> None:
        run_id = create_mission(self.project, "20260704-032")
        evidence_path = run_path(self.project, run_id) / "evidence.md"
        original = evidence_path.read_text(encoding="utf-8")
        ref_file = self.project / "data.json"
        ref_file.write_text("{}\n", encoding="utf-8")
        add_evidence(self.project, run_id, "first note")
        add_evidence_file(self.project, run_id, str(ref_file), "json data file")
        text = evidence_path.read_text(encoding="utf-8")
        self.assertTrue(text.startswith(original.rstrip("\n")))
        self.assertIn("claim: first note", text)
        self.assertIn("claim: json data file", text)
        self.assertIn("type: file", text)

    def test_evidence_add_file_fails_for_missing_run(self) -> None:
        ref_file = self.project / "exists.txt"
        ref_file.write_text("x\n", encoding="utf-8")
        with self.assertRaises(FileNotFoundError):
            add_evidence_file(self.project, "missing-run", str(ref_file), "note")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "add-file",
                    "missing-run",
                    str(self.project),
                    "--file",
                    str(ref_file),
                    "--note",
                    "note",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("run not found", buf.getvalue())

    def test_evidence_add_file_fails_for_missing_evidence_file(self) -> None:
        run_id = create_mission(self.project, "20260704-033")
        (run_path(self.project, run_id) / "evidence.md").unlink()
        ref_file = self.project / "exists.txt"
        ref_file.write_text("x\n", encoding="utf-8")
        with self.assertRaises(FileNotFoundError):
            add_evidence_file(self.project, run_id, str(ref_file), "note")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "add-file",
                    run_id,
                    str(self.project),
                    "--file",
                    str(ref_file),
                    "--note",
                    "note",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("evidence file missing", buf.getvalue())

    def test_evidence_add_file_fails_for_empty_note(self) -> None:
        run_id = create_mission(self.project, "20260704-034")
        ref_file = self.project / "exists.txt"
        ref_file.write_text("x\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            add_evidence_file(self.project, run_id, str(ref_file), "   ")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "add-file",
                    run_id,
                    str(self.project),
                    "--file",
                    str(ref_file),
                    "--note",
                    "   ",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("note must not be empty", buf.getvalue())

    def test_evidence_add_file_fails_for_empty_file_path(self) -> None:
        run_id = create_mission(self.project, "20260704-035")
        with self.assertRaises(ValueError):
            add_evidence_file(self.project, run_id, "   ", "note")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "add-file",
                    run_id,
                    str(self.project),
                    "--file",
                    "   ",
                    "--note",
                    "note",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("file path must not be empty", buf.getvalue())

    def test_evidence_add_file_fails_for_nonexistent_referenced_file(self) -> None:
        run_id = create_mission(self.project, "20260704-036")
        missing = self.project / "does-not-exist.txt"
        with self.assertRaises(FileNotFoundError):
            add_evidence_file(self.project, run_id, str(missing), "note")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "add-file",
                    run_id,
                    str(self.project),
                    "--file",
                    str(missing),
                    "--note",
                    "note",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("referenced file not found", buf.getvalue())

    def test_evidence_add_file_does_not_copy_file(self) -> None:
        run_id = create_mission(self.project, "20260704-037")
        ref_file = self.project / "source.txt"
        ref_file.write_text("original\n", encoding="utf-8")
        base = run_path(self.project, run_id)
        before = {p.name for p in base.iterdir()}
        add_evidence_file(self.project, run_id, str(ref_file), "source reference")
        after = {p.name for p in base.iterdir()}
        self.assertEqual(before, after)
        self.assertFalse((base / "source.txt").exists())

    def test_evidence_add_file_does_not_inspect_or_mutate_file(self) -> None:
        run_id = create_mission(self.project, "20260704-038")
        ref_file = self.project / "immutable.txt"
        original_content = "must not change\n"
        ref_file.write_text(original_content, encoding="utf-8")
        mtime_before = ref_file.stat().st_mtime
        add_evidence_file(self.project, run_id, str(ref_file), "unchanged file")
        self.assertEqual(ref_file.read_text(encoding="utf-8"), original_content)
        self.assertEqual(ref_file.stat().st_mtime, mtime_before)

    def test_evidence_add_file_does_not_change_run_status(self) -> None:
        run_id = create_mission(self.project, "20260704-039")
        base = run_path(self.project, run_id)
        ref_file = self.project / "ref.txt"
        ref_file.write_text("x\n", encoding="utf-8")
        meta_before = (base / "run.json").read_text(encoding="utf-8")
        add_evidence_file(self.project, run_id, str(ref_file), "status unchanged")
        meta_after = (base / "run.json").read_text(encoding="utf-8")
        self.assertEqual(meta_before, meta_after)
        meta = json.loads(meta_after)
        self.assertEqual(meta["status"], "open")

    def test_evidence_add_file_does_not_modify_audit_owner_closure(self) -> None:
        run_id = create_mission(self.project, "20260704-040")
        base = run_path(self.project, run_id)
        ref_file = self.project / "ref.txt"
        ref_file.write_text("x\n", encoding="utf-8")
        audit_before = (base / "audit.md").read_text(encoding="utf-8")
        owner_before = (base / "owner-decision.md").read_text(encoding="utf-8")
        closure_before = (base / "closure.md").read_text(encoding="utf-8")
        add_evidence_file(self.project, run_id, str(ref_file), "audit untouched")
        self.assertEqual(audit_before, (base / "audit.md").read_text(encoding="utf-8"))
        self.assertEqual(owner_before, (base / "owner-decision.md").read_text(encoding="utf-8"))
        self.assertEqual(closure_before, (base / "closure.md").read_text(encoding="utf-8"))

    def test_closure_validation_unchanged_after_evidence_add_file(self) -> None:
        run_id = create_mission(self.project, "20260704-041")
        ref_file = self.project / "ref.txt"
        ref_file.write_text("x\n", encoding="utf-8")
        add_evidence(self.project, run_id, "baseline evidence")
        before = validate_run_for_closure(self.project, run_id)
        add_evidence_file(self.project, run_id, str(ref_file), "additional file reference")
        after = validate_run_for_closure(self.project, run_id)
        self.assertEqual(before.ok, after.ok)
        self.assertEqual(before.errors, after.errors)
        self.assertFalse(before.ok)
        self.assertIn("mission statement is placeholder/unfilled", before.errors)

    def test_evidence_add_command_output_appends_structured_block(self) -> None:
        run_id = create_mission(self.project, "20260704-050")
        output_file = self.project / "unittest-output.txt"
        output_file.write_text("test_foo ... ok\n", encoding="utf-8")
        cmd = "python -m unittest discover -s tests -v"
        add_evidence_command_output(
            self.project,
            run_id,
            cmd,
            str(output_file),
            "unit test output from local shell",
        )
        text = (run_path(self.project, run_id) / "evidence.md").read_text(encoding="utf-8")
        self.assertIn("## Evidence Entry —", text)
        self.assertIn("type: command-output", text)
        self.assertIn(f"command: {cmd}", text)
        self.assertIn(f"path: {output_file}", text)
        self.assertIn("claim: unit test output from local shell", text)
        self.assertIn("```text", text)
        self.assertIn("test_foo ... ok", text)
        self.assertRegex(text, r"## Evidence Entry — \d{4}-\d{2}-\d{2}T")

    def test_evidence_add_command_output_includes_bounded_output(self) -> None:
        run_id = create_mission(self.project, "20260704-051")
        output_file = self.project / "large-output.txt"
        output_file.write_text("x" * 9000, encoding="utf-8")
        add_evidence_command_output(
            self.project,
            run_id,
            "echo large",
            str(output_file),
            "large output",
        )
        text = (run_path(self.project, run_id) / "evidence.md").read_text(encoding="utf-8")
        self.assertIn("output truncated", text)
        self.assertIn("x" * 100, text)
        self.assertNotIn("x" * 9000, text)

    def test_evidence_add_command_output_does_not_modify_output_file(self) -> None:
        run_id = create_mission(self.project, "20260704-052")
        output_file = self.project / "immutable-output.txt"
        original = "must not change\n"
        output_file.write_text(original, encoding="utf-8")
        mtime_before = output_file.stat().st_mtime
        add_evidence_command_output(
            self.project,
            run_id,
            "python -m unittest",
            str(output_file),
            "unchanged output file",
        )
        self.assertEqual(output_file.read_text(encoding="utf-8"), original)
        self.assertEqual(output_file.stat().st_mtime, mtime_before)

    def test_evidence_add_command_output_preserves_previous_evidence(self) -> None:
        run_id = create_mission(self.project, "20260704-053")
        evidence_path = run_path(self.project, run_id) / "evidence.md"
        original = evidence_path.read_text(encoding="utf-8")
        output_file = self.project / "out.txt"
        output_file.write_text("ok\n", encoding="utf-8")
        add_evidence(self.project, run_id, "first note")
        add_evidence_command_output(
            self.project,
            run_id,
            "pytest -v",
            str(output_file),
            "pytest output",
        )
        text = evidence_path.read_text(encoding="utf-8")
        self.assertTrue(text.startswith(original.rstrip("\n")))
        self.assertIn("claim: first note", text)
        self.assertIn("claim: pytest output", text)
        self.assertIn("type: command-output", text)

    def test_evidence_list_shows_command_output_entries(self) -> None:
        run_id = create_mission(self.project, "20260704-054")
        output_file = self.project / "test-out.txt"
        output_file.write_text("passed\n", encoding="utf-8")
        cmd = "python -m unittest discover -s tests -v"
        add_evidence_command_output(
            self.project,
            run_id,
            cmd,
            str(output_file),
            "unit test output from local shell",
        )
        output = list_evidence(self.project, run_id)
        self.assertIn("[command-output] unit test output from local shell", output)
        self.assertIn(f"command: {cmd}", output)
        self.assertIn(f"path: {output_file}", output)

    def test_evidence_add_command_output_fails_for_missing_run(self) -> None:
        output_file = self.project / "exists.txt"
        output_file.write_text("x\n", encoding="utf-8")
        with self.assertRaises(FileNotFoundError):
            add_evidence_command_output(
                self.project,
                "missing-run",
                "echo hi",
                str(output_file),
                "note",
            )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "add-command-output",
                    "missing-run",
                    str(self.project),
                    "--command",
                    "echo hi",
                    "--output-file",
                    str(output_file),
                    "--note",
                    "note",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("run not found", buf.getvalue())

    def test_evidence_add_command_output_fails_for_missing_evidence_file(self) -> None:
        run_id = create_mission(self.project, "20260704-055")
        (run_path(self.project, run_id) / "evidence.md").unlink()
        output_file = self.project / "exists.txt"
        output_file.write_text("x\n", encoding="utf-8")
        with self.assertRaises(FileNotFoundError):
            add_evidence_command_output(
                self.project,
                run_id,
                "echo hi",
                str(output_file),
                "note",
            )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "add-command-output",
                    run_id,
                    str(self.project),
                    "--command",
                    "echo hi",
                    "--output-file",
                    str(output_file),
                    "--note",
                    "note",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("evidence file missing", buf.getvalue())

    def test_evidence_add_command_output_fails_for_empty_command(self) -> None:
        run_id = create_mission(self.project, "20260704-056")
        output_file = self.project / "exists.txt"
        output_file.write_text("x\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            add_evidence_command_output(
                self.project,
                run_id,
                "   ",
                str(output_file),
                "note",
            )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "add-command-output",
                    run_id,
                    str(self.project),
                    "--command",
                    "   ",
                    "--output-file",
                    str(output_file),
                    "--note",
                    "note",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("command must not be empty", buf.getvalue())

    def test_evidence_add_command_output_fails_for_empty_note(self) -> None:
        run_id = create_mission(self.project, "20260704-057")
        output_file = self.project / "exists.txt"
        output_file.write_text("x\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            add_evidence_command_output(
                self.project,
                run_id,
                "echo hi",
                str(output_file),
                "   ",
            )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "add-command-output",
                    run_id,
                    str(self.project),
                    "--command",
                    "echo hi",
                    "--output-file",
                    str(output_file),
                    "--note",
                    "   ",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("note must not be empty", buf.getvalue())

    def test_evidence_add_command_output_fails_for_missing_output_file(self) -> None:
        run_id = create_mission(self.project, "20260704-058")
        missing = self.project / "does-not-exist.txt"
        with self.assertRaises(FileNotFoundError):
            add_evidence_command_output(
                self.project,
                run_id,
                "echo hi",
                str(missing),
                "note",
            )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "add-command-output",
                    run_id,
                    str(self.project),
                    "--command",
                    "echo hi",
                    "--output-file",
                    str(missing),
                    "--note",
                    "note",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("output file not found", buf.getvalue())

    def test_evidence_add_command_output_does_not_execute_command(self) -> None:
        run_id = create_mission(self.project, "20260704-059")
        side_effect = self.project / "must-not-be-created.txt"
        output_file = self.project / "real-output.txt"
        output_file.write_text("captured output\n", encoding="utf-8")
        destructive_cmd = f'echo BOOM > "{side_effect}"'
        add_evidence_command_output(
            self.project,
            run_id,
            destructive_cmd,
            str(output_file),
            "declared but not run",
        )
        self.assertFalse(side_effect.exists())
        text = (run_path(self.project, run_id) / "evidence.md").read_text(encoding="utf-8")
        self.assertIn(f"command: {destructive_cmd}", text)
        self.assertIn("captured output", text)

    def test_evidence_add_command_output_does_not_change_run_status(self) -> None:
        run_id = create_mission(self.project, "20260704-060")
        base = run_path(self.project, run_id)
        output_file = self.project / "out.txt"
        output_file.write_text("x\n", encoding="utf-8")
        meta_before = (base / "run.json").read_text(encoding="utf-8")
        add_evidence_command_output(
            self.project,
            run_id,
            "pytest -v",
            str(output_file),
            "status unchanged",
        )
        meta_after = (base / "run.json").read_text(encoding="utf-8")
        self.assertEqual(meta_before, meta_after)
        meta = json.loads(meta_after)
        self.assertEqual(meta["status"], "open")

    def test_evidence_add_command_output_does_not_modify_audit_owner_closure(self) -> None:
        run_id = create_mission(self.project, "20260704-061")
        base = run_path(self.project, run_id)
        output_file = self.project / "out.txt"
        output_file.write_text("x\n", encoding="utf-8")
        audit_before = (base / "audit.md").read_text(encoding="utf-8")
        owner_before = (base / "owner-decision.md").read_text(encoding="utf-8")
        closure_before = (base / "closure.md").read_text(encoding="utf-8")
        add_evidence_command_output(
            self.project,
            run_id,
            "pytest -v",
            str(output_file),
            "audit untouched",
        )
        self.assertEqual(audit_before, (base / "audit.md").read_text(encoding="utf-8"))
        self.assertEqual(owner_before, (base / "owner-decision.md").read_text(encoding="utf-8"))
        self.assertEqual(closure_before, (base / "closure.md").read_text(encoding="utf-8"))

    def test_closure_validation_unchanged_after_evidence_add_command_output(self) -> None:
        run_id = create_mission(self.project, "20260704-062")
        output_file = self.project / "out.txt"
        output_file.write_text("x\n", encoding="utf-8")
        add_evidence(self.project, run_id, "baseline evidence")
        before = validate_run_for_closure(self.project, run_id)
        add_evidence_command_output(
            self.project,
            run_id,
            "pytest -v",
            str(output_file),
            "additional command output",
        )
        after = validate_run_for_closure(self.project, run_id)
        self.assertEqual(before.ok, after.ok)
        self.assertEqual(before.errors, after.errors)
        self.assertFalse(before.ok)
        self.assertIn("mission statement is placeholder/unfilled", before.errors)

    def test_evidence_snapshot_git_appends_structured_block(self) -> None:
        run_id = create_mission(self.project, "20260704-070")
        git_repo = self.project / "git-target"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        (git_repo / "README.md").write_text("# changed\n", encoding="utf-8")
        snapshot_evidence_git(
            self.project,
            run_id,
            "pre-commit repository state",
            repo=str(git_repo),
        )
        text = (run_path(self.project, run_id) / "evidence.md").read_text(encoding="utf-8")
        self.assertIn("## Evidence Entry —", text)
        self.assertIn("type: git-snapshot", text)
        self.assertIn(f"repo: {git_repo.resolve()}", text)
        self.assertIn("claim: pre-commit repository state", text)
        self.assertIn("git status --porcelain", text)
        self.assertIn("git diff --stat", text)
        self.assertRegex(text, r"## Evidence Entry — \d{4}-\d{2}-\d{2}T")

    def test_evidence_snapshot_git_records_head_when_available(self) -> None:
        run_id = create_mission(self.project, "20260704-071")
        git_repo = self.project / "git-head"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        snapshot_evidence_git(
            self.project,
            run_id,
            "head snapshot",
            repo=str(git_repo),
        )
        text = (run_path(self.project, run_id) / "evidence.md").read_text(encoding="utf-8")
        self.assertIn("head:", text)
        self.assertRegex(text, r"head: [0-9a-f]+")

    def test_evidence_snapshot_git_records_status_output(self) -> None:
        run_id = create_mission(self.project, "20260704-072")
        git_repo = self.project / "git-status"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        dirty = git_repo / "dirty.txt"
        dirty.write_text("untracked\n", encoding="utf-8")
        snapshot_evidence_git(
            self.project,
            run_id,
            "dirty tree",
            repo=str(git_repo),
        )
        text = (run_path(self.project, run_id) / "evidence.md").read_text(encoding="utf-8")
        self.assertIn("?? dirty.txt", text)

    def test_evidence_snapshot_git_records_diff_stat_when_enabled(self) -> None:
        run_id = create_mission(self.project, "20260704-073")
        git_repo = self.project / "git-diff"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        (git_repo / "README.md").write_text("# modified\n", encoding="utf-8")
        snapshot_evidence_git(
            self.project,
            run_id,
            "diff stat",
            repo=str(git_repo),
            include_diff_stat=True,
        )
        text = (run_path(self.project, run_id) / "evidence.md").read_text(encoding="utf-8")
        self.assertIn("git diff --stat", text)
        self.assertIn("README.md", text)

    def test_evidence_snapshot_git_omits_diff_stat_when_disabled(self) -> None:
        run_id = create_mission(self.project, "20260704-074")
        git_repo = self.project / "git-no-diff"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        (git_repo / "README.md").write_text("# modified\n", encoding="utf-8")
        snapshot_evidence_git(
            self.project,
            run_id,
            "no diff stat",
            repo=str(git_repo),
            include_diff_stat=False,
        )
        text = (run_path(self.project, run_id) / "evidence.md").read_text(encoding="utf-8")
        self.assertIn("git status --porcelain", text)
        self.assertNotIn("git diff --stat", text)

    def test_evidence_snapshot_git_preserves_previous_evidence(self) -> None:
        run_id = create_mission(self.project, "20260704-075")
        evidence_path = run_path(self.project, run_id) / "evidence.md"
        original = evidence_path.read_text(encoding="utf-8")
        git_repo = self.project / "git-preserve"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        add_evidence(self.project, run_id, "first note")
        snapshot_evidence_git(
            self.project,
            run_id,
            "git state",
            repo=str(git_repo),
        )
        text = evidence_path.read_text(encoding="utf-8")
        self.assertTrue(text.startswith(original.rstrip("\n")))
        self.assertIn("claim: first note", text)
        self.assertIn("claim: git state", text)
        self.assertIn("type: git-snapshot", text)

    def test_evidence_list_shows_git_snapshot_entries(self) -> None:
        run_id = create_mission(self.project, "20260704-076")
        git_repo = self.project / "git-list"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        snapshot_evidence_git(
            self.project,
            run_id,
            "pre-commit repository state",
            repo=str(git_repo),
        )
        output = list_evidence(self.project, run_id)
        self.assertIn("[git-snapshot] pre-commit repository state", output)
        self.assertIn(f"repo: {git_repo.resolve()}", output)
        self.assertRegex(output, r"branch/head: .+ @ [0-9a-f]+")

    def test_evidence_snapshot_git_fails_for_missing_run(self) -> None:
        git_repo = self.project / "git-missing-run"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        with self.assertRaises(FileNotFoundError):
            snapshot_evidence_git(
                self.project,
                "missing-run",
                "note",
                repo=str(git_repo),
            )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "snapshot-git",
                    "missing-run",
                    str(self.project),
                    "--note",
                    "note",
                    "--repo",
                    str(git_repo),
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("run not found", buf.getvalue())

    def test_evidence_snapshot_git_fails_for_missing_evidence_file(self) -> None:
        run_id = create_mission(self.project, "20260704-077")
        (run_path(self.project, run_id) / "evidence.md").unlink()
        git_repo = self.project / "git-no-evidence"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        with self.assertRaises(FileNotFoundError):
            snapshot_evidence_git(
                self.project,
                run_id,
                "note",
                repo=str(git_repo),
            )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "snapshot-git",
                    run_id,
                    str(self.project),
                    "--note",
                    "note",
                    "--repo",
                    str(git_repo),
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("evidence file missing", buf.getvalue())

    def test_evidence_snapshot_git_fails_for_empty_note(self) -> None:
        run_id = create_mission(self.project, "20260704-078")
        git_repo = self.project / "git-empty-note"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        with self.assertRaises(ValueError):
            snapshot_evidence_git(
                self.project,
                run_id,
                "   ",
                repo=str(git_repo),
            )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "snapshot-git",
                    run_id,
                    str(self.project),
                    "--note",
                    "   ",
                    "--repo",
                    str(git_repo),
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("note must not be empty", buf.getvalue())

    def test_evidence_snapshot_git_fails_for_missing_repo_path(self) -> None:
        run_id = create_mission(self.project, "20260704-079")
        missing = self.project / "does-not-exist"
        with self.assertRaises(FileNotFoundError):
            snapshot_evidence_git(
                self.project,
                run_id,
                "note",
                repo=str(missing),
            )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "snapshot-git",
                    run_id,
                    str(self.project),
                    "--note",
                    "note",
                    "--repo",
                    str(missing),
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("repo path not found", buf.getvalue())

    def test_evidence_snapshot_git_fails_gracefully_for_non_git_repo(self) -> None:
        run_id = create_mission(self.project, "20260704-080")
        not_git = self.project / "plain-dir"
        not_git.mkdir()
        with self.assertRaises(ValueError) as ctx:
            snapshot_evidence_git(
                self.project,
                run_id,
                "note",
                repo=str(not_git),
            )
        self.assertIn("not a git repository", str(ctx.exception))

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "evidence",
                    "snapshot-git",
                    run_id,
                    str(self.project),
                    "--note",
                    "note",
                    "--repo",
                    str(not_git),
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("not a git repository", buf.getvalue())

    def test_evidence_snapshot_git_does_not_change_run_status(self) -> None:
        run_id = create_mission(self.project, "20260704-081")
        base = run_path(self.project, run_id)
        git_repo = self.project / "git-status-unchanged"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        meta_before = (base / "run.json").read_text(encoding="utf-8")
        snapshot_evidence_git(
            self.project,
            run_id,
            "status unchanged",
            repo=str(git_repo),
        )
        meta_after = (base / "run.json").read_text(encoding="utf-8")
        self.assertEqual(meta_before, meta_after)
        meta = json.loads(meta_after)
        self.assertEqual(meta["status"], "open")

    def test_evidence_snapshot_git_does_not_modify_audit_owner_closure(self) -> None:
        run_id = create_mission(self.project, "20260704-082")
        base = run_path(self.project, run_id)
        git_repo = self.project / "git-audit-untouched"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        audit_before = (base / "audit.md").read_text(encoding="utf-8")
        owner_before = (base / "owner-decision.md").read_text(encoding="utf-8")
        closure_before = (base / "closure.md").read_text(encoding="utf-8")
        snapshot_evidence_git(
            self.project,
            run_id,
            "audit untouched",
            repo=str(git_repo),
        )
        self.assertEqual(audit_before, (base / "audit.md").read_text(encoding="utf-8"))
        self.assertEqual(owner_before, (base / "owner-decision.md").read_text(encoding="utf-8"))
        self.assertEqual(closure_before, (base / "closure.md").read_text(encoding="utf-8"))

    def test_closure_validation_unchanged_after_evidence_snapshot_git(self) -> None:
        run_id = create_mission(self.project, "20260704-083")
        git_repo = self.project / "git-validation"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        add_evidence(self.project, run_id, "baseline evidence")
        before = validate_run_for_closure(self.project, run_id)
        snapshot_evidence_git(
            self.project,
            run_id,
            "additional git snapshot",
            repo=str(git_repo),
        )
        after = validate_run_for_closure(self.project, run_id)
        self.assertEqual(before.ok, after.ok)
        self.assertEqual(before.errors, after.errors)
        self.assertFalse(before.ok)
        self.assertIn("mission statement is placeholder/unfilled", before.errors)

    def test_evidence_snapshot_git_uses_fixed_readonly_git_commands_only(self) -> None:
        expected = {
            ("rev-parse", "--is-inside-work-tree"),
            ("rev-parse", "--short", "HEAD"),
            ("branch", "--show-current"),
            ("status", "--porcelain"),
            ("diff", "--stat"),
        }
        self.assertEqual(set(GIT_SNAPSHOT_READONLY_ARGV), expected)
        forbidden = {
            "add",
            "commit",
            "push",
            "pull",
            "checkout",
            "reset",
            "clean",
            "merge",
            "rebase",
        }
        for argv in GIT_SNAPSHOT_READONLY_ARGV:
            self.assertNotIn(argv[0], forbidden)

    def test_evidence_snapshot_git_does_not_use_shell_true(self) -> None:
        workspace_source = (
            Path(__file__).resolve().parent.parent / "agent_os" / "workspace.py"
        ).read_text(encoding="utf-8")
        snapshot_section = workspace_source.split("GIT_SNAPSHOT_READONLY_ARGV", 1)[1]
        snapshot_section = snapshot_section.split("def add_evidence_file", 1)[0]
        self.assertNotIn("shell=True", snapshot_section)
        self.assertIn("shell=False", snapshot_section)

    def test_evidence_snapshot_git_does_not_expose_arbitrary_command_execution(self) -> None:
        run_id = create_mission(self.project, "20260704-084")
        git_repo = self.project / "git-no-shell"
        git_repo.mkdir()
        _init_git_repo(git_repo)
        side_effect = self.project / "must-not-be-created-by-git.txt"
        self.assertFalse(side_effect.exists())
        snapshot_evidence_git(
            self.project,
            run_id,
            "fixed commands only",
            repo=str(git_repo),
        )
        self.assertFalse(side_effect.exists())
        text = (run_path(self.project, run_id) / "evidence.md").read_text(encoding="utf-8")
        self.assertIn("type: git-snapshot", text)
        self.assertNotIn("must-not-be-created", text)


class PlanningInitTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_planning_init_creates_expected_structure(self) -> None:
        plan_id = "slither-demo"
        dest = init_planning_workspace(self.project, plan_id)
        self.assertTrue(dest.is_dir())
        for name in (
            "manifest.json",
            "README.md",
            "context-pack.md",
            "local-agentic-spec.md",
            "implementation-plan.md",
            "planning-audit.md",
        ):
            self.assertTrue((dest / name).is_file(), name)
        for subdir in ("evidence", "decisions", "revisions"):
            self.assertTrue((dest / subdir).is_dir(), subdir)

    def test_planning_init_copies_templates(self) -> None:
        plan_id = "planning_001"
        dest = init_planning_workspace(self.project, plan_id)
        template_dir = (
            Path(__file__).resolve().parent.parent / "agent_os" / "templates" / "planning"
        )
        for filename in (
            "context-pack.md",
            "local-agentic-spec.md",
            "implementation-plan.md",
            "planning-audit.md",
        ):
            template_text = (template_dir / filename).read_text(encoding="utf-8")
            actual = (dest / filename).read_text(encoding="utf-8")
            self.assertIn(f"plan_id: {plan_id}", actual)
            self.assertNotIn("{{PLAN_ID}}", actual)
            self.assertNotIn("{{CREATED_AT}}", actual)
            self.assertIn("# ", actual)
            self.assertIn(
                template_text.split("# ", 1)[1][:40].replace("{{PLAN_ID}}", plan_id),
                actual,
            )

    def test_planning_init_manifest_has_draft_status_and_safety_flags(self) -> None:
        plan_id = "planning_001"
        dest = init_planning_workspace(self.project, plan_id)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["plan_id"], plan_id)
        self.assertEqual(manifest["status"], "DRAFT")
        self.assertEqual(manifest["package_type"], "PLANNING_WORKSPACE")
        self.assertRegex(manifest["created_at"], r"^\d{4}-\d{2}-\d{2}T")
        self.assertEqual(manifest["artifact_paths"]["context_pack"], "context-pack.md")
        self.assertEqual(
            manifest["artifact_paths"]["local_agentic_spec"],
            "local-agentic-spec.md",
        )
        self.assertEqual(
            manifest["artifact_paths"]["implementation_plan"],
            "implementation-plan.md",
        )
        self.assertEqual(
            manifest["artifact_paths"]["planning_audit"],
            "planning-audit.md",
        )
        self.assertEqual(manifest["directories"]["evidence"], "evidence/")
        self.assertEqual(manifest["directories"]["decisions"], "decisions/")
        self.assertEqual(manifest["directories"]["revisions"], "revisions/")
        self.assertTrue(manifest["gates"]["planning_owner_decision_required"])
        self.assertTrue(manifest["gates"]["planning_audit_required"])
        self.assertFalse(manifest["gates"]["plan_revision_required"])
        self.assertFalse(manifest["gates"]["run_proposal_allowed"])
        self.assertTrue(manifest["authority"]["no_execution"])
        self.assertTrue(manifest["authority"]["no_agent_invocation"])
        self.assertTrue(manifest["authority"]["no_run_creation"])
        self.assertTrue(manifest["authority"]["no_self_approval"])

    def test_planning_init_rejects_invalid_plan_ids(self) -> None:
        invalid_ids = ["", "../x", "a/b", "my plan", ".hidden", "-bad", "Bad", "a.b"]
        for plan_id in invalid_ids:
            with self.subTest(plan_id=plan_id):
                with self.assertRaises(ValueError):
                    validate_plan_id(plan_id)
                if plan_id.startswith("-"):
                    continue
                buf = io.StringIO()
                with redirect_stderr(buf):
                    code = main(["planning", "init", plan_id, str(self.project)])
                self.assertEqual(code, 1)
                self.assertTrue(buf.getvalue().strip())

    def test_planning_init_does_not_overwrite_existing_workspace(self) -> None:
        plan_id = "slither-demo"
        init_planning_workspace(self.project, plan_id)
        manifest_path = planning_path(self.project, plan_id) / "manifest.json"
        original = manifest_path.read_text(encoding="utf-8")

        with self.assertRaises(FileExistsError):
            init_planning_workspace(self.project, plan_id)

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["planning", "init", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("already exists", buf.getvalue())
        self.assertEqual(original, manifest_path.read_text(encoding="utf-8"))

    def test_planning_init_fails_when_agent_os_not_initialized(self) -> None:
        bare = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(FileNotFoundError):
                init_planning_workspace(bare, "demo-plan")
            buf = io.StringIO()
            with redirect_stderr(buf):
                code = main(["planning", "init", "demo-plan", str(bare)])
            self.assertEqual(code, 1)
            self.assertIn("no workspace found", buf.getvalue())
        finally:
            import shutil

            shutil.rmtree(bare)

    def test_planning_init_does_not_create_runs_or_unrelated_files(self) -> None:
        plan_id = "slither-demo"
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        workspace_json_before = (workspace / "workspace.json").read_text(encoding="utf-8")

        init_planning_workspace(self.project, plan_id)

        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)
        self.assertEqual(
            workspace_json_before,
            (workspace / "workspace.json").read_text(encoding="utf-8"),
        )
        planning_root = workspace / "planning"
        self.assertEqual({plan_id}, {p.name for p in planning_root.iterdir()})

    def test_planning_init_cli_success_output(self) -> None:
        plan_id = "slither-demo"
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "init", plan_id, str(self.project)])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("created planning workspace:", output)
        self.assertIn("status: DRAFT", output)
        self.assertIn("next step: fill context-pack.md", output)
        self.assertIn("no runs were created and no agents were invoked", output)

    def test_planning_init_readme_has_non_authority_notice(self) -> None:
        plan_id = "slither-demo"
        dest = init_planning_workspace(self.project, plan_id)
        readme = (dest / "README.md").read_text(encoding="utf-8")
        self.assertIn("planning artifacts only", readme)
        self.assertIn("does **not** execute code", readme)
        self.assertIn("does **not** create runs", readme)
        self.assertIn("does **not** approve work", readme)
        self.assertIn("does **not** invoke agents", readme)
        self.assertIn("not executable", readme)


class PlanningStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _init_plan(self, plan_id: str = "slither-demo") -> Path:
        return init_planning_workspace(self.project, plan_id)

    def _snapshot_planning_tree(self) -> dict[str, str]:
        workspace = self.project / ".agent-os"
        snapshots: dict[str, str] = {}
        for path in workspace.rglob("*"):
            if path.is_file():
                rel = path.relative_to(workspace).as_posix()
                snapshots[rel] = path.read_text(encoding="utf-8")
        return snapshots

    def test_planning_status_success_on_init_workspace(self) -> None:
        plan_id = "slither-demo"
        dest = self._init_plan(plan_id)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "status", plan_id, str(self.project)])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn(f"planning workspace: {dest}", output)
        self.assertIn(f"plan_id: {plan_id}", output)
        self.assertIn("status: DRAFT", output)
        self.assertIn("created_at:", output)
        self.assertIn("manifest.json: present", output)
        self.assertIn("README.md: present", output)
        self.assertIn("context-pack.md: present", output)
        self.assertIn("local-agentic-spec.md: present", output)
        self.assertIn("implementation-plan.md: present", output)
        self.assertIn("planning-audit.md: present", output)
        self.assertIn("evidence/: present", output)
        self.assertIn("decisions/: present", output)
        self.assertIn("revisions/: present", output)
        self.assertIn("planning_owner_decision_required: true", output)
        self.assertIn("planning_audit_required: true", output)
        self.assertIn("plan_revision_required: false", output)
        self.assertIn("run_proposal_allowed: false", output)
        self.assertIn("no_execution: true", output)
        self.assertIn("no_agent_invocation: true", output)
        self.assertIn("no_run_creation: true", output)
        self.assertIn("no_self_approval: true", output)
        self.assertIn("structural result: OK", output)

    def test_planning_status_api_matches_cli(self) -> None:
        plan_id = "planning_001"
        self._init_plan(plan_id)
        report = status_planning_workspace(self.project, plan_id)
        self.assertTrue(report.structural_ok)
        self.assertIn("status: DRAFT", report.output)
        self.assertIn("structural result: OK", report.output)

    def test_planning_status_rejects_invalid_plan_ids(self) -> None:
        invalid_ids = ["", "../x", "a/b", "my plan", ".hidden", "-bad", "Bad", "a.b"]
        for plan_id in invalid_ids:
            with self.subTest(plan_id=plan_id):
                with self.assertRaises(ValueError):
                    validate_plan_id(plan_id)
                if plan_id.startswith("-"):
                    continue
                buf = io.StringIO()
                with redirect_stderr(buf):
                    code = main(["planning", "status", plan_id, str(self.project)])
                self.assertEqual(code, 1)
                self.assertTrue(buf.getvalue().strip())

    def test_planning_status_fails_when_agent_os_not_initialized(self) -> None:
        bare = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(FileNotFoundError):
                status_planning_workspace(bare, "demo-plan")
            buf = io.StringIO()
            with redirect_stderr(buf):
                code = main(["planning", "status", "demo-plan", str(bare)])
            self.assertEqual(code, 1)
            self.assertIn("no workspace found", buf.getvalue())
        finally:
            import shutil

            shutil.rmtree(bare)

    def test_planning_status_fails_for_missing_workspace(self) -> None:
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["planning", "status", "missing-plan", str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("planning workspace not found", buf.getvalue())

    def test_planning_status_fails_for_missing_manifest(self) -> None:
        plan_id = "no-manifest"
        dest = planning_path(self.project, plan_id)
        dest.mkdir(parents=True)
        for subdir in ("evidence", "decisions", "revisions"):
            (dest / subdir).mkdir()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["planning", "status", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("manifest.json missing", buf.getvalue())

    def test_planning_status_fails_for_malformed_manifest(self) -> None:
        plan_id = "bad-manifest"
        dest = self._init_plan(plan_id)
        (dest / "manifest.json").write_text("{not json", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["planning", "status", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("invalid manifest.json", buf.getvalue())

    def test_planning_status_fails_for_manifest_plan_id_mismatch(self) -> None:
        plan_id = "mismatch-plan"
        dest = self._init_plan(plan_id)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        manifest["plan_id"] = "other-plan"
        (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["planning", "status", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("manifest plan_id mismatch", buf.getvalue())

    def test_planning_status_reports_broken_when_artifact_missing(self) -> None:
        plan_id = "broken-artifact"
        dest = self._init_plan(plan_id)
        (dest / "context-pack.md").unlink()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "status", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        output = buf.getvalue()
        self.assertIn("context-pack.md: missing", output)
        self.assertIn("structural result: BROKEN", output)

    def test_planning_status_reports_broken_when_directory_missing(self) -> None:
        plan_id = "broken-dir"
        dest = self._init_plan(plan_id)
        import shutil

        shutil.rmtree(dest / "evidence")

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "status", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        output = buf.getvalue()
        self.assertIn("evidence/: missing", output)
        self.assertIn("structural result: BROKEN", output)

    def test_planning_status_is_read_only(self) -> None:
        plan_id = "slither-demo"
        self._init_plan(plan_id)
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        workspace_json_before = (workspace / "workspace.json").read_text(encoding="utf-8")
        planning_snapshots = self._snapshot_planning_tree()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "status", plan_id, str(self.project)])
        self.assertEqual(code, 0)

        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)
        self.assertEqual(
            workspace_json_before,
            (workspace / "workspace.json").read_text(encoding="utf-8"),
        )
        self.assertEqual(planning_snapshots, self._snapshot_planning_tree())
        self.assertIn("structural result: OK", buf.getvalue())


def _prepare_valid_planning_workspace(project: Path, plan_id: str) -> Path:
    """Fill init workspace enough to pass weak validation."""
    dest = init_planning_workspace(project, plan_id)
    _fill_planning_lifecycle_artifacts(dest, plan_id)
    return dest


def _fill_planning_lifecycle_artifacts(dest: Path, plan_id: str) -> None:
    """Write valid minimal planning artifact content for lifecycle integration tests."""
    examples = (
        Path(__file__).resolve().parent.parent
        / "examples"
        / "planning-workspace-slither-like"
    )
    for filename in (
        "context-pack.md",
        "local-agentic-spec.md",
        "implementation-plan.md",
        "planning-audit.md",
    ):
        text = (examples / filename).read_text(encoding="utf-8")
        text = text.replace("slither-like-example", plan_id)
        text = text.replace("example_only: true\n", "")
        (dest / filename).write_text(text, encoding="utf-8")


class PlanningValidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _snapshot_planning_tree(self) -> dict[str, str]:
        workspace = self.project / ".agent-os"
        snapshots: dict[str, str] = {}
        for path in workspace.rglob("*"):
            if path.is_file():
                rel = path.relative_to(workspace).as_posix()
                snapshots[rel] = path.read_text(encoding="utf-8")
        return snapshots

    def test_planning_validate_success_on_acceptable_workspace(self) -> None:
        plan_id = "slither-demo"
        dest = _prepare_valid_planning_workspace(self.project, plan_id)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "validate", plan_id, str(self.project)])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn(f"planning workspace: {dest}", output)
        self.assertIn(f"plan_id: {plan_id}", output)
        self.assertIn("status: DRAFT", output)
        self.assertIn("structural result: OK", output)
        self.assertIn("manifest validation: OK", output)
        self.assertIn("artifact validation: OK", output)
        self.assertIn("final validation result: OK", output)
        self.assertIn("no files were modified", output)
        self.assertIn("no runs were created", output)
        self.assertIn("no agents were invoked", output)

    def test_planning_validate_api_matches_cli(self) -> None:
        plan_id = "planning_001"
        _prepare_valid_planning_workspace(self.project, plan_id)
        report = validate_planning_workspace(self.project, plan_id)
        self.assertTrue(report.valid)
        self.assertIn("final validation result: OK", report.output)

    def test_planning_validate_fails_after_init_due_to_placeholders(self) -> None:
        plan_id = "fresh-plan"
        init_planning_workspace(self.project, plan_id)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "validate", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        output = buf.getvalue()
        self.assertIn("artifact validation: INVALID", output)
        self.assertIn("placeholder still present", output)
        self.assertIn("final validation result: INVALID", output)

    def test_planning_validate_fails_for_missing_manifest_field(self) -> None:
        plan_id = "missing-status"
        dest = _prepare_valid_planning_workspace(self.project, plan_id)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        del manifest["status"]
        (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "validate", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        output = buf.getvalue()
        self.assertIn("manifest validation: INVALID", output)
        self.assertIn("missing manifest field: status", output)
        self.assertIn("final validation result: INVALID", output)

    def test_planning_validate_fails_for_wrong_package_type(self) -> None:
        plan_id = "wrong-type"
        dest = _prepare_valid_planning_workspace(self.project, plan_id)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        manifest["package_type"] = "RUN_PACKAGE"
        (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "validate", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("wrong package_type", buf.getvalue())

    def test_planning_validate_fails_for_missing_gate(self) -> None:
        plan_id = "missing-gate"
        dest = _prepare_valid_planning_workspace(self.project, plan_id)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        del manifest["gates"]["run_proposal_allowed"]
        (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "validate", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("missing gate: run_proposal_allowed", buf.getvalue())

    def test_planning_validate_fails_for_missing_authority_flag(self) -> None:
        plan_id = "missing-authority"
        dest = _prepare_valid_planning_workspace(self.project, plan_id)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        manifest["authority"]["no_execution"] = False
        (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "validate", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        output = buf.getvalue()
        self.assertIn("authority flag must be true: no_execution", output)

    def test_planning_validate_fails_for_missing_artifact_type_marker(self) -> None:
        plan_id = "missing-marker"
        dest = _prepare_valid_planning_workspace(self.project, plan_id)
        path = dest / "context-pack.md"
        path.write_text(path.read_text(encoding="utf-8").replace("CONTEXT_PACK", "MISSING"), encoding="utf-8")

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "validate", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("missing artifact type marker", buf.getvalue())

    def test_planning_validate_fails_for_missing_required_section(self) -> None:
        plan_id = "missing-section"
        dest = _prepare_valid_planning_workspace(self.project, plan_id)
        path = dest / "local-agentic-spec.md"
        path.write_text(
            path.read_text(encoding="utf-8").replace("## Non-goals", "## Removed"),
            encoding="utf-8",
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "validate", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("required section missing", buf.getvalue())
        self.assertIn("Non-goals", buf.getvalue())

    def test_planning_validate_fails_for_placeholder_token(self) -> None:
        plan_id = "placeholder-token"
        dest = _prepare_valid_planning_workspace(self.project, plan_id)
        path = dest / "planning-audit.md"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n{{CUSTOM_PLACEHOLDER}}\n",
            encoding="utf-8",
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "validate", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("placeholder still present", buf.getvalue())

    def test_planning_validate_fails_for_structurally_broken_workspace(self) -> None:
        plan_id = "broken-structure"
        dest = _prepare_valid_planning_workspace(self.project, plan_id)
        (dest / "context-pack.md").unlink()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "validate", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        output = buf.getvalue()
        self.assertIn("structural result: BROKEN", output)
        self.assertIn("artifact missing: context-pack.md", output)
        self.assertIn("final validation result: INVALID", output)

    def test_planning_validate_is_read_only(self) -> None:
        plan_id = "slither-demo"
        _prepare_valid_planning_workspace(self.project, plan_id)
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        workspace_json_before = (workspace / "workspace.json").read_text(encoding="utf-8")
        planning_snapshots = self._snapshot_planning_tree()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "validate", plan_id, str(self.project)])
        self.assertEqual(code, 0)

        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)
        self.assertEqual(
            workspace_json_before,
            (workspace / "workspace.json").read_text(encoding="utf-8"),
        )
        self.assertEqual(planning_snapshots, self._snapshot_planning_tree())

    def test_planning_validate_fails_when_agent_os_not_initialized(self) -> None:
        bare = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(FileNotFoundError):
                validate_planning_workspace(bare, "demo-plan")
            buf = io.StringIO()
            with redirect_stderr(buf):
                code = main(["planning", "validate", "demo-plan", str(bare)])
            self.assertEqual(code, 1)
            self.assertIn("no workspace found", buf.getvalue())
        finally:
            import shutil

            shutil.rmtree(bare)


class PlanningDecideTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _snapshot_planning_tree(self) -> dict[str, str]:
        workspace = self.project / ".agent-os"
        snapshots: dict[str, str] = {}
        for path in workspace.rglob("*"):
            if path.is_file():
                rel = path.relative_to(workspace).as_posix()
                snapshots[rel] = path.read_text(encoding="utf-8")
        return snapshots

    def _decision_files(self, dest: Path) -> list[Path]:
        return sorted((dest / "decisions").glob("*__owner-decision.json"))

    def test_request_revision_creates_one_decision_record(self) -> None:
        plan_id = "decide-revision"
        dest = init_planning_workspace(self.project, plan_id)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "planning",
                    "decide",
                    plan_id,
                    str(self.project),
                    "--decision",
                    "REQUEST_REVISION",
                    "--summary",
                    "spec needs scope fix",
                ]
            )
        self.assertEqual(code, 0)
        files = self._decision_files(dest)
        self.assertEqual(len(files), 1)
        record = json.loads(files[0].read_text(encoding="utf-8"))
        self.assertEqual(record["record_type"], "PLANNING_OWNER_DECISION")
        self.assertEqual(record["plan_id"], plan_id)
        self.assertEqual(record["decision"], "REQUEST_REVISION")
        self.assertEqual(record["summary"], "spec needs scope fix")
        self.assertRegex(record["created_at"], r"^\d{4}-\d{2}-\d{2}T")
        self.assertEqual(record["workspace_status_at_decision"], "DRAFT")
        self.assertTrue(record["authority"]["does_not_mutate_manifest"])

    def test_block_succeeds_when_validation_fails(self) -> None:
        plan_id = "decide-block-invalid"
        dest = init_planning_workspace(self.project, plan_id)
        report = validate_planning_workspace(self.project, plan_id)
        self.assertFalse(report.valid)

        result = record_planning_owner_decision(
            self.project,
            plan_id,
            "BLOCK",
            "artifacts incomplete",
        )
        self.assertEqual(len(self._decision_files(dest)), 1)
        self.assertEqual(result.decision, "BLOCK")
        output = result.output
        self.assertIn("planning validation is not OK", output)

    def test_approve_succeeds_when_validation_passes(self) -> None:
        plan_id = "decide-approve-ok"
        dest = _prepare_valid_planning_workspace(self.project, plan_id)
        report = validate_planning_workspace(self.project, plan_id)
        self.assertTrue(report.valid)

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "planning",
                    "decide",
                    plan_id,
                    str(self.project),
                    "--decision",
                    "APPROVE_FOR_RUN_PROPOSALS",
                    "--summary",
                    "planning package acceptable",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(len(self._decision_files(dest)), 1)
        record = json.loads(self._decision_files(dest)[0].read_text(encoding="utf-8"))
        self.assertEqual(record["decision"], "APPROVE_FOR_RUN_PROPOSALS")

    def test_approve_fails_when_validation_fails(self) -> None:
        plan_id = "decide-approve-invalid"
        init_planning_workspace(self.project, plan_id)
        report = validate_planning_workspace(self.project, plan_id)
        self.assertFalse(report.valid)

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "planning",
                    "decide",
                    plan_id,
                    str(self.project),
                    "--decision",
                    "APPROVE_FOR_RUN_PROPOSALS",
                    "--summary",
                    "should not record",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn(
            "Cannot record APPROVE_FOR_RUN_PROPOSALS because planning validation is not OK.",
            buf.getvalue(),
        )
        dest = planning_path(self.project, plan_id)
        self.assertEqual(len(self._decision_files(dest)), 0)

    def test_close_creates_one_decision_record(self) -> None:
        plan_id = "decide-close"
        dest = init_planning_workspace(self.project, plan_id)
        result = record_planning_owner_decision(
            self.project,
            plan_id,
            "CLOSE",
            "planning abandoned",
        )
        self.assertEqual(len(self._decision_files(dest)), 1)
        record = json.loads(result.decision_path.read_text(encoding="utf-8"))
        self.assertEqual(record["decision"], "CLOSE")

    def test_invalid_decision_value_rejected(self) -> None:
        plan_id = "decide-bad-value"
        init_planning_workspace(self.project, plan_id)
        with self.assertRaises(ValueError) as ctx:
            record_planning_owner_decision(
                self.project,
                plan_id,
                "ACCEPT",
                "not allowed",
            )
        self.assertIn("invalid decision", str(ctx.exception))

    def test_empty_summary_rejected(self) -> None:
        plan_id = "decide-empty-summary"
        init_planning_workspace(self.project, plan_id)
        with self.assertRaises(ValueError):
            record_planning_owner_decision(
                self.project,
                plan_id,
                "BLOCK",
                "   ",
            )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "planning",
                    "decide",
                    plan_id,
                    str(self.project),
                    "--decision",
                    "BLOCK",
                    "--summary",
                    "   ",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("summary must not be empty", buf.getvalue())

    def test_fails_for_missing_workspace(self) -> None:
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "planning",
                    "decide",
                    "missing-plan",
                    str(self.project),
                    "--decision",
                    "BLOCK",
                    "--summary",
                    "no workspace",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("planning workspace not found", buf.getvalue())

    def test_fails_for_missing_manifest(self) -> None:
        plan_id = "no-manifest-decide"
        dest = planning_path(self.project, plan_id)
        dest.mkdir(parents=True)
        (dest / "decisions").mkdir()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "planning",
                    "decide",
                    plan_id,
                    str(self.project),
                    "--decision",
                    "BLOCK",
                    "--summary",
                    "missing manifest",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("manifest.json missing", buf.getvalue())

    def test_fails_for_manifest_plan_id_mismatch(self) -> None:
        plan_id = "mismatch-decide"
        dest = init_planning_workspace(self.project, plan_id)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        manifest["plan_id"] = "other-plan"
        (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "planning",
                    "decide",
                    plan_id,
                    str(self.project),
                    "--decision",
                    "BLOCK",
                    "--summary",
                    "mismatch",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("manifest plan_id mismatch", buf.getvalue())

    def test_fails_for_missing_decisions_directory(self) -> None:
        plan_id = "no-decisions-dir"
        dest = init_planning_workspace(self.project, plan_id)
        import shutil

        shutil.rmtree(dest / "decisions")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "planning",
                    "decide",
                    plan_id,
                    str(self.project),
                    "--decision",
                    "BLOCK",
                    "--summary",
                    "no decisions dir",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("decisions directory missing", buf.getvalue())

    def test_does_not_mutate_manifest(self) -> None:
        plan_id = "decide-manifest-unchanged"
        dest = init_planning_workspace(self.project, plan_id)
        manifest_before = (dest / "manifest.json").read_text(encoding="utf-8")
        record_planning_owner_decision(
            self.project,
            plan_id,
            "REQUEST_REVISION",
            "fix spec",
        )
        self.assertEqual(
            manifest_before,
            (dest / "manifest.json").read_text(encoding="utf-8"),
        )

    def test_does_not_create_runs_or_unrelated_files(self) -> None:
        plan_id = "decide-no-runs"
        dest = init_planning_workspace(self.project, plan_id)
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        workspace_json_before = (workspace / "workspace.json").read_text(encoding="utf-8")
        snapshots_before = self._snapshot_planning_tree()

        record_planning_owner_decision(
            self.project,
            plan_id,
            "BLOCK",
            "stop here",
        )

        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)
        self.assertEqual(
            workspace_json_before,
            (workspace / "workspace.json").read_text(encoding="utf-8"),
        )
        snapshots_after = self._snapshot_planning_tree()
        new_keys = set(snapshots_after) - set(snapshots_before)
        self.assertEqual(len(new_keys), 1)
        self.assertTrue(new_keys.pop().endswith("__owner-decision.json"))

    def test_preserves_existing_decision_files(self) -> None:
        plan_id = "decide-preserve"
        dest = init_planning_workspace(self.project, plan_id)
        existing = dest / "decisions" / "2026-01-01T00-00-00Z__owner-decision.json"
        existing_content = '{"record_type": "PLANNING_OWNER_DECISION", "decision": "BLOCK"}\n'
        existing.write_text(existing_content, encoding="utf-8")

        record_planning_owner_decision(
            self.project,
            plan_id,
            "REQUEST_REVISION",
            "new decision",
        )

        self.assertEqual(len(self._decision_files(dest)), 2)
        self.assertEqual(existing.read_text(encoding="utf-8"), existing_content)

    def test_cli_output_includes_safety_notes(self) -> None:
        plan_id = "decide-cli-output"
        init_planning_workspace(self.project, plan_id)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "planning",
                    "decide",
                    plan_id,
                    str(self.project),
                    "--decision",
                    "BLOCK",
                    "--summary",
                    "blocked for now",
                ]
            )
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("decision recorded", output)
        self.assertIn("manifest status was not changed", output)
        self.assertIn("no runs were created", output)
        self.assertIn("no agents were invoked", output)


class PlanningDecisionsListTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _snapshot_agent_os_tree(self) -> dict[str, str]:
        workspace = self.project / ".agent-os"
        snapshots: dict[str, str] = {}
        for path in workspace.rglob("*"):
            if path.is_file():
                rel = path.relative_to(workspace).as_posix()
                snapshots[rel] = path.read_text(encoding="utf-8")
        return snapshots

    def _write_owner_decision(
        self,
        dest: Path,
        filename: str,
        *,
        plan_id: str,
        decision: str = "BLOCK",
        summary: str = "test summary",
        created_at: str = "2026-01-01T00:00:00+00:00",
        workspace_status: str = "DRAFT",
    ) -> None:
        _write_json(
            dest / "decisions" / filename,
            {
                "record_type": "PLANNING_OWNER_DECISION",
                "plan_id": plan_id,
                "decision": decision,
                "summary": summary,
                "created_at": created_at,
                "workspace_status_at_decision": workspace_status,
                "authority": {
                    "records_decision_only": True,
                    "does_not_execute": True,
                    "does_not_create_runs": True,
                    "does_not_mutate_manifest": True,
                    "does_not_approve_runner_execution": True,
                },
            },
        )

    def test_list_zero_decisions_succeeds(self) -> None:
        plan_id = "list-empty"
        dest = init_planning_workspace(self.project, plan_id)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "decisions", "list", plan_id, str(self.project)])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn(f"planning workspace: {dest}", output)
        self.assertIn(f"plan_id: {plan_id}", output)
        self.assertIn("decision records: 0", output)
        self.assertIn("latest decision:", output)
        self.assertIn("none", output)

    def test_list_one_decision_from_decide_succeeds(self) -> None:
        plan_id = "list-one"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "REQUEST_REVISION",
            "spec needs scope fix",
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "decisions", "list", plan_id, str(self.project)])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("decision records: 1", output)
        self.assertIn("decision: REQUEST_REVISION", output)
        self.assertIn("summary: spec needs scope fix", output)
        self.assertIn("workspace_status_at_decision: DRAFT", output)
        self.assertIn("__owner-decision.json", output)

    def test_list_multiple_decisions_sorted_by_created_at(self) -> None:
        plan_id = "list-multi"
        dest = init_planning_workspace(self.project, plan_id)
        self._write_owner_decision(
            dest,
            "2026-01-03T00-00-00Z__owner-decision.json",
            plan_id=plan_id,
            decision="BLOCK",
            summary="third",
            created_at="2026-01-03T00:00:00+00:00",
        )
        self._write_owner_decision(
            dest,
            "2026-01-01T00-00-00Z__owner-decision.json",
            plan_id=plan_id,
            decision="REQUEST_REVISION",
            summary="first",
            created_at="2026-01-01T00:00:00+00:00",
        )
        self._write_owner_decision(
            dest,
            "2026-01-02T00-00-00Z__owner-decision.json",
            plan_id=plan_id,
            decision="CLOSE",
            summary="second",
            created_at="2026-01-02T00:00:00+00:00",
        )

        report = list_planning_owner_decisions(self.project, plan_id)
        self.assertEqual(report.count, 3)
        summaries = [r.summary for r in report.records]
        self.assertEqual(summaries, ["first", "second", "third"])

    def test_list_displays_latest_decision(self) -> None:
        plan_id = "list-latest"
        dest = init_planning_workspace(self.project, plan_id)
        self._write_owner_decision(
            dest,
            "2026-01-01T00-00-00Z__owner-decision.json",
            plan_id=plan_id,
            decision="BLOCK",
            summary="earlier",
            created_at="2026-01-01T00:00:00+00:00",
        )
        self._write_owner_decision(
            dest,
            "2026-01-02T00-00-00Z__owner-decision.json",
            plan_id=plan_id,
            decision="CLOSE",
            summary="latest one",
            created_at="2026-01-02T00:00:00+00:00",
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "decisions", "list", plan_id, str(self.project)])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        latest_section = output.split("latest decision:", 1)[1]
        self.assertIn("decision: CLOSE", latest_section)
        self.assertIn("summary: latest one", latest_section)

    def test_list_fails_for_malformed_decision_json(self) -> None:
        plan_id = "list-bad-json"
        dest = init_planning_workspace(self.project, plan_id)
        (dest / "decisions" / "broken.json").write_text("{not json", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["planning", "decisions", "list", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("invalid decision JSON", buf.getvalue())

    def test_list_fails_for_missing_required_field(self) -> None:
        plan_id = "list-missing-field"
        dest = init_planning_workspace(self.project, plan_id)
        (dest / "decisions" / "incomplete.json").write_text(
            json.dumps(
                {
                    "record_type": "PLANNING_OWNER_DECISION",
                    "plan_id": plan_id,
                    "decision": "BLOCK",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        with self.assertRaises(ValueError) as ctx:
            list_planning_owner_decisions(self.project, plan_id)
        self.assertIn("missing required field", str(ctx.exception))

    def test_list_fails_for_plan_id_mismatch(self) -> None:
        plan_id = "list-mismatch"
        dest = init_planning_workspace(self.project, plan_id)
        self._write_owner_decision(
            dest,
            "bad-plan.json",
            plan_id="other-plan",
            summary="wrong plan",
        )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["planning", "decisions", "list", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("decision plan_id mismatch", buf.getvalue())

    def test_list_skips_non_owner_decision_json(self) -> None:
        plan_id = "list-skip"
        dest = init_planning_workspace(self.project, plan_id)
        self._write_owner_decision(
            dest,
            "2026-01-01T00-00-00Z__owner-decision.json",
            plan_id=plan_id,
            summary="real decision",
        )
        (dest / "decisions" / "other.json").write_text(
            json.dumps({"record_type": "OTHER_RECORD", "note": "ignored"}) + "\n",
            encoding="utf-8",
        )

        report = list_planning_owner_decisions(self.project, plan_id)
        self.assertEqual(report.count, 1)
        self.assertEqual(len(report.skipped_files), 1)
        self.assertIn("OTHER_RECORD", report.skipped_files[0])
        self.assertIn("skipped files:", report.output)

    def test_list_fails_for_missing_workspace(self) -> None:
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                ["planning", "decisions", "list", "missing-plan", str(self.project)]
            )
        self.assertEqual(code, 1)
        self.assertIn("planning workspace not found", buf.getvalue())

    def test_list_fails_for_missing_manifest(self) -> None:
        plan_id = "list-no-manifest"
        dest = planning_path(self.project, plan_id)
        dest.mkdir(parents=True)
        (dest / "decisions").mkdir()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["planning", "decisions", "list", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("manifest.json missing", buf.getvalue())

    def test_list_fails_for_missing_decisions_directory(self) -> None:
        plan_id = "list-no-decisions-dir"
        dest = init_planning_workspace(self.project, plan_id)
        import shutil

        shutil.rmtree(dest / "decisions")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["planning", "decisions", "list", plan_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("decisions directory missing", buf.getvalue())

    def test_list_is_read_only(self) -> None:
        plan_id = "list-readonly"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "BLOCK",
            "blocked for now",
        )
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        snapshots_before = self._snapshot_agent_os_tree()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "decisions", "list", plan_id, str(self.project)])
        self.assertEqual(code, 0)

        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)
        self.assertEqual(snapshots_before, self._snapshot_agent_os_tree())

    def test_list_cli_output_includes_readonly_note(self) -> None:
        plan_id = "list-note"
        init_planning_workspace(self.project, plan_id)
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["planning", "decisions", "list", plan_id, str(self.project)])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("read-only", output)
        self.assertIn("no files modified", output)
        self.assertIn("no runs created", output)
        self.assertIn("no agents invoked", output)


class PlanningTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _snapshot_agent_os_tree(self) -> dict[str, str]:
        workspace = self.project / ".agent-os"
        snapshots: dict[str, str] = {}
        for path in workspace.rglob("*"):
            if path.is_file():
                rel = path.relative_to(workspace).as_posix()
                snapshots[rel] = path.read_text(encoding="utf-8")
        return snapshots

    def _write_owner_decision(
        self,
        dest: Path,
        filename: str,
        *,
        plan_id: str,
        decision: str,
        summary: str = "test summary",
        created_at: str = "2026-01-01T00:00:00+00:00",
        workspace_status: str = "DRAFT",
    ) -> None:
        _write_json(
            dest / "decisions" / filename,
            {
                "record_type": "PLANNING_OWNER_DECISION",
                "plan_id": plan_id,
                "decision": decision,
                "summary": summary,
                "created_at": created_at,
                "workspace_status_at_decision": workspace_status,
                "authority": {
                    "records_decision_only": True,
                    "does_not_execute": True,
                    "does_not_create_runs": True,
                    "does_not_mutate_manifest": True,
                    "does_not_approve_runner_execution": True,
                },
            },
        )

    def _set_manifest_status(self, dest: Path, status: str) -> None:
        manifest_path = dest / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["status"] = status
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    def _transition_cli(self, plan_id: str, to_status: str) -> tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(
                [
                    "planning",
                    "transition",
                    plan_id,
                    str(self.project),
                    "--to",
                    to_status,
                ]
            )
        return code, out_buf.getvalue(), err_buf.getvalue()

    def _prepare_approved_workspace(
        self,
        plan_id: str,
        *,
        status: str = "PLANNING_AUDIT_READY",
    ) -> Path:
        dest = _prepare_valid_planning_workspace(self.project, plan_id)
        self._set_manifest_status(dest, status)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "APPROVE_FOR_RUN_PROPOSALS",
            "approved for proposals",
        )
        return dest

    def test_approve_from_planning_audit_ready_succeeds(self) -> None:
        plan_id = "transition-approve-audit"
        dest = self._prepare_approved_workspace(plan_id, status="PLANNING_AUDIT_READY")
        manifest_before = (dest / "manifest.json").read_text(encoding="utf-8")

        code, output, _err = self._transition_cli(plan_id, "APPROVED_FOR_RUN_PROPOSALS")
        self.assertEqual(code, 0)
        self.assertIn("transition applied", output)
        self.assertIn(f"plan_id: {plan_id}", output)
        self.assertIn("from status: PLANNING_AUDIT_READY", output)
        self.assertIn("to status: APPROVED_FOR_RUN_PROPOSALS", output)
        self.assertIn("latest decision used: APPROVE_FOR_RUN_PROPOSALS", output)
        self.assertIn("manifest updated explicitly", output)
        self.assertIn("no runs were created", output)
        self.assertIn("no agents were invoked", output)

        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertNotEqual(manifest_before, json.dumps(manifest, indent=2) + "\n")
        self.assertEqual(manifest["status"], "APPROVED_FOR_RUN_PROPOSALS")
        self.assertTrue(manifest["gates"]["run_proposal_allowed"])
        self.assertFalse(manifest["gates"]["planning_owner_decision_required"])
        self.assertFalse(manifest["gates"]["planning_audit_required"])
        self.assertFalse(manifest["gates"]["plan_revision_required"])
        self.assertEqual(manifest["last_transition"]["from_status"], "PLANNING_AUDIT_READY")
        self.assertEqual(manifest["last_transition"]["to_status"], "APPROVED_FOR_RUN_PROPOSALS")

        evidence_files = list((dest / "evidence").glob("*__manifest-transition.json"))
        self.assertEqual(len(evidence_files), 1)
        record = json.loads(evidence_files[0].read_text(encoding="utf-8"))
        self.assertEqual(record["record_type"], "PLANNING_MANIFEST_TRANSITION")
        self.assertEqual(record["validation_result"], "OK")
        self.assertTrue(record["validation_required"])
        self.assertTrue(record["authority"]["does_not_create_runs"])

    def test_approve_from_plan_ready_succeeds(self) -> None:
        plan_id = "transition-approve-plan"
        dest = self._prepare_approved_workspace(plan_id, status="PLAN_READY")

        code, output, _err = self._transition_cli(plan_id, "APPROVED_FOR_RUN_PROPOSALS")
        self.assertEqual(code, 0)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "APPROVED_FOR_RUN_PROPOSALS")
        self.assertIn("from status: PLAN_READY", output)

    def test_request_revision_to_blocked_when_validation_fails(self) -> None:
        plan_id = "transition-revision-blocked"
        dest = init_planning_workspace(self.project, plan_id)
        self.assertFalse(validate_planning_workspace(self.project, plan_id).valid)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "REQUEST_REVISION",
            "needs revision",
        )

        code, _output, _err = self._transition_cli(plan_id, "BLOCKED")
        self.assertEqual(code, 0)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "BLOCKED")
        self.assertTrue(manifest["gates"]["plan_revision_required"])
        self.assertFalse(manifest["gates"]["run_proposal_allowed"])

    def test_block_to_blocked_when_validation_fails(self) -> None:
        plan_id = "transition-block-blocked"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "BLOCK",
            "blocked pending fix",
        )

        code, _output, _err = self._transition_cli(plan_id, "BLOCKED")
        self.assertEqual(code, 0)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "BLOCKED")

    def test_close_to_closed_succeeds(self) -> None:
        plan_id = "transition-close"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "CLOSE",
            "planning complete",
        )

        code, output, _err = self._transition_cli(plan_id, "CLOSED")
        self.assertEqual(code, 0)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "CLOSED")
        self.assertFalse(manifest["gates"]["run_proposal_allowed"])
        self.assertIn("to status: CLOSED", output)

    def test_approve_from_draft_fails(self) -> None:
        plan_id = "transition-approve-draft"
        dest = _prepare_valid_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "APPROVE_FOR_RUN_PROPOSALS",
            "approved",
        )

        code, _output, err = self._transition_cli(plan_id, "APPROVED_FOR_RUN_PROPOSALS")
        self.assertEqual(code, 1)
        self.assertIn("does not authorize transition from 'DRAFT'", err)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "DRAFT")

    def test_approve_fails_when_validation_no_longer_ok(self) -> None:
        plan_id = "transition-approve-stale-validation"
        dest = self._prepare_approved_workspace(plan_id, status="PLANNING_AUDIT_READY")
        path = dest / "planning-audit.md"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n{{STALE_PLACEHOLDER}}\n",
            encoding="utf-8",
        )

        code, _output, err = self._transition_cli(plan_id, "APPROVED_FOR_RUN_PROPOSALS")
        self.assertEqual(code, 1)
        self.assertIn("planning validation is not OK", err)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "PLANNING_AUDIT_READY")

    def test_request_revision_to_approved_fails(self) -> None:
        plan_id = "transition-revision-not-approve"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "REQUEST_REVISION",
            "fix scope",
        )

        code, _output, err = self._transition_cli(plan_id, "APPROVED_FOR_RUN_PROPOSALS")
        self.assertEqual(code, 1)
        self.assertIn("REQUEST_REVISION does not authorize", err)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "DRAFT")

    def test_block_to_closed_fails(self) -> None:
        plan_id = "transition-block-not-close"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "BLOCK",
            "blocked",
        )

        code, _output, err = self._transition_cli(plan_id, "CLOSED")
        self.assertEqual(code, 1)
        self.assertIn("BLOCK does not authorize transition to 'CLOSED'", err)

    def test_close_to_blocked_fails(self) -> None:
        plan_id = "transition-close-not-block"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "CLOSE",
            "close it",
        )

        code, _output, err = self._transition_cli(plan_id, "BLOCKED")
        self.assertEqual(code, 1)
        self.assertIn("CLOSE does not authorize transition to 'BLOCKED'", err)

    def test_unsupported_target_status_fails(self) -> None:
        plan_id = "transition-unsupported-target"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "CLOSE",
            "close it",
        )

        code, _output, err = self._transition_cli(plan_id, "DRAFT")
        self.assertEqual(code, 1)
        self.assertIn("unsupported transition target", err)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "DRAFT")

    def test_superseded_target_fails_with_future_workflow_message(self) -> None:
        plan_id = "transition-superseded"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "CLOSE",
            "close it",
        )

        code, _output, err = self._transition_cli(plan_id, "SUPERSEDED")
        self.assertEqual(code, 1)
        self.assertIn("supersession workflow", err)
        self.assertIn("superseding plan_id", err)

    def test_terminal_workspace_fails(self) -> None:
        plan_id = "transition-terminal"
        dest = init_planning_workspace(self.project, plan_id)
        self._set_manifest_status(dest, "CLOSED")
        record_planning_owner_decision(
            self.project,
            plan_id,
            "CLOSE",
            "already closed",
        )

        code, _output, err = self._transition_cli(plan_id, "CLOSED")
        self.assertEqual(code, 1)
        self.assertIn("terminal workspace cannot transition", err)

    def test_no_owner_decision_fails(self) -> None:
        plan_id = "transition-no-decision"
        init_planning_workspace(self.project, plan_id)

        code, _output, err = self._transition_cli(plan_id, "BLOCKED")
        self.assertEqual(code, 1)
        self.assertIn("no owner decision exists", err)

    def test_missing_evidence_directory_fails(self) -> None:
        plan_id = "transition-no-evidence-dir"
        dest = init_planning_workspace(self.project, plan_id)
        import shutil

        shutil.rmtree(dest / "evidence")
        record_planning_owner_decision(
            self.project,
            plan_id,
            "BLOCK",
            "blocked",
        )

        code, _output, err = self._transition_cli(plan_id, "BLOCKED")
        self.assertEqual(code, 1)
        self.assertIn("evidence directory missing", err)

    def test_missing_decisions_directory_fails(self) -> None:
        plan_id = "transition-no-decisions-dir"
        dest = init_planning_workspace(self.project, plan_id)
        import shutil

        shutil.rmtree(dest / "decisions")

        code, _output, err = self._transition_cli(plan_id, "BLOCKED")
        self.assertEqual(code, 1)
        self.assertIn("decisions directory missing", err)

    def test_malformed_decision_json_fails(self) -> None:
        plan_id = "transition-bad-decision"
        dest = init_planning_workspace(self.project, plan_id)
        (dest / "decisions" / "broken.json").write_text("{not json", encoding="utf-8")

        code, _output, err = self._transition_cli(plan_id, "BLOCKED")
        self.assertEqual(code, 1)
        self.assertIn("invalid decision JSON", err)

    def test_decision_plan_id_mismatch_fails(self) -> None:
        plan_id = "transition-decision-mismatch"
        dest = init_planning_workspace(self.project, plan_id)
        self._write_owner_decision(
            dest,
            "2026-01-01T00-00-00Z__owner-decision.json",
            plan_id="other-plan",
            decision="BLOCK",
        )

        code, _output, err = self._transition_cli(plan_id, "BLOCKED")
        self.assertEqual(code, 1)
        self.assertIn("decision plan_id mismatch", err)

    def test_manifest_missing_gates_fails(self) -> None:
        plan_id = "transition-no-gates"
        dest = init_planning_workspace(self.project, plan_id)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        del manifest["gates"]
        (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        record_planning_owner_decision(
            self.project,
            plan_id,
            "BLOCK",
            "blocked",
        )

        code, _output, err = self._transition_cli(plan_id, "BLOCKED")
        self.assertEqual(code, 1)
        self.assertIn("manifest lacks gates object", err)

    def test_evidence_filename_collision_fails(self) -> None:
        from unittest.mock import patch

        plan_id = "transition-evidence-collision"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "BLOCK",
            "blocked",
        )
        fixed_ts = "2026-07-05T20-15-30Z"
        collision = dest / "evidence" / f"{fixed_ts}__manifest-transition.json"
        collision.write_text("{}", encoding="utf-8")
        manifest_before = (dest / "manifest.json").read_text(encoding="utf-8")

        with patch("agent_os.planning._transition_filename_timestamp", return_value=fixed_ts):
            code, _output, err = self._transition_cli(plan_id, "BLOCKED")
        self.assertEqual(code, 1)
        self.assertIn("transition evidence file already exists", err)
        self.assertEqual(manifest_before, (dest / "manifest.json").read_text(encoding="utf-8"))

    def test_success_writes_only_manifest_and_one_evidence_record(self) -> None:
        plan_id = "transition-write-boundary"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "CLOSE",
            "done",
        )
        snapshots_before = self._snapshot_agent_os_tree()

        code, _output, _err = self._transition_cli(plan_id, "CLOSED")
        self.assertEqual(code, 0)

        snapshots_after = self._snapshot_agent_os_tree()
        changed = {
            rel
            for rel in set(snapshots_before) | set(snapshots_after)
            if snapshots_before.get(rel) != snapshots_after.get(rel)
        }
        self.assertEqual(len(changed), 2)
        changed_list = sorted(changed)
        self.assertTrue(changed_list[0].startswith(f"planning/{plan_id}/evidence/"))
        self.assertTrue(changed_list[0].endswith("__manifest-transition.json"))
        self.assertEqual(changed_list[1], f"planning/{plan_id}/manifest.json")

    def test_success_does_not_mutate_decision_files(self) -> None:
        plan_id = "transition-preserve-decisions"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "CLOSE",
            "done",
        )
        decision_snapshots = {
            path.name: path.read_text(encoding="utf-8")
            for path in (dest / "decisions").glob("*")
        }

        code, _output, _err = self._transition_cli(plan_id, "CLOSED")
        self.assertEqual(code, 0)

        for name, content in decision_snapshots.items():
            self.assertEqual((dest / "decisions" / name).read_text(encoding="utf-8"), content)

    def test_common_failure_does_not_mutate_manifest_or_create_evidence(self) -> None:
        plan_id = "transition-failure-no-write"
        dest = init_planning_workspace(self.project, plan_id)
        record_planning_owner_decision(
            self.project,
            plan_id,
            "BLOCK",
            "blocked",
        )
        manifest_before = (dest / "manifest.json").read_text(encoding="utf-8")
        evidence_before = list((dest / "evidence").iterdir())

        code, _output, _err = self._transition_cli(plan_id, "CLOSED")
        self.assertEqual(code, 1)
        self.assertEqual(manifest_before, (dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence_before, list((dest / "evidence").iterdir()))

    def test_success_does_not_create_runs(self) -> None:
        plan_id = "transition-no-runs"
        init_planning_workspace(self.project, plan_id)
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        record_planning_owner_decision(
            self.project,
            plan_id,
            "CLOSE",
            "done",
        )

        code, _output, _err = self._transition_cli(plan_id, "CLOSED")
        self.assertEqual(code, 0)
        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_api_matches_cli_for_success(self) -> None:
        plan_id = "transition-api"
        self._prepare_approved_workspace(plan_id, status="PLANNING_AUDIT_READY")
        result = transition_planning_workspace(
            self.project,
            plan_id,
            "APPROVED_FOR_RUN_PROPOSALS",
        )
        self.assertEqual(result.to_status, "APPROVED_FOR_RUN_PROPOSALS")
        self.assertIn("transition applied", result.output)


class PlanningProgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)
        self._progress_ts_counter = 0

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _next_progress_timestamp(self) -> str:
        self._progress_ts_counter += 1
        return f"2026-07-05T20-15-{self._progress_ts_counter:02d}Z"

    def _snapshot_agent_os_tree(self) -> dict[str, str]:
        workspace = self.project / ".agent-os"
        snapshots: dict[str, str] = {}
        for path in workspace.rglob("*"):
            if path.is_file():
                rel = path.relative_to(workspace).as_posix()
                snapshots[rel] = path.read_text(encoding="utf-8")
        return snapshots

    def _set_manifest_status(self, dest: Path, status: str) -> None:
        manifest_path = dest / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["status"] = status
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    def _fill_implementation_plan(self, dest: Path) -> None:
        impl = dest / "implementation-plan.md"
        text = impl.read_text(encoding="utf-8")
        text = text.replace("{{RUN_LABEL_1}}", "slice-01")
        text = text.replace("{{RUN_LABEL_2}}", "slice-02")
        impl.write_text(text, encoding="utf-8")

    def _progress_cli(
        self,
        plan_id: str,
        to_status: str,
        *,
        fixed_timestamp: str | None = None,
    ) -> tuple[int, str, str]:
        from unittest.mock import patch

        timestamp = fixed_timestamp or self._next_progress_timestamp()
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with patch(
            "agent_os.planning._progress_filename_timestamp",
            return_value=timestamp,
        ):
            with redirect_stdout(out_buf), redirect_stderr(err_buf):
                code = main(
                    [
                        "planning",
                        "progress",
                        plan_id,
                        str(self.project),
                        "--to",
                        to_status,
                    ]
                )
        return code, out_buf.getvalue(), err_buf.getvalue()

    def _progress_to_plan_ready(self, plan_id: str) -> Path:
        dest = init_planning_workspace(self.project, plan_id)
        code, _output, err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 0, msg=err)
        code, _output, err = self._progress_cli(plan_id, "SPEC_READY")
        self.assertEqual(code, 0, msg=err)
        self._fill_implementation_plan(dest)
        code, _output, err = self._progress_cli(plan_id, "PLAN_READY")
        self.assertEqual(code, 0, msg=err)
        return dest

    def test_draft_to_context_ready_succeeds(self) -> None:
        plan_id = "progress-context"
        dest = init_planning_workspace(self.project, plan_id)

        code, output, _err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 0)
        self.assertIn("artifact progress applied", output)
        self.assertIn(f"plan_id: {plan_id}", output)
        self.assertIn("from status: DRAFT", output)
        self.assertIn("to status: CONTEXT_READY", output)
        self.assertIn("manifest updated explicitly", output)
        self.assertIn("no owner decision was recorded", output)
        self.assertIn("no run proposals were approved", output)
        self.assertIn("no runs were created", output)
        self.assertIn("no agents were invoked", output)

        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "CONTEXT_READY")
        self.assertTrue(manifest["gates"]["planning_audit_required"])
        self.assertTrue(manifest["gates"]["planning_owner_decision_required"])
        self.assertFalse(manifest["gates"]["run_proposal_allowed"])

        evidence_files = list((dest / "evidence").glob("*__artifact-progress.json"))
        self.assertEqual(len(evidence_files), 1)
        record = json.loads(evidence_files[0].read_text(encoding="utf-8"))
        self.assertEqual(record["record_type"], "PLANNING_ARTIFACT_PROGRESS")
        self.assertTrue(record["authority"]["artifact_progress_only"])

    def test_context_ready_to_spec_ready_succeeds(self) -> None:
        plan_id = "progress-spec"
        dest = init_planning_workspace(self.project, plan_id)
        self._progress_cli(plan_id, "CONTEXT_READY")

        code, output, _err = self._progress_cli(plan_id, "SPEC_READY")
        self.assertEqual(code, 0)
        self.assertIn("from status: CONTEXT_READY", output)
        self.assertIn("to status: SPEC_READY", output)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "SPEC_READY")

    def test_spec_ready_to_plan_ready_succeeds(self) -> None:
        plan_id = "progress-plan"
        dest = init_planning_workspace(self.project, plan_id)
        self._progress_cli(plan_id, "CONTEXT_READY")
        self._progress_cli(plan_id, "SPEC_READY")
        self._fill_implementation_plan(dest)

        code, output, _err = self._progress_cli(plan_id, "PLAN_READY")
        self.assertEqual(code, 0)
        self.assertIn("from status: SPEC_READY", output)
        self.assertIn("to status: PLAN_READY", output)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "PLAN_READY")

    def test_plan_ready_to_planning_audit_ready_succeeds(self) -> None:
        plan_id = "progress-audit-ready"
        dest = self._progress_to_plan_ready(plan_id)

        code, output, _err = self._progress_cli(plan_id, "PLANNING_AUDIT_READY")
        self.assertEqual(code, 0)
        self.assertIn("from status: PLAN_READY", output)
        self.assertIn("to status: PLANNING_AUDIT_READY", output)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "PLANNING_AUDIT_READY")
        self.assertFalse(manifest["gates"]["planning_audit_required"])
        self.assertTrue(manifest["gates"]["planning_owner_decision_required"])
        self.assertFalse(manifest["gates"]["run_proposal_allowed"])

        evidence_files = sorted((dest / "evidence").glob("*__artifact-progress.json"))
        record = json.loads(evidence_files[-1].read_text(encoding="utf-8"))
        self.assertTrue(record["validation_required"])
        self.assertEqual(record["validation_result"], "OK")

    def test_skip_draft_to_spec_ready_fails(self) -> None:
        plan_id = "progress-skip"
        dest = init_planning_workspace(self.project, plan_id)

        code, _output, err = self._progress_cli(plan_id, "SPEC_READY")
        self.assertEqual(code, 1)
        self.assertIn("progress transition not sequential", err)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "DRAFT")

    def test_backwards_spec_ready_to_context_ready_fails(self) -> None:
        plan_id = "progress-backwards"
        dest = init_planning_workspace(self.project, plan_id)
        self._progress_cli(plan_id, "CONTEXT_READY")
        self._progress_cli(plan_id, "SPEC_READY")

        code, _output, err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 1)
        self.assertIn("progress transition not sequential", err)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "SPEC_READY")

    def test_same_status_transition_fails(self) -> None:
        plan_id = "progress-same"
        dest = init_planning_workspace(self.project, plan_id)
        self._progress_cli(plan_id, "CONTEXT_READY")

        code, _output, err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 1)
        self.assertIn("progress transition not sequential", err)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "CONTEXT_READY")

    def test_unsupported_target_approved_for_run_proposals_fails(self) -> None:
        plan_id = "progress-target-approve"
        dest = init_planning_workspace(self.project, plan_id)

        code, _output, err = self._progress_cli(plan_id, "APPROVED_FOR_RUN_PROPOSALS")
        self.assertEqual(code, 1)
        self.assertIn("unsupported progress target", err)
        self.assertEqual(
            json.loads((dest / "manifest.json").read_text(encoding="utf-8"))["status"],
            "DRAFT",
        )

    def test_unsupported_target_blocked_fails(self) -> None:
        plan_id = "progress-target-blocked"
        init_planning_workspace(self.project, plan_id)

        code, _output, err = self._progress_cli(plan_id, "BLOCKED")
        self.assertEqual(code, 1)
        self.assertIn("unsupported progress target", err)

    def test_unsupported_target_closed_fails(self) -> None:
        plan_id = "progress-target-closed"
        init_planning_workspace(self.project, plan_id)

        code, _output, err = self._progress_cli(plan_id, "CLOSED")
        self.assertEqual(code, 1)
        self.assertIn("unsupported progress target", err)

    def test_unsupported_target_superseded_fails(self) -> None:
        plan_id = "progress-target-superseded"
        init_planning_workspace(self.project, plan_id)

        code, _output, err = self._progress_cli(plan_id, "SUPERSEDED")
        self.assertEqual(code, 1)
        self.assertIn("unsupported progress target", err)

    def test_terminal_workspace_fails(self) -> None:
        plan_id = "progress-terminal"
        dest = init_planning_workspace(self.project, plan_id)
        self._set_manifest_status(dest, "CLOSED")

        code, _output, err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 1)
        self.assertIn("terminal workspace cannot progress", err)

    def test_blocked_workspace_fails(self) -> None:
        plan_id = "progress-blocked-ws"
        dest = init_planning_workspace(self.project, plan_id)
        self._set_manifest_status(dest, "BLOCKED")

        code, _output, err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED workspace cannot receive artifact progress", err)

    def test_approved_workspace_fails(self) -> None:
        plan_id = "progress-approved-ws"
        dest = init_planning_workspace(self.project, plan_id)
        self._set_manifest_status(dest, "APPROVED_FOR_RUN_PROPOSALS")

        code, _output, err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 1)
        self.assertIn("APPROVED_FOR_RUN_PROPOSALS workspace cannot receive", err)

    def test_context_ready_fails_if_context_pack_has_placeholder(self) -> None:
        plan_id = "progress-context-placeholder"
        dest = init_planning_workspace(self.project, plan_id)
        path = dest / "context-pack.md"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n{{CUSTOM_PLACEHOLDER}}\n",
            encoding="utf-8",
        )
        manifest_before = (dest / "manifest.json").read_text(encoding="utf-8")

        code, _output, err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 1)
        self.assertIn("artifact readiness check failed", err)
        self.assertIn("placeholder still present", err)
        self.assertEqual(manifest_before, (dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(list((dest / "evidence").iterdir()), [])

    def test_spec_ready_fails_if_local_spec_missing_section(self) -> None:
        plan_id = "progress-spec-section"
        dest = init_planning_workspace(self.project, plan_id)
        self._progress_cli(plan_id, "CONTEXT_READY")
        path = dest / "local-agentic-spec.md"
        path.write_text(
            path.read_text(encoding="utf-8").replace("## Non-goals", "## Removed"),
            encoding="utf-8",
        )

        code, _output, err = self._progress_cli(plan_id, "SPEC_READY")
        self.assertEqual(code, 1)
        self.assertIn("artifact readiness check failed", err)
        self.assertIn("Non-goals", err)

    def test_plan_ready_fails_if_implementation_plan_missing_allowed_paths(self) -> None:
        plan_id = "progress-plan-paths"
        dest = init_planning_workspace(self.project, plan_id)
        self._progress_cli(plan_id, "CONTEXT_READY")
        self._progress_cli(plan_id, "SPEC_READY")
        path = dest / "implementation-plan.md"
        path.write_text(
            path.read_text(encoding="utf-8").replace("allowed_paths", "removed_paths"),
            encoding="utf-8",
        )

        code, _output, err = self._progress_cli(plan_id, "PLAN_READY")
        self.assertEqual(code, 1)
        self.assertIn("artifact readiness check failed", err)
        self.assertIn("allowed_paths", err)

    def test_planning_audit_ready_fails_if_full_validation_not_ok(self) -> None:
        plan_id = "progress-audit-invalid"
        dest = self._progress_to_plan_ready(plan_id)
        path = dest / "planning-audit.md"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n{{STALE_PLACEHOLDER}}\n",
            encoding="utf-8",
        )

        code, _output, err = self._progress_cli(plan_id, "PLANNING_AUDIT_READY")
        self.assertEqual(code, 1)
        self.assertIn("planning validation is not OK", err)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "PLAN_READY")

    def test_missing_evidence_directory_fails(self) -> None:
        plan_id = "progress-no-evidence-dir"
        dest = init_planning_workspace(self.project, plan_id)
        import shutil

        shutil.rmtree(dest / "evidence")

        code, _output, err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 1)
        self.assertIn("evidence directory missing", err)

    def test_manifest_missing_gates_fails(self) -> None:
        plan_id = "progress-no-gates"
        dest = init_planning_workspace(self.project, plan_id)
        manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        del manifest["gates"]
        (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        code, _output, err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 1)
        self.assertIn("manifest lacks gates object", err)

    def test_evidence_filename_collision_fails(self) -> None:
        plan_id = "progress-evidence-collision"
        dest = init_planning_workspace(self.project, plan_id)
        fixed_ts = "2026-07-05T20-15-30Z"
        collision = dest / "evidence" / f"{fixed_ts}__artifact-progress.json"
        collision.write_text("{}", encoding="utf-8")
        manifest_before = (dest / "manifest.json").read_text(encoding="utf-8")

        code, _output, err = self._progress_cli(
            plan_id,
            "CONTEXT_READY",
            fixed_timestamp=fixed_ts,
        )
        self.assertEqual(code, 1)
        self.assertIn("progress evidence file already exists", err)
        self.assertEqual(manifest_before, (dest / "manifest.json").read_text(encoding="utf-8"))

    def test_success_writes_only_manifest_and_one_evidence_record(self) -> None:
        plan_id = "progress-write-boundary"
        init_planning_workspace(self.project, plan_id)
        snapshots_before = self._snapshot_agent_os_tree()

        code, _output, _err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 0)

        snapshots_after = self._snapshot_agent_os_tree()
        changed = {
            rel
            for rel in set(snapshots_before) | set(snapshots_after)
            if snapshots_before.get(rel) != snapshots_after.get(rel)
        }
        self.assertEqual(len(changed), 2)
        changed_list = sorted(changed)
        self.assertTrue(changed_list[0].startswith(f"planning/{plan_id}/evidence/"))
        self.assertTrue(changed_list[0].endswith("__artifact-progress.json"))
        self.assertEqual(changed_list[1], f"planning/{plan_id}/manifest.json")

    def test_success_does_not_mutate_decisions_or_artifacts(self) -> None:
        plan_id = "progress-preserve-artifacts"
        dest = init_planning_workspace(self.project, plan_id)
        artifact_snapshots = {
            name: (dest / name).read_text(encoding="utf-8")
            for name in (
                "context-pack.md",
                "local-agentic-spec.md",
                "implementation-plan.md",
                "planning-audit.md",
                "README.md",
            )
        }

        code, _output, _err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 0)

        for name, content in artifact_snapshots.items():
            self.assertEqual((dest / name).read_text(encoding="utf-8"), content)
        self.assertFalse(list((dest / "decisions").glob("*.json")))

    def test_common_failure_does_not_mutate_manifest_or_create_evidence(self) -> None:
        plan_id = "progress-failure-no-write"
        dest = init_planning_workspace(self.project, plan_id)
        path = dest / "context-pack.md"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n{{FAIL_PLACEHOLDER}}\n",
            encoding="utf-8",
        )
        manifest_before = (dest / "manifest.json").read_text(encoding="utf-8")
        evidence_before = list((dest / "evidence").iterdir())

        code, _output, _err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 1)
        self.assertEqual(manifest_before, (dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence_before, list((dest / "evidence").iterdir()))

    def test_success_does_not_create_runs(self) -> None:
        plan_id = "progress-no-runs"
        init_planning_workspace(self.project, plan_id)
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())

        code, _output, _err = self._progress_cli(plan_id, "CONTEXT_READY")
        self.assertEqual(code, 0)
        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_api_matches_cli_for_success(self) -> None:
        plan_id = "progress-api"
        init_planning_workspace(self.project, plan_id)
        result = progress_planning_workspace(self.project, plan_id, "CONTEXT_READY")
        self.assertEqual(result.to_status, "CONTEXT_READY")
        self.assertIn("artifact progress applied", result.output)


class PlanningLifecycleIntegrationTests(unittest.TestCase):
    plan_id = "slither-demo"
    approve_summary = (
        "Planning artifacts reviewed and approved for run proposals only."
    )
    progress_chain = (
        "CONTEXT_READY",
        "SPEC_READY",
        "PLAN_READY",
        "PLANNING_AUDIT_READY",
    )

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)
        self._progress_ts_counter = 0

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _next_progress_timestamp(self) -> str:
        self._progress_ts_counter += 1
        return f"2026-07-05T20-30-{self._progress_ts_counter:02d}Z"

    def _artifact_filenames(self) -> tuple[str, ...]:
        return (
            "context-pack.md",
            "local-agentic-spec.md",
            "implementation-plan.md",
            "planning-audit.md",
        )

    def _snapshot_artifacts(self, dest: Path) -> dict[str, str]:
        return {
            name: (dest / name).read_text(encoding="utf-8")
            for name in self._artifact_filenames()
        }

    def _progress_cli(self, to_status: str) -> tuple[int, str]:
        from unittest.mock import patch

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with patch(
            "agent_os.planning._progress_filename_timestamp",
            return_value=self._next_progress_timestamp(),
        ):
            with redirect_stdout(out_buf), redirect_stderr(err_buf):
                code = main(
                    [
                        "planning",
                        "progress",
                        self.plan_id,
                        str(self.project),
                        "--to",
                        to_status,
                    ]
                )
        if code != 0:
            self.fail(err_buf.getvalue() or out_buf.getvalue())
        return code, out_buf.getvalue()

    def test_full_planning_lifecycle_reaches_approved_for_run_proposals(self) -> None:
        plan_id = self.plan_id
        workspace = self.project / ".agent-os"

        init_planning_workspace(self.project, plan_id)
        dest = planning_path(self.project, plan_id)

        fresh_report = validate_planning_workspace(self.project, plan_id)
        self.assertFalse(fresh_report.valid)
        self.assertIn("artifact validation: INVALID", fresh_report.output)

        _fill_planning_lifecycle_artifacts(dest, plan_id)
        artifact_snapshots = self._snapshot_artifacts(dest)

        filled_report = validate_planning_workspace(self.project, plan_id)
        self.assertTrue(filled_report.valid)
        self.assertIn("status: DRAFT", filled_report.output)

        progress_evidence_count = 0
        for to_status in self.progress_chain:
            code, output = self._progress_cli(to_status)
            self.assertEqual(code, 0)
            self.assertIn("artifact progress applied", output)
            self.assertIn(f"to status: {to_status}", output)
            self.assertIn("no owner decision was recorded", output)
            self.assertIn("no runs were created", output)
            self.assertIn("no agents were invoked", output)

            manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], to_status)
            progress_evidence_count += 1
            progress_files = list(dest.glob("evidence/*__artifact-progress.json"))
            self.assertEqual(len(progress_files), progress_evidence_count)
            record = json.loads(progress_files[-1].read_text(encoding="utf-8"))
            self.assertEqual(record["record_type"], "PLANNING_ARTIFACT_PROGRESS")
            self.assertFalse(list((dest / "decisions").glob("*.json")))

        progress_report = validate_planning_workspace(self.project, plan_id)
        self.assertTrue(progress_report.valid)
        self.assertIn("status: PLANNING_AUDIT_READY", progress_report.output)

        decide_buf = io.StringIO()
        with redirect_stdout(decide_buf):
            decide_code = main(
                [
                    "planning",
                    "decide",
                    plan_id,
                    str(self.project),
                    "--decision",
                    "APPROVE_FOR_RUN_PROPOSALS",
                    "--summary",
                    self.approve_summary,
                ]
            )
        self.assertEqual(decide_code, 0)
        decide_output = decide_buf.getvalue()
        self.assertIn("decision recorded", decide_output)
        self.assertIn("manifest status was not changed", decide_output)

        decision_files = sorted(dest.glob("decisions/*__owner-decision.json"))
        self.assertEqual(len(decision_files), 1)
        decision_record = json.loads(decision_files[0].read_text(encoding="utf-8"))
        self.assertEqual(decision_record["decision"], "APPROVE_FOR_RUN_PROPOSALS")
        manifest_after_decide = json.loads(
            (dest / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest_after_decide["status"], "PLANNING_AUDIT_READY")
        self.assertEqual(list((workspace / "runs").iterdir()), [])

        list_report = list_planning_owner_decisions(self.project, plan_id)
        self.assertEqual(list_report.count, 1)
        self.assertEqual(len(list_report.records), 1)
        self.assertEqual(
            list_report.records[-1].decision,
            "APPROVE_FOR_RUN_PROPOSALS",
        )
        self.assertIn("APPROVE_FOR_RUN_PROPOSALS", list_report.output)

        decision_snapshots = {
            path.name: path.read_text(encoding="utf-8") for path in decision_files
        }
        transition_buf = io.StringIO()
        with redirect_stdout(transition_buf):
            transition_code = main(
                [
                    "planning",
                    "transition",
                    plan_id,
                    str(self.project),
                    "--to",
                    "APPROVED_FOR_RUN_PROPOSALS",
                ]
            )
        self.assertEqual(transition_code, 0)
        transition_output = transition_buf.getvalue()
        self.assertIn("transition applied", transition_output)
        self.assertIn("to status: APPROVED_FOR_RUN_PROPOSALS", transition_output)
        self.assertIn("no runs were created", transition_output)

        manifest_final = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest_final["status"], "APPROVED_FOR_RUN_PROPOSALS")
        gates = manifest_final["gates"]
        self.assertTrue(gates["run_proposal_allowed"])
        self.assertFalse(gates["planning_owner_decision_required"])
        self.assertFalse(gates["planning_audit_required"])
        self.assertFalse(gates["plan_revision_required"])

        transition_files = list(dest.glob("evidence/*__manifest-transition.json"))
        self.assertEqual(len(transition_files), 1)
        transition_record = json.loads(
            transition_files[0].read_text(encoding="utf-8")
        )
        self.assertEqual(transition_record["record_type"], "PLANNING_MANIFEST_TRANSITION")
        self.assertEqual(list((workspace / "runs").iterdir()), [])

        status_report = status_planning_workspace(self.project, plan_id)
        self.assertTrue(status_report.structural_ok)
        self.assertIn("status: APPROVED_FOR_RUN_PROPOSALS", status_report.output)
        self.assertIn("run_proposal_allowed: true", status_report.output)

        final_report = validate_planning_workspace(self.project, plan_id)
        self.assertTrue(final_report.valid)
        self.assertIn("final validation result: OK", final_report.output)

        for name, content in artifact_snapshots.items():
            self.assertEqual((dest / name).read_text(encoding="utf-8"), content)
        for name, content in decision_snapshots.items():
            self.assertEqual((dest / "decisions" / name).read_text(encoding="utf-8"), content)

        authority = manifest_final["authority"]
        self.assertTrue(authority["no_agent_invocation"])
        self.assertTrue(authority["no_run_creation"])
        self.assertTrue(authority["no_execution"])


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


class PlanningDocsHygieneTests(unittest.TestCase):
    """Regression guard for obsolete normal-flow manual manifest/status guidance."""

    _FORBIDDEN_NORMAL_FLOW_PHRASES: tuple[str, ...] = (
        "edit manifest.status",
        "manifest.status manually",
        "manually edit manifest",
        "update manifest manually",
        "update manifest.json manually",
        "advance gates manually",
        "gate advancement remain manual",
        "manual status edit",
        "current manual operator step",
        "artifact-progress transitions remain manual",
    )

    _RECOVERY_LINE_MARKERS: tuple[str, ...] = (
        "emergency",
        "outside the normal flow",
        "outside normal flow",
        "not the normal path",
        "not the normal flow",
        "emergency/recovery",
        "emergency recovery",
    )

    @classmethod
    def _iter_scan_texts(cls, repo_root: Path) -> list[tuple[str, str]]:
        items: list[tuple[str, str]] = []

        readme = repo_root / "README.md"
        if readme.is_file():
            items.append(("README.md", readme.read_text(encoding="utf-8")))

        for directory in ("docs", "agent_os/templates", "examples"):
            root = repo_root / directory
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("*")):
                if not path.is_file():
                    continue
                rel = path.relative_to(repo_root).as_posix()
                items.append((rel, path.read_text(encoding="utf-8")))

        items.append(
            (
                "agent_os/planning.py::_WORKSPACE_README",
                planning_module._WORKSPACE_README,
            )
        )
        return items

    def _line_is_allowed_exception(self, line: str) -> bool:
        lowered = line.lower()
        if any(marker in lowered for marker in self._RECOVERY_LINE_MARKERS):
            return True
        return "do not " in lowered or "don't " in lowered

    def test_docs_do_not_instruct_obsolete_manual_manifest_normal_flow(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        violations: list[str] = []

        for label, text in self._iter_scan_texts(repo_root):
            for line_no, line in enumerate(text.splitlines(), start=1):
                if self._line_is_allowed_exception(line):
                    continue
                lowered_line = line.lower()
                for phrase in self._FORBIDDEN_NORMAL_FLOW_PHRASES:
                    if phrase in lowered_line:
                        violations.append(
                            f"{label}:{line_no}: forbidden phrase {phrase!r}"
                        )

        self.assertEqual(
            violations,
            [],
            "obsolete normal-flow manual manifest/status guidance found:\n"
            + "\n".join(violations),
        )


class OrchestratorGoalIntakeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _read_artifact(self, intake_id: str) -> dict:
        return json.loads(self._artifact_path(intake_id).read_text(encoding="utf-8"))

    def test_orchestrator_intake_creates_expected_goal_intake_artifact(self) -> None:
        intake_id = "slither-demo"
        raw_goal = "Build me an online slither.io-like game"

        dest = create_goal_intake(self.project, intake_id, raw_goal)

        self.assertEqual(dest, self._artifact_path(intake_id))
        self.assertTrue(dest.is_file())
        artifact = self._read_artifact(intake_id)
        self.assertEqual(artifact["artifact_type"], "GOAL_INTAKE")
        self.assertEqual(artifact["schema_version"], "0.1")
        self.assertEqual(artifact["intake_id"], intake_id)

    def test_goal_intake_artifact_contains_all_required_fields(self) -> None:
        artifact = build_goal_intake_artifact(
            "demo",
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        missing = [field for field in GOAL_INTAKE_REQUIRED_FIELDS if field not in artifact]
        self.assertEqual(missing, [])

    def test_raw_goal_preserves_exact_input(self) -> None:
        raw_goal = "  Build me\tan online\n\nslither.io-like game  "
        create_goal_intake(self.project, "exact-input", raw_goal)
        artifact = self._read_artifact("exact-input")
        self.assertEqual(artifact["raw_goal"], raw_goal)

    def test_normalized_goal_is_whitespace_normalized_only(self) -> None:
        raw_goal = "  Build me\tan online\n\nslither.io-like game  "
        self.assertEqual(
            normalize_goal(raw_goal),
            "Build me an online slither.io-like game",
        )
        artifact = build_goal_intake_artifact(
            "normalize-only",
            raw_goal,
            created_at="2026-07-06T10:00:00+00:00",
        )
        self.assertEqual(
            artifact["normalized_goal"],
            "Build me an online slither.io-like game",
        )
        self.assertEqual(
            artifact["user_visible_summary"],
            artifact["normalized_goal"],
        )

    def test_broad_slither_like_goal_requires_clarification(self) -> None:
        artifact = build_goal_intake_artifact(
            "slither-demo",
            "Build me an online slither.io-like game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        self.assertEqual(artifact["ambiguity_level"], "HIGH")
        self.assertEqual(artifact["planning_readiness"], "REQUIRES_CLARIFICATION")
        self.assertTrue(artifact["open_questions"])

    def test_goal_intake_includes_all_non_authority_flags(self) -> None:
        artifact = build_goal_intake_artifact(
            "demo",
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        self.assertEqual(
            set(artifact["non_authority"]),
            set(GOAL_INTAKE_NON_AUTHORITY_FLAGS),
        )
        self.assertTrue(all(artifact["non_authority"].values()))

    def test_orchestrator_intake_rejects_empty_goals(self) -> None:
        with self.assertRaises(ValueError):
            build_goal_intake_artifact("demo", "   ")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["orchestrator", "intake", "demo", str(self.project), "--goal", ""])
        self.assertEqual(code, 1)
        self.assertIn("goal must not be empty", buf.getvalue())

    def test_orchestrator_intake_rejects_invalid_intake_ids(self) -> None:
        invalid_ids = ["", "../x", "a/b", "my plan", ".hidden", "-bad", "Bad", "a.b"]
        for intake_id in invalid_ids:
            with self.subTest(intake_id=intake_id):
                with self.assertRaises(ValueError):
                    validate_intake_id(intake_id)
                if not intake_id or intake_id.startswith("-"):
                    continue
                buf = io.StringIO()
                with redirect_stderr(buf):
                    code = main(
                        [
                            "orchestrator",
                            "intake",
                            intake_id,
                            str(self.project),
                            "--goal",
                            "Build a game",
                        ]
                    )
                self.assertEqual(code, 1)
                self.assertTrue(buf.getvalue().strip())

    def test_orchestrator_intake_refuses_to_overwrite_existing_artifact(self) -> None:
        intake_id = "slither-demo"
        create_goal_intake(self.project, intake_id, "Build a game")
        artifact_path = self._artifact_path(intake_id)
        original = artifact_path.read_text(encoding="utf-8")

        with self.assertRaises(FileExistsError):
            create_goal_intake(self.project, intake_id, "Build another game")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "intake",
                    intake_id,
                    str(self.project),
                    "--goal",
                    "Build another game",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("already exists", buf.getvalue())
        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))

    def test_orchestrator_intake_writes_only_expected_artifact_file(self) -> None:
        before = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }
        intake_id = "slither-demo"

        create_goal_intake(self.project, intake_id, "Build a game")

        after = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }
        self.assertEqual(
            after - before,
            {".agent-os/orchestrator/intakes/slither-demo/goal-intake.json"},
        )

    def test_orchestrator_intake_does_not_create_planning_artifacts(self) -> None:
        create_goal_intake(self.project, "slither-demo", "Build a game")
        forbidden_names = set(planning_module.PLANNING_ARTIFACT_FILES)
        created_names = {path.name for path in self.project.rglob("*") if path.is_file()}
        self.assertTrue(forbidden_names.isdisjoint(created_names))
        self.assertFalse((self.project / ".agent-os" / "planning").exists())

    def test_orchestrator_intake_fails_without_agent_os_init(self) -> None:
        bare = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(FileNotFoundError):
                create_goal_intake(bare, "slither-demo", "Build a game")
            buf = io.StringIO()
            with redirect_stderr(buf):
                code = main(
                    [
                        "orchestrator",
                        "intake",
                        "slither-demo",
                        str(bare),
                        "--goal",
                        "Build a game",
                    ]
                )
            self.assertEqual(code, 1)
            self.assertIn("no workspace found", buf.getvalue())
            self.assertFalse((bare / ".agent-os" / "orchestrator").exists())
        finally:
            import shutil

            shutil.rmtree(bare)

    def test_orchestrator_intake_validation_failure_leaves_no_orchestrator_files(
        self,
    ) -> None:
        orchestrator_root = self.project / ".agent-os" / "orchestrator"
        self.assertFalse(orchestrator_root.exists())

        with self.assertRaises(ValueError):
            create_goal_intake(self.project, "my plan", "Build a game")
        self.assertFalse(orchestrator_root.exists())
        self.assertEqual(list(self.project.rglob(GOAL_INTAKE_FILE)), [])

        with self.assertRaises(ValueError):
            create_goal_intake(self.project, "demo", "   ")
        self.assertFalse(orchestrator_root.exists())
        self.assertEqual(list(self.project.rglob(GOAL_INTAKE_FILE)), [])

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "intake",
                    "my plan",
                    str(self.project),
                    "--goal",
                    "Build a game",
                ]
            )
        self.assertEqual(code, 1)
        self.assertFalse(orchestrator_root.exists())
        self.assertEqual(list(self.project.rglob(GOAL_INTAKE_FILE)), [])

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                ["orchestrator", "intake", "demo", str(self.project), "--goal", ""]
            )
        self.assertEqual(code, 1)
        self.assertIn("goal must not be empty", buf.getvalue())
        self.assertFalse(orchestrator_root.exists())
        self.assertEqual(list(self.project.rglob(GOAL_INTAKE_FILE)), [])

    def test_orchestrator_intake_does_not_create_planning_run_slice(self) -> None:
        create_goal_intake(self.project, "slither-demo", "Build a game")
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("PLANNING_RUN_SLICE", combined)

    def test_orchestrator_intake_does_not_create_runs(self) -> None:
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())

        create_goal_intake(self.project, "slither-demo", "Build a game")

        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_orchestrator_intake_does_not_invoke_external_subprocess(self) -> None:
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(
                    [
                        "orchestrator",
                        "intake",
                        "slither-demo",
                        str(self.project),
                        "--goal",
                        "Build a game",
                    ]
                )
        self.assertEqual(code, 0)
        self.assertTrue(self._artifact_path("slither-demo").is_file())

    def test_orchestrator_intake_does_not_require_runner_files(self) -> None:
        self.assertFalse((self.project / "agent-os-runner-experimental").exists())

        create_goal_intake(self.project, "slither-demo", "Build a game")

        self.assertFalse((self.project / "agent-os-runner-experimental").exists())

    def test_orchestrator_intake_cli_success_output_is_operator_readable(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "intake",
                    "slither-demo",
                    str(self.project),
                    "--goal",
                    "Build a game",
                ]
            )
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("created goal intake artifact:", output)
        self.assertIn("artifact_type: GOAL_INTAKE", output)
        self.assertIn("deterministic intake/scaffold only", output)
        self.assertIn("no LLM", output)
        self.assertIn("no planning approval", output)
        self.assertIn("no runs", output)
        self.assertIn("no executor invocation", output)

    def test_orchestrator_intake_cli_help_marks_scaffold_only(self) -> None:
        help_text = build_parser().format_help()
        compact_help = re.sub(r"\s+", " ", help_text)
        self.assertIn("orchestrator", help_text)
        self.assertIn("no LLM", compact_help)
        self.assertIn("no execution", compact_help)

        parser = build_parser()
        orchestrator_action = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        orchestrator_parser = orchestrator_action.choices["orchestrator"]
        orchestrator_sub = next(
            action
            for action in orchestrator_parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        intake_help = orchestrator_sub.choices["intake"].format_help()
        compact_intake_help = re.sub(r"\s+", " ", intake_help)
        self.assertIn("GOAL_INTAKE artifact only", compact_intake_help)
        self.assertIn("Does not call an LLM", compact_intake_help)
        self.assertIn("choose architecture", compact_intake_help)
        self.assertIn("create runs", compact_intake_help)
        self.assertIn("invoke an executor", compact_intake_help)


class OrchestratorGoalIntakeStatusValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _write_artifact(self, intake_id: str, artifact: dict) -> Path:
        path = self._artifact_path(intake_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        return path

    def test_orchestrator_status_succeeds_on_valid_intake_and_is_read_only(self) -> None:
        intake_id = "slither-demo"
        artifact_path = self._create_slither_intake(intake_id)
        original = artifact_path.read_text(encoding="utf-8")
        before = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "status", intake_id, str(self.project)])

        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("intake_id: slither-demo", output)
        self.assertIn("artifact_type: GOAL_INTAKE", output)
        self.assertIn("schema_version: 0.1", output)
        self.assertIn("ambiguity_level: HIGH", output)
        self.assertIn("planning_readiness: REQUIRES_CLARIFICATION", output)
        self.assertIn("owner_clarifications: 0", output)
        self.assertNotIn("latest_clarification_id:", output)
        self.assertNotIn("latest_clarification_created_at:", output)
        self.assertIn("validation: OK", output)
        self.assertIn("no planning draft was created", output)
        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))
        after = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_orchestrator_status_fails_on_missing_intake_and_creates_no_files(
        self,
    ) -> None:
        before = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                ["orchestrator", "status", "missing-intake", str(self.project)]
            )

        self.assertEqual(code, 1)
        self.assertIn("goal intake artifact not found", buf.getvalue())
        after = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)
        self.assertFalse(
            (
                self.project
                / ".agent-os"
                / "orchestrator"
                / "intakes"
                / "missing-intake"
            ).exists()
        )

    def test_orchestrator_status_fails_on_invalid_intake_and_does_not_modify_artifact(
        self,
    ) -> None:
        intake_id = "invalid-status"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        artifact_path = self._write_artifact(intake_id, artifact)
        original = artifact_path.read_text(encoding="utf-8")

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "status", intake_id, str(self.project)])

        self.assertEqual(code, 1)
        output = buf.getvalue()
        self.assertIn(f"intake_id: {intake_id}", output)
        self.assertIn("artifact_type: PLANNING_WORKSPACE_DRAFT", output)
        self.assertIn("validation: INVALID", output)
        self.assertIn("wrong artifact_type", output)
        self.assertIn("no planning draft was created", output)
        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))

    def test_orchestrator_validate_succeeds_on_valid_intake_and_is_read_only(self) -> None:
        intake_id = "slither-demo"
        artifact_path = self._create_slither_intake(intake_id)
        original = artifact_path.read_text(encoding="utf-8")
        before = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "validate", intake_id, str(self.project)])

        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("final validation result: OK", output)
        self.assertIn("validation is not approval", output)
        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))
        after = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_broad_slither_like_intake_validates_with_high_ambiguity(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        report = validate_goal_intake(self.project, intake_id)

        self.assertTrue(report.valid)
        artifact = load_goal_intake(self.project, intake_id)
        self.assertEqual(artifact["ambiguity_level"], "HIGH")
        self.assertEqual(artifact["planning_readiness"], "REQUIRES_CLARIFICATION")

    def test_validation_rejects_missing_intake(self) -> None:
        with self.assertRaises(FileNotFoundError):
            validate_goal_intake(self.project, "missing-intake")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                ["orchestrator", "validate", "missing-intake", str(self.project)]
            )
        self.assertEqual(code, 1)
        self.assertIn("goal intake artifact not found", buf.getvalue())

    def test_validation_rejects_malformed_json(self) -> None:
        intake_id = "broken-json"
        path = self._artifact_path(intake_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not-json", encoding="utf-8")

        report = validate_goal_intake(self.project, intake_id)
        self.assertFalse(report.valid)
        self.assertTrue(any("malformed JSON" in error for error in report.errors))

    def test_validation_rejects_wrong_artifact_type(self) -> None:
        intake_id = "wrong-type"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        self._write_artifact(intake_id, artifact)

        report = validate_goal_intake(self.project, intake_id)
        self.assertFalse(report.valid)
        self.assertTrue(any("wrong artifact_type" in error for error in report.errors))

    def test_validation_rejects_unsupported_schema_version(self) -> None:
        intake_id = "bad-version"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["schema_version"] = "9.9"
        self._write_artifact(intake_id, artifact)

        report = validate_goal_intake(self.project, intake_id)
        self.assertFalse(report.valid)
        self.assertTrue(
            any("unsupported schema_version" in error for error in report.errors)
        )

    def test_validation_rejects_missing_required_fields(self) -> None:
        intake_id = "missing-field"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        del artifact["raw_goal"]
        self._write_artifact(intake_id, artifact)

        report = validate_goal_intake(self.project, intake_id)
        self.assertFalse(report.valid)
        self.assertTrue(
            any("missing required field: raw_goal" in error for error in report.errors)
        )

    def test_validation_rejects_wrong_field_types(self) -> None:
        intake_id = "wrong-types"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["open_questions"] = "not-a-list"
        self._write_artifact(intake_id, artifact)

        report = validate_goal_intake(self.project, intake_id)
        self.assertFalse(report.valid)
        self.assertTrue(
            any("open_questions must be a list" in error for error in report.errors)
        )

    def test_validation_rejects_missing_non_authority_flags(self) -> None:
        intake_id = "missing-flag"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        del artifact["non_authority"]["does_not_create_run"]
        self._write_artifact(intake_id, artifact)

        report = validate_goal_intake(self.project, intake_id)
        self.assertFalse(report.valid)
        self.assertTrue(
            any(
                "missing non_authority flag: does_not_create_run" in error
                for error in report.errors
            )
        )

    def test_validation_rejects_false_non_authority_flags(self) -> None:
        intake_id = "false-flag"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["non_authority"]["does_not_invoke_executor"] = False
        self._write_artifact(intake_id, artifact)

        report = validate_goal_intake(self.project, intake_id)
        self.assertFalse(report.valid)
        self.assertTrue(
            any(
                "non_authority flag must be true: does_not_invoke_executor" in error
                for error in report.errors
            )
        )

    def test_validation_rejects_intake_id_mismatch(self) -> None:
        intake_id = "path-id"
        artifact = build_goal_intake_artifact(
            "artifact-id",
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        self._write_artifact(intake_id, artifact)

        report = validate_goal_intake(self.project, intake_id)
        self.assertFalse(report.valid)
        self.assertTrue(any("intake_id mismatch" in error for error in report.errors))

    def test_validation_rejects_high_ambiguity_with_draft_allowed(self) -> None:
        intake_id = "incoherent"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["ambiguity_level"] = "HIGH"
        artifact["planning_readiness"] = "DRAFT_ALLOWED"
        self._write_artifact(intake_id, artifact)

        report = validate_goal_intake(self.project, intake_id)
        self.assertFalse(report.valid)
        self.assertTrue(
            any("HIGH ambiguity must not be DRAFT_ALLOWED" in error for error in report.errors)
        )

    def test_validation_rejects_high_ambiguity_with_not_ready(self) -> None:
        intake_id = "high-not-ready"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["ambiguity_level"] = "HIGH"
        artifact["planning_readiness"] = "NOT_READY"
        artifact_path = self._write_artifact(intake_id, artifact)
        original = artifact_path.read_text(encoding="utf-8")

        report = validate_goal_intake(self.project, intake_id)
        self.assertFalse(report.valid)
        self.assertTrue(
            any(
                "incoherent readiness: HIGH ambiguity should be REQUIRES_CLARIFICATION"
                in error
                for error in report.errors
            )
        )
        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))

    def test_validation_rejects_planning_run_slice_in_artifact_content(self) -> None:
        intake_id = "slice-contamination"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["raw_goal"] = "Goal references PLANNING_RUN_SLICE in JSON content"
        artifact_path = self._write_artifact(intake_id, artifact)
        original = artifact_path.read_text(encoding="utf-8")

        report = validate_goal_intake(self.project, intake_id)
        self.assertFalse(report.valid)
        self.assertTrue(
            any(
                "goal intake content must not contain PLANNING_RUN_SLICE" in error
                for error in report.errors
            )
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "validate", intake_id, str(self.project)])

        self.assertEqual(code, 1)
        self.assertIn("PLANNING_RUN_SLICE", buf.getvalue())
        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))

    def test_status_validate_do_not_create_planning_artifacts(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)
        forbidden_names = set(planning_module.PLANNING_ARTIFACT_FILES)

        for command in ("status", "validate"):
            with self.subTest(command=command):
                code = main(["orchestrator", command, intake_id, str(self.project)])
                self.assertEqual(code, 0)
                created_names = {
                    path.name for path in self.project.rglob("*") if path.is_file()
                }
                self.assertTrue(forbidden_names.isdisjoint(created_names))
                self.assertFalse((self.project / ".agent-os" / "planning").exists())

    def test_status_validate_do_not_create_planning_run_slice(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        for command in ("status", "validate"):
            with self.subTest(command=command):
                main(["orchestrator", command, intake_id, str(self.project)])
                combined = "\n".join(
                    path.read_text(encoding="utf-8")
                    for path in self.project.rglob("*")
                    if path.is_file()
                )
                self.assertNotIn("PLANNING_RUN_SLICE", combined)

    def test_status_validate_do_not_create_runs(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())

        for command in ("status", "validate"):
            with self.subTest(command=command):
                main(["orchestrator", command, intake_id, str(self.project)])

        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_status_validate_do_not_invoke_external_subprocess(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            for command in ("status", "validate"):
                with self.subTest(command=command):
                    code = main(["orchestrator", command, intake_id, str(self.project)])
                    self.assertEqual(code, 0)

    def test_status_validate_do_not_modify_goal_intake_json(self) -> None:
        intake_id = "slither-demo"
        artifact_path = self._create_slither_intake(intake_id)
        original = artifact_path.read_text(encoding="utf-8")

        main(["orchestrator", "status", intake_id, str(self.project)])
        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))

        main(["orchestrator", "validate", intake_id, str(self.project)])
        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))

    def test_orchestrator_status_validate_cli_help_marks_read_only(self) -> None:
        parser = build_parser()
        orchestrator_action = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        orchestrator_parser = orchestrator_action.choices["orchestrator"]
        orchestrator_sub = next(
            action
            for action in orchestrator_parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )

        for command in ("status", "validate"):
            with self.subTest(command=command):
                help_text = orchestrator_sub.choices[command].format_help()
                compact_help = re.sub(r"\s+", " ", help_text)
                self.assertIn("read-only", compact_help.lower())
                self.assertIn("Does not call an LLM", compact_help)
                self.assertIn("create planning drafts", compact_help)
                self.assertIn("invoke an executor", compact_help)

    def test_missing_workspace_fails_without_creating_orchestrator_dir(self) -> None:
        bare = Path(tempfile.mkdtemp())
        try:
            for command in ("status", "validate"):
                with self.subTest(command=command):
                    buf = io.StringIO()
                    with redirect_stderr(buf):
                        code = main(
                            ["orchestrator", command, "slither-demo", str(bare)]
                        )
                    self.assertEqual(code, 1)
                    self.assertIn("no workspace found", buf.getvalue())
                    self.assertFalse((bare / ".agent-os" / "orchestrator").exists())
        finally:
            import shutil

            shutil.rmtree(bare)


class OrchestratorOwnerClarificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(
            self.project,
            intake_id,
            clarification_id,
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _write_artifact(self, intake_id: str, artifact: dict) -> Path:
        path = self._artifact_path(intake_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        return path

    def test_orchestrator_clarify_creates_expected_owner_clarification_artifact(
        self,
    ) -> None:
        intake_id = "slither-demo"
        clarification_id = "scope-v1"
        answer = "Target 20 players per room; browser-only MVP."
        self._create_slither_intake(intake_id)

        dest = create_owner_clarification(
            self.project,
            intake_id,
            clarification_id,
            answer,
        )

        self.assertEqual(dest, self._clarification_path(intake_id, clarification_id))
        self.assertTrue(dest.is_file())
        artifact = json.loads(dest.read_text(encoding="utf-8"))
        self.assertEqual(artifact["artifact_type"], "OWNER_CLARIFICATION")
        self.assertEqual(artifact["schema_version"], "0.1")
        self.assertEqual(artifact["applies_to_open_questions"], [])
        self.assertEqual(artifact["explicit_constraints_added"], [])
        self.assertEqual(artifact["non_goals_added"], [])
        self.assertEqual(artifact["risk_notes"], [])

    def test_owner_clarification_artifact_contains_all_required_fields(self) -> None:
        artifact = build_owner_clarification_artifact(
            "slither-demo",
            "scope-v1",
            "Browser-only MVP.",
            created_at="2026-07-06T10:00:00+00:00",
        )
        missing = [
            field
            for field in OWNER_CLARIFICATION_REQUIRED_FIELDS
            if field not in artifact
        ]
        self.assertEqual(missing, [])
        self.assertEqual(artifact["applies_to_open_questions"], [])
        self.assertEqual(artifact["explicit_constraints_added"], [])
        self.assertEqual(artifact["non_goals_added"], [])
        self.assertEqual(artifact["risk_notes"], [])

    def test_owner_answer_preserves_exact_input(self) -> None:
        intake_id = "slither-demo"
        answer = "  Target 20\tplayers per room.\n\nBrowser-only MVP.  "
        self._create_slither_intake(intake_id)

        create_owner_clarification(self.project, intake_id, "scope-v1", answer)
        artifact = load_owner_clarification(self.project, intake_id, "scope-v1")
        self.assertEqual(artifact["owner_answer"], answer)

    def test_clarification_creation_preserves_goal_intake_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        artifact_path = self._create_slither_intake(intake_id)
        original = artifact_path.read_bytes()

        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only MVP.",
        )

        self.assertEqual(original, artifact_path.read_bytes())

    def test_clarification_creation_requires_valid_goal_intake(self) -> None:
        intake_id = "invalid-intake"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        self._write_artifact(intake_id, artifact)

        with self.assertRaises(ValueError) as ctx:
            create_owner_clarification(
                self.project,
                intake_id,
                "scope-v1",
                "Browser-only MVP.",
            )
        self.assertIn("invalid goal intake artifact", str(ctx.exception))
        self.assertFalse(self._clarification_path(intake_id, "scope-v1").exists())

    def test_clarify_missing_workspace_fails_without_orchestrator_tree(self) -> None:
        bare = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(FileNotFoundError):
                create_owner_clarification(
                    bare,
                    "slither-demo",
                    "scope-v1",
                    "Browser-only MVP.",
                )
            buf = io.StringIO()
            with redirect_stderr(buf):
                code = main(
                    [
                        "orchestrator",
                        "clarify",
                        "slither-demo",
                        str(bare),
                        "--clarification-id",
                        "scope-v1",
                        "--answer",
                        "Browser-only MVP.",
                    ]
                )
            self.assertEqual(code, 1)
            self.assertIn("no workspace found", buf.getvalue())
            self.assertFalse((bare / ".agent-os" / "orchestrator").exists())
        finally:
            import shutil

            shutil.rmtree(bare)

    def test_clarify_rejects_invalid_intake_id_without_creating_artifacts(self) -> None:
        intake_id = "../escape"
        clarification_id = "scope-v1"
        self._create_slither_intake("slither-demo")
        before = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "clarify",
                    intake_id,
                    str(self.project),
                    "--clarification-id",
                    clarification_id,
                    "--answer",
                    "Escape attempt.",
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("invalid intake id", buf.getvalue())
        self.assertFalse(self._clarification_path(intake_id, clarification_id).exists())
        self.assertFalse(
            (self.project / ".agent-os" / "orchestrator" / "intakes" / "escape").exists()
        )
        after = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_clarify_missing_intake_fails_without_clarification_artifact(self) -> None:
        clarifications_dir = (
            self.project
            / ".agent-os"
            / "orchestrator"
            / "intakes"
            / "missing-intake"
            / CLARIFICATIONS_DIR
        )

        with self.assertRaises(FileNotFoundError):
            create_owner_clarification(
                self.project,
                "missing-intake",
                "scope-v1",
                "Browser-only MVP.",
            )

        self.assertFalse(clarifications_dir.exists())

    def test_clarify_invalid_intake_artifact_fails_without_clarification_artifact(
        self,
    ) -> None:
        intake_id = "broken-intake"
        path = self._artifact_path(intake_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not-json", encoding="utf-8")

        with self.assertRaises(ValueError):
            create_owner_clarification(
                self.project,
                intake_id,
                "scope-v1",
                "Browser-only MVP.",
            )

        self.assertFalse(self._clarification_path(intake_id, "scope-v1").exists())

    def test_clarify_rejects_empty_answer(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        with self.assertRaises(ValueError):
            create_owner_clarification(self.project, intake_id, "scope-v1", "   ")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "clarify",
                    intake_id,
                    str(self.project),
                    "--clarification-id",
                    "scope-v1",
                    "--answer",
                    "",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("clarification answer must not be empty", buf.getvalue())
        self.assertFalse(self._clarification_path(intake_id, "scope-v1").exists())

    def test_clarify_rejects_invalid_clarification_ids(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)
        invalid_ids = ["", "../x", "a/b", "my plan", ".hidden", "-bad", "Bad", "a.b"]

        for clarification_id in invalid_ids:
            with self.subTest(clarification_id=clarification_id):
                with self.assertRaises(ValueError):
                    validate_clarification_id(clarification_id)
                if not clarification_id or clarification_id.startswith("-"):
                    continue
                buf = io.StringIO()
                with redirect_stderr(buf):
                    code = main(
                        [
                            "orchestrator",
                            "clarify",
                            intake_id,
                            str(self.project),
                            "--clarification-id",
                            clarification_id,
                            "--answer",
                            "Browser-only MVP.",
                        ]
                    )
                self.assertEqual(code, 1)
                self.assertTrue(buf.getvalue().strip())

    def test_clarify_refuses_to_overwrite_existing_clarification(self) -> None:
        intake_id = "slither-demo"
        clarification_id = "scope-v1"
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            clarification_id,
            "First answer.",
        )
        clarification_path = self._clarification_path(intake_id, clarification_id)
        original = clarification_path.read_text(encoding="utf-8")

        with self.assertRaises(FileExistsError):
            create_owner_clarification(
                self.project,
                intake_id,
                clarification_id,
                "Second answer.",
            )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "clarify",
                    intake_id,
                    str(self.project),
                    "--clarification-id",
                    clarification_id,
                    "--answer",
                    "Second answer.",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("already exists", buf.getvalue())
        self.assertEqual(original, clarification_path.read_text(encoding="utf-8"))

    def test_clarify_rejects_path_escape_attempts(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        with self.assertRaises(ValueError):
            create_owner_clarification(
                self.project,
                intake_id,
                "../escape",
                "Escape attempt.",
            )

        clarifications_dir = orchestrator_intake_path(self.project, intake_id) / CLARIFICATIONS_DIR
        self.assertFalse(clarifications_dir.exists())

    def test_owner_clarification_includes_all_non_authority_flags(self) -> None:
        artifact = build_owner_clarification_artifact(
            "slither-demo",
            "scope-v1",
            "Browser-only MVP.",
            created_at="2026-07-06T10:00:00+00:00",
        )
        self.assertEqual(
            set(artifact["non_authority"]),
            set(OWNER_CLARIFICATION_NON_AUTHORITY_FLAGS),
        )
        self.assertTrue(all(artifact["non_authority"].values()))

    def test_clarification_creation_does_not_change_planning_readiness(self) -> None:
        intake_id = "slither-demo"
        artifact_path = self._create_slither_intake(intake_id)
        before = json.loads(artifact_path.read_text(encoding="utf-8"))[
            "planning_readiness"
        ]

        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only MVP.",
        )

        after = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]
        self.assertEqual(before, after)
        self.assertEqual(before, "REQUIRES_CLARIFICATION")

    def test_clarification_creation_does_not_create_planning_artifacts(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)
        forbidden_names = set(planning_module.PLANNING_ARTIFACT_FILES)

        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only MVP.",
        )

        created_names = {path.name for path in self.project.rglob("*") if path.is_file()}
        self.assertTrue(forbidden_names.isdisjoint(created_names))
        self.assertFalse((self.project / ".agent-os" / "planning").exists())

    def test_clarification_creation_does_not_create_planning_run_slice(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only MVP.",
        )

        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("PLANNING_RUN_SLICE", combined)

    def test_clarification_creation_does_not_create_runs(self) -> None:
        intake_id = "slither-demo"
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        self._create_slither_intake(intake_id)

        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only MVP.",
        )

        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_clarification_creation_does_not_invoke_external_subprocess(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(
                    [
                        "orchestrator",
                        "clarify",
                        intake_id,
                        str(self.project),
                        "--clarification-id",
                        "scope-v1",
                        "--answer",
                        "Browser-only MVP.",
                    ]
                )
        self.assertEqual(code, 0)
        self.assertTrue(self._clarification_path(intake_id, "scope-v1").is_file())

    def test_orchestrator_status_reports_latest_after_two_clarifications_read_only(
        self,
    ) -> None:
        intake_id = "slither-demo"
        artifact_path = self._create_slither_intake(intake_id)
        original_intake = artifact_path.read_text(encoding="utf-8")
        create_owner_clarification(
            self.project,
            intake_id,
            "players-v2",
            "Target 20 players per room.",
        )
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only MVP.",
        )
        records = list_owner_clarifications(self.project, intake_id)
        self.assertEqual(len(records), 2)
        latest = records[-1]
        clarification_paths = {
            path.relative_to(self.project).as_posix(): path.read_text(encoding="utf-8")
            for path in self.project.rglob("clarifications/*.json")
        }
        before = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "status", intake_id, str(self.project)])

        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("owner_clarifications: 2", output)
        self.assertIn(f"latest_clarification_id: {latest.clarification_id}", output)
        self.assertIn(
            f"latest_clarification_created_at: {latest.created_at}",
            output,
        )
        self.assertIn(
            "they do not create a planning draft and do not change planning_readiness",
            output,
        )
        self.assertEqual(original_intake, artifact_path.read_text(encoding="utf-8"))
        for rel_path, original_text in clarification_paths.items():
            current = (self.project / rel_path).read_text(encoding="utf-8")
            self.assertEqual(original_text, current)
        after = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_orchestrator_status_reports_clarification_count_read_only(self) -> None:
        intake_id = "slither-demo"
        artifact_path = self._create_slither_intake(intake_id)
        original = artifact_path.read_text(encoding="utf-8")
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only MVP.",
        )
        before = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "status", intake_id, str(self.project)])

        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("owner_clarifications: 1", output)
        self.assertIn("latest_clarification_id: scope-v1", output)
        self.assertIn(
            "they do not create a planning draft and do not change planning_readiness",
            output,
        )
        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))
        after = {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_orchestrator_clarify_cli_help_marks_context_only(self) -> None:
        parser = build_parser()
        orchestrator_action = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        orchestrator_parser = orchestrator_action.choices["orchestrator"]
        orchestrator_sub = next(
            action
            for action in orchestrator_parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        clarify_help = orchestrator_sub.choices["clarify"].format_help()
        compact_help = re.sub(r"\s+", " ", clarify_help)
        self.assertIn("owner-provided clarification", compact_help)
        self.assertIn("Does not call an LLM", compact_help)
        self.assertIn("modify goal-intake.json", compact_help)
        self.assertIn("change planning_readiness", compact_help)
        self.assertIn("generate planning drafts", compact_help)
        self.assertIn("invoke an executor", compact_help)

    def test_list_and_validate_owner_clarification_helpers(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only MVP.",
        )

        records = list_owner_clarifications(self.project, intake_id)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].clarification_id, "scope-v1")

        report = validate_owner_clarification(self.project, intake_id, "scope-v1")
        self.assertTrue(report.valid)


class OrchestratorGoalIntakeReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(
            self.project,
            intake_id,
            clarification_id,
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _create_simple_intake(self, intake_id: str = "fix-login") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Fix the login timeout bug in the auth module",
        )

    def _write_artifact(self, intake_id: str, artifact: dict) -> Path:
        path = self._artifact_path(intake_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        return path

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def test_orchestrator_readiness_succeeds_read_only_for_valid_intake_zero_clarifications(
        self,
    ) -> None:
        intake_id = "fix-login"
        artifact_path = self._create_simple_intake(intake_id)
        original = artifact_path.read_text(encoding="utf-8")
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "readiness", intake_id, str(self.project)])

        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("goal_intake_valid: yes", output)
        self.assertIn("owner_clarification_count: 0", output)
        self.assertIn("readiness_review_state: OWNER_REVIEW_REQUIRED", output)
        self.assertIn("next_required_action: OWNER_READINESS_DECISION_REQUIRED", output)
        self.assertIn("readiness review is read-only", output)
        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))
        self.assertEqual(before, self._project_files())

    def test_high_requires_clarification_zero_clarifications_blocked(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        report = review_goal_intake_readiness(self.project, intake_id)

        self.assertEqual(report.readiness_review_state, "BLOCKED_REQUIRES_CLARIFICATION")
        self.assertEqual(report.next_required_action, "ADD_OWNER_CLARIFICATION")
        self.assertEqual(report.owner_clarification_count, 0)
        self.assertIsNone(report.latest_clarification_id)

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "readiness", intake_id, str(self.project)])
        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("readiness_review_state: BLOCKED_REQUIRES_CLARIFICATION", output)
        self.assertIn("next_required_action: ADD_OWNER_CLARIFICATION", output)

    def test_high_requires_clarification_one_clarification_owner_review_required(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max; no persistence.",
        )

        report = review_goal_intake_readiness(self.project, intake_id)

        self.assertEqual(
            report.readiness_review_state,
            "OWNER_CLARIFICATION_PRESENT_REVIEW_REQUIRED",
        )
        self.assertEqual(report.next_required_action, "OWNER_READINESS_DECISION_REQUIRED")
        self.assertEqual(report.owner_clarification_count, 1)
        self.assertEqual(report.latest_clarification_id, "scope-v1")

    def test_readiness_review_never_modifies_goal_intake_json(self) -> None:
        intake_id = "slither-demo"
        artifact_path = self._create_slither_intake(intake_id)
        original = artifact_path.read_text(encoding="utf-8")

        review_goal_intake_readiness(self.project, intake_id)
        main(["orchestrator", "readiness", intake_id, str(self.project)])

        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))

    def test_readiness_review_never_modifies_clarification_artifacts(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)
        clarification_path = create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max.",
        )
        original = clarification_path.read_text(encoding="utf-8")

        review_goal_intake_readiness(self.project, intake_id)

        self.assertEqual(original, clarification_path.read_text(encoding="utf-8"))

    def test_readiness_review_includes_non_authority_flags(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)

        report = review_goal_intake_readiness(self.project, intake_id)

        for flag in READINESS_REVIEW_NON_AUTHORITY_FLAGS:
            self.assertTrue(report.non_authority[flag])
        self.assertIn("does_not_generate_planning_draft: true", report.output)
        self.assertIn(
            "requires_future_owner_readiness_decision: true",
            report.output,
        )

    def test_readiness_review_does_not_emit_draft_allowed_states(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)

        report = review_goal_intake_readiness(self.project, intake_id)

        self.assertNotIn(report.readiness_review_state, {"DRAFT_ALLOWED", "READY_FOR_DRAFT"})
        self.assertNotIn("readiness_review_state: DRAFT_ALLOWED", report.output)
        self.assertNotIn("readiness_review_state: READY_FOR_DRAFT", report.output)

    def test_readiness_review_does_not_create_planning_artifacts(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)
        forbidden_names = set(planning_module.PLANNING_ARTIFACT_FILES)

        main(["orchestrator", "readiness", intake_id, str(self.project)])

        created_names = {
            path.name for path in self.project.rglob("*") if path.is_file()
        }
        self.assertTrue(forbidden_names.isdisjoint(created_names))
        self.assertFalse((self.project / ".agent-os" / "planning").exists())

    def test_readiness_review_does_not_create_planning_run_slice(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        main(["orchestrator", "readiness", intake_id, str(self.project)])

        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("PLANNING_RUN_SLICE", combined)

    def test_readiness_review_does_not_create_runs(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())

        main(["orchestrator", "readiness", intake_id, str(self.project)])

        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_readiness_review_does_not_invoke_external_subprocess(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code = main(["orchestrator", "readiness", intake_id, str(self.project)])
        self.assertEqual(code, 0)

    def test_readiness_missing_workspace_fails_without_orchestrator_tree(self) -> None:
        bare = Path(tempfile.mkdtemp())
        try:
            buf = io.StringIO()
            with redirect_stderr(buf):
                code = main(["orchestrator", "readiness", "slither-demo", str(bare)])
            self.assertEqual(code, 1)
            self.assertIn("no workspace found", buf.getvalue())
            self.assertFalse((bare / ".agent-os" / "orchestrator").exists())
        finally:
            import shutil

            shutil.rmtree(bare)

    def test_readiness_missing_intake_fails_without_creating_files(self) -> None:
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                ["orchestrator", "readiness", "missing-intake", str(self.project)]
            )

        self.assertEqual(code, 1)
        self.assertIn("goal intake artifact not found", buf.getvalue())
        self.assertEqual(before, self._project_files())
        self.assertFalse(
            (
                self.project
                / ".agent-os"
                / "orchestrator"
                / "intakes"
                / "missing-intake"
            ).exists()
        )

    def test_readiness_invalid_intake_blocked_without_writing_files(self) -> None:
        intake_id = "invalid-readiness"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        artifact_path = self._write_artifact(intake_id, artifact)
        original = artifact_path.read_text(encoding="utf-8")
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "readiness", intake_id, str(self.project)])

        self.assertEqual(code, 1)
        output = buf.getvalue()
        self.assertIn("goal_intake_valid: no", output)
        self.assertIn("readiness_review_state: BLOCKED_INVALID_INTAKE", output)
        self.assertIn("next_required_action: FIX_GOAL_INTAKE_STRUCTURE", output)
        self.assertIn("wrong artifact_type", output)
        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))
        self.assertEqual(before, self._project_files())

    def test_readiness_invalid_clarification_reported_blocking_without_mutation(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)
        clarification_path = self._clarification_path(intake_id, "broken")
        clarification_path.parent.mkdir(parents=True, exist_ok=True)
        clarification_path.write_text("{not-json", encoding="utf-8")
        original = clarification_path.read_text(encoding="utf-8")

        report = review_goal_intake_readiness(self.project, intake_id)

        self.assertEqual(report.intake_id, intake_id)
        self.assertEqual(report.readiness_review_state, "BLOCKED_INVALID_INTAKE")
        self.assertEqual(report.next_required_action, "FIX_CLARIFICATION_STRUCTURE")
        self.assertTrue(any("malformed JSON" in reason for reason in report.blocking_reasons))
        self.assertEqual(original, clarification_path.read_text(encoding="utf-8"))

    def test_readiness_report_carries_intake_id(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)

        report = review_goal_intake_readiness(self.project, intake_id)

        self.assertEqual(report.intake_id, intake_id)

    def test_orchestrator_readiness_cli_invalid_clarification_blocking_without_mutation(
        self,
    ) -> None:
        intake_id = "slither-demo"
        artifact_path = self._create_slither_intake(intake_id)
        intake_original = artifact_path.read_text(encoding="utf-8")
        clarification_path = self._clarification_path(intake_id, "broken")
        clarification_path.parent.mkdir(parents=True, exist_ok=True)
        clarification_path.write_text("{not-json", encoding="utf-8")
        clarification_original = clarification_path.read_text(encoding="utf-8")
        before = self._project_files()
        forbidden_names = set(planning_module.PLANNING_ARTIFACT_FILES)
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "readiness", intake_id, str(self.project)])

        output = buf.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("goal intake readiness review:", output)
        self.assertIn(f"intake_id: {intake_id}", output)
        self.assertIn("goal_intake_valid: yes", output)
        self.assertIn("readiness_review_state: BLOCKED_INVALID_INTAKE", output)
        self.assertIn("next_required_action: FIX_CLARIFICATION_STRUCTURE", output)
        self.assertIn("blocking_reasons:", output)
        self.assertIn("malformed JSON", output)
        self.assertIn("readiness review is read-only", output)
        self.assertEqual(intake_original, artifact_path.read_text(encoding="utf-8"))
        self.assertEqual(
            clarification_original,
            clarification_path.read_text(encoding="utf-8"),
        )
        self.assertEqual(before, self._project_files())
        created_names = {
            path.name for path in self.project.rglob("*") if path.is_file()
        }
        self.assertTrue(forbidden_names.isdisjoint(created_names))
        self.assertFalse((self.project / ".agent-os" / "planning").exists())
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("PLANNING_RUN_SLICE", combined)
        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_orchestrator_readiness_cli_help_marks_read_only(self) -> None:
        parser = build_parser()
        orchestrator_action = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        orchestrator_parser = orchestrator_action.choices["orchestrator"]
        orchestrator_sub = next(
            action
            for action in orchestrator_parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )

        help_text = orchestrator_sub.choices["readiness"].format_help()
        compact_help = re.sub(r"\s+", " ", help_text)
        self.assertIn("read-only", compact_help.lower())
        self.assertIn("Does not call an LLM", compact_help)
        self.assertIn("create planning drafts", compact_help)
        self.assertIn("invoke an executor", compact_help)
        self.assertIn("approve planning", compact_help)

    def test_orchestrator_validate_unchanged_without_clarification_requirement(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        report = validate_goal_intake(self.project, intake_id)
        self.assertTrue(report.valid)

    def test_orchestrator_status_remains_read_only_after_readiness_slice(self) -> None:
        intake_id = "slither-demo"
        artifact_path = self._create_slither_intake(intake_id)
        original = artifact_path.read_text(encoding="utf-8")
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "status", intake_id, str(self.project)])

        self.assertEqual(code, 0)
        self.assertIn("owner_clarifications: 0", buf.getvalue())
        self.assertEqual(original, artifact_path.read_text(encoding="utf-8"))
        self.assertEqual(before, self._project_files())


class OrchestratorOwnerReadinessDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(
            self.project,
            intake_id,
            clarification_id,
        )

    def _decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(
            self.project,
            intake_id,
            decision_id,
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _create_simple_intake(self, intake_id: str = "fix-login") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Fix the login timeout bug in the auth module",
        )

    def _write_artifact(self, intake_id: str, artifact: dict) -> Path:
        path = self._artifact_path(intake_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        return path

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _slither_with_clarification(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max; no persistence.",
        )

    def test_decide_readiness_creates_expected_artifact_path(self) -> None:
        intake_id = "slither-demo"
        decision_id = "owner-v1"
        self._slither_with_clarification(intake_id)

        dest = create_owner_readiness_decision(
            self.project,
            intake_id,
            decision_id,
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope is clear enough for draft prep.",
        )

        self.assertEqual(dest, self._decision_path(intake_id, decision_id))
        self.assertTrue(dest.is_file())

    def test_owner_readiness_decision_artifact_contains_all_required_fields(self) -> None:
        artifact = build_owner_readiness_decision_artifact(
            "slither-demo",
            "owner-v1",
            "BLOCK_INTAKE",
            "Stopping this intake.",
            readiness_review_state_at_decision="OWNER_REVIEW_REQUIRED",
            next_required_action_at_decision="OWNER_READINESS_DECISION_REQUIRED",
            owner_clarification_count_at_decision=0,
            latest_clarification_id_at_decision=None,
            created_at="2026-07-06T10:00:00+00:00",
        )
        missing = [
            field
            for field in OWNER_READINESS_DECISION_REQUIRED_FIELDS
            if field not in artifact
        ]
        self.assertEqual(missing, [])

    def test_owner_summary_preserves_exact_input(self) -> None:
        intake_id = "slither-demo"
        summary = "  Authorize draft prep after review.\t\n\nNot approval.  "
        self._slither_with_clarification(intake_id)

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            summary,
        )
        artifact = load_owner_readiness_decision(self.project, intake_id, "owner-v1")
        self.assertEqual(artifact["owner_summary"], summary)

    def test_artifact_includes_readiness_review_snapshot_fields(self) -> None:
        intake_id = "slither-demo"
        self._slither_with_clarification(intake_id)
        report = review_goal_intake_readiness(self.project, intake_id)

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Ready for future draft prep.",
        )
        artifact = load_owner_readiness_decision(self.project, intake_id, "owner-v1")
        self.assertEqual(
            artifact["readiness_review_state_at_decision"],
            report.readiness_review_state,
        )
        self.assertEqual(
            artifact["next_required_action_at_decision"],
            report.next_required_action,
        )
        self.assertEqual(
            artifact["owner_clarification_count_at_decision"],
            report.owner_clarification_count,
        )
        self.assertEqual(
            artifact["latest_clarification_id_at_decision"],
            report.latest_clarification_id,
        )

    def test_artifact_includes_all_required_non_authority_flags(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "Stopping intake.",
        )
        artifact = load_owner_readiness_decision(self.project, intake_id, "owner-v1")
        for flag in OWNER_READINESS_DECISION_NON_AUTHORITY_FLAGS:
            self.assertTrue(artifact["non_authority"][flag])

    def test_decision_creation_requires_valid_goal_intake(self) -> None:
        intake_id = "invalid-intake"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        self._write_artifact(intake_id, artifact)

        with self.assertRaises(ValueError) as ctx:
            create_owner_readiness_decision(
                self.project,
                intake_id,
                "owner-v1",
                "BLOCK_INTAKE",
                "Stop.",
            )
        self.assertIn("invalid goal intake artifact", str(ctx.exception))
        self.assertFalse(self._decision_path(intake_id, "owner-v1").exists())

    def test_decide_readiness_missing_workspace_fails_without_orchestrator_tree(
        self,
    ) -> None:
        bare = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(FileNotFoundError):
                create_owner_readiness_decision(
                    bare,
                    "slither-demo",
                    "owner-v1",
                    "BLOCK_INTAKE",
                    "Stop.",
                )
            buf = io.StringIO()
            with redirect_stderr(buf):
                code = main(
                    [
                        "orchestrator",
                        "decide-readiness",
                        "slither-demo",
                        str(bare),
                        "--decision",
                        "BLOCK_INTAKE",
                        "--decision-id",
                        "owner-v1",
                        "--summary",
                        "Stop.",
                    ]
                )
            self.assertEqual(code, 1)
            self.assertIn("no workspace found", buf.getvalue())
            self.assertFalse((bare / ".agent-os" / "orchestrator").exists())
        finally:
            import shutil

            shutil.rmtree(bare)

    def test_decide_readiness_missing_intake_fails_without_decision_artifact(
        self,
    ) -> None:
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "decide-readiness",
                    "missing-intake",
                    str(self.project),
                    "--decision",
                    "BLOCK_INTAKE",
                    "--decision-id",
                    "owner-v1",
                    "--summary",
                    "Stop.",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("goal intake artifact not found", buf.getvalue())
        self.assertFalse(
            (
                self.project
                / ".agent-os"
                / "orchestrator"
                / "intakes"
                / "missing-intake"
            ).exists()
        )

    def test_decide_readiness_invalid_intake_fails_without_decision_artifact(
        self,
    ) -> None:
        intake_id = "invalid-decision"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        self._write_artifact(intake_id, artifact)

        with self.assertRaises(ValueError):
            create_owner_readiness_decision(
                self.project,
                intake_id,
                "owner-v1",
                "BLOCK_INTAKE",
                "Stop.",
            )
        self.assertFalse(self._decision_path(intake_id, "owner-v1").exists())

    def test_decide_readiness_rejects_empty_summary(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)

        with self.assertRaises(ValueError) as ctx:
            create_owner_readiness_decision(
                self.project,
                intake_id,
                "owner-v1",
                "BLOCK_INTAKE",
                "",
            )
        self.assertIn("owner summary must not be empty", str(ctx.exception))

    def test_decide_readiness_rejects_invalid_decision_ids(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        invalid_ids = ("", " ", "../escape", "bad id", ".hidden")

        for decision_id in invalid_ids:
            with self.subTest(decision_id=decision_id):
                with self.assertRaises(ValueError):
                    create_owner_readiness_decision(
                        self.project,
                        intake_id,
                        decision_id,
                        "BLOCK_INTAKE",
                        "Stop.",
                    )
                self.assertFalse(self._decision_path(intake_id, decision_id).exists())

    def test_decide_readiness_rejects_unsupported_decision_values(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)

        with self.assertRaises(ValueError) as ctx:
            create_owner_readiness_decision(
                self.project,
                intake_id,
                "owner-v1",
                "APPROVE_PLANNING",
                "Not allowed.",
            )
        self.assertIn("unsupported decision value", str(ctx.exception))

    def test_decide_readiness_refuses_to_overwrite_existing_decision(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "First decision.",
        )
        existing = self._decision_path(intake_id, "owner-v1").read_text(encoding="utf-8")

        with self.assertRaises(FileExistsError):
            create_owner_readiness_decision(
                self.project,
                intake_id,
                "owner-v1",
                "REQUEST_MORE_CLARIFICATION",
                "Second decision.",
            )
        self.assertEqual(
            existing,
            self._decision_path(intake_id, "owner-v1").read_text(encoding="utf-8"),
        )

    def test_decide_readiness_rejects_path_escape_attempts(self) -> None:
        intake_id = "../escape"
        self._create_simple_intake("fix-login")
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "decide-readiness",
                    intake_id,
                    str(self.project),
                    "--decision",
                    "BLOCK_INTAKE",
                    "--decision-id",
                    "owner-v1",
                    "--summary",
                    "Escape attempt.",
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("invalid intake id", buf.getvalue())
        self.assertEqual(before, self._project_files())

    def test_authorize_draft_preparation_rejected_when_blocked_requires_clarification(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        with self.assertRaises(ValueError) as ctx:
            create_owner_readiness_decision(
                self.project,
                intake_id,
                "owner-v1",
                "AUTHORIZE_DRAFT_PREPARATION",
                "Too early.",
            )
        self.assertIn("AUTHORIZE_DRAFT_PREPARATION is not allowed", str(ctx.exception))
        self.assertIn("BLOCKED_REQUIRES_CLARIFICATION", str(ctx.exception))
        self.assertFalse(self._decision_path(intake_id, "owner-v1").exists())

    def test_authorize_draft_preparation_succeeds_when_clarification_present(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._slither_with_clarification(intake_id)

        dest = create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

        artifact = json.loads(dest.read_text(encoding="utf-8"))
        self.assertEqual(artifact["decision"], "AUTHORIZE_DRAFT_PREPARATION")
        self.assertEqual(
            artifact["readiness_review_state_at_decision"],
            "OWNER_CLARIFICATION_PRESENT_REVIEW_REQUIRED",
        )

    def test_request_more_clarification_succeeds_without_planning_draft(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)
        forbidden_names = set(planning_module.PLANNING_ARTIFACT_FILES)

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "REQUEST_MORE_CLARIFICATION",
            "Need more scope detail.",
        )

        created_names = {path.name for path in self.project.rglob("*") if path.is_file()}
        self.assertTrue(forbidden_names.isdisjoint(created_names))
        self.assertFalse((self.project / ".agent-os" / "planning").exists())

    def test_block_intake_succeeds_without_planning_draft(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        forbidden_names = set(planning_module.PLANNING_ARTIFACT_FILES)

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "Stopping this intake.",
        )

        created_names = {path.name for path in self.project.rglob("*") if path.is_file()}
        self.assertTrue(forbidden_names.isdisjoint(created_names))

    def test_decision_creation_preserves_goal_intake_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        self._slither_with_clarification(intake_id)
        artifact_path = self._artifact_path(intake_id)
        original = artifact_path.read_bytes()

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Future draft only.",
        )

        self.assertEqual(original, artifact_path.read_bytes())

    def test_decision_creation_preserves_clarification_artifacts_byte_for_byte(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._slither_with_clarification(intake_id)
        clarification_path = self._clarification_path(intake_id, "scope-v1")
        original = clarification_path.read_bytes()

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Future draft only.",
        )

        self.assertEqual(original, clarification_path.read_bytes())

    def test_decision_creation_does_not_change_planning_readiness(self) -> None:
        intake_id = "slither-demo"
        self._slither_with_clarification(intake_id)
        artifact_path = self._artifact_path(intake_id)
        before = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Future draft only.",
        )

        after = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]
        self.assertEqual(before, after)

    def test_decision_creation_does_not_create_planning_artifacts(self) -> None:
        intake_id = "slither-demo"
        self._slither_with_clarification(intake_id)
        forbidden_names = set(planning_module.PLANNING_ARTIFACT_FILES)

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Future draft only.",
        )

        created_names = {path.name for path in self.project.rglob("*") if path.is_file()}
        self.assertTrue(forbidden_names.isdisjoint(created_names))

    def test_decision_creation_does_not_create_planning_run_slice(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "Stop.",
        )

        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("PLANNING_RUN_SLICE", combined)

    def test_decision_creation_does_not_create_runs(self) -> None:
        intake_id = "fix-login"
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        self._create_simple_intake(intake_id)

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "Stop.",
        )

        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_decision_creation_does_not_invoke_external_subprocess(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)

        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code = main(
                [
                    "orchestrator",
                    "decide-readiness",
                    intake_id,
                    str(self.project),
                    "--decision",
                    "BLOCK_INTAKE",
                    "--decision-id",
                    "owner-v1",
                    "--summary",
                    "Stop.",
                ]
            )
        self.assertEqual(code, 0)

    def test_orchestrator_validate_unchanged_without_readiness_decision_requirement(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._slither_with_clarification(intake_id)

        report = validate_goal_intake(self.project, intake_id)
        self.assertTrue(report.valid)

    def test_orchestrator_readiness_remains_read_only_and_does_not_mutate_decisions(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._slither_with_clarification(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Future draft only.",
        )
        decision_path = self._decision_path(intake_id, "owner-v1")
        original = decision_path.read_text(encoding="utf-8")
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "readiness", intake_id, str(self.project)])

        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("owner_readiness_decision_count: 1", output)
        self.assertIn("latest_readiness_decision_id: owner-v1", output)
        self.assertIn("latest_readiness_decision: AUTHORIZE_DRAFT_PREPARATION", output)
        self.assertIn("owner readiness decisions do not generate a planning draft", output)
        self.assertEqual(original, decision_path.read_text(encoding="utf-8"))
        self.assertEqual(before, self._project_files())

    def test_orchestrator_decide_readiness_cli_help_marks_non_authoritative(self) -> None:
        parser = build_parser()
        orchestrator_action = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        orchestrator_parser = orchestrator_action.choices["orchestrator"]
        orchestrator_sub = next(
            action
            for action in orchestrator_parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )

        help_text = orchestrator_sub.choices["decide-readiness"].format_help()
        compact_help = re.sub(r"\s+", " ", help_text)
        self.assertIn("owner-provided", compact_help.lower())
        self.assertIn("Does not call an LLM", compact_help)
        self.assertIn("generate planning drafts", compact_help)
        self.assertIn("AUTHORIZE_DRAFT_PREPARATION authorizes only a future", compact_help)

    def test_orchestrator_decide_readiness_cli_success_includes_boundary_notes(
        self,
    ) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "decide-readiness",
                    intake_id,
                    str(self.project),
                    "--decision",
                    "BLOCK_INTAKE",
                    "--decision-id",
                    "owner-v1",
                    "--summary",
                    "Stop.",
                ]
            )

        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("created owner readiness decision artifact:", output)
        self.assertIn("artifact_type: OWNER_READINESS_DECISION", output)
        self.assertIn("decision: BLOCK_INTAKE", output)
        self.assertIn("no planning draft", output)
        self.assertIn("no executor invocation", output)

    def test_orchestrator_decide_readiness_cli_success_includes_decision_request_more(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "decide-readiness",
                    intake_id,
                    str(self.project),
                    "--decision",
                    "REQUEST_MORE_CLARIFICATION",
                    "--decision-id",
                    "owner-v1",
                    "--summary",
                    "Need more scope detail.",
                ]
            )

        self.assertEqual(code, 0)
        self.assertIn("decision: REQUEST_MORE_CLARIFICATION", buf.getvalue())

    def test_orchestrator_decide_readiness_cli_success_includes_decision_authorize(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._slither_with_clarification(intake_id)

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "decide-readiness",
                    intake_id,
                    str(self.project),
                    "--decision",
                    "AUTHORIZE_DRAFT_PREPARATION",
                    "--decision-id",
                    "owner-v1",
                    "--summary",
                    "Future draft prep only.",
                ]
            )

        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("decision: AUTHORIZE_DRAFT_PREPARATION", output)
        self.assertIn("no draft was generated", output)

    def test_validate_owner_readiness_decision_succeeds_on_valid_artifact(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "Stop.",
        )

        report = validate_owner_readiness_decision(self.project, intake_id, "owner-v1")
        self.assertTrue(report.valid)
        self.assertIn("structural validation: OK", report.output)
        self.assertIn("final validation result: OK", report.output)

    def test_validate_owner_readiness_decision_rejects_wrong_artifact_type(
        self,
    ) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        artifact = build_owner_readiness_decision_artifact(
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "Stop.",
            readiness_review_state_at_decision="OWNER_REVIEW_REQUIRED",
            next_required_action_at_decision="OWNER_READINESS_DECISION_REQUIRED",
            owner_clarification_count_at_decision=0,
            latest_clarification_id_at_decision=None,
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        path = self._decision_path(intake_id, "owner-v1")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        report = validate_owner_readiness_decision(self.project, intake_id, "owner-v1")
        self.assertFalse(report.valid)
        self.assertTrue(
            any("wrong artifact_type" in error for error in report.errors)
        )

    def test_validate_owner_readiness_decision_rejects_unsupported_schema_version(
        self,
    ) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        artifact = build_owner_readiness_decision_artifact(
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "Stop.",
            readiness_review_state_at_decision="OWNER_REVIEW_REQUIRED",
            next_required_action_at_decision="OWNER_READINESS_DECISION_REQUIRED",
            owner_clarification_count_at_decision=0,
            latest_clarification_id_at_decision=None,
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["schema_version"] = "9.9"
        path = self._decision_path(intake_id, "owner-v1")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        report = validate_owner_readiness_decision(self.project, intake_id, "owner-v1")
        self.assertFalse(report.valid)
        self.assertTrue(
            any("unsupported schema_version" in error for error in report.errors)
        )

    def test_validate_owner_readiness_decision_rejects_missing_non_authority_flag(
        self,
    ) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        artifact = build_owner_readiness_decision_artifact(
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "Stop.",
            readiness_review_state_at_decision="OWNER_REVIEW_REQUIRED",
            next_required_action_at_decision="OWNER_READINESS_DECISION_REQUIRED",
            owner_clarification_count_at_decision=0,
            latest_clarification_id_at_decision=None,
            created_at="2026-07-06T10:00:00+00:00",
        )
        del artifact["non_authority"]["does_not_create_run"]
        path = self._decision_path(intake_id, "owner-v1")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        report = validate_owner_readiness_decision(self.project, intake_id, "owner-v1")
        self.assertFalse(report.valid)
        self.assertTrue(
            any(
                "missing non_authority flag: does_not_create_run" in error
                for error in report.errors
            )
        )

    def test_validate_owner_readiness_decision_rejects_false_non_authority_flag(
        self,
    ) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        artifact = build_owner_readiness_decision_artifact(
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "Stop.",
            readiness_review_state_at_decision="OWNER_REVIEW_REQUIRED",
            next_required_action_at_decision="OWNER_READINESS_DECISION_REQUIRED",
            owner_clarification_count_at_decision=0,
            latest_clarification_id_at_decision=None,
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["non_authority"]["does_not_invoke_executor"] = False
        path = self._decision_path(intake_id, "owner-v1")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        report = validate_owner_readiness_decision(self.project, intake_id, "owner-v1")
        self.assertFalse(report.valid)
        self.assertTrue(
            any(
                "non_authority flag must be true: does_not_invoke_executor" in error
                for error in report.errors
            )
        )

    def test_validate_owner_readiness_decision_rejects_decision_id_mismatch(
        self,
    ) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        artifact = build_owner_readiness_decision_artifact(
            intake_id,
            "artifact-id",
            "BLOCK_INTAKE",
            "Stop.",
            readiness_review_state_at_decision="OWNER_REVIEW_REQUIRED",
            next_required_action_at_decision="OWNER_READINESS_DECISION_REQUIRED",
            owner_clarification_count_at_decision=0,
            latest_clarification_id_at_decision=None,
            created_at="2026-07-06T10:00:00+00:00",
        )
        path = self._decision_path(intake_id, "path-id")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        report = validate_owner_readiness_decision(self.project, intake_id, "path-id")
        self.assertFalse(report.valid)
        self.assertTrue(
            any("decision_id mismatch" in error for error in report.errors)
        )

    def test_authorize_draft_preparation_succeeds_when_owner_review_required(
        self,
    ) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        report = review_goal_intake_readiness(self.project, intake_id)
        self.assertEqual(report.readiness_review_state, "OWNER_REVIEW_REQUIRED")

        forbidden_names = set(planning_module.PLANNING_ARTIFACT_FILES)
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())

        dest = create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Simple intake ready for future draft prep only.",
        )

        artifact = json.loads(dest.read_text(encoding="utf-8"))
        self.assertEqual(artifact["decision"], "AUTHORIZE_DRAFT_PREPARATION")
        self.assertEqual(
            artifact["readiness_review_state_at_decision"],
            "OWNER_REVIEW_REQUIRED",
        )
        created_names = {path.name for path in self.project.rglob("*") if path.is_file()}
        self.assertTrue(forbidden_names.isdisjoint(created_names))
        self.assertFalse((self.project / ".agent-os" / "planning").exists())
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("PLANNING_RUN_SLICE", combined)
        self.assertEqual(before_runs, list((workspace / "runs").iterdir()))

    def test_authorize_draft_preparation_blocked_when_clarification_structurally_invalid(
        self,
    ) -> None:
        intake_id = "slither-demo"
        artifact_path = self._create_slither_intake(intake_id)
        intake_original = artifact_path.read_text(encoding="utf-8")
        clarification_path = self._clarification_path(intake_id, "broken")
        clarification_path.parent.mkdir(parents=True, exist_ok=True)
        clarification_path.write_text("{not-json", encoding="utf-8")
        clarification_original = clarification_path.read_text(encoding="utf-8")
        before = self._project_files()

        with self.assertRaises(ValueError) as ctx:
            create_owner_readiness_decision(
                self.project,
                intake_id,
                "owner-v1",
                "AUTHORIZE_DRAFT_PREPARATION",
                "Should not authorize.",
            )
        self.assertIn("AUTHORIZE_DRAFT_PREPARATION is not allowed", str(ctx.exception))
        self.assertIn("BLOCKED_INVALID_INTAKE", str(ctx.exception))
        self.assertFalse(self._decision_path(intake_id, "owner-v1").exists())
        self.assertEqual(intake_original, artifact_path.read_text(encoding="utf-8"))
        self.assertEqual(
            clarification_original,
            clarification_path.read_text(encoding="utf-8"),
        )
        self.assertEqual(before, self._project_files())

    def test_orchestrator_status_reports_latest_readiness_decision_read_only(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._slither_with_clarification(intake_id)
        artifact_path = self._artifact_path(intake_id)
        original_intake = artifact_path.read_text(encoding="utf-8")
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Future draft only.",
        )
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "status", intake_id, str(self.project)])

        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("owner_readiness_decisions: 1", output)
        self.assertIn("latest_readiness_decision_id: owner-v1", output)
        self.assertIn(
            "latest_readiness_decision: AUTHORIZE_DRAFT_PREPARATION",
            output,
        )
        self.assertIn("they do not generate a planning draft", output)
        self.assertEqual(original_intake, artifact_path.read_text(encoding="utf-8"))
        self.assertEqual(before, self._project_files())


class OrchestratorDraftPreparationPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(
            self.project,
            intake_id,
            clarification_id,
        )

    def _decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(
            self.project,
            intake_id,
            decision_id,
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _create_simple_intake(self, intake_id: str = "fix-login") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Fix the login timeout bug in the auth module",
        )

    def _write_artifact(self, intake_id: str, artifact: dict) -> Path:
        path = self._artifact_path(intake_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        return path

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _slither_with_clarification(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max; no persistence.",
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._slither_with_clarification(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def test_draft_preflight_confirmed_when_latest_authorize_coherent(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "draft-preflight", intake_id, str(self.project)])

        self.assertEqual(code, 0)
        output = buf.getvalue()
        report = preflight_draft_preparation(self.project, intake_id)
        self.assertEqual(
            report.preflight_state,
            "DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED",
        )
        self.assertEqual(
            report.next_required_action,
            "FUTURE_DRAFT_PREPARATION_STEP_REQUIRES_SEPARATE_COMMAND",
        )
        self.assertIn(
            "preflight_state: DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED",
            output,
        )
        self.assertIn(
            "next_required_action: FUTURE_DRAFT_PREPARATION_STEP_REQUIRES_SEPARATE_COMMAND",
            output,
        )
        self.assertIn("latest_decision: AUTHORIZE_DRAFT_PREPARATION", output)

    def test_draft_preflight_blocked_without_readiness_decisions(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)

        report = preflight_draft_preparation(self.project, intake_id)
        self.assertEqual(report.preflight_state, "BLOCKED_NO_READINESS_DECISION")
        self.assertEqual(report.next_required_action, "ADD_OWNER_READINESS_DECISION")

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "draft-preflight", intake_id, str(self.project)])
        self.assertEqual(code, 1)
        self.assertIn("preflight_state: BLOCKED_NO_READINESS_DECISION", buf.getvalue())
        self.assertIn("next_required_action: ADD_OWNER_READINESS_DECISION", buf.getvalue())

    def test_draft_preflight_blocked_when_latest_requests_clarification(self) -> None:
        intake_id = "slither-demo"
        self._create_slither_intake(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "REQUEST_MORE_CLARIFICATION",
            "Need more scope detail.",
        )

        report = preflight_draft_preparation(self.project, intake_id)
        self.assertEqual(
            report.preflight_state,
            "BLOCKED_LATEST_DECISION_REQUESTS_CLARIFICATION",
        )
        self.assertEqual(report.next_required_action, "ADD_OWNER_CLARIFICATION")

    def test_draft_preflight_blocked_when_latest_blocks_intake(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "Stopping intake.",
        )

        report = preflight_draft_preparation(self.project, intake_id)
        self.assertEqual(
            report.preflight_state,
            "BLOCKED_LATEST_DECISION_BLOCKS_INTAKE",
        )
        self.assertEqual(report.next_required_action, "STOP_INTAKE")

    def test_draft_preflight_more_recent_block_overrides_older_authorize(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "BLOCK_INTAKE",
            "Changed mind; stop intake.",
        )

        report = preflight_draft_preparation(self.project, intake_id)
        self.assertEqual(
            report.preflight_state,
            "BLOCKED_LATEST_DECISION_BLOCKS_INTAKE",
        )
        self.assertEqual(report.latest_decision_id, "owner-v2")

    def test_draft_preflight_more_recent_clarification_overrides_older_authorize(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        artifact_path = self._artifact_path(intake_id)
        clarification_path = self._clarification_path(intake_id, "scope-v1")
        decision_path_v1 = self._decision_path(intake_id, "owner-v1")
        original_intake = artifact_path.read_bytes()
        original_clarification = clarification_path.read_bytes()
        original_decision_v1 = decision_path_v1.read_bytes()

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "REQUEST_MORE_CLARIFICATION",
            "Need updated scope constraints.",
        )
        decision_path_v2 = self._decision_path(intake_id, "owner-v2")
        original_decision_v2 = decision_path_v2.read_bytes()
        before_files = self._project_files()
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        forbidden_names = set(planning_module.PLANNING_ARTIFACT_FILES)

        report = preflight_draft_preparation(self.project, intake_id)
        self.assertEqual(
            report.preflight_state,
            "BLOCKED_LATEST_DECISION_REQUESTS_CLARIFICATION",
        )
        self.assertEqual(report.next_required_action, "ADD_OWNER_CLARIFICATION")
        self.assertEqual(report.latest_decision_id, "owner-v2")
        self.assertEqual(report.latest_decision, "REQUEST_MORE_CLARIFICATION")
        self.assertNotEqual(
            report.preflight_state,
            "DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED",
        )

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "draft-preflight", intake_id, str(self.project)])
        self.assertEqual(code, 1)
        output = buf.getvalue()
        self.assertIn(
            "preflight_state: BLOCKED_LATEST_DECISION_REQUESTS_CLARIFICATION",
            output,
        )
        self.assertIn("next_required_action: ADD_OWNER_CLARIFICATION", output)
        self.assertIn("latest_decision: REQUEST_MORE_CLARIFICATION", output)
        self.assertNotIn(
            "DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED",
            output,
        )

        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            main(["orchestrator", "draft-preflight", intake_id, str(self.project)])

        self.assertEqual(original_intake, artifact_path.read_bytes())
        self.assertEqual(original_clarification, clarification_path.read_bytes())
        self.assertEqual(original_decision_v1, decision_path_v1.read_bytes())
        self.assertEqual(original_decision_v2, decision_path_v2.read_bytes())
        self.assertEqual(before_files, self._project_files())

        created_names = {path.name for path in self.project.rglob("*") if path.is_file()}
        self.assertTrue(forbidden_names.isdisjoint(created_names))
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("PLANNING_RUN_SLICE", combined)
        self.assertEqual(before_runs, list((workspace / "runs").iterdir()))

    def test_draft_preflight_blocked_when_authorization_snapshot_stale(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v2",
            "Add websocket transport requirement.",
        )

        report = preflight_draft_preparation(self.project, intake_id)
        self.assertEqual(
            report.preflight_state,
            "BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT",
        )
        self.assertEqual(
            report.next_required_action,
            "RESOLVE_OR_REPLACE_READINESS_DECISION",
        )

    def test_draft_preflight_blocked_on_invalid_readiness_decision(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        artifact = build_owner_readiness_decision_artifact(
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "Stop.",
            readiness_review_state_at_decision="OWNER_REVIEW_REQUIRED",
            next_required_action_at_decision="OWNER_READINESS_DECISION_REQUIRED",
            owner_clarification_count_at_decision=0,
            latest_clarification_id_at_decision=None,
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        path = self._decision_path(intake_id, "owner-v1")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        report = preflight_draft_preparation(self.project, intake_id)
        self.assertEqual(report.preflight_state, "BLOCKED_INVALID_READINESS_DECISION")
        self.assertEqual(
            report.next_required_action,
            "RESOLVE_OR_REPLACE_READINESS_DECISION",
        )

    def test_draft_preflight_missing_workspace_fails_without_orchestrator_tree(
        self,
    ) -> None:
        bare = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(FileNotFoundError):
                preflight_draft_preparation(bare, "slither-demo")
            buf = io.StringIO()
            with redirect_stderr(buf):
                code = main(
                    ["orchestrator", "draft-preflight", "slither-demo", str(bare)]
                )
            self.assertEqual(code, 1)
            self.assertIn("no workspace found", buf.getvalue())
            self.assertFalse((bare / ".agent-os" / "orchestrator").exists())
        finally:
            import shutil

            shutil.rmtree(bare)

    def test_draft_preflight_missing_intake_fails_without_creating_files(self) -> None:
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-preflight",
                    "missing-intake",
                    str(self.project),
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("goal intake artifact not found", buf.getvalue())
        self.assertFalse(
            (
                self.project
                / ".agent-os"
                / "orchestrator"
                / "intakes"
                / "missing-intake"
            ).exists()
        )

    def test_draft_preflight_invalid_intake_blocked_without_writing_files(self) -> None:
        intake_id = "invalid-preflight"
        artifact = build_goal_intake_artifact(
            intake_id,
            "Build a game",
            created_at="2026-07-06T10:00:00+00:00",
        )
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        self._write_artifact(intake_id, artifact)
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "draft-preflight", intake_id, str(self.project)])

        self.assertEqual(code, 1)
        self.assertIn("preflight_state: BLOCKED_INVALID_INTAKE", buf.getvalue())
        self.assertIn("next_required_action: FIX_GOAL_INTAKE_STRUCTURE", buf.getvalue())
        self.assertEqual(before, self._project_files())

    def test_draft_preflight_preserves_goal_intake_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        artifact_path = self._artifact_path(intake_id)
        original = artifact_path.read_bytes()

        preflight_draft_preparation(self.project, intake_id)
        main(["orchestrator", "draft-preflight", intake_id, str(self.project)])

        self.assertEqual(original, artifact_path.read_bytes())

    def test_draft_preflight_preserves_clarification_artifacts_byte_for_byte(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        clarification_path = self._clarification_path(intake_id, "scope-v1")
        original = clarification_path.read_bytes()

        preflight_draft_preparation(self.project, intake_id)

        self.assertEqual(original, clarification_path.read_bytes())

    def test_draft_preflight_preserves_readiness_decision_artifacts_byte_for_byte(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        decision_path = self._decision_path(intake_id, "owner-v1")
        original = decision_path.read_bytes()

        preflight_draft_preparation(self.project, intake_id)

        self.assertEqual(original, decision_path.read_bytes())

    def test_draft_preflight_does_not_change_planning_readiness(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        artifact_path = self._artifact_path(intake_id)
        before = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]

        preflight_draft_preparation(self.project, intake_id)

        after = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]
        self.assertEqual(before, after)

    def test_draft_preflight_includes_all_required_non_authority_flags(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)

        report = preflight_draft_preparation(self.project, intake_id)
        for flag in DRAFT_PREPARATION_PREFLIGHT_NON_AUTHORITY_FLAGS:
            self.assertTrue(report.non_authority[flag])
        for flag in DRAFT_PREPARATION_PREFLIGHT_NON_AUTHORITY_FLAGS:
            self.assertIn(f"{flag}: true", report.output)

    def test_draft_preflight_does_not_emit_draft_allowed_states(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)

        report = preflight_draft_preparation(self.project, intake_id)
        self.assertNotIn(report.preflight_state, {"DRAFT_ALLOWED", "READY_FOR_DRAFT"})
        self.assertNotIn("preflight_state: DRAFT_ALLOWED", report.output)
        self.assertNotIn("preflight_state: READY_FOR_DRAFT", report.output)

    def test_draft_preflight_does_not_create_planning_artifacts(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        forbidden_names = set(planning_module.PLANNING_ARTIFACT_FILES)

        preflight_draft_preparation(self.project, intake_id)

        created_names = {path.name for path in self.project.rglob("*") if path.is_file()}
        self.assertTrue(forbidden_names.isdisjoint(created_names))

    def test_draft_preflight_does_not_create_planning_run_slice(self) -> None:
        intake_id = "fix-login"
        self._create_simple_intake(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Future draft only.",
        )

        preflight_draft_preparation(self.project, intake_id)
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("PLANNING_RUN_SLICE", combined)

    def test_draft_preflight_does_not_create_runs(self) -> None:
        intake_id = "fix-login"
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        self._create_simple_intake(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Future draft only.",
        )

        preflight_draft_preparation(self.project, intake_id)

        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_draft_preflight_does_not_invoke_external_subprocess(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)

        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code = main(
                ["orchestrator", "draft-preflight", intake_id, str(self.project)]
            )
        self.assertEqual(code, 0)

    def test_orchestrator_draft_preflight_cli_help_marks_read_only(self) -> None:
        parser = build_parser()
        orchestrator_action = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        orchestrator_parser = orchestrator_action.choices["orchestrator"]
        orchestrator_sub = next(
            action
            for action in orchestrator_parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )

        help_text = orchestrator_sub.choices["draft-preflight"].format_help()
        compact_help = re.sub(r"\s+", " ", help_text)
        self.assertIn("read-only", compact_help.lower())
        self.assertIn("No draft generation occurs", compact_help)

    def test_orchestrator_draft_preflight_cli_output_includes_boundary_notes(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "draft-preflight", intake_id, str(self.project)])

        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("preflight_state:", output)
        self.assertIn("next_required_action:", output)
        self.assertIn("latest_decision: AUTHORIZE_DRAFT_PREPARATION", output)
        self.assertIn("draft-preparation preflight is read-only", output)
        self.assertIn("no planning draft was generated", output)
        self.assertNotIn("planning draft was created", output.lower())

    def test_orchestrator_validate_unchanged_without_readiness_decision_requirement(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)

        report = validate_goal_intake(self.project, intake_id)
        self.assertTrue(report.valid)

    def test_orchestrator_readiness_unchanged_and_read_only_after_preflight_slice(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "readiness", intake_id, str(self.project)])

        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("readiness review is read-only", output)
        self.assertEqual(before, self._project_files())

    def test_orchestrator_status_unchanged_and_read_only_after_preflight_slice(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        artifact_path = self._artifact_path(intake_id)
        original_intake = artifact_path.read_text(encoding="utf-8")
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["orchestrator", "status", intake_id, str(self.project)])

        self.assertEqual(code, 0)
        output = buf.getvalue()
        self.assertIn("read-only inspection", output)
        self.assertIn("no planning draft was created", output)
        self.assertEqual(original_intake, artifact_path.read_text(encoding="utf-8"))
        self.assertEqual(before, self._project_files())

    def test_no_existing_command_gained_draft_generation_after_preflight_slice(
        self,
    ) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        decide_intake_id = "fix-login"
        self._create_simple_intake(decide_intake_id)
        forbidden_names = set(planning_module.PLANNING_ARTIFACT_FILES)

        main(["orchestrator", "status", intake_id, str(self.project)])
        main(["orchestrator", "validate", intake_id, str(self.project)])
        main(["orchestrator", "readiness", intake_id, str(self.project)])
        main(
            [
                "orchestrator",
                "decide-readiness",
                decide_intake_id,
                str(self.project),
                "--decision",
                "BLOCK_INTAKE",
                "--decision-id",
                "owner-v1",
                "--summary",
                "Regression sweep only.",
            ]
        )

        created_names = {path.name for path in self.project.rglob("*") if path.is_file()}
        self.assertTrue(forbidden_names.isdisjoint(created_names))


def _implementation_plan_without_created_at(content: str) -> str:
    """Normalize implementation-plan frontmatter for substance-only comparisons."""
    return re.sub(r"^created_at: .+$", "created_at: NORMALIZED", content, flags=re.MULTILINE)


class OrchestratorPreparePlanningDraftTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(
            self.project,
            intake_id,
            clarification_id,
        )

    def _decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(
            self.project,
            intake_id,
            decision_id,
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _create_simple_intake(self, intake_id: str = "fix-login") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Fix the login timeout bug in the auth module",
        )

    def _write_artifact(self, intake_id: str, artifact: dict) -> Path:
        path = self._artifact_path(intake_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        return path

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _slither_with_clarification(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max; no persistence.",
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._slither_with_clarification(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _prepare(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def test_creates_scaffold_only_when_preflight_confirmed(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)

        code, output = self._prepare(intake_id, plan_id)
        self.assertEqual(code, 0)
        self.assertTrue(planning_path(self.project, plan_id).is_dir())
        self.assertIn("planning workspace draft scaffold created:", output)

    def test_created_workspace_is_draft_state(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)

        manifest = json.loads(
            (planning_path(self.project, plan_id) / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(manifest["status"], "DRAFT")

    def test_created_workspace_includes_orchestrator_provenance(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)

        provenance_path = (
            planning_path(self.project, plan_id)
            / "evidence"
            / "orchestrator-provenance.json"
        )
        self.assertTrue(provenance_path.is_file())

    def test_provenance_contains_required_fields(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)

        provenance = json.loads(
            (
                planning_path(self.project, plan_id)
                / "evidence"
                / "orchestrator-provenance.json"
            ).read_text(encoding="utf-8")
        )
        required_fields = (
            "artifact_type",
            "schema_version",
            "plan_id",
            "intake_id",
            "source_goal_intake_path",
            "source_preflight_state",
            "source_authorize_decision_id",
            "source_authorize_decision_value",
            "source_readiness_review_state",
            "source_next_required_action",
            "owner_clarification_count",
            "latest_clarification_id",
            "created_at",
            "non_authority",
        )
        for field in required_fields:
            self.assertIn(field, provenance, f"missing provenance field: {field}")
        self.assertEqual(provenance["artifact_type"], "ORCHESTRATOR_PLANNING_DRAFT_SOURCE")
        self.assertEqual(provenance["schema_version"], "0.1")
        self.assertEqual(provenance["plan_id"], plan_id)
        self.assertEqual(provenance["intake_id"], intake_id)

    def test_provenance_non_authority_flags_all_true(self) -> None:
        from agent_os.orchestrator import (
            ORCHESTRATOR_PLANNING_DRAFT_SOURCE_NON_AUTHORITY_FLAGS,
        )

        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)

        provenance = json.loads(
            (
                planning_path(self.project, plan_id)
                / "evidence"
                / "orchestrator-provenance.json"
            ).read_text(encoding="utf-8")
        )
        non_authority = provenance["non_authority"]
        for flag in ORCHESTRATOR_PLANNING_DRAFT_SOURCE_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, non_authority)
            self.assertTrue(non_authority[flag])

    def test_provenance_references_intake_and_authorize_decision(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)

        provenance = json.loads(
            (
                planning_path(self.project, plan_id)
                / "evidence"
                / "orchestrator-provenance.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(provenance["intake_id"], intake_id)
        self.assertEqual(provenance["source_authorize_decision_id"], "owner-v1")
        self.assertEqual(
            provenance["source_authorize_decision_value"],
            "AUTHORIZE_DRAFT_PREPARATION",
        )

    def test_refuses_when_preflight_not_confirmed(self) -> None:
        intake_id = "fix-login"
        plan_id = "fix-login-plan"
        self._create_simple_intake(intake_id)
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("draft-preparation preflight not confirmed", buf.getvalue())
        self.assertFalse(planning_path(self.project, plan_id).exists())
        self.assertEqual(before, self._project_files())

    def test_refuses_when_latest_decision_requests_clarification(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._create_slither_intake(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "REQUEST_MORE_CLARIFICATION",
            "Need more scope detail.",
        )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(planning_path(self.project, plan_id).exists())

    def test_refuses_when_latest_decision_blocks_intake(self) -> None:
        intake_id = "fix-login"
        plan_id = "fix-login-plan"
        self._create_simple_intake(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "BLOCK_INTAKE",
            "Stopping intake.",
        )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(planning_path(self.project, plan_id).exists())

    def test_refuses_when_authorization_stale(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v2",
            "Updated scope after authorization.",
        )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(planning_path(self.project, plan_id).exists())

    def test_refuses_missing_workspace_without_orchestrator_tree(self) -> None:
        bare = self.project / "bare"
        bare.mkdir()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    "slither-demo",
                    str(bare),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse((bare / ".agent-os").exists())

    def test_refuses_missing_intake_without_planning_workspace(self) -> None:
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    "missing-intake",
                    str(self.project),
                    "--plan-id",
                    "orphan-plan",
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(planning_path(self.project, "orphan-plan").exists())

    def test_refuses_invalid_intake_without_planning_workspace(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        path = self._create_slither_intake(intake_id)
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact["artifact_type"] = "WRONG_TYPE"
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(planning_path(self.project, plan_id).exists())

    def test_refuses_invalid_plan_id(self) -> None:
        self._authorize_slither()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "../escape",
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(planning_path(self.project, "../escape").exists())

    def test_refuses_existing_planning_workspace(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        init_planning_workspace(self.project, plan_id)
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("already exists", buf.getvalue())
        self.assertEqual(before, self._project_files())

    def test_preserves_goal_intake_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        artifact_path = self._artifact_path(intake_id)
        original = artifact_path.read_bytes()

        self._prepare(intake_id)

        self.assertEqual(original, artifact_path.read_bytes())

    def test_preserves_clarification_artifacts_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        clarification_path = self._clarification_path(intake_id, "scope-v1")
        original = clarification_path.read_bytes()

        self._prepare(intake_id)

        self.assertEqual(original, clarification_path.read_bytes())

    def test_preserves_readiness_decision_artifacts_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        decision_path = self._decision_path(intake_id, "owner-v1")
        original = decision_path.read_bytes()

        self._prepare(intake_id)

        self.assertEqual(original, decision_path.read_bytes())

    def test_does_not_change_planning_readiness(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        artifact_path = self._artifact_path(intake_id)
        before = json.loads(artifact_path.read_text(encoding="utf-8"))[
            "planning_readiness"
        ]

        self._prepare(intake_id)

        after = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]
        self.assertEqual(before, after)

    def test_does_not_generate_architecture_choices(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)

        workspace = planning_path(self.project, plan_id)
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in workspace.rglob("*")
            if path.is_file()
        ).lower()
        for forbidden in (
            "backend:",
            "frontend:",
            "database:",
            "postgresql",
            "react",
            "kubernetes",
            "selected architecture",
            "chosen stack",
        ):
            self.assertNotIn(forbidden, combined)

    def test_does_not_generate_implementation_plan_beyond_placeholders(self) -> None:
        plan_id = "slither-plan-v1"
        baseline_id = "baseline-init-only"
        init_planning_workspace(self.project, baseline_id)
        self._authorize_slither()
        self._prepare(plan_id=plan_id)

        orchestrator_impl = (
            planning_path(self.project, plan_id) / "implementation-plan.md"
        ).read_text(encoding="utf-8")
        baseline_impl = (
            planning_path(self.project, baseline_id) / "implementation-plan.md"
        ).read_text(encoding="utf-8")
        self.assertIn("PLACEHOLDER", orchestrator_impl)
        # created_at differs across separate init_planning_workspace calls; compare
        # implementation-plan substance only, not per-workspace timestamps.
        self.assertEqual(
            _implementation_plan_without_created_at(
                orchestrator_impl.replace(plan_id, baseline_id)
            ),
            _implementation_plan_without_created_at(baseline_impl),
        )

    def test_does_not_generate_planning_run_slice(self) -> None:
        from agent_os.orchestrator import (
            ORCHESTRATOR_PLANNING_DRAFT_SOURCE_NON_AUTHORITY_FLAGS,
        )

        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)

        provenance = json.loads(
            (
                planning_path(self.project, plan_id)
                / "evidence"
                / "orchestrator-provenance.json"
            ).read_text(encoding="utf-8")
        )
        self.assertTrue(
            provenance["non_authority"]["does_not_generate_planning_run_slice"]
        )
        notes = (
            planning_path(self.project, plan_id)
            / "evidence"
            / "orchestrator-draft-scaffold-notes.md"
        ).read_text(encoding="utf-8")
        self.assertIn("PLANNING_RUN_SLICE", notes)
        self.assertIn("not generated", notes.lower())
        for flag in ORCHESTRATOR_PLANNING_DRAFT_SOURCE_NON_AUTHORITY_FLAGS:
            self.assertTrue(provenance["non_authority"][flag])

    def test_does_not_create_runner_proposals(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        before_runs = list((self.project / ".agent-os" / "runs").iterdir())

        self._prepare(plan_id=plan_id)

        after_runs = list((self.project / ".agent-os" / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_does_not_create_runs(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)

        runs_dir = self.project / ".agent-os" / "runs"
        self.assertEqual(list(runs_dir.iterdir()), [])

    def test_does_not_invoke_external_subprocess(self) -> None:
        self._authorize_slither()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 0)

    def test_does_not_call_planning_progress_transition_decide(self) -> None:
        self._authorize_slither()
        with (
            patch.object(
                planning_module,
                "progress_planning_workspace",
                side_effect=AssertionError("progress invoked"),
            ),
            patch.object(
                planning_module,
                "transition_planning_workspace",
                side_effect=AssertionError("transition invoked"),
            ),
            patch.object(
                planning_module,
                "record_planning_owner_decision",
                side_effect=AssertionError("decide invoked"),
            ),
        ):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 0)

    def test_draft_preflight_unchanged_and_read_only(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                ["orchestrator", "draft-preflight", intake_id, str(self.project)]
            )

        self.assertEqual(code, 0)
        self.assertIn("draft-preparation preflight is read-only", buf.getvalue())
        self.assertEqual(before, self._project_files())

    def test_validate_readiness_status_unchanged(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        before = self._project_files()

        validate_report = validate_goal_intake(self.project, intake_id)
        self.assertTrue(validate_report.valid)
        readiness_report = review_goal_intake_readiness(self.project, intake_id)
        self.assertTrue(readiness_report.goal_intake_valid)
        status_report = goal_intake_status(self.project, intake_id)
        self.assertTrue(status_report.validation_ok)
        self.assertEqual(before, self._project_files())

    def test_cli_help_states_draft_scaffold_boundaries(self) -> None:
        parser = build_parser()
        orchestrator_parser = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
            and "orchestrator" in action.choices
        )
        orchestrator_sub = next(
            action
            for action in orchestrator_parser.choices["orchestrator"]._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        help_text = orchestrator_sub.choices["prepare-planning-draft"].format_help()
        compact = re.sub(r"\s+", " ", help_text)
        self.assertIn("DRAFT", compact)
        self.assertIn("generate architecture", compact.lower())
        self.assertIn("PLANNING_RUN_SLICE", compact)
        self.assertIn("validate", compact.lower())
        self.assertIn("executor", compact.lower())

    def test_cli_output_includes_workspace_provenance_and_boundary_notes(
        self,
    ) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        code, output = self._prepare(plan_id=plan_id)

        self.assertEqual(code, 0)
        self.assertIn("planning workspace draft scaffold created:", output)
        self.assertIn("orchestrator provenance:", output)
        self.assertIn("no architecture generation", output)
        self.assertIn("no runner proposals", output)

    def test_created_workspace_does_not_claim_validation_or_approval(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)

        validation = validate_planning_workspace(self.project, plan_id)
        self.assertFalse(validation.valid)
        manifest = json.loads(
            (planning_path(self.project, plan_id) / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(manifest["status"], "DRAFT")
        self.assertFalse(manifest["gates"]["run_proposal_allowed"])

    def test_created_workspace_not_confusable_with_approved(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)

        manifest = json.loads(
            (planning_path(self.project, plan_id) / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertNotEqual(manifest["status"], "APPROVED_FOR_RUN_PROPOSALS")
        notes = (
            planning_path(self.project, plan_id)
            / "evidence"
            / "orchestrator-draft-scaffold-notes.md"
        ).read_text(encoding="utf-8")
        self.assertIn("not granted", notes.lower())
        self.assertIn("draft", notes.lower())

    def test_rolls_back_workspace_when_provenance_write_fails(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        existing_plan_id = "existing-plan-v1"
        self._authorize_slither(intake_id)
        init_planning_workspace(self.project, existing_plan_id)

        artifact_path = self._artifact_path(intake_id)
        goal_intake_bytes = artifact_path.read_bytes()
        clarification_bytes = self._clarification_path(intake_id, "scope-v1").read_bytes()
        decision_bytes = self._decision_path(intake_id, "owner-v1").read_bytes()
        before_files = self._project_files()
        runs_dir = self.project / ".agent-os" / "runs"
        before_runs = list(runs_dir.iterdir())

        def failing_provenance_write(path: Path, data: dict) -> None:
            self.assertTrue(
                planning_path(self.project, plan_id).is_dir(),
                "planning workspace init must complete before provenance write",
            )
            raise OSError("simulated provenance write failure")

        with (
            patch("subprocess.run", side_effect=AssertionError("subprocess invoked")),
            patch(
                "agent_os.orchestrator._write_json",
                side_effect=failing_provenance_write,
            ),
        ):
            with self.assertRaises(OSError) as ctx:
                prepare_planning_workspace_draft(self.project, intake_id, plan_id)
            self.assertIn("simulated provenance write failure", str(ctx.exception))

        self.assertFalse(planning_path(self.project, plan_id).exists())
        self.assertFalse(
            (
                planning_path(self.project, plan_id)
                / "evidence"
                / "orchestrator-provenance.json"
            ).exists()
        )
        self.assertTrue(planning_path(self.project, existing_plan_id).is_dir())
        self.assertEqual(before_files, self._project_files())
        self.assertEqual(goal_intake_bytes, artifact_path.read_bytes())
        self.assertEqual(
            clarification_bytes,
            self._clarification_path(intake_id, "scope-v1").read_bytes(),
        )
        self.assertEqual(
            decision_bytes,
            self._decision_path(intake_id, "owner-v1").read_bytes(),
        )
        self.assertEqual(before_runs, list(runs_dir.iterdir()))


class OrchestratorTransportPlanningContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(
            self.project,
            intake_id,
            clarification_id,
        )

    def _decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(
            self.project,
            intake_id,
            decision_id,
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _create_simple_intake(self, intake_id: str = "fix-login") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Fix the login timeout bug in the auth module",
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _slither_with_clarification(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max; no persistence.",
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._slither_with_clarification(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _prepare(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _transport(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _transport_json_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            planning_path(self.project, plan_id)
            / "evidence"
            / "orchestrator-context-transport.json"
        )

    def _transport_md_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            planning_path(self.project, plan_id)
            / "evidence"
            / "orchestrator-context-transport.md"
        )

    def _provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            planning_path(self.project, plan_id)
            / "evidence"
            / "orchestrator-provenance.json"
        )

    def test_succeeds_only_on_existing_draft_scaffold_from_confirmed_preflight(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        prepare_code, _ = self._prepare(intake_id, plan_id)
        self.assertEqual(prepare_code, 0)

        code, output = self._transport(intake_id, plan_id)
        self.assertEqual(code, 0)
        self.assertIn("orchestrator context transport created:", output)

    def test_json_context_transport_artifact_created(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)
        self.assertTrue(self._transport_json_path(plan_id).is_file())

    def test_markdown_context_transport_artifact_created(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)
        self.assertTrue(self._transport_md_path(plan_id).is_file())

    def test_json_contains_required_fields(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)

        artifact = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        required_fields = (
            "artifact_type",
            "schema_version",
            "plan_id",
            "intake_id",
            "source_goal_intake_path",
            "source_context",
            "owner_clarifications",
            "owner_readiness_decision",
            "draft_preflight",
            "planning_workspace",
            "created_at",
            "non_authority",
        )
        for field in required_fields:
            self.assertIn(field, artifact, f"missing field: {field}")
        self.assertEqual(artifact["artifact_type"], "ORCHESTRATOR_CONTEXT_TRANSPORT")
        self.assertEqual(artifact["schema_version"], "0.1")

    def test_json_non_authority_flags_all_true(self) -> None:
        from agent_os.orchestrator import (
            ORCHESTRATOR_CONTEXT_TRANSPORT_NON_AUTHORITY_FLAGS,
        )

        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)

        artifact = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        non_authority = artifact["non_authority"]
        for flag in ORCHESTRATOR_CONTEXT_TRANSPORT_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, non_authority)
            self.assertTrue(non_authority[flag])

    def test_raw_goal_copied_verbatim(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        raw_goal = "Build me an online slither.io-like game"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)

        artifact = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        markdown = self._transport_md_path(plan_id).read_text(encoding="utf-8")
        self.assertEqual(artifact["source_context"]["raw_goal"], raw_goal)
        self.assertIn(raw_goal, markdown)

    def test_owner_clarification_answers_copied_verbatim(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        answer = "Browser-only demo with 10 players max; no persistence."
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)

        artifact = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        markdown = self._transport_md_path(plan_id).read_text(encoding="utf-8")
        self.assertEqual(len(artifact["owner_clarifications"]), 1)
        self.assertEqual(artifact["owner_clarifications"][0]["owner_answer"], answer)
        self.assertIn(answer, markdown)

    def test_owner_readiness_decision_summary_copied_verbatim(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        summary = "Scope clarified; authorize future draft prep only."
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)

        artifact = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        markdown = self._transport_md_path(plan_id).read_text(encoding="utf-8")
        self.assertEqual(artifact["owner_readiness_decision"]["owner_summary"], summary)
        self.assertIn(summary, markdown)

    def test_draft_preflight_state_and_latest_decision_recorded(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)

        artifact = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        draft_preflight = artifact["draft_preflight"]
        self.assertEqual(
            draft_preflight["preflight_state"],
            "DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED",
        )
        self.assertEqual(draft_preflight["latest_decision_id"], "owner-v1")

    def test_planning_workspace_status_at_transport_is_draft(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)

        artifact = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        self.assertEqual(artifact["planning_workspace"]["status_at_transport"], "DRAFT")

    def test_refuses_missing_workspace(self) -> None:
        bare = self.project / "bare"
        bare.mkdir()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    "slither-demo",
                    str(bare),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse((bare / ".agent-os").exists())

    def test_refuses_missing_intake(self) -> None:
        plan_id = "orphan-plan"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    "missing-intake",
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(self._transport_json_path(plan_id).exists())

    def test_refuses_invalid_intake(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        path = self._artifact_path(intake_id)
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact["artifact_type"] = "WRONG_TYPE"
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(self._transport_json_path(plan_id).exists())

    def test_refuses_missing_planning_workspace(self) -> None:
        self._authorize_slither()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "missing-plan",
                ]
            )

        self.assertEqual(code, 1)

    def test_refuses_invalid_plan_id(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)

        artifact_path = self._artifact_path(intake_id)
        goal_intake_bytes = artifact_path.read_bytes()
        clarification_bytes = self._clarification_path(intake_id, "scope-v1").read_bytes()
        decision_bytes = self._decision_path(intake_id, "owner-v1").read_bytes()
        workspace = planning_path(self.project, plan_id)
        template_paths = (
            workspace / "context-pack.md",
            workspace / "local-agentic-spec.md",
            workspace / "implementation-plan.md",
            workspace / "planning-audit.md",
        )
        template_bytes = {path: path.read_bytes() for path in template_paths}
        before_files = self._project_files()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    "../escape",
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("invalid plan id", buf.getvalue())
        self.assertFalse(self._transport_json_path(plan_id).exists())
        self.assertFalse(self._transport_md_path(plan_id).exists())
        self.assertFalse(planning_path(self.project, "../escape").exists())
        self.assertEqual(before_files, self._project_files())
        self.assertEqual(goal_intake_bytes, artifact_path.read_bytes())
        self.assertEqual(
            clarification_bytes,
            self._clarification_path(intake_id, "scope-v1").read_bytes(),
        )
        self.assertEqual(
            decision_bytes,
            self._decision_path(intake_id, "owner-v1").read_bytes(),
        )
        for path, original in template_bytes.items():
            self.assertEqual(original, path.read_bytes(), msg=str(path))

    def test_refuses_path_escape_intake_id(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)

        artifact_path = self._artifact_path(intake_id)
        goal_intake_bytes = artifact_path.read_bytes()
        clarification_bytes = self._clarification_path(intake_id, "scope-v1").read_bytes()
        decision_bytes = self._decision_path(intake_id, "owner-v1").read_bytes()
        workspace = planning_path(self.project, plan_id)
        provenance_bytes = self._provenance_path(plan_id).read_bytes()
        template_paths = (
            workspace / "context-pack.md",
            workspace / "local-agentic-spec.md",
            workspace / "implementation-plan.md",
            workspace / "planning-audit.md",
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
        )
        template_bytes = {path: path.read_bytes() for path in template_paths}
        before_files = self._project_files()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    "../escape",
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("invalid intake id", buf.getvalue())
        self.assertFalse(self._transport_json_path(plan_id).exists())
        self.assertFalse(self._transport_md_path(plan_id).exists())
        self.assertFalse(
            (self.project / ".agent-os" / "orchestrator" / "intakes" / "escape").exists()
        )
        self.assertEqual(before_files, self._project_files())
        self.assertEqual(goal_intake_bytes, artifact_path.read_bytes())
        self.assertEqual(
            clarification_bytes,
            self._clarification_path(intake_id, "scope-v1").read_bytes(),
        )
        self.assertEqual(
            decision_bytes,
            self._decision_path(intake_id, "owner-v1").read_bytes(),
        )
        self.assertEqual(provenance_bytes, self._provenance_path(plan_id).read_bytes())
        for path, original in template_bytes.items():
            self.assertEqual(original, path.read_bytes(), msg=str(path))

    def test_refuses_non_draft_planning_workspace(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        manifest_path = planning_path(self.project, plan_id) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["status"] = "CONTEXT_READY"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(self._transport_json_path(plan_id).exists())

    def test_refuses_missing_orchestrator_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        init_planning_workspace(self.project, plan_id)

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(self._transport_json_path(plan_id).exists())

    def test_refuses_provenance_intake_plan_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        provenance = json.loads(
            self._provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["plan_id"] = "wrong-plan"
        self._provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(self._transport_json_path(plan_id).exists())

    def test_refuses_provenance_intake_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        provenance_path = self._provenance_path(plan_id)
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        self.assertEqual(provenance["plan_id"], plan_id)
        self.assertEqual(provenance["intake_id"], intake_id)
        provenance["intake_id"] = "wrong-intake"
        provenance_path.write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )
        provenance_bytes = provenance_path.read_bytes()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("intake_id mismatch", buf.getvalue())
        self.assertFalse(self._transport_json_path(plan_id).exists())
        self.assertFalse(self._transport_md_path(plan_id).exists())
        self.assertEqual(provenance_bytes, provenance_path.read_bytes())

    def test_refuses_stale_incoherent_authorization(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v2",
            "Updated scope after authorization.",
        )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(self._transport_json_path(plan_id).exists())

    def test_refuses_latest_request_more_clarification_after_older_authorize(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "REQUEST_MORE_CLARIFICATION",
            "Need more scope detail.",
        )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(self._transport_json_path(plan_id).exists())

    def test_refuses_latest_block_intake_after_older_authorize(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "BLOCK_INTAKE",
            "Stopping intake.",
        )

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertFalse(self._transport_json_path(plan_id).exists())

    def test_refuses_existing_context_transport_artifacts(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)
        json_bytes = self._transport_json_path(plan_id).read_bytes()
        md_bytes = self._transport_md_path(plan_id).read_bytes()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("already exist", buf.getvalue())
        self.assertEqual(json_bytes, self._transport_json_path(plan_id).read_bytes())
        self.assertEqual(md_bytes, self._transport_md_path(plan_id).read_bytes())

    def test_preserves_goal_intake_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        self._prepare(intake_id)
        artifact_path = self._artifact_path(intake_id)
        original = artifact_path.read_bytes()

        self._transport(intake_id)

        self.assertEqual(original, artifact_path.read_bytes())

    def test_preserves_clarification_artifacts_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        self._prepare(intake_id)
        clarification_path = self._clarification_path(intake_id, "scope-v1")
        original = clarification_path.read_bytes()

        self._transport(intake_id)

        self.assertEqual(original, clarification_path.read_bytes())

    def test_preserves_readiness_decision_artifacts_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        self._prepare(intake_id)
        decision_path = self._decision_path(intake_id, "owner-v1")
        original = decision_path.read_bytes()

        self._transport(intake_id)

        self.assertEqual(original, decision_path.read_bytes())

    def test_preserves_orchestrator_provenance_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        provenance_path = self._provenance_path(plan_id)
        original = provenance_path.read_bytes()

        self._transport(plan_id=plan_id)

        self.assertEqual(original, provenance_path.read_bytes())

    def test_preserves_orchestrator_draft_scaffold_notes_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        notes_path = (
            planning_path(self.project, plan_id)
            / "evidence"
            / "orchestrator-draft-scaffold-notes.md"
        )
        original = notes_path.read_bytes()

        self._transport(plan_id=plan_id)

        self.assertEqual(original, notes_path.read_bytes())

    def test_does_not_mutate_context_pack(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        context_pack = planning_path(self.project, plan_id) / "context-pack.md"
        original = context_pack.read_bytes()

        self._transport(plan_id=plan_id)

        self.assertEqual(original, context_pack.read_bytes())

    def test_does_not_mutate_local_agentic_spec(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        spec_path = planning_path(self.project, plan_id) / "local-agentic-spec.md"
        original = spec_path.read_bytes()

        self._transport(plan_id=plan_id)

        self.assertEqual(original, spec_path.read_bytes())

    def test_does_not_mutate_implementation_plan(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        impl_path = planning_path(self.project, plan_id) / "implementation-plan.md"
        original = impl_path.read_bytes()

        self._transport(plan_id=plan_id)

        self.assertEqual(original, impl_path.read_bytes())

    def test_does_not_mutate_planning_audit(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        audit_path = planning_path(self.project, plan_id) / "planning-audit.md"
        original = audit_path.read_bytes()

        self._transport(plan_id=plan_id)

        self.assertEqual(original, audit_path.read_bytes())

    def test_does_not_change_planning_workspace_status(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        manifest_path = planning_path(self.project, plan_id) / "manifest.json"
        before = json.loads(manifest_path.read_text(encoding="utf-8"))["status"]

        self._transport(plan_id=plan_id)

        after = json.loads(manifest_path.read_text(encoding="utf-8"))["status"]
        self.assertEqual(before, after)
        self.assertEqual(after, "DRAFT")

    def test_does_not_generate_architecture_choices(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)

        transport_md = self._transport_md_path(plan_id).read_text(encoding="utf-8").lower()
        for forbidden in (
            "backend:",
            "frontend:",
            "database:",
            "postgresql",
            "react",
            "kubernetes",
            "selected architecture",
            "chosen stack",
        ):
            self.assertNotIn(forbidden, transport_md)

    def test_does_not_generate_implementation_tasks(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)

        transport_json = self._transport_json_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn("PLANNING_RUN_SLICE", transport_json)
        transport_md = self._transport_md_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertIn("implementation plan", transport_md)
        self.assertIn("not generated", transport_md)

    def test_does_not_generate_planning_run_slice(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)

        artifact = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        self.assertTrue(
            artifact["non_authority"]["does_not_generate_planning_run_slice"]
        )
        markdown = self._transport_md_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("PLANNING_RUN_SLICE", markdown)
        self.assertIn("not generated", markdown.lower())

    def test_does_not_create_runner_proposals(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        before_runs = list((self.project / ".agent-os" / "runs").iterdir())

        self._transport(plan_id=plan_id)

        after_runs = list((self.project / ".agent-os" / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_does_not_create_runs(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)

        runs_dir = self.project / ".agent-os" / "runs"
        self.assertEqual(list(runs_dir.iterdir()), [])

    def test_does_not_invoke_external_subprocess(self) -> None:
        self._authorize_slither()
        self._prepare()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 0)

    def test_does_not_call_planning_progress_transition_decide(self) -> None:
        self._authorize_slither()
        self._prepare()
        with (
            patch.object(
                planning_module,
                "progress_planning_workspace",
                side_effect=AssertionError("progress invoked"),
            ),
            patch.object(
                planning_module,
                "transition_planning_workspace",
                side_effect=AssertionError("transition invoked"),
            ),
            patch.object(
                planning_module,
                "record_planning_owner_decision",
                side_effect=AssertionError("decide invoked"),
            ),
        ):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 0)

    def test_cleans_up_json_when_markdown_write_fails(self) -> None:
        from agent_os.orchestrator import transport_planning_context

        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        json_path = self._transport_json_path(plan_id)
        md_path = self._transport_md_path(plan_id)

        original_write_text = Path.write_text

        def failing_markdown_write(self_path: Path, *args, **kwargs) -> int:
            if self_path == md_path:
                raise OSError("simulated markdown write failure")
            return original_write_text(self_path, *args, **kwargs)

        with patch.object(Path, "write_text", failing_markdown_write):
            with self.assertRaises(OSError) as ctx:
                transport_planning_context(self.project, intake_id, plan_id)
            self.assertIn("simulated markdown write failure", str(ctx.exception))

        self.assertFalse(json_path.exists())
        self.assertFalse(md_path.exists())

    def test_cli_help_states_context_transport_boundaries(self) -> None:
        parser = build_parser()
        orchestrator_parser = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
            and "orchestrator" in action.choices
        )
        orchestrator_sub = next(
            action
            for action in orchestrator_parser.choices["orchestrator"]._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        help_text = orchestrator_sub.choices[
            "transport-planning-context"
        ].format_help()
        compact = re.sub(r"\s+", " ", help_text)
        self.assertIn("context transport", compact.lower())
        self.assertIn("architecture", compact.lower())
        self.assertIn("implementation plan", compact.lower())
        self.assertIn("PLANNING_RUN_SLICE", compact)
        self.assertIn("validate", compact.lower())
        self.assertIn("executor", compact.lower())

    def test_cli_output_includes_paths_status_and_boundary_notes(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        code, output = self._transport(plan_id=plan_id)

        self.assertEqual(code, 0)
        self.assertIn("context transport json:", output)
        self.assertIn("context transport markdown:", output)
        self.assertIn("workspace_status: DRAFT", output)
        self.assertIn("no architecture generation", output)
        self.assertIn("no runner proposals", output)

    def test_existing_commands_unchanged(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        self._prepare(intake_id)
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            preflight_code = main(
                ["orchestrator", "draft-preflight", intake_id, str(self.project)]
            )
        self.assertEqual(preflight_code, 0)
        self.assertIn("draft-preparation preflight is read-only", buf.getvalue())

        validate_report = validate_goal_intake(self.project, intake_id)
        self.assertTrue(validate_report.valid)
        readiness_report = review_goal_intake_readiness(self.project, intake_id)
        self.assertTrue(readiness_report.goal_intake_valid)
        status_report = goal_intake_status(self.project, intake_id)
        self.assertTrue(status_report.validation_ok)
        self.assertEqual(before, self._project_files())

    def test_context_transport_not_confusable_with_approval(self) -> None:
        plan_id = "slither-plan-v1"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)

        markdown = self._transport_md_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertIn("not authority", markdown)
        self.assertIn("not validated or approved", markdown)
        self.assertIn("source material only", markdown)
        validation = validate_planning_workspace(self.project, plan_id)
        self.assertFalse(validation.valid)


class OrchestratorDraftContextPackTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(
            self.project,
            intake_id,
            clarification_id,
        )

    def _decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(
            self.project,
            intake_id,
            decision_id,
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _slither_with_clarification(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max; no persistence.",
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._slither_with_clarification(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _prepare(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _transport(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _draft(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-pack-draft-provenance.json"
        )

    def _transport_json_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-transport.json"
        )

    def _transport_md_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-transport.md"
        )

    def _provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-provenance.json"
        )

    def _setup_ready_for_draft(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)

    def test_succeeds_only_when_draft_workspace_has_matching_transport(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)

        code, output = self._draft(intake_id, plan_id)
        self.assertEqual(code, 0)
        self.assertIn("orchestrator context pack draft created:", output)

    def test_context_pack_md_is_drafted(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        before = self._context_pack_path(plan_id).read_bytes()

        self._draft(plan_id=plan_id)

        after = self._context_pack_path(plan_id).read_text(encoding="utf-8")
        self.assertNotEqual(before, after.encode("utf-8"))
        self.assertIn("DRAFT", after)

    def test_context_pack_draft_provenance_created(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)
        self.assertTrue(self._draft_provenance_path(plan_id).is_file())

    def test_provenance_contains_required_fields(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        self._draft(intake_id, plan_id)

        artifact = json.loads(
            self._draft_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        required_fields = (
            "artifact_type",
            "schema_version",
            "plan_id",
            "intake_id",
            "source_context_transport_json_path",
            "source_context_transport_md_path",
            "source_goal_intake_path",
            "source_preflight_state",
            "source_authorize_decision_id",
            "context_pack_path",
            "context_pack_status",
            "planning_workspace_status_at_draft",
            "created_at",
            "non_authority",
        )
        for field in required_fields:
            self.assertIn(field, artifact, f"missing field: {field}")
        self.assertEqual(
            artifact["artifact_type"],
            "ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE",
        )
        self.assertEqual(artifact["schema_version"], "0.1")

    def test_provenance_non_authority_flags_all_true(self) -> None:
        from agent_os.orchestrator import (
            ORCHESTRATOR_CONTEXT_PACK_DRAFT_NON_AUTHORITY_FLAGS,
        )

        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)

        artifact = json.loads(
            self._draft_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        non_authority = artifact["non_authority"]
        for flag in ORCHESTRATOR_CONTEXT_PACK_DRAFT_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, non_authority)
            self.assertTrue(non_authority[flag])

    def test_raw_goal_copied_verbatim(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        raw_goal = "Build me an online slither.io-like game"
        self._setup_ready_for_draft(intake_id, plan_id)
        self._draft(intake_id, plan_id)

        context_pack = self._context_pack_path(plan_id).read_text(encoding="utf-8")
        self.assertIn(raw_goal, context_pack)

    def test_owner_clarification_answers_copied_verbatim(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        answer = "Browser-only demo with 10 players max; no persistence."
        self._setup_ready_for_draft(intake_id, plan_id)
        self._draft(intake_id, plan_id)

        context_pack = self._context_pack_path(plan_id).read_text(encoding="utf-8")
        self.assertIn(answer, context_pack)

    def test_owner_readiness_decision_summary_copied_verbatim(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        summary = "Scope clarified; authorize future draft prep only."
        self._setup_ready_for_draft(intake_id, plan_id)
        self._draft(intake_id, plan_id)

        context_pack = self._context_pack_path(plan_id).read_text(encoding="utf-8")
        self.assertIn(summary, context_pack)

    def test_drafted_context_pack_labels_draft_non_authority(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)

        context_pack = self._context_pack_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertIn("draft", context_pack)
        self.assertIn("non-authority", context_pack)

    def test_drafted_context_pack_states_architecture_undecided(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)

        context_pack = self._context_pack_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertIn("architecture", context_pack)
        self.assertIn("undecided", context_pack)

    def test_drafted_context_pack_states_local_agentic_spec_not_generated(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)

        context_pack = self._context_pack_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertIn("local agentic spec", context_pack)
        self.assertIn("not generated", context_pack)

    def test_drafted_context_pack_states_implementation_plan_not_generated(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)

        context_pack = self._context_pack_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertIn("implementation plan", context_pack)
        self.assertIn("not generated", context_pack)

    def test_drafted_context_pack_states_planning_run_slice_not_generated(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)

        context_pack = self._context_pack_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("PLANNING_RUN_SLICE", context_pack)
        self.assertIn("not generated", context_pack.lower())

    def test_drafted_context_pack_states_workspace_not_validated_or_approved(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)

        context_pack = self._context_pack_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertIn("not validated or approved", context_pack)

    def test_refuses_missing_workspace(self) -> None:
        bare = self.project / "bare"
        bare.mkdir()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    "slither-demo",
                    str(bare),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )

        self.assertEqual(code, 1)

    def test_refuses_missing_intake(self) -> None:
        plan_id = "orphan-plan"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    "missing-intake",
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertTrue(self._context_pack_path(plan_id).read_bytes())

    def test_refuses_invalid_intake(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        path = self._artifact_path(intake_id)
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact["artifact_type"] = "WRONG_TYPE"
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)

    def test_refuses_missing_planning_workspace(self) -> None:
        self._authorize_slither()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "missing-plan",
                ]
            )

        self.assertEqual(code, 1)

    def test_refuses_non_draft_planning_workspace(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        manifest_path = self._workspace(plan_id) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["status"] = "CONTEXT_READY"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        code, _ = self._draft(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_orchestrator_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        init_planning_workspace(self.project, plan_id)
        self._transport_json_path(plan_id).parent.mkdir(parents=True, exist_ok=True)
        self._transport_json_path(plan_id).write_text("{}", encoding="utf-8")
        self._transport_md_path(plan_id).write_text("# stub\n", encoding="utf-8")

        code, _ = self._draft(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_context_transport_json(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)

        code, _ = self._draft(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_context_transport_markdown(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        transport = {
            "artifact_type": "ORCHESTRATOR_CONTEXT_TRANSPORT",
            "schema_version": "0.1",
            "plan_id": plan_id,
            "intake_id": intake_id,
            "source_context": {},
            "owner_clarifications": [],
            "owner_readiness_decision": {},
        }
        self._transport_json_path(plan_id).parent.mkdir(parents=True, exist_ok=True)
        self._transport_json_path(plan_id).write_text(
            json.dumps(transport, indent=2) + "\n",
            encoding="utf-8",
        )

        code, _ = self._draft(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_provenance_plan_id_intake_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        provenance = json.loads(
            self._provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["plan_id"] = "wrong-plan"
        self._provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, _ = self._draft(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_context_transport_plan_id_intake_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        transport = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        transport["intake_id"] = "wrong-intake"
        self._transport_json_path(plan_id).write_text(
            json.dumps(transport, indent=2) + "\n",
            encoding="utf-8",
        )

        code, _ = self._draft(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_stale_incoherent_authorization(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        provenance = json.loads(
            self._provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["source_authorize_decision_id"] = "stale-decision"
        self._provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, _ = self._draft(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_latest_request_more_clarification_after_older_authorize(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "REQUEST_MORE_CLARIFICATION",
            "Need more scope detail.",
        )

        code, _ = self._draft(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_latest_block_intake_after_older_authorize(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "BLOCK_INTAKE",
            "Stopping intake.",
        )

        code, _ = self._draft(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_modified_context_pack_and_does_not_overwrite(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        context_pack = self._context_pack_path(plan_id)
        original = context_pack.read_bytes()
        context_pack.write_text(
            context_pack.read_text(encoding="utf-8").replace(
                "PLACEHOLDER",
                "CUSTOMIZED",
                1,
            ),
            encoding="utf-8",
        )
        modified = context_pack.read_bytes()

        code, _ = self._draft(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertEqual(modified, context_pack.read_bytes())
        self.assertNotEqual(original, context_pack.read_bytes())

    def test_accepts_crlf_context_pack_placeholder_but_not_modified_crlf(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        context_pack = self._context_pack_path(plan_id)
        crlf_placeholder = context_pack.read_text(encoding="utf-8").replace("\n", "\r\n")
        context_pack.write_bytes(crlf_placeholder.encode("utf-8"))

        code, output = self._draft(intake_id, plan_id)
        self.assertEqual(code, 0)
        self.assertIn("orchestrator context pack draft created:", output)
        self.assertTrue(self._draft_provenance_path(plan_id).is_file())
        self.assertIn("DRAFT", self._context_pack_path(plan_id).read_text(encoding="utf-8"))

        intake_id_2 = "slither-crlf-mod"
        plan_id_2 = "slither-plan-crlf-mod"
        self._setup_ready_for_draft(intake_id_2, plan_id_2)
        context_pack_2 = self._context_pack_path(plan_id_2)
        modified_crlf = (
            context_pack_2.read_text(encoding="utf-8")
            .replace("PLACEHOLDER", "CUSTOMIZED", 1)
            .replace("\n", "\r\n")
        )
        context_pack_2.write_bytes(modified_crlf.encode("utf-8"))
        modified_bytes = context_pack_2.read_bytes()

        code, _ = self._draft(intake_id_2, plan_id_2)
        self.assertEqual(code, 1)
        self.assertEqual(modified_bytes, context_pack_2.read_bytes())
        self.assertFalse(self._draft_provenance_path(plan_id_2).exists())

    def test_refuses_invalid_plan_id(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)

        context_pack_bytes = self._context_pack_path(plan_id).read_bytes()
        transport_json_bytes = self._transport_json_path(plan_id).read_bytes()
        transport_md_bytes = self._transport_md_path(plan_id).read_bytes()
        provenance_bytes = self._provenance_path(plan_id).read_bytes()
        artifact_bytes = self._artifact_path(intake_id).read_bytes()
        clarification_bytes = self._clarification_path(intake_id, "scope-v1").read_bytes()
        decision_bytes = self._decision_path(intake_id, "owner-v1").read_bytes()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    "../escape",
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("invalid plan id", buf.getvalue())
        self.assertFalse(self._draft_provenance_path(plan_id).exists())
        self.assertFalse(planning_path(self.project, "../escape").exists())
        self.assertEqual(context_pack_bytes, self._context_pack_path(plan_id).read_bytes())
        self.assertEqual(
            transport_json_bytes,
            self._transport_json_path(plan_id).read_bytes(),
        )
        self.assertEqual(
            transport_md_bytes,
            self._transport_md_path(plan_id).read_bytes(),
        )
        self.assertEqual(provenance_bytes, self._provenance_path(plan_id).read_bytes())
        self.assertEqual(artifact_bytes, self._artifact_path(intake_id).read_bytes())
        self.assertEqual(
            clarification_bytes,
            self._clarification_path(intake_id, "scope-v1").read_bytes(),
        )
        self.assertEqual(
            decision_bytes,
            self._decision_path(intake_id, "owner-v1").read_bytes(),
        )

    def test_refuses_path_escape_intake_id(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)

        artifact_path = self._artifact_path(intake_id)
        goal_intake_bytes = artifact_path.read_bytes()
        clarification_bytes = self._clarification_path(intake_id, "scope-v1").read_bytes()
        decision_bytes = self._decision_path(intake_id, "owner-v1").read_bytes()
        workspace = planning_path(self.project, plan_id)
        context_pack_bytes = self._context_pack_path(plan_id).read_bytes()
        provenance_bytes = self._provenance_path(plan_id).read_bytes()
        transport_json_bytes = self._transport_json_path(plan_id).read_bytes()
        transport_md_bytes = self._transport_md_path(plan_id).read_bytes()
        evidence_paths = (
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
            self._transport_json_path(plan_id),
            self._transport_md_path(plan_id),
            self._provenance_path(plan_id),
        )
        evidence_bytes = {path: path.read_bytes() for path in evidence_paths}
        before_files = self._project_files()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    "../escape",
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("invalid intake id", buf.getvalue())
        self.assertFalse(self._draft_provenance_path(plan_id).exists())
        self.assertFalse(
            (self.project / ".agent-os" / "orchestrator" / "intakes" / "escape").exists()
        )
        self.assertEqual(before_files, self._project_files())
        self.assertEqual(goal_intake_bytes, artifact_path.read_bytes())
        self.assertEqual(
            clarification_bytes,
            self._clarification_path(intake_id, "scope-v1").read_bytes(),
        )
        self.assertEqual(
            decision_bytes,
            self._decision_path(intake_id, "owner-v1").read_bytes(),
        )
        self.assertEqual(context_pack_bytes, self._context_pack_path(plan_id).read_bytes())
        self.assertEqual(provenance_bytes, self._provenance_path(plan_id).read_bytes())
        self.assertEqual(
            transport_json_bytes,
            self._transport_json_path(plan_id).read_bytes(),
        )
        self.assertEqual(
            transport_md_bytes,
            self._transport_md_path(plan_id).read_bytes(),
        )
        for path, original in evidence_bytes.items():
            self.assertEqual(original, path.read_bytes(), msg=str(path))

    def test_refuses_missing_context_pack_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)

        workspace = planning_path(self.project, plan_id)
        context_pack = self._context_pack_path(plan_id)
        transport_json_bytes = self._transport_json_path(plan_id).read_bytes()
        transport_md_bytes = self._transport_md_path(plan_id).read_bytes()
        provenance_bytes = self._provenance_path(plan_id).read_bytes()
        template_paths = (
            workspace / "local-agentic-spec.md",
            workspace / "implementation-plan.md",
            workspace / "planning-audit.md",
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
        )
        template_bytes = {path: path.read_bytes() for path in template_paths}
        context_pack.unlink()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("context-pack.md missing", buf.getvalue())
        self.assertFalse(self._draft_provenance_path(plan_id).exists())
        self.assertFalse(context_pack.exists())
        self.assertEqual(
            transport_json_bytes,
            self._transport_json_path(plan_id).read_bytes(),
        )
        self.assertEqual(
            transport_md_bytes,
            self._transport_md_path(plan_id).read_bytes(),
        )
        self.assertEqual(provenance_bytes, self._provenance_path(plan_id).read_bytes())
        for path, original in template_bytes.items():
            self.assertEqual(original, path.read_bytes(), msg=str(path))

    def test_refuses_existing_context_pack_draft_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        self._draft(intake_id, plan_id)
        context_pack_bytes = self._context_pack_path(plan_id).read_bytes()
        provenance_bytes = self._draft_provenance_path(plan_id).read_bytes()

        code, _ = self._draft(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertEqual(context_pack_bytes, self._context_pack_path(plan_id).read_bytes())
        self.assertEqual(
            provenance_bytes,
            self._draft_provenance_path(plan_id).read_bytes(),
        )

    def test_preserves_goal_intake_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        artifact_path = self._artifact_path(intake_id)
        original = artifact_path.read_bytes()

        self._draft(intake_id, plan_id)

        self.assertEqual(original, artifact_path.read_bytes())

    def test_does_not_change_planning_readiness(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        artifact_path = self._artifact_path(intake_id)
        original_bytes = artifact_path.read_bytes()
        before = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]

        self._draft(intake_id, plan_id)

        after = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]
        self.assertEqual(before, after)
        self.assertEqual(original_bytes, artifact_path.read_bytes())

    def test_preserves_clarification_artifacts_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        clarification_path = self._clarification_path(intake_id, "scope-v1")
        original = clarification_path.read_bytes()

        self._draft(intake_id, plan_id)

        self.assertEqual(original, clarification_path.read_bytes())

    def test_preserves_readiness_decision_artifacts_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        decision_path = self._decision_path(intake_id, "owner-v1")
        original = decision_path.read_bytes()

        self._draft(intake_id, plan_id)

        self.assertEqual(original, decision_path.read_bytes())

    def test_preserves_orchestrator_provenance_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        provenance_path = self._provenance_path(plan_id)
        original = provenance_path.read_bytes()

        self._draft(plan_id=plan_id)

        self.assertEqual(original, provenance_path.read_bytes())

    def test_preserves_scaffold_notes_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        notes_path = (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-draft-scaffold-notes.md"
        )
        original = notes_path.read_bytes()

        self._draft(plan_id=plan_id)

        self.assertEqual(original, notes_path.read_bytes())

    def test_preserves_context_transport_json_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        transport_path = self._transport_json_path(plan_id)
        original = transport_path.read_bytes()

        self._draft(plan_id=plan_id)

        self.assertEqual(original, transport_path.read_bytes())

    def test_preserves_context_transport_markdown_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        transport_md = self._transport_md_path(plan_id)
        original = transport_md.read_bytes()

        self._draft(plan_id=plan_id)

        self.assertEqual(original, transport_md.read_bytes())

    def test_preserves_local_agentic_spec_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        spec_path = self._workspace(plan_id) / "local-agentic-spec.md"
        original = spec_path.read_bytes()

        self._draft(plan_id=plan_id)

        self.assertEqual(original, spec_path.read_bytes())

    def test_preserves_implementation_plan_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        impl_path = self._workspace(plan_id) / "implementation-plan.md"
        original = impl_path.read_bytes()

        self._draft(plan_id=plan_id)

        self.assertEqual(original, impl_path.read_bytes())

    def test_preserves_planning_audit_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        audit_path = self._workspace(plan_id) / "planning-audit.md"
        original = audit_path.read_bytes()

        self._draft(plan_id=plan_id)

        self.assertEqual(original, audit_path.read_bytes())

    def test_does_not_change_planning_workspace_status(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        manifest_path = self._workspace(plan_id) / "manifest.json"
        before = json.loads(manifest_path.read_text(encoding="utf-8"))["status"]

        self._draft(plan_id=plan_id)

        after = json.loads(manifest_path.read_text(encoding="utf-8"))["status"]
        self.assertEqual(before, after)
        self.assertEqual(after, "DRAFT")

    def test_does_not_generate_architecture_choices(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)

        context_pack = self._context_pack_path(plan_id).read_text(encoding="utf-8").lower()
        for forbidden in (
            "backend:",
            "frontend:",
            "database:",
            "postgresql",
            "react",
            "kubernetes",
            "selected architecture",
            "chosen stack",
        ):
            self.assertNotIn(forbidden, context_pack)

    def test_does_not_generate_local_agentic_spec(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        spec_path = self._workspace(plan_id) / "local-agentic-spec.md"
        original = spec_path.read_text(encoding="utf-8")

        self._draft(plan_id=plan_id)

        self.assertEqual(original, spec_path.read_text(encoding="utf-8"))

    def test_does_not_generate_implementation_tasks(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)

        context_pack = self._context_pack_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn("allowed_paths", context_pack)
        self.assertNotIn("check_command", context_pack)

    def test_does_not_generate_planning_run_slice(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)

        artifact = json.loads(
            self._draft_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        self.assertTrue(
            artifact["non_authority"]["does_not_generate_planning_run_slice"]
        )

    def test_does_not_create_runner_proposals(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        before_runs = list((self.project / ".agent-os" / "runs").iterdir())

        self._draft(plan_id=plan_id)

        after_runs = list((self.project / ".agent-os" / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_does_not_create_runs(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)

        runs_dir = self.project / ".agent-os" / "runs"
        self.assertEqual(list(runs_dir.iterdir()), [])

    def test_does_not_invoke_external_subprocess(self) -> None:
        self._setup_ready_for_draft()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 0)

    def test_does_not_call_planning_progress_transition_decide(self) -> None:
        self._setup_ready_for_draft()
        with (
            patch.object(
                planning_module,
                "progress_planning_workspace",
                side_effect=AssertionError("progress invoked"),
            ),
            patch.object(
                planning_module,
                "transition_planning_workspace",
                side_effect=AssertionError("transition invoked"),
            ),
            patch.object(
                planning_module,
                "record_planning_owner_decision",
                side_effect=AssertionError("decide invoked"),
            ),
        ):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 0)

    def test_restores_context_pack_when_provenance_write_fails(self) -> None:
        from agent_os.orchestrator import draft_context_pack_from_transport

        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(intake_id, plan_id)
        context_pack = self._context_pack_path(plan_id)
        original = context_pack.read_bytes()
        provenance_path = self._draft_provenance_path(plan_id)

        original_write_json = None
        from agent_os import orchestrator as orchestrator_module

        original_write_json = orchestrator_module._write_json

        def failing_provenance_write(path: Path, data: dict) -> None:
            if path == provenance_path:
                raise OSError("simulated provenance write failure")
            original_write_json(path, data)

        with patch.object(orchestrator_module, "_write_json", failing_provenance_write):
            with self.assertRaises(OSError) as ctx:
                draft_context_pack_from_transport(self.project, intake_id, plan_id)
            self.assertIn("simulated provenance write failure", str(ctx.exception))

        self.assertEqual(original, context_pack.read_bytes())
        self.assertFalse(provenance_path.exists())

    def test_cli_help_states_context_pack_draft_boundaries(self) -> None:
        parser = build_parser()
        orchestrator_parser = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
            and "orchestrator" in action.choices
        )
        orchestrator_sub = next(
            action
            for action in orchestrator_parser.choices["orchestrator"]._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        help_text = orchestrator_sub.choices["draft-context-pack"].format_help()
        compact = re.sub(r"\s+", " ", help_text)
        self.assertIn("context-pack", compact.lower())
        self.assertIn("architecture", compact.lower())
        self.assertIn("local agentic spec", compact.lower())
        self.assertIn("implementation plan", compact.lower())
        self.assertIn("PLANNING_RUN_SLICE", compact)
        self.assertIn("validate", compact.lower())
        self.assertIn("executor", compact.lower())

    def test_cli_output_includes_paths_status_and_boundary_notes(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        code, output = self._draft(plan_id=plan_id)

        self.assertEqual(code, 0)
        self.assertIn("context pack:", output)
        self.assertIn("context pack draft provenance:", output)
        self.assertIn("context_pack_status: DRAFT_NON_AUTHORITY", output)
        self.assertIn("workspace_status: DRAFT", output)
        self.assertIn("no architecture generation", output)
        self.assertIn("no runner proposals", output)

    def test_existing_commands_unchanged(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        self._prepare(intake_id)
        self._transport(intake_id)
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            preflight_code = main(
                ["orchestrator", "draft-preflight", intake_id, str(self.project)]
            )
        self.assertEqual(preflight_code, 0)
        self.assertIn("draft-preparation preflight is read-only", buf.getvalue())

        validate_report = validate_goal_intake(self.project, intake_id)
        self.assertTrue(validate_report.valid)
        readiness_report = review_goal_intake_readiness(self.project, intake_id)
        self.assertTrue(readiness_report.goal_intake_valid)
        status_report = goal_intake_status(self.project, intake_id)
        self.assertTrue(status_report.validation_ok)

        transport_files = {
            self._transport_json_path().relative_to(self.project).as_posix(),
            self._transport_md_path().relative_to(self.project).as_posix(),
        }
        after = self._project_files()
        self.assertEqual(before, after)
        self.assertTrue(transport_files.issubset(after))

    def test_context_pack_draft_not_confusable_with_approval(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_draft(plan_id=plan_id)
        self._draft(plan_id=plan_id)

        context_pack = self._context_pack_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertIn("non-authority", context_pack)
        self.assertIn("not validated or approved", context_pack)
        self.assertIn("source context", context_pack)
        validation = validate_planning_workspace(self.project, plan_id)
        self.assertFalse(validation.valid)


class OrchestratorLocalAgenticSpecPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(
            self.project,
            intake_id,
            clarification_id,
        )

    def _decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(
            self.project,
            intake_id,
            decision_id,
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _slither_with_clarification(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max; no persistence.",
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._slither_with_clarification(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _prepare(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _transport(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _draft_context_pack(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _preflight(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "local-agentic-spec-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-pack-draft-provenance.json"
        )

    def _transport_json_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-transport.json"
        )

    def _transport_md_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-transport.md"
        )

    def _provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-provenance.json"
        )

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_preflight(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)

    def _tracked_artifact_paths(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> dict[Path, bytes]:
        workspace = self._workspace(plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._clarification_path(intake_id, "scope-v1"),
            self._decision_path(intake_id, "owner-v1"),
            self._provenance_path(plan_id),
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
            self._transport_json_path(plan_id),
            self._transport_md_path(plan_id),
            self._draft_provenance_path(plan_id),
            self._context_pack_path(plan_id),
            self._local_spec_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def test_successful_preflight_after_context_pack_draft(self) -> None:
        self._setup_ready_for_preflight()
        code, output = self._preflight()
        self.assertEqual(code, 0)
        self.assertIn("local-agentic-spec draft preflight", output)

    def test_success_state_is_confirmed_no_spec_generated(self) -> None:
        self._setup_ready_for_preflight()
        from agent_os.orchestrator import preflight_local_agentic_spec_draft

        report = preflight_local_agentic_spec_draft(
            self.project,
            "slither-demo",
            "slither-plan-v1",
        )
        self.assertEqual(
            report.preflight_state,
            "LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_NO_SPEC_GENERATED",
        )

    def test_success_next_action_requires_separate_command(self) -> None:
        self._setup_ready_for_preflight()
        from agent_os.orchestrator import preflight_local_agentic_spec_draft

        report = preflight_local_agentic_spec_draft(
            self.project,
            "slither-demo",
            "slither-plan-v1",
        )
        self.assertEqual(
            report.next_required_action,
            "FUTURE_LOCAL_AGENTIC_SPEC_DRAFT_REQUIRES_SEPARATE_COMMAND",
        )

    def test_report_contains_all_required_fields(self) -> None:
        self._setup_ready_for_preflight()
        from agent_os.orchestrator import preflight_local_agentic_spec_draft

        report = preflight_local_agentic_spec_draft(
            self.project,
            "slither-demo",
            "slither-plan-v1",
        )
        required_fields = (
            "preflight_state",
            "next_required_action",
            "plan_id",
            "intake_id",
            "planning_workspace_status",
            "context_pack_status",
            "context_pack_path",
            "context_pack_provenance_path",
            "local_agentic_spec_path",
            "implementation_plan_path",
            "planning_audit_path",
            "latest_decision_id",
            "latest_decision",
            "source_preflight_state",
            "checked_at",
            "non_authority",
        )
        for field in required_fields:
            self.assertTrue(hasattr(report, field), f"missing field: {field}")

    def test_report_non_authority_flags_all_true(self) -> None:
        self._setup_ready_for_preflight()
        from agent_os.orchestrator import (
            LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_NON_AUTHORITY_FLAGS,
            preflight_local_agentic_spec_draft,
        )

        report = preflight_local_agentic_spec_draft(
            self.project,
            "slither-demo",
            "slither-plan-v1",
        )
        for flag in LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, report.non_authority)
            self.assertTrue(report.non_authority[flag])

    def test_preflight_is_read_only_on_success(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._tracked_artifact_paths(intake_id, plan_id)
        manifest_bytes = (self._workspace(plan_id) / "manifest.json").read_bytes()

        self._preflight(intake_id, plan_id)

        after = self._tracked_artifact_paths(intake_id, plan_id)
        self.assertEqual(before, after)
        self.assertEqual(
            manifest_bytes,
            (self._workspace(plan_id) / "manifest.json").read_bytes(),
        )

    def test_does_not_change_planning_readiness(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        artifact_path = self._artifact_path(intake_id)
        original_bytes = artifact_path.read_bytes()
        before = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]

        self._preflight(intake_id, plan_id)

        after = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]
        self.assertEqual(before, after)
        self.assertEqual(original_bytes, artifact_path.read_bytes())

    def test_preflight_is_read_only_on_failure(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        transport = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        transport["intake_id"] = "wrong-intake"
        self._transport_json_path(plan_id).write_text(
            json.dumps(transport, indent=2) + "\n",
            encoding="utf-8",
        )

        before_artifacts = self._tracked_artifact_paths(intake_id, plan_id)
        before_files = self._project_files()
        manifest_path = self._workspace(plan_id) / "manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        implementation_plan = self._implementation_plan_path(plan_id).read_text(
            encoding="utf-8"
        )

        with (
            patch("subprocess.run", side_effect=AssertionError("subprocess invoked")),
            patch.object(
                planning_module,
                "progress_planning_workspace",
                side_effect=AssertionError("progress invoked"),
            ),
            patch.object(
                planning_module,
                "transition_planning_workspace",
                side_effect=AssertionError("transition invoked"),
            ),
            patch.object(
                planning_module,
                "record_planning_owner_decision",
                side_effect=AssertionError("decide invoked"),
            ),
        ):
            code, output = self._preflight(intake_id, plan_id)

        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_UNEXPECTED_STRUCTURE", output)
        self.assertEqual(before_artifacts, self._tracked_artifact_paths(intake_id, plan_id))
        self.assertEqual(before_files, self._project_files())
        self.assertEqual(manifest_bytes, manifest_path.read_bytes())
        self.assertEqual(before_runs, list((workspace / "runs").iterdir()))
        self.assertIn('"artifact_type": "PLANNING_RUN_SLICE"', implementation_plan)
        self.assertIn("PLACEHOLDER-slice-id", implementation_plan)
        self.assertEqual(
            implementation_plan,
            self._implementation_plan_path(plan_id).read_text(encoding="utf-8"),
        )

    def test_refuses_missing_workspace(self) -> None:
        bare = self.project / "bare"
        bare.mkdir()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "local-agentic-spec-preflight",
                    "slither-demo",
                    str(bare),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_WORKSPACE", buf.getvalue())

    def test_refuses_missing_intake(self) -> None:
        plan_id = "orphan-plan"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)
        self._draft_context_pack(plan_id=plan_id)

        code, output = self._preflight("missing-intake", plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_INVALID_INTAKE", output)

    def test_refuses_invalid_intake(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        path = self._artifact_path(intake_id)
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact["artifact_type"] = "WRONG_TYPE"
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_INVALID_INTAKE", output)

    def test_refuses_missing_planning_workspace(self) -> None:
        self._authorize_slither()
        code, output = self._preflight(plan_id="missing-plan")
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_PLANNING_WORKSPACE", output)

    def test_refuses_non_draft_planning_workspace(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        manifest_path = self._workspace(plan_id) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["status"] = "CONTEXT_READY"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_WORKSPACE_NOT_DRAFT", output)

    def test_refuses_missing_orchestrator_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        init_planning_workspace(self.project, plan_id)
        self._transport_json_path(plan_id).parent.mkdir(parents=True, exist_ok=True)
        self._transport_json_path(plan_id).write_text("{}", encoding="utf-8")
        self._transport_md_path(plan_id).write_text("# stub\n", encoding="utf-8")

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_ORCHESTRATOR_PROVENANCE", output)

    def test_refuses_missing_context_transport_json(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_CONTEXT_TRANSPORT", output)

    def test_refuses_missing_context_transport_markdown(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        transport = {
            "artifact_type": "ORCHESTRATOR_CONTEXT_TRANSPORT",
            "schema_version": "0.1",
            "plan_id": plan_id,
            "intake_id": intake_id,
            "source_context": {},
            "owner_clarifications": [],
            "owner_readiness_decision": {},
        }
        self._transport_json_path(plan_id).parent.mkdir(parents=True, exist_ok=True)
        self._transport_json_path(plan_id).write_text(
            json.dumps(transport, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_CONTEXT_TRANSPORT", output)

    def test_refuses_missing_context_pack_draft_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_CONTEXT_PACK_DRAFT_PROVENANCE", output)

    def test_refuses_missing_context_pack_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        self._context_pack_path(plan_id).unlink()

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_UNEXPECTED_STRUCTURE", output)

    def test_refuses_provenance_plan_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        provenance = json.loads(
            self._provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["plan_id"] = "wrong-plan"
        self._provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT", output)

    def test_refuses_provenance_intake_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        provenance = json.loads(
            self._provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["intake_id"] = "wrong-intake"
        self._provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT", output)

    def test_refuses_context_transport_plan_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        transport = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        transport["plan_id"] = "wrong-plan"
        self._transport_json_path(plan_id).write_text(
            json.dumps(transport, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_UNEXPECTED_STRUCTURE", output)

    def test_refuses_context_transport_intake_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        transport = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        transport["intake_id"] = "wrong-intake"
        self._transport_json_path(plan_id).write_text(
            json.dumps(transport, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_UNEXPECTED_STRUCTURE", output)

    def test_refuses_context_pack_draft_provenance_plan_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        provenance = json.loads(
            self._draft_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["plan_id"] = "wrong-plan"
        self._draft_provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CONTEXT_PACK_PROVENANCE_MISMATCH", output)

    def test_refuses_context_pack_draft_provenance_intake_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        provenance = json.loads(
            self._draft_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["intake_id"] = "wrong-intake"
        self._draft_provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CONTEXT_PACK_PROVENANCE_MISMATCH", output)

    def test_refuses_stale_incoherent_authorization(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        provenance = json.loads(
            self._provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["source_authorize_decision_id"] = "stale-decision"
        self._provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT", output)

    def test_refuses_latest_request_more_clarification_after_older_authorize(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "REQUEST_MORE_CLARIFICATION",
            "Need more scope detail.",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_DECISION_REQUESTS_CLARIFICATION", output)

    def test_refuses_latest_block_intake_after_older_authorize(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "BLOCK_INTAKE",
            "Stopping intake.",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_DECISION_BLOCKS_INTAKE", output)

    def test_refuses_context_pack_not_draft_non_authority(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        context_pack = self._context_pack_path(plan_id)
        context_pack.write_text(
            context_pack.read_text(encoding="utf-8").replace(
                "DRAFT_NON_AUTHORITY",
                "APPROVED",
            ),
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CONTEXT_PACK_NOT_DRAFT_NON_AUTHORITY", output)

    def _remove_boundary_note(self, plan_id: str, needle: str) -> None:
        context_pack = self._context_pack_path(plan_id)
        lines = [
            line
            for line in context_pack.read_text(encoding="utf-8").splitlines()
            if needle.lower() not in line.lower()
        ]
        context_pack.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_refuses_context_pack_missing_architecture_undecided_boundary(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(plan_id=plan_id)
        self._remove_boundary_note(plan_id, "architecture")
        code, output = self._preflight(plan_id=plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CONTEXT_PACK_BOUNDARY_NOTES_MISSING", output)

    def test_refuses_context_pack_missing_local_spec_not_generated_boundary(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(plan_id=plan_id)
        self._remove_boundary_note(plan_id, "local agentic spec")
        code, output = self._preflight(plan_id=plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CONTEXT_PACK_BOUNDARY_NOTES_MISSING", output)

    def test_refuses_context_pack_missing_implementation_plan_not_generated_boundary(
        self,
    ) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(plan_id=plan_id)
        self._remove_boundary_note(plan_id, "implementation plan")
        code, output = self._preflight(plan_id=plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CONTEXT_PACK_BOUNDARY_NOTES_MISSING", output)

    def test_refuses_context_pack_missing_planning_run_slice_not_generated_boundary(
        self,
    ) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(plan_id=plan_id)
        self._remove_boundary_note(plan_id, "PLANNING_RUN_SLICE")
        code, output = self._preflight(plan_id=plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CONTEXT_PACK_BOUNDARY_NOTES_MISSING", output)

    def test_refuses_modified_local_agentic_spec(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8").replace(
                "PLACEHOLDER",
                "CUSTOMIZED",
                1,
            ),
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_MODIFIED", output)

    def test_refuses_modified_implementation_plan(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        plan = self._implementation_plan_path(plan_id)
        plan.write_text(
            plan.read_text(encoding="utf-8").replace("PLACEHOLDER", "CUSTOMIZED", 1),
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_IMPLEMENTATION_PLAN_ALREADY_MODIFIED", output)

    def test_refuses_modified_planning_audit(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        audit = self._planning_audit_path(plan_id)
        audit.write_text(
            audit.read_text(encoding="utf-8").replace("PLACEHOLDER", "CUSTOMIZED", 1),
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_PLANNING_AUDIT_ALREADY_MODIFIED", output)

    def test_refuses_invalid_plan_id(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._tracked_artifact_paths(intake_id, plan_id)

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "local-agentic-spec-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    "../escape",
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("invalid plan id", buf.getvalue())
        after = self._tracked_artifact_paths(intake_id, plan_id)
        self.assertEqual(before, after)

    def test_refuses_path_escape_intake_id(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._tracked_artifact_paths(intake_id, plan_id)

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "local-agentic-spec-preflight",
                    "../escape",
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("invalid intake id", buf.getvalue())
        self.assertEqual(before, self._tracked_artifact_paths(intake_id, plan_id))

    def test_creates_no_preflight_artifact(self) -> None:
        self._setup_ready_for_preflight()
        before = self._project_files()
        self._preflight()
        after = self._project_files()
        self.assertEqual(before, after)

    def test_does_not_mutate_context_pack(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._context_pack_path(plan_id).read_bytes()
        self._preflight(intake_id, plan_id)
        self.assertEqual(before, self._context_pack_path(plan_id).read_bytes())

    def test_does_not_mutate_local_agentic_spec(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._local_spec_path(plan_id).read_bytes()
        self._preflight(intake_id, plan_id)
        self.assertEqual(before, self._local_spec_path(plan_id).read_bytes())

    def test_does_not_mutate_implementation_plan(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._implementation_plan_path(plan_id).read_bytes()
        self._preflight(intake_id, plan_id)
        self.assertEqual(before, self._implementation_plan_path(plan_id).read_bytes())

    def test_does_not_mutate_planning_audit(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._planning_audit_path(plan_id).read_bytes()
        self._preflight(intake_id, plan_id)
        self.assertEqual(before, self._planning_audit_path(plan_id).read_bytes())

    def test_does_not_mutate_evidence_artifacts(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        workspace = self._workspace(plan_id)
        evidence_paths = [
            self._provenance_path(plan_id),
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
            self._transport_json_path(plan_id),
            self._transport_md_path(plan_id),
            self._draft_provenance_path(plan_id),
        ]
        before = {path: path.read_bytes() for path in evidence_paths}
        self._preflight(intake_id, plan_id)
        for path, original in before.items():
            self.assertEqual(original, path.read_bytes(), msg=str(path))

    def test_does_not_mutate_source_orchestrator_artifacts(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._clarification_path(intake_id, "scope-v1"),
            self._decision_path(intake_id, "owner-v1"),
        ]
        before = {path: path.read_bytes() for path in paths}
        self._preflight(intake_id, plan_id)
        for path, original in before.items():
            self.assertEqual(original, path.read_bytes(), msg=str(path))

    def test_does_not_change_planning_workspace_status(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        manifest_path = self._workspace(plan_id) / "manifest.json"
        before = manifest_path.read_bytes()
        self._preflight(intake_id, plan_id)
        self.assertEqual(before, manifest_path.read_bytes())

    def test_does_not_generate_architecture_choices(self) -> None:
        self._setup_ready_for_preflight()
        self._preflight()
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file()
        ).lower()
        self.assertNotIn("backend:", combined)
        self.assertNotIn("frontend:", combined)
        self.assertNotIn("database:", combined)

    def test_does_not_generate_local_agentic_spec(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._local_spec_path(plan_id).read_bytes()
        self._preflight(intake_id, plan_id)
        self.assertEqual(before, self._local_spec_path(plan_id).read_bytes())

    def test_does_not_generate_implementation_tasks(self) -> None:
        self._setup_ready_for_preflight()
        self._preflight()
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file()
        )
        self.assertNotIn('"slice_id": "slice-', combined)

    def test_does_not_generate_planning_run_slice(self) -> None:
        self._setup_ready_for_preflight()
        self._preflight()
        plan = self._implementation_plan_path().read_text(encoding="utf-8")
        self.assertIn('"artifact_type": "PLANNING_RUN_SLICE"', plan)
        self.assertIn("PLACEHOLDER-slice-id", plan)

    def test_does_not_create_runner_proposals(self) -> None:
        self._setup_ready_for_preflight()
        before = self._project_files()
        self._preflight()
        after = self._project_files()
        self.assertEqual(before, after)

    def test_does_not_create_runs(self) -> None:
        self._setup_ready_for_preflight()
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        self._preflight()
        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_does_not_invoke_external_subprocess(self) -> None:
        self._setup_ready_for_preflight()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code = main(
                [
                    "orchestrator",
                    "local-agentic-spec-preflight",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 0)

    def test_does_not_call_planning_progress_transition_decide(self) -> None:
        self._setup_ready_for_preflight()
        with (
            patch.object(planning_module, "progress_planning_workspace") as progress,
            patch.object(planning_module, "transition_planning_workspace") as transition,
            patch.object(planning_module, "record_planning_owner_decision") as decide,
        ):
            self._preflight()
        progress.assert_not_called()
        transition.assert_not_called()
        decide.assert_not_called()

    def test_cli_help_states_preflight_boundaries(self) -> None:
        parser = build_parser()
        orchestrator_parser = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
            and "orchestrator" in action.choices
        )
        orchestrator_sub = next(
            action
            for action in orchestrator_parser.choices["orchestrator"]._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        help_text = orchestrator_sub.choices[
            "local-agentic-spec-preflight"
        ].format_help()
        compact = re.sub(r"\s+", " ", help_text)
        self.assertIn("read-only", compact.lower())
        self.assertIn("local agentic spec", compact.lower())
        self.assertIn("architecture", compact.lower())
        self.assertIn("implementation plan", compact.lower())
        self.assertIn("PLANNING_RUN_SLICE", compact)
        self.assertIn("validate", compact.lower())
        self.assertIn("executor", compact.lower())

    def test_cli_output_includes_paths_status_and_boundary_notes(self) -> None:
        self._setup_ready_for_preflight()
        code, output = self._preflight()
        self.assertEqual(code, 0)
        self.assertIn("preflight_state:", output)
        self.assertIn("next_required_action:", output)
        self.assertIn("planning_workspace_status: DRAFT", output)
        self.assertIn("context_pack_path:", output)
        self.assertIn("local_agentic_spec_path:", output)
        self.assertIn("architecture undecided", output.lower())
        self.assertIn("no local agentic spec was generated", output.lower())

    def test_existing_commands_unchanged(self) -> None:
        intake_id = "slither-demo"
        self._authorize_slither(intake_id)
        self._prepare(intake_id)
        self._transport(intake_id)
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            preflight_code = main(
                ["orchestrator", "draft-preflight", intake_id, str(self.project)]
            )
        self.assertEqual(preflight_code, 0)
        self.assertIn("draft-preparation preflight is read-only", buf.getvalue())

        self.assertEqual(self._draft_context_pack(intake_id)[0], 0)
        after = self._project_files()
        self.assertEqual(before | {
            self._context_pack_path().relative_to(self.project).as_posix(),
            self._draft_provenance_path().relative_to(self.project).as_posix(),
        }, after)

    def test_successful_preflight_not_confusable_with_spec_generation(self) -> None:
        self._setup_ready_for_preflight()
        code, output = self._preflight()
        self.assertEqual(code, 0)
        lowered = output.lower()
        self.assertIn("preflight confirmed", lowered)
        self.assertIn("no local agentic spec was generated", lowered)
        self.assertNotIn("local agentic spec created", lowered)
        self.assertIn("not architecture decision", lowered)


class OrchestratorLocalAgenticSpecScaffoldTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(
            self.project,
            intake_id,
            clarification_id,
        )

    def _decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(
            self.project,
            intake_id,
            decision_id,
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _slither_with_clarification(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max; no persistence.",
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._slither_with_clarification(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _prepare(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _transport(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _draft_context_pack(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _preflight(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "local-agentic-spec-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _scaffold(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-local-agentic-spec",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-pack-draft-provenance.json"
        )

    def _scaffold_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-local-agentic-spec-scaffold-provenance.json"
        )

    def _transport_json_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-transport.json"
        )

    def _transport_md_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-transport.md"
        )

    def _provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-provenance.json"
        )

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_scaffold(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

    def _tracked_artifact_paths(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> dict[Path, bytes]:
        workspace = self._workspace(plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._clarification_path(intake_id, "scope-v1"),
            self._decision_path(intake_id, "owner-v1"),
            self._provenance_path(plan_id),
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
            self._transport_json_path(plan_id),
            self._transport_md_path(plan_id),
            self._draft_provenance_path(plan_id),
            self._context_pack_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def test_succeeds_only_after_successful_preflight(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

        self._draft_context_pack(intake_id, plan_id)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)
        code, output = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 0)
        self.assertIn("orchestrator local-agentic-spec scaffold created:", output)

    def test_local_agentic_spec_replaced_with_scaffold(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        before = self._local_spec_path(plan_id).read_bytes()

        self._scaffold(plan_id=plan_id)

        after = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotEqual(before, after.encode("utf-8"))
        self.assertIn("SCAFFOLD_DRAFT_NON_AUTHORITY", after)

    def test_scaffold_provenance_created(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)
        self.assertTrue(self._scaffold_provenance_path(plan_id).is_file())

    def test_provenance_contains_required_fields(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self._scaffold(intake_id, plan_id)

        artifact = json.loads(
            self._scaffold_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        required_fields = (
            "artifact_type",
            "schema_version",
            "plan_id",
            "intake_id",
            "source_context_pack_path",
            "source_context_pack_draft_provenance_path",
            "source_preflight_state",
            "source_preflight_next_action",
            "source_authorize_decision_id",
            "local_agentic_spec_path",
            "local_agentic_spec_status",
            "planning_workspace_status_at_scaffold",
            "created_at",
            "non_authority",
        )
        for field in required_fields:
            self.assertIn(field, artifact, f"missing field: {field}")
        self.assertEqual(
            artifact["artifact_type"],
            "ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE",
        )
        self.assertEqual(artifact["schema_version"], "0.1")

    def test_provenance_non_authority_flags_all_true(self) -> None:
        from agent_os.orchestrator import (
            ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_NON_AUTHORITY_FLAGS,
        )

        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        artifact = json.loads(
            self._scaffold_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        non_authority = artifact["non_authority"]
        for flag in ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, non_authority)
            self.assertTrue(non_authority[flag])

    def test_scaffold_labels_scaffold_draft_non_authority(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("SCAFFOLD_DRAFT_NON_AUTHORITY", spec)

    def test_scaffold_contains_source_context_pack_paths(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("context-pack", spec.lower())
        self.assertIn("orchestrator-context-pack-draft-provenance.json", spec)

    def test_scaffold_states_requirements_extraction_not_performed(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertIn("requirements extraction", spec)
        self.assertIn("not performed", spec)
        self.assertIn("pending_future_requirements_extraction", spec)

    def test_scaffold_states_architecture_undecided(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("UNDECIDED_NOT_GENERATED", spec)
        self.assertIn("architecture", spec.lower())

    def test_scaffold_states_implementation_plan_not_generated(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("Implementation Plan", spec)
        self.assertIn("NOT_GENERATED", spec)

    def test_scaffold_states_planning_run_slice_not_generated(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("PLANNING_RUN_SLICE", spec)
        self.assertIn("NOT_GENERATED", spec)

    def test_scaffold_contains_only_pending_substantive_sections(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("PENDING_FUTURE_REQUIREMENTS_EXTRACTION", spec)
        self.assertNotIn("PLACEHOLDER — one-paragraph summary", spec)

    def test_scaffold_does_not_copy_raw_goal(self) -> None:
        plan_id = "slither-plan-v1"
        raw_goal = "Build me an online slither.io-like game"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn(raw_goal, spec)

    def test_scaffold_does_not_copy_normalized_goal_into_substantive_sections(
        self,
    ) -> None:
        intake_id = "norm-goal-demo"
        plan_id = "norm-goal-plan"
        raw_goal = "Build  me   an online slither.io-like game"
        create_goal_intake(self.project, intake_id, raw_goal)
        artifact = json.loads(self._artifact_path(intake_id).read_text(encoding="utf-8"))
        normalized_goal = artifact["normalized_goal"]
        self.assertNotEqual(raw_goal, normalized_goal)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max; no persistence.",
        )
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)
        self._scaffold(intake_id, plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn(normalized_goal, spec)
        substantive_start = spec.index("## Spec sections")
        substantive_body = spec[substantive_start:]
        self.assertNotIn(normalized_goal, substantive_body)

    def test_scaffold_does_not_copy_clarification_answers(self) -> None:
        plan_id = "slither-plan-v1"
        answer = "Browser-only demo with 10 players max; no persistence."
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn(answer, spec)

    def test_scaffold_does_not_generate_functional_requirements(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertNotIn("the system shall", spec)
        self.assertNotIn("user story", spec)

    def test_scaffold_does_not_generate_user_stories(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertNotIn("as a user", spec)
        self.assertNotIn("user stories", spec)

    def test_scaffold_does_not_generate_acceptance_criteria(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("Acceptance Criteria", spec)
        self.assertIn("| Acceptance Criteria | NOT_GENERATED |", spec)

    def test_refuses_missing_workspace(self) -> None:
        bare = self.project / "bare"
        bare.mkdir()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-local-agentic-spec",
                    "slither-demo",
                    str(bare),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )

        self.assertEqual(code, 1)

    def test_refuses_missing_intake(self) -> None:
        plan_id = "orphan-plan"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)
        self._draft_context_pack(plan_id=plan_id)
        self._preflight(plan_id=plan_id)

        code, _ = self._scaffold("missing-intake", plan_id)
        self.assertEqual(code, 1)

    def test_refuses_invalid_intake(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        path = self._artifact_path(intake_id)
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact["artifact_type"] = "WRONG_TYPE"
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_planning_workspace(self) -> None:
        self._authorize_slither()
        code, _ = self._scaffold(plan_id="missing-plan")
        self.assertEqual(code, 1)

    def test_refuses_non_draft_planning_workspace(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        manifest_path = self._workspace(plan_id) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["status"] = "CONTEXT_READY"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_failed_local_agentic_spec_preflight(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_when_local_agentic_spec_preflight_no_longer_confirmed_at_scaffold_time(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

        before = self._tracked_artifact_paths(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8").replace("PLACEHOLDER", "CUSTOMIZED", 1),
            encoding="utf-8",
        )
        local_spec_bytes = local_spec.read_bytes()

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertFalse(self._scaffold_provenance_path(plan_id).exists())
        self.assertEqual(local_spec_bytes, local_spec.read_bytes())
        after = self._tracked_artifact_paths(intake_id, plan_id)
        self.assertEqual(before, after)

    def test_refuses_when_context_pack_mutated_after_local_agentic_spec_preflight(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

        context_pack = self._context_pack_path(plan_id)
        context_pack.write_text(
            context_pack.read_text(encoding="utf-8").replace(
                "DRAFT_NON_AUTHORITY",
                "APPROVED",
            ),
            encoding="utf-8",
        )
        mutated_context_pack = context_pack.read_bytes()
        implementation_plan_before = self._implementation_plan_path(plan_id).read_bytes()
        planning_audit_before = self._planning_audit_path(plan_id).read_bytes()
        local_spec_before = self._local_spec_path(plan_id).read_bytes()

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertFalse(self._scaffold_provenance_path(plan_id).exists())
        self.assertEqual(mutated_context_pack, context_pack.read_bytes())
        self.assertEqual(
            implementation_plan_before,
            self._implementation_plan_path(plan_id).read_bytes(),
        )
        self.assertEqual(
            planning_audit_before,
            self._planning_audit_path(plan_id).read_bytes(),
        )
        self.assertEqual(local_spec_before, self._local_spec_path(plan_id).read_bytes())

    def test_refuses_stale_incoherent_authorization(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        provenance = json.loads(
            self._provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["source_authorize_decision_id"] = "stale-decision"
        self._provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_latest_request_more_clarification_after_authorize(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "REQUEST_MORE_CLARIFICATION",
            "Need more detail on multiplayer scope.",
        )

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_latest_block_intake_after_authorize(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "BLOCK_INTAKE",
            "Scope too broad; stop intake.",
        )

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_context_pack_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self._context_pack_path(plan_id).unlink()

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_context_pack_draft_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self._draft_provenance_path(plan_id).unlink()

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_local_agentic_spec_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self._local_spec_path(plan_id).unlink()

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_modified_local_agentic_spec_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        path = self._local_spec_path(plan_id)
        path.write_text(path.read_text(encoding="utf-8") + "\nmodified\n", encoding="utf-8")

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_modified_implementation_plan_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        path = self._implementation_plan_path(plan_id)
        path.write_text(path.read_text(encoding="utf-8") + "\nmodified\n", encoding="utf-8")

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_modified_planning_audit_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        path = self._planning_audit_path(plan_id)
        path.write_text(path.read_text(encoding="utf-8") + "\nmodified\n", encoding="utf-8")

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_existing_scaffold_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self._scaffold(intake_id, plan_id)
        local_spec_bytes = self._local_spec_path(plan_id).read_bytes()
        provenance_bytes = self._scaffold_provenance_path(plan_id).read_bytes()

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertEqual(local_spec_bytes, self._local_spec_path(plan_id).read_bytes())
        self.assertEqual(
            provenance_bytes,
            self._scaffold_provenance_path(plan_id).read_bytes(),
        )

    def test_refuses_invalid_plan_id(self) -> None:
        self._setup_ready_for_scaffold()
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-local-agentic-spec",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "../escape",
                ]
            )
        self.assertEqual(code, 1)

    def test_refuses_path_escape_intake_id(self) -> None:
        self._setup_ready_for_scaffold()
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-local-agentic-spec",
                    "../escape",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 1)

    def test_preserves_goal_intake_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        artifact_path = self._artifact_path(intake_id)
        original = artifact_path.read_bytes()

        self._scaffold(intake_id, plan_id)

        self.assertEqual(original, artifact_path.read_bytes())

    def test_preserves_clarification_artifacts_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        clarification_path = self._clarification_path(intake_id, "scope-v1")
        original = clarification_path.read_bytes()

        self._scaffold(intake_id, plan_id)

        self.assertEqual(original, clarification_path.read_bytes())

    def test_preserves_readiness_decision_artifacts_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        decision_path = self._decision_path(intake_id, "owner-v1")
        original = decision_path.read_bytes()

        self._scaffold(intake_id, plan_id)

        self.assertEqual(original, decision_path.read_bytes())

    def test_preserves_orchestrator_provenance_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        provenance_path = self._provenance_path(plan_id)
        original = provenance_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, provenance_path.read_bytes())

    def test_preserves_scaffold_notes_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        notes_path = self._workspace(plan_id) / "evidence" / "orchestrator-draft-scaffold-notes.md"
        original = notes_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, notes_path.read_bytes())

    def test_preserves_context_transport_json_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        transport_path = self._transport_json_path(plan_id)
        original = transport_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, transport_path.read_bytes())

    def test_preserves_context_transport_markdown_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        transport_path = self._transport_md_path(plan_id)
        original = transport_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, transport_path.read_bytes())

    def test_preserves_context_pack_draft_provenance_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        provenance_path = self._draft_provenance_path(plan_id)
        original = provenance_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, provenance_path.read_bytes())

    def test_preserves_context_pack_md_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        context_pack_path = self._context_pack_path(plan_id)
        original = context_pack_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, context_pack_path.read_bytes())

    def test_preserves_implementation_plan_md_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        plan_path = self._implementation_plan_path(plan_id)
        original = plan_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, plan_path.read_bytes())

    def test_preserves_planning_audit_md_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        audit_path = self._planning_audit_path(plan_id)
        original = audit_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, audit_path.read_bytes())

    def test_does_not_change_planning_workspace_status(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        manifest_path = self._workspace(plan_id) / "manifest.json"
        before = manifest_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(before, manifest_path.read_bytes())

    def test_does_not_generate_architecture_choices(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        for forbidden in ("postgresql", "react", "kubernetes", "mongodb", "redis"):
            self.assertNotIn(forbidden, spec)

    def test_does_not_generate_implementation_tasks(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn("allowed_paths", spec)
        self.assertNotIn("check_command", spec)

    def test_does_not_generate_planning_run_slice(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        implementation_plan = self._implementation_plan_path(plan_id).read_text(
            encoding="utf-8"
        )
        self.assertIn('"artifact_type": "PLANNING_RUN_SLICE"', implementation_plan)

    def test_does_not_create_runner_proposals(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        workspace = self.project / ".agent-os"
        before = list((workspace / "runs").iterdir())

        self._scaffold(plan_id=plan_id)

        after = list((workspace / "runs").iterdir())
        self.assertEqual(before, after)

    def test_does_not_create_runs(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        self._scaffold(plan_id=plan_id)
        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_does_not_invoke_external_subprocess(self) -> None:
        self._setup_ready_for_scaffold()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code = main(
                [
                    "orchestrator",
                    "scaffold-local-agentic-spec",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 0)

    def test_does_not_call_planning_progress_transition_decide(self) -> None:
        self._setup_ready_for_scaffold()
        with (
            patch.object(planning_module, "progress_planning_workspace") as progress,
            patch.object(planning_module, "transition_planning_workspace") as transition,
            patch.object(planning_module, "record_planning_owner_decision") as decide,
        ):
            self._scaffold()
        progress.assert_not_called()
        transition.assert_not_called()
        decide.assert_not_called()

    def test_restores_local_spec_when_provenance_write_fails(self) -> None:
        from agent_os.orchestrator import scaffold_local_agentic_spec_from_context_pack

        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        original = local_spec.read_bytes()
        provenance_path = self._scaffold_provenance_path(plan_id)

        from agent_os import orchestrator as orchestrator_module

        original_write_json = orchestrator_module._write_json

        def failing_provenance_write(path: Path, data: dict) -> None:
            if path == provenance_path:
                raise OSError("simulated provenance write failure")
            original_write_json(path, data)

        with patch.object(orchestrator_module, "_write_json", failing_provenance_write):
            with self.assertRaises(OSError) as ctx:
                scaffold_local_agentic_spec_from_context_pack(
                    self.project,
                    intake_id,
                    plan_id,
                )
            self.assertIn("simulated provenance write failure", str(ctx.exception))

        self.assertEqual(original, local_spec.read_bytes())
        self.assertFalse(provenance_path.exists())

    def test_cli_help_states_scaffold_boundaries(self) -> None:
        parser = build_parser()
        orchestrator_parser = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
            and "orchestrator" in action.choices
        )
        orchestrator_sub = next(
            action
            for action in orchestrator_parser.choices["orchestrator"]._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        help_text = orchestrator_sub.choices[
            "scaffold-local-agentic-spec"
        ].format_help()
        compact = re.sub(r"\s+", " ", help_text)
        self.assertIn("scaffold", compact.lower())
        self.assertIn("requirements", compact.lower())
        self.assertIn("architecture", compact.lower())
        self.assertIn("implementation plan", compact.lower())
        self.assertIn("PLANNING_RUN_SLICE", compact)
        self.assertIn("validate", compact.lower())
        self.assertIn("executor", compact.lower())

    def test_cli_output_includes_paths_status_and_boundary_notes(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        code, output = self._scaffold(plan_id=plan_id)
        self.assertEqual(code, 0)
        self.assertIn("local agentic spec:", output)
        self.assertIn("local agentic spec scaffold provenance:", output)
        self.assertIn("workspace_status: DRAFT", output)
        self.assertIn("no requirements extraction", output.lower())

    def test_existing_commands_unchanged(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)
        self._draft_context_pack(intake_id, plan_id)
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            preflight_code = main(
                [
                    "orchestrator",
                    "local-agentic-spec-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        self.assertEqual(preflight_code, 0)
        self.assertIn("local-agentic-spec draft preflight", buf.getvalue())

        after = self._project_files()
        self.assertEqual(before, after)

    def test_scaffold_not_confusable_with_spec_approval(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        provenance = json.loads(
            self._scaffold_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        self.assertIn("scaffold", spec)
        self.assertIn("not validated or approved", spec)
        self.assertNotIn("approved", provenance.get("non_authority", {}))
        validation = validate_planning_workspace(self.project, plan_id)
        self.assertFalse(validation.valid)

    def test_no_artifact_claims_local_agentic_spec_approval(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        provenance = self._scaffold_provenance_path(plan_id).read_text(encoding="utf-8").lower()
        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertNotIn("local agentic spec approved", provenance)
        self.assertNotIn("spec approved", spec)
        self.assertIn("does_not_approve_plan", provenance)


class OrchestratorRequirementsExtractionPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(
            self.project,
            intake_id,
            clarification_id,
        )

    def _decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(
            self.project,
            intake_id,
            decision_id,
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _slither_with_clarification(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max; no persistence.",
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._slither_with_clarification(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _prepare(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _transport(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _draft_context_pack(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _local_spec_preflight(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "local-agentic-spec-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _scaffold(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-local-agentic-spec",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _preflight(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "requirements-extraction-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-pack-draft-provenance.json"
        )

    def _scaffold_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-local-agentic-spec-scaffold-provenance.json"
        )

    def _transport_json_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-transport.json"
        )

    def _transport_md_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-transport.md"
        )

    def _provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-provenance.json"
        )

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_preflight(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._local_spec_preflight(intake_id, plan_id)[0], 0)
        self.assertEqual(self._scaffold(intake_id, plan_id)[0], 0)

    def _tracked_artifact_paths(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> dict[Path, bytes]:
        workspace = self._workspace(plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._clarification_path(intake_id, "scope-v1"),
            self._decision_path(intake_id, "owner-v1"),
            self._provenance_path(plan_id),
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
            self._transport_json_path(plan_id),
            self._transport_md_path(plan_id),
            self._draft_provenance_path(plan_id),
            self._scaffold_provenance_path(plan_id),
            self._context_pack_path(plan_id),
            self._local_spec_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def _remove_local_spec_boundary_note(
        self,
        plan_id: str,
        needle: str,
    ) -> None:
        spec_path = self._local_spec_path(plan_id)
        lines = [
            line
            for line in spec_path.read_text(encoding="utf-8").splitlines()
            if needle.lower() not in line.lower()
        ]
        spec_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_successful_preflight_after_scaffold(self) -> None:
        self._setup_ready_for_preflight()
        code, output = self._preflight()
        self.assertEqual(code, 0)
        self.assertIn("requirements extraction preflight", output)

    def test_success_state_is_confirmed_no_requirements_generated(self) -> None:
        self._setup_ready_for_preflight()
        from agent_os.orchestrator import preflight_requirements_extraction

        report = preflight_requirements_extraction(
            self.project,
            "slither-demo",
            "slither-plan-v1",
        )
        self.assertEqual(
            report.preflight_state,
            "REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NO_REQUIREMENTS_GENERATED",
        )

    def test_success_next_action_requires_separate_command(self) -> None:
        self._setup_ready_for_preflight()
        from agent_os.orchestrator import preflight_requirements_extraction

        report = preflight_requirements_extraction(
            self.project,
            "slither-demo",
            "slither-plan-v1",
        )
        self.assertEqual(
            report.next_required_action,
            "FUTURE_REQUIREMENTS_EXTRACTION_REQUIRES_SEPARATE_COMMAND",
        )

    def test_report_contains_all_required_fields(self) -> None:
        self._setup_ready_for_preflight()
        from agent_os.orchestrator import preflight_requirements_extraction

        report = preflight_requirements_extraction(
            self.project,
            "slither-demo",
            "slither-plan-v1",
        )
        required_fields = (
            "preflight_state",
            "next_required_action",
            "plan_id",
            "intake_id",
            "planning_workspace_status",
            "local_agentic_spec_status",
            "local_agentic_spec_path",
            "local_agentic_spec_scaffold_provenance_path",
            "context_pack_path",
            "context_pack_provenance_path",
            "implementation_plan_path",
            "planning_audit_path",
            "latest_decision_id",
            "latest_decision",
            "source_preflight_state",
            "checked_at",
            "non_authority",
        )
        for field in required_fields:
            self.assertTrue(hasattr(report, field), f"missing field: {field}")

    def test_report_non_authority_flags_all_true(self) -> None:
        self._setup_ready_for_preflight()
        from agent_os.orchestrator import (
            REQUIREMENTS_EXTRACTION_PREFLIGHT_NON_AUTHORITY_FLAGS,
            preflight_requirements_extraction,
        )

        report = preflight_requirements_extraction(
            self.project,
            "slither-demo",
            "slither-plan-v1",
        )
        for flag in REQUIREMENTS_EXTRACTION_PREFLIGHT_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, report.non_authority)
            self.assertTrue(report.non_authority[flag])

    def test_preflight_is_read_only_on_success(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._tracked_artifact_paths(intake_id, plan_id)
        manifest_bytes = (self._workspace(plan_id) / "manifest.json").read_bytes()

        self._preflight(intake_id, plan_id)

        after = self._tracked_artifact_paths(intake_id, plan_id)
        self.assertEqual(before, after)
        self.assertEqual(
            manifest_bytes,
            (self._workspace(plan_id) / "manifest.json").read_bytes(),
        )

    def test_does_not_change_planning_readiness(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        artifact_path = self._artifact_path(intake_id)
        original_bytes = artifact_path.read_bytes()
        before = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]

        self._preflight(intake_id, plan_id)

        after = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]
        self.assertEqual(before, after)
        self.assertEqual(original_bytes, artifact_path.read_bytes())

    def test_preflight_is_read_only_on_failure(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        scaffold_provenance = json.loads(
            self._scaffold_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        scaffold_provenance["intake_id"] = "wrong-intake"
        self._scaffold_provenance_path(plan_id).write_text(
            json.dumps(scaffold_provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        before_artifacts = self._tracked_artifact_paths(intake_id, plan_id)
        before_files = self._project_files()
        manifest_path = self._workspace(plan_id) / "manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        implementation_plan = self._implementation_plan_path(plan_id).read_text(
            encoding="utf-8"
        )

        with (
            patch("subprocess.run", side_effect=AssertionError("subprocess invoked")),
            patch.object(
                planning_module,
                "progress_planning_workspace",
                side_effect=AssertionError("progress invoked"),
            ),
            patch.object(
                planning_module,
                "transition_planning_workspace",
                side_effect=AssertionError("transition invoked"),
            ),
            patch.object(
                planning_module,
                "record_planning_owner_decision",
                side_effect=AssertionError("decide invoked"),
            ),
        ):
            code, output = self._preflight(intake_id, plan_id)

        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_PROVENANCE_MISMATCH", output)
        self.assertEqual(before_artifacts, self._tracked_artifact_paths(intake_id, plan_id))
        self.assertEqual(before_files, self._project_files())
        self.assertEqual(manifest_bytes, manifest_path.read_bytes())
        self.assertEqual(before_runs, list((workspace / "runs").iterdir()))
        self.assertIn('"artifact_type": "PLANNING_RUN_SLICE"', implementation_plan)
        self.assertIn("PLACEHOLDER-slice-id", implementation_plan)
        self.assertEqual(
            implementation_plan,
            self._implementation_plan_path(plan_id).read_text(encoding="utf-8"),
        )

    def test_refuses_missing_workspace(self) -> None:
        bare = self.project / "bare"
        bare.mkdir()

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "requirements-extraction-preflight",
                    "slither-demo",
                    str(bare),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_WORKSPACE", buf.getvalue())

    def test_refuses_missing_intake(self) -> None:
        plan_id = "orphan-plan"
        self._authorize_slither()
        self._prepare(plan_id=plan_id)
        self._transport(plan_id=plan_id)
        self._draft_context_pack(plan_id=plan_id)
        self._local_spec_preflight(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        code, output = self._preflight("missing-intake", plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_INVALID_INTAKE", output)

    def test_refuses_invalid_intake(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        path = self._artifact_path(intake_id)
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact["artifact_type"] = "WRONG_TYPE"
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_INVALID_INTAKE", output)

    def test_refuses_missing_planning_workspace(self) -> None:
        self._authorize_slither()
        code, output = self._preflight(plan_id="missing-plan")
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_PLANNING_WORKSPACE", output)

    def test_refuses_non_draft_planning_workspace(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        manifest_path = self._workspace(plan_id) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["status"] = "CONTEXT_READY"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_WORKSPACE_NOT_DRAFT", output)

    def test_refuses_missing_orchestrator_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        init_planning_workspace(self.project, plan_id)
        self._transport_json_path(plan_id).parent.mkdir(parents=True, exist_ok=True)
        self._transport_json_path(plan_id).write_text("{}", encoding="utf-8")
        self._transport_md_path(plan_id).write_text("# stub\n", encoding="utf-8")

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_ORCHESTRATOR_PROVENANCE", output)

    def test_refuses_missing_context_transport_json(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_CONTEXT_TRANSPORT", output)

    def test_refuses_missing_context_transport_markdown(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        transport = {
            "artifact_type": "ORCHESTRATOR_CONTEXT_TRANSPORT",
            "schema_version": "0.1",
            "plan_id": plan_id,
            "intake_id": intake_id,
            "source_context": {},
            "owner_clarifications": [],
            "owner_readiness_decision": {},
        }
        self._transport_json_path(plan_id).parent.mkdir(parents=True, exist_ok=True)
        self._transport_json_path(plan_id).write_text(
            json.dumps(transport, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_CONTEXT_TRANSPORT", output)

    def test_refuses_missing_context_pack_draft_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_CONTEXT_PACK_DRAFT_PROVENANCE", output)

    def test_refuses_missing_local_agentic_spec_scaffold_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)
        self._draft_context_pack(intake_id, plan_id)
        self._local_spec_preflight(intake_id, plan_id)

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE", output)

    def test_refuses_missing_context_pack_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        self._context_pack_path(plan_id).unlink()

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_UNEXPECTED_STRUCTURE", output)

    def test_refuses_missing_local_agentic_spec_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        self._local_spec_path(plan_id).unlink()

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_UNEXPECTED_STRUCTURE", output)

    def test_refuses_missing_implementation_plan_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        self._implementation_plan_path(plan_id).unlink()

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_UNEXPECTED_STRUCTURE", output)

    def test_refuses_missing_planning_audit_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        self._planning_audit_path(plan_id).unlink()

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_UNEXPECTED_STRUCTURE", output)

    def test_refuses_provenance_plan_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        provenance = json.loads(
            self._provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["plan_id"] = "wrong-plan"
        self._provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT", output)

    def test_refuses_provenance_intake_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        provenance = json.loads(
            self._provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["intake_id"] = "wrong-intake"
        self._provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT", output)

    def test_refuses_context_transport_plan_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        transport = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        transport["plan_id"] = "wrong-plan"
        self._transport_json_path(plan_id).write_text(
            json.dumps(transport, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_UNEXPECTED_STRUCTURE", output)

    def test_refuses_context_transport_intake_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        transport = json.loads(
            self._transport_json_path(plan_id).read_text(encoding="utf-8")
        )
        transport["intake_id"] = "wrong-intake"
        self._transport_json_path(plan_id).write_text(
            json.dumps(transport, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_UNEXPECTED_STRUCTURE", output)

    def test_refuses_context_pack_draft_provenance_plan_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        draft_provenance = json.loads(
            self._draft_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        draft_provenance["plan_id"] = "wrong-plan"
        self._draft_provenance_path(plan_id).write_text(
            json.dumps(draft_provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CONTEXT_PACK_PROVENANCE_MISMATCH", output)

    def test_refuses_context_pack_draft_provenance_intake_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        draft_provenance = json.loads(
            self._draft_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        draft_provenance["intake_id"] = "wrong-intake"
        self._draft_provenance_path(plan_id).write_text(
            json.dumps(draft_provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CONTEXT_PACK_PROVENANCE_MISMATCH", output)

    def test_refuses_scaffold_provenance_plan_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        scaffold_provenance = json.loads(
            self._scaffold_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        scaffold_provenance["plan_id"] = "wrong-plan"
        self._scaffold_provenance_path(plan_id).write_text(
            json.dumps(scaffold_provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_PROVENANCE_MISMATCH", output)

    def test_refuses_scaffold_provenance_intake_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        scaffold_provenance = json.loads(
            self._scaffold_provenance_path(plan_id).read_text(encoding="utf-8")
        )
        scaffold_provenance["intake_id"] = "wrong-intake"
        self._scaffold_provenance_path(plan_id).write_text(
            json.dumps(scaffold_provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_PROVENANCE_MISMATCH", output)

    def test_refuses_stale_incoherent_authorization(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        provenance = json.loads(
            self._provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["source_authorize_decision_id"] = "stale-decision"
        self._provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT", output)

    def test_refuses_latest_request_more_clarification_after_authorize(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "REQUEST_MORE_CLARIFICATION",
            "Need more detail on multiplayer scope.",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_DECISION_REQUESTS_CLARIFICATION", output)

    def test_refuses_latest_block_intake_after_authorize(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "BLOCK_INTAKE",
            "Scope too broad; stop intake.",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_DECISION_BLOCKS_INTAKE", output)

    def test_refuses_local_agentic_spec_not_scaffold_draft_non_authority(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8").replace(
                "SCAFFOLD_DRAFT_NON_AUTHORITY",
                "APPROVED",
            ),
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_NOT_SCAFFOLD_DRAFT_NON_AUTHORITY", output)

    def test_refuses_missing_requirements_extraction_not_performed_boundary(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(plan_id=plan_id)
        self._remove_local_spec_boundary_note(plan_id, "requirements extraction")
        code, output = self._preflight(plan_id=plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_BOUNDARY_NOTES_MISSING", output)

    def test_refuses_missing_architecture_undecided_boundary(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(plan_id=plan_id)
        self._remove_local_spec_boundary_note(plan_id, "architecture")
        code, output = self._preflight(plan_id=plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_BOUNDARY_NOTES_MISSING", output)

    def test_refuses_missing_implementation_plan_not_generated_boundary(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(plan_id=plan_id)
        self._remove_local_spec_boundary_note(plan_id, "implementation plan")
        code, output = self._preflight(plan_id=plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_BOUNDARY_NOTES_MISSING", output)

    def test_refuses_missing_planning_run_slice_not_generated_boundary(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(plan_id=plan_id)
        self._remove_local_spec_boundary_note(plan_id, "PLANNING_RUN_SLICE")
        code, output = self._preflight(plan_id=plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_BOUNDARY_NOTES_MISSING", output)

    def test_refuses_local_agentic_spec_with_generated_functional_requirements(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\n## Functional Requirements\n\nThe system shall handle login.\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_REQUIREMENTS", output)

    def test_refuses_local_agentic_spec_with_user_stories(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\n## User Stories\n\nAs a user I want to play.\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_USER_STORIES", output)

    def test_refuses_local_agentic_spec_with_acceptance_criteria(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\n## Acceptance Criteria\n\nGiven a player When they join Then game starts.\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_ACCEPTANCE_CRITERIA", output)

    def test_refuses_local_agentic_spec_with_architecture_decision_language(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\nSelected backend: Node.js with WebSockets.\n",
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("architecture", output.lower())

    def test_refuses_modified_implementation_plan(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        plan = self._implementation_plan_path(plan_id)
        plan.write_text(
            plan.read_text(encoding="utf-8").replace("PLACEHOLDER", "CUSTOMIZED", 1),
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_IMPLEMENTATION_PLAN_ALREADY_MODIFIED", output)

    def test_refuses_modified_planning_audit(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        audit = self._planning_audit_path(plan_id)
        audit.write_text(
            audit.read_text(encoding="utf-8").replace("PLACEHOLDER", "CUSTOMIZED", 1),
            encoding="utf-8",
        )

        code, output = self._preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_PLANNING_AUDIT_ALREADY_MODIFIED", output)

    def test_refuses_invalid_plan_id(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._tracked_artifact_paths(intake_id, plan_id)

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "requirements-extraction-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    "../escape",
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("invalid plan id", buf.getvalue())
        self.assertEqual(before, self._tracked_artifact_paths(intake_id, plan_id))

    def test_refuses_path_escape_intake_id(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._tracked_artifact_paths(intake_id, plan_id)

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "requirements-extraction-preflight",
                    "../escape",
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )

        self.assertEqual(code, 1)
        self.assertIn("invalid intake id", buf.getvalue())
        self.assertEqual(before, self._tracked_artifact_paths(intake_id, plan_id))

    def test_creates_no_preflight_artifact(self) -> None:
        self._setup_ready_for_preflight()
        before = self._project_files()
        self._preflight()
        after = self._project_files()
        self.assertEqual(before, after)

    def test_does_not_mutate_context_pack(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._context_pack_path(plan_id).read_bytes()
        self._preflight(intake_id, plan_id)
        self.assertEqual(before, self._context_pack_path(plan_id).read_bytes())

    def test_does_not_mutate_local_agentic_spec(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._local_spec_path(plan_id).read_bytes()
        self._preflight(intake_id, plan_id)
        self.assertEqual(before, self._local_spec_path(plan_id).read_bytes())

    def test_does_not_mutate_implementation_plan(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._implementation_plan_path(plan_id).read_bytes()
        self._preflight(intake_id, plan_id)
        self.assertEqual(before, self._implementation_plan_path(plan_id).read_bytes())

    def test_does_not_mutate_planning_audit(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._planning_audit_path(plan_id).read_bytes()
        self._preflight(intake_id, plan_id)
        self.assertEqual(before, self._planning_audit_path(plan_id).read_bytes())

    def test_does_not_mutate_evidence_artifacts(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = {
            path: path.read_bytes()
            for path in (
                self._provenance_path(plan_id),
                self._workspace(plan_id) / "evidence" / "orchestrator-draft-scaffold-notes.md",
                self._transport_json_path(plan_id),
                self._transport_md_path(plan_id),
                self._draft_provenance_path(plan_id),
                self._scaffold_provenance_path(plan_id),
            )
        }
        self._preflight(intake_id, plan_id)
        for path, original in before.items():
            self.assertEqual(original, path.read_bytes(), msg=str(path))

    def test_does_not_mutate_source_orchestrator_artifacts(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._clarification_path(intake_id, "scope-v1"),
            self._decision_path(intake_id, "owner-v1"),
        ]
        before = {path: path.read_bytes() for path in paths}
        self._preflight(intake_id, plan_id)
        for path, original in before.items():
            self.assertEqual(original, path.read_bytes(), msg=str(path))

    def test_does_not_change_planning_workspace_status(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        manifest_path = self._workspace(plan_id) / "manifest.json"
        before = manifest_path.read_bytes()
        self._preflight(intake_id, plan_id)
        self.assertEqual(before, manifest_path.read_bytes())

    def test_does_not_extract_requirements(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        before = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self._preflight(intake_id, plan_id)
        after = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertEqual(before, after)
        self.assertNotIn("the system shall", after.lower())

    def test_does_not_generate_user_stories(self) -> None:
        self._setup_ready_for_preflight()
        self._preflight()
        spec = self._local_spec_path().read_text(encoding="utf-8").lower()
        self.assertNotIn("as a user", spec)

    def test_does_not_generate_acceptance_criteria(self) -> None:
        self._setup_ready_for_preflight()
        self._preflight()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("| Acceptance Criteria | NOT_GENERATED |", spec)

    def test_does_not_generate_architecture_choices(self) -> None:
        self._setup_ready_for_preflight()
        self._preflight()
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file()
        ).lower()
        self.assertNotIn("backend: node", combined)
        self.assertNotIn("selected backend", combined)

    def test_does_not_generate_implementation_tasks(self) -> None:
        self._setup_ready_for_preflight()
        self._preflight()
        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file()
        )
        self.assertNotIn('"slice_id": "slice-', combined)

    def test_does_not_generate_planning_run_slice(self) -> None:
        self._setup_ready_for_preflight()
        self._preflight()
        plan = self._implementation_plan_path().read_text(encoding="utf-8")
        self.assertIn('"artifact_type": "PLANNING_RUN_SLICE"', plan)
        self.assertIn("PLACEHOLDER-slice-id", plan)

    def test_does_not_create_runner_proposals(self) -> None:
        self._setup_ready_for_preflight()
        before = self._project_files()
        self._preflight()
        self.assertEqual(before, self._project_files())

    def test_does_not_create_runs(self) -> None:
        self._setup_ready_for_preflight()
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        self._preflight()
        self.assertEqual(before_runs, list((workspace / "runs").iterdir()))

    def test_does_not_invoke_external_subprocess(self) -> None:
        self._setup_ready_for_preflight()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code = main(
                [
                    "orchestrator",
                    "requirements-extraction-preflight",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 0)

    def test_does_not_call_planning_progress_transition_decide(self) -> None:
        self._setup_ready_for_preflight()
        with (
            patch.object(planning_module, "progress_planning_workspace") as progress,
            patch.object(planning_module, "transition_planning_workspace") as transition,
            patch.object(planning_module, "record_planning_owner_decision") as decide,
        ):
            self._preflight()
        progress.assert_not_called()
        transition.assert_not_called()
        decide.assert_not_called()

    def test_cli_help_states_preflight_boundaries(self) -> None:
        parser = build_parser()
        orchestrator_parser = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
            and "orchestrator" in action.choices
        )
        orchestrator_sub = next(
            action
            for action in orchestrator_parser.choices["orchestrator"]._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        help_text = orchestrator_sub.choices[
            "requirements-extraction-preflight"
        ].format_help()
        compact = re.sub(r"\s+", " ", help_text)
        self.assertIn("read-only", compact.lower())
        self.assertIn("requirements", compact.lower())
        self.assertIn("architecture", compact.lower())
        self.assertIn("implementation plan", compact.lower())
        self.assertIn("PLANNING_RUN_SLICE", compact)
        self.assertIn("validate", compact.lower())
        self.assertIn("executor", compact.lower())

    def test_cli_output_includes_paths_status_and_boundary_notes(self) -> None:
        self._setup_ready_for_preflight()
        code, output = self._preflight()
        self.assertEqual(code, 0)
        self.assertIn("local_agentic_spec_path:", output)
        self.assertIn("planning_workspace_status: DRAFT", output)
        self.assertIn("SCAFFOLD_DRAFT_NON_AUTHORITY", output)
        self.assertIn("requirements extraction", output.lower())

    def test_existing_commands_unchanged(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)
        self._draft_context_pack(intake_id, plan_id)
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            draft_preflight_code = main(
                [
                    "orchestrator",
                    "draft-preflight",
                    intake_id,
                    str(self.project),
                ]
            )
            local_preflight_code = main(
                [
                    "orchestrator",
                    "local-agentic-spec-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        self.assertEqual(draft_preflight_code, 0)
        self.assertEqual(local_preflight_code, 0)
        self.assertIn("draft-preparation preflight", buf.getvalue())

        after = self._project_files()
        self.assertEqual(before, after)

    def test_preflight_not_confusable_with_requirements_extraction_or_approval(
        self,
    ) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(plan_id=plan_id)
        code, output = self._preflight(plan_id=plan_id)
        self.assertEqual(code, 0)
        self.assertIn("no requirements were extracted", output.lower())
        self.assertIn("not validated or approved", output.lower())
        validation = validate_planning_workspace(self.project, plan_id)
        self.assertFalse(validation.valid)


class OrchestratorRequirementsExtractionScaffoldTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(
            self.project,
            intake_id,
            clarification_id,
        )

    def _decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(
            self.project,
            intake_id,
            decision_id,
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _slither_with_clarification(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max; no persistence.",
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._slither_with_clarification(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _prepare(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _transport(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _draft_context_pack(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _local_spec_preflight(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "local-agentic-spec-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _scaffold_local_spec(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-local-agentic-spec",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _preflight(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "requirements-extraction-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _scaffold(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-requirements-extraction",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-pack-draft-provenance.json"
        )

    def _scaffold_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-local-agentic-spec-scaffold-provenance.json"
        )

    def _requirements_scaffold_provenance_path(
        self,
        plan_id: str = "slither-plan-v1",
    ) -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-requirements-extraction-scaffold-provenance.json"
        )

    def _transport_json_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-transport.json"
        )

    def _transport_md_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-transport.md"
        )

    def _provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-provenance.json"
        )

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_scaffold(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._local_spec_preflight(intake_id, plan_id)[0], 0)
        self.assertEqual(self._scaffold_local_spec(intake_id, plan_id)[0], 0)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

    def _tracked_artifact_paths(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> dict[Path, bytes]:
        workspace = self._workspace(plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._clarification_path(intake_id, "scope-v1"),
            self._decision_path(intake_id, "owner-v1"),
            self._provenance_path(plan_id),
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
            self._transport_json_path(plan_id),
            self._transport_md_path(plan_id),
            self._draft_provenance_path(plan_id),
            self._scaffold_provenance_path(plan_id),
            self._context_pack_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def test_succeeds_only_after_successful_requirements_extraction_preflight(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)
        self._draft_context_pack(intake_id, plan_id)
        self._local_spec_preflight(intake_id, plan_id)

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

        self._scaffold_local_spec(intake_id, plan_id)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)
        code, output = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 0)
        self.assertIn("orchestrator requirements-extraction scaffold created:", output)

    def test_local_agentic_spec_replaced_with_requirements_extraction_scaffold(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        before = self._local_spec_path(plan_id).read_bytes()

        self._scaffold(plan_id=plan_id)

        after = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotEqual(before, after.encode("utf-8"))
        self.assertIn("REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY", after)

    def test_requirements_extraction_scaffold_provenance_created(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)
        self.assertTrue(self._requirements_scaffold_provenance_path(plan_id).is_file())

    def test_provenance_contains_required_fields(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self._scaffold(intake_id, plan_id)

        artifact = json.loads(
            self._requirements_scaffold_provenance_path(plan_id).read_text(
                encoding="utf-8"
            )
        )
        required_fields = (
            "artifact_type",
            "schema_version",
            "plan_id",
            "intake_id",
            "source_local_agentic_spec_scaffold_provenance_path",
            "source_context_pack_path",
            "source_requirements_extraction_preflight_state",
            "source_requirements_extraction_preflight_next_action",
            "source_authorize_decision_id",
            "local_agentic_spec_path",
            "local_agentic_spec_status",
            "planning_workspace_status_at_scaffold",
            "created_at",
            "non_authority",
        )
        for field in required_fields:
            self.assertIn(field, artifact, f"missing field: {field}")
        self.assertEqual(
            artifact["artifact_type"],
            "ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE",
        )
        self.assertEqual(artifact["schema_version"], "0.1")

    def test_provenance_non_authority_flags_all_true(self) -> None:
        from agent_os.orchestrator import (
            ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY_FLAGS,
        )

        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        artifact = json.loads(
            self._requirements_scaffold_provenance_path(plan_id).read_text(
                encoding="utf-8"
            )
        )
        non_authority = artifact["non_authority"]
        for flag in ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, non_authority)
            self.assertTrue(non_authority[flag])

    def test_scaffold_labels_requirements_extraction_scaffold_non_authority(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY", spec)

    def test_scaffold_contains_source_context_pack_and_scaffold_provenance_paths(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("context-pack", spec.lower())
        self.assertIn(
            "orchestrator-local-agentic-spec-scaffold-provenance.json",
            spec,
        )

    def test_scaffold_states_requirements_extraction_not_performed(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertIn("requirements extraction", spec)
        self.assertIn("not performed", spec)

    def test_scaffold_states_future_requirements_extraction_requires_separate_command(
        self,
    ) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertIn("separate command", spec)
        self.assertIn("future requirements extraction", spec)

    def test_scaffold_states_architecture_undecided(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("UNDECIDED_NOT_GENERATED", spec)
        self.assertIn("architecture", spec.lower())

    def test_scaffold_states_implementation_plan_not_generated(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("Implementation Plan", spec)
        self.assertIn("NOT_GENERATED", spec)

    def test_scaffold_states_planning_run_slice_not_generated(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("PLANNING_RUN_SLICE", spec)
        self.assertIn("NOT_GENERATED", spec)

    def test_scaffold_contains_only_empty_requirements_containers(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("NO_REQUIREMENTS_EXTRACTED", spec)
        self.assertNotIn("PENDING_FUTURE_REQUIREMENTS_EXTRACTION", spec)
        self.assertNotIn("The system shall", spec)

    def test_scaffold_uses_no_requirements_extracted_and_not_generated_markers(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("| Functional Requirements | NO_REQUIREMENTS_EXTRACTED |", spec)
        self.assertIn("| User Stories | NOT_GENERATED |", spec)
        self.assertIn("| Acceptance Criteria | NOT_GENERATED |", spec)

    def test_scaffold_does_not_include_raw_goal(self) -> None:
        plan_id = "slither-plan-v1"
        raw_goal = "Build me an online slither.io-like game"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn(raw_goal, spec)

    def test_scaffold_does_not_include_normalized_goal(self) -> None:
        intake_id = "norm-goal-demo"
        plan_id = "norm-goal-plan"
        raw_goal = "Build  me   an online slither.io-like game"
        create_goal_intake(self.project, intake_id, raw_goal)
        artifact = json.loads(self._artifact_path(intake_id).read_text(encoding="utf-8"))
        normalized_goal = artifact["normalized_goal"]
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo.",
        )
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Authorize draft prep.",
        )
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)
        self._draft_context_pack(intake_id, plan_id)
        self._local_spec_preflight(intake_id, plan_id)
        self._scaffold_local_spec(intake_id, plan_id)
        self._preflight(intake_id, plan_id)
        self._scaffold(intake_id, plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn(normalized_goal, spec)

    def test_scaffold_does_not_include_clarification_answers(self) -> None:
        plan_id = "slither-plan-v1"
        clarification = "Browser-only demo with 10 players max; no persistence."
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn(clarification, spec)

    def test_scaffold_does_not_generate_functional_requirements(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn("The system shall", spec)
        self.assertNotIn("FR-", spec)

    def test_scaffold_does_not_generate_non_functional_requirements(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        functional_section = spec.split("## Requirements containers")[0]
        self.assertNotIn("latency", functional_section.lower())
        self.assertIn("NO_REQUIREMENTS_EXTRACTED", spec)

    def test_scaffold_does_not_generate_constraints(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("| Constraints | NO_REQUIREMENTS_EXTRACTED |", spec)
        self.assertNotIn("must use", spec.lower())

    def test_scaffold_does_not_generate_out_of_scope_decisions(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("| Out of Scope | NO_REQUIREMENTS_EXTRACTED |", spec)
        self.assertNotIn("explicitly excluded", spec.lower())

    def test_scaffold_does_not_generate_user_stories(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn("As a user", spec)
        self.assertIn("| User Stories | NOT_GENERATED |", spec)

    def test_scaffold_does_not_generate_acceptance_criteria(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn("Given ", spec)
        self.assertIn("| Acceptance Criteria | NOT_GENERATED |", spec)

    def test_scaffold_does_not_generate_architecture_choices(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        for forbidden in ("postgresql", "react", "kubernetes", "selected backend"):
            self.assertNotIn(forbidden, spec)

    def test_refuses_missing_workspace(self) -> None:
        project = Path(self._tmp.name) / "missing"
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-requirements-extraction",
                    "slither-demo",
                    str(project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 1)

    def test_refuses_missing_intake(self) -> None:
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-requirements-extraction",
                    "missing-intake",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 1)

    def test_refuses_invalid_intake(self) -> None:
        intake_id = "invalid-intake"
        create_goal_intake(self.project, intake_id, "Valid goal for invalid test")
        artifact_path = self._artifact_path(intake_id)
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        artifact["planning_readiness"] = "DRAFT_ALLOWED"
        artifact_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-requirements-extraction",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 1)

    def test_refuses_missing_planning_workspace(self) -> None:
        self._authorize_slither()
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-requirements-extraction",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "missing-plan",
                ]
            )
        self.assertEqual(code, 1)

    def test_refuses_non_draft_planning_workspace(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        manifest_path = self._workspace(plan_id) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["status"] = "CONTEXT_READY"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_failed_requirements_extraction_preflight(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)
        self._draft_context_pack(intake_id, plan_id)
        self._local_spec_preflight(intake_id, plan_id)

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_stale_incoherent_authorization(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        provenance = json.loads(
            self._provenance_path(plan_id).read_text(encoding="utf-8")
        )
        provenance["source_authorize_decision_id"] = "stale-decision"
        self._provenance_path(plan_id).write_text(
            json.dumps(provenance, indent=2) + "\n",
            encoding="utf-8",
        )

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_latest_request_more_clarification_after_authorize(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "REQUEST_MORE_CLARIFICATION",
            "Need more detail on multiplayer scope.",
        )

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_latest_block_intake_after_authorize(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "BLOCK_INTAKE",
            "Scope too broad; stop intake.",
        )

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_context_pack_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self._context_pack_path(plan_id).unlink()

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_local_agentic_spec_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self._local_spec_path(plan_id).unlink()

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_not_scaffold_draft_non_authority(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8").replace(
                "SCAFFOLD_DRAFT_NON_AUTHORITY",
                "APPROVED",
            ),
            encoding="utf-8",
        )

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_already_containing_requirements(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\n## Functional Requirements\n\nThe system shall handle login.\n",
            encoding="utf-8",
        )

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_already_containing_user_stories(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\n## User Stories\n\nAs a user I want to play.\n",
            encoding="utf-8",
        )

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_already_containing_acceptance_criteria(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\n## Acceptance Criteria\n\nGiven a player When they join Then game starts.\n",
            encoding="utf-8",
        )

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_already_containing_architecture_decision_language(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\nSelected backend: Node.js with WebSockets.\n",
            encoding="utf-8",
        )

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_local_agentic_spec_scaffold_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self._scaffold_provenance_path(plan_id).unlink()

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_modified_implementation_plan_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        path = self._implementation_plan_path(plan_id)
        path.write_text(path.read_text(encoding="utf-8") + "\nmodified\n", encoding="utf-8")

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_modified_planning_audit_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        path = self._planning_audit_path(plan_id)
        path.write_text(path.read_text(encoding="utf-8") + "\nmodified\n", encoding="utf-8")

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_context_pack_draft_provenance_without_mutation(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        local_spec_before = self._local_spec_path(plan_id).read_bytes()
        implementation_plan_before = self._implementation_plan_path(plan_id).read_bytes()
        planning_audit_before = self._planning_audit_path(plan_id).read_bytes()

        self._draft_provenance_path(plan_id).unlink()
        before = self._tracked_artifact_paths(intake_id, plan_id)

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertEqual(local_spec_before, self._local_spec_path(plan_id).read_bytes())
        self.assertFalse(self._requirements_scaffold_provenance_path(plan_id).exists())
        self.assertEqual(
            implementation_plan_before,
            self._implementation_plan_path(plan_id).read_bytes(),
        )
        self.assertEqual(
            planning_audit_before,
            self._planning_audit_path(plan_id).read_bytes(),
        )
        self.assertEqual(before, self._tracked_artifact_paths(intake_id, plan_id))

    def test_refuses_when_draft_preflight_not_confirmed_at_scaffold_time_without_mutation(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        before = self._tracked_artifact_paths(intake_id, plan_id)
        local_spec_before = self._local_spec_path(plan_id).read_bytes()
        implementation_plan_before = self._implementation_plan_path(plan_id).read_bytes()
        planning_audit_before = self._planning_audit_path(plan_id).read_bytes()

        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "BLOCK_INTAKE",
            "Scope too broad; stop intake.",
        )

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertEqual(local_spec_before, self._local_spec_path(plan_id).read_bytes())
        self.assertFalse(self._requirements_scaffold_provenance_path(plan_id).exists())
        self.assertEqual(
            implementation_plan_before,
            self._implementation_plan_path(plan_id).read_bytes(),
        )
        self.assertEqual(
            planning_audit_before,
            self._planning_audit_path(plan_id).read_bytes(),
        )
        self.assertEqual(before, self._tracked_artifact_paths(intake_id, plan_id))

    def test_refuses_requirements_extraction_preflight_next_action_mismatch_without_mutation(
        self,
    ) -> None:
        from agent_os import orchestrator as orchestrator_module
        from agent_os.orchestrator import (
            REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE,
            RequirementsExtractionPreflightReport,
            preflight_requirements_extraction,
        )

        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        real_report = preflight_requirements_extraction(self.project, intake_id, plan_id)
        before = self._tracked_artifact_paths(intake_id, plan_id)
        local_spec_before = self._local_spec_path(plan_id).read_bytes()

        spoofed = RequirementsExtractionPreflightReport(
            output=real_report.output,
            preflight_state=REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE,
            next_required_action="UNEXPECTED_NEXT_ACTION",
            plan_id=real_report.plan_id,
            intake_id=real_report.intake_id,
            planning_workspace_status=real_report.planning_workspace_status,
            local_agentic_spec_status=real_report.local_agentic_spec_status,
            local_agentic_spec_path=real_report.local_agentic_spec_path,
            local_agentic_spec_scaffold_provenance_path=(
                real_report.local_agentic_spec_scaffold_provenance_path
            ),
            context_pack_path=real_report.context_pack_path,
            context_pack_provenance_path=real_report.context_pack_provenance_path,
            implementation_plan_path=real_report.implementation_plan_path,
            planning_audit_path=real_report.planning_audit_path,
            latest_decision_id=real_report.latest_decision_id,
            latest_decision=real_report.latest_decision,
            source_preflight_state=real_report.source_preflight_state,
            checked_at=real_report.checked_at,
            blocking_reasons=(),
            non_authority=real_report.non_authority,
        )

        with patch.object(
            orchestrator_module,
            "preflight_requirements_extraction",
            return_value=spoofed,
        ):
            code, _ = self._scaffold(intake_id, plan_id)

        self.assertEqual(code, 1)
        self.assertEqual(local_spec_before, self._local_spec_path(plan_id).read_bytes())
        self.assertFalse(self._requirements_scaffold_provenance_path(plan_id).exists())
        self.assertEqual(before, self._tracked_artifact_paths(intake_id, plan_id))

    def test_refuses_local_agentic_spec_containing_requirement_id_pattern(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\nREQ-001: placeholder requirement.\n",
            encoding="utf-8",
        )
        injected = local_spec.read_bytes()

        code, _ = self._scaffold(intake_id, plan_id)

        self.assertEqual(code, 1)
        self.assertEqual(injected, local_spec.read_bytes())
        self.assertFalse(self._requirements_scaffold_provenance_path(plan_id).exists())

    def test_refuses_existing_requirements_extraction_scaffold_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self._scaffold(intake_id, plan_id)
        local_spec_bytes = self._local_spec_path(plan_id).read_bytes()
        provenance_bytes = self._requirements_scaffold_provenance_path(plan_id).read_bytes()

        code, _ = self._scaffold(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertEqual(local_spec_bytes, self._local_spec_path(plan_id).read_bytes())
        self.assertEqual(
            provenance_bytes,
            self._requirements_scaffold_provenance_path(plan_id).read_bytes(),
        )

    def test_refuses_invalid_plan_id(self) -> None:
        self._setup_ready_for_scaffold()
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-requirements-extraction",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "../escape",
                ]
            )
        self.assertEqual(code, 1)

    def test_refuses_path_escape_intake_id(self) -> None:
        self._setup_ready_for_scaffold()
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-requirements-extraction",
                    "../escape",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 1)

    def test_preserves_goal_intake_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        artifact_path = self._artifact_path(intake_id)
        original = artifact_path.read_bytes()

        self._scaffold(intake_id, plan_id)

        self.assertEqual(original, artifact_path.read_bytes())

    def test_preserves_clarification_artifacts_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        clarification_path = self._clarification_path(intake_id, "scope-v1")
        original = clarification_path.read_bytes()

        self._scaffold(intake_id, plan_id)

        self.assertEqual(original, clarification_path.read_bytes())

    def test_preserves_readiness_decision_artifacts_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        decision_path = self._decision_path(intake_id, "owner-v1")
        original = decision_path.read_bytes()

        self._scaffold(intake_id, plan_id)

        self.assertEqual(original, decision_path.read_bytes())

    def test_preserves_orchestrator_provenance_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        provenance_path = self._provenance_path(plan_id)
        original = provenance_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, provenance_path.read_bytes())

    def test_preserves_scaffold_notes_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        notes_path = self._workspace(plan_id) / "evidence" / "orchestrator-draft-scaffold-notes.md"
        original = notes_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, notes_path.read_bytes())

    def test_preserves_context_transport_json_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        transport_path = self._transport_json_path(plan_id)
        original = transport_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, transport_path.read_bytes())

    def test_preserves_context_transport_markdown_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        transport_path = self._transport_md_path(plan_id)
        original = transport_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, transport_path.read_bytes())

    def test_preserves_context_pack_draft_provenance_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        provenance_path = self._draft_provenance_path(plan_id)
        original = provenance_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, provenance_path.read_bytes())

    def test_preserves_local_agentic_spec_scaffold_provenance_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        provenance_path = self._scaffold_provenance_path(plan_id)
        original = provenance_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, provenance_path.read_bytes())

    def test_preserves_context_pack_md_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        context_pack_path = self._context_pack_path(plan_id)
        original = context_pack_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, context_pack_path.read_bytes())

    def test_preserves_implementation_plan_md_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        plan_path = self._implementation_plan_path(plan_id)
        original = plan_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, plan_path.read_bytes())

    def test_preserves_planning_audit_md_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        audit_path = self._planning_audit_path(plan_id)
        original = audit_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(original, audit_path.read_bytes())

    def test_does_not_change_planning_workspace_status(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        manifest_path = self._workspace(plan_id) / "manifest.json"
        before = manifest_path.read_bytes()

        self._scaffold(plan_id=plan_id)

        self.assertEqual(before, manifest_path.read_bytes())

    def test_does_not_extract_requirements(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("NO_REQUIREMENTS_EXTRACTED", spec)
        self.assertNotIn("REQ-", spec)

    def test_does_not_generate_user_stories(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn("As a user", spec)

    def test_does_not_generate_acceptance_criteria(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn("Given a", spec)

    def test_does_not_generate_architecture_choices(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertNotIn("selected backend", spec)

    def test_does_not_generate_implementation_tasks(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn("allowed_paths", spec)

    def test_does_not_generate_planning_run_slice(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        implementation_plan = self._implementation_plan_path(plan_id).read_text(
            encoding="utf-8"
        )
        self.assertIn('"artifact_type": "PLANNING_RUN_SLICE"', implementation_plan)
        self.assertIn("PLACEHOLDER-slice-id", implementation_plan)

    def test_does_not_create_runner_proposals(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        workspace = self.project / ".agent-os"
        before = list((workspace / "runs").iterdir())

        self._scaffold(plan_id=plan_id)

        after = list((workspace / "runs").iterdir())
        self.assertEqual(before, after)

    def test_does_not_create_runs(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        self._scaffold(plan_id=plan_id)
        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_does_not_invoke_external_subprocess(self) -> None:
        self._setup_ready_for_scaffold()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code = main(
                [
                    "orchestrator",
                    "scaffold-requirements-extraction",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                ]
            )
        self.assertEqual(code, 0)

    def test_does_not_call_planning_progress_transition_decide(self) -> None:
        self._setup_ready_for_scaffold()
        with (
            patch.object(planning_module, "progress_planning_workspace") as progress,
            patch.object(planning_module, "transition_planning_workspace") as transition,
            patch.object(planning_module, "record_planning_owner_decision") as decide,
        ):
            self._scaffold()
        progress.assert_not_called()
        transition.assert_not_called()
        decide.assert_not_called()

    def test_restores_local_spec_when_provenance_write_fails(self) -> None:
        from agent_os.orchestrator import scaffold_requirements_extraction

        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        original = local_spec.read_bytes()
        provenance_path = self._requirements_scaffold_provenance_path(plan_id)

        from agent_os import orchestrator as orchestrator_module

        original_write_json = orchestrator_module._write_json

        def failing_provenance_write(path: Path, data: dict) -> None:
            if path == provenance_path:
                raise OSError("simulated provenance write failure")
            original_write_json(path, data)

        with patch.object(orchestrator_module, "_write_json", failing_provenance_write):
            with self.assertRaises(OSError) as ctx:
                scaffold_requirements_extraction(
                    self.project,
                    intake_id,
                    plan_id,
                )
            self.assertIn("simulated provenance write failure", str(ctx.exception))

        self.assertEqual(original, local_spec.read_bytes())
        self.assertFalse(provenance_path.exists())

    def test_scaffold_is_read_only_on_pre_write_failure(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(intake_id, plan_id)
        path = self._implementation_plan_path(plan_id)
        path.write_text(
            path.read_text(encoding="utf-8") + "\nmodified\n",
            encoding="utf-8",
        )

        before_artifacts = self._tracked_artifact_paths(intake_id, plan_id)
        before_files = self._project_files()
        local_spec_before = self._local_spec_path(plan_id).read_bytes()
        manifest_path = self._workspace(plan_id) / "manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())
        implementation_plan = self._implementation_plan_path(plan_id).read_text(
            encoding="utf-8"
        )

        with (
            patch("subprocess.run", side_effect=AssertionError("subprocess invoked")),
            patch.object(
                planning_module,
                "progress_planning_workspace",
                side_effect=AssertionError("progress invoked"),
            ),
            patch.object(
                planning_module,
                "transition_planning_workspace",
                side_effect=AssertionError("transition invoked"),
            ),
            patch.object(
                planning_module,
                "record_planning_owner_decision",
                side_effect=AssertionError("decide invoked"),
            ),
        ):
            code, _ = self._scaffold(intake_id, plan_id)

        self.assertEqual(code, 1)
        self.assertEqual(local_spec_before, self._local_spec_path(plan_id).read_bytes())
        self.assertFalse(self._requirements_scaffold_provenance_path(plan_id).exists())
        self.assertEqual(before_artifacts, self._tracked_artifact_paths(intake_id, plan_id))
        self.assertEqual(before_files, self._project_files())
        self.assertEqual(manifest_bytes, manifest_path.read_bytes())
        self.assertEqual(before_runs, list((workspace / "runs").iterdir()))
        self.assertIn('"artifact_type": "PLANNING_RUN_SLICE"', implementation_plan)
        self.assertIn("PLACEHOLDER-slice-id", implementation_plan)
        self.assertEqual(
            implementation_plan,
            self._implementation_plan_path(plan_id).read_text(encoding="utf-8"),
        )

    def test_cli_help_states_scaffold_boundaries(self) -> None:
        parser = build_parser()
        orchestrator_parser = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
            and "orchestrator" in action.choices
        )
        orchestrator_sub = next(
            action
            for action in orchestrator_parser.choices["orchestrator"]._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        help_text = orchestrator_sub.choices[
            "scaffold-requirements-extraction"
        ].format_help()
        compact = re.sub(r"\s+", " ", help_text)
        self.assertIn("scaffold", compact.lower())
        self.assertIn("requirements", compact.lower())
        self.assertIn("user stories", compact.lower())
        self.assertIn("acceptance criteria", compact.lower())
        self.assertIn("architecture", compact.lower())
        self.assertIn("implementation plan", compact.lower())
        self.assertIn("PLANNING_RUN_SLICE", compact)
        self.assertIn("validate", compact.lower())
        self.assertIn("executor", compact.lower())

    def test_cli_output_includes_paths_status_and_boundary_notes(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        code, output = self._scaffold(plan_id=plan_id)
        self.assertEqual(code, 0)
        self.assertIn("local agentic spec:", output)
        self.assertIn("requirements extraction scaffold provenance:", output)
        self.assertIn("workspace_status: DRAFT", output)
        self.assertIn("REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY", output)
        self.assertIn("no requirements extraction", output.lower())

    def test_existing_commands_unchanged(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        self._prepare(intake_id, plan_id)
        self._transport(intake_id, plan_id)
        self._draft_context_pack(intake_id, plan_id)
        self._local_spec_preflight(intake_id, plan_id)
        self._scaffold_local_spec(intake_id, plan_id)
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            draft_preflight_code = main(
                [
                    "orchestrator",
                    "draft-preflight",
                    intake_id,
                    str(self.project),
                ]
            )
            req_preflight_code = main(
                [
                    "orchestrator",
                    "requirements-extraction-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        self.assertEqual(draft_preflight_code, 0)
        self.assertEqual(req_preflight_code, 0)
        self.assertIn("requirements extraction preflight", buf.getvalue().lower())

        after = self._project_files()
        self.assertEqual(before, after)

    def test_scaffold_not_confusable_with_requirements_extraction_or_approval(
        self,
    ) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        code, output = self._scaffold(plan_id=plan_id)
        self.assertEqual(code, 0)
        self.assertIn("no requirements extraction", output.lower())
        self.assertIn("not validated or approved", output.lower())
        validation = validate_planning_workspace(self.project, plan_id)
        self.assertFalse(validation.valid)

    def test_no_artifact_claims_requirements_approval(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_scaffold(plan_id=plan_id)
        self._scaffold(plan_id=plan_id)

        provenance = (
            self._requirements_scaffold_provenance_path(plan_id)
            .read_text(encoding="utf-8")
            .lower()
        )
        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertNotIn("requirements approved", provenance)
        self.assertNotIn("requirements approved", spec)
        self.assertIn("does_not_approve_plan", provenance)


class OrchestratorRequirementsExtractionOwnerDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(
            self.project,
            intake_id,
            clarification_id,
        )

    def _readiness_decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(
            self.project,
            intake_id,
            decision_id,
        )

    def _requirements_extraction_decision_path(
        self,
        intake_id: str,
        plan_id: str,
        decision_id: str,
    ) -> Path:
        return orchestrator_requirements_extraction_decision_path(
            self.project,
            intake_id,
            plan_id,
            decision_id,
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project,
            intake_id,
            "Build me an online slither.io-like game",
        )

    def _write_artifact(self, intake_id: str, artifact: dict) -> Path:
        path = self._artifact_path(intake_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        return path

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _slither_with_clarification(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project,
            intake_id,
            "scope-v1",
            "Browser-only demo with 10 players max; no persistence.",
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._slither_with_clarification(intake_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _prepare(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "prepare-planning-draft",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _transport(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "transport-planning-context",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _draft_context_pack(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "draft-context-pack",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _local_spec_preflight(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "local-agentic-spec-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _scaffold_local_spec(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-local-agentic-spec",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _preflight(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "requirements-extraction-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _scaffold(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "scaffold-requirements-extraction",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        return code, buf.getvalue()

    def _decide(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_EXTRACTION",
        decision_id: str = "req-ext-owner-v1",
        summary: str = "Authorize future extraction only.",
    ) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                [
                    "orchestrator",
                    "decide-requirements-extraction",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                    "--decision",
                    decision,
                    "--decision-id",
                    decision_id,
                    "--summary",
                    summary,
                ]
            )
        return code, buf.getvalue()

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-pack-draft-provenance.json"
        )

    def _scaffold_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-local-agentic-spec-scaffold-provenance.json"
        )

    def _requirements_scaffold_provenance_path(
        self,
        plan_id: str = "slither-plan-v1",
    ) -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-requirements-extraction-scaffold-provenance.json"
        )

    def _transport_json_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-transport.json"
        )

    def _transport_md_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-context-transport.md"
        )

    def _provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-provenance.json"
        )

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_scaffold(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._local_spec_preflight(intake_id, plan_id)[0], 0)
        self.assertEqual(self._scaffold_local_spec(intake_id, plan_id)[0], 0)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

    def _setup_ready_for_decision(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> None:
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self.assertEqual(self._scaffold(intake_id, plan_id)[0], 0)

    def _tracked_artifact_paths(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
    ) -> dict[Path, bytes]:
        workspace = self._workspace(plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._clarification_path(intake_id, "scope-v1"),
            self._readiness_decision_path(intake_id, "owner-v1"),
            self._provenance_path(plan_id),
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
            self._transport_json_path(plan_id),
            self._transport_md_path(plan_id),
            self._draft_provenance_path(plan_id),
            self._scaffold_provenance_path(plan_id),
            self._requirements_scaffold_provenance_path(plan_id),
            self._context_pack_path(plan_id),
            self._local_spec_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def _record_decision(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision_id: str = "req-ext-owner-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_EXTRACTION",
        summary: str = "Authorize future extraction only.",
    ):
        return create_requirements_extraction_owner_decision(
            self.project,
            intake_id,
            plan_id,
            decision_id,
            decision,
            summary,
        )

    def test_succeeds_after_coherent_requirements_extraction_scaffold_exists(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)

        code, output = self._decide(intake_id, plan_id)
        self.assertEqual(code, 0)
        self.assertIn("created requirements extraction owner decision artifact:", output)

    def test_decision_artifact_created_at_expected_path(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        decision_id = "req-ext-owner-v1"
        self._setup_ready_for_decision(intake_id, plan_id)

        report = self._record_decision(intake_id, plan_id, decision_id)

        expected = self._requirements_extraction_decision_path(
            intake_id,
            plan_id,
            decision_id,
        )
        self.assertEqual(report.decision_path, expected)
        self.assertTrue(expected.is_file())
        self.assertIn(
            REQUIREMENTS_EXTRACTION_DECISIONS_DIR,
            expected.as_posix(),
        )

    def test_decision_artifact_contains_required_fields(self) -> None:
        artifact = build_requirements_extraction_owner_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-ext-owner-v1",
            "AUTHORIZE_REQUIREMENTS_EXTRACTION",
            "Authorize future extraction only.",
            source_requirements_extraction_scaffold_provenance_path=(
                ".agent-os/planning/slither-plan-v1/evidence/"
                "orchestrator-requirements-extraction-scaffold-provenance.json"
            ),
            source_requirements_extraction_scaffold_status=(
                "REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY"
            ),
            source_requirements_extraction_scaffold_created_at=(
                "2026-07-06T10:00:00+00:00"
            ),
            source_requirements_extraction_preflight_state=(
                "REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NO_REQUIREMENTS_GENERATED"
            ),
            source_requirements_extraction_preflight_next_action=(
                "FUTURE_REQUIREMENTS_EXTRACTION_REQUIRES_SEPARATE_COMMAND"
            ),
            planning_workspace_status_at_decision="DRAFT",
            created_at="2026-07-06T10:00:00+00:00",
        )
        missing = [
            field
            for field in REQUIREMENTS_EXTRACTION_OWNER_DECISION_REQUIRED_FIELDS
            if field not in artifact
        ]
        self.assertEqual(missing, [])

    def test_decision_artifact_contains_all_non_authority_flags_true(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        self._record_decision(intake_id, plan_id)

        artifact = load_requirements_extraction_owner_decision(
            self.project,
            intake_id,
            plan_id,
            "req-ext-owner-v1",
        )
        for flag in REQUIREMENTS_EXTRACTION_OWNER_DECISION_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, artifact["non_authority"])
            self.assertTrue(artifact["non_authority"][flag])

    def test_authorize_recorded_but_does_not_extract_requirements(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        local_spec_before = self._local_spec_path(plan_id).read_bytes()

        self._record_decision(plan_id=plan_id, decision="AUTHORIZE_REQUIREMENTS_EXTRACTION")

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertEqual(local_spec_before, self._local_spec_path(plan_id).read_bytes())
        self.assertIn("NO_REQUIREMENTS_EXTRACTED", spec)
        self.assertNotIn("The system shall", spec)

    def test_request_more_context_recorded_and_does_not_extract_requirements(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)

        self._record_decision(
            plan_id=plan_id,
            decision="REQUEST_MORE_CONTEXT",
            summary="Need more product context before extraction.",
        )

        artifact = load_requirements_extraction_owner_decision(
            self.project,
            "slither-demo",
            plan_id,
            "req-ext-owner-v1",
        )
        self.assertEqual(artifact["decision"], "REQUEST_MORE_CONTEXT")
        self.assertIn("NO_REQUIREMENTS_EXTRACTED", self._local_spec_path(plan_id).read_text())

    def test_block_recorded_and_does_not_extract_requirements(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)

        self._record_decision(
            plan_id=plan_id,
            decision="BLOCK_REQUIREMENTS_EXTRACTION",
            summary="Block extraction for now.",
        )

        artifact = load_requirements_extraction_owner_decision(
            self.project,
            "slither-demo",
            plan_id,
            "req-ext-owner-v1",
        )
        self.assertEqual(artifact["decision"], "BLOCK_REQUIREMENTS_EXTRACTION")
        self.assertIn("NO_REQUIREMENTS_EXTRACTED", self._local_spec_path(plan_id).read_text())

    def test_owner_summary_preserved_verbatim(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        summary = "  Authorize extraction later.\t\n\nNot approval.  "
        self._setup_ready_for_decision(intake_id, plan_id)

        self._record_decision(intake_id, plan_id, summary=summary)

        artifact = load_requirements_extraction_owner_decision(
            self.project,
            intake_id,
            plan_id,
            "req-ext-owner-v1",
        )
        self.assertEqual(artifact["owner_summary"], summary)

    def _valid_decision_artifact(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision_id: str = "req-ext-owner-v1",
    ) -> dict:
        return build_requirements_extraction_owner_decision_artifact(
            intake_id,
            plan_id,
            decision_id,
            "AUTHORIZE_REQUIREMENTS_EXTRACTION",
            "Authorize future extraction only.",
            source_requirements_extraction_scaffold_provenance_path=(
                f".agent-os/planning/{plan_id}/evidence/"
                "orchestrator-requirements-extraction-scaffold-provenance.json"
            ),
            source_requirements_extraction_scaffold_status=(
                "REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY"
            ),
            source_requirements_extraction_scaffold_created_at=(
                "2026-07-06T10:00:00+00:00"
            ),
            source_requirements_extraction_preflight_state=(
                "REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NO_REQUIREMENTS_GENERATED"
            ),
            source_requirements_extraction_preflight_next_action=(
                "FUTURE_REQUIREMENTS_EXTRACTION_REQUIRES_SEPARATE_COMMAND"
            ),
            planning_workspace_status_at_decision="DRAFT",
            created_at="2026-07-06T10:00:00+00:00",
        )

    def _write_decision_artifact(
        self,
        intake_id: str,
        plan_id: str,
        decision_id: str,
        artifact: dict,
    ) -> Path:
        path = self._requirements_extraction_decision_path(
            intake_id,
            plan_id,
            decision_id,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        return path

    def test_validate_requirements_extraction_owner_decision_succeeds_on_valid_artifact(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        decision_id = "req-ext-owner-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        self._record_decision(intake_id, plan_id, decision_id)

        report = validate_requirements_extraction_owner_decision(
            self.project,
            intake_id,
            plan_id,
            decision_id,
        )
        self.assertTrue(report.valid)
        self.assertEqual(report.errors, ())

    def test_validate_requirements_extraction_owner_decision_rejects_malformed_json(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        decision_id = "req-ext-owner-v1"
        path = self._requirements_extraction_decision_path(
            intake_id,
            plan_id,
            decision_id,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not-json", encoding="utf-8")

        report = validate_requirements_extraction_owner_decision(
            self.project,
            intake_id,
            plan_id,
            decision_id,
        )
        self.assertFalse(report.valid)
        self.assertTrue(any("malformed JSON" in error for error in report.errors))

    def test_validate_requirements_extraction_owner_decision_rejects_wrong_artifact_type(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        decision_id = "req-ext-owner-v1"
        artifact = self._valid_decision_artifact(intake_id, plan_id, decision_id)
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        self._write_decision_artifact(intake_id, plan_id, decision_id, artifact)

        report = validate_requirements_extraction_owner_decision(
            self.project,
            intake_id,
            plan_id,
            decision_id,
        )
        self.assertFalse(report.valid)
        self.assertTrue(
            any("wrong artifact_type" in error for error in report.errors)
        )

    def test_validate_requirements_extraction_owner_decision_rejects_invalid_decision_value(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        decision_id = "req-ext-owner-v1"
        artifact = self._valid_decision_artifact(intake_id, plan_id, decision_id)
        artifact["decision"] = "APPROVE_REQUIREMENTS"
        self._write_decision_artifact(intake_id, plan_id, decision_id, artifact)

        report = validate_requirements_extraction_owner_decision(
            self.project,
            intake_id,
            plan_id,
            decision_id,
        )
        self.assertFalse(report.valid)
        self.assertTrue(
            any("invalid decision value" in error for error in report.errors)
        )

    def test_validate_requirements_extraction_owner_decision_rejects_missing_non_authority_flag(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        decision_id = "req-ext-owner-v1"
        artifact = self._valid_decision_artifact(intake_id, plan_id, decision_id)
        del artifact["non_authority"]["does_not_create_run"]
        self._write_decision_artifact(intake_id, plan_id, decision_id, artifact)

        report = validate_requirements_extraction_owner_decision(
            self.project,
            intake_id,
            plan_id,
            decision_id,
        )
        self.assertFalse(report.valid)
        self.assertTrue(
            any(
                "missing non_authority flag: does_not_create_run" in error
                for error in report.errors
            )
        )

    def test_validate_requirements_extraction_owner_decision_rejects_false_non_authority_flag(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        decision_id = "req-ext-owner-v1"
        artifact = self._valid_decision_artifact(intake_id, plan_id, decision_id)
        artifact["non_authority"]["does_not_invoke_executor"] = False
        self._write_decision_artifact(intake_id, plan_id, decision_id, artifact)

        report = validate_requirements_extraction_owner_decision(
            self.project,
            intake_id,
            plan_id,
            decision_id,
        )
        self.assertFalse(report.valid)
        self.assertTrue(
            any(
                "non_authority flag must be true: does_not_invoke_executor" in error
                for error in report.errors
            )
        )

    def test_decide_requirements_extraction_rejects_empty_summary(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        decision_id = "req-ext-owner-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        before_artifacts = self._tracked_artifact_paths(intake_id, plan_id)
        local_spec_bytes = self._local_spec_path(plan_id).read_bytes()
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())

        with self.assertRaises(ValueError) as ctx:
            create_requirements_extraction_owner_decision(
                self.project,
                intake_id,
                plan_id,
                decision_id,
                "AUTHORIZE_REQUIREMENTS_EXTRACTION",
                "",
            )
        self.assertIn("owner summary must not be empty", str(ctx.exception))
        self.assertFalse(
            self._requirements_extraction_decision_path(
                intake_id,
                plan_id,
                decision_id,
            ).exists()
        )

        with (
            patch("subprocess.run", side_effect=AssertionError("subprocess invoked")),
            patch.object(
                planning_module,
                "progress_planning_workspace",
                side_effect=AssertionError("progress invoked"),
            ),
            patch.object(
                planning_module,
                "transition_planning_workspace",
                side_effect=AssertionError("transition invoked"),
            ),
            patch.object(
                planning_module,
                "record_planning_owner_decision",
                side_effect=AssertionError("decide invoked"),
            ),
        ):
            buf = io.StringIO()
            with redirect_stderr(buf):
                code = main(
                    [
                        "orchestrator",
                        "decide-requirements-extraction",
                        intake_id,
                        str(self.project),
                        "--plan-id",
                        plan_id,
                        "--decision",
                        "AUTHORIZE_REQUIREMENTS_EXTRACTION",
                        "--decision-id",
                        decision_id,
                        "--summary",
                        "",
                    ]
                )

        self.assertEqual(code, 1)
        self.assertIn("owner summary must not be empty", buf.getvalue())
        self.assertFalse(
            self._requirements_extraction_decision_path(
                intake_id,
                plan_id,
                decision_id,
            ).exists()
        )
        self.assertEqual(before_artifacts, self._tracked_artifact_paths(intake_id, plan_id))
        self.assertEqual(local_spec_bytes, self._local_spec_path(plan_id).read_bytes())
        self.assertEqual(before_runs, list((workspace / "runs").iterdir()))

    def test_refuses_existing_decision_id_without_overwrite(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        decision_id = "req-ext-owner-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        self._record_decision(intake_id, plan_id, decision_id)
        existing = self._requirements_extraction_decision_path(
            intake_id,
            plan_id,
            decision_id,
        ).read_text(encoding="utf-8")

        with self.assertRaises(FileExistsError):
            create_requirements_extraction_owner_decision(
                self.project,
                intake_id,
                plan_id,
                decision_id,
                "REQUEST_MORE_CONTEXT",
                "Second decision.",
            )
        self.assertEqual(
            existing,
            self._requirements_extraction_decision_path(
                intake_id,
                plan_id,
                decision_id,
            ).read_text(encoding="utf-8"),
        )

    def test_latest_decision_ordering_deterministic_by_created_at_then_decision_id(
        self,
    ) -> None:
        from agent_os import orchestrator as orchestrator_module

        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        times = iter(
            [
                "2026-07-06T10:00:00+00:00",
                "2026-07-06T10:00:00+00:00",
                "2026-07-06T11:00:00+00:00",
            ]
        )

        with patch.object(orchestrator_module, "_utc_now", side_effect=lambda: next(times)):
            create_requirements_extraction_owner_decision(
                self.project,
                intake_id,
                plan_id,
                "req-ext-bbb",
                "REQUEST_MORE_CONTEXT",
                "Earlier tie-breaker id.",
            )
            create_requirements_extraction_owner_decision(
                self.project,
                intake_id,
                plan_id,
                "req-ext-aaa",
                "BLOCK_REQUIREMENTS_EXTRACTION",
                "Same timestamp, earlier id.",
            )
            create_requirements_extraction_owner_decision(
                self.project,
                intake_id,
                plan_id,
                "req-ext-zzz",
                "AUTHORIZE_REQUIREMENTS_EXTRACTION",
                "Latest timestamp.",
            )

        decisions = list_requirements_extraction_owner_decisions(
            self.project,
            intake_id,
            plan_id,
        )
        self.assertEqual(
            [record.decision_id for record in decisions],
            ["req-ext-aaa", "req-ext-bbb", "req-ext-zzz"],
        )
        self.assertEqual(decisions[-1].decision, "AUTHORIZE_REQUIREMENTS_EXTRACTION")

    def test_refuses_missing_workspace(self) -> None:
        bare = Path(tempfile.mkdtemp())
        try:
            with self.assertRaises(FileNotFoundError):
                create_requirements_extraction_owner_decision(
                    bare,
                    "slither-demo",
                    "slither-plan-v1",
                    "req-ext-owner-v1",
                    "BLOCK_REQUIREMENTS_EXTRACTION",
                    "Stop.",
                )
            buf = io.StringIO()
            with redirect_stderr(buf):
                code = main(
                    [
                        "orchestrator",
                        "decide-requirements-extraction",
                        "slither-demo",
                        str(bare),
                        "--plan-id",
                        "slither-plan-v1",
                        "--decision",
                        "BLOCK_REQUIREMENTS_EXTRACTION",
                        "--decision-id",
                        "req-ext-owner-v1",
                        "--summary",
                        "Stop.",
                    ]
                )
            self.assertEqual(code, 1)
            self.assertIn("no workspace found", buf.getvalue())
        finally:
            import shutil

            shutil.rmtree(bare)

    def test_refuses_missing_intake(self) -> None:
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "decide-requirements-extraction",
                    "missing-intake",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                    "--decision",
                    "BLOCK_REQUIREMENTS_EXTRACTION",
                    "--decision-id",
                    "req-ext-owner-v1",
                    "--summary",
                    "Stop.",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("goal intake artifact not found", buf.getvalue())

    def test_refuses_invalid_intake(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        artifact_path = self._artifact_path(intake_id)
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        artifact_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        with self.assertRaises(ValueError):
            create_requirements_extraction_owner_decision(
                self.project,
                intake_id,
                plan_id,
                "req-ext-owner-v1",
                "BLOCK_REQUIREMENTS_EXTRACTION",
                "Stop.",
            )
        self.assertFalse(
            self._requirements_extraction_decision_path(
                intake_id,
                plan_id,
                "req-ext-owner-v1",
            ).exists()
        )

    def test_refuses_missing_planning_workspace(self) -> None:
        self._setup_ready_for_decision()
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "decide-requirements-extraction",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "missing-plan",
                    "--decision",
                    "AUTHORIZE_REQUIREMENTS_EXTRACTION",
                    "--decision-id",
                    "req-ext-owner-v1",
                    "--summary",
                    "Authorize.",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("planning workspace not found", buf.getvalue())

    def test_refuses_non_draft_planning_workspace(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        manifest_path = self._workspace(plan_id) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["status"] = "CONTEXT_READY"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_requirements_extraction_scaffold_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        self._requirements_scaffold_provenance_path(plan_id).unlink()

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_malformed_requirements_extraction_scaffold_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        provenance_path = self._requirements_scaffold_provenance_path(plan_id)
        provenance_path.write_text("{not-json", encoding="utf-8")

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_scaffold_provenance_plan_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        provenance_path = self._requirements_scaffold_provenance_path(plan_id)
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        provenance["plan_id"] = "other-plan"
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_scaffold_provenance_intake_id_mismatch(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        provenance_path = self._requirements_scaffold_provenance_path(plan_id)
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        provenance["intake_id"] = "other-intake"
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_scaffold_provenance_non_authority_missing_or_false(self) -> None:
        from agent_os.orchestrator import (
            ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY_FLAGS,
        )

        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        provenance_path = self._requirements_scaffold_provenance_path(plan_id)
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        flag = ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY_FLAGS[0]
        provenance["non_authority"][flag] = False
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_requirements_extraction_preflight_not_confirmed(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "BLOCK_INTAKE",
            "Scope too broad; stop intake.",
        )

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_incoherent_requirements_extraction_scaffold(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8").replace("not performed", "done"),
            encoding="utf-8",
        )

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_missing_local_agentic_spec_md(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        self._local_spec_path(plan_id).unlink()

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_not_requirements_extraction_scaffold_non_authority(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8").replace(
                "REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY",
                "APPROVED",
            ),
            encoding="utf-8",
        )

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_containing_actual_requirements(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\n## Functional Requirements\n\nThe system shall handle login.\n",
            encoding="utf-8",
        )

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_containing_requirement_id_pattern(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\nREQ-001: placeholder requirement.\n",
            encoding="utf-8",
        )

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_containing_user_stories(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\n## User Stories\n\nAs a user I want to play.\n",
            encoding="utf-8",
        )

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_containing_acceptance_criteria(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\n## Acceptance Criteria\n\nGiven a player When they join Then game starts.\n",
            encoding="utf-8",
        )

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_containing_architecture_decision_language(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\nSelected backend: Node.js with WebSockets.\n",
            encoding="utf-8",
        )

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_containing_implementation_tasks(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\n## Implementation Tasks\n\n- Task 1: build lobby.\n",
            encoding="utf-8",
        )

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_local_agentic_spec_containing_planning_run_slice_content(
        self,
    ) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        local_spec = self._local_spec_path(plan_id)
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8")
            + "\n## PLANNING_RUN_SLICE\n\nslice-id: demo-slice\n",
            encoding="utf-8",
        )

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_latest_readiness_request_more_clarification(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "REQUEST_MORE_CLARIFICATION",
            "Need more detail on multiplayer scope.",
        )

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_latest_readiness_block_intake(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v2",
            "BLOCK_INTAKE",
            "Scope too broad; stop intake.",
        )

        code, _ = self._decide(intake_id, plan_id)
        self.assertEqual(code, 1)

    def test_refuses_invalid_requirements_extraction_decision_value(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)

        with self.assertRaises(ValueError) as ctx:
            create_requirements_extraction_owner_decision(
                self.project,
                intake_id,
                plan_id,
                "req-ext-owner-v1",
                "APPROVE_REQUIREMENTS",
                "Not allowed.",
            )
        self.assertIn("unsupported decision value", str(ctx.exception))

    def test_refuses_invalid_decision_id(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        invalid_ids = ("", " ", "../escape", "bad id", ".hidden")

        for decision_id in invalid_ids:
            with self.subTest(decision_id=decision_id):
                with self.assertRaises(ValueError):
                    create_requirements_extraction_owner_decision(
                        self.project,
                        intake_id,
                        plan_id,
                        decision_id,
                        "BLOCK_REQUIREMENTS_EXTRACTION",
                        "Stop.",
                    )
                self.assertFalse(
                    self._requirements_extraction_decision_path(
                        intake_id,
                        plan_id,
                        decision_id,
                    ).exists()
                )

    def test_refuses_path_escape_decision_id(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        before = self._project_files()

        with self.assertRaises(ValueError):
            create_requirements_extraction_owner_decision(
                self.project,
                intake_id,
                plan_id,
                "../escape",
                "BLOCK_REQUIREMENTS_EXTRACTION",
                "Escape attempt.",
            )
        self.assertEqual(before, self._project_files())

    def test_refuses_path_escape_intake_id(self) -> None:
        self._setup_ready_for_decision()
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "decide-requirements-extraction",
                    "../escape",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                    "--decision",
                    "BLOCK_REQUIREMENTS_EXTRACTION",
                    "--decision-id",
                    "req-ext-owner-v1",
                    "--summary",
                    "Escape attempt.",
                ]
            )
        self.assertEqual(code, 1)
        self.assertIn("invalid intake id", buf.getvalue())
        self.assertEqual(before, self._project_files())

    def test_refuses_invalid_plan_id(self) -> None:
        self._setup_ready_for_decision()
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "decide-requirements-extraction",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "../escape",
                    "--decision",
                    "AUTHORIZE_REQUIREMENTS_EXTRACTION",
                    "--decision-id",
                    "req-ext-owner-v1",
                    "--summary",
                    "Authorize.",
                ]
            )
        self.assertEqual(code, 1)

    def test_preserves_goal_intake_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        artifact_path = self._artifact_path(intake_id)
        original = artifact_path.read_bytes()

        self._record_decision(intake_id, plan_id)

        self.assertEqual(original, artifact_path.read_bytes())

    def test_preserves_clarification_artifacts_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        clarification_path = self._clarification_path(intake_id, "scope-v1")
        original = clarification_path.read_bytes()

        self._record_decision(intake_id, plan_id)

        self.assertEqual(original, clarification_path.read_bytes())

    def test_preserves_readiness_decision_artifacts_byte_for_byte(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        decision_path = self._readiness_decision_path(intake_id, "owner-v1")
        original = decision_path.read_bytes()

        self._record_decision(intake_id, plan_id)

        self.assertEqual(original, decision_path.read_bytes())

    def test_preserves_orchestrator_provenance_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        provenance_path = self._provenance_path(plan_id)
        original = provenance_path.read_bytes()

        self._record_decision(plan_id=plan_id)

        self.assertEqual(original, provenance_path.read_bytes())

    def test_preserves_context_transport_json_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        transport_path = self._transport_json_path(plan_id)
        original = transport_path.read_bytes()

        self._record_decision(plan_id=plan_id)

        self.assertEqual(original, transport_path.read_bytes())

    def test_preserves_context_transport_markdown_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        transport_path = self._transport_md_path(plan_id)
        original = transport_path.read_bytes()

        self._record_decision(plan_id=plan_id)

        self.assertEqual(original, transport_path.read_bytes())

    def test_preserves_context_pack_draft_provenance_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        provenance_path = self._draft_provenance_path(plan_id)
        original = provenance_path.read_bytes()

        self._record_decision(plan_id=plan_id)

        self.assertEqual(original, provenance_path.read_bytes())

    def test_preserves_local_agentic_spec_scaffold_provenance_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        provenance_path = self._scaffold_provenance_path(plan_id)
        original = provenance_path.read_bytes()

        self._record_decision(plan_id=plan_id)

        self.assertEqual(original, provenance_path.read_bytes())

    def test_preserves_requirements_extraction_scaffold_provenance_byte_for_byte(
        self,
    ) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        provenance_path = self._requirements_scaffold_provenance_path(plan_id)
        original = provenance_path.read_bytes()

        self._record_decision(plan_id=plan_id)

        self.assertEqual(original, provenance_path.read_bytes())

    def test_preserves_context_pack_md_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        context_pack_path = self._context_pack_path(plan_id)
        original = context_pack_path.read_bytes()

        self._record_decision(plan_id=plan_id)

        self.assertEqual(original, context_pack_path.read_bytes())

    def test_preserves_local_agentic_spec_md_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        local_spec_path = self._local_spec_path(plan_id)
        original = local_spec_path.read_bytes()

        self._record_decision(plan_id=plan_id)

        self.assertEqual(original, local_spec_path.read_bytes())

    def test_preserves_implementation_plan_md_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        plan_path = self._implementation_plan_path(plan_id)
        original = plan_path.read_bytes()

        self._record_decision(plan_id=plan_id)

        self.assertEqual(original, plan_path.read_bytes())

    def test_preserves_planning_audit_md_byte_for_byte(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        audit_path = self._planning_audit_path(plan_id)
        original = audit_path.read_bytes()

        self._record_decision(plan_id=plan_id)

        self.assertEqual(original, audit_path.read_bytes())

    def test_does_not_change_planning_workspace_status(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        manifest_path = self._workspace(plan_id) / "manifest.json"
        before = manifest_path.read_bytes()

        self._record_decision(plan_id=plan_id)

        self.assertEqual(before, manifest_path.read_bytes())

    def test_does_not_extract_requirements(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        self._record_decision(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertIn("NO_REQUIREMENTS_EXTRACTED", spec)
        self.assertNotIn("The system shall", spec)

    def test_does_not_generate_requirement_ids(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        self._record_decision(plan_id=plan_id)

        combined = "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.project.rglob("*")
            if path.is_file() and path.suffix in {".md", ".json"}
        )
        self.assertNotIn("REQ-001", combined)
        self.assertNotIn("FR-", combined)

    def test_does_not_generate_user_stories(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        self._record_decision(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn("As a user", spec)

    def test_does_not_generate_acceptance_criteria(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        self._record_decision(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn("Given a", spec)

    def test_does_not_generate_architecture_choices(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        self._record_decision(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        self.assertNotIn("selected backend", spec)

    def test_does_not_generate_implementation_tasks(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        self._record_decision(plan_id=plan_id)

        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        self.assertNotIn("allowed_paths", spec)

    def test_does_not_generate_planning_run_slice(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        self._record_decision(plan_id=plan_id)

        implementation_plan = self._implementation_plan_path(plan_id).read_text(
            encoding="utf-8"
        )
        self.assertIn('"artifact_type": "PLANNING_RUN_SLICE"', implementation_plan)
        self.assertIn("PLACEHOLDER-slice-id", implementation_plan)

    def test_does_not_create_runner_proposals(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        workspace = self.project / ".agent-os"
        before = list((workspace / "runs").iterdir())

        self._record_decision(plan_id=plan_id)

        after = list((workspace / "runs").iterdir())
        self.assertEqual(before, after)

    def test_does_not_create_runs(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())

        self._record_decision(plan_id=plan_id)

        after_runs = list((workspace / "runs").iterdir())
        self.assertEqual(before_runs, after_runs)

    def test_does_not_invoke_external_subprocess(self) -> None:
        self._setup_ready_for_decision()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code = main(
                [
                    "orchestrator",
                    "decide-requirements-extraction",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "slither-plan-v1",
                    "--decision",
                    "AUTHORIZE_REQUIREMENTS_EXTRACTION",
                    "--decision-id",
                    "req-ext-owner-v1",
                    "--summary",
                    "Authorize future extraction only.",
                ]
            )
        self.assertEqual(code, 0)

    def test_does_not_call_planning_progress_transition_decide(self) -> None:
        self._setup_ready_for_decision()
        with (
            patch.object(planning_module, "progress_planning_workspace") as progress,
            patch.object(planning_module, "transition_planning_workspace") as transition,
            patch.object(planning_module, "record_planning_owner_decision") as decide,
        ):
            self._record_decision()
        progress.assert_not_called()
        transition.assert_not_called()
        decide.assert_not_called()

    def test_does_not_validate_or_approve_workspace(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        before = validate_planning_workspace(self.project, plan_id)

        self._record_decision(plan_id=plan_id)

        after = validate_planning_workspace(self.project, plan_id)
        self.assertFalse(before.valid)
        self.assertFalse(after.valid)
        self.assertEqual(before.output, after.output)

    def test_does_not_approve_requirements(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        self._record_decision(plan_id=plan_id)

        artifact = load_requirements_extraction_owner_decision(
            self.project,
            "slither-demo",
            plan_id,
            "req-ext-owner-v1",
        )
        self.assertTrue(artifact["non_authority"]["does_not_approve_requirements"])
        combined = json.dumps(artifact).lower()
        self.assertNotIn("requirements approved", combined)

    def test_failure_path_does_not_create_partial_decision_artifact(self) -> None:
        from agent_os import orchestrator as orchestrator_module

        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        decision_id = "req-ext-owner-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        dest = self._requirements_extraction_decision_path(
            intake_id,
            plan_id,
            decision_id,
        )
        original_write_json = orchestrator_module._write_json

        def failing_write(path: Path, data: dict) -> None:
            if path == dest:
                raise OSError("simulated decision write failure")
            original_write_json(path, data)

        with patch.object(orchestrator_module, "_write_json", failing_write):
            with self.assertRaises(OSError) as ctx:
                create_requirements_extraction_owner_decision(
                    self.project,
                    intake_id,
                    plan_id,
                    decision_id,
                    "AUTHORIZE_REQUIREMENTS_EXTRACTION",
                    "Authorize future extraction only.",
                )
            self.assertIn("simulated decision write failure", str(ctx.exception))
        self.assertFalse(dest.exists())

    def test_failure_path_preserves_source_evidence_and_planning_artifacts(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        path = self._implementation_plan_path(plan_id)
        path.write_text(
            path.read_text(encoding="utf-8") + "\nmodified\n",
            encoding="utf-8",
        )

        before_artifacts = self._tracked_artifact_paths(intake_id, plan_id)
        before_files = self._project_files()
        manifest_path = self._workspace(plan_id) / "manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        workspace = self.project / ".agent-os"
        before_runs = list((workspace / "runs").iterdir())

        with (
            patch("subprocess.run", side_effect=AssertionError("subprocess invoked")),
            patch.object(
                planning_module,
                "progress_planning_workspace",
                side_effect=AssertionError("progress invoked"),
            ),
            patch.object(
                planning_module,
                "transition_planning_workspace",
                side_effect=AssertionError("transition invoked"),
            ),
            patch.object(
                planning_module,
                "record_planning_owner_decision",
                side_effect=AssertionError("decide invoked"),
            ),
        ):
            code, _ = self._decide(intake_id, plan_id)

        self.assertEqual(code, 1)
        self.assertFalse(
            self._requirements_extraction_decision_path(
                intake_id,
                plan_id,
                "req-ext-owner-v1",
            ).exists()
        )
        self.assertEqual(before_artifacts, self._tracked_artifact_paths(intake_id, plan_id))
        self.assertEqual(before_files, self._project_files())
        self.assertEqual(manifest_bytes, manifest_path.read_bytes())
        self.assertEqual(before_runs, list((workspace / "runs").iterdir()))

    def test_cli_help_states_owner_decision_boundaries(self) -> None:
        parser = build_parser()
        orchestrator_parser = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
            and "orchestrator" in action.choices
        )
        orchestrator_sub = next(
            action
            for action in orchestrator_parser.choices["orchestrator"]._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        help_text = orchestrator_sub.choices[
            "decide-requirements-extraction"
        ].format_help()
        compact = re.sub(r"\s+", " ", help_text)
        self.assertIn("owner-provided", compact.lower())
        self.assertIn("extract or infer requirements", compact.lower())
        self.assertIn("approve requirements", compact.lower())
        self.assertIn("architecture", compact.lower())
        self.assertIn("implementation plan", compact.lower())
        self.assertIn("PLANNING_RUN_SLICE", compact)
        self.assertIn("validate", compact.lower())
        self.assertIn("executor", compact.lower())

    def test_cli_output_includes_decision_path_status_and_boundary_notes(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        code, output = self._decide(plan_id=plan_id)
        self.assertEqual(code, 0)
        self.assertIn("created requirements extraction owner decision artifact:", output)
        self.assertIn("artifact_type: REQUIREMENTS_EXTRACTION_OWNER_DECISION", output)
        self.assertIn(
            "decision: AUTHORIZE_REQUIREMENTS_EXTRACTION",
            output,
        )
        self.assertIn("planning_workspace_status: DRAFT", output)
        self.assertIn("no requirements extraction", output.lower())
        self.assertIn("no requirements approval", output.lower())

    def test_cli_output_for_authorize_states_authorization_is_not_extraction(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        code, output = self._decide(
            plan_id=plan_id,
            decision="AUTHORIZE_REQUIREMENTS_EXTRACTION",
        )
        self.assertEqual(code, 0)
        self.assertIn("authorization is not extraction", output.lower())

    def test_existing_commands_unchanged(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(intake_id, plan_id)
        before = self._project_files()

        buf = io.StringIO()
        with redirect_stdout(buf):
            draft_preflight_code = main(
                [
                    "orchestrator",
                    "draft-preflight",
                    intake_id,
                    str(self.project),
                ]
            )
            req_preflight_code = main(
                [
                    "orchestrator",
                    "requirements-extraction-preflight",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
            scaffold_code = main(
                [
                    "orchestrator",
                    "scaffold-requirements-extraction",
                    intake_id,
                    str(self.project),
                    "--plan-id",
                    plan_id,
                ]
            )
        self.assertEqual(draft_preflight_code, 0)
        self.assertEqual(req_preflight_code, 1)
        self.assertEqual(scaffold_code, 1)
        self.assertIn("requirements extraction preflight", buf.getvalue().lower())
        self.assertEqual(before, self._project_files())

    def test_decision_not_confusable_with_extraction_approval_architecture_or_runner(
        self,
    ) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        code, output = self._decide(plan_id=plan_id)
        self.assertEqual(code, 0)
        self.assertIn("no requirements extraction", output.lower())
        self.assertIn("no requirements approval", output.lower())
        self.assertIn("no architecture decision", output.lower())
        self.assertIn("no implementation plan", output.lower())
        self.assertIn("no executor invocation", output.lower())

        artifact = load_requirements_extraction_owner_decision(
            self.project,
            "slither-demo",
            plan_id,
            "req-ext-owner-v1",
        )
        self.assertEqual(
            artifact["artifact_type"],
            "REQUIREMENTS_EXTRACTION_OWNER_DECISION",
        )
        self.assertTrue(artifact["non_authority"]["authorization_is_not_extraction"])
        validation = validate_planning_workspace(self.project, plan_id)
        self.assertFalse(validation.valid)

    def test_no_artifact_claims_requirements_approval(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        self._record_decision(plan_id=plan_id)

        decision_text = (
            self._requirements_extraction_decision_path(
                "slither-demo",
                plan_id,
                "req-ext-owner-v1",
            )
            .read_text(encoding="utf-8")
            .lower()
        )
        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8").lower()
        provenance = (
            self._requirements_scaffold_provenance_path(plan_id)
            .read_text(encoding="utf-8")
            .lower()
        )
        self.assertNotIn("requirements approved", decision_text)
        self.assertNotIn("requirements approved", spec)
        self.assertNotIn("requirements approved", provenance)
        self.assertIn("does_not_approve_requirements", decision_text)



class OrchestratorRequirementsExtractionExecutionCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(self.project, intake_id, clarification_id)

    def _readiness_decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(self.project, intake_id, decision_id)

    def _requirements_extraction_decision_path(
        self, intake_id: str, plan_id: str, decision_id: str
    ) -> Path:
        return orchestrator_requirements_extraction_decision_path(
            self.project, intake_id, plan_id, decision_id
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project, intake_id, "Build me an online slither.io-like game"
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project, intake_id, "scope-v1", "Browser-only demo with 10 players max."
        )
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _run(self, argv: list[str]) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def _prepare(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "prepare-planning-draft", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _transport(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "transport-planning-context", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _draft_context_pack(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "draft-context-pack", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _local_spec_preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "local-agentic-spec-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold_local_spec(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-local-agentic-spec", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "requirements-extraction-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-requirements-extraction", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _decide(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_EXTRACTION",
        decision_id: str = "req-ext-owner-v1",
        summary: str = "Authorize future extraction only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-extraction",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _execution_check(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-extraction-execution-check",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-context-pack-draft-provenance.json"

    def _scaffold_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-local-agentic-spec-scaffold-provenance.json"

    def _requirements_scaffold_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-requirements-extraction-scaffold-provenance.json"
        )

    def _transport_json_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-context-transport.json"

    def _transport_md_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-context-transport.md"

    def _provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-provenance.json"

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._local_spec_preflight(intake_id, plan_id)[0], 0)
        self.assertEqual(self._scaffold_local_spec(intake_id, plan_id)[0], 0)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

    def _setup_ready_for_decision(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self.assertEqual(self._scaffold(intake_id, plan_id)[0], 0)

    def _setup_ready_for_execution_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_decision(intake_id, plan_id)
        self.assertEqual(self._decide(intake_id, plan_id)[0], 0)

    def _tracked_artifact_paths(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> dict[Path, bytes]:
        workspace = self._workspace(plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._clarification_path(intake_id, "scope-v1"),
            self._readiness_decision_path(intake_id, "owner-v1"),
            self._provenance_path(plan_id),
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
            self._transport_json_path(plan_id),
            self._transport_md_path(plan_id),
            self._draft_provenance_path(plan_id),
            self._scaffold_provenance_path(plan_id),
            self._requirements_scaffold_provenance_path(plan_id),
            self._context_pack_path(plan_id),
            self._local_spec_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
            self._requirements_extraction_decision_path(intake_id, plan_id, "req-ext-owner-v1"),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def _valid_decision_artifact(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision_id: str = "req-ext-owner-v1",
    ) -> dict:
        return build_requirements_extraction_owner_decision_artifact(
            intake_id,
            plan_id,
            decision_id,
            "AUTHORIZE_REQUIREMENTS_EXTRACTION",
            "Authorize future extraction only.",
            source_requirements_extraction_scaffold_provenance_path=(
                f".agent-os/planning/{plan_id}/evidence/"
                "orchestrator-requirements-extraction-scaffold-provenance.json"
            ),
            source_requirements_extraction_scaffold_status="REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY",
            source_requirements_extraction_scaffold_created_at="2026-07-06T10:00:00+00:00",
            source_requirements_extraction_preflight_state=(
                "REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NO_REQUIREMENTS_GENERATED"
            ),
            source_requirements_extraction_preflight_next_action=(
                "FUTURE_REQUIREMENTS_EXTRACTION_REQUIRES_SEPARATE_COMMAND"
            ),
            planning_workspace_status_at_decision="DRAFT",
            created_at="2026-07-06T10:00:00+00:00",
        )

    def _write_decision_artifact(
        self, intake_id: str, plan_id: str, decision_id: str, artifact: dict
    ) -> Path:
        path = self._requirements_extraction_decision_path(intake_id, plan_id, decision_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        return path
    def test_succeeds_only_when_latest_decision_is_authorize(self) -> None:
        plan_id = "slither-plan-v1"
        self._setup_ready_for_decision(plan_id=plan_id)
        self._decide(plan_id=plan_id, decision="REQUEST_MORE_CONTEXT", decision_id="req-ext-a", summary="Need context.")
        code, output = self._execution_check(plan_id=plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_REQUESTS_MORE_CONTEXT", output)
        self._decide(plan_id=plan_id, decision="AUTHORIZE_REQUIREMENTS_EXTRACTION", decision_id="req-ext-b")
        code, output = self._execution_check(plan_id=plan_id)
        self.assertEqual(code, 0)
        self.assertIn("latest_requirements_extraction_decision: AUTHORIZE_REQUIREMENTS_EXTRACTION", output)

    def test_success_state_is_confirmed_no_extraction_performed(self) -> None:
        self._setup_ready_for_execution_check()
        report = check_requirements_extraction_execution_authorization(self.project, "slither-demo", "slither-plan-v1")
        self.assertEqual(report.check_state, REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_STATE)

    def test_success_next_action_is_future_command_may_be_run_separately(self) -> None:
        self._setup_ready_for_execution_check()
        report = check_requirements_extraction_execution_authorization(self.project, "slither-demo", "slither-plan-v1")
        self.assertEqual(report.next_required_action, REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_NEXT_ACTION)

    def test_report_contains_required_fields(self) -> None:
        self._setup_ready_for_execution_check()
        report = check_requirements_extraction_execution_authorization(self.project, "slither-demo", "slither-plan-v1")
        for field in (
            "check_state", "next_required_action", "plan_id", "intake_id", "planning_workspace_status",
            "local_agentic_spec_status", "local_agentic_spec_path", "requirements_extraction_scaffold_provenance_path",
            "latest_requirements_extraction_decision_id", "latest_requirements_extraction_decision",
            "latest_requirements_extraction_decision_created_at", "latest_requirements_extraction_decision_path",
            "latest_readiness_decision_id", "latest_readiness_decision",
            "source_requirements_extraction_preflight_state", "source_requirements_extraction_preflight_next_action",
            "checked_at", "non_authority",
        ):
            self.assertIsNotNone(getattr(report, field), field)
            self.assertIn(f"{field}:", report.output)

    def test_report_contains_all_non_authority_flags_true(self) -> None:
        self._setup_ready_for_execution_check()
        report = check_requirements_extraction_execution_authorization(self.project, "slither-demo", "slither-plan-v1")
        for flag in REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, report.non_authority)
            self.assertTrue(report.non_authority[flag])

    def test_success_report_identifies_latest_decision_metadata(self) -> None:
        self._setup_ready_for_execution_check()
        report = check_requirements_extraction_execution_authorization(self.project, "slither-demo", "slither-plan-v1")
        self.assertEqual(report.latest_requirements_extraction_decision_id, "req-ext-owner-v1")
        self.assertEqual(report.latest_requirements_extraction_decision, "AUTHORIZE_REQUIREMENTS_EXTRACTION")
        self.assertTrue(report.latest_requirements_extraction_decision_path.is_file())
        self.assertTrue(report.latest_requirements_extraction_decision_created_at)

    def test_success_does_not_extract_requirements(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._local_spec_path().read_bytes()
        self._execution_check()
        self.assertEqual(before, self._local_spec_path().read_bytes())
        self.assertNotIn("The system shall", self._local_spec_path().read_text())

    def test_success_does_not_approve_requirements(self) -> None:
        self._setup_ready_for_execution_check()
        _, output = self._execution_check()
        self.assertIn("not requirements approval", output.lower())

    def test_success_does_not_validate_or_approve_workspace(self) -> None:
        self._setup_ready_for_execution_check()
        before = validate_planning_workspace(self.project, "slither-plan-v1")
        self._execution_check()
        after = validate_planning_workspace(self.project, "slither-plan-v1")
        self.assertFalse(before.valid)
        self.assertEqual(before.output, after.output)

    def test_success_does_not_create_runner_proposals_or_runs(self) -> None:
        self._setup_ready_for_execution_check()
        runs = self.project / ".agent-os" / "runs"
        before = list(runs.iterdir())
        self._execution_check()
        self.assertEqual(before, list(runs.iterdir()))

    def test_success_does_not_invoke_executor_subprocess(self) -> None:
        self._setup_ready_for_execution_check()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code, _ = self._execution_check()
        self.assertEqual(code, 0)

    def test_refuses_missing_workspace(self) -> None:
        bare = Path(tempfile.mkdtemp())
        try:
            code, output = self._run(
                ["orchestrator", "requirements-extraction-execution-check", "slither-demo", str(bare), "--plan-id", "slither-plan-v1"]
            )
            self.assertEqual(code, 1)
            self.assertIn("BLOCKED_MISSING_WORKSPACE", output)
        finally:
            import shutil
            shutil.rmtree(bare)

    def test_refuses_missing_intake(self) -> None:
        code, output = self._run(
            ["orchestrator", "requirements-extraction-execution-check", "missing", str(self.project), "--plan-id", "slither-plan-v1"]
        )
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_INVALID_INTAKE", output)

    def test_refuses_invalid_intake(self) -> None:
        path = self._artifact_path("bad-intake")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{", encoding="utf-8")
        code, output = self._execution_check("bad-intake")
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_INVALID_INTAKE", output)

    def test_refuses_missing_planning_workspace(self) -> None:
        self._authorize_slither()
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_PLANNING_WORKSPACE", output)

    def test_refuses_non_draft_planning_workspace(self) -> None:
        self._setup_ready_for_execution_check()
        manifest = self._workspace() / "manifest.json"
        data = json.loads(manifest.read_text())
        data["status"] = "APPROVED"
        manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_WORKSPACE_NOT_DRAFT", output)

    def test_refuses_missing_requirements_extraction_scaffold_provenance(self) -> None:
        self._setup_ready_for_decision()
        self._requirements_scaffold_provenance_path().unlink()
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE", output)

    def test_refuses_malformed_scaffold_provenance(self) -> None:
        self._setup_ready_for_decision()
        self._requirements_scaffold_provenance_path().write_text("{bad", encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MALFORMED_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE", output)

    def test_refuses_scaffold_provenance_plan_id_mismatch(self) -> None:
        self._setup_ready_for_decision()
        p = json.loads(self._requirements_scaffold_provenance_path().read_text())
        p["plan_id"] = "other-plan"
        self._requirements_scaffold_provenance_path().write_text(json.dumps(p, indent=2) + "\n", encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_MISMATCH", output)

    def test_refuses_scaffold_provenance_intake_id_mismatch(self) -> None:
        self._setup_ready_for_decision()
        p = json.loads(self._requirements_scaffold_provenance_path().read_text())
        p["intake_id"] = "other-intake"
        self._requirements_scaffold_provenance_path().write_text(json.dumps(p, indent=2) + "\n", encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_MISMATCH", output)

    def test_refuses_scaffold_provenance_non_authority_missing_or_false(self) -> None:
        self._setup_ready_for_decision()
        p = json.loads(self._requirements_scaffold_provenance_path().read_text())
        p["non_authority"]["does_not_extract_requirements"] = False
        self._requirements_scaffold_provenance_path().write_text(json.dumps(p, indent=2) + "\n", encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MALFORMED_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE", output)

    def test_refuses_incoherent_requirements_extraction_scaffold(self) -> None:
        self._setup_ready_for_decision()
        self._local_spec_path().write_text(
            self._local_spec_path()
            .read_text(encoding="utf-8")
            .replace("requirements extraction", "REMOVED", -1)
            .replace("not performed", "REMOVED", -1),
            encoding="utf-8",
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_EXTRACTION_SCAFFOLD_NOT_COHERENT", output)

    def test_refuses_missing_local_agentic_spec_md(self) -> None:
        self._setup_ready_for_decision()
        self._local_spec_path().unlink()
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_EXTRACTION_SCAFFOLD_NOT_COHERENT", output)

    def test_refuses_local_agentic_spec_not_requirements_extraction_scaffold(self) -> None:
        self._setup_ready_for_decision()
        local_spec = self._local_spec_path()
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8").replace("REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY", "APPROVED"),
            encoding="utf-8",
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_NOT_REQUIREMENTS_EXTRACTION_SCAFFOLD", output)

    def test_refuses_local_agentic_spec_with_actual_requirements(self) -> None:
        self._setup_ready_for_decision()
        local_spec = self._local_spec_path()
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8") + "\n## Functional Requirements\n\nThe system shall handle login.\n",
            encoding="utf-8",
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_REQUIREMENTS", output)

    def test_refuses_local_agentic_spec_with_requirement_id(self) -> None:
        self._setup_ready_for_decision()
        local_spec = self._local_spec_path()
        local_spec.write_text(local_spec.read_text(encoding="utf-8") + "\nREQ-001: placeholder.\n", encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_REQUIREMENT_IDS", output)

    def test_refuses_local_agentic_spec_with_user_stories(self) -> None:
        self._setup_ready_for_decision()
        local_spec = self._local_spec_path()
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8") + "\n## User Stories\n\nAs a user I want to play.\n",
            encoding="utf-8",
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_USER_STORIES", output)

    def test_refuses_local_agentic_spec_with_acceptance_criteria(self) -> None:
        self._setup_ready_for_decision()
        local_spec = self._local_spec_path()
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8") + "\n## Acceptance Criteria\n\nGiven a user When they click Then it works.\n",
            encoding="utf-8",
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_ACCEPTANCE_CRITERIA", output)

    def test_refuses_local_agentic_spec_with_architecture_decision_language(self) -> None:
        self._setup_ready_for_decision()
        local_spec = self._local_spec_path()
        local_spec.write_text(local_spec.read_text(encoding="utf-8") + "\nSelected backend: postgres\n", encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_ARCHITECTURE", output)

    def test_refuses_local_agentic_spec_with_implementation_tasks(self) -> None:
        self._setup_ready_for_decision()
        local_spec = self._local_spec_path()
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8") + "\n## Implementation Tasks\n\n- [ ] task one\n",
            encoding="utf-8",
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_IMPLEMENTATION_TASKS", output)

    def test_refuses_local_agentic_spec_with_planning_run_slice_content(self) -> None:
        self._setup_ready_for_decision()
        local_spec = self._local_spec_path()
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8") + '\n## PLANNING_RUN_SLICE\n\n{"artifact_type": "PLANNING_RUN_SLICE"}\n',
            encoding="utf-8",
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_PLANNING_RUN_SLICE", output)

    def test_refuses_modified_implementation_plan(self) -> None:
        self._setup_ready_for_decision()
        plan = self._implementation_plan_path()
        plan.write_text(plan.read_text(encoding="utf-8").replace("PLACEHOLDER", "CUSTOMIZED", 1), encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_IMPLEMENTATION_PLAN_ALREADY_MODIFIED", output)

    def test_refuses_modified_planning_audit(self) -> None:
        self._setup_ready_for_decision()
        audit = self._planning_audit_path()
        audit.write_text(audit.read_text(encoding="utf-8").replace("PLACEHOLDER", "CUSTOMIZED", 1), encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_PLANNING_AUDIT_ALREADY_MODIFIED", output)

    def test_refuses_requirements_extraction_preflight_not_confirmed(self) -> None:
        self._setup_ready_for_decision()
        p = json.loads(self._requirements_scaffold_provenance_path().read_text())
        p["source_requirements_extraction_preflight_state"] = "BLOCKED"
        self._requirements_scaffold_provenance_path().write_text(json.dumps(p, indent=2) + "\n", encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MALFORMED_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE", output)

    def test_refuses_latest_readiness_request_more_clarification_after_authorize(self) -> None:
        self._setup_ready_for_execution_check()
        create_owner_readiness_decision(self.project, "slither-demo", "owner-v2", "REQUEST_MORE_CLARIFICATION", "Need more detail.")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_READINESS_DECISION_REQUESTS_CLARIFICATION", output)

    def test_refuses_latest_readiness_block_intake_after_authorize(self) -> None:
        self._setup_ready_for_execution_check()
        create_owner_readiness_decision(self.project, "slither-demo", "owner-v2", "BLOCK_INTAKE", "Stop intake.")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_READINESS_DECISION_BLOCKS_INTAKE", output)

    def test_refuses_no_requirements_extraction_owner_decision(self) -> None:
        self._setup_ready_for_decision()
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_NO_REQUIREMENTS_EXTRACTION_OWNER_DECISION", output)

    def test_refuses_malformed_requirements_extraction_owner_decision_artifact(self) -> None:
        self._setup_ready_for_decision()
        path = self._requirements_extraction_decision_path("slither-demo", "slither-plan-v1", "req-ext-owner-v1")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{bad", encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MALFORMED_REQUIREMENTS_EXTRACTION_OWNER_DECISION", output)

    def test_refuses_latest_request_more_context_decision(self) -> None:
        self._setup_ready_for_decision()
        self._decide(decision="REQUEST_MORE_CONTEXT", summary="Need more context.")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_REQUESTS_MORE_CONTEXT", output)

    def test_refuses_latest_block_requirements_extraction_decision(self) -> None:
        self._setup_ready_for_decision()
        self._decide(decision="BLOCK_REQUIREMENTS_EXTRACTION", summary="Block extraction.")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_BLOCKS_EXTRACTION", output)

    def test_refuses_latest_request_more_context_after_older_authorize_by_ordering(self) -> None:
        from agent_os import orchestrator as orchestrator_module
        self._setup_ready_for_decision()
        times = iter(["2026-07-06T10:00:00+00:00", "2026-07-06T11:00:00+00:00"])
        with patch.object(orchestrator_module, "_utc_now", side_effect=lambda: next(times)):
            create_requirements_extraction_owner_decision(self.project, "slither-demo", "slither-plan-v1", "req-ext-auth", "AUTHORIZE_REQUIREMENTS_EXTRACTION", "Authorize.")
            create_requirements_extraction_owner_decision(self.project, "slither-demo", "slither-plan-v1", "req-ext-more", "REQUEST_MORE_CONTEXT", "Need context.")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_REQUESTS_MORE_CONTEXT", output)

    def test_refuses_latest_block_after_older_authorize_by_ordering(self) -> None:
        from agent_os import orchestrator as orchestrator_module
        self._setup_ready_for_decision()
        times = iter(["2026-07-06T10:00:00+00:00", "2026-07-06T11:00:00+00:00"])
        with patch.object(orchestrator_module, "_utc_now", side_effect=lambda: next(times)):
            create_requirements_extraction_owner_decision(self.project, "slither-demo", "slither-plan-v1", "req-ext-auth", "AUTHORIZE_REQUIREMENTS_EXTRACTION", "Authorize.")
            create_requirements_extraction_owner_decision(self.project, "slither-demo", "slither-plan-v1", "req-ext-block", "BLOCK_REQUIREMENTS_EXTRACTION", "Block.")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_BLOCKS_EXTRACTION", output)

    def test_succeeds_when_latest_authorize_after_older_request_or_block_by_ordering(self) -> None:
        from agent_os import orchestrator as orchestrator_module
        self._setup_ready_for_decision()
        times = iter(["2026-07-06T10:00:00+00:00", "2026-07-06T10:00:00+00:00", "2026-07-06T11:00:00+00:00"])
        with patch.object(orchestrator_module, "_utc_now", side_effect=lambda: next(times)):
            create_requirements_extraction_owner_decision(self.project, "slither-demo", "slither-plan-v1", "req-ext-more", "REQUEST_MORE_CONTEXT", "Need context.")
            create_requirements_extraction_owner_decision(self.project, "slither-demo", "slither-plan-v1", "req-ext-block", "BLOCK_REQUIREMENTS_EXTRACTION", "Block.")
            create_requirements_extraction_owner_decision(self.project, "slither-demo", "slither-plan-v1", "req-ext-auth", "AUTHORIZE_REQUIREMENTS_EXTRACTION", "Authorize.")
        code, output = self._execution_check()
        self.assertEqual(code, 0)
        self.assertIn(REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_STATE, output)

    def test_refuses_stale_latest_authorize_decision(self) -> None:
        self._setup_ready_for_execution_check()
        artifact = load_requirements_extraction_owner_decision(self.project, "slither-demo", "slither-plan-v1", "req-ext-owner-v1")
        artifact["source_requirements_extraction_scaffold_created_at"] = "stale-time"
        self._write_decision_artifact("slither-demo", "slither-plan-v1", "req-ext-owner-v1", artifact)
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_EXTRACTION_OWNER_DECISION_STALE_OR_INCOHERENT", output)

    def test_refuses_invalid_plan_id(self) -> None:
        self._setup_ready_for_execution_check()
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["orchestrator", "requirements-extraction-execution-check", "slither-demo", str(self.project), "--plan-id", "../escape"])
        self.assertEqual(code, 1)
        self.assertIn("invalid plan id", buf.getvalue())

    def test_refuses_path_escape_intake_id(self) -> None:
        self._setup_ready_for_execution_check()
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(["orchestrator", "requirements-extraction-execution-check", "../escape", str(self.project), "--plan-id", "slither-plan-v1"])
        self.assertEqual(code, 1)
        self.assertIn("invalid intake id", buf.getvalue())

    def test_preserves_goal_intake_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_clarification_artifacts_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_readiness_decision_artifacts_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_orchestrator_provenance_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_context_transport_json_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_context_transport_markdown_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_context_pack_draft_provenance_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_local_agentic_spec_scaffold_provenance_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_requirements_extraction_scaffold_provenance_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_requirements_extraction_owner_decision_artifacts_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_context_pack_md_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_local_agentic_spec_md_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_implementation_plan_md_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_preserves_planning_audit_md_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_does_not_change_planning_workspace_status(self) -> None:
        self._setup_ready_for_execution_check()
        manifest = self._workspace() / "manifest.json"
        before = manifest.read_bytes()
        self._execution_check()
        self.assertEqual(before, manifest.read_bytes())

    def test_does_not_change_planning_readiness(self) -> None:
        self._setup_ready_for_execution_check()
        artifact_path = self._artifact_path("slither-demo")
        before = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]
        self._execution_check()
        after = json.loads(artifact_path.read_text(encoding="utf-8"))["planning_readiness"]
        self.assertEqual(before, after)

    def test_creates_no_check_artifact(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._project_files()
        self._execution_check()
        self.assertEqual(before, self._project_files())

    def test_failure_path_creates_no_partial_artifact(self) -> None:
        self._setup_ready_for_decision()
        before = self._project_files()
        self._execution_check()
        self.assertEqual(before, self._project_files())

    def test_failure_path_preserves_source_evidence_and_planning_artifacts(self) -> None:
        self._setup_ready_for_decision()
        before = self._tracked_artifact_paths()
        self._execution_check()
        self.assertEqual(before, self._tracked_artifact_paths())

    def test_does_not_extract_requirements(self) -> None:
        self._setup_ready_for_execution_check()
        self._execution_check()
        self.assertIn("NO_REQUIREMENTS_EXTRACTED", self._local_spec_path().read_text())
        self.assertNotIn("The system shall", self._local_spec_path().read_text())

    def test_does_not_generate_requirement_ids(self) -> None:
        self._setup_ready_for_execution_check()
        self._execution_check()
        combined = "\n".join(p.read_text(encoding="utf-8") for p in self.project.rglob("*") if p.is_file() and p.suffix in {".md", ".json"})
        self.assertNotIn("REQ-001", combined)

    def test_does_not_generate_user_stories(self) -> None:
        self._setup_ready_for_execution_check()
        self._execution_check()
        combined = "\n".join(p.read_text(encoding="utf-8") for p in self.project.rglob("*") if p.is_file() and p.suffix in {".md", ".json"})
        self.assertNotIn("As a user", combined)

    def test_does_not_generate_acceptance_criteria(self) -> None:
        self._setup_ready_for_execution_check()
        self._execution_check()
        combined = "\n".join(p.read_text(encoding="utf-8") for p in self.project.rglob("*") if p.is_file() and p.suffix in {".md", ".json"})
        self.assertNotIn("Given a", combined)

    def test_does_not_generate_architecture_choices(self) -> None:
        self._setup_ready_for_execution_check()
        self._execution_check()
        combined = "\n".join(p.read_text(encoding="utf-8") for p in self.project.rglob("*") if p.is_file() and p.suffix in {".md", ".json"})
        self.assertNotIn("selected backend", combined)

    def test_does_not_generate_implementation_tasks(self) -> None:
        self._setup_ready_for_execution_check()
        self._execution_check()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertNotIn("allowed_paths", spec)

    def test_does_not_generate_planning_run_slice(self) -> None:
        self._setup_ready_for_execution_check()
        self._execution_check()
        text = self._implementation_plan_path().read_text(encoding="utf-8")
        self.assertIn("PLACEHOLDER-slice-id", text)

    def test_does_not_create_runner_proposals(self) -> None:
        self._setup_ready_for_execution_check()
        runs = self.project / ".agent-os" / "runs"
        before = list(runs.iterdir())
        self._execution_check()
        self.assertEqual(before, list(runs.iterdir()))

    def test_does_not_create_runs(self) -> None:
        self._setup_ready_for_execution_check()
        runs = self.project / ".agent-os" / "runs"
        before = list(runs.iterdir())
        self._execution_check()
        self.assertEqual(before, list(runs.iterdir()))

    def test_does_not_invoke_subprocess_executor(self) -> None:
        self._setup_ready_for_execution_check()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code, _ = self._execution_check()
        self.assertEqual(code, 0)

    def test_does_not_call_planning_progress_transition_decide(self) -> None:
        self._setup_ready_for_execution_check()
        with (
            patch.object(planning_module, "progress_planning_workspace") as progress,
            patch.object(planning_module, "transition_planning_workspace") as transition,
            patch.object(planning_module, "record_planning_owner_decision") as decide,
        ):
            self._execution_check()
        progress.assert_not_called()
        transition.assert_not_called()
        decide.assert_not_called()

    def test_does_not_validate_or_approve_workspace(self) -> None:
        self._setup_ready_for_execution_check()
        before = validate_planning_workspace(self.project, "slither-plan-v1")
        self._execution_check()
        after = validate_planning_workspace(self.project, "slither-plan-v1")
        self.assertFalse(before.valid)
        self.assertEqual(before.output, after.output)

    def test_does_not_approve_requirements(self) -> None:
        self._setup_ready_for_execution_check()
        _, output = self._execution_check()
        self.assertIn("not requirements approval", output.lower())
        self.assertNotIn("requirements approved", output.lower())

    def test_cli_help_states_pre_execution_check_boundaries(self) -> None:
        parser = build_parser()
        orchestrator_parser = next(
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction) and "orchestrator" in action.choices
        )
        orchestrator_sub = next(
            action for action in orchestrator_parser.choices["orchestrator"]._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        help_text = orchestrator_sub.choices["requirements-extraction-execution-check"].format_help()
        compact = re.sub(r"\s+", " ", help_text)
        self.assertIn("pre-execution check", compact.lower())
        self.assertIn("extract or infer requirements", compact.lower())
        self.assertIn("approve requirements", compact.lower())
        self.assertIn("architecture", compact.lower())
        self.assertIn("implementation plan", compact.lower())
        self.assertIn("validate", compact.lower())
        self.assertIn("executor", compact.lower())

    def test_cli_output_includes_latest_decision_draft_status_and_boundary_notes(self) -> None:
        self._setup_ready_for_execution_check()
        code, output = self._execution_check()
        self.assertEqual(code, 0)
        self.assertIn("latest_requirements_extraction_decision_id: req-ext-owner-v1", output)
        self.assertIn("latest_requirements_extraction_decision: AUTHORIZE_REQUIREMENTS_EXTRACTION", output)
        self.assertIn("planning_workspace_status: DRAFT", output)
        self.assertIn("not requirements extraction", output.lower())

    def test_cli_output_states_successful_check_is_not_extraction_or_approval(self) -> None:
        self._setup_ready_for_execution_check()
        code, output = self._execution_check()
        self.assertEqual(code, 0)
        self.assertIn("not extraction", output.lower())
        self.assertIn("not requirements approval", output.lower())

    def test_existing_commands_unchanged(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_execution_check(intake_id, plan_id)
        before = self._project_files()
        buf = io.StringIO()
        with redirect_stdout(buf):
            decide_code = main([
                "orchestrator", "decide-requirements-extraction", intake_id, str(self.project),
                "--plan-id", plan_id, "--decision", "REQUEST_MORE_CONTEXT",
                "--decision-id", "req-ext-owner-v2", "--summary", "Need context.",
            ])
            preflight_code = main([
                "orchestrator", "requirements-extraction-preflight", intake_id, str(self.project),
                "--plan-id", plan_id,
            ])
            scaffold_code = main([
                "orchestrator", "scaffold-requirements-extraction", intake_id, str(self.project),
                "--plan-id", plan_id,
            ])
        self.assertEqual(decide_code, 0)
        self.assertEqual(preflight_code, 1)
        self.assertEqual(scaffold_code, 1)
        self.assertEqual(before | {p for p in self._project_files() if "req-ext-owner-v2" in p}, self._project_files())

    def test_successful_check_not_confusable_with_extraction_approval_architecture_or_runner(self) -> None:
        self._setup_ready_for_execution_check()
        code, output = self._execution_check()
        self.assertEqual(code, 0)
        self.assertIn("not requirements extraction", output.lower())
        self.assertIn("not requirements approval", output.lower())
        self.assertIn("not architecture decision", output.lower())
        self.assertIn("not implementation plan", output.lower())
        self.assertIn("not workspace validation or approval", output.lower())

    def test_no_artifact_or_report_claims_requirements_approval(self) -> None:
        self._setup_ready_for_execution_check()
        _, output = self._execution_check()
        self.assertNotIn("requirements approved", output.lower())

class OrchestratorExtractRequirementsDraftTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(self.project, intake_id, clarification_id)

    def _readiness_decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(self.project, intake_id, decision_id)

    def _requirements_extraction_decision_path(
        self, intake_id: str, plan_id: str, decision_id: str
    ) -> Path:
        return orchestrator_requirements_extraction_decision_path(
            self.project, intake_id, plan_id, decision_id
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project, intake_id, "Build me an online slither.io-like game"
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project, intake_id, "scope-v1", "Browser-only demo with 10 players max."
        )
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _run(self, argv: list[str]) -> tuple[int, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(argv)
        return code, out_buf.getvalue() + err_buf.getvalue()

    def _prepare(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "prepare-planning-draft", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _transport(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "transport-planning-context", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _draft_context_pack(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "draft-context-pack", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _local_spec_preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "local-agentic-spec-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold_local_spec(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-local-agentic-spec", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "requirements-extraction-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-requirements-extraction", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _decide(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_EXTRACTION",
        decision_id: str = "req-ext-owner-v1",
        summary: str = "Authorize future extraction only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-extraction",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _execution_check(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-extraction-execution-check",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "extract-requirements-draft",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-context-pack-draft-provenance.json"

    def _scaffold_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-local-agentic-spec-scaffold-provenance.json"

    def _requirements_scaffold_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-requirements-extraction-scaffold-provenance.json"
        )

    def _requirements_draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-requirements-draft-provenance.json"

    def _transport_json_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-context-transport.json"

    def _transport_md_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-context-transport.md"

    def _provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-provenance.json"

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._local_spec_preflight(intake_id, plan_id)[0], 0)
        self.assertEqual(self._scaffold_local_spec(intake_id, plan_id)[0], 0)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

    def _setup_ready_for_decision(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self.assertEqual(self._scaffold(intake_id, plan_id)[0], 0)

    def _setup_ready_for_execution_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_decision(intake_id, plan_id)
        self.assertEqual(self._decide(intake_id, plan_id)[0], 0)

    def _setup_ready_for_extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_execution_check(intake_id, plan_id)
        self.assertEqual(self._execution_check(intake_id, plan_id)[0], 0)

    def _tracked_artifact_paths(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> dict[Path, bytes]:
        workspace = self._workspace(plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._clarification_path(intake_id, "scope-v1"),
            self._readiness_decision_path(intake_id, "owner-v1"),
            self._provenance_path(plan_id),
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
            self._transport_json_path(plan_id),
            self._transport_md_path(plan_id),
            self._draft_provenance_path(plan_id),
            self._scaffold_provenance_path(plan_id),
            self._requirements_scaffold_provenance_path(plan_id),
            self._context_pack_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
            self._requirements_extraction_decision_path(intake_id, plan_id, "req-ext-owner-v1"),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def _candidate_texts(self, plan_id: str = "slither-plan-v1") -> list[str]:
        spec = self._local_spec_path(plan_id).read_text(encoding="utf-8")
        return re.findall(r"candidate_text:\s*(.+)", spec)

    def test_succeeds_only_after_successful_execution_check(self) -> None:
        self._setup_ready_for_decision()
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())
        self._decide()
        self.assertEqual(self._execution_check()[0], 0)
        self.assertEqual(self._extract()[0], 0)

    def test_local_agentic_spec_replaced_with_requirements_draft_non_authority(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn(REQUIREMENTS_DRAFT_STATUS, spec)
        self.assertNotIn("REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY", spec)

    def test_requirements_draft_provenance_created_at_expected_path(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        self.assertTrue(self._requirements_draft_provenance_path().is_file())

    def test_provenance_contains_required_fields(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        provenance = json.loads(self._requirements_draft_provenance_path().read_text())
        for field in (
            "artifact_type", "schema_version", "plan_id", "intake_id",
            "source_context_transport_path", "source_context_pack_path",
            "source_requirements_extraction_scaffold_provenance_path",
            "source_requirements_extraction_owner_decision_id",
            "source_requirements_extraction_owner_decision_path",
            "source_requirements_extraction_execution_check_state",
            "source_requirements_extraction_execution_check_next_action",
            "local_agentic_spec_path", "local_agentic_spec_status",
            "requirement_candidate_count", "requirement_candidate_ids",
            "planning_workspace_status_at_draft", "created_at", "non_authority",
        ):
            self.assertIn(field, provenance, field)

    def test_provenance_contains_all_non_authority_flags_true(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        for flag in REQUIREMENTS_DRAFT_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, report.non_authority)
            self.assertTrue(report.non_authority[flag])
        provenance = json.loads(self._requirements_draft_provenance_path().read_text())
        for flag in REQUIREMENTS_DRAFT_NON_AUTHORITY_FLAGS:
            self.assertTrue(provenance["non_authority"][flag])

    def test_provenance_candidate_count_matches_local_agentic_spec(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        provenance = json.loads(self._requirements_draft_provenance_path().read_text())
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertEqual(provenance["requirement_candidate_count"], report.requirement_candidate_count)
        self.assertEqual(spec.count("DRAFT-REQ-"), report.requirement_candidate_count)
        self.assertEqual(
            tuple(provenance["requirement_candidate_ids"]),
            report.requirement_candidate_ids,
        )
        for candidate_id in report.requirement_candidate_ids:
            self.assertIn(candidate_id, spec)

    def test_candidate_ids_are_deterministic_draft_ids(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        self.assertGreater(len(report.requirement_candidate_ids), 0)
        self.assertEqual(report.requirement_candidate_ids[0], "DRAFT-REQ-001")

    def test_candidate_ids_are_not_approved_style_ids(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        for candidate_id in report.requirement_candidate_ids:
            self.assertRegex(candidate_id, r"^DRAFT-REQ-\d{3}$")
            self.assertNotRegex(candidate_id, r"^(REQ|FR|NFR)-\d+$")

    def test_each_candidate_is_draft_requirement_candidate_non_authority(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        for candidate in report.candidates:
            self.assertEqual(candidate.status, DRAFT_REQUIREMENT_CANDIDATE_STATUS)

    def test_each_candidate_is_source_bounded(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        spec = self._local_spec_path().read_text(encoding="utf-8")
        for candidate in report.candidates:
            self.assertEqual(candidate.source_bounded, DRAFT_REQUIREMENT_SOURCE_BOUNDED_MARKER)
            self.assertTrue(candidate.source_path)
            self.assertTrue(candidate.source_field)
            self.assertTrue(candidate.source_quote_or_reference)
            self.assertIn("Draft candidate derived from source", candidate.candidate_text)
            self.assertIn(
                f"**source_bounded:** `{DRAFT_REQUIREMENT_SOURCE_BOUNDED_MARKER}`",
                spec,
            )
        self.assertEqual(
            spec.count(f"**source_bounded:** `{DRAFT_REQUIREMENT_SOURCE_BOUNDED_MARKER}`"),
            len(report.candidates),
        )

    def test_each_candidate_is_not_validated(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        for candidate in report.candidates:
            self.assertEqual(candidate.validation_status, "NOT_VALIDATED")

    def test_each_candidate_is_not_approved(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        for candidate in report.candidates:
            self.assertEqual(candidate.approval_status, "NOT_APPROVED")

    def test_each_candidate_has_architecture_status_not_decided(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        for candidate in report.candidates:
            self.assertEqual(candidate.architecture_status, "NOT_DECIDED")

    def test_each_candidate_has_implementation_status_not_planned(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        for candidate in report.candidates:
            self.assertEqual(candidate.implementation_status, "NOT_PLANNED")

    def test_candidate_text_derived_from_explicit_source_material(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        goal_candidate = next(
            c for c in report.candidates if "slither.io-like game" in c.candidate_text.lower()
        )
        self.assertIn("Build me an online slither.io-like game", goal_candidate.source_quote_or_reference)

    def test_broad_slither_goal_stays_broad_without_inferred_subrequirements(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        combined = "\n".join(c.candidate_text.lower() for c in report.candidates)
        source_combined = "\n".join(c.source_quote_or_reference.lower() for c in report.candidates)
        for term in (
            "websocket",
            "leaderboard",
            "accounts",
            "physics",
            "deployment",
            "rendering engine",
            "database",
            "realtime multiplayer",
            "multiplayer",
        ):
            if term not in source_combined:
                self.assertNotIn(term, combined)

    def test_candidate_text_does_not_use_shall_or_must_unless_quoted(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        for candidate in report.candidates:
            lowered = candidate.candidate_text.lower()
            if "shall" in lowered and "shall" not in candidate.source_quote_or_reference.lower():
                self.fail(candidate.candidate_text)
            if " must " in f" {lowered} " and "must" not in candidate.source_quote_or_reference.lower():
                self.fail(candidate.candidate_text)

    def test_candidate_text_does_not_include_user_story_form(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        combined = "\n".join(c.candidate_text for c in report.candidates)
        self.assertNotIn("As a user", combined)

    def test_candidate_text_does_not_include_acceptance_criteria_language(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        combined = "\n".join(c.candidate_text for c in report.candidates)
        self.assertNotIn("Given a", combined)

    def test_candidate_text_does_not_include_architecture_choices(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        combined = "\n".join(c.candidate_text.lower() for c in report.candidates)
        self.assertNotIn("selected backend", combined)
        self.assertNotIn("database", combined)

    def test_candidate_text_does_not_include_implementation_tasks(self) -> None:
        self._setup_ready_for_extract()
        report = extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        combined = "\n".join(c.candidate_text for c in report.candidates)
        self.assertNotIn("allowed_paths", combined)

    def test_local_agentic_spec_states_draft_non_authority_unvalidated_unapproved(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8").lower()
        self.assertIn("draft", spec)
        self.assertIn("non-authority", spec)
        self.assertIn("unvalidated", spec)
        self.assertIn("unapproved", spec)

    def test_local_agentic_spec_states_future_validation_requires_separate_command(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8").lower()
        self.assertIn("requirements validation", spec)
        self.assertIn("separate command", spec)

    def test_local_agentic_spec_states_architecture_not_generated(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("UNDECIDED_NOT_GENERATED", spec)

    def test_local_agentic_spec_states_implementation_plan_not_generated(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("## Implementation Plan", spec)
        self.assertIn("NOT_GENERATED", spec)

    def test_local_agentic_spec_states_planning_run_slice_not_generated(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("## PLANNING_RUN_SLICE", spec)
        self.assertIn("NOT_GENERATED", spec)

    def test_local_agentic_spec_states_workspace_not_validated_or_approved(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8").lower()
        self.assertIn("not validated or approved", spec)

    def test_local_agentic_spec_states_runner_executor_not_invoked(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8").lower()
        self.assertIn("not created or invoked", spec)

    def test_refuses_missing_workspace(self) -> None:
        bare = Path(tempfile.mkdtemp())
        try:
            code, output = self._run(
                ["orchestrator", "extract-requirements-draft", "slither-demo", str(bare), "--plan-id", "slither-plan-v1"]
            )
            self.assertEqual(code, 1)
            self.assertIn("no workspace found", output.lower())
        finally:
            import shutil
            shutil.rmtree(bare)

    def test_refuses_missing_intake(self) -> None:
        code, output = self._run(
            ["orchestrator", "extract-requirements-draft", "missing", str(self.project), "--plan-id", "slither-plan-v1"]
        )
        self.assertEqual(code, 1)
        self.assertIn("goal intake artifact not found", output.lower())

    def test_refuses_invalid_intake(self) -> None:
        path = self._artifact_path("bad-intake")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{", encoding="utf-8")
        code, output = self._extract("bad-intake")
        self.assertEqual(code, 1)

    def test_refuses_missing_planning_workspace(self) -> None:
        self._authorize_slither()
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("planning workspace not found", output.lower())

    def test_refuses_non_draft_planning_workspace(self) -> None:
        self._setup_ready_for_extract()
        manifest = self._workspace() / "manifest.json"
        data = json.loads(manifest.read_text())
        data["status"] = "APPROVED"
        manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("must be DRAFT", output)

    def test_refuses_failed_requirements_extraction_execution_check(self) -> None:
        self._setup_ready_for_decision()
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_latest_owner_request_more_context(self) -> None:
        self._setup_ready_for_decision()
        self._decide(decision="REQUEST_MORE_CONTEXT", decision_id="req-ext-a", summary="Need context.")
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_latest_owner_block_requirements_extraction(self) -> None:
        self._setup_ready_for_decision()
        self._decide(decision="BLOCK_REQUIREMENTS_EXTRACTION", decision_id="req-ext-b", summary="Blocked.")
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_stale_incoherent_owner_authorize(self) -> None:
        self._setup_ready_for_extract()
        path = self._requirements_extraction_decision_path("slither-demo", "slither-plan-v1", "req-ext-owner-v1")
        artifact = json.loads(path.read_text())
        artifact["source_requirements_extraction_scaffold_status"] = "WRONG"
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_incoherent_requirements_extraction_scaffold(self) -> None:
        self._setup_ready_for_extract()
        self._local_spec_path().write_text(
            self._local_spec_path().read_text(encoding="utf-8").replace("not performed", "REMOVED"),
            encoding="utf-8",
        )
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_missing_local_agentic_spec_md(self) -> None:
        self._setup_ready_for_extract()
        self._local_spec_path().unlink()
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_local_agentic_spec_not_requirements_extraction_scaffold(self) -> None:
        self._setup_ready_for_extract()
        local_spec = self._local_spec_path()
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8").replace(
                "REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY", "APPROVED"
            ),
            encoding="utf-8",
        )
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_local_agentic_spec_already_containing_requirements(self) -> None:
        self._setup_ready_for_extract()
        local_spec = self._local_spec_path()
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8") + "\nThe system shall handle login.\n",
            encoding="utf-8",
        )
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_local_agentic_spec_already_containing_draft_req(self) -> None:
        self._setup_ready_for_extract()
        local_spec = self._local_spec_path()
        local_spec.write_text(local_spec.read_text(encoding="utf-8") + "\nDRAFT-REQ-999\n", encoding="utf-8")
        code, output = self._extract()
        self.assertEqual(code, 1)
        lowered = output.lower()
        self.assertTrue(
            "already contains requirements draft" in lowered
            or "execution check not confirmed" in lowered
        )

    def test_refuses_local_agentic_spec_already_containing_req_001(self) -> None:
        self._setup_ready_for_extract()
        local_spec = self._local_spec_path()
        local_spec.write_text(local_spec.read_text(encoding="utf-8") + "\nREQ-001\n", encoding="utf-8")
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_local_agentic_spec_already_containing_nfr_001(self) -> None:
        self._setup_ready_for_extract()
        before_tracked = self._tracked_artifact_paths()
        local_spec = self._local_spec_path()
        local_spec.write_text(local_spec.read_text(encoding="utf-8") + "\nNFR-001\n", encoding="utf-8")
        after_append = local_spec.read_bytes()
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())
        self.assertEqual(after_append, local_spec.read_bytes())
        self.assertFalse(self._requirements_draft_provenance_path().exists())
        for path, content in before_tracked.items():
            self.assertEqual(content, path.read_bytes())

    def test_refuses_local_agentic_spec_already_containing_user_stories(self) -> None:
        self._setup_ready_for_extract()
        local_spec = self._local_spec_path()
        local_spec.write_text(local_spec.read_text(encoding="utf-8") + "\nAs a user I want login.\n", encoding="utf-8")
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_local_agentic_spec_already_containing_acceptance_criteria(self) -> None:
        self._setup_ready_for_extract()
        local_spec = self._local_spec_path()
        local_spec.write_text(local_spec.read_text(encoding="utf-8") + "\nGiven a user When login Then success.\n", encoding="utf-8")
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_local_agentic_spec_already_containing_architecture_decision_language(self) -> None:
        self._setup_ready_for_extract()
        local_spec = self._local_spec_path()
        local_spec.write_text(local_spec.read_text(encoding="utf-8") + "\nSelected backend: Node.js\n", encoding="utf-8")
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_local_agentic_spec_already_containing_implementation_tasks(self) -> None:
        self._setup_ready_for_extract()
        local_spec = self._local_spec_path()
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8") + "\n## Implementation Tasks\n\n- Task one\n",
            encoding="utf-8",
        )
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_local_agentic_spec_already_containing_planning_run_slice_content(self) -> None:
        self._setup_ready_for_extract()
        local_spec = self._local_spec_path()
        local_spec.write_text(
            local_spec.read_text(encoding="utf-8") + '\n"artifact_type": "PLANNING_RUN_SLICE"\n',
            encoding="utf-8",
        )
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_modified_implementation_plan(self) -> None:
        self._setup_ready_for_extract()
        self._implementation_plan_path().write_text("# modified\n", encoding="utf-8")
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_modified_planning_audit(self) -> None:
        self._setup_ready_for_extract()
        self._planning_audit_path().write_text("# modified\n", encoding="utf-8")
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("execution check not confirmed", output.lower())

    def test_refuses_missing_context_transport_json(self) -> None:
        self._setup_ready_for_extract()
        self._transport_json_path().unlink()
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("context transport json not found", output.lower())

    def test_refuses_malformed_context_transport_json(self) -> None:
        self._setup_ready_for_extract()
        self._transport_json_path().write_text("{bad", encoding="utf-8")
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("invalid context transport json", output.lower())

    def test_refuses_missing_context_pack_md(self) -> None:
        self._setup_ready_for_extract()
        self._context_pack_path().unlink()
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("context-pack.md missing", output.lower())

    def test_refuses_existing_requirements_draft_provenance_and_does_not_overwrite(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        before = self._requirements_draft_provenance_path().read_bytes()
        code, output = self._extract()
        self.assertEqual(code, 1)
        self.assertIn("requirements draft provenance already exists", output.lower())
        self.assertEqual(before, self._requirements_draft_provenance_path().read_bytes())

    def test_refuses_invalid_plan_id(self) -> None:
        self._setup_ready_for_extract()
        code, output = self._run(
            ["orchestrator", "extract-requirements-draft", "slither-demo", str(self.project), "--plan-id", "bad plan"]
        )
        self.assertEqual(code, 1)

    def test_refuses_path_escape_intake_id(self) -> None:
        code, output = self._run(
            ["orchestrator", "extract-requirements-draft", "../evil", str(self.project), "--plan-id", "slither-plan-v1"]
        )
        self.assertEqual(code, 1)

    def test_preserves_goal_intake_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        self.assertEqual(before[self._artifact_path("slither-demo")], self._artifact_path("slither-demo").read_bytes())

    def test_preserves_clarification_artifacts_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        path = self._clarification_path("slither-demo", "scope-v1")
        self.assertEqual(before[path], path.read_bytes())

    def test_preserves_readiness_decision_artifacts_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        path = self._readiness_decision_path("slither-demo", "owner-v1")
        self.assertEqual(before[path], path.read_bytes())

    def test_preserves_orchestrator_provenance_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        path = self._provenance_path()
        self.assertEqual(before[path], path.read_bytes())

    def test_preserves_context_transport_json_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        path = self._transport_json_path()
        self.assertEqual(before[path], path.read_bytes())

    def test_preserves_context_transport_markdown_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        path = self._transport_md_path()
        self.assertEqual(before[path], path.read_bytes())

    def test_preserves_context_pack_draft_provenance_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        path = self._draft_provenance_path()
        self.assertEqual(before[path], path.read_bytes())

    def test_preserves_local_agentic_spec_scaffold_provenance_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        path = self._scaffold_provenance_path()
        self.assertEqual(before[path], path.read_bytes())

    def test_preserves_requirements_extraction_scaffold_provenance_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        path = self._requirements_scaffold_provenance_path()
        self.assertEqual(before[path], path.read_bytes())

    def test_preserves_requirements_extraction_owner_decision_artifacts_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        path = self._requirements_extraction_decision_path("slither-demo", "slither-plan-v1", "req-ext-owner-v1")
        self.assertEqual(before[path], path.read_bytes())

    def test_preserves_context_pack_md_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        path = self._context_pack_path()
        self.assertEqual(before[path], path.read_bytes())

    def test_preserves_implementation_plan_md_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        path = self._implementation_plan_path()
        self.assertEqual(before[path], path.read_bytes())

    def test_preserves_planning_audit_md_byte_for_byte(self) -> None:
        self._setup_ready_for_extract()
        before = self._tracked_artifact_paths()
        self._extract()
        path = self._planning_audit_path()
        self.assertEqual(before[path], path.read_bytes())

    def test_does_not_change_planning_workspace_status(self) -> None:
        self._setup_ready_for_extract()
        manifest = self._workspace() / "manifest.json"
        before = manifest.read_bytes()
        self._extract()
        self.assertEqual(before, manifest.read_bytes())

    def test_does_not_approve_requirements(self) -> None:
        self._setup_ready_for_extract()
        _, output = self._extract()
        self.assertIn("no requirements approval", output.lower())
        self.assertNotIn("requirements approved", output.lower())

    def test_does_not_validate_requirements(self) -> None:
        self._setup_ready_for_extract()
        _, output = self._extract()
        self.assertIn("not validated", output.lower())

    def test_does_not_generate_user_stories(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("## User Stories", spec)
        self.assertIn("NOT_GENERATED", spec)
        self.assertNotIn("As a user", spec)

    def test_does_not_generate_acceptance_criteria(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("## Acceptance Criteria", spec)
        self.assertIn("NOT_GENERATED", spec)
        self.assertNotIn("Given a", spec)

    def test_does_not_generate_architecture_choices(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8").lower()
        self.assertIn("undecided", spec)
        self.assertNotIn("selected backend", spec)

    def test_does_not_generate_implementation_tasks(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertNotIn("allowed_paths", spec)

    def test_does_not_generate_planning_run_slice(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("## PLANNING_RUN_SLICE", spec)
        self.assertIn("NOT_GENERATED", spec)

    def test_does_not_create_runner_proposals(self) -> None:
        self._setup_ready_for_extract()
        runs = self.project / ".agent-os" / "runs"
        before = list(runs.iterdir())
        self._extract()
        self.assertEqual(before, list(runs.iterdir()))

    def test_does_not_create_runs(self) -> None:
        self._setup_ready_for_extract()
        runs = self.project / ".agent-os" / "runs"
        before = list(runs.iterdir())
        self._extract()
        self.assertEqual(before, list(runs.iterdir()))

    def test_does_not_invoke_subprocess_executor(self) -> None:
        self._setup_ready_for_extract()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code, _ = self._extract()
        self.assertEqual(code, 0)

    def test_does_not_call_planning_progress_transition_decide(self) -> None:
        self._setup_ready_for_extract()
        with (
            patch.object(planning_module, "progress_planning_workspace") as progress,
            patch.object(planning_module, "transition_planning_workspace") as transition,
            patch.object(planning_module, "record_planning_owner_decision") as decide,
        ):
            self._extract()
        progress.assert_not_called()
        transition.assert_not_called()
        decide.assert_not_called()

    def test_does_not_validate_or_approve_workspace(self) -> None:
        self._setup_ready_for_extract()
        before = validate_planning_workspace(self.project, "slither-plan-v1")
        self._extract()
        after = validate_planning_workspace(self.project, "slither-plan-v1")
        self.assertFalse(before.valid)
        self.assertEqual(before.output, after.output)

    def test_restores_local_agentic_spec_when_provenance_write_fails(self) -> None:
        self._setup_ready_for_extract()
        original = self._local_spec_path().read_bytes()
        with patch("agent_os.orchestrator._write_json", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                extract_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        self.assertEqual(original, self._local_spec_path().read_bytes())
        self.assertFalse(self._requirements_draft_provenance_path().exists())

    def test_cli_help_states_draft_extraction_boundaries(self) -> None:
        parser = build_parser()
        orchestrator_parser = next(
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction) and "orchestrator" in action.choices
        )
        orchestrator_sub = next(
            action for action in orchestrator_parser.choices["orchestrator"]._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        help_text = orchestrator_sub.choices["extract-requirements-draft"].format_help()
        compact = re.sub(r"\s+", " ", help_text)
        for phrase in (
            "draft", "approve", "validate requirements", "user stories",
            "acceptance criteria", "architecture", "implementation plan", "executor",
        ):
            self.assertIn(phrase, compact.lower())

    def test_cli_output_includes_paths_count_status_and_boundary_notes(self) -> None:
        self._setup_ready_for_extract()
        code, output = self._extract()
        self.assertEqual(code, 0)
        self.assertIn("local agentic spec:", output)
        self.assertIn("requirements draft provenance:", output)
        self.assertIn("requirement_candidate_count:", output)
        self.assertIn(REQUIREMENTS_DRAFT_STATUS, output)

    def test_cli_output_states_draft_non_authority_not_validated_not_approved(self) -> None:
        self._setup_ready_for_extract()
        _, output = self._extract()
        lowered = output.lower()
        self.assertIn("draft", lowered)
        self.assertIn("non-authority", lowered)
        self.assertIn("not validated", lowered)
        self.assertIn("not approved", lowered)

    def test_existing_commands_unchanged(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_extract(intake_id, plan_id)
        before = self._project_files()
        buf = io.StringIO()
        with redirect_stdout(buf):
            check_code = main([
                "orchestrator", "requirements-extraction-execution-check", intake_id, str(self.project),
                "--plan-id", plan_id,
            ])
            preflight_code = main([
                "orchestrator", "requirements-extraction-preflight", intake_id, str(self.project),
                "--plan-id", plan_id,
            ])
        self.assertEqual(check_code, 0)
        self.assertEqual(preflight_code, 1)
        self.assertEqual(
            before | {p for p in self._project_files() if "requirements-draft" in p},
            self._project_files(),
        )

    def test_created_draft_not_confusable_with_approval_architecture_or_runner(self) -> None:
        self._setup_ready_for_extract()
        _, output = self._extract()
        lowered = output.lower()
        self.assertIn("no requirements approval", lowered)
        self.assertIn("no architecture generation", lowered)
        self.assertIn("no runner proposals", lowered)

    def test_no_artifact_claims_requirements_approval(self) -> None:
        self._setup_ready_for_extract()
        self._extract()
        combined = "\n".join(
            p.read_text(encoding="utf-8").lower()
            for p in self.project.rglob("*")
            if p.is_file() and p.suffix in {".md", ".json"}
        )
        self.assertNotIn("requirements approved", combined)


class OrchestratorRequirementsDraftValidationPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(self.project, intake_id, clarification_id)

    def _readiness_decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(self.project, intake_id, decision_id)

    def _requirements_extraction_decision_path(
        self, intake_id: str, plan_id: str, decision_id: str
    ) -> Path:
        return orchestrator_requirements_extraction_decision_path(
            self.project, intake_id, plan_id, decision_id
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project, intake_id, "Build me an online slither.io-like game"
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project, intake_id, "scope-v1", "Browser-only demo with 10 players max."
        )
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _run(self, argv: list[str]) -> tuple[int, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(argv)
        return code, out_buf.getvalue() + err_buf.getvalue()

    def _prepare(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "prepare-planning-draft", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _transport(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "transport-planning-context", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _draft_context_pack(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "draft-context-pack", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _local_spec_preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "local-agentic-spec-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold_local_spec(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-local-agentic-spec", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "requirements-extraction-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-requirements-extraction", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _decide(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_EXTRACTION",
        decision_id: str = "req-ext-owner-v1",
        summary: str = "Authorize future extraction only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-extraction",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _execution_check(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-extraction-execution-check",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "extract-requirements-draft",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _validation_preflight(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-draft-validation-preflight",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-context-pack-draft-provenance.json"

    def _scaffold_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-local-agentic-spec-scaffold-provenance.json"

    def _requirements_scaffold_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-requirements-extraction-scaffold-provenance.json"
        )

    def _requirements_draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-requirements-draft-provenance.json"

    def _transport_json_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-context-transport.json"

    def _transport_md_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-context-transport.md"

    def _provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-provenance.json"

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._local_spec_preflight(intake_id, plan_id)[0], 0)
        self.assertEqual(self._scaffold_local_spec(intake_id, plan_id)[0], 0)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

    def _setup_ready_for_decision(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self.assertEqual(self._scaffold(intake_id, plan_id)[0], 0)

    def _setup_ready_for_execution_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_decision(intake_id, plan_id)
        self.assertEqual(self._decide(intake_id, plan_id)[0], 0)

    def _setup_ready_for_extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_execution_check(intake_id, plan_id)
        self.assertEqual(self._execution_check(intake_id, plan_id)[0], 0)

    def _setup_ready_for_preflight(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_extract(intake_id, plan_id)
        self.assertEqual(self._extract(intake_id, plan_id)[0], 0)

    def _tracked_artifact_paths(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> dict[Path, bytes]:
        workspace = self._workspace(plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._clarification_path(intake_id, "scope-v1"),
            self._readiness_decision_path(intake_id, "owner-v1"),
            self._provenance_path(plan_id),
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
            self._transport_json_path(plan_id),
            self._transport_md_path(plan_id),
            self._draft_provenance_path(plan_id),
            self._scaffold_provenance_path(plan_id),
            self._requirements_scaffold_provenance_path(plan_id),
            self._requirements_draft_provenance_path(plan_id),
            self._context_pack_path(plan_id),
            self._local_spec_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
            self._requirements_extraction_decision_path(intake_id, plan_id, "req-ext-owner-v1"),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def _valid_decision_artifact(
        self,
        *,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision_id: str = "req-ext-owner-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_EXTRACTION",
        summary: str = "Authorize future extraction only.",
        created_at: str = "2026-07-06T10:00:00+00:00",
    ) -> dict:
        return build_requirements_extraction_owner_decision_artifact(
            intake_id,
            plan_id,
            decision_id,
            decision,
            summary,
            source_requirements_extraction_scaffold_provenance_path=(
                f".agent-os/planning/{plan_id}/evidence/"
                "orchestrator-requirements-extraction-scaffold-provenance.json"
            ),
            source_requirements_extraction_scaffold_status="REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY",
            source_requirements_extraction_scaffold_created_at="2026-07-06T10:00:00+00:00",
            source_requirements_extraction_preflight_state=(
                "REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NO_REQUIREMENTS_GENERATED"
            ),
            source_requirements_extraction_preflight_next_action=(
                "FUTURE_REQUIREMENTS_EXTRACTION_REQUIRES_SEPARATE_COMMAND"
            ),
            planning_workspace_status_at_decision="DRAFT",
            created_at=created_at,
        )

    def _write_decision_artifact(
        self, intake_id: str, plan_id: str, decision_id: str, artifact: dict
    ) -> Path:
        path = self._requirements_extraction_decision_path(intake_id, plan_id, decision_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        return path

    def test_successful_requirements_draft_validation_preflight(self) -> None:
        self._setup_ready_for_preflight()
        report = requirements_draft_validation_preflight(
            self.project, "slither-demo", "slither-plan-v1"
        )
        self.assertEqual(
            report.preflight_state,
            REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_STATE,
        )
        self.assertEqual(
            report.next_required_action,
            REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_NEXT_ACTION,
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 0)
        self.assertIn(REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_STATE, output)
        self.assertIn(REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_NEXT_ACTION, output)

    def test_command_is_read_only(self) -> None:
        self._setup_ready_for_preflight()
        before = self._tracked_artifact_paths()
        code, _ = self._validation_preflight()
        self.assertEqual(code, 0)
        for path, content in before.items():
            self.assertEqual(content, path.read_bytes(), str(path))

    def test_refuses_missing_intake(self) -> None:
        code, output = self._validation_preflight("missing-intake")
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_INVALID_INTAKE", output)

    def test_refuses_missing_planning_workspace(self) -> None:
        self._authorize_slither()
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_PLANNING_WORKSPACE", output)

    def test_refuses_non_draft_planning_workspace(self) -> None:
        self._setup_ready_for_preflight()
        manifest_path = self._workspace() / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["status"] = "APPROVED"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_PLANNING_WORKSPACE_NOT_DRAFT", output)

    def test_refuses_missing_orchestrator_provenance(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._authorize_slither(intake_id)
        init_planning_workspace(self.project, plan_id)
        self._transport_json_path(plan_id).parent.mkdir(parents=True, exist_ok=True)
        self._transport_json_path(plan_id).write_text("{}", encoding="utf-8")
        self._transport_md_path(plan_id).write_text("# stub\n", encoding="utf-8")
        code, output = self._validation_preflight(intake_id, plan_id)
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_ORCHESTRATOR_PROVENANCE", output)

    def test_refuses_missing_local_agentic_spec_md(self) -> None:
        self._setup_ready_for_preflight()
        self._local_spec_path().unlink()
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_LOCAL_AGENTIC_SPEC", output)

    def test_refuses_missing_requirements_draft_provenance(self) -> None:
        self._setup_ready_for_preflight()
        self._requirements_draft_provenance_path().unlink()
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_REQUIREMENTS_DRAFT_PROVENANCE", output)

    def test_refuses_wrong_local_agentic_spec_scaffold_status(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                REQUIREMENTS_DRAFT_STATUS, "REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY"
            ),
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_WRONG_LOCAL_AGENTIC_SPEC_STATUS", output)

    def test_refuses_wrong_local_agentic_spec_approved_status(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                REQUIREMENTS_DRAFT_STATUS, "APPROVED_REQUIREMENTS"
            ),
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_WRONG_LOCAL_AGENTIC_SPEC_STATUS", output)

    def test_refuses_promoted_req_identifier(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(spec.read_text(encoding="utf-8") + "\n### REQ-001\n", encoding="utf-8")
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_PROMOTED_REQUIREMENT_IDENTIFIER", output)

    def test_refuses_promoted_fr_identifier(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(spec.read_text(encoding="utf-8") + "\n### FR-001\n", encoding="utf-8")
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_PROMOTED_REQUIREMENT_IDENTIFIER", output)

    def test_refuses_promoted_nfr_identifier(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(spec.read_text(encoding="utf-8") + "\n### NFR-001\n", encoding="utf-8")
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_PROMOTED_REQUIREMENT_IDENTIFIER", output)

    def test_draft_req_identifier_not_treated_as_promoted_req(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("### DRAFT-REQ-001", spec)
        code, output = self._validation_preflight()
        self.assertEqual(code, 0)
        self.assertNotIn("BLOCKED_PROMOTED_REQUIREMENT_IDENTIFIER", output)

    def test_refuses_candidate_with_wrong_status(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                f"**status:** `{DRAFT_REQUIREMENT_CANDIDATE_STATUS}`",
                "**status:** `APPROVED_REQUIREMENT`",
                1,
            ),
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CANDIDATE_NOT_DRAFT_NON_AUTHORITY", output)

    def test_refuses_inferred_unsourced_slither_detail_in_candidate(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                "- **candidate_text:** Draft candidate derived from source",
                "- **candidate_text:** Draft candidate derived from source with websocket support",
                1,
            ),
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_DRAFT_HAS_INFERRED_UNSOURCED_DETAILS", output)

    def test_refuses_candidate_missing_source_bounded(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                f"**source_bounded:** `{DRAFT_REQUIREMENT_SOURCE_BOUNDED_MARKER}`",
                "**source_bounded:** `NOT_BOUNDED`",
                1,
            ),
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CANDIDATE_NOT_SOURCE_BOUNDED", output)

    def test_refuses_candidate_missing_not_validated(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                "**validation_status:** `NOT_VALIDATED`",
                "**validation_status:** `VALIDATED`",
                1,
            ),
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CANDIDATE_NOT_VALIDATED", output)

    def test_refuses_candidate_missing_not_approved(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                "**approval_status:** `NOT_APPROVED`",
                "**approval_status:** `APPROVED`",
                1,
            ),
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CANDIDATE_NOT_APPROVED", output)

    def test_refuses_candidate_architecture_status_not_undecided(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                "**architecture_status:** `NOT_DECIDED`",
                "**architecture_status:** `DECIDED`",
                1,
            ),
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CANDIDATE_ARCHITECTURE_STATUS_NOT_UNDECIDED", output)

    def test_refuses_candidate_implementation_status_not_unplanned(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                "**implementation_status:** `NOT_PLANNED`",
                "**implementation_status:** `PLANNED`",
                1,
            ),
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CANDIDATE_IMPLEMENTATION_STATUS_NOT_UNPLANNED", output)

    def test_refuses_provenance_candidate_count_mismatch(self) -> None:
        self._setup_ready_for_preflight()
        provenance = json.loads(self._requirements_draft_provenance_path().read_text())
        provenance["requirement_candidate_count"] = provenance["requirement_candidate_count"] + 1
        self._requirements_draft_provenance_path().write_text(
            json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_PROVENANCE_CANDIDATE_COUNT_MISMATCH", output)

    def test_refuses_provenance_candidate_id_mismatch(self) -> None:
        self._setup_ready_for_preflight()
        provenance = json.loads(self._requirements_draft_provenance_path().read_text())
        provenance["requirement_candidate_ids"] = ["DRAFT-REQ-999"]
        self._requirements_draft_provenance_path().write_text(
            json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_PROVENANCE_CANDIDATE_ID_MISMATCH", output)

    def test_refuses_wrong_intake_id_in_provenance(self) -> None:
        self._setup_ready_for_preflight()
        provenance = json.loads(self._requirements_draft_provenance_path().read_text())
        provenance["intake_id"] = "wrong-intake"
        self._requirements_draft_provenance_path().write_text(
            json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_PROVENANCE_INTAKE_ID_MISMATCH", output)

    def test_refuses_wrong_plan_id_in_provenance(self) -> None:
        self._setup_ready_for_preflight()
        provenance = json.loads(self._requirements_draft_provenance_path().read_text())
        provenance["plan_id"] = "wrong-plan"
        self._requirements_draft_provenance_path().write_text(
            json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_PROVENANCE_PLAN_ID_MISMATCH", output)

    def test_refuses_malformed_provenance_json(self) -> None:
        self._setup_ready_for_preflight()
        self._requirements_draft_provenance_path().write_text("{bad", encoding="utf-8")
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MALFORMED_REQUIREMENTS_DRAFT_PROVENANCE", output)

    def test_refuses_later_blocking_requirements_extraction_decision(self) -> None:
        self._setup_ready_for_preflight()
        self._write_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-ext-block-v2",
            self._valid_decision_artifact(
                decision_id="req-ext-block-v2",
                decision="BLOCK_REQUIREMENTS_EXTRACTION",
                summary="Blocked after draft.",
                created_at="2099-01-01T00:00:00+00:00",
            ),
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_BLOCKS_EXTRACTION", output)

    def test_refuses_later_request_more_context_decision(self) -> None:
        self._setup_ready_for_preflight()
        self._write_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-ext-context-v2",
            self._valid_decision_artifact(
                decision_id="req-ext-context-v2",
                decision="REQUEST_MORE_CONTEXT",
                summary="Need more context after draft.",
                created_at="2099-01-01T00:00:00+00:00",
            ),
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn(
            "BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_REQUESTS_MORE_CONTEXT",
            output,
        )

    def test_refuses_forbidden_user_story_content(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8") + "\nAs a user I want login.\n",
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_DRAFT_HAS_USER_STORIES", output)

    def test_refuses_forbidden_acceptance_criteria_content(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8") + "\nGiven a user When login Then success.\n",
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_DRAFT_HAS_ACCEPTANCE_CRITERIA", output)

    def test_refuses_forbidden_architecture_content(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8") + "\nSelected backend: Node.js\n",
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_DRAFT_HAS_ARCHITECTURE", output)

    def test_refuses_forbidden_implementation_plan_content(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8") + "\n## Implementation Tasks\n\n- Task one\n",
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_DRAFT_HAS_IMPLEMENTATION_PLAN", output)

    def test_refuses_forbidden_planning_run_slice_content(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8") + '\n"artifact_type": "PLANNING_RUN_SLICE"\n',
            encoding="utf-8",
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_DRAFT_HAS_PLANNING_RUN_SLICE", output)

    def test_allows_planning_run_slice_not_generated_boundary(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("## PLANNING_RUN_SLICE", spec)
        self.assertIn("NOT_GENERATED", spec)
        code, output = self._validation_preflight()
        self.assertEqual(code, 0)
        self.assertNotIn("BLOCKED_REQUIREMENTS_DRAFT_HAS_PLANNING_RUN_SLICE", output)

    def test_creates_no_preflight_artifact(self) -> None:
        self._setup_ready_for_preflight()
        before = self._project_files()
        self._validation_preflight()
        after = self._project_files()
        self.assertEqual(before, after)
        workspace_evidence = self._workspace() / "evidence"
        for forbidden_name in (
            "orchestrator-requirements-draft-validation-preflight.json",
            "orchestrator-requirements-draft-validation-preflight.md",
        ):
            self.assertFalse((workspace_evidence / forbidden_name).exists(), forbidden_name)

    def test_refuses_stale_provenance_owner_decision_after_newer_authorize(self) -> None:
        self._setup_ready_for_preflight()
        self._write_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-ext-owner-v2",
            self._valid_decision_artifact(
                decision_id="req-ext-owner-v2",
                decision="AUTHORIZE_REQUIREMENTS_EXTRACTION",
                summary="Newer authorize after draft provenance.",
                created_at="2099-01-01T00:00:00+00:00",
            ),
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_DRAFT_DECISION_CHAIN_INCOHERENT", output)

    def test_refuses_malformed_requirements_extraction_owner_decision_artifact(self) -> None:
        self._setup_ready_for_preflight()
        path = self._requirements_extraction_decision_path(
            "slither-demo", "slither-plan-v1", "req-ext-owner-v1"
        )
        path.write_text("{bad", encoding="utf-8")
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MALFORMED_REQUIREMENTS_EXTRACTION_OWNER_DECISION", output)

    def test_latest_decision_ordering_deterministic_by_created_at_then_decision_id(
        self,
    ) -> None:
        self._setup_ready_for_preflight()
        tie_time = "2099-01-01T00:00:00+00:00"
        self._write_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-ext-aaa",
            self._valid_decision_artifact(
                decision_id="req-ext-aaa",
                decision="BLOCK_REQUIREMENTS_EXTRACTION",
                summary="Same timestamp, earlier id.",
                created_at=tie_time,
            ),
        )
        self._write_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-ext-bbb",
            self._valid_decision_artifact(
                decision_id="req-ext-bbb",
                decision="REQUEST_MORE_CONTEXT",
                summary="Same timestamp, later id wins.",
                created_at=tie_time,
            ),
        )
        code, output = self._validation_preflight()
        self.assertEqual(code, 1)
        self.assertIn(
            "BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_REQUESTS_MORE_CONTEXT",
            output,
        )

    def test_does_not_invoke_subprocess_runner_or_executor(self) -> None:
        self._setup_ready_for_preflight()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code, _ = self._validation_preflight()
        self.assertEqual(code, 0)

    def test_report_contains_all_non_authority_flags_true(self) -> None:
        self._setup_ready_for_preflight()
        report = requirements_draft_validation_preflight(
            self.project, "slither-demo", "slither-plan-v1"
        )
        for flag in REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, report.non_authority)
            self.assertTrue(report.non_authority[flag])

    def test_cli_help_states_validation_preflight_boundaries(self) -> None:
        parser = build_parser()
        orchestrator_parser = next(
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction) and "orchestrator" in action.choices
        )
        orchestrator_sub = next(
            action for action in orchestrator_parser.choices["orchestrator"]._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        help_text = orchestrator_sub.choices[
            "requirements-draft-validation-preflight"
        ].format_help()
        compact = re.sub(r"\s+", " ", help_text)
        for phrase in (
            "read-only",
            "validate",
            "approve",
            "user stories",
            "acceptance criteria",
            "architecture",
            "implementation plan",
            "executor",
        ):
            self.assertIn(phrase, compact.lower())


class OrchestratorRequirementsValidationOwnerDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _clarification_path(self, intake_id: str, clarification_id: str) -> Path:
        return orchestrator_clarification_path(self.project, intake_id, clarification_id)

    def _readiness_decision_path(self, intake_id: str, decision_id: str) -> Path:
        return orchestrator_readiness_decision_path(self.project, intake_id, decision_id)

    def _requirements_extraction_decision_path(
        self, intake_id: str, plan_id: str, decision_id: str
    ) -> Path:
        return orchestrator_requirements_extraction_decision_path(
            self.project, intake_id, plan_id, decision_id
        )

    def _requirements_validation_decision_path(
        self, intake_id: str, plan_id: str, decision_id: str
    ) -> Path:
        return orchestrator_requirements_validation_decision_path(
            self.project, intake_id, plan_id, decision_id
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project, intake_id, "Build me an online slither.io-like game"
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project, intake_id, "scope-v1", "Browser-only demo with 10 players max."
        )
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _run(self, argv: list[str]) -> tuple[int, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(argv)
        return code, out_buf.getvalue() + err_buf.getvalue()

    def _prepare(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "prepare-planning-draft", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _transport(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "transport-planning-context", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _draft_context_pack(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "draft-context-pack", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _local_spec_preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "local-agentic-spec-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold_local_spec(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-local-agentic-spec", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "requirements-extraction-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-requirements-extraction", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _decide_extraction(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_EXTRACTION",
        decision_id: str = "req-ext-owner-v1",
        summary: str = "Authorize future extraction only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-extraction",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _execution_check(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-extraction-execution-check",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "extract-requirements-draft",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _decide(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_VALIDATION",
        decision_id: str = "req-val-owner-v1",
        summary: str = "Authorize future validation only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-validation",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-context-pack-draft-provenance.json"

    def _scaffold_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-local-agentic-spec-scaffold-provenance.json"

    def _requirements_scaffold_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-requirements-extraction-scaffold-provenance.json"
        )

    def _requirements_draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-requirements-draft-provenance.json"

    def _transport_json_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-context-transport.json"

    def _transport_md_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-context-transport.md"

    def _provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-provenance.json"

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._local_spec_preflight(intake_id, plan_id)[0], 0)
        self.assertEqual(self._scaffold_local_spec(intake_id, plan_id)[0], 0)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

    def _setup_ready_for_decision(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self.assertEqual(self._scaffold(intake_id, plan_id)[0], 0)

    def _setup_ready_for_execution_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_decision(intake_id, plan_id)
        self.assertEqual(self._decide_extraction(intake_id, plan_id)[0], 0)

    def _setup_ready_for_extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_execution_check(intake_id, plan_id)
        self.assertEqual(self._execution_check(intake_id, plan_id)[0], 0)

    def _setup_ready_for_preflight(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_extract(intake_id, plan_id)
        self.assertEqual(self._extract(intake_id, plan_id)[0], 0)

    def _record_decision(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision_id: str = "req-val-owner-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_VALIDATION",
        summary: str = "Authorize future validation only.",
    ):
        return create_requirements_validation_owner_decision(
            self.project,
            intake_id,
            plan_id,
            decision_id,
            decision,
            summary,
        )

    def _tracked_artifact_paths(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> dict[Path, bytes]:
        workspace = self._workspace(plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._clarification_path(intake_id, "scope-v1"),
            self._readiness_decision_path(intake_id, "owner-v1"),
            self._provenance_path(plan_id),
            workspace / "evidence" / "orchestrator-draft-scaffold-notes.md",
            self._transport_json_path(plan_id),
            self._transport_md_path(plan_id),
            self._draft_provenance_path(plan_id),
            self._scaffold_provenance_path(plan_id),
            self._requirements_scaffold_provenance_path(plan_id),
            self._requirements_draft_provenance_path(plan_id),
            self._context_pack_path(plan_id),
            self._local_spec_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
            self._requirements_extraction_decision_path(intake_id, plan_id, "req-ext-owner-v1"),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def test_records_request_revision_decision_append_only_no_validation(self) -> None:
        self._setup_ready_for_preflight()
        before = self._tracked_artifact_paths()
        report = self._record_decision(
            decision="REQUEST_REQUIREMENTS_DRAFT_REVISION",
            summary="Draft needs more source context.",
        )
        self.assertEqual(report.status, REQUIREMENTS_VALIDATION_OWNER_DECISION_RECORDED_STATE)
        self.assertEqual(report.next_required_action, REQUIREMENTS_VALIDATION_REQUEST_NEXT_ACTION)
        artifact = load_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        self.assertEqual(artifact["decision"], "REQUEST_REQUIREMENTS_DRAFT_REVISION")
        self.assertEqual(artifact["status"], REQUIREMENTS_VALIDATION_OWNER_DECISION_RECORDED_STATE)
        self.assertTrue(artifact["non_authority"]["does_not_validate_requirements"])
        for path, content in before.items():
            self.assertEqual(content, path.read_bytes(), str(path))

    def test_records_block_decision_append_only_no_validation(self) -> None:
        self._setup_ready_for_preflight()
        report = self._record_decision(
            decision_id="req-val-block-v1",
            decision="BLOCK_REQUIREMENTS_VALIDATION",
            summary="Block validation for now.",
        )
        self.assertEqual(report.decision, "BLOCK_REQUIREMENTS_VALIDATION")
        self.assertEqual(report.next_required_action, REQUIREMENTS_VALIDATION_BLOCK_NEXT_ACTION)
        artifact = load_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-block-v1"
        )
        self.assertEqual(
            artifact["source_requirements_draft_validation_preflight_state"],
            REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_STATE,
        )
        self.assertEqual(
            artifact["source_requirements_draft_validation_preflight_next_action"],
            REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_NEXT_ACTION,
        )
        self.assertTrue(artifact["non_authority"]["owner_decision_is_not_validation"])

    def test_records_request_revision_preflight_snapshot_does_not_authorize_validation(
        self,
    ) -> None:
        self._setup_ready_for_preflight()
        self._record_decision(
            decision="REQUEST_REQUIREMENTS_DRAFT_REVISION",
            summary="Draft needs more source context.",
        )
        artifact = load_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        self.assertEqual(
            artifact["source_requirements_draft_validation_preflight_state"],
            REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_STATE,
        )
        self.assertEqual(
            artifact["source_requirements_draft_validation_preflight_next_action"],
            REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_NEXT_ACTION,
        )
        self.assertTrue(
            artifact["non_authority"][
                "authorizes_future_validation_only_when_decision_is_authorize"
            ]
        )

    def test_records_authorize_only_when_preflight_passes(self) -> None:
        self._setup_ready_for_preflight()
        report = self._record_decision()
        self.assertEqual(report.decision, "AUTHORIZE_REQUIREMENTS_VALIDATION")
        self.assertEqual(report.next_required_action, REQUIREMENTS_VALIDATION_AUTHORIZE_NEXT_ACTION)
        artifact = load_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        self.assertEqual(
            artifact["source_requirements_draft_validation_preflight_state"],
            REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_STATE,
        )
        self.assertEqual(
            artifact["source_requirements_draft_validation_preflight_next_action"],
            REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_NEXT_ACTION,
        )
        self.assertTrue(
            artifact["non_authority"][
                "authorizes_future_validation_only_when_decision_is_authorize"
            ]
        )

    def test_authorize_fails_closed_when_preflight_would_fail(self) -> None:
        self._setup_ready_for_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                REQUIREMENTS_DRAFT_STATUS, "REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY"
            ),
            encoding="utf-8",
        )
        with self.assertRaises(ValueError) as ctx:
            self._record_decision()
        self.assertIn("requirements draft validation preflight not confirmed", str(ctx.exception))
        self.assertFalse(
            self._requirements_validation_decision_path(
                "slither-demo", "slither-plan-v1", "req-val-owner-v1"
            ).exists()
        )

    def test_decision_artifact_path_is_plan_scoped(self) -> None:
        self._setup_ready_for_preflight()
        report = self._record_decision(decision_id="req-val-plan-v1")
        expected = self._requirements_validation_decision_path(
            "slither-demo", "slither-plan-v1", "req-val-plan-v1"
        )
        self.assertEqual(report.decision_path, expected)
        self.assertIn(REQUIREMENTS_VALIDATION_DECISIONS_DIR, expected.as_posix())
        self.assertIn("slither-plan-v1", expected.as_posix())

    def test_duplicate_decision_id_fails_closed_without_overwrite(self) -> None:
        self._setup_ready_for_preflight()
        self._record_decision(decision_id="req-val-dup-v1", decision="BLOCK_REQUIREMENTS_VALIDATION")
        existing = self._requirements_validation_decision_path(
            "slither-demo", "slither-plan-v1", "req-val-dup-v1"
        ).read_text(encoding="utf-8")
        with self.assertRaises(FileExistsError):
            create_requirements_validation_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-val-dup-v1",
                "REQUEST_REQUIREMENTS_DRAFT_REVISION",
                "Second decision.",
            )
        self.assertEqual(
            existing,
            self._requirements_validation_decision_path(
                "slither-demo", "slither-plan-v1", "req-val-dup-v1"
            ).read_text(encoding="utf-8"),
        )

    def test_refuses_invalid_decision_value(self) -> None:
        self._setup_ready_for_preflight()
        with self.assertRaises(ValueError) as ctx:
            create_requirements_validation_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-val-owner-v1",
                "APPROVE_REQUIREMENTS",
                "Not allowed.",
            )
        self.assertIn("unsupported decision value", str(ctx.exception))

    def test_refuses_invalid_decision_id_and_path_traversal(self) -> None:
        self._setup_ready_for_preflight()
        for decision_id in ("", " ", "../escape", "bad id", ".hidden"):
            with self.subTest(decision_id=decision_id):
                with self.assertRaises(ValueError):
                    create_requirements_validation_owner_decision(
                        self.project,
                        "slither-demo",
                        "slither-plan-v1",
                        decision_id,
                        "BLOCK_REQUIREMENTS_VALIDATION",
                        "Stop.",
                    )

    def test_refuses_empty_summary(self) -> None:
        self._setup_ready_for_preflight()
        with self.assertRaises(ValueError) as ctx:
            create_requirements_validation_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-val-owner-v1",
                "BLOCK_REQUIREMENTS_VALIDATION",
                "",
            )
        self.assertIn("owner summary must not be empty", str(ctx.exception))
        code, output = self._decide(summary="")
        self.assertEqual(code, 1)
        self.assertIn("owner summary must not be empty", output)

    def test_refuses_wrong_intake_plan_binding(self) -> None:
        self._setup_ready_for_preflight("slither-demo", "slither-plan-v1")
        self._create_slither_intake("other-intake")
        with self.assertRaises(ValueError) as ctx:
            create_requirements_validation_owner_decision(
                self.project,
                "other-intake",
                "slither-plan-v1",
                "req-val-owner-v1",
                "BLOCK_REQUIREMENTS_VALIDATION",
                "Wrong intake for this plan.",
            )
        self.assertIn("intake_id mismatch", str(ctx.exception))

    def test_does_not_modify_local_agentic_spec_md(self) -> None:
        self._setup_ready_for_preflight()
        before = self._local_spec_path().read_bytes()
        self._record_decision()
        self.assertEqual(before, self._local_spec_path().read_bytes())

    def test_does_not_create_validation_report(self) -> None:
        self._setup_ready_for_preflight()
        before = self._project_files()
        self._record_decision()
        after = self._project_files()
        new_files = after - before
        self.assertTrue(all("validation-report" not in path for path in new_files))
        self.assertTrue(all("requirements-validation-decisions" in path for path in new_files))

    def test_does_not_promote_draft_req_to_req(self) -> None:
        self._setup_ready_for_preflight()
        spec_text = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("DRAFT-REQ-", spec_text)
        self.assertNotRegex(spec_text, r"(?<![A-Z-])REQ-\d+")
        self._record_decision()
        after = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("DRAFT-REQ-", after)
        self.assertNotRegex(after, r"(?<![A-Z-])REQ-\d+")

    def test_does_not_create_architecture_implementation_plan_or_planning_run_slice(self) -> None:
        self._setup_ready_for_preflight()
        before = self._project_files()
        self._record_decision()
        after = self._project_files()
        new_files = after - before
        forbidden = (
            "architecture",
            "implementation-plan",
            "planning-run-slice",
            "PLANNING_RUN_SLICE",
        )
        for path in new_files:
            lowered = path.lower()
            self.assertFalse(any(token.lower() in lowered for token in forbidden if token != "implementation-plan"))
        self.assertEqual(
            self._implementation_plan_path().read_bytes(),
            (self._workspace() / "implementation-plan.md").read_bytes(),
        )

    def test_does_not_invoke_subprocess_runner_or_executor(self) -> None:
        self._setup_ready_for_preflight()
        with (
            patch("subprocess.run", side_effect=AssertionError("subprocess invoked")),
            patch.object(
                planning_module,
                "progress_planning_workspace",
                side_effect=AssertionError("progress invoked"),
            ),
            patch.object(
                planning_module,
                "transition_planning_workspace",
                side_effect=AssertionError("transition invoked"),
            ),
            patch.object(
                planning_module,
                "record_planning_owner_decision",
                side_effect=AssertionError("decide invoked"),
            ),
        ):
            code = self._decide()[0]
        self.assertEqual(code, 0)

    def test_latest_decision_ordering_deterministic_by_created_at_then_decision_id(
        self,
    ) -> None:
        from agent_os import orchestrator as orchestrator_module

        self._setup_ready_for_preflight()
        times = iter(
            [
                "2026-07-06T10:00:00+00:00",
                "2026-07-06T10:00:00+00:00",
                "2026-07-06T11:00:00+00:00",
            ]
        )
        with patch.object(orchestrator_module, "_utc_now", side_effect=lambda: next(times)):
            create_requirements_validation_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-val-bbb",
                "REQUEST_REQUIREMENTS_DRAFT_REVISION",
                "Earlier tie-breaker id.",
            )
            create_requirements_validation_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-val-aaa",
                "BLOCK_REQUIREMENTS_VALIDATION",
                "Same timestamp, earlier id.",
            )
            create_requirements_validation_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-val-zzz",
                "BLOCK_REQUIREMENTS_VALIDATION",
                "Latest timestamp.",
            )

        decisions = list_requirements_validation_owner_decisions(
            self.project, "slither-demo", "slither-plan-v1"
        )
        self.assertEqual(
            [record.decision_id for record in decisions],
            ["req-val-aaa", "req-val-bbb", "req-val-zzz"],
        )

    def test_cli_happy_path_authorize_requirements_validation(self) -> None:
        self._setup_ready_for_preflight()
        code, output = self._decide()
        self.assertEqual(code, 0)
        self.assertIn("created requirements validation owner decision artifact:", output)
        self.assertIn(REQUIREMENTS_VALIDATION_OWNER_DECISION_RECORDED_STATE, output)
        self.assertIn(REQUIREMENTS_VALIDATION_AUTHORIZE_NEXT_ACTION, output)
        self.assertIn("authorization is not validation", output.lower())

    def test_cli_failure_path_invalid_decision(self) -> None:
        self._setup_ready_for_preflight()
        with self.assertRaises(SystemExit) as ctx:
            self._decide(decision="APPROVE_REQUIREMENTS")
        self.assertEqual(ctx.exception.code, 2)

    def test_cli_help_states_owner_decision_is_not_validation_or_approval(self) -> None:
        parser = build_parser()
        orchestrator_parser = next(
            action for action in parser._actions
            if isinstance(action, argparse._SubParsersAction) and "orchestrator" in action.choices
        )
        orchestrator_sub = next(
            action for action in orchestrator_parser.choices["orchestrator"]._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        help_text = orchestrator_sub.choices["decide-requirements-validation"].format_help()
        compact = re.sub(r"\s+", " ", help_text)
        self.assertIn("owner-provided", compact.lower())
        self.assertIn("validate", compact.lower())
        self.assertIn("approve requirements", compact.lower())
        self.assertIn("promote draft", compact.lower())
        self.assertIn("validation report", compact.lower())
        self.assertIn("executor", compact.lower())

    def test_decision_artifact_contains_required_non_authority_flags(self) -> None:
        self._setup_ready_for_preflight()
        self._record_decision()
        artifact = load_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        for flag in REQUIREMENTS_VALIDATION_OWNER_DECISION_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, artifact["non_authority"])
            self.assertTrue(artifact["non_authority"][flag])

    def test_validate_requirements_validation_owner_decision_helper(self) -> None:
        self._setup_ready_for_preflight()
        self._record_decision()
        report = validate_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        self.assertTrue(report.valid)
        self.assertEqual(report.errors, ())

    def test_refuses_invalid_intake(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_preflight(intake_id, plan_id)
        artifact_path = self._artifact_path(intake_id)
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        artifact_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        with self.assertRaises(ValueError):
            create_requirements_validation_owner_decision(
                self.project,
                intake_id,
                plan_id,
                "req-val-owner-v1",
                "BLOCK_REQUIREMENTS_VALIDATION",
                "Stop.",
            )
        self.assertFalse(
            self._requirements_validation_decision_path(
                intake_id, plan_id, "req-val-owner-v1"
            ).exists()
        )

    def test_refuses_invalid_plan_id(self) -> None:
        self._setup_ready_for_preflight()
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "decide-requirements-validation",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "../escape",
                    "--decision",
                    "BLOCK_REQUIREMENTS_VALIDATION",
                    "--decision-id",
                    "req-val-owner-v1",
                    "--summary",
                    "Stop.",
                ]
            )
        self.assertEqual(code, 1)

    def test_load_validated_requirements_validation_owner_decisions_loads_valid_artifacts(
        self,
    ) -> None:
        from agent_os import orchestrator as orchestrator_module

        self._setup_ready_for_preflight()
        times = iter(
            [
                "2026-07-06T10:00:00+00:00",
                "2026-07-06T11:00:00+00:00",
            ]
        )
        with patch.object(orchestrator_module, "_utc_now", side_effect=lambda: next(times)):
            create_requirements_validation_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-val-aaa",
                "BLOCK_REQUIREMENTS_VALIDATION",
                "First block.",
            )
            create_requirements_validation_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-val-bbb",
                "REQUEST_REQUIREMENTS_DRAFT_REVISION",
                "Request revision.",
            )

        records, errors = orchestrator_module._load_validated_requirements_validation_owner_decisions(
            self.project, "slither-demo", "slither-plan-v1"
        )
        self.assertEqual(errors, [])
        self.assertEqual(
            [record.decision_id for record in records],
            ["req-val-aaa", "req-val-bbb"],
        )
        self.assertEqual(records[0].decision, "BLOCK_REQUIREMENTS_VALIDATION")
        self.assertEqual(records[1].decision, "REQUEST_REQUIREMENTS_DRAFT_REVISION")

    def test_load_validated_requirements_validation_owner_decisions_reports_malformed_artifacts(
        self,
    ) -> None:
        self._setup_ready_for_preflight()
        self._record_decision(
            decision_id="req-val-good",
            decision="BLOCK_REQUIREMENTS_VALIDATION",
            summary="Valid decision.",
        )
        bad_path = self._requirements_validation_decision_path(
            "slither-demo", "slither-plan-v1", "req-val-bad"
        )
        bad_path.write_text("{", encoding="utf-8")

        from agent_os import orchestrator as orchestrator_module

        records, errors = orchestrator_module._load_validated_requirements_validation_owner_decisions(
            self.project, "slither-demo", "slither-plan-v1"
        )
        self.assertEqual([record.decision_id for record in records], ["req-val-good"])
        self.assertTrue(any("malformed decision artifact req-val-bad" in error for error in errors))

    def test_load_validated_requirements_validation_owner_decisions_rejects_wrong_scope(
        self,
    ) -> None:
        self._setup_ready_for_preflight()
        self._record_decision(
            decision_id="req-val-scope",
            decision="BLOCK_REQUIREMENTS_VALIDATION",
            summary="Scoped decision.",
        )
        path = self._requirements_validation_decision_path(
            "slither-demo", "slither-plan-v1", "req-val-scope"
        )
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact["plan_id"] = "other-plan"
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        from agent_os import orchestrator as orchestrator_module

        records, errors = orchestrator_module._load_validated_requirements_validation_owner_decisions(
            self.project, "slither-demo", "slither-plan-v1"
        )
        self.assertEqual(records, ())
        self.assertTrue(
            any(
                "decision artifact req-val-scope: plan_id mismatch" in error
                for error in errors
            )
        )

    def test_load_validated_requirements_validation_owner_decisions_rejects_wrong_artifact_type(
        self,
    ) -> None:
        self._setup_ready_for_preflight()
        self._record_decision(
            decision_id="req-val-type",
            decision="BLOCK_REQUIREMENTS_VALIDATION",
            summary="Type check.",
        )
        path = self._requirements_validation_decision_path(
            "slither-demo", "slither-plan-v1", "req-val-type"
        )
        artifact = json.loads(path.read_text(encoding="utf-8"))
        artifact["artifact_type"] = "OWNER_READINESS_DECISION"
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

        from agent_os import orchestrator as orchestrator_module

        records, errors = orchestrator_module._load_validated_requirements_validation_owner_decisions(
            self.project, "slither-demo", "slither-plan-v1"
        )
        self.assertEqual(records, ())
        self.assertTrue(
            any(
                "decision artifact req-val-type: wrong artifact_type" in error
                for error in errors
            )
        )


class OrchestratorRequirementsValidationExecutionCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _requirements_validation_decision_path(
        self, intake_id: str, plan_id: str, decision_id: str
    ) -> Path:
        return orchestrator_requirements_validation_decision_path(
            self.project, intake_id, plan_id, decision_id
        )

    def _requirements_extraction_decision_path(
        self, intake_id: str, plan_id: str, decision_id: str
    ) -> Path:
        return orchestrator_requirements_extraction_decision_path(
            self.project, intake_id, plan_id, decision_id
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project, intake_id, "Build me an online slither.io-like game"
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project, intake_id, "scope-v1", "Browser-only demo with 10 players max."
        )
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _run(self, argv: list[str]) -> tuple[int, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(argv)
        return code, out_buf.getvalue() + err_buf.getvalue()

    def _prepare(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "prepare-planning-draft", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _transport(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "transport-planning-context", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _draft_context_pack(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "draft-context-pack", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _local_spec_preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "local-agentic-spec-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold_local_spec(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-local-agentic-spec", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "requirements-extraction-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-requirements-extraction", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _decide_extraction(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_EXTRACTION",
        decision_id: str = "req-ext-owner-v1",
        summary: str = "Authorize future extraction only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-extraction",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _extraction_execution_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-extraction-execution-check",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "extract-requirements-draft",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _decide(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_VALIDATION",
        decision_id: str = "req-val-owner-v1",
        summary: str = "Authorize future validation only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-validation",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _execution_check(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-validation-execution-check",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _requirements_draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-requirements-draft-provenance.json"

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._local_spec_preflight(intake_id, plan_id)[0], 0)
        self.assertEqual(self._scaffold_local_spec(intake_id, plan_id)[0], 0)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

    def _setup_ready_for_decision(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self.assertEqual(self._scaffold(intake_id, plan_id)[0], 0)

    def _setup_ready_for_extraction_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_decision(intake_id, plan_id)
        self.assertEqual(self._decide_extraction(intake_id, plan_id)[0], 0)

    def _setup_ready_for_extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_extraction_check(intake_id, plan_id)
        self.assertEqual(self._extraction_execution_check(intake_id, plan_id)[0], 0)
        self.assertEqual(self._extract(intake_id, plan_id)[0], 0)

    def _setup_ready_for_execution_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_extract(intake_id, plan_id)
        self.assertEqual(self._decide(intake_id, plan_id)[0], 0)

    def _tracked_artifact_paths(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> dict[Path, bytes]:
        workspace = self._workspace(plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._requirements_draft_provenance_path(plan_id),
            self._local_spec_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
            self._requirements_extraction_decision_path(intake_id, plan_id, "req-ext-owner-v1"),
            self._requirements_validation_decision_path(intake_id, plan_id, "req-val-owner-v1"),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def _write_validation_decision_artifact(
        self, intake_id: str, plan_id: str, decision_id: str, artifact: dict
    ) -> Path:
        path = self._requirements_validation_decision_path(intake_id, plan_id, decision_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        return path

    def _valid_validation_decision_artifact(
        self,
        *,
        decision_id: str = "req-val-owner-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_VALIDATION",
        created_at: str = "2026-07-06T10:00:00+00:00",
        preflight_state: str = REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_STATE,
        preflight_next_action: str = REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_NEXT_ACTION,
    ) -> dict:
        plan_id = "slither-plan-v1"
        draft_provenance = str(self._requirements_draft_provenance_path(plan_id))
        draft_created_at = "2026-07-06T10:00:00+00:00"
        if self._requirements_draft_provenance_path(plan_id).is_file():
            provenance = json.loads(
                self._requirements_draft_provenance_path(plan_id).read_text(encoding="utf-8")
            )
            if isinstance(provenance, dict) and isinstance(provenance.get("created_at"), str):
                draft_created_at = provenance["created_at"]
        return build_requirements_validation_owner_decision_artifact(
            "slither-demo",
            plan_id,
            decision_id,
            decision,
            "Owner decision summary.",
            source_requirements_draft_validation_preflight_state=preflight_state,
            source_requirements_draft_validation_preflight_next_action=preflight_next_action,
            source_requirements_draft_provenance_path=draft_provenance,
            source_requirements_draft_status=REQUIREMENTS_DRAFT_STATUS,
            source_requirements_draft_created_at=draft_created_at,
            planning_workspace_status_at_decision="DRAFT",
            created_at=created_at,
        )

    def test_successful_execution_check_after_authorize(self) -> None:
        self._setup_ready_for_execution_check()
        report = requirements_validation_execution_check(
            self.project, "slither-demo", "slither-plan-v1"
        )
        self.assertEqual(report.execution_check_state, REQUIREMENTS_VALIDATION_EXECUTION_CHECK_CONFIRMED_STATE)
        self.assertEqual(
            report.next_required_action,
            REQUIREMENTS_VALIDATION_EXECUTION_CHECK_CONFIRMED_NEXT_ACTION,
        )
        self.assertEqual(report.latest_requirements_validation_owner_decision, "AUTHORIZE_REQUIREMENTS_VALIDATION")

    def test_read_only_preserves_files_byte_for_byte(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._tracked_artifact_paths()
        self._execution_check()
        after = self._tracked_artifact_paths()
        self.assertEqual(before, after)

    def test_does_not_create_execution_check_artifact(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._project_files()
        self._execution_check()
        after = self._project_files()
        new_files = after - before
        self.assertEqual(new_files, set())

    def test_fails_closed_when_no_owner_decision(self) -> None:
        self._setup_ready_for_extract()
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_NO_REQUIREMENTS_VALIDATION_OWNER_DECISION", output)

    def test_fails_closed_when_latest_is_request_revision(self) -> None:
        self._setup_ready_for_extract()
        self._decide(decision="REQUEST_REQUIREMENTS_DRAFT_REVISION", summary="Revise draft.")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_REQUIREMENTS_VALIDATION_DECISION_REQUESTS_REVISION", output)

    def test_fails_closed_when_latest_is_block(self) -> None:
        self._setup_ready_for_extract()
        self._decide(decision="BLOCK_REQUIREMENTS_VALIDATION", summary="Block validation.")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_REQUIREMENTS_VALIDATION_DECISION_BLOCKS_VALIDATION", output)

    def test_fails_closed_when_later_request_supersedes_authorize(self) -> None:
        self._setup_ready_for_extract()
        self._write_validation_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-val-auth",
            self._valid_validation_decision_artifact(
                decision_id="req-val-auth",
                created_at="2026-07-06T10:00:00+00:00",
            ),
        )
        self._write_validation_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-val-req",
            self._valid_validation_decision_artifact(
                decision_id="req-val-req",
                decision="REQUEST_REQUIREMENTS_DRAFT_REVISION",
                created_at="2026-07-06T11:00:00+00:00",
                preflight_state=REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_STATE,
                preflight_next_action=REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_NEXT_ACTION,
            ),
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_REQUIREMENTS_VALIDATION_DECISION_REQUESTS_REVISION", output)

    def test_fails_closed_when_later_block_supersedes_authorize(self) -> None:
        self._setup_ready_for_extract()
        self._write_validation_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-val-auth",
            self._valid_validation_decision_artifact(
                decision_id="req-val-auth",
                created_at="2026-07-06T10:00:00+00:00",
            ),
        )
        self._write_validation_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-val-block",
            self._valid_validation_decision_artifact(
                decision_id="req-val-block",
                decision="BLOCK_REQUIREMENTS_VALIDATION",
                created_at="2026-07-06T11:00:00+00:00",
                preflight_state=REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_STATE,
                preflight_next_action=REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_NEXT_ACTION,
            ),
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_REQUIREMENTS_VALIDATION_DECISION_BLOCKS_VALIDATION", output)

    def test_deterministic_latest_ordering_by_created_at_then_decision_id(self) -> None:
        self._setup_ready_for_extract()
        self._write_validation_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-val-b",
            self._valid_validation_decision_artifact(
                decision_id="req-val-b",
                decision="REQUEST_REQUIREMENTS_DRAFT_REVISION",
                created_at="2026-07-06T10:00:00+00:00",
                preflight_state=REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_STATE,
                preflight_next_action=REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_NEXT_ACTION,
            ),
        )
        self._write_validation_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-val-a",
            self._valid_validation_decision_artifact(
                decision_id="req-val-a",
                decision="BLOCK_REQUIREMENTS_VALIDATION",
                created_at="2026-07-06T10:00:00+00:00",
                preflight_state=REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_STATE,
                preflight_next_action=REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_NEXT_ACTION,
            ),
        )
        self._write_validation_decision_artifact(
            "slither-demo",
            "slither-plan-v1",
            "req-val-c",
            self._valid_validation_decision_artifact(
                decision_id="req-val-c",
                created_at="2026-07-06T11:00:00+00:00",
            ),
        )
        code, output = self._execution_check()
        self.assertEqual(code, 0)
        self.assertIn("latest_requirements_validation_owner_decision_id: req-val-c", output)

    def test_fails_closed_on_malformed_owner_decision_artifact(self) -> None:
        self._setup_ready_for_extract()
        path = self._requirements_validation_decision_path(
            "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{bad", encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MALFORMED_REQUIREMENTS_VALIDATION_OWNER_DECISION", output)

    def test_fails_closed_on_wrong_intake_id_in_decision_artifact(self) -> None:
        self._setup_ready_for_execution_check()
        artifact = load_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        artifact["intake_id"] = "wrong-intake"
        self._write_validation_decision_artifact(
            "slither-demo", "slither-plan-v1", "req-val-owner-v1", artifact
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MALFORMED_REQUIREMENTS_VALIDATION_OWNER_DECISION", output)

    def test_fails_closed_on_wrong_plan_id_in_decision_artifact(self) -> None:
        self._setup_ready_for_execution_check()
        artifact = load_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        artifact["plan_id"] = "wrong-plan"
        self._write_validation_decision_artifact(
            "slither-demo", "slither-plan-v1", "req-val-owner-v1", artifact
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MALFORMED_REQUIREMENTS_VALIDATION_OWNER_DECISION", output)

    def test_fails_closed_on_wrong_artifact_type_in_decision_artifact(self) -> None:
        self._setup_ready_for_execution_check()
        artifact = load_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        artifact["artifact_type"] = "WRONG_TYPE"
        self._write_validation_decision_artifact(
            "slither-demo", "slither-plan-v1", "req-val-owner-v1", artifact
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MALFORMED_REQUIREMENTS_VALIDATION_OWNER_DECISION", output)

    def test_fails_closed_when_preflight_would_now_fail(self) -> None:
        self._setup_ready_for_execution_check()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                REQUIREMENTS_DRAFT_STATUS, "REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY"
            ),
            encoding="utf-8",
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_WRONG_LOCAL_AGENTIC_SPEC_STATUS", output)

    def test_fails_closed_when_local_agentic_spec_missing(self) -> None:
        self._setup_ready_for_execution_check()
        self._local_spec_path().unlink()
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_LOCAL_AGENTIC_SPEC", output)

    def test_fails_closed_when_requirements_draft_provenance_missing(self) -> None:
        self._setup_ready_for_execution_check()
        self._requirements_draft_provenance_path().unlink()
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MISSING_REQUIREMENTS_DRAFT_PROVENANCE", output)

    def test_fails_closed_when_requirements_draft_status_no_longer_draft(self) -> None:
        self._setup_ready_for_execution_check()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                REQUIREMENTS_DRAFT_STATUS, "APPROVED_REQUIREMENTS"
            ),
            encoding="utf-8",
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_WRONG_LOCAL_AGENTIC_SPEC_STATUS", output)

    def test_fails_closed_when_draft_req_markers_invalid(self) -> None:
        self._setup_ready_for_execution_check()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                DRAFT_REQUIREMENT_CANDIDATE_STATUS, "APPROVED_REQUIREMENT"
            ),
            encoding="utf-8",
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CANDIDATE_NOT_DRAFT_NON_AUTHORITY", output)

    def test_fails_closed_when_promoted_req_identifier_appears(self) -> None:
        self._setup_ready_for_execution_check()
        spec = self._local_spec_path()
        spec.write_text(spec.read_text(encoding="utf-8") + "\n### REQ-001\n", encoding="utf-8")
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_PROMOTED_REQUIREMENT_IDENTIFIER", output)

    def test_fails_closed_when_forbidden_downstream_content_appears(self) -> None:
        self._setup_ready_for_execution_check()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8") + "\n## User Stories\n\nAs a user I want to play.\n",
            encoding="utf-8",
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_DRAFT_HAS_USER_STORIES", output)

    def test_does_not_validate_requirements(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._local_spec_path().read_bytes()
        self._execution_check()
        self.assertEqual(before, self._local_spec_path().read_bytes())
        self.assertNotIn("VALIDATED_REQUIREMENTS", self._local_spec_path().read_text())

    def test_does_not_approve_requirements(self) -> None:
        self._setup_ready_for_execution_check()
        _, output = self._execution_check()
        self.assertIn("not requirements approval", output.lower())

    def test_does_not_promote_draft_req_to_req(self) -> None:
        self._setup_ready_for_execution_check()
        spec_text = self._local_spec_path().read_text(encoding="utf-8")
        self._execution_check()
        after = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("DRAFT-REQ-", after)
        self.assertNotRegex(after, r"(?<!DRAFT-)REQ-\d{3}\b")
        self.assertEqual(spec_text, after)

    def test_does_not_create_validation_report(self) -> None:
        self._setup_ready_for_execution_check()
        before = self._project_files()
        self._execution_check()
        after = self._project_files()
        new_files = after - before
        self.assertTrue(all("validation-report" not in path for path in new_files))

    def test_does_not_create_architecture_implementation_plan_or_slice(self) -> None:
        self._setup_ready_for_execution_check()
        before_impl = self._implementation_plan_path().read_bytes()
        before_audit = self._planning_audit_path().read_bytes()
        self._execution_check()
        self.assertEqual(before_impl, self._implementation_plan_path().read_bytes())
        self.assertEqual(before_audit, self._planning_audit_path().read_bytes())
        self.assertNotIn('{"artifact_type": "PLANNING_RUN_SLICE"}', self._local_spec_path().read_text())

    def test_does_not_invoke_subprocess_runner_or_executor(self) -> None:
        self._setup_ready_for_execution_check()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code, _ = self._execution_check()
        self.assertEqual(code, 0)

    def test_cli_success_path(self) -> None:
        self._setup_ready_for_execution_check()
        code, output = self._execution_check()
        self.assertEqual(code, 0)
        self.assertIn(REQUIREMENTS_VALIDATION_EXECUTION_CHECK_CONFIRMED_STATE, output)

    def test_cli_failure_path(self) -> None:
        self._setup_ready_for_extract()
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_NO_REQUIREMENTS_VALIDATION_OWNER_DECISION", output)

    def test_report_contains_required_fields_and_non_authority_flags(self) -> None:
        self._setup_ready_for_execution_check()
        report = requirements_validation_execution_check(
            self.project, "slither-demo", "slither-plan-v1"
        )
        for field in (
            "execution_check_state",
            "next_required_action",
            "plan_id",
            "intake_id",
            "latest_requirements_validation_owner_decision_id",
            "latest_requirements_validation_owner_decision",
            "source_requirements_draft_validation_preflight_state",
            "source_requirements_draft_validation_preflight_next_action",
        ):
            self.assertIsNotNone(getattr(report, field), field)
            self.assertIn(f"{field}:", report.output)
        for flag in REQUIREMENTS_VALIDATION_EXECUTION_CHECK_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, report.non_authority)
            self.assertTrue(report.non_authority[flag])

    def test_fails_closed_on_stale_authorize_decision_metadata(self) -> None:
        self._setup_ready_for_execution_check()
        artifact = load_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        artifact["source_requirements_draft_created_at"] = "stale-time"
        self._write_validation_decision_artifact(
            "slither-demo", "slither-plan-v1", "req-val-owner-v1", artifact
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_OWNER_DECISION_STALE_OR_INCOHERENT", output)

    def test_fails_closed_on_stale_preflight_state_in_authorize_decision(self) -> None:
        self._setup_ready_for_execution_check()
        artifact = load_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        artifact["source_requirements_draft_validation_preflight_state"] = (
            "STALE_PREFLIGHT_STATE"
        )
        self._write_validation_decision_artifact(
            "slither-demo", "slither-plan-v1", "req-val-owner-v1", artifact
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_OWNER_DECISION_STALE_OR_INCOHERENT", output)
        self.assertIn("stale preflight state", output)

    def test_fails_closed_on_wrong_authorize_next_required_action(self) -> None:
        self._setup_ready_for_execution_check()
        artifact = load_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        artifact["next_required_action"] = "WRONG_NEXT_ACTION"
        self._write_validation_decision_artifact(
            "slither-demo", "slither-plan-v1", "req-val-owner-v1", artifact
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_OWNER_DECISION_STALE_OR_INCOHERENT", output)
        self.assertIn("next_required_action", output)

    def test_fails_closed_on_false_non_authority_in_owner_decision_artifact(self) -> None:
        self._setup_ready_for_execution_check()
        artifact = load_requirements_validation_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-val-owner-v1"
        )
        artifact["non_authority"]["does_not_validate_requirements"] = False
        self._write_validation_decision_artifact(
            "slither-demo", "slither-plan-v1", "req-val-owner-v1", artifact
        )
        code, output = self._execution_check()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_MALFORMED_REQUIREMENTS_VALIDATION_OWNER_DECISION", output)
        self.assertIn("non_authority flag must be true", output)

    def test_formatter_uses_passed_non_authority_dict(self) -> None:
        from agent_os.orchestrator import _format_requirements_validation_execution_check

        non_authority = {
            key: True for key in REQUIREMENTS_VALIDATION_EXECUTION_CHECK_NON_AUTHORITY_FLAGS
        }
        non_authority["does_not_write_artifacts"] = False
        output = _format_requirements_validation_execution_check(
            plan_id="plan-a",
            intake_id="intake-a",
            planning_workspace_status="DRAFT",
            local_agentic_spec_status=None,
            local_agentic_spec_path=None,
            requirements_draft_provenance_path=None,
            latest_requirements_validation_owner_decision_id=None,
            latest_requirements_validation_owner_decision=None,
            latest_requirements_validation_owner_decision_created_at=None,
            latest_requirements_validation_owner_decision_path=None,
            source_requirements_draft_validation_preflight_state=None,
            source_requirements_draft_validation_preflight_next_action=None,
            execution_check_state="BLOCKED_TEST",
            next_required_action="FIX_TEST",
            blocking_reasons=["test reason"],
            checked_at="2026-07-06T10:00:00+00:00",
            non_authority=non_authority,
        )
        self.assertIn("does_not_write_artifacts: false", output)
        self.assertIn("execution_check_is_not_validation: true", output)

    def test_docs_state_execution_check_is_not_validation_and_not_approval(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        for rel in (
            "docs/orchestrator/goal-intake-artifact.md",
            "docs/orchestrator/goal-to-planning-workspace-contract.md",
            "docs/planning-workspace-layout.md",
        ):
            text = (repo_root / rel).read_text(encoding="utf-8").lower()
            self.assertIn("requirements-validation-execution-check", text)
            self.assertIn("not validation", text)
            self.assertIn("not approval", text)


class OrchestratorRequirementsDraftValidationReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _requirements_validation_decision_path(
        self, intake_id: str, plan_id: str, decision_id: str
    ) -> Path:
        return orchestrator_requirements_validation_decision_path(
            self.project, intake_id, plan_id, decision_id
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project, intake_id, "Build me an online slither.io-like game"
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project, intake_id, "scope-v1", "Browser-only demo with 10 players max."
        )
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _run(self, argv: list[str]) -> tuple[int, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(argv)
        return code, out_buf.getvalue() + err_buf.getvalue()

    def _prepare(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "prepare-planning-draft", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _transport(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "transport-planning-context", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _draft_context_pack(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "draft-context-pack", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _local_spec_preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "local-agentic-spec-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold_local_spec(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-local-agentic-spec", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "requirements-extraction-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-requirements-extraction", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _decide_extraction(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_EXTRACTION",
        decision_id: str = "req-ext-owner-v1",
        summary: str = "Authorize future extraction only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-extraction",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _extraction_execution_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-extraction-execution-check",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "extract-requirements-draft",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _decide(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_VALIDATION",
        decision_id: str = "req-val-owner-v1",
        summary: str = "Authorize future validation only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-validation",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _execution_check(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-validation-execution-check",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _validate(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "validate-requirements-draft",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _requirements_draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-requirements-draft-provenance.json"

    def _validation_report_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-requirements-draft-validation-report.json"
        )

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._local_spec_preflight(intake_id, plan_id)[0], 0)
        self.assertEqual(self._scaffold_local_spec(intake_id, plan_id)[0], 0)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

    def _setup_ready_for_decision(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self.assertEqual(self._scaffold(intake_id, plan_id)[0], 0)

    def _setup_ready_for_extraction_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_decision(intake_id, plan_id)
        self.assertEqual(self._decide_extraction(intake_id, plan_id)[0], 0)

    def _setup_ready_for_extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_extraction_check(intake_id, plan_id)
        self.assertEqual(self._extraction_execution_check(intake_id, plan_id)[0], 0)
        self.assertEqual(self._extract(intake_id, plan_id)[0], 0)

    def _setup_ready_for_execution_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_extract(intake_id, plan_id)
        self.assertEqual(self._decide(intake_id, plan_id)[0], 0)

    def _setup_ready_for_validate(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_execution_check(intake_id, plan_id)
        self.assertEqual(self._execution_check(intake_id, plan_id)[0], 0)

    def _tracked_artifact_paths(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> dict[Path, bytes]:
        workspace = self._workspace(plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._requirements_draft_provenance_path(plan_id),
            self._local_spec_path(plan_id),
            self._context_pack_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
            self._requirements_validation_decision_path(intake_id, plan_id, "req-val-owner-v1"),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def test_successful_validation_report_after_execution_check(self) -> None:
        self._setup_ready_for_validate()
        report = validate_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        self.assertEqual(report.status, REQUIREMENTS_DRAFT_VALIDATION_REPORT_CREATED_STATE)
        self.assertEqual(
            report.next_required_action,
            REQUIREMENTS_DRAFT_VALIDATION_REPORT_CREATED_NEXT_ACTION,
        )
        self.assertTrue(self._validation_report_path().is_file())

    def test_report_path_and_schema_are_correct(self) -> None:
        self._setup_ready_for_validate()
        validate_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        report_path = self._validation_report_path()
        self.assertTrue(report_path.is_file())
        artifact = json.loads(report_path.read_text(encoding="utf-8"))
        for field in (
            "artifact_type",
            "schema_version",
            "plan_id",
            "intake_id",
            "source_command",
            "status",
            "next_required_action",
            "validation_report_path",
            "local_agentic_spec_path",
            "requirements_draft_provenance_path",
            "source_requirements_validation_execution_check_state",
            "source_requirements_validation_execution_check_next_action",
            "latest_requirements_validation_owner_decision_id",
            "requirement_candidate_count",
            "candidate_results",
            "created_at",
            "non_authority",
        ):
            self.assertIn(field, artifact, field)
        self.assertEqual(
            artifact["artifact_type"],
            "ORCHESTRATOR_REQUIREMENTS_DRAFT_VALIDATION_REPORT",
        )
        self.assertEqual(artifact["status"], REQUIREMENTS_DRAFT_VALIDATION_REPORT_CREATED_STATE)

    def test_report_contains_one_entry_per_draft_req_candidate(self) -> None:
        self._setup_ready_for_validate()
        report = validate_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        provenance = json.loads(self._requirements_draft_provenance_path().read_text())
        self.assertEqual(
            len(report.candidate_results),
            provenance["requirement_candidate_count"],
        )
        self.assertEqual(
            tuple(r.draft_requirement_id for r in report.candidate_results),
            tuple(provenance["requirement_candidate_ids"]),
        )

    def test_candidate_pass_remains_not_approved_and_not_promoted(self) -> None:
        self._setup_ready_for_validate()
        report = validate_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        for result in report.candidate_results:
            self.assertEqual(result.validation_result, REQUIREMENTS_DRAFT_VALIDATION_RESULT_PASS)
            self.assertEqual(result.approval_status, "NOT_APPROVED")
            self.assertEqual(result.promotion_status, "NOT_PROMOTED")

    def test_pass_does_not_assign_req_ids(self) -> None:
        self._setup_ready_for_validate()
        report = validate_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        for result in report.candidate_results:
            self.assertEqual(result.approved_requirement_id, "NOT_ASSIGNED")
        artifact = json.loads(self._validation_report_path().read_text())
        combined = json.dumps(artifact)
        self.assertNotRegex(combined, r'"(REQ|FR|NFR)-\d{3}"')

    def _sample_valid_draft_candidate(
        self,
        *,
        candidate_id: str = "DRAFT-REQ-001",
        **overrides: object,
    ) -> DraftRequirementCandidate:
        fields = {
            "id": candidate_id,
            "status": DRAFT_REQUIREMENT_CANDIDATE_STATUS,
            "source_bounded": DRAFT_REQUIREMENT_SOURCE_BOUNDED_MARKER,
            "source_type": "goal_intake",
            "source_path": ".agent-os/orchestrator/intakes/slither-demo/goal-intake.json",
            "source_field": "normalized_goal",
            "source_quote_or_reference": "Build me an online slither.io-like game",
            "candidate_text": (
                "Draft candidate derived from source goal: "
                "Build me an online slither.io-like game."
            ),
            "validation_status": "NOT_VALIDATED",
            "approval_status": "NOT_APPROVED",
            "architecture_status": "NOT_DECIDED",
            "implementation_status": "NOT_PLANNED",
        }
        fields.update(overrides)
        return DraftRequirementCandidate(**fields)

    def test_blocked_candidate_remains_not_approved_not_promoted_no_req_id(self) -> None:
        candidate = self._sample_valid_draft_candidate(id="REQ-001")
        result = _validate_single_draft_requirement_candidate(
            candidate,
            provenance_ids=["REQ-001"],
            spec_content="REQ-001",
        )
        self.assertEqual(result.validation_result, REQUIREMENTS_DRAFT_VALIDATION_RESULT_BLOCKED)
        self.assertTrue(result.blocking_reasons)
        self.assertEqual(result.approval_status, "NOT_APPROVED")
        self.assertEqual(result.promotion_status, "NOT_PROMOTED")
        self.assertEqual(result.approved_requirement_id, "NOT_ASSIGNED")

    def test_needs_revision_candidate_remains_not_approved_not_promoted_no_req_id(
        self,
    ) -> None:
        candidate = self._sample_valid_draft_candidate(
            source_quote_or_reference="",
            candidate_text="Draft candidate derived from source goal: broad goal.",
        )
        result = _validate_single_draft_requirement_candidate(
            candidate,
            provenance_ids=["DRAFT-REQ-001"],
            spec_content="DRAFT-REQ-001",
        )
        self.assertEqual(
            result.validation_result,
            REQUIREMENTS_DRAFT_VALIDATION_RESULT_NEEDS_REVISION,
        )
        self.assertTrue(result.blocking_reasons)
        self.assertEqual(result.approval_status, "NOT_APPROVED")
        self.assertEqual(result.promotion_status, "NOT_PROMOTED")
        self.assertEqual(result.approved_requirement_id, "NOT_ASSIGNED")

    def test_report_retains_non_pass_candidate_results_without_dropping(self) -> None:
        self._setup_ready_for_validate()
        provenance = json.loads(self._requirements_draft_provenance_path().read_text())
        first_id = provenance["requirement_candidate_ids"][0]
        pass_candidate = self._sample_valid_draft_candidate(candidate_id=first_id)
        needs_revision_candidate = self._sample_valid_draft_candidate(
            candidate_id="DRAFT-REQ-999",
            source_quote_or_reference="",
            candidate_text="Draft candidate derived from source goal: broad goal.",
        )
        blocked_candidate = self._sample_valid_draft_candidate(id="REQ-001")
        mixed_candidates = (
            pass_candidate,
            needs_revision_candidate,
            blocked_candidate,
        )
        parse_calls = 0

        def _parse_side_effect(content: str):
            nonlocal parse_calls
            parse_calls += 1
            if parse_calls == 1:
                return _parse_requirements_draft_candidates_from_spec(content)
            return mixed_candidates

        with patch(
            "agent_os.orchestrator._parse_requirements_draft_candidates_from_spec",
            side_effect=_parse_side_effect,
        ):
            report = validate_requirements_draft(
                self.project,
                "slither-demo",
                "slither-plan-v1",
            )
        self.assertEqual(len(report.candidate_results), 3)
        by_id = {result.draft_requirement_id: result for result in report.candidate_results}
        self.assertEqual(
            by_id[first_id].validation_result,
            REQUIREMENTS_DRAFT_VALIDATION_RESULT_PASS,
        )
        self.assertEqual(
            by_id["DRAFT-REQ-999"].validation_result,
            REQUIREMENTS_DRAFT_VALIDATION_RESULT_NEEDS_REVISION,
        )
        self.assertEqual(
            by_id["REQ-001"].validation_result,
            REQUIREMENTS_DRAFT_VALIDATION_RESULT_BLOCKED,
        )
        for result in report.candidate_results:
            self.assertEqual(result.approval_status, "NOT_APPROVED")
            self.assertEqual(result.promotion_status, "NOT_PROMOTED")
            self.assertEqual(result.approved_requirement_id, "NOT_ASSIGNED")

    def test_report_non_authority_flags_present_and_true(self) -> None:
        self._setup_ready_for_validate()
        report = validate_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        for flag in REQUIREMENTS_DRAFT_VALIDATION_REPORT_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, report.non_authority)
            self.assertTrue(report.non_authority[flag])
        artifact = json.loads(self._validation_report_path().read_text())
        for flag in REQUIREMENTS_DRAFT_VALIDATION_REPORT_NON_AUTHORITY_FLAGS:
            self.assertTrue(artifact["non_authority"][flag])

    def test_fails_closed_when_execution_check_fails(self) -> None:
        self._setup_ready_for_extract()
        before = self._project_files()
        with self.assertRaises(ValueError):
            validate_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        self.assertEqual(before, self._project_files())
        self.assertFalse(self._validation_report_path().exists())

    def test_fails_closed_when_latest_decision_requests_revision(self) -> None:
        self._setup_ready_for_extract()
        self._decide(decision="REQUEST_REQUIREMENTS_DRAFT_REVISION", summary="Revise draft.")
        before = self._project_files()
        code, output = self._validate()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_REQUIREMENTS_VALIDATION_DECISION_REQUESTS_REVISION", output)
        self.assertEqual(before, self._project_files())
        self.assertFalse(self._validation_report_path().exists())

    def test_fails_closed_when_latest_decision_blocks_validation(self) -> None:
        self._setup_ready_for_extract()
        self._decide(decision="BLOCK_REQUIREMENTS_VALIDATION", summary="Block validation.")
        before = self._project_files()
        code, output = self._validate()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_LATEST_REQUIREMENTS_VALIDATION_DECISION_BLOCKS_VALIDATION", output)
        self.assertEqual(before, self._project_files())
        self.assertFalse(self._validation_report_path().exists())

    def test_fails_closed_when_validation_report_already_exists(self) -> None:
        self._setup_ready_for_validate()
        self.assertEqual(self._validate()[0], 0)
        code, output = self._validate()
        self.assertEqual(code, 1)
        self.assertIn("validation report already exists", output.lower())

    def test_does_not_modify_local_agentic_spec(self) -> None:
        self._setup_ready_for_validate()
        before = self._local_spec_path().read_bytes()
        self._validate()
        self.assertEqual(before, self._local_spec_path().read_bytes())

    def test_does_not_modify_context_pack(self) -> None:
        self._setup_ready_for_validate()
        before = self._context_pack_path().read_bytes()
        self._validate()
        self.assertEqual(before, self._context_pack_path().read_bytes())

    def test_does_not_create_approved_requirements(self) -> None:
        self._setup_ready_for_validate()
        self._validate()
        combined = "\n".join(
            p.read_text(encoding="utf-8")
            for p in self.project.rglob("*")
            if p.is_file() and p.suffix in {".md", ".json"}
        )
        self.assertNotIn("APPROVED_REQUIREMENTS", combined)
        self.assertNotIn("REQUIREMENTS_APPROVED", combined)

    def test_does_not_create_architecture(self) -> None:
        self._setup_ready_for_validate()
        self._validate()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("UNDECIDED_NOT_GENERATED", spec)
        combined = "\n".join(
            p.read_text(encoding="utf-8")
            for p in self.project.rglob("*")
            if p.is_file() and p.suffix in {".md", ".json"}
        )
        self.assertNotIn("selected backend", combined.lower())

    def test_does_not_create_implementation_plan(self) -> None:
        self._setup_ready_for_validate()
        before = self._implementation_plan_path().read_bytes()
        self._validate()
        self.assertEqual(before, self._implementation_plan_path().read_bytes())

    def test_does_not_create_planning_run_slice(self) -> None:
        self._setup_ready_for_validate()
        self._validate()
        self.assertNotIn(
            '{"artifact_type": "PLANNING_RUN_SLICE"}',
            self._local_spec_path().read_text(encoding="utf-8"),
        )

    def test_does_not_create_runner_proposal_or_run(self) -> None:
        self._setup_ready_for_validate()
        before = self._project_files()
        self._validate()
        after = self._project_files()
        new_files = after - before
        self.assertEqual(len(new_files), 1)
        self.assertIn(
            ".agent-os/planning/slither-plan-v1/evidence/orchestrator-requirements-draft-validation-report.json",
            new_files,
        )

    def test_does_not_invoke_subprocess_runner_or_executor(self) -> None:
        self._setup_ready_for_validate()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code, _ = self._validate()
        self.assertEqual(code, 0)

    def test_atomic_rollback_no_partial_artifact_on_failure(self) -> None:
        self._setup_ready_for_validate()
        with patch("agent_os.orchestrator._write_json", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                validate_requirements_draft(self.project, "slither-demo", "slither-plan-v1")
        self.assertFalse(self._validation_report_path().exists())
        self.assertFalse(self._validation_report_path().with_suffix(".json.tmp").exists())

    def test_cli_success_path(self) -> None:
        self._setup_ready_for_validate()
        code, output = self._validate()
        self.assertEqual(code, 0)
        self.assertIn(REQUIREMENTS_DRAFT_VALIDATION_REPORT_CREATED_STATE, output)

    def test_cli_failure_path(self) -> None:
        self._setup_ready_for_extract()
        code, output = self._validate()
        self.assertEqual(code, 1)
        self.assertIn("requirements validation execution check not confirmed", output.lower())

    def test_docs_state_validation_report_is_not_approval_and_not_promotion(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        for rel in (
            "docs/orchestrator/goal-intake-artifact.md",
            "docs/orchestrator/goal-to-planning-workspace-contract.md",
            "docs/planning-workspace-layout.md",
        ):
            text = (repo_root / rel).read_text(encoding="utf-8").lower()
            self.assertIn("validate-requirements-draft", text)
            self.assertIn("not approval", text)
            self.assertIn("not promotion", text)


class OrchestratorRequirementsApprovalPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project, intake_id, "Build me an online slither.io-like game"
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project, intake_id, "scope-v1", "Browser-only demo with 10 players max."
        )
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _run(self, argv: list[str]) -> tuple[int, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(argv)
        return code, out_buf.getvalue() + err_buf.getvalue()

    def _prepare(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "prepare-planning-draft", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _transport(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "transport-planning-context", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _draft_context_pack(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "draft-context-pack", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _local_spec_preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "local-agentic-spec-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold_local_spec(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-local-agentic-spec", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "requirements-extraction-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-requirements-extraction", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _decide_extraction(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_EXTRACTION",
        decision_id: str = "req-ext-owner-v1",
        summary: str = "Authorize future extraction only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-extraction",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _extraction_execution_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-extraction-execution-check",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "extract-requirements-draft",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _decide(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_VALIDATION",
        decision_id: str = "req-val-owner-v1",
        summary: str = "Authorize future validation only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-validation",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _execution_check(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-validation-execution-check",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _validate(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "validate-requirements-draft",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _approval_preflight(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-approval-preflight",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _requirements_draft_provenance_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "evidence" / "orchestrator-requirements-draft-provenance.json"

    def _validation_report_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-requirements-draft-validation-report.json"
        )

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._local_spec_preflight(intake_id, plan_id)[0], 0)
        self.assertEqual(self._scaffold_local_spec(intake_id, plan_id)[0], 0)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

    def _setup_ready_for_decision(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self.assertEqual(self._scaffold(intake_id, plan_id)[0], 0)

    def _setup_ready_for_extraction_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_decision(intake_id, plan_id)
        self.assertEqual(self._decide_extraction(intake_id, plan_id)[0], 0)

    def _setup_ready_for_extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_extraction_check(intake_id, plan_id)
        self.assertEqual(self._extraction_execution_check(intake_id, plan_id)[0], 0)
        self.assertEqual(self._extract(intake_id, plan_id)[0], 0)

    def _setup_ready_for_execution_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_extract(intake_id, plan_id)
        self.assertEqual(self._decide(intake_id, plan_id)[0], 0)

    def _setup_ready_for_validate(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_execution_check(intake_id, plan_id)
        self.assertEqual(self._execution_check(intake_id, plan_id)[0], 0)

    def _setup_ready_for_approval_preflight(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_validate(intake_id, plan_id)
        self.assertEqual(self._validate(intake_id, plan_id)[0], 0)

    def _write_validation_report_artifact(self, artifact: dict) -> None:
        self._validation_report_path().write_text(
            json.dumps(artifact, indent=2),
            encoding="utf-8",
        )

    def _load_validation_report_artifact(self) -> dict:
        return json.loads(self._validation_report_path().read_text(encoding="utf-8"))

    def _tracked_artifact_paths(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> dict[Path, bytes]:
        workspace = self._workspace(plan_id)
        paths = [
            self._artifact_path(intake_id),
            self._requirements_draft_provenance_path(plan_id),
            self._local_spec_path(plan_id),
            self._context_pack_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
            self._validation_report_path(plan_id),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def test_successful_approval_preflight_after_validation_report(self) -> None:
        self._setup_ready_for_approval_preflight()
        report = requirements_approval_preflight(
            self.project, "slither-demo", "slither-plan-v1"
        )
        self.assertEqual(
            report.approval_preflight_state,
            REQUIREMENTS_APPROVAL_PREFLIGHT_CONFIRMED_STATE,
        )
        self.assertEqual(
            report.next_required_action,
            REQUIREMENTS_APPROVAL_PREFLIGHT_CONFIRMED_NEXT_ACTION,
        )

    def test_report_fields_and_non_authority_flags_are_present(self) -> None:
        self._setup_ready_for_approval_preflight()
        report = requirements_approval_preflight(
            self.project, "slither-demo", "slither-plan-v1"
        )
        for field in (
            "approval_preflight_state",
            "next_required_action",
            "plan_id",
            "intake_id",
            "source_requirements_validation_execution_check_state",
            "source_requirements_validation_execution_check_next_action",
            "source_requirements_validation_report_path",
            "source_requirements_validation_report_status",
            "source_requirements_validation_report_next_action",
            "candidate_count",
            "candidate_validation_results_summary",
        ):
            self.assertIsNotNone(getattr(report, field), field)
            self.assertIn(f"{field}:", report.output)
        for flag in REQUIREMENTS_APPROVAL_PREFLIGHT_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, report.non_authority)
            self.assertTrue(report.non_authority[flag])

    def test_command_and_api_are_read_only_and_preserve_files(self) -> None:
        self._setup_ready_for_approval_preflight()
        before = self._tracked_artifact_paths()
        code, _ = self._approval_preflight()
        self.assertEqual(code, 0)
        after = self._tracked_artifact_paths()
        self.assertEqual(before, after)

    def test_does_not_create_approval_preflight_artifact(self) -> None:
        self._setup_ready_for_approval_preflight()
        before = self._project_files()
        self._approval_preflight()
        after = self._project_files()
        self.assertEqual(before, after)

    def test_does_not_modify_validation_report(self) -> None:
        self._setup_ready_for_approval_preflight()
        before = self._validation_report_path().read_bytes()
        self._approval_preflight()
        self.assertEqual(before, self._validation_report_path().read_bytes())

    def test_does_not_modify_local_agentic_spec(self) -> None:
        self._setup_ready_for_approval_preflight()
        before = self._local_spec_path().read_bytes()
        self._approval_preflight()
        self.assertEqual(before, self._local_spec_path().read_bytes())

    def test_does_not_create_approved_requirements(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._approval_preflight()
        combined = "\n".join(
            p.read_text(encoding="utf-8")
            for p in self.project.rglob("*")
            if p.is_file() and p.suffix in {".md", ".json"}
        )
        self.assertNotIn("APPROVED_REQUIREMENTS", combined)
        self.assertNotIn("REQUIREMENTS_APPROVED", combined)

    def test_does_not_assign_req_ids(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._approval_preflight()
        combined = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("DRAFT-REQ-", combined)
        self.assertNotRegex(combined, r"(?<!DRAFT-)REQ-\d{3}\b")

    def test_does_not_create_architecture(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._approval_preflight()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("UNDECIDED_NOT_GENERATED", spec)

    def test_does_not_create_implementation_plan(self) -> None:
        self._setup_ready_for_approval_preflight()
        before = self._implementation_plan_path().read_bytes()
        self._approval_preflight()
        self.assertEqual(before, self._implementation_plan_path().read_bytes())

    def test_does_not_create_planning_run_slice(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._approval_preflight()
        self.assertNotIn(
            '{"artifact_type": "PLANNING_RUN_SLICE"}',
            self._local_spec_path().read_text(encoding="utf-8"),
        )

    def test_does_not_create_runner_proposal_or_run(self) -> None:
        self._setup_ready_for_approval_preflight()
        before = self._project_files()
        self._approval_preflight()
        self.assertEqual(before, self._project_files())

    def test_does_not_invoke_subprocess_runner_or_executor(self) -> None:
        self._setup_ready_for_approval_preflight()
        with patch("subprocess.run", side_effect=AssertionError("subprocess invoked")):
            code, _ = self._approval_preflight()
        self.assertEqual(code, 0)

    def test_fails_closed_when_execution_check_fails(self) -> None:
        self._setup_ready_for_extract()
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_NO_REQUIREMENTS_VALIDATION_OWNER_DECISION", output)

    def test_fails_closed_when_validation_report_missing(self) -> None:
        self._setup_ready_for_validate()
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_REPORT_MISSING", output)

    def test_fails_closed_when_validation_report_has_wrong_status(self) -> None:
        self._setup_ready_for_approval_preflight()
        artifact = self._load_validation_report_artifact()
        artifact["status"] = "WRONG_STATUS"
        self._write_validation_report_artifact(artifact)
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_REPORT_MALFORMED", output)

    def test_fails_closed_when_validation_report_has_wrong_next_action(self) -> None:
        self._setup_ready_for_approval_preflight()
        artifact = self._load_validation_report_artifact()
        artifact["next_required_action"] = "WRONG_NEXT_ACTION"
        self._write_validation_report_artifact(artifact)
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_REPORT_MALFORMED", output)

    def test_fails_closed_when_validation_report_has_wrong_intake_id(self) -> None:
        self._setup_ready_for_approval_preflight()
        artifact = self._load_validation_report_artifact()
        artifact["intake_id"] = "wrong-intake"
        self._write_validation_report_artifact(artifact)
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_REPORT_SCOPE_MISMATCH", output)

    def test_fails_closed_when_validation_report_has_wrong_plan_id(self) -> None:
        self._setup_ready_for_approval_preflight()
        artifact = self._load_validation_report_artifact()
        artifact["plan_id"] = "wrong-plan"
        self._write_validation_report_artifact(artifact)
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_REPORT_SCOPE_MISMATCH", output)

    def test_fails_closed_when_validation_report_has_malformed_json(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._validation_report_path().write_text("{not-json", encoding="utf-8")
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_REPORT_MALFORMED", output)

    def test_fails_closed_when_validation_report_has_false_non_authority_flags(self) -> None:
        self._setup_ready_for_approval_preflight()
        artifact = self._load_validation_report_artifact()
        artifact["non_authority"]["validation_report_is_not_approval"] = False
        self._write_validation_report_artifact(artifact)
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_REPORT_MALFORMED", output)

    def test_fails_closed_when_candidate_count_mismatches_current_draft(self) -> None:
        self._setup_ready_for_approval_preflight()
        artifact = self._load_validation_report_artifact()
        artifact["candidate_results"] = artifact["candidate_results"][:1]
        artifact["requirement_candidate_count"] = 1
        self._write_validation_report_artifact(artifact)
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_REPORT_STALE_OR_INCOHERENT", output)

    def test_fails_closed_when_candidate_id_mismatches_current_draft(self) -> None:
        self._setup_ready_for_approval_preflight()
        artifact = self._load_validation_report_artifact()
        artifact["candidate_results"][0]["draft_requirement_id"] = "DRAFT-REQ-999"
        self._write_validation_report_artifact(artifact)
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_REPORT_STALE_OR_INCOHERENT", output)

    def test_fails_closed_when_validation_report_assigns_approved_requirement_id(self) -> None:
        self._setup_ready_for_approval_preflight()
        artifact = self._load_validation_report_artifact()
        artifact["candidate_results"][0]["approved_requirement_id"] = "REQ-001"
        self._write_validation_report_artifact(artifact)
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn(
            "BLOCKED_REQUIREMENTS_VALIDATION_REPORT_HAS_APPROVAL_OR_PROMOTION_LEAKAGE",
            output,
        )

    def test_fails_closed_when_validation_report_marks_candidate_approved(self) -> None:
        self._setup_ready_for_approval_preflight()
        artifact = self._load_validation_report_artifact()
        artifact["candidate_results"][0]["approval_status"] = "APPROVED"
        self._write_validation_report_artifact(artifact)
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn(
            "BLOCKED_REQUIREMENTS_VALIDATION_REPORT_HAS_APPROVAL_OR_PROMOTION_LEAKAGE",
            output,
        )

    def test_fails_closed_when_validation_report_marks_candidate_promoted(self) -> None:
        self._setup_ready_for_approval_preflight()
        artifact = self._load_validation_report_artifact()
        artifact["candidate_results"][0]["promotion_status"] = "PROMOTED"
        self._write_validation_report_artifact(artifact)
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn(
            "BLOCKED_REQUIREMENTS_VALIDATION_REPORT_HAS_APPROVAL_OR_PROMOTION_LEAKAGE",
            output,
        )

    def test_fails_closed_when_validation_report_has_needs_revision_candidate(self) -> None:
        self._setup_ready_for_approval_preflight()
        artifact = self._load_validation_report_artifact()
        artifact["candidate_results"][0]["validation_result"] = (
            REQUIREMENTS_DRAFT_VALIDATION_RESULT_NEEDS_REVISION
        )
        self._write_validation_report_artifact(artifact)
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn(
            "BLOCKED_REQUIREMENTS_VALIDATION_REPORT_HAS_NON_PASS_CANDIDATES",
            output,
        )

    def test_fails_closed_when_validation_report_has_blocked_candidate(self) -> None:
        self._setup_ready_for_approval_preflight()
        artifact = self._load_validation_report_artifact()
        artifact["candidate_results"][0]["validation_result"] = (
            REQUIREMENTS_DRAFT_VALIDATION_RESULT_BLOCKED
        )
        self._write_validation_report_artifact(artifact)
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn(
            "BLOCKED_REQUIREMENTS_VALIDATION_REPORT_HAS_NON_PASS_CANDIDATES",
            output,
        )

    def test_fails_closed_when_current_draft_changes_after_validation_report(self) -> None:
        self._setup_ready_for_approval_preflight()
        spec = self._local_spec_path()
        spec.write_text(
            spec.read_text(encoding="utf-8").replace(
                DRAFT_REQUIREMENT_CANDIDATE_STATUS, "APPROVED_REQUIREMENT"
            ),
            encoding="utf-8",
        )
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_CANDIDATE_NOT_DRAFT_NON_AUTHORITY", output)

    def test_cli_success_path(self) -> None:
        self._setup_ready_for_approval_preflight()
        code, output = self._approval_preflight()
        self.assertEqual(code, 0)
        self.assertIn(REQUIREMENTS_APPROVAL_PREFLIGHT_CONFIRMED_STATE, output)

    def test_cli_failure_path(self) -> None:
        self._setup_ready_for_validate()
        code, output = self._approval_preflight()
        self.assertEqual(code, 1)
        self.assertIn("BLOCKED_REQUIREMENTS_VALIDATION_REPORT_MISSING", output)

    def test_docs_state_approval_preflight_is_not_approval_and_not_promotion(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        for rel in (
            "docs/orchestrator/goal-intake-artifact.md",
            "docs/orchestrator/goal-to-planning-workspace-contract.md",
            "docs/planning-workspace-layout.md",
        ):
            text = (repo_root / rel).read_text(encoding="utf-8").lower()
            self.assertIn("requirements-approval-preflight", text)
            self.assertIn("not approval", text)
            self.assertIn("not promotion", text)


class OrchestratorRequirementsApprovalOwnerDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.project = Path(self._tmp.name)
        init_workspace(self.project)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _artifact_path(self, intake_id: str) -> Path:
        return orchestrator_intake_path(self.project, intake_id) / GOAL_INTAKE_FILE

    def _requirements_approval_decision_path(
        self, intake_id: str, plan_id: str, decision_id: str
    ) -> Path:
        return orchestrator_requirements_approval_decision_path(
            self.project, intake_id, plan_id, decision_id
        )

    def _create_slither_intake(self, intake_id: str = "slither-demo") -> Path:
        return create_goal_intake(
            self.project, intake_id, "Build me an online slither.io-like game"
        )

    def _authorize_slither(self, intake_id: str = "slither-demo") -> None:
        self._create_slither_intake(intake_id)
        create_owner_clarification(
            self.project, intake_id, "scope-v1", "Browser-only demo with 10 players max."
        )
        create_owner_readiness_decision(
            self.project,
            intake_id,
            "owner-v1",
            "AUTHORIZE_DRAFT_PREPARATION",
            "Scope clarified; authorize future draft prep only.",
        )

    def _run(self, argv: list[str]) -> tuple[int, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = main(argv)
        return code, out_buf.getvalue() + err_buf.getvalue()

    def _prepare(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "prepare-planning-draft", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _transport(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "transport-planning-context", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _draft_context_pack(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "draft-context-pack", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _local_spec_preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "local-agentic-spec-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold_local_spec(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-local-agentic-spec", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _preflight(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "requirements-extraction-preflight", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            ["orchestrator", "scaffold-requirements-extraction", intake_id, str(self.project), "--plan-id", plan_id]
        )

    def _decide_extraction(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_EXTRACTION",
        decision_id: str = "req-ext-owner-v1",
        summary: str = "Authorize future extraction only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-extraction",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _extraction_execution_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-extraction-execution-check",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "extract-requirements-draft",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _decide_validation(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_VALIDATION",
        decision_id: str = "req-val-owner-v1",
        summary: str = "Authorize future validation only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-validation",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _execution_check(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "requirements-validation-execution-check",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _validate(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "validate-requirements-draft",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
            ]
        )

    def _decide(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_APPROVAL",
        decision_id: str = "req-appr-owner-v1",
        summary: str = "Authorize future approval execution check only.",
    ) -> tuple[int, str]:
        return self._run(
            [
                "orchestrator",
                "decide-requirements-approval",
                intake_id,
                str(self.project),
                "--plan-id",
                plan_id,
                "--decision",
                decision,
                "--decision-id",
                decision_id,
                "--summary",
                summary,
            ]
        )

    def _project_files(self) -> set[str]:
        return {
            path.relative_to(self.project).as_posix()
            for path in self.project.rglob("*")
            if path.is_file()
        }

    def _workspace(self, plan_id: str = "slither-plan-v1") -> Path:
        return planning_path(self.project, plan_id)

    def _validation_report_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return (
            self._workspace(plan_id)
            / "evidence"
            / "orchestrator-requirements-draft-validation-report.json"
        )

    def _local_spec_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "local-agentic-spec.md"

    def _context_pack_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "context-pack.md"

    def _implementation_plan_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "implementation-plan.md"

    def _planning_audit_path(self, plan_id: str = "slither-plan-v1") -> Path:
        return self._workspace(plan_id) / "planning-audit.md"

    def _setup_ready_for_scaffold(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._authorize_slither(intake_id)
        self.assertEqual(self._prepare(intake_id, plan_id)[0], 0)
        self.assertEqual(self._transport(intake_id, plan_id)[0], 0)
        self.assertEqual(self._draft_context_pack(intake_id, plan_id)[0], 0)
        self.assertEqual(self._local_spec_preflight(intake_id, plan_id)[0], 0)
        self.assertEqual(self._scaffold_local_spec(intake_id, plan_id)[0], 0)
        self.assertEqual(self._preflight(intake_id, plan_id)[0], 0)

    def _setup_ready_for_decision(self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1") -> None:
        self._setup_ready_for_scaffold(intake_id, plan_id)
        self.assertEqual(self._scaffold(intake_id, plan_id)[0], 0)

    def _setup_ready_for_extraction_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_decision(intake_id, plan_id)
        self.assertEqual(self._decide_extraction(intake_id, plan_id)[0], 0)

    def _setup_ready_for_extract(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_extraction_check(intake_id, plan_id)
        self.assertEqual(self._extraction_execution_check(intake_id, plan_id)[0], 0)
        self.assertEqual(self._extract(intake_id, plan_id)[0], 0)

    def _setup_ready_for_execution_check(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_extract(intake_id, plan_id)
        self.assertEqual(self._decide_validation(intake_id, plan_id)[0], 0)

    def _setup_ready_for_validate(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_execution_check(intake_id, plan_id)
        self.assertEqual(self._execution_check(intake_id, plan_id)[0], 0)

    def _setup_ready_for_approval_preflight(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> None:
        self._setup_ready_for_validate(intake_id, plan_id)
        self.assertEqual(self._validate(intake_id, plan_id)[0], 0)

    def _record_decision(
        self,
        intake_id: str = "slither-demo",
        plan_id: str = "slither-plan-v1",
        decision_id: str = "req-appr-owner-v1",
        decision: str = "AUTHORIZE_REQUIREMENTS_APPROVAL",
        summary: str = "Authorize future approval execution check only.",
    ):
        return create_requirements_approval_owner_decision(
            self.project,
            intake_id,
            plan_id,
            decision_id,
            decision,
            summary,
        )

    def _tracked_artifact_paths(
        self, intake_id: str = "slither-demo", plan_id: str = "slither-plan-v1"
    ) -> dict[Path, bytes]:
        paths = [
            self._artifact_path(intake_id),
            self._local_spec_path(plan_id),
            self._context_pack_path(plan_id),
            self._implementation_plan_path(plan_id),
            self._planning_audit_path(plan_id),
            self._validation_report_path(plan_id),
        ]
        return {path: path.read_bytes() for path in paths if path.is_file()}

    def test_records_request_revision_decision_append_only_no_approval(self) -> None:
        self._setup_ready_for_approval_preflight()
        before = self._tracked_artifact_paths()
        report = self._record_decision(
            decision="REQUEST_REQUIREMENTS_APPROVAL_REVISION",
            summary="Validation report needs more review.",
        )
        self.assertEqual(report.status, REQUIREMENTS_APPROVAL_OWNER_DECISION_RECORDED_STATE)
        self.assertEqual(report.next_required_action, REQUIREMENTS_APPROVAL_REQUEST_NEXT_ACTION)
        artifact = load_requirements_approval_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-appr-owner-v1"
        )
        self.assertEqual(artifact["decision"], "REQUEST_REQUIREMENTS_APPROVAL_REVISION")
        self.assertTrue(artifact["non_authority"]["does_not_approve_requirements"])
        for path, content in before.items():
            self.assertEqual(content, path.read_bytes(), str(path))

    def test_records_block_decision_append_only_no_approval(self) -> None:
        self._setup_ready_for_approval_preflight()
        report = self._record_decision(
            decision_id="req-appr-block-v1",
            decision="BLOCK_REQUIREMENTS_APPROVAL",
            summary="Block approval for now.",
        )
        self.assertEqual(report.decision, "BLOCK_REQUIREMENTS_APPROVAL")
        self.assertEqual(report.next_required_action, REQUIREMENTS_APPROVAL_BLOCK_NEXT_ACTION)
        artifact = load_requirements_approval_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-appr-block-v1"
        )
        self.assertEqual(
            artifact["source_requirements_approval_preflight_state"],
            REQUIREMENTS_APPROVAL_PREFLIGHT_NOT_REQUIRED_STATE,
        )
        self.assertTrue(artifact["non_authority"]["owner_decision_is_not_approval"])

    def test_records_authorize_only_when_preflight_passes(self) -> None:
        self._setup_ready_for_approval_preflight()
        report = self._record_decision()
        self.assertEqual(report.decision, "AUTHORIZE_REQUIREMENTS_APPROVAL")
        self.assertEqual(report.next_required_action, REQUIREMENTS_APPROVAL_AUTHORIZE_NEXT_ACTION)
        artifact = load_requirements_approval_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-appr-owner-v1"
        )
        self.assertEqual(
            artifact["source_requirements_approval_preflight_state"],
            REQUIREMENTS_APPROVAL_PREFLIGHT_CONFIRMED_STATE,
        )
        self.assertEqual(
            artifact["source_requirements_approval_preflight_next_action"],
            REQUIREMENTS_APPROVAL_PREFLIGHT_CONFIRMED_NEXT_ACTION,
        )

    def test_authorize_fails_closed_when_preflight_would_fail(self) -> None:
        self._setup_ready_for_validate()
        with self.assertRaises(ValueError) as ctx:
            self._record_decision()
        self.assertIn("requirements approval preflight not confirmed", str(ctx.exception))

    def test_authorize_writes_no_artifact_when_preflight_fails(self) -> None:
        self._setup_ready_for_validate()
        with self.assertRaises(ValueError):
            self._record_decision()
        self.assertFalse(
            self._requirements_approval_decision_path(
                "slither-demo", "slither-plan-v1", "req-appr-owner-v1"
            ).exists()
        )

    def test_decision_artifact_path_is_plan_scoped(self) -> None:
        self._setup_ready_for_approval_preflight()
        report = self._record_decision(decision_id="req-appr-plan-v1")
        expected = self._requirements_approval_decision_path(
            "slither-demo", "slither-plan-v1", "req-appr-plan-v1"
        )
        self.assertEqual(report.decision_path, expected)
        self.assertIn(REQUIREMENTS_APPROVAL_DECISIONS_DIR, expected.as_posix())
        self.assertIn("slither-plan-v1", expected.as_posix())

    def test_duplicate_decision_id_fails_closed_without_overwrite(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._record_decision(
            decision_id="req-appr-dup-v1", decision="BLOCK_REQUIREMENTS_APPROVAL"
        )
        existing = self._requirements_approval_decision_path(
            "slither-demo", "slither-plan-v1", "req-appr-dup-v1"
        ).read_text(encoding="utf-8")
        with self.assertRaises(FileExistsError):
            create_requirements_approval_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-appr-dup-v1",
                "REQUEST_REQUIREMENTS_APPROVAL_REVISION",
                "Second decision.",
            )
        self.assertEqual(
            existing,
            self._requirements_approval_decision_path(
                "slither-demo", "slither-plan-v1", "req-appr-dup-v1"
            ).read_text(encoding="utf-8"),
        )

    def test_refuses_invalid_decision_value(self) -> None:
        self._setup_ready_for_approval_preflight()
        with self.assertRaises(ValueError) as ctx:
            create_requirements_approval_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-appr-owner-v1",
                "APPROVE_REQUIREMENTS",
                "Not allowed.",
            )
        self.assertIn("unsupported decision value", str(ctx.exception))

    def test_refuses_invalid_decision_id_and_path_traversal(self) -> None:
        self._setup_ready_for_approval_preflight()
        for decision_id in ("", " ", "../escape", "bad id", ".hidden"):
            with self.subTest(decision_id=decision_id):
                with self.assertRaises(ValueError):
                    create_requirements_approval_owner_decision(
                        self.project,
                        "slither-demo",
                        "slither-plan-v1",
                        decision_id,
                        "BLOCK_REQUIREMENTS_APPROVAL",
                        "Stop.",
                    )

    def test_refuses_invalid_intake(self) -> None:
        intake_id = "slither-demo"
        plan_id = "slither-plan-v1"
        self._setup_ready_for_approval_preflight(intake_id, plan_id)
        artifact_path = self._artifact_path(intake_id)
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        artifact["artifact_type"] = "PLANNING_WORKSPACE_DRAFT"
        artifact_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            create_requirements_approval_owner_decision(
                self.project,
                intake_id,
                plan_id,
                "req-appr-owner-v1",
                "BLOCK_REQUIREMENTS_APPROVAL",
                "Stop.",
            )

    def test_refuses_invalid_plan_id(self) -> None:
        self._setup_ready_for_approval_preflight()
        buf = io.StringIO()
        with redirect_stderr(buf):
            code = main(
                [
                    "orchestrator",
                    "decide-requirements-approval",
                    "slither-demo",
                    str(self.project),
                    "--plan-id",
                    "../escape",
                    "--decision",
                    "BLOCK_REQUIREMENTS_APPROVAL",
                    "--decision-id",
                    "req-appr-owner-v1",
                    "--summary",
                    "Stop.",
                ]
            )
        self.assertEqual(code, 1)

    def test_refuses_empty_summary(self) -> None:
        self._setup_ready_for_approval_preflight()
        with self.assertRaises(ValueError) as ctx:
            create_requirements_approval_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-appr-owner-v1",
                "BLOCK_REQUIREMENTS_APPROVAL",
                "",
            )
        self.assertIn("owner summary must not be empty", str(ctx.exception))
        code, output = self._decide(summary="")
        self.assertEqual(code, 1)
        self.assertIn("owner summary must not be empty", output)

    def test_refuses_wrong_intake_plan_binding(self) -> None:
        self._setup_ready_for_approval_preflight("slither-demo", "slither-plan-v1")
        self._create_slither_intake("other-intake")
        with self.assertRaises(ValueError) as ctx:
            create_requirements_approval_owner_decision(
                self.project,
                "other-intake",
                "slither-plan-v1",
                "req-appr-owner-v1",
                "BLOCK_REQUIREMENTS_APPROVAL",
                "Wrong intake for this plan.",
            )
        self.assertIn("intake_id mismatch", str(ctx.exception))

    def test_request_block_preflight_snapshot_does_not_authorize_approval(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._record_decision(
            decision="REQUEST_REQUIREMENTS_APPROVAL_REVISION",
            summary="Needs revision.",
        )
        artifact = load_requirements_approval_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-appr-owner-v1"
        )
        self.assertEqual(
            artifact["source_requirements_approval_preflight_state"],
            REQUIREMENTS_APPROVAL_PREFLIGHT_NOT_REQUIRED_STATE,
        )
        self.assertEqual(
            artifact["source_requirements_approval_preflight_next_action"],
            REQUIREMENTS_APPROVAL_PREFLIGHT_NOT_REQUIRED_NEXT_ACTION,
        )

    def test_authorize_preflight_snapshot_records_confirmed_state(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._record_decision()
        artifact = load_requirements_approval_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-appr-owner-v1"
        )
        self.assertEqual(
            artifact["source_requirements_approval_preflight_state"],
            REQUIREMENTS_APPROVAL_PREFLIGHT_CONFIRMED_STATE,
        )
        self.assertEqual(
            artifact["source_requirements_validation_report_status"],
            REQUIREMENTS_DRAFT_VALIDATION_REPORT_CREATED_STATE,
        )

    def test_does_not_modify_local_agentic_spec_md(self) -> None:
        self._setup_ready_for_approval_preflight()
        before = self._local_spec_path().read_bytes()
        self._record_decision()
        self.assertEqual(before, self._local_spec_path().read_bytes())

    def test_does_not_modify_validation_report(self) -> None:
        self._setup_ready_for_approval_preflight()
        before = self._validation_report_path().read_bytes()
        self._record_decision()
        self.assertEqual(before, self._validation_report_path().read_bytes())

    def test_does_not_create_approved_requirements(self) -> None:
        self._setup_ready_for_approval_preflight()
        before = self._project_files()
        self._record_decision()
        after = self._project_files()
        new_files = after - before
        self.assertTrue(all("requirements-approval-decisions" in path for path in new_files))
        combined = "\n".join(
            p.read_text(encoding="utf-8")
            for p in self.project.rglob("*")
            if p.is_file() and p.suffix in {".md", ".json"}
        )
        self.assertNotIn("APPROVED_REQUIREMENTS", combined)
        self.assertNotIn("REQUIREMENTS_APPROVED", combined)

    def test_does_not_assign_req_ids(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._record_decision()
        combined = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("DRAFT-REQ-", combined)
        self.assertNotRegex(combined, r"(?<!DRAFT-)REQ-\d{3}\b")

    def test_does_not_promote_draft_req_to_req(self) -> None:
        self._setup_ready_for_approval_preflight()
        spec_text = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("DRAFT-REQ-", spec_text)
        self._record_decision()
        after = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("DRAFT-REQ-", after)
        self.assertNotRegex(after, r"(?<![A-Z-])REQ-\d+")

    def test_does_not_create_architecture(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._record_decision()
        spec = self._local_spec_path().read_text(encoding="utf-8")
        self.assertIn("UNDECIDED_NOT_GENERATED", spec)

    def test_does_not_create_implementation_plan(self) -> None:
        self._setup_ready_for_approval_preflight()
        before = self._implementation_plan_path().read_bytes()
        self._record_decision()
        self.assertEqual(before, self._implementation_plan_path().read_bytes())

    def test_does_not_create_planning_run_slice(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._record_decision()
        self.assertNotIn(
            '{"artifact_type": "PLANNING_RUN_SLICE"}',
            self._local_spec_path().read_text(encoding="utf-8"),
        )

    def test_does_not_create_runner_proposal_or_run(self) -> None:
        self._setup_ready_for_approval_preflight()
        before = self._project_files()
        self._record_decision()
        after = self._project_files()
        new_files = after - before
        self.assertEqual(len(new_files), 1)
        self.assertIn("requirements-approval-decisions", next(iter(new_files)))

    def test_does_not_invoke_subprocess_runner_or_executor(self) -> None:
        self._setup_ready_for_approval_preflight()
        with (
            patch("subprocess.run", side_effect=AssertionError("subprocess invoked")),
            patch.object(
                planning_module,
                "progress_planning_workspace",
                side_effect=AssertionError("progress invoked"),
            ),
            patch.object(
                planning_module,
                "transition_planning_workspace",
                side_effect=AssertionError("transition invoked"),
            ),
            patch.object(
                planning_module,
                "record_planning_owner_decision",
                side_effect=AssertionError("decide invoked"),
            ),
        ):
            code = self._decide()[0]
        self.assertEqual(code, 0)

    def test_decision_artifact_contains_required_non_authority_flags(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._record_decision()
        artifact = load_requirements_approval_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-appr-owner-v1"
        )
        for flag in REQUIREMENTS_APPROVAL_OWNER_DECISION_NON_AUTHORITY_FLAGS:
            self.assertIn(flag, artifact["non_authority"])
            self.assertTrue(artifact["non_authority"][flag])

    def test_validate_requirements_approval_owner_decision_helper(self) -> None:
        self._setup_ready_for_approval_preflight()
        self._record_decision()
        report = validate_requirements_approval_owner_decision(
            self.project, "slither-demo", "slither-plan-v1", "req-appr-owner-v1"
        )
        self.assertTrue(report.valid)
        self.assertEqual(report.errors, ())

    def test_latest_decision_ordering_deterministic_by_created_at_then_decision_id(
        self,
    ) -> None:
        from agent_os import orchestrator as orchestrator_module

        self._setup_ready_for_approval_preflight()
        times = iter(
            [
                "2026-07-06T10:00:00+00:00",
                "2026-07-06T10:00:00+00:00",
                "2026-07-06T11:00:00+00:00",
            ]
        )
        with patch.object(orchestrator_module, "_utc_now", side_effect=lambda: next(times)):
            create_requirements_approval_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-appr-bbb",
                "REQUEST_REQUIREMENTS_APPROVAL_REVISION",
                "Earlier tie-breaker id.",
            )
            create_requirements_approval_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-appr-aaa",
                "BLOCK_REQUIREMENTS_APPROVAL",
                "Same timestamp, earlier id.",
            )
            create_requirements_approval_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-appr-zzz",
                "BLOCK_REQUIREMENTS_APPROVAL",
                "Latest timestamp.",
            )

        decisions = list_requirements_approval_owner_decisions(
            self.project, "slither-demo", "slither-plan-v1"
        )
        self.assertEqual(
            [record.decision_id for record in decisions],
            ["req-appr-aaa", "req-appr-bbb", "req-appr-zzz"],
        )

    def test_load_validated_requirements_approval_owner_decisions_loads_valid_artifacts(
        self,
    ) -> None:
        from agent_os import orchestrator as orchestrator_module

        self._setup_ready_for_approval_preflight()
        times = iter(
            [
                "2026-07-06T10:00:00+00:00",
                "2026-07-06T11:00:00+00:00",
            ]
        )
        with patch.object(orchestrator_module, "_utc_now", side_effect=lambda: next(times)):
            create_requirements_approval_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-appr-aaa",
                "BLOCK_REQUIREMENTS_APPROVAL",
                "First block.",
            )
            create_requirements_approval_owner_decision(
                self.project,
                "slither-demo",
                "slither-plan-v1",
                "req-appr-bbb",
                "REQUEST_REQUIREMENTS_APPROVAL_REVISION",
                "Request revision.",
            )

        records, errors = orchestrator_module._load_validated_requirements_approval_owner_decisions(
            self.project, "slither-demo", "slither-plan-v1"
        )
        self.assertEqual(errors, [])
        self.assertEqual(
            [record.decision_id for record in records],
            ["req-appr-aaa", "req-appr-bbb"],
        )

    def test_cli_happy_path_authorize_requirements_approval(self) -> None:
        self._setup_ready_for_approval_preflight()
        code, output = self._decide()
        self.assertEqual(code, 0)
        self.assertIn("created requirements approval owner decision artifact:", output)
        self.assertIn(REQUIREMENTS_APPROVAL_OWNER_DECISION_RECORDED_STATE, output)
        self.assertIn(REQUIREMENTS_APPROVAL_AUTHORIZE_NEXT_ACTION, output)
        self.assertIn("authorization is not approval", output.lower())

    def test_cli_failure_path_invalid_decision(self) -> None:
        self._setup_ready_for_approval_preflight()
        with self.assertRaises(SystemExit) as ctx:
            self._decide(decision="APPROVE_REQUIREMENTS")
        self.assertEqual(ctx.exception.code, 2)

    def test_docs_state_owner_approval_decision_is_not_promotion(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        for rel in (
            "docs/orchestrator/goal-intake-artifact.md",
            "docs/orchestrator/goal-to-planning-workspace-contract.md",
            "docs/planning-workspace-layout.md",
        ):
            text = (repo_root / rel).read_text(encoding="utf-8").lower()
            self.assertIn("decide-requirements-approval", text)
            self.assertIn("not approval", text)
            self.assertIn("not promotion", text)
            self.assertIn("not architecture", text)


class OrchestratorDocsGuardTests(unittest.TestCase):
    """Guard doctrine for CORE_ORCHESTRATOR_001 goal-to-planning workspace contract."""

    _ORCHESTRATOR_DOCS: tuple[str, ...] = (
        "docs/orchestrator/goal-to-planning-workspace-contract.md",
        "docs/orchestrator/goal-intake-artifact.md",
        "docs/orchestrator/architecture-decision-boundary.md",
        "docs/orchestrator/slither-like-demo-contract.md",
    )

    _REQUIRED_BOUNDARY_PHRASES: tuple[str, ...] = (
        "goal intake is not planning approval",
        "planning draft is not a validated workspace",
        "architecture recommendation is not owner decision",
        "implementation plan is not runner proposal",
        "PLANNING_RUN_SLICE is not an approved run",
        "generated Markdown prose is not machine authority",
        "runner import remains explicit",
        "executor invocation remains separate",
    )

    _INDEPENDENT_VALIDATION_MARKERS: tuple[str, ...] = (
        "independent",
        "audit",
    )

    _FORBIDDEN_RUNNER_MODIFICATION_PHRASES: tuple[str, ...] = (
        "modify agent-os-runner",
        "modified agent-os-runner",
        "requires modifying the runner",
        "runner files are modified",
        "must modify runner",
    )

    _FUTURE_CLI_COMMANDS: tuple[str, ...] = (
        "agent-os orchestrator draft-export",
    )

    @classmethod
    def _repo_root(cls) -> Path:
        return Path(__file__).resolve().parent.parent

    @classmethod
    def _orchestrator_docs_text(cls) -> str:
        repo_root = cls._repo_root()
        parts: list[str] = []
        for rel in cls._ORCHESTRATOR_DOCS:
            path = repo_root / rel
            parts.append(path.read_text(encoding="utf-8"))
        return "\n".join(parts)

    def test_orchestrator_contract_docs_exist(self) -> None:
        repo_root = self._repo_root()
        missing = [
            rel
            for rel in self._ORCHESTRATOR_DOCS
            if not (repo_root / rel).is_file()
        ]
        self.assertEqual(missing, [], f"missing orchestrator docs: {missing}")

    def test_slither_like_demo_contract_exists(self) -> None:
        path = self._repo_root() / "docs/orchestrator/slither-like-demo-contract.md"
        self.assertTrue(path.is_file(), "slither-like demo contract doc must exist")
        text = path.read_text(encoding="utf-8")
        self.assertIn("Build me an online slither.io-like game", text)

    def test_orchestrator_docs_contain_required_boundary_phrases(self) -> None:
        combined = self._orchestrator_docs_text().lower()
        missing = [
            phrase
            for phrase in self._REQUIRED_BOUNDARY_PHRASES
            if phrase.lower() not in combined
        ]
        self.assertEqual(
            missing,
            [],
            "orchestrator docs missing required boundary phrases:\n"
            + "\n".join(missing),
        )

    def test_independent_validation_doctrine_documented(self) -> None:
        combined = self._orchestrator_docs_text().lower()
        self.assertIn("independent validation", combined)
        self.assertTrue(
            all(marker in combined for marker in self._INDEPENDENT_VALIDATION_MARKERS),
            "independent validation doctrine must mention audit independence",
        )
        self.assertIn("owner decision remains", combined)

    def test_orchestrator_docs_do_not_require_runner_modification(self) -> None:
        combined = self._orchestrator_docs_text().lower()
        violations = [
            phrase
            for phrase in self._FORBIDDEN_RUNNER_MODIFICATION_PHRASES
            if phrase in combined
        ]
        self.assertEqual(
            violations,
            [],
            "orchestrator docs must not require runner modification:\n"
            + "\n".join(violations),
        )

    def test_future_orchestrator_cli_marked_not_implemented(self) -> None:
        repo_root = self._repo_root()
        contract = (
            repo_root / "docs/orchestrator/goal-to-planning-workspace-contract.md"
        ).read_text(encoding="utf-8")
        lowered = contract.lower()
        for command in self._FUTURE_CLI_COMMANDS:
            if command in lowered:
                idx = lowered.index(command)
                window = lowered[max(0, idx - 200) : idx + len(command) + 200]
                self.assertTrue(
                    "not implemented" in window or "future work" in window,
                    f"{command!r} must be marked as not implemented or future work",
                )

    def test_goal_intake_cli_marked_as_scaffold_only(self) -> None:
        repo_root = self._repo_root()
        doc = (
            repo_root / "docs/orchestrator/goal-intake-artifact.md"
        ).read_text(encoding="utf-8")
        self.assertIn("agent-os orchestrator intake", doc)
        lowered = doc.lower()
        plain = lowered.replace("**", "")
        self.assertIn("deterministic scaffold", lowered)
        self.assertIn("does not call an llm", plain)
        self.assertIn("does not create a planning workspace", plain)
        self.assertIn("does_not_create_runner_proposal", doc)
        self.assertIn("does_not_invoke_executor", doc)


if __name__ == "__main__":
    unittest.main()
