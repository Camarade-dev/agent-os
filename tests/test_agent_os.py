"""Tests for Agent OS v0 CLI and validation."""

from __future__ import annotations

import io
import json
import re
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_os.cli import main
from agent_os.paths import TEMPLATE_FILES, planning_path, run_path
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


class OrchestratorDocsGuardTests(unittest.TestCase):
    """Guard doctrine for CORE_ORCHESTRATOR_001 goal-to-planning workspace contract."""

    _ORCHESTRATOR_DOCS: tuple[str, ...] = (
        "docs/orchestrator/goal-to-planning-workspace-contract.md",
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
        "agent-os orchestrator intake",
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


if __name__ == "__main__":
    unittest.main()
