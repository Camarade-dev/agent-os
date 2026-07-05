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
from agent_os.planning import init_planning_workspace, status_planning_workspace, validate_plan_id
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


if __name__ == "__main__":
    unittest.main()
