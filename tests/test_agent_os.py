"""Tests for Agent OS v0 CLI and validation."""

from __future__ import annotations

import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_os.cli import main
from agent_os.paths import TEMPLATE_FILES, run_path
from agent_os.validate import validate_run_for_closure
from agent_os.workspace import (
    add_evidence,
    close_run,
    create_mission,
    init_workspace,
    list_runs,
    record_audit,
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


if __name__ == "__main__":
    unittest.main()
