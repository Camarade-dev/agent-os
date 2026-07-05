"""Agent OS command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent_os import __version__
from agent_os.planning import (
    PLANNING_OWNER_DECISIONS,
    init_planning_workspace,
    list_planning_owner_decisions,
    progress_planning_workspace,
    record_planning_owner_decision,
    status_planning_workspace,
    transition_planning_workspace,
    validate_planning_workspace,
)
from agent_os.workspace import (
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


def _project_path(value: str | None) -> Path:
    return Path(value or ".").resolve()


def cmd_init(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    root = init_workspace(project)
    print(f"initialized workspace: {root}")
    return 0


def cmd_mission(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    run_id = create_mission(project, args.run_id)
    print(f"created run: {run_id}")
    print(f"path: {project / '.agent-os' / 'runs' / run_id}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    workspace = project / ".agent-os"
    if not workspace.is_dir():
        print("no workspace found (run `agent-os init` first)")
        return 1

    runs = list_runs(project)
    if not runs:
        print("no runs")
        return 0

    for run in runs:
        status = run.get("status", "open")
        run_id = run.get("run_id", "?")
        blocked = run.get("missing", [])
        line = f"{run_id}: {status}"
        if blocked:
            line += f" (blocked: {', '.join(blocked)})"
        print(line)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        record_audit(project, args.run_id, args.verdict, args.notes or "")
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"audit recorded for run {args.run_id}: {args.verdict}")
    return 0


def cmd_evidence_list(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        output = list_evidence(project, args.run_id)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(output)
    return 0


def cmd_evidence_add(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        add_evidence(
            project,
            args.run_id,
            args.note,
            evidence_type=args.type,
            artifact_path=args.artifact_path,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"evidence added for run {args.run_id}")
    return 0


def cmd_evidence_add_file(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        add_evidence_file(project, args.run_id, args.file, args.note)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"file evidence registered for run {args.run_id}")
    return 0


def cmd_evidence_add_command_output(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        add_evidence_command_output(
            project,
            args.run_id,
            args.command,
            args.output_file,
            args.note,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"command-output evidence registered for run {args.run_id}")
    return 0


def cmd_evidence_snapshot_git(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        snapshot_evidence_git(
            project,
            args.run_id,
            args.note,
            repo=args.repo,
            include_diff_stat=args.include_diff_stat,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"git snapshot evidence added for run {args.run_id}")
    return 0


def cmd_planning_init(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        dest = init_planning_workspace(project, args.plan_id)
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"created planning workspace: {dest}")
    print("status: DRAFT")
    print("next step: fill context-pack.md")
    print("note: no runs were created and no agents were invoked")
    return 0


def cmd_planning_status(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        report = status_planning_workspace(project, args.plan_id)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(report.output)
    return 0 if report.structural_ok else 1


def cmd_planning_validate(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        report = validate_planning_workspace(project, args.plan_id)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(report.output)
    return 0 if report.valid else 1


def cmd_planning_decisions_list(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        report = list_planning_owner_decisions(project, args.plan_id)
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(report.output)
    return 0


def cmd_planning_decide(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        result = record_planning_owner_decision(
            project,
            args.plan_id,
            args.decision,
            args.summary,
        )
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(result.output)
    return 0


def cmd_planning_transition(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        result = transition_planning_workspace(
            project,
            args.plan_id,
            args.to_status,
        )
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(result.output)
    return 0


def cmd_planning_progress(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    try:
        result = progress_planning_workspace(
            project,
            args.plan_id,
            args.to_status,
        )
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(result.output)
    return 0


def cmd_close(args: argparse.Namespace) -> int:
    project = _project_path(args.path)
    ok, errors = close_run(project, args.run_id)
    if not ok:
        if len(errors) == 1:
            print(
                f"closure blocked for run {args.run_id}: {errors[0]}",
                file=sys.stderr,
            )
        else:
            print(f"closure blocked for run {args.run_id}:", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
        return 1
    print(f"run closed: {args.run_id}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-os",
        description="Local epistemic protocol for governed agentic execution",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    init_parser = sub.add_parser("init", help="bootstrap .agent-os/ in a target project")
    init_parser.add_argument("path", nargs="?", help="target project directory")
    init_parser.set_defaults(func=cmd_init)

    mission_parser = sub.add_parser("mission", help="create a standardized run from templates")
    mission_parser.add_argument("path", nargs="?", help="target project directory")
    mission_parser.add_argument("--run-id", help="optional explicit run id")
    mission_parser.set_defaults(func=cmd_mission)

    status_parser = sub.add_parser("status", help="report open/closed runs and blocked fields")
    status_parser.add_argument("path", nargs="?", help="target project directory")
    status_parser.set_defaults(func=cmd_status)

    audit_parser = sub.add_parser("audit", help="record an audit verdict for a run")
    audit_parser.add_argument("run_id", help="run identifier")
    audit_parser.add_argument("path", nargs="?", help="target project directory")
    audit_parser.add_argument(
        "--verdict",
        required=True,
        choices=["pass", "fail", "needs_revision"],
        help="audit verdict",
    )
    audit_parser.add_argument("--notes", default="", help="optional audit notes")
    audit_parser.set_defaults(func=cmd_audit)

    close_parser = sub.add_parser("close", help="attempt fail-closed run closure")
    close_parser.add_argument("run_id", help="run identifier")
    close_parser.add_argument("path", nargs="?", help="target project directory")
    close_parser.set_defaults(func=cmd_close)

    evidence_parser = sub.add_parser("evidence", help="evidence capture helpers (registrar only)")
    evidence_sub = evidence_parser.add_subparsers(dest="evidence_command", required=True)

    evidence_add_parser = evidence_sub.add_parser(
        "add",
        help="append a structured evidence block to evidence.md",
    )
    evidence_add_parser.add_argument("run_id", help="run identifier")
    evidence_add_parser.add_argument("path", nargs="?", help="target project directory")
    evidence_add_parser.add_argument("--note", required=True, help="evidence note text")
    evidence_add_parser.add_argument(
        "--type",
        default="note",
        help="evidence type (default: note)",
    )
    evidence_add_parser.add_argument(
        "--path",
        dest="artifact_path",
        help="optional local artifact path reference (not copied)",
    )
    evidence_add_parser.set_defaults(func=cmd_evidence_add)

    evidence_add_file_parser = evidence_sub.add_parser(
        "add-file",
        help="register an existing local file path as evidence (reference only)",
    )
    evidence_add_file_parser.add_argument("run_id", help="run identifier")
    evidence_add_file_parser.add_argument("path", nargs="?", help="target project directory")
    evidence_add_file_parser.add_argument(
        "--file",
        required=True,
        help="path to an existing local file (not copied)",
    )
    evidence_add_file_parser.add_argument(
        "--note",
        required=True,
        help="evidence claim text for the referenced file",
    )
    evidence_add_file_parser.set_defaults(func=cmd_evidence_add_file)

    evidence_add_cmd_parser = evidence_sub.add_parser(
        "add-command-output",
        help="register a declared command and owner-supplied output file (no execution)",
    )
    evidence_add_cmd_parser.add_argument("run_id", help="run identifier")
    evidence_add_cmd_parser.add_argument("path", nargs="?", help="target project directory")
    evidence_add_cmd_parser.add_argument(
        "--command",
        required=True,
        help="declared command string (not executed)",
    )
    evidence_add_cmd_parser.add_argument(
        "--output-file",
        required=True,
        help="path to an existing output file (read as text; not created by running --command)",
    )
    evidence_add_cmd_parser.add_argument(
        "--note",
        required=True,
        help="evidence claim text for the command output",
    )
    evidence_add_cmd_parser.set_defaults(func=cmd_evidence_add_command_output)

    evidence_list_parser = evidence_sub.add_parser(
        "list",
        help="print a read-only index of structured evidence entries",
    )
    evidence_list_parser.add_argument("run_id", help="run identifier")
    evidence_list_parser.add_argument("path", nargs="?", help="target project directory")
    evidence_list_parser.set_defaults(func=cmd_evidence_list)

    evidence_snapshot_git_parser = evidence_sub.add_parser(
        "snapshot-git",
        help="capture read-only git state into evidence.md (fixed allowlist only)",
    )
    evidence_snapshot_git_parser.add_argument("run_id", help="run identifier")
    evidence_snapshot_git_parser.add_argument("path", nargs="?", help="target project directory")
    evidence_snapshot_git_parser.add_argument(
        "--note",
        required=True,
        help="evidence claim text for the git snapshot",
    )
    evidence_snapshot_git_parser.add_argument(
        "--repo",
        help="git repository path to inspect (default: target project)",
    )
    evidence_snapshot_git_parser.add_argument(
        "--include-diff-stat",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="include git diff --stat output (default: true)",
    )
    evidence_snapshot_git_parser.set_defaults(func=cmd_evidence_snapshot_git)

    planning_parser = sub.add_parser(
        "planning",
        help="planning workspace bootstrap (registrar only; no execution)",
    )
    planning_sub = planning_parser.add_subparsers(dest="planning_command", required=True)

    planning_init_parser = planning_sub.add_parser(
        "init",
        help="bootstrap a DRAFT planning workspace under .agent-os/planning/<plan-id>/",
    )
    planning_init_parser.add_argument("plan_id", help="plan identifier (filesystem-safe slug)")
    planning_init_parser.add_argument("path", nargs="?", help="target project directory")
    planning_init_parser.set_defaults(func=cmd_planning_init)

    planning_status_parser = planning_sub.add_parser(
        "status",
        help="inspect an existing planning workspace (read-only)",
    )
    planning_status_parser.add_argument("plan_id", help="plan identifier (filesystem-safe slug)")
    planning_status_parser.add_argument("path", nargs="?", help="target project directory")
    planning_status_parser.set_defaults(func=cmd_planning_status)

    planning_validate_parser = planning_sub.add_parser(
        "validate",
        help="weak read-only validation of a planning workspace (no execution approval)",
    )
    planning_validate_parser.add_argument("plan_id", help="plan identifier (filesystem-safe slug)")
    planning_validate_parser.add_argument("path", nargs="?", help="target project directory")
    planning_validate_parser.set_defaults(func=cmd_planning_validate)

    planning_decisions_parser = planning_sub.add_parser(
        "decisions",
        help="read-only owner decision listing (no execution)",
    )
    planning_decisions_sub = planning_decisions_parser.add_subparsers(
        dest="planning_decisions_command",
        required=True,
    )

    planning_decisions_list_parser = planning_decisions_sub.add_parser(
        "list",
        help="list owner decision records in a planning workspace (read-only)",
    )
    planning_decisions_list_parser.add_argument(
        "plan_id",
        help="plan identifier (filesystem-safe slug)",
    )
    planning_decisions_list_parser.add_argument(
        "path",
        nargs="?",
        help="target project directory",
    )
    planning_decisions_list_parser.set_defaults(func=cmd_planning_decisions_list)

    planning_decide_parser = planning_sub.add_parser(
        "decide",
        help="record an owner decision in a planning workspace (evidence only)",
    )
    planning_decide_parser.add_argument("plan_id", help="plan identifier (filesystem-safe slug)")
    planning_decide_parser.add_argument("path", nargs="?", help="target project directory")
    planning_decide_parser.add_argument(
        "--decision",
        required=True,
        choices=list(PLANNING_OWNER_DECISIONS),
        help="owner decision value",
    )
    planning_decide_parser.add_argument(
        "--summary",
        required=True,
        help="short owner decision summary",
    )
    planning_decide_parser.set_defaults(func=cmd_planning_decide)

    planning_transition_parser = planning_sub.add_parser(
        "transition",
        help="apply an explicit manifest transition authorized by owner decision",
    )
    planning_transition_parser.add_argument(
        "plan_id",
        help="plan identifier (filesystem-safe slug)",
    )
    planning_transition_parser.add_argument("path", nargs="?", help="target project directory")
    planning_transition_parser.add_argument(
        "--to",
        dest="to_status",
        required=True,
        help="target manifest status (APPROVED_FOR_RUN_PROPOSALS, BLOCKED, or CLOSED)",
    )
    planning_transition_parser.set_defaults(func=cmd_planning_transition)

    planning_progress_parser = planning_sub.add_parser(
        "progress",
        help="apply an explicit artifact-progress manifest transition (no owner decision)",
    )
    planning_progress_parser.add_argument(
        "plan_id",
        help="plan identifier (filesystem-safe slug)",
    )
    planning_progress_parser.add_argument("path", nargs="?", help="target project directory")
    planning_progress_parser.add_argument(
        "--to",
        dest="to_status",
        required=True,
        help=(
            "target artifact-readiness status "
            "(CONTEXT_READY, SPEC_READY, PLAN_READY, or PLANNING_AUDIT_READY)"
        ),
    )
    planning_progress_parser.set_defaults(func=cmd_planning_progress)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
