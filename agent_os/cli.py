"""Agent OS command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agent_os import __version__
from agent_os.workspace import (
    add_evidence,
    close_run,
    create_mission,
    init_workspace,
    list_runs,
    record_audit,
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
