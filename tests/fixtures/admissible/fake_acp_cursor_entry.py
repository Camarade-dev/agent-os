"""Deterministic fake ``cursor-agent`` entry bundle for the native ACP lane.

The ACP attestation pins the exact server argv ``<node.exe> <index.js> acp``, so
the executor's real spawn path can only be exercised end to end by an
``index.js`` that behaves like the entry bundle.  This fixture is that entry: it
performs the mission's physical effects in its own working directory and then
serves exactly one ACP turn through :mod:`fake_acp_server_process`.

No Cursor agent and no model is ever contacted; the mission effects are read
from a caller-written plan file so the test, not this fixture, owns them.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

FAKE_SERVER = str(Path(__file__).with_name("fake_acp_server_process.py"))

_GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "Deterministic Fake Executor",
    "GIT_AUTHOR_EMAIL": "fake@invalid.example",
    "GIT_COMMITTER_NAME": "Deterministic Fake Executor",
    "GIT_COMMITTER_EMAIL": "fake@invalid.example",
    "GIT_AUTHOR_DATE": "2026-01-02T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-02T00:00:00Z",
}


def _materialize(plan: dict) -> None:
    """Apply the plan's files and optional single commit inside the cwd."""

    workspace = Path.cwd()
    for relative, text in sorted(plan.get("files", {}).items()):
        target = workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    message = plan.get("commit_message")
    if message is None:
        return
    environment = dict(os.environ)
    environment.update(_GIT_IDENTITY)
    for argv in (["git", "add", "--all"], ["git", "commit", "--quiet", "-m", message]):
        subprocess.run(
            argv, cwd=workspace, env=environment, shell=False, check=True,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("subcommand")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--scenario", default="success")
    parser.add_argument("--record", default=None)
    args = parser.parse_args()
    if args.subcommand != "acp":
        # The attested argv ends in ``acp``; anything else is not this entry's
        # contract and must not be served.
        return 2
    _materialize(json.loads(Path(args.plan).read_text(encoding="utf-8")))
    server_argv = [FAKE_SERVER, "--scenario", args.scenario]
    if args.record is not None:
        server_argv += ["--record", args.record]
    sys.argv = server_argv
    runpy.run_path(FAKE_SERVER, run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main())
