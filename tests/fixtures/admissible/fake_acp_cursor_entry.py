"""Deterministic fake ``cursor-agent`` entry bundle for the native ACP lane.

The ACP attestation pins the exact server argv ``<node.exe> <index.js> acp``, so
the executor's real spawn path can only be exercised end to end by an
``index.js`` that behaves like the entry bundle.  This fixture is that entry: it
serves exactly one ACP turn through :mod:`fake_acp_server_process`, which
performs the mission's physical effects in its own working directory *while
answering the prompt*.

Ordering matters and is not incidental.  A real provider does the mission's work
after ``session/prompt``, never during startup, and the client's complete
pre-prompt workspace identity refuses to submit a mission into a workspace the
server already touched.  Materializing at entry time would trip that boundary
for a reason no real run has, so the plan is forwarded to the server instead.

No Cursor agent and no model is ever contacted; the mission effects are read
from a caller-written plan file so the test, not this fixture, owns them.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import runpy
import sys

FAKE_SERVER = str(Path(__file__).with_name("fake_acp_server_process.py"))


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
    server_argv = [FAKE_SERVER, "--scenario", args.scenario, "--plan", args.plan]
    if args.record is not None:
        server_argv += ["--record", args.record]
    sys.argv = server_argv
    runpy.run_path(FAKE_SERVER, run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main())
