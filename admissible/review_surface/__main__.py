"""Launch the Slice-5B operator review surface against a persisted archive.

Usage::

    python -m admissible.review_surface <archive_root> [--port N] [--disposition-dir DIR]

Binds to loopback only, prints the exact local URL, and serves until Ctrl-C.
It never invokes a provider, verifier, executor, retry, or repair, and never
mutates the archive. The operator chooses ACCEPT_RESULT / REJECT_RESULT in the
browser; this launcher never chooses on their behalf.
"""

from __future__ import annotations

import argparse
import sys
import time

from admissible.review_surface.server import ReviewServer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="admissible.review_surface")
    parser.add_argument("archive_root", help="path to the persisted run archive")
    parser.add_argument("--port", type=int, default=0, help="loopback port (0 = ephemeral)")
    parser.add_argument("--disposition-dir", default=None, help="directory for the durable disposition (default: sibling <name>.review.d)")
    args = parser.parse_args(argv)

    server = ReviewServer(args.archive_root, disposition_dir=args.disposition_dir, port=args.port)
    server.start()
    model = server.context.model
    print("Admissible V0 — Operator Review Surface (Slice 5B)")
    print(f"  archive:      {server.archive_root}")
    print(f"  session:      {model.session_id}")
    print(f"  disposition:  {server.disposition_dir}")
    print(f"  integrity:    {'SOUND' if model.integrity.get('ok') else 'UNCERTAIN'}")
    print(f"  URL:          {server.url}")
    print("  (loopback only; Ctrl-C to stop)")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nstopping…")
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
