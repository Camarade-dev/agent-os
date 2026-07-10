"""Manual browser-runtime capability diagnostic (PART P.72).

Reports what the Chromium CDP provider can detect about the local
environment -- discovery source, executable path/basename, and version --
without ever launching a target application, opening a loopback server, or
touching a workspace. Safe to run at any time to answer "is a supported
browser available on this machine right now?"
"""

from __future__ import annotations

import json
import sys
from typing import Any

from admissible.browser_runtime.chromium_provider import ChromiumCdpRuntimeProvider


def diagnose_browser_capability() -> dict[str, Any]:
    """Return the capability report a real verification run would see."""

    provider = ChromiumCdpRuntimeProvider()
    return provider.detect_capability().to_dict()


def main(argv: list[str] | None = None) -> int:
    report = diagnose_browser_capability()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("available") else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
