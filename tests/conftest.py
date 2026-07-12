"""Session-wide regression guard: never launch a browser merely to probe its version.

Wraps ``subprocess.Popen.__init__`` for the whole ``tests/`` session and raises
before the OS process is created if the call targets an allowlisted
Chromium-family executable with a version-probe flag (``--version``/``-version``).
Real runtime launches (``ProcessTreeHandle`` in
admissible/browser_runtime/process_cleanup.py) never pass a version flag, so
this never interferes with an explicitly authorized runtime verification
launch -- only with the exact defect pattern this guard exists to catch.
"""

from __future__ import annotations

import os
import subprocess

_BROWSER_BASENAMES = {
    "chrome.exe",
    "chrome",
    "msedge.exe",
    "msedge",
    "chromium.exe",
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "microsoft-edge",
    "microsoft-edge-stable",
}
_VERSION_FLAGS = {"--version", "-version"}

_original_popen_init = subprocess.Popen.__init__


def _guarded_popen_init(self, args, *a, **kw):
    argv = args if isinstance(args, (list, tuple)) else [args]
    if argv:
        basename = os.path.basename(str(argv[0])).lower()
        if basename in _BROWSER_BASENAMES and any(str(item) in _VERSION_FLAGS for item in argv[1:]):
            raise AssertionError(
                f"blocked an attempt to launch a browser executable merely to probe its version: {argv!r}"
            )
    return _original_popen_init(self, args, *a, **kw)


subprocess.Popen.__init__ = _guarded_popen_init
