"""Read-only interactive operator preview of the archived generated application.

This is a *manual observation surface*, not a second automated verification. It
lets the operator open and play the exact eight-file archived Neon Serpents
application from the loopback review UI, serving **exact archived bytes** with no
rewriting, bundling, or regeneration.

Containment is enforced server-side and does not rely on the CSP:

* only the eight persisted ``FileEvidence`` target paths are serveable (strict
  allowlist by exact, forward-slash, unquoted relative path);
* every file is re-hashed and verified against its authoritative
  ``FileEvidence`` sha256 immediately before it is served;
* the resolved file must stay inside the archive ``target/`` directory
  (symlink-escape defense);
* if archive or target integrity is uncertain, the preview is disabled and
  explicit uncertainty is returned.

The CSP is an *additional* network-containment layer (block external
connections, forms, objects, framing, workers, ``<base>`` navigation), never a
substitute for the above.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

# Fixed MIME handling for the archived application's file kinds. Anything not
# listed is served as an opaque octet-stream (still nosniff-guarded).
_MIME_BY_SUFFIX = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".md": "text/plain; charset=utf-8",
}

PREVIEW_INDEX = "index.html"

# Restrictive CSP: permit the self-hosted HTML/CSS/JS game to run while blocking
# external connections and side effects. Intentionally narrow.
PREVIEW_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'none'; "
    "object-src 'none'; "
    "frame-src 'none'; "
    "child-src 'none'; "
    "worker-src 'none'; "
    "form-action 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "manifest-src 'none'"
)

PREVIEW_SECURITY_HEADERS = {
    "Content-Security-Policy": PREVIEW_CSP,
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
}


class PreviewError(Exception):
    """Base for preview refusals; carries an HTTP status and machine code."""

    def __init__(self, status: int, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.status = status
        self.code = code
        self.detail = detail


class PreviewRefused(PreviewError):
    """The requested path is not an allowlisted, integrity-verified target file."""


class PreviewUncertain(PreviewError):
    """Archive/target integrity is not sound; the preview is disabled."""


@dataclass(frozen=True)
class PreviewFile:
    relative_path: str
    data: bytes
    content_type: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _mime_for(rel: str) -> str:
    return _MIME_BY_SUFFIX.get(Path(rel).suffix.lower(), "application/octet-stream")


def build_allowlist(model) -> dict[str, str]:
    """Return {relative_path: expected_sha256} for the persisted target files.

    Derived solely from authoritative ``FileEvidence`` (the model's
    ``facts.target_files``). Paths are the exact forward-slash relative paths.
    """

    allow: dict[str, str] = {}
    for entry in model.facts.get("target_files", []):
        rel = entry.get("path")
        sha = entry.get("expected_sha256")
        if isinstance(rel, str) and isinstance(sha, str) and rel and sha:
            allow[rel] = sha
    return allow


def _reject_raw_path(raw: str) -> None:
    """Refuse obviously hostile shapes before any allowlist/normalization."""

    if raw == "":
        raise PreviewRefused(404, "empty_path")
    if "\x00" in raw:
        raise PreviewRefused(400, "nul_byte")
    if "\\" in raw:  # backslash / alternate separator / windows path
        raise PreviewRefused(404, "backslash_separator")
    if raw.startswith("/"):  # absolute POSIX path
        raise PreviewRefused(404, "absolute_path")
    # Drive-letter absolute path (e.g. "C:foo" or "C:/foo") after unquote.
    if len(raw) >= 2 and raw[1] == ":" and raw[0].isalpha():
        raise PreviewRefused(404, "drive_path")


def resolve_preview_file(
    *,
    archive_root: Path,
    model,
    requested: str,
) -> PreviewFile:
    """Resolve a preview request to exact, hash-verified archived bytes.

    ``requested`` is the raw path segment after the ``/preview/`` prefix (still
    percent-encoded). ``/preview/`` maps to ``index.html``.

    Raises :class:`PreviewUncertain` if integrity is not sound, or
    :class:`PreviewRefused` for anything not on the verified target allowlist.
    """

    # 1. Integrity gate: overall archive AND per-target integrity must be sound.
    if not model.integrity.get("ok", False):
        raise PreviewUncertain(409, "archive_integrity_uncertain", "archive integrity is not sound")

    allowlist = build_allowlist(model)
    if not allowlist:
        raise PreviewUncertain(409, "no_target_evidence", "no persisted target FileEvidence")

    # 2. Normalize the request to a candidate relative path.
    raw = requested
    # `/preview/` (empty remainder) resolves to the archived index.html.
    if raw in ("", "/"):
        candidate = PREVIEW_INDEX
    else:
        decoded = unquote(raw)
        _reject_raw_path(decoded)
        # Reject any traversal segment explicitly (defense in depth; the
        # allowlist below is already immune to traversal).
        parts = decoded.split("/")
        if any(p in ("..", ".") or p == "" for p in parts):
            raise PreviewRefused(404, "traversal_or_empty_segment")
        candidate = decoded

    # 3. Strict allowlist membership (exact FileEvidence path).
    if candidate not in allowlist:
        raise PreviewRefused(404, "not_allowlisted", candidate)

    # 4. Per-target integrity must be individually sound.
    entry = next((e for e in model.facts.get("target_files", []) if e.get("path") == candidate), None)
    if entry is None or not entry.get("integrity_ok", False):
        raise PreviewUncertain(409, "target_integrity_uncertain", candidate)

    # 5. Symlink-escape defense: the resolved file must stay under target/.
    target_dir = (archive_root / "target").resolve()
    file_path = (archive_root / "target" / candidate)
    try:
        resolved = file_path.resolve()
        resolved.relative_to(target_dir)
    except (ValueError, OSError):
        raise PreviewRefused(404, "outside_target_dir", candidate)
    if not resolved.is_file() or file_path.is_symlink():
        raise PreviewRefused(404, "not_a_regular_file", candidate)

    # 6. Serve exact bytes, hash-verified against authoritative FileEvidence.
    data = resolved.read_bytes()
    expected = allowlist[candidate]
    if _sha256(data) != expected:
        # Bytes changed since the model was built -> fail closed, do not serve.
        raise PreviewUncertain(409, "target_hash_mismatch", candidate)

    return PreviewFile(relative_path=candidate, data=data, content_type=_mime_for(candidate))
