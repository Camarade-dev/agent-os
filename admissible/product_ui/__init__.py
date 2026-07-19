"""Source-controlled static presentation assets for the local G3 launcher."""
from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent
_ASSET_FILES = {
    "/ui/assets/app.css": ("app.css", "text/css; charset=utf-8"),
    "/ui/assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


def render_document(*, csrf_nonce: str, authorization_mode: str) -> bytes:
    """Render the fixed shell with transport-owned, HTML-escaped bootstrap facts."""
    from html import escape

    source = (_ROOT / "index.html").read_text(encoding="utf-8")
    return source.replace("{{CSRF_NONCE}}", escape(csrf_nonce, quote=True)).replace(
        "{{AUTHORIZATION_MODE}}", escape(authorization_mode, quote=True)
    ).encode("utf-8")


def get_asset(path: str) -> tuple[bytes, str] | None:
    """Return only an explicitly allowlisted local asset."""
    selected = _ASSET_FILES.get(path)
    if selected is None:
        return None
    filename, content_type = selected
    return (_ROOT / filename).read_bytes(), content_type


__all__ = ["get_asset", "render_document"]
