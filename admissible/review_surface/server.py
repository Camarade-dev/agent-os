"""Loopback-only HTTP review surface for a persisted V0 run (Slice 5B).

A tiny stdlib HTTP server bound *exclusively* to an exact loopback address. It
exposes only a fixed set of read endpoints plus one narrowly-scoped terminal
disposition endpoint. It:

* binds only to ``127.0.0.1`` (never a wildcard / external interface);
* serves only the review model and a *fixed whitelist* of evidence artifacts —
  never arbitrary repository files, with no path-traversal surface;
* makes no external network requests;
* requires an unguessable per-launch review token for the state-changing POST;
* validates loopback origin, expected session identity, and expected evidence
  fingerprints on every mutation;
* spawns no child processes and shuts down cleanly.

The server holds a :class:`ReviewContext` (immutable review model + disposition
store). It never invokes a provider, verifier, executor, retry, or repair, and
it never mutates the archive.
"""

from __future__ import annotations

import hmac
import json
import secrets
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from admissible.review_surface.disposition_store import (
    DispositionConflict,
    DispositionCorrupt,
    ReviewDispositionStore,
)
from admissible.review_surface.evidence_model import (
    DOM_ARTIFACT,
    SCREENSHOT_ARTIFACT,
    ReviewModel,
    build_review_model,
)
from admissible.review_surface.preview import (
    PREVIEW_SECURITY_HEADERS,
    PreviewError,
    PreviewRefused,
    PreviewUncertain,
    resolve_preview_file,
)

LOOPBACK_HOST = "127.0.0.1"

# Fixed evidence artifact whitelist: logical name -> (content type, is_binary).
_EVIDENCE_CONTENT_TYPES = {
    SCREENSHOT_ARTIFACT: ("image/png", True),
    DOM_ARTIFACT: ("text/html; charset=utf-8", False),
}


@dataclass
class ReviewContext:
    archive_root: Path
    disposition_dir: Path
    token: str
    _model: ReviewModel

    @property
    def session_id(self) -> str:
        return self._model.session_id

    def rebuild_model(self) -> ReviewModel:
        """Re-read the model from disk (evidence is authoritative, never cached blindly)."""

        self._model = build_review_model(self.archive_root)
        return self._model

    @property
    def model(self) -> ReviewModel:
        return self._model

    def store(self) -> ReviewDispositionStore:
        return ReviewDispositionStore(self.disposition_dir)

    def artifact_path(self, name: str) -> Path | None:
        """Resolve a *whitelisted* evidence artifact to a concrete file path.

        Only exact whitelist keys are accepted; anything else (including any
        traversal attempt) returns ``None`` without touching the filesystem.
        """

        if name not in _EVIDENCE_CONTENT_TYPES:
            return None
        artifacts_dir = self.archive_root / "runtime-store" / f"{self.session_id}.runtime.d"
        candidate = artifacts_dir / name
        # Defensive containment: the resolved path must stay inside the artifacts dir.
        try:
            candidate.resolve().relative_to(artifacts_dir.resolve())
        except ValueError:
            return None
        return candidate if candidate.is_file() else None


class _Handler(BaseHTTPRequestHandler):
    server_version = "AdmissibleReviewSurface/1.0"
    protocol_version = "HTTP/1.1"

    # -- helpers --------------------------------------------------------
    @property
    def ctx(self) -> ReviewContext:
        return self.server.review_context  # type: ignore[attr-defined]

    def _client_is_loopback(self) -> bool:
        host = self.client_address[0]
        return host in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    def _host_header_is_loopback(self) -> bool:
        host_header = self.headers.get("Host", "")
        hostname = host_header.rsplit(":", 1)[0] if host_header else ""
        return hostname in ("127.0.0.1", "localhost", "[::1]", "::1")

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _refuse_json_close(self, status: int, payload: Any) -> None:
        """Emit a deterministic JSON refusal and close the connection.

        Used for POST guards that return *before* the (possibly non-empty)
        declared request body is read. Under HTTP/1.1 keep-alive the unread
        body would otherwise linger in the socket; closing the connection with
        an explicit ``Connection: close`` avoids the Windows reset that would
        surface to a client as ``ConnectionAbortedError`` even though the
        request was safely refused. Status and JSON error semantics are
        preserved; the body is never drained.
        """

        self.close_connection = True
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, status: int, data: bytes, content_type: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _token_ok(self) -> bool:
        supplied = self.headers.get("X-Review-Token", "")
        return bool(supplied) and hmac.compare_digest(supplied, self.ctx.token)

    def log_message(self, *args: Any) -> None:  # silence default stderr logging
        return

    # -- GET ------------------------------------------------------------
    def do_GET(self) -> None:
        path = urlparse(self.path).path
        # Loopback client and loopback Host are independent, both-required
        # preconditions for *any* GET. Refuse before reading or returning any
        # archive data, JSON, HTML, screenshot, DOM, or target bytes. The Host
        # policy is exactly the one enforced on the mutation endpoint.
        if not self._client_is_loopback():
            self._send_json(403, {"error": "non_loopback_client"})
            return
        if not self._host_header_is_loopback():
            self._send_json(403, {"error": "non_loopback_host"})
            return

        if path == "/" or path == "/index.html":
            html = _render_index_html(self.ctx.token).encode("utf-8")
            self._send_bytes(200, html, "text/html; charset=utf-8")
            return

        if path == "/api/review":
            model = self.ctx.rebuild_model()
            existing = self.ctx.store().load(self.ctx.session_id)
            self._send_json(
                200,
                {
                    "model": model.to_dict(),
                    "disposition": existing.to_dict() if existing else None,
                },
            )
            return

        if path == "/api/disposition":
            try:
                existing = self.ctx.store().load(self.ctx.session_id)
            except DispositionCorrupt as exc:
                self._send_json(409, {"error": "disposition_corrupt", "detail": str(exc)})
                return
            self._send_json(200, {"disposition": existing.to_dict() if existing else None})
            return

        if path.startswith("/api/evidence/"):
            name = path[len("/api/evidence/"):]
            self._serve_evidence(name)
            return

        if path == "/preview" or path == "/preview/":
            self._serve_preview("")
            return
        if path.startswith("/preview/"):
            self._serve_preview(path[len("/preview/"):])
            return

        self._send_json(404, {"error": "not_found"})

    def _serve_preview(self, requested: str) -> None:
        # Rebuild the model from evidence so the allowlist and hashes are
        # authoritative for THIS request (never a stale cache).
        model = self.ctx.rebuild_model()
        try:
            preview = resolve_preview_file(
                archive_root=self.ctx.archive_root,
                model=model,
                requested=requested,
            )
        except PreviewUncertain as exc:
            self._send_preview_error(exc)
            return
        except PreviewRefused as exc:
            self._send_preview_error(exc)
            return
        except PreviewError as exc:  # pragma: no cover - defensive catch-all
            self._send_preview_error(exc)
            return
        self._send_bytes(
            200,
            preview.data,
            preview.content_type,
            extra=dict(PREVIEW_SECURITY_HEADERS),
        )

    def _send_preview_error(self, exc: PreviewError) -> None:
        # Even refusals carry the containment headers, and never leak bytes.
        body = json.dumps(
            {"error": exc.code, "detail": exc.detail, "preview_disabled": isinstance(exc, PreviewUncertain)},
            ensure_ascii=False,
        ).encode("utf-8")
        self.send_response(exc.status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in PREVIEW_SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _serve_evidence(self, name: str) -> None:
        spec = _EVIDENCE_CONTENT_TYPES.get(name)
        artifact_path = self.ctx.artifact_path(name)
        if spec is None or artifact_path is None:
            self._send_json(404, {"error": "unknown_artifact"})
            return
        content_type, _is_binary = spec
        # Re-verify integrity against the review model before serving: never
        # silently serve evidence that fails its integrity check.
        model = self.ctx.model
        entry = model.evidence_artifacts.get(name, {})
        if not entry.get("integrity_ok", False):
            self._send_json(
                409,
                {
                    "error": "evidence_integrity_failed",
                    "artifact": name,
                    "detail": entry.get("detail", "integrity check failed"),
                },
            )
            return
        data = artifact_path.read_bytes()
        self._send_bytes(200, data, content_type, extra={"X-Evidence-Integrity": "ok"})

    # -- POST -----------------------------------------------------------
    def do_POST(self) -> None:
        path = urlparse(self.path).path
        # Every guard below returns *before* the request body is read, so each
        # refusal closes the connection deterministically (see _refuse_json_close).
        if path != "/api/disposition":
            self._refuse_json_close(404, {"error": "not_found"})
            return

        # Mutation guards: loopback client, loopback Host, launch token.
        if not self._client_is_loopback():
            self._refuse_json_close(403, {"error": "non_loopback_client"})
            return
        if not self._host_header_is_loopback():
            self._refuse_json_close(403, {"error": "non_loopback_host"})
            return
        if not self._token_ok():
            self._refuse_json_close(401, {"error": "invalid_or_missing_token"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._refuse_json_close(400, {"error": "bad_content_length"})
            return
        if length <= 0 or length > 64 * 1024:
            self._refuse_json_close(400, {"error": "bad_request_size"})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"error": "malformed_json"})
            return
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "malformed_json"})
            return

        result = self._apply_disposition(payload)
        self._send_json(result[0], result[1])

    def _apply_disposition(self, payload: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        disposition = payload.get("disposition")
        note = payload.get("note", "") or ""
        expected_session = payload.get("session_id")
        expected_fps = payload.get("expected_fingerprints")

        # Reconstruct authoritative facts fresh from evidence.
        model = self.ctx.rebuild_model()
        actual_fps = model.fingerprints

        # 1. Expected session identity must match the persisted session.
        if expected_session is not None and expected_session != model.session_id:
            return 409, {"error": "session_identity_mismatch"}

        # 2. Expected evidence fingerprints must match what is on disk.
        if not isinstance(expected_fps, dict) or not expected_fps:
            return 400, {"error": "missing_expected_fingerprints"}
        for key, value in expected_fps.items():
            if actual_fps.get(key) != value:
                return 409, {"error": "evidence_fingerprint_mismatch", "field": key}

        # 3. Evidence integrity must be sound to attach a durable disposition.
        if model.uncertain:
            return 409, {"error": "evidence_uncertain", "detail": "archive integrity is not sound"}

        if disposition not in ("ACCEPT_RESULT", "REJECT_RESULT"):
            return 400, {"error": "invalid_disposition"}

        try:
            record = self.ctx.store().record(
                session_id=model.session_id,
                disposition=disposition,
                evidence_fingerprints=dict(actual_fps),
                note=str(note),
            )
        except DispositionConflict as exc:
            return 409, {"error": "contradictory_disposition", "detail": str(exc)}
        except DispositionCorrupt as exc:
            return 409, {"error": "disposition_corrupt", "detail": str(exc)}
        return 200, {"disposition": record.to_dict()}


class ReviewServer:
    """A loopback-bound review server with explicit start/stop lifecycle."""

    def __init__(
        self,
        archive_root: str | Path,
        *,
        disposition_dir: str | Path | None = None,
        port: int = 0,
        token: str | None = None,
    ) -> None:
        self.archive_root = Path(archive_root)
        if disposition_dir is None:
            disposition_dir = self.archive_root.parent / f"{self.archive_root.name}.review.d"
        self.disposition_dir = Path(disposition_dir)
        self.token = token or secrets.token_urlsafe(32)
        model = build_review_model(self.archive_root)
        self._context = ReviewContext(
            archive_root=self.archive_root,
            disposition_dir=self.disposition_dir,
            token=self.token,
            _model=model,
        )
        self._httpd = ThreadingHTTPServer((LOOPBACK_HOST, port), _Handler)
        # Attach context so handlers can reach it.
        self._httpd.review_context = self._context  # type: ignore[attr-defined]
        self._thread: threading.Thread | None = None

    @property
    def context(self) -> ReviewContext:
        return self._context

    @property
    def address(self) -> tuple[str, int]:
        return self._httpd.server_address  # type: ignore[return-value]

    @property
    def url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}/"

    def start(self) -> "ReviewServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="review-surface", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def __enter__(self) -> "ReviewServer":
        return self.start()

    def __exit__(self, *exc: Any) -> None:
        self.stop()


def launch_review_server(
    archive_root: str | Path,
    *,
    disposition_dir: str | Path | None = None,
    port: int = 0,
    token: str | None = None,
) -> ReviewServer:
    """Build and start a review server (caller is responsible for ``stop()``)."""

    return ReviewServer(
        archive_root, disposition_dir=disposition_dir, port=port, token=token
    ).start()


def _render_index_html(token: str) -> str:
    # The token is embedded so the same-origin page can authorize the single
    # mutation. It is safe here: the page is only reachable over loopback.
    return _INDEX_HTML_TEMPLATE.replace("__REVIEW_TOKEN__", token)


_INDEX_HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admissible V0 — Operator Review</title>
<style>
  :root{ --bg:#0b0e14; --panel:#141a24; --line:#232c3a; --text:#e6edf3; --dim:#8a97a8;
    --ok:#3fb950; --warn:#d29922; --bad:#f85149; --accent:#58a6ff; }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);font-family:"Segoe UI",system-ui,sans-serif;line-height:1.5}
  header{padding:1rem 1.5rem;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:5}
  h1{font-size:1.1rem;margin:0;letter-spacing:.02em}
  .sub{color:var(--dim);font-size:.85rem;margin-top:.25rem}
  main{max-width:1080px;margin:0 auto;padding:1.5rem;display:grid;gap:1.25rem}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:1rem 1.25rem}
  .card h2{font-size:.8rem;text-transform:uppercase;letter-spacing:.12em;color:var(--dim);margin:0 0 .75rem}
  table{width:100%;border-collapse:collapse;font-size:.85rem}
  td,th{text-align:left;padding:.35rem .5rem;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--dim);font-weight:600;width:42%}
  code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:.8rem;word-break:break-all}
  .pill{display:inline-block;padding:.1rem .55rem;border-radius:999px;font-size:.75rem;font-weight:700}
  .pill.ok{background:rgba(63,185,80,.15);color:var(--ok)}
  .pill.bad{background:rgba(248,81,73,.15);color:var(--bad)}
  .pill.warn{background:rgba(210,153,34,.15);color:var(--warn)}
  .banner{border-radius:8px;padding:.9rem 1.1rem;font-weight:600}
  .banner.ok{background:rgba(63,185,80,.12);border:1px solid var(--ok)}
  .banner.bad{background:rgba(248,81,73,.12);border:1px solid var(--bad)}
  pre{background:#0d1117;border:1px solid var(--line);border-radius:6px;padding:.75rem;overflow:auto;font-size:.78rem;max-height:340px}
  img.shot{max-width:100%;border:1px solid var(--line);border-radius:6px;display:block}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:1.25rem}
  @media(max-width:760px){.grid2{grid-template-columns:1fr}}
  button{font:inherit;font-weight:700;border:none;border-radius:6px;padding:.7rem 1.2rem;cursor:pointer}
  .accept{background:var(--ok);color:#03210c}
  .reject{background:var(--bad);color:#2a0705}
  button:disabled{opacity:.4;cursor:not-allowed}
  .note{width:100%;background:#0d1117;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:.6rem;font:inherit;margin:.5rem 0}
  .disp-actions{display:flex;gap:1rem;margin-top:.75rem;flex-wrap:wrap}
  .muted{color:var(--dim);font-size:.8rem}
  .final{font-size:1rem;font-weight:700}
</style>
</head>
<body>
<header>
  <h1>Admissible V0 — Local Operator Review Surface</h1>
  <div class="sub">Slice 5B · loopback only · read-only evidence + one terminal disposition</div>
</header>
<main id="root"><div class="card">Loading review model…</div></main>
<script>
const TOKEN = "__REVIEW_TOKEN__";
const el = (t,a={},...c)=>{const n=document.createElement(t);for(const k in a){if(k==="class")n.className=a[k];else if(k==="html")n.innerHTML=a[k];else n.setAttribute(k,a[k]);}for(const x of c)n.append(x);return n;};
function rows(obj){const t=el("table");for(const [k,v] of obj){const tr=el("tr");tr.append(el("th",{},k));const td=el("td");if(v&&v.__pill){td.append(el("span",{class:"pill "+v.cls},v.text));}else{td.append(el("span",{class:"mono"},String(v)));}tr.append(td);t.append(tr);}return t;}
const pill=(text,cls)=>({__pill:true,text,cls});
const bool=(v,goodIsTrue=true)=>pill(String(v),(!!v===goodIsTrue)?"ok":"bad");
function integrityPill(ok){return ok?pill("SOUND","ok"):pill("UNCERTAIN","bad");}

async function load(){
  const r = await fetch("/api/review"); const data = await r.json();
  render(data.model, data.disposition);
}
function render(m, disposition){
  const root=document.getElementById("root"); root.innerHTML="";
  const f=m.facts, rt=m.runtime, integ=m.integrity;

  // Integrity banner
  const banner=el("div",{class:"banner "+(integ.ok?"ok":"bad")});
  banner.append(integ.ok
    ? "Archive integrity SOUND — every persisted evidence file reproduced its recorded hash."
    : "ARCHIVE INTEGRITY UNCERTAIN — one or more evidence files failed their checks. Facts below may be untrustworthy.");
  root.append(el("div",{class:"card"},banner));
  if(!integ.ok){
    const c=el("div",{class:"card"}); c.append(el("h2",{},"Integrity problems"));
    const pre=el("pre",{}); pre.textContent=JSON.stringify(integ.problems,null,2); c.append(pre); root.append(c);
  }

  // Governed run facts
  const runCard=el("div",{class:"card"}); runCard.append(el("h2",{},"Governed run"));
  runCard.append(rows([
    ["Session ID", f.session_id],["Execution phase", f.phase],["Revision", f.revision],
    ["Provider (Cursor) invocations", f.provider_invocation_count],
    ["Consumed results", f.consumed_result_count],
    ["Admitted operations", f.admitted_operation_count],
    ["Physical receipts", f.physical_receipt_count],
    ["FileEvidence records", f.file_evidence_count],
    ["Mandatory paths remaining", f.mandatory_paths_remaining_count],
    ["Structural verdict", f.structural_verification.passed?pill("PASSED","ok"):pill("FAILED","bad")],
    ["Structural checks", f.structural_verification.check_count],
  ]));
  root.append(runCard);

  // Mission
  const mc=el("div",{class:"card"}); mc.append(el("h2",{},"Immutable mission text"));
  const mp=el("pre",{}); mp.textContent=f.mission_text||"(none)"; mc.append(mp); root.append(mc);

  // Two-column: target files + runtime verdict
  const g=el("div",{class:"grid2"});
  const tf=el("div",{class:"card"}); tf.append(el("h2",{},"Generated target files"));
  const tt=el("table"); tt.append(el("tr",{},el("th",{},"path"),el("th",{},"sha256"),el("th",{},"ok")));
  for(const t of f.target_files){const tr=el("tr");tr.append(el("td",{class:"mono"},t.path));tr.append(el("td",{class:"mono"},(t.observed_sha256||"").slice(0,16)+"…"));const td=el("td");td.append(el("span",{class:"pill "+(t.integrity_ok?"ok":"bad")},t.integrity_ok?"ok":"BAD"));tr.append(td);tt.append(tr);}
  tf.append(tt); g.append(tf);

  const rc=el("div",{class:"card"}); rc.append(el("h2",{},"Runtime verification"));
  rc.append(rows([
    ["Verdict", rt.verdict==="PASS"?pill("PASS","ok"):pill(String(rt.verdict),"warn")],
    ["Reason codes", (rt.reason_codes||[]).join(", ")],
    ["Provider invoked", bool(rt.provider_invoked,false)],
    ["Retry attempted", bool(rt.retry_attempted,false)],
    ["Repair attempted", bool(rt.repair_attempted,false)],
    ["Chrome / provider", (rt.provider_id||"")+" · "+(rt.browser_version||"")],
    ["Browser executable", rt.browser_executable],
    ["Navigation ok", bool(rt.navigation_ok)],["Page loaded", bool(rt.page_loaded)],
    ["DOMContentLoaded", bool(rt.dom_content_loaded)],["Ready state", rt.ready_state],
    ["Final URL", rt.final_url],["Loopback origin", rt.loopback_origin],
    ["Uncaught exceptions", rt.uncaught_exception_count],
    ["Console errors", rt.console_error_count],
    ["External request attempts", rt.external_request_attempt_count],
    ["Tree hash before", (rt.tree_hash_before||"").slice(0,16)+"…"],
    ["Tree hash after", (rt.tree_hash_after||"").slice(0,16)+"…"],
    ["Tree byte-identical", bool(rt.tree_byte_identical)],
    ["Orphan processes", rt.orphan_process_count],
    ["Browser exit", JSON.stringify(rt.browser_exit)],
    ["Server exit", JSON.stringify(rt.server_exit)],
  ]));
  g.append(rc); root.append(g);

  // Screenshot + DOM evidence
  const ev=el("div",{class:"card"}); ev.append(el("h2",{},"Runtime evidence"));
  const shotEntry=(m.evidence_artifacts||{})["screenshot.png"]||{};
  if(shotEntry.integrity_ok){
    ev.append(el("div",{class:"muted"},"screenshot.png (integrity ok)"));
    ev.append(el("img",{class:"shot",src:"/api/evidence/screenshot.png",alt:"runtime screenshot"}));
  }else{
    ev.append(el("div",{class:"banner bad"},"Screenshot failed integrity check — not shown as trustworthy."));
  }
  const domEntry=(m.evidence_artifacts||{})["document.html"]||{};
  const domLink=el("p",{});
  domLink.append(el("a",{href:"/api/evidence/document.html",target:"_blank",style:"color:var(--accent)"},
    domEntry.integrity_ok?"Open serialized DOM (document.html)":"Serialized DOM unavailable / failed integrity"));
  ev.append(domLink);
  ev.append(el("p",{class:"muted"},"Note: runtime verification passing does NOT establish that the game is playable."));
  root.append(ev);

  // Interactive preview (manual operator observation surface)
  const pv=el("div",{class:"card"}); pv.append(el("h2",{},"Interactive preview"));
  pv.append(el("p",{class:"muted"},
    "Manual and interactive. Read-only with respect to the archived target. This is NOT additional automated verification, NOT new runtime evidence, and NOT proof of playability until you actually test it. Opening it does not record any acceptance decision."));
  const openBtn=el("button",{class:"accept",style:"background:var(--accent);color:#03121f"},"OPEN INTERACTIVE PREVIEW");
  const pvMsg=el("div",{class:"muted"});
  if(!integ.ok){
    openBtn.disabled=true; pvMsg.textContent="Preview disabled while archive/target integrity is uncertain.";
  }else{
    openBtn.onclick=()=>{ window.open("/preview/","_blank","noopener"); window.__previewOpened=true; pvMsg.textContent="Preview opened in a new tab — interact with the game, then choose a disposition below."; if(window.updateGate)window.updateGate(); };
  }
  pv.append(openBtn,pvMsg); root.append(pv);

  // Fingerprints
  const fp=el("div",{class:"card"}); fp.append(el("h2",{},"Evidence fingerprints"));
  fp.append(rows(Object.entries(m.fingerprints).map(([k,v])=>[k,(v||"(none)")])));
  root.append(fp);

  // Disposition
  const dc=el("div",{class:"card"}); dc.append(el("h2",{},"Terminal disposition"));
  if(disposition){
    dc.append(el("div",{class:"final"},"Recorded: "+disposition.disposition));
    dc.append(el("div",{class:"muted"},"at "+disposition.timestamp+" · nonce "+disposition.disposition_nonce));
    if(disposition.note) dc.append(el("p",{},"Note: "+disposition.note));
    dc.append(el("p",{class:"muted"},"This disposition is durable and write-once. ACCEPT does not change the runtime verdict; REJECT does not erase evidence."));
  }else{
    const note=el("textarea",{class:"note",placeholder:"Optional bounded operator note…",rows:"3",maxlength:"2000"});
    dc.append(note);
    const actions=el("div",{class:"disp-actions"});
    const accept=el("button",{class:"accept"},"ACCEPT_RESULT");
    const reject=el("button",{class:"reject"},"REJECT_RESULT");
    const msg=el("div",{class:"muted"});
    const post=async(d)=>{
      accept.disabled=reject.disabled=true; msg.textContent="Recording…";
      const body={disposition:d,note:note.value,session_id:m.session_id,expected_fingerprints:m.fingerprints};
      const r=await fetch("/api/disposition",{method:"POST",headers:{"Content-Type":"application/json","X-Review-Token":TOKEN},body:JSON.stringify(body)});
      const jr=await r.json();
      if(r.ok){ load(); } else { msg.textContent="Refused: "+(jr.error||r.status)+(jr.detail?(" — "+jr.detail):""); accept.disabled=reject.disabled=false; }
    };
    accept.onclick=()=>post("ACCEPT_RESULT"); reject.onclick=()=>post("REJECT_RESULT");
    // Gate: disposition stays disabled until the operator explicitly opens the
    // interactive preview during this review session (and integrity is sound).
    window.updateGate=function(){
      const gated = !integ.ok || !window.__previewOpened;
      accept.disabled=reject.disabled=gated;
      if(!integ.ok){ msg.textContent="Disposition disabled while archive integrity is uncertain."; }
      else if(!window.__previewOpened){ msg.textContent="Open the interactive preview and test the game before recording a disposition."; }
      else if(!msg.textContent.startsWith("Refused")){ msg.textContent="You may now record a terminal disposition."; }
    };
    actions.append(accept,reject); dc.append(actions,msg);
    updateGate();
  }
  root.append(dc);
}
load();
</script>
</body>
</html>
"""
