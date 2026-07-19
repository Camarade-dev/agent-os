from __future__ import annotations

from html.parser import HTMLParser
from http.client import HTTPConnection
import json
from pathlib import Path
import re
import pytest

from admissible.product_launcher.ui_transport import create_ui_loopback_server
from admissible.product_ui import get_asset, render_document


ROOT = Path(__file__).parents[1]
HTML = render_document(csrf_nonce="c" * 64, authorization_mode="INTERACTIVE_BOUND_CONFIRMATION").decode()
CSS = (ROOT / "admissible/product_ui/app.css").read_text(encoding="utf-8")
JS = (ROOT / "admissible/product_ui/app.js").read_text(encoding="utf-8")


class TagAudit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.labels = []
        self.h1 = 0
        self.external = []

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        if "id" in data:
            self.ids.add(data["id"])
        if tag == "label":
            self.labels.append(data.get("for"))
        if tag == "h1":
            self.h1 += 1
        for name in ("src", "href"):
            if data.get(name, "").startswith(("http://", "https://", "//")):
                self.external.append(data[name])


class FakeLauncher:
    def __init__(self, mode="PRECOMMITTED_DIGEST"):
        self.authorization_mode = mode
        self.calls = []
        self.polls = 0

    def bootstrap(self, nonce):
        return {"service":"admissible-product-launcher","version":"g2.5","repository_display_path":"safe-repository","required_source_head":"a"*40,"authorization_mode":self.authorization_mode,"authorization_semantics_notice":"The launcher forwards the owner-supplied digest unchanged and never derives it.","owner_authorization_encoding":"latin-1","g2_ready":True,"g2_api_version":"v1","csrf_nonce":nonce,"supported_authoring_template_ids":["observed_local_git_v1"],"visual_ui_available":False}

    def author_and_validate(self, body):
        self.calls.append(("author", body))
        return 200, {"contract_id":"contract-1","profile_fingerprint":"b"*64,"contract_summary":{"profile_id":"profile-1","run_id":"run-1","session_id":"session-1","gate_id":"gate-1","mission_id":"mission-1","workspace_source_kind":"OBSERVED_LOCAL_GIT","verification_mode":"NONE","template_id":"observed_local_git_v1"},"generated_ids":{},"execution_started":False,"authorization_mode":self.authorization_mode}

    def enqueue_preparation(self, contract_id):
        self.calls.append(("prepare", contract_id))
        return 202, {"preparation_id":"preparation-1","state":"QUEUED"}

    def preparation_status(self, preparation_id):
        self.calls.append(("poll", preparation_id)); self.polls += 1
        state = "RUNNING" if self.polls == 1 else "READY"
        return {"preparation_id":preparation_id,"contract_id":"contract-1","state":state,"authorization_mode":self.authorization_mode,"authorization_semantics_notice":"The launcher forwards the owner-supplied digest unchanged and never derives it.","consumed":False,"created_at":"now","updated_at":"now","payload_fingerprint":"c"*64 if state=="READY" else None,"safe_payload_summary":{"run_id":"run-1"} if state=="READY" else None,"authorization_payload":{"payload_fingerprint":"c"*64} if state=="READY" else None,"blocked_summary":None,"error_type":None}

    def launch_run(self, **kwargs):
        self.calls.append(("launch", kwargs))
        return 202, {"control_run_id":"control-1","control_state":"QUEUED"}


def request(server, method, path, body=None, headers=None):
    connection = HTTPConnection(server.host, server.port, timeout=5)
    raw = None if body is None else json.dumps(body).encode()
    request_headers = {"Host":f"{server.host}:{server.port}", **(headers or {})}
    if raw is not None:
        request_headers.update({"Content-Type":"application/json","Content-Length":str(len(raw))})
    connection.request(method, path, body=raw, headers=request_headers)
    response = connection.getresponse(); payload = response.read(); result=(response.status,dict(response.getheaders()),payload); connection.close(); return result


def test_static_shell_dom_semantics_and_local_assets():
    audit=TagAudit();audit.feed(HTML)
    assert audit.h1 == 1 and not audit.external
    assert {"mission-text","gate-objective","completion-conditions","commit-message","template-id","model","timeout-seconds","owner-phrase"}.issubset(set(audit.labels))
    assert 'aria-live="polite"' in HTML and 'role="alert"' in HTML
    assert all(step in HTML for step in ("Compose","Contract","Authorize"))
    assert "Mission accepted" in HTML and "HTTP 202 is not a verified result" in HTML
    assert "Visual Compose/Contract/Authorize interface is not installed in G2.5." not in HTML
    assert get_asset("/ui/assets/app.css")[1] == "text/css; charset=utf-8"
    assert get_asset("/ui/assets/app.js")[1] == "text/javascript; charset=utf-8"
    assert get_asset("/ui/assets/../index.html") is None and get_asset("/ui/assets/missing.js") is None


def test_client_security_and_exact_request_contract():
    assert '"/ui/api/v1/bootstrap"' in JS
    assert '"/ui/api/v1/contracts"' in JS
    assert "/preparations`" in JS and '"/ui/api/v1/runs"' in JS
    assert "X-Admissible-UI-CSRF" in JS
    assert "X-Admissible-Owner-Authorization" in JS
    assert "X-Admissible-Owner-Authorization-Digest" in JS
    assert "JSON.stringify({contract_id:ui.contract.response.contract_id,preparation_id:ui.preparation.id})" in JS
    assert not re.search(r"(?:local|session)Storage|indexedDB|serviceWorker|EventSource|WebSocket|sendBeacon|navigator\.beacon", JS, re.I)
    assert "innerHTML" not in JS and "eval(" not in JS and "new Function" not in JS
    assert "crypto.subtle" not in JS and "SHA-256" not in JS and "digest(" not in JS
    assert "/api/v1/" not in JS.replace("/ui/api/v1/", "")
    assert not re.search(r"/ui/api/v1/runs/.*(?:result|status)", JS)
    assert "localStorage" not in HTML+CSS and "https://" not in HTML+CSS+JS


def test_explicit_state_machine_polling_and_secret_clearing_contract():
    for state in ("BOOTSTRAP_LOADING","COMPOSE","AUTHORING","CONTRACT_READY","PREPARATION_QUEUED","PREPARATION_RUNNING","PREPARATION_READY","PREPARATION_BLOCKED","PREPARATION_FAILED","LAUNCHING","LAUNCH_ACCEPTED","REQUEST_ERROR"):
        assert state in JS
    assert "allowedTransitions" in JS and "INVALID_STATE_TRANSITION" in JS
    assert "pollCount>=120" in JS and "setTimeout(tick,750)" in JS
    assert "AbortController" in JS and "clearTimeout" in JS and "pagehide" in JS
    assert "finally" in JS and "clearSecrets()" in JS
    assert 'phrase.value=""' in JS and 'digest.value=""' in JS
    assert "^[0-9a-f]{64}$" in JS
    assert "codePointAt(0)>255" in JS
    assert "compute" not in JS.lower() and "hashlib" not in JS.lower()


def test_css_responsive_accessible_and_overflow_guards():
    assert "@media(max-width:760px)" in CSS
    assert "@media(prefers-reduced-motion:reduce)" in CSS
    assert "overflow-wrap:anywhere" in CSS and "min-width:0" in CSS
    assert ":focus-visible" in CSS
    assert CSS.count("{") == CSS.count("}")


def test_real_http_static_delivery_headers_allowlist_and_traversal():
    launcher=FakeLauncher();server=create_ui_loopback_server(launcher,csrf_generator=lambda _n:"z"*64).start()
    try:
        for path,mime in (("/","text/html; charset=utf-8"),("/ui/assets/app.css","text/css; charset=utf-8"),("/ui/assets/app.js","text/javascript; charset=utf-8")):
            status,headers,body=request(server,"GET",path);assert status==200;assert headers["Content-Type"]==mime;assert headers["Cache-Control"]=="no-store";assert headers["X-Content-Type-Options"]=="nosniff";assert headers["Referrer-Policy"]=="no-referrer";assert "frame-ancestors 'none'" in headers["Content-Security-Policy"];assert b"http://" not in body and b"https://" not in body
        for path in ("/ui/assets/missing.js","/ui/assets/../product_launcher/ui_transport.py","/ui/assets/%2e%2e/index.html"):
            status,_,body=request(server,"GET",path);assert status==404;assert json.loads(body)=={"error":"NOT_FOUND"}
    finally:server.stop()


@pytest.mark.parametrize("mode", ["INTERACTIVE_BOUND_CONFIRMATION", "PRECOMMITTED_DIGEST"])
def test_full_http_rehearsal_ends_at_launch_acceptance_without_secret_leak(mode):
    launcher=FakeLauncher(mode);server=create_ui_loopback_server(launcher,csrf_generator=lambda _n:"q"*64).start();csrf=server.csrf_nonce
    owner={"mission_text":"mission","gate_objective":"objective","completion_conditions_text":"complete","required_material_paths":["README.md"],"commit_message":"feat: mission","model":"auto","timeout_seconds":60,"template_id":"observed_local_git_v1"}
    mut={"X-Admissible-UI-CSRF":csrf};phrase="owner-secret-phrase";digest="d"*64
    try:
        assert request(server,"GET","/")[0]==200
        status,_,raw=request(server,"GET","/ui/api/v1/bootstrap");assert status==200
        status,_,raw=request(server,"POST","/ui/api/v1/contracts",owner,mut);contract=json.loads(raw);assert status==200
        status,_,raw=request(server,"POST",f'/ui/api/v1/contracts/{contract["contract_id"]}/preparations',{},mut);prep=json.loads(raw);assert status==202
        assert json.loads(request(server,"GET",f'/ui/api/v1/preparations/{prep["preparation_id"]}')[2])["state"]=="RUNNING"
        ready_raw=request(server,"GET",f'/ui/api/v1/preparations/{prep["preparation_id"]}')[2];assert json.loads(ready_raw)["state"]=="READY"
        launch_headers={**mut,"X-Admissible-Owner-Authorization":phrase}
        if mode == "PRECOMMITTED_DIGEST": launch_headers["X-Admissible-Owner-Authorization-Digest"]=digest
        status,_,launch_raw=request(server,"POST","/ui/api/v1/runs",{"contract_id":contract["contract_id"],"preparation_id":prep["preparation_id"]},launch_headers)
        launch=json.loads(launch_raw);assert status==202 and launch=={"control_run_id":"control-1","control_state":"QUEUED"}
        visible=raw+ready_raw+launch_raw;assert phrase.encode() not in visible and digest.encode() not in visible
        assert [call[0] for call in launcher.calls]==["author","prepare","poll","poll","launch"]
    finally:server.stop()
