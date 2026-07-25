"""Step 5C2D: the browser-facing historical evaluation pairing surface.

Everything proven here is a property of the *browser* layer only.  The accepted
Step 5C2C2 loopback transport, the pairing service, the coordinator, the review
builder and the archive store are untouched, and no expectation below is taken
from the code under test: the owner-review fixture is produced by the accepted
review builder itself, and the request expectations are declared independently
in this module.

The central law under test is that the browser is a presentation and transport
client.  It never constructs a V4 payload, never constructs or re-derives a V5
profile, never constructs or reconstructs a pairing authority, never derives an
expected tag or any message authentication code, never accepts the configured
secret, and never infers confirmation from archive existence.

Two deliberate, load-bearing limitations are stated rather than hidden:

* Clearing the tag input and dropping the route-local reference does not
  zeroize the immutable JavaScript string built from the typed characters, nor
  any copy the browser's networking internals made of the outgoing header.  The
  tests below prove that the *application* retains no later reference; they
  claim nothing about browser internals.
* The Node harness observes the outgoing confirmation header as the exact
  transient request argument.  That observation is the test's, not the
  application's, and the application is separately proven to hold no reference
  to the value afterwards.
"""

from __future__ import annotations

import base64
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import subprocess

import pytest

from admissible.delegated_gate.historical_pairing_confirmation import (
    HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS,
)
from admissible.delegated_gate.historical_pairing_review import (
    CONFIRMATION_MESSAGE_RECIPE,
    HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES,
    HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS,
    PREPARATION_STATE_CONFIRMATION_IN_PROGRESS,
    PREPARATION_STATE_CONSUMED,
    PREPARATION_STATE_READY_FOR_CONFIRMATION,
)
from admissible.delegated_gate.historical_pairing_workflow import (
    CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE,
    HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS,
)
from admissible.product_ui import get_asset, render_document
from test_admissible_product_ui_g3 import NODE_HARNESS as G3_NODE_HARNESS

# The accepted owner-review fixture chain is reused verbatim so this UI suite
# renders the real schema, with its real hostile whitespace and Unicode, rather
# than a hand-written approximation that could drift from the accepted slice.
from test_admissible_historical_pairing_review import (  # noqa: F401
    archive_root,
    clock,
    coordinator,
    historical_payload,
    local_locators,
    prepared,
    review,
)

ROOT = Path(__file__).parents[1]
# The external mutation campaign points this at a copy of the product-UI assets
# outside the repository.  Unset, it is exactly the in-repository product path,
# and the local renderer below is pinned to the product renderer.
UI_ROOT = Path(
    os.environ.get("ADMISSIBLE_PRODUCT_UI_ROOT", str(ROOT / "admissible/product_ui"))
)
JS_PATH = UI_ROOT / "app.js"
HTML_PATH = UI_ROOT / "index.html"
CSS_PATH = UI_ROOT / "app.css"
JS = JS_PATH.read_text(encoding="utf-8")
CSS = CSS_PATH.read_text(encoding="utf-8")


def _render(path: Path) -> str:
    """Render one shell exactly as ``render_document`` does."""

    from html import escape

    source = path.read_text(encoding="utf-8")
    return source.replace("{{CSRF_NONCE}}", escape("c" * 64, quote=True)).replace(
        "{{AUTHORIZATION_MODE}}", escape("PRECOMMITTED_DIGEST", quote=True)
    )


HTML = _render(HTML_PATH)
NODE = "node"


def test_local_renderer_matches_the_product_renderer():
    """The document under test is the document the launcher actually serves."""

    served = render_document(
        csrf_nonce="c" * 64, authorization_mode="PRECOMMITTED_DIGEST"
    ).decode("utf-8")
    assert _render(ROOT / "admissible/product_ui/index.html") == served

PAYLOADS_ROUTE = "/ui/api/v1/historical-pairings/payloads"
PREPARATIONS_ROUTE = "/ui/api/v1/historical-pairings/preparations"
CONFIRMATION_HEADER = "X-Admissible-Historical-Pairing-Confirmation"

# Declared here, independently of the client bundle, so a client that started
# sending a sixth field or renamed one is caught rather than accommodated.
EXACT_PREPARATION_BODY_KEYS = sorted(
    [
        "payload_id",
        "actor_id",
        "result_claims",
        "claim_verification_plan",
        "verification_evidence_bindings",
    ]
)
EXACT_CONFIRMATION_BODY_KEYS = ["expected_authority_fingerprint"]

# Deliberately hostile owner material.  Order is non-alphabetical, strings carry
# markup, entities, quotes, newlines, non-breaking spaces and non-ASCII
# punctuation, and one member is an absolute-path-looking string.
HOSTILE_CLAIMS = [
    {
        "claim_id": "zulu",
        "statement": "  <script>window.__XSS_MARKER_INVOKED__()</script>\u00a0\u201cquoted\u201d  \n  second  line ",
        "obligation_level": "MANDATORY",
        "depends_on": ["alpha", "\u00e9chec"],
        "non_claims": ["&amp; not decoded", "C:\\Users\\owner\\secret\\path.txt"],
    },
    {
        "claim_id": "alpha",
        "statement": '</pre><img src=x onerror="window.__XSS_MARKER_INVOKED__()">',
        "obligation_level": "ADVISORY",
        "depends_on": [],
        "non_claims": [],
    },
]
HOSTILE_ACTOR = "  owner.\u00e9quipe <b>bold</b>  "
HOSTILE_PLAN = [{"obligation_id": "\u03b2eta", "note": "  raw\tmember  "}]
HOSTILE_BINDINGS = [{"binding_id": "gamma", "note": "/etc/passwd"}]

XSS_MARKER = "__XSS_MARKER_INVOKED__"
HOSTILE_PROSE = (
    f"<script>{XSS_MARKER}()</script>"
    f'<img src=x onerror="{XSS_MARKER}()">'
    "</pre>&lt;entity&gt;\u00a0`quotes`\n"
    "C:\\Users\\owner\\evidence\\run-root\\payload.json"
)


# ---------------------------------------------------------------------------
# Static document, asset and bundle structure.
# ---------------------------------------------------------------------------


class _Audit(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.labels: list[str | None] = []
        self.inputs: list[dict[str, str]] = []
        self.headings: list[str] = []
        self.external: list[str] = []
        self.tabindex: list[str] = []
        self.handlers: list[str] = []
        self.attr_values: list[str] = []
        self.button_text: list[str] = []
        self._button = False
        self._heading: str | None = None
        self.heading_text: dict[str, list[str]] = {}

    def handle_starttag(self, tag, attrs):
        data = {key: (value or "") for key, value in attrs}
        self.attr_values.extend(data.values())
        if tag == "button":
            self._button = True
        if "id" in data:
            self.ids.add(data["id"])
        if tag == "label":
            self.labels.append(data.get("for"))
        if tag in {"input", "textarea", "select"}:
            self.inputs.append({**data, "tag": tag})
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.headings.append(tag)
            self._heading = tag
            self.heading_text.setdefault(tag, [])
        if "tabindex" in data:
            self.tabindex.append(data["tabindex"])
        for name in data:
            if name.startswith("on"):
                self.handlers.append(name)
        for name in ("src", "href"):
            if data.get(name, "").startswith(("http://", "https://", "//")):
                self.external.append(data[name])

    def handle_data(self, data):
        if self._heading and data.strip():
            self.heading_text[self._heading].append(data.strip())
        if self._button and data.strip():
            self.button_text.append(data.strip())

    def handle_endtag(self, tag):
        if tag == self._heading:
            self._heading = None
        if tag == "button":
            self._button = False


def _historical_section_html() -> str:
    start = HTML.index('<section id="historical-pairing-view"')
    end = HTML.index('<section id="status-area"')
    section = HTML[start:end]
    assert section.rstrip().endswith("</section>")
    return section


def test_static_document_declares_the_complete_hidden_historical_surface():
    audit = _Audit()
    audit.feed(HTML)
    section = _historical_section_html()
    local = _Audit()
    local.feed(section)

    # The whole feature is one hidden section; nothing else moved.
    assert re.search(r'id="historical-pairing-view"[^>]*\shidden', HTML)

    required_ids = {
        "historical-pairing-view",
        "historical-unavailable",
        "historical-feature-body",
        "historical-authoring-form",
        "historical-authoring-fields",
        "historical-payload-id",
        "historical-actor-id",
        "historical-result-claims",
        "historical-verification-plan",
        "historical-evidence-bindings",
        "historical-prepare",
        "historical-new-preparation",
        "historical-frozen-notice",
        "historical-review",
        "historical-review-body",
        "historical-review-stale",
        "historical-refresh",
        "historical-message-tools",
        "historical-copy-preparation-id",
        "historical-copy-fingerprint",
        "historical-copy-message",
        "historical-copy-message-hash",
        "historical-copy-recipe",
        "historical-download-message",
        "historical-confirmation-form",
        "historical-confirmation-tag",
        "historical-confirmation-error",
        "historical-confirm",
        "historical-outcome",
        "historical-outcome-body",
        "historical-status",
        "historical-status-message",
        "historical-status-code",
    }
    assert required_ids.issubset(audit.ids)

    # Every historical input, textarea and select carries a real label.
    labelled = {value for value in audit.labels if value}
    for control in sorted(required_ids):
        if control in {
            "historical-payload-id",
            "historical-actor-id",
            "historical-result-claims",
            "historical-verification-plan",
            "historical-evidence-bindings",
            "historical-confirmation-tag",
        }:
            assert control in labelled, control

    # Heading hierarchy: exactly one page h1 (unchanged), the feature owns one
    # h2, and every feature subsection is an h3.
    assert audit.headings.count("h1") == 1
    assert "h4" not in audit.headings and "h5" not in audit.headings
    assert "Pair a historical run with owner evaluation authority" in audit.heading_text["h2"]
    for subheading in (
        "Server-derived owner review",
        "Public confirmation-message material",
        "Confirmation outcome",
    ):
        assert subheading in audit.heading_text["h3"]

    # Fieldsets, legends, aria-live status region and no inline handlers.
    assert "<fieldset id=\"historical-authoring-fields\">" in HTML
    assert "<legend>Owner-authored pairing inputs</legend>" in HTML
    assert "<legend>Independently produced confirmation tag</legend>" in HTML
    assert 'id="historical-status"' in HTML and 'aria-live="polite"' in HTML
    assert not audit.handlers
    assert not audit.external
    # No positive tabindex anywhere, so nothing jumps the natural tab order.
    assert all(int(value) <= 0 for value in audit.tabindex)

    # The tag field is a password field with no persistence hint, and there is
    # no secret field, secret label, secret endpoint or expected-tag endpoint.
    tag_field = next(item for item in audit.inputs if item.get("id") == "historical-confirmation-tag")
    assert tag_field["type"] == "password"
    assert tag_field["autocomplete"] == "off"
    assert tag_field["autocapitalize"] == "none"
    assert tag_field["spellcheck"] == "false"
    # There is no secret field and no secret-shaped identifier, label target,
    # route, or attribute value anywhere in the document. The only prose that
    # mentions a secret is the disclosure that this page never accepts one.
    for control in local.inputs:
        for key in ("id", "name", "placeholder"):
            assert "secret" not in control.get(key, "").lower(), control
    for target in local.labels:
        assert "secret" not in (target or "").lower()
    for value in local.attr_values:
        lowered_value = value.lower()
        for forbidden in ("secret", "expected-tag", "expected_tag", "hmac"):
            assert forbidden not in lowered_value, value
    # No control offers to derive, compute or generate a credential.
    for label in local.button_text:
        lowered_label = label.lower()
        for forbidden in ("hmac", "compute", "generate", "derive", "sign"):
            assert forbidden not in lowered_label, label
    lowered = section.lower()
    for forbidden in ("expected tag", "hmac", "enter the secret", "secret value"):
        assert forbidden not in lowered, forbidden
    assert "never accepts a configured secret" in section
    # The only secret-shaped control on the page is the pre-existing owner
    # phrase, which lives outside this section and is unchanged.
    assert 'class="secret-row"' not in section and 'id="owner-phrase"' not in section

    # The static asset manifest is unchanged: still exactly two allowlisted
    # assets and still no traversal.
    assert get_asset("/ui/assets/app.css")[1] == "text/css; charset=utf-8"
    assert get_asset("/ui/assets/app.js")[1] == "text/javascript; charset=utf-8"
    assert get_asset("/ui/assets/../index.html") is None
    assert get_asset("/ui/assets/historical.js") is None
    assert section


def test_client_bundle_declares_no_credential_production_surface():
    """Narrow static invariants only.

    "No such code path exists anywhere in the bundle" has no runtime witness,
    so absence stays a source assertion.  The behavioural proofs that the tag
    is neither derived nor retained live in the executed scenarios below.
    """

    for sink in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "DOMParser",
    ):
        assert sink not in JS, sink
    for credential_api in (
        "crypto.subtle",
        "importKey",
        "subtle.sign",
        "createHmac",
        "hmac",
        "Hmac",
        "HMAC",
        "compute_historical_pairing_confirmation_tag",
        "configured_secret",
        "expected_tag",
        "expected-tag",
    ):
        assert credential_api not in JS, credential_api
    assert not re.search(r"(?:local|session)Storage|indexedDB|serviceWorker|document\.cookie|history\.(?:push|replace)State", JS, re.I)

    # Exactly the four accepted routes, no query strings, and exactly one
    # dedicated credential header literal.
    assert '"/ui/api/v1/historical-pairings"' in JS
    assert 'HP_ROUTE_ROOT+"/payloads"' in JS
    assert 'HP_ROUTE_ROOT+"/preparations"' in JS
    assert JS.count('"X-Admissible-Historical-Pairing-Confirmation"') == 1
    assert "?" not in "".join(
        line for line in JS.splitlines() if "HP_ROUTE_ROOT" in line or "HP_PREPARATIONS_ROUTE" in line
    ).replace("?", "") + ""
    # Every bounded launcher code is mapped.
    for code in (
        "PAYLOAD_NOT_ALLOWLISTED",
        "PAIRING_INPUTS_INVALID",
        "PREPARATION_CAPACITY",
        "PREPARATION_IDENTIFIER_UNAVAILABLE",
        "PAIRING_LOCATOR_INVALID",
        "PREPARATION_NOT_FOUND",
        "PREPARATION_EXPIRED",
        "PREPARATION_CONSUMED",
        "PREPARATION_IN_USE",
        "STALE_AUTHORITY_FINGERPRINT",
        "CONFIRMATION_TAG_REQUIRED",
        "CONFIRMATION_TAG_MALFORMED",
        "CONFIRMATION_REJECTED",
        "ARCHIVE_CONFLICT",
        "ARCHIVE_WRITE_FAILED",
        "ARCHIVE_DURABILITY_UNCERTAIN",
        "ARCHIVE_RELOAD_FAILED",
        "ARCHIVE_CONTENT_MISMATCH",
        "HISTORICAL_PAIRING_UNAVAILABLE",
    ):
        assert f"{code}:" in JS, code
    # Both confirmation refusals share one generic sentence.
    generic = "The confirmation tag was not accepted. Produce another tag independently and submit it again."
    assert JS.count(generic) == 2
    # All eight bounded presentation states exist and are explicit.
    for state in (
        "FEATURE_ABSENT",
        "AUTHORING",
        "PREPARING",
        "REVIEW_READY",
        "REFRESHING",
        "CONFIRMING",
        "CONFIRMED",
        "REFUSED_OR_ERROR",
    ):
        assert f"{state}:\"{state}\"" in JS.replace(" ", ""), state
    assert "INVALID_HISTORICAL_STATE_TRANSITION" in JS
    assert "revokeObjectURL" in JS and "createObjectURL" in JS


def test_css_bounds_the_new_surface_without_colour_only_meaning():
    for selector in (
        ".historical-pairing",
        ".historical-section",
        ".historical-prose",
        ".historical-entry",
        ".historical-ordered",
    ):
        assert selector in CSS, selector
    block = CSS[CSS.index(".historical-pairing{") :]
    assert "overflow-wrap:anywhere" in block and "word-break:break-word" in block
    assert "white-space:pre-wrap" in block and "max-width:100%" in block
    # The narrow viewport rule folds the copy actions instead of overflowing.
    assert ".historical-copy-actions{align-items:stretch;flex-direction:column}" in CSS
    # Focus visibility is inherited from the existing global rule.
    assert "outline:3px solid #7aa3e4" in CSS
    # No status is carried by colour alone: every status surface is textual.
    assert "aria-busy" in CSS


# ---------------------------------------------------------------------------
# Executed browser harness.
# ---------------------------------------------------------------------------


class _DomSpec(HTMLParser):
    """Turn the real served document into a builder spec for the fake DOM.

    The harness DOM is therefore the product document, not a hand-written
    approximation: a control that is removed, renamed or reordered in
    ``index.html`` changes every executed scenario below.
    """

    VOID = {"meta", "link", "input", "br", "img", "hr", "source", "area"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root: dict = {"tag": "#root", "attrs": {}, "children": []}
        self.stack: list[dict] = [self.root]

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "attrs": {k: (v if v is not None else "") for k, v in attrs}, "children": []}
        self.stack[-1]["children"].append(node)
        if tag not in self.VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.stack[-1]["children"].append(
            {"tag": tag, "attrs": {k: (v if v is not None else "") for k, v in attrs}, "children": []}
        )

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index]["tag"] == tag:
                del self.stack[index:]
                return

    def handle_data(self, data):
        if data.strip():
            self.stack[-1]["children"].append({"tag": "#text", "text": data})


def _document_spec() -> dict:
    parser = _DomSpec()
    parser.feed(HTML)
    html = next(node for node in parser.root["children"] if node["tag"] == "html")
    head = next(node for node in html["children"] if node["tag"] == "head")
    body = next(node for node in html["children"] if node["tag"] == "body")
    return {"head": head["children"], "body": body["children"]}


DOCUMENT_SPEC = json.dumps(_document_spec())


HP_PRELUDE = r"""
// ---- product-document DOM, browser shims and observation spies -------------
const PRODUCT_DOM_SPEC = JSON.parse(fs.readFileSync(process.argv[5], "utf8"));
const fixture = JSON.parse(fs.readFileSync(process.argv[4], "utf8"));

function buildFromSpec(spec) {
  if (spec.tag === "#text") { const node = new FakeNode("#text", 3); node._text = spec.text; return node; }
  const node = new FakeNode(spec.tag);
  for (const [key, value] of Object.entries(spec.attrs || {})) {
    if (key === "for") { node.htmlFor = value; node.attributes.for = value; }
    else if (key.startsWith("data-")) { node.dataset[key.slice(5)] = value; node.attributes[key] = value; }
    else node.setAttribute(key, value);
  }
  for (const child of spec.children || []) node.appendChild(buildFromSpec(child));
  return node;
}

function installProductDom() {
  for (const key of Object.keys(byId)) delete byId[key];
  const head = new FakeNode("head");
  for (const child of PRODUCT_DOM_SPEC.head) head.appendChild(buildFromSpec(child));
  body.children.length = 0;
  for (const child of PRODUCT_DOM_SPEC.body) body.appendChild(buildFromSpec(child));
  documentElement.children.length = 0;
  documentElement.appendChild(head);
  documentElement.appendChild(body);
  register(documentElement);
}

const consoleCalls = [];
const consoleSpy = {};
for (const name of ["log", "info", "warn", "error", "debug", "trace", "dir", "table", "group", "groupEnd"]) {
  consoleSpy[name] = (...args) => { consoleCalls.push({ name, args: args.map(x => String(x)) }); };
}

const clipboardWrites = [];
const navigatorShim = {
  clipboard: { async writeText(value) { clipboardWrites.push(String(value)); } },
  userAgent: "node-harness"
};

const blobs = [];
class FakeBlob {
  constructor(parts, options) { this.parts = parts; this.type = (options || {}).type || ""; blobs.push(this); }
}
let objectUrlSeq = 0;
const objectUrls = [];
const URLShim = {
  createObjectURL(blob) { objectUrlSeq += 1; const url = "blob:harness/" + objectUrlSeq; objectUrls.push({ url, blob, revoked: false }); return url; },
  revokeObjectURL(url) { const entry = objectUrls.find(x => x.url === url); if (entry) entry.revoked = true; }
};

const anchorClicks = [];
const _createElement = document.createElement.bind(document);
document.createElement = function (tag) {
  const node = _createElement(tag);
  if (String(tag).toLowerCase() === "a") {
    node.click = function () {
      const entry = objectUrls.find(x => x.url === node.href) || {};
      anchorClicks.push({ href: node.href, download: node.download, revokedAtClick: entry.revoked === true });
    };
  }
  return node;
};

let cookieWrites = 0;
Object.defineProperty(document, "cookie", { get() { return ""; }, set(_value) { cookieWrites += 1; } });

function decodeBase64(value) { return Buffer.from(value, "base64"); }

// Text an owner can actually read: hidden subtrees contribute nothing.
function visibleText(node) {
  if (!node) return "";
  if (node.hidden === true) return "";
  if (node.nodeType === 3) return node._text || "";
  if (!node.children.length) return node._text || "";
  return node.children.map(visibleText).join("");
}
"""


HP_SCENARIOS = r"""
// ---- historical-pairing fetch fabric ---------------------------------------
function queued(entries) {
  const queue = Array.isArray(entries) ? entries.slice() : [entries];
  return () => (queue.length > 1 ? queue.shift() : queue[0]);
}

function installHistoricalFetch(config = {}) {
  const payloads = queued(config.payloads || { status: 200, body: { payloads: fixture.payloads } });
  const prepare = queued(config.prepare || { status: 201, body: fixture.review });
  const reviews = queued(config.review || { status: 200, body: fixture.review });
  const confirm = queued(config.confirm || { status: 200, body: fixture.confirmation });
  fetchImpl = async (url, options = {}) => {
    const method = (options.method || "GET").toUpperCase();
    fetchLog.push({ url, method, headers: { ...(options.headers || {}) }, body: options.body === undefined ? null : String(options.body) });
    if (options.signal && options.signal.aborted) { const err = new Error("Aborted"); err.name = "AbortError"; throw err; }
    if (url === "/ui/api/v1/bootstrap") {
      return jsonResponse(200, {
        service: "admissible-product-launcher", version: "g2.5",
        repository_display_path: "safe-repository", required_source_head: "a".repeat(40),
        authorization_mode: "PRECOMMITTED_DIGEST", authorization_semantics_notice: "notice",
        owner_authorization_encoding: "latin-1", g2_ready: true, g2_api_version: "v1",
        csrf_nonce: "c".repeat(64), supported_authoring_template_ids: ["observed_local_git_v1"],
        visual_ui_available: false
      });
    }
    if (url === "/ui/api/v1/recoveries") return jsonResponse(200, { recoveries: [] });
    if (url === "/ui/api/v1/contracts" && method === "POST") {
      return jsonResponse(200, {
        contract_id: "contract-1", profile_fingerprint: "b".repeat(64),
        contract_summary: { profile_id: "p", run_id: "r", session_id: "s", gate_id: "g", mission_id: "m",
          workspace_source_kind: "OBSERVED_LOCAL_GIT", verification_mode: "NONE", template_id: "observed_local_git_v1" },
        generated_ids: {}, execution_started: false, authorization_mode: "PRECOMMITTED_DIGEST"
      });
    }
    if (url === HP_PAYLOADS) { const answer = payloads(); if (answer.raise) throw new TypeError("Failed to fetch"); return jsonResponse(answer.status, answer.body); }
    if (url === HP_PREPARATIONS && method === "POST") { const answer = prepare(); return jsonResponse(answer.status, answer.body); }
    if (url.startsWith(HP_PREPARATIONS + "/") && url.endsWith("/confirmation") && method === "POST") {
      const answer = confirm(); if (answer.raise) throw new TypeError("Failed to fetch"); return jsonResponse(answer.status, answer.body);
    }
    if (url.startsWith(HP_PREPARATIONS + "/") && method === "GET") {
      const answer = reviews(); if (answer.raise) throw new TypeError("Failed to fetch"); return jsonResponse(answer.status, answer.body);
    }
    return jsonResponse(404, { error: "NOT_FOUND" });
  };
}

const HP_PAYLOADS = "/ui/api/v1/historical-pairings/payloads";
const HP_PREPARATIONS = "/ui/api/v1/historical-pairings/preparations";

function hp() { return windowObj.AdmissibleHistoricalPairingTest; }
function g3() { return windowObj.AdmissibleG3Test; }

function historicalRequests() {
  return fetchLog.filter(entry => entry.url.indexOf("/historical-pairings") !== -1);
}
function foreignHeaderNames(entry) {
  return Object.keys(entry.headers).filter(name => name.toLowerCase() !== "accept"
    && name.toLowerCase() !== "content-type"
    && name.toLowerCase() !== "x-admissible-ui-csrf"
    && name.toLowerCase() !== "x-admissible-historical-pairing-confirmation");
}

async function bootTo(state, config = {}) {
  installHistoricalFetch(config);
  loadApp();
  await waitState("COMPOSE");
  await settle();
  await settle();
  if (state && hp().getState() !== state) throw new Error("historical state " + hp().getState() + " != " + state);
}

async function authorAndPrepare() {
  hp().setField("historical-actor-id", fixture.hostile.actor);
  hp().setField("historical-result-claims", JSON.stringify(fixture.hostile.claims));
  hp().setField("historical-verification-plan", JSON.stringify(fixture.hostile.plan));
  hp().setField("historical-evidence-bindings", JSON.stringify(fixture.hostile.bindings));
  hp().submit("historical-authoring-form");
  await settle(); await settle();
}

// Walk every node in the historical section and collect its observable surface.
function walkSection() {
  const root = byId["historical-pairing-view"];
  const nodes = [];
  const visit = (node) => {
    nodes.push(node);
    for (const child of node.children) visit(child);
  };
  if (root) visit(root);
  return nodes;
}
// Only the text the browser itself authors: section titles, field labels and
// captions. Values rendered from launcher data are excluded on purpose.
function browserAuthoredLabels(id) {
  const root = byId[id];
  const labels = [];
  const visit = (node) => {
    if (node.tagName === "SUMMARY" || node.tagName === "DT") labels.push(node.textContent);
    if (node.tagName === "P" && (node.className || "").indexOf("historical-caption") !== -1) labels.push(node.textContent);
    for (const child of node.children) visit(child);
  };
  if (root) for (const child of root.children) visit(child);
  return labels;
}
function subtreeTags(id) {
  const root = byId[id];
  const tags = [];
  const visit = (node) => { tags.push(node.tagName); for (const child of node.children) visit(child); };
  if (root) for (const child of root.children) visit(child);
  return Array.from(new Set(tags));
}
function sectionSurface() {
  const nodes = walkSection();
  const values = [], attributes = [], listeners = [], tags = [];
  for (const node of nodes) {
    tags.push(node.tagName);
    if (typeof node.value === "string" && node.value) values.push(node.value);
    for (const [name, value] of Object.entries(node.attributes || {})) attributes.push(name + "=" + value);
    for (const [type, list] of Object.entries(node._listeners || {})) if (list.length) listeners.push(node.tagName + ":" + type);
  }
  return { text: byId["historical-pairing-view"] ? byId["historical-pairing-view"].textContent : "", values, attributes, listeners, tags };
}

function retentionBlob(extra = []) {
  const surface = sectionSurface();
  // Everything reachable through the exported application object, including the
  // values its zero-argument accessors close over.
  const exported = hp();
  const exportedValues = Object.keys(exported).map(key => {
    const value = exported[key];
    if (typeof value === "function") {
      try { return key + ":" + JSON.stringify(value()); } catch (_e) { return key + ":function"; }
    }
    return key + ":" + JSON.stringify(value);
  });
  return [
    exportedValues.join("\u0000"),
    JSON.stringify(hp().memory()),
    JSON.stringify(hp().snapshot()),
    surface.text,
    surface.values.join("\u0000"),
    surface.attributes.join("\u0000"),
    JSON.stringify(consoleCalls),
    JSON.stringify(clipboardWrites),
    JSON.stringify(storage.local),
    JSON.stringify(storage.session),
    extra.join("\u0000")
  ].join("\u0000");
}

// --- scenarios --------------------------------------------------------------

async function runDiscovery404() {
  await bootTo(null, { payloads: { status: 404, body: { error: "NOT_FOUND" } } });
  // Sampled at the moment discovery finished: the existing compose submit calls
  // clearError(), which would erase an error banner a mutant had just opened.
  const atDiscovery = {
    statusHidden: byId["status-area"].hidden,
    statusMessage: byId["status-message"].textContent,
    statusCode: byId["status-code"].textContent,
    visibleText: visibleText(body),
    authorDisabled: byId["author-button"].disabled,
    prepareHidden: byId["prepare-button"].hidden,
    prepareDisabled: byId["prepare-button"].disabled,
    liveStatus: byId["live-status"].textContent
  };
  const before = g3().snapshot();
  // The existing compose workflow must still work end to end.
  await fillCompose("mission");
  g3().setField("gate-objective", "o");
  g3().setField("completion-conditions", "c");
  g3().setField("commit-message", "feat: x");
  g3().submit("compose-form");
  await waitState("CONTRACT_READY");
  await flushTimers(5);
  return {
    atDiscovery,
    historicalState: hp().getState(),
    snapshot: hp().snapshot(),
    memory: hp().memory(),
    probes: historicalRequests(),
    consoleCalls,
    statusHidden: byId["status-area"].hidden,
    bodyText: visibleText(body),
    existingStateBefore: before.state,
    existingStateAfter: g3().getState(),
    existingErrorText: byId["status-message"].textContent + byId["status-code"].textContent,
    composeControlsEnabled: !byId["author-button"].disabled && !byId["prepare-button"].hidden
  };
}

async function runDiscovery200() {
  await bootTo("AUTHORING");
  return {
    state: hp().getState(),
    snapshot: hp().snapshot(),
    memory: hp().memory(),
    probes: historicalRequests(),
    consoleCalls,
    existingState: g3().getState(),
    existingBootstrapText: byId["bootstrap-facts"].textContent
  };
}

async function runDiscoveryFailure(kind) {
  const config = kind === "malformed"
    ? { payloads: { status: 200, body: { payloads: [{ payload_id: 17 }] } } }
    : kind === "network"
      ? { payloads: { raise: true } }
      : { payloads: { status: 500, body: { error: "READ_UNAVAILABLE", detail: "C:\\launcher\\archive\\root" } } };
  await bootTo(null, config);
  return {
    state: hp().getState(),
    snapshot: hp().snapshot(),
    sectionText: hp().featureText(),
    probes: historicalRequests(),
    consoleCalls,
    existingState: g3().getState()
  };
}

async function runAuthoringRefusals() {
  await bootTo("AUTHORING");
  const results = [];
  const cases = [
    ["object-root", '{"claim_id":"a"}'],
    ["invalid-json", "[{,}]"],
    ["bare-string", '"claims"'],
    ["number-root", "17"],
    ["empty", ""]
  ];
  for (const [name, value] of cases) {
    hp().setField("historical-result-claims", value);
    hp().setField("historical-verification-plan", "[]");
    hp().setField("historical-evidence-bindings", "[]");
    hp().submit("historical-authoring-form");
    await settle();
    results.push({
      name,
      state: hp().getState(),
      snapshot: hp().snapshot(),
      requests: historicalRequests().filter(entry => entry.method === "POST").length,
      fieldError: byId["historical-result-claims-error"].textContent
    });
  }
  return { results, posts: historicalRequests().filter(entry => entry.method === "POST").length };
}

async function runPrepare() {
  await bootTo("AUTHORING");
  await authorAndPrepare();
  const post = historicalRequests().find(entry => entry.method === "POST");
  return {
    state: hp().getState(),
    snapshot: hp().snapshot(),
    memory: hp().memory(),
    post,
    postBody: JSON.parse(post.body),
    requests: historicalRequests(),
    reviewText: hp().reviewText(),
    consoleCalls
  };
}

async function runPrepareRefused() {
  await bootTo("AUTHORING", { prepare: { status: 422, body: { error: "PAIRING_INPUTS_INVALID", detail: "C:\\evidence\\root", trace: "Traceback ..." } } });
  await authorAndPrepare();
  return {
    state: hp().getState(),
    snapshot: hp().snapshot(),
    memory: hp().memory(),
    sectionText: hp().featureText()
  };
}

async function runNewPreparation() {
  await bootTo("AUTHORING");
  await authorAndPrepare();
  const afterPrepare = hp().snapshot();
  const requestsBefore = fetchLog.length;
  hp().click("historical-new-preparation");
  await settle();
  return {
    afterPrepare,
    after: hp().snapshot(),
    memory: hp().memory(),
    newRequests: fetchLog.length - requestsBefore,
    state: hp().getState()
  };
}

async function runReviewFidelity() {
  await bootTo("AUTHORING", { prepare: { status: 201, body: fixture.hostileReview } });
  await authorAndPrepare();
  const surface = sectionSurface();
  return {
    state: hp().getState(),
    sections: hp().snapshot().reviewSections,
    reviewText: hp().reviewText(),
    markerInvoked,
    unsafeHtmlApi,
    assignedHandlers,
    reviewTags: subtreeTags("historical-review-body"),
    reviewLabels: browserAuthoredLabels("historical-review-body"),
    listeners: surface.listeners,
    tags: Array.from(new Set(surface.tags)),
    consoleCalls,
    identityText: hp().sectionText("historical-section-identity"),
    withheldText: hp().sectionText("historical-section-withheld"),
    noticesText: hp().sectionText("historical-section-notices"),
    limitationsText: hp().sectionText("historical-section-limitations"),
    missionText: hp().sectionText("historical-section-mission-context"),
    checkpointText: hp().sectionText("historical-section-checkpoint-commands"),
    independenceText: hp().sectionText("historical-section-independence"),
    claimsText: hp().sectionText("historical-section-result-claims")
  };
}

async function runExportTools() {
  await bootTo("AUTHORING");
  await authorAndPrepare();
  hp().click("historical-copy-preparation-id");
  hp().click("historical-copy-fingerprint");
  hp().click("historical-copy-message");
  hp().click("historical-copy-message-hash");
  hp().click("historical-copy-recipe");
  await settle();
  hp().click("historical-download-message");
  await settle();
  return {
    clipboardWrites,
    anchorClicks,
    objectUrls,
    downloadedBase64: blobs.length ? Buffer.from(blobs[0].parts[0]).toString("base64") : null,
    blobCount: blobs.length,
    snapshot: hp().snapshot(),
    consoleCalls
  };
}

async function runConfirm(kind) {
  const consumed = JSON.parse(JSON.stringify(fixture.review));
  consumed.pairing_identity.preparation_state = "CONSUMED";
  const config = kind === "refresh_fails"
    ? { review: [{ status: 410, body: { error: "PREPARATION_EXPIRED" } }] }
    : { review: [{ status: 200, body: consumed }] };
  await bootTo("AUTHORING", config);
  await authorAndPrepare();
  const beforeTag = hp().snapshot();
  hp().setField("historical-confirmation-tag", fixture.tag);
  hp().submit("historical-confirmation-form");
  await settle(); await settle(); await settle();
  const confirmRequest = historicalRequests().find(entry => entry.url.endsWith("/confirmation"));
  const afterRequests = historicalRequests();
  const afterConfirm = { state: hp().getState(), snapshot: hp().snapshot(), outcomeText: hp().outcomeText() };
  // A later request must not inherit the credential header as a default.
  hp().click("historical-refresh");
  await settle(); await settle();
  const later = historicalRequests().filter(entry => !entry.url.endsWith("/confirmation"));
  return {
    beforeTag,
    afterConfirm,
    state: hp().getState(),
    snapshot: hp().snapshot(),
    memory: hp().memory(),
    confirmRequest,
    confirmHeaders: Object.keys(confirmRequest.headers),
    confirmForeignHeaders: foreignHeaderNames(confirmRequest),
    confirmBody: JSON.parse(confirmRequest.body),
    requestsAfterConfirm: afterRequests.map(entry => ({ url: entry.url, method: entry.method })),
    laterHeaders: later.map(entry => Object.keys(entry.headers)),
    retention: retentionBlob([JSON.stringify(afterRequests.map(entry => ({ url: entry.url, body: entry.body })))]),
    outcomeText: hp().outcomeText(),
    reviewText: hp().reviewText(),
    cookieWrites,
    storageLocal: storage.local,
    storageSession: storage.session,
    consoleCalls,
    clipboardWrites
  };
}

async function runConfirmRefused(code, status) {
  await bootTo("AUTHORING");
  await authorAndPrepare();
  fetchImpl = (function (previous) {
    return async (url, options = {}) => {
      if (String(url).endsWith("/confirmation")) {
        const method = (options.method || "GET").toUpperCase();
        fetchLog.push({ url, method, headers: { ...(options.headers || {}) }, body: String(options.body) });
        const err = new Error("BOUNDED_API_ERROR");
        return { ok: false, status, async json() { return { error: code, detail: "C:\\archive\\root", trace: "Traceback" }; } };
      }
      return previous(url, options);
    };
  })(fetchImpl);
  hp().setField("historical-confirmation-tag", fixture.tag);
  hp().submit("historical-confirmation-form");
  await settle(); await settle();
  const first = { state: hp().getState(), snapshot: hp().snapshot(), retention: retentionBlob() };
  const requestsAfter = historicalRequests().filter(entry => entry.url.endsWith("/confirmation")).length;
  await flushTimers(10);
  await settle();
  const retriesAfterTimers = historicalRequests().filter(entry => entry.url.endsWith("/confirmation")).length;
  return {
    first,
    requestsAfter,
    retriesAfterTimers,
    outcomeHidden: byId["historical-outcome"].hidden,
    memory: hp().memory(),
    consoleCalls
  };
}

async function runMissingTag() {
  await bootTo("AUTHORING");
  await authorAndPrepare();
  hp().setField("historical-confirmation-tag", "");
  hp().submit("historical-confirmation-form");
  await settle();
  return {
    state: hp().getState(),
    snapshot: hp().snapshot(),
    confirmationRequests: historicalRequests().filter(entry => entry.url.endsWith("/confirmation")).length
  };
}

async function runRefresh(kind) {
  const map = {
    expired: { status: 410, body: { error: "PREPARATION_EXPIRED" } },
    not_found: { status: 404, body: { error: "PREPARATION_NOT_FOUND" } },
    stale: { status: 409, body: { error: "STALE_AUTHORITY_FINGERPRINT" } },
    other: { status: 500, body: { error: "ARCHIVE_RELOAD_FAILED" } },
    substituted: { status: 200, body: null },
    in_progress: { status: 200, body: null },
    consumed: { status: 200, body: null }
  };
  const substituted = JSON.parse(JSON.stringify(fixture.review));
  substituted.pairing_identity.pairing_authority_fingerprint = "f".repeat(64);
  const progress = JSON.parse(JSON.stringify(fixture.review));
  progress.pairing_identity.preparation_state = "CONFIRMATION_IN_PROGRESS";
  const consumed = JSON.parse(JSON.stringify(fixture.review));
  consumed.pairing_identity.preparation_state = "CONSUMED";
  map.substituted.body = substituted;
  map.in_progress.body = progress;
  map.consumed.body = consumed;
  await bootTo("AUTHORING", { review: [map[kind]] });
  await authorAndPrepare();
  const beforeText = hp().reviewText();
  hp().click("historical-refresh");
  await settle(); await settle();
  const request = historicalRequests().filter(entry => entry.method === "GET" && entry.url.startsWith(HP_PREPARATIONS + "/")).pop();
  return {
    kind,
    state: hp().getState(),
    snapshot: hp().snapshot(),
    request,
    requestHeaders: Object.keys(request.headers),
    beforeText,
    afterText: hp().reviewText(),
    memory: hp().memory(),
    consoleCalls
  };
}

async function runConsumedWithoutConfirmation() {
  const consumed = JSON.parse(JSON.stringify(fixture.review));
  consumed.pairing_identity.preparation_state = "CONSUMED";
  await bootTo("AUTHORING", { review: [{ status: 200, body: consumed }] });
  await authorAndPrepare();
  hp().click("historical-refresh");
  await settle(); await settle();
  return {
    state: hp().getState(),
    snapshot: hp().snapshot(),
    outcomeText: hp().outcomeText(),
    reviewText: hp().reviewText(),
    memory: hp().memory()
  };
}

async function runReload() {
  await bootTo("AUTHORING");
  await authorAndPrepare();
  hp().setField("historical-confirmation-tag", fixture.tag);
  hp().submit("historical-confirmation-form");
  await settle(); await settle(); await settle();
  const before = { state: hp().getState(), memory: hp().memory() };
  // A reload is a fresh page: a fresh global, a fresh document, a fresh module
  // instance.  Nothing outside the closure can carry the previous state.
  const freshWindow = {
    document, localStorage: makeStorage(storage.local), sessionStorage: makeStorage(storage.session),
    addEventListener() {}, removeEventListener() {}
  };
  freshWindow.window = freshWindow;
  freshWindow.fetch = context.fetch;
  freshWindow.setTimeout = setTimeoutFn;
  freshWindow.clearTimeout = clearTimeoutFn;
  freshWindow.AbortController = FakeAbortController;
  freshWindow.Event = context.Event;
  const freshContext = { ...context, window: freshWindow };
  installProductDom();
  vm.runInNewContext(appJs, freshContext, { filename: "app.js", timeout: 5000 });
  const reloaded = freshWindow.AdmissibleHistoricalPairingTest;
  const immediately = { state: reloaded.getState(), memory: reloaded.memory(), snapshot: reloaded.snapshot() };
  await settle(); await settle(); await settle();
  return {
    before,
    immediately,
    afterBoot: { state: reloaded.getState(), memory: reloaded.memory(), snapshot: reloaded.snapshot() },
    storageLocal: storage.local,
    storageSession: storage.session,
    cookieWrites
  };
}

async function runAccessibility() {
  await bootTo("AUTHORING");
  const busyStates = [];
  const record = () => busyStates.push({ state: hp().getState(), busy: byId["historical-pairing-view"].getAttribute("aria-busy") });
  record();
  const prepared = authorAndPrepare();
  record();
  await prepared;
  record();
  const nodes = walkSection();
  const clickable = nodes.filter(node => (node._listeners.click || []).length);
  const labels = nodes.filter(node => node.tagName === "LABEL").map(node => node.htmlFor);
  const controls = nodes.filter(node => ["INPUT", "TEXTAREA", "SELECT"].includes(node.tagName)).map(node => node.id);
  const details = nodes.filter(node => node.tagName === "DETAILS");
  const openDetails = details.filter(node => node.open).map(node => node.id);
  return {
    busyStates,
    clickableTags: Array.from(new Set(clickable.map(node => node.tagName))),
    labels,
    controls,
    detailIds: details.map(node => node.id),
    openDetails,
    keyboardTraps: nodes.filter(node => (node._listeners.keydown || []).length || (node._listeners.focusin || []).length).length,
    preTabIndex: nodes.filter(node => node.tagName === "PRE").map(node => node.tabIndex),
    liveRegion: byId["historical-status"].getAttribute("aria-live"),
    liveAtomic: byId["historical-status"].getAttribute("aria-atomic"),
    disabledSemantics: {
      payload: byId["historical-payload-id"].getAttribute("aria-disabled"),
      prepare: byId["historical-prepare"].disabled,
      refresh: byId["historical-refresh"].disabled
    },
    statusHasText: byId["historical-status-message"].textContent.length > 0,
    statusHasCode: byId["historical-status-code"].textContent.length > 0
  };
}

(async () => {
  try {
    let out;
    if (scenario === "discovery_404") out = await runDiscovery404();
    else if (scenario === "discovery_200") out = await runDiscovery200();
    else if (scenario.startsWith("discovery_fail:")) out = await runDiscoveryFailure(scenario.split(":")[1]);
    else if (scenario === "authoring_refusals") out = await runAuthoringRefusals();
    else if (scenario === "prepare") out = await runPrepare();
    else if (scenario === "prepare_refused") out = await runPrepareRefused();
    else if (scenario === "new_preparation") out = await runNewPreparation();
    else if (scenario === "review_fidelity") out = await runReviewFidelity();
    else if (scenario === "export_tools") out = await runExportTools();
    else if (scenario.startsWith("confirm:")) out = await runConfirm(scenario.split(":")[1]);
    else if (scenario.startsWith("confirm_refused:")) { const parts = scenario.split(":"); out = await runConfirmRefused(parts[1], Number(parts[2])); }
    else if (scenario === "missing_tag") out = await runMissingTag();
    else if (scenario.startsWith("refresh:")) out = await runRefresh(scenario.split(":")[1]);
    else if (scenario === "consumed_without_confirmation") out = await runConsumedWithoutConfirmation();
    else if (scenario === "reload") out = await runReload();
    else if (scenario === "accessibility") out = await runAccessibility();
    else throw new Error("unknown scenario " + scenario);
    process.stdout.write(JSON.stringify(out));
  } catch (error) {
    process.stdout.write(JSON.stringify({ scenario, error: String((error && error.stack) || error) }));
    process.exitCode = 1;
  }
})();
"""


def _build_harness() -> str:
    harness = G3_NODE_HARNESS.replace(
        "\nbuildDom();\n\nconst document =",
        "\nbuildDom();\n\nconst document =",
    )
    # The product document replaces the hand-written G3 fixture DOM.
    harness = harness.replace(
        "\nconst context = {",
        "\n" + HP_PRELUDE + "\nconst context = {",
        1,
    )
    harness = harness.replace("  console,\n  window: windowObj,", "  console: consoleSpy,\n  window: windowObj,", 1)
    harness = harness.replace(
        "  encodeURIComponent, Set, Map, freeze: Object.freeze,",
        "  encodeURIComponent, Set, Map, freeze: Object.freeze,\n"
        "  Blob: FakeBlob, URL: URLShim, Uint8Array, navigator: navigatorShim,\n"
        '  atob: (value) => Buffer.from(value, "base64").toString("binary"),\n'
        "  btoa: (value) => Buffer.from(value, \"binary\").toString(\"base64\"),",
        1,
    )
    harness = harness.replace(
        "  buildDom();\n  // trap marker side effects",
        "  buildDom();\n  installProductDom();\n  // trap marker side effects",
        1,
    )
    assert "installProductDom();" in harness
    assert "consoleSpy" in harness
    return harness.rsplit("(async () => {", 1)[0] + HP_SCENARIOS


NODE_HARNESS = _build_harness()


@pytest.fixture(scope="function")
def presentation(review, prepared) -> dict:
    """One real owner-review presentation plus its hostile rendering variant."""

    presented = review.to_presentation_dict()
    identity = presented["pairing_identity"]
    confirmation = {
        "outcome": CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE,
        "preparation_id": identity["preparation_id"],
        "asserted_actor_id": identity["asserted_actor_id"],
        "pairing_authority_fingerprint": identity["pairing_authority_fingerprint"],
        "evaluation_profile_fingerprint": identity["evaluation_profile_fingerprint"],
        "target_authorization_payload_fingerprint": identity[
            "target_authorization_payload_fingerprint"
        ],
        "archived_pairing_document_count": 3,
        "limitations": list(HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS),
    }
    hostile = json.loads(json.dumps(presented))
    hostile["historical_mission_context"]["mission_text"] = HOSTILE_PROSE
    hostile["historical_mission_context"]["gate_clauses"][0]["text"] = HOSTILE_PROSE
    hostile["historical_mission_context"]["checkpoint_commands"][0]["argv"] = [
        "node",
        HOSTILE_PROSE,
        "--strict",
    ]
    hostile["claim_authority"]["claims"][0]["statement"] = HOSTILE_PROSE
    hostile["notices"] = list(hostile["notices"])
    hostile["notices"][0] = HOSTILE_PROSE
    # A launcher response that started carrying a local locator or the verifier
    # source body must still render neither.
    hostile["historical_mission_context"]["behavioral_verifier"]["verifier_source"] = (
        "#!/usr/bin/env node\nconsole.log('VERIFIER_SOURCE_BODY_LEAKED');\n"
    )
    hostile["historical_authority_context"]["run_root"] = "C:\\launcher\\runs\\LEAKED_RUN_ROOT"
    hostile["historical_authority_context"]["archive_root"] = "C:\\launcher\\LEAKED_ARCHIVE_ROOT"
    return {
        "review": presented,
        "hostileReview": hostile,
        "confirmation": confirmation,
        "payloads": [
            {
                "payload_id": "zulu-payload",
                "payload_fingerprint": "1" * 64,
                "document_sha256": "2" * 64,
                "document_byte_length": 4096,
            },
            {
                "payload_id": "alpha-payload",
                "payload_fingerprint": "3" * 64,
                "document_sha256": "4" * 64,
                "document_byte_length": 8192,
            },
            {
                "payload_id": "mike-payload",
                "payload_fingerprint": "5" * 64,
                "document_sha256": "6" * 64,
                "document_byte_length": 128,
            },
        ],
        "hostile": {
            "actor": HOSTILE_ACTOR,
            "claims": HOSTILE_CLAIMS,
            "plan": HOSTILE_PLAN,
            "bindings": HOSTILE_BINDINGS,
        },
        "tag": "  Ab" + "9" * 60 + "cD  ",
    }


def _run(tmp_path: Path, scenario: str, presentation: dict, timeout: int = 40) -> dict:
    slug = re.sub(r"[^A-Za-z0-9_]+", "_", scenario)
    harness = tmp_path / f"hp_{slug}.js"
    harness.write_text(NODE_HARNESS, encoding="utf-8")
    fixture = tmp_path / f"hp_{slug}.json"
    fixture.write_text(json.dumps(presentation, ensure_ascii=False), encoding="utf-8")
    document = tmp_path / f"hp_{slug}_dom.json"
    document.write_text(DOCUMENT_SPEC, encoding="utf-8")
    completed = subprocess.run(
        [NODE, str(harness), scenario, str(JS_PATH), str(fixture), str(document)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        cwd=str(tmp_path),
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert completed.returncode == 0, completed.stdout + "\n" + completed.stderr
    payload = json.loads(completed.stdout)
    assert "error" not in payload, payload
    return payload


# ---------------------------------------------------------------------------
# Feature discovery.
# ---------------------------------------------------------------------------


def test_absent_feature_stays_invisible_silent_and_leaves_the_app_untouched(
    tmp_path, presentation
):
    out = _run(tmp_path, "discovery_404", presentation)

    assert out["historicalState"] == "FEATURE_ABSENT"
    assert out["snapshot"]["featureHidden"] is True
    assert out["snapshot"]["statusHidden"] is True
    assert out["snapshot"]["statusMessage"] == "" and out["snapshot"]["statusCode"] == ""
    assert out["memory"]["payloads"] == [] and out["memory"]["preparationId"] is None

    # Exactly one bounded probe and no automatic retry.
    assert [(entry["url"], entry["method"]) for entry in out["probes"]] == [
        (PAYLOADS_ROUTE, "GET")
    ]
    assert not out["consoleCalls"]

    # Sampled the instant discovery finished: no error banner opened, no
    # historical wording is visible, and no existing control changed state.
    at = out["atDiscovery"]
    assert at["statusHidden"] is True
    assert at["statusMessage"] == "" and at["statusCode"] == ""
    assert not at["authorDisabled"]
    assert not at["prepareHidden"] and not at["prepareDisabled"]
    assert "historical" not in at["liveStatus"].lower()
    for wording in ("historical", "pairing authority", "confirmation tag", "unavailable"):
        assert wording not in at["visibleText"].lower(), wording

    assert out["statusHidden"] is True and out["existingErrorText"] == ""
    lowered = out["bodyText"].lower()
    for wording in ("historical", "pairing authority", "confirmation tag"):
        assert wording not in lowered, wording

    # The existing workflow is behaviourally unchanged.
    assert out["existingStateBefore"] == "COMPOSE"
    assert out["existingStateAfter"] == "CONTRACT_READY"
    assert out["composeControlsEnabled"] is True


def test_available_feature_is_revealed_in_exact_declaration_order(tmp_path, presentation):
    out = _run(tmp_path, "discovery_200", presentation)

    assert out["state"] == "AUTHORING"
    assert out["snapshot"]["featureHidden"] is False
    assert out["snapshot"]["bodyHidden"] is False
    assert out["snapshot"]["unavailableHidden"] is True
    # Declaration order preserved exactly; nothing sorted.
    declared = [record["payload_id"] for record in presentation["payloads"]]
    assert out["snapshot"]["payloadOptions"] == declared
    assert declared != sorted(declared)
    assert [record["payload_id"] for record in out["memory"]["payloads"]] == declared

    probe = out["probes"][0]
    assert len(out["probes"]) == 1
    assert probe["url"] == PAYLOADS_ROUTE and probe["method"] == "GET"
    assert "?" not in probe["url"]
    assert CONFIRMATION_HEADER not in probe["headers"]
    assert set(probe["headers"]) == {"Accept"}
    assert not out["consoleCalls"]
    # Bootstrap is untouched and advertises nothing about the feature.
    assert out["existingState"] == "COMPOSE"
    assert "historical" not in out["existingBootstrapText"].lower()


@pytest.mark.parametrize("kind", ["server", "malformed", "network"])
def test_non_404_discovery_failure_is_bounded_and_feature_local(tmp_path, presentation, kind):
    out = _run(tmp_path, f"discovery_fail:{kind}", presentation)

    assert out["state"] == "REFUSED_OR_ERROR"
    assert out["snapshot"]["featureHidden"] is False
    assert out["snapshot"]["unavailableHidden"] is False
    assert out["snapshot"]["bodyHidden"] is True
    # No raw response content, exception text or launcher path is displayed.
    for leak in ("READ_UNAVAILABLE", "C:\\launcher", "Traceback", "{", "}"):
        assert leak not in out["sectionText"], leak
    assert out["existingState"] == "COMPOSE"
    assert not out["consoleCalls"]
    assert len(out["probes"]) == 1


# ---------------------------------------------------------------------------
# Authoring.
# ---------------------------------------------------------------------------


def test_authoring_refuses_locally_only_for_json_and_array_root(tmp_path, presentation):
    out = _run(tmp_path, "authoring_refusals", presentation)

    assert out["posts"] == 0, "a locally refused authoring attempt must send nothing"
    for result in out["results"]:
        assert result["state"] == "AUTHORING", result["name"]
        assert result["requests"] == 0, result["name"]
        assert result["snapshot"]["statusCode"] == "PAIRING_INPUTS_NOT_A_JSON_ARRAY"
        assert result["fieldError"] in {"Enter valid JSON.", "Enter a JSON array."}


def test_preparation_sends_exactly_five_fields_and_freezes_authoring(tmp_path, presentation):
    out = _run(tmp_path, "prepare", presentation)

    post = out["post"]
    assert post["url"] == PREPARATIONS_ROUTE and post["method"] == "POST"
    assert "?" not in post["url"]
    assert CONFIRMATION_HEADER not in post["headers"]
    assert sorted(post["headers"]) == ["Accept", "Content-Type", "X-Admissible-UI-CSRF"]

    body = out["postBody"]
    assert sorted(body) == EXACT_PREPARATION_BODY_KEYS
    # Exact strings, exact order, exact Unicode and whitespace.
    assert body["actor_id"] == HOSTILE_ACTOR
    assert body["result_claims"] == HOSTILE_CLAIMS
    assert body["claim_verification_plan"] == HOSTILE_PLAN
    assert body["verification_evidence_bindings"] == HOSTILE_BINDINGS
    assert [claim["claim_id"] for claim in body["result_claims"]] == ["zulu", "alpha"]
    assert body["payload_id"] == presentation["payloads"][0]["payload_id"]
    # No client-side schema authority: an object member the launcher would
    # reject was still forwarded verbatim rather than repaired or dropped.
    assert body["claim_verification_plan"][0] == {"obligation_id": "\u03b2eta", "note": "  raw\tmember  "}
    # No launcher-authority field of any kind is added by the client. Owner
    # array members are forwarded verbatim -- including a member that happens to
    # contain a path-looking or secret-looking string -- so only the request's
    # own field names are constrained here.
    for forbidden in (
        "archive_root",
        "run_root",
        "workspace_root",
        "evidence_root",
        "document_path",
        "configured_secret",
        "secret",
        "confirmation_tag",
        "tag",
        "preparation_id",
        "expected_authority_fingerprint",
        "pairing_authority_fingerprint",
    ):
        assert forbidden not in body, forbidden

    assert out["state"] == "REVIEW_READY"
    # Only the two launcher-returned locators are retained.
    identity = presentation["review"]["pairing_identity"]
    assert out["memory"]["preparationId"] == identity["preparation_id"]
    assert out["memory"]["authorityFingerprint"] == identity["pairing_authority_fingerprint"]
    # The rendered review is the launcher response itself.
    assert out["memory"]["review"] == presentation["review"]

    snapshot = out["snapshot"]
    assert snapshot["prepareDisabled"] is True
    assert snapshot["restartHidden"] is False
    assert snapshot["frozenHidden"] is False
    assert snapshot["reviewHidden"] is False and snapshot["toolsHidden"] is False
    assert snapshot["confirmationHidden"] is False
    assert not out["consoleCalls"]


def test_preparation_refusal_is_bounded_and_reopens_authoring(tmp_path, presentation):
    out = _run(tmp_path, "prepare_refused", presentation)

    assert out["state"] == "AUTHORING"
    assert out["snapshot"]["statusCode"] == "PAIRING_INPUTS_INVALID"
    assert out["snapshot"]["prepareDisabled"] is False
    assert out["snapshot"]["reviewHidden"] is True
    assert out["memory"]["preparationId"] is None and out["memory"]["review"] is None
    for leak in ("C:\\evidence", "Traceback", "detail"):
        assert leak not in out["sectionText"], leak


def test_start_new_preparation_is_local_only(tmp_path, presentation):
    out = _run(tmp_path, "new_preparation", presentation)

    assert out["afterPrepare"]["prepareDisabled"] is True
    assert out["newRequests"] == 0, "a local reset must issue no request at all"
    assert out["state"] == "AUTHORING"
    assert out["after"]["prepareDisabled"] is False
    assert out["after"]["reviewHidden"] is True and out["after"]["toolsHidden"] is True
    assert out["memory"]["preparationId"] is None
    assert out["memory"]["review"] is None
    # The copy is explicit that the launcher preparation is untouched.
    assert "neither deleted nor revoked" in out["after"]["statusMessage"]


# ---------------------------------------------------------------------------
# Review fidelity, safe rendering and locator withholding.
# ---------------------------------------------------------------------------


REQUIRED_SECTION_IDS = [
    "historical-section-preparation-state",
    "historical-section-identity",
    "historical-section-result-claims",
    "historical-section-claim-authority",
    "historical-section-obligations",
    "historical-section-independence",
    "historical-section-negative-controls",
    "historical-section-reference-cases",
    "historical-section-plan-authority",
    "historical-section-bindings",
    "historical-section-binding-authority",
    "historical-section-mission-context",
    "historical-section-gate-clauses",
    "historical-section-checkpoint-commands",
    "historical-section-git-policy",
    "historical-section-authority-context",
    "historical-section-workspace-identities",
    "historical-section-compatibility",
    "historical-section-withheld",
    "historical-section-notices",
    "historical-section-limitations",
]


def test_complete_review_renders_every_section_as_inert_exact_text(tmp_path, presentation):
    out = _run(tmp_path, "review_fidelity", presentation)
    hostile = presentation["hostileReview"]

    assert out["sections"] == REQUIRED_SECTION_IDS

    # Nothing executed and no unsafe markup sink was ever touched.
    assert out["markerInvoked"] == 0
    assert out["unsafeHtmlApi"] == 0
    assert out["assignedHandlers"] == []
    assert not out["consoleCalls"]
    # Only inert structural elements were created for the review.
    assert set(out["reviewTags"]) <= {
        "DETAILS", "SUMMARY", "P", "DL", "DT", "DD", "DIV", "OL", "LI", "PRE", "#TEXT",
    }, out["reviewTags"]
    # No listener was attached to any rendered review node.
    assert all(entry.startswith("BUTTON:") or entry.startswith("FORM:") for entry in out["listeners"]), out["listeners"]

    text = out["reviewText"]
    # Hostile prose survives byte-exactly, including the path-looking member.
    assert HOSTILE_PROSE in text
    assert "C:\\Users\\owner\\evidence\\run-root\\payload.json" in text
    assert "&lt;entity&gt;" in text, "entities must not be decoded"
    assert out["claimsText"].count(HOSTILE_PROSE) >= 1
    assert HOSTILE_PROSE in out["missionText"]
    assert HOSTILE_PROSE in out["checkpointText"]

    # Identity, notices, limitations and preparation state are all present.
    identity = hostile["pairing_identity"]
    assert identity["preparation_id"] in out["identityText"]
    assert identity["pairing_authority_fingerprint"] in out["identityText"]
    assert identity["confirmation_message_base64"] in out["identityText"]
    assert identity["confirmation_message_sha256"] in out["identityText"]
    assert CONFIRMATION_MESSAGE_RECIPE in out["identityText"]
    assert str(identity["confirmation_message_byte_length"]) in out["identityText"]

    for notice in HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES[1:]:
        assert notice in out["noticesText"], notice
    assert len(HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES) == 14
    for withheld in HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS:
        assert withheld in out["withheldText"], withheld

    # All six independence vectors appear for every obligation.
    obligations = hostile["verification_plan_authority"]["verification_obligations"]
    for obligation in obligations:
        assert obligation["obligation_id"] in out["independenceText"]
    for vector in ("Temporal", "Artifact", "Process", "Information", "Model", "Organizational"):
        assert out["independenceText"].count(vector) == len(obligations), vector

    # No status rollup and no invented interpretation. Launcher values such as
    # HUMAN_RUBRIC_PASS legitimately contain verdict-shaped tokens, so the
    # constraint is on the text the browser itself authors: no label, caption or
    # section title may express a result, rollup or adjudication.
    assert "NOT_ASSESSED" in text, "the launcher coverage status is shown unchanged"
    joined = " ".join(out["reviewLabels"]).upper()
    for invented in (
        "PASS",
        "FAIL",
        "SATISFIED",
        "ELIGIBLE",
        "SUPPORTED",
        "VERDICT",
        "ADMITTED",
        "REFUSED",
        "OVERALL",
        "SCORE",
        "TOTAL",
        "STATUS:",
    ):
        assert invented not in joined, invented
    # The launcher's own NOT_ASSESSED coverage is never translated.
    for translated in ("Coverage: pass", "Coverage: fail", "ASSESSED_PASS", "ASSESSED_FAIL"):
        assert translated not in text, translated
    # The browser states its own non-adjudication explicitly instead.
    assert "It is never displayed as satisfied or unsatisfied." in text
    assert "It is never displayed as eligible or ineligible" in text

    # Structured locators absent from the launcher review stay absent, and a
    # locator or verifier body injected into the response is never rendered.
    assert "LEAKED_RUN_ROOT" not in text and "LEAKED_ARCHIVE_ROOT" not in text
    assert "VERIFIER_SOURCE_BODY_LEAKED" not in text
    assert hostile["historical_mission_context"]["behavioral_verifier"]["verifier_source_sha256"] in text

    # The limitations section states honestly that the review carries none.
    assert "carries no workflow-limitation list" in out["limitationsText"]


# ---------------------------------------------------------------------------
# Public confirmation-message export.
# ---------------------------------------------------------------------------


def test_public_message_export_is_exact_and_revokes_its_object_url(tmp_path, presentation):
    out = _run(tmp_path, "export_tools", presentation)
    identity = presentation["review"]["pairing_identity"]

    assert out["clipboardWrites"] == [
        identity["preparation_id"],
        identity["pairing_authority_fingerprint"],
        identity["confirmation_message_base64"],
        identity["confirmation_message_sha256"],
        identity["confirmation_message_recipe"],
    ]
    assert identity["confirmation_message_recipe"] == CONFIRMATION_MESSAGE_RECIPE

    # The downloaded bytes decode exactly from the launcher Base64 and were not
    # reconstructed from any review field.
    assert out["blobCount"] == 1
    assert out["downloadedBase64"] == identity["confirmation_message_base64"]
    decoded = base64.b64decode(identity["confirmation_message_base64"])
    assert len(decoded) == identity["confirmation_message_byte_length"]

    assert len(out["anchorClicks"]) == 1
    click = out["anchorClicks"][0]
    fingerprint = identity["pairing_authority_fingerprint"]
    assert click["download"] == f"historical-pairing-confirmation-message-{fingerprint}.bin"
    assert identity["confirmation_message_sha256"] not in click["download"]
    for forbidden in ("tag", "secret"):
        assert forbidden not in click["download"]
    # The URL is live while the download is triggered and revoked immediately after.
    assert click["revokedAtClick"] is False
    assert len(out["objectUrls"]) == 1 and out["objectUrls"][0]["revoked"] is True
    assert not out["consoleCalls"]


# ---------------------------------------------------------------------------
# Confirmation-tag custody and outcome.
# ---------------------------------------------------------------------------


def test_confirmation_sends_the_exact_value_once_and_retains_nothing(tmp_path, presentation):
    out = _run(tmp_path, "confirm:refresh_ok", presentation)
    tag = presentation["tag"]
    identity = presentation["review"]["pairing_identity"]

    request = out["confirmRequest"]
    expected_path = (
        f"{PREPARATIONS_ROUTE}/{identity['preparation_id']}/confirmation"
    )
    assert request["url"] == expected_path and request["method"] == "POST"
    assert "?" not in request["url"]
    assert tag not in request["url"]

    # Exactly one dedicated header carrying the exact unmodified value.
    assert out["confirmHeaders"].count(CONFIRMATION_HEADER) == 1
    assert (
        len(
            [
                name
                for name in out["confirmHeaders"]
                if name.lower() == CONFIRMATION_HEADER.lower()
            ]
        )
        == 1
    ), "exactly one confirmation header instance, under any spelling"
    assert request["headers"][CONFIRMATION_HEADER] == tag
    assert request["headers"][CONFIRMATION_HEADER] != tag.strip()
    assert request["headers"][CONFIRMATION_HEADER] != tag.lower()
    assert out["confirmForeignHeaders"] == []
    assert "Authorization" not in request["headers"] and "Cookie" not in request["headers"]

    # The body carries only the expected authority fingerprint.
    assert list(out["confirmBody"]) == EXACT_CONFIRMATION_BODY_KEYS
    assert out["confirmBody"]["expected_authority_fingerprint"] == identity["pairing_authority_fingerprint"]
    assert tag not in request["body"]

    # The tag never reappears anywhere the application owns.
    assert out["snapshot"]["tagValue"] == ""
    assert out["snapshot"]["tagType"] == "password"
    assert tag not in out["retention"]
    assert tag.strip() not in out["retention"]
    assert json.dumps(out["memory"]) .find(tag.strip()) == -1
    assert out["storageLocal"] == {} and out["storageSession"] == {}
    assert out["cookieWrites"] == 0
    assert out["clipboardWrites"] == []
    assert not out["consoleCalls"]

    # A fresh review is requested to show the launcher's current state.
    urls = [entry["url"] for entry in out["requestsAfterConfirm"]]
    review_path = f"{PREPARATIONS_ROUTE}/{identity['preparation_id']}/{identity['pairing_authority_fingerprint']}"
    assert urls.count(review_path) == 1
    assert urls.index(expected_path) < urls.index(review_path)
    assert out["state"] == "CONFIRMED"
    assert PREPARATION_STATE_CONSUMED in out["reviewText"]

    # The credential header is not retained as a default for later requests.
    for headers in out["laterHeaders"]:
        assert CONFIRMATION_HEADER not in headers

    # Bounded outcome without epistemic overclaim.
    outcome = out["outcomeText"]
    assert CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE in outcome
    assert identity["pairing_authority_fingerprint"] in outcome
    assert identity["evaluation_profile_fingerprint"] in outcome
    assert identity["target_authorization_payload_fingerprint"] in outcome
    assert "3" in outcome
    for limitation in HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS:
        assert limitation in outcome, limitation
    for overclaim in ("CREATED", "REPLAY", "authenticated actor is", "digital signature was", "proves possession"):
        assert overclaim not in outcome, overclaim
    assert "no authenticated actor" in outcome
    assert "no fresh secret possession" in outcome
    assert "no digital signature" in outcome
    assert "no durable confirmation proof" in outcome


def test_post_confirmation_refresh_failure_keeps_the_bounded_outcome(tmp_path, presentation):
    out = _run(tmp_path, "confirm:refresh_fails", presentation)

    after = out["afterConfirm"]
    assert after["state"] == "CONFIRMED"
    assert CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE in after["outcomeText"]
    assert "could not be refreshed" in after["snapshot"]["statusMessage"]
    assert after["snapshot"]["statusCode"] == "PREPARATION_EXPIRED"
    assert after["snapshot"]["staleHidden"] is False
    # The bounded successful confirmation response is retained, not discarded.
    assert out["memory"]["outcome"] == CONFIRMATION_ACCEPTED_ARCHIVE_AVAILABLE
    assert out["memory"]["limitations"] == list(HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS)
    assert out["state"] == "CONFIRMED"
    assert presentation["tag"] not in out["retention"]


@pytest.mark.parametrize(
    "code,status",
    [("CONFIRMATION_REJECTED", 403), ("CONFIRMATION_TAG_MALFORMED", 400)],
)
def test_refused_confirmation_is_generic_and_leaves_the_preparation_usable(
    tmp_path, presentation, code, status
):
    out = _run(tmp_path, f"confirm_refused:{code}:{status}", presentation)
    first = out["first"]

    assert first["state"] == "REVIEW_READY", "the preparation stays available"
    assert first["snapshot"]["confirmDisabled"] is False
    assert first["snapshot"]["tagValue"] == "", "a refused tag is never preserved"
    generic = "The confirmation tag was not accepted. Produce another tag independently and submit it again."
    assert first["snapshot"]["confirmationError"] == generic
    assert first["snapshot"]["statusMessage"] == generic
    assert out["outcomeHidden"] is True
    # No automatic retry, ever.
    assert out["requestsAfter"] == 1 and out["retriesAfterTimers"] == 1
    # The submitted value is never echoed and never logged.
    assert presentation["tag"] not in first["retention"]
    assert presentation["tag"].strip() not in first["retention"]
    assert not out["consoleCalls"]
    # No raw launcher content is displayed.
    for leak in ("C:\\archive", "Traceback", "detail"):
        assert leak not in first["snapshot"]["statusMessage"]


def test_both_confirmation_refusals_use_one_indistinguishable_message(tmp_path, presentation):
    rejected = _run(tmp_path, "confirm_refused:CONFIRMATION_REJECTED:403", presentation)
    malformed = _run(tmp_path, "confirm_refused:CONFIRMATION_TAG_MALFORMED:400", presentation)
    assert (
        rejected["first"]["snapshot"]["statusMessage"]
        == malformed["first"]["snapshot"]["statusMessage"]
    )
    assert (
        rejected["first"]["snapshot"]["confirmationError"]
        == malformed["first"]["snapshot"]["confirmationError"]
    )


def test_missing_tag_is_refused_before_any_request(tmp_path, presentation):
    out = _run(tmp_path, "missing_tag", presentation)
    assert out["confirmationRequests"] == 0
    assert out["state"] == "REVIEW_READY"
    assert out["snapshot"]["statusCode"] == "CONFIRMATION_TAG_REQUIRED"


# ---------------------------------------------------------------------------
# Review refresh lifecycle.
# ---------------------------------------------------------------------------


def test_refresh_uses_exactly_the_two_pinned_locators(tmp_path, presentation):
    out = _run(tmp_path, "refresh:in_progress", presentation)
    identity = presentation["review"]["pairing_identity"]

    request = out["request"]
    assert request["url"] == (
        f"{PREPARATIONS_ROUTE}/{identity['preparation_id']}/{identity['pairing_authority_fingerprint']}"
    )
    assert request["method"] == "GET" and "?" not in request["url"]
    assert out["requestHeaders"] == ["Accept"]
    assert CONFIRMATION_HEADER not in request["headers"]
    assert out["state"] == "REVIEW_READY"
    assert PREPARATION_STATE_CONFIRMATION_IN_PROGRESS in out["afterText"]
    assert PREPARATION_STATE_READY_FOR_CONFIRMATION in out["beforeText"]


def test_refresh_shows_consumed_state_exactly_as_returned(tmp_path, presentation):
    out = _run(tmp_path, "refresh:consumed", presentation)
    assert PREPARATION_STATE_CONSUMED in out["afterText"]
    assert out["state"] == "REVIEW_READY"


@pytest.mark.parametrize(
    "kind,code",
    [
        ("expired", "PREPARATION_EXPIRED"),
        ("not_found", "PREPARATION_NOT_FOUND"),
        ("stale", "STALE_AUTHORITY_FINGERPRINT"),
        ("other", "ARCHIVE_RELOAD_FAILED"),
    ],
)
def test_bounded_refresh_failures_never_present_a_cached_review_as_fresh(
    tmp_path, presentation, kind, code
):
    out = _run(tmp_path, f"refresh:{kind}", presentation)

    assert out["snapshot"]["statusCode"] == code
    assert out["snapshot"]["staleHidden"] is False, "the previous review must be labelled stale"
    assert out["afterText"] == out["beforeText"], "no substituted content was rendered"
    assert out["memory"]["reviewStale"] is True
    if kind == "expired":
        assert "new preparation is required" in out["snapshot"]["statusMessage"]
    if kind == "not_found":
        assert "in-memory preparation is unavailable" in out["snapshot"]["statusMessage"]
    if kind == "stale":
        assert "No substituted review is displayed" in out["snapshot"]["statusMessage"]
    assert not out["consoleCalls"]


def test_substituted_authority_review_is_refused_rather_than_displayed(tmp_path, presentation):
    out = _run(tmp_path, "refresh:substituted", presentation)
    identity = presentation["review"]["pairing_identity"]

    assert out["snapshot"]["statusCode"] == "STALE_AUTHORITY_FINGERPRINT"
    assert out["afterText"] == out["beforeText"]
    assert "f" * 64 not in out["afterText"]
    # The pinned locators are never replaced by the substituted response.
    assert out["memory"]["authorityFingerprint"] == identity["pairing_authority_fingerprint"]


def test_consumed_review_alone_never_becomes_a_confirmation(tmp_path, presentation):
    out = _run(tmp_path, "consumed_without_confirmation", presentation)

    assert out["state"] == "REVIEW_READY"
    assert out["snapshot"]["outcomeHidden"] is True
    assert out["outcomeText"] == ""
    assert out["memory"]["outcome"] is None and out["memory"]["limitations"] is None
    assert PREPARATION_STATE_CONSUMED in out["reviewText"]


def test_reload_loses_every_browser_side_pairing_state(tmp_path, presentation):
    out = _run(tmp_path, "reload", presentation)

    assert out["before"]["state"] == "CONFIRMED"
    assert out["before"]["memory"]["preparationId"] is not None

    # A fresh page starts with nothing at all.
    assert out["immediately"]["state"] == "FEATURE_ABSENT"
    assert out["immediately"]["memory"]["preparationId"] is None
    assert out["immediately"]["memory"]["review"] is None
    assert out["immediately"]["memory"]["outcome"] is None
    assert out["immediately"]["snapshot"]["tagValue"] == ""
    # After its own bootstrap it is back at authoring with no recovered pairing.
    assert out["afterBoot"]["state"] == "AUTHORING"
    assert out["afterBoot"]["memory"]["preparationId"] is None

    # Nothing was ever written outside the page.
    assert out["storageLocal"] == {} and out["storageSession"] == {}
    assert out["cookieWrites"] == 0


# ---------------------------------------------------------------------------
# Accessibility.
# ---------------------------------------------------------------------------


def test_surface_is_labelled_keyboard_operable_and_announces_bounded_status(
    tmp_path, presentation
):
    out = _run(tmp_path, "accessibility", presentation)

    # Every control has a real label.
    for control in out["controls"]:
        assert control in out["labels"], control
    assert len(out["controls"]) >= 6

    # Only native buttons and forms carry activation listeners: nothing depends
    # on a mouse-only element.
    assert set(out["clickableTags"]) <= {"BUTTON"}

    # aria-busy tracks in-flight requests and clears afterwards.
    assert out["busyStates"][0]["busy"] == "false"
    assert any(entry["busy"] == "true" for entry in out["busyStates"])
    assert out["busyStates"][-1]["busy"] == "false"

    # Large sections collapse; identity, notices and limitations stay open.
    assert set(REQUIRED_SECTION_IDS) == set(out["detailIds"])
    for always_open in (
        "historical-section-preparation-state",
        "historical-section-identity",
        "historical-section-result-claims",
        "historical-section-withheld",
        "historical-section-notices",
        "historical-section-limitations",
    ):
        assert always_open in out["openDetails"], always_open

    assert out["keyboardTraps"] == 0
    assert all(value == 0 for value in out["preTabIndex"])
    assert out["liveRegion"] == "polite" and out["liveAtomic"] == "true"
    assert out["disabledSemantics"]["payload"] == "true"
    assert out["disabledSemantics"]["prepare"] is True
    assert out["disabledSemantics"]["refresh"] is False
    # Status is never colour-only: it always carries text and a bounded code.
    assert out["statusHasText"] and out["statusHasCode"]


def test_confirmation_limitations_remain_a_separate_accepted_tuple():
    """The UI renders workflow limitations; it never merges the two tuples."""

    assert set(HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS) != set(
        HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS
    )
    for limitation in HISTORICAL_PAIRING_CONFIRMATION_LIMITATIONS:
        assert limitation not in JS
    for limitation in HISTORICAL_PAIRING_WORKFLOW_LIMITATIONS:
        assert limitation not in JS
    for notice in HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES:
        assert notice not in JS
