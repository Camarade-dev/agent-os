from __future__ import annotations

from html.parser import HTMLParser
from http.client import HTTPConnection
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
import time
from urllib.request import urlopen

import pytest

from admissible.product_launcher.ui_transport import create_ui_loopback_server
from admissible.product_ui import get_asset, render_document


ROOT = Path(__file__).parents[1]
HTML = render_document(csrf_nonce="c" * 64, authorization_mode="INTERACTIVE_BOUND_CONFIRMATION").decode()
CSS = (ROOT / "admissible/product_ui/app.css").read_text(encoding="utf-8")
JS = (ROOT / "admissible/product_ui/app.js").read_text(encoding="utf-8")
JS_PATH = ROOT / "admissible/product_ui/app.js"
CSS_BYTES = (ROOT / "admissible/product_ui/app.css").read_bytes()
JS_BYTES = JS_PATH.read_bytes()
CHROME = Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
NODE = "node"


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
        self.launch_delay = 0.0
        self.launch_status = 202
        self.launch_body = {"control_run_id": "control-1", "control_state": "QUEUED"}

    def bootstrap(self, nonce):
        return {
            "service": "admissible-product-launcher",
            "version": "g2.5",
            "repository_display_path": "safe-repository",
            "required_source_head": "a" * 40,
            "authorization_mode": self.authorization_mode,
            "authorization_semantics_notice": (
                "The launcher forwards the owner-supplied digest unchanged and never derives it."
            ),
            "owner_authorization_encoding": "latin-1",
            "g2_ready": True,
            "g2_api_version": "v1",
            "csrf_nonce": nonce,
            "supported_authoring_template_ids": ["observed_local_git_v1"],
            "visual_ui_available": False,
        }

    def author_and_validate(self, body):
        self.calls.append(("author", body))
        return 200, {
            "contract_id": "contract-1",
            "profile_fingerprint": "b" * 64,
            "contract_summary": {
                "profile_id": "profile-1",
                "run_id": "run-1",
                "session_id": "session-1",
                "gate_id": "gate-1",
                "mission_id": "mission-1",
                "workspace_source_kind": "OBSERVED_LOCAL_GIT",
                "verification_mode": "NONE",
                "template_id": "observed_local_git_v1",
            },
            "generated_ids": {},
            "execution_started": False,
            "authorization_mode": self.authorization_mode,
        }

    def enqueue_preparation(self, contract_id):
        self.calls.append(("prepare", contract_id))
        return 202, {"preparation_id": "preparation-1", "state": "QUEUED"}

    def preparation_status(self, preparation_id):
        self.calls.append(("poll", preparation_id))
        self.polls += 1
        state = "RUNNING" if self.polls == 1 else "READY"
        return {
            "preparation_id": preparation_id,
            "contract_id": "contract-1",
            "state": state,
            "authorization_mode": self.authorization_mode,
            "authorization_semantics_notice": (
                "The launcher forwards the owner-supplied digest unchanged and never derives it."
            ),
            "consumed": False,
            "created_at": "now",
            "updated_at": "now",
            "payload_fingerprint": "c" * 64 if state == "READY" else None,
            "safe_payload_summary": {"run_id": "run-1"} if state == "READY" else None,
            "authorization_payload": {"payload_fingerprint": "c" * 64} if state == "READY" else None,
            "blocked_summary": None,
            "error_type": None,
        }

    def launch_run(self, **kwargs):
        self.calls.append(("launch", kwargs))
        if self.launch_delay:
            time.sleep(self.launch_delay)
        return self.launch_status, self.launch_body


def request(server, method, path, body=None, headers=None):
    connection = HTTPConnection(server.host, server.port, timeout=5)
    raw = None if body is None else json.dumps(body).encode()
    request_headers = {"Host": f"{server.host}:{server.port}", **(headers or {})}
    if raw is not None:
        request_headers.update({"Content-Type": "application/json", "Content-Length": str(len(raw))})
    connection.request(method, path, body=raw, headers=request_headers)
    response = connection.getresponse()
    payload = response.read()
    result = (response.status, dict(response.getheaders()), payload)
    connection.close()
    return result


def _raw_http_exchange(host: str, port: int, request_bytes: bytes, timeout: float = 3.0) -> tuple[bytes, bool]:
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(request_bytes)
        chunks: list[bytes] = []
        while True:
            try:
                piece = sock.recv(65536)
            except socket.timeout:
                break
            if not piece:
                return b"".join(chunks), True
            chunks.append(piece)
        return b"".join(chunks), False
    finally:
        sock.close()


NODE_HARNESS = r"""
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const scenario = process.argv[2];
const appJsPath = process.argv[3];
const appJs = fs.readFileSync(appJsPath, "utf8");

const MARKER = "__XSS_MARKER_INVOKED__";
let markerInvoked = 0;
const timers = new Map();
let nextTimerId = 1;
let nowMs = 0;
const fetchLog = [];
const storage = { local: Object.create(null), session: Object.create(null) };
let fetchImpl = null;
const pendingFetches = [];
const createdTags = [];
const assignedHandlers = [];
let unsafeHtmlApi = 0;

function makeStorage(bucket) {
  return {
    getItem(key) { return Object.prototype.hasOwnProperty.call(bucket, key) ? bucket[key] : null; },
    setItem(key, value) { bucket[String(key)] = String(value); },
    removeItem(key) { delete bucket[key]; },
    clear() { for (const key of Object.keys(bucket)) delete bucket[key]; },
    key(i) { return Object.keys(bucket)[i] || null; },
    get length() { return Object.keys(bucket).length; }
  };
}

class FakeAbortSignal {
  constructor() { this.aborted = false; this._listeners = []; }
  addEventListener(type, fn) { if (type === "abort") this._listeners.push(fn); }
  removeEventListener(type, fn) { this._listeners = this._listeners.filter(x => x !== fn); }
  _abort() {
    if (this.aborted) return;
    this.aborted = true;
    const err = new Error("Aborted"); err.name = "AbortError";
    for (const fn of this._listeners.splice(0)) fn(err);
  }
}
class FakeAbortController {
  constructor() { this.signal = new FakeAbortSignal(); }
  abort() { this.signal._abort(); }
}

class FakeNode {
  constructor(tagName = "", type = 1) {
    this.tagName = String(tagName).toUpperCase();
    this.nodeName = this.tagName;
    this.nodeType = type;
    this.children = [];
    this.childNodes = this.children;
    this.parentNode = null;
    this.attributes = Object.create(null);
    this.className = "";
    this.id = "";
    this._text = "";
    this.value = "";
    this.type = tagName === "input" ? "text" : "";
    this.hidden = false;
    this.disabled = false;
    this.required = false;
    this.checked = false;
    this.selected = false;
    this.maxLength = 0;
    this.autocomplete = "";
    this.pattern = "";
    this.htmlFor = "";
    this._listeners = Object.create(null);
    this.dataset = {};
    this.style = {};
  }
  get textContent() {
    if (!this.children.length) return this._text;
    return this.children.map(c => c.textContent).join("");
  }
  set textContent(v) {
    this.children.length = 0;
    this._text = v == null ? "" : String(v);
  }
  get innerHTML() { return this.textContent; }
  set innerHTML(v) { unsafeHtmlApi += 1; this.textContent = v; }
  get outerHTML() { return `<${this.tagName}>${this.textContent}</${this.tagName}>`; }
  setAttribute(name, value) {
    const key = String(name);
    this.attributes[key] = String(value);
    if (key === "id") { this.id = String(value); byId[this.id] = this; }
    if (key === "class") this.className = String(value);
    if (key === "type") this.type = String(value);
    if (key === "value") this.value = String(value);
    if (key === "content") this.content = String(value);
    if (key === "hidden") this.hidden = true;
    if (key === "disabled") this.disabled = true;
    if (key.startsWith("on")) assignedHandlers.push(key);
  }
  removeAttribute(name) {
    const key = String(name);
    delete this.attributes[key];
    if (key === "hidden") this.hidden = false;
    if (key === "disabled") this.disabled = false;
    if (key === "aria-disabled") delete this.attributes[key];
  }
  getAttribute(name) {
    const key = String(name);
    if (key === "hidden") return this.hidden ? "" : null;
    if (key === "disabled") return this.disabled ? "" : null;
    return Object.prototype.hasOwnProperty.call(this.attributes, key) ? this.attributes[key] : null;
  }
  hasAttribute(name) { return this.getAttribute(name) !== null; }
  append(...nodes) { for (const n of nodes) this.appendChild(n); }
  appendChild(node) {
    if (typeof node === "string") { const t = new FakeNode("#text", 3); t.textContent = node; node = t; }
    node.parentNode = this; this.children.push(node); return node;
  }
  removeChild(node) {
    const idx = this.children.indexOf(node);
    if (idx >= 0) this.children.splice(idx, 1);
    node.parentNode = null;
    return node;
  }
  remove() { if (this.parentNode) this.parentNode.removeChild(this); }
  replaceChildren(...nodes) { this.children.length = 0; this.append(...nodes); }
  focus() {}
  click() {
    const list = this._listeners.click || [];
    for (const fn of list.slice()) fn({ type: "click", preventDefault() {}, target: this });
  }
  addEventListener(type, fn) {
    (this._listeners[type] = this._listeners[type] || []).push(fn);
  }
  removeEventListener(type, fn) {
    this._listeners[type] = (this._listeners[type] || []).filter(x => x !== fn);
  }
  dispatchEvent(event) {
    const list = this._listeners[event.type] || [];
    for (const fn of list.slice()) fn(event);
    return true;
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  querySelectorAll(sel) {
    const out = [];
    const visit = (node) => {
      if (matchSelector(node, sel)) out.push(node);
      for (const child of node.children) visit(child);
    };
    for (const child of this.children) visit(child);
    return out;
  }
}

function matchSelector(node, sel) {
  if (!sel) return false;
  if (sel.startsWith("#")) return node.id === sel.slice(1);
  if (sel.startsWith(".")) return (" " + (node.className || "") + " ").includes(" " + sel.slice(1) + " ");
  if (sel.includes("[")) {
    const m = /^([a-z0-9-]*)\[([^=\]]+)(?:=['"]?([^'"\]]+)['"]?)?\]$/i.exec(sel);
    if (!m) return false;
    if (m[1] && node.tagName !== m[1].toUpperCase()) return false;
    const attr = m[2];
    const expected = m[3];
    const actual = node.getAttribute(attr);
    if (expected === undefined) return actual !== null;
    return actual === expected;
  }
  if (sel.includes(" ")) {
    const parts = sel.trim().split(/\s+/);
    // only support simple descendant for "input" under current node via querySelectorAll walk
    return matchSelector(node, parts[parts.length - 1]);
  }
  return node.tagName === sel.toUpperCase();
}

function el(tag, attrs = {}, children = []) {
  const node = new FakeNode(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "text") node.textContent = v;
    else if (k === "className") { node.className = v; node.setAttribute("class", v); }
    else if (k === "htmlFor") { node.htmlFor = v; node.setAttribute("for", v); }
    else node.setAttribute(k, v);
  }
  for (const child of children) node.appendChild(typeof child === "string" ? Object.assign(new FakeNode("#text", 3), {_text: child}) : child);
  return node;
}

const byId = Object.create(null);
function register(node) {
  if (node.id) byId[node.id] = node;
  for (const child of node.children) register(child);
  return node;
}

const body = el("body");
const documentElement = el("html");
documentElement.appendChild(body);

function buildDom() {
  const metaCsrf = el("meta", { name: "admissible-ui-csrf", content: "c".repeat(64) });
  const metaMode = el("meta", { name: "admissible-authorization-mode", content: "PRECOMMITTED_DIGEST" });
  const head = el("head", {}, [metaCsrf, metaMode]);
  documentElement.children = [head, body];
  head.parentNode = documentElement; body.parentNode = documentElement;

  const steps = el("nav", { className: "steps" }, [
    el("ol", {}, [
      el("li", { "data-step": "compose" }),
      el("li", { "data-step": "contract" }),
      el("li", { "data-step": "authorize" }),
    ])
  ]);
  steps.children[0].children[0].dataset.step = "compose";
  steps.children[0].children[1].dataset.step = "contract";
  steps.children[0].children[2].dataset.step = "authorize";

  const nodes = [
    el("div", { id: "live-status" }),
    el("section", { id: "loading-view" }),
    el("section", { id: "compose-view", hidden: "true" }, [
      el("form", { id: "compose-form" }, [
        el("textarea", { id: "mission-text" }),
        el("p", { id: "mission-error" }),
        el("textarea", { id: "gate-objective" }),
        el("p", { id: "objective-error" }),
        el("textarea", { id: "completion-conditions" }),
        el("p", { id: "conditions-error" }),
        el("div", { id: "material-list" }),
        el("button", { id: "add-material", type: "button" }),
        el("input", { id: "commit-message" }),
        el("p", { id: "commit-error" }),
        el("select", { id: "template-id" }),
        el("input", { id: "model" }),
        el("input", { id: "timeout-seconds" }),
        el("button", { id: "author-button", type: "submit" }),
      ])
    ]),
    el("section", { id: "contract-view", hidden: "true" }, [
      el("dl", { id: "contract-facts" }),
      el("dl", { id: "intent-facts" }),
      el("button", { id: "back-to-compose", type: "button" }),
      el("button", { id: "prepare-button", type: "button", className: "button primary" }),
    ]),
    el("section", { id: "preparation-view", hidden: "true" }, [
      el("p", { id: "preparation-copy" }),
      el("button", { id: "retry-preparation", type: "button", hidden: "true" }),
      el("button", { type: "button", className: "button quiet reset-flow", text: "Return to compose" }),
    ]),
    el("section", { id: "authorize-view", hidden: "true" }, [
      el("dl", { id: "preparation-facts" }),
      el("pre", { id: "canonical-payload" }),
      el("pre", { id: "safe-summary" }),
      el("p", { id: "mode-label" }),
      el("p", { id: "authorization-notice" }),
      el("p", { id: "encoding-notice" }),
      el("div", { id: "digest-slot" }),
      el("form", { id: "authorize-form" }, [
        el("input", { id: "owner-phrase", type: "password" }),
        el("button", { id: "toggle-phrase", type: "button", "aria-pressed": "false", text: "Show" }),
        el("p", { id: "owner-phrase-error" }),
        el("button", { type: "button", className: "button quiet reset-flow", text: "Return to compose" }),
        el("button", { id: "launch-button", type: "submit" }),
      ])
    ]),
    el("section", { id: "accepted-view", hidden: "true" }, [
      el("dl", { id: "accepted-facts" }),
      el("button", { type: "button", className: "button primary reset-flow", text: "Compose another mission" }),
    ]),
    el("dl", { id: "bootstrap-facts" }),
    el("section", { id: "status-area", hidden: "true" }, [
      el("p", { id: "status-message" }),
      el("code", { id: "status-code" }),
      el("button", { id: "retry-bootstrap", type: "button", hidden: "true" }),
    ]),
    steps,
  ];
  body.replaceChildren(...nodes);
  // ensure inputs have defaults used by compose
  byId["model"] && (byId["model"].value = "auto");
  byId["timeout-seconds"] && (byId["timeout-seconds"].value = "60");
  // rebuild id index
  for (const key of Object.keys(byId)) delete byId[key];
  register(documentElement);
  // class-based reset buttons need className set properly
  for (const node of body.querySelectorAll(".reset-flow")) {
    if (!node.className.includes("reset-flow")) node.className += (node.className ? " " : "") + "reset-flow";
  }
}

// Fix el() for data-step and hidden boolean attrs
const _origEl = el;
el = function(tag, attrs = {}, children = []) {
  const node = new FakeNode(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "text") node.textContent = v;
    else if (k === "className") { node.className = v; node.attributes.class = v; }
    else if (k === "htmlFor") { node.htmlFor = v; node.attributes.for = v; }
    else if (k === "hidden") { node.hidden = true; node.attributes.hidden = ""; }
    else if (k.startsWith("data-")) { node.dataset[k.slice(5)] = String(v); node.attributes[k] = String(v); }
    else node.setAttribute(k, v);
  }
  for (const child of children) {
    if (typeof child === "string") {
      const t = new FakeNode("#text", 3); t._text = child; node.appendChild(t);
    } else node.appendChild(child);
  }
  return node;
};

buildDom();

const document = {
  body,
  documentElement,
  getElementById(id) { return byId[id] || null; },
  querySelector(sel) {
    if (sel.startsWith("meta[")) {
      const name = /name=["']([^"']+)["']/.exec(sel)?.[1];
      for (const node of documentElement.querySelectorAll("meta")) {
        if (node.getAttribute("name") === name) return node;
      }
      return null;
    }
    return documentElement.querySelector(sel);
  },
  querySelectorAll(sel) { return documentElement.querySelectorAll(sel); },
  createElement(tag) {
    const node = new FakeNode(tag);
    createdTags.push(String(tag).toLowerCase());
    Object.defineProperty(node, "id", {
      get() { return node._id || ""; },
      set(v) { node._id = String(v); node.attributes.id = node._id; if (node._id) byId[node._id] = node; }
    });
    Object.defineProperty(node, "onerror", {
      set(fn) { assignedHandlers.push("onerror"); if (typeof fn === "function") try { fn(); } catch (_) {} },
      get() { return null; }
    });
    Object.defineProperty(node, "onload", {
      set(fn) { assignedHandlers.push("onload"); if (typeof fn === "function") try { fn(); } catch (_) {} },
      get() { return null; }
    });
    return node;
  }
};

const windowObj = {
  document,
  AdmissibleG3Test: undefined,
  localStorage: makeStorage(storage.local),
  sessionStorage: makeStorage(storage.session),
  addEventListener(type, fn, opts) {
    (windowObj._listeners = windowObj._listeners || {});
    (windowObj._listeners[type] = windowObj._listeners[type] || []).push({ fn, opts });
  },
  dispatch(type) {
    for (const { fn } of (windowObj._listeners && windowObj._listeners[type]) || []) fn({});
  }
};

function setTimeoutFn(fn, ms) {
  const id = nextTimerId++;
  timers.set(id, { fn, due: nowMs + (ms || 0) });
  return id;
}
function clearTimeoutFn(id) { timers.delete(id); }
async function flushTimers(maxSteps = 50) {
  for (let step = 0; step < maxSteps; step++) {
    if (!timers.size) return;
    let nextDue = Infinity;
    for (const t of timers.values()) nextDue = Math.min(nextDue, t.due);
    nowMs = nextDue;
    const due = [];
    for (const [id, t] of timers.entries()) if (t.due <= nowMs) due.push([id, t]);
    if (!due.length) return;
    for (const [id, t] of due) {
      timers.delete(id);
      // Do not await the callback: poll ticks may block on deferred fetch.
      Promise.resolve().then(() => t.fn()).catch(() => {});
    }
    await settle();
  }
}

function jsonResponse(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() { return body; }
  };
}

function installDefaultFetch(mode = "happy") {
  let poll = 0;
  fetchImpl = async (url, options = {}) => {
    const method = (options.method || "GET").toUpperCase();
    fetchLog.push({ url, method, headers: { ...(options.headers || {}) } });
    if (options.signal && options.signal.aborted) {
      const err = new Error("Aborted"); err.name = "AbortError"; throw err;
    }
    if (url === "/ui/api/v1/bootstrap") {
      return jsonResponse(200, {
        service: "admissible-product-launcher", version: "g2.5",
        repository_display_path: "safe-repository", required_source_head: "a".repeat(40),
        authorization_mode: "PRECOMMITTED_DIGEST",
        authorization_semantics_notice: "notice",
        owner_authorization_encoding: "latin-1", g2_ready: true, g2_api_version: "v1",
        csrf_nonce: "c".repeat(64), supported_authoring_template_ids: ["observed_local_git_v1"],
        visual_ui_available: false
      });
    }
    if (url === "/ui/api/v1/contracts" && method === "POST") {
      const input = JSON.parse(options.body || "{}");
      return jsonResponse(200, {
        contract_id: "contract-xss-1",
        profile_fingerprint: "b".repeat(64),
        contract_summary: {
          profile_id: "profile-<img onerror=1>",
          run_id: "run-1", session_id: "session-1", gate_id: "gate-1", mission_id: "mission-1",
          workspace_source_kind: "OBSERVED_LOCAL_GIT", verification_mode: "NONE",
          template_id: "observed_local_git_v1"
        },
        generated_ids: { profile_id: "gen-<script>alert(1)</script>" },
        execution_started: false,
        authorization_mode: "PRECOMMITTED_DIGEST",
        echo_mission: input.mission_text
      });
    }
    if (url.includes("/preparations") && method === "POST") {
      return jsonResponse(202, { preparation_id: "preparation-1", state: "QUEUED" });
    }
    if (url.startsWith("/ui/api/v1/preparations/") && method === "GET") {
      poll += 1;
      if (mode === "stay_queued") {
        return jsonResponse(200, {
          preparation_id: "preparation-1", contract_id: "contract-xss-1", state: "QUEUED",
          authorization_mode: "PRECOMMITTED_DIGEST", authorization_semantics_notice: "notice",
          consumed: false, created_at: "now", updated_at: "now",
          payload_fingerprint: null, safe_payload_summary: null, authorization_payload: null,
          blocked_summary: null, error_type: null
        });
      }
      const state = poll === 1 ? "RUNNING" : "READY";
      return jsonResponse(200, {
        preparation_id: "preparation-1", contract_id: "contract-xss-1", state,
        authorization_mode: "PRECOMMITTED_DIGEST",
        authorization_semantics_notice: "notice <svg onload=1>",
        consumed: false, created_at: "now", updated_at: "now",
        payload_fingerprint: state === "READY" ? "c".repeat(64) : null,
        safe_payload_summary: state === "READY" ? { note: "</pre><script>" } : null,
        authorization_payload: state === "READY" ? { payload: "<script>", marker: "`quotes`" } : null,
        blocked_summary: state === "BLOCKED" ? { reason: "<img onerror=1>" } : null,
        error_type: null
      });
    }
    if (url === "/ui/api/v1/runs" && method === "POST") {
      if (mode === "launch_400") return jsonResponse(400, { error: "OWNER_AUTHORIZATION_INVALID" });
      if (mode === "launch_409") return jsonResponse(409, { error: "RUN_CONFLICT" });
      if (mode === "launch_500") return jsonResponse(500, { error: "WRITE_UNAVAILABLE" });
      if (mode === "launch_network") { const err = new Error("network"); throw err; }
      return jsonResponse(202, { control_run_id: "control-1", control_state: "QUEUED" });
    }
    return jsonResponse(404, { error: "NOT_FOUND" });
  };
}

function deferredFetchController() {
  const queue = [];
  fetchImpl = (url, options = {}) => new Promise((resolve, reject) => {
    const entry = { url, options, resolve, reject, method: (options.method || "GET").toUpperCase() };
    fetchLog.push({ url, method: entry.method, headers: { ...(options.headers || {}) } });
    if (options.signal) {
      options.signal.addEventListener("abort", () => {
        const err = new Error("Aborted"); err.name = "AbortError"; reject(err);
      });
    }
    queue.push(entry);
  });
  return {
    queue,
    async resolveNext(status, body) {
      const entry = queue.shift();
      if (!entry) throw new Error("no pending fetch");
      entry.resolve(jsonResponse(status, body));
      await Promise.resolve();
      await Promise.resolve();
    },
    pending() { return queue.map(x => ({ url: x.url, method: x.method })); }
  };
}

async function settle() {
  for (let i = 0; i < 20; i++) await Promise.resolve();
}

const context = {
  console,
  window: windowObj,
  document,
  fetch: (...args) => fetchImpl(...args),
  setTimeout: setTimeoutFn,
  clearTimeout: clearTimeoutFn,
  AbortController: FakeAbortController,
  Event: class Event {
    constructor(type, init = {}) { this.type = type; this.bubbles = !!init.bubbles; this.cancelable = !!init.cancelable; }
    preventDefault() {}
  },
  Object, Array, String, Number, Boolean, JSON, Error, Promise, Math, RegExp, Date,
  encodeURIComponent, Set, Map, freeze: Object.freeze,
};
context.global = context;
context.globalThis = context;
windowObj.window = windowObj;
windowObj.fetch = context.fetch;
windowObj.setTimeout = setTimeoutFn;
windowObj.clearTimeout = clearTimeoutFn;
windowObj.AbortController = FakeAbortController;
windowObj.Event = context.Event;
// mirror common browser globals
for (const key of ["document", "fetch", "setTimeout", "clearTimeout", "AbortController", "Event"]) {
  // already on context
}

function loadApp() {
  markerInvoked = 0;
  unsafeHtmlApi = 0;
  createdTags.length = 0;
  assignedHandlers.length = 0;
  fetchLog.length = 0;
  timers.clear();
  nowMs = 0;
  storage.local = Object.create(null);
  storage.session = Object.create(null);
  windowObj.localStorage = makeStorage(storage.local);
  windowObj.sessionStorage = makeStorage(storage.session);
  windowObj._listeners = {};
  buildDom();
  // trap marker side effects
  context[MARKER] = () => { markerInvoked += 1; };
  vm.runInNewContext(appJs, context, { filename: "app.js", timeout: 5000 });
  if (!context.window.AdmissibleG3Test && !windowObj.AdmissibleG3Test) {
    // app writes to window via Object.defineProperty on global window - ensure same object
  }
  // The IIFE uses unqualified document/fetch/window from the context object.
  // Object.defineProperty(window, ...) needs window in context.
}

// Ensure app.js sees window
context.window = windowObj;

async function waitState(wanted, steps = 40) {
  const g3 = windowObj.AdmissibleG3Test;
  for (let i = 0; i < steps; i++) {
    await settle();
    await flushTimers(5);
    if (g3.getState() === wanted) return;
  }
  throw new Error(`state ${wanted} not reached, have ${g3.getState()}`);
}

async function fillCompose(payload) {
  const g3 = windowObj.AdmissibleG3Test;
  g3.setField("mission-text", payload);
  g3.setField("gate-objective", payload);
  g3.setField("completion-conditions", payload);
  g3.setField("commit-message", "feat: safe");
  // template filled by bootstrap
  const select = document.getElementById("template-id");
  if (select && select.children[0]) select.value = select.children[0].value || select.children[0].textContent;
}

async function runDomInjection() {
  installDefaultFetch("happy");
  loadApp();
  await waitState("COMPOSE");
  const payload = `<script>${MARKER}()</script><img onerror="${MARKER}()"><svg onload="${MARKER}()"></svg></pre>"\`quotes\`\u0001\u0007`;
  await fillCompose(payload);
  windowObj.AdmissibleG3Test.submit("compose-form");
  await waitState("CONTRACT_READY");
  windowObj.AdmissibleG3Test.click("prepare-button");
  await flushTimers(40);
  await waitState("PREPARATION_READY");
  const snap = windowObj.AdmissibleG3Test.snapshot();
  const textBlob = [
    snap.intentFacts, snap.contractFacts, snap.canonicalPayload, snap.preparationCopy,
    document.getElementById("safe-summary").textContent,
    document.getElementById("authorization-notice").textContent,
    document.getElementById("mode-label").textContent,
  ].join("\n");
  return {
    scenario: "dom_injection",
    state: snap.state,
    markerInvoked,
    unsafeHtmlApi,
    createdScriptTags: createdTags.filter(t => t === "script").length,
    assignedHandlers: assignedHandlers.slice(),
    textContainsPayload: textBlob.includes("<script>") && textBlob.includes("quotes"),
    hasExecutableNodes: createdTags.includes("script") || assignedHandlers.length > 0,
    snapshotSecretsEmpty: snap.phraseValue === "" && snap.digestValue === "",
  };
}

async function assertSecretsClear(label) {
  const snap = windowObj.AdmissibleG3Test.snapshot();
  const phrase = document.getElementById("owner-phrase");
  const digest = document.getElementById("owner-digest");
  const toggle = document.getElementById("toggle-phrase");
  const rendered = snap.statusMessage + snap.statusCode + snap.acceptedText + snap.preparationCopy;
  return {
    label,
    state: snap.state,
    phraseEmpty: phrase.value === "",
    phraseTypePassword: phrase.type === "password",
    digestEmpty: !digest || digest.value === "",
    revealReset: toggle.textContent === "Show" && toggle.getAttribute("aria-pressed") === "false",
    noSecretInErrors: !rendered.includes("owner-secret") && !rendered.includes("d".repeat(64)),
    noLocalStorage: Object.keys(storage.local).length === 0,
    noSessionStorage: Object.keys(storage.session).length === 0,
    snapshotPhraseEmpty: snap.phraseValue === "",
    snapshotDigestEmpty: snap.digestValue === "",
  };
}

async function goToReady(mode = "happy") {
  installDefaultFetch(mode);
  loadApp();
  await waitState("COMPOSE");
  await fillCompose("mission");
  windowObj.AdmissibleG3Test.setField("gate-objective", "objective");
  windowObj.AdmissibleG3Test.setField("completion-conditions", "complete");
  windowObj.AdmissibleG3Test.setField("commit-message", "feat: mission");
  windowObj.AdmissibleG3Test.submit("compose-form");
  await waitState("CONTRACT_READY");
  windowObj.AdmissibleG3Test.click("prepare-button");
  await flushTimers(30);
  await waitState("PREPARATION_READY");
  windowObj.AdmissibleG3Test.setField("owner-phrase", "owner-secret-phrase");
  windowObj.AdmissibleG3Test.setField("owner-digest", "d".repeat(64));
  document.getElementById("owner-phrase").type = "text";
  document.getElementById("toggle-phrase").textContent = "Hide";
  document.getElementById("toggle-phrase").setAttribute("aria-pressed", "true");
}

async function runSecretClearing() {
  const results = [];
  for (const mode of ["happy", "launch_400", "launch_409", "launch_500", "launch_network"]) {
    await goToReady(mode);
    fetchLog.length = 0;
    windowObj.AdmissibleG3Test.submit("authorize-form");
    await settle();
    await flushTimers(5);
    results.push(await assertSecretsClear(mode));
  }
  await goToReady("happy");
  windowObj.AdmissibleG3Test.setField("owner-phrase", "owner-secret-phrase");
  windowObj.AdmissibleG3Test.setField("owner-digest", "d".repeat(64));
  windowObj.AdmissibleG3Test.reset();
  await settle();
  results.push(await assertSecretsClear("reset"));
  return { scenario: "secret_clearing", results };
}

async function runStalePolling() {
  const ctl = deferredFetchController();
  loadApp();
  // bootstrap
  await settle();
  await ctl.resolveNext(200, {
    service: "admissible-product-launcher", version: "g2.5",
    repository_display_path: "safe-repository", required_source_head: "a".repeat(40),
    authorization_mode: "PRECOMMITTED_DIGEST", authorization_semantics_notice: "notice",
    owner_authorization_encoding: "latin-1", g2_ready: true, g2_api_version: "v1",
    csrf_nonce: "c".repeat(64), supported_authoring_template_ids: ["observed_local_git_v1"],
    visual_ui_available: false
  });
  await waitState("COMPOSE");
  await fillCompose("mission");
  windowObj.AdmissibleG3Test.setField("gate-objective", "o");
  windowObj.AdmissibleG3Test.setField("completion-conditions", "c");
  windowObj.AdmissibleG3Test.setField("commit-message", "feat: x");
  windowObj.AdmissibleG3Test.submit("compose-form");
  await settle();
  await ctl.resolveNext(200, {
    contract_id: "contract-1", profile_fingerprint: "b".repeat(64),
    contract_summary: { profile_id: "p", run_id: "r", session_id: "s", gate_id: "g", mission_id: "m",
      workspace_source_kind: "OBSERVED_LOCAL_GIT", verification_mode: "NONE", template_id: "observed_local_git_v1" },
    generated_ids: {}, execution_started: false, authorization_mode: "PRECOMMITTED_DIGEST"
  });
  await waitState("CONTRACT_READY");

  // start prepare but hold the POST
  const preparePromise = windowObj.AdmissibleG3Test.prepare();
  await settle();
  const prepPending = ctl.pending().filter(x => x.method === "POST");
  // reset while preparation POST in flight
  windowObj.AdmissibleG3Test.reset();
  await settle();
  // resolve stale preparation POST
  await ctl.resolveNext(202, { preparation_id: "stale-prep", state: "QUEUED" });
  await preparePromise.catch(() => {});
  await settle();
  const afterStale = windowObj.AdmissibleG3Test.snapshot();

  // new flow
  await fillCompose("mission-2");
  windowObj.AdmissibleG3Test.setField("gate-objective", "o");
  windowObj.AdmissibleG3Test.setField("completion-conditions", "c");
  windowObj.AdmissibleG3Test.setField("commit-message", "feat: y");
  windowObj.AdmissibleG3Test.submit("compose-form");
  await settle();
  await ctl.resolveNext(200, {
    contract_id: "contract-2", profile_fingerprint: "b".repeat(64),
    contract_summary: { profile_id: "p", run_id: "r", session_id: "s", gate_id: "g", mission_id: "m",
      workspace_source_kind: "OBSERVED_LOCAL_GIT", verification_mode: "NONE", template_id: "observed_local_git_v1" },
    generated_ids: {}, execution_started: false, authorization_mode: "PRECOMMITTED_DIGEST"
  });
  await waitState("CONTRACT_READY");
  windowObj.AdmissibleG3Test.prepare();
  await settle();
  await ctl.resolveNext(202, { preparation_id: "prep-2", state: "QUEUED" });
  await settle();
  // one poll in flight
  let inFlightPolls = ctl.pending().filter(x => x.url.includes("/preparations/") && x.method === "GET");
  await ctl.resolveNext(200, {
    preparation_id: "prep-2", contract_id: "contract-2", state: "RUNNING",
    authorization_mode: "PRECOMMITTED_DIGEST", authorization_semantics_notice: "n",
    consumed: false, created_at: "now", updated_at: "now",
    payload_fingerprint: null, safe_payload_summary: null, authorization_payload: null,
    blocked_summary: null, error_type: null
  });
  await settle();
  await flushTimers(2);
  inFlightPolls = ctl.pending().filter(x => x.url.includes("/preparations/") && x.method === "GET");
  const duringPoll = windowObj.AdmissibleG3Test.snapshot();

  // terminal READY stops polling
  await ctl.resolveNext(200, {
    preparation_id: "prep-2", contract_id: "contract-2", state: "READY",
    authorization_mode: "PRECOMMITTED_DIGEST", authorization_semantics_notice: "n",
    consumed: false, created_at: "now", updated_at: "now",
    payload_fingerprint: "c".repeat(64),
    safe_payload_summary: { run_id: "r" },
    authorization_payload: { payload_fingerprint: "c".repeat(64) },
    blocked_summary: null, error_type: null
  });
  await settle();
  await flushTimers(5);
  const readySnap = windowObj.AdmissibleG3Test.snapshot();
  const pollsAfterReady = ctl.pending().filter(x => x.url.includes("/preparations/"));

  // launch acceptance stops polling
  windowObj.AdmissibleG3Test.setField("owner-phrase", "secret");
  windowObj.AdmissibleG3Test.setField("owner-digest", "d".repeat(64));
  windowObj.AdmissibleG3Test.submit("authorize-form");
  await settle();
  await ctl.resolveNext(202, { control_run_id: "control-1", control_state: "QUEUED" });
  await settle();
  const accepted = windowObj.AdmissibleG3Test.snapshot();

  // page teardown aborts polling: start another prepare path briefly then pagehide
  // (accepted already stopped). Re-bootstrap-like: just fire pagehide and ensure no timers.
  windowObj.dispatch("pagehide");
  await settle();
  const timersAfterTeardown = timers.size;

  return {
    scenario: "stale_polling",
    staleDidNotTakeOver: afterStale.state === "COMPOSE" && afterStale.preparationId === null,
    preparePosts: fetchLog.filter(x => x.method === "POST" && x.url.includes("/preparations")).length,
    onePollInFlight: inFlightPolls.length <= 1,
    duringPollHasController: duringPoll.hasPollController,
    readyStoppedPolling: readySnap.state === "PREPARATION_READY" && !readySnap.hasPollController && !readySnap.hasPollTimer && pollsAfterReady.length === 0,
    acceptedStoppedPolling: accepted.state === "LAUNCH_ACCEPTED" && !accepted.hasPollController && !accepted.hasPollTimer,
    teardownClearedTimers: timersAfterTeardown === 0,
    prepPendingAtReset: prepPending.length === 1,
  };
}

async function runNoPost202() {
  installDefaultFetch("happy");
  loadApp();
  await waitState("COMPOSE");
  await fillCompose("mission");
  windowObj.AdmissibleG3Test.setField("gate-objective", "objective");
  windowObj.AdmissibleG3Test.setField("completion-conditions", "complete");
  windowObj.AdmissibleG3Test.setField("commit-message", "feat: mission");
  windowObj.AdmissibleG3Test.submit("compose-form");
  await waitState("CONTRACT_READY");
  windowObj.AdmissibleG3Test.click("prepare-button");
  await flushTimers(30);
  await waitState("PREPARATION_READY");
  windowObj.AdmissibleG3Test.setField("owner-phrase", "owner-secret-phrase");
  windowObj.AdmissibleG3Test.setField("owner-digest", "d".repeat(64));
  fetchLog.length = 0;
  windowObj.AdmissibleG3Test.submit("authorize-form");
  await settle();
  await flushTimers(20);
  const snap = windowObj.AdmissibleG3Test.snapshot();
  const after = fetchLog.map(x => x.url);
  return {
    scenario: "no_post_202",
    state: snap.state,
    fetchAfterLaunch: after,
    noRunIdRead: after.every(u => !/\/ui\/api\/v1\/runs\/[^/]+$/.test(u)),
    noResultRead: after.every(u => !u.includes("/result")),
    noRunsList: after.filter(u => u === "/ui/api/v1/runs").length === 1, // the POST only
    onlyLaunchPost: after.length === 1 && after[0] === "/ui/api/v1/runs",
    acceptedRendered: snap.acceptedText.includes("control-1"),
  };
}

async function runDuplicatePrepare() {
  const ctl = deferredFetchController();
  loadApp();
  await settle();
  await ctl.resolveNext(200, {
    service: "admissible-product-launcher", version: "g2.5",
    repository_display_path: "safe-repository", required_source_head: "a".repeat(40),
    authorization_mode: "PRECOMMITTED_DIGEST", authorization_semantics_notice: "notice",
    owner_authorization_encoding: "latin-1", g2_ready: true, g2_api_version: "v1",
    csrf_nonce: "c".repeat(64), supported_authoring_template_ids: ["observed_local_git_v1"],
    visual_ui_available: false
  });
  await waitState("COMPOSE");
  await fillCompose("mission");
  windowObj.AdmissibleG3Test.setField("gate-objective", "o");
  windowObj.AdmissibleG3Test.setField("completion-conditions", "c");
  windowObj.AdmissibleG3Test.setField("commit-message", "feat: x");
  windowObj.AdmissibleG3Test.submit("compose-form");
  await settle();
  await ctl.resolveNext(200, {
    contract_id: "contract-1", profile_fingerprint: "b".repeat(64),
    contract_summary: { profile_id: "p", run_id: "r", session_id: "s", gate_id: "g", mission_id: "m",
      workspace_source_kind: "OBSERVED_LOCAL_GIT", verification_mode: "NONE", template_id: "observed_local_git_v1" },
    generated_ids: {}, execution_started: false, authorization_mode: "PRECOMMITTED_DIGEST"
  });
  await waitState("CONTRACT_READY");
  fetchLog.length = 0;
  windowObj.AdmissibleG3Test.prepare();
  windowObj.AdmissibleG3Test.prepare();
  windowObj.AdmissibleG3Test.prepare();
  await settle();
  const posts = ctl.pending().filter(x => x.method === "POST" && x.url.includes("/preparations"));
  const snapMid = windowObj.AdmissibleG3Test.snapshot();
  await ctl.resolveNext(202, { preparation_id: "preparation-1", state: "QUEUED" });
  await settle();
  const snapQueued = windowObj.AdmissibleG3Test.snapshot();
  const polls = ctl.pending().filter(x => x.method === "GET" && x.url.includes("/preparations/"));
  return {
    scenario: "duplicate_prepare",
    postsInFlight: posts.length,
    preparePostsLogged: fetchLog.filter(x => x.method === "POST" && x.url.includes("/preparations")).length,
    prepareDisabledMid: snapMid.prepareDisabled === true,
    prepareDisabledQueued: snapQueued.prepareDisabled === true,
    stateQueued: snapQueued.state === "PREPARATION_QUEUED",
    onePoll: polls.length === 1,
  };
}

async function runResetDuringLaunch() {
  const ctl = deferredFetchController();
  loadApp();
  await settle();
  await ctl.resolveNext(200, {
    service: "admissible-product-launcher", version: "g2.5",
    repository_display_path: "safe-repository", required_source_head: "a".repeat(40),
    authorization_mode: "PRECOMMITTED_DIGEST", authorization_semantics_notice: "notice",
    owner_authorization_encoding: "latin-1", g2_ready: true, g2_api_version: "v1",
    csrf_nonce: "c".repeat(64), supported_authoring_template_ids: ["observed_local_git_v1"],
    visual_ui_available: false
  });
  await waitState("COMPOSE");
  await fillCompose("mission");
  windowObj.AdmissibleG3Test.setField("gate-objective", "o");
  windowObj.AdmissibleG3Test.setField("completion-conditions", "c");
  windowObj.AdmissibleG3Test.setField("commit-message", "feat: x");
  windowObj.AdmissibleG3Test.submit("compose-form");
  await settle();
  await ctl.resolveNext(200, {
    contract_id: "contract-1", profile_fingerprint: "b".repeat(64),
    contract_summary: { profile_id: "p", run_id: "r", session_id: "s", gate_id: "g", mission_id: "m",
      workspace_source_kind: "OBSERVED_LOCAL_GIT", verification_mode: "NONE", template_id: "observed_local_git_v1" },
    generated_ids: {}, execution_started: false, authorization_mode: "PRECOMMITTED_DIGEST"
  });
  await waitState("CONTRACT_READY");
  windowObj.AdmissibleG3Test.prepare();
  await settle();
  await ctl.resolveNext(202, { preparation_id: "preparation-1", state: "QUEUED" });
  await settle();
  await ctl.resolveNext(200, {
    preparation_id: "preparation-1", contract_id: "contract-1", state: "READY",
    authorization_mode: "PRECOMMITTED_DIGEST", authorization_semantics_notice: "n",
    consumed: false, created_at: "now", updated_at: "now",
    payload_fingerprint: "c".repeat(64),
    safe_payload_summary: { run_id: "r" },
    authorization_payload: { payload_fingerprint: "c".repeat(64) },
    blocked_summary: null, error_type: null
  });
  await settle();
  await waitState("PREPARATION_READY");
  windowObj.AdmissibleG3Test.setField("owner-phrase", "owner-secret-phrase");
  windowObj.AdmissibleG3Test.setField("owner-digest", "d".repeat(64));
  windowObj.AdmissibleG3Test.submit("authorize-form");
  await settle();
  const launching = windowObj.AdmissibleG3Test.snapshot();
  let resetThrew = false;
  try { windowObj.AdmissibleG3Test.reset(); } catch (_err) { resetThrew = true; }
  await settle();
  const afterResetAttempt = windowObj.AdmissibleG3Test.snapshot();
  await ctl.resolveNext(202, { control_run_id: "control-1", control_state: "QUEUED" });
  await settle();
  const accepted = windowObj.AdmissibleG3Test.snapshot();
  return {
    scenario: "reset_during_launch",
    launchingState: launching.state,
    resetDisabledWhileLaunching: launching.resetDisabled.every(Boolean),
    resetThrew,
    stateUnchangedByReset: afterResetAttempt.state === "LAUNCHING",
    contractPreserved: afterResetAttempt.contractId === "contract-1",
    secretsNotRedisplayed: afterResetAttempt.phraseValue === "" || afterResetAttempt.state === "LAUNCHING",
    acceptedState: accepted.state,
    acceptedText: accepted.acceptedText,
    resetEnabledAfter: accepted.resetDisabled.every(v => v === false),
    secretsCleared: accepted.phraseValue === "" && accepted.digestValue === "",
  };
}

(async () => {
  try {
    let out;
    if (scenario === "dom_injection") out = await runDomInjection();
    else if (scenario === "secret_clearing") out = await runSecretClearing();
    else if (scenario === "stale_polling") out = await runStalePolling();
    else if (scenario === "no_post_202") out = await runNoPost202();
    else if (scenario === "duplicate_prepare") out = await runDuplicatePrepare();
    else if (scenario === "reset_during_launch") out = await runResetDuringLaunch();
    else throw new Error("unknown scenario");
    process.stdout.write(JSON.stringify(out));
  } catch (error) {
    process.stdout.write(JSON.stringify({ scenario, error: String(error && error.stack || error) }));
    process.exitCode = 1;
  }
})();
"""


def _run_node_scenario(tmp_path: Path, scenario: str) -> dict:
    harness = tmp_path / f"g3_harness_{scenario}.js"
    harness.write_text(NODE_HARNESS, encoding="utf-8")
    completed = subprocess.run(
        [NODE, str(harness), scenario, str(JS_PATH)],
        capture_output=True,
        text=True,
        timeout=20,
        cwd=str(tmp_path),
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert completed.returncode == 0, completed.stdout + "\n" + completed.stderr
    assert completed.stderr == "" or "ExperimentalWarning" in completed.stderr
    payload = json.loads(completed.stdout)
    assert "error" not in payload, payload
    return payload


def test_static_shell_dom_semantics_and_local_assets():
    audit = TagAudit()
    audit.feed(HTML)
    assert audit.h1 == 1 and not audit.external
    assert {
        "mission-text",
        "gate-objective",
        "completion-conditions",
        "commit-message",
        "template-id",
        "model",
        "timeout-seconds",
        "owner-phrase",
    }.issubset(set(audit.labels))
    assert 'aria-live="polite"' in HTML and 'role="alert"' in HTML
    assert all(step in HTML for step in ("Compose", "Contract", "Authorize"))
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
    assert not re.search(
        r"(?:local|session)Storage|indexedDB|serviceWorker|EventSource|WebSocket|sendBeacon|navigator\.beacon",
        JS,
        re.I,
    )
    assert "innerHTML" not in JS and "eval(" not in JS and "new Function" not in JS
    assert "crypto.subtle" not in JS and "SHA-256" not in JS and "digest(" not in JS
    assert "/api/v1/" not in JS.replace("/ui/api/v1/", "")
    assert not re.search(r"/ui/api/v1/runs/.*(?:result|status)", JS)
    assert "localStorage" not in HTML + CSS and "https://" not in HTML + CSS + JS


def test_explicit_state_machine_polling_and_secret_clearing_contract():
    for state in (
        "BOOTSTRAP_LOADING",
        "COMPOSE",
        "AUTHORING",
        "CONTRACT_READY",
        "PREPARATION_QUEUED",
        "PREPARATION_RUNNING",
        "PREPARATION_READY",
        "PREPARATION_BLOCKED",
        "PREPARATION_FAILED",
        "LAUNCHING",
        "LAUNCH_ACCEPTED",
        "REQUEST_ERROR",
    ):
        assert state in JS
    assert "allowedTransitions" in JS and "INVALID_STATE_TRANSITION" in JS
    assert "pollCount>=120" in JS and "setTimeout(tick,750)" in JS
    assert "AbortController" in JS and "clearTimeout" in JS and "pagehide" in JS
    assert "finally" in JS and "clearSecrets()" in JS
    assert 'phrase.value=""' in JS and 'digest.value=""' in JS
    assert "^[0-9a-f]{64}$" in JS
    assert "codePointAt(0)>255" in JS
    assert "compute" not in JS.lower() and "hashlib" not in JS.lower()
    assert "if(ui.state===STATES.LAUNCHING)return;" in JS
    assert "ui.prepareInFlight" in JS
    assert "Connection" not in JS  # client must not be the sole close authority


def test_css_responsive_accessible_and_overflow_guards():
    assert "@media(max-width:760px)" in CSS
    assert "@media(prefers-reduced-motion:reduce)" in CSS
    assert "overflow-wrap:anywhere" in CSS and "min-width:0" in CSS
    assert ":focus-visible" in CSS
    assert CSS.count("{") == CSS.count("}")
    assert ".button:disabled" in CSS


def test_real_http_static_delivery_headers_allowlist_and_traversal():
    launcher = FakeLauncher()
    server = create_ui_loopback_server(launcher, csrf_generator=lambda _n: "z" * 64).start()
    try:
        for path, mime in (
            ("/", "text/html; charset=utf-8"),
            ("/ui/assets/app.css", "text/css; charset=utf-8"),
            ("/ui/assets/app.js", "text/javascript; charset=utf-8"),
        ):
            status, headers, body = request(server, "GET", path)
            assert status == 200
            assert headers["Content-Type"] == mime
            assert headers["Cache-Control"] == "no-store"
            assert headers["X-Content-Type-Options"] == "nosniff"
            assert headers["Referrer-Policy"] == "no-referrer"
            assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
            assert headers.get("Connection", "").lower() == "close"
            assert b"http://" not in body and b"https://" not in body
        for path in (
            "/ui/assets/missing.js",
            "/ui/assets/../product_launcher/ui_transport.py",
            "/ui/assets/%2e%2e/index.html",
        ):
            status, headers, body = request(server, "GET", path)
            assert status == 404
            assert json.loads(body) == {"error": "NOT_FOUND"}
            assert headers.get("Connection", "").lower() == "close"
    finally:
        server.stop()


@pytest.mark.parametrize("mode", ["INTERACTIVE_BOUND_CONFIRMATION", "PRECOMMITTED_DIGEST"])
def test_full_http_rehearsal_ends_at_launch_acceptance_without_secret_leak(mode):
    launcher = FakeLauncher(mode)
    server = create_ui_loopback_server(launcher, csrf_generator=lambda _n: "q" * 64).start()
    csrf = server.csrf_nonce
    owner = {
        "mission_text": "mission",
        "gate_objective": "objective",
        "completion_conditions_text": "complete",
        "required_material_paths": ["README.md"],
        "commit_message": "feat: mission",
        "model": "auto",
        "timeout_seconds": 60,
        "template_id": "observed_local_git_v1",
    }
    mut = {"X-Admissible-UI-CSRF": csrf}
    phrase = "owner-secret-phrase"
    digest = "d" * 64
    try:
        assert request(server, "GET", "/")[0] == 200
        status, headers, raw = request(server, "GET", "/ui/api/v1/bootstrap")
        assert status == 200
        assert headers.get("Connection", "").lower() == "close"
        status, _, raw = request(server, "POST", "/ui/api/v1/contracts", owner, mut)
        contract = json.loads(raw)
        assert status == 200
        status, _, raw = request(
            server,
            "POST",
            f'/ui/api/v1/contracts/{contract["contract_id"]}/preparations',
            {},
            mut,
        )
        prep = json.loads(raw)
        assert status == 202
        assert json.loads(request(server, "GET", f'/ui/api/v1/preparations/{prep["preparation_id"]}')[2])[
            "state"
        ] == "RUNNING"
        ready_raw = request(server, "GET", f'/ui/api/v1/preparations/{prep["preparation_id"]}')[2]
        assert json.loads(ready_raw)["state"] == "READY"
        launch_headers = {**mut, "X-Admissible-Owner-Authorization": phrase}
        if mode == "PRECOMMITTED_DIGEST":
            launch_headers["X-Admissible-Owner-Authorization-Digest"] = digest
        status, launch_headers_out, launch_raw = request(
            server,
            "POST",
            "/ui/api/v1/runs",
            {"contract_id": contract["contract_id"], "preparation_id": prep["preparation_id"]},
            launch_headers,
        )
        launch = json.loads(launch_raw)
        assert status == 202 and launch == {"control_run_id": "control-1", "control_state": "QUEUED"}
        assert launch_headers_out.get("Connection", "").lower() == "close"
        visible = raw + ready_raw + launch_raw
        assert phrase.encode() not in visible and digest.encode() not in visible
        assert [call[0] for call in launcher.calls] == ["author", "prepare", "poll", "poll", "launch"]
    finally:
        server.stop()


def test_production_ui_send_closes_connection_for_multi_asset_delivery():
    before_threads = {t.ident for t in threading.enumerate()}
    launcher = FakeLauncher()
    server = create_ui_loopback_server(launcher, csrf_generator=lambda _n: "k" * 64).start()
    try:
        host, port = server.host, server.port
        html_req = (
            f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: text/html\r\n\r\n"
        ).encode("ascii")
        html_raw, eof = _raw_http_exchange(host, port, html_req)
        assert eof is True
        assert b"Connection: close" in html_raw.split(b"\r\n\r\n", 1)[0]
        assert b"<!doctype html>" in html_raw.lower() or b"ADMISSIBLE" in html_raw

        for path, expected in (("/ui/assets/app.css", CSS_BYTES), ("/ui/assets/app.js", JS_BYTES)):
            req = (
                f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: */*\r\n\r\n"
            ).encode("ascii")
            raw, asset_eof = _raw_http_exchange(host, port, req)
            assert asset_eof is True
            header, body = raw.split(b"\r\n\r\n", 1)
            assert b"Connection: close" in header
            assert body == expected

        status, headers, body = request(server, "GET", "/ui/api/v1/bootstrap")
        assert status == 200
        assert headers.get("Connection", "").lower() == "close"
        assert json.loads(body)["service"] == "admissible-product-launcher"
    finally:
        server.stop()
    leftover = {t.ident for t in threading.enumerate()} - before_threads
    assert not leftover


def test_real_chrome_loads_all_assets_and_reaches_compose(tmp_path):
    if not CHROME.is_file():
        pytest.skip("Chrome not installed")
    launcher = FakeLauncher()
    server = create_ui_loopback_server(launcher, csrf_generator=lambda _n: "b" * 64).start()
    profile = tmp_path / "chrome-profile"
    profile.mkdir()
    debug_port = 9222 + (os.getpid() % 1000)
    url = f"http://{server.host}:{server.port}/"
    cmd = [
        str(CHROME),
        f"--user-data-dir={profile}",
        f"--remote-debugging-port={debug_port}",
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-background-networking",
        url,
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 20
        version = None
        while time.time() < deadline:
            try:
                with urlopen(f"http://127.0.0.1:{debug_port}/json/version", timeout=1) as resp:
                    version = json.loads(resp.read().decode())
                break
            except Exception:
                time.sleep(0.2)
        assert version is not None, "Chrome debug port did not open"
        targets = None
        while time.time() < deadline:
            with urlopen(f"http://127.0.0.1:{debug_port}/json", timeout=1) as resp:
                targets = json.loads(resp.read().decode())
            page = next((t for t in targets if t.get("type") == "page" and url.rstrip("/") in t.get("url", "")), None)
            if page:
                break
            time.sleep(0.2)
        else:
            page = next((t for t in targets or [] if t.get("type") == "page"), None)
        assert page is not None
        # Use CDP HTTP /json/protocol indirectly via Runtime through websocket-less polling of title/body via /json
        # Evaluate through Chrome's /json/activate + a tiny CDP client over websocket if available; else fetch page.
        ws_url = page.get("webSocketDebuggerUrl")
        assert ws_url
        eval_script = tmp_path / "cdp_eval.py"
        eval_script.write_text(
            f"""
import json, time
from urllib.request import urlopen
try:
    import websocket
except ImportError:
    websocket = None
ws_url = {ws_url!r}
deadline = time.time() + 15
result = {{"ok": False}}
if websocket is None:
    # Fallback: confirm document bytes and assets via HTTP only, plus AdmissibleG3 presence via page source unavailable.
    result = {{"ok": False, "error": "websocket-client missing"}}
else:
    ws = websocket.create_connection(ws_url, timeout=5)
    msg_id = 0
    def send(method, params=None):
        global msg_id
        msg_id += 1
        ws.send(json.dumps({{"id": msg_id, "method": method, "params": params or {{}}}}))
        while True:
            raw = json.loads(ws.recv())
            if raw.get("id") == msg_id:
                return raw
    send("Page.enable")
    send("Network.enable")
    send("Runtime.enable")
    # wait for load
    while time.time() < deadline:
        got = send("Runtime.evaluate", {{"expression": "document.readyState + '|' + (window.AdmissibleG3Test && window.AdmissibleG3Test.getState()) + '|' + performance.getEntriesByType('resource').map(e=>e.name+'@'+e.responseStatus).join(',')", "returnByValue": True}})
        value = ((got.get("result") or {{}}).get("result") or {{}}).get("value")
        if value and value.startswith("complete|COMPOSE"):
            result = {{"ok": True, "value": value, "browser": {json.dumps(version)}}}
            break
        time.sleep(0.2)
    else:
        got = send("Runtime.evaluate", {{"expression": "document.readyState + '|' + String(!!window.AdmissibleG3Test) + '|' + (window.AdmissibleG3Test && window.AdmissibleG3Test.getState())", "returnByValue": True}})
        result = {{"ok": False, "value": ((got.get("result") or {{}}).get("result") or {{}}).get("value")}}
    # console / CSP errors
    # drain is best-effort; close
    ws.close()
print(json.dumps(result))
""",
            encoding="utf-8",
        )
        # Prefer stdlib-only CDP via raw websocket framing if websocket-client absent.
        # Implement minimal client inline.
        cdp_result = _chrome_cdp_wait_compose(ws_url, version, timeout=15)
        assert cdp_result["ok"], cdp_result
        value = cdp_result["value"]
        assert "complete|COMPOSE" in value
        assert "app.css" in value and "app.js" in value
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        server.stop()
    # port released
    probe = socket.socket()
    try:
        probe.settimeout(0.5)
        assert probe.connect_ex((server.host, server.port)) != 0
    finally:
        probe.close()


def _chrome_cdp_wait_compose(ws_url: str, version: dict, timeout: float = 15) -> dict:
    import base64
    import hashlib as _hashlib
    import os as _os
    import struct

    key = base64.b64encode(_os.urandom(16)).decode()
    # parse ws url
    assert ws_url.startswith("ws://")
    hostport_path = ws_url[len("ws://") :]
    hostport, _, path = hostport_path.partition("/")
    host, _, port_s = hostport.partition(":")
    port = int(port_s or "80")
    path = "/" + path
    sock = socket.create_connection((host, port), timeout=5)
    sock.settimeout(5)
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    sock.sendall(req)
    data = b""
    while b"\r\n\r\n" not in data:
        data += sock.recv(4096)
    assert b"101" in data.split(b"\r\n", 1)[0]

    def encode(payload: bytes) -> bytes:
        fin_opcode = 0x81
        mask_bit = 0x80
        length = len(payload)
        if length < 126:
            header = struct.pack("!BB", fin_opcode, mask_bit | length)
        elif length < 65536:
            header = struct.pack("!BBH", fin_opcode, mask_bit | 126, length)
        else:
            header = struct.pack("!BBQ", fin_opcode, mask_bit | 127, length)
        mask = _os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return header + mask + masked

    def decode() -> dict:
        hdr = b""
        while len(hdr) < 2:
            hdr += sock.recv(2 - len(hdr))
        length = hdr[1] & 0x7F
        if length == 126:
            ext = b""
            while len(ext) < 2:
                ext += sock.recv(2 - len(ext))
            length = struct.unpack("!H", ext)[0]
        elif length == 127:
            ext = b""
            while len(ext) < 8:
                ext += sock.recv(8 - len(ext))
            length = struct.unpack("!Q", ext)[0]
        payload = b""
        while len(payload) < length:
            payload += sock.recv(length - len(payload))
        return json.loads(payload.decode())

    msg_id = 0

    def send(method: str, params: dict | None = None) -> dict:
        nonlocal msg_id
        msg_id += 1
        sock.sendall(encode(json.dumps({"id": msg_id, "method": method, "params": params or {}}).encode()))
        while True:
            msg = decode()
            if msg.get("id") == msg_id:
                return msg

    send("Page.enable")
    send("Network.enable")
    send("Runtime.enable")
    deadline = time.time() + timeout
    last = None
    try:
        while time.time() < deadline:
            got = send(
                "Runtime.evaluate",
                {
                    "expression": (
                        "document.readyState + '|' + "
                        "(window.AdmissibleG3Test && window.AdmissibleG3Test.getState()) + '|' + "
                        "performance.getEntriesByType('resource').map(e => e.name).join(',')"
                    ),
                    "returnByValue": True,
                },
            )
            last = ((got.get("result") or {}).get("result") or {}).get("value")
            if isinstance(last, str) and last.startswith("complete|COMPOSE") and "app.css" in last and "app.js" in last:
                return {"ok": True, "value": last, "browser": version}
            time.sleep(0.2)
        return {"ok": False, "value": last, "browser": version}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def test_executed_client_dom_injection_is_inert(tmp_path):
    out = _run_node_scenario(tmp_path, "dom_injection")
    assert out["state"] == "PREPARATION_READY"
    assert out["markerInvoked"] == 0
    assert out["unsafeHtmlApi"] == 0
    assert out["createdScriptTags"] == 0
    assert out["assignedHandlers"] == []
    assert out["textContainsPayload"] is True
    assert out["hasExecutableNodes"] is False


def test_executed_client_secret_clearing_all_paths(tmp_path):
    out = _run_node_scenario(tmp_path, "secret_clearing")
    assert len(out["results"]) == 6
    for row in out["results"]:
        assert row["phraseEmpty"] and row["digestEmpty"]
        assert row["phraseTypePassword"] and row["revealReset"]
        assert row["noSecretInErrors"]
        assert row["noLocalStorage"] and row["noSessionStorage"]
        assert row["snapshotPhraseEmpty"] and row["snapshotDigestEmpty"]


def test_executed_client_stale_response_and_polling_cancellation(tmp_path):
    out = _run_node_scenario(tmp_path, "stale_polling")
    assert out["staleDidNotTakeOver"] is True
    assert out["onePollInFlight"] is True
    assert out["readyStoppedPolling"] is True
    assert out["acceptedStoppedPolling"] is True
    assert out["teardownClearedTimers"] is True


def test_executed_client_no_post_202_read(tmp_path):
    out = _run_node_scenario(tmp_path, "no_post_202")
    assert out["state"] == "LAUNCH_ACCEPTED"
    assert out["onlyLaunchPost"] is True
    assert out["noRunIdRead"] and out["noResultRead"] and out["noRunsList"]
    assert out["acceptedRendered"] is True


def test_executed_client_duplicate_prepare_deduped(tmp_path):
    out = _run_node_scenario(tmp_path, "duplicate_prepare")
    assert out["postsInFlight"] == 1
    assert out["preparePostsLogged"] == 1
    assert out["prepareDisabledMid"] is True
    assert out["prepareDisabledQueued"] is True
    assert out["stateQueued"] is True
    assert out["onePoll"] is True


def test_executed_client_reset_during_launching_is_safe(tmp_path):
    out = _run_node_scenario(tmp_path, "reset_during_launch")
    assert out["launchingState"] == "LAUNCHING"
    assert out["resetDisabledWhileLaunching"] is True
    assert out["resetThrew"] is False
    assert out["stateUnchangedByReset"] is True
    assert out["contractPreserved"] is True
    assert out["acceptedState"] == "LAUNCH_ACCEPTED"
    assert "control-1" in out["acceptedText"]
    assert out["resetEnabledAfter"] is True
    assert out["secretsCleared"] is True


def test_javascript_syntax_and_python_ast_and_css_braces():
    subprocess.run([NODE, "--check", str(JS_PATH)], check=True, capture_output=True, text=True, timeout=10)
    ast.parse((ROOT / "admissible/product_launcher/ui_transport.py").read_text(encoding="utf-8"))
    ast.parse((ROOT / "tests/test_admissible_product_ui_g3.py").read_text(encoding="utf-8"))
    assert CSS.count("{") == CSS.count("}")


def test_import_side_effect_free_for_product_ui():
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import admissible.product_ui as m; import admissible.product_launcher.ui_transport as t; "
            "print(m.__name__, t.SERVICE_VERSION)",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        cwd=str(ROOT),
        env=env,
    )
    assert completed.returncode == 0, completed.stderr
    assert "g2.5" in completed.stdout
