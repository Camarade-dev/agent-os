from __future__ import annotations

from html.parser import HTMLParser
import ast
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
from urllib.request import urlopen

import pytest

from admissible.product_launcher.ui_transport import create_ui_loopback_server
from admissible.product_ui import render_document
from test_admissible_product_ui_g3 import (
    CHROME,
    FakeLauncher,
    NODE_HARNESS as G3_NODE_HARNESS,
    _cdp_connect,
)


ROOT = Path(__file__).parents[1]
HTML = render_document(csrf_nonce="c" * 64, authorization_mode="PRECOMMITTED_DIGEST").decode()
CSS = (ROOT / "admissible/product_ui/app.css").read_text(encoding="utf-8")
JS_PATH = ROOT / "admissible/product_ui/app.js"
JS = JS_PATH.read_text(encoding="utf-8")
NODE = "node"


G4_DOM = r'''
function installG4Dom() {
  FakeNode.prototype.scrollIntoView = function() {};
  const accepted = byId["accepted-view"];
  accepted.append(
    el("h2", { id: "accepted-title" }),
    el("p", { id: "run-state-value" }),
    el("p", { id: "run-state-copy" }),
    el("p", { id: "run-verdict-pending", text: "No product verdict exists yet." })
  );
  const result = el("section", { id: "result-view", hidden: "true" }, [
    el("h2", { id: "result-title" }),
    el("div", { id: "result-classification" }),
    el("p", { id: "result-summary" }),
    el("p", { id: "non-authority-notice" }),
    el("div", { id: "evidence-glance" }),
    el("div", { id: "essential-evidence" }),
    el("div", { id: "supplemental-evidence" }),
    el("button", { type: "button", className: "button primary reset-flow", text: "Compose another mission" }),
  ]);
  const noResult = el("section", { id: "no-result-view", hidden: "true" }, [
    el("h2", { id: "no-result-title", text: "No authoritative result" }),
    el("dl", { id: "no-result-facts" }),
    el("p", { text: "The evidence root was unavailable." }),
    el("button", { type: "button", className: "button primary reset-flow", text: "Compose another mission" }),
  ]);
  body.append(result, noResult);
  const list = documentElement.querySelector("ol");
  if (list) {
    const run = el("li", { "data-step": "run" }); run.dataset.step = "run";
    const resultStep = el("li", { "data-step": "result" }); resultStep.dataset.step = "result";
    list.append(run, resultStep);
  }
  register(documentElement);
}
'''


G4_SCENARIOS = r'''
function resultFixture(options = {}) {
  const marker = options.malicious ? `<img src=x onerror="${MARKER}()"><script>${MARKER}()</script>` : "evidence note";
  const verdict = options.verdict || "ADMITTED_VERIFIED";
  const presentation = options.presentation || "ADMITTED";
  const completeness = options.completeness || "COMPLETE";
  const boundary = options.boundary || "NONE";
  const verification = options.verification || (verdict === "ADMITTED_OBSERVED" ? "OBSERVED" : verdict === "ADMITTED_VERIFIED" ? "INDEPENDENT" : "NONE");
  return {
    schema_version: "admissible_product_read_model_result_v1",
    non_authority_notice: `Persisted claims do not create authority. ${marker}`,
    run_id: options.malicious ? marker : "run-authoritative-1",
    presentation_status: presentation,
    execution_state: { state: "COMPLETED", provider_exit_code: 0, timed_out: false, termination_reason: null },
    result_admission_state: {
      verdict, verification_mode: verification, source: "AUTHORITATIVE_RECONSTRUCTION",
      truth_status: "AUTHORITATIVE", verdict_is_authoritative: verdict.startsWith("ADMITTED_") || verdict === "REFUSED",
      consistent: presentation !== "INCONSISTENT", claimed_verdict: "UNKNOWN", claim_is_authoritative: false,
    },
    failing_boundary: { boundary, failure_category: boundary === "NONE" ? null : "POLICY", detail: boundary === "NONE" ? null : marker, reasons: boundary === "NONE" ? [] : [marker] },
    material_git_result: {
      git: { present: "PRESENT", initial_git_head: "a".repeat(40), final_git_head: "b".repeat(40), commits_added: 1, source_repository_mutated: false, final_git_porcelain_status: "" },
      material: { present: "PRESENT", result: "PASSED", eligible: true, material_paths_compliant: true, workspace_clean: true, ineligibility_reasons: [] },
    },
    checkpoint_result: { present: "PRESENT", result: "PASSED", attempted: true, checkpoint_fingerprint: "c".repeat(64), verification_command_ids: [marker] },
    behavioral_verifier_result: { present: "PRESENT", result: "PASSED", exit_code: 0, timed_out: false, evidence_fingerprint: "d".repeat(64), notes: [marker] },
    evidence_completeness: { state: completeness, present_records: ["final-status"], absent_records: [], inconsistent_records: [], missing_required: [], notes: [marker] },
    human_disposition: { present: "ABSENT", disposition: "UNKNOWN", reason: null },
    timeline: [{ event_key: "terminal", label: marker, timestamp: "2026-07-20T10:00:04Z", presence: "PRESENT" }],
    artifacts: [{ artifact_id: "checkpoint", purpose: marker, relative_path: "evidence/checkpoint.json", sha256: "e".repeat(64), file_presence: "PRESENT" }],
    read_notes: [marker],
    transport_schema_version: "admissible_product_service_transport_v1",
    transport_redactions: ["diagnostics", "run_root"],
    run_root: `C:/private/${marker}`,
    diagnostics: [{ excerpt: marker }],
  };
}

function installRunFetch({ statuses, results }) {
  let statusIndex = 0;
  let resultIndex = 0;
  let inFlight = 0;
  let maxInFlight = 0;
  fetchImpl = async (url, options = {}) => {
    const method = (options.method || "GET").toUpperCase();
    fetchLog.push({ url, method, headers: { ...(options.headers || {}) } });
    inFlight += 1; maxInFlight = Math.max(maxInFlight, inFlight);
    try {
      if (url === "/ui/api/v1/runs" && method === "POST") return jsonResponse(202, { control_run_id: "control-g4-1", control_state: "QUEUED" });
      if (url.endsWith("/result")) {
        const item = results[Math.min(resultIndex++, results.length - 1)];
        return jsonResponse(item.status, item.body);
      }
      if (/\/ui\/api\/v1\/runs\/[^/]+$/.test(url)) {
        const item = statuses[Math.min(statusIndex++, statuses.length - 1)];
        return jsonResponse(200, {
          control_run_id: "control-g4-1", control_state: item,
          authoritative_session_id: item === "QUEUED" ? null : "session-authoritative-1",
          started_at: item === "QUEUED" ? null : "2026-07-20T10:00:00Z",
          ended_at: item === "TERMINAL" || item === "START_FAILED" ? "2026-07-20T10:00:04Z" : null,
          application_return_code: item === "TERMINAL" ? 7 : null,
          start_error_type: item === "START_FAILED" ? "RuntimeError" : null,
          terminal_evidence: item === "TERMINAL" ? "RUN_ROOT_PRESENT" : item === "START_FAILED" ? "RUN_ROOT_ABSENT" : null,
          product_summary: { product_verdict: "PASS", presentation_status: "AVAILABLE" },
        });
      }
      return jsonResponse(404, { error: "NOT_FOUND" });
    } finally { inFlight -= 1; }
  };
  return { get maxInFlight() { return maxInFlight; } };
}

async function readyForLaunch() {
  await goToReady("happy");
  fetchLog.length = 0;
}

async function runLifecycle() {
  await readyForLaunch();
  const tracker = installRunFetch({
    statuses: ["QUEUED", "STARTING", "RUNNING", "TERMINAL"],
    results: [{ status: 409, body: { error: "RESULT_NOT_READY" } }, { status: 200, body: resultFixture() }],
  });
  windowObj.AdmissibleG3Test.submit("authorize-form"); await settle();
  const accepted = windowObj.AdmissibleG4Test.snapshot();
  const states = [];
  for (let i = 0; i < 4; i++) { await flushTimers(1); await settle(); states.push(windowObj.AdmissibleG4Test.getState()); }
  const terminalText = document.getElementById("accepted-view").textContent;
  const verdictBeforeResult = document.getElementById("result-classification").textContent;
  await flushTimers(1); await settle();
  const after409 = windowObj.AdmissibleG4Test.snapshot();
  await flushTimers(1); await settle();
  const final = windowObj.AdmissibleG4Test.snapshot();
  const countAtResolution = fetchLog.length;
  await flushTimers(40); await settle();
  const g3 = windowObj.AdmissibleG3Test.snapshot();
  return {
    accepted, states, terminalText, verdictBeforeResult, after409, final,
    resultText: document.getElementById("result-view").textContent,
    classificationText: document.getElementById("result-classification").textContent,
    essentialText: document.getElementById("essential-evidence").textContent,
    supplementalText: document.getElementById("supplemental-evidence").textContent,
    requestUrls: fetchLog.map(x => x.url), maxInFlight: tracker.maxInFlight,
    noRequestsAfterResolution: fetchLog.length === countAtResolution,
    secretsEmpty: g3.phraseValue === "" && g3.digestValue === "",
    storageEmpty: Object.keys(storage.local).length === 0 && Object.keys(storage.session).length === 0,
  };
}

async function runStartFailed() {
  await readyForLaunch();
  installRunFetch({ statuses: ["START_FAILED"], results: [{ status: 410, body: { error: "NO_AUTHORITATIVE_RESULT", control_state: "START_FAILED", application_return_code: null, terminal_evidence: "RUN_ROOT_ABSENT", start_error_type: "RuntimeError" } }] });
  windowObj.AdmissibleG3Test.submit("authorize-form"); await settle();
  await flushTimers(1); await settle(); const startFailed = windowObj.AdmissibleG4Test.snapshot();
  await flushTimers(1); await settle(); const noResult = windowObj.AdmissibleG4Test.snapshot();
  const count = fetchLog.length; await flushTimers(30); await settle();
  return { startFailed, noResult, noResultText: document.getElementById("no-result-view").textContent, noRequestsAfter410: count === fetchLog.length };
}

async function runVariant(name) {
  const variants = {
    ADMITTED_OBSERVED: { verdict: "ADMITTED_OBSERVED", verification: "OBSERVED", presentation: "ADMITTED" },
    ADMITTED_VERIFIED: { verdict: "ADMITTED_VERIFIED", verification: "INDEPENDENT", presentation: "ADMITTED" },
    REFUSED: { verdict: "REFUSED", verification: "INDEPENDENT", presentation: "REFUSED", boundary: "BEHAVIORAL_VERIFICATION" },
    INCOMPLETE: { verdict: "UNKNOWN", verification: "NONE", presentation: "INCOMPLETE", completeness: "INCOMPLETE" },
    INCONSISTENT: { verdict: "UNKNOWN", verification: "NONE", presentation: "INCONSISTENT", completeness: "INCONSISTENT" },
    UNKNOWN: { verdict: "UNKNOWN", verification: "NONE", presentation: "UNKNOWN", completeness: "UNKNOWN" },
    UNSUPPORTED: { verdict: "UNSUPPORTED", verification: "UNSUPPORTED", presentation: "UNKNOWN", completeness: "UNKNOWN" },
  };
  await readyForLaunch();
  installRunFetch({ statuses: ["TERMINAL"], results: [{ status: 200, body: resultFixture(variants[name]) }] });
  windowObj.AdmissibleG3Test.submit("authorize-form"); await settle(); await flushTimers(2); await settle();
  return { state: windowObj.AdmissibleG4Test.getState(), text: document.getElementById("result-view").textContent, classification: document.getElementById("result-classification").textContent };
}

async function runMalicious() {
  await readyForLaunch();
  installRunFetch({ statuses: ["TERMINAL"], results: [{ status: 200, body: resultFixture({ malicious: true }) }] });
  windowObj.AdmissibleG3Test.submit("authorize-form"); await settle(); await flushTimers(2); await settle();
  return {
    state: windowObj.AdmissibleG4Test.getState(), markerInvoked, unsafeHtmlApi,
    createdScriptTags: createdTags.filter(x => x === "script").length,
    assignedHandlers: assignedHandlers.slice(), text: document.getElementById("result-view").textContent,
    forbiddenVisible: document.getElementById("result-view").textContent.includes("C:/private/") || document.getElementById("result-view").textContent.includes("excerpt"),
  };
}

async function runStaleAndSingleFlight() {
  await readyForLaunch();
  let statusResolve;
  fetchImpl = (url, options = {}) => {
    const method = (options.method || "GET").toUpperCase(); fetchLog.push({ url, method, headers: { ...(options.headers || {}) } });
    if (url === "/ui/api/v1/runs" && method === "POST") return Promise.resolve(jsonResponse(202, { control_run_id: "control-stale-status", control_state: "QUEUED" }));
    return new Promise(resolve => { statusResolve = resolve; });
  };
  windowObj.AdmissibleG3Test.submit("authorize-form"); await settle(); await flushTimers(1); await settle();
  const pendingStatus = windowObj.AdmissibleG4Test.snapshot(); const statusReadsBefore = fetchLog.length;
  await flushTimers(20); await settle(); const oneStatusInFlight = fetchLog.length === statusReadsBefore && pendingStatus.requestInFlight;
  windowObj.AdmissibleG3Test.reset(); statusResolve(jsonResponse(200, { control_state: "RUNNING", control_run_id: "control-stale-status" })); await settle();
  const staleStatusIgnored = windowObj.AdmissibleG4Test.getState() === "COMPOSE";

  await readyForLaunch();
  let resultResolve;
  fetchImpl = (url, options = {}) => {
    const method = (options.method || "GET").toUpperCase(); fetchLog.push({ url, method, headers: { ...(options.headers || {}) } });
    if (url === "/ui/api/v1/runs" && method === "POST") return Promise.resolve(jsonResponse(202, { control_run_id: "control-stale-result", control_state: "QUEUED" }));
    if (url.endsWith("/result")) return new Promise(resolve => { resultResolve = resolve; });
    return Promise.resolve(jsonResponse(200, { control_run_id: "control-stale-result", control_state: "TERMINAL", terminal_evidence: "RUN_ROOT_PRESENT", application_return_code: 0 }));
  };
  windowObj.AdmissibleG3Test.submit("authorize-form"); await settle(); await flushTimers(2); await settle();
  const pendingResult = windowObj.AdmissibleG4Test.snapshot();
  windowObj.AdmissibleG3Test.reset(); resultResolve(jsonResponse(200, resultFixture())); await settle();
  const staleResultIgnored = windowObj.AdmissibleG4Test.getState() === "COMPOSE" && document.getElementById("result-classification").textContent === "";
  return { oneStatusInFlight, pendingResultInFlight: pendingResult.requestInFlight, staleStatusIgnored, staleResultIgnored, resetAborted: !windowObj.AdmissibleG4Test.snapshot().hasAbortOwner && !windowObj.AdmissibleG4Test.snapshot().hasTimer };
}

async function runAuthoringSafeDetail() {
  installDefaultFetch("happy");
  loadApp();
  await waitState("COMPOSE");
  const g3 = windowObj.AdmissibleG3Test;
  g3.setField("mission-text", "owner mission retained");
  g3.setField("gate-objective", "owner objective retained");
  g3.setField("completion-conditions", "owner conditions retained");
  g3.setField("commit-message", "feat: owner commit retained");
  fetchImpl = async (url, options = {}) => {
    const method = (options.method || "GET").toUpperCase();
    fetchLog.push({ url, method, headers: { ...(options.headers || {}) } });
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
    if (url === "/ui/api/v1/contracts" && method === "POST") {
      return jsonResponse(400, {
        error: "AUTHORING_REJECTED",
        error_code: "GOLDEN_CONTRACT_MISMATCH",
        field: "mission_text",
        safe_message_key: "authoring.golden_contract_mismatch",
        detail: "C:/secret/path stack Traceback https://evil.example/leak owner-secret-phrase",
        nested: { exception: "RuntimeError: boom", stack: "File /tmp/x.py, line 1" },
        owner_value: "owner mission retained",
      });
    }
    return jsonResponse(404, { error: "NOT_FOUND" });
  };
  g3.submit("compose-form"); await settle(); await flushTimers(5); await settle();
  const matched = {
    state: windowObj.AdmissibleG4Test.getState(),
    statusVisible: document.getElementById("status-area").hidden === false,
    statusMessage: document.getElementById("status-message").textContent,
    statusCode: document.getElementById("status-code").textContent,
    errorArea: document.getElementById("status-area").textContent,
    missionValue: document.getElementById("mission-text").value,
    objectiveValue: document.getElementById("gate-objective").value,
    conditionsValue: document.getElementById("completion-conditions").value,
    commitValue: document.getElementById("commit-message").value,
    materialValues: Array.from(document.getElementById("material-list").querySelectorAll("input")).map(x => x.value),
    composeHidden: document.getElementById("compose-view").hidden,
    executionClaim: document.getElementById("status-area").textContent + document.getElementById("live-status").textContent,
  };

  fetchImpl = async (url, options = {}) => {
    const method = (options.method || "GET").toUpperCase();
    fetchLog.push({ url, method, headers: { ...(options.headers || {}) } });
    if (url === "/ui/api/v1/contracts" && method === "POST") {
      return jsonResponse(400, {
        error: "AUTHORING_REJECTED",
        error_code: "C:/unsafe/path",
        field: "<script>alert(1)</script>",
        detail: "raw body must stay invisible",
        nested: { boom: true },
        message: "do-not-echo",
      });
    }
    return jsonResponse(404, { error: "NOT_FOUND" });
  };
  g3.submit("compose-form"); await settle(); await flushTimers(5); await settle();
  const unsafe = {
    statusMessage: document.getElementById("status-message").textContent,
    statusCode: document.getElementById("status-code").textContent,
    errorArea: document.getElementById("status-area").textContent,
    missionValue: document.getElementById("mission-text").value,
  };

  fetchImpl = async (url, options = {}) => {
    const method = (options.method || "GET").toUpperCase();
    fetchLog.push({ url, method, headers: { ...(options.headers || {}) } });
    if (url === "/ui/api/v1/contracts" && method === "POST") {
      return jsonResponse(400, {
        error: "AUTHORING_REJECTED",
        error_code: 12,
        field: ["mission_text"],
        detail: { raw: true },
      });
    }
    return jsonResponse(404, { error: "NOT_FOUND" });
  };
  g3.submit("compose-form"); await settle(); await flushTimers(5); await settle();
  const malformed = {
    statusMessage: document.getElementById("status-message").textContent,
    statusCode: document.getElementById("status-code").textContent,
    errorArea: document.getElementById("status-area").textContent,
  };
  return { matched, unsafe, malformed };
}

const G4_TEST_HOOK_NEEDLE = 'Object.defineProperty(window,"AdmissibleG4Test",{value:Object.freeze({STATES,getState:()=>ui.state,snapshot:g4Snapshot}),writable:false,configurable:true});';
const G4_OBS_HOOK = 'Object.defineProperty(window,"AdmissibleG4Test",{value:Object.freeze({STATES,getState:()=>ui.state,snapshot:g4Snapshot,startRunObservation,observationFacts:()=>({pollController:ui.pollController,pollTimer:ui.pollTimer,resultResolved:ui.resultResolved,observationPhase:ui.observationPhase,requestInFlight:ui.requestInFlight,statusAttempts:ui.statusAttempts,resultAttempts:ui.resultAttempts})}),writable:false,configurable:true});';

function instrumentObservationSurface(source) {
  if (!source.includes(G4_TEST_HOOK_NEEDLE)) throw new Error("missing committed AdmissibleG4Test hook");
  const out = source.split(G4_TEST_HOOK_NEEDLE).join(G4_OBS_HOOK);
  const strip = (text) => text.split(G4_TEST_HOOK_NEEDLE).join("").split(G4_OBS_HOOK).join("");
  if (strip(source) !== strip(out)) throw new Error("instrumentation altered a non-observation surface");
  if ((out.match(/startRunObservation,observationFacts/g) || []).length !== 1) throw new Error("observation surface not uniquely instrumented");
  return { source: out, alteredOnlyObservationSurface: true };
}

function installCountingAbortController() {
  let created = 0;
  class CountingAbortController extends FakeAbortController {
    constructor() { super(); created += 1; }
  }
  context.AbortController = CountingAbortController;
  windowObj.AbortController = CountingAbortController;
  return {
    get created() { return created; },
    reset() { created = 0; },
  };
}

function statusRequestCount() {
  return fetchLog.filter((entry) => /\/ui\/api\/v1\/runs\/[^/]+$/.test(entry.url)).length;
}

function resultRequestCount() {
  return fetchLog.filter((entry) => String(entry.url).endsWith("/result")).length;
}

async function runSingleObservationOwnership() {
  const instrumented = instrumentObservationSurface(appJs);
  activeAppJs = instrumented.source;
  const controllers = installCountingAbortController();
  try {
    await readyForLaunch();
    controllers.reset();
    let inFlight = 0;
    let maxInFlight = 0;
    fetchImpl = (url, options = {}) => {
      const method = (options.method || "GET").toUpperCase();
      fetchLog.push({ url, method, headers: { ...(options.headers || {}) } });
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      if (url === "/ui/api/v1/runs" && method === "POST") {
        inFlight -= 1;
        return Promise.resolve(jsonResponse(202, { control_run_id: "control-obs-owner-1", control_state: "QUEUED" }));
      }
      return new Promise(() => {});
    };
    windowObj.AdmissibleG3Test.submit("authorize-form"); await settle();
    await flushTimers(1); await settle();
    const g4 = windowObj.AdmissibleG4Test;
    const before = g4.observationFacts();
    const ownerController = before.pollController;
    const timersBeforeSecondStart = timers.size;
    const controllersAtOwner = controllers.created;
    const statusBeforeSecondStart = statusRequestCount();
    g4.startRunObservation();
    await settle();
    const after = g4.observationFacts();
    return {
      alteredOnlyObservationSurface: instrumented.alteredOnlyObservationSurface,
      ownerPresent: ownerController !== null && ownerController !== undefined,
      sameController: after.pollController === ownerController,
      controllersCreatedAfterOwner: controllers.created - controllersAtOwner,
      timerCountBeforeSecondStart: timersBeforeSecondStart,
      timerCountAfterSecondStart: timers.size,
      noSecondTimer: timers.size === timersBeforeSecondStart,
      statusRequestCount: statusRequestCount(),
      onlyOneStatusRequest: statusBeforeSecondStart === 1 && statusRequestCount() === 1,
      maxInFlight,
      requestInFlight: after.requestInFlight,
      resultResolved: after.resultResolved,
      observationPhase: after.observationPhase,
    };
  } finally {
    activeAppJs = appJs;
    context.AbortController = FakeAbortController;
    windowObj.AbortController = FakeAbortController;
  }
}

async function run410TerminalOwnership() {
  const instrumented = instrumentObservationSurface(appJs);
  activeAppJs = instrumented.source;
  try {
    await readyForLaunch();
    const tracker = installRunFetch({
      statuses: ["TERMINAL"],
      results: [{
        status: 410,
        body: {
          error: "NO_AUTHORITATIVE_RESULT",
          control_state: "TERMINAL",
          application_return_code: 7,
          terminal_evidence: "RUN_ROOT_ABSENT",
          start_error_type: null,
        },
      }],
    });
    windowObj.AdmissibleG3Test.submit("authorize-form"); await settle();
    await flushTimers(2); await settle();
    const terminal = windowObj.AdmissibleG4Test.snapshot();
    const facts = windowObj.AdmissibleG4Test.observationFacts();
    const requestsAtTerminal = fetchLog.length;
    const statusAtTerminal = statusRequestCount();
    const resultAtTerminal = resultRequestCount();
    await flushTimers(40); await settle();
    return {
      alteredOnlyObservationSurface: instrumented.alteredOnlyObservationSurface,
      state: terminal.state,
      visibleState: windowObj.AdmissibleG4Test.getState(),
      resultResolved: facts.resultResolved === true && terminal.resultResolved === true,
      abortOwnerCleared: terminal.hasAbortOwner === false && facts.pollController === null,
      timerCleared: terminal.hasTimer === false && facts.pollTimer === null,
      observationPhaseCleared: facts.observationPhase === null,
      requestNotInFlight: facts.requestInFlight === false,
      noPendingPollTimer: timers.size === 0,
      requestsAtTerminal,
      requestsAfterAdvance: fetchLog.length,
      statusAtTerminal,
      statusAfterAdvance: statusRequestCount(),
      resultAtTerminal,
      resultAfterAdvance: resultRequestCount(),
      requestCountsStable: fetchLog.length === requestsAtTerminal && statusRequestCount() === statusAtTerminal && resultRequestCount() === resultAtTerminal,
      maxInFlight: tracker.maxInFlight,
      noResultText: document.getElementById("no-result-view").textContent,
    };
  } finally {
    activeAppJs = appJs;
  }
}

(async () => {
  try {
    let out;
    if (scenario === "g4_lifecycle") out = await runLifecycle();
    else if (scenario === "g4_start_failed") out = await runStartFailed();
    else if (scenario.startsWith("g4_variant:")) out = await runVariant(scenario.split(":")[1]);
    else if (scenario === "g4_malicious") out = await runMalicious();
    else if (scenario === "g4_stale") out = await runStaleAndSingleFlight();
    else if (scenario === "g4_authoring_detail") out = await runAuthoringSafeDetail();
    else if (scenario === "g4_single_observation_owner") out = await runSingleObservationOwnership();
    else if (scenario === "g4_410_terminal_ownership") out = await run410TerminalOwnership();
    else throw new Error("unknown scenario");
    process.stdout.write(JSON.stringify(out));
  } catch (error) {
    process.stdout.write(JSON.stringify({ scenario, error: String(error && error.stack || error) }));
    process.exitCode = 1;
  }
})();
'''


def _build_node_harness() -> str:
    harness = G3_NODE_HARNESS.replace(
        "\nbuildDom();\n\nconst document =",
        "\n" + G4_DOM + "\nbuildDom();\ninstallG4Dom();\n\nconst document =",
    )
    harness = harness.replace(
        "  buildDom();\n  // trap marker side effects",
        "  buildDom();\n  installG4Dom();\n  // trap marker side effects",
    )
    harness = harness.replace(
        "Object, Array, String, Number, Boolean, JSON, Error, Promise, Math, RegExp, Date,",
        "Object, Array, String, Number, Boolean, JSON, Error, Promise, Math, RegExp, Date: class FakeDate extends Date { static now() { return nowMs; } },",
    )
    harness = harness.replace(
        'const appJs = fs.readFileSync(appJsPath, "utf8");',
        'const appJs = fs.readFileSync(appJsPath, "utf8");\nlet activeAppJs = appJs;',
        1,
    )
    harness = harness.replace(
        'vm.runInNewContext(appJs, context, { filename: "app.js", timeout: 5000 });',
        'vm.runInNewContext(activeAppJs, context, { filename: "app.js", timeout: 5000 });',
        1,
    )
    return harness.rsplit("(async () => {", 1)[0] + G4_SCENARIOS


NODE_HARNESS = _build_node_harness()


def _run_node(tmp_path: Path, scenario: str, js_path: Path | None = None) -> dict:
    harness = tmp_path / f"g4_harness_{re.sub(r'[^A-Za-z0-9_]+', '_', scenario)}.js"
    harness.write_text(NODE_HARNESS, encoding="utf-8")
    completed = subprocess.run(
        [NODE, str(harness), scenario, str(js_path or JS_PATH)],
        capture_output=True,
        text=True,
        timeout=25,
        cwd=str(tmp_path),
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    assert completed.returncode == 0, completed.stdout + "\n" + completed.stderr
    payload = json.loads(completed.stdout)
    assert "error" not in payload, payload
    return payload


class ShellAudit(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.headings: list[str] = []
        self.current_heading = False

    def handle_starttag(self, tag: str, attrs) -> None:
        data = dict(attrs)
        if "id" in data:
            self.ids.add(data["id"])
        if tag in {"h1", "h2", "h3"}:
            self.current_heading = True

    def handle_endtag(self, tag: str) -> None:
        if tag in {"h1", "h2", "h3"}:
            self.current_heading = False

    def handle_data(self, data: str) -> None:
        if self.current_heading and data.strip():
            self.headings.append(data.strip())


def test_g4_shell_semantics_accessibility_and_lifecycle_steps():
    audit = ShellAudit()
    audit.feed(HTML)
    assert {"accepted-view", "result-view", "no-result-view", "live-status", "status-area"}.issubset(audit.ids)
    assert all(step in HTML for step in ("Compose", "Contract", "Authorize", "Run", "Result"))
    assert "Mission accepted" in HTML and "No authoritative result" in audit.headings
    assert 'aria-live="polite"' in HTML and 'aria-live="assertive"' in HTML and 'role="alert"' in HTML
    assert 'tabindex="-1"' in HTML and "Compose another mission" in HTML


def test_explicit_g4_state_machine_routes_and_polling_law():
    for state in (
        "RUN_ACCEPTED", "RUN_LOADING", "RUN_QUEUED", "RUN_STARTING", "RUN_RUNNING",
        "RUN_TERMINAL_LOADING_RESULT", "RUN_RESULT_READY", "RUN_NO_AUTHORITATIVE_RESULT",
        "RUN_START_FAILED", "RUN_REQUEST_ERROR",
    ):
        assert state in JS
    assert "POLL_INTERVAL_MS = 750" in JS and "MAX_STATUS_ATTEMPTS = 120" in JS
    assert "MAX_RESULT_ATTEMPTS = 120" in JS and "flowEpoch" in JS and "AbortController" in JS
    assert "pagehide" in JS and "beforeunload" in JS and "requestInFlight" in JS
    assert "product_summary" not in JS.replace('"product_summary"', "")
    assert "/ui/api/v1/runs" in JS and "authoritativeResultPath" in JS
    assert not re.search(r'api\("/ui/api/v1/runs"\)', JS)


def test_security_scans_and_bounded_observation_hook():
    assert all(api not in JS for api in ("innerHTML", "outerHTML=", "insertAdjacentHTML", "document.write", "eval(", "new Function"))
    assert "localStorage" not in JS and "sessionStorage" not in JS
    assert "run_root" in JS and "diagnostics" in JS and "FORBIDDEN_RESULT_FIELDS" in JS
    hook = JS.split('Object.defineProperty(window,"AdmissibleG4Test"', 1)[1].split("bootstrap();", 1)[0]
    assert all(secret not in hook.lower() for secret in ("csrf", "nonce", "token", "phrase", "digest", "authorization"))
    assert 'credentials:"omit"' in JS and 'cache:"no-store"' in JS and 'referrerPolicy:"no-referrer"' in JS
    assert "/api/v1/" not in JS.replace("/ui/api/v1/", "")


def test_mobile_overflow_focus_and_reduced_motion_contract():
    assert "@media(max-width:760px)" in CSS and "@media(max-width:420px)" in CSS
    assert "@media(prefers-reduced-motion:reduce)" in CSS and ":focus-visible" in CSS
    assert "overflow-x:hidden" in CSS and "overflow-wrap:anywhere" in CSS and "word-break:break-word" in CSS
    assert "grid-template-columns:repeat(5,1fr)" in CSS and CSS.count("{") == CSS.count("}")


def test_javascript_syntax_python_ast_and_test_harness_ast():
    subprocess.run([NODE, "--check", str(JS_PATH)], check=True, capture_output=True, text=True, timeout=10)
    ast.parse(Path(__file__).read_text(encoding="utf-8"))
    assert "fs.readFileSync(appJsPath" in NODE_HARNESS and "setTimeoutFn" in NODE_HARNESS
    assert "let activeAppJs = appJs" in NODE_HARNESS
    assert "instrumentObservationSurface" in NODE_HARNESS
    assert "g4_single_observation_owner" in NODE_HARNESS and "g4_410_terminal_ownership" in NODE_HARNESS
    assert "function startRunObservation" not in NODE_HARNESS
    assert "resultResolved = true" not in NODE_HARNESS.replace("facts.resultResolved === true", "")


def test_202_lifecycle_409_then_200_and_terminal_truth_boundaries(tmp_path):
    out = _run_node(tmp_path, "g4_lifecycle")
    assert out["accepted"]["state"] == "RUN_ACCEPTED" and out["accepted"]["initialControlState"] == "QUEUED"
    assert out["requestUrls"][:1] == ["/ui/api/v1/runs"]
    assert out["states"] == ["RUN_QUEUED", "RUN_STARTING", "RUN_RUNNING", "RUN_TERMINAL_LOADING_RESULT"]
    assert "not a success verdict" in out["terminalText"] and out["verdictBeforeResult"] == ""
    assert out["after409"]["state"] == "RUN_TERMINAL_LOADING_RESULT" and out["after409"]["resultAttempts"] == 1
    assert out["final"]["state"] == "RUN_RESULT_READY" and out["final"]["resultResolved"] is True
    assert out["maxInFlight"] == 1 and out["noRequestsAfterResolution"] is True


def test_result_evidence_and_transport_return_code_are_separate(tmp_path):
    out = _run_node(tmp_path, "g4_lifecycle")
    assert "ADMITTED_VERIFIED" in out["classificationText"] and "INDEPENDENT" in out["classificationText"] and "COMPLETE" in out["classificationText"]
    assert "Application return code (transport only)7" in out["terminalText"]
    for expected in ("Run identity", "Git and workspace result", "Required materials", "Checkpoint result", "Independent behavioral verification", "Completeness and failing boundary"):
        assert expected in out["essentialText"]
    for expected in ("Process facts", "Evidence inventory", "Notices and transport", "admissible_product_service_transport_v1"):
        assert expected in out["supplementalText"]
    assert "b" * 40 in out["resultText"] and "c" * 64 in out["resultText"] and "d" * 64 in out["resultText"]
    assert out["secretsEmpty"] and out["storageEmpty"]


def test_start_failed_and_410_no_authoritative_result(tmp_path):
    out = _run_node(tmp_path, "g4_start_failed")
    assert out["startFailed"]["state"] == "RUN_START_FAILED"
    assert out["noResult"]["state"] == "RUN_NO_AUTHORITATIVE_RESULT"
    assert "No authoritative result" in out["noResultText"]
    assert "START_FAILED" in out["noResultText"] and "RUN_ROOT_ABSENT" in out["noResultText"] and "RuntimeError" in out["noResultText"]
    assert "transport only" in out["noResultText"] and out["noRequestsAfter410"] is True


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ADMITTED_OBSERVED", "ADMITTED_OBSERVED"),
        ("ADMITTED_VERIFIED", "ADMITTED_VERIFIED"),
        ("REFUSED", "BEHAVIORAL_VERIFICATION"),
        ("INCOMPLETE", "INCOMPLETE"),
        ("INCONSISTENT", "INCONSISTENT"),
        ("UNKNOWN", "UNKNOWN"),
        ("UNSUPPORTED", "UNSUPPORTED"),
    ],
)
def test_exact_result_classifications_are_not_renamed(tmp_path, name, expected):
    out = _run_node(tmp_path, f"g4_variant:{name}")
    assert out["state"] == "RUN_RESULT_READY" and expected in out["classification"]
    if name == "REFUSED":
        assert "REFUSED" in out["classification"]


def test_html_shaped_result_values_are_inert_and_private_fields_hidden(tmp_path):
    out = _run_node(tmp_path, "g4_malicious")
    assert out["state"] == "RUN_RESULT_READY" and out["markerInvoked"] == 0
    assert out["unsafeHtmlApi"] == 0 and out["createdScriptTags"] == 0 and out["assignedHandlers"] == []
    assert "<script>" in out["text"] and out["forbiddenVisible"] is False


def test_stale_status_and_result_single_flight_and_reset_abort(tmp_path):
    out = _run_node(tmp_path, "g4_stale")
    assert out == {
        "oneStatusInFlight": True,
        "pendingResultInFlight": True,
        "staleStatusIgnored": True,
        "staleResultIgnored": True,
        "resetAborted": True,
    }


def test_second_start_run_observation_is_noop_while_owner_exists(tmp_path):
    out = _run_node(tmp_path, "g4_single_observation_owner")
    assert out["alteredOnlyObservationSurface"] is True
    assert out["ownerPresent"] is True
    assert out["sameController"] is True
    assert out["controllersCreatedAfterOwner"] == 0
    assert out["noSecondTimer"] is True
    assert out["timerCountBeforeSecondStart"] == 0
    assert out["timerCountAfterSecondStart"] == 0
    assert out["onlyOneStatusRequest"] is True
    assert out["statusRequestCount"] == 1
    assert out["maxInFlight"] == 1
    assert out["requestInFlight"] is True
    assert out["resultResolved"] is False
    assert out["observationPhase"] == "status"


def test_result_410_clears_observation_terminal_ownership(tmp_path):
    out = _run_node(tmp_path, "g4_410_terminal_ownership")
    assert out["alteredOnlyObservationSurface"] is True
    assert out["state"] == "RUN_NO_AUTHORITATIVE_RESULT"
    assert out["visibleState"] == "RUN_NO_AUTHORITATIVE_RESULT"
    assert out["resultResolved"] is True
    assert out["abortOwnerCleared"] is True
    assert out["timerCleared"] is True
    assert out["observationPhaseCleared"] is True
    assert out["requestNotInFlight"] is True
    assert out["noPendingPollTimer"] is True
    assert out["requestCountsStable"] is True
    assert out["maxInFlight"] == 1
    assert out["resultAtTerminal"] == 1
    assert out["statusAtTerminal"] == 1
    assert "No authoritative result" in out["noResultText"]
    assert "TERMINAL" in out["noResultText"] and "RUN_ROOT_ABSENT" in out["noResultText"]


def test_authoring_rejected_shows_safe_error_code_and_field(tmp_path):
    out = _run_node(tmp_path, "g4_authoring_detail")
    matched = out["matched"]
    assert matched["state"] == "COMPOSE"
    assert matched["statusVisible"] is True
    assert matched["statusMessage"] == "The launcher rejected one or more contract fields."
    assert matched["statusCode"] == "AUTHORING_REJECTED / GOLDEN_CONTRACT_MISMATCH (mission_text)"
    assert matched["composeHidden"] is False
    assert matched["missionValue"] == "owner mission retained"
    assert matched["objectiveValue"] == "owner objective retained"
    assert matched["conditionsValue"] == "owner conditions retained"
    assert matched["commitValue"] == "feat: owner commit retained"
    assert matched["materialValues"] == ["README.md"]
    rendered = matched["errorArea"] + matched["executionClaim"]
    for banned in (
        "C:/secret/path", "Traceback", "https://evil.example", "owner-secret-phrase",
        "RuntimeError", "/tmp/x.py", "authoring.golden_contract_mismatch", "execution started",
        '{"error"', "nested",
    ):
        assert banned not in rendered
    assert "owner mission retained" not in matched["errorArea"]

    unsafe = out["unsafe"]
    assert unsafe["statusMessage"] == "The launcher rejected one or more contract fields."
    assert unsafe["statusCode"] == "AUTHORING_REJECTED"
    for banned in ("C:/unsafe/path", "<script>", "alert(1)", "raw body must stay invisible", "do-not-echo"):
        assert banned not in unsafe["errorArea"]
    assert unsafe["missionValue"] == "owner mission retained"

    malformed = out["malformed"]
    assert malformed["statusMessage"] == "The launcher rejected one or more contract fields."
    assert malformed["statusCode"] == "AUTHORING_REJECTED"
    assert "12" not in malformed["statusCode"]
    assert "mission_text" not in malformed["statusCode"]
    assert "raw" not in malformed["errorArea"]


def _result_payload() -> dict:
    return {
        "non_authority_notice": "Persisted claims do not create authority.",
        "run_id": "run-real-server-1",
        "presentation_status": "ADMITTED",
        "execution_state": {"state": "COMPLETED", "provider_exit_code": 0},
        "result_admission_state": {"verdict": "ADMITTED_VERIFIED", "verification_mode": "INDEPENDENT"},
        "failing_boundary": {"boundary": "NONE", "reasons": []},
        "material_git_result": {
            "git": {"present": "PRESENT", "final_git_head": "b" * 40, "source_repository_mutated": False},
            "material": {"present": "PRESENT", "result": "PASSED", "eligible": True},
        },
        "checkpoint_result": {"present": "PRESENT", "result": "PASSED", "attempted": True},
        "behavioral_verifier_result": {"present": "PRESENT", "result": "PASSED", "exit_code": 0},
        "evidence_completeness": {"state": "COMPLETE", "missing_required": []},
        "timeline": [],
        "artifacts": [],
        "transport_schema_version": "admissible_product_service_transport_v1",
        "transport_redactions": ["diagnostics", "run_root"],
        "read_notes": [],
        "human_disposition": {"present": "ABSENT", "disposition": "UNKNOWN"},
    }


class SequenceLauncher(FakeLauncher):
    def __init__(self) -> None:
        super().__init__("PRECOMMITTED_DIGEST")
        self.statuses = ["QUEUED", "STARTING", "RUNNING", "TERMINAL"]
        self.proxy_calls: list[str] = []
        self.result_calls = 0

    def proxy_g2(self, method: str, path: str):
        assert method == "GET"
        self.proxy_calls.append(path)
        if path.endswith("/result"):
            self.result_calls += 1
            if self.result_calls == 1:
                return 409, {"error": "RESULT_NOT_READY"}
            return 200, _result_payload()
        state = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        return 200, {
            "control_run_id": "control-1",
            "control_state": state,
            "authoritative_session_id": None if state == "QUEUED" else "session-real-1",
            "started_at": None if state == "QUEUED" else "2026-07-20T10:00:00Z",
            "ended_at": "2026-07-20T10:00:04Z" if state == "TERMINAL" else None,
            "application_return_code": 0 if state == "TERMINAL" else None,
            "start_error_type": None,
            "terminal_evidence": "RUN_ROOT_PRESENT" if state == "TERMINAL" else None,
            "product_summary": {"product_verdict": "PASS"},
        }


def _free_port() -> int:
    probe = socket.socket()
    try:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
    finally:
        probe.close()


def test_full_real_server_browser_rehearsal_with_injected_sequences(tmp_path):
    if not CHROME.is_file():
        pytest.skip("Chrome not installed")
    launcher = SequenceLauncher()
    server = create_ui_loopback_server(launcher, csrf_generator=lambda _n: "f" * 64).start()
    profile = tmp_path / "chrome-profile-g4"
    profile.mkdir()
    debug_port = _free_port()
    url = f"http://{server.host}:{server.port}/"
    cmd = [
        str(CHROME), f"--user-data-dir={profile}", f"--remote-debugging-port={debug_port}",
        "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
        "--disable-extensions", "--disable-background-networking", url,
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    close_cdp = None
    try:
        deadline = time.time() + 20
        targets = None
        while time.time() < deadline:
            try:
                with urlopen(f"http://127.0.0.1:{debug_port}/json", timeout=1) as response:
                    targets = json.loads(response.read().decode())
                break
            except Exception:
                time.sleep(0.2)
        assert targets is not None
        page = next(item for item in targets if item.get("type") == "page" and url.rstrip("/") in item.get("url", ""))
        send, close_cdp = _cdp_connect(page["webSocketDebuggerUrl"])
        send("Runtime.enable")

        def evaluate(expression: str):
            got = send("Runtime.evaluate", {"expression": expression, "returnByValue": True})
            return ((got.get("result") or {}).get("result") or {}).get("value")

        def wait_for(expression: str, wanted, timeout_s: float = 20.0):
            end = time.time() + timeout_s
            last = None
            while time.time() < end:
                last = evaluate(expression)
                if last == wanted:
                    return last
                time.sleep(0.15)
            raise AssertionError(f"wait for {wanted!r} timed out; last={last!r}")

        wait_for("window.AdmissibleG3Test && window.AdmissibleG3Test.getState()", "COMPOSE")
        evaluate(
            "window.AdmissibleG3Test.setField('mission-text','browser mission');"
            "window.AdmissibleG3Test.setField('gate-objective','browser objective');"
            "window.AdmissibleG3Test.setField('completion-conditions','browser complete');"
            "window.AdmissibleG3Test.setField('commit-message','feat: browser');"
            "window.AdmissibleG3Test.submit('compose-form');"
        )
        wait_for("window.AdmissibleG3Test.getState()", "CONTRACT_READY")
        evaluate("window.AdmissibleG3Test.click('prepare-button')")
        wait_for("window.AdmissibleG3Test.getState()", "PREPARATION_READY")
        evaluate(
            "window.AdmissibleG3Test.setField('owner-phrase','owner-secret-phrase');"
            f"window.AdmissibleG3Test.setField('owner-digest','{'d' * 64}');"
            "window.AdmissibleG3Test.submit('authorize-form');"
        )
        wait_for("window.AdmissibleG4Test && window.AdmissibleG4Test.getState()", "RUN_RESULT_READY", 20)
        text = evaluate("document.getElementById('result-view').textContent")
        secret_state = evaluate("document.getElementById('owner-phrase').value + '|' + document.getElementById('owner-digest').value")
        overflow = evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
        assert "ADMITTED_VERIFIED" in text and "COMPLETE" in text and "Git and workspace result" in text
        assert secret_state == "|" and overflow is True
        assert launcher.proxy_calls == [
            "/api/v1/runs/control-1", "/api/v1/runs/control-1", "/api/v1/runs/control-1", "/api/v1/runs/control-1",
            "/api/v1/runs/control-1/result", "/api/v1/runs/control-1/result",
        ]
    finally:
        if close_cdp:
            close_cdp()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        server.stop()


UNBROKEN_TOKEN = ("OVERFLOWPROBE" * 200)[:1800]
HOSTILE_PREFIX = '<script>window.__g4_marker++</script><img src=x onerror="window.__g4_marker++">'
CONTAINED_SELECTORS = (".result-summary", ".non-authority-notice")
OVERFLOW_VIEWPORTS = ((1280, 800, False), (390, 844, True))

MEASURE_JS = r"""
(function(){
  const surface=document.getElementById("result-view");
  const rail=document.querySelector(".authority-rail");
  const surfaceRect=surface?surface.getBoundingClientRect():null;
  const railRect=rail?rail.getBoundingClientRect():null;
  const out={
    docScrollWidth:document.documentElement.scrollWidth,
    docClientWidth:document.documentElement.clientWidth,
    bodyScrollWidth:document.body.scrollWidth,
    surfaceRight:surfaceRect?surfaceRect.right:null,
    railLeft:railRect?railRect.left:null,
    marker:window.__g4_marker===undefined?-1:window.__g4_marker,
    injectedNodes:document.querySelectorAll("#result-view script,#result-view img,#result-view iframe,#result-view svg,#result-view object,#result-view embed").length,
    classificationLabels:Array.from(document.querySelectorAll("#result-classification .classification-label")).map(n=>n.textContent),
    classificationItems:document.querySelectorAll("#result-classification .classification-item").length,
    evidenceCards:document.querySelectorAll("#evidence-glance .evidence-card").length,
    evidenceSections:document.querySelectorAll("#essential-evidence details,#supplemental-evidence details").length,
    elements:{}
  };
  ["result-summary","non-authority-notice"].forEach(function(id){
    const node=document.getElementById(id);
    if(!node){out.elements[id]=null;return;}
    const rect=node.getBoundingClientRect();
    const range=document.createRange();
    range.selectNodeContents(node);
    const paint=range.getBoundingClientRect();
    out.elements[id]={
      scrollWidth:node.scrollWidth,
      clientWidth:node.clientWidth,
      left:rect.left,
      right:rect.right,
      width:rect.width,
      paintLeft:paint.left,
      paintRight:paint.right,
      textLength:node.textContent.length,
      text:node.textContent.slice(0,120)
    };
  });
  return JSON.stringify(out);
})()
"""


class OverflowLauncher(SequenceLauncher):
    """Serves one caller-chosen authoritative result payload through the real G4 flow."""

    def __init__(self) -> None:
        super().__init__()
        self.payload = _result_payload()

    def load(self, payload: dict) -> None:
        self.payload = payload
        self.statuses = ["QUEUED", "STARTING", "RUNNING", "TERMINAL"]
        self.result_calls = 0
        self.proxy_calls = []

    def proxy_g2(self, method: str, path: str):
        status, body = super().proxy_g2(method, path)
        if path.endswith("/result") and status == 200:
            return status, self.payload
        return status, body


def _notice_overflow_payload() -> dict:
    payload = _result_payload()
    payload["non_authority_notice"] = UNBROKEN_TOKEN
    return payload


def _summary_overflow_payload() -> dict:
    payload = _result_payload()
    payload["result_admission_state"] = {"verdict": UNBROKEN_TOKEN, "verification_mode": "INDEPENDENT"}
    return payload


def _hostile_overflow_payload() -> dict:
    payload = _result_payload()
    payload["presentation_status"] = "REFUSED"
    payload["result_admission_state"] = {"verdict": "REFUSED", "verification_mode": HOSTILE_PREFIX + UNBROKEN_TOKEN}
    payload["failing_boundary"] = {"boundary": HOSTILE_PREFIX + UNBROKEN_TOKEN, "reasons": []}
    payload["non_authority_notice"] = HOSTILE_PREFIX + UNBROKEN_TOKEN
    return payload


OVERFLOW_SCENARIOS = (
    ("notice_long_token", _notice_overflow_payload, True),
    ("summary_long_token", _summary_overflow_payload, True),
    ("refused_hostile_long_token", _hostile_overflow_payload, True),
    ("normal_admitted_verified", _result_payload, False),
)


def test_long_result_text_is_contained_in_summary_and_notice_surfaces(tmp_path):
    if not CHROME.is_file():
        pytest.skip("Chrome not installed")
    launcher = OverflowLauncher()
    server = create_ui_loopback_server(launcher, csrf_generator=lambda _n: "f" * 64).start()
    profile = tmp_path / "chrome-profile-g4-overflow"
    profile.mkdir()
    debug_port = _free_port()
    url = f"http://{server.host}:{server.port}/"
    cmd = [
        str(CHROME), f"--user-data-dir={profile}", f"--remote-debugging-port={debug_port}",
        "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
        "--disable-extensions", "--disable-background-networking", url,
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    close_cdp = None
    baseline_structure = None
    try:
        deadline = time.time() + 20
        targets = None
        while time.time() < deadline:
            try:
                with urlopen(f"http://127.0.0.1:{debug_port}/json", timeout=1) as response:
                    targets = json.loads(response.read().decode())
                break
            except Exception:
                time.sleep(0.2)
        assert targets is not None
        page = next(item for item in targets if item.get("type") == "page" and url.rstrip("/") in item.get("url", ""))
        send, close_cdp = _cdp_connect(page["webSocketDebuggerUrl"])
        send("Runtime.enable")
        send("Page.enable")

        def evaluate(expression: str):
            got = send("Runtime.evaluate", {"expression": expression, "returnByValue": True})
            return ((got.get("result") or {}).get("result") or {}).get("value")

        def wait_for(expression: str, wanted, timeout_s: float = 25.0):
            end = time.time() + timeout_s
            last = None
            while time.time() < end:
                last = evaluate(expression)
                if last == wanted:
                    return last
                time.sleep(0.15)
            raise AssertionError(f"wait for {wanted!r} timed out; last={last!r}")

        def drive_to_result():
            wait_for("window.AdmissibleG3Test && window.AdmissibleG3Test.getState()", "COMPOSE")
            evaluate("window.__g4_marker=0")
            evaluate(
                "window.AdmissibleG3Test.setField('mission-text','overflow mission');"
                "window.AdmissibleG3Test.setField('gate-objective','overflow objective');"
                "window.AdmissibleG3Test.setField('completion-conditions','overflow complete');"
                "window.AdmissibleG3Test.setField('commit-message','feat: overflow');"
                "window.AdmissibleG3Test.submit('compose-form');"
            )
            wait_for("window.AdmissibleG3Test.getState()", "CONTRACT_READY")
            evaluate("window.AdmissibleG3Test.click('prepare-button')")
            wait_for("window.AdmissibleG3Test.getState()", "PREPARATION_READY")
            evaluate(
                "window.AdmissibleG3Test.setField('owner-phrase','owner-secret-phrase');"
                f"window.AdmissibleG3Test.setField('owner-digest','{'d' * 64}');"
                "window.AdmissibleG3Test.submit('authorize-form');"
            )
            wait_for("window.AdmissibleG4Test && window.AdmissibleG4Test.getState()", "RUN_RESULT_READY", 25)

        for index, (name, build_payload, injected) in enumerate(OVERFLOW_SCENARIOS):
            launcher.load(build_payload())
            if index:
                send("Page.navigate", {"url": url})
                send("Runtime.enable")
                time.sleep(0.4)
            drive_to_result()

            for width, height, mobile in OVERFLOW_VIEWPORTS:
                send("Emulation.setDeviceMetricsOverride", {
                    "width": width, "height": height, "deviceScaleFactor": 1, "mobile": mobile,
                })
                time.sleep(0.3)
                evaluate("document.documentElement.offsetWidth")
                raw = evaluate(MEASURE_JS)
                assert isinstance(raw, str), f"{name} @{width}x{height}: measurement failed"
                m = json.loads(raw)
                where = f"{name} @{width}x{height}"

                assert m["marker"] == 0, f"{where}: hostile handler executed"
                assert m["injectedNodes"] == 0, f"{where}: hostile DOM node created"

                for element_id in ("result-summary", "non-authority-notice"):
                    e = m["elements"][element_id]
                    assert e is not None, f"{where}/{element_id}: element missing"
                    assert e["scrollWidth"] <= e["clientWidth"] + 1, (
                        f"{where}/{element_id}: scrollWidth {e['scrollWidth']} > clientWidth {e['clientWidth']}"
                    )
                    assert e["paintRight"] <= e["right"] + 1, (
                        f"{where}/{element_id}: text paints to {e['paintRight']} past element right {e['right']}"
                    )
                    assert e["right"] <= m["surfaceRight"] + 1, (
                        f"{where}/{element_id}: element right {e['right']} past result surface {m['surfaceRight']}"
                    )
                    assert e["paintRight"] <= m["surfaceRight"] + 1, f"{where}/{element_id}: paint past result surface"
                    if m["railLeft"] is not None and m["railLeft"] >= m["surfaceRight"] - 2:
                        assert e["paintRight"] <= m["railLeft"] + 1, (
                            f"{where}/{element_id}: text crosses the authority rail at {m['railLeft']}"
                        )
                    assert e["width"] > 0, f"{where}/{element_id}: element collapsed"

                assert m["docScrollWidth"] <= m["docClientWidth"] + 1, f"{where}: document overflow"
                assert m["bodyScrollWidth"] <= m["docClientWidth"] + 1, f"{where}: body overflow"

                notice = m["elements"]["non-authority-notice"]
                summary = m["elements"]["result-summary"]
                if injected:
                    assert max(notice["textLength"], summary["textLength"]) >= 1800, f"{where}: token not delivered"
                if name == "refused_hostile_long_token":
                    assert notice["text"].startswith("<script>"), f"{where}: HTML-shaped value was not literal text"
                    assert "REFUSED" in summary["text"], f"{where}: refusal verdict missing"

                if name == "normal_admitted_verified":
                    structure = (
                        tuple(m["classificationLabels"]), m["classificationItems"],
                        m["evidenceCards"], m["evidenceSections"], summary["text"], notice["text"],
                    )
                    if baseline_structure is None:
                        baseline_structure = structure
                    assert structure == baseline_structure, f"{where}: normal result structure changed"
                    assert m["classificationItems"] == 4 and m["evidenceCards"] == 4
                    assert summary["text"].startswith("Product verdict: ADMITTED_VERIFIED.")
                    assert notice["text"] == "Persisted claims do not create authority."

            send("Emulation.clearDeviceMetricsOverride")

        assert baseline_structure is not None
    finally:
        if close_cdp:
            close_cdp()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
        server.stop()


def test_result_summary_and_notice_declare_explicit_containment():
    for selector in CONTAINED_SELECTORS:
        rule = CSS.split(selector + "{", 1)[1].split("}", 1)[0]
        assert "overflow-wrap:anywhere" in rule, f"{selector} lost overflow-wrap containment"
        assert "word-break:break-word" in rule, f"{selector} lost word-break containment"
        assert "text-overflow" not in rule and "white-space:nowrap" not in rule
        assert "width:" not in rule.replace("max-width:100%", "").replace("min-width:0", "")
