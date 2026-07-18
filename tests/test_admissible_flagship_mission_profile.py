"""Gate L1C: canonical mission profiles, v4 payloads, and the flagship path.

Every native process is the deterministic fake runner from the sibling
executor harness; the behavioral verifier and checkpoint capture run through
the real committed verification paths (real ``node`` and real ``npm test``)
against the temporary incident-board fixture.  No live Cursor, provider, or
real native invocation is reachable from any test.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from test_admissible_delegated_gate_native_executor import (
    Clock,
    FakeNativeProcessRunner,
    _command,
    _commit,
    _injected_test_cursor,
)

from admissible.delegated_gate.canonical import canonical_bytes, fingerprint
from admissible.delegated_gate.fixture_registry import (
    INCIDENT_BOARD_INITIAL_COMMIT_MESSAGE,
    build_incident_board_repository,
)
from admissible.delegated_gate.mission_profile import (
    FLAGSHIP_INCIDENT_REPLAY_PROFILE,
    NativeMissionProfile,
)
from admissible.delegated_gate import native_canary as nc
from admissible.delegated_gate.native_canary import (
    AUTHORIZATION_SCHEMA_VERSION_V4,
    CANARY_CLASSIFICATION,
    DEFAULT_STDERR_BYTE_LIMIT,
    DEFAULT_STDOUT_BYTE_LIMIT,
    DEFAULT_TIMEOUT_SECONDS,
    NativeCanaryCoordinator,
    NativeCanaryStatus,
    RUN_PREFLIGHT_METADATA_FILE_NAME,
    _authorized,
    _observe_built_fixture,
    _write_run_metadata_once,
    build_canary_repository,
    build_native_agent_prompt,
    build_profile_authorization_payload,
    create_canary_session,
    legacy_canary_profile,
    main,
    npm_test_argv,
    reconstruct_completed_canary_success,
    resolve_fixture_builder,
    resolve_registered_profile,
)
from admissible.delegated_gate.native_executor import (
    AtomicNativeExecutionStore,
    NativeDelegatedExecutor,
    NativeEvidenceInvalid,
)
from admissible.delegated_gate.state import Phase
from admissible.delegated_gate.store import AtomicDelegatedSessionStore

import hashlib


FLAGSHIP = FLAGSHIP_INCIDENT_REPLAY_PROFILE
_CANARY_MISSION_FINGERPRINT = "1a296853942d359647a12fe7875bac32898690a1fafd16c8d02993c471ae687e"


# ---------------------------------------------------------------------------
# Reference mission implementation the scripted fake native process applies.
# ---------------------------------------------------------------------------

_EVENT_LOG_JS = """import { applyCreate, applyStatus, applySeverity, applyNote, initialBoard } from './reducer.js';

export const EVENT_VERSION = 1;
export const EVENT_TYPES = Object.freeze(['incident-created', 'status-changed', 'severity-changed', 'note-added']);

export function validateEvent(event) {
  if (typeof event !== 'object' || event === null || Array.isArray(event)) throw new TypeError('event must be an object');
  if (Object.keys(event).sort().join(',') !== 'id,payload,type,version') throw new TypeError('event must have exactly id, version, type, payload');
  if (typeof event.id !== 'string' || !event.id) throw new TypeError('event id must be a non-empty string');
  if (event.version !== EVENT_VERSION) throw new TypeError('unsupported event version');
  if (!EVENT_TYPES.includes(event.type)) throw new TypeError('unsupported event type');
  if (typeof event.payload !== 'object' || event.payload === null || Array.isArray(event.payload)) throw new TypeError('event payload must be an object');
  return event;
}

export function createEvent(id, type, payload) {
  return validateEvent({ id, version: EVENT_VERSION, type, payload });
}

export function appendEvent(events, event) {
  validateEvent(event);
  if (events.some((existing) => existing.id === event.id)) throw new Error(`duplicate event id: ${event.id}`);
  return [...events, event];
}

function applyEvent(board, event) {
  switch (event.type) {
    case 'incident-created': return applyCreate(board, event.payload);
    case 'status-changed': return applyStatus(board, event.payload);
    case 'severity-changed': return applySeverity(board, event.payload);
    case 'note-added': return applyNote(board, event.payload);
    default: throw new TypeError('unsupported event type');
  }
}

export function replayEvents(events, upTo = events.length) {
  if (!Array.isArray(events)) throw new TypeError('event log must be an array');
  if (!Number.isSafeInteger(upTo) || upTo < 0 || upTo > events.length) throw new RangeError('replay position out of range');
  const seen = new Set();
  let board = initialBoard();
  events.forEach((event, index) => {
    validateEvent(event);
    if (seen.has(event.id)) throw new Error(`duplicate event id: ${event.id}`);
    seen.add(event.id);
    if (index < upTo) board = applyEvent(board, event);
  });
  return board;
}
"""

_EVENT_STORE_JS = """import { appendEvent, replayEvents, validateEvent } from '../domain/event-log.js';

const LOG_KEY = 'incident-board/event-log';

function parseLog(raw) {
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new TypeError('event log must be a JSON array');
  const seen = new Set();
  for (const event of parsed) {
    validateEvent(event);
    if (seen.has(event.id)) throw new Error(`duplicate event id: ${event.id}`);
    seen.add(event.id);
  }
  return parsed;
}

export function createEventStore(storage) {
  const stored = storage.getItem(LOG_KEY);
  let events = stored === null ? [] : parseLog(stored);
  replayEvents(events);
  const persist = () => storage.setItem(LOG_KEY, JSON.stringify(events));
  return {
    events() { return events.slice(); },
    append(event) {
      const next = appendEvent(events, event);
      replayEvents(next);
      events = next;
      persist();
    },
    exportLog() { return JSON.stringify(events); },
    importLog(raw) {
      const next = parseLog(raw);
      replayEvents(next);
      events = next;
      persist();
    },
  };
}
"""

_CONTROLLER_JS = """import { replayEvents, createEvent } from '../domain/event-log.js';
import { createEventStore } from '../storage/event-store.js';

export function createController(storage) {
  const eventStore = createEventStore(storage);
  let board = replayEvents(eventStore.events());
  const record = (type, payload) => {
    const event = createEvent(`evt-${eventStore.events().length + 1}`, type, payload);
    eventStore.append(event);
    board = replayEvents(eventStore.events());
    return board;
  };
  return {
    board() { return board; },
    createIncident({ id, title, severity }) { return record('incident-created', { id, title, severity }); },
    updateStatus(id, status) { return record('status-changed', { id, status }); },
    updateSeverity(id, severity) { return record('severity-changed', { id, severity }); },
    addNote(id, note) { return record('note-added', { id, note }); },
    eventCount() { return eventStore.events().length; },
    timeline() { return eventStore.events(); },
    replayAt(position) { return replayEvents(eventStore.events(), position); },
    exportLog() { return eventStore.exportLog(); },
    importLog(raw) {
      eventStore.importLog(raw);
      board = replayEvents(eventStore.events());
      return board;
    },
  };
}
"""

_APP_JS = """import { createController } from './ui/controller.js';
import { renderBoard, renderTimeline } from './ui/render.js';

export function createApp(storage) {
  const controller = createController(storage);
  return {
    controller,
    render: () => renderBoard(controller.board()),
    renderTimeline: () => renderTimeline(controller.timeline()),
  };
}
"""

_RENDER_JS = """const REPLACEMENTS = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => REPLACEMENTS[character]);
}

export function renderIncident(incident) {
  const notes = incident.notes.map((note) => `<li class="note">${escapeHtml(note)}</li>`).join('');
  return `<article class="incident severity-${incident.severity} status-${incident.status}">`
    + `<h2>${escapeHtml(incident.title)}</h2>`
    + `<p class="meta">${escapeHtml(incident.id)} \\u00b7 ${incident.severity} \\u00b7 ${incident.status}</p>`
    + `<ul class="notes">${notes}</ul>`
    + `</article>`;
}

export function renderBoard(board) {
  if (board.incidents.length === 0) return '<p class="empty">No incidents recorded.</p>';
  return board.incidents.map(renderIncident).join('');
}

export function renderTimeline(events) {
  if (events.length === 0) return '<p class="empty">No recorded events.</p>';
  const rows = events.map((event, index) =>
    `<li class="event"><span class="position">${index + 1}</span> `
    + `<code>${escapeHtml(event.id)}</code> ${escapeHtml(event.type)}</li>`).join('');
  return `<ol class="timeline">${rows}</ol>`;
}

export function renderReplayControls(position, total) {
  return `<div class="replay-controls">`
    + `<button type="button" data-replay="previous">Previous</button>`
    + `<span class="replay-position">${position} / ${total}</span>`
    + `<button type="button" data-replay="next">Next</button>`
    + `<button type="button" data-replay="live">Live</button>`
    + `</div>`;
}
"""

_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local incident board</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<h1>Local incident board</h1>
<form id="create-form">
  <input name="id" placeholder="incident id" required>
  <input name="title" placeholder="title" required>
  <select name="severity">
    <option value="low">low</option>
    <option value="medium">medium</option>
    <option value="high" selected>high</option>
    <option value="critical">critical</option>
  </select>
  <button type="submit">Create incident</button>
</form>
<section id="board"></section>
<h2>Event timeline</h2>
<div id="replay-controls"></div>
<section id="timeline"></section>
<script type="module">
import { createApp } from './src/app.js';
import { createLocalStorageAdapter } from './src/storage/local-storage.js';
import { renderBoard, renderReplayControls } from './src/ui/render.js';

const app = createApp(createLocalStorageAdapter());
const board = document.getElementById('board');
const timeline = document.getElementById('timeline');
const controls = document.getElementById('replay-controls');
let position = null; // null renders the live authoritative board

const draw = () => {
  const total = app.controller.eventCount();
  const live = position === null || position >= total;
  board.innerHTML = live ? app.render() : renderBoard(app.controller.replayAt(position));
  timeline.innerHTML = app.renderTimeline();
  controls.innerHTML = renderReplayControls(live ? total : position, total);
};
controls.addEventListener('click', (event) => {
  const action = event.target instanceof HTMLElement ? event.target.dataset.replay : undefined;
  if (!action) return;
  const total = app.controller.eventCount();
  const current = position === null ? total : position;
  if (action === 'previous') position = Math.max(0, current - 1);
  if (action === 'next') position = Math.min(total, current + 1);
  if (action === 'live') position = null;
  draw();
});
document.getElementById('create-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const data = new FormData(event.target);
  app.controller.createIncident({
    id: String(data.get('id')),
    title: String(data.get('title')),
    severity: String(data.get('severity')),
  });
  event.target.reset();
  position = null;
  draw();
});
draw();
</script>
</body>
</html>
"""

_EVENT_REPLAY_TEST_JS = """import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { createMemoryStorage } from '../src/storage/memory-storage.js';
import { appendEvent, replayEvents, validateEvent, createEvent } from '../src/domain/event-log.js';

const canonical = (board) => JSON.stringify(board);

function seeded() {
  const storage = createMemoryStorage();
  const app = createApp(storage);
  app.controller.createIncident({ id: 'inc-1', title: 'Checkout latency', severity: 'high' });
  app.controller.updateStatus('inc-1', 'acknowledged');
  app.controller.addNote('inc-1', 'rollback started');
  return { storage, app };
}

test('replaying the same log from an empty board is deterministic', () => {
  const { app } = seeded();
  const events = JSON.parse(app.controller.exportLog());
  assert.equal(canonical(replayEvents(events)), canonical(app.controller.board()));
  assert.equal(canonical(replayEvents(events)), canonical(replayEvents(events)));
});

test('export then import reconstructs an equivalent board', () => {
  const { app } = seeded();
  const fresh = createApp(createMemoryStorage());
  fresh.controller.importLog(app.controller.exportLog());
  assert.equal(canonical(fresh.controller.board()), canonical(app.controller.board()));
});

test('a fresh instance restores the persisted history', () => {
  const { storage, app } = seeded();
  const restored = createApp(storage);
  assert.equal(canonical(restored.controller.board()), canonical(app.controller.board()));
  assert.equal(restored.controller.eventCount(), app.controller.eventCount());
});

test('replay positions expose beginning, intermediate, and final states', () => {
  const { app } = seeded();
  assert.equal(app.controller.replayAt(0).incidents.length, 0);
  assert.equal(app.controller.replayAt(1).incidents[0].status, 'open');
  assert.equal(app.controller.replayAt(2).incidents[0].status, 'acknowledged');
  assert.equal(canonical(app.controller.replayAt(app.controller.eventCount())), canonical(app.controller.board()));
  assert.throws(() => app.controller.replayAt(99), RangeError);
});

test('duplicate event ids never apply twice', () => {
  const { app } = seeded();
  const events = JSON.parse(app.controller.exportLog());
  assert.throws(() => appendEvent(events, events[0]));
  assert.throws(() => app.controller.importLog(JSON.stringify([...events, events[0]])));
});

test('malformed and unsupported events are rejected fail-closed', () => {
  assert.throws(() => validateEvent({ id: 'x', version: 2, type: 'incident-created', payload: {} }));
  assert.throws(() => validateEvent({ id: 'x', version: 1, type: 'other', payload: {} }));
  assert.throws(() => createEvent('', 'incident-created', {}));
  assert.throws(() => replayEvents([createEvent('e1', 'status-changed', { id: 'missing', status: 'resolved' })]));
});

test('a failed import leaves board and stored log unchanged', () => {
  const { app } = seeded();
  const boardBefore = canonical(app.controller.board());
  const logBefore = app.controller.exportLog();
  assert.throws(() => app.controller.importLog('not json'));
  const broken = JSON.parse(logBefore);
  broken[0] = { id: 'evt-broken', version: 9, type: 'incident-created', payload: {} };
  assert.throws(() => app.controller.importLog(JSON.stringify(broken)));
  assert.equal(canonical(app.controller.board()), boardBefore);
  assert.equal(app.controller.exportLog(), logBefore);
});

test('replay navigation never mutates the authoritative log', () => {
  const { app } = seeded();
  const logBefore = app.controller.exportLog();
  app.controller.replayAt(0);
  app.controller.replayAt(2);
  app.controller.replayAt(app.controller.eventCount());
  assert.equal(app.controller.exportLog(), logBefore);
});
"""

_README_APPENDIX = """
## Deterministic incident replay

Every incident mutation is recorded as a versioned event
(`{ id, version, type, payload }`, version `1`) in an append-only log persisted
through the injected storage adapter (`src/storage/event-store.js`). Board
state is reconstructed deterministically by replaying that log from an empty
board (`src/domain/event-log.js`).

- `exportLog()` / `importLog(text)` — validated, all-or-nothing export and
  import of the complete event log; malformed events, unsupported versions,
  duplicate IDs, and broken references are rejected without partial mutation.
- `replayAt(position)` — read-only historical state at any position; the
  authoritative log is never mutated by replay navigation.
- The browser UI shows the event timeline with manual Previous / Next / Live
  replay controls.
"""


def _materialize_incident_replay(repository: Path) -> None:
    """Scripted realistic final workspace mutation for the flagship mission."""

    (repository / "src" / "domain" / "event-log.js").write_text(_EVENT_LOG_JS, encoding="utf-8", newline="\n")
    (repository / "src" / "storage" / "event-store.js").write_text(_EVENT_STORE_JS, encoding="utf-8", newline="\n")
    (repository / "src" / "ui" / "controller.js").write_text(_CONTROLLER_JS, encoding="utf-8", newline="\n")
    (repository / "src" / "ui" / "render.js").write_text(_RENDER_JS, encoding="utf-8", newline="\n")
    (repository / "src" / "app.js").write_text(_APP_JS, encoding="utf-8", newline="\n")
    (repository / "index.html").write_text(_INDEX_HTML, encoding="utf-8", newline="\n")
    (repository / "test" / "event-replay.test.js").write_text(_EVENT_REPLAY_TEST_JS, encoding="utf-8", newline="\n")
    readme = repository / "README.md"
    original = readme.read_text(encoding="utf-8")
    trimmed = original.split("## Deliberately not implemented yet", 1)[0].rstrip() + "\n"
    readme.write_text(trimmed + _README_APPENDIX, encoding="utf-8", newline="\n")
    _commit(repository, FLAGSHIP.required_commit_message)


def _source_head(source: Path) -> str:
    return _command(["git", "rev-parse", "HEAD"], cwd=source).stdout.strip().lower()


@pytest.fixture(scope="module")
def flagship(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    """One complete synthetic flagship run through the real committed paths."""

    tmp = tmp_path_factory.mktemp("fl")
    source_parent = tmp / "source-parent"
    source_parent.mkdir()
    source = build_canary_repository(source_parent, repository_name="source").repository
    root = tmp / FLAGSHIP.run_id
    root.mkdir()
    fixture = build_incident_board_repository(root, repository_name="work")
    evidence = root / "evidence"
    evidence.mkdir()
    config, attestor = _injected_test_cursor(tmp)
    attestation = attestor(config)
    identity = _observe_built_fixture(fixture, FLAGSHIP)
    payload = build_profile_authorization_payload(
        source_repository=source,
        source_head=_source_head(source),
        attestation=attestation,
        run_root=root,
        profile=FLAGSHIP,
        initialized_workspace=identity,
    )
    _write_run_metadata_once(
        evidence / RUN_PREFLIGHT_METADATA_FILE_NAME,
        {
            "classification": CANARY_CLASSIFICATION,
            "authorization_payload": payload.to_dict(),
            "attestation": attestation.to_dict(),
            "local_capability_status": "PREFLIGHT_READY",
            "durability_capability": {"ready": True},
        },
    )
    store = AtomicNativeExecutionStore(evidence / "native-execution")
    session_store = AtomicDelegatedSessionStore(evidence / "delegated-state")
    session_store.create(create_canary_session(session_id=FLAGSHIP.session_id, profile=FLAGSHIP))
    runner = FakeNativeProcessRunner(mutation=_materialize_incident_replay)
    executor = NativeDelegatedExecutor(config=config, process_runner=runner, clock=Clock(), local_attestor=attestor)
    coordinator = NativeCanaryCoordinator(
        session_store=session_store, execution_store=store, executor=executor,
        backend_attestation=attestation, source_repository=source, work_workspace=fixture.repository,
        canary_parent=root, evidence_directory=evidence,
        timeout_seconds=FLAGSHIP.timeout_seconds, stdout_byte_limit=FLAGSHIP.stdout_byte_limit,
        stderr_byte_limit=FLAGSHIP.stderr_byte_limit, profile=FLAGSHIP,
    )
    outcome = coordinator.run(session_id=FLAGSHIP.session_id)
    return SimpleNamespace(
        root=root, source=source, work=fixture.repository, evidence=evidence,
        store=store, session_store=session_store, payload=payload,
        attestation=attestation, outcome=outcome, identity=identity,
    )


def _profile_variant(**changes) -> NativeMissionProfile:
    data = dict(FLAGSHIP.to_dict())
    data.update(changes)
    if "verifier_source" in changes:
        data["verifier_source_sha256"] = hashlib.sha256(changes["verifier_source"].encode("utf-8")).hexdigest()
    body = {key: value for key, value in data.items() if key != "profile_fingerprint"}
    data["profile_fingerprint"] = fingerprint(body)
    return NativeMissionProfile.from_dict(data)


# ---------------------------------------------------------------------------
# Profile canonicalization
# ---------------------------------------------------------------------------


def test_profile_fingerprint_is_non_self_referential_and_round_trips():
    data = FLAGSHIP.to_dict()
    assert NativeMissionProfile.from_dict(json.loads(json.dumps(data))) == FLAGSHIP
    body = {key: value for key, value in data.items() if key != "profile_fingerprint"}
    assert FLAGSHIP.profile_fingerprint == fingerprint(body)
    assert "profile_fingerprint" not in body
    tampered = dict(data)
    tampered["required_commit_message"] = "feat: something else"
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        NativeMissionProfile.from_dict(tampered)
    with pytest.raises(ValueError, match="keys"):
        NativeMissionProfile.from_dict({**data, "extra_key": 1})
    missing = dict(data)
    missing.pop("mission_text")
    with pytest.raises(ValueError, match="keys"):
        NativeMissionProfile.from_dict(missing)


def test_profile_rejects_out_of_range_and_contradictory_values():
    with pytest.raises(ValueError, match="timeout"):
        _profile_variant(timeout_seconds=3601)
    with pytest.raises(ValueError, match="stdout"):
        _profile_variant(stdout_byte_limit=16 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="unique"):
        _profile_variant(required_material_paths=["README.md", "README.md"])
    with pytest.raises(ValueError, match="digest"):
        data = dict(FLAGSHIP.to_dict())
        data["verifier_source_sha256"] = "0" * 64
        body = {key: value for key, value in data.items() if key != "profile_fingerprint"}
        data["profile_fingerprint"] = fingerprint(body)
        NativeMissionProfile.from_dict(data)
    with pytest.raises(ValueError, match="schema"):
        _profile_variant(schema_version="admissible_native_mission_profile_v0")
    with pytest.raises(ValueError, match="one-shot"):
        _profile_variant(budgets=[1, 1, 0, 0, 1])


def test_flagship_profile_matches_the_accepted_owner_contract():
    assert FLAGSHIP.profile_id == "incident-replay-v1"
    assert FLAGSHIP.run_id == FLAGSHIP.session_id == "native-cursor-longrun-001"
    assert FLAGSHIP.gate_id == "native-longrun-gate"
    assert (FLAGSHIP.fixture_id, FLAGSHIP.fixture_version) == ("local-incident-board", 1)
    assert FLAGSHIP.timeout_seconds == 3600
    assert (FLAGSHIP.stdout_byte_limit, FLAGSHIP.stderr_byte_limit) == (8_388_608, 1_048_576)
    assert FLAGSHIP.budgets == (1, 1, 0, 0, 0)
    assert FLAGSHIP.model == "auto"
    assert FLAGSHIP.required_commit_message == "feat: add deterministic incident replay"
    assert FLAGSHIP.required_material_paths == (
        "README.md", "index.html", "src/app.js", "src/domain/event-log.js",
        "src/storage/event-store.js", "src/ui/render.js", "test/event-replay.test.js",
    )
    (command,) = FLAGSHIP.checkpoint_commands
    assert (command.command_id, command.argv) == ("npm-test", ("npm.cmd", "test"))
    assert (command.timeout_seconds, command.max_capture_bytes) == (300, 1024 * 1024)
    assert (FLAGSHIP.verifier_timeout_seconds, FLAGSHIP.verifier_output_limit_bytes) == (60, 262144)
    assert "Stop only after" in FLAGSHIP.mission_text
    assert FLAGSHIP.fixture_initial_commit_message == INCIDENT_BOARD_INITIAL_COMMIT_MESSAGE


# ---------------------------------------------------------------------------
# Legacy byte-compatibility
# ---------------------------------------------------------------------------


def test_legacy_profile_reproduces_the_historical_canary_semantics():
    legacy = legacy_canary_profile()
    assert legacy.mission_text == nc.CANARY_MISSION
    assert legacy.gate_id == nc.CANARY_GATE_ID
    assert legacy.required_commit_message == nc.REQUIRED_COMMIT_MESSAGE
    assert frozenset(legacy.required_material_paths) == nc.EXPECTED_MATERIAL_PATHS
    assert legacy.verifier_source == nc._BEHAVIORAL_SCRIPT
    (command,) = legacy.checkpoint_commands
    assert (command.argv, command.timeout_seconds, command.max_capture_bytes) == (npm_test_argv(), 120, 256 * 1024)
    assert (legacy.timeout_seconds, legacy.stdout_byte_limit, legacy.stderr_byte_limit) == (
        DEFAULT_TIMEOUT_SECONDS, DEFAULT_STDOUT_BYTE_LIMIT, DEFAULT_STDERR_BYTE_LIMIT,
    )
    default_state = create_canary_session(session_id="probe-session")
    explicit_state = create_canary_session(session_id="probe-session", profile=legacy)
    assert default_state.mission.mission_fingerprint == _CANARY_MISSION_FINGERPRINT
    assert default_state.mission.mission_fingerprint == explicit_state.mission.mission_fingerprint
    assert default_state.current_gate.contract_fingerprint == explicit_state.current_gate.contract_fingerprint
    assert default_state.gate_plan.plan_fingerprint == explicit_state.gate_plan.plan_fingerprint


def test_legacy_prompt_remains_byte_identical(tmp_path: Path):
    workspace = tmp_path / "work"
    workspace.mkdir()
    state = create_canary_session(session_id="probe-session")
    prompt = build_native_agent_prompt(mission=state.mission, gate_contract=state.current_gate, work_workspace=workspace)
    clauses = "\n".join(f"- [{clause.clause_id}] {clause.text}" for clause in state.current_gate.clauses)
    expected = f"""{nc.NATIVE_PROMPT_HEADER}

Immutable mission:
{state.mission.specification}

Current gate objective:
{state.current_gate.objective}

Gate clauses:
{clauses}

Your exact assigned workspace is:
{workspace}

You have normal native autonomy only inside that assigned workspace: inspect the repository, edit files,
run shell commands, diagnose failures, use npm, run tests, and use Git locally as needed.

Required completion conditions:
- run the complete `npm test` suite;
- create exactly one intended local feature commit with complete message `{nc.REQUIRED_COMMIT_MESSAGE}`;
- use no `--trailer` when creating or amending the commit;
- add no commit-message body, `Co-authored-by`, sign-off, attribution, or other trailer;
- before stopping, run `git log -1 --format=%B` and verify that its complete output, after removing terminal newline characters only, is exactly `{nc.REQUIRED_COMMIT_MESSAGE}`;
- if the complete message is not exact, amend that same commit during this native invocation, do not create a second commit, and run the exact `%B` verification again;
- do not add or modify a Git remote;
- do not push;
- stop immediately only after the exact full-message verification passes.

Do not merely describe changes. Perform the work inside the assigned workspace.
"""
    assert prompt == expected


def test_flagship_prompt_carries_the_exact_completion_conditions(tmp_path: Path):
    workspace = tmp_path / "work"
    workspace.mkdir()
    state = create_canary_session(session_id=FLAGSHIP.session_id, profile=FLAGSHIP)
    prompt = build_native_agent_prompt(
        mission=state.mission, gate_contract=state.current_gate, work_workspace=workspace,
        required_commit_message=FLAGSHIP.required_commit_message,
        completion_conditions=FLAGSHIP.completion_conditions_text,
    )
    assert FLAGSHIP.completion_conditions_text in prompt
    assert FLAGSHIP.mission_text in prompt
    assert "`feat: add deterministic incident replay`" in prompt
    assert "do not continue with optional polish after the final commit" in prompt


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------


def test_registries_require_exact_hits():
    assert resolve_registered_profile("incident-replay-v1") == FLAGSHIP
    with pytest.raises(ValueError, match="unknown mission profile"):
        resolve_registered_profile("incident-replay-v2")
    assert resolve_fixture_builder("local-incident-board", 1) is build_incident_board_repository
    with pytest.raises(ValueError, match="unknown fixture builder"):
        resolve_fixture_builder("local-incident-board", 2)
    with pytest.raises(ValueError, match="unknown fixture builder"):
        resolve_fixture_builder("other-board", 1)


# ---------------------------------------------------------------------------
# Initial fixture smoke (real npm test, exactly once)
# ---------------------------------------------------------------------------


def test_incident_board_fixture_smoke(tmp_path: Path):
    fixture = build_incident_board_repository(tmp_path)
    repository = fixture.repository
    for relative in (
        "package.json", "index.html", "style.css", "src/app.js", "src/domain/incident.js",
        "src/domain/reducer.js", "src/storage/memory-storage.js", "src/storage/local-storage.js",
        "src/ui/controller.js", "src/ui/render.js", "test/incident.test.js", "test/board.test.js",
        "README.md", ".gitignore",
    ):
        assert (repository / relative).is_file(), relative
    for absent in (
        "src/domain/event-log.js", "src/storage/event-store.js", "test/event-replay.test.js",
    ):
        assert not (repository / absent).exists(), absent
    index_text = (repository / "index.html").read_text(encoding="utf-8")
    assert "createLocalStorageAdapter" in index_text
    assert "timeline" not in index_text.lower()
    readme_text = (repository / "README.md").read_text(encoding="utf-8")
    assert "intentionally absent" in readme_text or "not implemented" in readme_text.lower()
    assert fixture.initial_commit_message == INCIDENT_BOARD_INITIAL_COMMIT_MESSAGE
    assert _command(["git", "rev-list", "--count", "HEAD"], cwd=repository).stdout.strip() == "1"
    assert _command(["git", "remote"], cwd=repository).stdout.strip() == ""
    assert _command(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repository).stdout == ""
    completed = _command(list(npm_test_argv()), cwd=repository)
    assert completed.returncode == 0
    assert _command(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repository).stdout == ""
    again = tmp_path / "again"
    again.mkdir()
    rebuilt = build_incident_board_repository(again)
    assert (rebuilt.initial_head, rebuilt.initial_material_tree_hash) == (
        fixture.initial_head, fixture.initial_material_tree_hash,
    )


# ---------------------------------------------------------------------------
# v4 payload authority binding
# ---------------------------------------------------------------------------


def test_v4_payload_round_trips_and_requires_the_full_profile(flagship):
    payload = flagship.payload
    assert payload.schema_version == AUTHORIZATION_SCHEMA_VERSION_V4
    parsed = type(payload).from_dict(json.loads(json.dumps(payload.to_dict())))
    assert parsed == payload
    raw = payload.to_dict()
    raw["mission_profile"] = {
        "profile_id": FLAGSHIP.profile_id,
        "profile_fingerprint": FLAGSHIP.profile_fingerprint,
    }
    with pytest.raises(ValueError, match="keys"):
        type(payload).from_dict(raw)
    mismatched = payload.to_dict()
    mismatched["timeout_seconds"] = 900
    body = {key: value for key, value in mismatched.items() if key != "payload_fingerprint"}
    mismatched["payload_fingerprint"] = fingerprint(body)
    with pytest.raises(ValueError, match="contradicts the embedded mission profile"):
        type(payload).from_dict(mismatched)


def test_v4_substitution_changes_fingerprint_and_defeats_digest_reuse(flagship, monkeypatch):
    payload = flagship.payload
    phrase = "OWNER-AUTHORIZES-EXACTLY-THIS-PAYLOAD"
    digest = hashlib.sha256(phrase.encode("utf-8") + b"\0" + canonical_bytes(payload.to_dict())).hexdigest()
    monkeypatch.setenv(nc.OWNER_AUTHORIZATION_DIGEST_ENV, digest)
    assert _authorized(phrase, payload, active_source_repository=flagship.source)
    variants = {
        "mission text": _profile_variant(mission_text=FLAGSHIP.mission_text + "\nEXTRA."),
        "commit message": _profile_variant(required_commit_message="feat: add different replay"),
        "material path": _profile_variant(required_material_paths=[
            "README.md", "index.html", "src/app.js", "src/domain/event-log.js",
            "src/storage/event-store.js", "src/ui/render.js", "test/replay.test.js",
        ]),
        "verifier source": _profile_variant(verifier_source=FLAGSHIP.verifier_source + "\n// changed\n"),
        "timeout": _profile_variant(timeout_seconds=1800),
        "stdout limit": _profile_variant(stdout_byte_limit=4_194_304),
        "stderr limit": _profile_variant(stderr_byte_limit=524_288),
        "checkpoint command": _profile_variant(checkpoint_commands=[{
            "command_id": "npm-test", "argv": ["npm.cmd", "test"],
            "timeout_seconds": 240, "max_capture_bytes": 1024 * 1024,
        }]),
        "stop clause": _profile_variant(
            completion_conditions_text=FLAGSHIP.completion_conditions_text.replace(
                "- do not continue with optional polish after the final commit;\n", ""
            )
        ),
        "fixture version": _profile_variant(fixture_version=2),
    }
    for label, variant_profile in variants.items():
        variant_payload = build_profile_authorization_payload(
            source_repository=flagship.source,
            source_head=_source_head(flagship.source),
            attestation=flagship.attestation,
            run_root=flagship.root,
            profile=variant_profile,
            initialized_workspace=flagship.identity,
        )
        assert variant_payload.payload_fingerprint != payload.payload_fingerprint, label
        assert not _authorized(phrase, variant_payload, active_source_repository=flagship.source), label


def test_observed_fixture_identity_contradiction_blocks(tmp_path: Path):
    fixture = build_incident_board_repository(tmp_path)
    with pytest.raises(NativeEvidenceInvalid, match="initial commit message is not exact"):
        _observe_built_fixture(fixture, _profile_variant(fixture_initial_commit_message="chore: different fixture"))
    with pytest.raises(NativeEvidenceInvalid, match="contradict the independent observation"):
        _observe_built_fixture(
            SimpleNamespace(
                repository=fixture.repository,
                initial_head="0" * 40,
                initial_material_tree_hash=fixture.initial_material_tree_hash,
            ),
            FLAGSHIP,
        )


# ---------------------------------------------------------------------------
# CLI authority binding
# ---------------------------------------------------------------------------

_CLI_BASE = [
    "--source-repository", "unused-source", "--required-source-head", "0" * 40,
    "--run-root", "unused-root", "--run-id", "native-cursor-longrun-001",
    "--session-id", "native-cursor-longrun-001", "--executable", "unused-executable",
]


def _cli_blocked_detail(capsys) -> str:
    printed = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert printed["status"] == NativeCanaryStatus.PREFLIGHT_BLOCKED.value
    return printed["detail"]


def test_cli_unknown_profile_blocks_before_any_probe(capsys):
    assert main([*_CLI_BASE, "--profile-id", "no-such-profile"]) == 2
    assert "unknown mission profile" in _cli_blocked_detail(capsys)


def test_cli_profile_value_mismatch_blocks_before_any_probe(capsys):
    assert main([*_CLI_BASE, "--profile-id", "incident-replay-v1", "--timeout-seconds", "900"]) == 2
    assert "--timeout-seconds contradicts the selected profile" in _cli_blocked_detail(capsys)
    assert main([*_CLI_BASE, "--profile-id", "incident-replay-v1", "--stdout-byte-limit", "1024"]) == 2
    assert "--stdout-byte-limit contradicts the selected profile" in _cli_blocked_detail(capsys)
    assert main([*_CLI_BASE, "--profile-id", "incident-replay-v1", "--model", "gpt-x"]) == 2
    assert "--model contradicts the selected profile" in _cli_blocked_detail(capsys)
    mismatched_run = list(_CLI_BASE)
    mismatched_run[mismatched_run.index("native-cursor-longrun-001")] = "native-cursor-longrun-002"
    assert main([*mismatched_run, "--profile-id", "incident-replay-v1"]) == 2
    assert "profile authority" in _cli_blocked_detail(capsys)


def test_cli_profile_repeating_exact_values_reaches_source_preflight(capsys):
    assert main([
        *_CLI_BASE, "--profile-id", "incident-replay-v1", "--timeout-seconds", "3600",
        "--stdout-byte-limit", "8388608", "--stderr-byte-limit", "1048576", "--model", "auto",
    ]) == 2
    assert "source repository" in _cli_blocked_detail(capsys)


def test_cli_legacy_invocation_keeps_exact_historical_defaults(capsys):
    assert main([*_CLI_BASE, "--stdout-byte-limit", "999"]) == 2
    assert "exact historical default" in _cli_blocked_detail(capsys)
    assert main([*_CLI_BASE, "--timeout-seconds", "9999"]) == 2
    assert "timeout must be from 1 through 3600 seconds" in _cli_blocked_detail(capsys)
    assert main(_CLI_BASE) == 2
    assert "source repository" in _cli_blocked_detail(capsys)


# ---------------------------------------------------------------------------
# Synthetic full success path
# ---------------------------------------------------------------------------


def test_synthetic_flagship_run_reaches_checkpoint_captured_success(flagship):
    outcome = flagship.outcome
    assert outcome.canary_success
    assert outcome.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS
    assert (
        outcome.native_attempts_reserved, outcome.native_processes_started,
        outcome.native_processes_completed, outcome.process_observations_published,
        outcome.accepted_native_results_published,
    ) == (1, 1, 1, 1, 1)
    state = flagship.session_store.load(FLAGSHIP.session_id)
    assert state.phase is Phase.CHECKPOINT_CAPTURED
    assert state.current_gate.gate_id == FLAGSHIP.gate_id


def test_synthetic_run_persisted_truth_matches_the_profile(flagship):
    result = flagship.store.load_result(FLAGSHIP.session_id, FLAGSHIP.gate_id, 0)
    assert result.final_commit_message == FLAGSHIP.required_commit_message
    assert result.commits_added == 1
    assert result.final_git_porcelain_status == ""
    assert result.final_git_remotes == ()
    assert frozenset(FLAGSHIP.required_material_paths).issubset(set(result.changed_material_files))
    behavioral = flagship.store.load_behavioral_evidence(
        FLAGSHIP.session_id, FLAGSHIP.gate_id, 0,
        loader=nc.BehavioralVerifierEvidence.from_dict,
    )
    assert behavioral.exit_code == 0 and not behavioral.timed_out
    script = (flagship.store.directory / behavioral.script.relative_path).read_bytes()
    assert script == FLAGSHIP.verifier_source.encode("utf-8")
    state = flagship.session_store.load(FLAGSHIP.session_id)
    checkpoint = state.checkpoint_history[-1]
    commands = [record for record in checkpoint.evidence_records if getattr(record, "command_id", None)]
    assert [command.command_id for command in commands] == ["npm-test"]
    assert commands[0].exit_code == 0 and not commands[0].timed_out and not commands[0].output_truncated
    request = json.loads(
        (flagship.store._path("request", FLAGSHIP.session_id, FLAGSHIP.gate_id, 0)).read_text(encoding="utf-8")
    )
    assert request["timeout_seconds"] == 3600
    assert request["stdout_byte_limit"] == 8_388_608
    assert request["stderr_byte_limit"] == 1_048_576


def test_reconstruction_uses_the_persisted_profile_not_the_registry(flagship):
    def _trap(*_args, **_kwargs):
        raise AssertionError("reconstruction consulted the source registry")

    with mock.patch.object(nc, "registered_profiles", _trap), mock.patch.object(nc, "legacy_canary_profile", _trap):
        outcome = reconstruct_completed_canary_success(
            session_store=flagship.session_store, execution_store=flagship.store,
            evidence_directory=flagship.evidence, session_id=FLAGSHIP.session_id,
        )
    assert outcome.status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS
    assert outcome.canary_success


def test_reconstruction_fails_closed_on_a_tampered_persisted_profile(flagship):
    metadata_path = flagship.evidence / RUN_PREFLIGHT_METADATA_FILE_NAME
    original = metadata_path.read_bytes()
    try:
        parsed = json.loads(original.decode("utf-8"))
        profile_data = parsed["authorization_payload"]["mission_profile"]
        profile_data["required_commit_message"] = "feat: something the owner never authorized"
        metadata_path.write_bytes(json.dumps(parsed).encode("utf-8"))
        with pytest.raises(NativeEvidenceInvalid, match="persisted v4 authorization payload is invalid"):
            reconstruct_completed_canary_success(
                session_store=flagship.session_store, execution_store=flagship.store,
                evidence_directory=flagship.evidence, session_id=FLAGSHIP.session_id,
            )
        body = {key: value for key, value in profile_data.items() if key != "profile_fingerprint"}
        profile_data["profile_fingerprint"] = fingerprint(body)
        payload_data = parsed["authorization_payload"]
        payload_data["required_commit_message"] = profile_data["required_commit_message"]
        payload_body = {key: value for key, value in payload_data.items() if key != "payload_fingerprint"}
        payload_data["payload_fingerprint"] = fingerprint(payload_body)
        metadata_path.write_bytes(json.dumps(parsed).encode("utf-8"))
        with pytest.raises(NativeEvidenceInvalid, match="no longer satisfies eligibility"):
            reconstruct_completed_canary_success(
                session_store=flagship.session_store, execution_store=flagship.store,
                evidence_directory=flagship.evidence, session_id=FLAGSHIP.session_id,
            )
    finally:
        metadata_path.write_bytes(original)
    outcome = reconstruct_completed_canary_success(
        session_store=flagship.session_store, execution_store=flagship.store,
        evidence_directory=flagship.evidence, session_id=FLAGSHIP.session_id,
    )
    assert outcome.canary_success


def test_reconstruction_rejects_both_v4_contract_substitution_attacks(flagship):
    metadata_path = flagship.evidence / RUN_PREFLIGHT_METADATA_FILE_NAME
    original = metadata_path.read_bytes()

    def _substituted_metadata() -> dict:
        parsed = json.loads(original.decode("utf-8"))
        payload_data = parsed["authorization_payload"]
        profile_data = payload_data["mission_profile"]
        profile_data["mission_text"] += "\nPost-run substituted mission interpretation."
        profile_data["completion_conditions_text"] += "\n- accept the substituted interpretation;"
        profile_body = {key: value for key, value in profile_data.items() if key != "profile_fingerprint"}
        profile_data["profile_fingerprint"] = fingerprint(profile_body)
        substituted_profile = NativeMissionProfile.from_dict(profile_data)
        derived = create_canary_session(session_id=substituted_profile.session_id, profile=substituted_profile)
        payload_data["mission_fingerprint"] = derived.mission.mission_fingerprint
        payload_data["gate_plan_fingerprint"] = derived.gate_plan.plan_fingerprint
        payload_data["gate_contract_fingerprint"] = derived.current_gate.contract_fingerprint
        return parsed

    def _reconstruct():
        def _trap(*_args, **_kwargs):
            raise AssertionError("reconstruction consulted the source registry or historical adapter")

        with mock.patch.object(nc, "registered_profiles", _trap), mock.patch.object(nc, "legacy_canary_profile", _trap):
            return reconstruct_completed_canary_success(
                session_store=flagship.session_store, execution_store=flagship.store,
                evidence_directory=flagship.evidence, session_id=FLAGSHIP.session_id,
            )

    assert _reconstruct().status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS

    try:
        stale_outer = _substituted_metadata()
        stale_payload = stale_outer["authorization_payload"]
        stale_body = {key: value for key, value in stale_payload.items() if key != "payload_fingerprint"}
        assert stale_payload["payload_fingerprint"] != fingerprint(stale_body)
        metadata_path.write_bytes(canonical_bytes(stale_outer) + b"\n")
        with pytest.raises(NativeEvidenceInvalid, match="authorization payload fingerprint mismatch"):
            _reconstruct()
    finally:
        metadata_path.write_bytes(original)

    try:
        refingerprinted = _substituted_metadata()
        payload_data = refingerprinted["authorization_payload"]
        payload_body = {key: value for key, value in payload_data.items() if key != "payload_fingerprint"}
        payload_data["payload_fingerprint"] = fingerprint(payload_body)
        assert type(flagship.payload).from_dict(payload_data).mission_profile.mission_text.endswith(
            "Post-run substituted mission interpretation."
        )
        metadata_path.write_bytes(canonical_bytes(refingerprinted) + b"\n")
        with pytest.raises(NativeEvidenceInvalid, match="profile-derived mission fingerprint"):
            _reconstruct()
    finally:
        metadata_path.write_bytes(original)

    assert _reconstruct().status is NativeCanaryStatus.CHECKPOINT_CAPTURED_CANARY_SUCCESS
