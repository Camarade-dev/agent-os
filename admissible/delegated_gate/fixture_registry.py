"""Trusted deterministic native-mission fixture builders (Gate L1C).

This module is executable source-code trust, not serialized profile data: the
profile binds only ``(fixture_id, fixture_version)`` plus the independently
observed initialized-workspace identity, and the registry in
:mod:`native_canary` maps that exact pair to a builder defined here.

The fixture is a self-contained, dependency-free, fully offline local-first
incident-response board: domain, storage, controller, and rendering modules, a
browser UI over the provided localStorage adapter, initial passing Node tests,
and README documentation.  The deterministic event-replay capability the
flagship mission must add is deliberately absent.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

from admissible.delegated_gate.native_executor import _safe_directory


INCIDENT_BOARD_FIXTURE_ID = "local-incident-board"
INCIDENT_BOARD_FIXTURE_VERSION = 1
INCIDENT_BOARD_INITIAL_COMMIT_MESSAGE = "chore: initialize incident board fixture"
WORKFLOW_CONSOLE_FIXTURE_ID = "local-workflow-console"
WORKFLOW_CONSOLE_FIXTURE_VERSION = 1
WORKFLOW_CONSOLE_INITIAL_COMMIT_MESSAGE = "chore: initialize workflow console fixture"
NEON_SIEGE_FIXTURE_ID = "local-neon-siege"
NEON_SIEGE_FIXTURE_VERSION = 1
NEON_SIEGE_INITIAL_COMMIT_MESSAGE = "chore: initialize neon siege blank fixture"


@dataclass(frozen=True)
class BuiltFixture:
    """One freshly built fixture repository with its observed initial facts."""

    repository: Path
    initial_head: str
    initial_material_tree_hash: str
    initial_commit_message: str


def _run(argv: list[str], *, cwd: Path, env: dict[str, str] | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv, cwd=cwd, env=env, shell=False, check=False, capture_output=True,
        text=True, encoding="utf-8", errors="replace", timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"fixture command failed ({argv!r}): {result.stderr.strip()}")
    return result


def fixture_material_tree_hash(repository: str | Path) -> str:
    """Deterministic content hash over the fixture material (``.git`` excluded)."""

    root, _ = _safe_directory(repository, "fixture repository")
    digest = hashlib.sha256()
    entries: list[tuple[str, bytes]] = []
    for path in root.rglob("*"):
        if ".git" in path.relative_to(root).parts or not path.is_file():
            continue
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("fixture material cannot contain symlinks")
        entries.append((path.relative_to(root).as_posix(), path.read_bytes()))
    for relative, data in sorted(entries):
        digest.update(
            relative.encode("utf-8") + b"\0"
            + hashlib.sha256(data).hexdigest().encode("ascii") + b"\0"
            + str(len(data)).encode("ascii") + b"\n"
        )
    return digest.hexdigest()


_PACKAGE_JSON = {
    "name": "admissible-longrun-incident-board",
    "version": "1.0.0",
    "private": True,
    "type": "module",
    "scripts": {"test": "node --preserve-symlinks --preserve-symlinks-main --test"},
}


def _incident_board_files() -> dict[str, bytes]:
    package = (json.dumps(_PACKAGE_JSON, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return {
        "package.json": package,
        ".gitignore": b"node_modules/\n.cache/\n",
        "src/domain/incident.js": b"""export const SEVERITIES = Object.freeze(['low', 'medium', 'high', 'critical']);
export const STATUSES = Object.freeze(['open', 'acknowledged', 'resolved']);

export function createIncident({ id, title, severity }) {
  if (typeof id !== 'string' || !id) throw new TypeError('incident id must be a non-empty string');
  if (typeof title !== 'string' || !title.trim()) throw new TypeError('incident title must be non-empty text');
  if (!SEVERITIES.includes(severity)) throw new TypeError('incident severity is not a known severity');
  return { id, title, severity, status: 'open', notes: [] };
}

export function withStatus(incident, status) {
  if (!STATUSES.includes(status)) throw new TypeError('incident status is not a known status');
  return { ...incident, notes: [...incident.notes], status };
}

export function withSeverity(incident, severity) {
  if (!SEVERITIES.includes(severity)) throw new TypeError('incident severity is not a known severity');
  return { ...incident, notes: [...incident.notes], severity };
}

export function withNote(incident, note) {
  if (typeof note !== 'string' || !note.trim()) throw new TypeError('incident note must be non-empty text');
  return { ...incident, notes: [...incident.notes, note] };
}
""",
        "src/domain/reducer.js": b"""import { createIncident, withStatus, withSeverity, withNote } from './incident.js';

export function initialBoard() {
  return { incidents: [] };
}

function requireIndex(board, id) {
  const index = board.incidents.findIndex((incident) => incident.id === id);
  if (index < 0) throw new Error(`unknown incident: ${id}`);
  return index;
}

export function applyCreate(board, { id, title, severity }) {
  if (board.incidents.some((incident) => incident.id === id)) throw new Error(`duplicate incident: ${id}`);
  return { incidents: [...board.incidents, createIncident({ id, title, severity })] };
}

export function applyStatus(board, { id, status }) {
  const index = requireIndex(board, id);
  const incidents = board.incidents.slice();
  incidents[index] = withStatus(incidents[index], status);
  return { incidents };
}

export function applySeverity(board, { id, severity }) {
  const index = requireIndex(board, id);
  const incidents = board.incidents.slice();
  incidents[index] = withSeverity(incidents[index], severity);
  return { incidents };
}

export function applyNote(board, { id, note }) {
  const index = requireIndex(board, id);
  const incidents = board.incidents.slice();
  incidents[index] = withNote(incidents[index], note);
  return { incidents };
}
""",
        "src/storage/memory-storage.js": b"""export function createMemoryStorage(seed = {}) {
  const values = new Map(Object.entries(seed));
  return {
    getItem(key) { return values.has(key) ? values.get(key) : null; },
    setItem(key, value) { values.set(String(key), String(value)); },
    snapshot() { return Object.fromEntries([...values.entries()].sort()); },
  };
}
""",
        "src/storage/local-storage.js": b"""export function createLocalStorageAdapter(windowLike = globalThis) {
  const backing = windowLike.localStorage;
  if (!backing) throw new TypeError('window.localStorage is unavailable');
  return {
    getItem(key) {
      const value = backing.getItem(String(key));
      return value === null ? null : String(value);
    },
    setItem(key, value) { backing.setItem(String(key), String(value)); },
  };
}
""",
        "src/ui/controller.js": b"""import { initialBoard, applyCreate, applyStatus, applySeverity, applyNote } from '../domain/reducer.js';

const STATE_KEY = 'incident-board/state';

function restore(storage) {
  const raw = storage.getItem(STATE_KEY);
  if (raw === null) return initialBoard();
  const parsed = JSON.parse(raw);
  if (typeof parsed !== 'object' || parsed === null || !Array.isArray(parsed.incidents)) {
    throw new TypeError('stored board state is malformed');
  }
  return parsed;
}

export function createController(storage) {
  let board = restore(storage);
  const persist = () => storage.setItem(STATE_KEY, JSON.stringify(board));
  return {
    board() { return board; },
    createIncident(details) { board = applyCreate(board, details); persist(); return board; },
    updateStatus(id, status) { board = applyStatus(board, { id, status }); persist(); return board; },
    updateSeverity(id, severity) { board = applySeverity(board, { id, severity }); persist(); return board; },
    addNote(id, note) { board = applyNote(board, { id, note }); persist(); return board; },
  };
}
""",
        "src/ui/render.js": b"""const REPLACEMENTS = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

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
""",
        "src/app.js": b"""import { createController } from './ui/controller.js';
import { renderBoard } from './ui/render.js';

export function createApp(storage) {
  const controller = createController(storage);
  return { controller, render: () => renderBoard(controller.board()) };
}
""",
        "index.html": b"""<!DOCTYPE html>
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
<script type="module">
import { createApp } from './src/app.js';
import { createLocalStorageAdapter } from './src/storage/local-storage.js';

const app = createApp(createLocalStorageAdapter());
const board = document.getElementById('board');
const draw = () => { board.innerHTML = app.render(); };
document.getElementById('create-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const data = new FormData(event.target);
  app.controller.createIncident({
    id: String(data.get('id')),
    title: String(data.get('title')),
    severity: String(data.get('severity')),
  });
  event.target.reset();
  draw();
});
draw();
</script>
</body>
</html>
""",
        "style.css": b"""body { font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 46rem; padding: 0 1rem; }
form { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
.incident { border: 1px solid #ccd; border-radius: 6px; padding: 0.75rem 1rem; margin: 0.75rem 0; }
.incident h2 { margin: 0 0 0.25rem; font-size: 1.05rem; }
.meta { color: #667; font-size: 0.85rem; margin: 0; }
.notes { margin: 0.5rem 0 0; padding-left: 1.2rem; font-size: 0.9rem; }
.severity-critical { border-left: 4px solid #b33; }
.severity-high { border-left: 4px solid #d80; }
.status-resolved { opacity: 0.6; }
.empty { color: #667; }
""",
        "test/incident.test.js": b"""import test from 'node:test';
import assert from 'node:assert/strict';
import { createIncident, withStatus, withSeverity, withNote } from '../src/domain/incident.js';

test('incident creation validates its fields', () => {
  const incident = createIncident({ id: 'inc-1', title: 'Checkout latency', severity: 'high' });
  assert.deepEqual(incident, { id: 'inc-1', title: 'Checkout latency', severity: 'high', status: 'open', notes: [] });
  assert.throws(() => createIncident({ id: '', title: 'x', severity: 'high' }), TypeError);
  assert.throws(() => createIncident({ id: 'inc-2', title: '  ', severity: 'high' }), TypeError);
  assert.throws(() => createIncident({ id: 'inc-2', title: 'x', severity: 'urgent' }), TypeError);
});

test('incident transitions are pure and validated', () => {
  const incident = createIncident({ id: 'inc-1', title: 'Checkout latency', severity: 'high' });
  const acknowledged = withStatus(incident, 'acknowledged');
  const critical = withSeverity(acknowledged, 'critical');
  const noted = withNote(critical, 'rollback started');
  assert.equal(incident.status, 'open');
  assert.equal(acknowledged.status, 'acknowledged');
  assert.equal(critical.severity, 'critical');
  assert.deepEqual(noted.notes, ['rollback started']);
  assert.deepEqual(critical.notes, []);
  assert.throws(() => withStatus(incident, 'closed'), TypeError);
  assert.throws(() => withNote(incident, '   '), TypeError);
});
""",
        "test/board.test.js": b"""import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { createMemoryStorage } from '../src/storage/memory-storage.js';

test('board mutations flow through the controller', () => {
  const app = createApp(createMemoryStorage());
  app.controller.createIncident({ id: 'inc-1', title: 'Checkout latency', severity: 'high' });
  app.controller.updateStatus('inc-1', 'acknowledged');
  app.controller.updateSeverity('inc-1', 'critical');
  app.controller.addNote('inc-1', 'rollback started');
  const [incident] = app.controller.board().incidents;
  assert.equal(incident.status, 'acknowledged');
  assert.equal(incident.severity, 'critical');
  assert.deepEqual(incident.notes, ['rollback started']);
  assert.match(app.render(), /Checkout latency/);
});

test('a fresh controller over the same storage restores prior incidents', () => {
  const storage = createMemoryStorage();
  const first = createApp(storage);
  first.controller.createIncident({ id: 'inc-1', title: 'Checkout latency', severity: 'high' });
  first.controller.addNote('inc-1', 'rollback started');
  const second = createApp(storage);
  assert.deepEqual(second.controller.board(), first.controller.board());
});

test('unknown incidents and duplicate identities are rejected', () => {
  const app = createApp(createMemoryStorage());
  app.controller.createIncident({ id: 'inc-1', title: 'Checkout latency', severity: 'high' });
  assert.throws(() => app.controller.createIncident({ id: 'inc-1', title: 'again', severity: 'low' }));
  assert.throws(() => app.controller.updateStatus('missing', 'resolved'));
  assert.throws(() => app.controller.addNote('missing', 'note'));
});
""",
        "README.md": """# Local incident board

A self-contained, dependency-free, fully offline local-first incident-response
board. The browser UI (`index.html`) persists through the provided
`localStorage` adapter; tests inject the deterministic in-memory adapter.

Run the complete deterministic suite with `npm test`.

## Current capabilities

- incident creation with validated severity (`low`, `medium`, `high`, `critical`);
- status updates (`open`, `acknowledged`, `resolved`);
- note addition;
- injected storage (`src/storage/memory-storage.js`, `src/storage/local-storage.js`);
- pure HTML-string rendering (`src/ui/render.js`) testable under Node.

## Deliberately not implemented yet: deterministic incident replay

Event replay is intentionally absent. The planned design, when implemented,
follows this project's conventions:

- `src/domain/event-log.js` — versioned events (`{ id, version, type, payload }`,
  version `1`, types `incident-created`, `status-changed`, `severity-changed`,
  `note-added`) with `createEvent`, `validateEvent`, `appendEvent(events, event)`
  (append-only, duplicate-ID rejecting) and `replayEvents(events, upTo)`
  reconstructing board state deterministically from an empty board.
- `src/storage/event-store.js` — `createEventStore(storage)` persisting the
  append-only log through the injected storage adapter with `events()`,
  `append(event)`, `exportLog()` and all-or-nothing validated `importLog(text)`.
- `src/app.js` controller extensions — `eventCount()`, `timeline()`,
  `replayAt(position)` (read-only historical state), `exportLog()`,
  `importLog(text)`.
- a visible event timeline with manual replay controls in the browser UI that
  never mutate the authoritative persisted log.
""".encode("utf-8"),
    }


def build_incident_board_repository(temporary_root: str | Path, *, repository_name: str = "work") -> BuiltFixture:
    """Create one deterministic, dependency-free incident-board Git fixture."""

    parent, _ = _safe_directory(temporary_root, "fixture temporary root")
    if not repository_name or any(char in repository_name for char in "\\/\x00") or repository_name in {".", ".."}:
        raise ValueError("repository name must be one safe component")
    repository = parent / repository_name
    if repository.exists():
        raise ValueError("fixture repository path must be fresh")
    repository.mkdir()
    _safe_directory(repository, "fixture repository")
    for relative, content in _incident_board_files().items():
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    _run(["git", "init", "--quiet", "--initial-branch=main"], cwd=repository)
    _run(["git", "config", "core.autocrlf", "false"], cwd=repository)
    _run(["git", "config", "core.filemode", "false"], cwd=repository)
    _run(["git", "config", "commit.gpgsign", "false"], cwd=repository)
    _run(["git", "add", "--all"], cwd=repository)
    git_env = dict(os.environ)
    git_env.update({
        "GIT_AUTHOR_NAME": "Admissible Fixture", "GIT_AUTHOR_EMAIL": "fixture@invalid.example",
        "GIT_COMMITTER_NAME": "Admissible Fixture", "GIT_COMMITTER_EMAIL": "fixture@invalid.example",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    })
    _run(["git", "commit", "--quiet", "-m", INCIDENT_BOARD_INITIAL_COMMIT_MESSAGE], cwd=repository, env=git_env)
    head = _run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip().lower()
    if _run(["git", "remote"], cwd=repository).stdout.strip():
        raise RuntimeError("fixture unexpectedly has a remote")
    if _run(["git", "rev-list", "--count", "HEAD"], cwd=repository).stdout.strip() != "1":
        raise RuntimeError("fixture must have exactly one commit")
    message = _run(["git", "log", "-1", "--format=%B"], cwd=repository).stdout.rstrip("\r\n")
    if message != INCIDENT_BOARD_INITIAL_COMMIT_MESSAGE:
        raise RuntimeError("fixture initial commit message is not exact")
    if _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repository).stdout:
        raise RuntimeError("fixture initial worktree is not clean")
    return BuiltFixture(repository, head, fixture_material_tree_hash(repository), message)


_WORKFLOW_CONSOLE_PACKAGE_JSON = {
    "name": "admissible-flagship-workflow-console",
    "version": "1.0.0",
    "private": True,
    "type": "module",
    "scripts": {"test": "node --preserve-symlinks --preserve-symlinks-main --test"},
}


def _workflow_console_files() -> dict[str, bytes]:
    """The exact offline workflow-definition fixture material.

    This starting application deliberately stops at definition management.  It
    contains useful domain, storage, controller, rendering, and test seams but
    no scheduler, recovery engine, or hidden mission implementation.
    """

    package = (json.dumps(_WORKFLOW_CONSOLE_PACKAGE_JSON, indent=2, sort_keys=True) + "\n").encode("utf-8")
    sample_workflows = {
        "schemaVersion": 1,
        "workflows": [
            {
                "id": "release-checklist",
                "name": "Release checklist",
                "description": "Prepare an offline release candidate.",
                "tasks": [
                    {
                        "id": "package",
                        "title": "Package artifacts",
                        "description": "Create the candidate bundle.",
                        "dependsOn": [],
                        "maxAttempts": 2,
                        "backoffMs": 1000,
                    },
                    {
                        "id": "document",
                        "title": "Document candidate",
                        "description": "Write operator notes.",
                        "dependsOn": ["package"],
                        "maxAttempts": 1,
                        "backoffMs": 0,
                    },
                ],
            }
        ],
    }
    legacy_state = {
        "schemaVersion": 0,
        "runs": [
            {
                "runId": "legacy-run-001",
                "workflowId": "legacy-release",
                "status": "in_progress",
                "startedAt": 1700000000000,
                "tasks": [
                    {
                        "taskId": "prepare",
                        "status": "completed",
                        "attempts": 1,
                        "startedAt": 1700000000000,
                        "finishedAt": 1700000000100,
                        "result": {"artifact": "prepared.json"},
                    },
                    {
                        "taskId": "publish",
                        "status": "running",
                        "attempts": 2,
                        "startedAt": 1700000000200,
                    },
                    {
                        "taskId": "notify",
                        "status": "pending",
                        "attempts": 0,
                        "startedAt": None,
                    },
                ],
            }
        ],
    }
    return {
        ".gitignore": b"node_modules/\n.cache/\ncoverage/\n",
        "package.json": package,
        "src/domain/task.js": b"""function requireText(value, label) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new TypeError(`${label} must be non-empty text`);
  }
  return value.trim();
}

function requireNonNegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a non-negative integer`);
  }
  return value;
}

function normalizedDependencies(value) {
  if (!Array.isArray(value)) throw new TypeError('task dependsOn must be an array');
  const dependencies = value.map((entry) => requireText(entry, 'dependency id'));
  if (new Set(dependencies).size !== dependencies.length) {
    throw new TypeError('task dependency ids must be unique');
  }
  return [...dependencies].sort((left, right) => left.localeCompare(right));
}

export function createTask({
  id,
  title,
  description = '',
  dependsOn = [],
  maxAttempts = 1,
  backoffMs = 0,
}) {
  const taskId = requireText(id, 'task id');
  const taskTitle = requireText(title, 'task title');
  if (typeof description !== 'string') throw new TypeError('task description must be text');
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) {
    throw new TypeError('task maxAttempts must be a positive integer');
  }
  return Object.freeze({
    id: taskId,
    title: taskTitle,
    description: description.trim(),
    dependsOn: Object.freeze(normalizedDependencies(dependsOn)),
    maxAttempts,
    backoffMs: requireNonNegativeInteger(backoffMs, 'task backoffMs'),
  });
}

export function updateTaskMetadata(task, changes = {}) {
  if (typeof changes !== 'object' || changes === null || Array.isArray(changes)) {
    throw new TypeError('task changes must be an object');
  }
  return createTask({ ...task, ...changes, id: task.id });
}
""",
        "src/domain/workflow.js": b"""import { createTask, updateTaskMetadata } from './task.js';

function requireText(value, label) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new TypeError(`${label} must be non-empty text`);
  }
  return value.trim();
}

function cloneTasks(tasks) {
  if (!Array.isArray(tasks)) throw new TypeError('workflow tasks must be an array');
  const normalized = tasks.map((task) => createTask(task));
  const ids = normalized.map((task) => task.id);
  if (new Set(ids).size !== ids.length) throw new TypeError('workflow task ids must be unique');
  return normalized;
}

export function createWorkflow({ id, name, description = '', tasks = [] }) {
  if (typeof description !== 'string') throw new TypeError('workflow description must be text');
  return Object.freeze({
    id: requireText(id, 'workflow id'),
    name: requireText(name, 'workflow name'),
    description: description.trim(),
    tasks: Object.freeze(cloneTasks(tasks)),
  });
}

export function addWorkflowTask(workflow, taskInput) {
  const task = createTask(taskInput);
  if (workflow.tasks.some((candidate) => candidate.id === task.id)) {
    throw new Error(`task already exists: ${task.id}`);
  }
  return createWorkflow({ ...workflow, tasks: [...workflow.tasks, task] });
}

export function replaceWorkflowTask(workflow, taskId, changes) {
  const index = workflow.tasks.findIndex((task) => task.id === taskId);
  if (index < 0) throw new Error(`unknown task: ${taskId}`);
  const tasks = workflow.tasks.map((task, position) => (
    position === index ? updateTaskMetadata(task, changes) : task
  ));
  return createWorkflow({ ...workflow, tasks });
}

export function removeWorkflowTask(workflow, taskId) {
  if (!workflow.tasks.some((task) => task.id === taskId)) {
    throw new Error(`unknown task: ${taskId}`);
  }
  const referenced = workflow.tasks.filter((task) => task.dependsOn.includes(taskId));
  if (referenced.length) throw new Error(`task is referenced by: ${referenced.map((task) => task.id).join(', ')}`);
  return createWorkflow({ ...workflow, tasks: workflow.tasks.filter((task) => task.id !== taskId) });
}
""",
        "src/domain/configuration.js": b"""import { createWorkflow } from './workflow.js';

export const CONFIGURATION_SCHEMA_VERSION = 1;

export function emptyConfiguration() {
  return Object.freeze({ schemaVersion: CONFIGURATION_SCHEMA_VERSION, workflows: Object.freeze([]) });
}

export function validateConfiguration(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('configuration must be an object');
  }
  if (value.schemaVersion !== CONFIGURATION_SCHEMA_VERSION) {
    throw new TypeError('unsupported configuration schema version');
  }
  if (!Array.isArray(value.workflows)) throw new TypeError('configuration workflows must be an array');
  const workflows = value.workflows.map((workflow) => createWorkflow(workflow));
  const ids = workflows.map((workflow) => workflow.id);
  if (new Set(ids).size !== ids.length) throw new TypeError('workflow ids must be unique');
  return Object.freeze({
    schemaVersion: CONFIGURATION_SCHEMA_VERSION,
    workflows: Object.freeze(workflows),
  });
}

export function withWorkflow(configuration, workflow) {
  const next = createWorkflow(workflow);
  if (configuration.workflows.some((candidate) => candidate.id === next.id)) {
    throw new Error(`workflow already exists: ${next.id}`);
  }
  return validateConfiguration({
    schemaVersion: CONFIGURATION_SCHEMA_VERSION,
    workflows: [...configuration.workflows, next],
  });
}

export function replaceWorkflow(configuration, workflow) {
  const index = configuration.workflows.findIndex((candidate) => candidate.id === workflow.id);
  if (index < 0) throw new Error(`unknown workflow: ${workflow.id}`);
  return validateConfiguration({
    schemaVersion: CONFIGURATION_SCHEMA_VERSION,
    workflows: configuration.workflows.map((candidate, position) => (
      position === index ? workflow : candidate
    )),
  });
}
""",
        "src/serialization/config-export.js": b"""import { validateConfiguration } from '../domain/configuration.js';

function canonicalTask(task) {
  return {
    backoffMs: task.backoffMs,
    dependsOn: [...task.dependsOn].sort((left, right) => left.localeCompare(right)),
    description: task.description,
    id: task.id,
    maxAttempts: task.maxAttempts,
    title: task.title,
  };
}

function canonicalWorkflow(workflow) {
  return {
    description: workflow.description,
    id: workflow.id,
    name: workflow.name,
    tasks: [...workflow.tasks]
      .sort((left, right) => left.id.localeCompare(right.id))
      .map(canonicalTask),
  };
}

export function exportConfiguration(configuration) {
  const validated = validateConfiguration(configuration);
  const canonical = {
    schemaVersion: validated.schemaVersion,
    workflows: [...validated.workflows]
      .sort((left, right) => left.id.localeCompare(right.id))
      .map(canonicalWorkflow),
  };
  return `${JSON.stringify(canonical, null, 2)}\n`;
}
""",
        "src/storage/memory-storage.js": b"""export function createMemoryStorage(initial = {}) {
  if (typeof initial !== 'object' || initial === null || Array.isArray(initial)) {
    throw new TypeError('initial storage must be an object');
  }
  const values = new Map(Object.entries(initial).map(([key, value]) => [String(key), String(value)]));
  return {
    getItem(key) {
      const normalized = String(key);
      return values.has(normalized) ? values.get(normalized) : null;
    },
    setItem(key, value) {
      values.set(String(key), String(value));
    },
    removeItem(key) {
      values.delete(String(key));
    },
    clear() {
      values.clear();
    },
    dump() {
      return Object.fromEntries([...values.entries()].sort(([left], [right]) => left.localeCompare(right)));
    },
  };
}
""",
        "src/storage/local-storage.js": b"""export function createLocalStorageAdapter(storage = globalThis.localStorage) {
  if (!storage || typeof storage.getItem !== 'function' || typeof storage.setItem !== 'function') {
    throw new TypeError('browser storage adapter requires localStorage-compatible methods');
  }
  return {
    getItem(key) { return storage.getItem(key); },
    setItem(key, value) { storage.setItem(key, value); },
    removeItem(key) { storage.removeItem(key); },
  };
}
""",
        "src/storage/config-store.js": b"""import { emptyConfiguration, validateConfiguration } from '../domain/configuration.js';
import { exportConfiguration } from '../serialization/config-export.js';

export const CONFIGURATION_STORAGE_KEY = 'workflow-console/configuration';

function parseConfiguration(text) {
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new TypeError(`stored configuration is not valid JSON: ${error.message}`);
  }
  return validateConfiguration(parsed);
}

export function createConfigurationStore(storage) {
  if (!storage || typeof storage.getItem !== 'function' || typeof storage.setItem !== 'function') {
    throw new TypeError('configuration store requires an injected storage adapter');
  }
  return {
    load() {
      const raw = storage.getItem(CONFIGURATION_STORAGE_KEY);
      return raw === null ? emptyConfiguration() : parseConfiguration(raw);
    },
    save(configuration) {
      const validated = validateConfiguration(configuration);
      storage.setItem(CONFIGURATION_STORAGE_KEY, exportConfiguration(validated));
      return validated;
    },
    export(configuration) {
      return exportConfiguration(validateConfiguration(configuration));
    },
  };
}
""",
        "src/ui/controller.js": b"""import { replaceWorkflowTask, addWorkflowTask, removeWorkflowTask } from '../domain/workflow.js';
import { replaceWorkflow, withWorkflow } from '../domain/configuration.js';
import { createConfigurationStore } from '../storage/config-store.js';

export function createController(storage) {
  const store = createConfigurationStore(storage);
  let configuration = store.load();

  function persist(next) {
    configuration = store.save(next);
    return configuration;
  }

  function requireWorkflow(workflowId) {
    const value = configuration.workflows.find((workflow) => workflow.id === workflowId);
    if (!value) throw new Error(`unknown workflow: ${workflowId}`);
    return value;
  }

  return {
    createWorkflow(input) {
      persist(withWorkflow(configuration, input));
      return requireWorkflow(input.id);
    },
    addTask(workflowId, input) {
      const workflow = addWorkflowTask(requireWorkflow(workflowId), input);
      persist(replaceWorkflow(configuration, workflow));
      return workflow.tasks.find((task) => task.id === input.id);
    },
    updateTask(workflowId, taskId, changes) {
      const workflow = replaceWorkflowTask(requireWorkflow(workflowId), taskId, changes);
      persist(replaceWorkflow(configuration, workflow));
      return workflow.tasks.find((task) => task.id === taskId);
    },
    removeTask(workflowId, taskId) {
      const workflow = removeWorkflowTask(requireWorkflow(workflowId), taskId);
      persist(replaceWorkflow(configuration, workflow));
      return workflow;
    },
    workflows() {
      return configuration.workflows;
    },
    workflow(workflowId) {
      return requireWorkflow(workflowId);
    },
    configuration() {
      return configuration;
    },
    exportConfiguration() {
      return store.export(configuration);
    },
  };
}
""",
        "src/ui/render.js": b"""const ESCAPES = Object.freeze({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
});

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ESCAPES[character]);
}

export function renderTask(task) {
  const dependencies = task.dependsOn.length
    ? task.dependsOn.map((id) => `<code>${escapeHtml(id)}</code>`).join(', ')
    : '<span class="muted">none</span>';
  return `<li class="task" data-task-id="${escapeHtml(task.id)}">`
    + `<div><strong>${escapeHtml(task.title)}</strong> <code>${escapeHtml(task.id)}</code></div>`
    + `<p>${escapeHtml(task.description || 'No description')}</p>`
    + `<p class="task-meta">Dependencies: ${dependencies}</p>`
    + `<p class="task-meta">Attempts: ${task.maxAttempts}; base backoff: ${task.backoffMs} ms</p>`
    + `</li>`;
}

export function renderWorkflow(workflow) {
  const tasks = workflow.tasks.length
    ? workflow.tasks.map(renderTask).join('')
    : '<li class="empty">No tasks defined.</li>';
  return `<article class="workflow" data-workflow-id="${escapeHtml(workflow.id)}">`
    + `<header><h2>${escapeHtml(workflow.name)}</h2><code>${escapeHtml(workflow.id)}</code></header>`
    + `<p>${escapeHtml(workflow.description || 'No description')}</p>`
    + `<ul class="task-list">${tasks}</ul>`
    + `</article>`;
}

export function renderConsole(workflows) {
  if (!Array.isArray(workflows)) throw new TypeError('workflows must be an array');
  if (!workflows.length) {
    return '<section class="empty-state"><h2>No workflows</h2><p>Create a workflow to begin defining local operations.</p></section>';
  }
  return workflows.map(renderWorkflow).join('');
}
""",
        "src/ui/forms.js": b"""function text(form, name) {
  const value = String(new FormData(form).get(name) ?? '').trim();
  if (!value) throw new TypeError(`${name} is required`);
  return value;
}

export function workflowInput(form) {
  return {
    id: text(form, 'id'),
    name: text(form, 'name'),
    description: String(new FormData(form).get('description') ?? '').trim(),
  };
}

export function taskInput(form) {
  const data = new FormData(form);
  const dependencyText = String(data.get('dependsOn') ?? '').trim();
  return {
    id: text(form, 'id'),
    title: text(form, 'title'),
    description: String(data.get('description') ?? '').trim(),
    dependsOn: dependencyText ? dependencyText.split(',').map((value) => value.trim()).filter(Boolean) : [],
    maxAttempts: Number(data.get('maxAttempts') ?? 1),
    backoffMs: Number(data.get('backoffMs') ?? 0),
  };
}
""",
        "src/app.js": b"""import { createController } from './ui/controller.js';
import { renderConsole } from './ui/render.js';

export function createApp(storage, options = {}) {
  if (typeof options !== 'object' || options === null || Array.isArray(options)) {
    throw new TypeError('application options must be an object');
  }
  const controller = createController(storage);
  return {
    controller,
    render() {
      return renderConsole(controller.workflows());
    },
  };
}
""",
        "index.html": b"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Local workflow console</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <header class="page-header">
    <div>
      <p class="eyebrow">Local operations</p>
      <h1>Workflow console</h1>
      <p>Define repeatable work and keep its configuration in this browser.</p>
    </div>
    <button id="export-button" type="button">Export configuration</button>
  </header>

  <main>
    <section class="editor-panel">
      <h2>Create workflow</h2>
      <form id="workflow-form">
        <label>Workflow ID <input name="id" required></label>
        <label>Name <input name="name" required></label>
        <label>Description <textarea name="description"></textarea></label>
        <button type="submit">Create workflow</button>
      </form>

      <h2>Add task</h2>
      <form id="task-form">
        <label>Workflow
          <select name="workflowId" id="workflow-select" required></select>
        </label>
        <label>Task ID <input name="id" required></label>
        <label>Title <input name="title" required></label>
        <label>Description <textarea name="description"></textarea></label>
        <label>Dependency IDs <input name="dependsOn" placeholder="prepare, verify"></label>
        <label>Maximum attempts <input name="maxAttempts" type="number" min="1" value="1"></label>
        <label>Base backoff (ms) <input name="backoffMs" type="number" min="0" value="0"></label>
        <button type="submit">Add task</button>
      </form>
      <output id="message" aria-live="polite"></output>
    </section>

    <section class="workspace-panel">
      <div id="workflow-list"></div>
      <h2>Configuration export</h2>
      <pre id="configuration-export"></pre>
    </section>
  </main>

  <script type="module">
    import { createApp } from './src/app.js';
    import { createLocalStorageAdapter } from './src/storage/local-storage.js';
    import { workflowInput, taskInput } from './src/ui/forms.js';

    const app = createApp(createLocalStorageAdapter());
    const list = document.getElementById('workflow-list');
    const selector = document.getElementById('workflow-select');
    const exported = document.getElementById('configuration-export');
    const message = document.getElementById('message');

    function draw() {
      list.innerHTML = app.render();
      selector.innerHTML = app.controller.workflows()
        .map((workflow) => `<option value="${workflow.id}">${workflow.name}</option>`)
        .join('');
      exported.textContent = app.controller.exportConfiguration();
    }

    function report(action) {
      try {
        action();
        message.textContent = '';
        draw();
      } catch (error) {
        message.textContent = error instanceof Error ? error.message : String(error);
      }
    }

    document.getElementById('workflow-form').addEventListener('submit', (event) => {
      event.preventDefault();
      report(() => app.controller.createWorkflow(workflowInput(event.currentTarget)));
      if (!message.textContent) event.currentTarget.reset();
    });

    document.getElementById('task-form').addEventListener('submit', (event) => {
      event.preventDefault();
      const data = new FormData(event.currentTarget);
      report(() => app.controller.addTask(String(data.get('workflowId')), taskInput(event.currentTarget)));
      if (!message.textContent) event.currentTarget.reset();
    });

    document.getElementById('export-button').addEventListener('click', () => {
      exported.hidden = !exported.hidden;
    });

    draw();
  </script>
</body>
</html>
""",
        "style.css": b""":root {
  color-scheme: dark;
  font-family: Inter, ui-sans-serif, system-ui, sans-serif;
  background: #0b1020;
  color: #e8edf8;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  min-height: 100vh;
  background: radial-gradient(circle at top left, #172554, #0b1020 45%);
}

button, input, textarea, select { font: inherit; }

button {
  border: 0;
  border-radius: 0.55rem;
  padding: 0.7rem 1rem;
  background: #38bdf8;
  color: #082f49;
  font-weight: 700;
  cursor: pointer;
}

.page-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 2rem;
  padding: 2rem clamp(1rem, 5vw, 4rem);
  border-bottom: 1px solid #26314f;
}

.page-header h1 { margin: 0; font-size: clamp(2rem, 5vw, 3.6rem); }
.page-header p { color: #a9b5d0; }
.eyebrow { text-transform: uppercase; letter-spacing: 0.16em; font-size: 0.75rem; }

main {
  display: grid;
  grid-template-columns: minmax(18rem, 25rem) 1fr;
  gap: 1.5rem;
  padding: 1.5rem clamp(1rem, 5vw, 4rem) 4rem;
}

.editor-panel, .workspace-panel {
  border: 1px solid #26314f;
  border-radius: 1rem;
  padding: 1.25rem;
  background: rgba(15, 23, 42, 0.92);
}

form { display: grid; gap: 0.75rem; margin-bottom: 2rem; }
label { display: grid; gap: 0.35rem; color: #cbd5e1; }

input, textarea, select {
  width: 100%;
  border: 1px solid #3a4968;
  border-radius: 0.45rem;
  padding: 0.65rem;
  background: #10182c;
  color: #f8fafc;
}

.workflow {
  border: 1px solid #334155;
  border-radius: 0.75rem;
  padding: 1rem;
  margin-bottom: 1rem;
}

.workflow header { display: flex; align-items: baseline; justify-content: space-between; gap: 1rem; }
.workflow h2 { margin: 0; }
.task-list { display: grid; gap: 0.7rem; padding: 0; list-style: none; }
.task { border-left: 3px solid #38bdf8; padding: 0.7rem 0.9rem; background: #111c33; }
.task p { margin: 0.4rem 0 0; }
.task-meta, .muted { color: #94a3b8; }
.empty-state { padding: 3rem; text-align: center; color: #94a3b8; }
pre { overflow: auto; padding: 1rem; background: #080d19; border-radius: 0.6rem; }
output { min-height: 1.5rem; color: #fda4af; }

@media (max-width: 800px) {
  main { grid-template-columns: 1fr; }
  .page-header { align-items: flex-start; flex-direction: column; }
}
""",
        "README.md": b"""# Local workflow console

This dependency-free browser application manages workflow definitions for local
operators. It stores configuration through an injected key/value adapter and
can export the same logical configuration deterministically.

## Use

Open `index.html` in a modern browser. Create a workflow, then add tasks and
edit task metadata through the controller API. The browser adapter uses
`localStorage`; tests use the memory adapter.

Run the complete offline test suite with:

```text
npm test
```

No install step is required. The project has no third-party dependencies and
does not access the network.

## Existing public behavior

`createApp(storage, options = {})` returns an application with a controller and
a Node-testable HTML renderer. The controller supports:

- `createWorkflow(input)`
- `addTask(workflowId, input)`
- `updateTask(workflowId, taskId, changes)`
- `workflows()`
- `workflow(workflowId)`
- `exportConfiguration()`

Tasks retain dependency IDs as configuration metadata. They also retain a
positive maximum-attempt value and a non-negative base-backoff value. These
values describe operator intent only; this starting application does not act
on them.

Configuration is stored under `workflow-console/configuration`. Export orders
workflows, tasks and dependency IDs consistently, so equivalent definitions
produce identical text.

## Historical compatibility input

`test/fixtures/legacy-run-state-v0.json` is an inert product-compatibility
sample. The current application does not load, display, import or act on it.
A future extension must interpret its historical status values as follows:

- `completed` becomes `succeeded` while retaining the recorded result;
- `running` becomes recoverable queued work with an interrupted prior attempt;
- `pending` becomes `queued`.

Unsupported newer versions and invalid historical data must be rejected before
replacing previously valid stored data. This README states observable product
requirements only; it intentionally supplies no implementation design.

## Project layout

- `src/domain/` validates immutable workflow and task definitions.
- `src/storage/` contains injected configuration adapters.
- `src/serialization/` creates deterministic configuration text.
- `src/ui/` contains the controller, forms and HTML rendering.
- `test/` verifies the existing definition console.
""",
        "test/fixtures/sample-workflows.json": (json.dumps(sample_workflows, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        "test/fixtures/legacy-run-state-v0.json": (json.dumps(legacy_state, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        "test/workflow-definition.test.js": b"""import test from 'node:test';
import assert from 'node:assert/strict';
import { createTask, updateTaskMetadata } from '../src/domain/task.js';
import { createWorkflow, addWorkflowTask, replaceWorkflowTask, removeWorkflowTask } from '../src/domain/workflow.js';

test('task metadata is normalized and immutable', () => {
  const task = createTask({
    id: ' verify ',
    title: ' Verify package ',
    description: '  inspect output  ',
    dependsOn: ['package', 'archive'],
    maxAttempts: 3,
    backoffMs: 250,
  });
  assert.deepEqual(task, {
    id: 'verify',
    title: 'Verify package',
    description: 'inspect output',
    dependsOn: ['archive', 'package'],
    maxAttempts: 3,
    backoffMs: 250,
  });
  assert.ok(Object.isFrozen(task));
  assert.ok(Object.isFrozen(task.dependsOn));
});

test('task metadata rejects malformed values', () => {
  assert.throws(() => createTask({ id: '', title: 'Title' }), /task id/);
  assert.throws(() => createTask({ id: 'a', title: '', maxAttempts: 1 }), /task title/);
  assert.throws(() => createTask({ id: 'a', title: 'A', maxAttempts: 0 }), /maxAttempts/);
  assert.throws(() => createTask({ id: 'a', title: 'A', backoffMs: -1 }), /backoffMs/);
  assert.throws(() => createTask({ id: 'a', title: 'A', dependsOn: ['b', 'b'] }), /unique/);
});

test('updating metadata preserves task identity', () => {
  const original = createTask({ id: 'a', title: 'Original' });
  const updated = updateTaskMetadata(original, { id: 'different', title: 'Updated', maxAttempts: 2 });
  assert.equal(updated.id, 'a');
  assert.equal(updated.title, 'Updated');
  assert.equal(updated.maxAttempts, 2);
});

test('workflow task editing is immutable', () => {
  const original = createWorkflow({ id: 'release', name: 'Release' });
  const added = addWorkflowTask(original, { id: 'package', title: 'Package' });
  const edited = replaceWorkflowTask(added, 'package', { description: 'Create bundle' });
  assert.equal(original.tasks.length, 0);
  assert.equal(added.tasks[0].description, '');
  assert.equal(edited.tasks[0].description, 'Create bundle');
});

test('workflow task ids are unique and removals respect references', () => {
  const workflow = createWorkflow({
    id: 'release',
    name: 'Release',
    tasks: [
      { id: 'prepare', title: 'Prepare' },
      { id: 'verify', title: 'Verify', dependsOn: ['prepare'] },
    ],
  });
  assert.throws(() => addWorkflowTask(workflow, { id: 'prepare', title: 'Again' }), /already exists/);
  assert.throws(() => removeWorkflowTask(workflow, 'prepare'), /referenced/);
  assert.equal(removeWorkflowTask(workflow, 'verify').tasks.length, 1);
});
""",
        "test/config-store.test.js": b"""import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createMemoryStorage } from '../src/storage/memory-storage.js';
import { createConfigurationStore, CONFIGURATION_STORAGE_KEY } from '../src/storage/config-store.js';
import { validateConfiguration } from '../src/domain/configuration.js';
import { exportConfiguration } from '../src/serialization/config-export.js';

const sampleUrl = new URL('./fixtures/sample-workflows.json', import.meta.url);

async function sample() {
  return JSON.parse(await readFile(sampleUrl, 'utf8'));
}

test('empty storage returns an empty current configuration', () => {
  const store = createConfigurationStore(createMemoryStorage());
  assert.deepEqual(store.load(), { schemaVersion: 1, workflows: [] });
});

test('saved configuration restores through a fresh store', async () => {
  const storage = createMemoryStorage();
  const first = createConfigurationStore(storage);
  first.save(await sample());
  const second = createConfigurationStore(storage);
  assert.equal(exportConfiguration(second.load()), exportConfiguration(validateConfiguration(await sample())));
});

test('configuration export is deterministic across insertion order', () => {
  const left = validateConfiguration({
    schemaVersion: 1,
    workflows: [
      { id: 'z', name: 'Zulu', tasks: [{ id: 'b', title: 'B' }, { id: 'a', title: 'A' }] },
      { id: 'a', name: 'Alpha', tasks: [] },
    ],
  });
  const right = validateConfiguration({
    schemaVersion: 1,
    workflows: [
      { id: 'a', name: 'Alpha', tasks: [] },
      { id: 'z', name: 'Zulu', tasks: [{ id: 'a', title: 'A' }, { id: 'b', title: 'B' }] },
    ],
  });
  assert.equal(exportConfiguration(left), exportConfiguration(right));
});

test('invalid stored JSON fails closed without changing storage', () => {
  const storage = createMemoryStorage({ [CONFIGURATION_STORAGE_KEY]: '{broken' });
  const before = storage.dump();
  assert.throws(() => createConfigurationStore(storage).load(), /not valid JSON/);
  assert.deepEqual(storage.dump(), before);
});

test('legacy compatibility sample remains inert fixture data', async () => {
  const legacy = JSON.parse(await readFile(new URL('./fixtures/legacy-run-state-v0.json', import.meta.url), 'utf8'));
  assert.equal(legacy.schemaVersion, 0);
  assert.deepEqual(legacy.runs[0].tasks.map((task) => task.status), ['completed', 'running', 'pending']);
  assert.equal(createMemoryStorage().getItem(CONFIGURATION_STORAGE_KEY), null);
});
""",
        "test/controller.test.js": b"""import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';
import { createMemoryStorage } from '../src/storage/memory-storage.js';

test('controller creates workflows and tasks and restores them', () => {
  const storage = createMemoryStorage();
  const app = createApp(storage);
  app.controller.createWorkflow({ id: 'release', name: 'Release', description: 'Ship safely' });
  app.controller.addTask('release', { id: 'prepare', title: 'Prepare', maxAttempts: 2, backoffMs: 50 });
  app.controller.addTask('release', { id: 'verify', title: 'Verify', dependsOn: ['prepare'] });
  const restored = createApp(storage);
  assert.equal(restored.controller.workflow('release').tasks.length, 2);
  assert.deepEqual(restored.controller.workflow('release').tasks[1].dependsOn, ['prepare']);
});

test('controller edits task metadata without changing identity', () => {
  const app = createApp(createMemoryStorage());
  app.controller.createWorkflow({ id: 'release', name: 'Release' });
  app.controller.addTask('release', { id: 'prepare', title: 'Prepare' });
  const edited = app.controller.updateTask('release', 'prepare', {
    id: 'ignored',
    title: 'Prepare candidate',
    maxAttempts: 4,
    backoffMs: 125,
  });
  assert.equal(edited.id, 'prepare');
  assert.equal(edited.title, 'Prepare candidate');
  assert.equal(edited.maxAttempts, 4);
});

test('controller exposes deterministic configuration text', () => {
  const app = createApp(createMemoryStorage());
  app.controller.createWorkflow({ id: 'z', name: 'Zulu' });
  app.controller.createWorkflow({ id: 'a', name: 'Alpha' });
  const parsed = JSON.parse(app.controller.exportConfiguration());
  assert.deepEqual(parsed.workflows.map((workflow) => workflow.id), ['a', 'z']);
});

test('unknown workflow and task operations reject without mutation', () => {
  const app = createApp(createMemoryStorage());
  app.controller.createWorkflow({ id: 'known', name: 'Known' });
  const before = app.controller.exportConfiguration();
  assert.throws(() => app.controller.addTask('missing', { id: 'a', title: 'A' }), /unknown workflow/);
  assert.throws(() => app.controller.updateTask('known', 'missing', { title: 'No' }), /unknown task/);
  assert.equal(app.controller.exportConfiguration(), before);
});
""",
        "test/render.test.js": b"""import test from 'node:test';
import assert from 'node:assert/strict';
import { renderConsole, renderTask, renderWorkflow } from '../src/ui/render.js';
import { createTask } from '../src/domain/task.js';
import { createWorkflow } from '../src/domain/workflow.js';

test('empty console has a useful browser message', () => {
  assert.match(renderConsole([]), /No workflows/);
});

test('task rendering escapes operator-provided text', () => {
  const html = renderTask(createTask({
    id: 'task-1',
    title: '<script>alert(1)</script>',
    description: 'A & B',
    dependsOn: ['safe-id'],
    maxAttempts: 2,
    backoffMs: 25,
  }));
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
  assert.match(html, /A &amp; B/);
  assert.match(html, /Attempts: 2/);
});

test('workflow rendering includes task metadata', () => {
  const workflow = createWorkflow({
    id: 'release',
    name: 'Release workflow',
    description: 'Local release',
    tasks: [{ id: 'prepare', title: 'Prepare', dependsOn: [], maxAttempts: 3, backoffMs: 100 }],
  });
  const html = renderWorkflow(workflow);
  assert.match(html, /Release workflow/);
  assert.match(html, /prepare/);
  assert.match(html, /base backoff: 100 ms/);
});

test('console renders multiple workflows as testable HTML', () => {
  const html = renderConsole([
    createWorkflow({ id: 'a', name: 'Alpha' }),
    createWorkflow({ id: 'b', name: 'Beta' }),
  ]);
  assert.match(html, /data-workflow-id="a"/);
  assert.match(html, /data-workflow-id="b"/);
});
""",
    }


def build_workflow_console_repository(
    temporary_root: str | Path, *, repository_name: str = "work"
) -> BuiltFixture:
    """Create the deterministic, dependency-free workflow-console fixture."""

    parent, _ = _safe_directory(temporary_root, "fixture temporary root")
    if not repository_name or any(char in repository_name for char in "\\/\x00") or repository_name in {".", ".."}:
        raise ValueError("repository name must be one safe component")
    repository = parent / repository_name
    if repository.exists():
        raise ValueError("fixture repository path must be fresh")
    repository.mkdir()
    _safe_directory(repository, "fixture repository")
    files = _workflow_console_files()
    if len(files) != 22:
        raise RuntimeError("workflow-console fixture must contain exactly 22 material files")
    for relative, content in files.items():
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    _run(["git", "init", "--quiet", "--initial-branch=main"], cwd=repository)
    _run(["git", "config", "core.autocrlf", "false"], cwd=repository)
    _run(["git", "config", "core.filemode", "false"], cwd=repository)
    _run(["git", "config", "commit.gpgsign", "false"], cwd=repository)
    _run(["git", "add", "--all"], cwd=repository)
    git_env = dict(os.environ)
    git_env.update({
        "GIT_AUTHOR_NAME": "Admissible Fixture", "GIT_AUTHOR_EMAIL": "fixture@invalid.example",
        "GIT_COMMITTER_NAME": "Admissible Fixture", "GIT_COMMITTER_EMAIL": "fixture@invalid.example",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    })
    _run(["git", "commit", "--quiet", "-m", WORKFLOW_CONSOLE_INITIAL_COMMIT_MESSAGE], cwd=repository, env=git_env)
    head = _run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip().lower()
    if _run(["git", "remote"], cwd=repository).stdout.strip():
        raise RuntimeError("fixture unexpectedly has a remote")
    if _run(["git", "rev-list", "--count", "HEAD"], cwd=repository).stdout.strip() != "1":
        raise RuntimeError("fixture must have exactly one commit")
    message = _run(["git", "log", "-1", "--format=%B"], cwd=repository).stdout.rstrip("\r\n")
    if message != WORKFLOW_CONSOLE_INITIAL_COMMIT_MESSAGE:
        raise RuntimeError("fixture initial commit message is not exact")
    if _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repository).stdout:
        raise RuntimeError("fixture initial worktree is not clean")
    return BuiltFixture(repository, head, fixture_material_tree_hash(repository), message)


_NEON_SIEGE_PACKAGE_JSON = {
    "name": "neon-siege-blank-fixture",
    "version": "0.0.0",
    "private": True,
    "type": "module",
    "scripts": {
        "test": "node --preserve-symlinks --preserve-symlinks-main --test",
        "start": "node -e \"console.error('blank fixture: implement a local static start server'); process.exit(1)\"",
    },
}


def _neon_siege_blank_files() -> dict[str, bytes]:
    """Neutral blank-repository scaffolding with no gameplay or visuals."""

    package = (json.dumps(_NEON_SIEGE_PACKAGE_JSON, indent=2, sort_keys=True) + "\n").encode("utf-8")
    readme = (
        "# Neon Siege blank fixture\n"
        "\n"
        "This repository is the deterministic Admissible blank fixture for the\n"
        "Neon Siege native comparison experiment (`local-neon-siege` @ v1).\n"
        "\n"
        "It intentionally contains no gameplay, rendering, audio, upgrade,\n"
        "enemy, wave, HUD, or persistence implementation. The coding agent must\n"
        "build the complete static browser game from this empty scaffold.\n"
        "\n"
        "Fixture marker: `NEON_SIEGE_BLANK_FIXTURE_V1`\n"
    ).encode("utf-8")
    gitignore = b"node_modules/\n.cache/\n.DS_Store\n"
    identity_test = (
        "import assert from 'node:assert/strict';\n"
        "import { readFileSync } from 'node:fs';\n"
        "import { describe, it } from 'node:test';\n"
        "\n"
        "describe('neon-siege blank fixture identity', () => {\n"
        "  it('retains the blank fixture marker and no game implementation', () => {\n"
        "    const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');\n"
        "    assert.match(readme, /NEON_SIEGE_BLANK_FIXTURE_V1/);\n"
        "    assert.match(readme, /no gameplay/i);\n"
        "  });\n"
        "});\n"
    ).encode("utf-8")
    return {
        "README.md": readme,
        "package.json": package,
        ".gitignore": gitignore,
        "test/fixture-identity.test.js": identity_test,
    }


def build_neon_siege_blank_repository(
    temporary_root: str | Path, *, repository_name: str = "work"
) -> BuiltFixture:
    """Create the deterministic blank Neon Siege fixture (no game features)."""

    parent, _ = _safe_directory(temporary_root, "fixture temporary root")
    if not repository_name or any(char in repository_name for char in "\\/\x00") or repository_name in {".", ".."}:
        raise ValueError("repository name must be one safe component")
    repository = parent / repository_name
    if repository.exists():
        raise ValueError("fixture repository path must be fresh")
    repository.mkdir()
    _safe_directory(repository, "fixture repository")
    files = _neon_siege_blank_files()
    if len(files) != 4:
        raise RuntimeError("neon-siege blank fixture must contain exactly 4 material files")
    for relative, content in files.items():
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    _run(["git", "init", "--quiet", "--initial-branch=main"], cwd=repository)
    _run(["git", "config", "core.autocrlf", "false"], cwd=repository)
    _run(["git", "config", "core.filemode", "false"], cwd=repository)
    _run(["git", "config", "commit.gpgsign", "false"], cwd=repository)
    _run(["git", "add", "--all"], cwd=repository)
    git_env = dict(os.environ)
    git_env.update({
        "GIT_AUTHOR_NAME": "Admissible Fixture", "GIT_AUTHOR_EMAIL": "fixture@invalid.example",
        "GIT_COMMITTER_NAME": "Admissible Fixture", "GIT_COMMITTER_EMAIL": "fixture@invalid.example",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    })
    _run(["git", "commit", "--quiet", "-m", NEON_SIEGE_INITIAL_COMMIT_MESSAGE], cwd=repository, env=git_env)
    head = _run(["git", "rev-parse", "HEAD"], cwd=repository).stdout.strip().lower()
    if _run(["git", "remote"], cwd=repository).stdout.strip():
        raise RuntimeError("fixture unexpectedly has a remote")
    if _run(["git", "rev-list", "--count", "HEAD"], cwd=repository).stdout.strip() != "1":
        raise RuntimeError("fixture must have exactly one commit")
    message = _run(["git", "log", "-1", "--format=%B"], cwd=repository).stdout.rstrip("\r\n")
    if message != NEON_SIEGE_INITIAL_COMMIT_MESSAGE:
        raise RuntimeError("fixture initial commit message is not exact")
    if _run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repository).stdout:
        raise RuntimeError("fixture initial worktree is not clean")
    return BuiltFixture(repository, head, fixture_material_tree_hash(repository), message)


__all__ = [
    "INCIDENT_BOARD_FIXTURE_ID",
    "INCIDENT_BOARD_FIXTURE_VERSION",
    "INCIDENT_BOARD_INITIAL_COMMIT_MESSAGE",
    "NEON_SIEGE_FIXTURE_ID",
    "NEON_SIEGE_FIXTURE_VERSION",
    "NEON_SIEGE_INITIAL_COMMIT_MESSAGE",
    "WORKFLOW_CONSOLE_FIXTURE_ID",
    "WORKFLOW_CONSOLE_FIXTURE_VERSION",
    "WORKFLOW_CONSOLE_INITIAL_COMMIT_MESSAGE",
    "BuiltFixture",
    "build_incident_board_repository",
    "build_neon_siege_blank_repository",
    "build_workflow_console_repository",
    "fixture_material_tree_hash",
]
