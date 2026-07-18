"""Trusted local-incident-board fixture builder (Gate L1C).

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


__all__ = [
    "INCIDENT_BOARD_FIXTURE_ID",
    "INCIDENT_BOARD_FIXTURE_VERSION",
    "INCIDENT_BOARD_INITIAL_COMMIT_MESSAGE",
    "BuiltFixture",
    "build_incident_board_repository",
    "fixture_material_tree_hash",
]
