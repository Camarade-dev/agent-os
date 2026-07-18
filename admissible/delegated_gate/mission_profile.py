"""Canonical, data-only native mission profiles (Gate L1C).

A :class:`NativeMissionProfile` is the single serializable authority for one
owner-defined native mission: mission text, gate contract inputs, checkpoint
command definitions, the complete behavioral-verifier source, required Git
facts, and every execution/output budget.  It is canonical data only — no
callable, class object, closure, filesystem handle, or environment-selected
behavior can be represented — and it is bound by one non-self-referential
fingerprint: ``profile_fingerprint`` is the SHA-256 of the canonical JSON
bytes of the complete validated profile body, computed with the fingerprint
field excluded from its own input.

Trusted executable mappings (``fixture_id`` -> builder, ``profile_id`` ->
profile) live in source-code registries in :mod:`native_canary`; this module
holds only the values those registries serve.  The complete validated profile
of a new run is persisted inside its v4 authorization payload, so evidence-only
reconstruction never consults a registry after execution.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any, Mapping

from admissible.delegated_gate.canonical import (
    fingerprint,
    require_exact_keys,
    require_identifier,
    require_nonempty_text,
    require_safe_relative_path,
    require_sha256,
    require_strict_int,
    require_string_list,
)
from admissible.delegated_gate.models import EvidenceKind, VerificationCommand


MISSION_PROFILE_SCHEMA_VERSION = "admissible_native_mission_profile_v1"
# The one authorized one-shot budget shape:
# (provider invocations, native attempts, repair rounds, auditors, retries).
ONE_SHOT_PROFILE_BUDGETS: tuple[int, int, int, int, int] = (1, 1, 0, 0, 0)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ProfileCheckpointCommand:
    """One canonical checkpoint verification-command definition."""

    command_id: str
    argv: tuple[str, ...]
    timeout_seconds: int
    max_capture_bytes: int

    def validated(self) -> "ProfileCheckpointCommand":
        # VerificationCommand owns the protocol bounds (<=300 s, <=1 MiB);
        # constructing it applies them without duplicating the limits here.
        self.to_verification_command()
        return self

    def to_verification_command(self) -> VerificationCommand:
        if not isinstance(self.argv, tuple):
            raise ValueError("checkpoint command argv must be an ordered tuple")
        return VerificationCommand(
            command_id=self.command_id,
            argv=self.argv,
            timeout_seconds=self.timeout_seconds,
            max_capture_bytes=self.max_capture_bytes,
        ).validated()

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
            "max_capture_bytes": self.max_capture_bytes,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProfileCheckpointCommand":
        require_exact_keys(
            data,
            {"command_id", "argv", "timeout_seconds", "max_capture_bytes"},
            "profile checkpoint command",
        )
        return cls(
            command_id=data["command_id"],
            argv=require_string_list(data["argv"], "profile checkpoint argv"),
            timeout_seconds=data["timeout_seconds"],
            max_capture_bytes=data["max_capture_bytes"],
        ).validated()


@dataclass(frozen=True)
class NativeMissionProfile:
    """One immutable, canonically fingerprinted native mission definition."""

    schema_version: str
    profile_id: str
    fixture_id: str
    fixture_version: int
    run_id: str
    session_id: str
    gate_id: str
    mission_id: str
    mission_text: str
    gate_objective: str
    gate_clauses: tuple[tuple[str, str], ...]
    required_evidence_kinds: tuple[str, ...]
    checkpoint_commands: tuple[ProfileCheckpointCommand, ...]
    required_commit_message: str
    required_material_paths: tuple[str, ...]
    completion_conditions_text: str
    verifier_source: str
    verifier_source_sha256: str
    verifier_timeout_seconds: int
    verifier_output_limit_bytes: int
    budgets: tuple[int, int, int, int, int]
    timeout_seconds: int
    stdout_byte_limit: int
    stderr_byte_limit: int
    model: str
    fixture_initial_commit_message: str
    profile_fingerprint: str

    def _body(self) -> dict[str, Any]:
        """The complete canonical profile body, fingerprint field excluded."""

        data = dict(self.__dict__)
        data["gate_clauses"] = [list(clause) for clause in self.gate_clauses]
        data["required_evidence_kinds"] = list(self.required_evidence_kinds)
        data["checkpoint_commands"] = [command.to_dict() for command in self.checkpoint_commands]
        data["required_material_paths"] = list(self.required_material_paths)
        data["budgets"] = list(self.budgets)
        data.pop("profile_fingerprint")
        return data

    def validated(self) -> "NativeMissionProfile":
        if self.schema_version != MISSION_PROFILE_SCHEMA_VERSION:
            raise ValueError("unsupported native mission profile schema")
        require_identifier(self.profile_id, "profile_id")
        require_identifier(self.fixture_id, "profile fixture_id")
        require_strict_int(self.fixture_version, "profile fixture_version", minimum=1, maximum=1_000_000)
        require_identifier(self.run_id, "profile run_id")
        require_identifier(self.session_id, "profile session_id")
        require_identifier(self.gate_id, "profile gate_id")
        require_identifier(self.mission_id, "profile mission_id")
        require_nonempty_text(self.mission_text, "profile mission text")
        require_nonempty_text(self.gate_objective, "profile gate objective", max_bytes=8192)
        if not isinstance(self.gate_clauses, tuple) or not self.gate_clauses:
            raise ValueError("profile gate clauses must be a non-empty ordered tuple")
        clause_ids: list[str] = []
        for clause in self.gate_clauses:
            if not isinstance(clause, tuple) or len(clause) != 2:
                raise ValueError("profile gate clause must be an ordered (id, text) pair")
            clause_id, text = clause
            require_identifier(clause_id, "profile gate clause id")
            require_nonempty_text(text, "profile gate clause text", max_bytes=4096)
            clause_ids.append(clause_id)
        if len(set(clause_ids)) != len(clause_ids):
            raise ValueError("profile gate clause identities must be unique")
        if not isinstance(self.required_evidence_kinds, tuple) or not self.required_evidence_kinds:
            raise ValueError("profile evidence kinds must be a non-empty ordered tuple")
        known_kinds = {kind.value for kind in EvidenceKind}
        for kind in self.required_evidence_kinds:
            if not isinstance(kind, str) or kind not in known_kinds:
                raise ValueError("profile evidence kind is not a known evidence kind")
        if len(set(self.required_evidence_kinds)) != len(self.required_evidence_kinds):
            raise ValueError("profile evidence kinds must be unique")
        if not isinstance(self.checkpoint_commands, tuple) or not self.checkpoint_commands:
            raise ValueError("profile checkpoint commands must be a non-empty ordered tuple")
        command_ids: list[str] = []
        for command in self.checkpoint_commands:
            if not isinstance(command, ProfileCheckpointCommand):
                raise ValueError("profile checkpoint command has an invalid type")
            command.validated()
            command_ids.append(command.command_id)
        if len(set(command_ids)) != len(command_ids):
            raise ValueError("profile checkpoint command identities must be unique")
        require_nonempty_text(self.required_commit_message, "profile commit message", max_bytes=1024)
        if "\n" in self.required_commit_message or "\r" in self.required_commit_message:
            raise ValueError("profile commit message must be one exact single line")
        if not isinstance(self.required_material_paths, tuple) or not self.required_material_paths:
            raise ValueError("profile material paths must be a non-empty ordered tuple")
        for path in self.required_material_paths:
            require_safe_relative_path(path, "profile material path")
        if len(set(self.required_material_paths)) != len(self.required_material_paths):
            raise ValueError("profile material paths must be unique")
        require_nonempty_text(self.completion_conditions_text, "profile completion conditions", max_bytes=16384)
        require_nonempty_text(self.verifier_source, "profile verifier source", max_bytes=262144)
        require_sha256(self.verifier_source_sha256, "profile verifier source digest")
        if self.verifier_source_sha256 != _sha256_text(self.verifier_source):
            raise ValueError("profile verifier source digest contradicts the embedded source")
        require_strict_int(self.verifier_timeout_seconds, "profile verifier timeout", minimum=1, maximum=600)
        require_strict_int(
            self.verifier_output_limit_bytes, "profile verifier output limit", minimum=1, maximum=1024 * 1024
        )
        if not isinstance(self.budgets, tuple) or len(self.budgets) != 5:
            raise ValueError("profile budgets must be a five-item ordered tuple")
        for value in self.budgets:
            require_strict_int(value, "profile budget", minimum=0, maximum=1)
        if self.budgets != ONE_SHOT_PROFILE_BUDGETS:
            raise ValueError("profile budgets must be the exact one-shot budgets")
        require_strict_int(self.timeout_seconds, "profile timeout", minimum=1, maximum=3600)
        require_strict_int(self.stdout_byte_limit, "profile stdout limit", minimum=1, maximum=16 * 1024 * 1024)
        require_strict_int(self.stderr_byte_limit, "profile stderr limit", minimum=1, maximum=16 * 1024 * 1024)
        require_nonempty_text(self.model, "profile model", max_bytes=256)
        require_nonempty_text(
            self.fixture_initial_commit_message, "profile fixture initial commit message", max_bytes=1024
        )
        if "\n" in self.fixture_initial_commit_message or "\r" in self.fixture_initial_commit_message:
            raise ValueError("profile fixture initial commit message must be one exact single line")
        require_sha256(self.profile_fingerprint, "profile fingerprint")
        if fingerprint(self._body()) != self.profile_fingerprint:
            raise ValueError("native mission profile fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["profile_fingerprint"] = self.profile_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeMissionProfile":
        require_exact_keys(data, set(cls.__dataclass_fields__), "native mission profile")
        values = dict(data)
        raw_clauses = data["gate_clauses"]
        if not isinstance(raw_clauses, list) or any(
            not isinstance(clause, list) or len(clause) != 2 or any(not isinstance(part, str) for part in clause)
            for clause in raw_clauses
        ):
            raise ValueError("profile gate clauses must be an ordered array of [id, text] pairs")
        values["gate_clauses"] = tuple((clause[0], clause[1]) for clause in raw_clauses)
        values["required_evidence_kinds"] = require_string_list(
            data["required_evidence_kinds"], "profile evidence kinds"
        )
        raw_commands = data["checkpoint_commands"]
        if not isinstance(raw_commands, list) or not raw_commands:
            raise ValueError("profile checkpoint commands must be a non-empty ordered array")
        values["checkpoint_commands"] = tuple(
            ProfileCheckpointCommand.from_dict(item) for item in raw_commands
        )
        values["required_material_paths"] = require_string_list(
            data["required_material_paths"], "profile material paths"
        )
        raw_budgets = data["budgets"]
        if not isinstance(raw_budgets, list) or len(raw_budgets) != 5:
            raise ValueError("profile budgets must be a five-item ordered array")
        values["budgets"] = tuple(raw_budgets)
        return cls(**values).validated()


def create_native_mission_profile(**values: Any) -> NativeMissionProfile:
    """Build one canonically fingerprinted, validated mission profile.

    ``profile_fingerprint`` is derived from the complete body with the
    fingerprint field excluded, so it can never participate in its own input.
    """

    provisional = NativeMissionProfile(
        schema_version=MISSION_PROFILE_SCHEMA_VERSION,
        profile_fingerprint="0" * 64,
        **values,
    )
    return NativeMissionProfile(
        **{**provisional.__dict__, "profile_fingerprint": fingerprint(provisional._body())}
    ).validated()


# ---------------------------------------------------------------------------
# Flagship profile: incident-replay-v1 (Gate L1B owner contract, accepted).
# ---------------------------------------------------------------------------

FLAGSHIP_MISSION_TEXT = """Add deterministic, versioned incident replay and durable local persistence to
this local-first incident-response board.

Implement an append-only event log covering every supported incident mutation
(incident creation, status change, severity change, note addition).
Reconstruct board state deterministically by replaying that log from an empty
board. Add durable local persistence through the injected storage adapter,
validated export and import of the event log, duplicate-event-ID handling,
and fail-closed rejection of malformed or unsupported event data with no
partial mutation of the current board state or its stored log.

Add a visible event timeline and manual replay controls to the browser UI
that can move through the recorded history without mutating, truncating,
reordering, or appending to the authoritative persisted log.

Preserve the existing incident-board behavior and public interfaces where
reasonable. Add comprehensive tests using the existing Node test runner,
update the README, run the complete `npm test` suite, and create exactly one
local Git commit with the exact message `feat: add deterministic incident
replay`.

Do not add a remote. Do not push. Do not deploy. Stop only after the
complete `npm test` suite passes and the exact local commit has been
created; do not continue with optional polish after that commit."""

FLAGSHIP_REQUIRED_COMMIT_MESSAGE = "feat: add deterministic incident replay"

FLAGSHIP_COMPLETION_CONDITIONS_TEXT = f"""Required completion conditions:
- run the complete `npm test` suite and require it to pass;
- create exactly one intended local feature commit with complete message `{FLAGSHIP_REQUIRED_COMMIT_MESSAGE}`;
- use no `--trailer` when creating or amending the commit;
- add no commit-message body, `Co-authored-by`, sign-off, attribution, or other trailer;
- before stopping, run `git log -1 --format=%B` and verify that its complete output, after removing terminal newline characters only, is exactly `{FLAGSHIP_REQUIRED_COMMIT_MESSAGE}`;
- if the complete message is not exact, amend that same commit during this native invocation, do not create a second commit, and run the exact `%B` verification again;
- do not add or modify a Git remote;
- do not push;
- do not deploy;
- do not continue with optional polish after the final commit;
- stop immediately only after the complete `npm test` suite has passed and the exact full-message verification passes."""

# Deterministic Node behavioral verifier for incident-replay-v1.  It imports
# only the final public modules through file:// URLs, uses injected memory
# storage exclusively, performs no network access, mutates nothing in the
# workspace, and exits zero only when every assertion passes.
FLAGSHIP_VERIFIER_SOURCE = r"""import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const root = process.argv[2];
const load = (relative) => import(pathToFileURL(join(root, ...relative.split('/'))).href);
const { createApp } = await load('src/app.js');
const { createMemoryStorage } = await load('src/storage/memory-storage.js');
const eventLog = await load('src/domain/event-log.js');

const canonical = (board) => JSON.stringify(board);

// 1. A multi-step incident history can be created through the public app.
const storage = createMemoryStorage();
const app = createApp(storage);
app.controller.createIncident({ id: 'inc-1', title: 'Checkout latency spike', severity: 'high' });
app.controller.updateStatus('inc-1', 'acknowledged');
app.controller.updateSeverity('inc-1', 'critical');
app.controller.addNote('inc-1', 'rollback started');
app.controller.createIncident({ id: 'inc-2', title: 'Login error rate', severity: 'medium' });
const finalBoard = canonical(app.controller.board());
const eventTotal = app.controller.eventCount();
assert.equal(eventTotal, 5);

// 2. Export followed by import reconstructs the same canonical state, twice.
const exported = app.controller.exportLog();
const freshA = createApp(createMemoryStorage());
freshA.controller.importLog(exported);
assert.equal(canonical(freshA.controller.board()), finalBoard);
const freshB = createApp(createMemoryStorage());
freshB.controller.importLog(exported);
assert.equal(canonical(freshB.controller.board()), canonical(freshA.controller.board()));

// 3. A fresh instance over the same injected storage restores the history.
const restored = createApp(storage);
assert.equal(canonical(restored.controller.board()), finalBoard);
assert.equal(restored.controller.eventCount(), eventTotal);

// 4. Replay to beginning, an intermediate event, and the final event.
assert.equal(restored.controller.replayAt(0).incidents.length, 0);
const midway = restored.controller.replayAt(2);
assert.equal(midway.incidents.length, 1);
assert.equal(midway.incidents[0].status, 'acknowledged');
assert.equal(midway.incidents[0].severity, 'high');
assert.equal(canonical(restored.controller.replayAt(eventTotal)), finalBoard);

// 5. Duplicate event IDs cannot apply the same mutation twice.
const events = JSON.parse(exported);
assert.throws(() => eventLog.appendEvent(events, events[0]));
assert.throws(() => freshA.controller.importLog(JSON.stringify([...events, events[0]])));

// 6. Malformed, unsupported, and broken-reference events are rejected.
assert.throws(() => eventLog.validateEvent({ id: 'evt-x', version: 999, type: 'incident-created', payload: {} }));
assert.throws(() => eventLog.validateEvent({ id: 'evt-x', version: 1, type: 'unsupported-type', payload: {} }));
assert.throws(() => eventLog.replayEvents([
  { id: 'evt-x', version: 1, type: 'status-changed', payload: { id: 'missing', status: 'resolved' } },
]));

// 7. A failed import leaves the previous state and the stored log unchanged.
const beforeBoard = canonical(freshA.controller.board());
const beforeLog = freshA.controller.exportLog();
assert.throws(() => freshA.controller.importLog('not json at all'));
const broken = JSON.parse(exported);
broken[1] = { id: 'evt-broken', version: 999, type: 'status-changed', payload: {} };
assert.throws(() => freshA.controller.importLog(JSON.stringify(broken)));
assert.equal(canonical(freshA.controller.board()), beforeBoard);
assert.equal(freshA.controller.exportLog(), beforeLog);

// 8. Replay navigation never mutates the authoritative event log.
const logBefore = restored.controller.exportLog();
restored.controller.replayAt(0);
restored.controller.replayAt(3);
restored.controller.replayAt(eventTotal);
assert.equal(restored.controller.exportLog(), logBefore);
assert.equal(canonical(restored.controller.board()), finalBoard);

console.log('incident-replay behavioral verifier passed');
"""

FLAGSHIP_INCIDENT_REPLAY_PROFILE = create_native_mission_profile(
    profile_id="incident-replay-v1",
    fixture_id="local-incident-board",
    fixture_version=1,
    run_id="native-cursor-longrun-001",
    session_id="native-cursor-longrun-001",
    gate_id="native-longrun-gate",
    mission_id="native-longrun-incident-replay",
    mission_text=FLAGSHIP_MISSION_TEXT,
    gate_objective=(
        "Complete and locally commit deterministic incident replay with durable "
        "local persistence in the assigned incident-board repository."
    ),
    gate_clauses=(
        (
            "native-longrun.material",
            "The committed material implements deterministic, versioned incident replay "
            "with durable injected-storage persistence, validated export and import, "
            "duplicate-event handling, and fail-closed rejection of invalid event data.",
        ),
        (
            "native-longrun.tests",
            "The complete npm test suite passes independently at checkpoint capture.",
        ),
        (
            "native-longrun.behavior",
            "The independent behavioral verifier passes against the final public modules.",
        ),
        (
            "native-longrun.git",
            "The exact local commit exists, the worktree is clean, and no remote exists.",
        ),
    ),
    required_evidence_kinds=(
        EvidenceKind.TARGET_TREE.value,
        EvidenceKind.GIT_STATE.value,
        EvidenceKind.VERIFICATION_COMMAND.value,
    ),
    checkpoint_commands=(
        ProfileCheckpointCommand(
            command_id="npm-test",
            argv=("npm.cmd", "test"),
            timeout_seconds=300,
            max_capture_bytes=1024 * 1024,
        ),
    ),
    required_commit_message=FLAGSHIP_REQUIRED_COMMIT_MESSAGE,
    required_material_paths=(
        "README.md",
        "index.html",
        "src/app.js",
        "src/domain/event-log.js",
        "src/storage/event-store.js",
        "src/ui/render.js",
        "test/event-replay.test.js",
    ),
    completion_conditions_text=FLAGSHIP_COMPLETION_CONDITIONS_TEXT,
    verifier_source=FLAGSHIP_VERIFIER_SOURCE,
    verifier_source_sha256=_sha256_text(FLAGSHIP_VERIFIER_SOURCE),
    verifier_timeout_seconds=60,
    verifier_output_limit_bytes=262144,
    budgets=ONE_SHOT_PROFILE_BUDGETS,
    timeout_seconds=3600,
    stdout_byte_limit=8_388_608,
    stderr_byte_limit=1_048_576,
    model="auto",
    fixture_initial_commit_message="chore: initialize incident board fixture",
)


# ---------------------------------------------------------------------------
# Replacement flagship profile: workflow-recovery-v1.
# ---------------------------------------------------------------------------

WORKFLOW_RECOVERY_MISSION_TEXT = """Extend the existing local-first workflow console with a deterministic, durable
and resumable workflow execution engine. Preserve all existing
workflow-definition, task-editing, configuration-persistence,
configuration-export and browser behavior.

Work only inside the exact assigned workspace. Do not read or modify the source
repository, sibling run roots, sibling workspaces, evidence directories,
authorization records or prior-run artifacts.

Implement the following externally observable behavior:

1. Validate every workflow dependency graph before starting a run. Reject
missing dependencies, self-dependencies and cycles without persisting partial
run state. Produce a deterministic topological order. When multiple tasks are
otherwise equivalent, task ID ascending is the deterministic tie-breaker.

2. Represent task execution with explicit queued, running, succeeded, failed,
retry-wait and cancelled states. A terminal upstream failure must prevent
dependent work from starting; an explicit blocked representation may be used.
Enforce a configurable positive maximum-concurrency limit.

3. Expose `createWorkflowEngine({ storage, clock, outcomes, maxConcurrency })`
from `src/execution/engine.js`. The engine must expose `startRun`,
`advanceRun`, `cancelRun`, `recoverRun`, `run`, `listRuns`, `exportRuns` and
`importRuns`. One `advanceRun` call represents one complete deterministic
scheduler cycle: it starts eligible tasks until the configured concurrency
limit is filled and consults the injected outcome adapter for currently running
attempts during that cycle. `advanceRun` must not sleep.

4. The injected clock exposes `now()` returning a non-negative integer
timestamp. The injected outcome adapter exposes
`next({ runId, taskId, attempt })` and returns either
`{ status: "succeeded", result }`, `{ status: "failed", error }`, or `null`
to leave that attempt in progress.

5. Treat each task's maximum-attempt value as including its initial attempt.
For a failure at time `failureTime`, calculate the next attempt as
`failureTime + backoffMs * 2 ** (attempt - 1)`. Persist that timestamp, expose
it on the task entry returned by `run()` and `listRuns()` as `nextAttemptAt`, do
not retry early, and enter terminal failure after exhausting attempts.

6. Cancellation must cancel queued and retry-wait tasks, prevent new dependent
work from starting, preserve completed results and be idempotent. Repeating
cancellation must not add timeline entries or change deterministic export.

7. Persist workflow-run state through the injected storage adapter. Recover
state after a simulated process restart. A persisted running attempt must be
marked interrupted and made safely recoverable. Already succeeded attempts and
results must never be duplicated. Repeated recovery must be idempotent.

8. Use current run-state schema version `1`. Import the supplied version-0
legacy fixture by mapping completed tasks to succeeded, running tasks to
recoverable queued work with an interrupted attempt, and pending tasks to
queued. Reject unsupported future versions. Migration or import failure must
leave the previously valid stored state byte-for-byte unchanged.

9. Export run state deterministically. Validate the complete import before
mutation. Reject malformed relationships and duplicate run, task or attempt
identities atomically. Equivalent logical state must produce byte-identical
export independent of insertion order.

10. Integrate the engine through the existing
`createApp(storage, options = {})` composition boundary without breaking
existing public behavior. Display workflow-run status, task state, attempt
count and a chronological execution timeline. Expose start, cancel and
resume/recover controls. UI-facing summaries must be testable in Node without
a browser dependency.

11. Add comprehensive Node tests covering success, failure, negative
validation, retry exhaustion, cancellation, migration and restart recovery.
Do not use wall-clock sleeps. Update README documentation.

The following hard material paths must be created or materially modified by the
task commit:

- README.md
- index.html
- src/app.js
- src/execution/engine.js
- src/storage/run-store.js
- src/ui/render.js

Do not install dependencies, access the network, launch external commands as
workflow tasks, add a remote, push, deploy or modify anything outside the
assigned workspace."""

WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE = "feat: add resumable workflow execution"

WORKFLOW_RECOVERY_COMPLETION_CONDITIONS_TEXT = f"""Required completion conditions:
- satisfy every mission requirement and gate clause;

- run the complete `npm test` suite and require it to pass;

- confirm that each hard material path below is created or materially modified
  in the task commit:

  - README.md
  - index.html
  - src/app.js
  - src/execution/engine.js
  - src/storage/run-store.js
  - src/ui/render.js

- create exactly one intended local task commit after the fixture baseline with
  the exact complete message `{WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE}`;

- use no `--trailer` when creating or amending the commit;

- add no commit-message body, `Co-authored-by`, sign-off, attribution or other
  trailer;

- before stopping, run `git log -1 --format=%B` and verify that its complete
  output, after removing terminal newline characters only, is exactly
  `{WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE}`;

- if the complete message is not exact, amend that same task commit during this
  native invocation, do not create a second task commit, and run the exact
  `%B` verification again;

- confirm the worktree and index are clean;

- confirm no Git remotes exist;

- do not amend, replace or recreate the fixture baseline commit;

- do not read or modify the source repository, sibling run roots, sibling
  workspaces, evidence directories, authorization records or prior-run
  artifacts;

- do not install dependencies, access the network, launch external workflow
  commands, add a remote, push or deploy;

- do not continue with optional polish after the final verification.

Stop immediately only after the complete npm test suite passes, every required
material path is present in the single intended task commit, the exact complete
commit message has been verified with `git log -1 --format=%B`, the worktree
and index are clean, and the repository has zero remotes. Do not perform
further exploration or changes after those checks."""

# Independent public-behavior verifier.  Project imports are limited to the
# three authored interoperability boundaries; Node built-ins provide only
# assertions, path conversion, and read-only access to the supplied v0 fixture.
WORKFLOW_RECOVERY_VERIFIER_SOURCE = r"""import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const root = process.argv[2];
const load = (relative) => import(pathToFileURL(join(root, ...relative.split('/'))).href);
const { createApp } = await load('src/app.js');
const { createWorkflowEngine } = await load('src/execution/engine.js');
const { createMemoryStorage } = await load('src/storage/memory-storage.js');

const clone = (value) => JSON.parse(JSON.stringify(value));
const workflow = (id, tasks) => ({ id, name: id, tasks });
const task = (id, dependsOn = [], policy = {}) => ({
  id,
  title: id,
  description: `${id} description`,
  dependsOn,
  maxAttempts: policy.maxAttempts ?? 1,
  backoffMs: policy.backoffMs ?? 0,
});

function manualClock(initial = 0) {
  let value = initial;
  return {
    now: () => value,
    set(next) { value = next; },
    advance(delta) { value += delta; },
  };
}

function scriptedOutcomes(script = {}) {
  const calls = [];
  const queues = new Map(Object.entries(script).map(([id, values]) => [id, [...values]]));
  return {
    calls,
    next(context) {
      calls.push(clone(context));
      const queue = queues.get(context.taskId) ?? [];
      return queue.length ? queue.shift() : null;
    },
  };
}

function start(engine, runId, definition) {
  return engine.startRun({ runId, workflow: definition });
}

function runs(engine) {
  const value = engine.listRuns();
  assert.ok(Array.isArray(value), 'listRuns() must return an array');
  return value;
}

function current(engine, runId) {
  const value = runs(engine).find((candidate) => candidate.id === runId || candidate.runId === runId);
  assert.ok(value, `run ${runId} must be listed`);
  return value;
}

function tasksOf(run) {
  if (Array.isArray(run.tasks)) return run.tasks;
  assert.ok(run.tasks && typeof run.tasks === 'object', 'run tasks must be inspectable');
  return Object.values(run.tasks);
}

function taskOf(run, taskId) {
  const value = tasksOf(run).find((candidate) => candidate.id === taskId || candidate.taskId === taskId);
  assert.ok(value, `task ${taskId} must be inspectable`);
  return value;
}

function stateOf(value) {
  return value.state ?? value.status;
}

function attemptCount(value) {
  if (Array.isArray(value.attempts)) return value.attempts.length;
  return value.attemptCount ?? value.attempt ?? value.attempts ?? 0;
}

function terminal(run) {
  return ['succeeded', 'failed', 'cancelled'].includes(stateOf(run));
}

function drive(engine, runId, limit = 30) {
  for (let index = 0; index < limit && !terminal(current(engine, runId)); index += 1) {
    engine.advanceRun(runId);
  }
  return current(engine, runId);
}

function canonicalExport(engine) {
  const value = engine.exportRuns();
  assert.equal(typeof value, 'string', 'exportRuns() must return text');
  JSON.parse(value);
  return value;
}

function assertRequiredSurface(engine) {
  for (const name of ['startRun', 'advanceRun', 'cancelRun', 'recoverRun', 'run', 'listRuns', 'exportRuns', 'importRuns']) {
    assert.equal(typeof engine[name], 'function', `${name} must be a public engine method`);
  }
}

// Invalid graphs fail before any run-state mutation.
{
  const storage = createMemoryStorage();
  const engine = createWorkflowEngine({ storage, clock: manualClock(), outcomes: scriptedOutcomes(), maxConcurrency: 2 });
  assertRequiredSurface(engine);
  const before = canonicalExport(engine);
  assert.throws(() => start(engine, 'missing-run', workflow('missing', [task('a', ['absent'])])));
  assert.equal(canonicalExport(engine), before);
  assert.throws(() => start(engine, 'self-run', workflow('self', [task('a', ['a'])])));
  assert.equal(canonicalExport(engine), before);
  assert.throws(() => start(engine, 'cycle-run', workflow('cycle', [task('a', ['b']), task('b', ['a'])])));
  assert.equal(canonicalExport(engine), before);
}

// Canonical ordering is independent of definition insertion order.
function orderedCalls(tasks) {
  const outcomes = scriptedOutcomes({
    'root-a': [{ status: 'succeeded', result: 'a' }],
    'root-b': [{ status: 'succeeded', result: 'b' }],
    child: [{ status: 'succeeded', result: 'child' }],
  });
  const engine = createWorkflowEngine({ storage: createMemoryStorage(), clock: manualClock(10), outcomes, maxConcurrency: 1 });
  start(engine, 'ordered', workflow('ordered-workflow', tasks));
  drive(engine, 'ordered');
  return outcomes.calls.map((call) => call.taskId);
}
const orderingA = orderedCalls([task('root-b'), task('child', ['root-b', 'root-a']), task('root-a')]);
const orderingB = orderedCalls([task('root-a'), task('root-b'), task('child', ['root-a', 'root-b'])]);
assert.deepEqual(orderingA, ['root-a', 'root-b', 'child']);
assert.deepEqual(orderingB, orderingA);

// Bounded concurrency and deterministic runnable selection.
{
  const outcomes = scriptedOutcomes();
  const engine = createWorkflowEngine({ storage: createMemoryStorage(), clock: manualClock(20), outcomes, maxConcurrency: 2 });
  start(engine, 'concurrency', workflow('concurrency-workflow', [task('c'), task('a'), task('b')]));
  engine.advanceRun('concurrency');
  const visible = current(engine, 'concurrency');
  assert.equal(tasksOf(visible).filter((entry) => stateOf(entry) === 'running').length, 2);
  assert.deepEqual(outcomes.calls.slice(0, 2).map((call) => call.taskId), ['a', 'b']);
  assert.ok(tasksOf(visible).filter((entry) => stateOf(entry) === 'running').length <= 2);
}

// Retry timing, no early retry, success after the boundary, and exhaustion.
{
  const clock = manualClock(1_000);
  const outcomes = scriptedOutcomes({ flaky: [
    { status: 'failed', error: 'temporary' },
    { status: 'succeeded', result: 'recovered' },
  ] });
  const engine = createWorkflowEngine({ storage: createMemoryStorage(), clock, outcomes, maxConcurrency: 1 });
  start(engine, 'retry-success', workflow('retry-workflow', [task('flaky', [], { maxAttempts: 2, backoffMs: 50 })]));
  engine.advanceRun('retry-success');
  let visible = taskOf(current(engine, 'retry-success'), 'flaky');
  assert.equal(stateOf(visible), 'retry-wait');
  assert.equal(visible.nextAttemptAt, 1_050);
  assert.equal(attemptCount(visible), 1);
  clock.set(1_049);
  engine.advanceRun('retry-success');
  assert.equal(outcomes.calls.length, 1);
  clock.set(1_050);
  drive(engine, 'retry-success');
  visible = taskOf(current(engine, 'retry-success'), 'flaky');
  assert.equal(stateOf(visible), 'succeeded');
  assert.equal(attemptCount(visible), 2);

  const exhausted = scriptedOutcomes({ upstream: [
    { status: 'failed', error: 'first' },
    { status: 'failed', error: 'last' },
  ] });
  const exhaustedClock = manualClock(2_000);
  const failedEngine = createWorkflowEngine({ storage: createMemoryStorage(), clock: exhaustedClock, outcomes: exhausted, maxConcurrency: 1 });
  start(failedEngine, 'retry-failed', workflow('failed-workflow', [
    task('upstream', [], { maxAttempts: 2, backoffMs: 10 }),
    task('dependent', ['upstream']),
  ]));
  failedEngine.advanceRun('retry-failed');
  exhaustedClock.set(2_010);
  drive(failedEngine, 'retry-failed');
  const failed = current(failedEngine, 'retry-failed');
  assert.equal(stateOf(taskOf(failed, 'upstream')), 'failed');
  assert.notEqual(stateOf(taskOf(failed, 'dependent')), 'succeeded');
  assert.ok(!exhausted.calls.some((call) => call.taskId === 'dependent'));
}

// Cancellation preserves completed work and is byte-idempotent.
{
  const outcomes = scriptedOutcomes({
    done: [{ status: 'succeeded', result: { value: 7 } }],
    waiting: [{ status: 'failed', error: 'retry later' }],
  });
  const engine = createWorkflowEngine({ storage: createMemoryStorage(), clock: manualClock(3_000), outcomes, maxConcurrency: 1 });
  start(engine, 'cancelled', workflow('cancel-workflow', [
    task('done'),
    task('waiting', ['done'], { maxAttempts: 3, backoffMs: 100 }),
    task('downstream', ['waiting']),
  ]));
  engine.advanceRun('cancelled');
  engine.advanceRun('cancelled');
  assert.equal(stateOf(taskOf(current(engine, 'cancelled'), 'waiting')), 'retry-wait');
  engine.cancelRun('cancelled');
  const once = canonicalExport(engine);
  const cancelled = current(engine, 'cancelled');
  assert.equal(stateOf(taskOf(cancelled, 'done')), 'succeeded');
  assert.deepEqual(taskOf(cancelled, 'done').result, { value: 7 });
  assert.equal(stateOf(taskOf(cancelled, 'waiting')), 'cancelled');
  assert.equal(stateOf(taskOf(cancelled, 'downstream')), 'cancelled');
  engine.cancelRun('cancelled');
  assert.equal(canonicalExport(engine), once);
  engine.advanceRun('cancelled');
  assert.ok(!outcomes.calls.some((call) => call.taskId === 'downstream'));
}

// Restart recovery interrupts only in-progress work and never repeats success.
{
  const storage = createMemoryStorage();
  const clock = manualClock(4_000);
  const firstOutcomes = scriptedOutcomes({
    complete: [{ status: 'succeeded', result: 'kept' }],
    interrupted: [null],
  });
  const first = createWorkflowEngine({ storage, clock, outcomes: firstOutcomes, maxConcurrency: 1 });
  start(first, 'recovery', workflow('recovery-workflow', [task('complete'), task('interrupted', ['complete'])]));
  first.advanceRun('recovery');
  first.advanceRun('recovery');
  const completedAttempts = attemptCount(taskOf(current(first, 'recovery'), 'complete'));
  assert.equal(stateOf(taskOf(current(first, 'recovery'), 'interrupted')), 'running');

  const resumedOutcomes = scriptedOutcomes({ interrupted: [{ status: 'succeeded', result: 'resumed' }] });
  const second = createWorkflowEngine({ storage, clock, outcomes: resumedOutcomes, maxConcurrency: 1 });
  second.recoverRun('recovery');
  const recovered = current(second, 'recovery');
  assert.equal(stateOf(taskOf(recovered, 'complete')), 'succeeded');
  assert.equal(attemptCount(taskOf(recovered, 'complete')), completedAttempts);
  assert.notEqual(stateOf(taskOf(recovered, 'interrupted')), 'succeeded');
  assert.match(JSON.stringify(recovered).toLowerCase(), /interrupt/);
  drive(second, 'recovery');
  const finished = current(second, 'recovery');
  assert.equal(stateOf(taskOf(finished, 'interrupted')), 'succeeded');
  assert.equal(resumedOutcomes.calls.filter((call) => call.taskId === 'interrupted').length, 1);
  const stable = canonicalExport(second);
  second.recoverRun('recovery');
  assert.equal(canonicalExport(second), stable);
}

// Version-0 migration and fail-closed import validation.
{
  const legacyText = await readFile(join(root, 'test', 'fixtures', 'legacy-run-state-v0.json'), 'utf8');
  const storage = createMemoryStorage();
  const engine = createWorkflowEngine({ storage, clock: manualClock(5_000), outcomes: scriptedOutcomes(), maxConcurrency: 2 });
  engine.importRuns(legacyText);
  const migrated = JSON.parse(canonicalExport(engine));
  assert.equal(migrated.schemaVersion, 1);
  const legacy = current(engine, 'legacy-run-001');
  assert.equal(stateOf(taskOf(legacy, 'prepare')), 'succeeded');
  assert.deepEqual(taskOf(legacy, 'prepare').result, { artifact: 'prepared.json' });
  assert.equal(stateOf(taskOf(legacy, 'publish')), 'queued');
  assert.match(JSON.stringify(taskOf(legacy, 'publish')).toLowerCase(), /interrupt/);
  assert.equal(stateOf(taskOf(legacy, 'notify')), 'queued');

  const before = canonicalExport(engine);
  assert.throws(() => engine.importRuns(JSON.stringify({ schemaVersion: 99, runs: [] })));
  assert.equal(canonicalExport(engine), before);

  const duplicateRun = JSON.parse(before);
  assert.ok(Array.isArray(duplicateRun.runs) && duplicateRun.runs.length > 0);
  duplicateRun.runs.push(clone(duplicateRun.runs[0]));
  assert.throws(() => engine.importRuns(JSON.stringify(duplicateRun)));
  assert.equal(canonicalExport(engine), before);

  const duplicateTask = JSON.parse(before);
  assert.ok(Array.isArray(duplicateTask.runs[0].tasks) && duplicateTask.runs[0].tasks.length > 0);
  duplicateTask.runs[0].tasks.push(clone(duplicateTask.runs[0].tasks[0]));
  assert.throws(() => engine.importRuns(JSON.stringify(duplicateTask)));
  assert.equal(canonicalExport(engine), before);

  const duplicateAttempt = JSON.parse(before);
  const attemptedTask = duplicateAttempt.runs[0].tasks.find((entry) => Array.isArray(entry.attempts) && entry.attempts.length > 0);
  assert.ok(attemptedTask, 'migrated state must expose attempt identities');
  attemptedTask.attempts.push(clone(attemptedTask.attempts[0]));
  assert.throws(() => engine.importRuns(JSON.stringify(duplicateAttempt)));
  assert.equal(canonicalExport(engine), before);

  const brokenRelationship = JSON.parse(before);
  brokenRelationship.runs[0].tasks[0].dependsOn = ['absent-task'];
  assert.throws(() => engine.importRuns(JSON.stringify(brokenRelationship)));
  assert.equal(canonicalExport(engine), before);
}

// Equivalent completed runs export identically despite definition insertion order.
function deterministicExport(tasks) {
  const outcomes = scriptedOutcomes({ a: [{ status: 'succeeded', result: 'a' }], b: [{ status: 'succeeded', result: 'b' }] });
  const engine = createWorkflowEngine({ storage: createMemoryStorage(), clock: manualClock(6_000), outcomes, maxConcurrency: 1 });
  start(engine, 'deterministic', workflow('deterministic-workflow', tasks));
  drive(engine, 'deterministic');
  return canonicalExport(engine);
}
assert.equal(deterministicExport([task('b'), task('a')]), deterministicExport([task('a'), task('b')]));

// Existing definition operations and Node-testable run UI remain integrated.
{
  const storage = createMemoryStorage();
  const outcomes = scriptedOutcomes({ ui: [{ status: 'succeeded', result: 'shown' }] });
  const engine = createWorkflowEngine({ storage, clock: manualClock(7_000), outcomes, maxConcurrency: 1 });
  start(engine, 'ui-run', workflow('ui-workflow', [task('ui')]));
  drive(engine, 'ui-run');
  const app = createApp(storage, { clock: manualClock(7_000), outcomes: scriptedOutcomes(), maxConcurrency: 1 });
  app.controller.createWorkflow({ id: 'definition', name: 'Definition remains usable', description: 'existing behavior' });
  app.controller.addTask('definition', task('definition-task'));
  app.controller.updateTask('definition', 'definition-task', { title: 'Updated task' });
  assert.equal(app.controller.workflow('definition').tasks[0].title, 'Updated task');
  assert.equal(typeof app.controller.exportConfiguration(), 'string');
  const rendered = Object.entries(app)
    .filter(([name, value]) => name.startsWith('render') && typeof value === 'function')
    .map(([, render]) => render())
    .filter((value) => typeof value === 'string')
    .join('\n');
  for (const expected of ['ui-run', 'succeeded', 'attempt', 'timeline', 'start', 'cancel']) {
    assert.match(rendered.toLowerCase(), new RegExp(expected));
  }
  assert.match(rendered.toLowerCase(), /recover|resume/);
}

console.log('workflow-recovery behavioral verifier passed');
"""

WORKFLOW_RECOVERY_PROFILE = create_native_mission_profile(
    profile_id="workflow-recovery-v1",
    fixture_id="local-workflow-console",
    fixture_version=1,
    run_id="native-cursor-flagship-002",
    session_id="native-cursor-flagship-002",
    gate_id="workflow-recovery-gate",
    mission_id="native-flagship-workflow-recovery",
    mission_text=WORKFLOW_RECOVERY_MISSION_TEXT,
    gate_objective=(
        "Deliver a deterministic, durable and resumable workflow engine while preserving "
        "existing workflow-definition behavior and satisfying the one-commit offline contract."
    ),
    gate_clauses=(
        (
            "workflow-recovery.graph",
            "Dependency validation and deterministic topological ordering reject invalid "
            "graphs before mutation.",
        ),
        (
            "workflow-recovery.execution",
            "Scheduling, concurrency, retries, dependency blocking and cancellation obey "
            "deterministic state-transition rules.",
        ),
        (
            "workflow-recovery.persistence",
            "Versioned storage, migration, atomic import/export and restart recovery "
            "preserve durable identity without duplicate completion.",
        ),
        (
            "workflow-recovery.ui",
            "Existing definition behavior remains compatible while run summaries, task "
            "attempts, timelines and controls are integrated.",
        ),
        (
            "workflow-recovery.tests",
            "The complete offline Node test suite covers positive, negative and recovery "
            "behavior without wall-clock sleeps.",
        ),
        (
            "workflow-recovery.git",
            "The result is exactly one clean local task commit with the required message and "
            "zero remotes.",
        ),
    ),
    required_evidence_kinds=(
        EvidenceKind.TARGET_TREE.value,
        EvidenceKind.GIT_STATE.value,
        EvidenceKind.VERIFICATION_COMMAND.value,
    ),
    checkpoint_commands=(
        ProfileCheckpointCommand(
            command_id="npm-test",
            argv=("npm.cmd", "test"),
            timeout_seconds=300,
            max_capture_bytes=1024 * 1024,
        ),
    ),
    required_commit_message=WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE,
    required_material_paths=(
        "README.md",
        "index.html",
        "src/app.js",
        "src/execution/engine.js",
        "src/storage/run-store.js",
        "src/ui/render.js",
    ),
    completion_conditions_text=WORKFLOW_RECOVERY_COMPLETION_CONDITIONS_TEXT,
    verifier_source=WORKFLOW_RECOVERY_VERIFIER_SOURCE,
    verifier_source_sha256=_sha256_text(WORKFLOW_RECOVERY_VERIFIER_SOURCE),
    verifier_timeout_seconds=120,
    verifier_output_limit_bytes=524_288,
    budgets=ONE_SHOT_PROFILE_BUDGETS,
    timeout_seconds=3600,
    stdout_byte_limit=8_388_608,
    stderr_byte_limit=1_048_576,
    model="auto",
    fixture_initial_commit_message="chore: initialize workflow console fixture",
)


__all__ = [
    "FLAGSHIP_COMPLETION_CONDITIONS_TEXT",
    "FLAGSHIP_INCIDENT_REPLAY_PROFILE",
    "FLAGSHIP_MISSION_TEXT",
    "FLAGSHIP_REQUIRED_COMMIT_MESSAGE",
    "FLAGSHIP_VERIFIER_SOURCE",
    "MISSION_PROFILE_SCHEMA_VERSION",
    "ONE_SHOT_PROFILE_BUDGETS",
    "WORKFLOW_RECOVERY_COMPLETION_CONDITIONS_TEXT",
    "WORKFLOW_RECOVERY_MISSION_TEXT",
    "WORKFLOW_RECOVERY_PROFILE",
    "WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE",
    "WORKFLOW_RECOVERY_VERIFIER_SOURCE",
    "NativeMissionProfile",
    "ProfileCheckpointCommand",
    "create_native_mission_profile",
]
