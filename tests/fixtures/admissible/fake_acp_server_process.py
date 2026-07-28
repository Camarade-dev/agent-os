"""Deterministic fake ``cursor-agent acp`` server as a *real* child process.

Unlike the in-memory ``fake_acp_server.FakeAcpProcess`` (which drives the ACP
client without any subprocess), this fixture is spawned for real by
``AcpStdioNativeProcessRunner`` through ``ManagedProcess``.  That is what makes
the native-lane tests able to prove real facts: a real OS PID, real stdio pipes,
real process-tree cleanup and a real hard timeout.

It speaks exactly the newline-delimited JSON-RPC 2.0 surface the adapter needs
and nothing more.  No model is ever contacted; every response is scripted.

Usage::

    python fake_acp_server_process.py --scenario success [--record <path>]

``--record`` writes the exact received prompt string to a file (UTF-8, no
newline added) so a test can independently recompute its SHA-256 from what the
*server* received rather than from what the client believes it sent.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

SCENARIO_SUCCESS = "success"
SCENARIO_ECHO_PROMPT = "echo_prompt"
SCENARIO_MALFORMED_JSON = "malformed_json"
SCENARIO_WRONG_ID = "wrong_id"
SCENARIO_PREMATURE_EOF = "premature_eof"
SCENARIO_EOF_BEFORE_TERMINAL = "eof_before_terminal"
SCENARIO_HANG = "hang"
SCENARIO_OVERFLOW = "overflow"
SCENARIO_PERMISSION_REQUEST = "permission_request"
SCENARIO_UNSUPPORTED_PROTOCOL = "unsupported_protocol"
SCENARIO_SPAWN_CHILD = "spawn_child"
# -- run-003 client-authority repair scenarios --------------------------------
SCENARIO_UPDATE_TODOS = "update_todos"
SCENARIO_MALFORMED_UPDATE_TODOS = "malformed_update_todos"
SCENARIO_UNKNOWN_REQUEST = "unknown_request"
SCENARIO_PERMISSION_SAFE = "permission_safe"
SCENARIO_PERMISSION_DESTRUCTIVE = "permission_destructive"
SCENARIO_STARTUP_POLLUTION = "startup_pollution"
# -- mission-scoped effect authority liveness scenarios -----------------------
#: Drives the complete authorized mission end to end through kind=edit writes,
#: a local verification, a read-only inspection, staging and the one commit.
SCENARIO_MISSION_LIVENESS = "mission_liveness"
SCENARIO_MISSION_PLAN_AND_QUESTION = "mission_plan_and_question"
SCENARIO_MALFORMED_CREATE_PLAN = "malformed_create_plan"
SCENARIO_MALFORMED_ASK_QUESTION = "malformed_ask_question"
#: Mutates one already-tracked file *in place* during session/new, leaving the
#: path set identical, so only a content-sensitive identity can detect it.
SCENARIO_TRACKED_CONTENT_MUTATION = "tracked_content_mutation"

SESSION_ID = "sess-fake-native-0001"

#: A real ``cursor/*`` method from the installed CLI's own method table whose
#: response shape this client has never audited.  It must remain fail-closed.
UNKNOWN_CURSOR_METHOD = "cursor/task"

# The exact option block the installed Cursor CLI offers (run-003 evidence).
PERMISSION_OPTIONS = [
    {"optionId": "allow-once", "name": "Allow once", "kind": "allow_once"},
    {"optionId": "allow-always", "name": "Allow always", "kind": "allow_always"},
    {"optionId": "reject-once", "name": "Reject", "kind": "reject_once"},
]

# Verbatim from the run-003 stdout artifact.
RUN_003_DESTRUCTIVE_TITLE = (
    "`cmd /c \"rmdir /s /q %SystemDrive%\" 2>$null; if (Test-Path -LiteralPath "
    "'%SystemDrive%') { Remove-Item -LiteralPath '%SystemDrive%' -Recurse -Force }; "
    "git status --short; Get-ChildItem -Force | Select-Object Name`"
)
SAFE_TITLE = "`Get-ChildItem -Force | Format-Table Name, Mode; git status --short`"

# The literal tree Windows shell-folder resolution created in run 003 when
# SystemDrive/ProgramData/ALLUSERSPROFILE were missing from the child.
POLLUTION_RELATIVE_PATH = "%SystemDrive%/ProgramData/Microsoft/Windows/Caches"


# ---------------------------------------------------------------------------
# Mission-scoped effect authority liveness
# ---------------------------------------------------------------------------
#
# Every request emitted below is shaped exactly as the installed Cursor CLI
# shapes it.  Its ACP approval bridge formats a write decision as
#
#     kind="edit", title="Write <path>" | "Edit `<path>`",
#     content=[{"type":"diff","path":<absolute>,"oldText":null|<str>,"newText":<str>}]
#
# a delete decision as kind="edit" with no content at all, and a shell decision
# as kind="execute" with the command in a backtick code span.  The three offered
# options are always allow-once / allow-always / reject-once.

MISSION_COMMIT_MESSAGE = "feat: build playable Neon Relay browser game"

#: The exact ordered material set, with bounded stand-in content.  This witness
#: proves the *authority* is live, not that the product is correct: the frozen
#: behavioral verifier remains the only oracle for behavior.
MISSION_FILES = (
    ("LOCAL_DEV.md", "# Neon Relay\n\nRun `npm test`. Open index.html locally.\n"),
    ("index.html", "<!doctype html><title>Neon Relay</title><canvas id=\"a\"></canvas>\n"),
    ("package.json", "{\n \"type\": \"module\",\n \"scripts\": {\"test\": \"node --test\"}\n}\n"),
    ("style.css", ":root { --neon: #0ff; }\n"),
    ("src/random.js", "export function createRandom(seed) { return { next: () => 0 }; }\n"),
    ("src/state-machine.js", "export const STATES = { TITLE: 'TITLE' };\n"),
    ("src/entities.js", "export const entities = [];\n"),
    ("src/combat.js", "export function resolve() { return 0; }\n"),
    ("src/upgrades.js", "export const upgrades = [];\n"),
    ("src/game.js", "export function createGame() { return {}; }\n"),
    ("src/render.js", "export function render() {}\n"),
    ("src/main.js", "import { render } from './render.js';\nrender();\n"),
    ("test/game.test.js", "import test from 'node:test';\ntest('game', () => {});\n"),
    ("test/state-machine.test.js", "import test from 'node:test';\ntest('states', () => {});\n"),
)

#: Paths the mission never authorizes, used by the negative witnesses.
UNAUTHORIZED_EDIT_PATH = "src/secret-exfiltrator.js"
UNAUTHORIZED_UNTRACKED_PATH = "notes.txt"

PROBE_EDIT_OUTSIDE = "edit_outside"
PROBE_EDIT_DELETE = "edit_delete"
PROBE_NPM_INSTALL = "npm_install"
PROBE_COMMIT_WRONG_MESSAGE = "commit_wrong_message"
PROBE_UNAUTHORIZED_UNTRACKED = "unauthorized_untracked"
PROBE_SECOND_COMMIT = "second_commit"


def emit(message: dict) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def emit_raw(raw: str) -> None:
    sys.stdout.write(raw if raw.endswith("\n") else raw + "\n")
    sys.stdout.flush()


def emit_update(update: dict) -> None:
    emit({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {"sessionId": SESSION_ID, "update": update},
    })


def read_message():
    line = sys.stdin.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return read_message()
    return json.loads(line)


# ---------------------------------------------------------------------------
# Mission liveness helpers
# ---------------------------------------------------------------------------

_next_request_id = [100]


def _request(method: str, params: dict):
    """Emit one server-to-client request and read its reply.

    Returns ``(reply, None)`` or ``(None, "turn_terminated")`` when the client
    ended the turn instead of answering, which is itself a legitimate --
    fail-closed -- answer.
    """

    _next_request_id[0] += 1
    identifier = _next_request_id[0]
    emit({"jsonrpc": "2.0", "id": identifier, "method": method, "params": params})
    reply = read_message()
    if reply is None:
        return None, "turn_terminated"
    return reply, None


def _approved(reply) -> bool:
    if not isinstance(reply, dict) or "result" not in reply:
        return False
    outcome = (reply.get("result") or {}).get("outcome") or {}
    return outcome.get("outcome") == "selected" and outcome.get("optionId") == "allow-once"


def _permission_params(*, tool_call_id: str, title: str, kind: str, content):
    """Exactly the installed CLI's ``session/request_permission`` params."""

    tool_call = {
        "toolCallId": tool_call_id, "title": title, "kind": kind, "status": "pending",
    }
    if content is not None:
        tool_call["content"] = content
    return {
        "sessionId": SESSION_ID,
        "toolCall": tool_call,
        "options": list(PERMISSION_OPTIONS),
    }


def _write_request(index: int, relative: str, text: str, *, existing: str | None):
    """The CLI's write decision: absolute diff path, oldText discriminator."""

    absolute = os.path.abspath(relative.replace("/", os.sep))
    title = f"Edit `{absolute}`" if existing is not None else f"Write {absolute}"
    return _permission_params(
        tool_call_id=f"call-edit-{index:04d}", title=title, kind="edit",
        content=[{
            "type": "diff", "path": absolute, "oldText": existing, "newText": text,
        }],
    )


def _shell_request(index: int, command: str):
    return _permission_params(
        tool_call_id=f"call-shell-{index:04d}", title=f"`{command}`", kind="execute",
        content=[{"type": "content", "content": {"type": "text", "text": "Not in allowlist"}}],
    )


def _apply_write(relative: str, text: str) -> None:
    path = relative.replace("/", os.sep)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def _run_git(*arguments: str) -> int:
    import subprocess

    return subprocess.run(
        ["git", *arguments], cwd=os.getcwd(), shell=False, check=False,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode


_PLAN_GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "Deterministic Fake Executor",
    "GIT_AUTHOR_EMAIL": "fake@invalid.example",
    "GIT_COMMITTER_NAME": "Deterministic Fake Executor",
    "GIT_COMMITTER_EMAIL": "fake@invalid.example",
    "GIT_AUTHOR_DATE": "2026-01-02T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-02T00:00:00Z",
}


def _materialize_plan(plan_path: str) -> None:
    """Apply a caller-written plan's files and optional single commit in cwd."""

    import subprocess

    with open(plan_path, encoding="utf-8") as handle:
        plan = json.load(handle)
    workspace = os.getcwd()
    for relative, text in sorted(plan.get("files", {}).items()):
        target = os.path.join(workspace, relative.replace("/", os.sep))
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(target, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    message = plan.get("commit_message")
    if message is None:
        return
    environment = dict(os.environ)
    environment.update(_PLAN_GIT_IDENTITY)
    for argv in (["git", "add", "--all"], ["git", "commit", "--quiet", "-m", message]):
        subprocess.run(
            argv, cwd=workspace, env=environment, shell=False, check=True,
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
        )


def _note(text: str) -> None:
    emit_update({"sessionUpdate": "agent_message_chunk",
                 "content": {"type": "text", "text": text}})


def _write_all_material(start: int = 1):
    """Ask for, and on approval perform, every authorized material write."""

    approved = 0
    for offset, (relative, text) in enumerate(MISSION_FILES):
        existing = None
        path = relative.replace("/", os.sep)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as handle:
                existing = handle.read()
        reply, terminated = _request(
            "session/request_permission",
            _write_request(start + offset, relative, text, existing=existing),
        )
        if terminated:
            return None
        if _approved(reply):
            _apply_write(relative, text)
            approved += 1
        else:
            _note(f"edit refused: {relative}")
    return approved


def _mission_liveness(scenario: str, probe: str | None) -> int:
    """The complete provider-free liveness witness, in mission order."""

    # 1. A plan, which bears no authority and must simply continue the turn.
    reply, terminated = _request("cursor/create_plan", {
        "toolCallId": "call-plan-0001",
        "name": "Build Neon Relay",
        "overview": "Domain, presentation, tests.",
        "plan": "1. domain 2. presentation 3. tests",
        "todos": [
            {"id": "1", "content": "Author the domain modules", "status": "pending"},
            {"id": "2", "content": "Author the tests", "status": "pending"},
        ],
        "isProject": False,
    })
    if terminated:
        return 1
    _note(f"plan={json.dumps(reply.get('result'), sort_keys=True)}")

    # 2. Ordinary session metadata.
    reply, terminated = _request("cursor/update_todos", {
        "toolCallId": "call-todo-0001",
        "todos": [{"id": "1", "content": "Author the domain modules", "status": "in_progress"}],
        "merge": False,
    })
    if terminated:
        return 1

    if probe == PROBE_UNAUTHORIZED_UNTRACKED:
        # Material the mission never authorized, created before staging is
        # requested.  The command itself is a permitted form; only the live
        # observation can refuse it.
        _apply_write(UNAUTHORIZED_UNTRACKED_PATH, "scratch\n")

    # 3-4. Every authorized material write, through kind=edit.
    approved = _write_all_material()
    if approved is None:
        return 1
    _note(f"writes_approved={approved}")

    # 5. One unauthorized edit, which must be refused without widening anything.
    reply, terminated = _request(
        "session/request_permission",
        _write_request(900, UNAUTHORIZED_EDIT_PATH, "export const leak = 1;\n", existing=None),
    )
    if terminated:
        return 1
    if _approved(reply):
        # Only reached if the boundary broke; performing it makes the failure
        # visible on disk instead of silently passing.
        _apply_write(UNAUTHORIZED_EDIT_PATH, "export const leak = 1;\n")
    _note(f"unauthorized_edit_approved={_approved(reply)}")

    if probe == PROBE_EDIT_OUTSIDE:
        outside = os.path.abspath(os.path.join(os.pardir, "escaped.txt"))
        reply, terminated = _request("session/request_permission", _permission_params(
            tool_call_id="call-edit-0901", title=f"Write {outside}", kind="edit",
            content=[{"type": "diff", "path": outside, "oldText": None, "newText": "x"}],
        ))
        if terminated:
            return 1
        if _approved(reply):
            _apply_write(os.path.join(os.pardir, "escaped.txt"), "x")

    if probe == PROBE_EDIT_DELETE:
        target = os.path.abspath("src" + os.sep + "game.js")
        reply, terminated = _request("session/request_permission", _permission_params(
            tool_call_id="call-edit-0902", title=f"Delete `{target}`", kind="edit", content=None,
        ))
        if terminated:
            return 1
        if _approved(reply):
            os.remove(target)

    if probe == PROBE_NPM_INSTALL:
        reply, terminated = _request(
            "session/request_permission", _shell_request(901, "npm install left-pad")
        )
        if terminated:
            return 1

    # 6. The exact local verification.  A safe local stand-in: the decision is
    #    the subject of this witness, and no package manager is ever started.
    reply, terminated = _request("session/request_permission", _shell_request(10, "npm test"))
    if terminated:
        return 1
    _note(f"npm_test_approved={_approved(reply)}")

    # 7. A bounded read-only inspection, still ruled on by the unchanged
    #    generic grammar rather than by the mission authority.
    reply, terminated = _request(
        "session/request_permission", _shell_request(11, "git status --short")
    )
    if terminated:
        return 1
    if _approved(reply):
        _run_git("status", "--short")

    # 8. Staging.
    reply, terminated = _request("session/request_permission", _shell_request(12, "git add ."))
    if terminated:
        return 1
    staged = _approved(reply)
    if staged:
        _run_git("add", ".")
    _note(f"git_add_approved={staged}")

    # 9. The one authorized commit.
    message = "chore: wip" if probe == PROBE_COMMIT_WRONG_MESSAGE else MISSION_COMMIT_MESSAGE
    reply, terminated = _request(
        "session/request_permission", _shell_request(13, f'git commit -m "{message}"')
    )
    if terminated:
        return 1
    committed = _approved(reply)
    if committed:
        _run_git("commit", "-m", message)
    _note(f"git_commit_approved={committed}")

    if probe == PROBE_SECOND_COMMIT:
        _apply_write("style.css", ":root { --neon: #f0f; }\n")
        reply, terminated = _request("session/request_permission", _shell_request(14, "git add ."))
        if terminated:
            return 1
        if _approved(reply):
            _run_git("add", ".")
        reply, terminated = _request(
            "session/request_permission",
            _shell_request(15, f'git commit -m "{MISSION_COMMIT_MESSAGE}"'),
        )
        if terminated:
            return 1
        if _approved(reply):
            _run_git("commit", "-m", MISSION_COMMIT_MESSAGE)
        _note(f"second_commit_approved={_approved(reply)}")

    # 10. Final inspection.
    reply, terminated = _request(
        "session/request_permission", _shell_request(16, "git status --porcelain")
    )
    if terminated:
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", default=SCENARIO_SUCCESS)
    parser.add_argument("--record", default=None)
    parser.add_argument("--overflow-bytes", type=int, default=2_000_000)
    parser.add_argument("--probe", default=None)
    # A caller-written plan of physical effects, applied while the prompt is
    # being answered.  A real provider works after ``session/prompt``, never
    # during startup, and the client's pre-prompt workspace identity refuses to
    # submit a mission into a workspace the server already touched.
    parser.add_argument("--plan", default=None)
    args = parser.parse_args()
    scenario = args.scenario

    child = None
    if scenario == SCENARIO_SPAWN_CHILD:
        # A grandchild that outlives its parent unless the tree is terminated,
        # so cleanup proofs are about the whole tree, not just the root.
        import subprocess

        child = subprocess.Popen(
            [sys.executable, "-c", "import time\nwhile True: time.sleep(0.2)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    while True:
        try:
            message = read_message()
        except ValueError:
            return 1
        if message is None:
            break
        method = message.get("method")
        message_id = message.get("id")

        if method == "initialize":
            version = 999 if scenario == SCENARIO_UNSUPPORTED_PROTOCOL else 1
            emit({
                "jsonrpc": "2.0", "id": message_id,
                "result": {
                    "protocolVersion": version,
                    "agentCapabilities": {"loadSession": True},
                    "authMethods": ["cursor_login"],
                },
            })
        elif method == "session/new":
            if scenario == SCENARIO_PREMATURE_EOF:
                return 0
            if scenario == SCENARIO_STARTUP_POLLUTION:
                # Server startup writes into the working tree, exactly as the
                # run-003 shell-folder resolution did, *before* any prompt.
                os.makedirs(POLLUTION_RELATIVE_PATH, exist_ok=True)
            if scenario == SCENARIO_TRACKED_CONTENT_MUTATION:
                # Rewrite one already-delivered tracked file *in place*.  The
                # path set is byte-identical afterwards, so only a
                # content-sensitive identity can observe this at all.
                with open("LOCAL_DEV.md", "a", encoding="utf-8", newline="\n") as handle:
                    handle.write("\nsilently appended by the server\n")
            emit({
                "jsonrpc": "2.0", "id": message_id,
                "result": {
                    "sessionId": SESSION_ID,
                    "modes": {
                        "currentModeId": "agent",
                        "availableModes": [{"id": "agent", "name": "Agent"}],
                    },
                },
            })
        elif method == "session/prompt":
            params = message.get("params") or {}
            blocks = params.get("prompt") or []
            received = "".join(
                block.get("text", "")
                for block in blocks
                if isinstance(block, dict) and block.get("type") == "text"
            )
            if args.record:
                with open(args.record, "w", encoding="utf-8", newline="") as handle:
                    handle.write(received)
            if args.plan:
                _materialize_plan(args.plan)

            if scenario == SCENARIO_MALFORMED_JSON:
                emit_raw("{ this is not valid json ]")
                continue
            if scenario == SCENARIO_WRONG_ID:
                emit({"jsonrpc": "2.0", "id": 987654, "result": {"stopReason": "end_turn"}})
                continue
            if scenario == SCENARIO_EOF_BEFORE_TERMINAL:
                emit_update({"sessionUpdate": "agent_message_chunk",
                             "content": {"type": "text", "text": "partial"}})
                return 0
            if scenario in (SCENARIO_HANG, SCENARIO_SPAWN_CHILD):
                # Never answer: only the client's hard timeout can end this, and
                # for SPAWN_CHILD the grandchild must die with the tree.
                while True:
                    time.sleep(0.2)
            if scenario == SCENARIO_ECHO_PROMPT:
                # Exactly what the real server does: it echoes the user message
                # back as a session/update before answering.
                emit_update({"sessionUpdate": "user_message_chunk",
                             "content": {"type": "text", "text": received}})
            if scenario == SCENARIO_OVERFLOW:
                chunk = "x" * 65536
                written = 0
                while written < args.overflow_bytes:
                    emit_update({"sessionUpdate": "agent_message_chunk",
                                 "content": {"type": "text", "text": chunk}})
                    written += len(chunk)
            if scenario == SCENARIO_PERMISSION_REQUEST:
                emit({
                    "jsonrpc": "2.0", "id": "perm-1",
                    "method": "session/request_permission",
                    "params": {"sessionId": SESSION_ID, "options": list(PERMISSION_OPTIONS)},
                })
                reply = read_message()
                if reply is None:
                    return 1
                outcome = (reply.get("result") or {}).get("outcome") or {}
                emit_update({"sessionUpdate": "agent_message_chunk",
                             "content": {"type": "text",
                                         "text": f"permission={outcome.get('optionId')}"}})
            if scenario in (SCENARIO_PERMISSION_SAFE, SCENARIO_PERMISSION_DESTRUCTIVE):
                title = (
                    SAFE_TITLE if scenario == SCENARIO_PERMISSION_SAFE
                    else RUN_003_DESTRUCTIVE_TITLE
                )
                emit({
                    "jsonrpc": "2.0", "id": 7,
                    "method": "session/request_permission",
                    "params": {
                        "sessionId": SESSION_ID,
                        "toolCall": {
                            "toolCallId": "call-fake-0001",
                            "title": title,
                            "kind": "execute",
                            "status": "pending",
                            "content": [{
                                "type": "content",
                                "content": {"type": "text", "text": "Not in allowlist"},
                            }],
                        },
                        "options": list(PERMISSION_OPTIONS),
                    },
                })
                reply = read_message()
                if reply is None:
                    return 1
                outcome = (reply.get("result") or {}).get("outcome") or {}
                emit_update({"sessionUpdate": "agent_message_chunk",
                             "content": {"type": "text",
                                         "text": f"permission={outcome.get('optionId')}"}})
            if scenario in (SCENARIO_UPDATE_TODOS, SCENARIO_MALFORMED_UPDATE_TODOS):
                todos = (
                    [
                        {"id": "1", "content": "Implement domain modules", "status": "in_progress"},
                        {"id": "2", "content": "Implement presentation", "status": "pending"},
                    ]
                    if scenario == SCENARIO_UPDATE_TODOS
                    # An unknown status is exactly what strict validation exists
                    # to refuse; the CLI's own converter emits only four.
                    else [{"id": "1", "content": "Do the thing", "status": "half-done"}]
                )
                emit({
                    "jsonrpc": "2.0", "id": 2, "method": "cursor/update_todos",
                    "params": {
                        "toolCallId": "call-todo-0001", "todos": todos, "merge": False,
                    },
                })
                reply = read_message()
                if reply is None:
                    return 1
                emit_update({"sessionUpdate": "agent_message_chunk",
                             "content": {"type": "text",
                                         "text": f"todos={json.dumps(reply, sort_keys=True)}"}})
            if scenario == SCENARIO_MISSION_LIVENESS:
                if _mission_liveness(scenario, args.probe) != 0:
                    return 1
            if scenario == SCENARIO_MISSION_PLAN_AND_QUESTION:
                reply, terminated = _request("cursor/create_plan", {
                    "toolCallId": "call-plan-0002",
                    "plan": "do the work",
                    "todos": [{"id": "1", "content": "work", "status": "pending"}],
                })
                if terminated:
                    return 1
                _note(f"plan={json.dumps(reply.get('result'), sort_keys=True)}")
                reply, terminated = _request("cursor/ask_question", {
                    "sessionId": SESSION_ID,
                    "toolCallId": "call-ask-0002",
                    "title": "Which visual direction?",
                    "questions": [{
                        "id": "q1",
                        "prompt": "Pick a palette",
                        "options": [
                            {"id": "cyan", "label": "Cyan"},
                            {"id": "magenta", "label": "Magenta"},
                        ],
                        "allowMultiple": False,
                    }],
                })
                if terminated:
                    return 1
                _note(f"question={json.dumps(reply.get('result'), sort_keys=True)}")
            if scenario == SCENARIO_MALFORMED_CREATE_PLAN:
                # An unknown todo status: the CLI's own converter emits exactly
                # four, so anything else is a shape this client cannot trust.
                _request("cursor/create_plan", {
                    "toolCallId": "call-plan-0003",
                    "todos": [{"id": "1", "content": "work", "status": "half-done"}],
                })
                return 1
            if scenario == SCENARIO_MALFORMED_ASK_QUESTION:
                _request("cursor/ask_question", {
                    "toolCallId": "call-ask-0003",
                    "questions": [{"id": "q1", "options": [{"id": "a", "label": "A"}]}],
                })
                return 1
            if scenario == SCENARIO_UNKNOWN_REQUEST:
                # A method the installed CLI really does define but this client
                # has never audited a response shape for.  It must stay
                # unanswerable: the dispatch table grew by exactly the two
                # methods whose shapes were read out of the bundle.
                emit({
                    "jsonrpc": "2.0", "id": 5, "method": UNKNOWN_CURSOR_METHOD,
                    "params": {"toolCallId": "call-task-0001", "title": "anything"},
                })
                reply = read_message()
                if reply is None:
                    return 1

            emit_update({"sessionUpdate": "agent_message_chunk",
                         "content": {"type": "text", "text": "fake acp turn complete"}})
            emit({"jsonrpc": "2.0", "id": message_id, "result": {"stopReason": "end_turn"}})
        elif method == "session/cancel":
            return 0

    if child is not None:
        child.terminate()
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    sys.stdin.reconfigure(encoding="utf-8")
    sys.exit(main())
