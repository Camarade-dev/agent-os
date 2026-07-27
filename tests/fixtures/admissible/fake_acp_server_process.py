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

SESSION_ID = "sess-fake-native-0001"


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", default=SCENARIO_SUCCESS)
    parser.add_argument("--record", default=None)
    parser.add_argument("--overflow-bytes", type=int, default=2_000_000)
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
                    "params": {
                        "sessionId": SESSION_ID,
                        "options": [
                            {"optionId": "allow-once", "name": "Allow once", "kind": "allow_once"},
                            {"optionId": "allow-always", "name": "Allow always", "kind": "allow_always"},
                            {"optionId": "reject-once", "name": "Reject", "kind": "reject_once"},
                        ],
                    },
                })
                reply = read_message()
                if reply is None:
                    return 1
                outcome = (reply.get("result") or {}).get("outcome") or {}
                emit_update({"sessionUpdate": "agent_message_chunk",
                             "content": {"type": "text",
                                         "text": f"permission={outcome.get('optionId')}"}})

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
