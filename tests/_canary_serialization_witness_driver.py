"""In-namespace driver for the provider-free Codex serialization witness.

Runs inside a private routeless network namespace created by bubblewrap.  It
starts a loopback-only synthetic ChatGPT-compatible ``/v1/responses`` endpoint,
drives the real pinned Codex 0.145.0 app server through
``initialize`` / ``thread/start`` / ``turn/start`` with request parameters
supplied by the caller, and reports only the non-secret request metadata the
witness policy allows: the request path, the serialized ``model`` and the
serialized ``reasoning.effort``.

Nothing else from the captured request is retained: no prompt text, no input
items, no instructions, no headers, no synthetic token contents and no
response body.  The endpoint answers every request with a terminal synthetic
stream failure so no model or provider work can occur.

This file is a test helper, not a test module, and is never packaged.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path


SYNTHETIC_KEY = "synthetic-provider-free-key"
SYNTHETIC_AUTH = json.dumps({"OPENAI_API_KEY": SYNTHETIC_KEY}) + "\n"
STREAM_FAILURE = (
    b"event: response.failed\r\n"
    b'data: {"type":"response.failed","response":{"error":'
    b'{"code":"synthetic","message":"provider-free witness"}}}\n\n'
)


class WitnessEndpoint:
    """Loopback-only synthetic responses endpoint with a minimal capture."""

    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.port = self.listener.getsockname()[1]
        self.captures: list[dict] = []
        self.seen = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(
                target=self._handle, args=(connection,), daemon=True
            ).start()

    def _handle(self, connection: socket.socket) -> None:
        connection.settimeout(15)
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = connection.recv(65536)
                if not chunk:
                    return
                data += chunk
            head, rest = data.split(b"\r\n\r\n", 1)
            lines = head.decode("latin-1").split("\r\n")
            path = lines[0].split(" ")[1] if " " in lines[0] else "/"
            length = 0
            for line in lines[1:]:
                name, _, value = line.partition(":")
                if name.strip().lower() == "content-length":
                    length = int(value.strip())
            while len(rest) < length:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                rest += chunk
            body = json.loads(rest[:length].decode("utf-8"))
            reasoning = body.get("reasoning")
            self.captures.append(
                {
                    "request_path": path,
                    "model": body.get("model"),
                    "reasoning_effort": (
                        reasoning.get("effort")
                        if isinstance(reasoning, dict)
                        else None
                    ),
                }
            )
            self.seen.set()
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                b"Connection: close\r\n\r\n" + STREAM_FAILURE
            )
        except Exception as error:  # noqa: BLE001
            self.captures.append({"endpoint_error": type(error).__name__})
            self.seen.set()
        finally:
            try:
                connection.close()
            except OSError:
                pass

    def reset(self) -> None:
        self.captures = []
        self.seen.clear()

    def close(self) -> None:
        self._stop.set()
        self.listener.close()


def _read_until(process, wanted_id, timeout_deadline):
    import select
    import time

    records = []
    while time.monotonic() < timeout_deadline:
        ready, _, _ = select.select([process.stdout], [], [], 0.5)
        if not ready:
            continue
        line = process.stdout.readline()
        if not line:
            break
        try:
            record = json.loads(line)
        except ValueError:
            continue
        records.append(record)
        if record.get("id") == wanted_id:
            return record, records
    return None, records


def run_scenario(*, codex, home, cwd, endpoint, scenario, timeout_seconds):
    import time

    endpoint.reset()
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": os.fspath(home),
        "CODEX_HOME": os.fspath(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "SYNTHETIC_API_KEY": SYNTHETIC_KEY,
    }
    process = subprocess.Popen(
        [os.fspath(codex), "app-server", "--stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=environment,
        cwd=os.fspath(cwd),
    )
    deadline = time.monotonic() + timeout_seconds
    result = {"scenario": scenario["name"]}
    try:

        def send(message):
            process.stdin.write((json.dumps(message) + "\n").encode("utf-8"))
            process.stdin.flush()

        send(
            {
                "id": "initialize",
                "method": "initialize",
                "params": scenario["initialize_params"],
            }
        )
        initialized, _ = _read_until(process, "initialize", deadline)
        if initialized is None or "result" not in initialized:
            result["startup_error"] = "initialize did not complete"
            return result
        send({"method": "initialized", "params": {}})
        thread_params = dict(scenario["thread_params"])
        thread_params["cwd"] = os.fspath(cwd)
        send({"id": "thread", "method": "thread/start", "params": thread_params})
        thread_response, _ = _read_until(process, "thread", deadline)
        if thread_response is None:
            result["startup_error"] = "thread/start did not complete"
            return result
        if "error" in thread_response:
            result["thread_start_error"] = thread_response["error"].get("message", "")
            return result
        thread_result = thread_response["result"]
        result["thread_start_model"] = thread_result.get("model")
        result["thread_start_reasoning_effort"] = thread_result.get("reasoningEffort")
        turn_params = dict(scenario["turn_params"])
        turn_params["threadId"] = thread_result["thread"]["id"]
        turn_params["input"] = [{"type": "text", "text": "witness"}]
        send({"id": "turn", "method": "turn/start", "params": turn_params})
        turn_response, _ = _read_until(process, "turn", deadline)
        if turn_response is not None and "error" in turn_response:
            result["turn_start_error"] = turn_response["error"].get("message", "")
            return result
        endpoint.seen.wait(timeout=max(1.0, deadline - time.monotonic()))
        result["captures"] = list(endpoint.captures[:1])
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
        if process.stdin:
            process.stdin.close()
        if process.stdout:
            process.stdout.close()
    return result


def main(argv):
    codex = Path(argv[1])
    home = Path(argv[2])
    cwd = Path(argv[3])
    request = json.loads(Path(argv[4]).read_text(encoding="utf-8"))
    output = Path(argv[5])

    home.mkdir(parents=True, exist_ok=True)
    cwd.mkdir(parents=True, exist_ok=True)
    (home / "auth.json").write_text(SYNTHETIC_AUTH, encoding="utf-8")

    endpoint = WitnessEndpoint()
    try:
        # TOML is order sensitive: the loopback provider selector must precede
        # the canonical tables, and its own table must follow all of them.
        selector = '# witness-only loopback provider\nmodel_provider = "synthetic-loopback"\n'
        provider_table = (
            "\n[model_providers.synthetic-loopback]\n"
            'name = "synthetic-loopback"\n'
            f'base_url = "http://127.0.0.1:{endpoint.port}/v1"\n'
            'wire_api = "responses"\n'
            'env_key = "SYNTHETIC_API_KEY"\n'
            "requires_openai_auth = false\n"
        )
        canonical = request["canonical_config"].encode("utf-8")
        (home / "config.toml").write_bytes(
            selector.encode("utf-8") + canonical + provider_table.encode("utf-8")
        )
        results = {
            "endpoint_port": endpoint.port,
            "canonical_config_sha256_prefix_bytes": len(canonical),
            "scenarios": [],
        }
        for scenario in request["scenarios"]:
            results["scenarios"].append(
                run_scenario(
                    codex=codex,
                    home=home,
                    cwd=cwd,
                    endpoint=endpoint,
                    scenario=scenario,
                    timeout_seconds=request.get("timeout_seconds", 40),
                )
            )
    finally:
        endpoint.close()
    output.write_text(json.dumps(results), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
