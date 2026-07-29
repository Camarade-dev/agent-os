"""Confined runtime for the trusted Codex serialization verifier.

This module is never an authority by itself.  It runs only as the child of
``TrustedSerializationWitnessStore.verify_canary`` inside a new bubblewrap
network/PID/user namespace.  Its output is an untrusted, minimal observation
that the parent validates and durably anchors before returning a verified
receipt.

The child records no prompt, input item, instruction, authorization header,
credential, response body, or unrelated HTTP header.  Synthetic
authentication is generated per run and destroyed with the private temporary
directory.
"""

from __future__ import annotations

import json
import os
import select
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Mapping


_STREAM_FAILURE = (
    b"event: response.failed\r\n"
    b'data: {"type":"response.failed","response":{"error":'
    b'{"code":"admissible_local_refusal","message":"provider-free witness"}}}\n\n'
)


class _LoopbackEndpoint:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.capture: dict[str, Any] | None = None
        self.refusal_sent = False
        self.seen = threading.Event()
        self._closed = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._closed.is_set():
            try:
                connection, _address = self.listener.accept()
            except OSError:
                return
            try:
                self._handle(connection)
            finally:
                try:
                    connection.close()
                except OSError:
                    pass
            return

    def _handle(self, connection: socket.socket) -> None:
        connection.settimeout(15)
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = connection.recv(64 * 1024)
            if not chunk:
                raise RuntimeError("witness request ended before its HTTP headers")
            data.extend(chunk)
            if len(data) > 1024 * 1024:
                raise RuntimeError("witness HTTP headers exceeded their bound")
        head, body_prefix = bytes(data).split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        request_line = lines[0].split(" ")
        if len(request_line) < 2:
            raise RuntimeError("witness HTTP request line is malformed")
        length = 0
        for line in lines[1:]:
            name, separator, value = line.partition(":")
            if separator and name.strip().lower() == "content-length":
                length = int(value.strip())
        if not 1 <= length <= 4 * 1024 * 1024:
            raise RuntimeError("witness HTTP body length is out of bounds")
        body = bytearray(body_prefix)
        while len(body) < length:
            chunk = connection.recv(min(64 * 1024, length - len(body)))
            if not chunk:
                raise RuntimeError("witness HTTP body ended early")
            body.extend(chunk)
        decoded = json.loads(bytes(body[:length]).decode("utf-8"))
        reasoning = decoded.get("reasoning")
        self.capture = {
            "request_path": request_line[1],
            "serialized_model": decoded.get("model"),
            "serialized_reasoning_effort": (
                reasoning.get("effort") if isinstance(reasoning, dict) else None
            ),
        }
        connection.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Connection: close\r\n\r\n"
            + _STREAM_FAILURE
        )
        self.refusal_sent = True
        self.seen.set()

    def close(self) -> None:
        self._closed.set()
        self.listener.close()


def _read_until(
    process: subprocess.Popen[bytes],
    wanted_id: str,
    deadline: float,
) -> Mapping[str, Any] | None:
    if process.stdout is None:
        return None
    while time.monotonic() < deadline:
        ready, _write, _errors = select.select([process.stdout], [], [], 0.5)
        if not ready:
            if process.poll() is not None:
                return None
            continue
        line = process.stdout.readline()
        if not line:
            return None
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("id") == wanted_id:
            return value
    return None


def _network_observation() -> dict[str, Any]:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    probe.listen(1)
    probe.close()
    non_loopback_interfaces = sorted(
        name for _index, name in socket.if_nameindex() if name != "lo"
    )
    non_loopback_routes = 0
    route_file = Path("/proc/net/route")
    if route_file.is_file():
        for line in route_file.read_text(encoding="ascii").splitlines()[1:]:
            fields = line.split()
            if fields and fields[0] != "lo":
                non_loopback_routes += 1
    ipv6_route_file = Path("/proc/net/ipv6_route")
    if ipv6_route_file.is_file():
        for line in ipv6_route_file.read_text(encoding="ascii").splitlines():
            fields = line.split()
            if fields and fields[-1] != "lo":
                non_loopback_routes += 1
    resolver_file = Path("/etc/resolv.conf")
    resolver_size = (
        resolver_file.stat().st_size if resolver_file.exists() else None
    )
    nsswitch = Path("/etc/nsswitch.conf").read_text(encoding="ascii")
    resolver_files_only = nsswitch.splitlines() == ["hosts: files"]
    return {
        "loopback_bind_succeeded": True,
        "non_loopback_interfaces": non_loopback_interfaces,
        "non_loopback_route_entries": non_loopback_routes,
        "public_route_available": bool(
            non_loopback_interfaces or non_loopback_routes
        ),
        "resolver_available": not (
            resolver_size == 0 and resolver_files_only
        ),
        "resolver_file_size": resolver_size,
        "resolver_policy_files_only": resolver_files_only,
    }


def _run(request: Mapping[str, Any]) -> dict[str, Any]:
    codex = Path(request["codex_executable"])
    home = Path(request["codex_home"])
    cwd = Path(request["workspace"])
    home.mkdir(parents=True, exist_ok=False)
    cwd.mkdir(parents=True, exist_ok=False)

    endpoint = _LoopbackEndpoint()
    credential = request["synthetic_credential"]
    environment_key = "ADMISSIBLE_WITNESS_AUTH"
    auth_key = "OPENAI" + "_API_KEY"
    (home / "auth.json").write_text(
        json.dumps({auth_key: credential}, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    selector = (
        '# provider-free verifier local selector\n'
        'model_provider = "admissible-local-witness"\n'
    )
    provider = (
        "\n[model_providers.admissible-local-witness]\n"
        'name = "admissible-local-witness"\n'
        f'base_url = "http://127.0.0.1:{endpoint.port}/v1"\n'
        'wire_api = "responses"\n'
        f'env_key = "{environment_key}"\n'
        "requires_openai_auth = false\n"
    )
    canonical_config = request["canonical_configuration"].encode("utf-8")
    (home / "config.toml").write_bytes(
        selector.encode("utf-8")
        + canonical_config
        + provider.encode("utf-8")
    )

    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": os.fspath(home),
        "CODEX_HOME": os.fspath(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        environment_key: credential,
    }
    process = subprocess.Popen(
        (os.fspath(codex), "app-server", "--stdio"),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        cwd=os.fspath(cwd),
        env=environment,
    )
    deadline = time.monotonic() + request["timeout_seconds"]
    result: dict[str, Any] = {
        "witness_run_identity": request["witness_run_identity"],
        "witness_run_nonce": request["witness_run_nonce"],
        "network_observation": _network_observation(),
        "codex_process_pid": process.pid,
    }
    try:
        if process.stdin is None:
            raise RuntimeError("Codex witness stdin is unavailable")

        def send(value: Mapping[str, Any]) -> None:
            process.stdin.write(
                (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")
            )
            process.stdin.flush()

        send(
            {
                "id": "initialize",
                "method": "initialize",
                "params": request["initialize_params"],
            }
        )
        initialized = _read_until(process, "initialize", deadline)
        if initialized is None or "result" not in initialized:
            raise RuntimeError("pinned Codex initialize did not complete")
        send({"method": "initialized", "params": {}})
        thread_params = dict(request["thread_start_params"])
        thread_params["cwd"] = os.fspath(cwd)
        send({"id": "thread", "method": "thread/start", "params": thread_params})
        thread_response = _read_until(process, "thread", deadline)
        if thread_response is None or "result" not in thread_response:
            raise RuntimeError("pinned Codex thread/start did not complete")
        thread_result = thread_response["result"]
        result["effective_thread_start_model"] = thread_result.get("model")
        result["effective_thread_start_reasoning_effort"] = thread_result.get(
            "reasoningEffort"
        )
        turn_params = dict(request["turn_start_params"])
        turn_params["threadId"] = thread_result["thread"]["id"]
        turn_params["input"] = [{"type": "text", "text": "provider-free witness"}]
        send({"id": "turn", "method": "turn/start", "params": turn_params})
        turn_response = _read_until(process, "turn", deadline)
        if turn_response is None:
            raise RuntimeError("pinned Codex turn/start did not respond")
        if not endpoint.seen.wait(max(0.1, deadline - time.monotonic())):
            raise RuntimeError("pinned Codex serialized no captured request")
        result["captured_request"] = endpoint.capture
        result["synthetic_refusal_sent"] = endpoint.refusal_sent
    finally:
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        process.terminate()
        forced = False
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            forced = True
            process.kill()
            process.wait(timeout=5)
        result["process_terminal"] = {
            "returncode": process.returncode,
            "verifier_forced_kill": forced,
            "classification": (
                "VERIFIER_FORCED_KILL"
                if forced
                else "TERMINATED_AFTER_SYNTHETIC_REFUSAL"
            ),
        }
        if process.stdout is not None:
            process.stdout.close()
        endpoint.close()
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        raise SystemExit("usage: serialization_witness_runtime REQUEST OUTPUT")
    request = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    output = _run(request)
    Path(argv[2]).write_text(
        json.dumps(output, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
