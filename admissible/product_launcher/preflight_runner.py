"""Bounded managed child for canonical G1 preflight_only invocation."""
from __future__ import annotations

import argparse
import os
import sys
import threading
from pathlib import Path
from typing import Callable, Mapping

from admissible.delegated_gate.native_canary import run_native_mission_application
from admissible.delegated_gate.native_executor import DEFAULT_ENVIRONMENT_ALLOWLIST
from admissible.managed_process import (
    ManagedProcess,
    TERMINATION_CANCELLED,
    TERMINATION_CLEANUP_FAILED,
    TERMINATION_COMPLETED,
    TERMINATION_HARD_TIMEOUT,
)

WRAPPER_ARGUMENT_ERROR = 64
WRAPPER_INTERNAL_ERROR = 67


class PreflightChildFault(RuntimeError):
    pass


class PreflightChildTimedOut(RuntimeError):
    pass


class PreflightChildCancelled(RuntimeError):
    pass


class PreflightChildCleanupFailed(RuntimeError):
    pass


class _QuietParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def _curated_environment(parent: Mapping[str, str]) -> dict[str, str]:
    allowed = {name.upper() for name in DEFAULT_ENVIRONMENT_ALLOWLIST}
    child = {key: value for key, value in parent.items() if key.upper() in allowed}
    child["PYTHONDONTWRITEBYTECODE"] = "1"
    return child


class ProductionPreflightApplication:
    """Spawn one no-secret preflight child and return ``(code, stdout_bytes)``."""

    def __init__(
        self,
        *,
        process_factory: Callable[..., ManagedProcess] = ManagedProcess,
        child_argv: tuple[str, ...] | None = None,
    ):
        self._process_factory = process_factory
        self._child_argv = child_argv
        self._lock = threading.RLock()
        self._process_lock = threading.Lock()
        self._active: ManagedProcess | None = None
        self._closing = False

    def __call__(
        self,
        *,
        profile_document: str | Path,
        source_repository: str | Path,
        required_source_head: str,
        run_root: str | Path,
        run_id: str,
        session_id: str,
        executable: str,
        authority_timeout_seconds: int,
        authority_stdout_byte_limit: int,
        authority_stderr_byte_limit: int,
        process_timeout_seconds: int,
        process_stdout_capture_limit: int,
        process_stderr_capture_limit: int,
        executable_prefix_args: tuple[str, ...] = (),
        model: str | None = None,
        attestation_class: str = "package-bin",
        **_unused: object,
    ) -> tuple[int, bytes]:
        argv = [
            sys.executable,
            "-m",
            "admissible.product_launcher.preflight_runner",
            "--source-repository",
            str(source_repository),
            "--required-source-head",
            required_source_head,
            "--run-root",
            str(run_root),
            "--run-id",
            run_id,
            "--session-id",
            session_id,
            "--executable",
            executable,
            "--profile-document",
            str(profile_document),
            "--attestation-class",
            attestation_class,
        ]
        if self._child_argv is not None:
            argv = list(self._child_argv)
        else:
            for value in executable_prefix_args:
                argv.extend(("--executable-prefix-arg", value))
            for flag, value in (
                ("--model", model),
                ("--timeout-seconds", authority_timeout_seconds),
                ("--stdout-byte-limit", authority_stdout_byte_limit),
                ("--stderr-byte-limit", authority_stderr_byte_limit),
            ):
                if value is not None:
                    argv.extend((flag, str(value)))
        capture = max(
            int(process_stdout_capture_limit),
            int(process_stderr_capture_limit),
            1024,
        )
        environment = _curated_environment(os.environ)
        proc = self._process_factory(
            argv,
            cwd=str(Path(__file__).resolve().parents[2]),
            env=environment,
            want_stdin=False,
            max_capture_bytes=capture,
        )
        try:
            with self._lock:
                if self._closing:
                    raise RuntimeError("preflight launcher closed")
                proc.start()
                self._active = proc
            code = proc.wait(timeout=float(process_timeout_seconds))
            with self._process_lock:
                result = (
                    proc.terminate(reason=TERMINATION_HARD_TIMEOUT)
                    if code is None and proc.poll() is None
                    else proc.finish(reason=TERMINATION_COMPLETED)
                )
            with self._lock:
                cancellation_requested = self._closing
            if not result.cleanup_proven or result.termination_reason == TERMINATION_CLEANUP_FAILED:
                raise PreflightChildCleanupFailed()
            if cancellation_requested:
                raise PreflightChildCancelled()
            if result.termination_reason == TERMINATION_HARD_TIMEOUT:
                raise PreflightChildTimedOut()
            if result.termination_reason == TERMINATION_CANCELLED:
                raise PreflightChildCancelled()
            if result.termination_reason != TERMINATION_COMPLETED:
                raise PreflightChildFault()
            actual = result.exit_code if result.exit_code is not None else code
            if actual is None:
                raise PreflightChildFault()
            stdout_text = proc.captured_stdout()
            try:
                stdout = stdout_text.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise PreflightChildFault() from exc
            return int(actual), stdout
        finally:
            with self._lock:
                if self._active is proc:
                    self._active = None

    def terminate_active(self) -> None:
        with self._lock:
            self._closing = True
            proc = self._active
        if proc is not None:
            with self._process_lock:
                result = proc.terminate(reason=TERMINATION_CANCELLED)
            if not result.cleanup_proven:
                raise PreflightChildCleanupFailed()


def _parser() -> argparse.ArgumentParser:
    parser = _QuietParser(add_help=False)
    for name in (
        "source-repository",
        "required-source-head",
        "run-root",
        "run-id",
        "session-id",
        "executable",
        "profile-document",
        "attestation-class",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--executable-prefix-arg", action="append", default=[])
    parser.add_argument("--model")
    for name in ("timeout-seconds", "stdout-byte-limit", "stderr-byte-limit"):
        parser.add_argument("--" + name, type=int)
    return parser


def preflight_main(
    argv: list[str] | None = None,
    *,
    application: Callable[..., int] = run_native_mission_application,
) -> int:
    try:
        args = _parser().parse_args(argv)
    except (SystemExit, ValueError):
        return WRAPPER_ARGUMENT_ERROR
    try:
        return int(
            application(
                source_repository=args.source_repository,
                required_source_head=args.required_source_head,
                run_root=args.run_root,
                run_id=args.run_id,
                session_id=args.session_id,
                executable=args.executable,
                profile_document=args.profile_document,
                executable_prefix_args=tuple(args.executable_prefix_arg),
                model=args.model,
                timeout_seconds=args.timeout_seconds,
                stdout_byte_limit=args.stdout_byte_limit,
                stderr_byte_limit=args.stderr_byte_limit,
                attestation_class=args.attestation_class,
                preflight_only=True,
            )
        )
    except Exception:
        return WRAPPER_INTERNAL_ERROR


if __name__ == "__main__":
    sys.exit(preflight_main())

__all__ = [
    "PreflightChildCancelled",
    "PreflightChildCleanupFailed",
    "PreflightChildFault",
    "PreflightChildTimedOut",
    "ProductionPreflightApplication",
    "preflight_main",
]
