"""Unit tests for the RUN_046 callable-backend diagnostic harness.

Every test here uses a fake ``subprocess.Popen`` (never a real Cursor CLI or
any other real subprocess) and a fake ``psutil`` process tree where relevant,
per the RUN_046 hard constraint that the ordinary unit-test suite never makes
a provider/model call.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from admissible.diagnostics import callable_backend_probe as cbp


class _FakeStream:
    """Deterministic, non-blocking stand-in for a subprocess pipe."""

    def __init__(self, lines: list[str] | None = None) -> None:
        self._lines = list(lines or [])
        self._idx = 0
        self.closed = False

    def readline(self) -> str:
        if self._idx < len(self._lines):
            line = self._lines[self._idx]
            self._idx += 1
            return line
        return ""

    def close(self) -> None:
        self.closed = True

    def write(self, data: str) -> int:
        return len(data)

    def flush(self) -> None:
        pass


class _FakeProcess:
    """Deterministic stand-in for ``subprocess.Popen``'s return value."""

    def __init__(
        self,
        *,
        pid: int = 424242,
        exit_code: int | None = 0,
        stdout_lines: list[str] | None = None,
        stderr_lines: list[str] | None = None,
        raise_timeout_times: int = 0,
    ) -> None:
        self.pid = pid
        self._exit_code = exit_code
        self.stdout = _FakeStream(stdout_lines)
        self.stderr = _FakeStream(stderr_lines)
        self.stdin = _FakeStream([])
        self._raise_timeout_times = raise_timeout_times
        self._wait_calls = 0
        self.kill_calls = 0

    def wait(self, timeout: float | None = None) -> int:
        self._wait_calls += 1
        if self._wait_calls <= self._raise_timeout_times:
            raise subprocess.TimeoutExpired(cmd=["fake"], timeout=timeout)
        return self._exit_code if self._exit_code is not None else 0

    def poll(self) -> int | None:
        return self._exit_code

    def kill(self) -> None:
        self.kill_calls += 1


def _patched_popen(fake_process: _FakeProcess | Exception):
    def _factory(*args, **kwargs):
        if isinstance(fake_process, Exception):
            raise fake_process
        return fake_process

    return _factory


class LowLevelCaptureTests(unittest.TestCase):
    """PART K.28: success/empty/partial-timeout/no-output-timeout/nonzero/delayed."""

    def _capture(self, fake_process, *, timeout_seconds=5.0):
        with patch("subprocess.Popen", side_effect=_patched_popen(fake_process)):
            with tempfile.TemporaryDirectory() as tmp:
                return cbp._run_with_incremental_capture(
                    ["fake-cursor-agent"], cwd=tmp, env={}, timeout_seconds=timeout_seconds
                )

    def test_success_with_output(self) -> None:
        fake = _FakeProcess(exit_code=0, stdout_lines=["hello world\n"])
        result = self._capture(fake)
        self.assertFalse(result.timed_out)
        self.assertEqual(result.process_exit_code, 0)
        self.assertEqual(result.stdout, "hello world\n")
        self.assertIsNotNone(result.first_stdout_byte_at)
        self.assertIsNone(result.wrapper_error)
        self.assertEqual(cbp._classify(result, result.stdout.strip()), cbp.PROBE_STATUS_SUCCESS)

    def test_exit_zero_empty_output(self) -> None:
        fake = _FakeProcess(exit_code=0, stdout_lines=[])
        result = self._capture(fake)
        self.assertFalse(result.timed_out)
        self.assertEqual(result.stdout, "")
        self.assertIsNone(result.first_stdout_byte_at)
        self.assertEqual(cbp._classify(result, None), cbp.PROBE_STATUS_EMPTY_SUCCESS)

    def test_partial_output_then_timeout(self) -> None:
        fake = _FakeProcess(stdout_lines=["partial chunk\n"], raise_timeout_times=1)
        result = self._capture(fake)
        self.assertTrue(result.timed_out)
        self.assertIn("partial chunk", result.stdout)
        self.assertEqual(
            cbp._classify(result, None), cbp.PROBE_STATUS_TIMEOUT_AFTER_PARTIAL_OUTPUT
        )

    def test_no_output_then_timeout(self) -> None:
        fake = _FakeProcess(stdout_lines=[], stderr_lines=[], raise_timeout_times=1)
        result = self._capture(fake)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            cbp._classify(result, None), cbp.PROBE_STATUS_TIMEOUT_BEFORE_ANY_OUTPUT
        )

    def test_nonzero_exit(self) -> None:
        fake = _FakeProcess(exit_code=3, stdout_lines=[], stderr_lines=["boom\n"])
        result = self._capture(fake)
        self.assertEqual(result.process_exit_code, 3)
        self.assertEqual(cbp._classify(result, None), cbp.PROBE_STATUS_NONZERO_EXIT)

    def test_delayed_output_still_recorded(self) -> None:
        # Even though our fake stream is non-blocking, the harness must still
        # populate first-byte timing the moment content is observed.
        fake = _FakeProcess(exit_code=0, stdout_lines=["late line\n"])
        result = self._capture(fake)
        self.assertIsNotNone(result.first_stdout_byte_elapsed_ms)
        self.assertGreaterEqual(result.first_stdout_byte_elapsed_ms, 0.0)

    def test_wrapper_failure_when_spawn_raises(self) -> None:
        result = self._capture(FileNotFoundError("no such file"))
        self.assertFalse(result.process_started)
        self.assertIsNotNone(result.wrapper_error)
        self.assertEqual(cbp._classify(result, None), cbp.PROBE_STATUS_WRAPPER_FAILURE)


class RedactionTests(unittest.TestCase):
    def test_short_text_untouched(self) -> None:
        self.assertEqual(cbp._redact_preview("short"), "short")

    def test_long_text_truncated_deterministically(self) -> None:
        text = "x" * 1000
        preview = cbp._redact_preview(text, max_chars=50)
        self.assertTrue(preview.startswith("x" * 50))
        self.assertIn("truncated", preview)
        self.assertLess(len(preview), len(text))

    def test_none_passthrough(self) -> None:
        self.assertIsNone(cbp._redact_preview(None))


class ProcessTreeKillTests(unittest.TestCase):
    """PART K.28: wrapper child cleanup."""

    def test_tree_kill_reports_full_termination(self) -> None:
        fake_root = MagicMock(pid=111)
        fake_child = MagicMock(pid=222)
        fake_root.children.return_value = [fake_child]
        fake_root.name.return_value = "cmd.exe"
        fake_root.status.return_value = "running"
        fake_child.name.return_value = "node.exe"
        fake_child.status.return_value = "running"

        fake_psutil = MagicMock()
        fake_psutil.Process.return_value = fake_root
        fake_psutil.wait_procs.return_value = ([fake_root, fake_child], [])
        fake_psutil.Error = Exception
        fake_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        with patch.object(cbp, "psutil", fake_psutil):
            snapshot = cbp.tree_kill(111)

        self.assertEqual(snapshot.observed_via, "psutil")
        self.assertTrue(snapshot.all_terminated)
        self.assertEqual(len(snapshot.survivors_after_cleanup), 0)
        fake_root.kill.assert_called_once()
        fake_child.kill.assert_called_once()

    def test_tree_kill_reports_survivors(self) -> None:
        fake_root = MagicMock(pid=111)
        fake_root.children.return_value = []
        fake_root.name.return_value = "cmd.exe"
        fake_root.status.return_value = "running"

        fake_psutil = MagicMock()
        fake_psutil.Process.return_value = fake_root
        fake_psutil.wait_procs.return_value = ([], [fake_root])
        fake_psutil.Error = Exception
        fake_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        with patch.object(cbp, "psutil", fake_psutil):
            snapshot = cbp.tree_kill(111)

        self.assertFalse(snapshot.all_terminated)
        self.assertEqual(len(snapshot.survivors_after_cleanup), 1)

    def test_tree_kill_unavailable_without_psutil(self) -> None:
        with patch.object(cbp, "psutil", None):
            snapshot = cbp.tree_kill(999)
        self.assertEqual(snapshot.observed_via, "unavailable")
        self.assertIsNone(snapshot.all_terminated)


class HarnessBudgetAndSerialTests(unittest.TestCase):
    """PART K.28: invocation-budget enforcement, no automatic retry, serial-only."""

    def test_budget_enforced_across_direct_probes(self) -> None:
        fake = _FakeProcess(exit_code=0, stdout_lines=["ADMISSIBLE_PROBE_OK\n"])
        with tempfile.TemporaryDirectory() as tmp:
            harness = cbp.CallableBackendProbeHarness(max_real_invocations=1, workspace_root=tmp)
            with patch("subprocess.Popen", side_effect=_patched_popen(fake)):
                with patch.object(cbp.shutil, "which", return_value=None):
                    harness.run_direct_probe(
                        label="pair1", instruction_text="hi", command="C:/fake/cursor-agent.cmd"
                    )
                    with self.assertRaises(cbp.InvocationBudgetExceeded):
                        harness.run_direct_probe(
                            label="pair2", instruction_text="hi", command="C:/fake/cursor-agent.cmd"
                        )
        self.assertEqual(harness.used_real_invocations, 1)

    def test_no_automatic_retry_single_popen_call_on_timeout(self) -> None:
        fake = _FakeProcess(raise_timeout_times=1)
        with tempfile.TemporaryDirectory() as tmp:
            harness = cbp.CallableBackendProbeHarness(max_real_invocations=6, workspace_root=tmp)
            with patch("subprocess.Popen", side_effect=_patched_popen(fake)) as popen_mock:
                report = harness.run_direct_probe(
                    label="pair1",
                    instruction_text="hi",
                    command="C:/fake/cursor-agent.cmd",
                    timeout_seconds=1.0,
                )
        self.assertEqual(popen_mock.call_count, 1)
        self.assertTrue(report.timed_out)
        self.assertEqual(harness.used_real_invocations, 1)

    def test_serial_guard_rejects_reentrant_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            harness = cbp.CallableBackendProbeHarness(max_real_invocations=6, workspace_root=tmp)
            harness._begin(consumes_budget=False)
            try:
                with self.assertRaises(cbp.ProbeAlreadyRunning):
                    harness.run_direct_probe(
                        label="reentrant", instruction_text="hi", command="C:/fake/cursor-agent.cmd"
                    )
            finally:
                harness._end(consumes_budget=False)

    def test_acp_handshake_does_not_consume_budget(self) -> None:
        fake = _FakeProcess(
            exit_code=0,
            stdout_lines=['{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": 1}}\n'],
        )
        with tempfile.TemporaryDirectory() as tmp:
            harness = cbp.CallableBackendProbeHarness(max_real_invocations=6, workspace_root=tmp)
            with patch("subprocess.Popen", side_effect=_patched_popen(fake)):
                with patch.object(cbp, "tree_kill", return_value=cbp.ProcessTreeSnapshot(observed_via="unavailable", root_pid=fake.pid)):
                    record = harness.run_acp_handshake_probe(
                        command="C:/fake/cursor-agent.cmd", timeout_seconds=2.0
                    )
        self.assertEqual(harness.used_real_invocations, 0)
        self.assertTrue(record["acp_server_started"])
        self.assertTrue(record["response_line_received"])
        self.assertTrue(record["response_is_valid_jsonrpc"])
        self.assertTrue(record["response_id_matches_request"])

    def test_direct_probe_reports_wrapper_failure_when_command_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            harness = cbp.CallableBackendProbeHarness(max_real_invocations=6, workspace_root=tmp)
            with patch.object(cbp.shutil, "which", return_value=None):
                report = harness.run_direct_probe(label="pair1", instruction_text="hi", command=None)
        self.assertEqual(report.classification, cbp.PROBE_STATUS_WRAPPER_FAILURE)
        self.assertFalse(report.process_started)
        # A wrapper failure still consumes the budget: it was a real attempted invocation.
        self.assertEqual(harness.used_real_invocations, 1)


class AdapterProbeTests(unittest.TestCase):
    """The adapter path must drive the real production CursorCliAgentBackend."""

    def test_adapter_probe_success_uses_production_argv_building(self) -> None:
        fake = _FakeProcess(exit_code=0, stdout_lines=["ADMISSIBLE_PROBE_MEDIUM_OK\n"])
        with tempfile.TemporaryDirectory() as tmp:
            dummy_command = Path(tmp) / "cursor-agent.cmd"
            dummy_command.write_text("@echo off\n", encoding="utf-8")
            harness = cbp.CallableBackendProbeHarness(max_real_invocations=6, workspace_root=tmp)
            with patch("subprocess.Popen", side_effect=_patched_popen(fake)):
                report = harness.run_adapter_probe(
                    label="pair1", instruction_text="hi", command=str(dummy_command)
                )
        self.assertEqual(report.classification, cbp.PROBE_STATUS_SUCCESS)
        self.assertEqual(report.adapter_invoke_status, "success")
        self.assertTrue(report.usable_response_detected)

    def test_adapter_probe_timeout_raises_timeoutexpired_through_runner(self) -> None:
        fake = _FakeProcess(raise_timeout_times=1)
        with tempfile.TemporaryDirectory() as tmp:
            dummy_command = Path(tmp) / "cursor-agent.cmd"
            dummy_command.write_text("@echo off\n", encoding="utf-8")
            harness = cbp.CallableBackendProbeHarness(max_real_invocations=6, workspace_root=tmp)
            with patch("subprocess.Popen", side_effect=_patched_popen(fake)):
                report = harness.run_adapter_probe(
                    label="pair1",
                    instruction_text="hi",
                    command=str(dummy_command),
                    timeout_seconds=1.0,
                )
        self.assertEqual(report.adapter_invoke_status, "timeout")
        self.assertTrue(report.timed_out)


if __name__ == "__main__":
    unittest.main()
