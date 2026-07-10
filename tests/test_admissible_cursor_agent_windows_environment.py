"""Slice ADMISSIBLE_RUN_036 — Windows-safe Cursor Agent subprocess environment.

Verifies the allowlisted Windows/profile environment builder, nested ``%NAME%``
expansion, unresolved-token blocking, secret exclusion, probe parity, and that
no literal ``%SystemDrive%`` path segments reach subprocess invocation.

No real Cursor Agent invocation; subprocess is injected/mocked.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.agent_backend import (
    AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
    AGENT_INVOKE_SUCCESS,
    AgentInvocationRequest,
    CursorCliAgentBackend,
    CursorCliConfig,
    build_cursor_agent_safe_environment,
    probe_cursor_agent_cli_environment,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


class _FakeCompleted:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _windows_like_env(**overrides: str) -> dict[str, str]:
    base = {
        "PATH": r"C:\Windows\system32;C:\Windows",
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "COMSPEC": r"C:\Windows\system32\cmd.exe",
        "SystemRoot": r"C:\Windows",
        "WINDIR": r"C:\Windows",
        "SystemDrive": "C:",
        "USERPROFILE": r"C:\Users\testuser",
        "HOMEDRIVE": "C:",
        "HOMEPATH": r"\Users\testuser",
        "APPDATA": r"C:\Users\testuser\AppData\Roaming",
        "LOCALAPPDATA": r"C:\Users\testuser\AppData\Local",
        "ProgramData": r"%SystemDrive%\ProgramData",
        "ALLUSERSPROFILE": r"C:\ProgramData",
        "PUBLIC": r"C:\Users\Public",
        "TEMP": r"C:\Users\testuser\AppData\Local\Temp",
        "TMP": r"C:\Users\testuser\AppData\Local\Temp",
        "OPENAI_API_KEY": "sk-secret-should-not-forward",
        "CURSOR_API_KEY": "cursor-secret-should-not-forward",
        "RANDOM_APP_SETTING": "keep-out",
    }
    base.update(overrides)
    return base


class TestWindowsSafeEnvironmentBuilder(unittest.TestCase):
    def test_preserves_required_windows_profile_variables(self) -> None:
        env, diag = build_cursor_agent_safe_environment(_windows_like_env())
        self.assertIsNotNone(env)
        assert env is not None
        for key in (
            "PATH",
            "PATHEXT",
            "COMSPEC",
            "SystemRoot",
            "SystemDrive",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "ProgramData",
            "ALLUSERSPROFILE",
            "PUBLIC",
            "TEMP",
            "TMP",
        ):
            self.assertIn(key, env, msg=f"missing {key}")
        self.assertEqual(diag["environment_status"], "ok")
        self.assertTrue(diag["cursor_profile_environment_present"])
        self.assertTrue(diag["program_data_path_present"])

    def test_case_insensitive_lookup_uses_canonical_names(self) -> None:
        source = _windows_like_env(appdata=r"C:\Users\testuser\AppData\Roaming")
        source["appdata"] = source.pop("APPDATA")
        source["systemdrive"] = source.pop("SystemDrive")
        env, _diag = build_cursor_agent_safe_environment(source)
        self.assertIsNotNone(env)
        assert env is not None
        self.assertIn("APPDATA", env)
        self.assertIn("SystemDrive", env)
        self.assertNotIn("appdata", env)
        self.assertNotIn("systemdrive", env)

    def test_program_data_expands_system_drive_reference(self) -> None:
        env, diag = build_cursor_agent_safe_environment(_windows_like_env())
        self.assertIsNotNone(env)
        assert env is not None
        self.assertEqual(env["ProgramData"], r"C:\ProgramData")
        self.assertNotIn("%SystemDrive%", env["ProgramData"])
        self.assertEqual(diag["environment_paths"]["ProgramData"], r"C:\ProgramData")

    def test_unresolved_token_blocks_environment(self) -> None:
        env, diag = build_cursor_agent_safe_environment(
            _windows_like_env(ProgramData=r"%MissingDrive%\ProgramData")
        )
        self.assertIsNone(env)
        self.assertEqual(diag["environment_status"], "blocked")
        self.assertIn("MissingDrive", diag["unresolved_environment_variables"])

    def test_secret_like_variables_are_excluded(self) -> None:
        env, _diag = build_cursor_agent_safe_environment(_windows_like_env())
        self.assertIsNotNone(env)
        assert env is not None
        for forbidden in ("OPENAI_API_KEY", "CURSOR_API_KEY", "RANDOM_APP_SETTING"):
            self.assertNotIn(forbidden, env)

    def test_expansion_is_bounded(self) -> None:
        cyclic = _windows_like_env(TEMP=" %TMP%\\foo ", TMP=" %TEMP%\\bar ")
        env, diag = build_cursor_agent_safe_environment(cyclic)
        # Cyclic refs leave unresolved tokens — must block, not infinite-loop.
        self.assertIsNone(env)
        self.assertEqual(diag["environment_status"], "blocked")


class TestCursorAgentInvocationEnvironment(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.fake = self.tmp / "cursor-agent"
        self.fake.write_text("@echo off\n", encoding="utf-8")
        self.target = self.tmp / "project"
        self.target.mkdir()
        self.agent_ws = self.target / ".admissible" / "agent_workspace"
        self.agent_ws.mkdir(parents=True)
        self.config = CursorCliConfig.cursor_agent_preset(command=str(self.fake))
        self.win_env = _windows_like_env()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_invoke_blocks_when_environment_unresolved(self) -> None:
        bad_env = _windows_like_env(ProgramData=r"%MissingRoot%\ProgramData")
        backend = CursorCliAgentBackend(
            config=self.config,
            env=bad_env,
            runner=lambda *a, **k: _FakeCompleted("should-not-run"),
        )
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("no subprocess")):
            result = backend.invoke(
                AgentInvocationRequest(
                    instruction_text="hello",
                    agent_workspace_path=str(self.agent_ws),
                    target_workspace_path=str(self.target),
                )
            )
        self.assertEqual(result.status, AGENT_INVOKE_BLOCKED_BY_CONFIGURATION)
        self.assertEqual(result.environment_status, "blocked")

    def test_invoke_uses_safe_env_without_literal_percent_tokens(self) -> None:
        captured: dict = {}

        def runner(argv, **kwargs):
            captured["env"] = kwargs["env"]
            captured["shell"] = kwargs["shell"]
            return _FakeCompleted(stdout="ADMISSIBLE PROPOSAL ok")

        backend = CursorCliAgentBackend(
            config=self.config, env=self.win_env, runner=runner
        )
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("no subprocess")):
            result = backend.invoke(
                AgentInvocationRequest(
                    instruction_text="hello",
                    agent_workspace_path=str(self.agent_ws),
                    target_workspace_path=str(self.target),
                )
            )
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        self.assertFalse(captured["shell"])
        env = captured["env"]
        self.assertEqual(env["ProgramData"], r"C:\ProgramData")
        for value in env.values():
            self.assertNotIn("%SystemDrive%", value)

    def test_probe_uses_same_safe_env_and_shell_false(self) -> None:
        captured: dict = {}

        def runner(argv, **kwargs):
            captured["argv"] = argv
            captured["env"] = kwargs["env"]
            captured["shell"] = kwargs["shell"]
            captured["cwd"] = kwargs["cwd"]
            return _FakeCompleted(stdout="cursor-agent 0.42.0", returncode=0)

        probe = probe_cursor_agent_cli_environment(
            self.config,
            agent_workspace_path=self.agent_ws,
            env_base=self.win_env,
            runner=runner,
        )
        self.assertEqual(probe["probe_status"], "ok")
        self.assertFalse(captured["shell"])
        self.assertEqual(captured["argv"], [str(self.fake), "--version"])
        self.assertEqual(captured["env"]["ProgramData"], r"C:\ProgramData")
        self.assertEqual(Path(captured["cwd"]).resolve(), self.agent_ws.resolve())


if __name__ == "__main__":
    unittest.main()
