"""Tests for admissible.harness.provider_settings local configuration helper."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

from admissible.harness.provider_settings import (
    TOKEN_FIELD_WARNING,
    build_settings,
    default_settings,
    format_powershell_commands,
    load_html_template,
    main,
    write_settings,
)
from admissible.runner.model_clients import DEFAULT_HF_BASE_URL, HF_TOKEN_ENV

REPO_ROOT = Path(__file__).resolve().parent.parent
GITIGNORE_PATH = REPO_ROOT / ".gitignore"
HTML_PATH = REPO_ROOT / "admissible" / "harness" / "provider_settings.html"
MODULE_PATH = REPO_ROOT / "admissible" / "harness" / "provider_settings.py"

SECRET_TOKEN = "hf_test-token-not-real"


class TestDefaultSettings(unittest.TestCase):
    def test_default_settings_json_shape(self) -> None:
        settings = default_settings()
        self.assertEqual(settings["provider"], "hf")
        self.assertEqual(settings["base_url"], DEFAULT_HF_BASE_URL)
        self.assertEqual(settings["model"], "")
        self.assertEqual(settings["api_key_env_var"], HF_TOKEN_ENV)
        self.assertEqual(settings["timeout_seconds"], 60)
        self.assertNotIn("token", settings)

    def test_write_settings_generates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "settings.json"
            write_settings(out, default_settings())
            loaded = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(loaded["provider"], "hf")


class TestGitignore(unittest.TestCase):
    def test_admissible_directory_is_gitignored(self) -> None:
        content = GITIGNORE_PATH.read_text(encoding="utf-8")
        self.assertIn(".admissible/", content)


class TestSettingsPreferApiKeyEnvVar(unittest.TestCase):
    def test_settings_without_token_omit_token_field(self) -> None:
        settings = build_settings(model="my-model")
        self.assertEqual(settings["api_key_env_var"], HF_TOKEN_ENV)
        self.assertNotIn("token", settings)

    def test_token_field_warns_when_supplied(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            settings = build_settings(token=SECRET_TOKEN)
        self.assertIn("token", settings)
        self.assertTrue(any(TOKEN_FIELD_WARNING in str(w.message) for w in caught))


class TestHtmlTemplate(unittest.TestCase):
    def test_html_contains_no_external_script(self) -> None:
        html = load_html_template()
        lowered = html.lower()
        self.assertNotIn("<script src=", lowered)
        self.assertNotIn('src="http', lowered)
        self.assertNotIn("src='http", lowered)

    def test_html_contains_no_external_network_url_except_docs(self) -> None:
        html = load_html_template()
        # Allow documentation references to huggingface router URL in text
        for line in html.splitlines():
            if "src=" in line.lower():
                self.fail(f"unexpected external src in HTML: {line}")


class TestPowerShellGeneration(unittest.TestCase):
    def test_powershell_does_not_print_token_unless_supplied(self) -> None:
        settings = default_settings()
        output = format_powershell_commands(settings)
        self.assertNotIn(SECRET_TOKEN, output)
        self.assertIn("<your-token>", output)

    def test_powershell_prints_token_when_explicitly_supplied(self) -> None:
        settings = default_settings()
        output = format_powershell_commands(settings, token=SECRET_TOKEN)
        self.assertIn(SECRET_TOKEN, output)

    def test_cli_print_powershell_without_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out = Path(tmpdir) / "settings.json"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["--out", str(out), "--print-powershell"])
        self.assertEqual(exit_code, 0)
        combined = stdout.getvalue()
        self.assertNotIn(SECRET_TOKEN, combined)
        self.assertIn("ADMISSIBLE_HF_MODEL", combined)


class TestNoAgentOsImports(unittest.TestCase):
    def test_source_does_not_import_agent_os(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        for forbidden in ("import agent_os", "from agent_os"):
            self.assertNotIn(forbidden, source)

    def test_module_load_does_not_import_agent_os(self) -> None:
        for name in list(sys.modules):
            if name.startswith("agent_os"):
                self.fail(f"agent_os module {name!r} imported during provider_settings tests")


if __name__ == "__main__":
    unittest.main()
