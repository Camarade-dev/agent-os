"""Tests for Google Gemini model client and integration."""

from __future__ import annotations

import contextlib
import importlib
import io
import json
import logging
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from admissible.runner.baseline_runner import main as baseline_main
from admissible.runner.compare_runner import (
    FRONTIER_GEMINI_NOTE,
    run_system_on_envelopes,
)
from admissible.runner.demo_trace import build_demo_trace
from admissible.runner.model_clients import (
    ADMISSIBLE_DECISION_OUTPUT_SCHEMA,
    DEFAULT_GEMINI_BASE_URL,
    DEFAULT_GEMINI_MAX_OUTPUT_TOKENS,
    DEFAULT_GEMINI_TIMEOUT_SECONDS,
    GEMINI_API_KEY_ENV,
    GEMINI_API_KEY_FALLBACK_ENV,
    GEMINI_BASE_URL_ENV,
    GEMINI_DECISION_OUTPUT_SCHEMA,
    GEMINI_MAX_OUTPUT_TOKENS_ENV,
    GEMINI_MAX_RETRIES_ENV,
    GEMINI_MODEL_ENV,
    GEMINI_REQUEST_DELAY_ENV,
    GEMINI_THINKING_BUDGET_ENV,
    GEMINI_TIMEOUT_ENV,
    FixedResponseModelClient,
    GeminiGenerateContentModelClient,
    _parse_gemini_max_output_tokens,
    _parse_gemini_timeout_seconds,
    _sanitize_schema_for_gemini,
    build_gemini_model_client_from_env,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "benchmark" / "cases" / "tier_1_enriched"
GOLD_LABELS_PATH = REPO_ROOT / "benchmark" / "annotations" / "gold_labels.jsonl"
DEMO_PACK_PATH = REPO_ROOT / "benchmark" / "reports" / "demo-pack.json"
SAMPLE_CASE_PATH = CASES_DIR / "customer_communication" / "customer_refund_draft_allowed.envelope.json"

SECRET_KEY = "AIza-super-secret-key-do-not-leak"
VALID_BASELINE_RESPONSE = json.dumps({
    "decision": "REQUIRE_HUMAN_APPROVAL",
    "risk_level": "high",
    "reasons": [{"dimension": "authority", "summary": "test", "severity": "high"}],
    "missing_evidence": [],
    "required_approval": "finance",
    "safer_next_step": "review policy",
    "confidence": 0.5,
})


def _gemini_response_payload(text: str = VALID_BASELINE_RESPONSE) -> dict:
    return {
        "candidates": [
            {
                "content": {"parts": [{"text": text}]},
                "finishReason": "STOP",
            }
        ]
    }


class TestBuildGeminiModelClientFromEnv(unittest.TestCase):
    def test_raises_when_api_key_missing(self) -> None:
        env = {GEMINI_MODEL_ENV: "gemini-2.5-flash"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError) as ctx:
                build_gemini_model_client_from_env()
        self.assertIn(GEMINI_API_KEY_ENV, str(ctx.exception))
        self.assertNotIn(SECRET_KEY, str(ctx.exception))

    def test_raises_when_model_missing(self) -> None:
        env = {GEMINI_API_KEY_ENV: SECRET_KEY}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError) as ctx:
                build_gemini_model_client_from_env()
        self.assertIn(GEMINI_MODEL_ENV, str(ctx.exception))
        self.assertNotIn(SECRET_KEY, str(ctx.exception))

    def test_accepts_gemini_api_key_fallback(self) -> None:
        env = {GEMINI_API_KEY_FALLBACK_ENV: SECRET_KEY, GEMINI_MODEL_ENV: "gemini-2.5-flash"}
        with mock.patch.dict(os.environ, env, clear=True):
            client = build_gemini_model_client_from_env()
        self.assertEqual(client._api_key, SECRET_KEY)

    def test_default_base_url(self) -> None:
        env = {GEMINI_API_KEY_ENV: SECRET_KEY, GEMINI_MODEL_ENV: "gemini-2.5-flash"}
        with mock.patch.dict(os.environ, env, clear=True):
            client = build_gemini_model_client_from_env()
        self.assertEqual(client._base_url, DEFAULT_GEMINI_BASE_URL)


class TestGeminiGenerateContentModelClient(unittest.TestCase):
    def _client(self, timeout: float = DEFAULT_GEMINI_TIMEOUT_SECONDS) -> GeminiGenerateContentModelClient:
        return GeminiGenerateContentModelClient(
            api_key=SECRET_KEY,
            model="gemini-2.5-flash",
            base_url=DEFAULT_GEMINI_BASE_URL,
            timeout_seconds=timeout,
        )

    def test_request_url_uses_generate_content_endpoint(self) -> None:
        client = self._client()
        captured: list[object] = []

        def fake_urlopen(request, timeout=0):  # noqa: ARG001
            captured.append(request)
            return mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps(_gemini_response_payload()).encode("utf-8"),
            )

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            client.complete("test prompt")

        from urllib.request import Request

        request = captured[0]
        self.assertIsInstance(request, Request)
        self.assertTrue(request.full_url.endswith("/models/gemini-2.5-flash:generateContent"))

    def test_request_payload_uses_system_instruction_and_json_schema(self) -> None:
        client = self._client()
        captured: list[object] = []

        def fake_urlopen(request, timeout=0):  # noqa: ARG001
            captured.append(request)
            return mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps(_gemini_response_payload()).encode("utf-8"),
            )

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            client.complete("hello world")

        body = json.loads(captured[0].data.decode("utf-8"))  # type: ignore[attr-defined]
        self.assertIn("systemInstruction", body)
        self.assertEqual(body["contents"][0]["parts"][0]["text"], "hello world")
        generation_config = body["generationConfig"]
        self.assertEqual(generation_config["temperature"], 0)
        self.assertEqual(generation_config["maxOutputTokens"], DEFAULT_GEMINI_MAX_OUTPUT_TOKENS)
        self.assertEqual(generation_config["responseMimeType"], "application/json")
        self.assertEqual(generation_config["responseSchema"], GEMINI_DECISION_OUTPUT_SCHEMA)
        self.assertEqual(generation_config["thinkingConfig"], {"thinkingBudget": 0})

    def test_gemini_schema_strips_additional_properties_and_anyof(self) -> None:
        def walk(node: object) -> None:
            if isinstance(node, dict):
                self.assertNotIn("additionalProperties", node)
                self.assertNotIn("anyOf", node)
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(GEMINI_DECISION_OUTPUT_SCHEMA)
        self.assertEqual(
            GEMINI_DECISION_OUTPUT_SCHEMA,
            _sanitize_schema_for_gemini(ADMISSIBLE_DECISION_OUTPUT_SCHEMA),
        )
        safer_next_step = GEMINI_DECISION_OUTPUT_SCHEMA["properties"]["safer_next_step"]
        self.assertEqual(safer_next_step, {"type": "string", "nullable": True})

    def test_api_key_header_set_without_leaking_key_in_logs(self) -> None:
        client = self._client()
        captured: list[object] = []

        def fake_urlopen(request, timeout=0):  # noqa: ARG001
            captured.append(request)
            return mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps(_gemini_response_payload()).encode("utf-8"),
            )

        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        root = logging.getLogger()
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            with mock.patch("urllib.request.urlopen", fake_urlopen):
                client.complete("p")
        finally:
            root.removeHandler(handler)

        request = captured[0]
        header_items = dict(request.header_items())  # type: ignore[attr-defined]
        api_key_header = next(
            (value for name, value in header_items.items() if name.lower() == "x-goog-api-key"),
            None,
        )
        self.assertEqual(api_key_header, SECRET_KEY)
        self.assertNotIn(SECRET_KEY, log_stream.getvalue())

    def test_unsupported_response_shape_raises_value_error(self) -> None:
        client = self._client()
        with mock.patch(
            "urllib.request.urlopen",
            return_value=mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps({"unexpected": "shape"}).encode("utf-8"),
            ),
        ):
            with self.assertRaises(ValueError):
                client.complete("p")

    def test_http_errors_do_not_leak_key(self) -> None:
        import urllib.error

        client = self._client()
        http_error = urllib.error.HTTPError(
            url=DEFAULT_GEMINI_BASE_URL,
            code=401,
            msg="Unauthorized",
            hdrs=mock.Mock(),
            fp=io.BytesIO(b'{"error":"invalid key AIza-super-secret-key-do-not-leak"}'),
        )
        with mock.patch("urllib.request.urlopen", side_effect=http_error):
            with self.assertRaises(RuntimeError) as ctx:
                client.complete("p")
        self.assertNotIn(SECRET_KEY, str(ctx.exception))
        self.assertIn(GEMINI_API_KEY_ENV, str(ctx.exception))
        self.assertIn("api_message=", str(ctx.exception))

    def test_retries_on_http_429_then_succeeds(self) -> None:
        import urllib.error

        client = self._client()
        calls = {"count": 0}

        def fake_urlopen(request, timeout=0):  # noqa: ARG001
            calls["count"] += 1
            if calls["count"] == 1:
                raise urllib.error.HTTPError(
                    url=DEFAULT_GEMINI_BASE_URL,
                    code=429,
                    msg="Too Many Requests",
                    hdrs=mock.Mock(),
                    fp=io.BytesIO(b'{"error":{"message":"quota exceeded"}}'),
                )
            return mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps(_gemini_response_payload()).encode("utf-8"),
            )

        with mock.patch("urllib.request.urlopen", fake_urlopen), mock.patch(
            "admissible.runner.model_clients.time.sleep"
        ) as sleep_mock:
            self.assertEqual(client.complete("p"), VALID_BASELINE_RESPONSE)
        self.assertEqual(calls["count"], 2)
        self.assertGreaterEqual(sleep_mock.call_count, 1)

    def test_truncated_json_raises_clear_value_error(self) -> None:
        client = self._client()
        truncated = '{\n  "decision": "ALLOW_WITH_LIMITS",\n  "risk_level": "low"'
        payload = {
            "candidates": [
                {
                    "content": {"parts": [{"text": truncated}]},
                    "finishReason": "MAX_TOKENS",
                }
            ]
        }
        with mock.patch(
            "urllib.request.urlopen",
            return_value=mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps(payload).encode("utf-8"),
            ),
        ):
            with self.assertRaises(ValueError) as ctx:
                client.complete("p")
        message = str(ctx.exception)
        self.assertIn("MAX_TOKENS", message)
        self.assertIn(GEMINI_THINKING_BUDGET_ENV, message)

    def test_request_delay_env_parses(self) -> None:
        env = {
            GEMINI_API_KEY_ENV: SECRET_KEY,
            GEMINI_MODEL_ENV: "gemini-2.5-flash",
            GEMINI_REQUEST_DELAY_ENV: "6",
            GEMINI_MAX_RETRIES_ENV: "2",
            GEMINI_THINKING_BUDGET_ENV: "0",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            built = build_gemini_model_client_from_env()
        self.assertEqual(built._request_delay_seconds, 6.0)
        self.assertEqual(built._max_retries, 2)
        self.assertEqual(built._thinking_budget, 0)

    def test_timeout_and_max_output_tokens_env_parse(self) -> None:
        self.assertEqual(_parse_gemini_timeout_seconds("45"), 45.0)
        self.assertEqual(_parse_gemini_timeout_seconds("bad"), DEFAULT_GEMINI_TIMEOUT_SECONDS)
        self.assertEqual(_parse_gemini_max_output_tokens("3000"), 3000)

        env = {
            GEMINI_API_KEY_ENV: SECRET_KEY,
            GEMINI_MODEL_ENV: "gemini-2.5-flash",
            GEMINI_TIMEOUT_ENV: "45",
            GEMINI_MAX_OUTPUT_TOKENS_ENV: "3000",
            GEMINI_BASE_URL_ENV: "https://example.test/v1beta",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            built = build_gemini_model_client_from_env()
        self.assertEqual(built._timeout_seconds, 45.0)
        self.assertEqual(built._max_output_tokens, 3000)
        self.assertEqual(built._base_url, "https://example.test/v1beta")


class TestBaselineRunnerGeminiIntegration(unittest.TestCase):
    def test_baseline_runner_supports_provider_gemini(self) -> None:
        fake_client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)
        with mock.patch(
            "admissible.runner.baseline_runner.build_gemini_model_client_from_env",
            return_value=fake_client,
        ):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = baseline_main([
                    "--case", str(SAMPLE_CASE_PATH),
                    "--provider", "gemini",
                ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(fake_client.prompts), 1)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["decision"], "REQUIRE_HUMAN_APPROVAL")


class TestCompareRunnerGeminiIntegration(unittest.TestCase):
    def test_frontier_direct_gemini_supported_with_monkeypatched_client(self) -> None:
        with SAMPLE_CASE_PATH.open(encoding="utf-8") as f:
            envelope = json.load(f)
        fake_client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)
        with mock.patch(
            "admissible.runner.compare_runner.build_gemini_model_client_from_env",
            return_value=fake_client,
        ):
            decisions = run_system_on_envelopes("frontier_direct_gemini", [envelope])
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0]["system_id"], "frontier_direct_gemini_v0")

    def test_frontier_direct_gemini_includes_required_note(self) -> None:
        from admissible.runner.compare_runner import compare_systems

        fake_client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)
        with mock.patch(
            "admissible.runner.compare_runner.build_gemini_model_client_from_env",
            return_value=fake_client,
        ):
            comparison = compare_systems(
                CASES_DIR,
                GOLD_LABELS_PATH,
                ["frontier_direct_gemini"],
            )
        result = comparison["results"]["frontier_direct_gemini"]
        self.assertEqual(result["notes"], FRONTIER_GEMINI_NOTE)


class TestDemoTraceGeminiIntegration(unittest.TestCase):
    def test_demo_trace_supports_provider_gemini(self) -> None:
        fake_client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)
        with mock.patch(
            "admissible.runner.compare_runner.build_gemini_model_client_from_env",
            return_value=fake_client,
        ):
            trace = build_demo_trace(
                demo_pack_path=DEMO_PACK_PATH,
                gold_path=GOLD_LABELS_PATH,
                provider="gemini",
            )
        system_types = {d["system_type"] for d in trace["systems"]}
        self.assertIn("frontier_direct_gemini", system_types)
        self.assertNotIn("frontier_direct_mock", system_types)


class TestNoAgentOsImports(unittest.TestCase):
    MODEL_CLIENTS_PATH = REPO_ROOT / "admissible" / "runner" / "model_clients.py"

    def test_model_clients_module_does_not_import_agent_os(self) -> None:
        source = self.MODEL_CLIENTS_PATH.read_text(encoding="utf-8")
        for forbidden in ("import agent_os", "from agent_os"):
            self.assertNotIn(forbidden, source)

        before = {name for name in sys.modules if name.startswith("agent_os")}
        importlib.import_module("admissible.runner.model_clients")
        after = {name for name in sys.modules if name.startswith("agent_os")}
        self.assertEqual(after - before, set())


if __name__ == "__main__":
    unittest.main()
