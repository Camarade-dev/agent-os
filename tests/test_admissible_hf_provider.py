"""Tests for Hugging Face Inference Providers model client and integration."""

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

from admissible.runner.baseline_runner import (
    build_frontier_direct_prompt,
    main as baseline_main,
    run_frontier_direct_baseline,
)
from admissible.runner.compare_runner import (
    FRONTIER_HF_NOTE,
    run_system_on_envelopes,
)
from admissible.runner.demo_trace import build_demo_trace
from admissible.runner.model_clients import (
    ADMISSIBLE_DECISION_OUTPUT_RESPONSE_FORMAT,
    DEFAULT_HF_BASE_URL,
    DEFAULT_HF_MAX_TOKENS,
    DEFAULT_HF_TIMEOUT_SECONDS,
    HF_BASE_URL_ENV,
    HF_MAX_TOKENS_ENV,
    HF_MODEL_ENV,
    HF_TIMEOUT_ENV,
    HF_TOKEN_ENV,
    FixedResponseModelClient,
    HuggingFaceChatCompletionsModelClient,
    _parse_hf_max_tokens,
    _parse_hf_timeout_seconds,
    build_huggingface_model_client_from_env,
)
from benchmark.scoring.score_decisions import load_gold_annotations

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "benchmark" / "cases" / "tier_1_enriched"
GOLD_LABELS_PATH = REPO_ROOT / "benchmark" / "annotations" / "gold_labels.jsonl"
MOCK_RESPONSE_PATH = REPO_ROOT / "benchmark" / "examples" / "mock_frontier_response.json"
DEMO_PACK_PATH = REPO_ROOT / "benchmark" / "reports" / "demo-pack.json"
SAMPLE_CASE_PATH = CASES_DIR / "customer_communication" / "customer_refund_draft_allowed.envelope.json"

SECRET_TOKEN = "hf_super-secret-token-do-not-leak"
VALID_BASELINE_RESPONSE = json.dumps({
    "decision": "REQUIRE_HUMAN_APPROVAL",
    "risk_level": "high",
    "reasons": [{"dimension": "authority", "summary": "test", "severity": "high"}],
})


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


class TestBuildHuggingfaceModelClientFromEnv(unittest.TestCase):
    def test_raises_when_hf_token_missing(self) -> None:
        env = {HF_MODEL_ENV: "test-model"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError) as ctx:
                build_huggingface_model_client_from_env()
        self.assertIn(HF_TOKEN_ENV, str(ctx.exception))
        self.assertNotIn(SECRET_TOKEN, str(ctx.exception))

    def test_raises_when_hf_model_missing(self) -> None:
        env = {HF_TOKEN_ENV: SECRET_TOKEN}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError) as ctx:
                build_huggingface_model_client_from_env()
        self.assertIn(HF_MODEL_ENV, str(ctx.exception))
        self.assertNotIn(SECRET_TOKEN, str(ctx.exception))

    def test_default_base_url(self) -> None:
        env = {HF_TOKEN_ENV: SECRET_TOKEN, HF_MODEL_ENV: "test-model"}
        with mock.patch.dict(os.environ, env, clear=True):
            client = build_huggingface_model_client_from_env()
        self.assertEqual(client._base_url, DEFAULT_HF_BASE_URL)


class TestHuggingFaceChatCompletionsModelClient(unittest.TestCase):
    def _client(self, timeout: float = DEFAULT_HF_TIMEOUT_SECONDS) -> HuggingFaceChatCompletionsModelClient:
        return HuggingFaceChatCompletionsModelClient(
            token=SECRET_TOKEN,
            model="test-model",
            base_url=DEFAULT_HF_BASE_URL,
            timeout_seconds=timeout,
        )

    def test_request_url_ends_with_chat_completions(self) -> None:
        client = self._client()
        captured: list[object] = []

        def fake_urlopen(request, timeout=0):  # noqa: ARG001
            captured.append(request)
            return mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps({"text": VALID_BASELINE_RESPONSE}).encode("utf-8"),
            )

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            client.complete("test prompt")

        from urllib.request import Request

        request = captured[0]
        self.assertIsInstance(request, Request)
        self.assertTrue(request.full_url.endswith("/chat/completions"))

    def test_request_payload_uses_system_and_user_messages(self) -> None:
        client = self._client()
        captured: list[object] = []

        def fake_urlopen(request, timeout=0):  # noqa: ARG001
            captured.append(request)
            return mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps({"text": VALID_BASELINE_RESPONSE}).encode("utf-8"),
            )

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            client.complete("hello world")

        body = json.loads(captured[0].data.decode("utf-8"))  # type: ignore[attr-defined]
        self.assertEqual(body["model"], "test-model")
        self.assertEqual(len(body["messages"]), 2)
        self.assertEqual(body["messages"][0]["role"], "system")
        self.assertIn("action-admission evaluator", body["messages"][0]["content"])
        self.assertEqual(body["messages"][1], {"role": "user", "content": "hello world"})
        self.assertEqual(body["temperature"], 0)
        self.assertEqual(body["max_tokens"], DEFAULT_HF_MAX_TOKENS)
        self.assertEqual(body["response_format"], ADMISSIBLE_DECISION_OUTPUT_RESPONSE_FORMAT)

    def test_request_payload_uses_configurable_max_tokens(self) -> None:
        client = HuggingFaceChatCompletionsModelClient(
            token=SECRET_TOKEN,
            model="test-model",
            max_tokens=4000,
        )
        captured: list[object] = []

        def fake_urlopen(request, timeout=0):  # noqa: ARG001
            captured.append(request)
            return mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps({"text": VALID_BASELINE_RESPONSE}).encode("utf-8"),
            )

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            client.complete("hello world")

        body = json.loads(captured[0].data.decode("utf-8"))  # type: ignore[attr-defined]
        self.assertEqual(body["max_tokens"], 4000)

        env = {
            HF_TOKEN_ENV: SECRET_TOKEN,
            HF_MODEL_ENV: "test-model",
            HF_MAX_TOKENS_ENV: "4000",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            built = build_huggingface_model_client_from_env()
        self.assertEqual(built._max_tokens, 4000)

    def test_invalid_max_tokens_env_raises_value_error(self) -> None:
        env = {
            HF_TOKEN_ENV: SECRET_TOKEN,
            HF_MODEL_ENV: "test-model",
            HF_MAX_TOKENS_ENV: "not-a-number",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError) as ctx:
                build_huggingface_model_client_from_env()
        self.assertIn(HF_MAX_TOKENS_ENV, str(ctx.exception))

        with self.assertRaises(ValueError):
            _parse_hf_max_tokens("0")
        with self.assertRaises(ValueError):
            _parse_hf_max_tokens("-5")

    def test_request_payload_includes_json_schema_response_format(self) -> None:
        client = self._client()
        captured: list[object] = []

        def fake_urlopen(request, timeout=0):  # noqa: ARG001
            captured.append(request)
            return mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps({"text": VALID_BASELINE_RESPONSE}).encode("utf-8"),
            )

        with mock.patch("urllib.request.urlopen", fake_urlopen):
            client.complete("hello world")

        body = json.loads(captured[0].data.decode("utf-8"))  # type: ignore[attr-defined]
        response_format = body["response_format"]
        self.assertEqual(response_format["type"], "json_schema")
        self.assertEqual(
            response_format["json_schema"]["name"],
            "admissible_decision_output",
        )
        self.assertIn("decision", response_format["json_schema"]["schema"]["properties"])

    def test_authorization_header_set_without_leaking_token_in_logs(self) -> None:
        client = self._client()
        captured: list[object] = []

        def fake_urlopen(request, timeout=0):  # noqa: ARG001
            captured.append(request)
            return mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps({"text": VALID_BASELINE_RESPONSE}).encode("utf-8"),
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

        self.assertEqual(
            captured[0].get_header("Authorization"),  # type: ignore[attr-defined]
            f"Bearer {SECRET_TOKEN}",
        )
        self.assertNotIn(SECRET_TOKEN, log_stream.getvalue())

    def test_parses_openai_compatible_response(self) -> None:
        client = self._client()
        payload = {"choices": [{"message": {"content": VALID_BASELINE_RESPONSE}}]}
        with mock.patch(
            "urllib.request.urlopen",
            return_value=mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps(payload).encode("utf-8"),
            ),
        ):
            self.assertEqual(client.complete("p"), VALID_BASELINE_RESPONSE)

    def test_parses_text_response_shape(self) -> None:
        client = self._client()
        with mock.patch(
            "urllib.request.urlopen",
            return_value=mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps({"text": VALID_BASELINE_RESPONSE}).encode("utf-8"),
            ),
        ):
            self.assertEqual(client.complete("p"), VALID_BASELINE_RESPONSE)

    def test_parses_output_response_shape(self) -> None:
        client = self._client()
        with mock.patch(
            "urllib.request.urlopen",
            return_value=mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps({"output": VALID_BASELINE_RESPONSE}).encode("utf-8"),
            ),
        ):
            self.assertEqual(client.complete("p"), VALID_BASELINE_RESPONSE)

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

    def test_unsupported_shape_diagnostic_includes_top_level_and_message_keys(self) -> None:
        client = self._client()
        payload = {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": None},
                }
            ],
            "id": "resp-1",
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
        self.assertIn("top_level_keys", message)
        self.assertIn("first_message_keys", message)
        self.assertIn("'choices'", message)
        self.assertIn("'message'", message)

    def test_unsupported_shape_diagnostic_includes_finish_reason_and_usage(self) -> None:
        client = self._client()
        payload = {
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": None},
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 0, "total_tokens": 10},
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
        self.assertIn("first_choice_finish_reason", message)
        self.assertIn("'length'", message)
        self.assertIn("usage", message)
        self.assertIn("prompt_tokens", message)

    def test_unsupported_shape_diagnostic_does_not_leak_token(self) -> None:
        client = self._client()
        with mock.patch(
            "urllib.request.urlopen",
            return_value=mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps({"unexpected": "shape"}).encode("utf-8"),
            ),
        ):
            with self.assertRaises(ValueError) as ctx:
                client.complete("p")
        self.assertNotIn(SECRET_TOKEN, str(ctx.exception))

    def test_content_none_with_reasoning_content_raises_diagnostic(self) -> None:
        client = self._client()
        payload = {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "content": None,
                        "reasoning_content": '{"decision": "ALLOW"}',
                    },
                }
            ],
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
        self.assertIn("content_is_none", message)
        self.assertIn("reasoning_content_present", message)
        self.assertNotIn("ALLOW", message)

    def test_trailing_nuls_stripped_from_choices_content(self) -> None:
        client = self._client()
        payload = {
            "choices": [{"message": {"content": VALID_BASELINE_RESPONSE + "\x00\x00"}}],
        }
        with mock.patch(
            "urllib.request.urlopen",
            return_value=mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps(payload).encode("utf-8"),
            ),
        ):
            self.assertEqual(client.complete("p"), VALID_BASELINE_RESPONSE)

    def test_trailing_nuls_stripped_from_text_shape(self) -> None:
        client = self._client()
        with mock.patch(
            "urllib.request.urlopen",
            return_value=mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps(
                    {"text": VALID_BASELINE_RESPONSE + "\x00"}
                ).encode("utf-8"),
            ),
        ):
            self.assertEqual(client.complete("p"), VALID_BASELINE_RESPONSE)

    def test_trailing_nuls_stripped_from_output_shape(self) -> None:
        client = self._client()
        with mock.patch(
            "urllib.request.urlopen",
            return_value=mock.Mock(
                __enter__=lambda self: self,
                __exit__=lambda *args: None,
                read=lambda: json.dumps(
                    {"output": "  " + VALID_BASELINE_RESPONSE + "\x00  "}
                ).encode("utf-8"),
            ),
        ):
            self.assertEqual(client.complete("p"), VALID_BASELINE_RESPONSE)

    def test_http_errors_do_not_leak_token(self) -> None:
        import urllib.error

        client = self._client()
        http_error = urllib.error.HTTPError(
            url=DEFAULT_HF_BASE_URL,
            code=401,
            msg="Unauthorized",
            hdrs=mock.Mock(),
            fp=io.BytesIO(b'{"error":"invalid token hf_super-secret-token-do-not-leak"}'),
        )
        with mock.patch("urllib.request.urlopen", side_effect=http_error):
            with self.assertRaises(RuntimeError) as ctx:
                client.complete("p")
        self.assertNotIn(SECRET_TOKEN, str(ctx.exception))

    def test_timeout_env_var_parses(self) -> None:
        self.assertEqual(_parse_hf_timeout_seconds("90"), 90.0)
        self.assertEqual(_parse_hf_timeout_seconds("bad"), DEFAULT_HF_TIMEOUT_SECONDS)
        self.assertEqual(_parse_hf_timeout_seconds("-1"), DEFAULT_HF_TIMEOUT_SECONDS)

        env = {
            HF_TOKEN_ENV: SECRET_TOKEN,
            HF_MODEL_ENV: "test-model",
            HF_TIMEOUT_ENV: "45",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            built = build_huggingface_model_client_from_env()
        self.assertEqual(built._timeout_seconds, 45.0)


class TestBaselineRunnerHfIntegration(unittest.TestCase):
    def test_baseline_runner_supports_provider_hf(self) -> None:
        fake_client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)
        with mock.patch(
            "admissible.runner.baseline_runner.build_huggingface_model_client_from_env",
            return_value=fake_client,
        ):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = baseline_main([
                    "--case", str(SAMPLE_CASE_PATH),
                    "--provider", "hf",
                ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(fake_client.prompts), 1)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["decision"], "REQUIRE_HUMAN_APPROVAL")


class TestCompareRunnerHfIntegration(unittest.TestCase):
    def test_frontier_direct_hf_supported_with_monkeypatched_client(self) -> None:
        envelopes = [_load_json(SAMPLE_CASE_PATH)]
        fake_client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)
        with mock.patch(
            "admissible.runner.compare_runner.build_huggingface_model_client_from_env",
            return_value=fake_client,
        ):
            decisions = run_system_on_envelopes("frontier_direct_hf", envelopes)
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0]["system_id"], "frontier_direct_hf_v0")

    def test_frontier_direct_hf_includes_required_note(self) -> None:
        from admissible.runner.compare_runner import compare_systems

        fake_client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)
        with mock.patch(
            "admissible.runner.compare_runner.build_huggingface_model_client_from_env",
            return_value=fake_client,
        ):
            comparison = compare_systems(
                CASES_DIR,
                GOLD_LABELS_PATH,
                ["frontier_direct_hf"],
            )
        result = comparison["results"]["frontier_direct_hf"]
        self.assertEqual(result["notes"], FRONTIER_HF_NOTE)


class TestDemoTraceHfIntegration(unittest.TestCase):
    def test_demo_trace_supports_provider_hf(self) -> None:
        fake_client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)
        with mock.patch(
            "admissible.runner.compare_runner.build_huggingface_model_client_from_env",
            return_value=fake_client,
        ):
            trace = build_demo_trace(
                demo_pack_path=DEMO_PACK_PATH,
                gold_path=GOLD_LABELS_PATH,
                provider="hf",
            )
        system_types = {d["system_type"] for d in trace["systems"]}
        self.assertIn("frontier_direct_hf", system_types)
        self.assertNotIn("frontier_direct_mock", system_types)


class TestNoLeakageIntoHfPrompt(unittest.TestCase):
    def test_hf_prompts_do_not_contain_gold_annotations(self) -> None:
        envelope = _load_json(SAMPLE_CASE_PATH)
        gold_by_envelope_id = load_gold_annotations(GOLD_LABELS_PATH)
        gold = gold_by_envelope_id[envelope["envelope_id"]]
        client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)

        run_frontier_direct_baseline(envelope, model_client=client)
        prompt = client.prompts[0]
        for leaky_field in (
            "gold_decision", "rubric", "correct_label",
            "gold_safer_next_step", "gold_risk_level",
        ):
            self.assertNotIn(leaky_field, prompt)
        self.assertNotIn(
            gold["gold_decision"] + '"',
            prompt.replace(envelope["envelope_id"], ""),
        )

    def test_hf_prompts_do_not_contain_rules_only_outputs(self) -> None:
        envelope = _load_json(SAMPLE_CASE_PATH)
        client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)

        run_frontier_direct_baseline(envelope, model_client=client)
        prompt = client.prompts[0]
        self.assertNotIn("rules_only", prompt)
        self.assertEqual(prompt, build_frontier_direct_prompt(envelope))


class TestNoAgentOsImports(unittest.TestCase):
    """Docstrings may name agent_os to document the boundary; the module must not import it."""

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
