"""Tests for admissible.runner.model_clients and live provider integration."""

from __future__ import annotations

import contextlib
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
    FRONTIER_LIVE_NOTE,
    FRONTIER_MOCK_NOTE,
    run_system_on_envelopes,
)
from admissible.runner.model_clients import (
    API_KEY_ENV,
    API_URL_ENV,
    DEFAULT_TIMEOUT_SECONDS,
    MODEL_NAME_ENV,
    TIMEOUT_ENV,
    EnvConfiguredHttpModelClient,
    FixedResponseModelClient,
    _parse_timeout_seconds,
    build_model_client_from_env,
)
from benchmark.scoring.score_decisions import load_gold_annotations

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES_DIR = REPO_ROOT / "benchmark" / "cases" / "tier_1_enriched"
GOLD_LABELS_PATH = REPO_ROOT / "benchmark" / "annotations" / "gold_labels.jsonl"
MOCK_RESPONSE_PATH = REPO_ROOT / "benchmark" / "examples" / "mock_frontier_response.json"
SAMPLE_CASE_PATH = CASES_DIR / "customer_communication" / "customer_refund_draft_allowed.envelope.json"

SECRET_KEY = "super-secret-api-key-do-not-leak"
VALID_BASELINE_RESPONSE = json.dumps({
    "decision": "REQUIRE_HUMAN_APPROVAL",
    "risk_level": "high",
    "reasons": [{"dimension": "authority", "summary": "test", "severity": "high"}],
})


def _load_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


class TestFixedResponseModelClient(unittest.TestCase):
    def test_returns_fixed_string_response(self) -> None:
        client = FixedResponseModelClient('{"decision": "ALLOW"}')
        self.assertEqual(client.complete("any prompt"), '{"decision": "ALLOW"}')

    def test_accepts_dict_and_returns_json_text(self) -> None:
        payload = {"decision": "REFUSE", "risk_level": "high"}
        client = FixedResponseModelClient(payload)
        self.assertEqual(client.complete("prompt"), json.dumps(payload))

    def test_records_prompts(self) -> None:
        client = FixedResponseModelClient("ok")
        client.complete("first")
        client.complete("second")
        self.assertEqual(client.prompts, ["first", "second"])


class TestBuildModelClientFromEnv(unittest.TestCase):
    def test_raises_when_required_env_vars_missing(self) -> None:
        env = {
            API_URL_ENV: "https://example.com/v1/complete",
            API_KEY_ENV: SECRET_KEY,
        }
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError) as ctx:
                build_model_client_from_env()
        message = str(ctx.exception)
        self.assertIn(MODEL_NAME_ENV, message)
        self.assertNotIn(SECRET_KEY, message)

    def test_error_messages_do_not_leak_api_keys(self) -> None:
        env = {API_URL_ENV: "https://example.com/v1/complete", MODEL_NAME_ENV: "test-model"}
        with mock.patch.dict(os.environ, env, clear=True):
            with self.assertRaises(ValueError) as ctx:
                build_model_client_from_env()
        self.assertNotIn(SECRET_KEY, str(ctx.exception))


class TestEnvConfiguredHttpModelClient(unittest.TestCase):
    def _client(self, timeout: float = 30.0) -> EnvConfiguredHttpModelClient:
        return EnvConfiguredHttpModelClient(
            api_url="https://example.com/v1/complete",
            api_key=SECRET_KEY,
            model_name="test-model",
            timeout_seconds=timeout,
        )

    def test_builds_request_without_logging_api_key(self) -> None:
        client = self._client()
        captured_request: list[object] = []

        def fake_urlopen(request, timeout=0):  # noqa: ARG001
            captured_request.append(request)
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
                client.complete("test prompt")
        finally:
            root.removeHandler(handler)

        self.assertEqual(len(captured_request), 1)
        from urllib.request import Request

        request = captured_request[0]
        self.assertIsInstance(request, Request)
        self.assertEqual(request.get_header("Authorization"), f"Bearer {SECRET_KEY}")
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body, {"model": "test-model", "prompt": "test prompt"})
        self.assertNotIn(SECRET_KEY, log_stream.getvalue())

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

    def test_parses_choices_message_content_shape(self) -> None:
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

    def test_http_errors_raise_safe_exceptions_without_leaking_api_key(self) -> None:
        import urllib.error

        client = self._client()
        http_error = urllib.error.HTTPError(
            url="https://example.com",
            code=500,
            msg="Internal Server Error",
            hdrs=mock.Mock(),
            fp=io.BytesIO(b'{"error":"invalid key super-secret-api-key-do-not-leak"}'),
        )
        with mock.patch("urllib.request.urlopen", side_effect=http_error):
            with self.assertRaises(RuntimeError) as ctx:
                client.complete("p")
        self.assertNotIn(SECRET_KEY, str(ctx.exception))

    def test_timeout_config_parses_correctly(self) -> None:
        self.assertEqual(_parse_timeout_seconds("45"), 45.0)
        self.assertEqual(_parse_timeout_seconds("not-a-number"), DEFAULT_TIMEOUT_SECONDS)
        self.assertEqual(_parse_timeout_seconds("-1"), DEFAULT_TIMEOUT_SECONDS)
        self.assertEqual(_parse_timeout_seconds(None), DEFAULT_TIMEOUT_SECONDS)

        env = {
            API_URL_ENV: "https://example.com/v1/complete",
            API_KEY_ENV: SECRET_KEY,
            MODEL_NAME_ENV: "test-model",
            TIMEOUT_ENV: "12.5",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            built = build_model_client_from_env()
        self.assertEqual(built._timeout_seconds, 12.5)


class TestBaselineRunnerIntegration(unittest.TestCase):
    def test_mock_cli_path_still_works(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = baseline_main([
                "--case", str(SAMPLE_CASE_PATH),
                "--mock-response", str(MOCK_RESPONSE_PATH),
            ])
        self.assertEqual(exit_code, 0)
        result = json.loads(stdout.getvalue())
        self.assertIn("decision", result)

    def test_live_provider_path_with_monkeypatched_client(self) -> None:
        envelope = _load_json(SAMPLE_CASE_PATH)
        fake_client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)

        with mock.patch(
            "admissible.runner.baseline_runner.build_model_client_from_env",
            return_value=fake_client,
        ):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = baseline_main([
                    "--case", str(SAMPLE_CASE_PATH),
                    "--provider", "env-http",
                ])
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(fake_client.prompts), 1)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["decision"], "REQUIRE_HUMAN_APPROVAL")


class TestCompareRunnerLiveIntegration(unittest.TestCase):
    def setUp(self) -> None:
        self.envelopes = [_load_json(SAMPLE_CASE_PATH)]
        self.mock_response = json.loads(MOCK_RESPONSE_PATH.read_text(encoding="utf-8"))

    def test_frontier_direct_live_supported_when_client_monkeypatched(self) -> None:
        fake_client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)
        with mock.patch(
            "admissible.runner.compare_runner.build_model_client_from_env",
            return_value=fake_client,
        ):
            decisions = run_system_on_envelopes("frontier_direct_live", self.envelopes)
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0]["system_id"], "frontier_direct_live_v0")

    def test_live_provider_not_used_unless_frontier_direct_live_requested(self) -> None:
        with mock.patch(
            "admissible.runner.compare_runner.build_model_client_from_env",
        ) as build_live:
            run_system_on_envelopes(
                "frontier_direct_mock", self.envelopes, mock_response=self.mock_response
            )
        build_live.assert_not_called()

    def test_frontier_direct_mock_behavior_unchanged(self) -> None:
        from admissible.runner.compare_runner import compare_systems

        comparison = compare_systems(
            CASES_DIR,
            GOLD_LABELS_PATH,
            ["frontier_direct_mock"],
            mock_response_path=MOCK_RESPONSE_PATH,
        )
        result = comparison["results"]["frontier_direct_mock"]
        self.assertEqual(result["notes"], FRONTIER_MOCK_NOTE)
        self.assertEqual(comparison["notes"], FRONTIER_MOCK_NOTE)

    def test_frontier_direct_live_includes_required_note(self) -> None:
        from admissible.runner.compare_runner import compare_systems

        fake_client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)
        with mock.patch(
            "admissible.runner.compare_runner.build_model_client_from_env",
            return_value=fake_client,
        ):
            comparison = compare_systems(
                CASES_DIR,
                GOLD_LABELS_PATH,
                ["frontier_direct_live"],
            )
        result = comparison["results"]["frontier_direct_live"]
        self.assertEqual(result["notes"], FRONTIER_LIVE_NOTE)
        self.assertIn(FRONTIER_LIVE_NOTE, comparison["notes"])


class TestNoLeakageIntoLivePrompt(unittest.TestCase):
    def test_no_gold_annotations_in_live_prompt(self) -> None:
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

    def test_no_rules_only_outputs_in_live_prompt(self) -> None:
        envelope = _load_json(SAMPLE_CASE_PATH)
        client = FixedResponseModelClient(VALID_BASELINE_RESPONSE)

        run_frontier_direct_baseline(envelope, model_client=client)
        prompt = client.prompts[0]
        self.assertNotIn("rules_only", prompt)
        self.assertEqual(prompt, build_frontier_direct_prompt(envelope))


class TestNoAgentOsImports(unittest.TestCase):
    def test_model_clients_module_does_not_import_agent_os(self) -> None:
        import admissible.runner.model_clients as model_clients_module

        source_path = Path(model_clients_module.__file__).resolve()
        source = source_path.read_text(encoding="utf-8")
        self.assertNotIn("agent_os", source)
        loaded = sys.modules.get("admissible.runner.model_clients")
        self.assertIsNotNone(loaded)
        for name, module in list(sys.modules.items()):
            if name.startswith("agent_os") and module is not None:
                self.fail(f"agent_os module {name!r} was imported during model_clients tests")


if __name__ == "__main__":
    unittest.main()
