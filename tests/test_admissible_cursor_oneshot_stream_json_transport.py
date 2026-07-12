"""Tests for ADMISSIBLE_NARROW_FIX_CURSOR_ONESHOT_STREAM_JSON_ASK_AND_OPERATION_LIMIT.

Covers: canonical stream-json Ask-mode argv generation, legacy text/plan
configuration rejection, NDJSON parsing rules (terminal-result authority,
assistant-delta non-duplication, progress-only/createPlan non-extraction,
terminal-error handling, malformed/truncated NDJSON), the explicit
per-response operation-limit derivation and min(system, user) wiring, the
generated instruction packet consistently stating the effective limit,
admission-time rejection above the effective limit, and that managed-process
cleanup / target-workspace mutation safety are preserved.

No real Cursor Agent CLI invocation anywhere in this file; subprocess is
always injected/mocked. Fixtures live in
``tests/fixtures/admissible/cursor_oneshot_stream_json_fixtures.json``.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

from admissible.agent_backend import (
    AGENT_AVAILABILITY_UNSUPPORTED,
    AGENT_INVOKE_BLOCKED_BY_CONFIGURATION,
    AGENT_INVOKE_EMPTY_SUCCESS,
    AGENT_INVOKE_SUCCESS,
    AGENT_INVOKE_TERMINAL_ERROR,
    AGENT_INVOKE_TERMINAL_RESULT_WITHOUT_STRUCTURED_PROPOSAL,
    AGENT_INVOKE_TRANSPORT_PARSE_ERROR,
    CURSOR_AGENT_CLI_COMMAND,
    CURSOR_AGENT_CLI_DEFAULT_MODEL,
    CURSOR_CLI_ARGS_ENV,
    CURSOR_CLI_COMMAND_ENV,
    AgentInvocationRequest,
    CursorCliAgentBackend,
    CursorCliConfig,
    assess_cursor_cli_safety,
    cursor_agent_cli_safe_args_template,
)
from admissible.control_surface import ControlSurfaceController
from admissible.cursor_stream_json import (
    CLASSIFICATION_EMPTY_SUCCESS,
    CLASSIFICATION_SUCCESS,
    CLASSIFICATION_TERMINAL_ERROR,
    CLASSIFICATION_TERMINAL_RESULT_WITHOUT_STRUCTURED_PROPOSAL,
    CLASSIFICATION_TRANSPORT_PARSE_ERROR,
    parse_cursor_stream_json,
)
from admissible.governed_run import (
    derive_explicit_user_operation_limit,
    effective_max_structured_operations_per_response,
    validate_coherent_batch_limits,
)
from admissible.long_run_envelope_builder import extract_structured_operation_blocks

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_PATH = (
    REPO_ROOT / "tests" / "fixtures" / "admissible" / "cursor_oneshot_stream_json_fixtures.json"
)


def _load_fixtures() -> dict:
    return json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))


def _ndjson_lines_to_stdout(lines: list[dict]) -> str:
    return "\n".join(json.dumps(line) for line in lines)


class _FakeCompleted:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _make_fake_cursor_agent(tmp: Path) -> Path:
    fake = tmp / "cursor-agent"
    fake.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    fake.chmod(0o755)
    return fake


# ---------------------------------------------------------------------------
# Canonical argv generation + legacy configuration rejection
# ---------------------------------------------------------------------------


class TestCanonicalArgvGeneration(unittest.TestCase):
    def test_canonical_preset_argv_matches_task_spec(self) -> None:
        args = cursor_agent_cli_safe_args_template()
        # Equivalent to: --print --output-format stream-json --stream-partial-output
        # --mode ask --model {model} --workspace {agent_workspace} --trust {prompt}
        self.assertEqual(
            args,
            [
                "--print",
                "--output-format",
                "stream-json",
                "--stream-partial-output",
                "--mode",
                "ask",
                "--model",
                "{model}",
                "--workspace",
                "{agent_workspace}",
                "--trust",
                "{prompt}",
            ],
        )

    def test_model_placeholder_is_substituted_in_real_argv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake = _make_fake_cursor_agent(tmp_path)
            target = tmp_path / "target"
            agent_ws = tmp_path / "agent"
            target.mkdir()
            agent_ws.mkdir()
            captured: dict = {}

            def runner(argv, **kwargs):
                captured["argv"] = argv
                return _FakeCompleted(
                    stdout=json.dumps(
                        {
                            "type": "result",
                            "subtype": "success",
                            "is_error": False,
                            "result": (
                                "ADMISSIBLE_STRUCTURED_OPERATION:\n"
                                '{"operation": "write_file", "path": "a.txt", "content": "x"}'
                            ),
                        }
                    )
                )

            config = CursorCliConfig.cursor_agent_preset(command=str(fake))
            self.assertEqual(config.model, CURSOR_AGENT_CLI_DEFAULT_MODEL)
            backend = CursorCliAgentBackend(config=config, runner=runner)
            backend.invoke(
                AgentInvocationRequest(
                    instruction_text="hi",
                    target_workspace_path=str(target),
                    agent_workspace_path=str(agent_ws),
                )
            )
            model_idx = captured["argv"].index("--model")
            self.assertEqual(captured["argv"][model_idx + 1], CURSOR_AGENT_CLI_DEFAULT_MODEL)
            self.assertNotIn("{model}", captured["argv"])


class TestLegacyConfigurationRejection(unittest.TestCase):
    def test_legacy_text_plan_preset_fails_preflight_with_actionable_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake = _make_fake_cursor_agent(tmp_path)
            legacy_env = {
                CURSOR_CLI_COMMAND_ENV: str(fake),
                CURSOR_CLI_ARGS_ENV: (
                    "--print --output-format text --mode plan "
                    "--workspace {agent_workspace} --trust {prompt}"
                ),
            }
            config = CursorCliConfig.from_env(legacy_env)
            backend = CursorCliAgentBackend(config=config)
            self.assertEqual(backend.availability().status, AGENT_AVAILABILITY_UNSUPPORTED)

            def runner(argv, **kwargs):
                raise AssertionError("a legacy/incompatible config must never invoke the CLI")

            backend_with_runner = CursorCliAgentBackend(config=config, runner=runner)
            request = AgentInvocationRequest(
                instruction_text="hi",
                target_workspace_path=str(tmp_path / "target"),
                agent_workspace_path=str(tmp_path / "agent"),
            )
            result = backend_with_runner.invoke(request)
            self.assertEqual(result.status, AGENT_INVOKE_BLOCKED_BY_CONFIGURATION)
            message = (result.error_message or "").lower()
            self.assertIn("output format", message)
            self.assertIn("stream-json", message)
            self.assertIn("mode", message)
            self.assertIn("ask", message)
            # Actionable: identifies BOTH observed values, not just what's required.
            self.assertIn("text", message)
            self.assertIn("plan", message)

    def test_does_not_silently_launch_with_wrong_mode(self) -> None:
        """A partially-legacy config (stream-json but still plan mode) is also rejected."""
        blocking, _ = assess_cursor_cli_safety(
            CURSOR_AGENT_CLI_COMMAND,
            [
                "--print", "--output-format", "stream-json", "--stream-partial-output",
                "--mode", "plan", "--model", "auto",
                "--workspace", "{agent_workspace}", "{prompt}",
            ],
        )
        self.assertTrue(blocking)
        self.assertTrue(any("ask" in b.lower() for b in blocking))


# ---------------------------------------------------------------------------
# NDJSON parsing rules (pure unit tests on admissible.cursor_stream_json)
# ---------------------------------------------------------------------------


class TestStreamJsonParsing(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = _load_fixtures()

    def test_terminal_result_is_the_only_authoritative_response(self) -> None:
        fixture = self.fixtures["ask_mode_valid_transcript_four_operations"]
        stdout = _ndjson_lines_to_stdout(fixture["raw_stdout_ndjson_lines"])
        result = parse_cursor_stream_json(stdout)
        self.assertEqual(result.classification, CLASSIFICATION_SUCCESS)
        expected_terminal = [
            line for line in fixture["raw_stdout_ndjson_lines"] if line["type"] == "result"
        ][0]["result"]
        self.assertEqual(result.canonical_response, expected_terminal)

    def test_assistant_deltas_are_never_concatenated_into_response(self) -> None:
        stdout = "\n".join(
            [
                json.dumps({"type": "assistant", "text": "chunk one "}),
                json.dumps({"type": "assistant", "text": "chunk two "}),
                json.dumps(
                    {
                        "type": "result",
                        "subtype": "success",
                        "is_error": False,
                        "result": (
                            "ADMISSIBLE_STRUCTURED_OPERATION:\n"
                            '{"operation": "write_file", "path": "a.txt", "content": "x"}'
                        ),
                    }
                ),
            ]
        )
        result = parse_cursor_stream_json(stdout)
        self.assertEqual(result.classification, CLASSIFICATION_SUCCESS)
        self.assertNotIn("chunk one", result.canonical_response)
        self.assertNotIn("chunk two", result.canonical_response)
        self.assertEqual(result.diagnostics["assistant_event_count"], 2)

    def test_progress_only_createplan_terminal_is_not_success_or_empty(self) -> None:
        fixture = self.fixtures["stream_json_probe_createplan_progress_only"]
        stdout = _ndjson_lines_to_stdout(fixture["raw_stdout_ndjson_lines"])
        result = parse_cursor_stream_json(stdout)
        self.assertEqual(
            result.classification, CLASSIFICATION_TERMINAL_RESULT_WITHOUT_STRUCTURED_PROPOSAL
        )
        # Not misclassified as an empty transport response.
        self.assertNotEqual(result.classification, CLASSIFICATION_EMPTY_SUCCESS)
        for key, expected in fixture["expected_diagnostics"].items():
            self.assertEqual(result.diagnostics[key], expected, key)

    def test_createplan_and_interaction_query_never_extracted_as_operations(self) -> None:
        fixture = self.fixtures["stream_json_probe_createplan_progress_only"]
        stdout = _ndjson_lines_to_stdout(fixture["raw_stdout_ndjson_lines"])
        result = parse_cursor_stream_json(stdout)
        # The terminal text itself contains no structured-operation marker, and
        # the backend (tested separately) nulls response_text for this
        # classification so it never reaches the operation extractor.
        self.assertEqual(extract_structured_operation_blocks(result.canonical_response or ""), [])
        terminal_text = [
            line for line in fixture["raw_stdout_ndjson_lines"] if line["type"] == "result"
        ][0]["result"]
        self.assertEqual(extract_structured_operation_blocks(terminal_text), [])

    def test_terminal_error_is_distinguished_from_transport_parse_error(self) -> None:
        stdout = json.dumps(
            {"type": "result", "subtype": "error", "is_error": True, "result": ""}
        )
        result = parse_cursor_stream_json(stdout)
        self.assertEqual(result.classification, CLASSIFICATION_TERMINAL_ERROR)

    def test_malformed_ndjson_beyond_tolerance_is_transport_parse_error(self) -> None:
        stdout = "not json\nalso not json"
        result = parse_cursor_stream_json(stdout)
        self.assertEqual(result.classification, CLASSIFICATION_TRANSPORT_PARSE_ERROR)

    def test_truncated_ndjson_missing_terminal_result_is_transport_parse_error(self) -> None:
        stdout = "\n".join(
            [
                json.dumps({"type": "assistant", "text": "still working..."}),
                '{"type": "result", "subtype": "succ',  # truncated mid-line
            ]
        )
        result = parse_cursor_stream_json(stdout)
        self.assertEqual(result.classification, CLASSIFICATION_TRANSPORT_PARSE_ERROR)

    def test_no_terminal_result_at_all_is_transport_parse_error(self) -> None:
        stdout = json.dumps({"type": "assistant", "text": "no terminal event follows"})
        result = parse_cursor_stream_json(stdout)
        self.assertEqual(result.classification, CLASSIFICATION_TRANSPORT_PARSE_ERROR)

    def test_multiple_terminal_results_is_transport_parse_error(self) -> None:
        one = json.dumps({"type": "result", "subtype": "success", "is_error": False, "result": "a"})
        two = json.dumps({"type": "result", "subtype": "success", "is_error": False, "result": "b"})
        result = parse_cursor_stream_json(f"{one}\n{two}")
        self.assertEqual(result.classification, CLASSIFICATION_TRANSPORT_PARSE_ERROR)

    def test_recognizes_at_minimum_the_required_event_types(self) -> None:
        from admissible.cursor_stream_json import RECOGNIZED_EVENT_TYPES

        for required in (
            "system", "user", "thinking", "assistant", "tool_call",
            "interaction_query", "result",
        ):
            self.assertIn(required, RECOGNIZED_EVENT_TYPES)


# ---------------------------------------------------------------------------
# Backend-level classification driven from the sanitized fixtures
# ---------------------------------------------------------------------------


class TestBackendClassificationFromFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = _load_fixtures()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.fake = _make_fake_cursor_agent(self.tmp)
        self.target = self.tmp / "target"
        self.target.mkdir()
        self.agent_ws = self.tmp / "agent"
        self.agent_ws.mkdir()
        self.config = CursorCliConfig.cursor_agent_preset(command=str(self.fake))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _invoke_with_stdout(self, stdout: str):
        backend = CursorCliAgentBackend(
            config=self.config, runner=lambda argv, **kwargs: _FakeCompleted(stdout=stdout)
        )
        request = AgentInvocationRequest(
            instruction_text="scaffold the game",
            target_workspace_path=str(self.target),
            agent_workspace_path=str(self.agent_ws),
        )
        with mock.patch.object(subprocess, "run", side_effect=AssertionError("no real cursor")):
            return backend.invoke(request)

    def test_one_byte_text_mode_stdout_is_empty_success(self) -> None:
        for sample in self.fixtures["text_mode_empty_success_samples"]["raw_stdout_samples"]:
            with self.subTest(sample=repr(sample)):
                result = self._invoke_with_stdout(sample)
                self.assertEqual(result.status, AGENT_INVOKE_EMPTY_SUCCESS)

    def test_createplan_probe_fixture_is_terminal_result_without_structured_proposal(self) -> None:
        fixture = self.fixtures["stream_json_probe_createplan_progress_only"]
        stdout = _ndjson_lines_to_stdout(fixture["raw_stdout_ndjson_lines"])
        result = self._invoke_with_stdout(stdout)
        self.assertEqual(
            result.status, AGENT_INVOKE_TERMINAL_RESULT_WITHOUT_STRUCTURED_PROPOSAL
        )
        self.assertIsNone(result.response_text)

    def test_valid_ask_transcript_fixture_is_usable_canonical_response(self) -> None:
        fixture = self.fixtures["ask_mode_valid_transcript_four_operations"]
        stdout = _ndjson_lines_to_stdout(fixture["raw_stdout_ndjson_lines"])
        result = self._invoke_with_stdout(stdout)
        self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
        blocks = extract_structured_operation_blocks(result.response_text)
        total_ops = sum(len(b["operations"]) for b in blocks)
        self.assertEqual(total_ops, fixture["expected_operation_count"])

    def test_terminal_result_without_structured_proposal_is_a_terminal_block(self) -> None:
        from admissible.agent_backend import AGENT_INVOKE_TERMINAL_STATUSES

        self.assertIn(
            AGENT_INVOKE_TERMINAL_RESULT_WITHOUT_STRUCTURED_PROPOSAL,
            AGENT_INVOKE_TERMINAL_STATUSES,
        )


# ---------------------------------------------------------------------------
# Explicit user operation-limit derivation
# ---------------------------------------------------------------------------


class TestOperationLimitDerivation(unittest.TestCase):
    def test_derives_four_from_real_neon_phrasing(self) -> None:
        text = "Use no more than four write operations in one response."
        self.assertEqual(derive_explicit_user_operation_limit(text), 4)

    def test_derives_from_digit_and_word_variants(self) -> None:
        self.assertEqual(
            derive_explicit_user_operation_limit("at most 4 writes per response"), 4
        )
        self.assertEqual(
            derive_explicit_user_operation_limit(
                "maximum of four file operations per response"
            ),
            4,
        )
        self.assertEqual(
            derive_explicit_user_operation_limit(
                "no more than 6 write operations in one response"
            ),
            6,
        )

    def test_no_match_returns_none(self) -> None:
        self.assertIsNone(derive_explicit_user_operation_limit("Build a tiny local game."))
        self.assertIsNone(derive_explicit_user_operation_limit(""))

    def test_min_system_and_user_behavior(self) -> None:
        effective, explicit = effective_max_structured_operations_per_response(
            8, "Use no more than four write operations in one response."
        )
        self.assertEqual((effective, explicit), (4, 4))

        # A user limit above the system maximum never raises the ceiling.
        effective2, explicit2 = effective_max_structured_operations_per_response(
            8, "no more than 20 write operations in one response"
        )
        self.assertEqual((effective2, explicit2), (8, 20))

        # No explicit user limit: system default is untouched.
        effective3, explicit3 = effective_max_structured_operations_per_response(
            8, "Build a tiny local game."
        )
        self.assertEqual((effective3, explicit3), (8, None))


# ---------------------------------------------------------------------------
# Generated instruction packet + admission-time rejection (integration)
# ---------------------------------------------------------------------------


class TestGeneratedPacketAndAdmission(unittest.TestCase):
    def setUp(self) -> None:
        self.fixtures = _load_fixtures()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.workspace = self.tmp / "ws"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=self.tmp / "sessions")
        self.controller.submit_goal(
            "Build the Neon Serpents game. Use no more than four write operations in "
            "one response. Do not deploy."
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _start_run(self) -> None:
        from admissible.agent_backend import FixtureAgentBackend

        self.controller.start_high_autonomy_run(
            workspace_path=str(self.workspace),
            backend=FixtureAgentBackend(responses=[]),
            max_turns=4,
        )

    def test_effective_limit_and_generated_packet_state_four_not_eight(self) -> None:
        self._start_run()
        ha = self.controller._session.high_autonomy_run
        self.assertEqual(ha["max_structured_operations_per_response"], 4)

        started_entry = [
            e
            for e in self.controller._session.transcript
            if e.get("event_type") == "high_autonomy_run_started"
        ][0]
        detail = started_entry["payload"]
        self.assertEqual(detail["system_max_structured_operations_per_response"], 8)
        self.assertEqual(detail["explicit_user_operation_limit"], 4)
        self.assertEqual(detail["max_structured_operations_per_response"], 4)

        self.controller.tick_high_autonomy_run()
        view = self.controller.state_view()
        instruction_text = str(view.get("continuation_instruction", {}).get("instruction_text") or "")
        self.assertIn('"max_structured_operations_per_response":4', instruction_text)
        self.assertNotIn('"max_structured_operations_per_response":8', instruction_text)

    def test_admission_rejects_five_operations_above_effective_four(self) -> None:
        self._start_run()
        fixture = self.fixtures["five_operations_exceeds_effective_maximum"]
        terminal_text = [
            line for line in fixture["raw_stdout_ndjson_lines"] if line["type"] == "result"
        ][0]["result"]
        with self.assertRaises(ValueError) as ctx:
            self.controller.ingest_agent_response(terminal_text)
        message = str(ctx.exception)
        self.assertIn("5", message)
        self.assertIn("4", message)

    def test_operation_budget_check_uses_effective_limit_directly(self) -> None:
        fixture = self.fixtures["five_operations_exceeds_effective_maximum"]
        terminal_text = [
            line for line in fixture["raw_stdout_ndjson_lines"] if line["type"] == "result"
        ][0]["result"]
        blocks = extract_structured_operation_blocks(terminal_text)
        operations = [op for block in blocks for op in block["operations"]]
        self.assertEqual(len(operations), 5)
        with self.assertRaises(ValueError):
            validate_coherent_batch_limits(operations, max_operations=4)
        # And exactly four is accepted.
        validate_coherent_batch_limits(operations[:4], max_operations=4)


# ---------------------------------------------------------------------------
# Managed-process cleanup + target-workspace mutation safety preserved
# ---------------------------------------------------------------------------


class TestManagedCleanupAndTargetMutationPreserved(unittest.TestCase):
    def test_managed_oneshot_path_still_carries_cleanup_proof_on_success(self) -> None:
        from admissible.agent_backend import BACKEND_ID_CURSOR_ONESHOT
        from admissible.managed_process import ManagedOneshotResult, ManagedProcessResult

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake = _make_fake_cursor_agent(tmp_path)
            target = tmp_path / "target"
            agent_ws = tmp_path / "agent"
            target.mkdir()
            agent_ws.mkdir()
            config = CursorCliConfig.cursor_agent_preset(command=str(fake))

            ndjson_stdout = json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "result": (
                        "ADMISSIBLE_STRUCTURED_OPERATION:\n"
                        '{"operation": "write_file", "path": "a.txt", "content": "x"}'
                    ),
                }
            )

            def fake_managed_oneshot(argv, *, cwd, env, timeout_seconds, input_text=None, max_capture_bytes=0):
                mpr = ManagedProcessResult(
                    process_id=4242,
                    observed_descendant_ids=[4243],
                    exit_code=0,
                    termination_reason="completed",
                    graceful_termination_attempted=False,
                    force_termination_attempted=False,
                    cleanup_complete=True,
                    remaining_process_ids=[],
                    platform_strategy="windows_job_object",
                )
                return ManagedOneshotResult(
                    returncode=0, stdout=ndjson_stdout, stderr="", timed_out=False, process_result=mpr
                )

            backend = CursorCliAgentBackend(config=config, managed_oneshot=fake_managed_oneshot)
            before = sorted(p.name for p in target.iterdir())
            result = backend.invoke(
                AgentInvocationRequest(
                    instruction_text="hi",
                    target_workspace_path=str(target),
                    agent_workspace_path=str(agent_ws),
                )
            )
            after = sorted(p.name for p in target.iterdir())

            self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
            self.assertEqual(result.transport_kind, BACKEND_ID_CURSOR_ONESHOT)
            self.assertIsNotNone(result.managed_process_result)
            self.assertTrue(result.managed_process_result["cleanup_complete"])
            # The backend never writes the target workspace directly -- only
            # Admissible's bounded executor may, through the existing ingest path.
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
