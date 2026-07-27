"""Native ACP-over-stdio prompt transport and the Windows argv-length guard.

Every ACP test drives a *real* child process (the deterministic fake ACP server
in ``tests/fixtures/admissible/fake_acp_server_process.py``) through the real
``ManagedProcess`` lifecycle, so PIDs, process-tree cleanup and hard timeouts are
real facts rather than in-memory simulations.  No Cursor agent and no model is
ever contacted.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from admissible.delegated_gate.native_executor import (
    ACP_STDIO_CLAIMS,
    ACP_STDIO_NON_CLAIMS,
    ACP_STDIO_PROMPT_BINDING_POLICY,
    ATTESTATION_CLASS_ACP_STDIO,
    AcpStdioNativeProcessRunner,
    NATIVE_PROMPT_HEADER,
    NATIVE_PROMPT_TRANSPORTS,
    NativeArgvTooLongError,
    NativeEvidenceInvalid,
    NativeProcessInvocation,
    NativeProcessStartError,
    OBSERVATION_PROVEN_EMPTY,
    PROMPT_TRANSPORT_ACP_STDIO,
    PROMPT_TRANSPORT_ARGV,
    WINDOWS_MAX_COMMAND_LINE_CHARS,
    require_prompt_transport,
    require_windows_spawnable_argv,
    windows_serialized_command_line,
)

FAKE_SERVER = str(
    Path(__file__).parent / "fixtures" / "admissible" / "fake_acp_server_process.py"
)

# The exact Neon Relay prompt size that made the argv transport impossible.
NEON_RELAY_PROMPT_BYTES = 64660


def build_prompt(size_bytes: int = NEON_RELAY_PROMPT_BYTES) -> str:
    """A harness-shaped prompt of an exact UTF-8 byte size."""

    head = NATIVE_PROMPT_HEADER + "\n\nImmutable mission:\n"
    tail = "\nDo not merely describe changes.\n"
    filler = size_bytes - len(head.encode("utf-8")) - len(tail.encode("utf-8"))
    assert filler > 0
    body = ("neon relay line with \"quotes\" and \\backslashes\\\n" * (filler // 48))
    body = body[:filler]
    prompt = head + body + tail
    # Pad/trim to the exact byte length.
    while len(prompt.encode("utf-8")) < size_bytes:
        prompt += "."
    return prompt


def server_argv(scenario: str, record: str | None = None, **extra: str) -> tuple[str, ...]:
    argv = [sys.executable, FAKE_SERVER, "--scenario", scenario]
    if record is not None:
        argv += ["--record", record]
    for key, value in extra.items():
        argv += [f"--{key.replace('_', '-')}", str(value)]
    return tuple(argv)


class StartedRecorder:
    """Stands in for the CREATE_ONLY PROCESS_STARTED publication."""

    def __init__(self) -> None:
        self.proofs: list[object] = []

    def __call__(self, proof: object) -> None:
        self.proofs.append(proof)

    @property
    def process_ids(self) -> list[int | None]:
        return [getattr(proof, "process_id", None) for proof in self.proofs]


def make_invocation(
    argv: tuple[str, ...],
    prompt: str,
    *,
    cwd: str,
    started: StartedRecorder,
    timeout_seconds: int = 60,
    max_capture_bytes: int = 1024 * 1024,
    fingerprint: str | None = None,
    transport: str = PROMPT_TRANSPORT_ACP_STDIO,
) -> NativeProcessInvocation:
    return NativeProcessInvocation(
        argv, cwd, {}, timeout_seconds, max_capture_bytes, started,
        prompt_transport=transport, prompt=prompt,
        prompt_fingerprint=(
            fingerprint if fingerprint is not None
            else hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        ),
    )


# ---------------------------------------------------------------------------
# I.1 - I.3, I.7: exact prompt delivery over ACP
# ---------------------------------------------------------------------------


def test_full_size_neon_relay_prompt_is_delivered_over_acp(tmp_path):
    prompt = build_prompt()
    assert len(prompt.encode("utf-8")) == NEON_RELAY_PROMPT_BYTES
    record = tmp_path / "received.txt"
    started = StartedRecorder()
    argv = server_argv("success", str(record))

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(argv, prompt, cwd=str(tmp_path), started=started)
    )

    assert outcome.returncode == 0
    assert outcome.cleanup_observation == OBSERVATION_PROVEN_EMPTY
    assert outcome.cleanup_confirmed is True
    assert not outcome.timed_out
    # I.2 the server received the exact prompt string
    received = record.read_text(encoding="utf-8")
    assert received == prompt
    # I.3 recomputed independently from what the server received
    assert hashlib.sha256(received.encode("utf-8")).hexdigest() == (
        hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    )
    # I.7 the prompt never appears in argv
    assert all(prompt not in member for member in argv)
    assert not any(len(member) > 1000 for member in argv)


def test_the_real_neon_relay_v2_prompt_is_delivered_byte_identically(tmp_path):
    """End-to-end with the *actual* frozen mission prompt, not a synthetic one.

    This is the exact 64660-byte prompt whose argv serialization was 64903
    characters and died with WinError 206.  Over ACP it arrives intact.
    """

    from admissible.delegated_gate.mission_profile import NEON_RELAY_V2_PROFILE
    from admissible.delegated_gate.native_canary import (
        build_native_agent_prompt,
        create_canary_session,
    )

    profile = NEON_RELAY_V2_PROFILE
    state = create_canary_session(session_id=profile.session_id, profile=profile)
    prompt = build_native_agent_prompt(
        mission=state.mission, gate_contract=state.gate_plan.ordered_gate_contracts[0],
        work_workspace=tmp_path / "work", required_commit_message=profile.required_commit_message,
        completion_conditions=profile.completion_conditions_text, profile=profile,
        allow_projected_workspace=True,
    )
    assert len(prompt.encode("utf-8")) > WINDOWS_MAX_COMMAND_LINE_CHARS
    assert profile.verifier_source in prompt, "the frozen verifier is disclosed in full"

    record = tmp_path / "received.txt"
    started = StartedRecorder()
    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("echo_prompt", str(record)), prompt,
                        cwd=str(tmp_path), started=started, timeout_seconds=90)
    )

    assert outcome.returncode == 0
    assert outcome.cleanup_observation == OBSERVATION_PROVEN_EMPTY
    received = record.read_text(encoding="utf-8")
    assert received == prompt
    assert hashlib.sha256(received.encode("utf-8")).hexdigest() == (
        hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    )
    # The frozen verifier travelled intact but is not re-persisted in evidence.
    assert profile.verifier_source not in outcome.stdout
    assert "<redacted: prompt echo>" in outcome.stdout


def test_argv_stays_far_below_the_windows_limit_with_a_64kb_prompt(tmp_path):
    prompt = build_prompt()
    argv = server_argv("success")
    serialized = windows_serialized_command_line(argv)
    assert len(serialized) < 1000
    assert require_windows_spawnable_argv(argv) == len(serialized)
    # The very prompt that cannot fit an argv rides the ACP transport untouched.
    assert len(prompt) > WINDOWS_MAX_COMMAND_LINE_CHARS
    with pytest.raises(NativeArgvTooLongError):
        require_windows_spawnable_argv(argv[:-1] + (prompt,))


# ---------------------------------------------------------------------------
# I.4 - I.6: prompt-byte drift is detected before submission
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mutate, label",
    [
        (lambda p: p[:-1], "trimmed one character"),
        (lambda p: p.replace("\n", "\r\n", 1), "changed one newline"),
        (lambda p: p + "\n", "appended one newline"),
    ],
)
def test_prompt_byte_drift_is_refused_before_any_spawn(tmp_path, mutate, label):
    authorized = build_prompt()
    fingerprint = hashlib.sha256(authorized.encode("utf-8")).hexdigest()
    drifted = mutate(authorized)
    assert drifted != authorized, label
    started = StartedRecorder()

    with pytest.raises(NativeEvidenceInvalid, match="prompt fingerprint"):
        AcpStdioNativeProcessRunner().run(
            make_invocation(
                server_argv("success"), drifted, cwd=str(tmp_path),
                started=started, fingerprint=fingerprint,
            )
        )
    # Nothing was spawned: no PROCESS_STARTED proof exists.
    assert started.proofs == []


def test_unicode_normalization_drift_is_refused(tmp_path):
    import unicodedata

    authorized = build_prompt(4096) + "café école"
    fingerprint = hashlib.sha256(authorized.encode("utf-8")).hexdigest()
    decomposed = unicodedata.normalize("NFD", authorized)
    assert decomposed != authorized
    assert unicodedata.normalize("NFC", decomposed) == authorized
    started = StartedRecorder()

    with pytest.raises(NativeEvidenceInvalid, match="prompt fingerprint"):
        AcpStdioNativeProcessRunner().run(
            make_invocation(
                server_argv("success"), decomposed, cwd=str(tmp_path),
                started=started, fingerprint=fingerprint,
            )
        )
    assert started.proofs == []


def test_non_utf8_representable_drift_is_refused(tmp_path):
    # A multibyte body is required for a latin-1 round trip to actually change
    # anything; on pure ASCII the round trip is the identity and would prove
    # nothing.
    authorized = build_prompt(2048) + "café — 日本語 🎮"
    fingerprint = hashlib.sha256(authorized.encode("utf-8")).hexdigest()
    # A latin-1 round trip is a silent encoding fallback; it must not pass.
    drifted = authorized.encode("utf-8").decode("latin-1")
    assert drifted != authorized
    started = StartedRecorder()

    with pytest.raises(NativeEvidenceInvalid, match="prompt fingerprint"):
        AcpStdioNativeProcessRunner().run(
            make_invocation(
                server_argv("success"), drifted, cwd=str(tmp_path),
                started=started, fingerprint=fingerprint,
            )
        )
    assert started.proofs == []


def test_multibyte_prompt_round_trips_byte_identically(tmp_path):
    prompt = NATIVE_PROMPT_HEADER + "\n\n" + "héllo wörld — 日本語 🎮 ✅\n" * 200
    record = tmp_path / "received.txt"
    started = StartedRecorder()

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("success", str(record)), prompt,
                        cwd=str(tmp_path), started=started)
    )

    assert outcome.returncode == 0
    received = record.read_text(encoding="utf-8")
    assert received == prompt
    assert received.encode("utf-8") == prompt.encode("utf-8")


# ---------------------------------------------------------------------------
# I.8: the prompt is not newly persisted in execution evidence
# ---------------------------------------------------------------------------


def test_server_prompt_echo_is_redacted_from_retained_evidence(tmp_path):
    """The real ACP server echoes the user message back as a session/update.

    That echo must not turn the stdout artifact into a second copy of the
    prompt: the argv transport never persisted prompt bytes and neither may this
    one.
    """

    prompt = build_prompt()
    record = tmp_path / "received.txt"
    started = StartedRecorder()

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("echo_prompt", str(record)), prompt,
                        cwd=str(tmp_path), started=started)
    )

    assert outcome.returncode == 0
    # The server really did receive (and echo) the complete prompt...
    assert record.read_text(encoding="utf-8") == prompt
    # ...but the retained evidence carries none of it.
    body = prompt[len(NATIVE_PROMPT_HEADER):]
    assert prompt not in outcome.stdout
    assert body[:2000] not in outcome.stdout
    assert json.dumps(prompt, ensure_ascii=False)[1:-1] not in outcome.stdout
    assert "<redacted: prompt echo>" in outcome.stdout
    # The rest of the transcript survives.
    assert "fake acp turn complete" in outcome.stdout


# ---------------------------------------------------------------------------
# I.9 - I.11: protocol failures fail closed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario",
    ["malformed_json", "wrong_id", "eof_before_terminal", "premature_eof", "unsupported_protocol"],
)
def test_protocol_failures_fail_closed_with_proven_cleanup(tmp_path, scenario):
    prompt = build_prompt(4096)
    started = StartedRecorder()

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv(scenario), prompt, cwd=str(tmp_path),
                        started=started, timeout_seconds=30)
    )

    assert outcome.returncode != 0, f"{scenario} must never report success"
    assert outcome.cleanup_observation == OBSERVATION_PROVEN_EMPTY
    assert outcome.orphan_process_ids == ()
    # A real process really was started before the protocol failed.
    assert len(started.proofs) == 1


# ---------------------------------------------------------------------------
# I.12 - I.13: timeout and overflow
# ---------------------------------------------------------------------------


def test_timeout_fails_closed_and_kills_the_server_tree(tmp_path):
    prompt = build_prompt(4096)
    started = StartedRecorder()

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("hang"), prompt, cwd=str(tmp_path),
                        started=started, timeout_seconds=3)
    )

    assert outcome.timed_out is True
    assert outcome.returncode != 0
    assert outcome.cleanup_observation == OBSERVATION_PROVEN_EMPTY
    assert outcome.orphan_process_ids == ()
    assert len(started.proofs) == 1
    pid = outcome.process_id
    assert isinstance(pid, int) and pid > 0
    from admissible.managed_process import pid_alive

    assert not pid_alive(pid)


def test_timeout_kills_descendant_processes_too(tmp_path):
    prompt = build_prompt(2048)
    started = StartedRecorder()

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("spawn_child"), prompt, cwd=str(tmp_path),
                        started=started, timeout_seconds=3)
    )

    assert outcome.timed_out is True
    assert outcome.cleanup_observation == OBSERVATION_PROVEN_EMPTY
    assert outcome.orphan_process_ids == ()


def test_output_overflow_fails_closed_and_cleans_up(tmp_path):
    prompt = build_prompt(2048)
    started = StartedRecorder()

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(
            server_argv("overflow"), prompt, cwd=str(tmp_path), started=started,
            timeout_seconds=60, max_capture_bytes=64 * 1024,
        )
    )

    assert outcome.output_truncated is True
    assert outcome.returncode != 0, "an overflowing turn must never report success"
    assert outcome.cleanup_observation == OBSERVATION_PROVEN_EMPTY
    assert len(outcome.stdout.encode("utf-8")) <= 64 * 1024


# ---------------------------------------------------------------------------
# I.14 - I.16: process-start evidence and no-retry
# ---------------------------------------------------------------------------


def test_process_started_is_absent_when_spawn_itself_fails(tmp_path):
    prompt = build_prompt(1024)
    started = StartedRecorder()
    missing = str(tmp_path / "definitely-not-an-executable-xyz")

    with pytest.raises(NativeProcessStartError):
        AcpStdioNativeProcessRunner().run(
            make_invocation((missing, "acp"), prompt, cwd=str(tmp_path), started=started)
        )

    assert started.proofs == []


def test_process_started_carries_a_real_pid_and_is_published_once(tmp_path):
    prompt = build_prompt(2048)
    started = StartedRecorder()

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("success"), prompt, cwd=str(tmp_path), started=started)
    )

    assert len(started.proofs) == 1, "no retry and no second process"
    (pid,) = started.process_ids
    assert isinstance(pid, int) and pid > 0
    assert pid == outcome.process_id


def test_runner_never_retries_a_failed_turn(tmp_path):
    prompt = build_prompt(2048)
    started = StartedRecorder()

    AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("malformed_json"), prompt, cwd=str(tmp_path),
                        started=started, timeout_seconds=30)
    )

    assert len(started.proofs) == 1


def test_permission_requests_are_answered_so_the_turn_cannot_stall(tmp_path):
    prompt = build_prompt(2048)
    started = StartedRecorder()

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("permission_request"), prompt,
                        cwd=str(tmp_path), started=started, timeout_seconds=30)
    )

    assert outcome.returncode == 0
    assert "permission=allow-always" in outcome.stdout


# ---------------------------------------------------------------------------
# I.17 - I.18: ACP completion is not acceptance
# ---------------------------------------------------------------------------


def test_acp_completion_alone_establishes_no_acceptance(tmp_path):
    prompt = build_prompt(2048)
    started = StartedRecorder()

    outcome = AcpStdioNativeProcessRunner().run(
        make_invocation(server_argv("success"), prompt, cwd=str(tmp_path), started=started)
    )

    assert outcome.returncode == 0
    # The process outcome carries no checkpoint, verifier or acceptance field:
    # those remain downstream and independent.
    for forbidden in ("checkpoint", "accepted", "verdict", "verifier", "product"):
        assert not any(forbidden in name for name in vars(outcome)), forbidden
    assert ACP_STDIO_CLAIMS["acp_turn_proves_task_success"] is False
    assert ACP_STDIO_CLAIMS["acp_protocol_conformance_proven"] is False
    assert any("never task success" in claim for claim in ACP_STDIO_NON_CLAIMS)
    assert any(
        "does not establish checkpoint capture or product acceptance" in claim
        for claim in ACP_STDIO_NON_CLAIMS
    )


def test_transport_authority_rejects_unknown_values():
    assert NATIVE_PROMPT_TRANSPORTS == {PROMPT_TRANSPORT_ARGV, PROMPT_TRANSPORT_ACP_STDIO}
    for bad in ("", "argv", "acp", "ACP", "STDIO", None, 1, "ARGV_PROMPT "):
        with pytest.raises(ValueError):
            require_prompt_transport(bad, "transport")
    assert require_prompt_transport(PROMPT_TRANSPORT_ACP_STDIO, "t") == PROMPT_TRANSPORT_ACP_STDIO


def test_acp_runner_refuses_an_argv_transport_invocation(tmp_path):
    prompt = build_prompt(1024)
    started = StartedRecorder()
    with pytest.raises(NativeEvidenceInvalid):
        AcpStdioNativeProcessRunner().run(
            make_invocation(server_argv("success"), prompt, cwd=str(tmp_path),
                            started=started, transport=PROMPT_TRANSPORT_ARGV)
        )
    assert started.proofs == []


def test_acp_runner_refuses_argv_that_contains_the_prompt(tmp_path):
    prompt = build_prompt(1024)
    started = StartedRecorder()
    with pytest.raises(NativeEvidenceInvalid, match="never contain the prompt"):
        AcpStdioNativeProcessRunner().run(
            make_invocation(server_argv("success") + (prompt,), prompt,
                            cwd=str(tmp_path), started=started)
        )
    assert started.proofs == []


def test_prompt_binding_policy_is_declared():
    assert "prompt-never-in-argv" in ACP_STDIO_PROMPT_BINDING_POLICY
    assert "sha256-utf8-equality" in ACP_STDIO_PROMPT_BINDING_POLICY
    assert ATTESTATION_CLASS_ACP_STDIO == "LOCAL_ACP_STDIO"
