"""Windows argv-length guard: exact boundary, mutant kills and preflight refusal.

The guard exists because the Neon Relay v1 run reserved its single native
attempt and then died at ``CreateProcessW`` with WinError 206: its final
prompt-bearing command line was 64903 characters against a 32766-character
limit.  Every test here pins a property whose absence would let that happen
again.

No Cursor agent, no model and no provider process is involved.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from admissible.delegated_gate.mission_profile import (
    NEON_RELAY_PROFILE,
    NEON_RELAY_V2_PROFILE,
)
from admissible.delegated_gate.native_canary import (
    NATIVE_ARGV_LIMIT_REASON,
    NATIVE_TRANSPORT_BINDING_REASON,
    authorized_prompt_transport,
    preflight_prompt_transport_guard,
)
from admissible.delegated_gate.native_executor import (
    NativeArgvTooLongError,
    PROMPT_TRANSPORT_ACP_STDIO,
    PROMPT_TRANSPORT_ARGV,
    WINDOWS_MAX_COMMAND_LINE_CHARS,
    require_windows_spawnable_argv,
    windows_serialized_command_line,
)

WINDOWS_ONLY = pytest.mark.skipif(os.name != "nt", reason="Windows command-line limit")


def argv_with_serialized_length(total: int) -> tuple[str, ...]:
    """An argv whose ``list2cmdline`` serialization is exactly ``total`` chars.

    The filler is plain alphanumerics, so ``list2cmdline`` neither quotes nor
    escapes it and the length is exactly ``head + one separator + filler``.
    """

    head = ("C:\\node.exe", "index.js")
    base = len(windows_serialized_command_line(head))
    filler = "a" * (total - base - 1)
    argv = (*head, filler)
    assert len(windows_serialized_command_line(argv)) == total
    return argv


# ---------------------------------------------------------------------------
# Exact boundary
# ---------------------------------------------------------------------------


@WINDOWS_ONLY
def test_limit_is_the_empirically_established_boundary():
    assert WINDOWS_MAX_COMMAND_LINE_CHARS == 32766


@WINDOWS_ONLY
def test_serialized_length_32766_is_accepted():
    argv = argv_with_serialized_length(32766)
    assert require_windows_spawnable_argv(argv) == 32766


@WINDOWS_ONLY
def test_serialized_length_32767_is_refused():
    argv = argv_with_serialized_length(32767)
    with pytest.raises(NativeArgvTooLongError):
        require_windows_spawnable_argv(argv)


@WINDOWS_ONLY
@pytest.mark.parametrize("length", [32764, 32765, 32766])
def test_every_length_up_to_the_limit_is_accepted(length):
    assert require_windows_spawnable_argv(argv_with_serialized_length(length)) == length


@WINDOWS_ONLY
@pytest.mark.parametrize("length", [32767, 32768, 32769, 64903])
def test_every_length_past_the_limit_is_refused(length):
    with pytest.raises(NativeArgvTooLongError):
        require_windows_spawnable_argv(argv_with_serialized_length(length))


@WINDOWS_ONLY
def test_the_boundary_matches_real_createprocessw_behaviour():
    """The pinned constant is not folklore: prove it against a real spawn.

    32766 spawns; 32767 raises WinError 206.  Only ``python -c pass`` is ever
    started -- no provider is involved.
    """

    def attempt(total: int) -> str:
        head = [sys.executable, "-c", "pass"]
        base = len(subprocess.list2cmdline(head))
        argv = [*head, "a" * (total - base - 1)]
        assert len(subprocess.list2cmdline(argv)) == total
        try:
            proc = subprocess.Popen(
                argv, shell=False, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            proc.wait(timeout=60)
            return "spawned"
        except OSError as exc:
            return f"winerror_{getattr(exc, 'winerror', None)}"

    assert attempt(WINDOWS_MAX_COMMAND_LINE_CHARS) == "spawned"
    assert attempt(WINDOWS_MAX_COMMAND_LINE_CHARS + 1) == "winerror_206"


# ---------------------------------------------------------------------------
# Mutant kills
# ---------------------------------------------------------------------------


@WINDOWS_ONLY
def test_off_by_one_mutants_are_killed():
    """A guard using 32767 (or 32765) as the ceiling fails exactly one of these."""

    accepted = argv_with_serialized_length(WINDOWS_MAX_COMMAND_LINE_CHARS)
    refused = argv_with_serialized_length(WINDOWS_MAX_COMMAND_LINE_CHARS + 1)
    assert require_windows_spawnable_argv(accepted) == WINDOWS_MAX_COMMAND_LINE_CHARS
    with pytest.raises(NativeArgvTooLongError):
        require_windows_spawnable_argv(refused)
    # A ``>=`` mutant would refuse the accepted case; a ``+1`` mutant would
    # accept the refused case. Both are covered above.


@WINDOWS_ONLY
def test_measuring_one_argument_instead_of_the_serialized_argv_is_killed():
    """Many short members can exceed the limit while no single member does."""

    members = tuple("b" * 1000 for _ in range(40))
    argv = ("C:\\node.exe", *members)
    assert max(len(member) for member in argv) < WINDOWS_MAX_COMMAND_LINE_CHARS
    assert len(windows_serialized_command_line(argv)) > WINDOWS_MAX_COMMAND_LINE_CHARS
    with pytest.raises(NativeArgvTooLongError):
        require_windows_spawnable_argv(argv)


@WINDOWS_ONLY
def test_quoting_semantics_are_the_ones_subprocess_uses():
    """A naive ``' '.join(argv)` length undercounts quoted/escaped members."""

    argv = ("C:\\Program Files\\node.exe", 'a "quoted" value', "back\\slash\\")
    naive = len(" ".join(argv))
    serialized = len(windows_serialized_command_line(argv))
    assert serialized > naive
    assert windows_serialized_command_line(argv) == subprocess.list2cmdline(list(argv))


@WINDOWS_ONLY
def test_checking_only_the_static_template_is_killed():
    """The template's ``{prompt}`` placeholder is 8 characters; the real member
    was 64660. A guard that measured the template would have passed v1."""

    template = (
        "C:\\Users\\x\\AppData\\Local\\cursor-agent\\versions\\v\\node.exe",
        "C:\\Users\\x\\AppData\\Local\\cursor-agent\\versions\\v\\index.js",
        "--print", "--output-format", "stream-json", "--force", "--trust",
        "--model", "auto", "{prompt}",
    )
    assert require_windows_spawnable_argv(template) < 1000
    final = (*template[:-1], "P" * 64660)
    with pytest.raises(NativeArgvTooLongError):
        require_windows_spawnable_argv(final)


# ---------------------------------------------------------------------------
# Diagnostic content
# ---------------------------------------------------------------------------


@WINDOWS_ONLY
def test_diagnostic_reports_lengths_and_limit_only():
    secret = "SUPERSECRET-PROMPT-FRAGMENT-" + "z" * 40000
    argv = ("C:\\node.exe", secret)
    with pytest.raises(NativeArgvTooLongError) as excinfo:
        require_windows_spawnable_argv(argv, label="native prompt-bearing argv")
    message = str(excinfo.value)
    assert str(WINDOWS_MAX_COMMAND_LINE_CHARS) in message
    assert str(len(windows_serialized_command_line(argv))) in message
    # No prompt content of any length leaks into the diagnostic.
    assert "SUPERSECRET" not in message
    assert "zzzz" not in message
    assert len(message) < 400


# ---------------------------------------------------------------------------
# Transport binding
# ---------------------------------------------------------------------------


def test_profile_transports_are_pinned():
    assert NEON_RELAY_PROFILE.prompt_transport == PROMPT_TRANSPORT_ARGV
    assert NEON_RELAY_V2_PROFILE.prompt_transport == PROMPT_TRANSPORT_ACP_STDIO


def test_transport_binding_requires_profile_and_attestation_to_agree():
    class FakeAttestation:
        prompt_transport = PROMPT_TRANSPORT_ACP_STDIO

    assert authorized_prompt_transport(NEON_RELAY_V2_PROFILE, FakeAttestation()) == (
        PROMPT_TRANSPORT_ACP_STDIO
    )
    with pytest.raises(ValueError, match="disagree"):
        authorized_prompt_transport(NEON_RELAY_PROFILE, FakeAttestation())


def test_transport_binding_rejects_unknown_attestation_transport():
    class BadAttestation:
        prompt_transport = "SOMETHING_ELSE"

    with pytest.raises(ValueError):
        authorized_prompt_transport(NEON_RELAY_V2_PROFILE, BadAttestation())


# ---------------------------------------------------------------------------
# Preflight refusal, before any run root or attempt exists
# ---------------------------------------------------------------------------


class _StubArgvAttestation:
    """The exact v1 wrapper-chain shape: prompt substituted into the last member."""

    prompt_transport = PROMPT_TRANSPORT_ARGV
    static_argv_template = (
        "C:\\Users\\stris\\AppData\\Local\\cursor-agent\\versions\\2026.07.20-8cc9c0b\\node.exe",
        "C:\\Users\\stris\\AppData\\Local\\cursor-agent\\versions\\2026.07.20-8cc9c0b\\index.js",
        "--print", "--output-format", "stream-json", "--force", "--trust",
        "--model", "auto", "{prompt}",
    )

    def argv(self, *, prompt: str) -> tuple[str, ...]:
        return (*self.static_argv_template[:-1], prompt)


class _StubAcpAttestation:
    prompt_transport = PROMPT_TRANSPORT_ACP_STDIO
    static_argv_template = (
        "C:\\Users\\stris\\AppData\\Local\\cursor-agent\\versions\\2026.07.20-8cc9c0b\\node.exe",
        "C:\\Users\\stris\\AppData\\Local\\cursor-agent\\versions\\2026.07.20-8cc9c0b\\index.js",
        "acp",
    )

    def argv(self, *, prompt: str) -> tuple[str, ...]:
        return tuple(self.static_argv_template)


@WINDOWS_ONLY
def test_neon_relay_v1_preflight_is_refused_for_the_argv_limit(tmp_path):
    run_root = tmp_path / "native-cursor-neon-relay-001"
    with pytest.raises(NativeArgvTooLongError) as excinfo:
        preflight_prompt_transport_guard(
            profile=NEON_RELAY_PROFILE,
            session_id=NEON_RELAY_PROFILE.session_id,
            run_root=run_root,
            attestation=_StubArgvAttestation(),
            transport=PROMPT_TRANSPORT_ARGV,
        )
    message = str(excinfo.value)
    assert str(WINDOWS_MAX_COMMAND_LINE_CHARS) in message
    # Refusal consumed nothing: the run root was never created.
    assert not run_root.exists()
    assert list(tmp_path.iterdir()) == []


@WINDOWS_ONLY
def test_neon_relay_v2_preflight_passes_with_the_acp_transport(tmp_path):
    run_root = tmp_path / "native-cursor-neon-relay-002"
    diagnostic = preflight_prompt_transport_guard(
        profile=NEON_RELAY_V2_PROFILE,
        session_id=NEON_RELAY_V2_PROFILE.session_id,
        run_root=run_root,
        attestation=_StubAcpAttestation(),
        transport=PROMPT_TRANSPORT_ACP_STDIO,
    )
    assert diagnostic["prompt_transport"] == PROMPT_TRANSPORT_ACP_STDIO
    assert diagnostic["prompt_in_argv"] is False
    assert diagnostic["serialized_command_line_chars"] < 1000
    assert diagnostic["serialized_command_line_limit_chars"] == WINDOWS_MAX_COMMAND_LINE_CHARS
    assert diagnostic["argv_member_count"] == 3
    # The very same mission prompt that cannot fit an argv.
    assert diagnostic["prompt_utf8_bytes"] > WINDOWS_MAX_COMMAND_LINE_CHARS
    assert not run_root.exists()


@WINDOWS_ONLY
def test_the_two_neon_relay_profiles_project_the_same_prompt_size(tmp_path):
    """v2 changed identity and transport only: the prompt is the same size."""

    v1 = preflight_prompt_transport_guard(
        profile=NEON_RELAY_PROFILE, session_id=NEON_RELAY_PROFILE.session_id,
        run_root=tmp_path / "native-cursor-neon-relay-001",
        attestation=_StubAcpAttestation(), transport=PROMPT_TRANSPORT_ACP_STDIO,
    )
    v2 = preflight_prompt_transport_guard(
        profile=NEON_RELAY_V2_PROFILE, session_id=NEON_RELAY_V2_PROFILE.session_id,
        run_root=tmp_path / "native-cursor-neon-relay-002",
        attestation=_StubAcpAttestation(), transport=PROMPT_TRANSPORT_ACP_STDIO,
    )
    # Only the workspace path differs, and both roots have the same length.
    assert v1["prompt_utf8_bytes"] == v2["prompt_utf8_bytes"]


@WINDOWS_ONLY
def test_projected_prompt_matches_the_real_failed_run_measurement(tmp_path):
    """Pin the exact forensic numbers from native-cursor-neon-relay-001."""

    run_root = Path(
        r"C:\Users\stris\Documents\Projets\ENTRE\_neon-relay-runs\native-cursor-neon-relay-001"
    )
    try:
        diagnostic = preflight_prompt_transport_guard(
            profile=NEON_RELAY_PROFILE, session_id=NEON_RELAY_PROFILE.session_id,
            run_root=run_root, attestation=_StubAcpAttestation(),
            transport=PROMPT_TRANSPORT_ACP_STDIO,
        )
    except ValueError as exc:  # pragma: no cover - host-specific fixture path
        pytest.skip(f"neon relay fixture unavailable: {exc}")
    assert diagnostic["prompt_utf8_bytes"] == 64660
    assert diagnostic["prompt_chars"] == 64660

    # The exact argv this same prompt produces under the v1 argv transport is
    # the one that died with WinError 206: 64903 serialized characters. The
    # 243-character excess over the raw prompt is the launcher prefix plus the
    # quoting/escaping ``list2cmdline`` applies to the prompt member itself.
    with pytest.raises(NativeArgvTooLongError) as excinfo:
        preflight_prompt_transport_guard(
            profile=NEON_RELAY_PROFILE, session_id=NEON_RELAY_PROFILE.session_id,
            run_root=run_root, attestation=_StubArgvAttestation(),
            transport=PROMPT_TRANSPORT_ARGV,
        )
    assert "64903 characters" in str(excinfo.value)
