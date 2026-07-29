"""Real pinned Codex 0.145.0 provider-free serialization witness.

The witness proves that the content-attested pinned executable serializes
exactly ``model = gpt-5.3-codex`` and ``reasoning.effort = low`` onto its
outbound request, and that it fails for ``auto``, an omitted model, another
model, changed casing, an omitted effort, a substituted effort and a
substituted configuration.

Everything runs with synthetic authentication inside a private routeless
network namespace whose only interface is loopback.  No public DNS name, no
public endpoint and no real model or provider execution is involved: the
synthetic endpoint answers every request with a terminal stream failure.

Pinned Codex 0.145.0 compiles its TLS trust anchors in and 0.145.0 exposes no
configuration key or environment variable for an additional certificate
authority, so a synthetic TLS certificate cannot be trusted by the real
client.  The endpoint is therefore cleartext on loopback inside the private
namespace.  See ``admissible.capsule.serialization_witness`` for the recorded
policy, including what the witness does *not* prove.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from admissible.capsule.execution_authority import ExecutableFileIdentity
from admissible.capsule.host_codex_backend import (
    initialize_request,
    thread_start_request,
    turn_start_request,
)
from admissible.capsule.model_authority import (
    CANARY_CONFIGURED_MODEL,
    CANARY_CONFIGURED_REASONING_EFFORT,
    CodexModelAuthority,
    ephemeral_config_bytes,
)
from admissible.capsule.serialization_witness import (
    SerializationWitnessError,
    evaluate_serialization_witness,
    extract_witness_record,
    serialization_witness_identity,
)


PINNED_VERSION = "0.145.0"
DRIVER = Path(__file__).parent / "_canary_serialization_witness_driver.py"


def _interpreter_bindings() -> tuple[str, ...]:
    """Re-bind the interpreter tree when it lives under the namespace tmpfs."""

    bindings: list[str] = []
    for root in {Path(sys.prefix).resolve(), Path(sys.executable).resolve().parent}:
        if root.is_relative_to(Path("/tmp")):
            bindings.extend(("--ro-bind", str(root), str(root)))
    return tuple(bindings)


def _pinned_codex() -> Path:
    override = os.environ.get("ADMISSIBLE_PINNED_CODEX")
    candidates = []
    if override:
        candidates.append(Path(override))
    releases = Path.home() / ".codex" / "packages" / "standalone" / "releases"
    if releases.is_dir():
        candidates.extend(
            sorted(
                release / "bin" / "codex"
                for release in releases.iterdir()
                if release.name.startswith(f"{PINNED_VERSION}-")
            )
        )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    pytest.skip(f"pinned Codex {PINNED_VERSION} executable is not installed locally")


@pytest.fixture(scope="module")
def pinned_codex() -> Path:
    executable = _pinned_codex()
    completed = subprocess.run(
        (str(executable), "--version"),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
    )
    if completed.returncode != 0 or PINNED_VERSION not in completed.stdout:
        pytest.skip(f"local executable is not codex-cli {PINNED_VERSION}")
    if shutil.which("bwrap") is None:
        pytest.skip("provider-free witness requires local bubblewrap")
    return executable


@pytest.fixture(scope="module")
def pinned_identity(pinned_codex: Path) -> ExecutableFileIdentity:
    return ExecutableFileIdentity.attest(
        pinned_codex, label=f"pinned Codex {PINNED_VERSION} executable"
    )


def _authority(identity: ExecutableFileIdentity, *, model, effort) -> CodexModelAuthority:
    return CodexModelAuthority.create(
        configured_model=model,
        configured_reasoning_effort=effort,
        codex_executable_identity=identity.to_dict(),
        serialization_witness_identity=serialization_witness_identity(),
    )


def _scenario(name: str, *, thread_params, turn_params) -> dict:
    return {
        "name": name,
        "initialize_params": initialize_request("witness-initialize")["params"],
        "thread_params": thread_params,
        "turn_params": turn_params,
    }


def _bound_scenario(name: str, authority: CodexModelAuthority) -> dict:
    thread = thread_start_request("witness-thread", model_authority=authority)["params"]
    turn = turn_start_request(
        "witness-turn",
        thread_id="00000000-0000-0000-0000-000000000000",
        prompt="witness",
        model_authority=authority,
    )["params"]
    turn.pop("threadId")
    turn.pop("input")
    return _scenario(name, thread_params=thread, turn_params=turn)


def _run_witness(
    tmp_path: Path,
    codex: Path,
    scenarios: list[dict],
    *,
    canonical_config: bytes,
) -> dict:
    request_path = tmp_path / "witness-request.json"
    output_path = tmp_path / "witness-result.json"
    home = tmp_path / "witness-codex-home"
    workspace = tmp_path / "witness-cwd"
    request_path.write_text(
        json.dumps(
            {
                "canonical_config": canonical_config.decode("utf-8"),
                "scenarios": scenarios,
                "timeout_seconds": 40,
            }
        ),
        encoding="utf-8",
    )
    completed = subprocess.run(
        (
            "bwrap",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-user",
            "--new-session",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            *_interpreter_bindings(),
            "--bind",
            str(tmp_path),
            str(tmp_path),
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "LC_ALL",
            "C.UTF-8",
            "--chdir",
            str(tmp_path),
            sys.executable,
            str(DRIVER),
            str(codex),
            str(home),
            str(workspace),
            str(request_path),
            str(output_path),
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=60 + 45 * len(scenarios),
    )
    if completed.returncode != 0 or not output_path.exists():
        pytest.fail(
            "provider-free witness namespace failed: "
            f"rc={completed.returncode} stderr={completed.stderr[-2000:]}"
        )
    return json.loads(output_path.read_text(encoding="utf-8"))


def _records(scenario_result):
    return [
        extract_witness_record(
            request_path=capture["request_path"],
            request_body={
                "model": capture["model"],
                "reasoning": {"effort": capture["reasoning_effort"]},
            },
        )
        for capture in scenario_result.get("captures", ())
    ]


def test_namespace_is_private_and_routeless(tmp_path: Path, pinned_codex: Path):
    """The witness namespace has loopback only and no route off the host."""

    completed = subprocess.run(
        (
            "bwrap",
            "--unshare-net",
            "--unshare-pid",
            "--unshare-user",
            "--new-session",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            *_interpreter_bindings(),
            sys.executable,
            "-c",
            (
                "import json,socket\n"
                "result={}\n"
                "s=socket.socket(); s.bind(('127.0.0.1',0)); s.listen(1)\n"
                "result['loopback_bound']=True\n"
                "try:\n"
                "    socket.create_connection(('1.1.1.1',443),timeout=2)\n"
                "    result['egress']=True\n"
                "except OSError:\n"
                "    result['egress']=False\n"
                "try:\n"
                "    socket.getaddrinfo('chatgpt.com',443)\n"
                "    result['dns']=True\n"
                "except OSError:\n"
                "    result['dns']=False\n"
                "print(json.dumps(result))\n"
            ),
        ),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    observed = json.loads(completed.stdout)
    assert observed["loopback_bound"] is True
    assert observed["egress"] is False
    assert observed["dns"] is False


def test_pinned_executable_is_content_attested_not_a_mutable_symlink(
    pinned_codex: Path, pinned_identity: ExecutableFileIdentity
):
    assert pinned_identity.canonical_path == os.fspath(pinned_codex)
    assert f"{PINNED_VERSION}-" in pinned_identity.canonical_path
    pinned_identity.reattest(label="pinned Codex executable")
    mutable = Path.home() / ".local" / "bin" / "codex"
    if mutable.is_symlink():
        with pytest.raises(ValueError, match="symlink"):
            ExecutableFileIdentity.attest(mutable, label="mutable Codex symlink")
    current = Path.home() / ".codex" / "packages" / "standalone" / "current"
    if current.is_symlink():
        with pytest.raises(ValueError, match="symlink"):
            ExecutableFileIdentity.attest(
                current / "bin" / "codex", label="mutable Codex release symlink"
            )


def test_pinned_client_serializes_the_exact_bound_model_and_effort(
    tmp_path: Path, pinned_codex: Path, pinned_identity: ExecutableFileIdentity
):
    authority = _authority(
        pinned_identity,
        model=CANARY_CONFIGURED_MODEL,
        effort=CANARY_CONFIGURED_REASONING_EFFORT,
    )
    results = _run_witness(
        tmp_path,
        pinned_codex,
        [_bound_scenario("bound", authority)],
        canonical_config=authority.ephemeral_config_bytes,
    )
    scenario = results["scenarios"][0]
    assert "startup_error" not in scenario, scenario
    # Configured evidence reported by the app server before any effect.
    assert scenario["thread_start_model"] == "gpt-5.3-codex"
    assert scenario["thread_start_reasoning_effort"] == "low"
    # Provider-free serialized evidence taken off the real request.
    records = _records(scenario)
    evidence = evaluate_serialization_witness(records, authority)
    assert evidence["provider_free_serialized_model"] == "gpt-5.3-codex"
    assert evidence["provider_free_serialized_reasoning_effort"] == "low"
    assert evidence["observed_requests"] >= 1
    assert evidence["real_service_selected_model"] == "CANARY_TIME_OBSERVATION_ONLY"
    assert records[0].request_path.endswith("/responses")


def _strip(scenario: dict, *, model: bool = False, effort: bool = False) -> dict:
    """Remove a value from every layer of the channel, not only one of them."""

    if model:
        scenario["thread_params"].pop("model", None)
        scenario["thread_params"]["config"].pop("model", None)
        scenario["turn_params"].pop("model", None)
    if effort:
        scenario["thread_params"]["config"].pop("model_reasoning_effort", None)
        scenario["turn_params"].pop("effort", None)
    return scenario


def _substitute(scenario: dict, *, model: str | None = None, effort: str | None = None):
    if model is not None:
        scenario["thread_params"]["model"] = model
        scenario["thread_params"]["config"]["model"] = model
        scenario["turn_params"]["model"] = model
    if effort is not None:
        scenario["thread_params"]["config"]["model_reasoning_effort"] = effort
        scenario["turn_params"]["effort"] = effort
    return scenario


NEGATIVE_CASES = {
    "auto-model": (lambda s: _substitute(s, model="auto"), "bound"),
    "other-model": (lambda s: _substitute(s, model="gpt-5.6-sol"), "bound"),
    "changed-casing": (lambda s: _substitute(s, model="GPT-5.3-Codex"), "bound"),
    "medium-effort": (lambda s: _substitute(s, effort="medium"), "bound"),
    "high-effort": (lambda s: _substitute(s, effort="high"), "bound"),
    "xhigh-effort": (lambda s: _substitute(s, effort="xhigh"), "bound"),
    "omitted-model": (lambda s: _strip(s, model=True), "no-model"),
    "omitted-effort": (lambda s: _strip(s, effort=True), "no-effort"),
    "omitted-everything": (
        lambda s: _strip(s, model=True, effort=True),
        "empty",
    ),
}

CONFIGS = {
    "bound": lambda authority: authority.ephemeral_config_bytes,
    "no-model": lambda authority: authority.ephemeral_config_bytes.replace(
        b'model = "gpt-5.3-codex"\n', b""
    ),
    "no-effort": lambda authority: authority.ephemeral_config_bytes.replace(
        b'model_reasoning_effort = "low"\n', b""
    ),
    "empty": lambda authority: (
        authority.ephemeral_config_bytes.replace(
            b'model = "gpt-5.3-codex"\n', b""
        ).replace(b'model_reasoning_effort = "low"\n', b"")
    ),
}


@pytest.mark.parametrize("name", sorted(NEGATIVE_CASES))
def test_witness_fails_for_every_substituted_configuration(
    tmp_path: Path,
    pinned_codex: Path,
    pinned_identity: ExecutableFileIdentity,
    name: str,
):
    """Substituting or omitting either value at every layer breaks the witness."""

    authority = _authority(
        pinned_identity,
        model=CANARY_CONFIGURED_MODEL,
        effort=CANARY_CONFIGURED_REASONING_EFFORT,
    )
    mutate, config_key = NEGATIVE_CASES[name]
    scenario = mutate(_bound_scenario(name, authority))
    results = _run_witness(
        tmp_path,
        pinned_codex,
        [scenario],
        canonical_config=CONFIGS[config_key](authority),
    )
    observed = results["scenarios"][0]
    with pytest.raises(SerializationWitnessError):
        evaluate_serialization_witness(_records(observed), authority)


def test_witness_fails_for_a_substituted_ephemeral_configuration(
    tmp_path: Path, pinned_codex: Path, pinned_identity: ExecutableFileIdentity
):
    """A configuration bound to another model cannot satisfy the canary."""

    bound = _authority(
        pinned_identity,
        model=CANARY_CONFIGURED_MODEL,
        effort=CANARY_CONFIGURED_REASONING_EFFORT,
    )
    substituted = _authority(pinned_identity, model="gpt-5.6-sol", effort="high")
    assert substituted.ephemeral_config_bytes != bound.ephemeral_config_bytes
    results = _run_witness(
        tmp_path,
        pinned_codex,
        [_bound_scenario("substituted-config", substituted)],
        canonical_config=ephemeral_config_bytes(
            model="gpt-5.6-sol", reasoning_effort="high"
        ),
    )
    observed = results["scenarios"][0]
    with pytest.raises(SerializationWitnessError):
        evaluate_serialization_witness(_records(observed), bound)


def test_witness_fails_for_a_substituted_mutable_executable(
    tmp_path: Path, pinned_identity: ExecutableFileIdentity
):
    """A different Codex build cannot satisfy the bound model authority."""

    releases = Path.home() / ".codex" / "packages" / "standalone" / "releases"
    others = [
        release / "bin" / "codex"
        for release in sorted(releases.iterdir())
        if release.is_dir() and not release.name.startswith(f"{PINNED_VERSION}-")
    ] if releases.is_dir() else []
    others = [item for item in others if item.is_file()]
    if not others:
        pytest.skip("no second local Codex build is available to substitute")
    substituted = ExecutableFileIdentity.attest(
        others[0], label="substituted Codex executable"
    )
    assert substituted.sha256 != pinned_identity.sha256
    bound = _authority(
        pinned_identity,
        model=CANARY_CONFIGURED_MODEL,
        effort=CANARY_CONFIGURED_REASONING_EFFORT,
    )
    drifted = _authority(
        substituted,
        model=CANARY_CONFIGURED_MODEL,
        effort=CANARY_CONFIGURED_REASONING_EFFORT,
    )
    assert drifted.authority_fingerprint != bound.authority_fingerprint
