"""Step 5C2E1B: the real operator startup surface for historical pairing.

This module pins the entrypoint's complete contract: the two new filesystem
locator options, the four-state presence matrix, the loader-before-loader-before
-``ProductLauncher`` ordering, the identity of the two values that cross the
accepted constructor seam, the bounded fixed-code startup refusal, and the
preservation of every unrelated startup failure.

The behavioral tests carry the authority.  The static complement at the end is
secondary evidence only: it can prove an absence in the source text, never a
behavior.
"""

from __future__ import annotations

import ast
import base64
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
from http.client import HTTPConnection
from types import SimpleNamespace

import pytest

from admissible.delegated_gate.historical_pairing_workflow import (
    InvalidPairingCoordinatorConfiguration,
)
from admissible.delegated_gate.native_canary import (
    EVIDENCE_DIRECTORY_NAME,
    NATIVE_SIDECAR_DIRECTORY_NAME,
    WORKSPACE_DIRECTORY_NAME,
    NativeCanaryAuthorizationPayloadV4,
    load_historical_native_canary_authorization_payload_v4,
)
from admissible.historical_pairing_secret_file import (
    HISTORICAL_PAIRING_SECRET_LENGTH_INVALID,
    HISTORICAL_PAIRING_SECRET_PATH_INVALID,
    HISTORICAL_PAIRING_SECRET_UNAVAILABLE,
    HistoricalPairingSecretFileError,
)
from admissible.product_launcher import __main__ as entrypoint
from admissible.product_launcher import launcher as launcher_module
from admissible.product_launcher.historical_pairing_enablement import (
    HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID,
    HISTORICAL_PAIRING_CONFIG_MALFORMED,
    HISTORICAL_PAIRING_CONFIG_PATH_INVALID,
    HISTORICAL_PAIRING_CONFIG_UNAVAILABLE,
    HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION,
    HistoricalPairingEnablementDocumentError,
)
from admissible.product_launcher.historical_pairing_registry import (
    HistoricalPairingConfiguration,
    HistoricalPayloadEntry,
    HistoricalPayloadNotFound,
    HistoricalPayloadRegistryError,
    InvalidHistoricalPairingConfiguration,
    MalformedHistoricalPayloadDocument,
)
from admissible.product_launcher.historical_pairing_service import (
    HistoricalPairingFeatureConfigurationError,
)
from test_admissible_historical_evaluation_pairing import (
    _payload_for_runtime_profile,
    _refingerprint_payload,
)
from test_admissible_historical_v5_derivation import _runtime_v2_profile
from test_admissible_workflow_recovery_profile import _payload_harness


# Both are derived from the module actually imported, never from this file's own
# location, so an external mutant copy of the package is the thing examined and
# the thing launched.
ENTRYPOINT_SOURCE = Path(entrypoint.__file__).resolve()
PACKAGE_ROOT = ENTRYPOINT_SOURCE.parents[2]
READINESS = re.compile(r"^ui=http://127\.0\.0\.1:(\d+)/ g2_port=(\d+)$")
HISTORICAL_PAYLOADS_ROUTE = "/ui/api/v1/historical-pairings/payloads"

# Exactly the two new option strings, and nothing else.
NEW_OPTION_STRINGS = frozenset(
    {"--historical-pairing-config", "--historical-pairing-secret-file"}
)

# The configured secret used by every doubled test.  It carries trailing bytes a
# trimming defect would remove, so an accidental strip/normalize is a value
# change and not merely an identity change.
CONFIGURED_SECRET = b"CONFIGURED-HISTORICAL-SECRET-0123456789 \r\n"
# One real configured secret for the subprocess smoke: exact bytes, no trimming.
SMOKE_SECRET = b"smoke-historical-pairing-secret-0123456789\n"

# One accepted, inert configuration object for the doubled tests.  Using the real
# accepted type rather than an opaque sentinel means a "rebuild instead of pass
# through" defect produces an equal-but-distinct object and is caught by the
# identity assertion rather than by an incidental attribute error.
ACCEPTED_CONFIGURATION = HistoricalPairingConfiguration(
    archive_root=Path(os.path.abspath(os.sep + "historical-archive")),
    payload_entries=(
        HistoricalPayloadEntry(
            payload_id="doubled-payload",
            document_path=Path(os.path.abspath(os.sep + "historical-payload.json")),
        ),
    ),
    preparation_ttl_seconds=600,
    max_preparations=4,
)

# Environment variables a fallback defect would plausibly reach for.  None of
# them may ever influence this entrypoint.
FORBIDDEN_SECRET_ENVIRONMENT = (
    "ADMISSIBLE_HISTORICAL_PAIRING_SECRET",
    "HISTORICAL_PAIRING_SECRET",
    "ADMISSIBLE_HISTORICAL_PAIRING_SECRET_FILE",
)


# ---------------------------------------------------------------------------
# Independent canonical-JSON oracle, re-implemented with the standard library.
# ---------------------------------------------------------------------------


def _oracle_canonical_bytes(mapping: dict) -> bytes:
    return json.dumps(
        mapping, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Fixtures: one real source repository, one real standalone canonical V4.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def source_repository(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    """One ordinary git repository with one known HEAD, outside this repository."""

    root = tmp_path_factory.mktemp("s5c2e1b-src")
    repository = root / "source"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=entrypoint@example.invalid",
            "-c",
            "user.name=entrypoint",
            "commit",
            "--allow-empty",
            "-q",
            "-m",
            "base",
        ],
        cwd=repository,
        check=True,
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert len(head) in {40, 64}
    return SimpleNamespace(path=repository, head=head.lower())


@pytest.fixture(scope="module")
def historical_payload(
    tmp_path_factory: pytest.TempPathFactory,
) -> NativeCanaryAuthorizationPayloadV4:
    """One standalone historical V4 payload whose carried paths are all absent."""

    fixture_root = tmp_path_factory.mktemp("s5c2e1b-v4")
    runtime_profile = _runtime_v2_profile()
    live = _payload_harness(fixture_root, runtime_profile).payload.to_dict()
    absent = fixture_root / "absent-original-material"
    live["source_repository"] = str(absent / "source")
    live["executable"] = str(absent / "bin" / "agent.exe")
    live["launcher_prefix"] = [
        str(absent / "bin" / f"launcher-{index}.exe")
        for index, _value in enumerate(live["launcher_prefix"])
    ]
    run_root = absent / runtime_profile.run_id
    live["run_root"] = str(run_root)
    live["workspace_root"] = str(run_root / WORKSPACE_DIRECTORY_NAME)
    live["evidence_root"] = str(run_root / EVIDENCE_DIRECTORY_NAME)
    live["native_sidecar_root"] = str(
        run_root / EVIDENCE_DIRECTORY_NAME / NATIVE_SIDECAR_DIRECTORY_NAME
    )
    payload = load_historical_native_canary_authorization_payload_v4(
        _refingerprint_payload(live)
    )
    assert not absent.exists()
    return payload


# ---------------------------------------------------------------------------
# Deterministic doubles around the real ``main()`` flow.
# ---------------------------------------------------------------------------


class _FakeLauncher:
    """Records exactly what the entrypoint handed to the constructor seam."""

    def __init__(self, recorder, args, kwargs, *, serve_error=None):
        self.args = args
        self.kwargs = kwargs
        self.ui_port = 43101
        self.g2_port = 43102
        self._recorder = recorder
        self._serve_error = serve_error

    def start(self):
        self._recorder.events.append("start")
        return self

    def serve_forever(self):
        self._recorder.events.append("serve_forever")
        if self._serve_error is not None:
            raise self._serve_error

    def close(self):
        self._recorder.events.append("close")


def _recorder() -> SimpleNamespace:
    return SimpleNamespace(
        events=[],
        configuration_paths=[],
        secret_paths=[],
        launcher_calls=[],
        launchers=[],
        namespace=None,
    )


def _install_loader_doubles(
    monkeypatch: pytest.MonkeyPatch,
    recorder: SimpleNamespace,
    *,
    configuration=None,
    secret=CONFIGURED_SECRET,
    configuration_error: BaseException | None = None,
    secret_error: BaseException | None = None,
):
    """Replace both accepted loaders with recording doubles."""

    loaded_configuration = (
        configuration if configuration is not None else ACCEPTED_CONFIGURATION
    )

    def _load(*, path):
        recorder.events.append("load_configuration")
        recorder.configuration_paths.append(path)
        if configuration_error is not None:
            raise configuration_error
        return loaded_configuration

    def _read(*, path):
        recorder.events.append("read_secret")
        recorder.secret_paths.append(path)
        if secret_error is not None:
            raise secret_error
        return secret

    monkeypatch.setattr(entrypoint, "load_historical_pairing_configuration", _load)
    monkeypatch.setattr(entrypoint, "read_historical_pairing_secret_file", _read)
    return loaded_configuration


def _install_launcher_double(
    monkeypatch: pytest.MonkeyPatch,
    recorder: SimpleNamespace,
    *,
    construction_error: BaseException | None = None,
    serve_error: BaseException | None = None,
    forbidden: bool = False,
):
    def _factory(*args, **kwargs):
        if forbidden:  # pragma: no cover - the assertion is the point
            raise AssertionError(
                "ProductLauncher must not be constructed for this startup"
            )
        recorder.events.append("construct_launcher")
        recorder.launcher_calls.append((args, kwargs))
        if construction_error is not None:
            raise construction_error
        launcher = _FakeLauncher(recorder, args, kwargs, serve_error=serve_error)
        recorder.launchers.append(launcher)
        return launcher

    monkeypatch.setattr(entrypoint, "ProductLauncher", _factory)


def _install_parser_recorder(
    monkeypatch: pytest.MonkeyPatch, recorder: SimpleNamespace
) -> None:
    """Keep the real parser and capture the exact namespace it produced."""

    real_build = entrypoint.build_parser

    def _build():
        parser = real_build()
        real_parse = parser.parse_args

        def _parse(argv=None):
            namespace = real_parse(argv)
            recorder.namespace = namespace
            return namespace

        parser.parse_args = _parse
        return parser

    monkeypatch.setattr(entrypoint, "build_parser", _build)


def _install_side_effect_probes(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Record every worker pool and every socket bind the real launcher performs."""

    probes = SimpleNamespace(workers=[], binds=[], threads=[])
    from admissible.product_service import control as control_module

    for module in (launcher_module, control_module):
        real_pool = getattr(module, "ThreadPoolExecutor")

        def _pool(*args, _real=real_pool, **kwargs):
            probes.workers.append(_real.__name__)
            return _real(*args, **kwargs)

        monkeypatch.setattr(module, "ThreadPoolExecutor", _pool)

    real_bind = socket.socket.bind

    def _bind(self, address):
        probes.binds.append(address)
        return real_bind(self, address)

    monkeypatch.setattr(socket.socket, "bind", _bind)

    real_start = threading.Thread.start

    def _start(self):
        probes.threads.append(self.name)
        return real_start(self)

    monkeypatch.setattr(threading.Thread, "start", _start)
    return probes


def _argv(
    *,
    source: Path,
    head: str,
    run_parent: Path,
    contracts: Path,
    extra: tuple[str, ...] = (),
) -> list[str]:
    return [
        "--source-repository",
        str(source),
        "--required-source-head",
        head,
        "--run-parent",
        str(run_parent),
        "--contract-documents-directory",
        str(contracts),
        "--executable",
        "cursor-agent",
        "--no-browser",
        *extra,
    ]


@pytest.fixture()
def workspace(tmp_path: Path) -> SimpleNamespace:
    """Ordinary launcher locations that must stay absent on a refused startup."""

    source = tmp_path / "ordinary-source"
    source.mkdir()
    return SimpleNamespace(
        source=source,
        head="a" * 40,
        run_parent=tmp_path / "runs",
        contracts=tmp_path / "contracts",
        historical=tmp_path / "historical",
    )


def _assert_no_launcher_side_effects(workspace: SimpleNamespace) -> None:
    """No run directory and no contract directory may exist after a refusal."""

    assert not Path(str(workspace.run_parent)).resolve().exists()
    assert not Path(str(workspace.contracts)).resolve().exists()


# ---------------------------------------------------------------------------
# J. Default-startup compatibility: absent options change nothing at all.
# ---------------------------------------------------------------------------


def test_default_startup_constructs_the_launcher_exactly_as_before(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace, capsys
):
    recorder = _recorder()
    _install_loader_doubles(monkeypatch, recorder)
    _install_launcher_double(monkeypatch, recorder)

    exit_code = entrypoint.main(
        _argv(
            source=workspace.source,
            head=workspace.head,
            run_parent=workspace.run_parent,
            contracts=workspace.contracts,
        )
    )

    assert exit_code == 0
    args, kwargs = recorder.launcher_calls[0]
    # Exactly one positional argument and no keyword argument at all: no
    # explicit historical ``None`` kwargs are passed on a default launch.
    assert len(recorder.launcher_calls) == 1
    assert len(args) == 1
    assert kwargs == {}
    configuration = args[0]
    assert configuration.source_repository == workspace.source.resolve()
    assert configuration.required_source_head == workspace.head
    assert configuration.run_parent == Path(str(workspace.run_parent)).resolve()
    assert configuration.contract_documents_directory == (
        Path(str(workspace.contracts)).resolve()
    )
    assert configuration.executable == "cursor-agent"
    assert configuration.open_browser is False
    assert not hasattr(configuration, "historical_pairing_secret")
    assert not hasattr(configuration, "historical_pairing_configuration")
    assert recorder.events == ["construct_launcher", "start", "serve_forever", "close"]
    captured = capsys.readouterr()
    assert captured.out == "ui=http://127.0.0.1:43101/ g2_port=43102\n"
    assert captured.err == ""


def test_default_startup_never_touches_either_historical_loader(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace
):
    """Neither accepted loader runs, so no historical file is ever opened."""

    recorder = _recorder()
    _install_loader_doubles(monkeypatch, recorder)
    _install_launcher_double(monkeypatch, recorder)

    entrypoint.main(
        _argv(
            source=workspace.source,
            head=workspace.head,
            run_parent=workspace.run_parent,
            contracts=workspace.contracts,
        )
    )

    assert recorder.configuration_paths == []
    assert recorder.secret_paths == []
    assert "load_configuration" not in recorder.events
    assert "read_secret" not in recorder.events


def test_parser_defaults_are_pinned_including_both_absent_locators():
    namespace = entrypoint.build_parser().parse_args(
        [
            "--source-repository",
            "S",
            "--required-source-head",
            "H",
            "--run-parent",
            "R",
            "--contract-documents-directory",
            "C",
            "--executable",
            "E",
        ]
    )

    assert vars(namespace) == {
        "source_repository": "S",
        "required_source_head": "H",
        "run_parent": "R",
        "contract_documents_directory": "C",
        "executable": "E",
        "executable_prefix_arg": [],
        "attestation_class": "package-bin",
        "model_default": "auto",
        "timeout_default": 600,
        "timeout_maximum": 3600,
        "stdout_byte_limit": 8_388_608,
        "stderr_byte_limit": 1_048_576,
        "ui_port": 0,
        "g2_port": 0,
        "authorization_mode": "PRECOMMITTED_DIGEST",
        "no_browser": False,
        "historical_pairing_config": None,
        "historical_pairing_secret_file": None,
    }


def test_help_still_exits_zero_and_documents_both_locator_options(capsys):
    with pytest.raises(SystemExit) as raised:
        entrypoint.main(["--help"])

    assert raised.value.code == 0
    captured = capsys.readouterr()
    assert "--historical-pairing-config PATH" in captured.out
    assert "--historical-pairing-secret-file PATH" in captured.out
    assert captured.err == ""


def test_argument_errors_still_exit_two(capsys):
    with pytest.raises(SystemExit) as raised:
        entrypoint.main(["--source-repository", "S"])

    assert raised.value.code == 2
    assert capsys.readouterr().err != ""


def test_the_parser_exposes_exactly_two_new_options_and_no_literal_secret_option():
    """No ``--historical-pairing-secret`` action exists.

    argparse's pre-existing prefix abbreviation still resolves that spelling to
    the *file* option for every option in this parser, which is unchanged
    repository-wide behavior; what matters is that the value remains a
    filesystem locator and never literal secret material.
    """

    parser = entrypoint.build_parser()
    declared = {
        option
        for action in parser._actions
        for option in action.option_strings
        if option.startswith("--historical")
    }
    assert declared == NEW_OPTION_STRINGS

    namespace = parser.parse_args(
        [
            "--source-repository",
            "S",
            "--required-source-head",
            "H",
            "--run-parent",
            "R",
            "--contract-documents-directory",
            "C",
            "--executable",
            "E",
            "--historical-pairing-secret",
            "/tmp/locator",
        ]
    )
    assert namespace.historical_pairing_secret_file == Path("/tmp/locator")
    assert not hasattr(namespace, "historical_pairing_secret")


# ---------------------------------------------------------------------------
# C. Presence matrix: exactly one locator is a startup defect.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "option", ["--historical-pairing-config", "--historical-pairing-secret-file"]
)
def test_one_locator_alone_refuses_before_any_load_or_construction(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace, capsys, option
):
    recorder = _recorder()
    _install_loader_doubles(monkeypatch, recorder)
    _install_launcher_double(monkeypatch, recorder, forbidden=True)
    before = set(threading.enumerate())

    exit_code = entrypoint.main(
        _argv(
            source=workspace.source,
            head=workspace.head,
            run_parent=workspace.run_parent,
            contracts=workspace.contracts,
            extra=(option, str(workspace.historical / "value")),
        )
    )

    assert exit_code == entrypoint.HISTORICAL_PAIRING_STARTUP_EXIT_CODE == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error=HISTORICAL_PAIRING_CONFIGURATION_INCOMPLETE\n"
    # Refused before either loader, so no historical file was opened at all.
    assert recorder.events == []
    _assert_no_launcher_side_effects(workspace)
    assert set(threading.enumerate()) == before


@pytest.mark.parametrize(
    "option", ["--historical-pairing-config", "--historical-pairing-secret-file"]
)
def test_no_environment_variable_can_complete_a_partial_launch(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace, capsys, option
):
    """A partial launch stays a startup defect no matter what the environment holds.

    There is no environment fallback, no standard-input fallback, no prompt, and
    no keyring: the missing locator is missing, and the refusal is unconditional.
    """

    recorder = _recorder()
    _install_loader_doubles(monkeypatch, recorder)
    _install_launcher_double(monkeypatch, recorder, forbidden=True)
    for name in FORBIDDEN_SECRET_ENVIRONMENT:
        monkeypatch.setenv(name, str(workspace.historical / "supplied-by-environment"))

    exit_code = entrypoint.main(
        _argv(
            source=workspace.source,
            head=workspace.head,
            run_parent=workspace.run_parent,
            contracts=workspace.contracts,
            extra=(option, str(workspace.historical / "value")),
        )
    )

    assert exit_code == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error=HISTORICAL_PAIRING_CONFIGURATION_INCOMPLETE\n"
    assert recorder.events == []


# ---------------------------------------------------------------------------
# K. Enabled startup: order, identity, serving, and closing.
# ---------------------------------------------------------------------------


def test_enabled_startup_orders_configuration_then_secret_then_construction(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace, capsys
):
    recorder = _recorder()
    loaded = _install_loader_doubles(monkeypatch, recorder)
    _install_launcher_double(monkeypatch, recorder)
    _install_parser_recorder(monkeypatch, recorder)

    configuration_path = workspace.historical / "enablement.json"
    secret_path = workspace.historical / "secret.bin"
    exit_code = entrypoint.main(
        _argv(
            source=workspace.source,
            head=workspace.head,
            run_parent=workspace.run_parent,
            contracts=workspace.contracts,
            extra=(
                "--historical-pairing-config",
                str(configuration_path),
                "--historical-pairing-secret-file",
                str(secret_path),
            ),
        )
    )

    assert exit_code == 0
    assert recorder.events == [
        "load_configuration",
        "read_secret",
        "construct_launcher",
        "start",
        "serve_forever",
        "close",
    ]
    # Exactly once each.
    assert len(recorder.configuration_paths) == 1
    assert len(recorder.secret_paths) == 1
    assert len(recorder.launcher_calls) == 1

    # The exact Path objects argparse produced reach the loaders unchanged.
    assert recorder.configuration_paths[0] is recorder.namespace.historical_pairing_config
    assert recorder.secret_paths[0] is recorder.namespace.historical_pairing_secret_file
    assert recorder.configuration_paths[0] == configuration_path
    assert recorder.secret_paths[0] == secret_path

    args, kwargs = recorder.launcher_calls[0]
    # The ordinary configuration stays positional; both historical values are
    # keyword-only and are the exact objects the loaders returned.
    assert len(args) == 1
    launched_configuration = args[0]
    assert launched_configuration.source_repository == workspace.source.resolve()
    assert set(kwargs) == {
        "historical_pairing_configuration",
        "historical_pairing_secret",
    }
    assert kwargs["historical_pairing_configuration"] is loaded is ACCEPTED_CONFIGURATION
    assert kwargs["historical_pairing_secret"] is CONFIGURED_SECRET
    assert kwargs["historical_pairing_secret"] == CONFIGURED_SECRET
    # The non-secret ordinary configuration never gains either historical value,
    # neither as a declared field nor as a smuggled instance attribute.
    assert "historical_pairing_secret" not in vars(launched_configuration)
    assert "historical_pairing_configuration" not in vars(launched_configuration)
    assert [
        name
        for name, value in vars(launched_configuration).items()
        if isinstance(value, (bytes, bytearray))
    ] == []
    captured = capsys.readouterr()
    assert captured.out == "ui=http://127.0.0.1:43101/ g2_port=43102\n"
    assert captured.err == ""


def test_argparse_locators_are_never_resolved_expanded_or_absolutized(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace
):
    """A relative, ``~``-prefixed, or environment-shaped locator is passed as written.

    The accepted loaders are the sole path validators, so the entrypoint must
    hand them exactly what the operator typed and let them refuse it.
    """

    recorder = _recorder()
    _install_loader_doubles(monkeypatch, recorder)
    _install_launcher_double(monkeypatch, recorder)
    monkeypatch.setenv("ADMISSIBLE_ENTRYPOINT_PROBE", str(workspace.historical))

    for raw_configuration, raw_secret in (
        ("relative/enablement.json", "relative/secret.bin"),
        ("~/enablement.json", "~/secret.bin"),
        ("$ADMISSIBLE_ENTRYPOINT_PROBE/c.json", "%ADMISSIBLE_ENTRYPOINT_PROBE%/s.bin"),
        ("./a/../enablement.json", "./a/../secret.bin"),
    ):
        recorder.configuration_paths.clear()
        recorder.secret_paths.clear()
        entrypoint.main(
            _argv(
                source=workspace.source,
                head=workspace.head,
                run_parent=workspace.run_parent,
                contracts=workspace.contracts,
                extra=(
                    "--historical-pairing-config",
                    raw_configuration,
                    "--historical-pairing-secret-file",
                    raw_secret,
                ),
            )
        )
        assert recorder.configuration_paths == [Path(raw_configuration)]
        assert recorder.secret_paths == [Path(raw_secret)]
        assert str(recorder.configuration_paths[0]) == str(Path(raw_configuration))
        assert not recorder.configuration_paths[0].is_absolute()
        assert not recorder.secret_paths[0].is_absolute()


def test_close_runs_even_when_serving_raises(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace
):
    recorder = _recorder()
    _install_loader_doubles(monkeypatch, recorder)
    _install_launcher_double(
        monkeypatch, recorder, serve_error=KeyboardInterrupt("stop")
    )

    with pytest.raises(KeyboardInterrupt):
        entrypoint.main(
            _argv(
                source=workspace.source,
                head=workspace.head,
                run_parent=workspace.run_parent,
                contracts=workspace.contracts,
                extra=(
                    "--historical-pairing-config",
                    str(workspace.historical / "c.json"),
                    "--historical-pairing-secret-file",
                    str(workspace.historical / "s.bin"),
                ),
            )
        )

    assert recorder.events.count("close") == 1
    assert recorder.events[-1] == "close"


# ---------------------------------------------------------------------------
# E. Entrypoint-owned secret-reference minimization.
# ---------------------------------------------------------------------------


def _module_state_holding(module, needle: bytes) -> list[str]:
    """Bounded one-level scan of a module's globals for the configured secret."""

    encodings = {
        needle,
        base64.b64encode(needle),
        needle.hex().encode("ascii"),
    }
    found = []
    for name, value in list(vars(module).items()):
        candidates = [value]
        if isinstance(value, (list, tuple, set, frozenset)):
            candidates = list(value)
        elif isinstance(value, dict):
            candidates = list(value.keys()) + list(value.values())
        for candidate in candidates:
            if isinstance(candidate, (bytes, bytearray)) and bytes(candidate) in encodings:
                found.append(name)
            elif isinstance(candidate, str) and any(
                item.decode("latin-1") in candidate for item in encodings
            ):
                found.append(name)
    return found


def test_enabled_startup_retains_no_secret_in_entrypoint_state_or_output(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace, capsys
):
    recorder = _recorder()
    _install_loader_doubles(monkeypatch, recorder)
    _install_launcher_double(monkeypatch, recorder)

    entrypoint.main(
        _argv(
            source=workspace.source,
            head=workspace.head,
            run_parent=workspace.run_parent,
            contracts=workspace.contracts,
            extra=(
                "--historical-pairing-config",
                str(workspace.historical / "c.json"),
                "--historical-pairing-secret-file",
                str(workspace.historical / "s.bin"),
            ),
        )
    )

    captured = capsys.readouterr()
    for encoded in (
        CONFIGURED_SECRET.decode("latin-1"),
        base64.b64encode(CONFIGURED_SECRET).decode("ascii"),
        CONFIGURED_SECRET.hex(),
        str(len(CONFIGURED_SECRET)),
    ):
        assert encoded not in captured.out
        assert encoded not in captured.err
    assert _module_state_holding(entrypoint, CONFIGURED_SECRET) == []
    # The launcher legitimately received it; the entrypoint kept nothing.
    assert recorder.launcher_calls[0][1]["historical_pairing_secret"] is (
        CONFIGURED_SECRET
    )


def test_secret_reference_is_dropped_from_the_entrypoint_frame_on_failure(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace
):
    """An escaping construction failure must not carry the secret in a frame.

    Rebinding the local reference does not zeroize immutable Python bytes; it
    does keep the retained traceback frame from exposing them.
    """

    recorder = _recorder()
    _install_loader_doubles(monkeypatch, recorder)
    _install_launcher_double(
        monkeypatch,
        recorder,
        construction_error=ValueError("source repository HEAD does not match"),
    )

    with pytest.raises(ValueError) as raised:
        entrypoint.main(
            _argv(
                source=workspace.source,
                head=workspace.head,
                run_parent=workspace.run_parent,
                contracts=workspace.contracts,
                extra=(
                    "--historical-pairing-config",
                    str(workspace.historical / "c.json"),
                    "--historical-pairing-secret-file",
                    str(workspace.historical / "s.bin"),
                ),
            )
        )

    traceback = raised.value.__traceback__
    inspected = 0
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename == str(ENTRYPOINT_SOURCE):
            inspected += 1
            for name, value in frame.f_locals.items():
                assert value is not CONFIGURED_SECRET, name
                assert not (
                    isinstance(value, (bytes, bytearray))
                    and bytes(value) == CONFIGURED_SECRET
                ), name
        traceback = traceback.tb_next
    assert inspected >= 2


# ---------------------------------------------------------------------------
# L. Real loader failures: bounded code, fixed exit, and no side effect.
# ---------------------------------------------------------------------------


def _enablement_document(
    *,
    archive_root: Path,
    payloads: list[tuple[str, Path]],
    ttl_seconds: int = 600,
    max_preparations: int = 4,
    schema_version: str = HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION,
) -> str:
    return json.dumps(
        {
            "schema_version": schema_version,
            "archive_root": str(archive_root),
            "payloads": [
                {"payload_id": payload_id, "document_path": str(path)}
                for payload_id, path in payloads
            ],
            "preparation_ttl_seconds": ttl_seconds,
            "max_preparations": max_preparations,
        }
    )


@pytest.fixture()
def historical_files(
    tmp_path: Path, historical_payload: NativeCanaryAuthorizationPayloadV4
) -> SimpleNamespace:
    root = tmp_path / "historical"
    root.mkdir()
    document = root / "payload.json"
    document.write_bytes(_oracle_canonical_bytes(historical_payload.to_dict()))
    secret = root / "secret.bin"
    secret.write_bytes(SMOKE_SECRET)
    configuration = root / "enablement.json"
    configuration.write_text(
        _enablement_document(
            archive_root=root / "archive",
            payloads=[("smoke-payload", document)],
        ),
        encoding="utf-8",
    )
    return SimpleNamespace(
        root=root,
        document=document,
        secret=secret,
        configuration=configuration,
        archive_root=root / "archive",
    )


def _refused_startup(
    workspace: SimpleNamespace,
    *,
    configuration_path: Path,
    secret_path: Path,
    capsys,
    expected_code: str,
) -> None:
    exit_code = entrypoint.main(
        _argv(
            source=workspace.source,
            head=workspace.head,
            run_parent=workspace.run_parent,
            contracts=workspace.contracts,
            extra=(
                "--historical-pairing-config",
                str(configuration_path),
                "--historical-pairing-secret-file",
                str(secret_path),
            ),
        )
    )
    captured = capsys.readouterr()
    assert exit_code == 3
    assert captured.out == ""
    assert captured.err == f"error={expected_code}\n"
    assert "Traceback" not in captured.err
    assert captured.err.count("\n") == 1
    _assert_no_launcher_side_effects(workspace)


def test_loader_failures_refuse_boundedly_before_product_launcher(
    monkeypatch: pytest.MonkeyPatch,
    workspace: SimpleNamespace,
    historical_files: SimpleNamespace,
    tmp_path: Path,
    capsys,
):
    """Every accepted loader refusal, each proven to precede any construction."""

    recorder = _recorder()
    _install_launcher_double(monkeypatch, recorder, forbidden=True)
    probes = _install_side_effect_probes(monkeypatch)
    root = historical_files.root
    good_configuration = historical_files.configuration
    good_secret = historical_files.secret

    unavailable = root / "absent.json"
    malformed = root / "malformed.json"
    malformed.write_text("{not json", encoding="utf-8")
    fields_invalid = root / "fields.json"
    fields_invalid.write_text(
        json.dumps({"schema_version": HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION}),
        encoding="utf-8",
    )
    relative_archive = root / "relative-archive.json"
    relative_archive.write_text(
        json.dumps(
            {
                "schema_version": HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION,
                "archive_root": "relative-archive",
                "payloads": [
                    {
                        "payload_id": "smoke-payload",
                        "document_path": str(historical_files.document),
                    }
                ],
                "preparation_ttl_seconds": 600,
                "max_preparations": 4,
            }
        ),
        encoding="utf-8",
    )
    duplicate_id = root / "duplicate-id.json"
    second_document = root / "payload-copy.json"
    second_document.write_bytes(historical_files.document.read_bytes())
    duplicate_id.write_text(
        _enablement_document(
            archive_root=root / "archive",
            payloads=[
                ("smoke-payload", historical_files.document),
                ("smoke-payload", second_document),
            ],
        ),
        encoding="utf-8",
    )
    duplicate_path = root / "duplicate-path.json"
    duplicate_path.write_text(
        _enablement_document(
            archive_root=root / "archive",
            payloads=[
                ("smoke-payload", historical_files.document),
                ("other-payload", historical_files.document),
            ],
        ),
        encoding="utf-8",
    )
    short_secret = root / "short.bin"
    short_secret.write_bytes(b"tooshort")
    absent_secret = root / "absent.bin"

    cases = [
        ("configuration path invalid", Path("relative.json"), good_secret,
         HISTORICAL_PAIRING_CONFIG_PATH_INVALID),
        ("configuration unavailable", unavailable, good_secret,
         HISTORICAL_PAIRING_CONFIG_UNAVAILABLE),
        ("configuration malformed", malformed, good_secret,
         HISTORICAL_PAIRING_CONFIG_MALFORMED),
        ("configuration fields invalid", fields_invalid, good_secret,
         HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID),
        ("accepted configuration invalid", relative_archive, good_secret,
         entrypoint.HISTORICAL_PAIRING_CONFIGURATION_INVALID),
        ("duplicate payload identity", duplicate_id, good_secret,
         entrypoint.HISTORICAL_PAIRING_CONFIGURATION_INVALID),
        ("duplicate payload path", duplicate_path, good_secret,
         entrypoint.HISTORICAL_PAIRING_CONFIGURATION_INVALID),
        ("secret path invalid", good_configuration, Path("relative.bin"),
         HISTORICAL_PAIRING_SECRET_PATH_INVALID),
        ("secret unavailable", good_configuration, absent_secret,
         HISTORICAL_PAIRING_SECRET_UNAVAILABLE),
        ("secret length invalid", good_configuration, short_secret,
         HISTORICAL_PAIRING_SECRET_LENGTH_INVALID),
    ]
    for label, configuration_path, secret_path, expected in cases:
        _refused_startup(
            workspace,
            configuration_path=configuration_path,
            secret_path=secret_path,
            capsys=capsys,
            expected_code=expected,
        )
        assert recorder.events == [], label
        # No worker pool and no bound socket may exist for a refused startup.
        assert probes.workers == [], label
        assert probes.binds == [], label
        assert [name for name in probes.threads if "admissible" in name] == [], label
    assert not (tmp_path / "runs").exists()
    assert not (tmp_path / "contracts").exists()


def test_a_configuration_defect_is_refused_before_the_secret_file_is_opened(
    monkeypatch: pytest.MonkeyPatch,
    workspace: SimpleNamespace,
    historical_files: SimpleNamespace,
    capsys,
):
    recorder = _recorder()
    _install_launcher_double(monkeypatch, recorder, forbidden=True)
    opened: list[str] = []
    real_open = open

    def _tracking_open(file, *args, **kwargs):
        opened.append(str(file))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", _tracking_open)
    malformed = historical_files.root / "malformed.json"
    malformed.write_text("{", encoding="utf-8")

    _refused_startup(
        workspace,
        configuration_path=malformed,
        secret_path=historical_files.secret,
        capsys=capsys,
        expected_code=HISTORICAL_PAIRING_CONFIG_MALFORMED,
    )

    assert str(malformed) in opened
    assert str(historical_files.secret) not in opened


# ---------------------------------------------------------------------------
# L (continued). Real ProductLauncher historical-construction failures.
# ---------------------------------------------------------------------------


def _forbid_serving(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make "the launcher started serving" a loud failure instead of a hang.

    Every startup in this section must be refused before serving.  Left alone,
    a defect that reaches the real ``serve_forever`` would block the suite
    forever rather than report anything, so serving is turned into an immediate,
    reportable failure.  ``close`` still runs through the ordinary finally path.
    """

    def _must_not_serve(self):  # pragma: no cover - reaching it is the failure
        raise AssertionError("the launcher reached serve_forever after a refusal")

    monkeypatch.setattr(launcher_module.ProductLauncher, "serve_forever", _must_not_serve)


def _real_startup(
    workspace: SimpleNamespace,
    source_repository: SimpleNamespace,
    *,
    configuration_path: Path,
    secret_path: Path,
) -> int:
    return entrypoint.main(
        _argv(
            source=source_repository.path,
            head=source_repository.head,
            run_parent=workspace.run_parent,
            contracts=workspace.contracts,
            extra=(
                "--historical-pairing-config",
                str(configuration_path),
                "--historical-pairing-secret-file",
                str(secret_path),
            ),
        )
    )


@pytest.mark.parametrize(
    "case",
    ["malformed standalone v4", "noncanonical standalone v4", "empty payload list",
     "duplicate payload fingerprint"],
)
def test_real_construction_failures_refuse_before_worker_directory_or_socket(
    monkeypatch: pytest.MonkeyPatch,
    workspace: SimpleNamespace,
    historical_files: SimpleNamespace,
    source_repository: SimpleNamespace,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    capsys,
    case,
):
    """The real launcher is constructed; the accepted seam refuses first."""

    probes = _install_side_effect_probes(monkeypatch)
    _forbid_serving(monkeypatch)
    root = historical_files.root
    if case == "malformed standalone v4":
        historical_files.document.write_bytes(b"{\"not\": \"a payload\"}")
        expected = entrypoint.HISTORICAL_PAIRING_PAYLOAD_REFUSED
        configuration_path = historical_files.configuration
    elif case == "noncanonical standalone v4":
        historical_files.document.write_bytes(
            _oracle_canonical_bytes(historical_payload.to_dict()) + b"\n"
        )
        expected = entrypoint.HISTORICAL_PAIRING_PAYLOAD_REFUSED
        configuration_path = historical_files.configuration
    elif case == "empty payload list":
        configuration_path = root / "empty.json"
        configuration_path.write_text(
            _enablement_document(archive_root=root / "archive", payloads=[]),
            encoding="utf-8",
        )
        expected = entrypoint.HISTORICAL_PAIRING_CONFIGURATION_INVALID
    else:
        twin = root / "payload-twin.json"
        twin.write_bytes(historical_files.document.read_bytes())
        configuration_path = root / "twins.json"
        configuration_path.write_text(
            _enablement_document(
                archive_root=root / "archive",
                payloads=[
                    ("smoke-payload", historical_files.document),
                    ("twin-payload", twin),
                ],
            ),
            encoding="utf-8",
        )
        expected = entrypoint.HISTORICAL_PAIRING_CONFIGURATION_INVALID

    exit_code = _real_startup(
        workspace,
        source_repository,
        configuration_path=configuration_path,
        secret_path=historical_files.secret,
    )

    captured = capsys.readouterr()
    assert exit_code == 3
    assert captured.out == ""
    assert captured.err == f"error={expected}\n"
    # The accepted constructor ordering is re-pinned here: the historical
    # refusal escapes before any worker, directory, or socket exists.
    assert probes.workers == []
    assert probes.binds == []
    assert not [name for name in probes.threads if "admissible" in name]
    _assert_no_launcher_side_effects(workspace)
    assert not historical_files.archive_root.exists()


# ---------------------------------------------------------------------------
# M. Hostile recognized exceptions and the exact-type policy.
# ---------------------------------------------------------------------------


HOSTILE_TEXT = (
    "secret=" + CONFIGURED_SECRET.decode("latin-1") + " "
    "b64=" + base64.b64encode(CONFIGURED_SECRET).decode("ascii") + " "
    "hex=" + CONFIGURED_SECRET.hex() + " "
    "length=" + str(len(CONFIGURED_SECRET)) + " "
    "path=C:/configured/secret.bin at 0x7ffdeadbeef"
)


def _hostile(exc: BaseException) -> BaseException:
    """Load one accepted exception instance with every hostile carrier there is."""

    exc.args = (HOSTILE_TEXT, CONFIGURED_SECRET, len(CONFIGURED_SECRET))
    exc.configured_secret = CONFIGURED_SECRET
    exc.observed_length = len(CONFIGURED_SECRET)
    exc.base64_secret = base64.b64encode(CONFIGURED_SECRET)
    exc.hex_secret = CONFIGURED_SECRET.hex()
    exc.configured_path = "C:/configured/secret.bin"
    exc.memory_address = "0x7ffdeadbeef"
    exc.__cause__ = ValueError(HOSTILE_TEXT)
    exc.__context__ = RuntimeError(HOSTILE_TEXT)
    if hasattr(exc, "add_note"):
        exc.add_note(HOSTILE_TEXT)
    return exc


HOSTILE_CASES = [
    (
        HistoricalPairingEnablementDocumentError(HISTORICAL_PAIRING_CONFIG_MALFORMED),
        HISTORICAL_PAIRING_CONFIG_MALFORMED,
    ),
    (
        HistoricalPairingSecretFileError(HISTORICAL_PAIRING_SECRET_LENGTH_INVALID),
        HISTORICAL_PAIRING_SECRET_LENGTH_INVALID,
    ),
    (
        InvalidHistoricalPairingConfiguration(HOSTILE_TEXT),
        entrypoint.HISTORICAL_PAIRING_CONFIGURATION_INVALID,
    ),
    (
        MalformedHistoricalPayloadDocument(HOSTILE_TEXT),
        entrypoint.HISTORICAL_PAIRING_PAYLOAD_REFUSED,
    ),
    (
        HistoricalPairingFeatureConfigurationError(HOSTILE_TEXT),
        entrypoint.HISTORICAL_PAIRING_CONFIGURATION_INVALID,
    ),
    (
        HistoricalPayloadRegistryError(HOSTILE_TEXT),
        entrypoint.HISTORICAL_PAIRING_STARTUP_REFUSED,
    ),
    (
        HistoricalPayloadNotFound(HOSTILE_TEXT),
        entrypoint.HISTORICAL_PAIRING_STARTUP_REFUSED,
    ),
    (
        InvalidPairingCoordinatorConfiguration(HOSTILE_TEXT),
        entrypoint.HISTORICAL_PAIRING_STARTUP_REFUSED,
    ),
]


@pytest.mark.parametrize("index", range(len(HOSTILE_CASES)))
@pytest.mark.parametrize("stage", ["configuration", "secret", "construction"])
def test_hostile_recognized_failures_emit_only_their_fixed_code(
    monkeypatch: pytest.MonkeyPatch,
    workspace: SimpleNamespace,
    capsys,
    index,
    stage,
):
    template, expected = HOSTILE_CASES[index]
    hostile = _hostile(type(template)(*template.args[:1]))
    if isinstance(
        template,
        (HistoricalPairingEnablementDocumentError, HistoricalPairingSecretFileError),
    ):
        hostile = _hostile(type(template)(template.code))
    recorder = _recorder()
    _install_loader_doubles(
        monkeypatch,
        recorder,
        configuration_error=hostile if stage == "configuration" else None,
        secret_error=hostile if stage == "secret" else None,
    )
    _install_launcher_double(
        monkeypatch,
        recorder,
        construction_error=hostile if stage == "construction" else None,
    )

    exit_code = entrypoint.main(
        _argv(
            source=workspace.source,
            head=workspace.head,
            run_parent=workspace.run_parent,
            contracts=workspace.contracts,
            extra=(
                "--historical-pairing-config",
                str(workspace.historical / "c.json"),
                "--historical-pairing-secret-file",
                str(workspace.historical / "s.bin"),
            ),
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 3
    assert captured.out == ""
    assert captured.err == f"error={expected}\n"
    combined = captured.out + captured.err
    for leak in (
        CONFIGURED_SECRET.decode("latin-1"),
        base64.b64encode(CONFIGURED_SECRET).decode("ascii"),
        CONFIGURED_SECRET.hex(),
        str(len(CONFIGURED_SECRET)),
        "C:/configured/secret.bin",
        "0x7ffdeadbeef",
        "Traceback",
        HOSTILE_TEXT,
    ):
        assert leak not in combined


def test_a_bounded_type_carrying_a_foreign_code_collapses_to_the_generic_refusal(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace, capsys
):
    """Only a code inside the type's own frozen set is ever emitted directly."""

    hostile = HistoricalPairingEnablementDocumentError(
        HISTORICAL_PAIRING_CONFIG_MALFORMED
    )
    hostile._code = HOSTILE_TEXT
    assert hostile.code == HOSTILE_TEXT
    recorder = _recorder()
    _install_loader_doubles(monkeypatch, recorder, configuration_error=hostile)
    _install_launcher_double(monkeypatch, recorder, forbidden=True)

    exit_code = entrypoint.main(
        _argv(
            source=workspace.source,
            head=workspace.head,
            run_parent=workspace.run_parent,
            contracts=workspace.contracts,
            extra=(
                "--historical-pairing-config",
                str(workspace.historical / "c.json"),
                "--historical-pairing-secret-file",
                str(workspace.historical / "s.bin"),
            ),
        )
    )

    captured = capsys.readouterr()
    assert exit_code == 3
    assert captured.err == "error=HISTORICAL_PAIRING_STARTUP_REFUSED\n"
    assert HOSTILE_TEXT not in captured.err


@pytest.mark.parametrize("index", range(len(HOSTILE_CASES)))
def test_an_unregistered_subclass_never_inherits_a_narrow_code(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace, index
):
    """The exact policy: an unregistered subclass keeps ordinary behavior.

    It is not silently given its base class's narrow code and it is not quietly
    swallowed into the generic refusal either; it propagates exactly as any
    unrelated startup defect does.
    """

    template, _expected = HOSTILE_CASES[index]
    subclass = type("UnregisteredHistoricalSubclass", (type(template),), {})
    recorder = _recorder()
    _install_loader_doubles(
        monkeypatch, recorder, configuration_error=subclass("unregistered")
    )
    _install_launcher_double(monkeypatch, recorder, forbidden=True)

    with pytest.raises(subclass):
        entrypoint.main(
            _argv(
                source=workspace.source,
                head=workspace.head,
                run_parent=workspace.run_parent,
                contracts=workspace.contracts,
                extra=(
                    "--historical-pairing-config",
                    str(workspace.historical / "c.json"),
                    "--historical-pairing-secret-file",
                    str(workspace.historical / "s.bin"),
                ),
            )
        )
    assert entrypoint._historical_startup_code(subclass("unregistered")) is None


# ---------------------------------------------------------------------------
# H. Unrelated startup failures keep exactly their previous behavior.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        ValueError("unable to observe source repository HEAD"),
        ValueError("source repository HEAD does not match required HEAD"),
        RuntimeError("G2 token and UI CSRF nonce must be distinct"),
        OSError("address already in use"),
    ],
)
def test_unrelated_construction_failures_are_never_converted(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace, capsys, error
):
    recorder = _recorder()
    _install_loader_doubles(monkeypatch, recorder)
    _install_launcher_double(monkeypatch, recorder, construction_error=error)

    with pytest.raises(type(error)) as raised:
        entrypoint.main(
            _argv(
                source=workspace.source,
                head=workspace.head,
                run_parent=workspace.run_parent,
                contracts=workspace.contracts,
                extra=(
                    "--historical-pairing-config",
                    str(workspace.historical / "c.json"),
                    "--historical-pairing-secret-file",
                    str(workspace.historical / "s.bin"),
                ),
            )
        )

    assert raised.value is error
    assert str(raised.value) == str(error)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "error=" not in captured.err


def test_a_real_source_head_mismatch_stays_an_ordinary_failure(
    monkeypatch: pytest.MonkeyPatch,
    workspace: SimpleNamespace,
    historical_files: SimpleNamespace,
    source_repository: SimpleNamespace,
    capsys,
):
    """A genuine unrelated launcher refusal is not laundered into exit 3."""

    _forbid_serving(monkeypatch)
    mismatched = SimpleNamespace(path=source_repository.path, head="b" * 40)
    with pytest.raises(ValueError) as raised:
        _real_startup(
            workspace,
            mismatched,
            configuration_path=historical_files.configuration,
            secret_path=historical_files.secret,
        )

    assert "HEAD" in str(raised.value)
    assert "error=" not in capsys.readouterr().err


def test_an_invalid_ordinary_configuration_is_refused_before_the_presence_matrix(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace, capsys
):
    recorder = _recorder()
    _install_loader_doubles(monkeypatch, recorder)
    _install_launcher_double(monkeypatch, recorder, forbidden=True)

    with pytest.raises(ValueError):
        entrypoint.main(
            _argv(
                source=workspace.source,
                head="not-hex",
                run_parent=workspace.run_parent,
                contracts=workspace.contracts,
                extra=("--historical-pairing-config", str(workspace.historical)),
            )
        )

    assert recorder.events == []
    assert "error=" not in capsys.readouterr().err


# ---------------------------------------------------------------------------
# G. The exact-type mapping itself.
# ---------------------------------------------------------------------------


def test_the_startup_mapping_is_keyed_by_exact_type_only():
    mapping = entrypoint._HISTORICAL_STARTUP_CODES
    assert set(mapping) == {
        InvalidHistoricalPairingConfiguration,
        MalformedHistoricalPayloadDocument,
        HistoricalPairingFeatureConfigurationError,
        HistoricalPayloadRegistryError,
        HistoricalPayloadNotFound,
        InvalidPairingCoordinatorConfiguration,
    }
    assert set(mapping.values()) <= entrypoint.HISTORICAL_PAIRING_STARTUP_ERROR_CODES
    assert set(entrypoint._HISTORICAL_BOUNDED_CODE_TYPES) == {
        HistoricalPairingEnablementDocumentError,
        HistoricalPairingSecretFileError,
    }
    with pytest.raises(TypeError):
        mapping[ValueError] = "x"
    # Unrelated exceptions are simply unrecognized.
    for unrelated in (ValueError("x"), RuntimeError("x"), OSError("x"), KeyError("x")):
        assert entrypoint._historical_startup_code(unrelated) is None


def test_every_emitted_code_is_bounded_and_path_free():
    for code in entrypoint.HISTORICAL_PAIRING_STARTUP_ERROR_CODES:
        assert re.fullmatch(r"[A-Z_]+", code)
    assert entrypoint._refuse_historical_startup("NOT_A_KNOWN_CODE") == 3


def test_a_foreign_code_is_never_emitted(capsys):
    entrypoint._refuse_historical_startup("SECRET=" + CONFIGURED_SECRET.hex())
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error=HISTORICAL_PAIRING_STARTUP_REFUSED\n"


# ---------------------------------------------------------------------------
# O. Static confidentiality complement (secondary evidence only).
# ---------------------------------------------------------------------------


def _entrypoint_tree() -> ast.Module:
    return ast.parse(ENTRYPOINT_SOURCE.read_text(encoding="utf-8"))


def test_the_entrypoint_declares_no_literal_secret_or_environment_source():
    tree = _entrypoint_tree()
    options = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("--")
    }
    assert {option for option in options if "historical" in option} == (
        NEW_OPTION_STRINGS
    )

    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(alias.name for alias in node.names)
    for forbidden in (
        "os",
        "base64",
        "binascii",
        "codecs",
        "hmac",
        "hashlib",
        "getpass",
        "secrets",
        "admissible.delegated_gate.historical_evaluation_store",
        "admissible.delegated_gate.historical_pairing_confirmation",
    ):
        assert forbidden not in imported, forbidden

    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    for forbidden in (
        "environ",
        "getenv",
        "stdin",
        "strip",
        "lstrip",
        "rstrip",
        "decode",
        "encode",
        "hex",
        "b64encode",
        "b64decode",
        "hexlify",
        "unhexlify",
        "digest",
        "hexdigest",
        "read_bytes",
        "read_text",
    ):
        assert forbidden not in attributes, forbidden

    names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    for forbidden in ("input", "getpass", "open", "bytes", "bytearray", "eval", "exec"):
        assert forbidden not in names, forbidden


def _executable_source() -> str:
    """Unparse the entrypoint with every docstring removed.

    The prose docstrings explain at length what the module deliberately does not
    do, so they necessarily name the very concepts this check forbids.  Only the
    executable text is examined.
    """

    tree = _entrypoint_tree()
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        body = node.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            node.body = body[1:] or [ast.Pass()]
    return ast.unparse(ast.fix_missing_locations(tree))


def test_the_entrypoint_names_no_tag_authority_or_archive_concept():
    source = ENTRYPOINT_SOURCE.read_text(encoding="utf-8")
    body = "\n".join(
        line
        for line in source.splitlines()
        if not line.lstrip().startswith("#")
    )
    executable = _executable_source()
    for forbidden in (
        "expected_tag",
        "presented_tag",
        "confirmation_tag",
        "compute_tag",
        "pairing_authority",
        "ClaimAuthority",
        "NativeCanaryAuthorizationPayloadV4",
        "v5",
        "V5",
        "archive_root",
        "confirm(",
        "PairingConfirmation",
    ):
        assert forbidden not in executable, forbidden
    assert "LauncherConfiguration(" in body
    assert "historical_pairing_secret=secret" in body


def test_the_launcher_configuration_never_gains_a_historical_field():
    from admissible.product_launcher.configuration import LauncherConfiguration

    fields = set(LauncherConfiguration.__dataclass_fields__)
    assert not [name for name in fields if "historical" in name]
    assert not [name for name in fields if "secret" in name]


# ---------------------------------------------------------------------------
# N. Real module invocation through a subprocess.
# ---------------------------------------------------------------------------


def _subprocess_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    # Exactly the package tree this module imported, so a subprocess always runs
    # the same code the in-process tests examined.
    environment["PYTHONPATH"] = str(PACKAGE_ROOT)
    for name in FORBIDDEN_SECRET_ENVIRONMENT:
        environment.pop(name, None)
    return environment


def test_module_help_through_a_real_subprocess():
    completed = subprocess.run(
        [sys.executable, "-m", "admissible.product_launcher", "--help"],
        cwd=PACKAGE_ROOT,
        env=_subprocess_environment(),
        capture_output=True,
        text=True,
        timeout=90,
    )

    assert completed.returncode == 0
    assert "--historical-pairing-config PATH" in completed.stdout
    assert "--historical-pairing-secret-file PATH" in completed.stdout


def _readiness_line(process: subprocess.Popen, timeout: float = 45.0) -> str:
    captured: list[str] = []

    def _read():
        captured.append(process.stdout.readline())

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    reader.join(timeout)
    if not captured or not captured[0].strip():
        process.kill()
        _out, err = process.communicate(timeout=60)
        raise AssertionError(f"no readiness line; stderr={err!r}")
    return captured[0].strip()


def _serving_launcher(extra: list[str], workspace_root: Path, source: SimpleNamespace):
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "admissible.product_launcher",
            *_argv(
                source=source.path,
                head=source.head,
                run_parent=workspace_root / "runs",
                contracts=workspace_root / "contracts",
                extra=tuple(extra),
            ),
        ],
        cwd=PACKAGE_ROOT,
        env=_subprocess_environment(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _get(port: int, route: str) -> tuple[int, dict]:
    connection = HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        connection.request("GET", route)
        response = connection.getresponse()
        return response.status, json.loads(response.read().decode("utf-8"))
    finally:
        connection.close()


def test_default_subprocess_startup_serves_and_answers_an_ordinary_404(
    tmp_path: Path, source_repository: SimpleNamespace
):
    process = _serving_launcher([], tmp_path, source_repository)
    try:
        line = _readiness_line(process)
        match = READINESS.fullmatch(line)
        assert match, line
        status, body = _get(int(match.group(1)), HISTORICAL_PAYLOADS_ROUTE)
        # Exactly the ordinary unknown-route answer: no FEATURE_DISABLED, no
        # partial feature, nothing about historical pairing at all.
        assert (status, body) == (404, {"error": "NOT_FOUND"})
    finally:
        process.terminate()
        process.wait(timeout=30)


def test_enabled_subprocess_startup_serves_the_configured_payload(
    tmp_path: Path,
    source_repository: SimpleNamespace,
    historical_files: SimpleNamespace,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    process = _serving_launcher(
        [
            "--historical-pairing-config",
            str(historical_files.configuration),
            "--historical-pairing-secret-file",
            str(historical_files.secret),
        ],
        tmp_path,
        source_repository,
    )
    try:
        line = _readiness_line(process)
        match = READINESS.fullmatch(line)
        assert match, line
        status, body = _get(int(match.group(1)), HISTORICAL_PAYLOADS_ROUTE)
        assert status == 200
        assert [record["payload_id"] for record in body["payloads"]] == [
            "smoke-payload"
        ]
        assert body["payloads"][0]["payload_fingerprint"] == (
            historical_payload.payload_fingerprint
        )
        assert body["payloads"][0]["document_byte_length"] == len(
            historical_files.document.read_bytes()
        )
    finally:
        process.terminate()
        process.wait(timeout=30)


def test_a_partial_subprocess_launch_refuses_with_one_bounded_line(
    tmp_path: Path, source_repository: SimpleNamespace, historical_files: SimpleNamespace
):
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "admissible.product_launcher",
            *_argv(
                source=source_repository.path,
                head=source_repository.head,
                run_parent=tmp_path / "runs",
                contracts=tmp_path / "contracts",
                extra=(
                    "--historical-pairing-config",
                    str(historical_files.configuration),
                ),
            ),
        ],
        cwd=PACKAGE_ROOT,
        env=_subprocess_environment(),
        capture_output=True,
        text=True,
        timeout=90,
    )

    assert completed.returncode == 3
    assert completed.stdout == ""
    assert completed.stderr == "error=HISTORICAL_PAIRING_CONFIGURATION_INCOMPLETE\n"
    assert not (tmp_path / "runs").exists()
    assert not (tmp_path / "contracts").exists()
