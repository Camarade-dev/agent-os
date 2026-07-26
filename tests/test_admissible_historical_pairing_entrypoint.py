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
from collections import deque
import functools
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import threading
from http.client import HTTPConnection
from types import (
    CellType,
    FrameType,
    FunctionType,
    MappingProxyType,
    MemberDescriptorType,
    MethodType,
    ModuleType,
    SimpleNamespace,
    TracebackType,
)
from typing import NamedTuple

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
    MAX_HISTORICAL_PAIRING_SECRET_BYTES,
    MIN_HISTORICAL_PAIRING_SECRET_BYTES,
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
    """Records exactly what the entrypoint handed to the constructor seam.

    ``start``, ``serve_forever`` and ``close`` each accept one optional injected
    failure so the entrypoint's complete post-construction lifecycle -- not only
    its serving phase -- can be driven deterministically.  All three default to
    the pre-existing succeed-and-record behavior.
    """

    def __init__(
        self,
        recorder,
        args,
        kwargs,
        *,
        serve_error=None,
        start_error=None,
        close_error=None,
    ):
        self.args = args
        self.kwargs = kwargs
        self.ui_port = 43101
        self.g2_port = 43102
        self._recorder = recorder
        self._serve_error = serve_error
        self._start_error = start_error
        self._close_error = close_error

    def start(self):
        self._recorder.events.append("start")
        if self._start_error is not None:
            raise self._start_error
        return self

    def serve_forever(self):
        self._recorder.events.append("serve_forever")
        if self._serve_error is not None:
            raise self._serve_error

    def close(self):
        self._recorder.events.append("close")
        if self._close_error is not None:
            raise self._close_error


def _recorder() -> SimpleNamespace:
    return SimpleNamespace(
        events=[],
        configuration_paths=[],
        secret_paths=[],
        launcher_calls=[],
        launchers=[],
        namespace=None,
        # Every frame that called the constructor seam, kept alive so the
        # entrypoint's own local secret reference can still be read after the
        # frame has returned or unwound.
        caller_frames=[],
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
    start_error: BaseException | None = None,
    close_error: BaseException | None = None,
    forbidden: bool = False,
):
    def _factory(*args, **kwargs):
        if forbidden:  # pragma: no cover - the assertion is the point
            raise AssertionError(
                "ProductLauncher must not be constructed for this startup"
            )
        recorder.events.append("construct_launcher")
        recorder.launcher_calls.append((args, kwargs))
        # The calling frame is the entrypoint's own frame.  Holding it keeps its
        # locals readable after it returns or unwinds, which is the only way to
        # observe that the entrypoint really dropped its local secret reference.
        recorder.caller_frames.append(sys._getframe(1))
        if construction_error is not None:
            raise construction_error
        launcher = _FakeLauncher(
            recorder,
            args,
            kwargs,
            serve_error=serve_error,
            start_error=start_error,
            close_error=close_error,
        )
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
# E. Entrypoint-owned secret custody.
#
# The scanner below replaces the earlier one-level scan of the entrypoint's
# module globals.  That scan could only ever see a secret bound directly to a
# module name (or sitting one level inside a plain container bound to one), so
# every ordinary indirection -- a default argument, a closure cell, an object
# field, a slot, a nested mapping, a partial, an exception attribute, a retained
# traceback frame -- was invisible to it, and a regression that retained the
# configured secret through any of them would have shipped undetected.
#
# Scope and policy
# ----------------
#
# The traversal is deliberately *not* a heap walk.  It starts from explicit
# application-owned roots (the entrypoint module namespace, and any exception or
# traceback the test itself decided to retain) and it never leaves that
# ownership boundary:
#
#   * a module is descended only when its ``__name__`` is an owned module;
#   * a class is descended only when its ``__module__`` is an owned module;
#   * a function is never descended through ``__globals__``, so reaching one
#     function can never pull in an entire foreign module's state;
#   * a frame is descended only when its code object's filename is an owned
#     entrypoint source file;
#   * an object explicitly named as an accepted recipient (the constructed
#     launcher, which legitimately holds the configured secret for its whole
#     lifetime) is a hard stop and is reported as such rather than silently
#     skipped;
#   * import machinery names (``__builtins__`` and friends) are never followed.
#
# Everything is bounded: an identity-based visited set, a maximum depth, a
# maximum visited-node count, and a deterministic ``_ScanBudgetExceeded`` failure
# when either bound is reached.  No property, descriptor, or other user code is
# executed to obtain a value: instance dictionaries come from
# ``object.__getattribute__``, exception state comes from ``BaseException``'s own
# descriptors rather than from possibly-overridden attributes, and slots are read
# through their real member descriptors.
# ---------------------------------------------------------------------------


# One high-entropy binary sentinel, used as the configured secret by every
# custody test.  It is deliberately hostile to careless handling: it is not
# valid UTF-8 (``\xc3\x28`` is a truncated two-byte sequence and
# ``\xed\xa0\x80`` is an encoded surrogate), and it carries a NUL, a CRLF,
# ordinary spaces, and high bytes.  A defect that decodes, trims, splits on
# lines, or NUL-terminates it therefore changes its value rather than merely
# moving it, and every such change is still detected by the encodings below.
SENTINEL_SECRET = (
    b"\x9f\x00\xc3\x28 \xed\xa0\x80SENTINEL\r\n\xfe\xff \x80\x13"
    b"\xa7\xd4\x6b\x00\xf0\x9f\x92\xa9 \x7f\xbe\xef\r\n\xc2"
)

# Bounds for the traversal.  Both are far above what a clean application-owned
# graph needs and far below a heap walk, so exceeding either is a real signal
# that the ownership boundary leaked rather than a tuning accident.
_SCAN_MAX_DEPTH = 32
_SCAN_MAX_NODES = 50_000

# Module-namespace names that are import machinery rather than application
# state.  Following them would leave the application-owned graph immediately.
_IMPORT_MACHINERY_NAMES = frozenset(
    {"__builtins__", "__loader__", "__spec__", "__cached__", "__path__"}
)

# Read through ``BaseException``'s own descriptors so an exception subclass that
# overrides ``args``/``__cause__``/``__context__`` with a property cannot run its
# code during a scan, and cannot hide a retained secret behind one either.
_EXCEPTION_ARGS = BaseException.__dict__["args"]
_EXCEPTION_CAUSE = BaseException.__dict__["__cause__"]
_EXCEPTION_CONTEXT = BaseException.__dict__["__context__"]
_EXCEPTION_TRACEBACK = BaseException.__dict__["__traceback__"]


class _ScanBudgetExceeded(AssertionError):
    """Deterministic refusal when the bounded traversal budget is exhausted.

    Raised rather than returning a partial answer: a truncated scan that
    silently reported "no disclosure" would be exactly the false negative this
    whole section exists to remove.
    """


class _Disclosure(NamedTuple):
    """One located disclosure: where it is and what form it took.

    It deliberately carries no secret material, so it is safe to place in an
    assertion message, a diff, or a failure report.
    """

    path: str
    form: str


class _ScanResult(NamedTuple):
    disclosures: tuple
    visited: int
    depth: int
    stopped_at: tuple

    @property
    def paths(self) -> tuple:
        return tuple(item.path for item in self.disclosures)


def _secret_forms(secret: bytes):
    """The byte and text forms whose *complete* presence counts as disclosure."""

    encoded = base64.b64encode(secret)
    hexed = secret.hex().encode("ascii")
    byte_forms = (("exact", secret), ("base64", encoded), ("hex", hexed))
    text_forms = (
        # Latin-1 is total over bytes, so this is the exact text representation
        # of the sentinel and not a lossy approximation of it.
        ("text", secret.decode("latin-1")),
        ("base64-text", encoded.decode("ascii")),
        ("hex-text", hexed.decode("ascii")),
    )
    return byte_forms, text_forms


def _text_form(value: str, text_forms) -> str | None:
    for label, form in text_forms:
        if form in value:
            return label
    return None


def _disclosure_form(value, secret: bytes, byte_forms, text_forms) -> str | None:
    """Classify one value, matching only *complete* secrets and encodings.

    Nothing shorter than the whole secret (or the whole of one of its explicit
    encodings) is ever reported, so an incidental short byte run can never
    manufacture an unbounded stream of false positives.
    """

    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            raw = bytes(value)
        except (TypeError, ValueError):  # pragma: no cover - exotic buffer
            return None
        if value is secret:
            return "identity"
        for label, form in byte_forms:
            if form not in raw:
                continue
            if label != "exact":
                return label
            return "copy" if raw == form else "embedded"
        return None
    if isinstance(value, str):
        return _text_form(value, text_forms)
    return None


def _attribute_segment(name: str, text_forms) -> str:
    """One ``.name`` path segment, redacted if the name itself discloses."""

    return f".{'<redacted>' if _text_form(name, text_forms) else name}"


def _key_segment(key, text_forms) -> str:
    """One ``["key"]`` path segment, redacted if the key itself discloses."""

    if isinstance(key, str):
        if _text_form(key, text_forms):
            return '["<redacted>"]'
        return f'["{key}"]'
    if isinstance(key, int) and not isinstance(key, bool):
        return f"[{key}]"
    return "[<key>]"


def _descriptor_value(descriptor, obj):
    try:
        return descriptor.__get__(obj, type(obj))
    except Exception:  # pragma: no cover - defensive only
        return None


def _instance_dict(obj):
    """The real instance dictionary, without triggering a ``__dict__`` property."""

    try:
        mapping = object.__getattribute__(obj, "__dict__")
    except Exception:  # pragma: no cover - objects without an instance dict
        return None
    return mapping if isinstance(mapping, dict) else None


def _slot_items(obj):
    """Yield ``(name, value)`` for every declared slot without running user code.

    Slot values are read through the real ``member_descriptor`` found on the
    declaring class, so a same-named property defined further along the MRO is
    never invoked.
    """

    for cls in getattr(type(obj), "__mro__", ()):
        declared = cls.__dict__.get("__slots__")
        if declared is None:
            continue
        names = (declared,) if isinstance(declared, str) else tuple(declared)
        for name in names:
            descriptor = cls.__dict__.get(name)
            if not isinstance(descriptor, MemberDescriptorType):
                continue
            try:
                yield name, descriptor.__get__(obj, cls)
            except AttributeError:
                # An unset slot holds nothing and therefore discloses nothing.
                continue


def _member_children(obj, path: str, text_forms):
    mapping = _instance_dict(obj)
    if mapping is not None:
        for name, value in list(mapping.items()):
            yield f"{path}{_attribute_segment(str(name), text_forms)}", value
    for name, value in _slot_items(obj):
        yield f"{path}{_attribute_segment(name, text_forms)}", value


def _namespace_children(obj, path: str, text_forms):
    for name, value in sorted(vars(obj).items(), key=lambda item: item[0]):
        if name in _IMPORT_MACHINERY_NAMES:
            continue
        yield f"{path}{_attribute_segment(name, text_forms)}", value


def _application_children(
    obj, path: str, *, owned_modules, owned_frame_files, text_forms
):
    """Yield every application-owned child of ``obj`` as ``(path, value)``."""

    if isinstance(obj, ModuleType):
        if getattr(obj, "__name__", None) in owned_modules:
            yield from _namespace_children(obj, path, text_forms)
        return
    if isinstance(obj, type):
        if getattr(obj, "__module__", None) in owned_modules:
            yield from _namespace_children(obj, path, text_forms)
        return
    if isinstance(obj, (str, bytes, bytearray, memoryview, int, float, complex)):
        return
    if obj is None:
        return
    if isinstance(obj, TracebackType):
        yield f"{path}.tb_frame", obj.tb_frame
        if obj.tb_next is not None:
            yield f"{path}.tb_next", obj.tb_next
        return
    if isinstance(obj, FrameType):
        if obj.f_code.co_filename not in owned_frame_files:
            # A frame outside the entrypoint's own source is not application
            # state; its globals are never followed either.
            return
        for name, value in sorted(obj.f_locals.items(), key=lambda item: item[0]):
            yield f"{path}.f_locals{_key_segment(name, text_forms)}", value
        return
    if isinstance(obj, BaseException):
        args = _descriptor_value(_EXCEPTION_ARGS, obj)
        if isinstance(args, tuple):
            for index, value in enumerate(args):
                yield f"{path}.args[{index}]", value
        for label, descriptor in (
            ("__cause__", _EXCEPTION_CAUSE),
            ("__context__", _EXCEPTION_CONTEXT),
            ("__traceback__", _EXCEPTION_TRACEBACK),
        ):
            value = _descriptor_value(descriptor, obj)
            if value is not None:
                yield f"{path}.{label}", value
        # ``__notes__`` and every custom attribute live in the instance
        # dictionary and are reached here.
        yield from _member_children(obj, path, text_forms)
        return
    if isinstance(obj, functools.partial):
        yield f"{path}.func", obj.func
        for index, value in enumerate(obj.args):
            yield f"{path}.args[{index}]", value
        for key, value in list(obj.keywords.items()):
            yield f"{path}.keywords{_key_segment(key, text_forms)}", value
        yield from _member_children(obj, path, text_forms)
        return
    if isinstance(obj, MethodType):
        yield f"{path}.__self__", obj.__self__
        yield f"{path}.__func__", obj.__func__
        return
    if isinstance(obj, FunctionType):
        for index, value in enumerate(obj.__defaults__ or ()):
            yield f"{path}.__defaults__[{index}]", value
        for key, value in list((obj.__kwdefaults__ or {}).items()):
            yield f"{path}.__kwdefaults__{_key_segment(key, text_forms)}", value
        for index, cell in enumerate(obj.__closure__ or ()):
            try:
                contents = cell.cell_contents
            except ValueError:
                # An empty cell -- exactly what a shared cell rebound to nothing
                # looks like when the closure has not run yet.
                continue
            yield f"{path}.__closure__[{index}].cell_contents", contents
        for name, value in list(vars(obj).items()):
            yield f"{path}{_attribute_segment(str(name), text_forms)}", value
        return
    if isinstance(obj, CellType):
        try:
            yield f"{path}.cell_contents", obj.cell_contents
        except ValueError:
            pass
        return
    if isinstance(obj, (dict, MappingProxyType)):
        for index, (key, value) in enumerate(list(obj.items())):
            yield f"{path}.<key {index}>", key
            yield f"{path}{_key_segment(key, text_forms)}", value
        return
    if isinstance(obj, (list, tuple)):
        for index, value in enumerate(list(obj)):
            yield f"{path}[{index}]", value
        return
    if isinstance(obj, (set, frozenset)):
        for index, value in enumerate(list(obj)):
            yield f"{path}.<member {index}>", value
        return
    yield from _member_children(obj, path, text_forms)


def _scan_application_owned(
    roots,
    secret: bytes,
    *,
    owned_modules=(),
    owned_frame_files=(),
    recipient_ids=(),
    max_depth: int = _SCAN_MAX_DEPTH,
    max_nodes: int = _SCAN_MAX_NODES,
) -> _ScanResult:
    """Breadth-first, cycle-safe, bounded scan of an application-owned graph."""

    byte_forms, text_forms = _secret_forms(secret)
    owned_modules = frozenset(owned_modules)
    owned_frame_files = frozenset(owned_frame_files)
    recipient_ids = frozenset(recipient_ids)
    seen: set[int] = set()
    keepalive: list = []
    disclosures: list[_Disclosure] = []
    stopped_at: list[str] = []
    visited = 0
    deepest = 0
    queue = deque((label, value, 0) for label, value in roots)
    while queue:
        path, value, depth = queue.popleft()
        identity = id(value)
        visited += 1
        deepest = max(deepest, depth)
        if visited > max_nodes:
            raise _ScanBudgetExceeded(
                f"visited more than {max_nodes} application-owned nodes; "
                f"the ownership boundary leaked at {path}"
            )
        if identity in recipient_ids:
            # An accepted recipient of the configured secret.  Reported, never
            # silently skipped, so the boundary stays visible in the result.
            stopped_at.append(path)
            continue
        # Classification happens before de-duplication on purpose.  One secret
        # object commonly sits at several ownership paths at once -- a partial's
        # positional argument and its keyword, two frame locals along one
        # traceback -- and reporting only the first would hide every other place
        # a reader would have to go and remove it.
        form = _disclosure_form(value, secret, byte_forms, text_forms)
        if form is not None:
            disclosures.append(_Disclosure(path, form))
            continue
        if identity in seen:
            # Already descended through another path; its children are already
            # queued or reported, so re-descending would only loop.
            continue
        seen.add(identity)
        # Kept alive for the whole scan so a freed object's address can never be
        # reused by a later one and silently look "already visited".
        keepalive.append(value)
        if depth >= max_depth:
            raise _ScanBudgetExceeded(
                f"reached the maximum depth of {max_depth} at {path}"
            )
        for child_path, child in _application_children(
            value,
            path,
            owned_modules=owned_modules,
            owned_frame_files=owned_frame_files,
            text_forms=text_forms,
        ):
            queue.append((child_path, child, depth + 1))
    return _ScanResult(
        disclosures=tuple(sorted(set(disclosures))),
        visited=visited,
        depth=deepest,
        stopped_at=tuple(sorted(set(stopped_at))),
    )


def _entrypoint_custody(
    secret: bytes, *, extra_roots=(), recipient_ids=()
) -> _ScanResult:
    """Scan exactly the real entrypoint's own application-owned state."""

    return _scan_application_owned(
        [("module", entrypoint), *extra_roots],
        secret,
        owned_modules=frozenset({entrypoint.__name__}),
        owned_frame_files=frozenset({str(ENTRYPOINT_SOURCE)}),
        recipient_ids=recipient_ids,
    )


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
    # The doubles installed on the entrypoint module are test state, not
    # application state: the recording loader closes over the configured secret
    # and the recording constructor closes over the recorder that captured it.
    # Removing them first is what makes the scan below a statement about the
    # entrypoint and not about its test harness.
    monkeypatch.undo()
    assert _entrypoint_custody(CONFIGURED_SECRET).paths == ()
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
# E1. The scanner itself: sentinel properties, bounds, and ownership boundary.
# ---------------------------------------------------------------------------


# One synthetic owned module.  Every positive control below builds its retention
# form here rather than in the product, so the scanner's ability to find a form
# is proven independently of whether the product currently contains one.
_PROBE_MODULE_NAME = "admissible_entrypoint_custody_probe"

# ``co_filename`` is whatever the import system compiled this file under, which
# is normally identical to ``__file__``; both spellings are accepted so a probe
# frame is recognized as owned either way.
_OWNED_TEST_FRAME_FILES = frozenset({__file__, str(Path(__file__).resolve())})


def _probe_module() -> ModuleType:
    return ModuleType(_PROBE_MODULE_NAME)


def _probe_custody(module, *, extra_roots=(), recipient_ids=()) -> _ScanResult:
    return _scan_application_owned(
        [("module", module), *extra_roots],
        SENTINEL_SECRET,
        owned_modules=frozenset({_PROBE_MODULE_NAME}),
        owned_frame_files=_OWNED_TEST_FRAME_FILES,
        recipient_ids=recipient_ids,
    )


def test_the_sentinel_carries_every_required_disclosure_hazard():
    """The sentinel is a real secret-file value and a hostile one.

    Every assertion below is reduced to a boolean or a count first.  A failing
    ``assert b"\\x00" in SENTINEL_SECRET`` would print the whole sentinel into
    the report, and no test in this section is allowed to disclose the material
    it exists to protect.
    """

    with pytest.raises(UnicodeDecodeError):
        SENTINEL_SECRET.decode("utf-8")
    carries_nul = b"\x00" in SENTINEL_SECRET
    carries_crlf = b"\r\n" in SENTINEL_SECRET
    carries_space = b" " in SENTINEL_SECRET
    carries_high_bytes = any(byte >= 0x80 for byte in SENTINEL_SECRET)
    assert carries_nul and carries_crlf and carries_space and carries_high_bytes
    assert len(set(SENTINEL_SECRET)) >= 24
    # It is configurable through the real accepted secret-file reader, so every
    # test that writes it to disk is exercising a genuinely acceptable secret.
    assert (
        MIN_HISTORICAL_PAIRING_SECRET_BYTES
        <= len(SENTINEL_SECRET)
        <= MAX_HISTORICAL_PAIRING_SECRET_BYTES
    )
    # Latin-1 is total over bytes, so the text form is exact rather than lossy.
    assert SENTINEL_SECRET.decode("latin-1").encode("latin-1") == SENTINEL_SECRET


_DISCLOSURE_FORMS = (
    ("the exact object", lambda: SENTINEL_SECRET, "identity"),
    ("equal copied bytes", lambda: bytes(bytearray(SENTINEL_SECRET)), "copy"),
    ("bytes embedding the secret", lambda: b"k=" + SENTINEL_SECRET + b";", "embedded"),
    ("a bytearray", lambda: bytearray(SENTINEL_SECRET), "copy"),
    ("a memoryview", lambda: memoryview(bytes(bytearray(SENTINEL_SECRET))), "copy"),
    ("the latin-1 text form", lambda: SENTINEL_SECRET.decode("latin-1"), "text"),
    (
        "text embedding the latin-1 form",
        lambda: "secret=" + SENTINEL_SECRET.decode("latin-1"),
        "text",
    ),
    ("base64 bytes", lambda: base64.b64encode(SENTINEL_SECRET), "base64"),
    (
        "base64 text",
        lambda: base64.b64encode(SENTINEL_SECRET).decode("ascii"),
        "base64-text",
    ),
    ("lowercase hex bytes", lambda: SENTINEL_SECRET.hex().encode("ascii"), "hex"),
    ("lowercase hex text", lambda: SENTINEL_SECRET.hex(), "hex-text"),
)


@pytest.mark.parametrize(
    "make,form",
    [(make, form) for _label, make, form in _DISCLOSURE_FORMS],
    ids=[label for label, _make, _form in _DISCLOSURE_FORMS],
)
def test_every_required_disclosure_form_is_classified(make, form):
    module = _probe_module()
    module._value = make()

    result = _probe_custody(module)

    assert result.paths == ("module._value",)
    assert result.disclosures[0].form == form


# Named rather than parametrized by value: a bytes parameter would put secret
# fragments straight into the generated test identifiers.
_NON_DISCLOSING_VALUES = (
    ("empty bytes", lambda: b""),
    ("a leading fragment", lambda: SENTINEL_SECRET[:8]),
    ("a trailing fragment", lambda: SENTINEL_SECRET[8:]),
    ("a hex fragment", lambda: SENTINEL_SECRET.hex()[:20]),
    (
        "a base64 fragment",
        lambda: base64.b64encode(SENTINEL_SECRET).decode("ascii")[:16],
    ),
    ("a bounded startup code", lambda: "HISTORICAL_PAIRING_STARTUP_REFUSED"),
    ("the secret length", lambda: str(len(SENTINEL_SECRET))),
)


@pytest.mark.parametrize(
    "make",
    [make for _label, make in _NON_DISCLOSING_VALUES],
    ids=[label for label, _make in _NON_DISCLOSING_VALUES],
)
def test_partial_material_is_never_classified_as_a_disclosure(make):
    """Only a complete secret or a complete explicit encoding counts.

    Reporting arbitrary fragments would make the scanner fire on unrelated
    state, and a scanner that cries wolf gets its assertion weakened later.
    """

    module = _probe_module()
    module._value = make()

    assert _probe_custody(module).paths == ()


def test_the_traversal_bound_fails_deterministically_rather_than_truncating():
    """Exceeding either bound raises; it never returns a reassuring empty list."""

    deep = _probe_module()
    node = {"credential": SENTINEL_SECRET}
    for _ in range(_SCAN_MAX_DEPTH + 8):
        node = {"next": node}
    deep._deep = node
    with pytest.raises(_ScanBudgetExceeded) as raised_depth:
        _probe_custody(deep)
    assert "maximum depth" in str(raised_depth.value)

    wide = _probe_module()
    # Distinct objects, so identity de-duplication cannot quietly shrink the
    # traversal below the bound the way interned small integers would.
    wide._wide = [object() for _ in range(512)]
    with pytest.raises(_ScanBudgetExceeded) as raised_nodes:
        _scan_application_owned(
            [("module", wide)],
            SENTINEL_SECRET,
            owned_modules=frozenset({_PROBE_MODULE_NAME}),
            max_nodes=256,
        )
    assert "application-owned nodes" in str(raised_nodes.value)


def test_a_reference_cycle_terminates_instead_of_looping():
    module = _probe_module()
    left: dict = {}
    right = {"left": left}
    left["right"] = right
    left["credential"] = SENTINEL_SECRET
    module._cycle = left

    result = _probe_custody(module)

    assert result.paths == ('module._cycle["credential"]',)


def test_the_scan_stops_at_the_application_ownership_boundary(
    monkeypatch: pytest.MonkeyPatch,
):
    """The traversal is an owned-graph walk, never a heap walk.

    A foreign module the entrypoint imports is out of scope even though it is
    trivially reachable by name from the entrypoint's own namespace; the same
    object bound in the entrypoint's own namespace is found immediately.  That
    pair is what keeps the ownership rule honest in both directions.
    """

    monkeypatch.setattr(
        launcher_module, "_custody_probe_foreign", SENTINEL_SECRET, raising=False
    )
    assert entrypoint.ProductLauncher.__module__ == launcher_module.__name__
    assert _entrypoint_custody(SENTINEL_SECRET).paths == ()

    monkeypatch.setattr(
        entrypoint, "_custody_probe_owned", SENTINEL_SECRET, raising=False
    )
    assert _entrypoint_custody(SENTINEL_SECRET).paths == ("module._custody_probe_owned",)


def test_the_clean_entrypoint_graph_stays_far_inside_the_traversal_bounds():
    result = _entrypoint_custody(SENTINEL_SECRET)

    assert result.paths == ()
    assert result.stopped_at == ()
    assert 0 < result.visited < _SCAN_MAX_NODES // 8
    assert result.depth < _SCAN_MAX_DEPTH // 2


def _plant_object_attribute(module):
    module._custody_holder = _AttributeHolder(SENTINEL_SECRET)
    return "module._custody_holder.secret"


def _plant_function_defaults(module):
    def _keep(held=SENTINEL_SECRET):  # pragma: no cover - never called
        return held

    module._custody_keep = _keep
    return "module._custody_keep.__defaults__[0]"


def _plant_nested_mapping(module):
    module._custody_state = {"a": {"b": {"credential": SENTINEL_SECRET}}}
    return 'module._custody_state["a"]["b"]["credential"]'


def _plant_partial(module):
    module._custody_bound = functools.partial(_consume, SENTINEL_SECRET)
    return "module._custody_bound.args[0]"


def _plant_slot_holder(module):
    module._custody_slots = _SlotHolder(SENTINEL_SECRET)
    return "module._custody_slots.credential"


_REAL_MODULE_PLANTS = (
    ("object attribute", "_custody_holder", _plant_object_attribute),
    ("function defaults", "_custody_keep", _plant_function_defaults),
    ("nested mapping", "_custody_state", _plant_nested_mapping),
    ("functools.partial", "_custody_bound", _plant_partial),
    ("object slots", "_custody_slots", _plant_slot_holder),
)


@pytest.mark.parametrize(
    "name,plant",
    [(name, plant) for _label, name, plant in _REAL_MODULE_PLANTS],
    ids=[label for label, _name, _plant in _REAL_MODULE_PLANTS],
)
def test_indirect_retention_is_found_in_the_real_entrypoint_module(
    monkeypatch: pytest.MonkeyPatch, name, plant
):
    """Non-vacuity on the shipped module, not only on a synthetic probe.

    The earlier one-level scan saw a module global and nothing else, so each of
    these placements would have gone unreported even though every one of them is
    genuine application-owned retention.  ``monkeypatch`` removes the plant
    again, so the module is left exactly as it was found.
    """

    assert _entrypoint_custody(SENTINEL_SECRET).paths == ()

    monkeypatch.setattr(entrypoint, name, None, raising=False)
    expected = plant(entrypoint)

    assert _entrypoint_custody(SENTINEL_SECRET).paths == (expected,)


# ---------------------------------------------------------------------------
# E2. Positive controls: every real retention form is located exactly.
# ---------------------------------------------------------------------------


class _AttributeHolder:
    def __init__(self, secret):
        self.secret = secret

    def read(self):  # pragma: no cover - only ever referenced, never called
        return self.secret


class _SlotHolder:
    __slots__ = ("credential",)

    def __init__(self, secret):
        self.credential = secret


def _consume(*args, **kwargs):  # pragma: no cover - a partial target, never called
    return None


def _retained_owned_traceback(secret: bytes) -> BaseException:
    """One retained exception whose owned frames still hold the secret."""

    def _raise(held):
        raise ValueError("owned frame")

    try:
        _raise(secret)
    except ValueError as exc:
        return exc
    raise AssertionError("unreachable")  # pragma: no cover


def _shared_cell_reader():
    """A closure reading the *same* cell the caller rebinds afterwards."""

    secret = SENTINEL_SECRET

    def _peek():
        return secret

    secret = None
    return _peek


def _copied_value_reader():
    """A closure over a separate immutable copy, which rebinding cannot reach.

    ``bytes(b)`` returns ``b`` itself for an immutable ``bytes``, so the copy is
    forced through a ``bytearray`` to produce a genuinely distinct object.
    """

    secret = SENTINEL_SECRET
    duplicate = bytes(bytearray(secret))

    def _peek():
        return duplicate

    secret = None
    return _peek


def _form_module_global(module):
    module._retained_secret = SENTINEL_SECRET
    return ("module._retained_secret",)


def _form_default_argument_closure(module):
    def _build():
        secret = SENTINEL_SECRET

        def _peek(held=secret):
            return held

        secret = None
        return _peek

    module._captured = _build()
    # The value was captured at definition time, so rebinding the local reached
    # nothing: this really is retention and not a shared cell.
    captured_the_secret = module._captured() is SENTINEL_SECRET
    assert captured_the_secret
    return ("module._captured.__defaults__[0]",)


def _form_function_defaults(module):
    def _keep(held=SENTINEL_SECRET):
        return held

    module._keep_default = _keep
    return ("module._keep_default.__defaults__[0]",)


def _form_function_kwdefaults(module):
    def _keep(*, held=SENTINEL_SECRET):
        return held

    module._keep_kwdefault = _keep
    return ('module._keep_kwdefault.__kwdefaults__["held"]',)


def _form_function_attribute(module):
    def _keep():
        return None

    _keep.configured_secret = SENTINEL_SECRET
    module._keep_attribute = _keep
    return ("module._keep_attribute.configured_secret",)


def _form_object_attribute(module):
    module._holder = _AttributeHolder(SENTINEL_SECRET)
    return ("module._holder.secret",)


def _form_object_slot(module):
    module._slot_holder = _SlotHolder(SENTINEL_SECRET)
    assert not hasattr(module._slot_holder, "__dict__")
    return ("module._slot_holder.credential",)


def _form_nested_mapping(module):
    module._state = {"outer": {"inner": {"credential": SENTINEL_SECRET}}}
    return ('module._state["outer"]["inner"]["credential"]',)


def _form_nested_sequence(module):
    module._records = [("configured", [SENTINEL_SECRET])]
    return ("module._records[0][1][0]",)


def _form_partial(module):
    module._bound = functools.partial(
        _consume, SENTINEL_SECRET, credential=SENTINEL_SECRET
    )
    return ("module._bound.args[0]", 'module._bound.keywords["credential"]')


def _form_exception_attribute(module):
    error = RuntimeError("bounded")
    error.configured_secret = SENTINEL_SECRET
    module._error = error
    return ("module._error.configured_secret",)


def _form_retained_traceback(module):
    module._error = _retained_owned_traceback(SENTINEL_SECRET)
    return (
        'module._error.__traceback__.tb_frame.f_locals["secret"]',
        'module._error.__traceback__.tb_next.tb_frame.f_locals["held"]',
    )


_RETENTION_FORMS = (
    ("module-level bytes global", _form_module_global),
    ("value-capturing closure default argument", _form_default_argument_closure),
    ("function __defaults__", _form_function_defaults),
    ("function __kwdefaults__", _form_function_kwdefaults),
    ("function attribute", _form_function_attribute),
    ("module-level object attribute", _form_object_attribute),
    ("object __slots__", _form_object_slot),
    ("three-level nested mapping", _form_nested_mapping),
    ("nested list inside tuple inside list", _form_nested_sequence),
    ("functools.partial argument and keyword", _form_partial),
    ("exception custom attribute", _form_exception_attribute),
    ("retained owned traceback frame", _form_retained_traceback),
)


@pytest.mark.parametrize(
    "build",
    [build for _label, build in _RETENTION_FORMS],
    ids=[label for label, _build in _RETENTION_FORMS],
)
def test_the_scanner_locates_every_real_retention_form(build):
    """Each form: clean control empty, injected form found at its exact path."""

    assert _probe_custody(_probe_module()).paths == ()

    module = _probe_module()
    expected = build(module)
    result = _probe_custody(module)

    assert result.paths == tuple(sorted(expected))
    # Diagnosable without disclosing: the result names a location and an
    # encoding, and never carries the material itself.  The membership tests are
    # reduced to booleans so a failure cannot print what it just found.
    for item in result.disclosures:
        path_discloses = any(
            form in item.path
            for form in (
                SENTINEL_SECRET.decode("latin-1"),
                SENTINEL_SECRET.hex(),
                base64.b64encode(SENTINEL_SECRET).decode("ascii"),
            )
        )
        assert not path_discloses
        assert item.form in {
            "identity",
            "copy",
            "embedded",
            "text",
            "base64",
            "base64-text",
            "hex",
            "hex-text",
        }


def test_every_required_retention_form_is_covered_exactly_once():
    """The twelve required forms are all present and none was quietly dropped."""

    labels = [label for label, _build in _RETENTION_FORMS]
    assert len(labels) == len(set(labels)) == 12


def _target_bound_method(module):
    module._bound_method = _AttributeHolder(SENTINEL_SECRET).read
    return "module._bound_method.__self__.secret"


def _target_mapping_proxy(module):
    module._proxy = MappingProxyType({"credential": SENTINEL_SECRET})
    return 'module._proxy["credential"]'


def _target_frozenset(module):
    module._members = frozenset({SENTINEL_SECRET})
    return "module._members.<member 0>"


def _target_set(module):
    module._set = {SENTINEL_SECRET}
    return "module._set.<member 0>"


def _target_mapping_key(module):
    module._keyed = {SENTINEL_SECRET: "value"}
    return "module._keyed.<key 0>"


def _target_closure_cell(module):
    module._reader = _copied_value_reader()
    return "module._reader.__closure__[0].cell_contents"


_TRAVERSAL_TARGETS = (
    ("bound method __self__", _target_bound_method),
    ("MappingProxyType value", _target_mapping_proxy),
    ("frozenset member", _target_frozenset),
    ("set member", _target_set),
    ("dict key", _target_mapping_key),
    ("closure cell contents", _target_closure_cell),
)


@pytest.mark.parametrize(
    "plant",
    [plant for _label, plant in _TRAVERSAL_TARGETS],
    ids=[label for label, _plant in _TRAVERSAL_TARGETS],
)
def test_every_declared_traversal_target_is_actually_inspected(plant):
    """The remaining declared inspection targets, each proven non-vacuous.

    A traversal branch nothing exercises is a branch that can be deleted without
    a single test noticing, which is how a scanner quietly stops scanning.
    """

    module = _probe_module()
    expected = plant(module)

    assert _probe_custody(module).paths == (expected,)


def test_a_retained_exception_supplied_as_a_root_is_inspected_directly():
    """An exception the test retains is a root in its own right, not only a global."""

    error = RuntimeError("bounded")
    error.configured_secret = SENTINEL_SECRET
    error.__cause__ = ValueError(SENTINEL_SECRET.hex())
    error.__context__ = RuntimeError(base64.b64encode(SENTINEL_SECRET))
    error.add_note("note=" + SENTINEL_SECRET.decode("latin-1"))

    result = _scan_application_owned(
        [("exception", error)],
        SENTINEL_SECRET,
        owned_modules=frozenset({_PROBE_MODULE_NAME}),
        owned_frame_files=_OWNED_TEST_FRAME_FILES,
    )

    assert result.paths == (
        "exception.__cause__.args[0]",
        "exception.__context__.args[0]",
        "exception.__notes__[0]",
        "exception.configured_secret",
    )


def test_a_closure_sharing_the_rebound_cell_is_not_retention():
    """Why a closure over the entrypoint's own local cell is behaviourally inert.

    The entrypoint's ``finally: secret = None`` rebinds the very cell such a
    closure reads, so the closure observes ``None`` and retains nothing.  That
    is a genuine equivalence, not a gap in the scanner: the four value-capturing
    routes below all use the same sentinel and are all reported.
    """

    shared = _probe_module()
    shared._peek = _shared_cell_reader()
    assert shared._peek() is None
    assert shared._peek.__closure__[0].cell_contents is None
    assert _probe_custody(shared).paths == ()

    default_argument = _probe_module()
    copied = _probe_module()
    copied._peek = _copied_value_reader()
    field = _probe_module()
    nested = _probe_module()
    captures = (
        ("default argument", default_argument, _form_default_argument_closure(default_argument)),
        ("separate immutable copy", copied, ("module._peek.__closure__[0].cell_contents",)),
        ("object field", field, _form_object_attribute(field)),
        ("nested container", nested, _form_nested_mapping(nested)),
    )
    for label, module, expected in captures:
        assert _probe_custody(module).paths == tuple(sorted(expected)), label
    # The copy is a distinct object carrying identical bytes, which is exactly
    # the form an "it is not the same object, so it is not the secret" defect
    # would produce.
    equal_bytes = copied._peek() == SENTINEL_SECRET
    distinct_object = copied._peek() is not SENTINEL_SECRET
    assert equal_bytes and distinct_object
    assert _probe_custody(copied).disclosures[0].form == "copy"


# ---------------------------------------------------------------------------
# E3. Every startup outcome leaves no application-owned secret behind.
# ---------------------------------------------------------------------------


_STARTUP_OUTCOMES = (
    "constructor success",
    "recognized historical constructor failure",
    "unrelated constructor failure",
    "start failure",
    "serve failure",
    "close failure",
)


def _startup_outcome(case: str):
    """Return ``(launcher double kwargs, escaping type, exit code)``."""

    if case == "constructor success":
        return {}, None, 0
    if case == "recognized historical constructor failure":
        return (
            {"construction_error": MalformedHistoricalPayloadDocument("refused")},
            None,
            3,
        )
    if case == "unrelated constructor failure":
        return (
            {"construction_error": ValueError("unable to observe source repository HEAD")},
            ValueError,
            None,
        )
    if case == "start failure":
        return {"start_error": RuntimeError("ui server refused to bind")}, RuntimeError, None
    if case == "serve failure":
        return {"serve_error": RuntimeError("serving loop failed")}, RuntimeError, None
    return {"close_error": RuntimeError("close refused")}, RuntimeError, None


@pytest.mark.parametrize("case", _STARTUP_OUTCOMES)
def test_no_application_owned_secret_survives_any_startup_outcome(
    monkeypatch: pytest.MonkeyPatch, workspace: SimpleNamespace, capsys, case
):
    kwargs, escaping, exit_code = _startup_outcome(case)
    recorder = _recorder()
    _install_loader_doubles(monkeypatch, recorder, secret=SENTINEL_SECRET)
    _install_launcher_double(monkeypatch, recorder, **kwargs)
    argv = _argv(
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

    retained = None
    if escaping is None:
        assert entrypoint.main(argv) == exit_code
    else:
        with pytest.raises(escaping) as caught:
            entrypoint.main(argv)
        # Retained on purpose: an escaping exception keeps its frames alive, and
        # those frames are exactly where a dropped-reference defect would still
        # be visible.  It is released at the end of this test.
        retained = caught.value

    captured = capsys.readouterr()
    # Reduced to one boolean so a failure reports "output disclosed the secret"
    # instead of printing the secret and the output that carried it.
    output_discloses = any(
        encoded in stream
        for encoded in (
            SENTINEL_SECRET.decode("latin-1"),
            base64.b64encode(SENTINEL_SECRET).decode("ascii"),
            SENTINEL_SECRET.hex(),
        )
        for stream in (captured.out, captured.err)
    )
    assert not output_discloses

    # The constructed launcher is the accepted recipient and holds the
    # configured secret for its whole lifetime by design.  The scan stops at
    # that boundary and reports the stop, rather than reporting the accepted
    # design as a leak or silently pretending the boundary is not there.
    recipients = frozenset(id(launcher) for launcher in recorder.launchers)
    frames = list(recorder.caller_frames)
    # The doubles are test state living on the entrypoint module; removing them
    # is what makes the scan a statement about the entrypoint.
    monkeypatch.undo()

    result = _entrypoint_custody(
        SENTINEL_SECRET,
        extra_roots=() if retained is None else (("exception", retained),),
        recipient_ids=recipients,
    )
    assert result.paths == (), case

    if case in {"start failure", "serve failure", "close failure"}:
        # The launcher really was reachable from a retained entrypoint frame, so
        # the recipient boundary above is load-bearing rather than decorative.
        assert result.stopped_at, case

    assert len(frames) == 1
    assert frames[0].f_code.co_filename == str(ENTRYPOINT_SOURCE)
    assert frames[0].f_code.co_name == "_launcher_with_historical_pairing"
    # Constructor success and constructor failure alike: the entrypoint's own
    # local reference is gone by the time the frame is observable.
    assert frames[0].f_locals["secret"] is None
    assert frames[0].f_locals["loaded_configuration"] is ACCEPTED_CONFIGURATION
    del retained


def test_the_startup_outcome_matrix_covers_the_whole_lifecycle():
    assert len(_STARTUP_OUTCOMES) == len(set(_STARTUP_OUTCOMES)) == 6


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


# ---------------------------------------------------------------------------
# P. The exact bytes a refused startup writes to the two standard streams.
#
# The subprocess assertions above all run with ``text=True``, and universal
# newline translation silently rewrites a ``\r\n`` terminator into ``\n`` before
# any of them can see it.  A real operator, a shell redirect, and a log
# collector all see the untranslated bytes, so the byte-exact contract is pinned
# here with binary capture instead.  On this platform the production write of a
# single ``"\n"`` through ``sys.stderr`` really does emit ``os.linesep``; the
# expectation is derived from ``os.linesep`` rather than hardcoded, and no
# production behavior is changed to force one terminator or the other.
# ---------------------------------------------------------------------------


def _startup_stderr_expectation(code: str) -> bytes:
    return b"error=" + code.encode("ascii") + os.linesep.encode("ascii")


def _run_startup_to_completion(
    extra: tuple[str, ...], workspace_root: Path, source: SimpleNamespace
) -> subprocess.CompletedProcess:
    """Run the real module and capture both streams as raw, untranslated bytes."""

    return subprocess.run(
        [
            sys.executable,
            "-m",
            "admissible.product_launcher",
            *_argv(
                source=source.path,
                head=source.head,
                run_parent=workspace_root / "runs",
                contracts=workspace_root / "contracts",
                extra=extra,
            ),
        ],
        cwd=PACKAGE_ROOT,
        env=_subprocess_environment(),
        # Deliberately no ``text=True``: newline translation is exactly what
        # this test exists to see through.
        capture_output=True,
        timeout=120,
    )


_EXACT_STDERR_CASES = (
    "partial configuration",
    "enablement document refusal",
    "secret file refusal",
    "product launcher historical construction refusal",
)


@pytest.mark.parametrize("case", _EXACT_STDERR_CASES)
def test_a_refused_startup_writes_exactly_one_bounded_stderr_line_of_bytes(
    tmp_path: Path,
    source_repository: SimpleNamespace,
    historical_files: SimpleNamespace,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    case,
):
    root = historical_files.root
    secret_file = root / "sentinel-secret.bin"
    secret_file.write_bytes(SENTINEL_SECRET)
    configured_secret = SENTINEL_SECRET
    configuration_path = historical_files.configuration
    secret_path = secret_file

    if case == "partial configuration":
        extra = ("--historical-pairing-config", str(configuration_path))
        expected = entrypoint.HISTORICAL_PAIRING_CONFIGURATION_INCOMPLETE
    elif case == "enablement document refusal":
        configuration_path = root / "malformed-enablement.json"
        configuration_path.write_text("{not json", encoding="utf-8")
        expected = HISTORICAL_PAIRING_CONFIG_MALFORMED
        extra = (
            "--historical-pairing-config",
            str(configuration_path),
            "--historical-pairing-secret-file",
            str(secret_path),
        )
    elif case == "secret file refusal":
        secret_path = root / "too-short-secret.bin"
        configured_secret = b"tooshort"
        secret_path.write_bytes(configured_secret)
        expected = HISTORICAL_PAIRING_SECRET_LENGTH_INVALID
        extra = (
            "--historical-pairing-config",
            str(configuration_path),
            "--historical-pairing-secret-file",
            str(secret_path),
        )
    else:
        # A real ``ProductLauncher`` construction: both loaders succeed, the
        # source HEAD verifies, and the accepted registry refuses the configured
        # standalone V4 document inside the constructor.
        historical_files.document.write_bytes(b'{"not": "a payload"}')
        expected = entrypoint.HISTORICAL_PAIRING_PAYLOAD_REFUSED
        extra = (
            "--historical-pairing-config",
            str(configuration_path),
            "--historical-pairing-secret-file",
            str(secret_path),
        )

    completed = _run_startup_to_completion(extra, tmp_path, source_repository)

    assert completed.returncode == entrypoint.HISTORICAL_PAIRING_STARTUP_EXIT_CODE
    assert completed.stdout == b""
    assert completed.stderr == _startup_stderr_expectation(expected)
    # One line, terminated by the platform's own newline exactly once, with no
    # second terminator and no blank continuation line after it.
    assert completed.stderr.count(b"\n") == 1
    assert completed.stderr.count(os.linesep.encode("ascii")) == 1
    assert not completed.stderr.endswith(os.linesep.encode("ascii") * 2)
    assert completed.stderr.endswith(os.linesep.encode("ascii"))
    # ASCII only: no encoded secret byte, no mojibake, no BOM.
    assert max(completed.stderr) < 0x80
    assert b"Traceback" not in completed.stderr
    assert b"File \"" not in completed.stderr

    combined = completed.stdout + completed.stderr
    forbidden = (
        configured_secret,
        base64.b64encode(configured_secret),
        configured_secret.hex().encode("ascii"),
        str(secret_path).encode("utf-8", "surrogateescape"),
        str(configuration_path).encode("utf-8", "surrogateescape"),
        str(historical_files.document).encode("utf-8", "surrogateescape"),
        str(len(configured_secret)).encode("ascii"),
    )
    # One boolean, so a failure names the defect instead of printing the
    # material that proves it.
    discloses = any(material in combined for material in forbidden)
    assert not discloses
    assert not (tmp_path / "runs").exists()
    assert not (tmp_path / "contracts").exists()


def test_the_exact_stderr_matrix_covers_every_required_refusal_stage():
    assert len(_EXACT_STDERR_CASES) == len(set(_EXACT_STDERR_CASES)) == 4


# ---------------------------------------------------------------------------
# Q. Startup children never carry the configured secret on any channel.
# ---------------------------------------------------------------------------


class _ChildInvocation(NamedTuple):
    argv: tuple
    environment: dict
    cwd: object
    stdin: object
    payload: object


def _install_child_process_observer(monkeypatch: pytest.MonkeyPatch) -> list:
    """Record every child process this startup creates, on every channel.

    Both ``subprocess.run`` and ``Popen.__init__`` are observed, so a child
    created through either route is seen, and the real call is always performed
    afterwards: this is an observer, not a replacement for child creation.
    """

    invocations: list[_ChildInvocation] = []

    def _record(args, kwargs) -> None:
        argv = args if isinstance(args, (list, tuple)) else [args]
        environment = kwargs.get("env")
        invocations.append(
            _ChildInvocation(
                argv=tuple(str(item) for item in argv),
                # ``env=None`` means the child inherits this process's whole
                # environment, so that is what has to be inspected.  Recording an
                # empty mapping instead would make the test vacuous.
                environment=dict(os.environ)
                if environment is None
                else {str(key): str(value) for key, value in dict(environment).items()},
                cwd=kwargs.get("cwd"),
                stdin=kwargs.get("stdin"),
                payload=kwargs.get("input"),
            )
        )

    real_run = subprocess.run

    def _run(args, **kwargs):
        _record(args, kwargs)
        return real_run(args, **kwargs)

    monkeypatch.setattr(subprocess, "run", _run)

    real_init = subprocess.Popen.__init__

    def _init(self, args, *rest, **kwargs):
        _record(args, kwargs)
        return real_init(self, args, *rest, **kwargs)

    monkeypatch.setattr(subprocess.Popen, "__init__", _init)
    return invocations


def test_no_startup_child_receives_the_configured_secret_or_its_locators(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    source_repository: SimpleNamespace,
    historical_files: SimpleNamespace,
    capsys,
):
    """A real enabled construction, with every child invocation inspected.

    The expected source-HEAD ``git`` verification really does occur here; what
    matters is that neither it nor any other child sees the configured secret in
    any form, nor either of the two configured locators.
    """

    secret_file = historical_files.root / "sentinel-secret.bin"
    secret_file.write_bytes(SENTINEL_SECRET)
    invocations = _install_child_process_observer(monkeypatch)
    # Return from serving immediately: this test is about construction and
    # start, and the real ``serve_forever`` would block the suite forever.
    monkeypatch.setattr(
        launcher_module.ProductLauncher, "serve_forever", lambda self: None
    )

    exit_code = entrypoint.main(
        _argv(
            source=source_repository.path,
            head=source_repository.head,
            run_parent=tmp_path / "runs",
            contracts=tmp_path / "contracts",
            extra=(
                "--historical-pairing-config",
                str(historical_files.configuration),
                "--historical-pairing-secret-file",
                str(secret_file),
            ),
        )
    )

    assert exit_code == 0
    assert invocations, "the startup created no child at all"
    # The expected source-HEAD verification is present rather than assumed.
    assert any("rev-parse" in item for call in invocations for item in call.argv)

    forbidden_text = (
        SENTINEL_SECRET.decode("latin-1"),
        base64.b64encode(SENTINEL_SECRET).decode("ascii"),
        SENTINEL_SECRET.hex(),
        str(secret_file),
        str(historical_files.configuration),
    )
    forbidden_bytes = (
        SENTINEL_SECRET,
        base64.b64encode(SENTINEL_SECRET),
        SENTINEL_SECRET.hex().encode("ascii"),
        str(secret_file).encode("utf-8", "surrogateescape"),
        str(historical_files.configuration).encode("utf-8", "surrogateescape"),
    )
    for index, call in enumerate(invocations):
        channels = [
            *call.argv,
            *call.environment.keys(),
            *call.environment.values(),
        ]
        if call.cwd is not None:
            channels.append(str(call.cwd))
        for supplied in (call.stdin, call.payload):
            if isinstance(supplied, str):
                channels.append(supplied)
        text_discloses = any(
            material in channel for channel in channels for material in forbidden_text
        )
        assert not text_discloses, index

        byte_channels = [item.encode("utf-8", "surrogateescape") for item in call.argv]
        for supplied in (call.stdin, call.payload):
            if isinstance(supplied, (bytes, bytearray)):
                byte_channels.append(bytes(supplied))
        byte_discloses = any(
            material in channel
            for channel in byte_channels
            for material in forbidden_bytes
        )
        assert not byte_discloses, index

    capsys.readouterr()


# ---------------------------------------------------------------------------
# R. Inherited argparse abbreviation: documented, not repaired.
# ---------------------------------------------------------------------------


def test_the_secret_abbreviation_stays_a_locator_and_is_refused_by_the_loader(
    monkeypatch: pytest.MonkeyPatch,
    workspace: SimpleNamespace,
    historical_files: SimpleNamespace,
    capsys,
):
    """``--historical-pairing-secret`` is argparse prefix matching, not an option.

    The parser declares exactly two historical options and neither of them
    accepts literal secret material.  argparse's long-standing prefix
    abbreviation resolves the shorter spelling to the *file* option, which is
    repository-wide behavior for every option in every parser here and is not
    modified by this slice: ``allow_abbrev`` is left alone, no destination is
    added, and no abbreviation is blocked.  What is pinned is the consequence
    that matters -- the value stays a filesystem locator, and a literal-looking
    value is refused by the accepted secret-file loader rather than being read
    as the secret itself.

    The separate, inherited ``--h`` ambiguity between ``--help`` and the two
    historical options is recorded here as a compatibility note only; it is
    pre-existing argparse behavior and is out of scope for this slice.
    """

    parser = entrypoint.build_parser()
    assert not [
        action for action in parser._actions if action.dest == "historical_pairing_secret"
    ]
    assert {
        option
        for action in parser._actions
        for option in action.option_strings
        if option.startswith("--historical")
    } == NEW_OPTION_STRINGS

    literal = "not-a-path-just-literal-secret-text"
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
            literal,
        ]
    )
    # It landed on the file destination, unchanged, and it is a Path locator --
    # never bytes, never decoded text, never a literal secret.
    assert not hasattr(namespace, "historical_pairing_secret")
    assert type(namespace.historical_pairing_secret_file) is type(Path("."))
    assert isinstance(namespace.historical_pairing_secret_file, Path)
    assert namespace.historical_pairing_secret_file == Path(literal)
    assert not namespace.historical_pairing_secret_file.is_absolute()

    # End to end: the accepted loader refuses that relative, literal-looking
    # locator with its own bounded code.  No launcher is ever constructed.
    recorder = _recorder()
    _install_launcher_double(monkeypatch, recorder, forbidden=True)

    exit_code = entrypoint.main(
        _argv(
            source=workspace.source,
            head=workspace.head,
            run_parent=workspace.run_parent,
            contracts=workspace.contracts,
            extra=(
                "--historical-pairing-config",
                str(historical_files.configuration),
                "--historical-pairing-secret",
                literal,
            ),
        )
    )

    captured = capsys.readouterr()
    assert exit_code == entrypoint.HISTORICAL_PAIRING_STARTUP_EXIT_CODE
    assert captured.out == ""
    assert captured.err == f"error={HISTORICAL_PAIRING_SECRET_PATH_INVALID}\n"
    assert recorder.events == []
    _assert_no_launcher_side_effects(workspace)
