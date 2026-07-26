"""Step 5C2E2: independent exact-byte historical-pairing tag utility."""

import ast
import base64
import builtins
import contextlib
import functools
import hashlib
import hmac
import importlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import tomllib
from types import FunctionType
from types import MappingProxyType
from types import MemberDescriptorType
from types import MethodType
from types import SimpleNamespace
import zipfile

import pytest

from admissible import historical_pairing_secret_file as secret_reader_module
from admissible.delegated_gate.historical_evaluation import (
    HistoricalEvaluationPairingAuthority,
)
from admissible.delegated_gate.historical_pairing_confirmation import (
    build_historical_pairing_confirmation_message,
    compute_historical_pairing_confirmation_tag,
)
from admissible.historical_pairing_secret_file import (
    HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES,
    HISTORICAL_PAIRING_SECRET_LENGTH_INVALID,
    HISTORICAL_PAIRING_SECRET_PATH_INVALID,
    HISTORICAL_PAIRING_SECRET_UNAVAILABLE,
    HistoricalPairingSecretFileError,
)
from admissible.operator_tools import historical_pairing_tag as tool


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "admissible" / "operator_tools" / "historical_pairing_tag.py"
INIT_PATH = ROOT / "admissible" / "operator_tools" / "__init__.py"
PYPROJECT_PATH = ROOT / "pyproject.toml"

VECTOR_SECRET = b"historical-pairing-confirmation-vector-secret"
VECTOR_AUTHORITY_DOCUMENT = {
    "schema_version": "admissible_historical_evaluation_pairing_authority_v1",
    "actor_id": "owner.asserted-actor",
    "evaluation_profile_fingerprint": "a1" * 32,
    "target_authorization_payload_fingerprint": "b2" * 32,
    "authority_fingerprint": (
        "e9f86652070b248a03af3ad46c2eea7a9f6db6ef078034aad16f82c0b9d0000a"
    ),
}
VECTOR_MESSAGE = (
    b"admissible_historical_evaluation_pairing_confirmation_v1"
    b"\x00"
    b'{"actor_id":"owner.asserted-actor","authority_fingerprint":"e9f86652070b'
    b'248a03af3ad46c2eea7a9f6db6ef078034aad16f82c0b9d0000a","evaluation_profil'
    b'e_fingerprint":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1'
    b'a1a1a1a1","schema_version":"admissible_historical_evaluation_pairing_aut'
    b'hority_v1","target_authorization_payload_fingerprint":"b2b2b2b2b2b2b2b2b'
    b'2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"}'
)
VECTOR_TAG = "9c6454bb1e9020f271bfd730d8fbeee72aef58450e0e7aea3181a55e0a95da46"


def _write_inputs(
    root: Path,
    *,
    message: bytes = VECTOR_MESSAGE,
    secret: bytes = VECTOR_SECRET,
) -> tuple[Path, Path]:
    message_path = root / "public-confirmation-message.bin"
    secret_path = root / "historical-pairing-secret.bin"
    message_path.write_bytes(message)
    secret_path.write_bytes(secret)
    return message_path, secret_path


def _argv(message_path: Path, secret_path: Path) -> list[str]:
    return [
        "--message-file",
        os.fspath(message_path),
        "--secret-file",
        os.fspath(secret_path),
    ]


def _run_direct(
    tmp_path: Path,
    capfdbinary,
    *,
    message: bytes = VECTOR_MESSAGE,
    secret: bytes = VECTOR_SECRET,
):
    message_path, secret_path = _write_inputs(
        tmp_path,
        message=message,
        secret=secret,
    )
    result = tool.main(_argv(message_path, secret_path))
    captured = capfdbinary.readouterr()
    return result, captured


def _expected_output(secret: bytes, message: bytes) -> bytes:
    tag = hmac.new(key=secret, msg=message, digestmod=hashlib.sha256).hexdigest()
    return tag.encode("ascii") + os.linesep.encode("ascii")


def _forged_secret_error(code):
    failure = HistoricalPairingSecretFileError.__new__(
        HistoricalPairingSecretFileError
    )
    RuntimeError.__init__(failure, "bounded-constructor-bypassed")
    failure._code = code
    return failure


def _forged_message_error(code):
    failure = tool.HistoricalPairingTagMessageFileError.__new__(
        tool.HistoricalPairingTagMessageFileError
    )
    RuntimeError.__init__(failure, "bounded-constructor-bypassed")
    failure._code = code
    return failure


def _main_return_frame(invoke):
    frames = []

    def trace(frame, event, _argument):
        if frame.f_code is tool.main.__code__ and event == "return":
            frames.append(frame)
        return trace

    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        invoke()
    finally:
        sys.settrace(previous)
    assert len(frames) == 1
    return frames[0]


def _assert_released(frame):
    assert frame.f_locals["message"] is None
    assert frame.f_locals["secret"] is None
    assert frame.f_locals["tag"] is None
    assert frame.f_locals.get("payload") is None


# Exact computation and byte preservation.


def test_known_vector_matches_both_standard_library_and_accepted_primitive(
    tmp_path: Path,
    capfdbinary,
):
    authority = HistoricalEvaluationPairingAuthority.from_dict(
        dict(VECTOR_AUTHORITY_DOCUMENT)
    )
    assert build_historical_pairing_confirmation_message(
        pairing_authority=authority
    ) == VECTOR_MESSAGE
    assert compute_historical_pairing_confirmation_tag(
        secret=VECTOR_SECRET,
        pairing_authority=authority,
    ) == VECTOR_TAG
    result, captured = _run_direct(tmp_path, capfdbinary)
    assert result == 0
    assert captured.out == VECTOR_TAG.encode("ascii") + os.linesep.encode("ascii")
    assert captured.err == b""


def test_computation_is_exactly_hmac_sha256(tmp_path: Path, capfdbinary):
    message = bytes(range(256)) + b"\r\n\x00  exact public bytes \n"
    secret = b"\x00 binary key \r\n with spaces \x00"
    result, captured = _run_direct(
        tmp_path,
        capfdbinary,
        message=message,
        secret=secret,
    )
    assert result == 0
    assert captured.out == _expected_output(secret, message)
    assert captured.err == b""
    assert captured.out != hashlib.sha256(message).hexdigest().encode() + os.linesep.encode()
    assert captured.out != (
        hmac.new(key=secret, msg=message, digestmod=hashlib.sha512)
        .hexdigest()
        .encode()
        + os.linesep.encode()
    )


def test_one_byte_message_change_changes_the_fixture_tag(
    tmp_path: Path,
    capfdbinary,
):
    first, _ = _write_inputs(tmp_path, message=VECTOR_MESSAGE)
    other_root = tmp_path / "other"
    other_root.mkdir()
    second, second_secret = _write_inputs(
        other_root,
        message=VECTOR_MESSAGE[:-1] + bytes([VECTOR_MESSAGE[-1] ^ 1]),
    )
    first_secret = tmp_path / "historical-pairing-secret.bin"
    assert tool.main(_argv(first, first_secret)) == 0
    first_output = capfdbinary.readouterr().out
    assert tool.main(_argv(second, second_secret)) == 0
    second_output = capfdbinary.readouterr().out
    assert first_output != second_output


def test_non_nul_secret_change_changes_the_fixture_tag(
    tmp_path: Path,
    capfdbinary,
):
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first = _write_inputs(first_root, secret=b"K" * 32)
    second = _write_inputs(second_root, secret=b"K" * 31 + b"L")
    assert tool.main(_argv(*first)) == 0
    first_output = capfdbinary.readouterr().out
    assert tool.main(_argv(*second)) == 0
    second_output = capfdbinary.readouterr().out
    assert first_output != second_output


def test_short_key_trailing_nul_equivalence_is_hmac_key_normalization(
    tmp_path: Path,
    capfdbinary,
):
    bare_root = tmp_path / "bare"
    nul_root = tmp_path / "trailing-nul"
    bare_root.mkdir()
    nul_root.mkdir()
    bare = _write_inputs(bare_root, secret=b"k" * 16)
    trailing_nul = _write_inputs(nul_root, secret=b"k" * 16 + b"\x00")
    assert tool.main(_argv(*bare)) == 0
    bare_output = capfdbinary.readouterr().out
    assert tool.main(_argv(*trailing_nul)) == 0
    nul_output = capfdbinary.readouterr().out
    assert bare_output == nul_output
    assert bare[1].read_bytes() != trailing_nul[1].read_bytes()


@pytest.mark.parametrize(
    "message",
    [
        b"line\n",
        b"line\r\n",
        b"line\x00",
        b" leading and trailing spaces ",
        b"\r\n\x00 \n",
    ],
)
def test_message_lf_crlf_nul_and_spaces_are_never_removed(
    tmp_path: Path,
    capfdbinary,
    message: bytes,
):
    result, captured = _run_direct(tmp_path, capfdbinary, message=message)
    assert result == 0
    assert captured.out == _expected_output(VECTOR_SECRET, message)


@pytest.mark.parametrize(
    "secret",
    [
        b"k" * 16 + b"\n",
        b"k" * 16 + b"\r\n",
        b"k" * 16 + b"\x00",
        b" leading and trailing secret spaces ",
        b"k" * 16 + b"\r\n\x00 \n",
    ],
)
def test_secret_lf_crlf_nul_and_spaces_are_never_removed_by_the_helper(
    tmp_path: Path,
    capfdbinary,
    secret: bytes,
):
    result, captured = _run_direct(tmp_path, capfdbinary, secret=secret)
    assert result == 0
    assert captured.out == _expected_output(secret, VECTOR_MESSAGE)


# Exact CLI and output.


def test_direct_main_returns_integer_and_emits_only_native_line(
    tmp_path: Path,
    capfdbinary,
):
    result, captured = _run_direct(tmp_path, capfdbinary)
    assert type(result) is int
    assert result == 0
    assert captured.out == VECTOR_TAG.encode("ascii") + os.linesep.encode("ascii")
    assert captured.err == b""
    tag = captured.out[: -len(os.linesep.encode("ascii"))].decode("ascii")
    assert len(tag) == 64
    assert tag == tag.lower()
    assert set(tag) <= set("0123456789abcdef")
    assert captured.out.count(os.linesep.encode("ascii")) == 1


def test_module_entrypoint_emits_exact_bytes_from_outside_repository(tmp_path: Path):
    message_path, secret_path = _write_inputs(tmp_path)
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    environment["PYTHONPATH"] = os.pathsep.join(
        [os.fspath(ROOT), environment.get("PYTHONPATH", "")]
    )
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "admissible.operator_tools.historical_pairing_tag",
            *_argv(message_path, secret_path),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout == VECTOR_TAG.encode("ascii") + os.linesep.encode("ascii")
    assert completed.stderr == b""


def test_console_script_declaration_targets_main_and_existing_scripts_are_unchanged(
    tmp_path: Path,
    capfdbinary,
):
    document = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    scripts = document["project"]["scripts"]
    assert scripts == {
        "agent-os": "agent_os.cli:main",
        "admissible": "admissible.product_launcher.__main__:main",
        "admissible-historical-pairing-tag": (
            "admissible.operator_tools.historical_pairing_tag:main"
        ),
        "admissible-historical-pairing-v4-extract": (
            "admissible.operator_tools.historical_pairing_v4_extract:main"
        ),
    }
    module_name, attribute = scripts["admissible-historical-pairing-tag"].split(":")
    target = getattr(importlib.import_module(module_name), attribute)
    assert target is tool.main
    result, captured = _run_direct(tmp_path, capfdbinary)
    assert result == 0
    assert captured.out == _expected_output(VECTOR_SECRET, VECTOR_MESSAGE)


def test_parser_has_exactly_two_required_locator_inputs():
    parser = tool._parser()
    assert parser.allow_abbrev is False
    operator_actions = [
        action for action in parser._actions if action.dest not in {"help"}
    ]
    assert [(action.option_strings, action.required, action.type) for action in operator_actions] == [
        (["--message-file"], True, Path),
        (["--secret-file"], True, Path),
    ]


def test_parser_preserves_locator_lexemes_without_expansion_or_io(
    monkeypatch: pytest.MonkeyPatch,
):
    touched = []
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: touched.append(args))
    parser = tool._parser()
    message_literal = r"..\~\$PAIRING_TAG_MESSAGE\message.bin"
    secret_literal = r"%PAIRING_TAG_SECRET%\secret.bin"
    namespace = parser.parse_args(
        [
            "--message-file",
            message_literal,
            "--secret-file",
            secret_literal,
        ]
    )
    assert namespace.message_file == Path(message_literal)
    assert namespace.secret_file == Path(secret_literal)
    assert not namespace.message_file.is_absolute()
    assert not namespace.secret_file.is_absolute()
    assert touched == []


@pytest.mark.parametrize(
    "abbreviation",
    ["--message", "--secret", "--message-f", "--secret-f"],
)
def test_abbreviated_options_are_usage_errors_and_open_nothing(
    abbreviation: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
):
    opened = []
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: opened.append(args))
    arguments = [
        "--message-file",
        "full-message",
        "--secret-file",
        "full-secret",
        abbreviation,
        "abbreviated-value",
    ]
    with pytest.raises(SystemExit) as failure:
        tool.main(arguments)
    assert failure.value.code == 2
    assert opened == []
    assert "unrecognized arguments" in capsys.readouterr().err


def test_help_is_exit_zero_and_usage_failure_is_exit_two(capsys):
    with pytest.raises(SystemExit) as help_exit:
        tool.main(["--help"])
    assert help_exit.value.code == 0
    help_output = capsys.readouterr()
    assert "--message-file" in help_output.out
    assert "--secret-file" in help_output.out
    with pytest.raises(SystemExit) as usage_exit:
        tool.main([])
    assert usage_exit.value.code == 2
    assert "usage:" in capsys.readouterr().err


# Public-message path and descriptor policy.


@pytest.mark.parametrize("length", [1, tool.MAX_HISTORICAL_PAIRING_MESSAGE_BYTES])
def test_message_lengths_at_both_inclusive_bounds_are_accepted(
    tmp_path: Path,
    length: int,
):
    path = tmp_path / f"message-{length}.bin"
    expected = b"x" * length
    path.write_bytes(expected)
    returned = tool._read_historical_pairing_message_file(path)
    assert type(returned) is bytes
    assert returned == expected


@pytest.mark.parametrize(
    "length",
    [0, tool.MAX_HISTORICAL_PAIRING_MESSAGE_BYTES + 1],
)
def test_message_lengths_outside_bounds_are_refused(tmp_path: Path, length: int):
    path = tmp_path / f"message-{length}.bin"
    path.write_bytes(b"x" * length)
    with pytest.raises(tool.HistoricalPairingTagMessageFileError) as failure:
        tool._read_historical_pairing_message_file(path)
    assert failure.value.code == tool.HISTORICAL_PAIRING_TAG_MESSAGE_LENGTH_INVALID


def test_message_reader_opens_once_and_reads_bound_plus_one_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "message.bin"
    expected = b"exact\x00bytes\r\n "
    path.write_bytes(expected)
    original_open = builtins.open
    opens = []
    reads = []
    handles = []

    class TrackingHandle:
        def __init__(self, handle):
            self.handle = handle
            self.closed_at_exit = False

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            self.handle.close()
            self.closed_at_exit = self.handle.closed

        def fileno(self):
            return self.handle.fileno()

        def read(self, amount=-1):
            reads.append(amount)
            return self.handle.read(amount)

    def tracked_open(candidate, mode):
        opens.append((candidate, mode))
        wrapper = TrackingHandle(original_open(candidate, mode))
        handles.append(wrapper)
        return wrapper

    monkeypatch.setattr(builtins, "open", tracked_open)
    returned = tool._read_historical_pairing_message_file(path)
    assert returned == expected
    assert opens == [(path, "rb")]
    assert reads == [tool.MAX_HISTORICAL_PAIRING_MESSAGE_BYTES + 1]
    assert handles[0].closed_at_exit is True


def test_message_reader_refuses_relative_nul_and_noncanonical_without_opening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    canonical = tmp_path / "message.bin"
    canonical.write_bytes(b"x")
    candidates = [
        Path("message.bin"),
        Path(os.fspath(canonical) + "\x00"),
        tmp_path / ".." / tmp_path.name / "message.bin",
    ]
    opened = []
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: opened.append(args))
    for candidate in candidates:
        with pytest.raises(tool.HistoricalPairingTagMessageFileError) as failure:
            tool._read_historical_pairing_message_file(candidate)
        assert failure.value.code == tool.HISTORICAL_PAIRING_TAG_MESSAGE_PATH_INVALID
    assert opened == []


def test_missing_and_directory_message_paths_are_unavailable(tmp_path: Path):
    for candidate in [tmp_path / "missing.bin", tmp_path]:
        with pytest.raises(tool.HistoricalPairingTagMessageFileError) as failure:
            tool._read_historical_pairing_message_file(candidate)
        assert failure.value.code == tool.HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE


def test_reported_message_symlink_and_reparse_point_are_refused_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "message.bin"
    opened = []
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: opened.append(args))
    link_metadata = SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
    monkeypatch.setattr(tool.os, "lstat", lambda candidate: link_metadata)
    with pytest.raises(tool.HistoricalPairingTagMessageFileError) as failure:
        tool._read_historical_pairing_message_file(path)
    assert failure.value.code == tool.HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE
    assert opened == []

    reparse_metadata = SimpleNamespace(
        st_mode=stat.S_IFREG,
        st_file_attributes=tool._REPARSE_POINT_FLAG,
    )
    monkeypatch.setattr(tool.os, "lstat", lambda candidate: reparse_metadata)
    with pytest.raises(tool.HistoricalPairingTagMessageFileError):
        tool._read_historical_pairing_message_file(path)
    assert opened == []


def test_real_direct_message_symlink_is_refused_when_platform_can_create_one(
    tmp_path: Path,
):
    target = tmp_path / "target.bin"
    target.write_bytes(b"message")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(target)
    except OSError as failure:
        pytest.skip(f"platform cannot create an unprivileged test symlink: {failure}")
    with pytest.raises(tool.HistoricalPairingTagMessageFileError) as refusal:
        tool._read_historical_pairing_message_file(link)
    assert refusal.value.code == tool.HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE


def test_opened_message_descriptor_must_be_regular_and_is_not_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "message.bin"
    path.write_bytes(b"message")
    reads = []
    original_open = builtins.open

    class Handle:
        def __init__(self):
            self.handle = original_open(path, "rb")

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self.handle.close()

        def fileno(self):
            return self.handle.fileno()

        def read(self, amount):
            reads.append(amount)
            return self.handle.read(amount)

    monkeypatch.setattr(builtins, "open", lambda *_args, **_kwargs: Handle())
    monkeypatch.setattr(
        tool.os,
        "fstat",
        lambda _descriptor: SimpleNamespace(
            st_mode=stat.S_IFDIR,
            st_file_attributes=0,
        ),
    )
    with pytest.raises(tool.HistoricalPairingTagMessageFileError) as refusal:
        tool._read_historical_pairing_message_file(path)
    assert refusal.value.code == tool.HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE
    assert reads == []


def test_literal_home_and_environment_shaped_components_are_not_expanded(
    tmp_path: Path,
):
    literal = tmp_path / "~" / "$PAIRING_TAG_MESSAGE"
    literal.mkdir(parents=True)
    path = literal / "%MESSAGE_FILE%.bin"
    path.write_bytes(b"literal")
    assert tool._read_historical_pairing_message_file(path) == b"literal"


def test_message_reader_accesses_no_parent_sibling_or_directory_listing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    path = tmp_path / "message.bin"
    sibling = tmp_path / "never-touch.bin"
    path.write_bytes(b"message")
    sibling.write_bytes(b"sibling")
    lstat_paths = []
    open_paths = []
    original_lstat = tool.os.lstat
    original_open = builtins.open

    def record_lstat(candidate):
        lstat_paths.append(candidate)
        return original_lstat(candidate)

    def record_open(candidate, mode):
        open_paths.append((candidate, mode))
        return original_open(candidate, mode)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("directory or neighbouring path access")

    monkeypatch.setattr(tool.os, "lstat", record_lstat)
    monkeypatch.setattr(tool.os, "listdir", forbidden)
    monkeypatch.setattr(tool.os, "scandir", forbidden)
    monkeypatch.setattr(Path, "iterdir", forbidden)
    monkeypatch.setattr(Path, "glob", forbidden)
    monkeypatch.setattr(Path, "rglob", forbidden)
    monkeypatch.setattr(builtins, "open", record_open)
    assert tool._read_historical_pairing_message_file(path) == b"message"
    assert lstat_paths == [path]
    assert open_paths == [(path, "rb")]


# Secret-reader boundary, bounded failures, and ordering.


def test_shared_reader_is_called_once_and_exact_objects_reach_hmac_by_identity(
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    message = bytes(bytearray(b"public message identity"))
    secret = bytes(bytearray(b"secret identity material"))
    message_path = Path("C:/configured/message.bin")
    secret_path = Path("C:/configured/secret.bin")
    calls = []

    def read_message(path):
        calls.append(("message", path))
        return message

    def read_secret(*, path):
        calls.append(("secret", path))
        return secret

    class Digest:
        def hexdigest(self):
            return "a" * 64

    def new(*, key, msg, digestmod):
        calls.append(("hmac", key, msg, digestmod))
        assert key is secret
        assert msg is message
        assert digestmod is hashlib.sha256
        return Digest()

    monkeypatch.setattr(tool, "_read_historical_pairing_message_file", read_message)
    monkeypatch.setattr(tool, "read_historical_pairing_secret_file", read_secret)
    monkeypatch.setattr(tool.hmac, "new", new)
    assert tool.main(_argv(message_path, secret_path)) == 0
    captured = capfdbinary.readouterr()
    assert captured.out == b"a" * 64 + os.linesep.encode("ascii")
    assert captured.err == b""
    assert calls == [
        ("message", message_path),
        ("secret", secret_path),
        ("hmac", secret, message, hashlib.sha256),
    ]


def test_message_refusal_happens_before_secret_reader(
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    calls = []

    def message_refusal(_path):
        calls.append("message")
        raise tool.HistoricalPairingTagMessageFileError(
            tool.HISTORICAL_PAIRING_TAG_MESSAGE_LENGTH_INVALID
        )

    def secret_reader(*, path):
        calls.append(("secret", path))
        raise AssertionError("secret file must remain unopened")

    monkeypatch.setattr(
        tool,
        "_read_historical_pairing_message_file",
        message_refusal,
    )
    monkeypatch.setattr(tool, "read_historical_pairing_secret_file", secret_reader)
    result = tool.main(
        _argv(Path("C:/configured/message.bin"), Path("C:/configured/secret.bin"))
    )
    captured = capfdbinary.readouterr()
    assert result == tool.HISTORICAL_PAIRING_TAG_EXIT_CODE
    assert calls == ["message"]
    assert captured.out == b""
    assert captured.err == (
        b"error=HISTORICAL_PAIRING_TAG_MESSAGE_LENGTH_INVALID"
        + os.linesep.encode("ascii")
    )


@pytest.mark.parametrize(
    "code",
    sorted(HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES),
)
def test_exact_shared_secret_codes_are_forwarded_as_one_bounded_line(
    code: str,
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    monkeypatch.setattr(
        tool,
        "_read_historical_pairing_message_file",
        lambda _path: VECTOR_MESSAGE,
    )

    def refusal(*, path):
        raise HistoricalPairingSecretFileError(code)

    monkeypatch.setattr(tool, "read_historical_pairing_secret_file", refusal)
    result = tool.main(
        _argv(Path("C:/configured/message.bin"), Path("C:/configured/secret.bin"))
    )
    captured = capfdbinary.readouterr()
    assert result == 3
    assert captured.out == b""
    assert captured.err == f"error={code}".encode() + os.linesep.encode()


@pytest.mark.parametrize("forged_code", ["FOREIGN_CODE", ["unhashable"]])
def test_forged_or_unknown_secret_code_collapses_to_generic_refusal(
    forged_code,
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    monkeypatch.setattr(
        tool,
        "_read_historical_pairing_message_file",
        lambda _path: VECTOR_MESSAGE,
    )

    def refusal(*, path):
        raise _forged_secret_error(forged_code)

    monkeypatch.setattr(tool, "read_historical_pairing_secret_file", refusal)
    result = tool.main(
        _argv(Path("C:/configured/message.bin"), Path("C:/configured/secret.bin"))
    )
    captured = capfdbinary.readouterr()
    assert result == 3
    assert captured.out == b""
    assert captured.err == (
        b"error=HISTORICAL_PAIRING_TAG_COMPUTATION_REFUSED"
        + os.linesep.encode()
    )


def test_secret_error_subclass_propagates_as_unrelated_defect(
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    class UnregisteredSecretFailure(HistoricalPairingSecretFileError):
        pass

    monkeypatch.setattr(
        tool,
        "_read_historical_pairing_message_file",
        lambda _path: VECTOR_MESSAGE,
    )

    def refusal(*, path):
        raise UnregisteredSecretFailure(HISTORICAL_PAIRING_SECRET_UNAVAILABLE)

    monkeypatch.setattr(tool, "read_historical_pairing_secret_file", refusal)
    with pytest.raises(UnregisteredSecretFailure):
        tool.main(
            _argv(
                Path("C:/configured/message.bin"),
                Path("C:/configured/secret.bin"),
            )
        )
    captured = capfdbinary.readouterr()
    assert captured.out == b""
    assert captured.err == b""


def test_message_error_type_is_bounded_and_unknown_constructor_input_collapses():
    fixed = tool.HistoricalPairingTagMessageFileError(
        tool.HISTORICAL_PAIRING_TAG_MESSAGE_PATH_INVALID
    )
    assert fixed.code == tool.HISTORICAL_PAIRING_TAG_MESSAGE_PATH_INVALID
    assert str(fixed) == fixed.code
    assert repr(fixed) == f"<HistoricalPairingTagMessageFileError code={fixed.code}>"
    forged = tool.HistoricalPairingTagMessageFileError(
        "path=C:\\secret message=bytes length=999"
    )
    assert forged.code == tool.HISTORICAL_PAIRING_TAG_COMPUTATION_REFUSED
    assert forged.args == (tool.HISTORICAL_PAIRING_TAG_COMPUTATION_REFUSED,)
    assert forged.__cause__ is None
    assert forged.__context__ is None
    assert not hasattr(forged, "__notes__")


def test_forged_message_error_code_collapses_to_generic_refusal(
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    monkeypatch.setattr(
        tool,
        "_read_historical_pairing_message_file",
        lambda _path: (_ for _ in ()).throw(
            _forged_message_error("path=C:\\private\\message.bin")
        ),
    )
    result = tool.main(
        _argv(
            Path("C:/private/message.bin"),
            Path("C:/private/secret.bin"),
        )
    )
    captured = capfdbinary.readouterr()
    assert result == 3
    assert captured.out == b""
    assert captured.err == (
        b"error=HISTORICAL_PAIRING_TAG_COMPUTATION_REFUSED"
        + os.linesep.encode()
    )


def test_unexpected_computation_failure_propagates_without_bounded_conversion(
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    class ComputationDefect(Exception):
        pass

    monkeypatch.setattr(
        tool,
        "_read_historical_pairing_message_file",
        lambda _path: VECTOR_MESSAGE,
    )
    monkeypatch.setattr(
        tool,
        "read_historical_pairing_secret_file",
        lambda *, path: VECTOR_SECRET,
    )

    def defect(**_kwargs):
        raise ComputationDefect("ordinary traceback sentinel")

    monkeypatch.setattr(tool.hmac, "new", defect)
    with pytest.raises(ComputationDefect, match="ordinary traceback sentinel"):
        tool.main(
            _argv(
                Path("C:/configured/message.bin"),
                Path("C:/configured/secret.bin"),
            )
        )
    captured = capfdbinary.readouterr()
    assert captured.out == b""
    assert captured.err == b""


# Import, no-contact, static laws, and package inclusion.


def test_operator_package_initializer_is_completely_inert():
    source = INIT_PATH.read_text(encoding="utf-8")
    assert source.strip() == ""
    assert ast.parse(source).body == []


def test_helper_direct_import_set_is_exactly_the_allowed_leaf_set():
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module)
    assert imported == [
        "argparse",
        "hashlib",
        "hmac",
        "os",
        "pathlib",
        "stat",
        "sys",
        "admissible.historical_pairing_secret_file",
    ]


def test_fresh_helper_import_loads_no_product_archive_execution_or_evidence_module(
    tmp_path: Path,
):
    program = textwrap.dedent(
        """
        import json
        import sys
        import admissible.operator_tools.historical_pairing_tag
        forbidden = (
            "admissible.product_launcher",
            "admissible.product_service",
            "admissible.product_ui",
            "admissible.delegated_gate",
            "admissible.execution",
            "admissible.evidence",
            "admissible.archive",
            "admissible.store",
        )
        print(json.dumps(sorted(
            name for name in sys.modules
            if any(name == item or name.startswith(item + ".") for item in forbidden)
        )))
        """
    )
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = os.fspath(ROOT)
    completed = subprocess.run(
        [sys.executable, "-c", program],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(completed.stdout) == []
    assert completed.stderr == ""


def test_helper_performs_only_the_two_configured_file_opens_and_no_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    import http.client
    import socket
    import urllib.request

    message_path, secret_path = _write_inputs(tmp_path)
    opens = []
    original_open = builtins.open

    def tracked_open(candidate, mode):
        opens.append((Path(candidate), mode))
        if Path(candidate) not in {message_path, secret_path}:
            raise AssertionError(f"unrelated file access: {candidate}")
        return original_open(candidate, mode)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("forbidden contact, process, or directory access")

    monkeypatch.setattr(builtins, "open", tracked_open)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(http.client, "HTTPConnection", forbidden)
    monkeypatch.setattr(http.client, "HTTPSConnection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "check_output", forbidden)
    monkeypatch.setattr(os, "listdir", forbidden)
    monkeypatch.setattr(os, "scandir", forbidden)
    monkeypatch.setattr(Path, "iterdir", forbidden)
    monkeypatch.setattr(Path, "glob", forbidden)
    monkeypatch.setattr(Path, "rglob", forbidden)
    assert tool.main(_argv(message_path, secret_path)) == 0
    captured = capfdbinary.readouterr()
    assert captured.out == _expected_output(VECTOR_SECRET, VECTOR_MESSAGE)
    assert captured.err == b""
    assert opens == [(message_path, "rb"), (secret_path, "rb")]


def test_executable_helper_ast_contains_no_interpretation_contact_or_extra_source():
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
    ]
    attribute_calls = {
        node.func.attr
        for node in calls
        if isinstance(node.func, ast.Attribute)
    }
    name_calls = {
        node.func.id for node in calls if isinstance(node.func, ast.Name)
    }
    assert not (
        attribute_calls
        & {
            "strip",
            "lstrip",
            "rstrip",
            "resolve",
            "expanduser",
            "decode",
            "b64decode",
            "loads",
            "load",
            "listdir",
            "scandir",
            "iterdir",
            "glob",
            "rglob",
            "connect",
            "request",
            "run",
            "Popen",
        }
    )
    assert not (name_calls & {"eval", "exec", "input", "open_url"})
    option_literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("--")
    }
    assert option_literals == {"--message-file", "--secret-file"}
    lowered = MODULE_PATH.read_text(encoding="utf-8").lower()
    for forbidden in (
        "base64",
        "keyring",
        "environ",
        "getenv",
        "stdin",
        "urllib",
        "requests",
        "socket",
        "http",
        "productlauncher",
        "product_launcher",
        "product_service",
        "product_ui",
        "delegated_gate",
        "archive",
        "canonical_json",
        "confirmation submission",
    ):
        assert forbidden not in lowered


def test_hmac_call_shape_and_read_order_are_statically_pinned():
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    main_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    source = ast.unparse(main_node)
    message_index = source.index("_read_historical_pairing_message_file")
    secret_index = source.index("read_historical_pairing_secret_file")
    hmac_index = source.index("hmac.new")
    stdout_index = source.index("sys.stdout.buffer.write")
    assert message_index < secret_index < hmac_index < stdout_index
    hmac_call = next(
        node
        for node in ast.walk(main_node)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "hmac"
        and node.func.attr == "new"
    )
    assert [keyword.arg for keyword in hmac_call.keywords] == [
        "key",
        "msg",
        "digestmod",
    ]
    assert ast.unparse(hmac_call.keywords[0].value) == "secret"
    assert ast.unparse(hmac_call.keywords[1].value) == "message"
    assert ast.unparse(hmac_call.keywords[2].value) == "hashlib.sha256"


@pytest.fixture(scope="module")
def installed_distribution(tmp_path_factory: pytest.TempPathFactory):
    """Build one wheel outside the repository and install it into its own tree.

    The build and the installation are module-scoped because both the packaging
    assertions and the installed-execution assertions need exactly the same
    artifact, and building it twice would prove nothing extra.  Nothing in this
    fixture reads from the repository except the copied source snapshot.
    """

    root = tmp_path_factory.mktemp("dist")
    source_root = root / "source"
    source_root.mkdir()
    for package in ("admissible", "agent_os"):
        shutil.copytree(
            ROOT / package,
            source_root / package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    for name in ("pyproject.toml", "README.md"):
        shutil.copy2(ROOT / name, source_root / name)
    wheel_root = root / "wheel"
    wheel_root.mkdir()
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--no-isolation",
            "--outdir",
            os.fspath(wheel_root),
        ],
        cwd=source_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    wheels = list(wheel_root.glob("*.whl"))
    assert len(wheels) == 1
    install_root = root / "install"
    install = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-index",
            "--target",
            os.fspath(install_root),
            os.fspath(wheels[0]),
        ],
        cwd=root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert install.returncode == 0, install.stdout + install.stderr
    run_root = root / "run"
    run_root.mkdir()
    return SimpleNamespace(
        source_root=source_root,
        wheel_path=wheels[0],
        install=install,
        install_root=install_root,
        run_root=run_root,
    )


def test_wheel_built_and_installed_outside_repository_contains_all_declared_assets(
    installed_distribution,
):
    wheels = [installed_distribution.wheel_path]
    install = installed_distribution.install
    install_root = installed_distribution.install_root
    with zipfile.ZipFile(wheels[0]) as archive:
        names = set(archive.namelist())
        assert "admissible/operator_tools/__init__.py" in names
        assert "admissible/operator_tools/historical_pairing_tag.py" in names
        assert "admissible/product_ui/index.html" in names
        assert "admissible/product_ui/app.css" in names
        assert "admissible/product_ui/app.js" in names
        entry_points_name = next(
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        )
        entry_points = archive.read(entry_points_name).decode("utf-8")
        assert "agent-os = agent_os.cli:main" in entry_points
        assert "admissible = admissible.product_launcher.__main__:main" in entry_points
        assert (
            "admissible-historical-pairing-tag = "
            "admissible.operator_tools.historical_pairing_tag:main"
        ) in entry_points

    assert install.returncode == 0, install.stdout + install.stderr
    assert (install_root / "admissible" / "operator_tools" / "__init__.py").is_file()
    assert (
        install_root
        / "admissible"
        / "operator_tools"
        / "historical_pairing_tag.py"
    ).is_file()
    assert (install_root / "admissible" / "product_ui" / "index.html").is_file()


# Application-owned reference minimization.


def test_success_releases_message_secret_tag_and_temporary_output(
    tmp_path: Path,
    capfdbinary,
):
    message_path, secret_path = _write_inputs(tmp_path)
    frame = _main_return_frame(lambda: tool.main(_argv(message_path, secret_path)))
    captured = capfdbinary.readouterr()
    assert captured.out == _expected_output(VECTOR_SECRET, VECTOR_MESSAGE)
    assert captured.err == b""
    _assert_released(frame)


def test_message_refusal_retains_no_material(
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    monkeypatch.setattr(
        tool,
        "_read_historical_pairing_message_file",
        lambda _path: (_ for _ in ()).throw(
            tool.HistoricalPairingTagMessageFileError(
                tool.HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE
            )
        ),
    )
    frame = _main_return_frame(
        lambda: tool.main(
            _argv(
                Path("C:/configured/message.bin"),
                Path("C:/configured/secret.bin"),
            )
        )
    )
    assert capfdbinary.readouterr().out == b""
    _assert_released(frame)


def test_secret_refusal_releases_public_message(
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    message = b"retention-public-message-sentinel"
    monkeypatch.setattr(
        tool,
        "_read_historical_pairing_message_file",
        lambda _path: message,
    )
    monkeypatch.setattr(
        tool,
        "read_historical_pairing_secret_file",
        lambda *, path: (_ for _ in ()).throw(
            HistoricalPairingSecretFileError(HISTORICAL_PAIRING_SECRET_UNAVAILABLE)
        ),
    )
    frame = _main_return_frame(
        lambda: tool.main(
            _argv(
                Path("C:/configured/message.bin"),
                Path("C:/configured/secret.bin"),
            )
        )
    )
    assert capfdbinary.readouterr().out == b""
    _assert_released(frame)
    assert message not in frame.f_locals.values()


def test_unexpected_computation_failure_releases_both_inputs(
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    message = b"retention-message-sentinel"
    secret = b"retention-secret-sentinel"
    monkeypatch.setattr(
        tool,
        "_read_historical_pairing_message_file",
        lambda _path: message,
    )
    monkeypatch.setattr(
        tool,
        "read_historical_pairing_secret_file",
        lambda *, path: secret,
    )
    monkeypatch.setattr(
        tool.hmac,
        "new",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("computation defect")),
    )
    with pytest.raises(RuntimeError, match="computation defect"):
        frame = _main_return_frame(
            lambda: tool.main(
                _argv(
                    Path("C:/configured/message.bin"),
                    Path("C:/configured/secret.bin"),
                )
            )
        )
    # The helper frame is also available directly on the ordinary traceback.
    try:
        tool.main(
            _argv(
                Path("C:/configured/message.bin"),
                Path("C:/configured/secret.bin"),
            )
        )
    except RuntimeError as failure:
        frames = []
        traceback = failure.__traceback__
        while traceback is not None:
            if traceback.tb_frame.f_code is tool.main.__code__:
                frames.append(traceback.tb_frame)
            traceback = traceback.tb_next
        assert len(frames) == 1
        _assert_released(frames[0])
    assert capfdbinary.readouterr().out == b""


def test_stdout_write_failure_releases_tag_and_output_encoding(
    monkeypatch: pytest.MonkeyPatch,
):
    message = b"stdout-failure-message"
    secret = b"stdout-failure-secret"
    monkeypatch.setattr(
        tool,
        "_read_historical_pairing_message_file",
        lambda _path: message,
    )
    monkeypatch.setattr(
        tool,
        "read_historical_pairing_secret_file",
        lambda *, path: secret,
    )

    class WriteFailure(Exception):
        pass

    class BrokenBuffer:
        def write(self, _payload):
            raise WriteFailure("stdout unavailable")

    class BrokenStdout:
        buffer = BrokenBuffer()

    monkeypatch.setattr(tool.sys, "stdout", BrokenStdout())
    frames = []

    def trace(frame, event, _argument):
        if frame.f_code is tool.main.__code__ and event == "return":
            frames.append(frame)
        return trace

    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        with pytest.raises(WriteFailure, match="stdout unavailable"):
            tool.main(
                _argv(
                    Path("C:/configured/message.bin"),
                    Path("C:/configured/secret.bin"),
                )
            )
    finally:
        sys.settrace(previous)
    assert len(frames) == 1
    _assert_released(frames[0])


def test_module_and_callable_roots_retain_no_runtime_material_after_invocation(
    tmp_path: Path,
    capfdbinary,
):
    message = b"module-retention-message-sentinel"
    secret = b"module-retention-secret-sentinel"
    tag = hmac.new(key=secret, msg=message, digestmod=hashlib.sha256).hexdigest()
    result, captured = _run_direct(
        tmp_path,
        capfdbinary,
        message=message,
        secret=secret,
    )
    assert result == 0
    assert captured.out == tag.encode() + os.linesep.encode()
    assert captured.err == b""
    assert tool.main.__closure__ is None
    assert tool.main.__kwdefaults__ is None
    assert tool.main.__defaults__ == (None,)
    for name, value in vars(tool).items():
        if name.startswith("__"):
            continue
        assert value is not message
        assert value is not secret
        assert value != message
        assert value != secret
        assert value != tag
        assert value != tag.encode()


def test_explicit_helper_owned_roots_retain_no_input_encoding_or_tag(
    tmp_path: Path,
    capfdbinary,
):
    message = b"explicit-root-message-sentinel"
    secret = b"explicit-root-secret-sentinel"
    tag = hmac.new(key=secret, msg=message, digestmod=hashlib.sha256).hexdigest()
    result, captured = _run_direct(
        tmp_path,
        capfdbinary,
        message=message,
        secret=secret,
    )
    assert result == 0
    assert captured.out == tag.encode() + os.linesep.encode()
    sensitive = {
        message,
        secret,
        message.hex(),
        secret.hex(),
        base64.b64encode(message),
        base64.b64encode(secret),
        base64.b64encode(message).decode("ascii"),
        base64.b64encode(secret).decode("ascii"),
        tag,
        tag.encode("ascii"),
    }
    seen = set()

    def contains_sensitive(value, depth=0):
        if depth > 12 or id(value) in seen:
            return False
        seen.add(id(value))
        if type(value) in {bytes, str}:
            return value in sensitive
        if type(value) in {tuple, list, set, frozenset}:
            return any(contains_sensitive(item, depth + 1) for item in value)
        if type(value) is dict:
            return any(
                contains_sensitive(key, depth + 1)
                or contains_sensitive(item, depth + 1)
                for key, item in value.items()
            )
        if (
            isinstance(value, FunctionType)
            and value.__module__ == tool.__name__
        ):
            roots = [value.__defaults__, value.__kwdefaults__]
            if value.__closure__ is not None:
                roots.extend(cell.cell_contents for cell in value.__closure__)
            return any(contains_sensitive(root, depth + 1) for root in roots)
        if isinstance(value, type) and value.__module__ == tool.__name__:
            return contains_sensitive(vars(value), depth + 1)
        if (
            type(value).__module__ == tool.__name__
            and hasattr(value, "__dict__")
        ):
            return contains_sensitive(vars(value), depth + 1)
        return False

    owned_roots = {
        name: value
        for name, value in vars(tool).items()
        if not name.startswith("__")
    }
    assert not contains_sensitive(owned_roots)


@pytest.mark.parametrize(
    "code",
    [
        tool.HISTORICAL_PAIRING_TAG_MESSAGE_PATH_INVALID,
        tool.HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE,
        tool.HISTORICAL_PAIRING_TAG_MESSAGE_LENGTH_INVALID,
    ],
)
def test_message_refusal_output_is_one_path_free_fixed_line(
    code: str,
    monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    failure = tool.HistoricalPairingTagMessageFileError(code)
    monkeypatch.setattr(
        tool,
        "_read_historical_pairing_message_file",
        lambda _path: (_ for _ in ()).throw(failure),
    )
    result = tool.main(
        _argv(
            Path("C:/private/message.bin"),
            Path("C:/private/secret.bin"),
        )
    )
    captured = capfdbinary.readouterr()
    assert result == 3
    assert captured.out == b""
    assert captured.err == f"error={code}".encode() + os.linesep.encode()
    assert captured.err.count(os.linesep.encode()) == 1
    for forbidden in (b"C:", b"private", b"message.bin", b"secret.bin", VECTOR_TAG.encode()):
        assert forbidden not in captured.err


# ---------------------------------------------------------------------------
# Step 5C2E2.1: bounded application-owned retention scanner.
#
# The committed scanner walked only exact ``dict`` mappings, so ``vars(cls)``
# -- a ``MappingProxyType`` -- was skipped and every class-namespace retention
# form escaped.  It also recognized no ``bytearray``, ``memoryview``, Latin-1
# text or live HMAC object, and it truncated silently once its depth bound was
# reached.  The scanner below closes those gaps and fails deterministically
# instead of truncating.
# ---------------------------------------------------------------------------


MAX_OWNED_GRAPH_DEPTH = 24
MAX_OWNED_GRAPH_NODES = 100000


class OwnedGraphBoundExceeded(AssertionError):
    """Deterministic failure raised when a declared traversal bound is hit."""


def _entropy_block(label: bytes, length: int) -> bytes:
    """Deterministic high-entropy bytes: reproducible, yet structure-free.

    A high-entropy sentinel is what lets every disclosure check compare
    *complete* values.  Short-fragment matching is never needed, so the scanner
    cannot manufacture broad false positives out of ordinary module content.
    """

    block = b""
    counter = 0
    while len(block) < length:
        block += hashlib.sha256(label + counter.to_bytes(4, "big")).digest()
        counter += 1
    return block[:length]


RETENTION_SECRET = _entropy_block(b"5C2E2.1-retention-secret", 48)
RETENTION_MESSAGE = _entropy_block(b"5C2E2.1-retention-message", 96)
RETENTION_TAG = hmac.new(
    key=RETENTION_SECRET,
    msg=RETENTION_MESSAGE,
    digestmod=hashlib.sha256,
).hexdigest()

OWNED_MODULES = frozenset({tool.__name__, secret_reader_module.__name__})

# ``__builtins__`` reaches the whole interpreter and the import-machinery
# entries reach the whole loader graph; walking either would be a heap scan
# rather than an application-owned scan.  Every other module attribute --
# including ``__all__`` and ``__doc__`` -- is traversed.
_INTERPRETER_OWNED_MODULE_KEYS = frozenset(
    {"__builtins__", "__loader__", "__spec__", "__cached__"}
)

# Structural carriers are traversed wherever they are reached from an owned
# root, because they are transparent holders rather than foreign objects.
_STRUCTURAL_TYPES = (
    functools.partial,
    MethodType,
    SimpleNamespace,
    BaseException,
)


class OwnedGraphScanner:
    """Bounded, cycle-safe, descriptor-free application-owned retention walker.

    Traversal is restricted to explicitly supplied application-owned roots plus
    the structural carriers reachable from them.  It never walks the complete
    Python heap and never walks ``sys.modules``.  It invokes no property, no
    ``__getattr__``, no ``__getattribute__`` override, no iterator protocol on
    an unknown object, and no descriptor other than a slot ``member_descriptor``
    -- whose ``__get__`` is a plain C-level slot read.
    """

    def __init__(
        self,
        *,
        secret: bytes,
        message: bytes,
        tag: str,
        owned_modules: frozenset,
        max_depth: int = MAX_OWNED_GRAPH_DEPTH,
        max_nodes: int = MAX_OWNED_GRAPH_NODES,
    ) -> None:
        self.owned_modules = owned_modules
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.tag = tag
        self.byte_forms = {
            "secret-bytes": secret,
            "secret-hex-bytes": secret.hex().encode("ascii"),
            "secret-base64-bytes": base64.b64encode(secret),
            "message-bytes": message,
            "message-hex-bytes": message.hex().encode("ascii"),
            "message-base64-bytes": base64.b64encode(message),
            "tag-bytes": tag.encode("ascii"),
            "tag-digest-bytes": bytes.fromhex(tag),
        }
        self.text_forms = {
            "secret-latin1-text": secret.decode("latin-1"),
            "secret-hex-text": secret.hex(),
            "secret-base64-text": base64.b64encode(secret).decode("ascii"),
            "message-latin1-text": message.decode("latin-1"),
            "message-hex-text": message.hex(),
            "message-base64-text": base64.b64encode(message).decode("ascii"),
            "tag-text": tag,
        }

    # -- disclosure classification -----------------------------------------

    def disclosure_form(self, value):
        """Name the complete-secret disclosure form a leaf carries, if any.

        Only *complete* forms are recognized, by equality or by containment of
        the whole form.  No short fragment is ever matched, so an ordinary
        module string cannot be reported by accident.
        """

        raw = None
        if isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
        elif isinstance(value, memoryview):
            try:
                raw = value.tobytes()
            except ValueError:
                raw = None
        if raw is not None:
            for name, form in self.byte_forms.items():
                if raw == form or form in raw:
                    return name
            return None
        if isinstance(value, str):
            for name, form in self.text_forms.items():
                if value == form or form in value:
                    return name
            return None
        if type(value) is hmac.HMAC:
            # A live HMAC retains the normalized key inside its own state.
            # ``hexdigest`` copies the inner hash and mutates nothing, and the
            # expected tag is supplied to the scanner rather than discovered.
            if value.hexdigest() == self.tag:
                return "hmac-object"
        return None

    def _safe_label(self, key, index):
        """Label a mapping key without ever placing material into a path."""

        if (
            type(key) is str
            and key.isidentifier()
            and self.disclosure_form(key) is None
        ):
            return key
        return "#%d" % index

    # -- traversal ----------------------------------------------------------

    @staticmethod
    def _instance_namespace(value):
        """Read ``__dict__`` without invoking ``__getattr__`` or an override."""

        try:
            namespace = object.__getattribute__(value, "__dict__")
        except AttributeError:
            return None
        return namespace if isinstance(namespace, dict) else None

    def _declared_module(self, value):
        """Read a class ``__module__`` without consulting a metaclass hook."""

        return vars(value).get("__module__")

    def _children(self, path, value):
        children = []

        if isinstance(value, (str, bytes, bytearray, memoryview, int, float)):
            return children
        if value is None or isinstance(value, complex) or value is Ellipsis:
            return children

        if isinstance(value, MappingProxyType):
            for index, (key, item) in enumerate(value.items()):
                label = self._safe_label(key, index)
                children.append((f"{path}<key {label}>", key))
                children.append((f"{path}[{label}]", item))
            return children

        if isinstance(value, dict):
            # ``dict.items`` is called unbound so an overridden ``items`` on a
            # dict subclass cannot run in place of the real mapping read.
            for index, (key, item) in enumerate(dict.items(value)):
                label = self._safe_label(key, index)
                children.append((f"{path}<key {label}>", key))
                children.append((f"{path}[{label}]", item))
            return children

        if isinstance(value, (list, tuple)):
            for index, item in enumerate(tuple(value)):
                children.append((f"{path}[{index}]", item))
            return children

        if isinstance(value, (set, frozenset)):
            for index, item in enumerate(sorted(value, key=id)):
                children.append((f"{path}{{{index}}}", item))
            return children

        if isinstance(value, functools.partial):
            children.append((f"{path}.func", value.func))
            children.append((f"{path}.args", value.args))
            children.append((f"{path}.keywords", value.keywords))
            return children

        if isinstance(value, MethodType):
            children.append((f"{path}.__self__", value.__self__))
            children.append((f"{path}.__func__", value.__func__))
            return children

        if isinstance(value, BaseException):
            children.append((f"{path}.args", value.args))
            if value.__cause__ is not None:
                children.append((f"{path}.__cause__", value.__cause__))
            if value.__context__ is not None:
                children.append((f"{path}.__context__", value.__context__))
            namespace = self._instance_namespace(value)
            if namespace is not None:
                children.append((f"{path}.__dict__", namespace))
                if "__notes__" in namespace:
                    children.append((f"{path}.__notes__", namespace["__notes__"]))
            children.extend(self._traceback_children(path, value.__traceback__))
            return children

        if isinstance(value, FunctionType):
            if value.__module__ not in self.owned_modules:
                return children
            children.append((f"{path}.__defaults__", value.__defaults__))
            children.append((f"{path}.__kwdefaults__", value.__kwdefaults__))
            if value.__closure__ is not None:
                for index, cell in enumerate(value.__closure__):
                    try:
                        contents = cell.cell_contents
                    except ValueError:
                        continue
                    children.append((f"{path}.__closure__[{index}]", contents))
            children.append((f"{path}.__dict__", value.__dict__))
            return children

        if isinstance(value, type):
            # ``vars`` of a class returns a ``MappingProxyType`` rather than an
            # exact ``dict``; reading its items yields the raw descriptor
            # objects and executes none of them.
            if self._declared_module(value) not in self.owned_modules:
                return children
            children.append((f"{path}.__dict__", vars(value)))
            return children

        value_type = type(value)
        if value_type.__module__ in self.owned_modules or isinstance(
            value, _STRUCTURAL_TYPES
        ):
            namespace = self._instance_namespace(value)
            if namespace is not None:
                children.append((f"{path}.__dict__", namespace))
            children.extend(self._slot_children(path, value, value_type))
        return children

    def _slot_children(self, path, value, value_type):
        """Read declared ``__slots__`` through member descriptors only."""

        children = []
        for klass in value_type.__mro__:
            for name, member in vars(klass).items():
                if type(member) is not MemberDescriptorType:
                    continue
                try:
                    held = member.__get__(value, klass)
                except AttributeError:
                    continue
                children.append((f"{path}.{name}", held))
        return children

    def _traceback_children(self, path, traceback_object):
        """Collect locals of owned frames only, never of foreign frames."""

        children = []
        index = 0
        while traceback_object is not None:
            frame = traceback_object.tb_frame
            if frame.f_globals.get("__name__") in self.owned_modules:
                children.append(
                    (
                        f"{path}.__traceback__[{index}].f_locals",
                        dict(frame.f_locals),
                    )
                )
            traceback_object = traceback_object.tb_next
            index += 1
        return children

    def scan(self, roots):
        """Breadth-first so every object is reported at its shortest path.

        Breadth-first order also makes the reported ownership path
        deterministic when one object is reachable through several owned
        routes, which an exact-path assertion depends on.
        """

        findings = []
        visited = set()
        # Every visited object is kept alive: a collected object's ``id`` can be
        # reused, which would silently mark a *different* object as visited.
        alive = []
        pending = [(name, value, 0) for name, value in roots.items()]
        cursor = 0
        examined = 0
        while cursor < len(pending):
            path, value, depth = pending[cursor]
            cursor += 1
            if depth > self.max_depth:
                raise OwnedGraphBoundExceeded(f"depth bound exceeded at {path}")
            marker = id(value)
            if marker in visited:
                continue
            visited.add(marker)
            alive.append(value)
            examined += 1
            if examined > self.max_nodes:
                raise OwnedGraphBoundExceeded(f"node bound exceeded at {path}")
            form = self.disclosure_form(value)
            if form is not None:
                findings.append((path, form))
            for child_path, child in self._children(path, value):
                pending.append((child_path, child, depth + 1))
        assert len(alive) == examined
        return sorted(set(findings))


def _owned_roots():
    """Explicit application-owned roots: the helper and its neutral leaf."""

    roots = {}
    for module in (tool, secret_reader_module):
        for name, value in vars(module).items():
            if name in _INTERPRETER_OWNED_MODULE_KEYS:
                continue
            roots[f"{module.__name__}.{name}"] = value
    return roots


def _scanner(**overrides):
    arguments = {
        "secret": RETENTION_SECRET,
        "message": RETENTION_MESSAGE,
        "tag": RETENTION_TAG,
        "owned_modules": OWNED_MODULES,
    }
    arguments.update(overrides)
    return OwnedGraphScanner(**arguments)


# ---------------------------------------------------------------------------
# Owned witness carriers.
#
# Every carrier declares the helper module as its owner, so a witness is placed
# on exactly the graph the scanner is asked to walk against the real helper --
# the same shape a retention mutant produces.  Each carrier is attached through
# ``monkeypatch`` and removed again, so no production object keeps it.
# ---------------------------------------------------------------------------


MODULE = tool.__name__
ERROR_CLASS = tool.HistoricalPairingTagMessageFileError
CLASS_NAMESPACE = f"{MODULE}.HistoricalPairingTagMessageFileError.__dict__[witness]"


class _OwnedSlotCarrier:
    """Owned instance whose only storage is a declared slot."""

    __slots__ = ("held",)

    def __init__(self, held):
        self.held = held


class _OwnedHostileAccess:
    """Owned class whose descriptors must never run during a scan.

    ``__getattribute__`` forwards dunder names because ``isinstance`` itself
    consults ``__class__``; every ordinary attribute name is trapped, and an
    ordinary name is exactly what an attribute-reading scanner would touch.
    """

    @property
    def trap(self):
        raise AssertionError("property executed during owned-graph scan")

    def __getattr__(self, name):
        raise AssertionError(f"__getattr__ executed during owned-graph scan: {name}")

    def __getattribute__(self, name):
        if name.startswith("__") and name.endswith("__"):
            return object.__getattribute__(self, name)
        raise AssertionError(
            f"__getattribute__ executed during owned-graph scan: {name}"
        )


_OwnedSlotCarrier.__module__ = MODULE
_OwnedHostileAccess.__module__ = MODULE


def _owned_default_body(positional=None, *, keyword=None):
    return positional, keyword


def _owned_frame_body(payload):
    held = payload
    raise RuntimeError("owned-frame-retention-witness")


def _owned_function(body, *, defaults=None, kwdefaults=None):
    """Rebuild ``body`` so its globals -- and therefore its owner -- are ours."""

    built = FunctionType(
        body.__code__,
        {"__name__": MODULE, "__builtins__": builtins},
        body.__name__,
    )
    built.__module__ = MODULE
    if defaults is not None:
        built.__defaults__ = defaults
    if kwdefaults is not None:
        built.__kwdefaults__ = kwdefaults
    return built


def _owned_frame_witness():
    """Raise inside an owned frame and keep the resulting traceback."""

    raiser = _owned_function(_owned_frame_body)
    try:
        raiser(RETENTION_SECRET)
    except RuntimeError as failure:
        return failure
    raise AssertionError("owned frame witness did not raise")


def _witness_secret_bytes_on_class(monkeypatch):
    monkeypatch.setattr(ERROR_CLASS, "witness", RETENTION_SECRET, raising=False)
    return [(CLASS_NAMESPACE, "secret-bytes")]


def _witness_bytearray_on_class(monkeypatch):
    monkeypatch.setattr(
        ERROR_CLASS, "witness", bytearray(RETENTION_SECRET), raising=False
    )
    return [(CLASS_NAMESPACE, "secret-bytes")]


def _witness_latin1_module_global(monkeypatch):
    monkeypatch.setattr(
        tool, "witness_text", RETENTION_SECRET.decode("latin-1"), raising=False
    )
    return [(f"{MODULE}.witness_text", "secret-latin1-text")]


def _witness_latin1_nested_container(monkeypatch):
    nested = {"outer": ({"inner": [RETENTION_SECRET.decode("latin-1")]},)}
    monkeypatch.setattr(tool, "witness_nested", nested, raising=False)
    return [
        (f"{MODULE}.witness_nested[outer][0][inner][0]", "secret-latin1-text")
    ]


def _witness_hmac_object_on_class(monkeypatch):
    live = hmac.new(
        key=RETENTION_SECRET,
        msg=RETENTION_MESSAGE,
        digestmod=hashlib.sha256,
    )
    monkeypatch.setattr(ERROR_CLASS, "witness", live, raising=False)
    return [(CLASS_NAMESPACE, "hmac-object")]


def _witness_tag_text_on_class(monkeypatch):
    monkeypatch.setattr(ERROR_CLASS, "witness", RETENTION_TAG, raising=False)
    return [(CLASS_NAMESPACE, "tag-text")]


def _witness_mapping_proxy(monkeypatch):
    monkeypatch.setattr(
        tool,
        "witness_proxy",
        MappingProxyType({"held": RETENTION_SECRET}),
        raising=False,
    )
    return [(f"{MODULE}.witness_proxy[held]", "secret-bytes")]


def _witness_object_slots(monkeypatch):
    monkeypatch.setattr(
        tool, "witness_slots", _OwnedSlotCarrier(RETENTION_SECRET), raising=False
    )
    return [(f"{MODULE}.witness_slots.held", "secret-bytes")]


def _witness_function_defaults_and_kwdefaults(monkeypatch):
    carrier = _owned_function(
        _owned_default_body,
        defaults=(RETENTION_SECRET,),
        kwdefaults={"keyword": bytearray(RETENTION_SECRET)},
    )
    # A plain function attribute is a third, independent owned root.
    carrier.retained = RETENTION_SECRET.hex()
    monkeypatch.setattr(tool, "witness_function", carrier, raising=False)
    return [
        (f"{MODULE}.witness_function.__defaults__[0]", "secret-bytes"),
        (f"{MODULE}.witness_function.__kwdefaults__[keyword]", "secret-bytes"),
        (f"{MODULE}.witness_function.__dict__[retained]", "secret-hex-text"),
    ]


def _witness_partial(monkeypatch):
    held = functools.partial(
        _owned_function(_owned_default_body),
        RETENTION_SECRET,
        keyword=bytearray(RETENTION_SECRET),
    )
    monkeypatch.setattr(tool, "witness_partial", held, raising=False)
    return [
        (f"{MODULE}.witness_partial.args[0]", "secret-bytes"),
        (f"{MODULE}.witness_partial.keywords[keyword]", "secret-bytes"),
    ]


def _witness_exception_state(monkeypatch):
    cause = RuntimeError(RETENTION_SECRET.hex())
    context = RuntimeError(base64.b64encode(RETENTION_SECRET).decode("ascii"))
    failure = ERROR_CLASS(tool.HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE)
    failure.args = (RETENTION_SECRET.decode("latin-1"),)
    failure.__cause__ = cause
    failure.__context__ = context
    failure.add_note(RETENTION_TAG)
    failure.retained = bytearray(RETENTION_SECRET)
    monkeypatch.setattr(tool, "witness_error", failure, raising=False)
    return [
        (f"{MODULE}.witness_error.args[0]", "secret-latin1-text"),
        (f"{MODULE}.witness_error.__cause__.args[0]", "secret-hex-text"),
        (f"{MODULE}.witness_error.__context__.args[0]", "secret-base64-text"),
        (f"{MODULE}.witness_error.__notes__[0]", "tag-text"),
        (f"{MODULE}.witness_error.__dict__[retained]", "secret-bytes"),
    ]


def _witness_owned_traceback_frame(monkeypatch):
    monkeypatch.setattr(
        tool, "witness_frame", _owned_frame_witness(), raising=False
    )
    return [
        (
            f"{MODULE}.witness_frame.__traceback__[1].f_locals[payload]",
            "secret-bytes",
        )
    ]


RETENTION_WITNESSES = {
    "secret-bytes-on-class-attribute": _witness_secret_bytes_on_class,
    "bytearray-on-class-attribute": _witness_bytearray_on_class,
    "latin1-text-on-module-global": _witness_latin1_module_global,
    "latin1-text-in-nested-container": _witness_latin1_nested_container,
    "hmac-object-on-class-attribute": _witness_hmac_object_on_class,
    "tag-text-on-class-attribute": _witness_tag_text_on_class,
    "secret-in-mapping-proxy": _witness_mapping_proxy,
    "secret-in-object-slots": _witness_object_slots,
    "secret-in-function-defaults-and-kwdefaults": (
        _witness_function_defaults_and_kwdefaults
    ),
    "secret-in-partial": _witness_partial,
    "secret-in-exception-state": _witness_exception_state,
    "secret-in-owned-traceback-frame-local": _witness_owned_traceback_frame,
}


def _describe(findings):
    """Diagnostics carry an ownership path and a form name -- never material."""

    return sorted(f"{path} :: {form}" for path, form in findings)


# Scanner unit behaviour.


def test_disclosure_detector_recognizes_every_required_complete_form():
    scanner = _scanner()
    secret = RETENTION_SECRET
    message = RETENTION_MESSAGE
    recognized = {
        "identity": scanner.disclosure_form(secret),
        "equal-copy": scanner.disclosure_form(bytes(bytearray(secret))),
        "bytearray": scanner.disclosure_form(bytearray(secret)),
        "memoryview": scanner.disclosure_form(memoryview(secret)),
        "latin1-text": scanner.disclosure_form(secret.decode("latin-1")),
        "hex-bytes": scanner.disclosure_form(secret.hex().encode("ascii")),
        "hex-text": scanner.disclosure_form(secret.hex()),
        "base64-bytes": scanner.disclosure_form(base64.b64encode(secret)),
        "base64-text": scanner.disclosure_form(
            base64.b64encode(secret).decode("ascii")
        ),
        "tag-bytes": scanner.disclosure_form(RETENTION_TAG.encode("ascii")),
        "tag-text": scanner.disclosure_form(RETENTION_TAG),
        "message-bytes": scanner.disclosure_form(message),
        "hmac-object": scanner.disclosure_form(
            hmac.new(key=secret, msg=message, digestmod=hashlib.sha256)
        ),
    }
    assert all(form is not None for form in recognized.values()), recognized
    assert recognized["identity"] == "secret-bytes"
    assert recognized["equal-copy"] == "secret-bytes"
    assert recognized["bytearray"] == "secret-bytes"
    assert recognized["memoryview"] == "secret-bytes"
    assert recognized["latin1-text"] == "secret-latin1-text"
    assert recognized["hmac-object"] == "hmac-object"
    # An embedded complete form is a disclosure; an unrelated value is not.
    assert scanner.disclosure_form(b"prefix" + secret + b"suffix") == "secret-bytes"
    assert scanner.disclosure_form(RETENTION_TAG[:32]) is None
    assert scanner.disclosure_form(secret[:16]) is None
    for ordinary in (
        b"",
        b"rb",
        "--message-file",
        "HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE",
        tool.__doc__,
        secret_reader_module.__doc__,
        hmac.new(key=b"k" * 16, msg=b"other", digestmod=hashlib.sha256),
    ):
        assert scanner.disclosure_form(ordinary) is None


def test_owned_graph_scan_of_the_clean_helper_reports_no_disclosure(
    tmp_path: Path,
    capfdbinary,
):
    result, captured = _run_direct(
        tmp_path,
        capfdbinary,
        message=RETENTION_MESSAGE,
        secret=RETENTION_SECRET,
    )
    assert result == 0
    assert captured.out == RETENTION_TAG.encode("ascii") + os.linesep.encode("ascii")
    assert captured.err == b""
    findings = _scanner().scan(_owned_roots())
    assert findings == [], _describe(findings)


@pytest.mark.parametrize("witness", sorted(RETENTION_WITNESSES))
def test_owned_graph_scan_detects_each_required_retention_witness(
    witness: str,
    tmp_path: Path,
    capfdbinary,
    monkeypatch: pytest.MonkeyPatch,
):
    scanner = _scanner()
    result, _captured = _run_direct(
        tmp_path,
        capfdbinary,
        message=RETENTION_MESSAGE,
        secret=RETENTION_SECRET,
    )
    assert result == 0
    assert scanner.scan(_owned_roots()) == []

    expected = RETENTION_WITNESSES[witness](monkeypatch)
    detected = scanner.scan(_owned_roots())
    assert detected == sorted(expected), _describe(detected)

    monkeypatch.undo()
    assert scanner.scan(_owned_roots()) == []


def test_owned_graph_scan_never_executes_a_property_or_attribute_hook(
    monkeypatch: pytest.MonkeyPatch,
):
    hostile = _OwnedHostileAccess()
    object.__setattr__(hostile, "held", RETENTION_SECRET)
    monkeypatch.setattr(tool, "witness_hostile", hostile, raising=False)
    monkeypatch.setattr(
        tool, "witness_hostile_class", _OwnedHostileAccess, raising=False
    )
    detected = _scanner().scan(_owned_roots())
    assert detected == [(f"{MODULE}.witness_hostile.__dict__[held]", "secret-bytes")], (
        _describe(detected)
    )


def test_owned_graph_scan_is_cycle_safe_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
):
    cycle = {"self": None, "held": RETENTION_SECRET}
    cycle["self"] = cycle
    monkeypatch.setattr(tool, "witness_cycle", cycle, raising=False)
    assert _scanner().scan(_owned_roots()) == [
        (f"{MODULE}.witness_cycle[held]", "secret-bytes")
    ]

    deep = RETENTION_SECRET
    for _level in range(40):
        deep = [deep]
    monkeypatch.setattr(tool, "witness_deep", deep, raising=False)
    with pytest.raises(OwnedGraphBoundExceeded, match="depth bound exceeded"):
        _scanner().scan(_owned_roots())
    with pytest.raises(OwnedGraphBoundExceeded, match="node bound exceeded"):
        _scanner(max_nodes=5).scan(_owned_roots())


def test_owned_graph_scan_walks_neither_sys_modules_nor_the_whole_heap():
    roots = _owned_roots()
    assert set(roots) == {
        f"{module.__name__}.{name}"
        for module in (tool, secret_reader_module)
        for name in vars(module)
        if name not in _INTERPRETER_OWNED_MODULE_KEYS
    }
    assert f"{MODULE}.__builtins__" not in roots
    scanner = _scanner()
    # An imported module reached from an owned root is a leaf: descending into
    # one would turn the owned scan into a walk of ``sys.modules``.
    imported = [value for value in roots.values() if isinstance(value, type(sys))]
    assert {module.__name__ for module in imported} >= {"os", "sys", "hmac"}
    for module in imported:
        assert scanner._children("probe", module) == []
    # A bounded owned graph, not a heap: far below the live object population.
    counted = []
    original = scanner._children

    def counting(path, value):
        counted.append(path)
        return original(path, value)

    scanner._children = counting
    assert scanner.scan(roots) == []
    assert len(counted) < 2000


def test_scan_diagnostics_disclose_only_path_and_form(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(ERROR_CLASS, "witness", RETENTION_SECRET, raising=False)
    # Both mapping keys are themselves complete disclosure forms, so a key
    # label that echoed the key would leak material straight into the path.
    keyed = {
        RETENTION_SECRET.decode("latin-1"): RETENTION_TAG,
        base64.b64encode(RETENTION_SECRET).decode("ascii"): RETENTION_MESSAGE,
    }
    monkeypatch.setattr(tool, "witness_keyed", keyed, raising=False)
    findings = _scanner().scan(_owned_roots())
    rendered = "\n".join(_describe(findings))
    assert (CLASS_NAMESPACE, "secret-bytes") in findings
    assert (f"{MODULE}.witness_keyed<key #0>", "secret-latin1-text") in findings
    assert (f"{MODULE}.witness_keyed<key #1>", "secret-base64-text") in findings
    assert (f"{MODULE}.witness_keyed[#0]", "tag-text") in findings
    assert (f"{MODULE}.witness_keyed[#1]", "message-bytes") in findings
    for material in (
        RETENTION_SECRET.decode("latin-1"),
        RETENTION_SECRET.hex(),
        base64.b64encode(RETENTION_SECRET).decode("ascii"),
        RETENTION_MESSAGE.decode("latin-1"),
        RETENTION_TAG,
    ):
        assert material not in rendered


# ---------------------------------------------------------------------------
# Behavioural no-contact and no-persistence observation.
#
# A final directory snapshot cannot see a file that was created and removed
# again inside one invocation.  The observer below records the *operations*
# instead, so a create-write-close-rename-delete sequence is caught even when
# the directory it happened in ends the test perfectly clean.
# ---------------------------------------------------------------------------


_WRITE_OPEN_FLAGS = ("w", "a", "x", "+")

_OS_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_RDWR
    | os.O_CREAT
    | os.O_TRUNC
    | os.O_APPEND
    | getattr(os, "O_EXCL", 0)
)


class SideEffectObserver:
    """Record every file, mutation, temporary, contact and scan operation."""

    def __init__(self, *, allowed_reads):
        self.events = []
        self.allowed_reads = [Path(item) for item in allowed_reads]
        self._saved = []

    # -- recording ----------------------------------------------------------

    def _target(self, value):
        try:
            return Path(os.fsdecode(value))
        except (TypeError, ValueError):
            return None

    def record(self, kind, target, *, writing):
        self.events.append((kind, self._target(target), bool(writing)))

    def read_only_source_opens(self):
        return [
            (target, kind)
            for kind, target, writing in self.events
            if not writing and kind in {"builtins.open", "io.open", "os.open"}
        ]

    def mutating_events(self):
        return [
            (kind, target)
            for kind, target, writing in self.events
            if writing or kind not in {"builtins.open", "io.open", "os.open"}
        ]

    def unauthorized_reads(self):
        """Read-only opens of anything other than a configured source."""

        return [
            (kind, target)
            for kind, target, writing in self.events
            if not writing and target not in self.allowed_reads
        ]

    # -- installation -------------------------------------------------------

    def _patch(self, owner, name, replacement):
        self._saved.append((owner, name, getattr(owner, name)))
        setattr(owner, name, replacement)

    def _open_spy(self, kind, original):
        def spy(target, mode="r", *args, **kwargs):
            writing = any(flag in str(mode) for flag in _WRITE_OPEN_FLAGS)
            self.record(kind, target, writing=writing)
            return original(target, mode, *args, **kwargs)

        return spy

    def _path_open_spy(self, original):
        def spy(path_self, mode="r", *args, **kwargs):
            writing = any(flag in str(mode) for flag in _WRITE_OPEN_FLAGS)
            self.record("Path.open", path_self, writing=writing)
            return original(path_self, mode, *args, **kwargs)

        return spy

    def _os_open_spy(self, original):
        def spy(target, flags, *args, **kwargs):
            self.record("os.open", target, writing=bool(flags & _OS_WRITE_FLAGS))
            return original(target, flags, *args, **kwargs)

        return spy

    def _mutation_spy(self, kind, original):
        def spy(first, *args, **kwargs):
            self.record(kind, first, writing=True)
            return original(first, *args, **kwargs)

        return spy

    def _temporary_spy(self, kind, original):
        def spy(*args, **kwargs):
            self.record(kind, None, writing=True)
            return original(*args, **kwargs)

        return spy

    def _forbidden_spy(self, kind):
        def spy(*args, **kwargs):
            target = args[0] if args else None
            self.record(kind, target, writing=True)
            raise AssertionError(f"forbidden runtime surface reached: {kind}")

        return spy

    def install(self):
        import http.client
        import socket
        import urllib.request

        # File opening and creation.
        self._patch(builtins, "open", self._open_spy("builtins.open", builtins.open))
        self._patch(io, "open", self._open_spy("io.open", io.open))
        self._patch(os, "open", self._os_open_spy(os.open))
        self._patch(Path, "open", self._path_open_spy(Path.open))
        for name in ("write_bytes", "write_text", "touch"):
            self._patch(
                Path,
                name,
                self._mutation_spy(f"Path.{name}", getattr(Path, name)),
            )

        # Mutation and removal.
        for name in ("rename", "replace", "remove", "unlink"):
            self._patch(
                os,
                name,
                self._mutation_spy(f"os.{name}", getattr(os, name)),
            )
        for name in ("rename", "replace", "unlink"):
            self._patch(
                Path,
                name,
                self._mutation_spy(f"Path.{name}", getattr(Path, name)),
            )

        # Temporary files.
        for name in ("mkstemp", "NamedTemporaryFile", "mkdtemp"):
            self._patch(
                tempfile,
                name,
                self._temporary_spy(f"tempfile.{name}", getattr(tempfile, name)),
            )

        # Existing forbidden surfaces.
        self._patch(socket, "socket", self._forbidden_spy("socket.socket"))
        self._patch(
            socket, "create_connection", self._forbidden_spy("socket.create_connection")
        )
        self._patch(
            http.client, "HTTPConnection", self._forbidden_spy("http.HTTPConnection")
        )
        self._patch(
            http.client, "HTTPSConnection", self._forbidden_spy("http.HTTPSConnection")
        )
        self._patch(urllib.request, "urlopen", self._forbidden_spy("urllib.urlopen"))
        for name in ("Popen", "run", "check_output", "check_call", "call"):
            self._patch(
                subprocess, name, self._forbidden_spy(f"subprocess.{name}")
            )
        for name in ("listdir", "scandir", "walk"):
            self._patch(os, name, self._forbidden_spy(f"os.{name}"))
        for name in ("iterdir", "glob", "rglob"):
            self._patch(Path, name, self._forbidden_spy(f"Path.{name}"))
        for name in ("putenv", "unsetenv"):
            self._patch(os, name, self._forbidden_spy(f"os.{name}"))

    def remove(self):
        for owner, name, original in reversed(self._saved):
            setattr(owner, name, original)
        self._saved.clear()


@contextlib.contextmanager
def _observed_runtime(*, allowed_reads):
    """Observe one runtime window only.

    Every module the observer patches is imported before the window opens and
    the helper is warmed up by the caller, so ordinary import-time reads are
    attributed to import and can never appear as a recorded runtime operation.
    """

    import http.client  # noqa: F401  (imported before the window opens)
    import socket  # noqa: F401
    import urllib.request  # noqa: F401

    observer = SideEffectObserver(allowed_reads=allowed_reads)
    environment_before = dict(os.environ)
    observer.install()
    try:
        yield observer
    finally:
        observer.remove()
    assert dict(os.environ) == environment_before


def _warm_up_helper(root: Path, capfdbinary):
    """Run one invocation before observation so no import is attributed to it."""

    message_path, secret_path = _write_inputs(
        root,
        message=RETENTION_MESSAGE,
        secret=RETENTION_SECRET,
    )
    assert tool.main(_argv(message_path, secret_path)) == 0
    capfdbinary.readouterr()
    return message_path, secret_path


def test_successful_invocation_performs_only_two_read_only_source_opens(
    tmp_path: Path,
    capfdbinary,
):
    warm_root = tmp_path / "warm"
    warm_root.mkdir()
    _warm_up_helper(warm_root, capfdbinary)

    observed_root = tmp_path / "observed"
    observed_root.mkdir()
    message_path, secret_path = _write_inputs(
        observed_root,
        message=RETENTION_MESSAGE,
        secret=RETENTION_SECRET,
    )
    with _observed_runtime(allowed_reads=[message_path, secret_path]) as observer:
        result = tool.main(_argv(message_path, secret_path))
    captured = capfdbinary.readouterr()
    assert result == 0
    assert captured.out == RETENTION_TAG.encode("ascii") + os.linesep.encode("ascii")
    assert captured.err == b""
    assert observer.events == [
        ("builtins.open", message_path, False),
        ("builtins.open", secret_path, False),
    ]
    assert observer.mutating_events() == []
    assert observer.unauthorized_reads() == []
    assert observer.read_only_source_opens() == [
        (message_path, "builtins.open"),
        (secret_path, "builtins.open"),
    ]


@pytest.mark.parametrize(
    "code",
    [
        tool.HISTORICAL_PAIRING_TAG_MESSAGE_PATH_INVALID,
        tool.HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE,
        tool.HISTORICAL_PAIRING_TAG_MESSAGE_LENGTH_INVALID,
    ],
)
def test_bounded_refusal_writes_creates_and_removes_nothing(
    code: str,
    tmp_path: Path,
    capfdbinary,
):
    warm_root = tmp_path / "warm"
    warm_root.mkdir()
    _warm_up_helper(warm_root, capfdbinary)

    refused_root = tmp_path / "refused"
    refused_root.mkdir()
    message_path = refused_root / "message.bin"
    secret_path = refused_root / "secret.bin"
    secret_path.write_bytes(RETENTION_SECRET)
    expected_entries = {secret_path}
    if code == tool.HISTORICAL_PAIRING_TAG_MESSAGE_LENGTH_INVALID:
        message_path.write_bytes(b"")
        expected_entries.add(message_path)
    elif code == tool.HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE:
        pass  # left missing
    else:
        message_path = Path("relative-message.bin")

    with _observed_runtime(
        allowed_reads=[message_path, secret_path]
    ) as observer:
        result = tool.main(_argv(message_path, secret_path))
    captured = capfdbinary.readouterr()
    assert result == tool.HISTORICAL_PAIRING_TAG_EXIT_CODE
    assert captured.out == b""
    assert captured.err == f"error={code}".encode("ascii") + os.linesep.encode("ascii")
    assert observer.mutating_events() == []
    assert observer.unauthorized_reads() == []
    assert set(refused_root.iterdir()) == expected_entries


def test_observer_detects_a_create_write_close_rename_and_delete_that_leaves_no_trace(
    tmp_path: Path,
):
    """The observer's own positive control: a clean directory proves nothing."""

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    first = workspace / "leaked.bin"
    second = workspace / "renamed.bin"

    with _observed_runtime(allowed_reads=[]) as observer:
        first.write_bytes(RETENTION_TAG.encode("ascii"))
        first.rename(second)
        with io.open(second, "rb") as handle:
            assert handle.read() == RETENTION_TAG.encode("ascii")
        os.remove(second)
        handle_descriptor, temporary_name = tempfile.mkstemp(dir=os.fspath(workspace))
        os.close(handle_descriptor)
        os.unlink(temporary_name)

    # The directory is spotless, so only the recorded operations can testify.
    assert list(workspace.iterdir()) == []
    kinds = [kind for kind, _target, _writing in observer.events]
    assert "Path.write_bytes" in kinds
    assert "Path.rename" in kinds
    assert "io.open" in kinds
    assert "os.remove" in kinds
    assert "tempfile.mkstemp" in kinds
    assert "os.unlink" in kinds
    assert observer.mutating_events() != []


def test_observer_refuses_contact_process_and_directory_scan_surfaces(tmp_path: Path):
    import socket
    import urllib.request

    workspace = tmp_path / "contact"
    workspace.mkdir()
    with _observed_runtime(allowed_reads=[]) as observer:
        for attempt in (
            lambda: socket.socket(),
            lambda: urllib.request.urlopen("http://127.0.0.1:1/"),
            lambda: subprocess.run([sys.executable, "-c", "pass"]),
            lambda: os.listdir(os.fspath(workspace)),
            lambda: list(workspace.iterdir()),
            lambda: os.putenv("HISTORICAL_PAIRING_TAG_PROBE", "1"),
        ):
            with pytest.raises(AssertionError, match="forbidden runtime surface"):
                attempt()
    assert {kind for kind, _target, _writing in observer.events} == {
        "socket.socket",
        "urllib.urlopen",
        "subprocess.run",
        "os.listdir",
        "Path.iterdir",
        "os.putenv",
    }


# Every surface the guard must watch, pinned so it can never silently shrink.
REQUIRED_OBSERVED_SURFACES = (
    (builtins, "open"),
    (io, "open"),
    (os, "open"),
    (Path, "open"),
    (Path, "write_bytes"),
    (Path, "write_text"),
    (Path, "touch"),
    (os, "rename"),
    (os, "replace"),
    (os, "remove"),
    (os, "unlink"),
    (Path, "rename"),
    (Path, "replace"),
    (Path, "unlink"),
    (tempfile, "mkstemp"),
    (tempfile, "NamedTemporaryFile"),
    (tempfile, "mkdtemp"),
    (subprocess, "Popen"),
    (subprocess, "run"),
    (subprocess, "check_output"),
    (os, "listdir"),
    (os, "scandir"),
    (os, "walk"),
    (Path, "iterdir"),
    (Path, "glob"),
    (Path, "rglob"),
    (os, "putenv"),
    (os, "unsetenv"),
)


def test_side_effect_observer_covers_every_required_surface_and_restores_it():
    import http.client
    import socket
    import urllib.request

    required = REQUIRED_OBSERVED_SURFACES + (
        (socket, "socket"),
        (socket, "create_connection"),
        (http.client, "HTTPConnection"),
        (http.client, "HTTPSConnection"),
        (urllib.request, "urlopen"),
    )
    before = {
        (owner.__name__, name): getattr(owner, name) for owner, name in required
    }
    with _observed_runtime(allowed_reads=[]):
        observed = {
            (owner.__name__, name)
            for owner, name in required
            if getattr(owner, name) is not before[(owner.__name__, name)]
        }
    assert observed == set(before)
    after = {
        (owner.__name__, name): getattr(owner, name) for owner, name in required
    }
    assert after == before


# ---------------------------------------------------------------------------
# Behavioural message opacity.
# ---------------------------------------------------------------------------


# Valid JSON whose exact bytes are deliberately non-canonical: CRLF, padding
# whitespace, unsorted keys, a duplicated key, and an escape spelling a parser
# would normalize.  It stays parseable so a parse-and-reserialize mutant runs
# to completion and is caught behaviourally rather than by a token scan.
NONCANONICAL_JSON_MESSAGE = (
    b"{\r\n"
    b'  "zeta"  :  "\\u0041\\u0042",\r\n'
    b'  "alpha" : 1,\r\n'
    b'  "alpha" : 2,\r\n'
    b'  "beta"  : [ 1,2 ,3 ]\r\n'
    b"}\r\n"
)


def _canonical_reserialization(raw: bytes) -> bytes:
    return json.dumps(
        json.loads(raw.decode("utf-8")),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_noncanonical_json_message_is_opaque_and_reaches_hmac_by_identity(
    tmp_path: Path,
    capfdbinary,
    monkeypatch: pytest.MonkeyPatch,
):
    message_path, secret_path = _write_inputs(
        tmp_path,
        message=NONCANONICAL_JSON_MESSAGE,
        secret=RETENTION_SECRET,
    )
    raw = message_path.read_bytes()
    assert raw == NONCANONICAL_JSON_MESSAGE
    canonical = _canonical_reserialization(raw)
    assert canonical != raw
    assert json.loads(raw.decode("utf-8")) == json.loads(canonical.decode("utf-8"))
    # Computed before ``hmac.new`` is instrumented, so the expectation itself
    # never lands in the recorded submissions.
    expected_output = _expected_output(RETENTION_SECRET, raw)
    canonical_output = _expected_output(RETENTION_SECRET, canonical)

    returned = []
    submitted = []
    original_reader = tool._read_historical_pairing_message_file
    original_new = tool.hmac.new

    def recording_reader(path):
        value = original_reader(path)
        returned.append(value)
        return value

    def recording_new(*, key, msg, digestmod):
        submitted.append(msg)
        return original_new(key=key, msg=msg, digestmod=digestmod)

    monkeypatch.setattr(
        tool, "_read_historical_pairing_message_file", recording_reader
    )
    monkeypatch.setattr(tool.hmac, "new", recording_new)
    assert tool.main(_argv(message_path, secret_path)) == 0
    captured = capfdbinary.readouterr()

    assert len(returned) == 1
    assert len(submitted) == 1
    # Identity, not equality: no copy, reserialization or normalization stands
    # between the exact file bytes and the computation.
    assert submitted[0] is returned[0]
    assert submitted[0] == raw
    assert captured.out == expected_output
    assert captured.out != canonical_output
    assert captured.err == b""


def test_canonical_reserialization_of_the_message_changes_the_tag(
    tmp_path: Path,
    capfdbinary,
):
    raw_root = tmp_path / "raw"
    canonical_root = tmp_path / "canonical"
    raw_root.mkdir()
    canonical_root.mkdir()
    canonical = _canonical_reserialization(NONCANONICAL_JSON_MESSAGE)
    raw_inputs = _write_inputs(
        raw_root, message=NONCANONICAL_JSON_MESSAGE, secret=RETENTION_SECRET
    )
    canonical_inputs = _write_inputs(
        canonical_root, message=canonical, secret=RETENTION_SECRET
    )
    assert tool.main(_argv(*raw_inputs)) == 0
    raw_output = capfdbinary.readouterr().out
    assert tool.main(_argv(*canonical_inputs)) == 0
    canonical_output = capfdbinary.readouterr().out
    assert raw_output == _expected_output(RETENTION_SECRET, NONCANONICAL_JSON_MESSAGE)
    assert canonical_output == _expected_output(RETENTION_SECRET, canonical)
    assert raw_output != canonical_output
    # The helper never parses: it cannot know the two files mean the same thing.
    assert json.loads(NONCANONICAL_JSON_MESSAGE.decode("utf-8")) == json.loads(
        canonical.decode("utf-8")
    )


# ---------------------------------------------------------------------------
# Installed-distribution execution.
#
# Building and installing a wheel proves packaging.  Only *running* the
# installed artifact, with the repository absent from the child's import
# search, proves the distribution is self-sufficient.
# ---------------------------------------------------------------------------


def _installed_environment(install_root: Path) -> dict:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    environment["PYTHONNOUSERSITE"] = "1"
    # Exactly the install tree: no repository path, no inherited PYTHONPATH.
    environment["PYTHONPATH"] = os.fspath(install_root)
    return environment


def _console_script(install_root: Path) -> Path:
    candidates = sorted(
        candidate
        for directory in ("bin", "Scripts")
        for candidate in (install_root / directory).glob(
            "admissible-historical-pairing-tag*"
        )
        if candidate.is_file()
    )
    assert candidates, f"installed console script missing under {install_root}"
    return candidates[0]


def _installed_inputs(run_root: Path) -> tuple[Path, Path]:
    return _write_inputs(
        run_root,
        message=RETENTION_MESSAGE,
        secret=RETENTION_SECRET,
    )


def _run_installed(command, installed_distribution, arguments):
    return subprocess.run(
        [*command, *arguments],
        cwd=installed_distribution.run_root,
        env=_installed_environment(installed_distribution.install_root),
        capture_output=True,
        check=False,
    )


def test_installed_module_and_console_script_emit_byte_exact_output(
    installed_distribution,
):
    message_path, secret_path = _installed_inputs(installed_distribution.run_root)
    expected = RETENTION_TAG.encode("ascii") + os.linesep.encode("ascii")
    invocations = {
        "module": [
            sys.executable,
            "-m",
            "admissible.operator_tools.historical_pairing_tag",
        ],
        "console-script": [os.fspath(_console_script(
            installed_distribution.install_root
        ))],
    }
    for label, command in invocations.items():
        completed = _run_installed(
            command, installed_distribution, _argv(message_path, secret_path)
        )
        assert completed.returncode == 0, (label, completed.stderr)
        assert completed.stdout == expected, label
        assert completed.stderr == b"", label


def test_installed_distribution_resolves_without_a_source_tree_fallback(
    installed_distribution,
):
    install_root = installed_distribution.install_root
    probe = textwrap.dedent(
        """
        import json
        import sys
        import admissible
        import admissible.operator_tools
        import admissible.operator_tools.historical_pairing_tag as helper
        import admissible.historical_pairing_secret_file as leaf
        print(json.dumps({
            "helper": helper.__file__,
            "leaf": leaf.__file__,
            "package": admissible.__file__,
            "package_path": list(admissible.__path__),
            "operator_path": list(admissible.operator_tools.__path__),
            "sys_path": [entry for entry in sys.path if entry],
        }))
        """
    )
    completed = _run_installed(
        [sys.executable, "-c", probe], installed_distribution, []
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == b""
    origins = json.loads(completed.stdout.decode("utf-8"))

    installed = os.path.normcase(os.fspath(install_root))
    repository = os.path.normcase(os.fspath(ROOT))
    for key in ("helper", "leaf", "package"):
        assert os.path.normcase(origins[key]).startswith(installed), (key, origins[key])
    for key in ("package_path", "operator_path"):
        for entry in origins[key]:
            assert os.path.normcase(entry).startswith(installed), (key, entry)
    searched = (
        origins["sys_path"] + origins["package_path"] + origins["operator_path"]
    )
    for entry in searched:
        normalized = os.path.normcase(entry)
        assert normalized != repository
        assert not normalized.startswith(repository + os.sep)


def test_installed_console_script_help_abbreviation_and_refusal_exit_codes(
    installed_distribution,
):
    script = _console_script(installed_distribution.install_root)
    module = [
        sys.executable,
        "-m",
        "admissible.operator_tools.historical_pairing_tag",
    ]
    message_path, secret_path = _installed_inputs(installed_distribution.run_root)

    for command in ([os.fspath(script)], module):
        helped = _run_installed(command, installed_distribution, ["--help"])
        assert helped.returncode == 0
        assert b"--message-file" in helped.stdout
        assert b"--secret-file" in helped.stdout
        assert helped.stderr == b""

        abbreviated = _run_installed(
            command,
            installed_distribution,
            [
                "--message-file",
                os.fspath(message_path),
                "--secret-file",
                os.fspath(secret_path),
                "--message",
                os.fspath(message_path),
            ],
        )
        assert abbreviated.returncode == 2
        assert abbreviated.stdout == b""
        assert b"unrecognized arguments" in abbreviated.stderr

        refused = _run_installed(
            command,
            installed_distribution,
            [
                "--message-file",
                "relative-message.bin",
                "--secret-file",
                os.fspath(secret_path),
            ],
        )
        assert refused.returncode == tool.HISTORICAL_PAIRING_TAG_EXIT_CODE
        assert refused.stdout == b""
        assert refused.stderr == (
            b"error=" + tool.HISTORICAL_PAIRING_TAG_MESSAGE_PATH_INVALID.encode("ascii")
            + os.linesep.encode("ascii")
        )


# ---------------------------------------------------------------------------
# Real file-level reparse point.
# ---------------------------------------------------------------------------


def _create_real_file_reparse_point(directory: Path) -> Path:
    """Create one real file-level reparse point, or skip honestly.

    An unprivileged file symbolic link is a genuine file-level reparse point on
    Windows when Developer Mode is enabled.  No dependency is added and no
    elevation is requested: when the platform refuses, the committed synthetic
    reparse-point test remains the only coverage and the limitation is reported
    rather than emulated with a directory junction.
    """

    target = directory / "reparse-target.bin"
    target.write_bytes(RETENTION_MESSAGE)
    link = directory / "reparse-message.bin"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as failure:
        pytest.skip(
            "platform cannot create an unprivileged file-level reparse point: "
            f"{failure}"
        )
    metadata = os.lstat(link)
    attributes = getattr(metadata, "st_file_attributes", 0)
    if not (attributes & tool._REPARSE_POINT_FLAG) and not stat.S_ISLNK(
        metadata.st_mode
    ):
        pytest.skip("platform reports no reparse-point metadata for the fixture")
    return link


def test_real_file_level_reparse_point_message_is_refused_before_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    link = _create_real_file_reparse_point(tmp_path)
    metadata = os.lstat(link)
    assert bool(
        getattr(metadata, "st_file_attributes", 0) & tool._REPARSE_POINT_FLAG
    ) or stat.S_ISLNK(metadata.st_mode)
    assert link.read_bytes() == RETENTION_MESSAGE  # the link really resolves

    opened = []
    monkeypatch.setattr(builtins, "open", lambda *args, **kwargs: opened.append(args))
    with pytest.raises(tool.HistoricalPairingTagMessageFileError) as refusal:
        tool._read_historical_pairing_message_file(link)
    assert refusal.value.code == tool.HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE
    assert opened == []


def test_real_file_level_reparse_point_message_refusal_is_one_bounded_line(
    tmp_path: Path,
    capfdbinary,
):
    link = _create_real_file_reparse_point(tmp_path)
    secret_path = tmp_path / "secret.bin"
    secret_path.write_bytes(RETENTION_SECRET)
    result = tool.main(_argv(link, secret_path))
    captured = capfdbinary.readouterr()
    assert result == tool.HISTORICAL_PAIRING_TAG_EXIT_CODE
    assert captured.out == b""
    assert captured.err == (
        b"error=" + tool.HISTORICAL_PAIRING_TAG_MESSAGE_UNAVAILABLE.encode("ascii")
        + os.linesep.encode("ascii")
    )
