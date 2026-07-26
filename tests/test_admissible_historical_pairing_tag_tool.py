"""Step 5C2E2: independent exact-byte historical-pairing tag utility."""

import ast
import base64
import builtins
import hashlib
import hmac
import importlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import textwrap
import tomllib
from types import SimpleNamespace
from types import FunctionType
import zipfile

import pytest

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


def test_wheel_built_and_installed_outside_repository_contains_all_declared_assets(
    tmp_path: Path,
):
    source_root = tmp_path / "source"
    source_root.mkdir()
    for package in ("admissible", "agent_os"):
        shutil.copytree(
            ROOT / package,
            source_root / package,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    for name in ("pyproject.toml", "README.md"):
        shutil.copy2(ROOT / name, source_root / name)
    wheel_root = tmp_path / "wheel"
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

    install_root = tmp_path / "install"
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
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
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
