"""Step 5C2E1A: bounded startup-only enablement and secret-file loaders.

Two independent laws are pinned here.

The secret reader must return *exactly* the bytes of one explicitly configured
regular file, with no decoding, trimming, normalization, or truncation, and must
fail through a bounded code that carries no secret, no observed length, no path,
and no operating-system text.

The enablement loader must translate one bounded non-secret JSON document into
the accepted ``HistoricalPairingConfiguration`` while owning only JSON transport
facts.  Every configuration question -- payload-identifier grammar, duplicate
rules, path law, TTL and capacity bounds -- stays with the accepted type, so the
loader is proven here to be a translator and not a second authority.

Expected byte strings in this module are independent literals or independently
constructed values; the modules under test are never asked to produce an
expectation they are then compared against.
"""

from __future__ import annotations

import ast
import builtins
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
import io
import json
import logging
import os
from pathlib import Path
import re
import stat
import sys
import threading
from types import SimpleNamespace
import warnings

import pytest

from admissible import historical_pairing_secret_file as secret_module
from admissible.historical_pairing_secret_file import (
    HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES,
    HISTORICAL_PAIRING_SECRET_LENGTH_INVALID,
    HISTORICAL_PAIRING_SECRET_PATH_INVALID,
    HISTORICAL_PAIRING_SECRET_UNAVAILABLE,
    MAX_HISTORICAL_PAIRING_SECRET_BYTES,
    MIN_HISTORICAL_PAIRING_SECRET_BYTES,
    HistoricalPairingSecretFileError,
    read_historical_pairing_secret_file,
)
from admissible.delegated_gate.historical_evaluation import (
    HistoricalEvaluationPairingAuthority,
)
from admissible.delegated_gate.historical_pairing_confirmation import (
    MAX_CONFIRMATION_SECRET_BYTES,
    MIN_CONFIRMATION_SECRET_BYTES,
    compute_historical_pairing_confirmation_tag,
)
from admissible.product_launcher import historical_pairing_enablement as enablement_module
from admissible.product_launcher.historical_pairing_enablement import (
    HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID,
    HISTORICAL_PAIRING_CONFIG_MALFORMED,
    HISTORICAL_PAIRING_CONFIG_PATH_INVALID,
    HISTORICAL_PAIRING_CONFIG_TOO_LARGE,
    HISTORICAL_PAIRING_CONFIG_UNAVAILABLE,
    HISTORICAL_PAIRING_ENABLEMENT_ERROR_CODES,
    HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION,
    MAX_HISTORICAL_PAIRING_ENABLEMENT_BYTES,
    HistoricalPairingEnablementDocumentError,
    load_historical_pairing_configuration,
)
from admissible.product_launcher import historical_pairing_registry as registry_module
from admissible.product_launcher.historical_pairing_registry import (
    HistoricalPairingConfiguration,
    HistoricalPayloadEntry,
    InvalidHistoricalPairingConfiguration,
)
from test_admissible_historical_pairing_confirmation import VECTOR_AUTHORITY_DOCUMENT


# ---------------------------------------------------------------------------
# Fixture material.
# ---------------------------------------------------------------------------


def _write(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    return path


def _enablement_document(
    *,
    archive_root: str,
    payloads: tuple[tuple[str, str], ...],
    schema_version: str = HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION,
    preparation_ttl_seconds: int = 900,
    max_preparations: int = 64,
) -> dict:
    return {
        "schema_version": schema_version,
        "archive_root": archive_root,
        "payloads": [
            {"payload_id": payload_id, "document_path": document_path}
            for payload_id, document_path in payloads
        ],
        "preparation_ttl_seconds": preparation_ttl_seconds,
        "max_preparations": max_preparations,
    }


def _document_bytes(document: dict) -> bytes:
    return json.dumps(document, indent=2).encode("utf-8")


@pytest.fixture()
def enablement_root(tmp_path: Path) -> Path:
    root = tmp_path / "enable"
    root.mkdir()
    return root


@pytest.fixture()
def valid_document(enablement_root: Path) -> dict:
    """One well-formed document whose configured paths are absent on disk.

    Nothing the loader is handed exists as a file: proving a successful load
    against absent payload documents is itself proof that no configured V4
    document was opened.
    """

    return _enablement_document(
        archive_root=str(enablement_root / "archive"),
        payloads=(
            ("first-payload", str(enablement_root / "one.json")),
            ("second-payload", str(enablement_root / "two.json")),
            ("third-payload", str(enablement_root / "three.json")),
        ),
    )


@pytest.fixture()
def valid_document_path(enablement_root: Path, valid_document: dict) -> Path:
    return _write(enablement_root / "enablement.json", _document_bytes(valid_document))


@pytest.fixture()
def secret_root(tmp_path: Path) -> Path:
    root = tmp_path / "secrets"
    root.mkdir()
    return root


# ---------------------------------------------------------------------------
# Filesystem observation.
# ---------------------------------------------------------------------------


class _RecordingHandle:
    """Wrap one real binary handle and record every requested read size."""

    def __init__(self, handle, sizes: list[int]) -> None:
        self._handle = handle
        self._sizes = sizes

    def read(self, size: int = -1):
        self._sizes.append(size)
        return self._handle.read(size)

    def fileno(self) -> int:
        return self._handle.fileno()

    def __enter__(self) -> "_RecordingHandle":
        self._handle.__enter__()
        return self

    def __exit__(self, *exc_info):
        return self._handle.__exit__(*exc_info)


class _Observation:
    def __init__(self) -> None:
        self.opened: list[Path] = []
        self.read_sizes: list[int] = []
        self.forbidden: list[str] = []


@contextmanager
def _filesystem_observation(module, monkeypatch: pytest.MonkeyPatch):
    """Record every open and every read size, and forbid traversal or creation."""

    observation = _Observation()
    real_open = builtins.open

    def spy_open(path, mode="r", *args, **kwargs):
        observation.opened.append(Path(os.fspath(path)))
        return _RecordingHandle(
            real_open(path, mode, *args, **kwargs), observation.read_sizes
        )

    def forbidden(name):
        def _raise(*args, **kwargs):
            observation.forbidden.append(name)
            raise AssertionError(f"loader performed a forbidden {name} call")

        return _raise

    monkeypatch.setattr(module, "open", spy_open, raising=False)
    for target, name in (
        (os, "listdir"),
        (os, "scandir"),
        (os, "walk"),
        (os, "mkdir"),
        (os, "makedirs"),
        (os, "readlink"),
    ):
        monkeypatch.setattr(target, name, forbidden(f"os.{name}"))
    for name in ("glob", "rglob", "iterdir", "mkdir", "resolve", "readlink"):
        monkeypatch.setattr(Path, name, forbidden(f"Path.{name}"))
    yield observation


class _PathAccess:
    """Every path handed to an open, stat, existence or directory entry point.

    Nothing is forbidden here and nothing is faked: each entry point delegates
    to the real implementation and records the exact path it was given, so a
    test can afterwards distinguish the one document the loader is allowed to
    touch from every configured path it must never touch.
    """

    def __init__(self) -> None:
        self.events: list[tuple[str, str]] = []

    def record(self, operation: str, value: object) -> None:
        try:
            recorded = os.fspath(value)
        except TypeError:
            # An integer file descriptor names no path and cannot be a
            # configured V4 document; record it verbatim rather than dropping it.
            recorded = f"<non-path {value!r}>"
        self.events.append((operation, recorded))

    def paths_for(self, operation: str) -> list[str]:
        return [path for name, path in self.events if name == operation]

    @property
    def paths(self) -> list[str]:
        return [path for _, path in self.events]


# Every entry point through which a configured V4 document could be opened,
# stat-ed, probed for existence, or reached through its directory.
OBSERVED_OS_ENTRY_POINTS = ("stat", "lstat", "access", "scandir", "listdir")
OBSERVED_PATH_ENTRY_POINTS = ("open", "stat", "lstat", "exists", "is_file", "is_dir")
OBSERVED_METADATA_OPERATIONS = (
    ("builtins.open",)
    + tuple(f"os.{name}" for name in OBSERVED_OS_ENTRY_POINTS)
    + tuple(f"Path.{name}" for name in OBSERVED_PATH_ENTRY_POINTS)
)


@contextmanager
def _path_access_observation(monkeypatch: pytest.MonkeyPatch):
    """Record the exact path of every open, stat, existence or directory call.

    ``builtins.open`` is wrapped rather than the module global, so a call that
    bypassed the module namespace would still be seen, and ``Path`` is wrapped
    on the class, so a bound-method call on any concrete flavour is seen too.
    """

    access = _PathAccess()
    real_open = builtins.open
    real_os = {name: getattr(os, name) for name in OBSERVED_OS_ENTRY_POINTS}
    real_path = {name: getattr(Path, name) for name in OBSERVED_PATH_ENTRY_POINTS}

    def spy_open(file, *args, **kwargs):
        access.record("builtins.open", file)
        return real_open(file, *args, **kwargs)

    def make_os_spy(name, real):
        def spy(path, *args, **kwargs):
            access.record(f"os.{name}", path)
            return real(path, *args, **kwargs)

        return spy

    def make_path_spy(name, real):
        def spy(self, *args, **kwargs):
            access.record(f"Path.{name}", self)
            return real(self, *args, **kwargs)

        return spy

    monkeypatch.setattr(builtins, "open", spy_open)
    for name, real in real_os.items():
        monkeypatch.setattr(os, name, make_os_spy(name, real))
    for name, real in real_path.items():
        monkeypatch.setattr(Path, name, make_path_spy(name, real))
    yield access


class _Quiet:
    def __init__(self, out: str, err: str, records: list, caught: list) -> None:
        self.out = out
        self.err = err
        self.records = records
        self.caught = caught


@contextmanager
def _no_output(caplog: pytest.LogCaptureFixture):
    """Capture stdout, stderr, logging and warnings for one bounded call."""

    out, err = io.StringIO(), io.StringIO()
    real_out, real_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        with caplog.at_level(logging.DEBUG):
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                quiet = _Quiet("", "", caplog.records, caught)
                yield quiet
    finally:
        sys.stdout, sys.stderr = real_out, real_err
    quiet.out = out.getvalue()
    quiet.err = err.getvalue()


def _assert_silent(quiet: _Quiet) -> None:
    assert quiet.out == ""
    assert quiet.err == ""
    assert quiet.records == []
    assert list(quiet.caught) == []


# ===========================================================================
# N. Secret reader.
# ===========================================================================


def test_secret_bounds_equal_the_accepted_confirmation_primitive():
    """The restated constants may never drift from the accepted key window."""

    assert MIN_HISTORICAL_PAIRING_SECRET_BYTES == MIN_CONFIRMATION_SECRET_BYTES == 16
    assert MAX_HISTORICAL_PAIRING_SECRET_BYTES == MAX_CONFIRMATION_SECRET_BYTES == 4096


@pytest.mark.parametrize("length", [16, 17, 63, 1024, 4095, 4096])
def test_secret_of_accepted_length_is_returned_exactly(
    secret_root: Path, length: int
):
    raw = bytes((index * 7 + 3) % 256 for index in range(length))
    path = _write(secret_root / f"secret-{length}.bin", raw)
    returned = read_historical_pairing_secret_file(path=path)
    assert type(returned) is bytes
    assert returned == raw
    assert len(returned) == length


@pytest.mark.parametrize("length", [0, 1, 2, 15, 4097, 4098, 8192])
def test_secret_outside_the_accepted_window_is_refused(
    secret_root: Path, length: int
):
    raw = b"s" * length
    path = _write(secret_root / f"secret-{length}.bin", raw)
    with pytest.raises(HistoricalPairingSecretFileError) as failure:
        read_historical_pairing_secret_file(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_SECRET_LENGTH_INVALID


def test_secret_read_requests_exactly_the_bound_plus_one_byte_once(
    secret_root: Path, monkeypatch: pytest.MonkeyPatch
):
    """One open, one read, exactly ``MAX + 1``: never unbounded and never twice."""

    path = _write(secret_root / "secret.bin", b"k" * 32)
    with _filesystem_observation(secret_module, monkeypatch) as observation:
        assert read_historical_pairing_secret_file(path=path) == b"k" * 32
    assert observation.opened == [path]
    assert observation.read_sizes == [MAX_HISTORICAL_PAIRING_SECRET_BYTES + 1]
    assert -1 not in observation.read_sizes
    assert observation.forbidden == []


def test_over_bound_secret_is_refused_and_never_truncated(
    secret_root: Path, monkeypatch: pytest.MonkeyPatch
):
    raw = b"o" * (MAX_HISTORICAL_PAIRING_SECRET_BYTES + 512)
    path = _write(secret_root / "huge.bin", raw)
    with _filesystem_observation(secret_module, monkeypatch) as observation:
        with pytest.raises(HistoricalPairingSecretFileError) as failure:
            read_historical_pairing_secret_file(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_SECRET_LENGTH_INVALID
    # The bound plus one byte is all that was ever requested from the handle.
    assert observation.read_sizes == [MAX_HISTORICAL_PAIRING_SECRET_BYTES + 1]


def test_secret_directory_is_refused(secret_root: Path):
    with pytest.raises(HistoricalPairingSecretFileError) as failure:
        read_historical_pairing_secret_file(path=secret_root)
    assert failure.value.code == HISTORICAL_PAIRING_SECRET_UNAVAILABLE


def test_missing_secret_file_is_refused(secret_root: Path):
    with pytest.raises(HistoricalPairingSecretFileError) as failure:
        read_historical_pairing_secret_file(path=secret_root / "absent.bin")
    assert failure.value.code == HISTORICAL_PAIRING_SECRET_UNAVAILABLE


def test_secret_relative_path_is_refused_and_never_resolved_against_cwd(
    secret_root: Path, monkeypatch: pytest.MonkeyPatch
):
    """A relative path is invalid, not resolved: the file exists in the cwd."""

    _write(secret_root / "secret.bin", b"k" * 32)
    monkeypatch.chdir(secret_root)
    assert Path("secret.bin").exists()
    with _filesystem_observation(secret_module, monkeypatch) as observation:
        with pytest.raises(HistoricalPairingSecretFileError) as failure:
            read_historical_pairing_secret_file(path=Path("secret.bin"))
    assert failure.value.code == HISTORICAL_PAIRING_SECRET_PATH_INVALID
    assert observation.opened == []


@pytest.mark.parametrize(
    "builder",
    [
        lambda root: Path(str(root) + os.sep + ".." + os.sep + root.name + os.sep + "s.bin"),
        lambda root: Path(str(root / "sub" / ".." / "s.bin")),
    ],
)
def test_secret_noncanonical_absolute_path_is_refused(secret_root: Path, builder):
    _write(secret_root / "s.bin", b"k" * 32)
    candidate = builder(secret_root)
    assert candidate.is_absolute()
    with pytest.raises(HistoricalPairingSecretFileError) as failure:
        read_historical_pairing_secret_file(path=candidate)
    assert failure.value.code == HISTORICAL_PAIRING_SECRET_PATH_INVALID


@pytest.mark.parametrize(
    "value",
    [
        None,
        "C:\\absolute\\string.bin",
        b"C:\\absolute\\bytes.bin",
        123,
        Path(""),
    ],
)
def test_secret_non_path_or_empty_value_is_refused(value):
    with pytest.raises(HistoricalPairingSecretFileError) as failure:
        read_historical_pairing_secret_file(path=value)
    assert failure.value.code == HISTORICAL_PAIRING_SECRET_PATH_INVALID


def test_secret_path_with_nul_is_refused_before_any_syscall(
    secret_root: Path, monkeypatch: pytest.MonkeyPatch
):
    candidate = Path(str(secret_root) + os.sep + "s\x00.bin")
    with _filesystem_observation(secret_module, monkeypatch) as observation:
        with pytest.raises(HistoricalPairingSecretFileError) as failure:
            read_historical_pairing_secret_file(path=candidate)
    assert failure.value.code == HISTORICAL_PAIRING_SECRET_PATH_INVALID
    assert observation.opened == []


def _redirecting_metadata(*, mode: int, reparse: bool) -> SimpleNamespace:
    return SimpleNamespace(
        st_mode=mode,
        st_file_attributes=(0x0400 if reparse else 0),
    )


def test_secret_symbolic_link_reported_by_lstat_is_refused(
    secret_root: Path, monkeypatch: pytest.MonkeyPatch
):
    """A pre-open symbolic link is refused on every platform, privileged or not."""

    path = _write(secret_root / "secret.bin", b"k" * 32)
    monkeypatch.setattr(
        secret_module.os,
        "lstat",
        lambda _p: _redirecting_metadata(mode=stat.S_IFLNK | 0o600, reparse=False),
    )
    with pytest.raises(HistoricalPairingSecretFileError) as failure:
        read_historical_pairing_secret_file(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_SECRET_UNAVAILABLE


def test_secret_reparse_point_reported_by_lstat_is_refused(
    secret_root: Path, monkeypatch: pytest.MonkeyPatch
):
    path = _write(secret_root / "secret.bin", b"k" * 32)
    monkeypatch.setattr(
        secret_module.os,
        "lstat",
        lambda _p: _redirecting_metadata(mode=stat.S_IFREG | 0o600, reparse=True),
    )
    with pytest.raises(HistoricalPairingSecretFileError) as failure:
        read_historical_pairing_secret_file(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_SECRET_UNAVAILABLE


def test_secret_opened_descriptor_must_itself_be_a_regular_file(
    secret_root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The post-open ``fstat`` decides the handle that was actually opened."""

    path = _write(secret_root / "secret.bin", b"k" * 32)
    monkeypatch.setattr(
        secret_module.os,
        "fstat",
        lambda _fd: _redirecting_metadata(mode=stat.S_IFIFO | 0o600, reparse=False),
    )
    with pytest.raises(HistoricalPairingSecretFileError) as failure:
        read_historical_pairing_secret_file(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_SECRET_UNAVAILABLE


def test_real_direct_symlink_to_a_valid_secret_is_refused(secret_root: Path):
    """The same law against a real platform symlink, when one can be created."""

    target = _write(secret_root / "target.bin", b"k" * 32)
    link = secret_root / "link.bin"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError, AttributeError) as exc:
        pytest.skip(f"platform refuses symbolic link creation: {type(exc).__name__}")
    with pytest.raises(HistoricalPairingSecretFileError) as failure:
        read_historical_pairing_secret_file(path=link)
    assert failure.value.code == HISTORICAL_PAIRING_SECRET_UNAVAILABLE
    # The target itself stays readable: only the redirection was refused.
    assert read_historical_pairing_secret_file(path=target) == b"k" * 32


# --- Exact byte preservation -----------------------------------------------


TRAILING_VARIANTS = {
    "bare": b"pairing-secret-material-0",
    "lf": b"pairing-secret-material-0\n",
    "crlf": b"pairing-secret-material-0\r\n",
    "cr": b"pairing-secret-material-0\r",
    "nul": b"pairing-secret-material-0\x00",
    "space": b"pairing-secret-material-0 ",
    "tab": b"pairing-secret-material-0\t",
    "spaces": b"pairing-secret-material-0   ",
    "leading_space": b" pairing-secret-material-0",
    "double_lf": b"pairing-secret-material-0\n\n",
}


@pytest.mark.parametrize("name", sorted(TRAILING_VARIANTS))
def test_trailing_and_leading_bytes_are_part_of_the_secret(
    secret_root: Path, name: str
):
    raw = TRAILING_VARIANTS[name]
    assert MIN_HISTORICAL_PAIRING_SECRET_BYTES <= len(raw)
    path = _write(secret_root / f"{name}.bin", raw)
    assert read_historical_pairing_secret_file(path=path) == raw


def _vector_authority() -> HistoricalEvaluationPairingAuthority:
    return HistoricalEvaluationPairingAuthority.from_dict(dict(VECTOR_AUTHORITY_DOCUMENT))


def test_every_trailing_variant_produces_a_distinct_secret_and_distinct_tag(
    secret_root: Path,
):
    """No trim, strip, or newline removal: each variant is a different key.

    The trailing-NUL variant is deliberately excluded from the *tag* comparison
    and pinned separately: HMAC zero-pads a key shorter than its block size, so
    a trailing NUL on a short key is a property of HMAC, not of this reader.
    The reader's own obligation -- returning distinct bytes for every variant --
    is asserted here over the complete set including that one.
    """

    authority = _vector_authority()
    returned: dict[str, bytes] = {}
    tags: dict[str, str] = {}
    for name in sorted(TRAILING_VARIANTS):
        path = _write(secret_root / f"tag-{name}.bin", TRAILING_VARIANTS[name])
        secret = read_historical_pairing_secret_file(path=path)
        returned[name] = secret
        if name != "nul":
            tags[name] = compute_historical_pairing_confirmation_tag(
                secret=secret, pairing_authority=authority
            )
    assert len(set(returned.values())) == len(TRAILING_VARIANTS)
    assert len(set(tags.values())) == len(TRAILING_VARIANTS) - 1


def test_trailing_nul_hmac_equivalence_is_an_hmac_property_not_a_reader_defect(
    secret_root: Path,
):
    """State the boundary exactly instead of implying a guarantee that is false.

    HMAC-SHA256 zero-pads any key shorter than its 64-byte block, so a secret
    that is shorter than the block and one that is that secret plus a trailing
    NUL are the same HMAC key and produce the same tag.  The reader still
    returns two different byte strings, and a key at or above the block size is
    hashed instead of padded, so the tags differ there.
    """

    authority = _vector_authority()
    short = b"pairing-secret-material-0"
    assert len(short) < 64
    short_bare = read_historical_pairing_secret_file(
        path=_write(secret_root / "short-bare.bin", short)
    )
    short_nul = read_historical_pairing_secret_file(
        path=_write(secret_root / "short-nul.bin", short + b"\x00")
    )
    assert short_bare != short_nul
    assert short_nul.endswith(b"\x00")
    assert compute_historical_pairing_confirmation_tag(
        secret=short_bare, pairing_authority=authority
    ) == compute_historical_pairing_confirmation_tag(
        secret=short_nul, pairing_authority=authority
    )

    block = b"k" * 64
    block_bare = read_historical_pairing_secret_file(
        path=_write(secret_root / "block-bare.bin", block)
    )
    block_nul = read_historical_pairing_secret_file(
        path=_write(secret_root / "block-nul.bin", block + b"\x00")
    )
    # Stated for exactly these two fixture values at exactly this length, and
    # deliberately not generalized into a universal cryptographic law: a key at
    # or above the block size is hashed rather than zero-padded, so these two
    # particular secrets are two particular different HMAC keys here.
    assert compute_historical_pairing_confirmation_tag(
        secret=block_bare, pairing_authority=authority
    ) != compute_historical_pairing_confirmation_tag(
        secret=block_nul, pairing_authority=authority
    )


# --- The documented HMAC semantics must stay honest -------------------------
#
# The behavioural proofs above establish what is true.  These tests pin the
# module documentation to the same truth, because a docstring is the only part
# of this reader an operator reads before configuring a secret, and the false
# claim these tests forbid is exactly the one an independent review removed.


def _normalized_documentation(module) -> str:
    """Collapse the module docstring to one lowercase whitespace-normal line."""

    return " ".join((module.__doc__ or "").split()).lower()


# Sentences the corrected documentation must state.  Each is an independent
# literal here: the module is never asked to supply the wording it is then
# compared against.
REQUIRED_SECRET_DOC_STATEMENTS = (
    # 1. The exact secret bytes are preserved.
    "every byte in the file is preserved as part of the configured secret",
    # 2. The reader performs no transformation.
    "the reader performs no transformation",
    # 3a. No claim of a distinct key or tag per distinct byte string.
    "the reader does not claim that every distinct byte string maps to a "
    "distinct hmac key or tag",
    # 3b. HMAC's own key normalization may make distinct byte strings equivalent.
    "hmac performs its own standard key normalization, including zero-padding "
    "of short keys, so some distinct byte strings may be hmac-equivalent",
)

# Distinctness language is permitted *only* inside the disclaiming statements
# above.  Everything else in the docstring is scanned for the false claims.
FORBIDDEN_SECRET_DOC_CLAIMS = (
    (r"different confirmation tags?", "distinct secret bytes always produce distinct tags"),
    (r"distinct confirmation tags?", "distinct secret bytes always produce distinct tags"),
    (r"different tags?\b", "a trailing NUL produces a different tag"),
    (r"distinct tags?\b", "a trailing NUL produces a different tag"),
    (r"distinct hmac keys?", "a one-to-one byte-string to HMAC-key mapping"),
    (r"one[- ]to[- ]one", "a one-to-one byte-string to HMAC-key mapping"),
    (r"biject\w*", "a one-to-one byte-string to HMAC-key mapping"),
    (
        r"every (?:trailing )?byte (?:therefore )?changes",
        "every trailing byte changes the confirmation tag",
    ),
    (
        r"always (?:produces?|yields?|changes|maps)",
        "an unconditional byte-difference-implies-tag-difference guarantee",
    ),
    (
        r"reader (?:canonicali[sz]es|normali[sz]es)",
        "the reader canonicalizes or normalizes the secret",
    ),
)


def test_secret_documentation_states_the_three_required_hmac_concepts():
    """Preserved bytes, no transformation, and HMAC's own key normalization."""

    documentation = _normalized_documentation(secret_module)
    for statement in REQUIRED_SECRET_DOC_STATEMENTS:
        assert statement in documentation, statement


def test_secret_documentation_claims_no_distinct_byte_to_distinct_tag_mapping():
    """The removed false claim may not return in any equivalent wording.

    The four disclaiming statements are excised first, so distinctness wording
    is legal exactly where it is disclaimed and nowhere else.  A restored
    sentence asserting that a trailing byte necessarily changes the confirmation
    tag therefore has nowhere to hide.
    """

    documentation = _normalized_documentation(secret_module)
    scanned = documentation
    for statement in REQUIRED_SECRET_DOC_STATEMENTS:
        scanned = scanned.replace(statement, " ")
    for pattern, claim in FORBIDDEN_SECRET_DOC_CLAIMS:
        found = re.search(pattern, scanned)
        assert found is None, f"documentation claims {claim}: {found.group(0)!r}"


def test_secret_documentation_disclaimer_survives_removal_of_the_false_claim():
    """The excision above cannot be what makes the previous test pass.

    If the disclaiming statements were absent, the excision would remove
    nothing; this pins that they are present *and* that the corrected paragraph
    is shorter than the whole docstring, so the scan really does examine text.
    """

    documentation = _normalized_documentation(secret_module)
    scanned = documentation
    for statement in REQUIRED_SECRET_DOC_STATEMENTS:
        scanned = scanned.replace(statement, " ")
    assert len(scanned) < len(documentation)
    assert "hmac" in documentation
    assert "confirmation tag" not in scanned


BINARY_SECRETS = {
    "all_byte_values": bytes(range(256)) * 2,
    "invalid_utf8": b"\xff\xfe\xfd\xfc" * 8,
    "lone_surrogate_encoding": b"\xed\xa0\x80" * 8,
    "embedded_nuls": b"\x00" * 8 + b"secret" + b"\x00" * 8,
    "high_and_low": bytes([0, 255]) * 16,
}


@pytest.mark.parametrize("name", sorted(BINARY_SECRETS))
def test_arbitrary_binary_secret_is_never_decoded_or_re_encoded(
    secret_root: Path, name: str
):
    """Bytes that are not valid UTF-8 round-trip untouched."""

    raw = BINARY_SECRETS[name]
    assert (
        MIN_HISTORICAL_PAIRING_SECRET_BYTES
        <= len(raw)
        <= MAX_HISTORICAL_PAIRING_SECRET_BYTES
    )
    path = _write(secret_root / f"{name}.bin", raw)
    assert read_historical_pairing_secret_file(path=path) == raw


def test_secret_case_and_encoding_shaped_content_is_not_normalized(
    secret_root: Path,
):
    raw = b"  MiXeD-Case Secret \t YWJjZGVm 616263 \r\n  "
    path = _write(secret_root / "shaped.bin", raw)
    returned = read_historical_pairing_secret_file(path=path)
    assert returned == raw
    assert returned != raw.strip()
    assert returned != raw.lower()
    assert returned != raw.upper()
    assert returned != raw.replace(b"\r\n", b"\n")


def test_returned_secret_is_unaffected_by_later_replacement_or_deletion(
    secret_root: Path,
):
    raw = b"original-secret-material-32-byte"
    path = _write(secret_root / "secret.bin", raw)
    returned = read_historical_pairing_secret_file(path=path)
    assert returned == raw

    _write(path, b"replacement-secret-material-xyz")
    assert returned == raw
    path.unlink()
    assert not path.exists()
    assert returned == raw
    assert type(returned) is bytes


def test_reader_touches_the_filesystem_only_during_the_call(
    secret_root: Path, monkeypatch: pytest.MonkeyPatch
):
    """After return, every filesystem entry point may be poisoned harmlessly."""

    raw = b"k" * 40
    path = _write(secret_root / "secret.bin", raw)
    before_threads = {item.name for item in threading.enumerate()}
    returned = read_historical_pairing_secret_file(path=path)

    def poisoned(*args, **kwargs):
        raise AssertionError("loader touched the filesystem after returning")

    monkeypatch.setattr(secret_module, "open", poisoned, raising=False)
    monkeypatch.setattr(secret_module.os, "lstat", poisoned)
    monkeypatch.setattr(secret_module.os, "fstat", poisoned)
    assert returned == raw
    assert {item.name for item in threading.enumerate()} == before_threads


# --- Bounded error boundary ------------------------------------------------


SECRET_FAILURE_CASES = (
    ("relative", lambda root: Path("relative-secret.bin")),
    ("missing", lambda root: root / "absent.bin"),
    ("directory", lambda root: root),
    ("empty", lambda root: _write(root / "empty.bin", b"")),
    ("short", lambda root: _write(root / "short.bin", b"0123456789abcde")),
    (
        "long",
        lambda root: _write(
            root / "long.bin", b"L" * (MAX_HISTORICAL_PAIRING_SECRET_BYTES + 1)
        ),
    ),
)


@pytest.mark.parametrize("name,builder", SECRET_FAILURE_CASES, ids=[c[0] for c in SECRET_FAILURE_CASES])
def test_secret_failure_leaks_nothing_through_message_repr_cause_or_context(
    secret_root: Path, caplog: pytest.LogCaptureFixture, name: str, builder
):
    marker = b"MARKER-SECRET-DO-NOT-LEAK-0123456789"
    if name in {"empty", "short", "long"}:
        pass
    candidate = builder(secret_root)
    with _no_output(caplog) as quiet:
        with pytest.raises(HistoricalPairingSecretFileError) as failure:
            read_historical_pairing_secret_file(path=candidate)
    _assert_silent(quiet)

    error = failure.value
    assert error.code in HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES
    assert str(error) == error.code
    assert repr(error) == f"<HistoricalPairingSecretFileError code={error.code}>"
    assert error.args == (error.code,)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert not error.__suppress_context__
    assert getattr(error, "__notes__", []) == []
    # Only the fixed code is retained; no length, path, or metadata attribute.
    assert set(vars(error)) == {"_code"}

    rendered = f"{error}|{error!r}|{error.args}|{sorted(vars(error).items())}"
    assert marker.decode() not in rendered
    for leak in (
        os.fspath(candidate),
        candidate.name,
        str(secret_root),
        "0x",
        "WinError",
        "Errno",
    ):
        assert leak not in rendered
    # No observed length is disclosed: the code carries no decimal digit at all.
    assert not any(character.isdigit() for character in rendered.split("|")[0])


def test_secret_error_type_cannot_be_talked_into_carrying_an_unbounded_message():
    """The bounded type structurally refuses any code outside the fixed set."""

    leaked = HistoricalPairingSecretFileError("secret=hunter2 length=37 C:\\keys\\k.bin")
    assert leaked.code == HISTORICAL_PAIRING_SECRET_UNAVAILABLE
    assert str(leaked) == HISTORICAL_PAIRING_SECRET_UNAVAILABLE
    assert "hunter2" not in repr(leaked)
    assert "C:\\keys" not in repr(leaked)
    assert HistoricalPairingSecretFileError().code == HISTORICAL_PAIRING_SECRET_UNAVAILABLE


def test_secret_reader_is_silent_on_the_success_path(
    secret_root: Path, caplog: pytest.LogCaptureFixture
):
    path = _write(secret_root / "secret.bin", b"k" * 32)
    with _no_output(caplog) as quiet:
        assert read_historical_pairing_secret_file(path=path) == b"k" * 32
    _assert_silent(quiet)


def test_secret_reader_requires_keyword_only_path(secret_root: Path):
    path = _write(secret_root / "secret.bin", b"k" * 32)
    with pytest.raises(TypeError):
        read_historical_pairing_secret_file(path)  # type: ignore[misc]


# --- No implicit expansion -------------------------------------------------


def test_literal_tilde_component_is_read_and_never_expanded(secret_root: Path):
    """A path component that merely looks like a home reference is literal."""

    home_shaped = secret_root / "~"
    raw = b"literal-tilde-secret-material-01"
    _write(home_shaped, raw)
    assert read_historical_pairing_secret_file(path=home_shaped) == raw


def test_literal_environment_shaped_component_is_read_and_never_expanded(
    secret_root: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("ADMISSIBLE_SECRET_DIR", str(secret_root / "elsewhere"))
    (secret_root / "elsewhere").mkdir()
    _write(secret_root / "elsewhere" / "s.bin", b"decoy-secret-material-must-not-win")

    literal_dir = secret_root / "%ADMISSIBLE_SECRET_DIR%"
    literal_dir.mkdir()
    raw = b"literal-percent-secret-material-1"
    _write(literal_dir / "s.bin", raw)
    assert read_historical_pairing_secret_file(path=literal_dir / "s.bin") == raw


# ===========================================================================
# O. Enablement configuration loader.
# ===========================================================================


def test_valid_document_loads_into_the_accepted_configuration(
    enablement_root: Path, valid_document_path: Path
):
    configuration = load_historical_pairing_configuration(path=valid_document_path)

    assert type(configuration) is HistoricalPairingConfiguration
    assert configuration.archive_root == enablement_root / "archive"
    assert configuration.preparation_ttl_seconds == 900
    assert configuration.max_preparations == 64
    assert type(configuration.payload_entries) is tuple
    assert [entry.payload_id for entry in configuration.payload_entries] == [
        "first-payload",
        "second-payload",
        "third-payload",
    ]
    assert [entry.document_path for entry in configuration.payload_entries] == [
        enablement_root / "one.json",
        enablement_root / "two.json",
        enablement_root / "three.json",
    ]
    for entry in configuration.payload_entries:
        assert type(entry) is HistoricalPayloadEntry
        assert type(entry.document_path) is type(Path())


def test_declaration_order_is_preserved_exactly(enablement_root: Path):
    """Neither sorted nor reversed: the operator's order is the public order."""

    order = ("zeta-payload", "alpha-payload", "mid-payload", "beta-payload")
    document = _enablement_document(
        archive_root=str(enablement_root / "archive"),
        payloads=tuple(
            (payload_id, str(enablement_root / f"{payload_id}.json"))
            for payload_id in order
        ),
    )
    path = _write(enablement_root / "c.json", _document_bytes(document))
    configuration = load_historical_pairing_configuration(path=path)
    identifiers = tuple(entry.payload_id for entry in configuration.payload_entries)
    assert identifiers == order
    assert identifiers != tuple(sorted(order))
    assert identifiers != tuple(reversed(order))


def test_empty_payload_list_is_accepted_and_stays_empty(enablement_root: Path):
    document = _enablement_document(
        archive_root=str(enablement_root / "archive"), payloads=()
    )
    path = _write(enablement_root / "c.json", _document_bytes(document))
    configuration = load_historical_pairing_configuration(path=path)
    assert configuration.payload_entries == ()


def test_ttl_and_capacity_are_transferred_unchanged(enablement_root: Path):
    document = _enablement_document(
        archive_root=str(enablement_root / "archive"),
        payloads=(("only-payload", str(enablement_root / "one.json")),),
        preparation_ttl_seconds=3601,
        max_preparations=7,
    )
    path = _write(enablement_root / "c.json", _document_bytes(document))
    configuration = load_historical_pairing_configuration(path=path)
    assert configuration.preparation_ttl_seconds == 3601
    assert configuration.max_preparations == 7


# --- Schema and field laws --------------------------------------------------


def test_schema_version_constant_is_exactly_the_accepted_literal():
    """The wire contract is pinned to a literal, not to itself.

    Every other schema test compares a document against the production
    constant, so a silent drift of that constant to any other value -- ``_v2``,
    ``_v3``, or an arbitrary same-shape string -- would leave them all green
    while every already-deployed enablement document became unloadable.  This
    is the only assertion that fails on that drift, and it inspects the real
    production constant rather than a copy.
    """

    assert (
        enablement_module.HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION
        == "admissible_historical_pairing_enablement_v1"
    )
    assert (
        HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION
        == "admissible_historical_pairing_enablement_v1"
    )
    assert type(HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION) is str


def test_document_declaring_the_accepted_literal_loads(enablement_root: Path):
    """The positive path, driven by the literal instead of by the constant."""

    document = _enablement_document(
        archive_root=str(enablement_root / "archive"),
        payloads=(("only-payload", str(enablement_root / "one.json")),),
        schema_version="admissible_historical_pairing_enablement_v1",
    )
    path = _write(enablement_root / "c.json", _document_bytes(document))
    configuration = load_historical_pairing_configuration(path=path)
    assert type(configuration) is HistoricalPairingConfiguration
    assert [entry.payload_id for entry in configuration.payload_entries] == [
        "only-payload"
    ]


@pytest.mark.parametrize(
    "schema_version",
    [
        "admissible_historical_pairing_enablement_v2",
        "admissible_historical_pairing_enablement_v3",
        "admissible_historical_pairing_enablement_v1 ",
        " admissible_historical_pairing_enablement_v1",
        "Admissible_Historical_Pairing_Enablement_V1",
        "admissible_historical_pairing_enablement",
        "",
    ],
)
def test_schema_version_must_match_exactly(enablement_root: Path, schema_version: str):
    document = _enablement_document(
        archive_root=str(enablement_root / "archive"),
        payloads=(("only-payload", str(enablement_root / "one.json")),),
        schema_version=schema_version,
    )
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID


@pytest.mark.parametrize(
    "missing",
    [
        "schema_version",
        "archive_root",
        "payloads",
        "preparation_ttl_seconds",
        "max_preparations",
    ],
)
def test_every_top_level_field_is_required(
    enablement_root: Path, valid_document: dict, missing: str
):
    document = {key: value for key, value in valid_document.items() if key != missing}
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID


@pytest.mark.parametrize(
    "unknown",
    ["secret_path", "confirmation_secret", "archive_root_2", "", "Payloads"],
)
def test_unknown_top_level_key_is_refused(
    enablement_root: Path, valid_document: dict, unknown: str
):
    document = dict(valid_document)
    document[unknown] = "value"
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID


@pytest.mark.parametrize(
    "member",
    [
        {"payload_id": "only-payload"},
        {"document_path": "C:\\absolute\\one.json"},
        {},
        {
            "payload_id": "only-payload",
            "document_path": "C:\\absolute\\one.json",
            "payload_fingerprint": "ab" * 32,
        },
        {"payload_id": "only-payload", "documentPath": "C:\\absolute\\one.json"},
    ],
)
def test_payload_member_key_set_must_be_exact(enablement_root: Path, member: dict):
    document = _enablement_document(
        archive_root=str(enablement_root / "archive"), payloads=()
    )
    document["payloads"] = [member]
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID


WRONG_TYPE_MUTATIONS = {
    "schema_version_int": ("schema_version", 1),
    "archive_root_int": ("archive_root", 7),
    "archive_root_null": ("archive_root", None),
    "archive_root_list": ("archive_root", ["C:\\archive"]),
    "payloads_object": ("payloads", {"first-payload": "C:\\one.json"}),
    "payloads_string": ("payloads", "C:\\one.json"),
    "payloads_null": ("payloads", None),
    "ttl_string": ("preparation_ttl_seconds", "900"),
    "ttl_float": ("preparation_ttl_seconds", 900.0),
    "ttl_bool": ("preparation_ttl_seconds", True),
    "ttl_null": ("preparation_ttl_seconds", None),
    "capacity_string": ("max_preparations", "64"),
    "capacity_float": ("max_preparations", 64.5),
    "capacity_bool": ("max_preparations", False),
}


@pytest.mark.parametrize("name", sorted(WRONG_TYPE_MUTATIONS))
def test_wrong_primitive_json_type_is_refused(
    enablement_root: Path, valid_document: dict, name: str
):
    key, value = WRONG_TYPE_MUTATIONS[name]
    document = dict(valid_document)
    document[key] = value
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID


@pytest.mark.parametrize(
    "member",
    [
        {"payload_id": 7, "document_path": "C:\\absolute\\one.json"},
        {"payload_id": None, "document_path": "C:\\absolute\\one.json"},
        {"payload_id": "only-payload", "document_path": 7},
        {"payload_id": "only-payload", "document_path": None},
        {"payload_id": "only-payload", "document_path": ["C:\\absolute\\one.json"]},
        {"payload_id": ["only-payload"], "document_path": "C:\\absolute\\one.json"},
    ],
)
def test_wrong_payload_member_value_type_is_refused(
    enablement_root: Path, member: dict
):
    document = _enablement_document(
        archive_root=str(enablement_root / "archive"), payloads=()
    )
    document["payloads"] = [member]
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID


@pytest.mark.parametrize(
    "member",
    ["C:\\absolute\\one.json", 7, None, ["only-payload", "C:\\absolute\\one.json"]],
)
def test_non_object_payload_member_is_refused(enablement_root: Path, member):
    document = _enablement_document(
        archive_root=str(enablement_root / "archive"), payloads=()
    )
    document["payloads"] = [member]
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID


# --- JSON transport laws ----------------------------------------------------


DUPLICATE_ROOT_KEY_DOCUMENT = b"""{
  "schema_version": "admissible_historical_pairing_enablement_v1",
  "archive_root": "C:\\\\archive\\\\one",
  "payloads": [],
  "preparation_ttl_seconds": 900,
  "max_preparations": 64,
  "archive_root": "C:\\\\archive\\\\two"
}"""

DUPLICATE_NESTED_KEY_DOCUMENT = b"""{
  "schema_version": "admissible_historical_pairing_enablement_v1",
  "archive_root": "C:\\\\archive",
  "payloads": [
    {
      "payload_id": "only-payload",
      "document_path": "C:\\\\one.json",
      "document_path": "C:\\\\two.json"
    }
  ],
  "preparation_ttl_seconds": 900,
  "max_preparations": 64
}"""

DUPLICATE_DEEP_KEY_DOCUMENT = b"""{
  "schema_version": "admissible_historical_pairing_enablement_v1",
  "archive_root": "C:\\\\archive",
  "payloads": [
    {
      "payload_id": "only-payload",
      "document_path": "C:\\\\one.json",
      "extra": {"inner": 1, "deeper": {"same": 1, "same": 2}}
    }
  ],
  "preparation_ttl_seconds": 900,
  "max_preparations": 64
}"""


@pytest.mark.parametrize(
    "raw",
    [
        DUPLICATE_ROOT_KEY_DOCUMENT,
        DUPLICATE_NESTED_KEY_DOCUMENT,
        DUPLICATE_DEEP_KEY_DOCUMENT,
    ],
    ids=["root", "payload_member", "deeply_nested"],
)
def test_duplicate_json_key_at_every_depth_is_refused(enablement_root: Path, raw: bytes):
    """A last-wins or first-wins duplicate is never silently resolved."""

    # The fixtures are genuine duplicates as far as a permissive parser is
    # concerned: an unguarded json.loads accepts every one of them.
    assert json.loads(raw.decode("utf-8"))
    path = _write(enablement_root / "c.json", raw)
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_MALFORMED


MALFORMED_DOCUMENTS = {
    "bom": b"\xef\xbb\xbf{\"schema_version\": \"x\"}",
    "invalid_utf8": b"{\"schema_version\": \"\xff\xfe\"}",
    "utf16_bom": b"\xff\xfe{\x00",
    "empty": b"",
    "whitespace_only": b"   \n\t ",
    "truncated": b"{\"schema_version\": ",
    "root_array": b"[]",
    "root_string": b"\"admissible\"",
    "root_number": b"7",
    "root_null": b"null",
    "root_true": b"true",
    "two_values": b"{\"a\": 1}{\"b\": 2}",
    "trailing_bytes": b"{\"a\": 1} trailing",
    "trailing_comma": b"{\"a\": 1,}",
    "single_quotes": b"{'a': 1}",
    "nan_constant": b"{\"a\": NaN}",
    "infinity_constant": b"{\"a\": Infinity}",
    "negative_infinity_constant": b"{\"a\": -Infinity}",
}


@pytest.mark.parametrize("name", sorted(MALFORMED_DOCUMENTS))
def test_malformed_transport_document_is_refused(enablement_root: Path, name: str):
    path = _write(enablement_root / "c.json", MALFORMED_DOCUMENTS[name])
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_MALFORMED


def test_bom_prefixed_otherwise_valid_document_is_refused(
    enablement_root: Path, valid_document: dict
):
    raw = b"\xef\xbb\xbf" + _document_bytes(valid_document)
    path = _write(enablement_root / "c.json", raw)
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_MALFORMED
    # The same document without the mark loads, so the mark alone is the reason.
    assert load_historical_pairing_configuration(
        path=_write(enablement_root / "clean.json", raw[3:])
    ).payload_entries


def test_surrounding_whitespace_is_accepted(
    enablement_root: Path, valid_document: dict
):
    raw = b"\n\t  " + _document_bytes(valid_document) + b"  \r\n\t"
    path = _write(enablement_root / "c.json", raw)
    assert load_historical_pairing_configuration(path=path).max_preparations == 64


# --- Bound laws -------------------------------------------------------------


def _padded_document(document: dict, total: int) -> bytes:
    body = json.dumps(document, separators=(",", ":")).encode("utf-8")
    assert len(body) < total
    return body + b" " * (total - len(body))


def test_document_of_exactly_the_bound_is_accepted(
    enablement_root: Path, valid_document: dict
):
    raw = _padded_document(valid_document, MAX_HISTORICAL_PAIRING_ENABLEMENT_BYTES)
    assert len(raw) == 65536 == MAX_HISTORICAL_PAIRING_ENABLEMENT_BYTES
    path = _write(enablement_root / "c.json", raw)
    configuration = load_historical_pairing_configuration(path=path)
    assert len(configuration.payload_entries) == 3


def test_document_one_byte_over_the_bound_is_refused(
    enablement_root: Path, valid_document: dict
):
    raw = _padded_document(valid_document, MAX_HISTORICAL_PAIRING_ENABLEMENT_BYTES + 1)
    path = _write(enablement_root / "c.json", raw)
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_TOO_LARGE


def test_document_read_requests_exactly_the_bound_plus_one_byte_once(
    enablement_root: Path, valid_document_path: Path, monkeypatch: pytest.MonkeyPatch
):
    with _filesystem_observation(enablement_module, monkeypatch) as observation:
        load_historical_pairing_configuration(path=valid_document_path)
    assert observation.opened == [valid_document_path]
    assert observation.read_sizes == [MAX_HISTORICAL_PAIRING_ENABLEMENT_BYTES + 1]
    assert -1 not in observation.read_sizes
    assert observation.forbidden == []


def test_enormous_document_is_never_pulled_into_memory(
    enablement_root: Path, valid_document: dict, monkeypatch: pytest.MonkeyPatch
):
    raw = _padded_document(valid_document, 4 * 1024 * 1024)
    path = _write(enablement_root / "c.json", raw)
    with _filesystem_observation(enablement_module, monkeypatch) as observation:
        with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
            load_historical_pairing_configuration(path=path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_TOO_LARGE
    assert observation.read_sizes == [MAX_HISTORICAL_PAIRING_ENABLEMENT_BYTES + 1]


# --- Configuration path law -------------------------------------------------


def test_relative_configuration_path_is_refused_and_never_resolved(
    enablement_root: Path, valid_document_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.chdir(enablement_root)
    assert Path("enablement.json").exists()
    with _filesystem_observation(enablement_module, monkeypatch) as observation:
        with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
            load_historical_pairing_configuration(path=Path("enablement.json"))
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_PATH_INVALID
    assert observation.opened == []


@pytest.mark.parametrize(
    "builder",
    [
        lambda root: Path(str(root) + os.sep + ".." + os.sep + root.name + os.sep + "enablement.json"),
        lambda root: Path(str(root / "sub" / ".." / "enablement.json")),
    ],
)
def test_noncanonical_configuration_path_is_refused(
    valid_document_path: Path, enablement_root: Path, builder
):
    candidate = builder(enablement_root)
    assert candidate.is_absolute()
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=candidate)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_PATH_INVALID


@pytest.mark.parametrize(
    "value", [None, "C:\\absolute\\enablement.json", b"bytes", 5, Path("")]
)
def test_non_path_configuration_value_is_refused(value):
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=value)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_PATH_INVALID


def test_configuration_path_with_nul_is_refused_before_any_syscall(
    enablement_root: Path, monkeypatch: pytest.MonkeyPatch
):
    candidate = Path(str(enablement_root) + os.sep + "c\x00.json")
    with _filesystem_observation(enablement_module, monkeypatch) as observation:
        with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
            load_historical_pairing_configuration(path=candidate)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_PATH_INVALID
    assert observation.opened == []


def test_missing_configuration_document_is_refused(enablement_root: Path):
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=enablement_root / "absent.json")
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_UNAVAILABLE


def test_configuration_directory_is_refused(enablement_root: Path):
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=enablement_root)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_UNAVAILABLE


def test_configuration_symbolic_link_reported_by_lstat_is_refused(
    valid_document_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(
        enablement_module.os,
        "lstat",
        lambda _p: _redirecting_metadata(mode=stat.S_IFLNK | 0o600, reparse=False),
    )
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=valid_document_path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_UNAVAILABLE


def test_configuration_reparse_point_reported_by_lstat_is_refused(
    valid_document_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(
        enablement_module.os,
        "lstat",
        lambda _p: _redirecting_metadata(mode=stat.S_IFREG | 0o600, reparse=True),
    )
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=valid_document_path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_UNAVAILABLE


def test_configuration_opened_descriptor_must_itself_be_a_regular_file(
    valid_document_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(
        enablement_module.os,
        "fstat",
        lambda _fd: _redirecting_metadata(mode=stat.S_IFIFO | 0o600, reparse=False),
    )
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=valid_document_path)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_UNAVAILABLE


def test_real_direct_symlink_to_a_valid_configuration_is_refused(
    enablement_root: Path, valid_document_path: Path
):
    link = enablement_root / "link.json"
    try:
        os.symlink(valid_document_path, link)
    except (OSError, NotImplementedError, AttributeError) as exc:
        pytest.skip(f"platform refuses symbolic link creation: {type(exc).__name__}")
    with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
        load_historical_pairing_configuration(path=link)
    assert failure.value.code == HISTORICAL_PAIRING_CONFIG_UNAVAILABLE
    assert load_historical_pairing_configuration(path=valid_document_path)


# --- Explicit paths inside the document -------------------------------------


def test_absolute_paths_inside_the_document_are_transferred_unchanged(
    tmp_path: Path, enablement_root: Path
):
    archive = tmp_path / "elsewhere" / "archive"
    document_path = tmp_path / "far" / "away" / "payload.json"
    document = _enablement_document(
        archive_root=str(archive),
        payloads=(("only-payload", str(document_path)),),
    )
    path = _write(enablement_root / "c.json", _document_bytes(document))
    configuration = load_historical_pairing_configuration(path=path)
    assert configuration.archive_root == archive
    assert configuration.payload_entries[0].document_path == document_path
    assert os.fspath(configuration.archive_root) == str(archive)


@pytest.mark.parametrize(
    "relative", ["archive", "./archive", "..\\archive", "~/archive", ""]
)
def test_relative_archive_root_is_refused_by_the_accepted_type(
    enablement_root: Path, relative: str
):
    """The accepted configuration type is the single authority for path law."""

    document = _enablement_document(archive_root=relative, payloads=())
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(InvalidHistoricalPairingConfiguration) as failure:
        load_historical_pairing_configuration(path=path)
    assert "canonical absolute path" in str(failure.value)


@pytest.mark.parametrize(
    "relative", ["one.json", "./one.json", "..\\one.json", "~/one.json", ""]
)
def test_relative_payload_document_path_is_refused_by_the_accepted_type(
    enablement_root: Path, relative: str
):
    document = _enablement_document(
        archive_root=str(enablement_root / "archive"),
        payloads=(("only-payload", relative),),
    )
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(InvalidHistoricalPairingConfiguration) as failure:
        load_historical_pairing_configuration(path=path)
    assert "canonical absolute path" in str(failure.value)


def test_relative_json_paths_are_never_resolved_against_cwd_or_config_parent(
    enablement_root: Path, monkeypatch: pytest.MonkeyPatch
):
    """The refusal must survive both plausible implicit bases actually existing."""

    (enablement_root / "archive").mkdir()
    _write(enablement_root / "one.json", b"{}")
    monkeypatch.chdir(enablement_root)
    document = _enablement_document(
        archive_root="archive", payloads=(("only-payload", "one.json"),)
    )
    path = _write(enablement_root / "c.json", _document_bytes(document))
    # Both a cwd-relative and a config-parent-relative resolution would succeed
    # here, so acceptance would prove an implicit base was applied.
    assert (Path.cwd() / "archive").is_dir()
    with pytest.raises(InvalidHistoricalPairingConfiguration):
        load_historical_pairing_configuration(path=path)


def test_noncanonical_json_paths_are_refused_by_the_accepted_type(
    enablement_root: Path,
):
    noncanonical = str(enablement_root) + os.sep + ".." + os.sep + "archive"
    document = _enablement_document(archive_root=noncanonical, payloads=())
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(InvalidHistoricalPairingConfiguration):
        load_historical_pairing_configuration(path=path)


def test_payload_identifier_grammar_stays_with_the_accepted_type(
    enablement_root: Path,
):
    document = _enablement_document(
        archive_root=str(enablement_root / "archive"),
        payloads=(("Not A Valid Id", str(enablement_root / "one.json")),),
    )
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(InvalidHistoricalPairingConfiguration) as failure:
        load_historical_pairing_configuration(path=path)
    assert "lowercase ASCII letters" in str(failure.value)


def test_duplicate_payload_identifier_stays_with_the_accepted_type(
    enablement_root: Path,
):
    document = _enablement_document(
        archive_root=str(enablement_root / "archive"),
        payloads=(
            ("same-payload", str(enablement_root / "one.json")),
            ("same-payload", str(enablement_root / "two.json")),
        ),
    )
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(InvalidHistoricalPairingConfiguration) as failure:
        load_historical_pairing_configuration(path=path)
    assert "unique" in str(failure.value)


def test_out_of_bounds_ttl_stays_with_the_accepted_type(enablement_root: Path):
    document = _enablement_document(
        archive_root=str(enablement_root / "archive"),
        payloads=(),
        preparation_ttl_seconds=0,
    )
    path = _write(enablement_root / "c.json", _document_bytes(document))
    with pytest.raises(InvalidHistoricalPairingConfiguration):
        load_historical_pairing_configuration(path=path)


# --- Side-effect freedom ----------------------------------------------------


def test_loader_opens_only_the_configuration_document_and_creates_nothing(
    enablement_root: Path, valid_document: dict, monkeypatch: pytest.MonkeyPatch
):
    """No configured V4 document is opened and no archive directory appears."""

    payload_document = _write(enablement_root / "one.json", b"{}")
    archive_root = enablement_root / "archive"
    path = _write(enablement_root / "c.json", _document_bytes(valid_document))
    before_threads = {item.name for item in threading.enumerate()}

    with _filesystem_observation(enablement_module, monkeypatch) as observation:
        configuration = load_historical_pairing_configuration(path=path)

    assert observation.opened == [path]
    assert payload_document not in observation.opened
    assert observation.forbidden == []
    assert not archive_root.exists()
    assert configuration.archive_root == archive_root
    assert {item.name for item in threading.enumerate()} == before_threads
    # Every configured payload document is still absent except the decoy that
    # was written before the call, whose bytes were never read.
    assert payload_document.read_bytes() == b"{}"
    assert not (enablement_root / "two.json").exists()
    assert not (enablement_root / "three.json").exists()


def test_no_configured_v4_document_receives_open_stat_or_existence_access(
    enablement_root: Path, monkeypatch: pytest.MonkeyPatch
):
    """Real decoys on disk, and not one metadata call reaches any of them.

    Every configured V4 document exists here, so an accidental ``stat`` would
    succeed instead of failing loudly: the only thing that can catch it is
    recording the exact path of every entry point and comparing it against the
    configured set.  The enablement document itself is allowed to be opened and
    metadata-checked; the archive root and the three payload documents are not.
    """

    decoys = tuple(
        _write(enablement_root / name, b'{"decoy": true}')
        for name in ("one.json", "two.json", "three.json")
    )
    archive_root = enablement_root / "archive"
    document = _enablement_document(
        archive_root=str(archive_root),
        payloads=(
            ("first-payload", str(decoys[0])),
            ("second-payload", str(decoys[1])),
            ("third-payload", str(decoys[2])),
        ),
    )
    path = _write(enablement_root / "c.json", _document_bytes(document))
    forbidden = {os.fspath(decoy) for decoy in decoys} | {os.fspath(archive_root)}

    with _path_access_observation(monkeypatch) as access:
        configuration = load_historical_pairing_configuration(path=path)

    # 1. Not one of the twelve observed entry points ever saw a forbidden path.
    for operation in OBSERVED_METADATA_OPERATIONS:
        for observed in access.paths_for(operation):
            assert observed not in forbidden, (operation, observed)

    # 2. Exact path law: the enablement document is the only path touched at
    #    all, so no directory-derived or parent-derived access reached them
    #    either.
    assert access.paths_for("builtins.open") == [os.fspath(path)]
    assert set(access.paths) == {os.fspath(path)}
    assert access.paths_for("os.scandir") == []
    assert access.paths_for("os.listdir") == []

    # 3. The archive root was not created, and the decoy bytes were not read.
    assert not archive_root.exists()
    assert configuration.archive_root == archive_root
    for decoy in decoys:
        assert decoy.read_bytes() == b'{"decoy": true}'
    assert [entry.document_path for entry in configuration.payload_entries] == list(
        decoys
    )


def test_accepted_configuration_validation_is_filesystem_free(
    enablement_root: Path, monkeypatch: pytest.MonkeyPatch
):
    """``validated()`` decides every configuration law without touching disk."""

    decoys = tuple(
        _write(enablement_root / name, b"{}") for name in ("a.json", "b.json")
    )
    configuration = HistoricalPairingConfiguration(
        archive_root=enablement_root / "archive",
        payload_entries=tuple(
            HistoricalPayloadEntry(payload_id=payload_id, document_path=decoy)
            for payload_id, decoy in zip(("first-payload", "second-payload"), decoys)
        ),
        preparation_ttl_seconds=900,
        max_preparations=64,
    )

    with _path_access_observation(monkeypatch) as access:
        assert configuration.validated() is configuration

    assert access.events == []
    assert not (enablement_root / "archive").exists()


def test_returned_configuration_retains_no_bytes_mapping_or_source_path(
    enablement_root: Path, valid_document_path: Path
):
    configuration = load_historical_pairing_configuration(path=valid_document_path)

    assert set(vars(configuration)) == {
        "archive_root",
        "payload_entries",
        "preparation_ttl_seconds",
        "max_preparations",
    }
    reachable = list(vars(configuration).values())
    for entry in configuration.payload_entries:
        assert set(vars(entry)) == {"payload_id", "document_path"}
        reachable.extend(vars(entry).values())
    for value in reachable:
        assert not isinstance(value, (bytes, bytearray, memoryview, dict))
    # The enablement document's own path is retained nowhere.
    assert valid_document_path not in reachable
    assert valid_document_path not in [
        entry.document_path for entry in configuration.payload_entries
    ]
    assert configuration.archive_root != valid_document_path


def test_returned_configuration_is_frozen_and_immune_to_source_mutation(
    enablement_root: Path, valid_document: dict
):
    path = _write(enablement_root / "c.json", _document_bytes(valid_document))
    configuration = load_historical_pairing_configuration(path=path)
    expected_ids = tuple(entry.payload_id for entry in configuration.payload_entries)

    # Mutate the parsed source in every way available to a caller.
    valid_document["payloads"].append(
        {"payload_id": "late-payload", "document_path": str(enablement_root / "x.json")}
    )
    valid_document["max_preparations"] = 1
    _write(path, _document_bytes(valid_document))
    path.unlink()

    assert tuple(entry.payload_id for entry in configuration.payload_entries) == expected_ids
    assert configuration.max_preparations == 64
    with pytest.raises(FrozenInstanceError):
        configuration.max_preparations = 1  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        configuration.payload_entries[0].payload_id = "other"  # type: ignore[misc]


def test_loader_touches_the_filesystem_only_during_the_call(
    valid_document_path: Path, monkeypatch: pytest.MonkeyPatch
):
    configuration = load_historical_pairing_configuration(path=valid_document_path)

    def poisoned(*args, **kwargs):
        raise AssertionError("loader touched the filesystem after returning")

    monkeypatch.setattr(enablement_module, "open", poisoned, raising=False)
    monkeypatch.setattr(enablement_module.os, "lstat", poisoned)
    monkeypatch.setattr(enablement_module.os, "fstat", poisoned)
    assert len(configuration.payload_entries) == 3
    assert configuration.validated() is configuration


def test_configuration_repr_discloses_no_path_identifier_or_content(
    enablement_root: Path, valid_document_path: Path
):
    configuration = load_historical_pairing_configuration(path=valid_document_path)
    rendered = repr(configuration)
    # The accepted configuration keeps its own accepted repr; this slice only
    # requires that no secret was added to it.
    assert "secret" not in rendered.lower()
    assert "0x" not in rendered


# --- Bounded error boundary -------------------------------------------------


CONFIG_FAILURE_CASES = (
    ("relative", lambda root: Path("relative.json"), None),
    ("missing", lambda root: root / "absent.json", None),
    ("directory", lambda root: root, None),
    ("malformed", lambda root: root / "bad.json", b"{"),
    ("bom", lambda root: root / "bom.json", b"\xef\xbb\xbf{}"),
    ("fields", lambda root: root / "fields.json", b"{}"),
    (
        "too_large",
        lambda root: root / "big.json",
        b"{" + b" " * (MAX_HISTORICAL_PAIRING_ENABLEMENT_BYTES + 8) + b"}",
    ),
)


@pytest.mark.parametrize(
    "name,builder,payload",
    CONFIG_FAILURE_CASES,
    ids=[case[0] for case in CONFIG_FAILURE_CASES],
)
def test_configuration_failure_leaks_nothing_and_is_silent(
    enablement_root: Path,
    caplog: pytest.LogCaptureFixture,
    name: str,
    builder,
    payload,
):
    candidate = builder(enablement_root)
    if payload is not None:
        _write(candidate, payload)
    with _no_output(caplog) as quiet:
        with pytest.raises(HistoricalPairingEnablementDocumentError) as failure:
            load_historical_pairing_configuration(path=candidate)
    _assert_silent(quiet)

    error = failure.value
    assert error.code in HISTORICAL_PAIRING_ENABLEMENT_ERROR_CODES
    assert str(error) == error.code
    assert repr(error) == f"<HistoricalPairingEnablementDocumentError code={error.code}>"
    assert error.args == (error.code,)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert not error.__suppress_context__
    assert getattr(error, "__notes__", []) == []
    assert set(vars(error)) == {"_code"}

    rendered = f"{error}|{error!r}|{error.args}|{sorted(vars(error).items())}"
    for leak in (
        os.fspath(candidate),
        candidate.name,
        str(enablement_root),
        "0x",
        "WinError",
        "Errno",
        "Expecting",
    ):
        assert leak not in rendered


def test_configuration_error_type_cannot_carry_an_unbounded_message():
    leaked = HistoricalPairingEnablementDocumentError(
        "archive_root=C:\\archive payload=abc raw={...}"
    )
    assert leaked.code == HISTORICAL_PAIRING_CONFIG_UNAVAILABLE
    assert "C:\\archive" not in repr(leaked)
    assert HistoricalPairingEnablementDocumentError().code == (
        HISTORICAL_PAIRING_CONFIG_UNAVAILABLE
    )


def test_loader_is_silent_on_the_success_path(
    valid_document_path: Path, caplog: pytest.LogCaptureFixture
):
    with _no_output(caplog) as quiet:
        load_historical_pairing_configuration(path=valid_document_path)
    _assert_silent(quiet)


def test_loader_requires_keyword_only_path(valid_document_path: Path):
    with pytest.raises(TypeError):
        load_historical_pairing_configuration(valid_document_path)  # type: ignore[misc]


def test_loader_never_returns_an_object_carrying_secret_bytes(
    valid_document_path: Path,
):
    """The loader has no secret parameter and no secret-bearing return type."""

    import inspect

    signature = inspect.signature(load_historical_pairing_configuration)
    assert list(signature.parameters) == ["path"]
    assert type(load_historical_pairing_configuration(path=valid_document_path)) is (
        HistoricalPairingConfiguration
    )


# ===========================================================================
# Import boundary and source laws.
# ===========================================================================


def _module_tree(module) -> ast.Module:
    return ast.parse(
        Path(module.__file__).read_text(encoding="utf-8"), filename=module.__file__
    )


def _imported_names(module) -> set[str]:
    imported: set[str] = set()
    for node in ast.walk(_module_tree(module)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    return imported


def test_secret_module_import_graph_is_exactly_the_neutral_leaf_set():
    assert _imported_names(secret_module) == {"__future__", "os", "pathlib", "stat"}


def test_enablement_module_import_graph_is_exactly_the_declared_set():
    assert _imported_names(enablement_module) == {
        "__future__",
        "json",
        "os",
        "pathlib",
        "stat",
        "typing",
        "admissible.product_launcher.historical_pairing_registry",
    }


FORBIDDEN_SECRET_IMPORT_FRAGMENTS = (
    "admissible.product_launcher",
    "admissible.product_service",
    "admissible.product_ui",
    "admissible.product_read_model",
    "admissible.delegated_gate",
    "admissible.review_surface",
    "admissible.browser_runtime",
    "admissible.execution",
    "admissible.evaluator",
    "historical_evaluation",
    "historical_pairing_confirmation",
    "historical_pairing_workflow",
    "native_canary",
    "native_executor",
    "checkpoint",
    "store",
    "archive",
    "subprocess",
    "socket",
    "threading",
    "logging",
    "warnings",
    "http",
    "json",
    "base64",
    "hmac",
    "hashlib",
)


@pytest.mark.parametrize("fragment", FORBIDDEN_SECRET_IMPORT_FRAGMENTS)
def test_secret_module_names_no_forbidden_dependency(fragment: str):
    source = Path(secret_module.__file__).read_text(encoding="utf-8")
    import_lines = "\n".join(
        line
        for line in source.splitlines()
        if line.startswith("import ") or line.startswith("from ")
    )
    assert fragment not in import_lines


FORBIDDEN_ENABLEMENT_IMPORT_FRAGMENTS = (
    "admissible.product_service",
    "admissible.product_ui",
    "admissible.product_read_model",
    "admissible.delegated_gate",
    "admissible.review_surface",
    "admissible.browser_runtime",
    "admissible.historical_pairing_secret_file",
    "product_launcher.launcher",
    "product_launcher.historical_pairing_service",
    "subprocess",
    "socket",
    "threading",
    "logging",
    "warnings",
    "http",
)


@pytest.mark.parametrize("fragment", FORBIDDEN_ENABLEMENT_IMPORT_FRAGMENTS)
def test_enablement_module_names_no_forbidden_dependency(fragment: str):
    source = Path(enablement_module.__file__).read_text(encoding="utf-8")
    import_lines = "\n".join(
        line
        for line in source.splitlines()
        if line.startswith("import ") or line.startswith("from ")
    )
    assert fragment not in import_lines


def test_secret_module_is_importable_without_any_admissible_package_module():
    """The neutral leaf imports nothing from its own product at runtime.

    Everything the module pulled in is either the standard library or the bare
    ``admissible`` package itself, which a plain module import cannot avoid.
    """

    tree = _module_tree(secret_module)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
            )
            for name in names:
                assert not name.startswith("admissible")


FORBIDDEN_TRAVERSAL_ATTRIBUTES = frozenset(
    {
        "glob",
        "rglob",
        "iterdir",
        "walk",
        "listdir",
        "scandir",
        "parent",
        "parents",
        "resolve",
        "readlink",
        "joinpath",
        "expanduser",
        "expandvars",
        "mkdir",
        "makedirs",
        "samefile",
        "cwd",
        "home",
        "getcwd",
        "chdir",
    }
)


@pytest.mark.parametrize("module", [secret_module, enablement_module])
def test_modules_contain_no_traversal_expansion_or_creation_construct(module):
    tree = _module_tree(module)
    referenced = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert not (referenced & FORBIDDEN_TRAVERSAL_ATTRIBUTES), sorted(
        referenced & FORBIDDEN_TRAVERSAL_ATTRIBUTES
    )
    # No path arithmetic operator is applied to a configured path either.
    assert not [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
    ]


FORBIDDEN_SECRET_TRANSFORM_ATTRIBUTES = frozenset(
    {
        "decode",
        "encode",
        "strip",
        "rstrip",
        "lstrip",
        "split",
        "rsplit",
        "splitlines",
        "lower",
        "upper",
        "casefold",
        "replace",
        "translate",
        "removeprefix",
        "removesuffix",
        "hex",
        "b64decode",
        "b64encode",
        "unhexlify",
        "normalize",
    }
)


def test_secret_module_applies_no_transformation_to_the_bytes_it_read():
    tree = _module_tree(secret_module)
    referenced = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert not (referenced & FORBIDDEN_SECRET_TRANSFORM_ATTRIBUTES), sorted(
        referenced & FORBIDDEN_SECRET_TRANSFORM_ATTRIBUTES
    )
    # And no slicing anywhere, which would be a silent truncation.  A plain
    # index subscript is what a type annotation such as ``tuple[str, bytes]``
    # is made of, so only a genuine slice expression is forbidden.
    assert not [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice)
    ]


@pytest.mark.parametrize("module", [secret_module, enablement_module])
def test_modules_emit_nothing_to_stdout_stderr_logging_or_warnings(module):
    tree = _module_tree(module)
    called = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "print" not in called
    source = Path(module.__file__).read_text(encoding="utf-8")
    for forbidden in ("sys.stdout", "sys.stderr", "logging.", "warnings.", "print("):
        assert forbidden not in source


def test_module_public_surfaces_are_exactly_the_declared_api():
    assert secret_module.__all__ == [
        "HISTORICAL_PAIRING_SECRET_FILE_ERROR_CODES",
        "HISTORICAL_PAIRING_SECRET_LENGTH_INVALID",
        "HISTORICAL_PAIRING_SECRET_PATH_INVALID",
        "HISTORICAL_PAIRING_SECRET_UNAVAILABLE",
        "MAX_HISTORICAL_PAIRING_SECRET_BYTES",
        "MIN_HISTORICAL_PAIRING_SECRET_BYTES",
        "HistoricalPairingSecretFileError",
        "read_historical_pairing_secret_file",
    ]
    assert enablement_module.__all__ == [
        "HISTORICAL_PAIRING_CONFIG_FIELDS_INVALID",
        "HISTORICAL_PAIRING_CONFIG_MALFORMED",
        "HISTORICAL_PAIRING_CONFIG_PATH_INVALID",
        "HISTORICAL_PAIRING_CONFIG_TOO_LARGE",
        "HISTORICAL_PAIRING_CONFIG_UNAVAILABLE",
        "HISTORICAL_PAIRING_ENABLEMENT_ERROR_CODES",
        "HISTORICAL_PAIRING_ENABLEMENT_FIELDS",
        "HISTORICAL_PAIRING_ENABLEMENT_PAYLOAD_FIELDS",
        "HISTORICAL_PAIRING_ENABLEMENT_SCHEMA_VERSION",
        "MAX_HISTORICAL_PAIRING_ENABLEMENT_BYTES",
        "HistoricalPairingEnablementDocumentError",
        "load_historical_pairing_configuration",
    ]


def test_neither_module_defines_a_secret_bearing_dataclass():
    for module in (secret_module, enablement_module):
        tree = _module_tree(module)
        classes = [
            node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)
        ]
        for node in classes:
            # Only bounded error types are defined here; no dataclass at all.
            assert not node.decorator_list, node.name
            assert node.name.endswith("Error"), node.name


# --- The three copies of the explicit-path law must agree exactly -----------


PATH_LAW_CORPUS = (
    Path(os.path.abspath(os.sep + "abs" + os.sep + "canonical.bin")),
    Path("relative.bin"),
    Path("."),
    Path(""),
    Path(os.sep + "rooted-no-drive.bin"),
    Path(os.path.abspath(os.sep + "abs") + os.sep + ".." + os.sep + "x.bin"),
    Path(os.path.abspath(os.sep + "abs") + os.sep + "sub" + os.sep + ".." + os.sep + "x.bin"),
    Path(os.path.abspath(os.sep + "abs") + os.sep + "nul\x00.bin"),
    Path(os.path.abspath(os.sep + "abs") + os.sep + "~"),
    Path(os.path.abspath(os.sep + "abs") + os.sep + "%TEMP%"),
    "not-a-path-object",
    None,
    7,
)


@pytest.mark.parametrize("candidate", PATH_LAW_CORPUS, ids=range(len(PATH_LAW_CORPUS)))
def test_every_explicit_path_law_copy_agrees_with_the_accepted_registry(candidate):
    """The neutral leaf, the loader and the accepted registry share one law.

    The neutral leaf cannot import the accepted registry without ceasing to be a
    neutral leaf, so the law is restated in each module; this test is what keeps
    the restatements from drifting.
    """

    try:
        registry_module._validated_absolute_path(candidate, label="probe")
        accepted = True
    except InvalidHistoricalPairingConfiguration:
        accepted = False

    assert secret_module._is_explicit_absolute_path(candidate) is accepted
    assert enablement_module._is_explicit_absolute_path(candidate) is accepted
