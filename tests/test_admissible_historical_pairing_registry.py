"""Step 5C2C1: server-configurable standalone historical V4 payload registry.

Every expectation about document bytes in this module is computed by an
independent canonical-JSON oracle that re-implements the documented rule with
the standard library.  The registry under test is never asked to produce an
expectation it is then compared against.
"""

from __future__ import annotations

import ast
import builtins
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, fields
import hashlib
import json
import os
from pathlib import Path
import re

import pytest

from admissible.delegated_gate.mission_profile import NativeMissionProfile
from admissible.delegated_gate.native_canary import (
    EVIDENCE_DIRECTORY_NAME,
    NATIVE_SIDECAR_DIRECTORY_NAME,
    WORKSPACE_DIRECTORY_NAME,
    NativeCanaryAuthorizationPayloadV4,
    load_historical_native_canary_authorization_payload_v4,
)
from admissible.product_launcher import historical_pairing_registry as registry_module
from admissible.product_launcher.historical_pairing_registry import (
    MAX_CONFIGURED_HISTORICAL_PAYLOADS,
    MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES,
    MAX_PAYLOAD_ID_LENGTH,
    MIN_PAYLOAD_ID_LENGTH,
    HistoricalPairingConfiguration,
    HistoricalPayloadEntry,
    HistoricalPayloadMetadata,
    HistoricalPayloadNotFound,
    HistoricalPayloadRegistry,
    HistoricalPayloadRegistryError,
    InvalidHistoricalPairingConfiguration,
    MalformedHistoricalPayloadDocument,
)
from test_admissible_historical_evaluation_pairing import (
    _payload_for_runtime_profile,
    _refingerprint_payload,
    _refingerprint_profile,
)
from test_admissible_historical_v5_derivation import _runtime_v2_profile
from test_admissible_workflow_recovery_profile import _payload_harness


# ---------------------------------------------------------------------------
# Independent canonical-JSON oracle.
# ---------------------------------------------------------------------------


def _oracle_canonical_bytes(mapping: dict) -> bytes:
    """Re-implement the documented canonical rule with the standard library."""

    return json.dumps(
        mapping, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Fixture material: two distinct standalone historical V4 documents whose every
# carried filesystem path is absent on disk.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def historical_payload(
    tmp_path_factory: pytest.TempPathFactory,
) -> NativeCanaryAuthorizationPayloadV4:
    fixture_root = tmp_path_factory.mktemp("s5c2c1-reg")
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


@pytest.fixture(scope="module")
def other_payload(
    historical_payload: NativeCanaryAuthorizationPayloadV4,
) -> NativeCanaryAuthorizationPayloadV4:
    """A second, genuinely distinct payload for duplicate-fingerprint proofs."""

    profile = historical_payload.mission_profile.to_dict()
    profile["mission_text"] = profile["mission_text"] + "\nSecond mission."
    variant = NativeMissionProfile.from_dict(_refingerprint_profile(profile))
    payload = _payload_for_runtime_profile(historical_payload, variant)
    assert payload.payload_fingerprint != historical_payload.payload_fingerprint
    return payload


def _document_bytes(payload: NativeCanaryAuthorizationPayloadV4) -> bytes:
    return _oracle_canonical_bytes(payload.to_dict())


@pytest.fixture()
def document_root(tmp_path: Path) -> Path:
    root = tmp_path / "configured-documents"
    root.mkdir()
    return root


def _write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def _entry(payload_id: str, path: Path) -> HistoricalPayloadEntry:
    return HistoricalPayloadEntry(payload_id=payload_id, document_path=path)


def _configuration(
    tmp_path: Path,
    entries: tuple[HistoricalPayloadEntry, ...],
    **overrides,
) -> HistoricalPairingConfiguration:
    values = dict(
        archive_root=tmp_path / "archive",
        payload_entries=entries,
    )
    values.update(overrides)
    return HistoricalPairingConfiguration(**values)


def _registry(
    tmp_path: Path,
    entries: tuple[HistoricalPayloadEntry, ...],
    **overrides,
) -> HistoricalPayloadRegistry:
    return HistoricalPayloadRegistry(
        configuration=_configuration(tmp_path, entries, **overrides)
    )


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
        self.listings: list[str] = []


@contextmanager
def _filesystem_observation(monkeypatch: pytest.MonkeyPatch):
    """Record every open the registry performs and forbid every directory walk."""

    observation = _Observation()
    real_open = builtins.open

    def spy_open(path, mode="r", *args, **kwargs):
        observation.opened.append(Path(os.fspath(path)))
        return _RecordingHandle(
            real_open(path, mode, *args, **kwargs), observation.read_sizes
        )

    def forbidden(name):
        def _raise(*args, **kwargs):
            observation.listings.append(name)
            raise AssertionError(f"registry performed a forbidden {name} call")

        return _raise

    monkeypatch.setattr(registry_module, "open", spy_open, raising=False)
    for target, name in (
        (os, "listdir"),
        (os, "scandir"),
        (os, "walk"),
    ):
        monkeypatch.setattr(target, name, forbidden(f"os.{name}"))
    for name in ("glob", "rglob", "iterdir"):
        monkeypatch.setattr(Path, name, forbidden(f"Path.{name}"))
    yield observation


# ---------------------------------------------------------------------------
# C. payload_id grammar.
# ---------------------------------------------------------------------------


VALID_PAYLOAD_IDS = (
    "abc",
    "a1b",
    "0ab",
    "999",
    "payload-001",
    "a-b-c-d",
    "z" * MAX_PAYLOAD_ID_LENGTH,
    "9" + "-" * (MAX_PAYLOAD_ID_LENGTH - 1),
)

INVALID_PAYLOAD_IDS = (
    "",
    "a",
    "ab",
    "z" * (MAX_PAYLOAD_ID_LENGTH + 1),
    "-abc",
    "Abc",
    "ABC",
    "a.b",
    "a..b",
    "../abc",
    "a/b",
    "a\\b",
    "a:b",
    "c:/abc",
    "C:\\abc",
    "file:///abc",
    "http://abc",
    "a%2fb",
    "a~b",
    "a b",
    "a\tb",
    "a\nb",
    "a\x00b",
    "abç",
    "a_b",
    "a+b",
    "a\u2010b",
)


@pytest.mark.parametrize("payload_id", VALID_PAYLOAD_IDS)
def test_valid_payload_id_grammar_is_accepted(document_root: Path, payload_id: str):
    entry = _entry(payload_id, document_root / f"{payload_id}.json")
    assert entry.validated() is entry
    assert MIN_PAYLOAD_ID_LENGTH <= len(payload_id) <= MAX_PAYLOAD_ID_LENGTH


@pytest.mark.parametrize("payload_id", INVALID_PAYLOAD_IDS)
def test_invalid_payload_id_grammar_is_refused(document_root: Path, payload_id: str):
    entry = _entry(payload_id, document_root / "document.json")
    with pytest.raises(InvalidHistoricalPairingConfiguration):
        entry.validated()


@pytest.mark.parametrize("payload_id", (None, 3, b"abc", ("abc",), True))
def test_non_string_payload_id_is_refused(document_root: Path, payload_id):
    with pytest.raises(InvalidHistoricalPairingConfiguration):
        _entry(payload_id, document_root / "document.json").validated()


def test_string_subclass_payload_id_is_refused(document_root: Path):
    class _Sneaky(str):
        pass

    with pytest.raises(InvalidHistoricalPairingConfiguration):
        _entry(_Sneaky("abc"), document_root / "document.json").validated()


def test_payload_id_grammar_is_the_documented_narrow_expression():
    pattern = registry_module._PAYLOAD_ID
    assert pattern.pattern == (
        r"[a-z0-9][a-z0-9-]{%d,%d}"
        % (MIN_PAYLOAD_ID_LENGTH - 1, MAX_PAYLOAD_ID_LENGTH - 1)
    )
    assert (MIN_PAYLOAD_ID_LENGTH, MAX_PAYLOAD_ID_LENGTH) == (3, 64)
    for character in ".:/\\%~ \t\n\x00+_":
        assert not pattern.fullmatch(f"ab{character}")


def test_payload_id_is_never_canonical_material(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    """A locator never enters the payload, its fingerprint, or its bytes."""

    marker = "locator-marker-9137"
    raw = _document_bytes(historical_payload)
    path = _write(document_root / "one.json", raw)
    registry = _registry(tmp_path, (_entry(marker, path),))
    payload = registry.get(payload_id=marker)
    assert payload.payload_fingerprint == historical_payload.payload_fingerprint
    assert marker.encode("utf-8") not in _document_bytes(payload)
    assert marker not in json.dumps(payload.to_dict())


# ---------------------------------------------------------------------------
# B/E. Configuration shape and configured path policy.
# ---------------------------------------------------------------------------


def test_configuration_is_explicitly_non_secret():
    names = {field.name for field in fields(HistoricalPairingConfiguration)}
    assert names == {
        "archive_root",
        "payload_entries",
        "preparation_ttl_seconds",
        "max_preparations",
    }
    forbidden = re.compile(
        r"secret|tag|phrase|digest|token|nonce|evidence|preparation_id|state",
        re.IGNORECASE,
    )
    assert not [name for name in names if forbidden.search(name)]


def test_configuration_and_entry_are_frozen(document_root: Path, tmp_path: Path):
    entry = _entry("abc", document_root / "one.json")
    configuration = _configuration(tmp_path, (entry,))
    with pytest.raises(FrozenInstanceError):
        entry.payload_id = "def"
    with pytest.raises(FrozenInstanceError):
        configuration.archive_root = tmp_path


def test_launcher_configuration_is_untouched():
    """The accepted LauncherConfiguration is not extended, wrapped, or replaced."""

    from admissible.product_launcher.configuration import LauncherConfiguration

    assert not issubclass(HistoricalPairingConfiguration, LauncherConfiguration)
    assert "LauncherConfiguration" not in registry_module.__dict__
    source = Path(registry_module.__file__).read_text(encoding="utf-8")
    assert "LauncherConfiguration" not in source


@pytest.mark.parametrize(
    "value",
    (
        "not-a-path",
        None,
        3,
    ),
)
def test_non_path_document_path_is_refused(value):
    with pytest.raises(InvalidHistoricalPairingConfiguration):
        _entry("abc", value).validated()


def test_relative_and_dot_segment_document_paths_are_refused(tmp_path: Path):
    for candidate in (
        Path("relative/document.json"),
        Path("./document.json"),
        tmp_path / ".." / tmp_path.name / "document.json",
        Path(f"{tmp_path}{os.sep}sub{os.sep}..{os.sep}document.json"),
    ):
        with pytest.raises(InvalidHistoricalPairingConfiguration):
            _entry("abc", candidate).validated()


def test_nul_bearing_document_path_is_refused(tmp_path: Path):
    with pytest.raises(InvalidHistoricalPairingConfiguration):
        _entry("abc", Path(f"{tmp_path}\x00/document.json")).validated()


def test_archive_root_must_be_canonical_and_absolute(document_root: Path):
    entry = _entry("abc", document_root / "one.json")
    for archive_root in (Path("relative"), "not-a-path", None):
        with pytest.raises(InvalidHistoricalPairingConfiguration):
            HistoricalPairingConfiguration(
                archive_root=archive_root, payload_entries=(entry,)
            ).validated()


def test_configuration_bounds_are_enforced(tmp_path: Path, document_root: Path):
    entry = _entry("abc", document_root / "one.json")
    for overrides in (
        {"preparation_ttl_seconds": 0},
        {"preparation_ttl_seconds": 86_401},
        {"preparation_ttl_seconds": True},
        {"max_preparations": 0},
        {"max_preparations": 4_097},
        {"payload_entries": [entry]},
        {"payload_entries": (object(),)},
    ):
        with pytest.raises(InvalidHistoricalPairingConfiguration):
            _configuration(tmp_path, (entry,), **overrides).validated()


def test_configured_entry_count_is_bounded(tmp_path: Path, document_root: Path):
    entries = tuple(
        _entry(f"payload-{index:04d}", document_root / f"{index}.json")
        for index in range(MAX_CONFIGURED_HISTORICAL_PAYLOADS + 1)
    )
    with pytest.raises(InvalidHistoricalPairingConfiguration):
        _configuration(tmp_path, entries).validated()


# ---------------------------------------------------------------------------
# C/H. Duplicate refusal and declaration ordering.
# ---------------------------------------------------------------------------


def test_duplicate_payload_id_is_refused_without_first_or_last_wins(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    other_payload: NativeCanaryAuthorizationPayloadV4,
    monkeypatch: pytest.MonkeyPatch,
):
    first = _write(document_root / "one.json", _document_bytes(historical_payload))
    second = _write(document_root / "two.json", _document_bytes(other_payload))
    entries = (_entry("shared-id", first), _entry("shared-id", second))
    with _filesystem_observation(monkeypatch) as observation:
        with pytest.raises(InvalidHistoricalPairingConfiguration) as failure:
            _registry(tmp_path, entries)
    assert "unique" in str(failure.value)
    # The refusal precedes every open: no first-wins and no last-wins.
    assert observation.opened == []


def test_duplicate_document_path_is_refused(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _write(document_root / "one.json", _document_bytes(historical_payload))
    entries = (_entry("first-id", path), _entry("second-id", path))
    with _filesystem_observation(monkeypatch) as observation:
        with pytest.raises(InvalidHistoricalPairingConfiguration) as failure:
            _registry(tmp_path, entries)
    assert "unique" in str(failure.value)
    assert observation.opened == []


def test_duplicate_payload_fingerprint_across_distinct_paths_is_refused(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    raw = _document_bytes(historical_payload)
    first = _write(document_root / "one.json", raw)
    second = _write(document_root / "copy.json", raw)
    with pytest.raises(InvalidHistoricalPairingConfiguration) as failure:
        _registry(tmp_path, (_entry("first-id", first), _entry("second-id", second)))
    assert "distinct" in str(failure.value)


def test_declaration_order_is_preserved_exactly(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    other_payload: NativeCanaryAuthorizationPayloadV4,
):
    # Deliberately reverse-alphabetical so any silent sort is visible.
    zulu = _write(document_root / "zulu.json", _document_bytes(other_payload))
    alpha = _write(document_root / "alpha.json", _document_bytes(historical_payload))
    registry = _registry(
        tmp_path, (_entry("zulu-payload", zulu), _entry("alpha-payload", alpha))
    )
    assert registry.payload_ids == ("zulu-payload", "alpha-payload")
    assert tuple(item.payload_id for item in registry.metadata) == (
        "zulu-payload",
        "alpha-payload",
    )
    assert registry.metadata[0].payload_fingerprint == other_payload.payload_fingerprint
    assert (
        registry.metadata[1].payload_fingerprint
        == historical_payload.payload_fingerprint
    )


# ---------------------------------------------------------------------------
# D/F. Form-A loading, canonical reload, bounded read.
# ---------------------------------------------------------------------------


def test_form_a_standalone_document_loads_to_the_exact_pinned_payload(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    monkeypatch: pytest.MonkeyPatch,
):
    raw = _document_bytes(historical_payload)
    path = _write(document_root / "one.json", raw)
    with _filesystem_observation(monkeypatch) as observation:
        registry = _registry(tmp_path, (_entry("only-payload", path),))
    payload = registry.get(payload_id="only-payload")
    assert isinstance(payload, NativeCanaryAuthorizationPayloadV4)
    assert payload.payload_fingerprint == historical_payload.payload_fingerprint
    assert _document_bytes(payload) == raw
    assert payload.to_dict() == historical_payload.to_dict()

    metadata = registry.metadata
    assert len(metadata) == 1
    assert metadata[0] == HistoricalPayloadMetadata(
        payload_id="only-payload",
        payload_fingerprint=historical_payload.payload_fingerprint,
        document_sha256=hashlib.sha256(raw).hexdigest(),
        document_byte_length=len(raw),
    )
    # Exactly the configured path was opened, exactly once.
    assert observation.opened == [path]
    assert observation.listings == []


def test_form_b_wrapper_is_refused_as_a_malformed_standalone_document(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    for wrapper in (
        {"authorization_payload": historical_payload.to_dict()},
        {
            "schema_version": "admissible_canary_preflight_v1",
            "authorization_payload": historical_payload.to_dict(),
        },
        {**historical_payload.to_dict(), "authorization_payload": {}},
    ):
        path = _write(
            document_root / "wrapper.json", _oracle_canonical_bytes(wrapper)
        )
        with pytest.raises(MalformedHistoricalPayloadDocument) as failure:
            _registry(tmp_path, (_entry("wrapped", path),))
        assert "standalone" in str(failure.value)


def test_non_canonical_but_parseable_document_bytes_are_refused(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    pretty = json.dumps(historical_payload.to_dict(), indent=2).encode("utf-8")
    assert pretty != _document_bytes(historical_payload)
    path = _write(document_root / "pretty.json", pretty)
    with pytest.raises(MalformedHistoricalPayloadDocument) as failure:
        _registry(tmp_path, (_entry("pretty-payload", path),))
    assert "canonical" in str(failure.value)


def test_malformed_truncated_duplicate_key_and_non_object_documents_are_refused(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    raw = _document_bytes(historical_payload)
    text = raw.decode("utf-8")
    duplicated = text.replace(
        '{"attestation_non_claims"',
        '{"schema_version":"x","schema_version":"y","attestation_non_claims"',
        1,
    )
    assert duplicated != text
    cases = {
        "truncated.json": (raw[: len(raw) // 2], "JSON"),
        "not-json.json": (b"this is not json at all", "JSON"),
        "invalid-utf8.json": (b'{"a":"\xff\xfe"}', "JSON"),
        "duplicate-key.json": (duplicated.encode("utf-8"), "JSON"),
        "array.json": (b"[]", "JSON object"),
        "string.json": (b'"a string"', "JSON object"),
        "number.json": (b"17", "JSON object"),
        "empty.json": (b"", "JSON"),
    }
    for name, (data, expected_fragment) in cases.items():
        path = _write(document_root / name, data)
        with pytest.raises(MalformedHistoricalPayloadDocument) as failure:
            _registry(tmp_path, (_entry("broken-payload", path),))
        assert expected_fragment in str(failure.value)


def test_bounded_read_requests_exactly_the_bound_plus_one_byte(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _write(document_root / "one.json", _document_bytes(historical_payload))
    with _filesystem_observation(monkeypatch) as observation:
        _registry(tmp_path, (_entry("only-payload", path),))
    assert observation.read_sizes == [MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES + 1]
    assert MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES == 4 * 1024 * 1024


def test_document_byte_bound_boundary_is_exact(
    tmp_path: Path,
    document_root: Path,
):
    """At the bound the size check passes; one byte over, it refuses first."""

    at_bound = _write(
        document_root / "at-bound.json",
        b"x" * MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES,
    )
    with pytest.raises(MalformedHistoricalPayloadDocument) as at_failure:
        _registry(tmp_path, (_entry("at-bound", at_bound),))
    assert "JSON" in str(at_failure.value)
    assert "bound" not in str(at_failure.value)

    over_bound = _write(
        document_root / "over-bound.json",
        b"x" * (MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES + 1),
    )
    with pytest.raises(MalformedHistoricalPayloadDocument) as over_failure:
        _registry(tmp_path, (_entry("over-bound", over_bound),))
    assert "bound" in str(over_failure.value)


def test_missing_and_directory_documents_are_refused(
    tmp_path: Path, document_root: Path
):
    missing = document_root / "absent.json"
    assert not missing.exists()
    with pytest.raises(MalformedHistoricalPayloadDocument):
        _registry(tmp_path, (_entry("absent-payload", missing),))

    directory = document_root / "a-directory"
    directory.mkdir()
    with pytest.raises(MalformedHistoricalPayloadDocument) as failure:
        _registry(tmp_path, (_entry("directory-payload", directory),))
    assert "regular file" in str(failure.value)


def test_configured_symbolic_link_is_refused_when_supported(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    target = _write(
        document_root / "target.json", _document_bytes(historical_payload)
    )
    link = document_root / "link.json"
    try:
        os.symlink(os.fspath(target), os.fspath(link))
    except (OSError, NotImplementedError, AttributeError) as exc:
        pytest.skip(f"this host cannot create a symbolic link: {exc}")
    assert os.path.lexists(link)
    with pytest.raises(MalformedHistoricalPayloadDocument) as failure:
        _registry(tmp_path, (_entry("linked-payload", link),))
    assert "non-redirecting" in str(failure.value)


def test_reparse_point_metadata_is_classified_as_redirecting():
    """The redirection classifier is exercised without needing a real junction."""

    class _Metadata:
        st_mode = 0o100644
        st_file_attributes = registry_module._REPARSE_POINT_FLAG

    class _Ordinary:
        st_mode = 0o100644
        st_file_attributes = 0

    assert registry_module._is_redirecting(_Metadata()) is True
    assert registry_module._is_redirecting(_Ordinary()) is False


# ---------------------------------------------------------------------------
# G. Evidence blindness.
# ---------------------------------------------------------------------------


FORBIDDEN_DIRECT_IMPORTS = (
    "admissible.delegated_gate.store",
    "admissible.delegated_gate.checkpoint",
    "admissible.delegated_gate.native_executor",
    "admissible.delegated_gate.native_acceptance",
    "admissible.delegated_gate.events",
    "admissible.product_read_model",
    "admissible.review_surface",
    "admissible.browser_runtime",
    "glob",
    "shutil",
    "fnmatch",
)


def test_registry_names_no_evidence_or_execution_module_directly():
    """The module's own import graph names no forbidden module.

    This is deliberately a direct-import law.  The accepted historical V4 loader
    lives beside the execution modules, so a transitive-import ban is impossible
    and is not claimed here; the runtime filesystem tests carry that weight.
    """

    source = Path(registry_module.__file__).read_text(encoding="utf-8")
    import_lines = [
        line
        for line in source.splitlines()
        if line.startswith("import ") or line.startswith("from ")
    ]
    joined = "\n".join(import_lines)
    for forbidden in FORBIDDEN_DIRECT_IMPORTS:
        assert forbidden not in joined, forbidden


FORBIDDEN_ATTRIBUTE_NAMES = frozenset(
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
    }
)


def test_registry_source_contains_no_directory_traversal_construct():
    """An AST law, immune to prose: no traversal attribute is ever referenced."""

    tree = ast.parse(
        Path(registry_module.__file__).read_text(encoding="utf-8"),
        filename=registry_module.__file__,
    )
    referenced = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert not (referenced & FORBIDDEN_ATTRIBUTE_NAMES), sorted(
        referenced & FORBIDDEN_ATTRIBUTE_NAMES
    )
    # No path arithmetic operator is applied to a configured path either.
    assert not [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)
    ]


def test_registry_opens_only_configured_paths_and_dereferences_no_payload_path(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    other_payload: NativeCanaryAuthorizationPayloadV4,
    monkeypatch: pytest.MonkeyPatch,
):
    first = _write(document_root / "one.json", _document_bytes(historical_payload))
    second = _write(document_root / "two.json", _document_bytes(other_payload))
    sibling = _write(document_root / "sibling.json", b"{}")
    with _filesystem_observation(monkeypatch) as observation:
        registry = _registry(
            tmp_path, (_entry("first-payload", first), _entry("second-payload", second))
        )
    assert observation.opened == [first, second]
    assert sibling not in observation.opened
    assert observation.listings == []

    carried = {
        historical_payload.source_repository,
        historical_payload.run_root,
        historical_payload.workspace_root,
        historical_payload.evidence_root,
        historical_payload.native_sidecar_root,
        historical_payload.executable,
        *historical_payload.launcher_prefix,
    }
    opened = {str(item) for item in observation.opened}
    assert not (carried & opened)
    for value in carried:
        assert not Path(value).exists()
    assert registry.payload_ids == ("first-payload", "second-payload")


def test_lookup_after_construction_performs_zero_filesystem_access(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    monkeypatch: pytest.MonkeyPatch,
):
    path = _write(document_root / "one.json", _document_bytes(historical_payload))
    registry = _registry(tmp_path, (_entry("only-payload", path),))

    # The spies record and delegate rather than raise: an exception thrown from
    # inside a patched os primitive can escape into pytest's own machinery and
    # abort the session instead of failing this test cleanly.
    touches: list[str] = []

    def recorder(label, real):
        def _spy(*args, **kwargs):
            touches.append(label)
            return real(*args, **kwargs)

        return _spy

    monkeypatch.setattr(
        registry_module, "open", recorder("open", builtins.open), raising=False
    )
    for name in ("lstat", "stat", "open", "listdir", "scandir", "walk"):
        monkeypatch.setattr(
            os, name, recorder(f"os.{name}", getattr(os, name))
        )

    observed_ids = registry.payload_ids
    observed_metadata = registry.metadata[0].payload_id
    payload = registry.get(payload_id="only-payload")
    rendered = repr(registry)
    missing = None
    try:
        registry.get(payload_id="missing-payload")
    except HistoricalPayloadNotFound as exc:
        missing = exc
    monkeypatch.undo()

    assert touches == []
    assert observed_ids == ("only-payload",)
    assert observed_metadata == "only-payload"
    assert payload.payload_fingerprint == historical_payload.payload_fingerprint
    assert rendered == "<HistoricalPayloadRegistry payloads=1>"
    assert isinstance(missing, HistoricalPayloadNotFound)


def test_replacing_or_deleting_the_source_document_has_no_effect(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
    other_payload: NativeCanaryAuthorizationPayloadV4,
):
    raw = _document_bytes(historical_payload)
    path = _write(document_root / "one.json", raw)
    registry = _registry(tmp_path, (_entry("only-payload", path),))

    path.write_bytes(_document_bytes(other_payload))
    payload = registry.get(payload_id="only-payload")
    assert payload.payload_fingerprint == historical_payload.payload_fingerprint
    assert registry.metadata[0].document_sha256 == hashlib.sha256(raw).hexdigest()

    path.unlink()
    assert not path.exists()
    again = registry.get(payload_id="only-payload")
    assert again is payload
    assert registry.metadata[0].document_byte_length == len(raw)

    # Only a newly constructed registry ever observes new bytes.
    _write(path, _document_bytes(other_payload))
    fresh = _registry(tmp_path, (_entry("only-payload", path),))
    assert fresh.get(payload_id="only-payload").payload_fingerprint == (
        other_payload.payload_fingerprint
    )


# ---------------------------------------------------------------------------
# H. Public surface.
# ---------------------------------------------------------------------------


def test_public_surface_is_narrow_and_carries_no_path(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    path = _write(document_root / "one.json", _document_bytes(historical_payload))
    registry = _registry(tmp_path, (_entry("only-payload", path),))

    public = {name for name in dir(registry) if not name.startswith("_")}
    assert public == {"get", "metadata", "payload_ids"}

    assert {field.name for field in fields(HistoricalPayloadMetadata)} == {
        "payload_id",
        "payload_fingerprint",
        "document_sha256",
        "document_byte_length",
    }

    rendered = f"{registry!r} {registry.metadata!r}"
    for forbidden in (
        str(path),
        path.name,
        str(document_root),
        str(tmp_path),
        "archive",
        "0x",
        "\\",
    ):
        assert forbidden not in rendered
    assert rendered.startswith("<HistoricalPayloadRegistry payloads=1>")


def test_registry_records_are_not_reachable_or_mutable(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    path = _write(document_root / "one.json", _document_bytes(historical_payload))
    registry = _registry(tmp_path, (_entry("only-payload", path),))
    with pytest.raises(TypeError):
        registry._records["injected"] = None
    with pytest.raises(AttributeError):
        registry.payload_ids.append("injected")
    with pytest.raises(FrozenInstanceError):
        registry.metadata[0].payload_id = "injected"
    assert registry.payload_ids == ("only-payload",)


def test_unregistered_and_malformed_lookups_are_bounded(
    tmp_path: Path,
    document_root: Path,
    historical_payload: NativeCanaryAuthorizationPayloadV4,
):
    path = _write(document_root / "one.json", _document_bytes(historical_payload))
    registry = _registry(tmp_path, (_entry("only-payload", path),))
    with pytest.raises(HistoricalPayloadNotFound):
        registry.get(payload_id="other-payload")
    with pytest.raises(InvalidHistoricalPairingConfiguration):
        registry.get(payload_id="../escape")
    assert issubclass(HistoricalPayloadNotFound, HistoricalPayloadRegistryError)
    assert issubclass(
        InvalidHistoricalPairingConfiguration, HistoricalPayloadRegistryError
    )
    assert issubclass(
        MalformedHistoricalPayloadDocument, HistoricalPayloadRegistryError
    )


def test_registry_requires_the_exact_configuration_type(tmp_path: Path):
    with pytest.raises(InvalidHistoricalPairingConfiguration):
        HistoricalPayloadRegistry(configuration=object())

    class _Subclass(HistoricalPairingConfiguration):
        pass

    with pytest.raises(InvalidHistoricalPairingConfiguration):
        HistoricalPayloadRegistry(
            configuration=_Subclass(archive_root=tmp_path, payload_entries=())
        )


def test_empty_configuration_is_a_valid_empty_registry(tmp_path: Path):
    registry = _registry(tmp_path, ())
    assert registry.payload_ids == ()
    assert registry.metadata == ()
    assert repr(registry) == "<HistoricalPayloadRegistry payloads=0>"
