"""Step 5C2E0: independent standalone historical V4 extraction utility.

Every wrapper fixture in this module is generated through the repository's own
serialization conventions -- the exact ``json.dumps(..., sort_keys=True)`` shape
the preflight-only envelope is printed with, and the exact
``canonical_bytes(...) + b"\\n"`` shape the run preflight metadata file is
written with -- rather than through a hand-written approximation.  Canonical
expectations are computed by an independent standard-library oracle, so the
extractor is never asked to produce an expectation it is then compared against.
"""

import ast
import base64
import builtins
import contextlib
from copy import deepcopy
import functools
import hashlib
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

from admissible.delegated_gate.canonical import canonical_bytes
from admissible.delegated_gate.native_canary import (
    CANARY_CLASSIFICATION,
    EVIDENCE_DIRECTORY_NAME,
    NATIVE_SIDECAR_DIRECTORY_NAME,
    RUN_PREFLIGHT_METADATA_FILE_NAME,
    WORKSPACE_DIRECTORY_NAME,
    NativeCanaryAuthorizationPayloadV4,
    load_historical_native_canary_authorization_payload_v4,
)
from admissible.delegated_gate.native_executor import NativePreflightStatus
from admissible.product_launcher.historical_pairing_registry import (
    MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES,
    HistoricalPairingConfiguration,
    HistoricalPayloadEntry,
    HistoricalPayloadRegistry,
)
from admissible.operator_tools import historical_pairing_v4_extract as tool

from test_admissible_historical_evaluation_pairing import _refingerprint_payload
from test_admissible_historical_v5_derivation import _runtime_v2_profile
from test_admissible_workflow_recovery_profile import _payload_harness


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "admissible" / "operator_tools" / "historical_pairing_v4_extract.py"
INIT_PATH = ROOT / "admissible" / "operator_tools" / "__init__.py"
PYPROJECT_PATH = ROOT / "pyproject.toml"

EXIT = tool.HISTORICAL_PAIRING_V4_EXTRACT_EXIT_CODE
SUCCESS_LINE = b"status=STANDALONE_V4_WRITTEN" + os.linesep.encode("ascii")


def _error_line(code: str) -> bytes:
    return b"error=" + code.encode("ascii") + os.linesep.encode("ascii")


def _entropy_text(label: bytes, length: int) -> str:
    """Deterministic, structure-free sentinel text for containment checks."""

    block = ""
    counter = 0
    while len(block) < length:
        block += hashlib.sha256(label + counter.to_bytes(4, "big")).hexdigest()
        counter += 1
    return block[:length]


SIBLING_SENTINEL = _entropy_text(b"5C2E0-wrapper-sibling", 96)
SECOND_SIBLING_SENTINEL = _entropy_text(b"5C2E0-wrapper-sibling-two", 96)


def _oracle_canonical_bytes(mapping: dict) -> bytes:
    """Re-implement the documented canonical rule with the standard library."""

    return json.dumps(
        mapping, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Real historical V4 fixture material.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def harness(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    """One real V4 payload whose every carried filesystem path is absent."""

    fixture_root = tmp_path_factory.mktemp("s5c2e0")
    runtime_profile = _runtime_v2_profile()
    built = _payload_harness(fixture_root, runtime_profile)
    live = built.payload.to_dict()
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
    return SimpleNamespace(
        payload=payload,
        document=payload.to_dict(),
        attestation=built.attestation.to_dict(),
        run_root=run_root,
    )


@pytest.fixture(scope="module")
def document(harness: SimpleNamespace) -> dict:
    return harness.document


@pytest.fixture(scope="module")
def canonical(document: dict) -> bytes:
    return _oracle_canonical_bytes(document)


@pytest.fixture(scope="module")
def sha256_head_document(document: dict) -> dict:
    """A second accepted payload whose source HEAD is a 64-character Git OID.

    The accepted historical loader permits both the 40- and the 64-character
    lowercase form.  Any extractor-local re-implementation of that grammar
    therefore has an observable, killable disagreement with the accepted API.
    """

    variant = deepcopy(document)
    variant["source_head"] = hashlib.sha256(b"5C2E0-sha256-head").hexdigest()
    refingerprinted = _refingerprint_payload(variant)
    assert len(refingerprinted["source_head"]) == 64
    load_historical_native_canary_authorization_payload_v4(refingerprinted)
    return refingerprinted


# ---------------------------------------------------------------------------
# Wrapper shapes, generated through the repository's own conventions.
# ---------------------------------------------------------------------------


def _preflight_only_wrapper(document: dict, attestation: dict, **extra) -> bytes:
    """Exactly the shape ``--preflight-only`` prints, serialized the same way."""

    envelope = {
        "status": NativePreflightStatus.PREFLIGHT_READY.value,
        "authorization_payload": document,
        "attestation": attestation,
        "where_diagnostic": {"resolution": "deterministic", "note": SIBLING_SENTINEL},
        "durability_capability": {"observed": True},
    }
    envelope.update(extra)
    return json.dumps(envelope, sort_keys=True).encode("utf-8")


def _run_preflight_metadata_wrapper(document: dict, attestation: dict, **extra) -> bytes:
    """Exactly the run preflight metadata file, written the same way."""

    envelope = {
        "classification": CANARY_CLASSIFICATION,
        "authorization_payload": document,
        "attestation": attestation,
        "local_capability_status": SIBLING_SENTINEL,
        "durability_capability": {"observed": True},
    }
    envelope.update(extra)
    return canonical_bytes(envelope) + b"\n"


def _minimal_wrapper(document: dict) -> bytes:
    return json.dumps({"authorization_payload": document}).encode("utf-8")


def _argv(wrapper: Path, output: Path) -> list[str]:
    return [
        "--wrapper-file",
        os.fspath(wrapper),
        "--output-file",
        os.fspath(output),
    ]


def _invoke(tmp_path: Path, wrapper_bytes: bytes, *, name: str = "out.json"):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(wrapper_bytes)
    output = tmp_path / name
    return tool.main(_argv(wrapper, output)), wrapper, output


def _accepts(tmp_path: Path, wrapper_bytes: bytes, canonical: bytes, capfdbinary):
    result, _wrapper, output = _invoke(tmp_path, wrapper_bytes)
    captured = capfdbinary.readouterr()
    assert result == 0, captured.err
    assert captured.out == SUCCESS_LINE
    assert captured.err == b""
    assert output.read_bytes() == canonical
    return output


def _refuses(tmp_path: Path, wrapper_bytes: bytes, code: str, capfdbinary):
    result, _wrapper, output = _invoke(tmp_path, wrapper_bytes)
    captured = capfdbinary.readouterr()
    assert result == EXIT
    assert captured.out == b""
    assert captured.err == _error_line(code)
    assert not output.exists()


# ---------------------------------------------------------------------------
# Wrapper forms.
# ---------------------------------------------------------------------------


def test_preflight_only_envelope_is_accepted(
    tmp_path: Path, harness, document, canonical, capfdbinary
):
    _accepts(
        tmp_path,
        _preflight_only_wrapper(document, harness.attestation),
        canonical,
        capfdbinary,
    )


def test_run_preflight_metadata_envelope_is_accepted(
    tmp_path: Path, harness, document, canonical, capfdbinary
):
    assert RUN_PREFLIGHT_METADATA_FILE_NAME
    _accepts(
        tmp_path,
        _run_preflight_metadata_wrapper(document, harness.attestation),
        canonical,
        capfdbinary,
    )


def test_minimal_top_level_wrapper_is_accepted(
    tmp_path: Path, document, canonical, capfdbinary
):
    _accepts(tmp_path, _minimal_wrapper(document), canonical, capfdbinary)


def test_arbitrary_unknown_sibling_fields_are_ignored(
    tmp_path: Path, harness, document, canonical, capfdbinary
):
    """Three structurally different wrappers produce byte-identical output."""

    variants = [
        _minimal_wrapper(document),
        _preflight_only_wrapper(document, harness.attestation),
        _run_preflight_metadata_wrapper(
            document,
            harness.attestation,
            unknown_future_member={"deeply": {"nested": [1, 2, {"x": None}]}},
            another_unknown=SECOND_SIBLING_SENTINEL,
        ),
    ]
    produced = []
    for index, wrapper_bytes in enumerate(variants):
        root = tmp_path / f"variant-{index}"
        root.mkdir()
        output = _accepts(root, wrapper_bytes, canonical, capfdbinary)
        produced.append(output.read_bytes())
    assert produced[0] == produced[1] == produced[2] == canonical


def test_poisonous_sibling_values_never_affect_output(
    tmp_path: Path, harness, document, canonical, capfdbinary
):
    """Blocked status, foreign classification and a decoy payload change nothing."""

    decoy = deepcopy(document)
    decoy["run_id"] = "decoy-run-id"
    wrapper = _preflight_only_wrapper(
        document,
        harness.attestation,
        status=NativePreflightStatus.PREFLIGHT_BLOCKED.value,
        classification="unrelated-classification",
        local_capability_status="BLOCKED",
        result={"verdict": "FAILED", "authorization_payload": decoy},
        acceptance={"accepted": False},
    )
    output = _accepts(tmp_path, wrapper, canonical, capfdbinary)
    raw = output.read_bytes()
    assert raw == canonical
    assert b"decoy-run-id" not in raw
    assert b"PREFLIGHT_BLOCKED" not in raw
    assert SIBLING_SENTINEL.encode("utf-8") not in raw
    assert b'"attestation":' not in raw
    assert b'"classification":' not in raw
    assert b'"result":' not in raw
    assert b'"acceptance":' not in raw


def test_bare_form_a_document_is_refused(
    tmp_path: Path, canonical, capfdbinary
):
    """The standalone product document has no wrapper member and is refused here."""

    _refuses(
        tmp_path,
        canonical,
        tool.HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_MISSING,
        capfdbinary,
    )


def test_nested_only_authorization_payload_is_refused(
    tmp_path: Path, document, capfdbinary
):
    """The member is never searched for below the top level."""

    for envelope in (
        {"outer": {"authorization_payload": document}},
        {"run": {"evidence": [{"authorization_payload": document}]}},
        {"authorization_payloads": [document]},
    ):
        root = tmp_path / str(len(list(tmp_path.iterdir())))
        root.mkdir()
        _refuses(
            root,
            json.dumps(envelope).encode("utf-8"),
            tool.HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_MISSING,
            capfdbinary,
        )


def test_missing_member_is_refused(tmp_path: Path, harness, capfdbinary):
    envelope = {
        "status": NativePreflightStatus.PREFLIGHT_READY.value,
        "attestation": harness.attestation,
    }
    _refuses(
        tmp_path,
        json.dumps(envelope, sort_keys=True).encode("utf-8"),
        tool.HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_MISSING,
        capfdbinary,
    )


@pytest.mark.parametrize(
    "value", ["[]", '"text"', "12", "true", "false", "null", "[{}]"]
)
def test_non_object_member_is_refused(tmp_path: Path, value: str, capfdbinary):
    _refuses(
        tmp_path,
        ('{"authorization_payload": %s}' % value).encode("utf-8"),
        tool.HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_MISSING,
        capfdbinary,
    )


def test_duplicate_top_level_authorization_payload_is_refused(
    tmp_path: Path, document, capfdbinary
):
    body = json.dumps(document)
    wrapper = ('{"authorization_payload": %s, "authorization_payload": %s}' % (
        body,
        body,
    )).encode("utf-8")
    # The document really is duplicated, and a permissive parser would take one.
    assert wrapper.count(b'"authorization_payload"') == 2
    _refuses(
        tmp_path, wrapper, tool.HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED, capfdbinary
    )


@pytest.mark.parametrize(
    "wrapper",
    [
        b'{"authorization_payload": {"a": 1, "a": 2}}',
        b'{"authorization_payload": {"nested": {"b": 1, "b": 2}}}',
        b'{"authorization_payload": {"list": [{"c": 1, "c": 2}]}}',
        b'{"status": "X", "status": "Y", "authorization_payload": {}}',
        b'{"authorization_payload": {}, "deep": {"x": {"y": {"z": 1, "z": 2}}}}',
    ],
)
def test_duplicate_keys_at_every_depth_are_refused(
    tmp_path: Path, wrapper: bytes, capfdbinary
):
    _refuses(
        tmp_path, wrapper, tool.HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED, capfdbinary
    )


# ---------------------------------------------------------------------------
# Wrapper JSON transport.
# ---------------------------------------------------------------------------


def test_strict_utf8_sibling_text_is_decoded_and_still_ignored(
    tmp_path: Path, document, canonical, capfdbinary
):
    envelope = {"authorization_payload": document, "note": "café — naïve ✓ 𝄞"}
    wrapper = json.dumps(envelope, ensure_ascii=False).encode("utf-8")
    assert b"\xc3\xa9" in wrapper
    output = _accepts(tmp_path, wrapper, canonical, capfdbinary)
    assert "café".encode("utf-8") not in output.read_bytes()


@pytest.mark.parametrize(
    "raw",
    [
        b"\xef\xbb\xbf" + b'{"authorization_payload": {}}',
        b'{"authorization_payload": {"k": "\xff\xfe"}}',
        b"\xff\xfe" + b'{"a": 1}',
        b'{"a": "\x80\x80"}',
    ],
)
def test_bom_and_invalid_utf8_are_refused(tmp_path: Path, raw: bytes, capfdbinary):
    _refuses(tmp_path, raw, tool.HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED, capfdbinary)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"authorization_payload": {"x": NaN}}',
        b'{"authorization_payload": {"x": Infinity}}',
        b'{"authorization_payload": {"x": -Infinity}}',
        b'{"sibling": NaN, "authorization_payload": {}}',
        b'{"sibling": [1, Infinity], "authorization_payload": {}}',
    ],
)
def test_non_finite_json_constants_are_refused(
    tmp_path: Path, raw: bytes, capfdbinary
):
    # The stock parser really would accept these, so the refusal is the tool's.
    assert json.loads(raw.decode("ascii")) is not None
    _refuses(tmp_path, raw, tool.HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED, capfdbinary)


@pytest.mark.parametrize(
    "raw",
    [b"[]", b'"text"', b"12", b"true", b"null", b"   ", b"", b"{", b"not json"],
)
def test_non_object_root_and_malformed_json_are_refused(
    tmp_path: Path, raw: bytes, capfdbinary
):
    _refuses(tmp_path, raw, tool.HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED, capfdbinary)


def test_multiple_json_values_are_refused(tmp_path: Path, document, capfdbinary):
    body = json.dumps({"authorization_payload": document})
    _refuses(
        tmp_path,
        (body + " " + body).encode("utf-8"),
        tool.HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED,
        capfdbinary,
    )


def test_wrapper_byte_bound_is_exact_and_inclusive(
    tmp_path: Path, document, canonical, capfdbinary
):
    bound = tool.MAX_HISTORICAL_PAIRING_V4_WRAPPER_BYTES
    assert bound == 8 * 1024 * 1024
    base = json.dumps(
        {"authorization_payload": document, "pad": ""}, separators=(",", ":")
    ).encode("utf-8")
    padded = json.dumps(
        {"authorization_payload": document, "pad": "p" * (bound - len(base))},
        separators=(",", ":"),
    ).encode("utf-8")
    assert len(padded) == bound
    accepted_root = tmp_path / "at-bound"
    accepted_root.mkdir()
    _accepts(accepted_root, padded, canonical, capfdbinary)

    oversized_root = tmp_path / "over-bound"
    oversized_root.mkdir()
    _refuses(
        oversized_root,
        b"x" * (bound + 1),
        tool.HISTORICAL_PAIRING_V4_WRAPPER_TOO_LARGE,
        capfdbinary,
    )


def test_wrapper_is_opened_once_and_read_once_at_bound_plus_one(
    tmp_path: Path, document, monkeypatch: pytest.MonkeyPatch, capfdbinary
):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    output = tmp_path / "out.json"
    opens: list = []
    reads: list = []
    original_open = builtins.open

    class Recording:
        def __init__(self, handle):
            self._handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            self._handle.close()

        def fileno(self):
            return self._handle.fileno()

        def read(self, size=-1):
            reads.append(size)
            return self._handle.read(size)

    def recording_open(target, mode="r", *args, **kwargs):
        opens.append((Path(os.fsdecode(target)), mode))
        handle = original_open(target, mode, *args, **kwargs)
        if mode == "rb":
            return Recording(handle)
        return handle

    monkeypatch.setattr(builtins, "open", recording_open)
    assert tool.main(_argv(wrapper, output)) == 0
    capfdbinary.readouterr()
    assert opens == [
        (wrapper, "rb"),
        (output, "xb"),
    ]
    assert reads == [tool.MAX_HISTORICAL_PAIRING_V4_WRAPPER_BYTES + 1]


def test_reported_wrapper_symlink_and_reparse_point_are_refused_before_open(
    tmp_path: Path, document, monkeypatch: pytest.MonkeyPatch
):
    # The file really exists and really is a loadable wrapper, so anything that
    # opens it succeeds: the refusal can only come from the metadata decision.
    path = tmp_path / "wrapper.json"
    path.write_bytes(_minimal_wrapper(document))
    opened: list = []
    original_open = builtins.open

    def recording_open(target, mode="r", *args, **kwargs):
        opened.append((Path(os.fsdecode(target)), mode))
        return original_open(target, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", recording_open)
    for metadata in (
        SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0),
        SimpleNamespace(
            st_mode=stat.S_IFREG, st_file_attributes=tool._REPARSE_POINT_FLAG
        ),
    ):
        monkeypatch.setattr(tool.os, "lstat", lambda _candidate, m=metadata: m)
        with pytest.raises(tool.HistoricalPairingV4ExtractError) as refusal:
            tool._read_wrapper_file(path)
        assert refusal.value.code == tool.HISTORICAL_PAIRING_V4_WRAPPER_UNAVAILABLE
    assert opened == []


def test_real_direct_wrapper_symlink_is_refused(tmp_path: Path, document):
    target = tmp_path / "target.json"
    target.write_bytes(_minimal_wrapper(document))
    link = tmp_path / "link.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as failure:
        pytest.skip(f"platform cannot create an unprivileged test symlink: {failure}")
    assert link.read_bytes() == target.read_bytes()  # the link really resolves
    with pytest.raises(tool.HistoricalPairingV4ExtractError) as refusal:
        tool._read_wrapper_file(link)
    assert refusal.value.code == tool.HISTORICAL_PAIRING_V4_WRAPPER_UNAVAILABLE


def test_missing_and_directory_wrapper_paths_are_unavailable(
    tmp_path: Path, capfdbinary
):
    for candidate in (tmp_path / "absent.json", tmp_path):
        output = tmp_path / f"out-{candidate.name}.json"
        assert tool.main(_argv(candidate, output)) == EXIT
        captured = capfdbinary.readouterr()
        assert captured.out == b""
        assert captured.err == _error_line(
            tool.HISTORICAL_PAIRING_V4_WRAPPER_UNAVAILABLE
        )
        assert not output.exists()


@pytest.mark.parametrize(
    "candidate",
    ["relative/wrapper.json", "~/wrapper.json", "$HOME/wrapper.json"],
)
def test_relative_and_unexpanded_wrapper_locators_are_path_invalid(
    tmp_path: Path, candidate: str, capfdbinary
):
    output = tmp_path / "out.json"
    assert tool.main(_argv(Path(candidate), output)) == EXIT
    captured = capfdbinary.readouterr()
    assert captured.out == b""
    assert captured.err == _error_line(
        tool.HISTORICAL_PAIRING_V4_WRAPPER_PATH_INVALID
    )
    assert not output.exists()


def test_noncanonical_and_nul_wrapper_locators_are_path_invalid(tmp_path: Path):
    noncanonical = tmp_path / "sub" / ".." / "wrapper.json"
    assert Path(os.path.abspath(os.fspath(noncanonical))) != noncanonical
    for candidate in (noncanonical, Path(os.fspath(tmp_path / "a\x00b"))):
        with pytest.raises(tool.HistoricalPairingV4ExtractError) as refusal:
            tool._read_wrapper_file(candidate)
        assert refusal.value.code == tool.HISTORICAL_PAIRING_V4_WRAPPER_PATH_INVALID


# ---------------------------------------------------------------------------
# Accepted V4 validation and canonical output.
# ---------------------------------------------------------------------------


def test_accepted_loader_is_called_once_with_the_exact_nested_mapping(
    tmp_path: Path, harness, document, canonical, monkeypatch: pytest.MonkeyPatch,
    capfdbinary,
):
    calls: list = []
    original = tool.load_historical_native_canary_authorization_payload_v4

    def recording(mapping):
        calls.append(mapping)
        return original(mapping)

    monkeypatch.setattr(
        tool, "load_historical_native_canary_authorization_payload_v4", recording
    )
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_preflight_only_wrapper(document, harness.attestation))
    output = tmp_path / "out.json"
    assert tool.main(_argv(wrapper, output)) == 0
    capfdbinary.readouterr()

    assert len(calls) == 1
    reached = calls[0]
    assert type(reached) is dict
    assert reached == document
    # Exactly the nested mapping: no sibling and no wrapper root reaches it.
    assert "status" not in reached
    assert "attestation" not in reached
    assert "authorization_payload" not in reached
    assert output.read_bytes() == canonical


def test_canonical_bytes_is_called_over_the_validated_payload_to_dict(
    tmp_path: Path, document, canonical, monkeypatch: pytest.MonkeyPatch, capfdbinary
):
    seen: list = []
    original = tool.canonical_bytes

    def recording(value):
        seen.append(value)
        return original(value)

    monkeypatch.setattr(tool, "canonical_bytes", recording)
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    output = tmp_path / "out.json"
    assert tool.main(_argv(wrapper, output)) == 0
    capfdbinary.readouterr()

    assert len(seen) == 1
    assert seen[0] == document
    assert output.read_bytes() == canonical == _oracle_canonical_bytes(seen[0])


def test_pretty_and_noncanonical_nested_json_yields_identical_canonical_bytes(
    tmp_path: Path, harness, document, canonical, capfdbinary
):
    reordered = dict(reversed(list(document.items())))
    assert list(reordered) != list(document)
    pretty = json.dumps(
        {
            "authorization_payload": reordered,
            "attestation": harness.attestation,
        },
        indent=4,
        sort_keys=False,
    ).encode("utf-8")
    assert b"\n" in pretty and b"    " in pretty
    output = _accepts(tmp_path, pretty, canonical, capfdbinary)
    raw = output.read_bytes()
    assert b"\n" not in raw
    assert len(raw) < len(pretty)
    # The canonicality law itself, independent of any payload content: the
    # produced bytes are a fixed point of the documented canonical rule.
    assert _oracle_canonical_bytes(json.loads(raw.decode("utf-8"))) == raw
    assert raw == _oracle_canonical_bytes(document)


def test_sha256_source_head_payload_is_accepted_exactly_as_the_loader_accepts_it(
    tmp_path: Path, sha256_head_document, capfdbinary
):
    """The extractor owns no field grammar of its own; the loader decides."""

    expected = _oracle_canonical_bytes(sha256_head_document)
    _accepts(tmp_path, _minimal_wrapper(sha256_head_document), expected, capfdbinary)


@pytest.mark.parametrize(
    "mutation",
    [
        ("run_id", "changed-run-id"),
        ("schema_version", "not-a-v4"),
        ("payload_fingerprint", "0" * 64),
        ("clean_worktree_required", False),
        ("timeout_seconds", 3),
    ],
)
def test_altered_v4_field_is_rejected_by_the_accepted_loader(
    tmp_path: Path, document, mutation, capfdbinary
):
    key, value = mutation
    altered = deepcopy(document)
    altered[key] = value
    with pytest.raises((TypeError, ValueError)):
        load_historical_native_canary_authorization_payload_v4(altered)
    _refuses(
        tmp_path,
        _minimal_wrapper(altered),
        tool.HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED,
        capfdbinary,
    )


def test_extra_or_missing_v4_key_is_refused(tmp_path: Path, document, capfdbinary):
    for altered in (
        {**document, "unexpected_extra": 1},
        {k: v for k, v in document.items() if k != "run_id"},
    ):
        root = tmp_path / str(len(list(tmp_path.iterdir())))
        root.mkdir()
        _refuses(
            root,
            _minimal_wrapper(altered),
            tool.HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED,
            capfdbinary,
        )


def test_output_reloads_through_the_product_registry_under_its_form_a_law(
    tmp_path: Path, harness, document, canonical, capfdbinary
):
    output = _accepts(
        tmp_path,
        _run_preflight_metadata_wrapper(document, harness.attestation),
        canonical,
        capfdbinary,
    )
    raw = output.read_bytes()
    reloaded = load_historical_native_canary_authorization_payload_v4(
        json.loads(raw.decode("utf-8"))
    )
    # The registry's exact committed byte law.
    assert raw == canonical_bytes(reloaded.to_dict())

    registry = HistoricalPayloadRegistry(
        configuration=HistoricalPairingConfiguration(
            archive_root=tmp_path / "archive",
            payload_entries=(
                HistoricalPayloadEntry(
                    payload_id="extracted-standalone", document_path=output
                ),
            ),
        )
    )
    assert registry.payload_ids == ("extracted-standalone",)
    registered = registry.get(payload_id="extracted-standalone")
    assert registered.payload_fingerprint == harness.payload.payload_fingerprint
    assert registry.metadata[0].document_byte_length == len(raw)
    assert registry.metadata[0].document_sha256 == hashlib.sha256(raw).hexdigest()


def test_standalone_output_bound_equals_the_registry_document_bound():
    assert (
        tool.MAX_STANDALONE_HISTORICAL_V4_BYTES
        == MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES
        == 4 * 1024 * 1024
    )


def test_canonical_output_above_the_bound_is_refused_before_the_output_is_touched(
    tmp_path: Path, document, monkeypatch: pytest.MonkeyPatch, capfdbinary
):
    monkeypatch.setattr(tool, "MAX_STANDALONE_HISTORICAL_V4_BYTES", 1024)
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    output = tmp_path / "out.json"
    assert tool.main(_argv(wrapper, output)) == EXIT
    captured = capfdbinary.readouterr()
    assert captured.out == b""
    assert captured.err == _error_line(
        tool.HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED
    )
    assert not output.exists()


def test_accepted_refusal_types_are_exact_and_a_subclass_propagates(
    tmp_path: Path, document, monkeypatch: pytest.MonkeyPatch
):
    assert tool.ACCEPTED_HISTORICAL_V4_REFUSAL_TYPES == frozenset({TypeError, ValueError})

    class UnregisteredValueError(ValueError):
        pass

    def raising(_mapping):
        raise UnregisteredValueError("lower detail")

    monkeypatch.setattr(
        tool, "load_historical_native_canary_authorization_payload_v4", raising
    )
    with pytest.raises(UnregisteredValueError):
        tool._accepted_historical_payload(dict(document))


def test_bounded_v4_refusal_carries_no_cause_context_or_lower_text(
    tmp_path: Path, document
):
    altered = deepcopy(document)
    altered["run_id"] = "changed-run-id"
    with pytest.raises(tool.HistoricalPairingV4ExtractError) as refusal:
        tool._accepted_historical_payload(altered)
    failure = refusal.value
    assert failure.code == tool.HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED
    assert str(failure) == tool.HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED
    assert failure.args == (tool.HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED,)
    assert failure.__cause__ is None
    assert failure.__context__ is None
    assert "changed-run-id" not in repr(failure)


def test_forged_or_unknown_code_collapses_to_one_generic_refusal(
    tmp_path: Path, document, monkeypatch: pytest.MonkeyPatch, capfdbinary
):
    assert (
        tool.HISTORICAL_PAIRING_V4_EXTRACT_REFUSED
        not in tool.HISTORICAL_PAIRING_V4_EXTRACT_ERROR_CODES
    )
    forged = tool.HistoricalPairingV4ExtractError("HISTORICAL_PAIRING_V4_FORGED")
    assert forged.code == tool.HISTORICAL_PAIRING_V4_EXTRACT_REFUSED

    class Forged(tool.HistoricalPairingV4ExtractError):
        @property
        def code(self):
            return "C:/secret/path.json"

    def raising(_path):
        raise Forged()

    monkeypatch.setattr(tool, "_extract_standalone_v4_bytes", raising)
    with pytest.raises(Forged):
        tool.main(_argv(tmp_path / "w.json", tmp_path / "o.json"))
    captured = capfdbinary.readouterr()
    assert captured.out == b"" and captured.err == b""

    monkeypatch.undo()
    monkeypatch.setattr(
        tool,
        "_extract_standalone_v4_bytes",
        lambda _path: (_ for _ in ()).throw(
            tool.HistoricalPairingV4ExtractError("HISTORICAL_PAIRING_V4_FORGED")
        ),
    )
    assert tool.main(_argv(tmp_path / "w.json", tmp_path / "o.json")) == EXIT
    captured = capfdbinary.readouterr()
    assert captured.out == b""
    assert captured.err == _error_line(tool.HISTORICAL_PAIRING_V4_EXTRACT_REFUSED)


# ---------------------------------------------------------------------------
# Output path and create-only writer.
# ---------------------------------------------------------------------------


def test_output_is_created_with_exact_create_only_binary_mode(
    tmp_path: Path, document, monkeypatch: pytest.MonkeyPatch, capfdbinary
):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    output = tmp_path / "sub" / "out.json"
    output.parent.mkdir()
    calls: list = []
    original_open = builtins.open

    def recording_open(target, mode="r", *args, **kwargs):
        calls.append((Path(os.fsdecode(target)), mode, args, kwargs))
        return original_open(target, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", recording_open)
    assert tool.main(_argv(wrapper, output)) == 0
    capfdbinary.readouterr()
    assert calls[-1] == (output, "xb", (), {})


@pytest.mark.parametrize("existing", ["file", "directory", "symlink", "dangling"])
def test_any_existing_output_component_is_refused(
    tmp_path: Path, document, existing: str, capfdbinary
):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    output = tmp_path / "out.json"
    preserved = None
    if existing == "file":
        preserved = b"pre-existing partial output"
        output.write_bytes(preserved)
    elif existing == "directory":
        output.mkdir()
    else:
        target = tmp_path / "link-target.json"
        if existing == "symlink":
            target.write_bytes(b"target")
        try:
            output.symlink_to(target)
        except (OSError, NotImplementedError) as failure:
            pytest.skip(f"platform cannot create a test symlink: {failure}")

    assert tool.main(_argv(wrapper, output)) == EXIT
    captured = capfdbinary.readouterr()
    assert captured.out == b""
    assert captured.err == _error_line(tool.HISTORICAL_PAIRING_V4_OUTPUT_EXISTS)
    if preserved is not None:
        assert output.read_bytes() == preserved


def test_missing_output_parent_is_refused_and_never_created(
    tmp_path: Path, document, capfdbinary
):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    parent = tmp_path / "absent-parent"
    output = parent / "out.json"
    assert tool.main(_argv(wrapper, output)) == EXIT
    captured = capfdbinary.readouterr()
    assert captured.out == b""
    assert captured.err == _error_line(
        tool.HISTORICAL_PAIRING_V4_OUTPUT_UNAVAILABLE
    )
    assert not parent.exists()
    assert not output.exists()


@pytest.mark.parametrize(
    "candidate", ["relative-out.json", "~/out.json", "$HOME/out.json"]
)
def test_relative_and_unexpanded_output_locators_are_path_invalid(
    tmp_path: Path, document, candidate: str, capfdbinary
):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    assert tool.main(_argv(wrapper, Path(candidate))) == EXIT
    captured = capfdbinary.readouterr()
    assert captured.out == b""
    assert captured.err == _error_line(tool.HISTORICAL_PAIRING_V4_OUTPUT_PATH_INVALID)
    assert not (Path.cwd() / candidate).exists()


class _ChunkedHandle:
    """A handle that writes at most ``limit`` bytes per call, like a short write."""

    def __init__(self, handle, limit: int):
        self._handle = handle
        self._limit = limit
        self.writes: list = []
        self.flushed = 0

    def write(self, data):
        chunk = bytes(data)[: self._limit]
        self.writes.append(len(chunk))
        return self._handle.write(chunk)

    def flush(self):
        self.flushed += 1
        return self._handle.flush()

    def fileno(self):
        return self._handle.fileno()

    def close(self):
        return self._handle.close()


@pytest.mark.parametrize("limit", [1, 7, 1024])
def test_complete_write_under_simulated_short_writes(
    tmp_path: Path, document, canonical, limit: int,
    monkeypatch: pytest.MonkeyPatch, capfdbinary,
):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    output = tmp_path / "out.json"
    original_open = builtins.open
    handles: list = []

    def chunked_open(target, mode="r", *args, **kwargs):
        handle = original_open(target, mode, *args, **kwargs)
        if mode == "xb":
            wrapped = _ChunkedHandle(handle, limit)
            handles.append(wrapped)
            return wrapped
        return handle

    monkeypatch.setattr(builtins, "open", chunked_open)
    assert tool.main(_argv(wrapper, output)) == 0
    capfdbinary.readouterr()
    assert len(handles) == 1
    assert sum(handles[0].writes) == len(canonical)
    assert len(handles[0].writes) >= len(canonical) // limit
    assert output.read_bytes() == canonical


def test_flush_and_fsync_both_occur_in_order(
    tmp_path: Path, document, monkeypatch: pytest.MonkeyPatch, capfdbinary
):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    output = tmp_path / "out.json"
    order: list = []
    original_open = builtins.open
    original_fsync = os.fsync

    class Observed(_ChunkedHandle):
        def write(self, data):
            order.append("write")
            return super().write(data)

        def flush(self):
            order.append("flush")
            return super().flush()

    def observed_open(target, mode="r", *args, **kwargs):
        handle = original_open(target, mode, *args, **kwargs)
        if mode == "xb":
            return Observed(handle, 1 << 30)
        return handle

    def observed_fsync(descriptor):
        order.append("fsync")
        return original_fsync(descriptor)

    monkeypatch.setattr(builtins, "open", observed_open)
    monkeypatch.setattr(os, "fsync", observed_fsync)
    assert tool.main(_argv(wrapper, output)) == 0
    capfdbinary.readouterr()
    assert order == ["write", "flush", "fsync"]


def test_standalone_output_has_no_trailing_newline_bom_or_envelope(
    tmp_path: Path, harness, document, canonical, capfdbinary
):
    output = _accepts(
        tmp_path,
        _run_preflight_metadata_wrapper(document, harness.attestation),
        canonical,
        capfdbinary,
    )
    raw = output.read_bytes()
    assert not raw.endswith(b"\n")
    assert not raw.endswith(b"\r\n")
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert raw.startswith(b"{") and raw.endswith(b"}")
    assert b'"authorization_payload"' not in raw
    assert b'"status"' not in raw
    assert b'"classification"' not in raw
    assert b'"attestation"' not in raw
    assert json.loads(raw.decode("utf-8")) == document


def test_write_failure_removes_only_the_created_output(
    tmp_path: Path, document, monkeypatch: pytest.MonkeyPatch, capfdbinary
):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    decoy = tmp_path / "decoy.json"
    decoy.write_bytes(b"decoy content")
    output = tmp_path / "out.json"
    original_open = builtins.open
    removed: list = []
    original_unlink = os.unlink

    class Failing(_ChunkedHandle):
        def write(self, data):
            super().write(data)
            raise OSError("simulated device failure")

    def failing_open(target, mode="r", *args, **kwargs):
        handle = original_open(target, mode, *args, **kwargs)
        if mode == "xb":
            return Failing(handle, 4)
        return handle

    def recording_unlink(target, *args, **kwargs):
        removed.append(Path(os.fsdecode(target)))
        return original_unlink(target, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", failing_open)
    monkeypatch.setattr(os, "unlink", recording_unlink)
    assert tool.main(_argv(wrapper, output)) == EXIT
    captured = capfdbinary.readouterr()
    assert captured.out == b""
    assert captured.err == _error_line(
        tool.HISTORICAL_PAIRING_V4_OUTPUT_WRITE_REFUSED
    )
    assert removed == [output]
    assert not output.exists()
    assert decoy.read_bytes() == b"decoy content"
    assert wrapper.exists()


def test_create_only_publication_is_documented_as_non_atomic():
    """The limitation is stated, not tested away."""

    doc = " ".join(tool.__doc__.split())
    assert "create-only, not crash-atomic" in doc
    assert "abrupt process termination may leave a partial create-only output" in doc
    assert "never silently overwritten" in doc
    assert "remove it explicitly before" in doc
    assert "No temporary sibling, directory scan or automatic backup exists." in doc
    source = MODULE_PATH.read_text(encoding="utf-8")
    for forbidden in ("mkstemp", "NamedTemporaryFile", "mkdtemp", "os.replace", "rename"):
        assert forbidden not in source


def test_partial_create_only_output_is_never_silently_overwritten(
    tmp_path: Path, document, capfdbinary
):
    """The exact state an abrupt termination can leave behind is refused."""

    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    output = tmp_path / "out.json"
    partial = _oracle_canonical_bytes(document)[:64]
    output.write_bytes(partial)
    assert tool.main(_argv(wrapper, output)) == EXIT
    captured = capfdbinary.readouterr()
    assert captured.out == b""
    assert captured.err == _error_line(tool.HISTORICAL_PAIRING_V4_OUTPUT_EXISTS)
    assert output.read_bytes() == partial


# ---------------------------------------------------------------------------
# Operation order.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "wrapper_bytes",
    [
        b"not json",
        b'{"no_member": 1}',
        b'{"authorization_payload": []}',
        b'{"authorization_payload": {"a": 1}}',
    ],
)
def test_refused_wrapper_never_touches_the_output_locator(
    tmp_path: Path, wrapper_bytes: bytes, monkeypatch: pytest.MonkeyPatch, capfdbinary
):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(wrapper_bytes)
    output = tmp_path / "out.json"
    touched: list = []
    original_open = builtins.open
    original_lstat = os.lstat

    def recording_open(target, mode="r", *args, **kwargs):
        touched.append(("open", Path(os.fsdecode(target))))
        return original_open(target, mode, *args, **kwargs)

    def recording_lstat(target, *args, **kwargs):
        touched.append(("lstat", Path(os.fsdecode(target))))
        return original_lstat(target, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", recording_open)
    monkeypatch.setattr(os, "lstat", recording_lstat)
    assert tool.main(_argv(wrapper, output)) == EXIT
    capfdbinary.readouterr()
    assert touched == [("lstat", wrapper), ("open", wrapper)]
    assert not output.exists()


# ---------------------------------------------------------------------------
# CLI surface.
# ---------------------------------------------------------------------------


def test_parser_exposes_exactly_two_required_locator_inputs():
    parser = tool._parser()
    assert parser.allow_abbrev is False
    options = {
        option
        for action in parser._actions
        for option in action.option_strings
        if option != "-h" and option != "--help"
    }
    assert options == {"--wrapper-file", "--output-file"}
    for action in parser._actions:
        if action.dest in {"wrapper_file", "output_file"}:
            assert action.required is True
            assert action.type is Path


def test_parser_preserves_locator_lexemes_without_expansion_or_io(
    monkeypatch: pytest.MonkeyPatch,
):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("argparse touched the filesystem")

    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(os.path, "realpath", forbidden)
    monkeypatch.setattr(os.path, "expanduser", forbidden)
    monkeypatch.setattr(os.path, "expandvars", forbidden)
    lexemes = ["~/w.json", "$HOME/o.json"]
    args = tool._parser().parse_args(
        ["--wrapper-file", lexemes[0], "--output-file", lexemes[1]]
    )
    assert os.fspath(args.wrapper_file) == os.fspath(Path(lexemes[0]))
    assert os.fspath(args.output_file) == os.fspath(Path(lexemes[1]))
    assert "~" in os.fspath(args.wrapper_file)
    assert "$HOME" in os.fspath(args.output_file)


@pytest.mark.parametrize(
    "abbreviation", ["--wrapper", "--wrapper-f", "--output", "--output-f"]
)
def test_abbreviations_are_usage_errors(
    tmp_path: Path, abbreviation: str, capsys
):
    with pytest.raises(SystemExit) as exit_state:
        tool.main(
            [
                abbreviation,
                os.fspath(tmp_path / "w.json"),
                "--output-file",
                os.fspath(tmp_path / "o.json"),
            ]
        )
    assert exit_state.value.code == 2
    captured = capsys.readouterr()
    assert "unrecognized arguments" in captured.err or "required" in captured.err


def test_help_is_exit_zero_and_missing_argument_is_exit_two(capsys):
    with pytest.raises(SystemExit) as helped:
        tool.main(["--help"])
    assert helped.value.code == 0
    assert "--wrapper-file" in capsys.readouterr().out

    with pytest.raises(SystemExit) as usage:
        tool.main([])
    assert usage.value.code == 2


def test_no_forbidden_locator_or_execution_option_is_exposed():
    parser = tool._parser()
    exposed = {
        option for action in parser._actions for option in action.option_strings
    }
    for forbidden in (
        "--run-root",
        "--evidence-root",
        "--evidence-directory",
        "--search-root",
        "--glob",
        "--payload-fingerprint",
        "--payload",
        "--stdin",
        "--server-url",
        "--archive-root",
        "--secret-file",
        "--tag",
        "--confirm",
        "--execute",
    ):
        assert forbidden not in exposed


# ---------------------------------------------------------------------------
# Claims.
# ---------------------------------------------------------------------------


def test_success_stdout_is_exactly_one_native_line_with_empty_stderr(
    tmp_path: Path, document, capfdbinary
):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    output = tmp_path / "out.json"
    assert tool.main(_argv(wrapper, output)) == 0
    captured = capfdbinary.readouterr()
    assert captured.out == b"status=STANDALONE_V4_WRITTEN" + os.linesep.encode("ascii")
    assert captured.out.count(b"STANDALONE_V4_WRITTEN") == 1
    assert captured.err == b""


def test_emitted_bytes_carry_no_path_payload_or_outcome_material(
    tmp_path: Path, harness, document, canonical, capfdbinary
):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_preflight_only_wrapper(document, harness.attestation))
    output = tmp_path / "out.json"
    assert tool.main(_argv(wrapper, output)) == 0
    captured = capfdbinary.readouterr()
    emitted = captured.out + captured.err
    for material in (
        os.fspath(wrapper).encode("utf-8"),
        os.fspath(output).encode("utf-8"),
        document["run_id"].encode("utf-8"),
        document["payload_fingerprint"].encode("ascii"),
        SIBLING_SENTINEL.encode("utf-8"),
        canonical,
    ):
        assert material not in emitted


def test_no_emitted_or_documented_wording_implies_an_outcome():
    doc = " ".join(tool.__doc__.split()).lower()
    emitted = SUCCESS_LINE.decode("ascii").lower()
    for claim in (
        "verified",
        "accepted",
        "authorized",
        "admissible",
        "successful run",
        "proven execution",
        "eligible",
        "admitted",
    ):
        assert claim not in emitted
    # The module names each claim only to disclaim it.
    for claim, disclaimer in (
        ("verified", "not thereby"),
        ("proven execution", "not thereby"),
    ):
        assert claim in doc and disclaimer in doc
    assert "status=standalone_v4_written" == emitted.strip().lower()


@pytest.mark.parametrize("code", sorted(tool.HISTORICAL_PAIRING_V4_EXTRACT_ERROR_CODES))
def test_every_bounded_code_renders_one_fixed_ascii_line(code: str, capfdbinary):
    tool._write_refusal(code)
    captured = capfdbinary.readouterr()
    assert captured.err == _error_line(code)
    assert captured.out == b""
    assert code == code.upper()
    assert set(code) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def test_frozen_error_code_membership_is_exactly_the_ten_declared_codes():
    assert tool.HISTORICAL_PAIRING_V4_EXTRACT_ERROR_CODES == frozenset(
        {
            "HISTORICAL_PAIRING_V4_WRAPPER_PATH_INVALID",
            "HISTORICAL_PAIRING_V4_WRAPPER_UNAVAILABLE",
            "HISTORICAL_PAIRING_V4_WRAPPER_TOO_LARGE",
            "HISTORICAL_PAIRING_V4_WRAPPER_MALFORMED",
            "HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_MISSING",
            "HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED",
            "HISTORICAL_PAIRING_V4_OUTPUT_PATH_INVALID",
            "HISTORICAL_PAIRING_V4_OUTPUT_EXISTS",
            "HISTORICAL_PAIRING_V4_OUTPUT_UNAVAILABLE",
            "HISTORICAL_PAIRING_V4_OUTPUT_WRITE_REFUSED",
        }
    )
    assert type(tool.HISTORICAL_PAIRING_V4_EXTRACT_ERROR_CODES) is frozenset
    assert tool.HISTORICAL_PAIRING_V4_EXTRACT_EXIT_CODE == 3


def test_unexpected_unrelated_exception_preserves_ordinary_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfdbinary
):
    class UnrelatedDefect(RuntimeError):
        pass

    def raising(_path):
        raise UnrelatedDefect("unrelated")

    monkeypatch.setattr(tool, "_extract_standalone_v4_bytes", raising)
    with pytest.raises(UnrelatedDefect):
        tool.main(_argv(tmp_path / "w.json", tmp_path / "o.json"))
    captured = capfdbinary.readouterr()
    assert captured.out == b""
    assert captured.err == b""


# ---------------------------------------------------------------------------
# Import boundary.
# ---------------------------------------------------------------------------


def test_operator_package_initializer_is_still_completely_inert():
    source = INIT_PATH.read_text(encoding="utf-8")
    assert source.strip() == ""
    assert ast.parse(source).body == []


def test_direct_import_set_is_exactly_the_allowed_narrow_set():
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module)
    assert imported == [
        "argparse",
        "json",
        "os",
        "pathlib",
        "stat",
        "sys",
        "admissible.delegated_gate.canonical",
        "admissible.delegated_gate.native_canary",
    ]


def test_production_module_names_no_forbidden_surface_in_executable_source():
    """Executable identifiers only.

    Prose in the module docstring legitimately mentions globbing and scanning
    in order to disclaim them, so the check is made against the identifiers the
    module actually executes rather than against raw source text.
    """

    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    identifiers = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                identifiers.update(alias.name.split("."))
                if alias.asname:
                    identifiers.add(alias.asname)
        elif isinstance(node, ast.ImportFrom):
            identifiers.update((node.module or "").split("."))
            for alias in node.names:
                identifiers.add(alias.name)
    for forbidden in (
        "historical_pairing_registry",
        "MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES",
        "ProductLauncher",
        "product_launcher",
        "product_service",
        "product_ui",
        "historical_pairing_workflow",
        "historical_pairing_confirmation",
        "historical_evaluation_store",
        "historical_pairing_review",
        "subprocess",
        "socket",
        "http",
        "urllib",
        "glob",
        "rglob",
        "listdir",
        "scandir",
        "iterdir",
        "walk",
        "makedirs",
        "mkdir",
        "rename",
        "replace",
        "expanduser",
        "expandvars",
        "resolve",
        "realpath",
        "parent",
        "exists",
    ):
        assert forbidden not in identifiers, forbidden
    # Names that no honest prose in this module can contain.
    for forbidden in (
        "MAX_HISTORICAL_PAYLOAD_DOCUMENT_BYTES",
        "ProductLauncher",
        "product_launcher",
        "historical_pairing_registry",
    ):
        assert forbidden not in source, forbidden


def test_fresh_import_loads_no_product_registry_service_ui_or_transport_module(
    tmp_path: Path,
):
    """The extractor is honestly heavier than the tag helper.

    It must import the accepted V4 loader, and that loader lives beside the
    execution modules by construction.  What is proven here is the exact set of
    product-surface modules that stay absent, not a claim that importing
    ``native_canary`` is lightweight or execution-free.
    """

    program = textwrap.dedent(
        """
        import json
        import sys
        import admissible.operator_tools.historical_pairing_v4_extract
        forbidden = (
            "admissible.product_launcher",
            "admissible.product_service",
            "admissible.product_ui",
            "admissible.product_read_model",
            "admissible.browser_runtime",
            "admissible.v0_controller",
        )
        print(json.dumps({
            "forbidden": sorted(
                name for name in sys.modules
                if any(name == item or name.startswith(item + ".")
                       for item in forbidden)
            ),
            "loader": "admissible.delegated_gate.native_canary" in sys.modules,
        }))
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
    observed = json.loads(completed.stdout)
    assert observed["forbidden"] == []
    assert observed["loader"] is True
    assert completed.stderr == ""


# ---------------------------------------------------------------------------
# Behavioural no-execution, no-discovery observation.
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
    """Record every file, metadata, mutation, contact and scan operation."""

    def __init__(self, *, allowed_reads, allowed_writes):
        self.events: list = []
        self.allowed_reads = [Path(item) for item in allowed_reads]
        self.allowed_writes = [Path(item) for item in allowed_writes]
        self._saved: list = []

    def _target(self, value):
        try:
            return Path(os.fsdecode(value))
        except (TypeError, ValueError):
            return None

    def record(self, kind, target, *, writing):
        self.events.append((kind, self._target(target), bool(writing)))

    def unauthorized(self):
        findings = []
        for kind, target, writing in self.events:
            allowed = self.allowed_writes if writing else self.allowed_reads
            if target not in allowed:
                findings.append((kind, target, writing))
        return findings

    def kinds(self):
        return [kind for kind, _target, _writing in self.events]

    def _patch(self, owner, name, replacement):
        self._saved.append((owner, name, getattr(owner, name)))
        setattr(owner, name, replacement)

    def _open_spy(self, kind, original):
        def spy(target, mode="r", *args, **kwargs):
            writing = any(flag in str(mode) for flag in _WRITE_OPEN_FLAGS)
            self.record(kind, target, writing=writing)
            return original(target, mode, *args, **kwargs)

        return spy

    def _os_open_spy(self, original):
        def spy(target, flags, *args, **kwargs):
            self.record("os.open", target, writing=bool(flags & _OS_WRITE_FLAGS))
            return original(target, flags, *args, **kwargs)

        return spy

    def _metadata_spy(self, kind, original):
        def spy(target, *args, **kwargs):
            self.record(kind, target, writing=False)
            return original(target, *args, **kwargs)

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
            raise AssertionError(f"forbidden runtime surface reached: {kind}")

        return spy

    def install(self):
        import http.client
        import socket
        import urllib.request

        self._patch(builtins, "open", self._open_spy("builtins.open", builtins.open))
        self._patch(io, "open", self._open_spy("io.open", io.open))
        self._patch(os, "open", self._os_open_spy(os.open))
        self._patch(Path, "open", self._open_spy("Path.open", Path.open))
        for name in ("lstat", "stat"):
            self._patch(
                os, name, self._metadata_spy(f"os.{name}", getattr(os, name))
            )
        for name in ("write_bytes", "write_text", "touch", "mkdir"):
            self._patch(
                Path, name, self._mutation_spy(f"Path.{name}", getattr(Path, name))
            )
        for name in ("rename", "replace", "remove", "unlink", "mkdir", "makedirs"):
            self._patch(
                os, name, self._mutation_spy(f"os.{name}", getattr(os, name))
            )
        for name in ("mkstemp", "NamedTemporaryFile", "mkdtemp"):
            self._patch(
                tempfile,
                name,
                self._temporary_spy(f"tempfile.{name}", getattr(tempfile, name)),
            )
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
            self._patch(subprocess, name, self._forbidden_spy(f"subprocess.{name}"))
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
def _observed_runtime(*, allowed_reads, allowed_writes):
    import http.client  # noqa: F401  (imported before the window opens)
    import socket  # noqa: F401
    import urllib.request  # noqa: F401

    observer = SideEffectObserver(
        allowed_reads=allowed_reads, allowed_writes=allowed_writes
    )
    environment_before = dict(os.environ)
    observer.install()
    try:
        yield observer
    finally:
        observer.remove()
    assert dict(os.environ) == environment_before


def _warm_up(root: Path, document: dict, capfdbinary) -> None:
    """One invocation before observation so no import is attributed to it."""

    wrapper = root / "warm-wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    assert tool.main(_argv(wrapper, root / "warm-out.json")) == 0
    capfdbinary.readouterr()


def test_successful_invocation_touches_only_the_two_configured_paths(
    tmp_path: Path, harness, document, canonical, capfdbinary
):
    _warm_up(tmp_path, document, capfdbinary)
    # A decoy evidence neighbourhood the utility must never discover.
    evidence = harness.run_root
    wrapper = tmp_path / "canary-preflight.json"
    wrapper.write_bytes(_preflight_only_wrapper(document, harness.attestation))
    for sibling in (
        "native-result.json",
        "terminal-record.json",
        "checkpoint.json",
        "disposition.json",
        "acceptance.json",
        "manifest.json",
        "attestation.json",
    ):
        (tmp_path / sibling).write_bytes(b"{}")
    # A real derivable evidence directory beside the wrapper: any path
    # arithmetic that reaches it succeeds rather than failing harmlessly.
    (tmp_path / "evidence").mkdir()
    output = tmp_path / "standalone-v4.json"

    with _observed_runtime(
        allowed_reads=[wrapper, output], allowed_writes=[output]
    ) as observer:
        assert tool.main(_argv(wrapper, output)) == 0
    capfdbinary.readouterr()

    assert observer.unauthorized() == []
    assert observer.kinds() == [
        "os.lstat",
        "builtins.open",
        "os.lstat",
        "builtins.open",
    ]
    assert output.read_bytes() == canonical
    assert not evidence.exists()


def test_bounded_refusal_creates_and_removes_nothing(
    tmp_path: Path, document, capfdbinary
):
    _warm_up(tmp_path, document, capfdbinary)
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(b'{"authorization_payload": {"a": 1}}')
    output = tmp_path / "never.json"

    with _observed_runtime(allowed_reads=[wrapper], allowed_writes=[]) as observer:
        assert tool.main(_argv(wrapper, output)) == EXIT
    capfdbinary.readouterr()

    assert observer.unauthorized() == []
    assert observer.kinds() == ["os.lstat", "builtins.open"]
    assert not output.exists()


def test_observer_detects_an_illicit_sibling_read_and_a_derived_root_probe(
    tmp_path: Path, document, capfdbinary
):
    """The observer really fails when the forbidden action is performed."""

    _warm_up(tmp_path, document, capfdbinary)
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    sibling = tmp_path / "native-result.json"
    sibling.write_bytes(b"{}")

    with _observed_runtime(allowed_reads=[wrapper], allowed_writes=[]) as observer:
        with open(sibling, "rb") as handle:
            handle.read()
        with contextlib.suppress(OSError):
            os.lstat(tmp_path / "derived-run-root")  # a deliberate derived probe
    findings = {target for _kind, target, _writing in observer.unauthorized()}
    assert sibling in findings

    with pytest.raises(AssertionError, match="forbidden runtime surface"):
        with _observed_runtime(allowed_reads=[], allowed_writes=[]):
            list(tmp_path.iterdir())


# ---------------------------------------------------------------------------
# Reference minimization.
# ---------------------------------------------------------------------------


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


def _assert_main_released(frame):
    assert frame.f_locals.get("canonical") is None
    assert frame.f_locals.get("line") is None
    assert "failure" not in frame.f_locals
    assert "raw" not in frame.f_locals
    assert "root" not in frame.f_locals


def test_success_release_of_main_locals(tmp_path: Path, document, capfdbinary):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_minimal_wrapper(document))
    output = tmp_path / "out.json"
    results: list = []
    frame = _main_return_frame(
        lambda: results.append(tool.main(_argv(wrapper, output)))
    )
    capfdbinary.readouterr()
    assert results == [0]
    _assert_main_released(frame)


@pytest.mark.parametrize(
    "scenario", ["wrapper-malformed", "v4-refused", "output-exists"]
)
def test_refusal_release_of_main_locals(
    tmp_path: Path, document, scenario: str, capfdbinary
):
    wrapper = tmp_path / "wrapper.json"
    output = tmp_path / "out.json"
    if scenario == "wrapper-malformed":
        wrapper.write_bytes(b"{")
    elif scenario == "v4-refused":
        wrapper.write_bytes(b'{"authorization_payload": {"a": 1}}')
    else:
        wrapper.write_bytes(_minimal_wrapper(document))
        output.write_bytes(b"existing")
    results: list = []
    frame = _main_return_frame(
        lambda: results.append(tool.main(_argv(wrapper, output)))
    )
    capfdbinary.readouterr()
    assert results == [EXIT]
    _assert_main_released(frame)


def test_helper_frames_release_every_wrapper_and_output_reference(
    tmp_path: Path, harness, document, capfdbinary
):
    wrapper = tmp_path / "wrapper.json"
    wrapper.write_bytes(_preflight_only_wrapper(document, harness.attestation))
    output = tmp_path / "out.json"
    frames: list = []
    watched = {
        tool._extract_standalone_v4_bytes.__code__,
        tool._write_standalone_v4_document.__code__,
    }

    def trace(frame, event, _argument):
        if frame.f_code in watched and event == "return":
            frames.append((frame.f_code.co_name, dict(frame.f_locals)))
        return trace

    previous = sys.gettrace()
    sys.settrace(trace)
    try:
        assert tool.main(_argv(wrapper, output)) == 0
    finally:
        sys.settrace(previous)
    capfdbinary.readouterr()

    observed = dict(frames)
    extraction = observed["_extract_standalone_v4_bytes"]
    for name in ("raw", "text", "root", "nested", "payload", "canonical"):
        assert extraction[name] is None, name
    assert observed["_write_standalone_v4_document"]["canonical"] is None
    assert observed["_write_standalone_v4_document"]["handle"] is None


# Owned-graph retention scan.

MAX_OWNED_GRAPH_DEPTH = 24
MAX_OWNED_GRAPH_NODES = 200000

OWNED_MODULES = frozenset({tool.__name__})

_INTERPRETER_OWNED_MODULE_KEYS = frozenset(
    {"__builtins__", "__loader__", "__spec__", "__cached__"}
)

_STRUCTURAL_TYPES = (functools.partial, MethodType, SimpleNamespace, BaseException)


class OwnedGraphBoundExceeded(AssertionError):
    """Deterministic failure raised when a declared traversal bound is hit."""


class OwnedGraphScanner:
    """Bounded, cycle-safe, descriptor-free application-owned retention walker."""

    def __init__(self, *, byte_forms, text_forms, owned_modules):
        self.owned_modules = owned_modules
        self.byte_forms = byte_forms
        self.text_forms = text_forms

    def disclosure_form(self, value):
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

    def _safe_label(self, key, index):
        if (
            type(key) is str
            and key.isidentifier()
            and self.disclosure_form(key) is None
        ):
            return key
        return "#%d" % index

    @staticmethod
    def _instance_namespace(value):
        try:
            namespace = object.__getattribute__(value, "__dict__")
        except AttributeError:
            return None
        return namespace if isinstance(namespace, dict) else None

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
            if vars(value).get("__module__") not in self.owned_modules:
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
        children = []
        index = 0
        while traceback_object is not None:
            frame = traceback_object.tb_frame
            if frame.f_globals.get("__name__") in self.owned_modules:
                children.append(
                    (f"{path}.__traceback__[{index}].f_locals", dict(frame.f_locals))
                )
            traceback_object = traceback_object.tb_next
            index += 1
        return children

    def scan(self, roots):
        findings = []
        visited = set()
        alive = []
        pending = [(name, value, 0) for name, value in roots.items()]
        cursor = 0
        examined = 0
        while cursor < len(pending):
            path, value, depth = pending[cursor]
            cursor += 1
            if depth > MAX_OWNED_GRAPH_DEPTH:
                raise OwnedGraphBoundExceeded(f"depth bound exceeded at {path}")
            marker = id(value)
            if marker in visited:
                continue
            visited.add(marker)
            alive.append(value)
            examined += 1
            if examined > MAX_OWNED_GRAPH_NODES:
                raise OwnedGraphBoundExceeded(f"node bound exceeded at {path}")
            form = self.disclosure_form(value)
            if form is not None:
                findings.append((path, form))
            for child_path, child in self._children(path, value):
                pending.append((child_path, child, depth + 1))
        assert len(alive) == examined
        return sorted(set(findings))


def _owned_roots():
    roots = {}
    for name, value in vars(tool).items():
        if name in _INTERPRETER_OWNED_MODULE_KEYS:
            continue
        roots[f"{tool.__name__}.{name}"] = value
    return roots


def _retention_scanner(wrapper_bytes: bytes, canonical: bytes):
    return OwnedGraphScanner(
        byte_forms={
            "wrapper-bytes": wrapper_bytes,
            "sibling-bytes": SIBLING_SENTINEL.encode("utf-8"),
            "output-bytes": canonical,
            "output-base64-bytes": base64.b64encode(canonical),
        },
        text_forms={
            "wrapper-text": wrapper_bytes.decode("utf-8"),
            "sibling-text": SIBLING_SENTINEL,
            "output-text": canonical.decode("utf-8"),
        },
        owned_modules=OWNED_MODULES,
    )


@pytest.mark.parametrize(
    "scenario",
    ["success", "wrapper-malformed", "v4-refused", "output-exists", "write-failure"],
)
def test_no_owned_root_retains_wrapper_sibling_or_output_material(
    tmp_path: Path, harness, document, canonical, scenario: str,
    monkeypatch: pytest.MonkeyPatch, capfdbinary,
):
    wrapper_bytes = _preflight_only_wrapper(document, harness.attestation)
    wrapper = tmp_path / "wrapper.json"
    output = tmp_path / "out.json"
    expected = EXIT
    if scenario == "success":
        wrapper.write_bytes(wrapper_bytes)
        expected = 0
    elif scenario == "wrapper-malformed":
        wrapper_bytes = wrapper_bytes[:-1]
        wrapper.write_bytes(wrapper_bytes)
    elif scenario == "v4-refused":
        wrapper_bytes = json.dumps(
            {"authorization_payload": {"a": 1}, "note": SIBLING_SENTINEL},
            sort_keys=True,
        ).encode("utf-8")
        wrapper.write_bytes(wrapper_bytes)
    elif scenario == "output-exists":
        wrapper.write_bytes(wrapper_bytes)
        output.write_bytes(b"existing")
    else:
        wrapper.write_bytes(wrapper_bytes)
        original_open = builtins.open

        class Failing(_ChunkedHandle):
            def write(self, data):
                raise OSError("simulated failure")

        def failing_open(target, mode="r", *args, **kwargs):
            handle = original_open(target, mode, *args, **kwargs)
            if mode == "xb":
                return Failing(handle, 4)
            return handle

        monkeypatch.setattr(builtins, "open", failing_open)

    assert tool.main(_argv(wrapper, output)) == expected
    capfdbinary.readouterr()
    monkeypatch.undo()

    scanner = _retention_scanner(wrapper_bytes, canonical)
    assert scanner.scan(_owned_roots()) == []


def test_retention_scanner_detects_each_required_witness(
    tmp_path: Path, harness, document, canonical
):
    wrapper_bytes = _preflight_only_wrapper(document, harness.attestation)
    scanner = _retention_scanner(wrapper_bytes, canonical)

    class Carrier:
        pass

    Carrier.__module__ = tool.__name__

    def owned_function():
        return None

    owned_function.__module__ = tool.__name__

    witnesses = {
        "module-global": {"witness": canonical},
        "nested-container": {"witness": {"deep": [{"held": SIBLING_SENTINEL}]}},
        "class-attribute": {"witness": Carrier},
        "partial": {"witness": functools.partial(owned_function, wrapper_bytes)},
        "exception-args": {"witness": RuntimeError(SIBLING_SENTINEL)},
    }
    Carrier.retained = wrapper_bytes

    for label, root in witnesses.items():
        findings = scanner.scan(root)
        assert findings, label


# ---------------------------------------------------------------------------
# Packaging.
# ---------------------------------------------------------------------------


def test_console_script_declarations_are_exact_and_existing_ones_are_unchanged():
    data = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))
    scripts = data["project"]["scripts"]
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
    assert data["tool"]["setuptools"]["package-data"]["admissible.product_ui"] == [
        "index.html",
        "app.css",
        "app.js",
    ]


def test_module_execution_uses_ordinary_sys_exit_of_main():
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    guards = [
        node
        for node in tree.body
        if isinstance(node, ast.If) and ast.unparse(node.test) == "__name__ == '__main__'"
    ]
    assert len(guards) == 1
    assert [ast.unparse(statement) for statement in guards[0].body] == [
        "sys.exit(main())"
    ]


@pytest.fixture(scope="module")
def installed_distribution(tmp_path_factory: pytest.TempPathFactory):
    """Build a wheel and an sdist outside the repository and install the wheel."""

    root = tmp_path_factory.mktemp("s5c2e0-dist")
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
    dist_root = root / "dist"
    dist_root.mkdir()
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    build = subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--wheel",
            "--sdist",
            "--no-isolation",
            "--outdir",
            os.fspath(dist_root),
        ],
        cwd=source_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    wheels = list(dist_root.glob("*.whl"))
    sdists = list(dist_root.glob("*.tar.gz"))
    assert len(wheels) == 1 and len(sdists) == 1
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
        sdist_path=sdists[0],
        install_root=install_root,
        run_root=run_root,
    )


def _installed_environment(install_root: Path) -> dict:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONPATH"] = os.fspath(install_root)
    return environment


def _script(install_root: Path, name: str) -> Path:
    candidates = sorted(
        candidate
        for directory in ("bin", "Scripts")
        for candidate in (install_root / directory).glob(f"{name}*")
        if candidate.is_file()
    )
    assert candidates, f"installed console script {name} missing under {install_root}"
    return candidates[0]


def _run_installed(command, distribution, arguments):
    return subprocess.run(
        [*command, *arguments],
        cwd=distribution.run_root,
        env=_installed_environment(distribution.install_root),
        capture_output=True,
        check=False,
    )


def test_built_distributions_carry_the_new_entrypoint_and_all_declared_assets(
    installed_distribution,
):
    with zipfile.ZipFile(installed_distribution.wheel_path) as archive:
        names = set(archive.namelist())
        assert "admissible/operator_tools/__init__.py" in names
        assert "admissible/operator_tools/historical_pairing_tag.py" in names
        assert "admissible/operator_tools/historical_pairing_v4_extract.py" in names
        for asset in ("index.html", "app.css", "app.js"):
            assert f"admissible/product_ui/{asset}" in names
        entry_points_name = next(
            name for name in names if name.endswith(".dist-info/entry_points.txt")
        )
        entry_points = archive.read(entry_points_name).decode("utf-8")
        for declaration in (
            "agent-os = agent_os.cli:main",
            "admissible = admissible.product_launcher.__main__:main",
            "admissible-historical-pairing-tag = "
            "admissible.operator_tools.historical_pairing_tag:main",
            "admissible-historical-pairing-v4-extract = "
            "admissible.operator_tools.historical_pairing_v4_extract:main",
        ):
            assert declaration in entry_points
        assert entry_points.count("admissible-historical-pairing-v4-extract") == 1

    assert installed_distribution.sdist_path.is_file()
    install_root = installed_distribution.install_root
    assert (install_root / "admissible" / "operator_tools" / "__init__.py").is_file()
    assert (
        install_root
        / "admissible"
        / "operator_tools"
        / "historical_pairing_v4_extract.py"
    ).is_file()
    assert (install_root / "admissible" / "product_ui" / "index.html").is_file()
    assert (
        install_root / "admissible" / "operator_tools" / "__init__.py"
    ).read_text(encoding="utf-8").strip() == ""


def test_installed_module_and_console_script_write_a_byte_exact_document(
    installed_distribution, harness, document, canonical
):
    run_root = installed_distribution.run_root
    wrapper = run_root / "canary-preflight.json"
    wrapper.write_bytes(_preflight_only_wrapper(document, harness.attestation))
    invocations = {
        "module": [
            sys.executable,
            "-m",
            "admissible.operator_tools.historical_pairing_v4_extract",
        ],
        "console-script": [
            os.fspath(
                _script(
                    installed_distribution.install_root,
                    "admissible-historical-pairing-v4-extract",
                )
            )
        ],
    }
    for label, command in invocations.items():
        output = run_root / f"standalone-{label}.json"
        completed = _run_installed(
            command, installed_distribution, _argv(wrapper, output)
        )
        assert completed.returncode == 0, (label, completed.stderr)
        assert completed.stdout == SUCCESS_LINE, label
        assert completed.stderr == b"", label
        assert output.read_bytes() == canonical, label


def test_installed_help_abbreviation_and_bounded_refusal_exit_codes(
    installed_distribution, harness, document
):
    run_root = installed_distribution.run_root
    wrapper = run_root / "refusal-wrapper.json"
    wrapper.write_bytes(_preflight_only_wrapper(document, harness.attestation))
    malformed = run_root / "malformed.json"
    malformed.write_bytes(b'{"authorization_payload": {"a": 1}}')
    existing = run_root / "already-present.json"
    existing.write_bytes(b"partial")

    commands = {
        "module": [
            sys.executable,
            "-m",
            "admissible.operator_tools.historical_pairing_v4_extract",
        ],
        "console-script": [
            os.fspath(
                _script(
                    installed_distribution.install_root,
                    "admissible-historical-pairing-v4-extract",
                )
            )
        ],
    }
    for label, command in commands.items():
        helped = _run_installed(command, installed_distribution, ["--help"])
        assert helped.returncode == 0, label
        assert b"--wrapper-file" in helped.stdout and b"--output-file" in helped.stdout
        assert helped.stderr == b""

        for abbreviation in ("--wrapper", "--wrapper-f", "--output", "--output-f"):
            abbreviated = _run_installed(
                command,
                installed_distribution,
                [
                    abbreviation,
                    os.fspath(wrapper),
                    "--output-file",
                    os.fspath(run_root / f"never-{label}.json"),
                ],
            )
            assert abbreviated.returncode == 2, (label, abbreviation)
            assert abbreviated.stdout == b""
            assert not (run_root / f"never-{label}.json").exists()

        refused = _run_installed(
            command,
            installed_distribution,
            _argv(malformed, run_root / f"never-malformed-{label}.json"),
        )
        assert refused.returncode == 3, label
        assert refused.stdout == b""
        assert refused.stderr == _error_line(
            tool.HISTORICAL_PAIRING_V4_AUTHORIZATION_PAYLOAD_REFUSED
        )

        clashed = _run_installed(
            command, installed_distribution, _argv(wrapper, existing)
        )
        assert clashed.returncode == 3, label
        assert clashed.stdout == b""
        assert clashed.stderr == _error_line(
            tool.HISTORICAL_PAIRING_V4_OUTPUT_EXISTS
        )
        assert existing.read_bytes() == b"partial"


def test_installed_tag_helper_remains_executable(installed_distribution):
    run_root = installed_distribution.run_root
    message = run_root / "tag-message.bin"
    secret = run_root / "tag-secret.bin"
    message.write_bytes(b"public confirmation message")
    secret.write_bytes(b"historical-pairing-secret-material")
    completed = _run_installed(
        [
            os.fspath(
                _script(
                    installed_distribution.install_root,
                    "admissible-historical-pairing-tag",
                )
            )
        ],
        installed_distribution,
        [
            "--message-file",
            os.fspath(message),
            "--secret-file",
            os.fspath(secret),
        ],
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == b""
    assert len(completed.stdout.strip()) == 64


def test_installed_distribution_resolves_without_a_source_tree_fallback(
    installed_distribution,
):
    probe = textwrap.dedent(
        """
        import json
        import sys
        import admissible
        import admissible.operator_tools
        import admissible.operator_tools.historical_pairing_v4_extract as helper
        print(json.dumps({
            "helper": helper.__file__,
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
    installed = os.path.normcase(os.fspath(installed_distribution.install_root))
    repository = os.path.normcase(os.fspath(ROOT))
    for key in ("helper", "package"):
        assert os.path.normcase(origins[key]).startswith(installed), key
    searched = (
        origins["sys_path"] + origins["package_path"] + origins["operator_path"]
    )
    for entry in searched:
        normalized = os.path.normcase(entry)
        assert normalized != repository
        assert not normalized.startswith(repository + os.sep)
