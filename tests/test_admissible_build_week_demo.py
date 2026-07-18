"""Act-3A: focused tests for the read-only Build Week demo generator.

Every context is the deterministic synthetic canary from the sibling
executor/acceptance harnesses; no live Cursor, provider, or backend is
reachable, and generation runs with every live capability trapped.  The
suite covers only the new demo surface: the frozen protocol keeps its own
test matrix.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from test_admissible_delegated_gate_native_executor import _rewrite_record, _tree_hashes
from test_admissible_native_checkpoint_acceptance import (
    _acceptance_context,
    _install_traps,
    _owner_statement,
    _review_args,
)

from admissible.build_week_demo import (
    BuildWeekDemoError,
    generate_build_week_demo,
    load_demo_facts,
    main,
)
from admissible.delegated_gate.native_acceptance import (
    NativeCheckpointReviewBindingStatus,
    record_native_checkpoint_acceptance,
    record_native_checkpoint_review_binding,
)
from admissible.delegated_gate.native_canary import CANARY_GATE_ID
from admissible.delegated_gate.native_executor import NativeExecutionStoreError
from admissible.delegated_gate.store import DelegatedGateStoreError

_BLOCKED = (BuildWeekDemoError, NativeExecutionStoreError, DelegatedGateStoreError, OSError, ValueError)
_ABSOLUTE_PATH = re.compile(r"[A-Za-z]:[\\/]")
_MISSION_OPENING = "Add deterministic high-score persistence to this small game-state package."
_COMMIT_MESSAGE = "feat: add deterministic high-score persistence"


def _accepted_context(tmp_path: Path, *, review_note: str | None = None):
    """One complete canonical-like run: success, review binding, acceptance."""

    if review_note is None:
        h, args = _acceptance_context(tmp_path)
    else:
        h, args = _acceptance_context(tmp_path, bind_review=False)
        outcome = record_native_checkpoint_review_binding(**{**_review_args(h), "note": review_note})
        assert outcome.status is NativeCheckpointReviewBindingStatus.REVIEW_BINDING_CREATED
        args["review_binding_fingerprint"] = outcome.review_binding.review_binding_fingerprint
        args["owner_statement"] = _owner_statement(args)
    record_native_checkpoint_acceptance(**args)
    return h


@pytest.fixture(scope="module")
def golden(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    """One shared canonical-like run with the page generated exactly once."""

    tmp = tmp_path_factory.mktemp("bw")
    h = _accepted_context(tmp)
    run_before = _tree_hashes(h.root)
    source_before = _tree_hashes(h.source)
    output = tmp / "site" / "index.html"
    destination, size, digest = generate_build_week_demo(h.root, output)
    return SimpleNamespace(
        h=h,
        output=destination,
        size=size,
        digest=digest,
        html=destination.read_text(encoding="utf-8"),
        run_before=run_before,
        source_before=source_before,
    )


def test_valid_fixture_renders_four_separate_statuses(golden, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    _install_traps(monkeypatch)
    output = tmp_path / "replay.html"
    generate_build_week_demo(golden.h.root, output)
    text = output.read_text(encoding="utf-8")
    for card_id in ("status-execution", "status-review", "status-acceptance", "status-archive"):
        assert f'id="{card_id}"' in text
    assert "CHECKPOINT_CAPTURED_CANARY_SUCCESS" in text
    assert text.count("PRESENT_VALID") >= 4  # two status cards plus two classification rows
    assert "ABSENT — intentionally outside this demo" in text
    assert _MISSION_OPENING in text
    assert _COMMIT_MESSAGE in text
    assert "npm" in text and "PASS" in text


def test_execution_reconstruction_failure_blocks_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h = _accepted_context(tmp_path)
    _rewrite_record(
        h.store._path("execution-eligibility", h.session_id, CANARY_GATE_ID, 0),
        lambda raw: raw.update({"eligible": False}),
        self_fingerprint="eligibility_fingerprint",
    )
    _install_traps(monkeypatch)
    with pytest.raises(_BLOCKED):
        load_demo_facts(h.root)
    output = tmp_path / "blocked" / "index.html"
    assert main(["--run-root", str(h.root), "--output", str(output)]) != 0
    page = output.read_text(encoding="utf-8")
    assert "CHECKPOINT_CAPTURED_CANARY_SUCCESS" not in page
    assert "PRESENT_VALID" not in page
    assert not _ABSOLUTE_PATH.search(page)


def test_missing_review_binding_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, _ = _acceptance_context(tmp_path, bind_review=False)
    _install_traps(monkeypatch)
    with pytest.raises(_BLOCKED, match="review binding classification is ABSENT"):
        load_demo_facts(h.root)


def test_missing_acceptance_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h, _ = _acceptance_context(tmp_path)
    _install_traps(monkeypatch)
    with pytest.raises(_BLOCKED, match="acceptance classification is ABSENT"):
        load_demo_facts(h.root)


def test_archive_lookalike_record_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    h = _accepted_context(tmp_path)
    lookalike = h.store.directory / f"{h.session_id}.{CANARY_GATE_ID}.attempt-0.native-archive.json"
    lookalike.write_text("{}", encoding="utf-8")
    _install_traps(monkeypatch)
    with pytest.raises(_BLOCKED, match="archive"):
        load_demo_facts(h.root)


def test_html_escaping_prevents_evidence_text_injection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    payload = '<script>alert("evidence")</script><img src=x onerror=alert(1)>'
    h = _accepted_context(tmp_path, review_note=payload)
    _install_traps(monkeypatch)
    output = tmp_path / "page.html"
    generate_build_week_demo(h.root, output)
    text = output.read_text(encoding="utf-8")
    assert payload not in text
    assert "<script>alert" not in text
    assert "<img" not in text
    assert "&lt;script&gt;alert" in text


def test_output_is_byte_deterministic(golden, tmp_path: Path):
    duplicate = tmp_path / "dup.html"
    _, size, digest = generate_build_week_demo(golden.h.root, duplicate)
    data = duplicate.read_bytes()
    assert data == golden.output.read_bytes()
    assert (size, digest) == (golden.size, golden.digest)
    assert data.endswith(b"\n") and not data.endswith(b"\n\n")


def test_no_external_resources_or_network_dependency(golden):
    lowered = golden.html.lower()
    for marker in ("http", "<link", "<img", "url(", "@import", "fetch(", "xmlhttprequest", "websocket", "src="):
        assert marker not in lowered, marker


def test_no_absolute_run_root_path_in_output(golden):
    assert str(golden.h.root) not in golden.html
    assert str(golden.h.work) not in golden.html
    assert str(golden.h.evidence) not in golden.html
    assert not _ABSOLUTE_PATH.search(golden.html)


def test_generation_modifies_only_the_output_file(golden):
    assert _tree_hashes(golden.h.root) == golden.run_before
    assert _tree_hashes(golden.h.source) == golden.source_before
    assert sorted(item.name for item in golden.output.parent.iterdir()) == ["index.html"]


def test_cli_success_reports_size_and_sha256(golden, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    _install_traps(monkeypatch)
    output = tmp_path / "cli" / "index.html"
    assert main(["--run-root", str(golden.h.root), "--output", str(output)]) == 0
    printed = capsys.readouterr().out
    data = output.read_bytes()
    assert f"bytes={len(data)}" in printed
    assert f"sha256={hashlib.sha256(data).hexdigest()}" in printed
    assert data == golden.output.read_bytes()


def test_cli_exits_nonzero_on_invalid_evidence(tmp_path: Path, capsys):
    empty_run_root = tmp_path / "empty-run"
    empty_run_root.mkdir()
    output = tmp_path / "invalid" / "index.html"
    assert main(["--run-root", str(empty_run_root), "--output", str(output)]) != 0
    page = output.read_text(encoding="utf-8")
    assert "validation failed" in page.lower()
    assert "PRESENT_VALID" not in page
    assert "CHECKPOINT_CAPTURED_CANARY_SUCCESS" not in page
    assert not _ABSOLUTE_PATH.search(page)


def test_output_beneath_run_root_is_refused(golden):
    inside = golden.h.root / "evidence" / "page.html"
    with pytest.raises(BuildWeekDemoError, match="outside the run root"):
        generate_build_week_demo(golden.h.root, inside)
    assert main(["--run-root", str(golden.h.root), "--output", str(inside)]) != 0
    assert not inside.exists()
    assert _tree_hashes(golden.h.root) == golden.run_before
