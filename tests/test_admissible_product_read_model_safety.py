"""Safety, discovery and independence tests for the product read model."""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

import admissible.product_read_model as prm
from admissible.product_read_model import (
    PresenceState,
    discover_runs,
    load_run_detail,
    load_run_root,
    render_result_json,
    render_run_html,
)
from admissible.product_read_model import evidence_reader
from admissible.product_read_model.evidence_reader import (
    ENV_OMITTED_MARKER,
    REDACTED_MARKER,
    read_json,
    resolve_root,
)
from tests.product_read_model.builders import (
    RunRootBuilder,
    build_behavioral_refusal,
    snapshot,
)


# --- reader: malformed / duplicate / oversized -------------------------------


def test_reader_reports_malformed_json_as_inconsistent(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "final-status.json").write_text("{not valid json", encoding="utf-8")
    read = read_json(resolve_root(tmp_path), "evidence/final-status.json")
    assert read.presence is PresenceState.INCONSISTENT
    assert "malformed" in (read.reason or "")


def test_reader_rejects_duplicate_keys(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "final-status.json").write_text('{"a": 1, "a": 2}', encoding="utf-8")
    read = read_json(resolve_root(tmp_path), "evidence/final-status.json")
    assert read.presence is PresenceState.INCONSISTENT
    assert "duplicate" in (read.reason or "")


def test_reader_reports_oversized_as_inconsistent(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "big.json").write_text('{"x": "' + "y" * 500 + '"}', encoding="utf-8")
    read = read_json(resolve_root(tmp_path), "evidence/big.json", max_bytes=32)
    assert read.presence is PresenceState.INCONSISTENT
    assert "oversized" in (read.reason or "")


def test_reader_missing_is_absent_not_inconsistent(tmp_path):
    read = read_json(resolve_root(tmp_path), "evidence/does-not-exist.json")
    assert read.presence is PresenceState.ABSENT
    assert read.reason is None


def test_reader_refuses_parent_traversal(tmp_path):
    outside = tmp_path.parent / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    read = read_json(resolve_root(tmp_path), "../outside.json")
    assert read.presence is PresenceState.INCONSISTENT
    assert "unsafe path" in (read.reason or "")


# --- reader: secret redaction ------------------------------------------------


def test_reader_redacts_secret_fields_and_env(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "s.json").write_text(
        '{"owner_phrase": "hunter2", "api_key": "sk-xyz", "password": "p", '
        '"session_token": "t", "environment": {"PATH": "x"}, "safe": "keep"}',
        encoding="utf-8",
    )
    read = read_json(resolve_root(tmp_path), "evidence/s.json")
    assert read.ok
    data = read.data
    assert data["owner_phrase"] == REDACTED_MARKER
    assert data["api_key"] == REDACTED_MARKER
    assert data["password"] == REDACTED_MARKER
    assert data["session_token"] == REDACTED_MARKER
    assert data["environment"] == ENV_OMITTED_MARKER
    assert data["safe"] == "keep"


def test_detail_json_never_contains_secret_values(tmp_path):
    b = RunRootBuilder(tmp_path / "run")
    b.preflight(secret=True).delegated_gate().request().attempt_reserved().process_started()
    b.process_observation(exit_code=0).result(exit_code=0).eligibility(eligible=True)
    b.behavioral(exit_code=1).terminal().final_status()
    detail = load_run_detail(tmp_path / "run")
    import json as _json

    blob = _json.dumps(detail.to_json()) + render_run_html(detail)
    assert "hunter2-secret" not in blob
    assert "sk-should-not-appear" not in blob
    assert "SECRET_ENV" not in blob
    assert "leak" not in blob


# --- reparse / symlink refusal ----------------------------------------------


def test_reader_refuses_symlink_leaf(tmp_path):
    outside = tmp_path.parent / "secret-target.json"
    outside.write_text('{"secret_data": 1}', encoding="utf-8")
    (tmp_path / "evidence").mkdir()
    link = tmp_path / "evidence" / "final-status.json"
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this host")
    read = read_json(resolve_root(tmp_path), "evidence/final-status.json")
    assert read.presence is PresenceState.INCONSISTENT
    assert "unsafe path" in (read.reason or "")


# --- no filesystem mutation --------------------------------------------------


def test_load_and_render_do_not_mutate(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    before = snapshot(root)
    detail = load_run_detail(root)
    render_result_json(detail)
    render_run_html(detail)
    load_run_root(root)
    after = snapshot(root)
    assert before == after


def test_discovery_does_not_mutate(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    build_behavioral_refusal(parent / "run-a")
    build_behavioral_refusal(parent / "run-b")
    before = snapshot(parent)
    discover_runs(parent)
    after = snapshot(parent)
    assert before == after


# --- discovery ---------------------------------------------------------------


def test_discovery_is_deterministic_and_lexical(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    for name in ("zeta", "alpha", "mike"):
        RunRootBuilder(parent / name, session_id=name).final_status()
    result = discover_runs(parent)
    names = [r.directory_name for r in result.runs]
    assert names == ["alpha", "mike", "zeta"]
    # stable across calls
    assert [r.directory_name for r in discover_runs(parent).runs] == names


def test_discovery_ignores_unrelated_directories(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    RunRootBuilder(parent / "real-run", session_id="real-run").final_status()
    (parent / "not-a-run").mkdir()
    (parent / "not-a-run" / "readme.txt").write_text("hi", encoding="utf-8")
    result = discover_runs(parent)
    assert [r.directory_name for r in result.runs] == ["real-run"]
    assert "not-a-run" in result.ignored_directories


def test_discovery_reports_duplicate_run_ids_as_conflict(tmp_path):
    parent = tmp_path / "parent"
    parent.mkdir()
    RunRootBuilder(parent / "dir-one", session_id="dupe").final_status()
    RunRootBuilder(parent / "dir-two", session_id="dupe").final_status()
    result = discover_runs(parent)
    assert result.conflicts
    conflict = result.conflicts[0]
    assert conflict.run_id == "dupe"
    assert len(conflict.run_roots) == 2


def test_explicit_run_root_can_be_loaded_directly(tmp_path):
    root = build_behavioral_refusal(tmp_path / "run")
    discovered = load_run_root(root)
    assert discovered.session_id == "run-synthetic"
    assert discovered.final_status_presence is PresenceState.PRESENT


def test_discovery_on_non_directory_is_safe(tmp_path):
    target = tmp_path / "afile"
    target.write_text("x", encoding="utf-8")
    result = discover_runs(target)
    assert result.runs == ()
    assert "not a directory" in " ".join(result.notes)


# --- registry independence (no production coupling) --------------------------


_FORBIDDEN_IMPORT_PREFIXES = (
    "admissible.delegated_gate",
    "admissible.review_surface",
    "admissible.product_service",
    "admissible.runner",
    "admissible.harness",
    "admissible.evaluator",
    "admissible.execution",
    "admissible.browser_runtime",
    "admissible.diagnostics",
    "admissible.v0_controller",
    "agent_os",
)


def _package_files() -> list[Path]:
    package_dir = Path(prm.__file__).parent
    return sorted(package_dir.glob("*.py"))


def test_read_model_imports_no_production_module():
    for path in _package_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue  # relative intra-package import
                module = node.module or ""
                assert not module.startswith(_FORBIDDEN_IMPORT_PREFIXES), f"{path.name} imports {module}"
                if module.startswith("admissible") and not module.startswith("admissible.product_read_model"):
                    raise AssertionError(f"{path.name} imports non-lane admissible module {module}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    assert not alias.name.startswith(_FORBIDDEN_IMPORT_PREFIXES), f"{path.name} imports {alias.name}"


def test_read_model_source_mentions_no_registry_or_profile():
    for path in _package_files():
        text = path.read_text(encoding="utf-8").lower()
        assert "profile_registry" not in text
        assert "import_profile" not in text


def test_changed_python_files_parse():
    for path in _package_files():
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
