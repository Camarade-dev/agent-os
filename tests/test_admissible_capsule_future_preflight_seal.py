"""Future preflight sealing is closed-world, root-bound and externally retained.

Every preparation here is a disposable temporary directory.  The historical V1
preparation, ``canary-preflight-v1``, owner-preflight trees and external spikes
are never written by this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from admissible.capsule.common import canonical_bytes, fingerprint
from admissible.capsule.preflight_seal import (
    FUTURE_PREFLIGHT_MANIFEST_PATH,
    FUTURE_PREFLIGHT_SEAL_PATH,
    RETAINED_SEAL_IDENTITY_SCHEMA_VERSION,
    SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION,
    FuturePreflightSealError,
    RetainedPreparationSealIdentity,
    observe_preparation_tree,
    publish_future_preflight_seal,
    validate_future_preflight_seal,
)
from tests._candidate_canary_binding import (
    build_sealed_candidate_preparation,
    candidate_canary_binding,
    write_owner_payload_file,
)


def _prepared(tmp_path: Path, **kwargs):
    prepared = build_sealed_candidate_preparation(tmp_path, **kwargs)
    return prepared["preparation_root"], prepared, prepared["sealed"]


def _revalidate(root: Path, prepared):
    return validate_future_preflight_seal(
        root=root,
        expected_model_binding_policy=prepared["policy"],
        expected_candidate_witness_receipt=prepared["receipt"],
        candidate_witness_store=prepared["store"],
        retained_seal_identity=prepared["retained_seal_identity"],
    )


def _writable(path: Path) -> Path:
    path.chmod(0o600)
    return path


def test_closed_world_manifest_covers_the_complete_tree_without_self_entry(
    tmp_path: Path,
):
    root, prepared, published = _prepared(tmp_path)
    reloaded = _revalidate(root, prepared)
    assert reloaded == published
    assert reloaded["closed_world"] is True
    assert reloaded["self_referential"] is False
    assert reloaded["classification"] == (
        SEALED_CANDIDATE_AWAITING_OWNER_AUTHORIZATION
    )
    assert FUTURE_PREFLIGHT_MANIFEST_PATH not in reloaded["covered_paths"]
    assert FUTURE_PREFLIGHT_SEAL_PATH not in reloaded["covered_paths"]
    observed = observe_preparation_tree(root)
    assert set(reloaded["covered_paths"]) == set(observed.covered_files)
    assert set(reloaded["expected_directories"]) == set(observed.directories)


def test_seal_binds_the_exact_preparation_root_identity(tmp_path: Path):
    root, _binding, published = _prepared(tmp_path)
    identity = published["preparation_root_identity"]
    live = os.lstat(root)
    assert identity["device"] == live.st_dev
    assert identity["inode"] == live.st_ino
    assert identity["root_type"] == "directory"


def test_added_file_anywhere_in_the_root_is_refused(tmp_path: Path):
    root, prepared, _published = _prepared(tmp_path)
    (root / "evidence" / "sneaked.txt").write_bytes(b"unlisted\n")
    with pytest.raises(FuturePreflightSealError, match="closed authorized entry set"):
        _revalidate(root, prepared)


def test_added_directory_is_refused(tmp_path: Path):
    root, prepared, _published = _prepared(tmp_path)
    (root / "extra-directory").mkdir()
    with pytest.raises(FuturePreflightSealError, match="closed authorized entry set"):
        _revalidate(root, prepared)


def test_unexpected_empty_directory_is_refused(tmp_path: Path):
    root, prepared, _published = _prepared(tmp_path)
    (root / "evidence" / "empty").mkdir()
    with pytest.raises(FuturePreflightSealError, match="closed authorized entry set"):
        _revalidate(root, prepared)


def test_removed_entry_is_refused(tmp_path: Path):
    root, prepared, _published = _prepared(tmp_path)
    _writable(root / "CANARY.txt").unlink()
    with pytest.raises(FuturePreflightSealError, match="closed authorized entry set"):
        _revalidate(root, prepared)


def test_renamed_entry_is_refused(tmp_path: Path):
    root, prepared, _published = _prepared(tmp_path)
    _writable(root / "CANARY.txt").rename(root / "CANARY-renamed.txt")
    with pytest.raises(FuturePreflightSealError, match="closed authorized entry set"):
        _revalidate(root, prepared)


def test_case_alias_of_a_covered_entry_is_refused(tmp_path: Path):
    root, prepared, _published = _prepared(tmp_path)
    (root / "canary.txt").write_bytes(b"admissible-chatgpt-codex-canary-v1\n")
    with pytest.raises(FuturePreflightSealError, match="alias"):
        _revalidate(root, prepared)


def test_symlinked_entry_in_the_tree_is_refused(tmp_path: Path):
    root, prepared, _published = _prepared(tmp_path)
    (root / "aliased.txt").symlink_to(root / "CANARY.txt")
    with pytest.raises(FuturePreflightSealError, match="symlink"):
        _revalidate(root, prepared)


def test_hardlinked_entry_in_the_tree_is_refused(tmp_path: Path):
    root, prepared, _published = _prepared(tmp_path)
    os.link(root / "CANARY.txt", root / "hardlinked.txt")
    with pytest.raises(FuturePreflightSealError, match="hardlink"):
        _revalidate(root, prepared)


def test_changed_covered_file_is_refused(tmp_path: Path):
    root, prepared, _published = _prepared(tmp_path)
    _writable(root / "CANARY.txt").write_bytes(
        b"admissible-chatgpt-codex-canary-v1\nextra\n"
    )
    with pytest.raises(FuturePreflightSealError, match="covered file changed"):
        _revalidate(root, prepared)


def test_changed_manifest_is_refused(tmp_path: Path):
    root, prepared, _published = _prepared(tmp_path)
    manifest = _writable(root / FUTURE_PREFLIGHT_MANIFEST_PATH)
    manifest.write_bytes(manifest.read_bytes() + b"\n")
    with pytest.raises(FuturePreflightSealError, match="final seal differs"):
        _revalidate(root, prepared)


def test_changed_final_seal_is_refused(tmp_path: Path):
    root, prepared, _published = _prepared(tmp_path)
    seal = _writable(root / FUTURE_PREFLIGHT_SEAL_PATH)
    value = json.loads(seal.read_text(encoding="utf-8"))
    value["seal_fingerprint"] = "0" * 64
    seal.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    with pytest.raises(FuturePreflightSealError, match="final seal differs"):
        _revalidate(root, prepared)


def test_byte_identical_copy_at_another_path_is_refused(tmp_path: Path):
    root, prepared, _published = _prepared(tmp_path)
    copied = tmp_path / "copied-preparation"
    shutil.copytree(root, copied)
    with pytest.raises(FuturePreflightSealError, match="copied, moved or re-created"):
        validate_future_preflight_seal(
            root=copied,
            expected_model_binding_policy=prepared["policy"],
            expected_candidate_witness_receipt=prepared["receipt"],
            candidate_witness_store=prepared["store"],
            retained_seal_identity=prepared["retained_seal_identity"],
        )


def test_expected_seal_fingerprint_cannot_be_retained_inside_the_preparation(
    tmp_path: Path,
):
    binding = candidate_canary_binding()
    root = tmp_path / "preparation"
    (root / "evidence").mkdir(parents=True)
    (root / "CANARY.txt").write_bytes(b"admissible-chatgpt-codex-canary-v1\n")
    write_owner_payload_file(
        path=root / "evidence" / "owner-payload.json",
        policy=binding["policy"],
        receipt=binding["receipt"],
    )
    with pytest.raises(FuturePreflightSealError, match="outside the preparation"):
        publish_future_preflight_seal(
            root=root,
            owner_payload_path="evidence/owner-payload.json",
            preparation_id="canary-preparation-inside-retention",
            run_id="canary-run-inside-retention",
            retained_seal_path=root / "evidence" / "expected-seal.json",
            model_binding_policy=binding["policy"],
            candidate_witness_receipt=binding["receipt"],
            candidate_witness_store=binding["store"],
        )


def test_internally_consistent_replacement_manifest_and_seal_are_refused(
    tmp_path: Path,
):
    """A consistent replacement pair still fails the externally retained identity."""

    root, prepared, _published = _prepared(tmp_path)
    manifest_path = _writable(root / FUTURE_PREFLIGHT_MANIFEST_PATH)
    seal_path = _writable(root / FUTURE_PREFLIGHT_SEAL_PATH)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["records"] = [
        record
        for record in manifest["records"]
        if record["relative_path"] != "CANARY.txt"
    ]
    manifest["manifest_fingerprint"] = fingerprint(
        {
            key: value
            for key, value in manifest.items()
            if key != "manifest_fingerprint"
        }
    )
    manifest_path.write_bytes(canonical_bytes(manifest))
    replacement_bytes = manifest_path.read_bytes()
    seal = json.loads(seal_path.read_text(encoding="utf-8"))
    seal["manifest_sha256"] = hashlib.sha256(replacement_bytes).hexdigest()
    seal["manifest_size"] = len(replacement_bytes)
    seal["manifest_fingerprint"] = manifest["manifest_fingerprint"]
    seal["seal_fingerprint"] = fingerprint(
        {key: value for key, value in seal.items() if key != "seal_fingerprint"}
    )
    seal_path.write_bytes(canonical_bytes(seal))
    with pytest.raises(FuturePreflightSealError, match="final seal differs"):
        _revalidate(root, prepared)


def test_replacement_expected_fingerprint_from_inside_the_preparation_is_refused(
    tmp_path: Path,
):
    root, _binding, published = _prepared(tmp_path)
    inside = root / "evidence" / "replacement-expected-seal.json"
    inside.write_text(
        json.dumps(
            {
                "schema_version": RETAINED_SEAL_IDENTITY_SCHEMA_VERSION,
                "preparation_root_identity": published[
                    "preparation_root_identity"
                ],
                "expected_manifest_fingerprint": published[
                    "manifest_fingerprint"
                ],
                "expected_seal_fingerprint": published["seal_fingerprint"],
                "retained_identity": published["retained_seal_identity"],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(FuturePreflightSealError, match="outside the preparation"):
        RetainedPreparationSealIdentity.load(retention_path=inside, root=root)


def test_manifest_refuses_a_missing_owner_payload_binding(tmp_path: Path):
    binding = candidate_canary_binding()
    root = tmp_path / "preparation"
    (root / "evidence").mkdir(parents=True)
    (root / "evidence" / "owner-payload.json").write_text(
        json.dumps({"schema_version": "future_owner_payload_v1"}),
        encoding="utf-8",
    )
    with pytest.raises(FuturePreflightSealError, match="does not bind"):
        publish_future_preflight_seal(
            root=root,
            owner_payload_path="evidence/owner-payload.json",
            preparation_id="canary-preparation-unbound-payload",
            run_id="canary-run-unbound-payload",
            retained_seal_path=tmp_path / "retained" / "expected-seal.json",
            model_binding_policy=binding["policy"],
            candidate_witness_receipt=binding["receipt"],
            candidate_witness_store=binding["store"],
        )


def test_extra_prepared_files_are_covered_rather_than_ignored(tmp_path: Path):
    root, prepared, published = _prepared(
        tmp_path,
        extra_files={
            "notes/plan.md": b"synthetic plan\n",
            "notes/nested/detail.txt": b"synthetic detail\n",
        },
    )
    assert "notes/plan.md" in published["covered_paths"]
    assert "notes/nested/detail.txt" in published["covered_paths"]
    assert "notes" in published["expected_directories"]
    assert "notes/nested" in published["expected_directories"]
    assert _revalidate(root, prepared) == published


def test_future_sealing_does_not_touch_a_historical_v1_preparation(
    tmp_path: Path,
):
    historical = tmp_path / "canary-preflight-v1"
    historical.mkdir()
    old = (
        b'{"classification":"CHATGPT_CODEX_CANARY_MODEL_UNRESOLVED",'
        b'"consumed":false,"schema_version":"historical_v1"}'
    )
    seal = historical / "preflight-seal.json"
    seal.write_bytes(old)
    before = seal.stat(), seal.read_bytes()
    _prepared(tmp_path / "future")
    after = seal.stat(), seal.read_bytes()
    assert after[1] == before[1]
    assert after[0].st_mtime_ns == before[0].st_mtime_ns
    assert b'"consumed":false' in after[1]
