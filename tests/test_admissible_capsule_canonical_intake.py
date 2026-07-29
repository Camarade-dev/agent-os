"""Provider-free tests for canonical intake: valid trees and every hostile category.

Everything here operates on real temporary directories on disk; nothing
invokes a provider, Docker, or a network transport.
"""

from __future__ import annotations

import os
import json
from pathlib import Path

import pytest

from admissible.capsule.intake import (
    NEON_RELAY_AUTHORITY,
    AcceptedMaterialIdentity,
    CanonicalIntake,
    IntakeAuthority,
    IntakeEvidence,
    IntakePublicationState,
    RejectionCode,
    path_policy_reasons,
    validate_and_copy,
)


def _write(path: Path, content: bytes = b"content") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _healthy_tree(root: Path) -> None:
    _write(root / "LOCAL_DEV.md", b"# dev notes\n")
    _write(root / "index.html", b"<html></html>\n")
    _write(root / "package.json", b'{"name": "neon-relay"}\n')
    _write(root / "style.css", b"body {}\n")
    for name in NEON_RELAY_AUTHORITY.authority_paths:
        if name.startswith("src/") or name.startswith("test/"):
            _write(root / name, f"// {name}\n".encode())


def test_healthy_baseline_is_accepted_and_bytes_are_copied(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    destination = tmp_path / "accepted"
    evidence_path = tmp_path / "evidence.json"

    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, destination, evidence_path)

    assert evidence.ruling == "ACCEPTED"
    assert evidence.published is True
    assert not evidence.rejection_reasons
    assert destination.is_dir()
    assert (destination / "index.html").read_bytes() == (source / "index.html").read_bytes()
    assert len(evidence.files) == len(NEON_RELAY_AUTHORITY.authority_paths)
    assert evidence_path.exists()
    identity = AcceptedMaterialIdentity.from_intake_evidence(evidence)
    assert identity.intake_authority_fingerprint == NEON_RELAY_AUTHORITY.authority_fingerprint
    assert identity.authorized_relative_paths == tuple(sorted(NEON_RELAY_AUTHORITY.authority_paths))
    assert identity.intake_evidence_fingerprint == evidence.evidence_fingerprint
    assert all(record.git_mode == "100644" for record in identity.files)
    replayed_evidence = IntakeEvidence.from_dict(json.loads(evidence_path.read_bytes()))
    assert AcceptedMaterialIdentity.from_intake_evidence(replayed_evidence) == identity


def test_rejected_intake_never_touches_destination(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    _write(source / "extra.txt", b"not authorized")
    destination = tmp_path / "accepted"
    evidence_path = tmp_path / "evidence.json"

    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, destination, evidence_path)

    assert evidence.ruling == "REJECTED"
    assert evidence.published is False
    assert not destination.exists()
    assert any(reason.code == RejectionCode.EXTRA_PATH for reason in evidence.rejection_reasons)


def test_accepted_identity_and_copy_preserve_exact_canonical_regular_file_modes(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    executable = source / "src" / "main.js"
    executable.chmod(0o755)
    destination = tmp_path / "accepted"
    evidence = validate_and_copy(
        source,
        NEON_RELAY_AUTHORITY,
        destination,
        tmp_path / "evidence.json",
    )
    identity = AcceptedMaterialIdentity.from_intake_evidence(evidence)
    modes = {record.relative_path: record.git_mode for record in identity.files}
    assert modes["src/main.js"] == "100755"
    assert (destination / "src" / "main.js").stat().st_mode & 0o777 == 0o755


def test_extra_directory_is_rejected(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    (source / "assets").mkdir()
    _write(source / "assets" / "sprite.png", b"\x89PNG")
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.EXTRA_DIRECTORY for reason in evidence.rejection_reasons)


def test_missing_file_is_rejected(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    (source / "src" / "main.js").unlink()
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.MISSING_PATH for reason in evidence.rejection_reasons)


def test_symlink_is_rejected(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    real = tmp_path / "outside.js"
    real.write_bytes(b"// outside\n")
    (source / "src" / "main.js").unlink()
    os.symlink(real, source / "src" / "main.js")
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.SYMLINK for reason in evidence.rejection_reasons)


def test_hard_link_is_rejected(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    target = source / "src" / "main.js"
    linked = source / "src" / "main2.js"
    os.link(target, linked)
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    codes = {reason.code for reason in evidence.rejection_reasons}
    assert RejectionCode.HARD_LINK in codes
    assert RejectionCode.EXTRA_PATH in codes


def test_fifo_is_rejected_as_special_file(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    (source / "src" / "main.js").unlink()
    os.mkfifo(source / "src" / "main.js")
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.SPECIAL_FILE for reason in evidence.rejection_reasons)


def test_case_collision_is_rejected(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    _write(source / "src" / "Game.js", b"// case-colliding path\n")
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.CASE_INSENSITIVE_COLLISION for reason in evidence.rejection_reasons)


def test_windows_reserved_basename_is_rejected(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    _write(source / "CON.txt", b"reserved")
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.WINDOWS_RESERVED_BASENAME for reason in evidence.rejection_reasons)


def test_trailing_dot_alias_is_rejected(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    _write(source / "extra.", b"trailing dot")
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.TRAILING_DOT_OR_SPACE for reason in evidence.rejection_reasons)


def test_ads_colon_is_rejected(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    _write(source / "extra:stream", b"ads shaped")
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.ADS_COLON for reason in evidence.rejection_reasons)


def test_oversized_file_is_rejected(tmp_path: Path):
    small_authority = IntakeAuthority.create(
        authority_id="small_limit_v1",
        authority_paths=("LOCAL_DEV.md",),
        allowed_directories=(),
        per_file_bytes=16,
    )
    source = tmp_path / "source"
    _write(source / "LOCAL_DEV.md", b"x" * 64)
    evidence = validate_and_copy(source, small_authority, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.FILE_TOO_LARGE for reason in evidence.rejection_reasons)


def test_aggregate_too_large_is_rejected(tmp_path: Path):
    tiny_authority = IntakeAuthority.create(
        authority_id="tiny_aggregate_v1",
        authority_paths=("a.txt", "b.txt"),
        allowed_directories=(),
        per_file_bytes=64,
        aggregate_bytes=32,
    )
    source = tmp_path / "source"
    _write(source / "a.txt", b"x" * 20)
    _write(source / "b.txt", b"y" * 20)
    evidence = validate_and_copy(source, tiny_authority, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.AGGREGATE_TOO_LARGE for reason in evidence.rejection_reasons)


def test_malformed_package_json_is_rejected(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    _write(source / "package.json", b"{not valid json")
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.MALFORMED_PACKAGE_JSON for reason in evidence.rejection_reasons)


def test_source_mutation_during_confirmed_read_is_detected(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    destination = tmp_path / "accepted"
    evidence_path = tmp_path / "evidence.json"

    with CanonicalIntake(source, NEON_RELAY_AUTHORITY) as intake:
        intake.observe()
        assert not intake.reasons
        # Mutate a confirmed file's bytes after observation, before copy.
        (source / "index.html").write_bytes(b"<html>mutated</html>\n")
        evidence = intake.copy_and_publish(destination, evidence_path)

    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.SOURCE_MUTATED for reason in evidence.rejection_reasons)
    assert not destination.exists()


def test_observation_bound_exceeded_is_rejected(tmp_path: Path):
    bounded_authority = IntakeAuthority.create(
        authority_id="bounded_entries_v1",
        authority_paths=("a.txt",),
        allowed_directories=(),
        observed_entries=1,
    )
    source = tmp_path / "source"
    _write(source / "a.txt", b"ok")
    _write(source / "b.txt", b"extra")
    evidence = validate_and_copy(source, bounded_authority, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    codes = {reason.code for reason in evidence.rejection_reasons}
    assert RejectionCode.OBSERVATION_BOUND_EXCEEDED in codes


@pytest.mark.parametrize(
    "path, expected_code",
    [
        ("../escape", RejectionCode.PATH_TRAVERSAL),
        ("a/../../etc/passwd", RejectionCode.PATH_TRAVERSAL),
        ("/absolute", RejectionCode.ABSOLUTE_PATH),
        ("dir\\backslash", RejectionCode.WINDOWS_SEPARATOR),
        ("a//b", RejectionCode.EMPTY_PATH_COMPONENT),
        ("", RejectionCode.EMPTY_PATH),
    ],
)
def test_path_policy_reasons_cover_hostile_shapes_unreachable_via_real_dirents(path, expected_code):
    codes = {reason.code for reason in path_policy_reasons(path)}
    assert expected_code in codes


def test_mount_crossing_is_detected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "source"
    _healthy_tree(source)

    real_stat = os.stat

    def fake_stat(path, *args, **kwargs):  # noqa: ANN001
        result = real_stat(path, *args, **kwargs)
        if isinstance(path, str) and path == "index.html" and kwargs.get("dir_fd") is not None:
            return os.stat_result(
                (
                    result.st_mode,
                    result.st_ino,
                    result.st_dev + 1,
                    result.st_nlink,
                    result.st_uid,
                    result.st_gid,
                    result.st_size,
                    int(result.st_atime),
                    int(result.st_mtime),
                    int(result.st_ctime),
                )
            )
        return result

    monkeypatch.setattr(os, "stat", fake_stat)
    evidence = validate_and_copy(source, NEON_RELAY_AUTHORITY, tmp_path / "accepted", tmp_path / "evidence.json")
    assert evidence.ruling == "REJECTED"
    assert any(reason.code == RejectionCode.MOUNT_CROSSING for reason in evidence.rejection_reasons)


def test_crash_after_publication_preparation_never_claims_or_creates_acceptance(tmp_path: Path):
    source = tmp_path / "source"
    _healthy_tree(source)
    destination = tmp_path / "accepted"
    evidence_path = tmp_path / "evidence.json"

    from admissible.capsule.common import CrashInjected

    with pytest.raises(CrashInjected, match="publication preparation"):
        validate_and_copy(
            source,
            NEON_RELAY_AUTHORITY,
            destination,
            evidence_path,
            crash_after_preparation=True,
        )

    durable = IntakeEvidence.from_dict(json.loads(evidence_path.read_bytes()))
    assert durable.publication_state is IntakePublicationState.PUBLICATION_PREPARED
    assert durable.published is False
    assert not destination.exists()
    with pytest.raises(ValueError, match="published accepted"):
        AcceptedMaterialIdentity.from_intake_evidence(durable)
