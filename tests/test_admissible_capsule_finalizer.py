"""Provider-free tests for the Admissible-owned Git finalizer.

Every repository here is a fake, disposable bare repository created fresh
under `tmp_path`. Nothing is pushed and no real remote exists.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from admissible.capsule.common import git
from admissible.capsule.finalizer import (
    FROZEN_IDENTITY,
    AcceptedBlob,
    AdmissibleFinalizer,
    FinalizationOutcome,
    FinalizerPreconditionError,
    initialize_disposable_repository,
)


PARENT_IDENTITY = {
    "author_name": "Capsule Fixture",
    "author_email": "capsule-fixture@example.invalid",
    "author_date": "1999-12-31T00:00:00+00:00",
    "committer_name": "Capsule Fixture",
    "committer_email": "capsule-fixture@example.invalid",
    "committer_date": "1999-12-31T00:00:00+00:00",
}


def _repo(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "disposable.git"
    parent = initialize_disposable_repository(repository, parent_identity=PARENT_IDENTITY)
    return repository, parent


def _blobs() -> tuple[AcceptedBlob, ...]:
    return (
        AcceptedBlob.create(relative_path="index.html", data=b"<html></html>\n"),
        AcceptedBlob.create(relative_path="src/main.js", data=b"// main\n"),
    )


def test_disposable_repository_has_no_hooks_or_remotes(tmp_path: Path):
    repository, _parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    assert finalizer.repository == repository
    remotes = git(repository, "remote").stdout.decode().split()
    assert remotes == []
    hooks_directory = repository / "hooks"
    assert not hooks_directory.exists() or not any(hooks_directory.iterdir())


def test_finalize_refuses_publication_when_evidence_is_not_durable(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    with pytest.raises(FinalizerPreconditionError):
        finalizer.finalize(
            parent=parent,
            accepted_blobs=_blobs(),
            private_index=tmp_path / "index",
            message="feat: build playable Neon Relay browser game\n",
            evidence_is_durable=False,
        )
    assert finalizer.current_ref() == parent


def test_finalize_publishes_exactly_one_commit_with_frozen_identity(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    message = "feat: build playable Neon Relay browser game\n"
    result = finalizer.finalize(
        parent=parent,
        accepted_blobs=_blobs(),
        private_index=tmp_path / "index",
        message=message,
        evidence_is_durable=True,
    )
    assert result.outcome == FinalizationOutcome.PUBLISHED
    assert result.ref_before == parent
    assert result.ref_after == result.commit
    assert finalizer.current_ref() == result.commit

    check = finalizer.verify(parent=parent, accepted_blobs=_blobs(), message=message)
    assert check["ok"] is True
    assert check["commit_count"] == 1
    assert check["remotes"] == []
    assert check["hooks"] == []

    identity_lines = (
        git(repository, "show", "-s", "--format=%an%n%ae%n%aI%n%cn%n%ce%n%cI", result.commit)
        .stdout.decode()
        .splitlines()
    )
    assert identity_lines[0] == FROZEN_IDENTITY["author_name"]
    assert identity_lines[1] == FROZEN_IDENTITY["author_email"]


def test_duplicate_finalization_is_idempotent(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    message = "feat: build playable Neon Relay browser game\n"
    first = finalizer.finalize(
        parent=parent,
        accepted_blobs=_blobs(),
        private_index=tmp_path / "index-1",
        message=message,
        evidence_is_durable=True,
    )
    second = finalizer.finalize(
        parent=parent,
        accepted_blobs=_blobs(),
        private_index=tmp_path / "index-2",
        message=message,
        evidence_is_durable=True,
    )
    assert first.outcome == FinalizationOutcome.PUBLISHED
    assert second.outcome == FinalizationOutcome.IDEMPOTENT_SAME_ACCEPTED_IDENTITY
    assert second.commit == first.commit
    assert second.ref_before == first.commit
    assert second.ref_after == first.commit
    rev_count = git(repository, "rev-list", "--count", finalizer.target_ref).stdout.decode().strip()
    assert rev_count == "2"  # trusted parent + exactly one accepted commit


def test_compare_and_swap_refuses_an_unexpected_concurrent_parent(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)

    unexpected_tree = git(repository, "show", "-s", "--format=%T", parent).stdout.decode().strip()
    unexpected_identity = dict(PARENT_IDENTITY)
    unexpected_identity["author_date"] = "1999-12-31T00:00:01+00:00"
    unexpected_identity["committer_date"] = "1999-12-31T00:00:01+00:00"
    from admissible.capsule.finalizer import _git_environment

    unexpected_commit = (
        git(
            repository,
            "commit-tree",
            unexpected_tree,
            "-p",
            parent,
            env=_git_environment(unexpected_identity),
            input_bytes=b"unexpected concurrent parent\n",
        )
        .stdout.decode()
        .strip()
    )
    git(repository, "update-ref", finalizer.target_ref, unexpected_commit, parent)

    result = finalizer.finalize(
        parent=parent,
        accepted_blobs=_blobs(),
        private_index=tmp_path / "index",
        message="feat: build playable Neon Relay browser game\n",
        evidence_is_durable=True,
    )
    assert result.outcome == FinalizationOutcome.COMPARE_AND_SWAP_REFUSED
    assert result.ref_before == unexpected_commit
    assert result.ref_after == unexpected_commit
    assert finalizer.current_ref() == unexpected_commit


def test_crash_before_update_ref_leaves_the_ref_untouched_and_commit_unreachable(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    from admissible.capsule.common import CrashInjected

    with pytest.raises(CrashInjected) as excinfo:
        finalizer.finalize(
            parent=parent,
            accepted_blobs=_blobs(),
            private_index=tmp_path / "index",
            message="feat: build playable Neon Relay browser game\n",
            evidence_is_durable=True,
            crash_before_update_ref=True,
        )
    assert finalizer.current_ref() == parent

    unreachable_commit = str(excinfo.value).rsplit("=", 1)[-1]
    reachable = git(repository, "rev-list", finalizer.target_ref).stdout.decode().split()
    assert unreachable_commit not in reachable
    # The blob/tree/commit objects exist loose in the object database (the
    # build step already ran), but nothing durable points at them.
    cat = git(repository, "cat-file", "-t", unreachable_commit, check=False)
    assert cat.returncode == 0
    assert cat.stdout.decode().strip() == "commit"


def test_finalizer_rejects_a_repository_that_carries_hooks(tmp_path: Path):
    repository, _parent = _repo(tmp_path)
    hooks_directory = repository / "hooks"
    hooks_directory.mkdir(parents=True, exist_ok=True)
    hook = hooks_directory / "pre-receive"
    hook.write_text("#!/bin/sh\nexit 1\n")
    hook.chmod(0o755)
    with pytest.raises(ValueError):
        AdmissibleFinalizer(repository)


def test_finalizer_rejects_a_repository_that_carries_a_remote(tmp_path: Path):
    repository, _parent = _repo(tmp_path)
    other = tmp_path / "other.git"
    initialize_disposable_repository(other, parent_identity=PARENT_IDENTITY)
    git(repository, "remote", "add", "origin", str(other))
    with pytest.raises(ValueError):
        AdmissibleFinalizer(repository)


def test_no_durable_accepted_effect_before_finalization_completes(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    finalizer.build_commit(
        parent=parent, accepted_blobs=_blobs(), private_index=tmp_path / "index", message="not yet published\n"
    )
    # Building a commit object is not publication: the ref must be untouched.
    assert finalizer.current_ref() == parent


def test_accepted_blob_provenance_is_bytes_only_never_a_git_object_read(tmp_path: Path):
    """A provider cannot smuggle a Git commit in: AcceptedBlob only ever
    carries bytes the caller supplies directly (from intake), never a Git
    object id resolved from some other, provider-controlled repository."""

    import dataclasses

    field_names = {field.name for field in dataclasses.fields(AcceptedBlob)}
    assert field_names == {"schema_version", "relative_path", "sha256", "data"}
    assert "object_id" not in field_names
    assert "git_ref" not in field_names

    with pytest.raises(ValueError):
        AcceptedBlob(
            schema_version="admissible_capsule_accepted_blob_v1",
            relative_path="index.html",
            sha256="0" * 64,
            data=b"tampered bytes that do not match the declared hash",
        ).validated()


def test_finalization_result_round_trips_through_evidence_only_dict(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    result = finalizer.finalize(
        parent=parent,
        accepted_blobs=_blobs(),
        private_index=tmp_path / "index",
        message="feat: build playable Neon Relay browser game\n",
        evidence_is_durable=True,
    )
    from admissible.capsule.finalizer import FinalizationResult

    reconstructed = FinalizationResult.from_dict(result.to_dict())
    assert reconstructed == result
