"""Provider-free tests for exact-tree, closed-environment Git finalization."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from admissible.capsule.common import fingerprint, git
from admissible.capsule.finalizer import (
    FROZEN_IDENTITY,
    AcceptedBlob,
    AdmissibleFinalizer,
    FinalizationOutcome,
    FinalizationResult,
    PreparedFinalization,
    _git_environment,
    initialize_disposable_repository,
)
from admissible.capsule.intake import (
    AcceptedMaterialIdentity,
    IntakeEvidence,
    IntakeFileRecord,
    IntakePublicationState,
)


PARENT_IDENTITY = {
    "author_name": "Capsule Fixture",
    "author_email": "capsule-fixture@example.invalid",
    "author_date": "1999-12-31T00:00:00+00:00",
    "committer_name": "Capsule Fixture",
    "committer_email": "capsule-fixture@example.invalid",
    "committer_date": "1999-12-31T00:00:00+00:00",
}
MESSAGE = "feat: build accepted material\n"


def _repo(tmp_path: Path) -> tuple[Path, str]:
    repository = tmp_path / "disposable.git"
    parent = initialize_disposable_repository(repository, parent_identity=PARENT_IDENTITY)
    return repository, parent


def _material_and_blobs() -> tuple[AcceptedMaterialIdentity, tuple[AcceptedBlob, ...]]:
    values = (
        ("index.html", b"<html></html>\n", "100644"),
        ("src/main.js", b"// main\n", "100755"),
    )
    records = tuple(
        IntakeFileRecord(
            relative_path=path,
            size=len(data),
            sha256=AcceptedBlob.create(
                relative_path=path, data=data, git_mode=mode
            ).sha256,
            git_mode=mode,
        ).validated()
        for path, data, mode in values
    )
    evidence = IntakeEvidence.create(
        authority_fingerprint="a" * 64,
        ruling="ACCEPTED",
        rejection_reasons=(),
        files=records,
        aggregate_fingerprint=fingerprint([record.to_dict() for record in records]),
        publication_state=IntakePublicationState.ACCEPTED_INTAKE_PUBLISHED,
    )
    material = AcceptedMaterialIdentity.from_intake_evidence(evidence)
    blobs = tuple(
        AcceptedBlob.create(relative_path=path, data=data, git_mode=mode)
        for path, data, mode in values
    )
    return material, blobs


def _prepare(
    finalizer: AdmissibleFinalizer,
    parent: str,
    tmp_path: Path,
    *,
    suffix: str = "1",
) -> PreparedFinalization:
    material, blobs = _material_and_blobs()
    return finalizer.prepare(
        parent=parent,
        accepted_material=material,
        accepted_blobs=blobs,
        private_index=tmp_path / f"index-{suffix}",
        message=MESSAGE,
    )


def test_disposable_repository_has_no_remotes_and_finalizer_owns_empty_hooks(tmp_path: Path):
    repository, _parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    assert git(repository, "remote", env=finalizer.environment).stdout.decode().split() == []
    assert finalizer.hooks_directory.is_dir()
    assert not any(finalizer.hooks_directory.iterdir())


def test_caller_boolean_cannot_claim_finalization_evidence_is_durable(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    prepared = _prepare(finalizer, parent, tmp_path)
    with pytest.raises(TypeError, match="evidence_is_durable"):
        finalizer.finalize(  # type: ignore[call-arg]
            prepared=prepared,
            evidence_is_durable=True,
        )
    assert finalizer.current_ref() == parent


def test_missing_trusted_durability_destination_refuses_finalization(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    prepared = _prepare(finalizer, parent, tmp_path)
    Path(prepared.durability_receipt.destination).unlink()
    with pytest.raises(ValueError, match="missing"):
        finalizer.finalize(prepared=prepared)
    assert finalizer.current_ref() == parent


def test_finalize_publishes_exact_tree_with_frozen_identity(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    prepared = _prepare(finalizer, parent, tmp_path)
    result = finalizer.finalize(prepared=prepared)

    assert result.outcome is FinalizationOutcome.PUBLISHED
    assert result.accepted_material == prepared.evidence.accepted_material
    assert result.expected_tree == prepared.evidence.expected_tree
    assert result.finalizer_authority == finalizer.authority
    assert result.parent == parent
    assert result.publication_ref == finalizer.target_ref
    assert result.resulting_commit == result.ref_after
    assert Path(result.durability_receipt.destination).read_bytes() == (
        result.durable_evidence.canonical_bytes()
    )
    assert finalizer.verify(prepared=prepared)["ok"] is True

    names = (
        git(
            repository,
            "show",
            "-s",
            "--format=%an%n%ae%n%cn%n%ce",
            result.commit,
            env=finalizer.environment,
        )
        .stdout.decode()
        .splitlines()
    )
    assert names == [
        FROZEN_IDENTITY["author_name"],
        FROZEN_IDENTITY["author_email"],
        FROZEN_IDENTITY["committer_name"],
        FROZEN_IDENTITY["committer_email"],
    ]
    dates = (
        git(
            repository,
            "show",
            "-s",
            "--format=%aI%n%cI",
            result.commit,
            env=finalizer.environment,
        )
        .stdout.decode()
        .splitlines()
    )
    assert dates == [
        FROZEN_IDENTITY["author_date"],
        FROZEN_IDENTITY["committer_date"],
    ]
    modes = {
        line.split()[3]: line.split()[0]
        for line in git(
            repository,
            "ls-tree",
            "-r",
            result.tree,
            env=finalizer.environment,
        ).stdout.decode().splitlines()
    }
    assert modes == {"index.html": "100644", "src/main.js": "100755"}


def test_duplicate_finalization_is_idempotent(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    first_prepared = _prepare(finalizer, parent, tmp_path, suffix="1")
    second_prepared = _prepare(finalizer, parent, tmp_path, suffix="2")
    first = finalizer.finalize(prepared=first_prepared)
    second = finalizer.finalize(prepared=second_prepared)
    assert first.outcome is FinalizationOutcome.PUBLISHED
    assert second.outcome is FinalizationOutcome.IDEMPOTENT_SAME_ACCEPTED_IDENTITY
    assert second.commit == first.commit


def test_compare_and_swap_refuses_an_unexpected_concurrent_parent(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    prepared = _prepare(finalizer, parent, tmp_path)
    unexpected = (
        git(
            repository,
            "commit-tree",
            prepared.evidence.expected_tree,
            "-p",
            parent,
            env=_git_environment(
                {**PARENT_IDENTITY, "author_date": "1999-12-31T00:00:01+00:00",
                 "committer_date": "1999-12-31T00:00:01+00:00"},
                environment_root=finalizer.environment_root,
                hooks_directory=finalizer.hooks_directory,
            ),
            input_bytes=b"concurrent\n",
        )
        .stdout.decode()
        .strip()
    )
    git(
        repository,
        "update-ref",
        finalizer.target_ref,
        unexpected,
        parent,
        env=finalizer.environment,
    )
    result = finalizer.finalize(prepared=prepared)
    assert result.outcome is FinalizationOutcome.COMPARE_AND_SWAP_REFUSED
    assert result.ref_before == unexpected
    assert result.ref_after == unexpected


def test_concurrent_finalization_has_one_publication_and_no_unbound_acceptance(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    first_finalizer = AdmissibleFinalizer(repository)
    second_finalizer = AdmissibleFinalizer(
        repository, evidence_store=first_finalizer.evidence_store
    )
    prepared = (
        _prepare(first_finalizer, parent, tmp_path, suffix="one"),
        _prepare(second_finalizer, parent, tmp_path, suffix="two"),
    )
    barrier = threading.Barrier(2)
    outcomes: list[FinalizationOutcome] = []
    errors: list[BaseException] = []

    def publish(finalizer: AdmissibleFinalizer, plan: PreparedFinalization) -> None:
        try:
            barrier.wait()
            outcomes.append(finalizer.finalize(prepared=plan).outcome)
        except BaseException as error:  # captured for deterministic assertion
            errors.append(error)

    threads = [
        threading.Thread(target=publish, args=(first_finalizer, prepared[0])),
        threading.Thread(target=publish, args=(second_finalizer, prepared[1])),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert not errors
    assert FinalizationOutcome.PUBLISHED in outcomes
    assert set(outcomes) <= {
        FinalizationOutcome.PUBLISHED,
        FinalizationOutcome.IDEMPOTENT_SAME_ACCEPTED_IDENTITY,
        FinalizationOutcome.COMPARE_AND_SWAP_REFUSED,
    }
    assert first_finalizer.current_ref() == prepared[0].evidence.resulting_commit


def test_crash_before_update_ref_leaves_ref_untouched(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    prepared = _prepare(finalizer, parent, tmp_path)
    from admissible.capsule.common import CrashInjected

    with pytest.raises(CrashInjected):
        finalizer.finalize(prepared=prepared, crash_before_update_ref=True)
    assert finalizer.current_ref() == parent


def test_finalizer_rejects_a_repository_that_carries_a_remote(tmp_path: Path):
    repository, _parent = _repo(tmp_path)
    other = tmp_path / "other.git"
    initialize_disposable_repository(other, parent_identity=PARENT_IDENTITY)
    git(repository, "remote", "add", "origin", str(other))
    with pytest.raises(ValueError, match="remotes"):
        AdmissibleFinalizer(repository)


def test_finalizer_rejects_repository_object_alternates(tmp_path: Path):
    repository, _parent = _repo(tmp_path)
    alternates = repository / "objects" / "info" / "alternates"
    alternates.parent.mkdir(parents=True, exist_ok=True)
    alternates.write_text(str(tmp_path / "hostile-objects") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="alternate object"):
        AdmissibleFinalizer(repository)


def test_building_and_preparing_do_not_publish(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    _prepare(finalizer, parent, tmp_path)
    assert finalizer.current_ref() == parent


def test_accepted_blob_has_bytes_mode_and_no_git_object_authority():
    import dataclasses

    fields = {field.name for field in dataclasses.fields(AcceptedBlob)}
    assert fields == {"schema_version", "relative_path", "sha256", "git_mode", "data"}
    assert "object_id" not in fields
    with pytest.raises(ValueError):
        AcceptedBlob(
            schema_version="admissible_capsule_accepted_blob_v2",
            relative_path="index.html",
            sha256="0" * 64,
            git_mode="100644",
            data=b"tampered",
        ).validated()


def test_finalization_result_round_trips_from_durable_evidence(tmp_path: Path):
    repository, parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    result = finalizer.finalize(prepared=_prepare(finalizer, parent, tmp_path))
    assert FinalizationResult.from_dict(result.to_dict()) == result


def test_nonempty_parent_cannot_smuggle_unauthorized_path(tmp_path: Path):
    repository, original_parent = _repo(tmp_path)
    finalizer = AdmissibleFinalizer(repository)
    blob = (
        git(
            repository,
            "hash-object",
            "-w",
            "--stdin",
            env=finalizer.environment,
            input_bytes=b"smuggled\n",
        )
        .stdout.decode()
        .strip()
    )
    smuggled_tree = (
        git(
            repository,
            "mktree",
            env=finalizer.environment,
            input_bytes=f"100644 blob {blob}\tsmuggled.txt\n".encode(),
        )
        .stdout.decode()
        .strip()
    )
    parent = (
        git(
            repository,
            "commit-tree",
            smuggled_tree,
            "-p",
            original_parent,
            env=_git_environment(
                PARENT_IDENTITY,
                environment_root=finalizer.environment_root,
                hooks_directory=finalizer.hooks_directory,
            ),
            input_bytes=b"parent with unauthorized file\n",
        )
        .stdout.decode()
        .strip()
    )
    git(
        repository,
        "update-ref",
        finalizer.target_ref,
        parent,
        original_parent,
        env=finalizer.environment,
    )
    result = finalizer.finalize(prepared=_prepare(finalizer, parent, tmp_path))
    paths = (
        git(
            repository,
            "ls-tree",
            "-r",
            "--name-only",
            result.commit,
            env=finalizer.environment,
        )
        .stdout.decode()
        .splitlines()
    )
    assert paths == ["index.html", "src/main.js"]
    assert "smuggled.txt" not in paths


def test_ambient_git_configuration_and_reference_transaction_hook_are_inert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    marker = tmp_path / "ambient-hook-ran"
    hooks = tmp_path / "ambient-hooks"
    hooks.mkdir()
    hook = hooks / "reference-transaction"
    hook.write_text(f"#!/bin/sh\nprintf ran > {marker}\nexit 99\n", encoding="utf-8")
    hook.chmod(0o755)
    global_config = tmp_path / "ambient-global.gitconfig"
    global_config.write_text(
        f"[core]\n\thooksPath = {hooks}\n[credential]\n\thelper = !exit 99\n",
        encoding="utf-8",
    )
    system_config = tmp_path / "ambient-system.gitconfig"
    system_config.write_text("[user]\n\tname = Ambient\n\temail = ambient@example.test\n", encoding="utf-8")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(global_config))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(system_config))
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", str(tmp_path / "alternates"))
    monkeypatch.setenv("GIT_REPLACE_REF_BASE", "refs/replace-hostile/")
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Ambient Attacker")

    repository, parent = _repo(tmp_path)
    git(
        repository,
        "config",
        "core.hooksPath",
        str(hooks),
        env=_git_environment(),
    )
    finalizer = AdmissibleFinalizer(repository)
    result = finalizer.finalize(prepared=_prepare(finalizer, parent, tmp_path))
    assert result.outcome is FinalizationOutcome.PUBLISHED
    assert not marker.exists()
    assert finalizer.environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert finalizer.environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert "GIT_ALTERNATE_OBJECT_DIRECTORIES" not in finalizer.environment
    assert "GIT_REPLACE_REF_BASE" not in finalizer.environment
