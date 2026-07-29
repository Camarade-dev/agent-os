"""The Admissible-owned Git finalizer: the sole path to an accepted commit.

Adapts the mechanism proven by the external, provider-free spike at
`admissible-capsule/spike-v1/finalizer-v1/scripts/git_finalizer.py`: a
private Git index, deterministic `commit-tree` with a frozen author/
committer identity, and a compare-and-swap `update-ref`. No provider process
ever touches the repository this class writes to, and no hooks or remotes
are permitted.

Every write here operates on fake, disposable repositories the caller
constructs (see `initialize_disposable_repository`); this module never
touches a real remote and this integration never pushes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.common import (
    CrashInjected,
    fingerprint,
    git,
    require_exact_keys,
    require_git_oid,
    require_nonempty_text,
    require_optional_git_oid,
    require_sha256,
)


ACCEPTED_BLOB_SCHEMA_VERSION = "admissible_capsule_accepted_blob_v1"
FINALIZATION_RESULT_SCHEMA_VERSION = "admissible_capsule_finalization_result_v1"

DEFAULT_TARGET_REF = "refs/heads/accepted"

FROZEN_IDENTITY: Mapping[str, str] = {
    "author_name": "Capsule Finalizer",
    "author_email": "capsule-finalizer@example.invalid",
    "author_date": "2000-01-01T00:00:00+00:00",
    "committer_name": "Capsule Finalizer",
    "committer_email": "capsule-finalizer@example.invalid",
    "committer_date": "2000-01-01T00:00:00+00:00",
}


class FinalizationOutcome(str, Enum):
    PUBLISHED = "PUBLISHED"
    IDEMPOTENT_SAME_ACCEPTED_IDENTITY = "IDEMPOTENT_SAME_ACCEPTED_IDENTITY"
    COMPARE_AND_SWAP_REFUSED = "COMPARE_AND_SWAP_REFUSED"


@dataclass(frozen=True)
class AcceptedBlob:
    """One accepted byte blob, sourced only from canonical intake evidence.

    There is no constructor path from a provider-controlled Git object to
    this type: callers must supply `relative_path`/`sha256`/`data` taken
    from `IntakeEvidence.files` and the bytes intake actually copied.
    """

    schema_version: str
    relative_path: str
    sha256: str
    data: bytes

    @classmethod
    def create(cls, *, relative_path: str, data: bytes) -> "AcceptedBlob":
        from admissible.capsule.common import sha256_bytes

        return cls(
            schema_version=ACCEPTED_BLOB_SCHEMA_VERSION,
            relative_path=relative_path,
            sha256=sha256_bytes(data),
            data=data,
        ).validated()

    def validated(self) -> "AcceptedBlob":
        if self.schema_version != ACCEPTED_BLOB_SCHEMA_VERSION:
            raise ValueError("unsupported accepted blob schema")
        require_nonempty_text(self.relative_path, "accepted blob relative_path", max_bytes=4096)
        require_sha256(self.sha256, "accepted blob sha256")
        if not isinstance(self.data, (bytes, bytearray)):
            raise ValueError("accepted blob data must be bytes")
        from admissible.capsule.common import sha256_bytes

        if sha256_bytes(bytes(self.data)) != self.sha256:
            raise ValueError("accepted blob sha256 does not match its bytes")
        return self


@dataclass(frozen=True)
class FinalizationResult:
    schema_version: str
    outcome: FinalizationOutcome
    parent: str
    tree: str | None
    commit: str | None
    ref_before: str | None
    ref_after: str | None
    result_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        outcome: FinalizationOutcome,
        parent: str,
        tree: str | None,
        commit: str | None,
        ref_before: str | None,
        ref_after: str | None,
    ) -> "FinalizationResult":
        body = {
            "schema_version": FINALIZATION_RESULT_SCHEMA_VERSION,
            "outcome": outcome.value,
            "parent": parent,
            "tree": tree,
            "commit": commit,
            "ref_before": ref_before,
            "ref_after": ref_after,
        }
        return cls(
            schema_version=FINALIZATION_RESULT_SCHEMA_VERSION,
            outcome=outcome,
            parent=parent,
            tree=tree,
            commit=commit,
            ref_before=ref_before,
            ref_after=ref_after,
            result_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "outcome": self.outcome.value,
            "parent": self.parent,
            "tree": self.tree,
            "commit": self.commit,
            "ref_before": self.ref_before,
            "ref_after": self.ref_after,
        }

    def validated(self) -> "FinalizationResult":
        if self.schema_version != FINALIZATION_RESULT_SCHEMA_VERSION:
            raise ValueError("unsupported finalization result schema")
        if not isinstance(self.outcome, FinalizationOutcome):
            raise ValueError("unknown finalization outcome")
        require_git_oid(self.parent, "parent")
        require_optional_git_oid(self.tree, "tree")
        require_optional_git_oid(self.commit, "commit")
        require_optional_git_oid(self.ref_before, "ref_before")
        require_optional_git_oid(self.ref_after, "ref_after")
        require_sha256(self.result_fingerprint, "result_fingerprint")
        if fingerprint(self._body()) != self.result_fingerprint:
            raise ValueError("finalization result fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["result_fingerprint"] = self.result_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FinalizationResult":
        require_exact_keys(
            data,
            {"schema_version", "outcome", "parent", "tree", "commit", "ref_before", "ref_after", "result_fingerprint"},
            "finalization result",
        )
        return cls(
            schema_version=data["schema_version"],
            outcome=FinalizationOutcome(data["outcome"]),
            parent=data["parent"],
            tree=data["tree"],
            commit=data["commit"],
            ref_before=data["ref_before"],
            ref_after=data["ref_after"],
            result_fingerprint=data["result_fingerprint"],
        ).validated()


def _git_environment(identity: Mapping[str, str]) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": identity["author_name"],
            "GIT_AUTHOR_EMAIL": identity["author_email"],
            "GIT_AUTHOR_DATE": identity["author_date"],
            "GIT_COMMITTER_NAME": identity["committer_name"],
            "GIT_COMMITTER_EMAIL": identity["committer_email"],
            "GIT_COMMITTER_DATE": identity["committer_date"],
            "LC_ALL": "C",
            "TZ": "UTC",
        }
    )
    return environment


def initialize_disposable_repository(
    repository: Path,
    *,
    parent_identity: Mapping[str, str],
    parent_message: str = "trusted synthetic parent\n",
    target_ref: str = DEFAULT_TARGET_REF,
) -> str:
    """Create a fake, disposable bare repository with no hooks or remotes.

    Returns the parent commit OID that `target_ref` is initialized to.
    """

    repository.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    template = repository.parent / f".{repository.name}.empty-template"
    template.mkdir(parents=True, exist_ok=True, mode=0o755)
    completed = subprocess.run(
        ["git", "init", "--bare", f"--template={template}", str(repository)],
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.decode("utf-8", "replace"))
    hooks_directory = repository / "hooks"
    if hooks_directory.exists():
        shutil.rmtree(hooks_directory)
    empty_tree = git(repository, "mktree", input_bytes=b"").stdout.decode().strip()
    parent = (
        git(
            repository,
            "commit-tree",
            empty_tree,
            env=_git_environment(parent_identity),
            input_bytes=parent_message.encode("utf-8"),
        )
        .stdout.decode()
        .strip()
    )
    git(repository, "update-ref", target_ref, parent)
    return parent


class FinalizerPreconditionError(ValueError):
    """No publication before all evidence is durable."""


class AdmissibleFinalizer:
    """The transaction boundary that turns accepted evidence into a Git commit.

    This is the exclusive path to `target_ref`. Nothing else in this
    integration is permitted to run `update-ref` against a repository this
    class manages.
    """

    def __init__(self, repository: Path, *, target_ref: str = DEFAULT_TARGET_REF):
        self.repository = repository
        self.target_ref = target_ref
        hooks_directory = repository / "hooks"
        if hooks_directory.exists() and any(hooks_directory.iterdir()):
            raise ValueError("finalizer repository must not carry Git hooks")
        remotes = git(repository, "remote").stdout.decode().split()
        if remotes:
            raise ValueError("finalizer repository must not carry remotes")

    def build_commit(
        self,
        *,
        parent: str,
        accepted_blobs: tuple[AcceptedBlob, ...],
        private_index: Path,
        message: str,
    ) -> dict[str, Any]:
        """Build (but do not publish) a commit using a private Git index.

        `private_index` is never the repository's default index — this
        keeps the finalizer's staging fully isolated from any other
        process that might share the repository.
        """

        private_index.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        if private_index.exists():
            private_index.unlink()
        environment = os.environ.copy()
        environment["GIT_INDEX_FILE"] = str(private_index.resolve())
        environment["LC_ALL"] = "C"
        git(self.repository, "read-tree", parent, env=environment)
        blobs: list[dict[str, str]] = []
        for blob in accepted_blobs:
            blob.validated()
            object_id = (
                git(
                    self.repository,
                    "hash-object",
                    "--no-filters",
                    "-w",
                    "--stdin",
                    env=environment,
                    input_bytes=bytes(blob.data),
                )
                .stdout.decode()
                .strip()
            )
            git(
                self.repository,
                "update-index",
                "--add",
                "--cacheinfo",
                f"100644,{object_id},{blob.relative_path}",
                env=environment,
            )
            blobs.append({"path": blob.relative_path, "object_id": object_id})
        tree = git(self.repository, "write-tree", env=environment).stdout.decode().strip()
        commit_environment = _git_environment(FROZEN_IDENTITY)
        commit_environment["GIT_INDEX_FILE"] = str(private_index.resolve())
        commit = (
            git(
                self.repository,
                "commit-tree",
                tree,
                "-p",
                parent,
                env=commit_environment,
                input_bytes=message.encode("utf-8"),
            )
            .stdout.decode()
            .strip()
        )
        return {"tree": tree, "commit": commit, "blobs": blobs}

    def finalize(
        self,
        *,
        parent: str,
        accepted_blobs: tuple[AcceptedBlob, ...],
        private_index: Path,
        message: str,
        evidence_is_durable: bool,
        crash_before_update_ref: bool = False,
    ) -> FinalizationResult:
        """Publish exactly one accepted commit, or refuse via CAS.

        `evidence_is_durable` must be an explicit, caller-verified True —
        this is the "no publication before all evidence is durable" gate.
        Callers pass `intake_evidence.published and verification.admissible`
        (both already durably written) rather than this method re-deriving
        durability itself.
        """

        if not evidence_is_durable:
            raise FinalizerPreconditionError(
                "finalization refused: intake and verification evidence are not both durable"
            )
        built = self.build_commit(
            parent=parent, accepted_blobs=accepted_blobs, private_index=private_index, message=message
        )
        current = git(self.repository, "show-ref", "--hash", "--verify", self.target_ref, check=False)
        current_id = current.stdout.decode().strip() if current.returncode == 0 else None
        if current_id == built["commit"]:
            return FinalizationResult.create(
                outcome=FinalizationOutcome.IDEMPOTENT_SAME_ACCEPTED_IDENTITY,
                parent=parent,
                tree=built["tree"],
                commit=built["commit"],
                ref_before=current_id,
                ref_after=current_id,
            )
        if crash_before_update_ref:
            raise CrashInjected(
                f"crash injected before update-ref; unreachable commit={built['commit']}"
            )
        updated = git(self.repository, "update-ref", self.target_ref, built["commit"], parent, check=False)
        if updated.returncode != 0:
            after = git(self.repository, "show-ref", "--hash", "--verify", self.target_ref, check=False)
            return FinalizationResult.create(
                outcome=FinalizationOutcome.COMPARE_AND_SWAP_REFUSED,
                parent=parent,
                tree=built["tree"],
                commit=built["commit"],
                ref_before=current_id,
                ref_after=(after.stdout.decode().strip() if after.returncode == 0 else None),
            )
        return FinalizationResult.create(
            outcome=FinalizationOutcome.PUBLISHED,
            parent=parent,
            tree=built["tree"],
            commit=built["commit"],
            ref_before=current_id,
            ref_after=built["commit"],
        )

    def current_ref(self) -> str | None:
        current = git(self.repository, "show-ref", "--hash", "--verify", self.target_ref, check=False)
        return current.stdout.decode().strip() if current.returncode == 0 else None

    def verify(self, *, parent: str, accepted_blobs: tuple[AcceptedBlob, ...], message: str) -> dict[str, Any]:
        """Read-only proof that `target_ref` matches the expected transaction."""

        ref = git(self.repository, "rev-parse", self.target_ref).stdout.decode().strip()
        commit_count = int(
            git(self.repository, "rev-list", "--count", f"{parent}..{ref}").stdout.decode().strip()
        )
        material_paths = (
            git(self.repository, "diff-tree", "--no-commit-id", "--name-only", "-r", parent, ref)
            .stdout.decode()
            .splitlines()
        )
        remotes = git(self.repository, "remote").stdout.decode().splitlines()
        hooks_directory = self.repository / "hooks"
        hooks = sorted(path.name for path in hooks_directory.iterdir()) if hooks_directory.exists() else []
        commit_message = git(self.repository, "show", "-s", "--format=%B", ref).stdout.decode().rstrip("\n")
        expected_paths = sorted(blob.relative_path for blob in accepted_blobs)
        return {
            "ref": ref,
            "commit_count": commit_count,
            "material_paths": material_paths,
            "remotes": remotes,
            "hooks": hooks,
            "message": commit_message,
            "ok": (
                commit_count == 1
                and sorted(material_paths) == expected_paths
                and not remotes
                and not hooks
                and commit_message == message.rstrip("\n")
            ),
        }
