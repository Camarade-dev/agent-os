"""Provider-neutral, Admissible-owned construction of exact accepted Git trees.

The parent commit contributes ancestry only. A finalization is prepared from
an explicitly empty private index, checked path-by-path against canonical
accepted material, durably recorded by a finalizer-owned evidence store, and
only then published with compare-and-swap.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from admissible.capsule.common import (
    CrashInjected,
    atomic_bytes,
    canonical_bytes,
    fingerprint,
    fsync_directory,
    git,
    require_exact_keys,
    require_git_oid,
    require_nonempty_text,
    require_sha256,
    sha256_bytes,
)
from admissible.capsule.intake import AcceptedMaterialIdentity, path_policy_reasons


ACCEPTED_BLOB_SCHEMA_VERSION = "admissible_capsule_accepted_blob_v2"
FINALIZER_STORE_AUTHORITY_SCHEMA_VERSION = "admissible_capsule_finalizer_store_authority_v1"
FINALIZER_AUTHORITY_SCHEMA_VERSION = "admissible_capsule_finalizer_authority_v1"
FINALIZED_TREE_ENTRY_SCHEMA_VERSION = "admissible_capsule_finalized_tree_entry_v1"
FINALIZATION_EVIDENCE_SCHEMA_VERSION = "admissible_capsule_finalization_evidence_v1"
DURABILITY_RECEIPT_SCHEMA_VERSION = "admissible_capsule_durability_receipt_v1"
FINALIZATION_RESULT_SCHEMA_VERSION = "admissible_capsule_finalization_result_v2"

DEFAULT_TARGET_REF = "refs/heads/accepted"

FROZEN_IDENTITY: Mapping[str, str] = {
    "author_name": "Capsule Finalizer",
    "author_email": "capsule-finalizer@example.invalid",
    "author_date": "2000-01-01T00:00:00+00:00",
    "committer_name": "Capsule Finalizer",
    "committer_email": "capsule-finalizer@example.invalid",
    "committer_date": "2000-01-01T00:00:00+00:00",
}

GIT_ENVIRONMENT_POLICY = {
    "inherit_environment": False,
    "system_config": False,
    "global_config": False,
    "xdg_config": False,
    "ambient_git_variables": False,
    "hooks": "finalizer-owned-empty-directory",
    "replacement_refs": False,
    "alternate_object_directories": False,
    "attributes": "disabled",
    "filters": "hash-object---no-filters",
    "identity": dict(FROZEN_IDENTITY),
}
GIT_ENVIRONMENT_POLICY_FINGERPRINT = fingerprint(GIT_ENVIRONMENT_POLICY)


class FinalizationOutcome(str, Enum):
    PUBLISHED = "PUBLISHED"
    IDEMPOTENT_SAME_ACCEPTED_IDENTITY = "IDEMPOTENT_SAME_ACCEPTED_IDENTITY"
    COMPARE_AND_SWAP_REFUSED = "COMPARE_AND_SWAP_REFUSED"


@dataclass(frozen=True)
class AcceptedBlob:
    """Bytes and canonical regular-file mode sourced from accepted intake."""

    schema_version: str
    relative_path: str
    sha256: str
    git_mode: str
    data: bytes

    @classmethod
    def create(
        cls,
        *,
        relative_path: str,
        data: bytes,
        git_mode: str = "100644",
    ) -> "AcceptedBlob":
        return cls(
            schema_version=ACCEPTED_BLOB_SCHEMA_VERSION,
            relative_path=relative_path,
            sha256=sha256_bytes(data),
            git_mode=git_mode,
            data=data,
        ).validated()

    def validated(self) -> "AcceptedBlob":
        if self.schema_version != ACCEPTED_BLOB_SCHEMA_VERSION:
            raise ValueError("unsupported accepted blob schema")
        require_nonempty_text(self.relative_path, "accepted blob relative_path", max_bytes=4096)
        if path_policy_reasons(self.relative_path):
            raise ValueError("accepted blob path violates canonical path policy")
        if self.git_mode not in {"100644", "100755"}:
            raise ValueError("accepted blob mode must be 100644 or 100755")
        require_sha256(self.sha256, "accepted blob sha256")
        if not isinstance(self.data, (bytes, bytearray)):
            raise ValueError("accepted blob data must be bytes")
        if sha256_bytes(bytes(self.data)) != self.sha256:
            raise ValueError("accepted blob sha256 does not match its bytes")
        return self


@dataclass(frozen=True)
class DurableEvidenceStoreAuthority:
    schema_version: str
    evidence_root: str
    authority_fingerprint: str

    @classmethod
    def create(cls, root: Path) -> "DurableEvidenceStoreAuthority":
        absolute = os.fspath(Path(os.path.abspath(root)))
        body = {
            "schema_version": FINALIZER_STORE_AUTHORITY_SCHEMA_VERSION,
            "evidence_root": absolute,
        }
        return cls(**body, authority_fingerprint=fingerprint(body)).validated()

    def _body(self) -> dict[str, str]:
        return {"schema_version": self.schema_version, "evidence_root": self.evidence_root}

    def validated(self) -> "DurableEvidenceStoreAuthority":
        if self.schema_version != FINALIZER_STORE_AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported durable evidence-store authority schema")
        if (
            not isinstance(self.evidence_root, str)
            or not os.path.isabs(self.evidence_root)
            or "\x00" in self.evidence_root
        ):
            raise ValueError("durable evidence root must be an absolute path")
        require_sha256(self.authority_fingerprint, "evidence-store authority fingerprint")
        if fingerprint(self._body()) != self.authority_fingerprint:
            raise ValueError("evidence-store authority fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, str]:
        return {**self._body(), "authority_fingerprint": self.authority_fingerprint}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DurableEvidenceStoreAuthority":
        require_exact_keys(
            data,
            {"schema_version", "evidence_root", "authority_fingerprint"},
            "durable evidence-store authority",
        )
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class FinalizerAuthority:
    schema_version: str
    repository: str
    publication_ref: str
    git_environment_policy_fingerprint: str
    evidence_store_authority: DurableEvidenceStoreAuthority
    authority_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        repository: Path,
        publication_ref: str,
        evidence_store_authority: DurableEvidenceStoreAuthority,
    ) -> "FinalizerAuthority":
        body = {
            "schema_version": FINALIZER_AUTHORITY_SCHEMA_VERSION,
            "repository": os.fspath(Path(os.path.abspath(repository))),
            "publication_ref": publication_ref,
            "git_environment_policy_fingerprint": GIT_ENVIRONMENT_POLICY_FINGERPRINT,
            "evidence_store_authority": evidence_store_authority.to_dict(),
        }
        return cls(
            schema_version=FINALIZER_AUTHORITY_SCHEMA_VERSION,
            repository=body["repository"],
            publication_ref=publication_ref,
            git_environment_policy_fingerprint=GIT_ENVIRONMENT_POLICY_FINGERPRINT,
            evidence_store_authority=evidence_store_authority,
            authority_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "repository": self.repository,
            "publication_ref": self.publication_ref,
            "git_environment_policy_fingerprint": self.git_environment_policy_fingerprint,
            "evidence_store_authority": self.evidence_store_authority.to_dict(),
        }

    def validated(self) -> "FinalizerAuthority":
        if self.schema_version != FINALIZER_AUTHORITY_SCHEMA_VERSION:
            raise ValueError("unsupported finalizer authority schema")
        if not isinstance(self.repository, str) or not os.path.isabs(self.repository) or "\x00" in self.repository:
            raise ValueError("finalizer repository identity must be an absolute path")
        if not self.publication_ref.startswith("refs/heads/"):
            raise ValueError("finalizer publication ref must be under refs/heads")
        require_nonempty_text(self.publication_ref, "publication ref", max_bytes=1024)
        require_sha256(self.git_environment_policy_fingerprint, "Git environment policy fingerprint")
        if self.git_environment_policy_fingerprint != GIT_ENVIRONMENT_POLICY_FINGERPRINT:
            raise ValueError("unsupported Git environment policy")
        self.evidence_store_authority.validated()
        require_sha256(self.authority_fingerprint, "finalizer authority fingerprint")
        if fingerprint(self._body()) != self.authority_fingerprint:
            raise ValueError("finalizer authority fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "authority_fingerprint": self.authority_fingerprint}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FinalizerAuthority":
        require_exact_keys(
            data,
            {
                "schema_version",
                "repository",
                "publication_ref",
                "git_environment_policy_fingerprint",
                "evidence_store_authority",
                "authority_fingerprint",
            },
            "finalizer authority",
        )
        return cls(
            schema_version=data["schema_version"],
            repository=data["repository"],
            publication_ref=data["publication_ref"],
            git_environment_policy_fingerprint=data["git_environment_policy_fingerprint"],
            evidence_store_authority=DurableEvidenceStoreAuthority.from_dict(
                data["evidence_store_authority"]
            ),
            authority_fingerprint=data["authority_fingerprint"],
        ).validated()


@dataclass(frozen=True)
class FinalizedTreeEntry:
    schema_version: str
    relative_path: str
    git_mode: str
    git_blob_oid: str
    sha256: str

    def validated(self) -> "FinalizedTreeEntry":
        if self.schema_version != FINALIZED_TREE_ENTRY_SCHEMA_VERSION:
            raise ValueError("unsupported finalized tree-entry schema")
        require_nonempty_text(self.relative_path, "finalized tree path", max_bytes=4096)
        if path_policy_reasons(self.relative_path):
            raise ValueError("finalized tree path violates canonical path policy")
        if self.git_mode not in {"100644", "100755"}:
            raise ValueError("finalized tree entry mode must be regular-file mode")
        require_git_oid(self.git_blob_oid, "finalized Git blob")
        require_sha256(self.sha256, "finalized blob sha256")
        return self

    def to_dict(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "relative_path": self.relative_path,
            "git_mode": self.git_mode,
            "git_blob_oid": self.git_blob_oid,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FinalizedTreeEntry":
        require_exact_keys(
            data,
            {"schema_version", "relative_path", "git_mode", "git_blob_oid", "sha256"},
            "finalized tree entry",
        )
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class FinalizationEvidence:
    """Durable authorization for one exact commit/ref transaction."""

    schema_version: str
    accepted_material: AcceptedMaterialIdentity
    expected_tree: str
    tree_entries: tuple[FinalizedTreeEntry, ...]
    finalizer_authority: FinalizerAuthority
    parent: str
    publication_ref: str
    resulting_commit: str
    message_sha256: str
    evidence_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        accepted_material: AcceptedMaterialIdentity,
        expected_tree: str,
        tree_entries: tuple[FinalizedTreeEntry, ...],
        finalizer_authority: FinalizerAuthority,
        parent: str,
        publication_ref: str,
        resulting_commit: str,
        message: str,
    ) -> "FinalizationEvidence":
        body = {
            "schema_version": FINALIZATION_EVIDENCE_SCHEMA_VERSION,
            "accepted_material": accepted_material.to_dict(),
            "expected_tree": expected_tree,
            "tree_entries": [entry.to_dict() for entry in tree_entries],
            "finalizer_authority": finalizer_authority.to_dict(),
            "parent": parent,
            "publication_ref": publication_ref,
            "resulting_commit": resulting_commit,
            "message_sha256": sha256_bytes(message.encode("utf-8")),
        }
        return cls(
            schema_version=FINALIZATION_EVIDENCE_SCHEMA_VERSION,
            accepted_material=accepted_material,
            expected_tree=expected_tree,
            tree_entries=tree_entries,
            finalizer_authority=finalizer_authority,
            parent=parent,
            publication_ref=publication_ref,
            resulting_commit=resulting_commit,
            message_sha256=body["message_sha256"],
            evidence_fingerprint=fingerprint(body),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "accepted_material": self.accepted_material.to_dict(),
            "expected_tree": self.expected_tree,
            "tree_entries": [entry.to_dict() for entry in self.tree_entries],
            "finalizer_authority": self.finalizer_authority.to_dict(),
            "parent": self.parent,
            "publication_ref": self.publication_ref,
            "resulting_commit": self.resulting_commit,
            "message_sha256": self.message_sha256,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())

    def validated(self) -> "FinalizationEvidence":
        if self.schema_version != FINALIZATION_EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported finalization evidence schema")
        self.accepted_material.validated()
        require_git_oid(self.expected_tree, "expected accepted Git tree")
        if not isinstance(self.tree_entries, tuple) or not self.tree_entries:
            raise ValueError("finalization evidence requires immutable exact tree entries")
        for entry in self.tree_entries:
            entry.validated()
        if tuple(entry.relative_path for entry in self.tree_entries) != tuple(
            sorted(entry.relative_path for entry in self.tree_entries)
        ):
            raise ValueError("finalized tree entries must be canonically ordered")
        material = {
            item.relative_path: (item.git_mode, item.sha256)
            for item in self.accepted_material.files
        }
        entries = {
            item.relative_path: (item.git_mode, item.sha256)
            for item in self.tree_entries
        }
        if entries != material:
            raise ValueError("finalized tree entries differ from accepted material")
        self.finalizer_authority.validated()
        require_git_oid(self.parent, "parent")
        if self.publication_ref != self.finalizer_authority.publication_ref:
            raise ValueError("finalization evidence publication ref differs from finalizer authority")
        require_git_oid(self.resulting_commit, "resulting commit")
        require_sha256(self.message_sha256, "finalization message sha256")
        require_sha256(self.evidence_fingerprint, "finalization evidence fingerprint")
        if fingerprint(self._body()) != self.evidence_fingerprint:
            raise ValueError("finalization evidence fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "evidence_fingerprint": self.evidence_fingerprint}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FinalizationEvidence":
        require_exact_keys(
            data,
            {
                "schema_version",
                "accepted_material",
                "expected_tree",
                "tree_entries",
                "finalizer_authority",
                "parent",
                "publication_ref",
                "resulting_commit",
                "message_sha256",
                "evidence_fingerprint",
            },
            "finalization evidence",
        )
        if not isinstance(data["tree_entries"], list):
            raise ValueError("finalization tree entries must be an array")
        return cls(
            schema_version=data["schema_version"],
            accepted_material=AcceptedMaterialIdentity.from_dict(data["accepted_material"]),
            expected_tree=data["expected_tree"],
            tree_entries=tuple(FinalizedTreeEntry.from_dict(item) for item in data["tree_entries"]),
            finalizer_authority=FinalizerAuthority.from_dict(data["finalizer_authority"]),
            parent=data["parent"],
            publication_ref=data["publication_ref"],
            resulting_commit=data["resulting_commit"],
            message_sha256=data["message_sha256"],
            evidence_fingerprint=data["evidence_fingerprint"],
        ).validated()


@dataclass(frozen=True)
class DurabilityReceipt:
    """Read-back-verifiable receipt for exact evidence bytes at an exact path."""

    schema_version: str
    store_authority: DurableEvidenceStoreAuthority
    evidence_fingerprint: str
    evidence_sha256: str
    destination: str
    destination_fingerprint: str
    receipt_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        store_authority: DurableEvidenceStoreAuthority,
        evidence: FinalizationEvidence,
        destination: Path,
    ) -> "DurabilityReceipt":
        body = {
            "schema_version": DURABILITY_RECEIPT_SCHEMA_VERSION,
            "store_authority": store_authority.to_dict(),
            "evidence_fingerprint": evidence.evidence_fingerprint,
            "evidence_sha256": sha256_bytes(evidence.canonical_bytes()),
            "destination": os.fspath(Path(os.path.abspath(destination))),
            "destination_fingerprint": fingerprint(
                {"absolute_destination": os.fspath(Path(os.path.abspath(destination)))}
            ),
        }
        return cls(
            schema_version=DURABILITY_RECEIPT_SCHEMA_VERSION,
            store_authority=store_authority,
            evidence_fingerprint=evidence.evidence_fingerprint,
            evidence_sha256=body["evidence_sha256"],
            destination=body["destination"],
            destination_fingerprint=body["destination_fingerprint"],
            receipt_fingerprint=fingerprint(body),
        ).verify(evidence)

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "store_authority": self.store_authority.to_dict(),
            "evidence_fingerprint": self.evidence_fingerprint,
            "evidence_sha256": self.evidence_sha256,
            "destination": self.destination,
            "destination_fingerprint": self.destination_fingerprint,
        }

    def validated_structure(self) -> "DurabilityReceipt":
        if self.schema_version != DURABILITY_RECEIPT_SCHEMA_VERSION:
            raise ValueError("unsupported durability receipt schema")
        self.store_authority.validated()
        require_sha256(self.evidence_fingerprint, "receipt evidence fingerprint")
        require_sha256(self.evidence_sha256, "receipt evidence sha256")
        if not isinstance(self.destination, str) or not os.path.isabs(self.destination) or "\x00" in self.destination:
            raise ValueError("receipt destination must be an absolute path")
        expected_destination = os.fspath(
            Path(self.store_authority.evidence_root) / f"{self.evidence_fingerprint}.json"
        )
        if self.destination != expected_destination:
            raise ValueError("receipt destination is outside its trusted evidence store")
        require_sha256(self.destination_fingerprint, "receipt destination fingerprint")
        if fingerprint({"absolute_destination": self.destination}) != self.destination_fingerprint:
            raise ValueError("receipt destination fingerprint mismatch")
        require_sha256(self.receipt_fingerprint, "durability receipt fingerprint")
        if fingerprint(self._body()) != self.receipt_fingerprint:
            raise ValueError("durability receipt fingerprint mismatch")
        return self

    def verify(self, evidence: FinalizationEvidence) -> "DurabilityReceipt":
        self.validated_structure()
        evidence.validated()
        raw = evidence.canonical_bytes()
        if evidence.evidence_fingerprint != self.evidence_fingerprint:
            raise ValueError("durability receipt is bound to different evidence")
        if sha256_bytes(raw) != self.evidence_sha256:
            raise ValueError("durability receipt evidence-byte hash mismatch")
        destination = Path(self.destination)
        try:
            info = destination.lstat()
        except FileNotFoundError as error:
            raise ValueError("durable finalization evidence is missing") from error
        if not stat.S_ISREG(info.st_mode) or destination.is_symlink():
            raise ValueError("durable finalization evidence is not a regular owned file")
        if destination.read_bytes() != raw:
            raise ValueError("durable finalization evidence bytes differ from the receipt")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "receipt_fingerprint": self.receipt_fingerprint}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DurabilityReceipt":
        require_exact_keys(
            data,
            {
                "schema_version",
                "store_authority",
                "evidence_fingerprint",
                "evidence_sha256",
                "destination",
                "destination_fingerprint",
                "receipt_fingerprint",
            },
            "durability receipt",
        )
        return cls(
            schema_version=data["schema_version"],
            store_authority=DurableEvidenceStoreAuthority.from_dict(data["store_authority"]),
            evidence_fingerprint=data["evidence_fingerprint"],
            evidence_sha256=data["evidence_sha256"],
            destination=data["destination"],
            destination_fingerprint=data["destination_fingerprint"],
            receipt_fingerprint=data["receipt_fingerprint"],
        ).validated_structure()


class DurableFinalizationEvidenceStore:
    """Finalizer-owned store which fsyncs evidence and verifies it by read-back."""

    def __init__(self, root: Path):
        self.root = Path(os.path.abspath(root))
        if self.root.is_symlink():
            raise ValueError("durable evidence root must not be a symlink")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.root.is_dir():
            raise ValueError("durable evidence root must be a directory")
        os.chmod(self.root, 0o700)
        fsync_directory(self.root.parent)
        self.authority = DurableEvidenceStoreAuthority.create(self.root)

    def persist(self, evidence: FinalizationEvidence) -> DurabilityReceipt:
        evidence.validated()
        destination = self.root / f"{evidence.evidence_fingerprint}.json"
        raw = evidence.canonical_bytes()
        if destination.exists():
            if destination.is_symlink() or destination.read_bytes() != raw:
                raise ValueError("conflicting durable finalization evidence")
        else:
            atomic_bytes(destination, raw, mode=0o600)
        return DurabilityReceipt.create(
            store_authority=self.authority,
            evidence=evidence,
            destination=destination,
        )

    def verify(
        self,
        evidence: FinalizationEvidence,
        receipt: DurabilityReceipt,
    ) -> DurabilityReceipt:
        if receipt.store_authority != self.authority:
            raise ValueError("durability receipt belongs to another trusted store")
        return receipt.verify(evidence)


@dataclass(frozen=True)
class PreparedFinalization:
    evidence: FinalizationEvidence
    durability_receipt: DurabilityReceipt

    def validated(self) -> "PreparedFinalization":
        self.evidence.validated()
        self.durability_receipt.verify(self.evidence)
        if (
            self.durability_receipt.store_authority
            != self.evidence.finalizer_authority.evidence_store_authority
        ):
            raise ValueError("prepared finalization receipt uses another evidence store")
        return self


@dataclass(frozen=True)
class FinalizationResult:
    schema_version: str
    outcome: FinalizationOutcome
    accepted_material: AcceptedMaterialIdentity
    expected_tree: str
    finalizer_authority: FinalizerAuthority
    durable_evidence: FinalizationEvidence
    durability_receipt: DurabilityReceipt
    parent: str
    publication_ref: str
    resulting_commit: str
    ref_before: str
    ref_after: str
    result_fingerprint: str

    @classmethod
    def create(
        cls,
        *,
        outcome: FinalizationOutcome,
        prepared: PreparedFinalization,
        ref_before: str,
        ref_after: str,
    ) -> "FinalizationResult":
        prepared.validated()
        evidence = prepared.evidence
        body = {
            "schema_version": FINALIZATION_RESULT_SCHEMA_VERSION,
            "outcome": outcome.value,
            "accepted_material": evidence.accepted_material.to_dict(),
            "expected_tree": evidence.expected_tree,
            "finalizer_authority": evidence.finalizer_authority.to_dict(),
            "durable_evidence": evidence.to_dict(),
            "durability_receipt": prepared.durability_receipt.to_dict(),
            "parent": evidence.parent,
            "publication_ref": evidence.publication_ref,
            "resulting_commit": evidence.resulting_commit,
            "ref_before": ref_before,
            "ref_after": ref_after,
        }
        return cls(
            schema_version=FINALIZATION_RESULT_SCHEMA_VERSION,
            outcome=outcome,
            accepted_material=evidence.accepted_material,
            expected_tree=evidence.expected_tree,
            finalizer_authority=evidence.finalizer_authority,
            durable_evidence=evidence,
            durability_receipt=prepared.durability_receipt,
            parent=evidence.parent,
            publication_ref=evidence.publication_ref,
            resulting_commit=evidence.resulting_commit,
            ref_before=ref_before,
            ref_after=ref_after,
            result_fingerprint=fingerprint(body),
        ).validated()

    @property
    def tree(self) -> str:
        return self.expected_tree

    @property
    def commit(self) -> str:
        return self.resulting_commit

    def _body(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "outcome": self.outcome.value,
            "accepted_material": self.accepted_material.to_dict(),
            "expected_tree": self.expected_tree,
            "finalizer_authority": self.finalizer_authority.to_dict(),
            "durable_evidence": self.durable_evidence.to_dict(),
            "durability_receipt": self.durability_receipt.to_dict(),
            "parent": self.parent,
            "publication_ref": self.publication_ref,
            "resulting_commit": self.resulting_commit,
            "ref_before": self.ref_before,
            "ref_after": self.ref_after,
        }

    def validated(self) -> "FinalizationResult":
        if self.schema_version != FINALIZATION_RESULT_SCHEMA_VERSION:
            raise ValueError("unsupported finalization result schema")
        if not isinstance(self.outcome, FinalizationOutcome):
            raise ValueError("unknown finalization outcome")
        self.accepted_material.validated()
        require_git_oid(self.expected_tree, "expected accepted Git tree")
        self.finalizer_authority.validated()
        self.durable_evidence.validated()
        self.durability_receipt.verify(self.durable_evidence)
        require_git_oid(self.parent, "parent")
        require_nonempty_text(self.publication_ref, "publication ref", max_bytes=1024)
        require_git_oid(self.resulting_commit, "resulting commit")
        require_git_oid(self.ref_before, "ref before")
        require_git_oid(self.ref_after, "ref after")
        evidence = self.durable_evidence
        if (
            self.accepted_material != evidence.accepted_material
            or self.expected_tree != evidence.expected_tree
            or self.finalizer_authority != evidence.finalizer_authority
            or self.parent != evidence.parent
            or self.publication_ref != evidence.publication_ref
            or self.resulting_commit != evidence.resulting_commit
            or self.durability_receipt.store_authority
            != self.finalizer_authority.evidence_store_authority
        ):
            raise ValueError("finalization result differs from its durable authorization evidence")
        if self.outcome is FinalizationOutcome.PUBLISHED and (
            self.ref_before != self.parent or self.ref_after != self.resulting_commit
        ):
            raise ValueError("published finalization carries contradictory ref identities")
        if self.outcome is FinalizationOutcome.IDEMPOTENT_SAME_ACCEPTED_IDENTITY and (
            self.ref_before != self.resulting_commit or self.ref_after != self.resulting_commit
        ):
            raise ValueError("idempotent finalization carries contradictory ref identities")
        repository = Path(self.finalizer_authority.repository)
        if not repository.is_dir():
            raise ValueError("finalization result repository is unavailable")
        read_environment = _git_environment()
        current = git(
            repository,
            "show-ref",
            "--hash",
            "--verify",
            self.publication_ref,
            env=read_environment,
            check=False,
        )
        current_id = current.stdout.decode().strip() if current.returncode == 0 else None
        if current_id != self.ref_after:
            raise ValueError("finalization result ref-after identity is not durable in its repository")
        commit_tree = (
            git(
                repository,
                "show",
                "-s",
                "--format=%T",
                self.resulting_commit,
                env=read_environment,
            )
            .stdout.decode()
            .strip()
        )
        commit_parents = (
            git(
                repository,
                "show",
                "-s",
                "--format=%P",
                self.resulting_commit,
                env=read_environment,
            )
            .stdout.decode()
            .split()
        )
        if commit_tree != self.expected_tree or commit_parents != [self.parent]:
            raise ValueError("finalization result commit differs from authorized tree or parent")
        require_sha256(self.result_fingerprint, "finalization result fingerprint")
        if fingerprint(self._body()) != self.result_fingerprint:
            raise ValueError("finalization result fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "result_fingerprint": self.result_fingerprint}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FinalizationResult":
        require_exact_keys(
            data,
            {
                "schema_version",
                "outcome",
                "accepted_material",
                "expected_tree",
                "finalizer_authority",
                "durable_evidence",
                "durability_receipt",
                "parent",
                "publication_ref",
                "resulting_commit",
                "ref_before",
                "ref_after",
                "result_fingerprint",
            },
            "finalization result",
        )
        return cls(
            schema_version=data["schema_version"],
            outcome=FinalizationOutcome(data["outcome"]),
            accepted_material=AcceptedMaterialIdentity.from_dict(data["accepted_material"]),
            expected_tree=data["expected_tree"],
            finalizer_authority=FinalizerAuthority.from_dict(data["finalizer_authority"]),
            durable_evidence=FinalizationEvidence.from_dict(data["durable_evidence"]),
            durability_receipt=DurabilityReceipt.from_dict(data["durability_receipt"]),
            parent=data["parent"],
            publication_ref=data["publication_ref"],
            resulting_commit=data["resulting_commit"],
            ref_before=data["ref_before"],
            ref_after=data["ref_after"],
            result_fingerprint=data["result_fingerprint"],
        ).validated()


def _git_executable_directory() -> str:
    executable = shutil.which("git", path=os.defpath)
    if executable is None:
        raise RuntimeError("git executable is unavailable")
    return os.fspath(Path(executable).parent)


def _git_environment(
    identity: Mapping[str, str] | None = None,
    *,
    environment_root: Path | None = None,
    hooks_directory: Path | None = None,
    private_index: Path | None = None,
) -> dict[str, str]:
    """Construct a minimal closed Git environment without ambient inheritance."""

    root = Path(environment_root or "/nonexistent/admissible-capsule-finalizer")
    hooks = Path(hooks_directory or "/dev/null")
    environment = {
        "PATH": _git_executable_directory(),
        "HOME": os.fspath(root / "home"),
        "XDG_CONFIG_HOME": os.fspath(root / "xdg"),
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_COUNT": "5",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_VALUE_0": os.fspath(hooks),
        "GIT_CONFIG_KEY_1": "core.attributesFile",
        "GIT_CONFIG_VALUE_1": os.devnull,
        "GIT_CONFIG_KEY_2": "core.excludesFile",
        "GIT_CONFIG_VALUE_2": os.devnull,
        "GIT_CONFIG_KEY_3": "core.autocrlf",
        "GIT_CONFIG_VALUE_3": "false",
        "GIT_CONFIG_KEY_4": "core.safecrlf",
        "GIT_CONFIG_VALUE_4": "false",
    }
    if private_index is not None:
        environment["GIT_INDEX_FILE"] = os.fspath(Path(os.path.abspath(private_index)))
    if identity is not None:
        environment.update(
            {
                "GIT_AUTHOR_NAME": identity["author_name"],
                "GIT_AUTHOR_EMAIL": identity["author_email"],
                "GIT_AUTHOR_DATE": identity["author_date"],
                "GIT_COMMITTER_NAME": identity["committer_name"],
                "GIT_COMMITTER_EMAIL": identity["committer_email"],
                "GIT_COMMITTER_DATE": identity["committer_date"],
            }
        )
    return environment


def _closed_environment_paths(repository: Path, name: str) -> tuple[Path, Path]:
    root = repository.parent / f".{repository.name}.{name}-git-environment"
    hooks = root / "hooks"
    for directory in (root, root / "home", root / "xdg", hooks):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
    return root, hooks


def initialize_disposable_repository(
    repository: Path,
    *,
    parent_identity: Mapping[str, str],
    parent_message: str = "trusted synthetic parent\n",
    target_ref: str = DEFAULT_TARGET_REF,
) -> str:
    """Create a disposable bare repository using the closed Git environment."""

    repository.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    environment_root, hooks = _closed_environment_paths(repository, "initializer")
    template = repository.parent / f".{repository.name}.empty-template"
    template.mkdir(parents=True, exist_ok=True, mode=0o700)
    environment = _git_environment(
        environment_root=environment_root,
        hooks_directory=hooks,
    )
    completed = subprocess.run(
        [
            os.fspath(Path(_git_executable_directory()) / "git"),
            "init",
            "--bare",
            f"--template={template}",
            str(repository),
        ],
        env=environment,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.decode("utf-8", "replace"))
    empty_tree = git(repository, "mktree", env=environment, input_bytes=b"").stdout.decode().strip()
    parent = (
        git(
            repository,
            "commit-tree",
            empty_tree,
            env=_git_environment(
                parent_identity,
                environment_root=environment_root,
                hooks_directory=hooks,
            ),
            input_bytes=parent_message.encode("utf-8"),
        )
        .stdout.decode()
        .strip()
    )
    git(repository, "update-ref", target_ref, parent, env=environment)
    return parent


class FinalizerPreconditionError(ValueError):
    """Finalization evidence, material, or durability is not authoritative."""


class FinalizerOperationalError(RuntimeError):
    """Git failed without evidence of a compare-and-swap conflict."""


class AdmissibleFinalizer:
    """Build, durably authorize, and publish one exact accepted Git commit."""

    def __init__(
        self,
        repository: Path,
        *,
        target_ref: str = DEFAULT_TARGET_REF,
        evidence_store: DurableFinalizationEvidenceStore | None = None,
    ):
        self.repository = Path(repository)
        self.target_ref = target_ref
        self.environment_root, self.hooks_directory = _closed_environment_paths(
            self.repository, "finalizer"
        )
        if any(self.hooks_directory.iterdir()):
            raise ValueError("finalizer-owned hooks directory must be empty")
        self.environment = _git_environment(
            environment_root=self.environment_root,
            hooks_directory=self.hooks_directory,
        )
        self.evidence_store = evidence_store or DurableFinalizationEvidenceStore(
            self.repository.parent / f"{self.repository.name}.finalization-evidence"
        )
        self.authority = FinalizerAuthority.create(
            repository=self.repository,
            publication_ref=target_ref,
            evidence_store_authority=self.evidence_store.authority,
        )
        for alternate_file in (
            self.repository / "objects" / "info" / "alternates",
            self.repository / "objects" / "info" / "http-alternates",
        ):
            if alternate_file.exists() or alternate_file.is_symlink():
                raise ValueError("finalizer repository must not use alternate object directories")
        remotes = git(self.repository, "remote", env=self.environment).stdout.decode().split()
        if remotes:
            raise ValueError("finalizer repository must not carry remotes")

    def _index_environment(self, private_index: Path) -> dict[str, str]:
        return _git_environment(
            environment_root=self.environment_root,
            hooks_directory=self.hooks_directory,
            private_index=private_index,
        )

    @staticmethod
    def _validate_material_blobs(
        accepted_material: AcceptedMaterialIdentity,
        accepted_blobs: tuple[AcceptedBlob, ...],
    ) -> tuple[AcceptedBlob, ...]:
        accepted_material.validated()
        if not isinstance(accepted_blobs, tuple) or not accepted_blobs:
            raise FinalizerPreconditionError("finalization requires immutable accepted blobs")
        for blob in accepted_blobs:
            blob.validated()
        ordered = tuple(sorted(accepted_blobs, key=lambda item: item.relative_path))
        if len({blob.relative_path for blob in ordered}) != len(ordered):
            raise FinalizerPreconditionError("accepted blobs contain duplicate paths")
        blob_manifest = [
            {
                "relative_path": blob.relative_path,
                "size": len(blob.data),
                "sha256": blob.sha256,
                "git_mode": blob.git_mode,
            }
            for blob in ordered
        ]
        if blob_manifest != [record.to_dict() for record in accepted_material.files]:
            raise FinalizerPreconditionError("accepted blobs differ from canonical accepted material")
        return ordered

    def _parse_tree(self, tree: str) -> tuple[FinalizedTreeEntry, ...]:
        raw = git(
            self.repository,
            "ls-tree",
            "-r",
            "-z",
            tree,
            env=self.environment,
        ).stdout
        entries: list[FinalizedTreeEntry] = []
        for record in raw.split(b"\0"):
            if not record:
                continue
            metadata, encoded_path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.decode("ascii").split(" ")
            if kind != "blob":
                raise FinalizerPreconditionError("expected accepted tree contains a non-blob entry")
            path = encoded_path.decode("utf-8", "strict")
            data = git(
                self.repository,
                "cat-file",
                "blob",
                object_id,
                env=self.environment,
            ).stdout
            entries.append(
                FinalizedTreeEntry(
                    schema_version=FINALIZED_TREE_ENTRY_SCHEMA_VERSION,
                    relative_path=path,
                    git_mode=mode,
                    git_blob_oid=object_id,
                    sha256=sha256_bytes(data),
                ).validated()
            )
        return tuple(sorted(entries, key=lambda item: item.relative_path))

    def build_commit(
        self,
        *,
        parent: str,
        accepted_material: AcceptedMaterialIdentity,
        accepted_blobs: tuple[AcceptedBlob, ...],
        private_index: Path,
        message: str,
    ) -> dict[str, Any]:
        """Build from an explicitly empty private index and verify every entry."""

        require_git_oid(parent, "parent")
        require_nonempty_text(message, "commit message", max_bytes=1024 * 1024)
        ordered = self._validate_material_blobs(accepted_material, accepted_blobs)
        private_index.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if private_index.exists():
            private_index.unlink()
        environment = self._index_environment(private_index)
        git(self.repository, "read-tree", "--empty", env=environment)
        for blob in ordered:
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
                f"{blob.git_mode},{object_id},{blob.relative_path}",
                env=environment,
            )
        tree = git(self.repository, "write-tree", env=environment).stdout.decode().strip()
        entries = self._parse_tree(tree)
        expected_manifest = {
            item.relative_path: (item.git_mode, item.sha256)
            for item in accepted_material.files
        }
        actual_manifest = {
            item.relative_path: (item.git_mode, item.sha256)
            for item in entries
        }
        if actual_manifest != expected_manifest:
            raise FinalizerPreconditionError(
                "produced Git tree has inherited, extra, missing, mode-mismatched, or byte-mismatched paths"
            )
        commit = (
            git(
                self.repository,
                "commit-tree",
                tree,
                "-p",
                parent,
                env=_git_environment(
                    FROZEN_IDENTITY,
                    environment_root=self.environment_root,
                    hooks_directory=self.hooks_directory,
                    private_index=private_index,
                ),
                input_bytes=message.encode("utf-8"),
            )
            .stdout.decode()
            .strip()
        )
        return {"tree": tree, "commit": commit, "tree_entries": entries}

    def prepare(
        self,
        *,
        parent: str,
        accepted_material: AcceptedMaterialIdentity,
        accepted_blobs: tuple[AcceptedBlob, ...],
        private_index: Path,
        message: str,
    ) -> PreparedFinalization:
        built = self.build_commit(
            parent=parent,
            accepted_material=accepted_material,
            accepted_blobs=accepted_blobs,
            private_index=private_index,
            message=message,
        )
        evidence = FinalizationEvidence.create(
            accepted_material=accepted_material,
            expected_tree=built["tree"],
            tree_entries=built["tree_entries"],
            finalizer_authority=self.authority,
            parent=parent,
            publication_ref=self.target_ref,
            resulting_commit=built["commit"],
            message=message,
        )
        receipt = self.evidence_store.persist(evidence)
        return PreparedFinalization(evidence=evidence, durability_receipt=receipt).validated()

    def _verify_prepared_objects(self, prepared: PreparedFinalization) -> None:
        prepared.validated()
        evidence = prepared.evidence
        if evidence.finalizer_authority != self.authority:
            raise FinalizerPreconditionError("prepared finalization belongs to another finalizer authority")
        self.evidence_store.verify(evidence, prepared.durability_receipt)
        entries = self._parse_tree(evidence.expected_tree)
        if entries != evidence.tree_entries:
            raise FinalizerPreconditionError("expected accepted tree no longer matches durable evidence")
        commit_tree = (
            git(
                self.repository,
                "show",
                "-s",
                "--format=%T",
                evidence.resulting_commit,
                env=self.environment,
            )
            .stdout.decode()
            .strip()
        )
        parents = (
            git(
                self.repository,
                "show",
                "-s",
                "--format=%P",
                evidence.resulting_commit,
                env=self.environment,
            )
            .stdout.decode()
            .split()
        )
        raw_commit = git(
            self.repository,
            "cat-file",
            "commit",
            evidence.resulting_commit,
            env=self.environment,
        ).stdout
        separator = raw_commit.find(b"\n\n")
        if separator < 0:
            raise FinalizerPreconditionError("prepared commit has no canonical message boundary")
        message = raw_commit[separator + 2 :]
        if (
            commit_tree != evidence.expected_tree
            or parents != [evidence.parent]
            or sha256_bytes(message) != evidence.message_sha256
        ):
            raise FinalizerPreconditionError("prepared commit differs from its durable evidence")

    def finalize(
        self,
        *,
        prepared: PreparedFinalization,
        crash_before_update_ref: bool = False,
    ) -> FinalizationResult:
        """Publish only after trusted evidence persistence and exact read-back."""

        self._verify_prepared_objects(prepared)
        evidence = prepared.evidence
        current = self.current_ref()
        if current is None:
            raise FinalizerOperationalError("publication ref unexpectedly does not exist")
        if current == evidence.resulting_commit:
            return FinalizationResult.create(
                outcome=FinalizationOutcome.IDEMPOTENT_SAME_ACCEPTED_IDENTITY,
                prepared=prepared,
                ref_before=current,
                ref_after=current,
            )
        if current != evidence.parent:
            return FinalizationResult.create(
                outcome=FinalizationOutcome.COMPARE_AND_SWAP_REFUSED,
                prepared=prepared,
                ref_before=current,
                ref_after=current,
            )
        if crash_before_update_ref:
            raise CrashInjected(
                f"crash injected before update-ref; unreachable commit={evidence.resulting_commit}"
            )
        updated = git(
            self.repository,
            "update-ref",
            evidence.publication_ref,
            evidence.resulting_commit,
            evidence.parent,
            env=self.environment,
            check=False,
        )
        if updated.returncode != 0:
            after = self.current_ref()
            if after is not None and after != current:
                return FinalizationResult.create(
                    outcome=FinalizationOutcome.COMPARE_AND_SWAP_REFUSED,
                    prepared=prepared,
                    ref_before=current,
                    ref_after=after,
                )
            raise FinalizerOperationalError(
                "Git update-ref failed without a compare-and-swap conflict: "
                + updated.stderr.decode("utf-8", "replace")
            )
        return FinalizationResult.create(
            outcome=FinalizationOutcome.PUBLISHED,
            prepared=prepared,
            ref_before=current,
            ref_after=evidence.resulting_commit,
        )

    def current_ref(self) -> str | None:
        current = git(
            self.repository,
            "show-ref",
            "--hash",
            "--verify",
            self.target_ref,
            env=self.environment,
            check=False,
        )
        return current.stdout.decode().strip() if current.returncode == 0 else None

    def verify(self, *, prepared: PreparedFinalization) -> dict[str, Any]:
        """Read-only proof of exact material, ancestry, authority, and receipt."""

        self._verify_prepared_objects(prepared)
        evidence = prepared.evidence
        ref = self.current_ref()
        ok = ref == evidence.resulting_commit
        if ok:
            committed_entries = self._parse_tree(evidence.expected_tree)
            ok = committed_entries == evidence.tree_entries
        return {
            "ref": ref,
            "parent": evidence.parent,
            "tree": evidence.expected_tree,
            "material_fingerprint": evidence.accepted_material.material_fingerprint,
            "finalizer_authority_fingerprint": self.authority.authority_fingerprint,
            "durability_receipt_fingerprint": prepared.durability_receipt.receipt_fingerprint,
            "ok": ok,
        }
