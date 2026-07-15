"""Persisted-fact-only proposal context for the V0 Cursor backend (Slice 3).

The content Cursor sees for an already-materialized file is *never* a fresh read
of the target application workspace.  It is reconstructed from the persisted V0
execution lineage that created the file:

    FileEvidence  ->  V0ExecutionReceipt  ->  admitted ProposedOperation
                                              (its complete intended content)

Equivalent persisted state therefore always produces a byte-identical context,
independent of live target drift.

The physical target is still *attested* immediately before a dispatch -- but
only as a fail-closed check.  If a materialized file no longer matches its
durable receipt, the backend does not build a different instruction, omit the
file, or substitute its content: it refuses to invoke Cursor at all and the
session enters a bounded ``materialized_context_drift`` technical pause.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from admissible.execution.bounded_write import BoundedWriteError, attest_physical_file
from admissible.v0_controller.cursor_failures import (
    V0BackendFailureKind,
    V0ProposalBackendFailure,
)
from admissible.v0_controller.state import BatchRecord, FileEvidence, SessionState

DEFAULT_MAX_CONTEXT_BYTES = 256 * 1024


@dataclass(frozen=True)
class PersistedContextFile:
    """One materialized file, reconstructed entirely from persisted V0 facts."""

    path: str
    sha256: str
    byte_count: int
    content_bytes: bytes
    action_id: str
    batch_id: str
    invocation_id: str
    execution_receipt_id: str

    def manifest_entry(self) -> dict[str, object]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "byte_count": self.byte_count,
            "action_id": self.action_id,
            "batch_id": self.batch_id,
            "invocation_id": self.invocation_id,
            "execution_receipt_id": self.execution_receipt_id,
        }


@dataclass(frozen=True)
class PersistedContextSnapshot:
    """The complete, deterministic context derived from one persisted state."""

    files: tuple[PersistedContextFile, ...]
    skipped_paths: tuple[str, ...]

    def contents(self) -> dict[str, bytes]:
        return {item.path: item.content_bytes for item in self.files}

    def manifest(self) -> dict[str, object]:
        return {
            "schema_version": "admissible_v0_persisted_context_v1",
            "files": [item.manifest_entry() for item in sorted(self.files, key=lambda item: item.path)],
            "skipped_paths": list(self.skipped_paths),
        }


def _fail(kind: V0BackendFailureKind, message: str) -> "V0ProposalBackendFailure":
    return V0ProposalBackendFailure(kind, message)


def _all_batches(state: SessionState) -> tuple[BatchRecord, ...]:
    batches = list(state.batch_history)
    if state.current_batch is not None:
        batches.append(state.current_batch)
    return tuple(batches)


def _persisted_content_for(state: SessionState, evidence: FileEvidence) -> bytes:
    """Join FileEvidence -> receipt -> admitted operation, or fail closed."""

    receipts = [
        receipt
        for receipt in state.execution_receipt_history
        if receipt.receipt_id == evidence.execution_receipt_id
    ]
    if len(receipts) != 1:
        raise _fail(
            V0BackendFailureKind.PERSISTED_CONTEXT_UNAVAILABLE,
            f"Exactly one persisted execution receipt must back {evidence.path!r}; found {len(receipts)}.",
        )
    receipt = receipts[0]
    if (
        receipt.session_id != state.session_id
        or receipt.path != evidence.path
        or receipt.action_id != evidence.action_id
        or receipt.batch_id != evidence.batch_id
        or receipt.invocation_id != evidence.invocation_id
        or receipt.execution_command_id != evidence.execution_command_id
        or receipt.sha256 != evidence.sha256
        or receipt.byte_count != evidence.byte_count
        or receipt.operation_kind != "write_file"
    ):
        raise _fail(
            V0BackendFailureKind.PERSISTED_CONTEXT_UNAVAILABLE,
            f"The persisted receipt for {evidence.path!r} does not correlate to its durable evidence.",
        )

    batches = [batch for batch in _all_batches(state) if batch.batch_id == evidence.batch_id]
    if len(batches) != 1:
        raise _fail(
            V0BackendFailureKind.PERSISTED_CONTEXT_UNAVAILABLE,
            f"Exactly one persisted batch must own {evidence.path!r}; found {len(batches)}.",
        )
    batch = batches[0]
    operations = [
        operation
        for operation in batch.proposed_operations
        if operation.operation_id == evidence.action_id
        and operation.operation_id in set(batch.admitted_operation_ids)
    ]
    if len(operations) != 1:
        raise _fail(
            V0BackendFailureKind.PERSISTED_CONTEXT_UNAVAILABLE,
            f"The admitted operation that wrote {evidence.path!r} is not in the persisted batch history.",
        )
    operation = operations[0]
    structured = operation.operation
    content = structured.get("content")
    if operation.path != evidence.path or structured.get("operation") != "write_file" or not isinstance(content, str):
        raise _fail(
            V0BackendFailureKind.PERSISTED_CONTEXT_UNAVAILABLE,
            f"The persisted admitted operation for {evidence.path!r} carries no complete write_file content.",
        )
    # Bytes, never text: the receipt's SHA-256 is over the exact bytes written,
    # so CRLF and every other line ending must survive untouched.
    content_bytes = content.encode("utf-8")
    if hashlib.sha256(content_bytes).hexdigest() != evidence.sha256 or len(content_bytes) != evidence.byte_count:
        raise _fail(
            V0BackendFailureKind.PERSISTED_CONTEXT_UNAVAILABLE,
            f"The persisted admitted content for {evidence.path!r} does not hash to its durable receipt.",
        )
    return content_bytes


def reattest_materialized_targets(state: SessionState) -> None:
    """Fail closed if any materialized physical file drifted from its receipt.

    This never *sources* content -- it only refuses to dispatch when the world
    no longer matches the persisted facts that the instruction was built from.
    """

    authority = state.workspace_authority
    if authority is None:
        raise _fail(
            V0BackendFailureKind.MATERIALIZED_CONTEXT_DRIFT,
            "Materialized proposal context requires the persisted workspace authority descriptor.",
        )
    for evidence in state.materialized_evidence:
        # The historical resolved path is a comparison fact only.  The file is
        # opened only after the current logical workspace has been revalidated
        # and the canonical relative admitted-operation path has been derived
        # through the original Slice 2 authority boundary.
        expected_content = _persisted_content_for(state, evidence)
        try:
            facts = attest_physical_file(
                authority=authority,
                relative_path=evidence.path,
                expected_resolved_target=evidence.resolved_target,
                expected_physical_identity_key=evidence.physical_identity_key,
                expected_content=expected_content,
            )
        except BoundedWriteError as exc:
            raise _fail(
                V0BackendFailureKind.MATERIALIZED_CONTEXT_DRIFT,
                f"The materialized target for {evidence.path!r} failed workspace-authority re-attestation: "
                f"{getattr(exc, 'diagnostic', 'physical_attestation_failed')}.",
            ) from exc
        if (
            facts.resolved_target != evidence.resolved_target
            or facts.physical_identity_key != evidence.physical_identity_key
            or facts.sha256 != evidence.sha256
            or facts.byte_count != evidence.byte_count
            or facts.content != expected_content
        ):
            raise _fail(
                V0BackendFailureKind.MATERIALIZED_CONTEXT_DRIFT,
                f"The materialized target for {evidence.path!r} no longer matches its durable receipt.",
            )


def build_persisted_context(
    state: SessionState,
    *,
    include_materialized_content: bool = True,
    max_context_bytes: int = DEFAULT_MAX_CONTEXT_BYTES,
) -> PersistedContextSnapshot:
    """Reconstruct the bounded proposal context from persisted facts alone."""

    if not include_materialized_content:
        return PersistedContextSnapshot(
            files=(),
            skipped_paths=tuple(sorted(item.path for item in state.materialized_evidence)),
        )
    files: list[PersistedContextFile] = []
    skipped: list[str] = []
    budget = max_context_bytes
    # Deterministic order: the persisted evidence order is itself deterministic,
    # but the budget must not depend on it, so bound by canonical path order.
    for evidence in sorted(state.materialized_evidence, key=lambda item: item.path):
        if evidence.byte_count > budget:
            skipped.append(evidence.path)
            continue
        content_bytes = _persisted_content_for(state, evidence)
        budget -= len(content_bytes)
        files.append(
            PersistedContextFile(
                path=evidence.path,
                sha256=evidence.sha256,
                byte_count=evidence.byte_count,
                content_bytes=content_bytes,
                action_id=evidence.action_id,
                batch_id=evidence.batch_id,
                invocation_id=evidence.invocation_id,
                execution_receipt_id=evidence.execution_receipt_id,
            )
        )
    return PersistedContextSnapshot(files=tuple(files), skipped_paths=tuple(skipped))


__all__ = [
    "DEFAULT_MAX_CONTEXT_BYTES",
    "PersistedContextFile",
    "PersistedContextSnapshot",
    "build_persisted_context",
    "reattest_materialized_targets",
]
