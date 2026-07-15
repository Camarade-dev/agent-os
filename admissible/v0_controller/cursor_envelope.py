"""The narrow typed V0 proposal envelope Cursor must return.

The canonical terminal ``result`` text is scanned for exactly one marker-delimited
JSON envelope.  Nothing else in the text is authority: prose, markdown fences,
Cursor status narration, and planning chatter are never inferred into actions.

Envelope shape (the only accepted form)::

    ADMISSIBLE_V0_PROPOSAL_BEGIN
    {
      "schema_version": "admissible_v0_proposal_envelope_v1",
      "invocation_id": "<exact persisted invocation id>",
      "batch_id": "<exact expected batch id>",
      "operations": [
        {"action_id": "...", "kind": "write_file", "path": "src/main.js", "content": "..."}
      ]
    }
    ADMISSIBLE_V0_PROPOSAL_END

At most four operations.  ``kind`` is preserved exactly as sent and must equal
``write_file``; every other kind (shell, command, network, browser, deploy,
package, git, ...) is rejected rather than normalized.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from admissible.v0_controller.adapters import MAX_PROPOSAL_OPERATIONS, V0ProposalOperation
from admissible.v0_controller.cursor_failures import V0BackendFailureKind, V0ProposalBackendFailure
from admissible.v0_controller.state import _safe_relative_path

ENVELOPE_SCHEMA_VERSION = "admissible_v0_proposal_envelope_v1"
ENVELOPE_BEGIN = "ADMISSIBLE_V0_PROPOSAL_BEGIN"
ENVELOPE_END = "ADMISSIBLE_V0_PROPOSAL_END"
WRITE_FILE_KIND = "write_file"

_OPERATION_FIELDS = frozenset({"action_id", "kind", "path", "content"})
_ENVELOPE_FIELDS = frozenset({"schema_version", "invocation_id", "batch_id", "operations"})


@dataclass(frozen=True)
class ParsedProposalEnvelope:
    """One authoritative typed proposal extracted from a terminal result."""

    schema_version: str
    invocation_id: str
    batch_id: str
    operations: tuple[V0ProposalOperation, ...]


def _reject(kind: V0BackendFailureKind, message: str) -> "V0ProposalBackendFailure":
    return V0ProposalBackendFailure(kind, message)


def _strip_code_fences(block: str) -> str:
    """Tolerate a fence *inside* the typed envelope; never accept a bare fence."""

    text = block.strip()
    if not text.startswith("```"):
        return text
    lines = text.splitlines()
    if len(lines) < 2 or not lines[-1].strip().startswith("```"):
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            "The typed envelope contains an unterminated markdown code fence.",
        )
    return "\n".join(lines[1:-1]).strip()


def extract_envelope_block(canonical_result: str) -> str:
    """Return the single marker-delimited block, rejecting zero or many."""

    begins = canonical_result.count(ENVELOPE_BEGIN)
    ends = canonical_result.count(ENVELOPE_END)
    if begins == 0:
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            "Terminal result carried no typed V0 proposal envelope; prose, markdown fences, and "
            "completion claims are not authority.",
        )
    if begins > 1 or ends > 1:
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            f"Terminal result carried {begins} proposal envelope begin marker(s) and {ends} end "
            "marker(s); exactly one authoritative envelope is required.",
        )
    if ends == 0:
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            "The typed V0 proposal envelope was never terminated.",
        )
    start = canonical_result.index(ENVELOPE_BEGIN) + len(ENVELOPE_BEGIN)
    stop = canonical_result.index(ENVELOPE_END)
    if stop < start:
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            "The typed V0 proposal envelope markers are inverted.",
        )
    return _strip_code_fences(canonical_result[start:stop])


def _decode(block: str) -> dict[str, Any]:
    try:
        decoded = json.loads(block)
    except (ValueError, TypeError) as exc:
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            f"The typed V0 proposal envelope is not valid JSON: {type(exc).__name__}.",
        ) from exc
    if not isinstance(decoded, dict):
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            "The typed V0 proposal envelope must decode to a JSON object.",
        )
    return decoded


def _parse_operations(raw_operations: Any, *, max_operations: int) -> tuple[V0ProposalOperation, ...]:
    if not isinstance(raw_operations, list) or not raw_operations:
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            "The typed V0 proposal envelope requires a non-empty `operations` array.",
        )
    if len(raw_operations) > max_operations:
        raise _reject(
            V0BackendFailureKind.PROPOSAL_OPERATION_LIMIT_EXCEEDED,
            f"The proposal carries {len(raw_operations)} operations; at most {max_operations} are permitted.",
        )
    operations: list[V0ProposalOperation] = []
    for index, item in enumerate(raw_operations):
        if not isinstance(item, dict):
            raise _reject(
                V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
                f"Operation {index} is not a JSON object.",
            )
        if set(item) != _OPERATION_FIELDS:
            raise _reject(
                V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
                f"Operation {index} fields must be exactly {sorted(_OPERATION_FIELDS)}.",
            )
        action_id = item["action_id"]
        kind = item["kind"]
        path = item["path"]
        content = item["content"]
        if not isinstance(action_id, str) or not action_id:
            raise _reject(
                V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
                f"Operation {index} has a missing or non-string `action_id`.",
            )
        # The kind is preserved exactly, never normalized: an unsupported kind
        # (shell/network/browser/deploy/...) must reject, not become a write.
        if kind != WRITE_FILE_KIND:
            raise _reject(
                V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
                f"Operation {index} has unsupported kind {kind!r}; only {WRITE_FILE_KIND!r} is permitted.",
            )
        if not isinstance(path, str) or not _safe_relative_path(path):
            raise _reject(
                V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
                f"Operation {index} path {path!r} is not a canonical relative workspace path.",
            )
        if not isinstance(content, str):
            raise _reject(
                V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
                f"Operation {index} must carry complete final file content as a string.",
            )
        operations.append(
            V0ProposalOperation(action_id=action_id, path=path, content=content, operation_kind=kind)
        )

    action_ids = [item.action_id for item in operations]
    if len(set(action_ids)) != len(action_ids):
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            "Proposal action IDs must be unique within one envelope.",
        )
    paths = [item.path for item in operations]
    if len(set(paths)) != len(paths):
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            "Proposal paths must be unique within one envelope.",
        )
    return tuple(operations)


def parse_proposal_envelope(
    canonical_result: str,
    *,
    expected_invocation_id: str,
    expected_batch_id: str,
    max_operations: int = MAX_PROPOSAL_OPERATIONS,
) -> ParsedProposalEnvelope:
    """Extract the one authoritative typed proposal, or fail closed."""

    envelope = _decode(extract_envelope_block(canonical_result))
    if set(envelope) != _ENVELOPE_FIELDS:
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            f"The typed V0 proposal envelope fields must be exactly {sorted(_ENVELOPE_FIELDS)}.",
        )
    if envelope["schema_version"] != ENVELOPE_SCHEMA_VERSION:
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            f"Unsupported proposal schema version {envelope['schema_version']!r}.",
        )
    invocation_id = envelope["invocation_id"]
    batch_id = envelope["batch_id"]
    if not isinstance(invocation_id, str) or not invocation_id or not isinstance(batch_id, str) or not batch_id:
        raise _reject(
            V0BackendFailureKind.INVALID_PROPOSAL_SCHEMA,
            "The typed V0 proposal envelope requires non-empty `invocation_id` and `batch_id`.",
        )
    if invocation_id != expected_invocation_id:
        raise _reject(
            V0BackendFailureKind.INVOCATION_MISMATCH,
            f"Proposal invocation_id {invocation_id!r} does not match the persisted invocation "
            f"{expected_invocation_id!r}.",
        )
    if batch_id != expected_batch_id:
        raise _reject(
            V0BackendFailureKind.INVOCATION_MISMATCH,
            f"Proposal batch_id {batch_id!r} does not match the expected turn batch {expected_batch_id!r}.",
        )
    operations = _parse_operations(envelope["operations"], max_operations=max_operations)
    return ParsedProposalEnvelope(
        schema_version=ENVELOPE_SCHEMA_VERSION,
        invocation_id=invocation_id,
        batch_id=batch_id,
        operations=operations,
    )


__all__ = [
    "ENVELOPE_BEGIN",
    "ENVELOPE_END",
    "ENVELOPE_SCHEMA_VERSION",
    "ParsedProposalEnvelope",
    "WRITE_FILE_KIND",
    "extract_envelope_block",
    "parse_proposal_envelope",
]
