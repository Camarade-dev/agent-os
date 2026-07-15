"""The isolated agent workspace given to Cursor.

Cursor never receives a writable path to the real target application workspace.
It is given its own directory containing only bounded proposal context:

- the rendered governed instruction;
- the typed instruction JSON;
- read-only copies of already-materialized application files, whose bytes come
  from the *persisted* admitted operation that created each durable receipt --
  never from a fresh read of the live target
  (:mod:`admissible.v0_controller.cursor_context`);
- a deterministic context manifest.

The synchronization is one-directional by construction, the agent workspace is
required to sit outside the target workspace, and the whole workspace is rebuilt
from scratch on every invocation so no stale file from another session or
invocation can survive into a later proposal.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from admissible.v0_controller.cursor_context import PersistedContextSnapshot
from admissible.v0_controller.cursor_failures import V0BackendFailureKind, V0ProposalBackendFailure

DEFAULT_MAX_CONTEXT_BYTES = 256 * 1024

INSTRUCTION_FILE = "INSTRUCTION.md"
INSTRUCTION_JSON_FILE = "instruction.json"
CONTEXT_MANIFEST_FILE = "context_manifest.json"
CONTEXT_DIRECTORY = "context"

_MANAGED_ENTRIES = (INSTRUCTION_FILE, INSTRUCTION_JSON_FILE, CONTEXT_MANIFEST_FILE, CONTEXT_DIRECTORY)


@dataclass(frozen=True)
class ContextFile:
    """One bounded, hash-recorded read-only copy of a materialized target file."""

    path: str
    sha256: str
    byte_count: int


@dataclass
class V0AgentWorkspace:
    """The only directory Cursor is allowed to see."""

    root: Path
    max_context_bytes: int = DEFAULT_MAX_CONTEXT_BYTES
    include_materialized_content: bool = True
    context_files: tuple[ContextFile, ...] = field(default_factory=tuple)
    skipped_context_paths: tuple[str, ...] = field(default_factory=tuple)

    def ensure(self, *, target_workspace: Path) -> Path:
        """Create the isolated workspace and prove it is not the target."""

        root = Path(self.root)
        target = Path(target_workspace).resolve()
        try:
            root.mkdir(parents=True, exist_ok=True)
            resolved = root.resolve()
        except OSError as exc:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.AGENT_WORKSPACE_UNAVAILABLE,
                f"The isolated agent workspace could not be created: {type(exc).__name__}: {exc}",
            ) from exc
        if resolved == target or target in resolved.parents or resolved in target.parents:
            raise V0ProposalBackendFailure(
                V0BackendFailureKind.AGENT_WORKSPACE_UNAVAILABLE,
                "The isolated agent workspace must not be, contain, or sit inside the target "
                "application workspace.",
            )
        return resolved

    def materialize(
        self,
        *,
        target_workspace: Path,
        instruction: Mapping[str, Any],
        prompt: str,
        snapshot: PersistedContextSnapshot,
    ) -> Path:
        """Write the bounded proposal context from persisted bytes; return the root."""

        resolved = self.ensure(target_workspace=target_workspace)
        # Every managed entry is rebuilt: a context file from an earlier session
        # or invocation must never leak into this proposal.
        for name in _MANAGED_ENTRIES:
            entry = resolved / name
            if entry.is_dir():
                shutil.rmtree(entry)
            elif entry.exists():
                entry.unlink()

        # Bytes, never text: platform newline translation would make a context
        # copy differ from the SHA-256 recorded against its durable receipt.
        (resolved / INSTRUCTION_FILE).write_bytes(prompt.encode("utf-8"))
        (resolved / INSTRUCTION_JSON_FILE).write_bytes(
            json.dumps(instruction, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
        )
        (resolved / CONTEXT_MANIFEST_FILE).write_bytes(
            json.dumps(snapshot.manifest(), indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")
        )

        context_root = resolved / CONTEXT_DIRECTORY
        recorded: list[ContextFile] = []
        for item in sorted(snapshot.files, key=lambda entry: entry.path):
            destination = context_root / Path(item.path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(item.content_bytes)
            written = destination.read_bytes()
            digest = hashlib.sha256(written).hexdigest()
            if digest != item.sha256 or len(written) != item.byte_count:
                raise V0ProposalBackendFailure(
                    V0BackendFailureKind.PERSISTED_CONTEXT_UNAVAILABLE,
                    f"The context copy of {item.path!r} does not match its persisted receipt hash.",
                )
            recorded.append(ContextFile(path=item.path, sha256=digest, byte_count=len(written)))
        self.context_files = tuple(recorded)
        self.skipped_context_paths = tuple(snapshot.skipped_paths)
        return resolved


__all__ = [
    "CONTEXT_DIRECTORY",
    "CONTEXT_MANIFEST_FILE",
    "DEFAULT_MAX_CONTEXT_BYTES",
    "INSTRUCTION_FILE",
    "INSTRUCTION_JSON_FILE",
    "ContextFile",
    "V0AgentWorkspace",
]
