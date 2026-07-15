"""The deterministic governed instruction handed to the V0 Cursor backend.

The instruction is a pure function of persisted state plus the persisted
dispatch command.  No clock, no random id, no mutable UI text, and no Cursor
status/diagnostic text ever enters it -- two dispatches of equivalent persisted
state produce byte-identical prompts.
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from admissible.v0_controller.adapters import MAX_PROPOSAL_OPERATIONS
from admissible.v0_controller.commands import Command, CommandKind
from admissible.v0_controller.cursor_envelope import (
    ENVELOPE_BEGIN,
    ENVELOPE_END,
    ENVELOPE_SCHEMA_VERSION,
    WRITE_FILE_KIND,
)
from admissible.v0_controller.state import SessionState

INSTRUCTION_SCHEMA_VERSION = "admissible_v0_governed_instruction_v1"

PROHIBITED_CAPABILITIES: tuple[str, ...] = (
    "shell",
    "terminal",
    "server",
    "browser",
    "network",
    "package_install",
    "deploy",
    "git",
    "external_services",
    "direct_workspace_write",
)


def expected_batch_id(state: SessionState, invocation_id: str) -> str:
    """The exact batch id this turn's proposal must carry."""

    return f"{invocation_id}:batch:{state.counters.batches + 1}"


def build_governed_instruction(
    *,
    state: SessionState,
    command: Command,
    materialized_context: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build the deterministic typed instruction for one dispatch command."""

    if command.kind != CommandKind.DISPATCH_AGENT:
        raise ValueError("governed instruction requires a dispatch_agent command")
    payload = command.payload
    invocation_id = payload.get("invocation_id")
    if not isinstance(invocation_id, str) or invocation_id != command.owner_id:
        raise ValueError("dispatch command payload does not carry its own invocation id")

    materialized = tuple(
        {
            "path": evidence.path,
            "sha256": evidence.sha256,
            "byte_count": evidence.byte_count,
        }
        for evidence in state.materialized_evidence
    )
    context = dict(materialized_context or {})
    return {
        "schema_version": INSTRUCTION_SCHEMA_VERSION,
        "invocation_id": invocation_id,
        "batch_id": expected_batch_id(state, invocation_id),
        "session_id": state.session_id,
        "mission": {
            "contract_id": state.contract.contract_id,
            "mandatory_paths": list(state.mandatory_paths),
            "structural_completion_only": state.contract.structural_completion_only,
        },
        "remaining_mandatory_paths": list(payload.get("mandatory_paths") or state.remaining_paths()),
        "materialized_paths": [dict(item) for item in materialized],
        "materialized_context": {path: context[path] for path in sorted(context)},
        "operation_limit": MAX_PROPOSAL_OPERATIONS,
        "proposal_only": True,
        "prohibited_capabilities": list(PROHIBITED_CAPABILITIES),
        "response_schema": {
            "envelope_begin": ENVELOPE_BEGIN,
            "envelope_end": ENVELOPE_END,
            "schema_version": ENVELOPE_SCHEMA_VERSION,
            "operation_kind": WRITE_FILE_KIND,
            "operation_fields": ["action_id", "kind", "path", "content"],
        },
    }


def _example_envelope(instruction: Mapping[str, Any]) -> str:
    remaining = list(instruction["remaining_mandatory_paths"])[:1] or ["<one remaining mandatory path>"]
    example = {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "invocation_id": instruction["invocation_id"],
        "batch_id": instruction["batch_id"],
        "operations": [
            {
                "action_id": "op-1",
                "kind": WRITE_FILE_KIND,
                "path": remaining[0],
                "content": "<complete final file content>",
            }
        ],
    }
    return json.dumps(example, indent=2, sort_keys=True, ensure_ascii=False)


def render_governed_prompt(instruction: Mapping[str, Any]) -> str:
    """Render the instruction as the single deterministic Cursor prompt string."""

    remaining = list(instruction["remaining_mandatory_paths"])
    materialized = list(instruction["materialized_paths"])
    context = dict(instruction["materialized_context"])
    lines: list[str] = [
        "You are a proposal-only backend for the Admissible V0 controller.",
        "",
        f"Mission contract: {instruction['mission']['contract_id']}",
        f"Invocation: {instruction['invocation_id']}",
        f"Batch: {instruction['batch_id']}",
        "",
        "REMAINING MANDATORY PATHS (propose only these):",
    ]
    lines.extend(f"  - {path}" for path in remaining)
    if materialized:
        lines.append("")
        lines.append("ALREADY MATERIALIZED (evidence-backed; do NOT rewrite or re-propose these):")
        lines.extend(
            f"  - {item['path']} (sha256={item['sha256']}, bytes={item['byte_count']})" for item in materialized
        )
    if context:
        lines.append("")
        lines.append("READ-ONLY CONTEXT COPIES of already-materialized files (never propose writes to them):")
        lines.extend(f"  - {path}" for path in sorted(context))
    lines.extend(
        [
            "",
            "HARD BOUNDARIES:",
            f"  - Propose at most {instruction['operation_limit']} operations.",
            f"  - Every operation kind must be exactly {WRITE_FILE_KIND!r}.",
            "  - You are proposal-only: you MUST NOT write, create, edit, or delete any file in the",
            "    target application workspace. Admissible's bounded executor performs every write.",
            "  - You MUST NOT run "
            + ", ".join(PROHIBITED_CAPABILITIES[:-1])
            + " commands, or any other project command.",
            "  - Provide the COMPLETE final content of each proposed file. Never send a diff, a patch,",
            "    a fragment, or a placeholder.",
            "  - Do not claim runtime, visual, browser, or subjective verification. You cannot observe it.",
            "  - Do not describe actions in prose: prose is never executed.",
            "",
            "REQUIRED RESPONSE FORMAT. Your final message must contain exactly one envelope, delimited",
            f"by {ENVELOPE_BEGIN} and {ENVELOPE_END}, containing only this JSON object:",
            "",
            ENVELOPE_BEGIN,
            _example_envelope(instruction),
            ENVELOPE_END,
            "",
            f"The envelope's invocation_id must be exactly {instruction['invocation_id']!r} and its",
            f"batch_id must be exactly {instruction['batch_id']!r}. Any other text you produce is",
            "diagnostic only and carries no authority.",
        ]
    )
    return "\n".join(lines)


__all__ = [
    "INSTRUCTION_SCHEMA_VERSION",
    "PROHIBITED_CAPABILITIES",
    "build_governed_instruction",
    "expected_batch_id",
    "render_governed_prompt",
]
