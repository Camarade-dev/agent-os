"""Bounded owner-input → canonical runtime-v2 contract authoring."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import secrets
from typing import Any, Callable, Mapping

from admissible.delegated_gate.canonical import canonical_bytes, require_safe_relative_path
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    ONE_SHOT_PROFILE_BUDGETS,
    GitEndStatePolicy,
    ProfileCheckpointCommand,
    RuntimePromptAuthority,
    VerificationAuthority,
    VerificationMode,
    WorkspaceSourceAuthority,
    WorkspaceSourceKind,
    create_native_mission_profile,
)
from admissible.delegated_gate.models import EvidenceKind
from admissible.product_launcher.configuration import (
    DEFAULT_TEMPLATE_ID,
    LauncherConfiguration,
    SUPPORTED_TEMPLATE_IDS,
)

OWNER_AUTHORING_FIELDS = frozenset(
    {
        "mission_text",
        "gate_objective",
        "completion_conditions_text",
        "required_material_paths",
        "commit_message",
        "model",
        "timeout_seconds",
        "template_id",
    }
)
REQUIRED_OWNER_FIELDS = frozenset(
    {
        "mission_text",
        "gate_objective",
        "completion_conditions_text",
        "required_material_paths",
        "commit_message",
    }
)
FORBIDDEN_OWNER_FIELDS = frozenset(
    {
        "schema_version",
        "profile_fingerprint",
        "budgets",
        "source_head",
        "source_repository",
        "required_source_head",
        "executable",
        "executable_prefix_args",
        "attestation_class",
        "verifier_source",
        "verifier_source_sha256",
        "checkpoint_commands",
        "workspace_source",
        "git_end_state_policy",
        "verification",
        "runtime_prompt",
        "owner_authorization",
        "owner_authorization_digest",
        "authorization_digest",
        "profile_id",
        "run_id",
        "session_id",
        "gate_id",
        "mission_id",
    }
)

MAX_MISSION_TEXT_BYTES = 65_536
MAX_OBJECTIVE_BYTES = 8_192
MAX_COMPLETION_BYTES = 65_536
MAX_COMMIT_MESSAGE_BYTES = 1_024
MAX_MODEL_BYTES = 256
MAX_MATERIAL_PATHS = 64
MAX_MATERIAL_PATH_BYTES = 512


class AuthoringError(Exception):
    """Bounded authoring rejection without internal diagnostics."""

    def __init__(self, error_code: str, *, field: str | None = None, safe_message_key: str):
        self.error_code = error_code
        self.field = field
        self.safe_message_key = safe_message_key
        super().__init__(error_code)

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "error_code": self.error_code,
            "safe_message_key": self.safe_message_key,
        }
        if self.field is not None:
            payload["field"] = self.field
        return payload


@dataclass(frozen=True)
class AuthoredContractDocument:
    document_path: str
    profile_fingerprint: str
    contract_summary: dict[str, object]
    generated_ids: dict[str, str]
    profile: object


def _require_text(value: object, field: str, *, max_bytes: int) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise AuthoringError(
            "INVALID_FIELD",
            field=field,
            safe_message_key="authoring.invalid_text",
        )
    if len(value.encode("utf-8")) > max_bytes:
        raise AuthoringError(
            "FIELD_TOO_LONG",
            field=field,
            safe_message_key="authoring.field_too_long",
        )
    return value


def _validate_owner_inputs(inputs: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(inputs, Mapping):
        raise AuthoringError(
            "INVALID_INPUT",
            safe_message_key="authoring.object_required",
        )
    keys = set(inputs)
    unknown = sorted(keys - OWNER_AUTHORING_FIELDS)
    if unknown:
        raise AuthoringError(
            "UNKNOWN_FIELD",
            field=unknown[0],
            safe_message_key="authoring.unknown_field",
        )
    forbidden = sorted(keys & FORBIDDEN_OWNER_FIELDS)
    if forbidden:
        raise AuthoringError(
            "FORBIDDEN_FIELD",
            field=forbidden[0],
            safe_message_key="authoring.forbidden_authority_field",
        )
    missing = sorted(REQUIRED_OWNER_FIELDS - keys)
    if missing:
        raise AuthoringError(
            "MISSING_FIELD",
            field=missing[0],
            safe_message_key="authoring.missing_field",
        )
    mission_text = _require_text(inputs["mission_text"], "mission_text", max_bytes=MAX_MISSION_TEXT_BYTES)
    gate_objective = _require_text(inputs["gate_objective"], "gate_objective", max_bytes=MAX_OBJECTIVE_BYTES)
    completion = _require_text(
        inputs["completion_conditions_text"],
        "completion_conditions_text",
        max_bytes=MAX_COMPLETION_BYTES,
    )
    commit_message = _require_text(inputs["commit_message"], "commit_message", max_bytes=MAX_COMMIT_MESSAGE_BYTES)
    if "\n" in commit_message or "\r" in commit_message:
        raise AuthoringError(
            "INVALID_FIELD",
            field="commit_message",
            safe_message_key="authoring.commit_message_single_line",
        )
    paths_raw = inputs["required_material_paths"]
    if not isinstance(paths_raw, list) or not paths_raw:
        raise AuthoringError(
            "INVALID_FIELD",
            field="required_material_paths",
            safe_message_key="authoring.material_paths_required",
        )
    if len(paths_raw) > MAX_MATERIAL_PATHS:
        raise AuthoringError(
            "FIELD_TOO_LONG",
            field="required_material_paths",
            safe_message_key="authoring.too_many_material_paths",
        )
    material_paths: list[str] = []
    for item in paths_raw:
        if not isinstance(item, str) or len(item.encode("utf-8")) > MAX_MATERIAL_PATH_BYTES:
            raise AuthoringError(
                "INVALID_FIELD",
                field="required_material_paths",
                safe_message_key="authoring.invalid_material_path",
            )
        try:
            material_paths.append(require_safe_relative_path(item, "required material path"))
        except ValueError as exc:
            raise AuthoringError(
                "INVALID_FIELD",
                field="required_material_paths",
                safe_message_key="authoring.invalid_material_path",
            ) from None
    if len(set(material_paths)) != len(material_paths):
        raise AuthoringError(
            "INVALID_FIELD",
            field="required_material_paths",
            safe_message_key="authoring.duplicate_material_path",
        )
    template_id = inputs.get("template_id", DEFAULT_TEMPLATE_ID)
    if not isinstance(template_id, str) or template_id not in SUPPORTED_TEMPLATE_IDS:
        raise AuthoringError(
            "INVALID_FIELD",
            field="template_id",
            safe_message_key="authoring.unsupported_template",
        )
    model = inputs.get("model")
    timeout_seconds = inputs.get("timeout_seconds")
    return {
        "mission_text": mission_text,
        "gate_objective": gate_objective,
        "completion_conditions_text": completion,
        "required_material_paths": tuple(material_paths),
        "commit_message": commit_message,
        "template_id": template_id,
        "model": model,
        "timeout_seconds": timeout_seconds,
    }


def _trusted_template_parts(
    *,
    configuration: LauncherConfiguration,
    validated: Mapping[str, Any],
    generated: Mapping[str, str],
) -> dict[str, Any]:
    """Assemble trusted non-owner authority for one observed-local-git template.

    Owner values fill mission content only. Schema version, budgets, source
    repository authority, verification, checkpoint argv, and runtime effect
    authority come exclusively from launcher configuration/templates.
    """

    if validated["template_id"] != DEFAULT_TEMPLATE_ID:
        raise AuthoringError(
            "INVALID_FIELD",
            field="template_id",
            safe_message_key="authoring.unsupported_template",
        )
    model = validated["model"]
    if model is None:
        model = configuration.model_default
    else:
        model = _require_text(model, "model", max_bytes=MAX_MODEL_BYTES)
    timeout = validated["timeout_seconds"]
    if timeout is None:
        timeout = configuration.timeout_default
    elif isinstance(timeout, bool) or not isinstance(timeout, int):
        raise AuthoringError(
            "INVALID_FIELD",
            field="timeout_seconds",
            safe_message_key="authoring.invalid_timeout",
        )
    elif not 1 <= timeout <= configuration.timeout_maximum:
        raise AuthoringError(
            "INVALID_FIELD",
            field="timeout_seconds",
            safe_message_key="authoring.timeout_out_of_bounds",
        )
    checkpoint = ProfileCheckpointCommand(
        command_id="workspace-marker-check",
        argv=("git", "status", "--porcelain"),
        timeout_seconds=30,
        max_capture_bytes=65_536,
    )
    return {
        "schema_version": MISSION_PROFILE_SCHEMA_VERSION_V2,
        "profile_id": generated["profile_id"],
        "run_id": generated["run_id"],
        "session_id": generated["session_id"],
        "gate_id": generated["gate_id"],
        "mission_id": generated["mission_id"],
        "mission_text": validated["mission_text"],
        "gate_objective": validated["gate_objective"],
        "gate_clauses": (
            (
                f"{generated['gate_id']}.material",
                "Required material paths exist under the assigned workspace.",
            ),
            (
                f"{generated['gate_id']}.git",
                "Exactly one local commit with the required complete message exists.",
            ),
        ),
        "required_evidence_kinds": (
            EvidenceKind.TARGET_TREE.value,
            EvidenceKind.GIT_STATE.value,
            EvidenceKind.VERIFICATION_COMMAND.value,
        ),
        "checkpoint_commands": (checkpoint,),
        "completion_conditions_text": validated["completion_conditions_text"],
        "budgets": ONE_SHOT_PROFILE_BUDGETS,
        "timeout_seconds": timeout,
        "stdout_byte_limit": configuration.stdout_byte_limit,
        "stderr_byte_limit": configuration.stderr_byte_limit,
        "model": model,
        "workspace_source": WorkspaceSourceAuthority(
            kind=WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY,
            local_repository_path=str(configuration.source_repository),
        ),
        "git_end_state_policy": GitEndStatePolicy(
            required_commits_added=1,
            required_complete_commit_message=validated["commit_message"],
            final_worktree_clean=True,
            final_index_clean=True,
            final_remotes_absent=True,
            required_material_paths=validated["required_material_paths"],
        ),
        "verification": VerificationAuthority(
            mode=VerificationMode.OBSERVED_ONLY,
            verifier_source=None,
            verifier_source_sha256=None,
            verifier_timeout_seconds=None,
            verifier_output_limit_bytes=None,
            disclose_complete_source=False,
        ),
        "runtime_prompt": RuntimePromptAuthority(
            permitted_effects=(
                "Edit and commit files only in the assigned workspace.",
            ),
            forbidden_effects=(
                "Do not use network, add remotes, push, deploy, or edit the source repository.",
            ),
            stop_clause=(
                "Stop immediately after the exact one-commit policy and configured checkpoints pass."
            ),
        ),
    }


def _safe_document_name(document_id: str) -> str:
    if not document_id or any(char not in "0123456789abcdef" for char in document_id):
        raise AuthoringError(
            "INTERNAL_ID_ERROR",
            safe_message_key="authoring.unsafe_identifier",
        )
    return f"contract-{document_id}.json"


def _write_once(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError as exc:
        raise AuthoringError(
            "DOCUMENT_EXISTS",
            safe_message_key="authoring.document_exists",
        ) from None
    except OSError as exc:
        raise AuthoringError(
            "DOCUMENT_WRITE_FAILED",
            safe_message_key="authoring.document_write_failed",
        ) from None
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise AuthoringError(
            "DOCUMENT_WRITE_FAILED",
            safe_message_key="authoring.document_write_failed",
        ) from None


def author_runtime_contract(
    inputs: Mapping[str, Any],
    *,
    launcher_configuration: LauncherConfiguration,
    documents_directory: str | Path,
    id_generator: Callable[[], str] | None = None,
    profile_builder: Callable[..., object] = create_native_mission_profile,
) -> AuthoredContractDocument:
    """Author one durable write-once runtime-v2 profile document.

    The document intentionally persists owner mission content. It never executes,
    never creates a run root, and never creates an evidence root. Fingerprint
    authority remains exclusively with G1 ``create_native_mission_profile``.
    """

    configuration = launcher_configuration.validated()
    validated = _validate_owner_inputs(inputs)
    generator = id_generator or (lambda: secrets.token_hex(16))
    document_id = generator()
    generated = {
        "document_id": document_id,
        "profile_id": f"authored-{document_id[:12]}",
        "run_id": f"run-{document_id[:12]}",
        "session_id": f"session-{document_id[:12]}",
        "gate_id": f"gate-{document_id[:12]}",
        "mission_id": f"mission-{document_id[:12]}",
    }
    builder_kwargs = _trusted_template_parts(
        configuration=configuration,
        validated=validated,
        generated=generated,
    )
    try:
        profile = profile_builder(**builder_kwargs)
    except Exception:
        raise AuthoringError(
            "BUILDER_REJECTED",
            safe_message_key="authoring.builder_rejected",
        ) from None
    fingerprint = getattr(profile, "profile_fingerprint", None)
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise AuthoringError(
            "BUILDER_REJECTED",
            safe_message_key="authoring.builder_rejected",
        )
    try:
        body = profile.to_dict()
        payload = canonical_bytes(body)
    except Exception:
        raise AuthoringError(
            "BUILDER_REJECTED",
            safe_message_key="authoring.builder_rejected",
        ) from None
    directory = Path(documents_directory)
    if not directory.is_absolute():
        raise AuthoringError(
            "INVALID_DOCUMENTS_DIRECTORY",
            safe_message_key="authoring.documents_directory_invalid",
        )
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / _safe_document_name(document_id)
    if ".." in path.name or path.parent.resolve() != directory.resolve():
        raise AuthoringError(
            "INTERNAL_ID_ERROR",
            safe_message_key="authoring.unsafe_identifier",
        )
    _write_once(path, payload)
    summary = {
        "schema_version": profile.schema_version,
        "profile_id": profile.profile_id,
        "run_id": profile.run_id,
        "session_id": profile.session_id,
        "gate_id": profile.gate_id,
        "mission_id": profile.mission_id,
        "workspace_source_kind": profile.effective_workspace_source.kind.value,
        "verification_mode": profile.verification_mode.value,
        "template_id": validated["template_id"],
    }
    return AuthoredContractDocument(
        document_path=str(path.resolve()),
        profile_fingerprint=fingerprint,
        contract_summary=summary,
        generated_ids={
            "document_id": generated["document_id"],
            "profile_id": profile.profile_id,
            "run_id": profile.run_id,
            "session_id": profile.session_id,
            "gate_id": profile.gate_id,
            "mission_id": profile.mission_id,
        },
        profile=profile,
    )


__all__ = [
    "AuthoringError",
    "AuthoredContractDocument",
    "OWNER_AUTHORING_FIELDS",
    "author_runtime_contract",
]
