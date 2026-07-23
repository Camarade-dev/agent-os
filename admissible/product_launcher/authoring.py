"""Bounded owner-input → canonical V2 or inert claim-aware V3 authoring."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import secrets
from typing import Any, Callable, Mapping

from admissible.delegated_gate.canonical import canonical_bytes, require_safe_relative_path
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V3,
    MISSION_PROFILE_SCHEMA_VERSION_V4,
    MISSION_PROFILE_SCHEMA_VERSION_V2,
    ONE_SHOT_PROFILE_BUDGETS,
    WORKFLOW_RECOVERY_COMPLETION_CONDITIONS_TEXT,
    WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE,
    WORKFLOW_RECOVERY_V2_MISSION_TEXT,
    WORKFLOW_RECOVERY_V2_PROFILE,
    WORKFLOW_RECOVERY_VERIFIER_SOURCE,
    ClaimAuthority,
    ClaimVerificationPlanAuthority,
    ClaimAuthorship,
    ClaimSetCoverageStatus,
    VerificationPlanAuthorship,
    VerificationPlanCoverageStatus,
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
    GOLDEN_TEMPLATE_ID,
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
        "result_claims",
        "claim_verification_plan",
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

# ---------------------------------------------------------------------------
# workflow-recovery-verified-v1: launcher-owned canonical golden contract.
#
# The golden template does not let the frozen behavioral verifier judge
# arbitrary mission text: every authority-defining contract field must equal
# the launcher-owned canonical value below, so the verifier and the visible
# contract can never diverge.  Only ``model`` and ``timeout_seconds`` remain
# owner-variable.
# ---------------------------------------------------------------------------

# The flagship v2 mission already disclosed the one-object startRun calling
# convention; the two remaining verifier dependencies it did not name are the
# supplied migration fixture and the fixture-provided storage adapter.
GOLDEN_WORKFLOW_INTEROPERABILITY_DISCLOSURE_TEXT = """The assigned workspace supplies the interoperability materials the behavioral
verifier relies on:

- the supplied legacy version-0 fixture is
  `test/fixtures/legacy-run-state-v0.json`;

- the verifier uses the fixture-provided storage adapter `createMemoryStorage`
  from `src/storage/memory-storage.js`."""

GOLDEN_WORKFLOW_MISSION_TEXT = (
    WORKFLOW_RECOVERY_V2_MISSION_TEXT
    + "\n\n"
    + GOLDEN_WORKFLOW_INTEROPERABILITY_DISCLOSURE_TEXT
)
GOLDEN_WORKFLOW_GATE_OBJECTIVE = (
    "Deliver a deterministic, durable and resumable workflow engine while preserving "
    "existing workflow-definition behavior and satisfying the one-commit offline "
    "verified contract."
)
GOLDEN_WORKFLOW_COMPLETION_CONDITIONS_TEXT = WORKFLOW_RECOVERY_COMPLETION_CONDITIONS_TEXT
GOLDEN_WORKFLOW_COMMIT_MESSAGE = WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE
GOLDEN_WORKFLOW_MATERIAL_PATHS = WORKFLOW_RECOVERY_V2_PROFILE.required_material_paths
# Independently pinned: authoring fails closed if the source-controlled
# verifier bytes ever drift from this launcher-recorded digest.
GOLDEN_WORKFLOW_VERIFIER_SOURCE_SHA256 = (
    "a4e2daf9179129a7929bea5825f95f494ed601eb4a9bbbbaf6a65eb3918149e1"
)
GOLDEN_WORKFLOW_VERIFIER_TIMEOUT_SECONDS = 120
GOLDEN_WORKFLOW_VERIFIER_OUTPUT_LIMIT_BYTES = 524_288
GOLDEN_TEMPLATE_RECOMMENDED_TIMEOUT_SECONDS = 1800

# Exact owner inputs the golden template requires for authority-defining
# contract fields; differing owner text is rejected, never silently replaced.
GOLDEN_EXACT_CONTRACT_FIELDS: dict[str, object] = {
    "mission_text": GOLDEN_WORKFLOW_MISSION_TEXT,
    "gate_objective": GOLDEN_WORKFLOW_GATE_OBJECTIVE,
    "completion_conditions_text": GOLDEN_WORKFLOW_COMPLETION_CONDITIONS_TEXT,
    "required_material_paths": GOLDEN_WORKFLOW_MATERIAL_PATHS,
    "commit_message": GOLDEN_WORKFLOW_COMMIT_MESSAGE,
}


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


CLAIM_AUTHORSHIP_NOTICE = "These result claims were explicitly authored by the owner."
CLAIM_COVERAGE_NOTICE = (
    "Claim-set coverage has not been assessed. Requirements omitted from this "
    "claim set may remain unrepresented."
)
CLAIM_ADJUDICATION_NOTICE = (
    "These claims are part of the draft contract but have not been adjudicated."
)
CLAIM_RUNTIME_NOTICE = "Claim-aware V3 contracts are not launchable in the current runtime."
CLAIM_V4_RUNTIME_NOTICE = "Claim-verification-plan V4 contracts are not launchable in the current runtime."
PLAN_AUTHORSHIP_NOTICE = "These verification obligations were explicitly authored by the owner."
PLAN_COVERAGE_NOTICE = (
    "Verification-plan coverage has not been assessed. Claims or requirements may "
    "lack an authorized verification obligation."
)
PLAN_NON_EXECUTION_NOTICE = (
    "These verification obligations describe intended evidence-acquisition procedures. "
    "They have not been executed and have produced no evidence."
)
PLAN_NO_ADJUDICATION_NOTICE = (
    "The presence of a verification obligation does not mean that its referenced "
    "claims are supported or adjudicated."
)
PLAN_INDEPENDENCE_NOTICE = (
    "Independence values are requirements of the plan, not evidence that those "
    "properties were achieved."
)
PLAN_PROCEDURE_BINDING_NOTICE = (
    "Procedure references have not been validated against current runtime capabilities."
)
PLAN_RUNTIME_NOTICE = CLAIM_V4_RUNTIME_NOTICE


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
    claim_authority = None
    if "result_claims" in inputs:
        raw_claims = inputs["result_claims"]
        if not isinstance(raw_claims, list) or not raw_claims:
            raise AuthoringError(
                "INVALID_RESULT_CLAIMS",
                field="result_claims",
                safe_message_key="authoring.result_claims_nonempty_array_required",
            )
        try:
            claim_authority = ClaimAuthority.from_dict(
                {
                    "authorship": ClaimAuthorship.OWNER_AUTHORED.value,
                    "coverage_status": ClaimSetCoverageStatus.NOT_ASSESSED.value,
                    "claims": raw_claims,
                }
            )
        except (TypeError, ValueError):
            raise AuthoringError(
                "INVALID_RESULT_CLAIMS",
                field="result_claims",
                safe_message_key="authoring.invalid_result_claims",
            ) from None
    plan_authority = None
    if "claim_verification_plan" in inputs:
        raw_plan = inputs["claim_verification_plan"]
        if claim_authority is None:
            raise AuthoringError(
                "VERIFICATION_PLAN_REQUIRES_RESULT_CLAIMS",
                field="claim_verification_plan",
                safe_message_key="authoring.verification_plan_requires_result_claims",
            )
        if not isinstance(raw_plan, list) or not raw_plan:
            raise AuthoringError(
                "INVALID_CLAIM_VERIFICATION_PLAN",
                field="claim_verification_plan",
                safe_message_key="authoring.verification_plan_nonempty_array_required",
            )
        claim_ids = [claim.claim_id for claim in claim_authority.claims]
        if len({claim_id.casefold() for claim_id in claim_ids}) != len(claim_ids):
            raise AuthoringError(
                "INVALID_CLAIM_VERIFICATION_PLAN",
                field="claim_verification_plan",
                safe_message_key="authoring.invalid_claim_verification_plan",
            )
        try:
            plan_authority = ClaimVerificationPlanAuthority.from_dict(
                {
                    "authorship": VerificationPlanAuthorship.OWNER_AUTHORED.value,
                    "coverage_status": VerificationPlanCoverageStatus.NOT_ASSESSED.value,
                    "verification_obligations": raw_plan,
                }
            )
        except (TypeError, ValueError):
            raise AuthoringError(
                "INVALID_CLAIM_VERIFICATION_PLAN",
                field="claim_verification_plan",
                safe_message_key="authoring.invalid_claim_verification_plan",
            ) from None
    return {
        "mission_text": mission_text,
        "gate_objective": gate_objective,
        "completion_conditions_text": completion,
        "required_material_paths": tuple(material_paths),
        "commit_message": commit_message,
        "template_id": template_id,
        "model": model,
        "timeout_seconds": timeout_seconds,
        "claim_authority": claim_authority,
        "claim_verification_plan_authority": plan_authority,
    }


def _owner_variable_values(
    *,
    configuration: LauncherConfiguration,
    validated: Mapping[str, Any],
    default_timeout: int,
) -> tuple[str, int]:
    """Resolve the only owner-variable authority values: model and timeout."""

    model = validated["model"]
    if model is None:
        model = configuration.model_default
    else:
        model = _require_text(model, "model", max_bytes=MAX_MODEL_BYTES)
    timeout = validated["timeout_seconds"]
    if timeout is None:
        timeout = default_timeout
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
    return model, timeout


def _require_exact_golden_contract(validated: Mapping[str, Any]) -> None:
    """Require exact launcher-owned canonical golden contract text.

    Differing owner content is rejected with one stable bounded error and is
    never silently replaced with the canonical value.
    """

    for field_name, canonical_value in GOLDEN_EXACT_CONTRACT_FIELDS.items():
        if validated[field_name] != canonical_value:
            raise AuthoringError(
                "GOLDEN_CONTRACT_MISMATCH",
                field=field_name,
                safe_message_key="authoring.golden_contract_mismatch",
            )


def _golden_template_parts(
    *,
    configuration: LauncherConfiguration,
    validated: Mapping[str, Any],
    generated: Mapping[str, str],
) -> dict[str, Any]:
    """Assemble the fixed trusted authority of workflow-recovery-verified-v1.

    Workspace fixture, frozen verifier, checkpoint, budgets, Git-policy
    structure, and effect authority are launcher-owned and never
    browser-variable; the exact-contract law above already pinned every
    owner-entered authority text to its canonical value.
    """

    _require_exact_golden_contract(validated)
    model, timeout = _owner_variable_values(
        configuration=configuration,
        validated=validated,
        default_timeout=min(
            GOLDEN_TEMPLATE_RECOMMENDED_TIMEOUT_SECONDS, configuration.timeout_maximum
        ),
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
        "gate_clauses": WORKFLOW_RECOVERY_V2_PROFILE.gate_clauses,
        "required_evidence_kinds": (
            EvidenceKind.TARGET_TREE.value,
            EvidenceKind.GIT_STATE.value,
            EvidenceKind.VERIFICATION_COMMAND.value,
        ),
        "checkpoint_commands": WORKFLOW_RECOVERY_V2_PROFILE.checkpoint_commands,
        "completion_conditions_text": validated["completion_conditions_text"],
        "budgets": ONE_SHOT_PROFILE_BUDGETS,
        "timeout_seconds": timeout,
        "stdout_byte_limit": configuration.stdout_byte_limit,
        "stderr_byte_limit": configuration.stderr_byte_limit,
        "model": model,
        "workspace_source": WorkspaceSourceAuthority(
            kind=WorkspaceSourceKind.REGISTERED_FIXTURE,
            fixture_id=WORKFLOW_RECOVERY_V2_PROFILE.fixture_id,
            fixture_version=WORKFLOW_RECOVERY_V2_PROFILE.fixture_version,
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
            mode=VerificationMode.FROZEN_BEHAVIORAL,
            verifier_source=WORKFLOW_RECOVERY_VERIFIER_SOURCE,
            verifier_source_sha256=GOLDEN_WORKFLOW_VERIFIER_SOURCE_SHA256,
            verifier_timeout_seconds=GOLDEN_WORKFLOW_VERIFIER_TIMEOUT_SECONDS,
            verifier_output_limit_bytes=GOLDEN_WORKFLOW_VERIFIER_OUTPUT_LIMIT_BYTES,
            disclose_complete_source=True,
        ),
        "runtime_prompt": RuntimePromptAuthority(
            permitted_effects=(
                "Edit and commit files only in the assigned fixture workspace.",
            ),
            forbidden_effects=(
                "Do not install dependencies, use the network, add remotes, push, "
                "deploy, or modify anything outside the assigned workspace.",
            ),
            stop_clause=(
                "Stop immediately after the complete npm test suite, the exact "
                "one-commit policy and the configured checkpoints pass."
            ),
        ),
    }


def _trusted_template_parts(
    *,
    configuration: LauncherConfiguration,
    validated: Mapping[str, Any],
    generated: Mapping[str, str],
) -> dict[str, Any]:
    """Assemble trusted non-owner authority for one launcher-owned template.

    Owner values fill mission content only. Schema version, budgets, source
    repository authority, verification, checkpoint argv, and runtime effect
    authority come exclusively from launcher configuration/templates.
    """

    template_id = validated["template_id"]
    if template_id not in configuration.template_ids:
        raise AuthoringError(
            "INVALID_FIELD",
            field="template_id",
            safe_message_key="authoring.unsupported_template",
        )
    if template_id == GOLDEN_TEMPLATE_ID:
        return _golden_template_parts(
            configuration=configuration,
            validated=validated,
            generated=generated,
        )
    if template_id != DEFAULT_TEMPLATE_ID:
        raise AuthoringError(
            "INVALID_FIELD",
            field="template_id",
            safe_message_key="authoring.unsupported_template",
        )
    model, timeout = _owner_variable_values(
        configuration=configuration,
        validated=validated,
        default_timeout=configuration.timeout_default,
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


def _remove_created_document(path: Path, *, unlink: Callable[[str], None]) -> None:
    """Remove exactly the path this invocation created inside the documents
    directory; a pre-existing collision path is never routed here."""

    try:
        unlink(str(path))
    except OSError:
        failure = AuthoringError(
            "DOCUMENT_CLEANUP_FAILED",
            safe_message_key="authoring.document_cleanup_failed",
        )
        # Internal-only diagnostic: to_dict() never includes this attribute,
        # so the residual path is never shown to the browser.
        failure.internal_residual_path = str(path)
        raise failure from None


def _write_once(
    path: Path,
    payload: bytes,
    *,
    write: Callable[[int, bytes], int] | None = None,
    fsync: Callable[[int], None] | None = None,
    close: Callable[[int], None] | None = None,
    unlink: Callable[[str], None] | None = None,
) -> None:
    # Resolved at call time so the production os primitives stay authoritative
    # while failure injection remains possible for committed tests.
    write_op = write if write is not None else os.write
    fsync_op = fsync if fsync is not None else os.fsync
    close_op = close if close is not None else os.close
    unlink_op = unlink if unlink is not None else os.unlink
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        fd = os.open(str(path), flags, 0o600)
    except FileExistsError:
        # The collision path pre-existed this invocation and is never unlinked.
        raise AuthoringError(
            "DOCUMENT_EXISTS",
            safe_message_key="authoring.document_exists",
        ) from None
    except OSError:
        raise AuthoringError(
            "DOCUMENT_WRITE_FAILED",
            safe_message_key="authoring.document_write_failed",
        ) from None
    # From here the path was created by this invocation: any failure before a
    # complete write+fsync+close must remove exactly this path and the document
    # must never be registered by the caller.
    fd_open = True
    try:
        view = memoryview(payload)
        while view:
            view = view[write_op(fd, view):]
        # Raw os.write is unbuffered, so there is no userspace buffer left to
        # flush before the durability fsync.
        fsync_op(fd)
        fd_open = False
        close_op(fd)
    except OSError:
        if fd_open:
            try:
                os.close(fd)
            except OSError:
                pass
        _remove_created_document(path, unlink=unlink_op)
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
    """Author one durable write-once V2 profile or inert V3 draft document.

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
    claim_authority = validated["claim_authority"]
    plan_authority = validated["claim_verification_plan_authority"]
    if plan_authority is not None:
        builder_kwargs["schema_version"] = MISSION_PROFILE_SCHEMA_VERSION_V4
        builder_kwargs["claim_authority"] = claim_authority
        builder_kwargs["claim_verification_plan_authority"] = plan_authority
    elif claim_authority is not None:
        builder_kwargs["schema_version"] = MISSION_PROFILE_SCHEMA_VERSION_V3
        builder_kwargs["claim_authority"] = claim_authority
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
        "gate_clauses": [
            {"clause_id": clause_id, "text": text}
            for clause_id, text in profile.gate_clauses
        ],
        "template_id": validated["template_id"],
    }
    if profile.schema_version in {MISSION_PROFILE_SCHEMA_VERSION_V3, MISSION_PROFILE_SCHEMA_VERSION_V4}:
        summary["profile_fingerprint"] = fingerprint
        summary["claim_authority"] = profile.claim_authority.to_dict()
        summary["claim_review_notices"] = {
            "authorship": CLAIM_AUTHORSHIP_NOTICE,
            "coverage": CLAIM_COVERAGE_NOTICE,
            "adjudication": CLAIM_ADJUDICATION_NOTICE,
            "runtime": (
                CLAIM_RUNTIME_NOTICE
                if profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V3
                else CLAIM_V4_RUNTIME_NOTICE
            ),
        }
    if profile.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V4:
        summary["claim_verification_plan_authority"] = (
            profile.claim_verification_plan_authority.to_dict()
        )
        summary["verification_plan_review_notices"] = {
            "authorship": PLAN_AUTHORSHIP_NOTICE,
            "coverage": PLAN_COVERAGE_NOTICE,
            "non_execution": PLAN_NON_EXECUTION_NOTICE,
            "no_adjudication": PLAN_NO_ADJUDICATION_NOTICE,
            "independence": PLAN_INDEPENDENCE_NOTICE,
            "procedure_binding": PLAN_PROCEDURE_BINDING_NOTICE,
            "runtime": PLAN_RUNTIME_NOTICE,
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
    "CLAIM_ADJUDICATION_NOTICE",
    "CLAIM_AUTHORSHIP_NOTICE",
    "CLAIM_COVERAGE_NOTICE",
    "CLAIM_RUNTIME_NOTICE",
    "GOLDEN_EXACT_CONTRACT_FIELDS",
    "GOLDEN_TEMPLATE_RECOMMENDED_TIMEOUT_SECONDS",
    "GOLDEN_WORKFLOW_COMMIT_MESSAGE",
    "GOLDEN_WORKFLOW_COMPLETION_CONDITIONS_TEXT",
    "GOLDEN_WORKFLOW_GATE_OBJECTIVE",
    "GOLDEN_WORKFLOW_INTEROPERABILITY_DISCLOSURE_TEXT",
    "GOLDEN_WORKFLOW_MATERIAL_PATHS",
    "GOLDEN_WORKFLOW_MISSION_TEXT",
    "GOLDEN_WORKFLOW_VERIFIER_OUTPUT_LIMIT_BYTES",
    "GOLDEN_WORKFLOW_VERIFIER_SOURCE_SHA256",
    "GOLDEN_WORKFLOW_VERIFIER_TIMEOUT_SECONDS",
    "OWNER_AUTHORING_FIELDS",
    "author_runtime_contract",
]
