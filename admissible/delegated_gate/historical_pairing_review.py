"""Complete, server-derived owner review for one pinned historical pairing.

This module builds one ephemeral, deeply immutable presentation object from
exactly four pinned inputs: the exact V5 evaluation profile, the exact
historical V4 authorization payload, the exact pairing authority, and the exact
public confirmation-message bytes created during preparation.  It reads nothing
else.

The review exists so an owner can see, in one place and without paraphrase, the
complete evaluation contract they are about to confirm: every result claim,
every verification obligation with all six independence requirements, every
negative control and reference case, every evidence binding, and the exact
human-readable historical mission authority the original run was executed
under.

What the review is not
----------------------

* It is not canonical.  It is not fingerprinted.  It is never persisted, never
  archived, and never enters a confirmation message.  It deliberately defines
  no ``to_dict`` so that an ephemeral presentation object can never be mistaken
  for an archive document; ``to_presentation_dict`` is the only serializer and
  it always returns freshly created containers.
* It computes no obligation result, satisfaction status, claim coverage rollup,
  eligibility result, admission, or ``ProductVerdict``.  Coverage status is
  reported exactly as the authority carries it, which is ``NOT_ASSESSED``.
* It resolves nothing.  No evidence is read, no source is located, no artifact
  or workspace existence is asserted, and no filesystem path carried inside the
  V4 payload is ever dereferenced.

Path withholding
----------------

Every local locator carried by the historical authorization is deliberately
withheld and named in ``HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS``.  The
mission-relative required material paths are presented, because they are owner
mission content rather than local locators, and so are the profile-authored
checkpoint command definitions.  No absolute local path value from the payload
ever appears in the review or in its presentation mapping.

Authority derivation
--------------------

Every authority fact is read from the pinned canonical objects.  The
confirmation-message bytes are presented only as an exact Base64 encoding, an
exact byte length, and a SHA-256 digest: the serializer never parses,
re-frames, or reinterprets those bytes to construct an authority fact.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
from typing import Any

from admissible.delegated_gate.canonical import require_sha256
from admissible.delegated_gate.historical_evaluation import (
    HistoricalEvaluationPairingAuthority,
    require_exact_v5_v2_runtime_authority_compatibility,
)
from admissible.delegated_gate.historical_pairing_confirmation import (
    HISTORICAL_PAIRING_CONFIRMATION_DOMAIN,
)
from admissible.delegated_gate.mission_profile import (
    MISSION_PROFILE_SCHEMA_VERSION_V5,
    NativeMissionProfile,
)
from admissible.delegated_gate.native_canary import (
    NativeCanaryAuthorizationPayloadV4,
)


# The three in-memory preparation states a review may snapshot.  They are
# process state and are never reconstructed from archive existence.
PREPARATION_STATE_READY_FOR_CONFIRMATION = "READY_FOR_CONFIRMATION"
PREPARATION_STATE_CONFIRMATION_IN_PROGRESS = "CONFIRMATION_IN_PROGRESS"
PREPARATION_STATE_CONSUMED = "CONSUMED"
HISTORICAL_PAIRING_PREPARATION_STATES: tuple[str, ...] = (
    PREPARATION_STATE_READY_FOR_CONFIRMATION,
    PREPARATION_STATE_CONFIRMATION_IN_PROGRESS,
    PREPARATION_STATE_CONSUMED,
)

# The one bounded compatibility fact the review may state.  No compatibility
# witness is persisted and no new authority or fingerprint is created.
EXACT_CANONICAL_MATCH_REVALIDATED = "EXACT_CANONICAL_MATCH_REVALIDATED"

# The exact fixed recipe of the public confirmation message, stated as text so
# an owner can reproduce it independently without this module encoding it again.
CONFIRMATION_MESSAGE_RECIPE = (
    "the exact confirmation message is the fixed domain constant "
    + HISTORICAL_PAIRING_CONFIRMATION_DOMAIN.decode("ascii")
    + ", one NUL separator byte, and the canonical JSON bytes of the complete "
    "pairing authority document"
)

MAX_CONFIRMATION_MESSAGE_BYTES = 65_536

# Every local locator the review deliberately never exposes.  Membership and
# ordering are pinned by tests so a later slice cannot quietly start presenting
# one of these values.
HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS: tuple[str, ...] = (
    "target_authorization_payload.source_repository",
    "target_authorization_payload.source_repository_identity",
    "target_authorization_payload.run_root",
    "target_authorization_payload.workspace_root",
    "target_authorization_payload.evidence_root",
    "target_authorization_payload.native_sidecar_root",
    "target_authorization_payload.executable",
    "target_authorization_payload.launcher_prefix",
    "target_authorization_payload.mission_profile.workspace_source"
    ".local_repository_path",
    "target_authorization_payload.mission_profile.verification.verifier_source",
    "historical_payload_registry.configured_document_path",
    "historical_pairing_coordinator.archive_root",
    "historical_pairing_coordinator.configured_secret",
    "historical_pairing_confirmation.expected_tag",
    "historical_pairing_confirmation.presented_tag",
    "historical_evaluation_pairing_authority.canonical_json_base64",
)

# Exactly fourteen ordered owner-review notices.  This tuple is non-canonical,
# is never persisted, and is part of no fingerprint.  It deliberately does not
# merge, rewrite, or replace the accepted Step 5C2A confirmation limitations or
# the accepted Step 5C2B workflow limitations, which remain separate.
HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES: tuple[str, ...] = (
    "this pairing authorizes post-run evaluation only and authorizes no "
    "execution",
    "the original execution was separately authorized earlier by the "
    "historical v4 authorization payload shown here",
    "the agent did not receive these result claims, this verification plan, or "
    "these evidence bindings during the original run",
    "the original run was not produced specifically for these claims",
    "no runtime evidence has been read to build this review",
    "no source, path, artifact, or workspace existence is asserted by this "
    "review",
    "no eligibility, obligation result, claim support, result admission, or "
    "ProductVerdict is asserted by this review",
    "actor_id is an asserted identifier and is not authenticated",
    "the confirmation construction is deterministic and carries no nonce, so "
    "acceptance does not prove fresh secret possession by the current operator",
    "the confirmation tag is a symmetric shared-secret message authentication "
    "code and is not a digital signature",
    "an existing archive alone never proves that a confirmation tag was "
    "presented",
    "the accepted lower-level historical evaluation store remains callable "
    "directly by trusted internal code without any confirmation",
    "multiple distinct pairings may coexist for one historical payload, and "
    "this workflow defines no revocation or supersession semantics",
    "preparation, review, and consumed status are in-memory process state that "
    "vanish on launcher restart and are never reconstructed from archive "
    "existence",
)


class HistoricalPairingOwnerReviewError(RuntimeError):
    """Bounded failure while building one owner review from pinned objects."""


# ---------------------------------------------------------------------------
# Frozen, deeply immutable presentation types.
#
# None of these is canonical, fingerprinted, or persisted.  None defines
# ``to_dict``.  Every ``to_presentation_dict`` creates fresh containers, so a
# caller can mutate what it receives without ever touching the review.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewedPairingIdentity:
    """Complete pairing and confirmation identity for one preparation."""

    preparation_id: str
    preparation_state: str
    asserted_actor_id: str
    pairing_authority_schema_version: str
    pairing_authority_fingerprint: str
    evaluation_profile_schema_version: str
    evaluation_profile_fingerprint: str
    target_authorization_payload_fingerprint: str
    evaluation_profile_is_launchable: bool
    confirmation_message_base64: str
    confirmation_message_byte_length: int
    confirmation_message_sha256: str
    confirmation_message_recipe: str

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "preparation_id": self.preparation_id,
            "preparation_state": self.preparation_state,
            "asserted_actor_id": self.asserted_actor_id,
            "pairing_authority_schema_version": (
                self.pairing_authority_schema_version
            ),
            "pairing_authority_fingerprint": self.pairing_authority_fingerprint,
            "evaluation_profile_schema_version": (
                self.evaluation_profile_schema_version
            ),
            "evaluation_profile_fingerprint": self.evaluation_profile_fingerprint,
            "target_authorization_payload_fingerprint": (
                self.target_authorization_payload_fingerprint
            ),
            "evaluation_profile_is_launchable": (
                self.evaluation_profile_is_launchable
            ),
            "confirmation_message_base64": self.confirmation_message_base64,
            "confirmation_message_byte_length": (
                self.confirmation_message_byte_length
            ),
            "confirmation_message_sha256": self.confirmation_message_sha256,
            "confirmation_message_recipe": self.confirmation_message_recipe,
        }


@dataclass(frozen=True)
class ReviewedResultClaim:
    """One owner-authored result claim, presented without normalization."""

    claim_id: str
    statement: str
    obligation_level: str
    depends_on: tuple[str, ...]
    non_claims: tuple[str, ...]

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "statement": self.statement,
            "obligation_level": self.obligation_level,
            "depends_on": list(self.depends_on),
            "non_claims": list(self.non_claims),
        }


@dataclass(frozen=True)
class ReviewedClaimAuthority:
    """Complete reviewed claim set with its exact authority classification."""

    authorship: str
    coverage_status: str
    claims: tuple[ReviewedResultClaim, ...]

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "authorship": self.authorship,
            "coverage_status": self.coverage_status,
            "claims": [claim.to_presentation_dict() for claim in self.claims],
        }


@dataclass(frozen=True)
class ReviewedIndependenceRequirements:
    """All six declared independence requirements, none summarized away."""

    temporal: bool
    artifact: bool
    process: bool
    information: bool
    model: bool
    organizational: bool

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "temporal": self.temporal,
            "artifact": self.artifact,
            "process": self.process,
            "information": self.information,
            "model": self.model,
            "organizational": self.organizational,
        }


@dataclass(frozen=True)
class ReviewedNegativeControl:
    """One declared negative control, without execution semantics."""

    control_id: str
    description: str

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "description": self.description,
        }


@dataclass(frozen=True)
class ReviewedVerificationObligation:
    """One complete verification obligation exactly as the plan declares it.

    No obligation result, satisfaction status, or claim coverage rollup is
    computed, and no ``method`` field is invented: the declared strategy and
    acceptance predicate are the schema's own fields.
    """

    obligation_id: str
    claim_ids: tuple[str, ...]
    strategy: str
    procedure_reference: str
    acceptance_predicate: str
    declared_coverage: str
    non_claims: tuple[str, ...]
    oracle_disclosed_to_subject: bool
    independence_requirements: ReviewedIndependenceRequirements
    negative_controls: tuple[ReviewedNegativeControl, ...]
    reference_cases: tuple[str, ...]

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "claim_ids": list(self.claim_ids),
            "strategy": self.strategy,
            "procedure_reference": self.procedure_reference,
            "acceptance_predicate": self.acceptance_predicate,
            "declared_coverage": self.declared_coverage,
            "non_claims": list(self.non_claims),
            "oracle_disclosed_to_subject": self.oracle_disclosed_to_subject,
            "independence_requirements": (
                self.independence_requirements.to_presentation_dict()
            ),
            "negative_controls": [
                control.to_presentation_dict()
                for control in self.negative_controls
            ],
            "reference_cases": list(self.reference_cases),
        }


@dataclass(frozen=True)
class ReviewedVerificationPlanAuthority:
    """Complete reviewed verification plan with its authority classification."""

    authorship: str
    coverage_status: str
    verification_obligations: tuple[ReviewedVerificationObligation, ...]

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "authorship": self.authorship,
            "coverage_status": self.coverage_status,
            "verification_obligations": [
                obligation.to_presentation_dict()
                for obligation in self.verification_obligations
            ],
        }


@dataclass(frozen=True)
class ReviewedEvidenceBinding:
    """One declared evidence binding, resolved against nothing."""

    binding_id: str
    obligation_id: str
    source_authority_type: str
    source_authority_reference: str

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "obligation_id": self.obligation_id,
            "source_authority_type": self.source_authority_type,
            "source_authority_reference": self.source_authority_reference,
        }


@dataclass(frozen=True)
class ReviewedEvidenceBindingAuthority:
    """Complete reviewed binding set with its authority classification."""

    authorship: str
    coverage_status: str
    bindings: tuple[ReviewedEvidenceBinding, ...]

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "authorship": self.authorship,
            "coverage_status": self.coverage_status,
            "bindings": [
                binding.to_presentation_dict() for binding in self.bindings
            ],
        }


@dataclass(frozen=True)
class ReviewedGateClause:
    """One ordered (id, text) gate clause from the historical authority."""

    clause_id: str
    text: str

    def to_presentation_dict(self) -> dict[str, Any]:
        return {"clause_id": self.clause_id, "text": self.text}


@dataclass(frozen=True)
class ReviewedCheckpointCommand:
    """One profile-authored checkpoint command definition.

    ``argv`` is mission content authored inside the profile, not one of the
    historical authorization's local locators, and is presented exactly.
    """

    command_id: str
    argv: tuple[str, ...]
    timeout_seconds: int
    max_capture_bytes: int

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
            "max_capture_bytes": self.max_capture_bytes,
        }


@dataclass(frozen=True)
class ReviewedBehavioralVerifierDisclosure:
    """Verifier identity and disclosure classification, never its source body.

    The complete verifier source is deliberately absent.  Only the digest, the
    byte length, the declared bounds, and the authority's own disclosure flag
    are presented.
    """

    mode: str
    verifier_source_sha256: str | None
    verifier_source_byte_length: int | None
    verifier_timeout_seconds: int | None
    verifier_output_limit_bytes: int | None
    disclose_complete_source: bool

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "verifier_source_sha256": self.verifier_source_sha256,
            "verifier_source_byte_length": self.verifier_source_byte_length,
            "verifier_timeout_seconds": self.verifier_timeout_seconds,
            "verifier_output_limit_bytes": self.verifier_output_limit_bytes,
            "disclose_complete_source": self.disclose_complete_source,
        }


@dataclass(frozen=True)
class ReviewedHistoricalMissionContext:
    """The exact human-readable mission authority the run was executed under.

    Owner-essential prose is presented exactly and is never replaced by a hash
    only.  Required material paths are mission-relative and are permitted.
    """

    mission_text: str
    gate_objective: str
    completion_conditions_text: str
    stop_clause: str
    permitted_effects: tuple[str, ...]
    forbidden_effects: tuple[str, ...]
    gate_clauses: tuple[ReviewedGateClause, ...]
    required_evidence_kinds: tuple[str, ...]
    checkpoint_commands: tuple[ReviewedCheckpointCommand, ...]
    required_material_paths: tuple[str, ...]
    required_complete_commit_message: str | None
    required_commits_added: int
    final_worktree_clean: bool
    final_index_clean: bool
    final_remotes_absent: bool
    behavioral_verifier: ReviewedBehavioralVerifierDisclosure

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "mission_text": self.mission_text,
            "gate_objective": self.gate_objective,
            "completion_conditions_text": self.completion_conditions_text,
            "stop_clause": self.stop_clause,
            "permitted_effects": list(self.permitted_effects),
            "forbidden_effects": list(self.forbidden_effects),
            "gate_clauses": [
                clause.to_presentation_dict() for clause in self.gate_clauses
            ],
            "required_evidence_kinds": list(self.required_evidence_kinds),
            "checkpoint_commands": [
                command.to_presentation_dict()
                for command in self.checkpoint_commands
            ],
            "required_material_paths": list(self.required_material_paths),
            "required_complete_commit_message": (
                self.required_complete_commit_message
            ),
            "required_commits_added": self.required_commits_added,
            "final_worktree_clean": self.final_worktree_clean,
            "final_index_clean": self.final_index_clean,
            "final_remotes_absent": self.final_remotes_absent,
            "behavioral_verifier": (
                self.behavioral_verifier.to_presentation_dict()
            ),
        }


@dataclass(frozen=True)
class ReviewedInitializedWorkspaceIdentity:
    """Independently observed content identities of the initialized workspace."""

    initial_git_head: str
    initial_material_tree_hash: str
    initial_commit_count: int
    initial_commit_message: str
    source_kind: str | None
    source_identity: str | None

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "initial_git_head": self.initial_git_head,
            "initial_material_tree_hash": self.initial_material_tree_hash,
            "initial_commit_count": self.initial_commit_count,
            "initial_commit_message": self.initial_commit_message,
            "source_kind": self.source_kind,
            "source_identity": self.source_identity,
        }


@dataclass(frozen=True)
class ReviewedHistoricalAuthorityContext:
    """Strict allowlist of non-result historical authorization facts.

    Every value here is an identifier, a fingerprint, a bounded scalar, a
    declared bound, or an inert classification string.  No local absolute path
    value appears.
    """

    authorization_schema_version: str
    target_authorization_payload_fingerprint: str
    run_id: str
    session_id: str
    profile_id: str
    gate_id: str
    mission_id: str
    historical_profile_fingerprint: str
    mission_fingerprint: str
    gate_plan_fingerprint: str
    gate_contract_fingerprint: str
    workspace_source_kind: str
    workspace_source_identity_fingerprint: str
    fixture_id: str | None
    fixture_version: int | None
    fixture_version_label: str
    selected_model: str
    budgets: tuple[int, ...]
    timeout_seconds: int
    stdout_byte_limit: int
    stderr_byte_limit: int
    clean_worktree_required: bool
    source_head: str
    backend_attestation_class: str
    backend_readiness_reason: str
    backend_attestation_fingerprint: str
    attestation_non_claims: tuple[str, ...]
    canary_non_claims: tuple[str, ...]
    initialized_workspace: ReviewedInitializedWorkspaceIdentity

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "authorization_schema_version": self.authorization_schema_version,
            "target_authorization_payload_fingerprint": (
                self.target_authorization_payload_fingerprint
            ),
            "run_id": self.run_id,
            "session_id": self.session_id,
            "profile_id": self.profile_id,
            "gate_id": self.gate_id,
            "mission_id": self.mission_id,
            "historical_profile_fingerprint": self.historical_profile_fingerprint,
            "mission_fingerprint": self.mission_fingerprint,
            "gate_plan_fingerprint": self.gate_plan_fingerprint,
            "gate_contract_fingerprint": self.gate_contract_fingerprint,
            "workspace_source_kind": self.workspace_source_kind,
            "workspace_source_identity_fingerprint": (
                self.workspace_source_identity_fingerprint
            ),
            "fixture_id": self.fixture_id,
            "fixture_version": self.fixture_version,
            "fixture_version_label": self.fixture_version_label,
            "selected_model": self.selected_model,
            "budgets": list(self.budgets),
            "timeout_seconds": self.timeout_seconds,
            "stdout_byte_limit": self.stdout_byte_limit,
            "stderr_byte_limit": self.stderr_byte_limit,
            "clean_worktree_required": self.clean_worktree_required,
            "source_head": self.source_head,
            "backend_attestation_class": self.backend_attestation_class,
            "backend_readiness_reason": self.backend_readiness_reason,
            "backend_attestation_fingerprint": (
                self.backend_attestation_fingerprint
            ),
            "attestation_non_claims": list(self.attestation_non_claims),
            "canary_non_claims": list(self.canary_non_claims),
            "initialized_workspace": (
                self.initialized_workspace.to_presentation_dict()
            ),
        }


@dataclass(frozen=True)
class ReviewedCompatibilityRevalidation:
    """One bounded fact from a fresh exact V5-to-V2 compatibility call.

    No compatibility witness is persisted and no new authority or fingerprint is
    created: the projected fingerprint is the historical V2 profile's own.
    """

    result: str
    projected_runtime_profile_fingerprint: str

    def to_presentation_dict(self) -> dict[str, Any]:
        return {
            "result": self.result,
            "projected_runtime_profile_fingerprint": (
                self.projected_runtime_profile_fingerprint
            ),
        }


@dataclass(frozen=True)
class HistoricalEvaluationPairingOwnerReview:
    """One complete, ephemeral, deeply immutable owner review.

    Every stored member is an immutable scalar, a tuple, or a frozen
    presentation dataclass.  No ``dict`` or ``list`` is stored anywhere in the
    object graph, so no caller can mutate a review by mutating something it
    reached through one.
    """

    pairing_identity: ReviewedPairingIdentity
    claim_authority: ReviewedClaimAuthority
    verification_plan_authority: ReviewedVerificationPlanAuthority
    verification_evidence_binding_authority: ReviewedEvidenceBindingAuthority
    historical_mission_context: ReviewedHistoricalMissionContext
    historical_authority_context: ReviewedHistoricalAuthorityContext
    compatibility_revalidation: ReviewedCompatibilityRevalidation
    withheld_fields: tuple[str, ...]
    notices: tuple[str, ...]

    def to_presentation_dict(self) -> dict[str, Any]:
        """Return a freshly created nested presentation mapping.

        Every call builds new dicts and lists; nothing is cached and nothing
        stored on the review is handed out by reference.
        """

        return {
            "pairing_identity": self.pairing_identity.to_presentation_dict(),
            "claim_authority": self.claim_authority.to_presentation_dict(),
            "verification_plan_authority": (
                self.verification_plan_authority.to_presentation_dict()
            ),
            "verification_evidence_binding_authority": (
                self.verification_evidence_binding_authority
                .to_presentation_dict()
            ),
            "historical_mission_context": (
                self.historical_mission_context.to_presentation_dict()
            ),
            "historical_authority_context": (
                self.historical_authority_context.to_presentation_dict()
            ),
            "compatibility_revalidation": (
                self.compatibility_revalidation.to_presentation_dict()
            ),
            "withheld_fields": list(self.withheld_fields),
            "notices": list(self.notices),
        }


# ---------------------------------------------------------------------------
# Derivation from the pinned canonical objects.
# ---------------------------------------------------------------------------


def _reviewed_claim_authority(
    evaluation_profile: NativeMissionProfile,
) -> ReviewedClaimAuthority:
    authority = evaluation_profile.claim_authority
    return ReviewedClaimAuthority(
        authorship=authority.authorship.value,
        coverage_status=authority.coverage_status.value,
        claims=tuple(
            ReviewedResultClaim(
                claim_id=claim.claim_id,
                statement=claim.statement,
                obligation_level=claim.obligation_level.value,
                # Owner order is preserved exactly; nothing sorts or dedupes.
                depends_on=tuple(claim.depends_on),
                non_claims=tuple(claim.non_claims),
            )
            for claim in authority.claims
        ),
    )


def _reviewed_plan_authority(
    evaluation_profile: NativeMissionProfile,
) -> ReviewedVerificationPlanAuthority:
    authority = evaluation_profile.claim_verification_plan_authority
    return ReviewedVerificationPlanAuthority(
        authorship=authority.authorship.value,
        coverage_status=authority.coverage_status.value,
        verification_obligations=tuple(
            ReviewedVerificationObligation(
                obligation_id=obligation.obligation_id,
                claim_ids=tuple(obligation.claim_ids),
                strategy=obligation.strategy.value,
                procedure_reference=obligation.procedure_reference,
                acceptance_predicate=obligation.acceptance_predicate.value,
                declared_coverage=obligation.declared_coverage,
                non_claims=tuple(obligation.non_claims),
                oracle_disclosed_to_subject=(
                    obligation.oracle_disclosed_to_subject
                ),
                independence_requirements=ReviewedIndependenceRequirements(
                    temporal=obligation.independence_requirements.temporal,
                    artifact=obligation.independence_requirements.artifact,
                    process=obligation.independence_requirements.process,
                    information=(
                        obligation.independence_requirements.information
                    ),
                    model=obligation.independence_requirements.model,
                    organizational=(
                        obligation.independence_requirements.organizational
                    ),
                ),
                negative_controls=tuple(
                    ReviewedNegativeControl(
                        control_id=control.control_id,
                        description=control.description,
                    )
                    for control in obligation.negative_controls
                ),
                reference_cases=tuple(obligation.reference_cases),
            )
            for obligation in authority.verification_obligations
        ),
    )


def _reviewed_binding_authority(
    evaluation_profile: NativeMissionProfile,
) -> ReviewedEvidenceBindingAuthority:
    authority = evaluation_profile.verification_evidence_binding_authority
    return ReviewedEvidenceBindingAuthority(
        authorship=authority.authorship.value,
        coverage_status=authority.coverage_status.value,
        bindings=tuple(
            ReviewedEvidenceBinding(
                binding_id=binding.binding_id,
                obligation_id=binding.obligation_id,
                source_authority_type=binding.source_authority_type.value,
                source_authority_reference=binding.source_authority_reference,
            )
            for binding in authority.bindings
        ),
    )


def _reviewed_mission_context(
    historical_profile: NativeMissionProfile,
) -> ReviewedHistoricalMissionContext:
    """Project the exact human-readable authority from the historical V2 profile."""

    policy = historical_profile.effective_git_end_state_policy
    verification = historical_profile.verification
    prompt = historical_profile.runtime_prompt
    source = verification.verifier_source
    return ReviewedHistoricalMissionContext(
        mission_text=historical_profile.mission_text,
        gate_objective=historical_profile.gate_objective,
        completion_conditions_text=(
            historical_profile.completion_conditions_text
        ),
        stop_clause=prompt.stop_clause,
        permitted_effects=tuple(prompt.permitted_effects),
        forbidden_effects=tuple(prompt.forbidden_effects),
        gate_clauses=tuple(
            ReviewedGateClause(clause_id=clause_id, text=text)
            for clause_id, text in historical_profile.gate_clauses
        ),
        required_evidence_kinds=tuple(
            historical_profile.required_evidence_kinds
        ),
        checkpoint_commands=tuple(
            ReviewedCheckpointCommand(
                command_id=command.command_id,
                argv=tuple(command.argv),
                timeout_seconds=command.timeout_seconds,
                max_capture_bytes=command.max_capture_bytes,
            )
            for command in historical_profile.checkpoint_commands
        ),
        required_material_paths=tuple(policy.required_material_paths),
        required_complete_commit_message=(
            policy.required_complete_commit_message
        ),
        required_commits_added=policy.required_commits_added,
        final_worktree_clean=policy.final_worktree_clean,
        final_index_clean=policy.final_index_clean,
        final_remotes_absent=policy.final_remotes_absent,
        behavioral_verifier=ReviewedBehavioralVerifierDisclosure(
            mode=verification.mode.value,
            verifier_source_sha256=verification.verifier_source_sha256,
            # A length is not the body: the complete source is never presented.
            verifier_source_byte_length=(
                None if source is None else len(source.encode("utf-8"))
            ),
            verifier_timeout_seconds=verification.verifier_timeout_seconds,
            verifier_output_limit_bytes=(
                verification.verifier_output_limit_bytes
            ),
            disclose_complete_source=verification.disclose_complete_source,
        ),
    )


def _reviewed_authority_context(
    target_authorization_payload: NativeCanaryAuthorizationPayloadV4,
) -> ReviewedHistoricalAuthorityContext:
    """Project the strict non-result allowlist, withholding every local locator."""

    historical_profile = target_authorization_payload.mission_profile
    workspace_source = historical_profile.effective_workspace_source
    workspace = target_authorization_payload.initialized_workspace
    return ReviewedHistoricalAuthorityContext(
        authorization_schema_version=(
            target_authorization_payload.schema_version
        ),
        target_authorization_payload_fingerprint=(
            target_authorization_payload.payload_fingerprint
        ),
        run_id=target_authorization_payload.run_id,
        session_id=target_authorization_payload.session_id,
        profile_id=historical_profile.profile_id,
        gate_id=historical_profile.gate_id,
        mission_id=historical_profile.mission_id,
        historical_profile_fingerprint=historical_profile.profile_fingerprint,
        mission_fingerprint=target_authorization_payload.mission_fingerprint,
        gate_plan_fingerprint=(
            target_authorization_payload.gate_plan_fingerprint
        ),
        gate_contract_fingerprint=(
            target_authorization_payload.gate_contract_fingerprint
        ),
        workspace_source_kind=workspace_source.kind.value,
        # A fingerprint of the source authority, never its local path value.
        workspace_source_identity_fingerprint=(
            workspace_source.identity_fingerprint
        ),
        fixture_id=workspace_source.fixture_id,
        fixture_version=workspace_source.fixture_version,
        fixture_version_label=target_authorization_payload.fixture_version,
        selected_model=target_authorization_payload.selected_model,
        budgets=tuple(target_authorization_payload.budgets),
        timeout_seconds=target_authorization_payload.timeout_seconds,
        stdout_byte_limit=target_authorization_payload.stdout_byte_limit,
        stderr_byte_limit=target_authorization_payload.stderr_byte_limit,
        clean_worktree_required=(
            target_authorization_payload.clean_worktree_required
        ),
        source_head=target_authorization_payload.source_head,
        backend_attestation_class=(
            target_authorization_payload.backend_attestation_class
        ),
        backend_readiness_reason=(
            target_authorization_payload.backend_readiness_reason
        ),
        backend_attestation_fingerprint=(
            target_authorization_payload.backend_attestation_fingerprint
        ),
        attestation_non_claims=tuple(
            target_authorization_payload.attestation_non_claims
        ),
        canary_non_claims=tuple(
            target_authorization_payload.canary_non_claims
        ),
        initialized_workspace=ReviewedInitializedWorkspaceIdentity(
            initial_git_head=workspace.initial_git_head,
            initial_material_tree_hash=workspace.initial_material_tree_hash,
            initial_commit_count=workspace.initial_commit_count,
            initial_commit_message=workspace.initial_commit_message,
            source_kind=workspace.source_kind,
            source_identity=workspace.source_identity,
        ),
    )


def build_historical_evaluation_pairing_owner_review(
    *,
    preparation_id: str,
    preparation_state: str,
    evaluation_profile: NativeMissionProfile,
    target_authorization_payload: NativeCanaryAuthorizationPayloadV4,
    pairing_authority: HistoricalEvaluationPairingAuthority,
    confirmation_message: bytes,
) -> HistoricalEvaluationPairingOwnerReview:
    """Build one complete owner review from exactly the four pinned objects.

    The function is pure with respect to the world: it opens no file, reads no
    secret, touches no archive, creates no authority or fingerprint, and leaves
    every supplied canonical object byte-identical.  The confirmation message is
    presented only as Base64, a byte length, and a digest; it is never parsed to
    recover an authority fact.
    """

    if type(preparation_id) is not str or not preparation_id:
        raise HistoricalPairingOwnerReviewError(
            "historical pairing owner review requires a bounded preparation "
            "identifier"
        )
    if preparation_state not in HISTORICAL_PAIRING_PREPARATION_STATES:
        raise HistoricalPairingOwnerReviewError(
            "historical pairing owner review preparation state is unsupported"
        )
    if not isinstance(evaluation_profile, NativeMissionProfile):
        raise HistoricalPairingOwnerReviewError(
            "historical pairing owner review requires the exact pinned v5 "
            "evaluation profile"
        )
    if (
        evaluation_profile.schema_version != MISSION_PROFILE_SCHEMA_VERSION_V5
        or evaluation_profile.is_launchable_runtime_profile
    ):
        raise HistoricalPairingOwnerReviewError(
            "historical pairing owner review requires an exact non-launchable "
            "v5 evaluation profile"
        )
    if not isinstance(
        target_authorization_payload, NativeCanaryAuthorizationPayloadV4
    ):
        raise HistoricalPairingOwnerReviewError(
            "historical pairing owner review requires the exact pinned "
            "historical v4 authorization payload"
        )
    if not isinstance(pairing_authority, HistoricalEvaluationPairingAuthority):
        raise HistoricalPairingOwnerReviewError(
            "historical pairing owner review requires the exact pinned pairing "
            "authority"
        )
    if type(confirmation_message) is not bytes or not confirmation_message:
        raise HistoricalPairingOwnerReviewError(
            "historical pairing owner review requires exact confirmation "
            "message bytes"
        )
    if len(confirmation_message) > MAX_CONFIRMATION_MESSAGE_BYTES:
        raise HistoricalPairingOwnerReviewError(
            "historical pairing owner review confirmation message exceeds its "
            "byte bound"
        )
    try:
        require_sha256(
            pairing_authority.authority_fingerprint,
            "historical pairing authority fingerprint",
        )
    except ValueError as exc:
        raise HistoricalPairingOwnerReviewError(
            "historical pairing owner review requires a canonical pairing "
            "authority fingerprint"
        ) from exc

    # A fresh call to the accepted pure compatibility function.  Only its
    # bounded result and the projected V2 fingerprint are reported; the
    # projection itself is discarded and nothing is persisted.
    try:
        projected = require_exact_v5_v2_runtime_authority_compatibility(
            evaluation_profile=evaluation_profile,
            target_authorization_payload=target_authorization_payload,
        )
    except (TypeError, ValueError) as exc:
        raise HistoricalPairingOwnerReviewError(
            "historical pairing owner review could not revalidate the exact "
            "v5 to v2 runtime-authority compatibility"
        ) from exc

    identity = ReviewedPairingIdentity(
        preparation_id=preparation_id,
        preparation_state=preparation_state,
        asserted_actor_id=pairing_authority.actor_id,
        pairing_authority_schema_version=pairing_authority.schema_version,
        pairing_authority_fingerprint=pairing_authority.authority_fingerprint,
        evaluation_profile_schema_version=evaluation_profile.schema_version,
        evaluation_profile_fingerprint=(
            pairing_authority.evaluation_profile_fingerprint
        ),
        target_authorization_payload_fingerprint=(
            pairing_authority.target_authorization_payload_fingerprint
        ),
        evaluation_profile_is_launchable=(
            evaluation_profile.is_launchable_runtime_profile
        ),
        confirmation_message_base64=base64.b64encode(
            confirmation_message
        ).decode("ascii"),
        confirmation_message_byte_length=len(confirmation_message),
        confirmation_message_sha256=hashlib.sha256(
            confirmation_message
        ).hexdigest(),
        confirmation_message_recipe=CONFIRMATION_MESSAGE_RECIPE,
    )

    return HistoricalEvaluationPairingOwnerReview(
        pairing_identity=identity,
        claim_authority=_reviewed_claim_authority(evaluation_profile),
        verification_plan_authority=_reviewed_plan_authority(evaluation_profile),
        verification_evidence_binding_authority=_reviewed_binding_authority(
            evaluation_profile
        ),
        historical_mission_context=_reviewed_mission_context(
            target_authorization_payload.mission_profile
        ),
        historical_authority_context=_reviewed_authority_context(
            target_authorization_payload
        ),
        compatibility_revalidation=ReviewedCompatibilityRevalidation(
            result=EXACT_CANONICAL_MATCH_REVALIDATED,
            projected_runtime_profile_fingerprint=projected.profile_fingerprint,
        ),
        withheld_fields=HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS,
        notices=HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES,
    )


__all__ = [
    "CONFIRMATION_MESSAGE_RECIPE",
    "EXACT_CANONICAL_MATCH_REVALIDATED",
    "HISTORICAL_PAIRING_OWNER_REVIEW_NOTICES",
    "HISTORICAL_PAIRING_OWNER_REVIEW_WITHHELD_FIELDS",
    "HISTORICAL_PAIRING_PREPARATION_STATES",
    "HistoricalEvaluationPairingOwnerReview",
    "HistoricalPairingOwnerReviewError",
    "MAX_CONFIRMATION_MESSAGE_BYTES",
    "PREPARATION_STATE_CONFIRMATION_IN_PROGRESS",
    "PREPARATION_STATE_CONSUMED",
    "PREPARATION_STATE_READY_FOR_CONFIRMATION",
    "ReviewedBehavioralVerifierDisclosure",
    "ReviewedCheckpointCommand",
    "ReviewedClaimAuthority",
    "ReviewedCompatibilityRevalidation",
    "ReviewedEvidenceBinding",
    "ReviewedEvidenceBindingAuthority",
    "ReviewedGateClause",
    "ReviewedHistoricalAuthorityContext",
    "ReviewedHistoricalMissionContext",
    "ReviewedIndependenceRequirements",
    "ReviewedInitializedWorkspaceIdentity",
    "ReviewedNegativeControl",
    "ReviewedPairingIdentity",
    "ReviewedResultClaim",
    "ReviewedVerificationObligation",
    "ReviewedVerificationPlanAuthority",
    "build_historical_evaluation_pairing_owner_review",
]
