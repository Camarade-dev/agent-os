"""Immutable, JSON-ready presentation types for the Admissible product read model.

Every type is a frozen dataclass with a ``to_json`` method returning only
JSON-compatible primitives (``dict``/``list``/``str``/``int``/``float``/``bool``/
``None``). Presentation types never carry ``Path`` objects, enums, tuples or
other non-JSON values in their serialized form.

The types keep the required layers explicitly separate:

* persisted canonical classification -> ``RunDetail.canonical_classification*``
* authoritative product verdict -> ``ProductVerdictView`` (``UNKNOWN`` by default)
* verification tier -> ``ProductVerdictView.verification_mode``
* human review / acceptance -> ``HumanDispositionView``
* evidence completeness -> ``EvidenceCompletenessView``
* presentation status -> ``RunDetail.presentation_status``
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .enums import (
    ClassificationKind,
    CompletenessState,
    ExecutionState,
    FailingBoundary,
    HumanDisposition,
    OutcomeState,
    PresentationStatus,
    PresenceState,
    ProductVerdict,
    TruthStatus,
    VerdictSource,
    VerificationMode,
)

RUN_DETAIL_SCHEMA_VERSION = "admissible_product_read_model_run_detail_v1"
RUN_SUMMARY_SCHEMA_VERSION = "admissible_product_read_model_run_summary_v1"


@dataclass(frozen=True)
class ArtifactView:
    """A declared execution artifact (stdout/stderr/script) with size and hash."""

    artifact_id: str | None
    purpose: str | None
    relative_path: str | None
    byte_count: int | None
    sha256: str | None
    truncated: bool | None
    schema_version: str | None
    file_presence: PresenceState

    def to_json(self) -> dict:
        return {
            "artifact_id": self.artifact_id,
            "purpose": self.purpose,
            "relative_path": self.relative_path,
            "byte_count": self.byte_count,
            "sha256": self.sha256,
            "truncated": self.truncated,
            "schema_version": self.schema_version,
            "file_presence": self.file_presence.value,
        }


@dataclass(frozen=True)
class DiagnosticExcerpt:
    """A bounded, redacted excerpt of a large diagnostic stream or detail string.

    ``excerpt`` holds already-redacted, already-bounded text. It is NOT
    HTML-escaped; the renderer escapes it at emit time.
    """

    label: str
    source_relative_path: str | None
    total_byte_count: int | None
    excerpt: str
    truncated: bool
    sha256: str | None
    encoding_note: str | None

    def to_json(self) -> dict:
        return {
            "label": self.label,
            "source_relative_path": self.source_relative_path,
            "total_byte_count": self.total_byte_count,
            "excerpt": self.excerpt,
            "truncated": self.truncated,
            "sha256": self.sha256,
            "encoding_note": self.encoding_note,
        }


@dataclass(frozen=True)
class RunIdentityView:
    """Stable identity fields for a run, sourced from persisted records."""

    run_id: str | None
    session_id: str | None
    run_root: str
    gate_id: str | None
    mission_id: str | None
    mission_fingerprint: str | None
    request_fingerprint: str | None
    final_status_presence: PresenceState

    def to_json(self) -> dict:
        return {
            "run_id": self.run_id,
            "session_id": self.session_id,
            "run_root": self.run_root,
            "gate_id": self.gate_id,
            "mission_id": self.mission_id,
            "mission_fingerprint": self.mission_fingerprint,
            "request_fingerprint": self.request_fingerprint,
            "final_status_presence": self.final_status_presence.value,
        }


@dataclass(frozen=True)
class AuthorizationView:
    """Owner-authorization facts, extracted with a secret-safe allow list."""

    present: PresenceState
    run_id: str | None
    session_id: str | None
    mission_id: str | None
    mission_fingerprint: str | None
    gate_id: str | None
    gate_contract_fingerprint: str | None
    required_commit_message: str | None
    authorized_model: str | None
    backend_identity: str | None
    classification: str | None
    clean_worktree_required: bool | None
    timeout_seconds: int | None
    budgets: dict | None
    objective: str | None
    non_claims: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "present": self.present.value,
            "run_id": self.run_id,
            "session_id": self.session_id,
            "mission_id": self.mission_id,
            "mission_fingerprint": self.mission_fingerprint,
            "gate_id": self.gate_id,
            "gate_contract_fingerprint": self.gate_contract_fingerprint,
            "required_commit_message": self.required_commit_message,
            "authorized_model": self.authorized_model,
            "backend_identity": self.backend_identity,
            "classification": self.classification,
            "clean_worktree_required": self.clean_worktree_required,
            "timeout_seconds": self.timeout_seconds,
            "budgets": dict(self.budgets) if self.budgets is not None else None,
            "objective": self.objective,
            "non_claims": list(self.non_claims),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class GateClauseView:
    """One authorized clause, retained in canonical persisted order."""

    clause_id: str
    text: str

    def to_json(self) -> dict:
        return {"clause_id": self.clause_id, "text": self.text}


@dataclass(frozen=True)
class GateClausesView:
    """Presentation-only availability of the persisted authorized clause set."""

    present: PresenceState
    clauses: tuple[GateClauseView, ...] = ()
    note: str | None = None

    def to_json(self) -> dict:
        return {
            "present": self.present.value,
            "clauses": [clause.to_json() for clause in self.clauses],
            "notice": (
                "These clauses are part of the authorized contract. They are not "
                "independently adjudicated unless linked to explicit verification evidence."
            ),
            "note": self.note,
        }


@dataclass(frozen=True)
class ProcessView:
    """Native provider process lifecycle, preferring harness observation."""

    present: PresenceState
    execution_state: ExecutionState
    process_id: int | None
    executable: str | None
    exit_code: int | None
    termination_reason: str | None
    timed_out: bool | None
    started_at: str | None
    ended_at: str | None
    timeout_seconds: int | None
    output_truncation_occurred: bool | None
    orphan_process_ids: tuple[int, ...]
    cleanup_confirmed: bool | None
    cleanup_observation: str | None
    observation_matches_result: bool | None
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "present": self.present.value,
            "execution_state": self.execution_state.value,
            "process_id": self.process_id,
            "executable": self.executable,
            "exit_code": self.exit_code,
            "termination_reason": self.termination_reason,
            "timed_out": self.timed_out,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "timeout_seconds": self.timeout_seconds,
            "output_truncation_occurred": self.output_truncation_occurred,
            "orphan_process_ids": list(self.orphan_process_ids),
            "cleanup_confirmed": self.cleanup_confirmed,
            "cleanup_observation": self.cleanup_observation,
            "observation_matches_result": self.observation_matches_result,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class WorkspaceGitView:
    """Workspace and source-repository Git facts from harness observation."""

    present: PresenceState
    initial_git_head: str | None
    final_git_head: str | None
    initial_material_tree_hash: str | None
    final_material_tree_hash: str | None
    final_git_porcelain_status: str | None
    git_remotes: tuple[str, ...]
    commits_added: int | None
    workspace_material_changed: bool | None
    source_repository_mutated: bool | None
    changed_material_files: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "present": self.present.value,
            "initial_git_head": self.initial_git_head,
            "final_git_head": self.final_git_head,
            "initial_material_tree_hash": self.initial_material_tree_hash,
            "final_material_tree_hash": self.final_material_tree_hash,
            "final_git_porcelain_status": self.final_git_porcelain_status,
            "git_remotes": list(self.git_remotes),
            "commits_added": self.commits_added,
            "workspace_material_changed": self.workspace_material_changed,
            "source_repository_mutated": self.source_repository_mutated,
            "changed_material_files": list(self.changed_material_files),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class MaterialView:
    """Material-path / Git eligibility result (harness eligibility record)."""

    present: PresenceState
    result: OutcomeState
    eligible: bool | None
    material_paths_compliant: bool | None
    workspace_clean: bool | None
    remotes_absent: bool | None
    exactly_one_commit: bool | None
    commit_message_compliant: bool | None
    source_and_root_integrity: bool | None
    ineligibility_reasons: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "present": self.present.value,
            "result": self.result.value,
            "eligible": self.eligible,
            "material_paths_compliant": self.material_paths_compliant,
            "workspace_clean": self.workspace_clean,
            "remotes_absent": self.remotes_absent,
            "exactly_one_commit": self.exactly_one_commit,
            "commit_message_compliant": self.commit_message_compliant,
            "source_and_root_integrity": self.source_and_root_integrity,
            "ineligibility_reasons": list(self.ineligibility_reasons),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class BehavioralVerificationView:
    """Immutable behavioral-verifier result. ABSENT never means PASSED."""

    present: PresenceState
    result: OutcomeState
    exit_code: int | None
    timed_out: bool | None
    evidence_fingerprint: str | None
    stdout_artifact: ArtifactView | None
    stderr_artifact: ArtifactView | None
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "present": self.present.value,
            "result": self.result.value,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "evidence_fingerprint": self.evidence_fingerprint,
            "stdout_artifact": self.stdout_artifact.to_json() if self.stdout_artifact else None,
            "stderr_artifact": self.stderr_artifact.to_json() if self.stderr_artifact else None,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class CheckpointView:
    """Checkpoint result. ABSENT (never attempted) is distinct from FAILED."""

    present: PresenceState
    result: OutcomeState
    attempted: bool
    checkpoint_fingerprint: str | None
    verification_command_ids: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "present": self.present.value,
            "result": self.result.value,
            "attempted": self.attempted,
            "checkpoint_fingerprint": self.checkpoint_fingerprint,
            "verification_command_ids": list(self.verification_command_ids),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class FailingBoundaryView:
    """Earliest refusal boundary plus the harness's own category and detail."""

    boundary: FailingBoundary
    failure_category: str | None
    detail: str | None
    reasons: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "boundary": self.boundary.value,
            "failure_category": self.failure_category,
            "detail": self.detail,
            "reasons": list(self.reasons),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class ProductVerdictView:
    """Effective authoritative product verdict, with the persisted claim demoted.

    Authority model (see :mod:`product_extractor`):

    * ``verdict`` is the *effective authoritative* verdict. It is ``UNKNOWN``
      unless an authoritative reconstruction (``truth_status == AUTHORITATIVE``)
      supplies a recognised value. A persisted ``evidence/product-verdict.json``
      block NEVER sets this field — it is evidence to display, not authority to
      trust.
    * ``source`` is the provenance of the *effective* verdict (``NONE`` or
      ``AUTHORITATIVE_RECONSTRUCTION``).
    * ``truth_status`` records the reconstruction seam's availability; only
      ``AUTHORITATIVE`` may back an admitted/refused effective verdict.
    * ``claimed_verdict`` / ``claimed_verification_mode`` carry the *unverified*
      persisted claim, if any. ``claim_is_authoritative`` is ``False`` by
      construction — a persisted claim can never be authoritative here.
    * ``consistent`` is ``False`` when an authoritative verdict and a persisted
      claim disagree, or when a persisted product claim survives a provider
      failure; the authoritative verdict (when present) is retained regardless.
    """

    # Effective authoritative verdict (never set by a persisted claim).
    verdict: ProductVerdict
    raw_verdict: str | None
    verification_mode: VerificationMode
    raw_verification_mode: str | None
    behavioral_non_claim: str | None
    source: VerdictSource
    truth_status: TruthStatus
    consistent: bool
    # Persisted claim (unverified, display-only).
    claim_present: bool
    claimed_verdict: ProductVerdict
    raw_claimed_verdict: str | None
    claimed_verification_mode: VerificationMode
    raw_claimed_verification_mode: str | None
    claim_is_authoritative: bool = False
    notes: tuple[str, ...] = ()

    @property
    def truth_available(self) -> bool:
        """True only when the seam supplied an authoritative reconstruction."""

        return self.truth_status is TruthStatus.AUTHORITATIVE

    @property
    def verdict_is_authoritative(self) -> bool:
        """True only for a recognised admitted/refused authoritative verdict."""

        return (
            self.source is VerdictSource.AUTHORITATIVE_RECONSTRUCTION
            and self.truth_status is TruthStatus.AUTHORITATIVE
            and self.verdict
            in (
                ProductVerdict.ADMITTED_OBSERVED,
                ProductVerdict.ADMITTED_VERIFIED,
                ProductVerdict.REFUSED,
            )
        )

    def to_json(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "raw_verdict": self.raw_verdict,
            "verification_mode": self.verification_mode.value,
            "raw_verification_mode": self.raw_verification_mode,
            "behavioral_non_claim": self.behavioral_non_claim,
            "source": self.source.value,
            "truth_status": self.truth_status.value,
            "truth_available": self.truth_available,
            "verdict_is_authoritative": self.verdict_is_authoritative,
            "consistent": self.consistent,
            "claim_present": self.claim_present,
            "claimed_verdict": self.claimed_verdict.value,
            "raw_claimed_verdict": self.raw_claimed_verdict,
            "claimed_verification_mode": self.claimed_verification_mode.value,
            "raw_claimed_verification_mode": self.raw_claimed_verification_mode,
            "claim_is_authoritative": self.claim_is_authoritative,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class HumanDispositionView:
    """Human review / acceptance, distinct from every machine verdict."""

    present: PresenceState
    disposition: HumanDisposition
    raw_disposition: str | None
    reason: str | None
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "present": self.present.value,
            "disposition": self.disposition.value,
            "raw_disposition": self.raw_disposition,
            "reason": self.reason,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class EvidenceTimelineEntry:
    """One deterministic timeline event with its persisted timestamp (or None)."""

    event_key: str
    label: str
    timestamp: str | None
    source_relative_path: str | None
    presence: PresenceState
    out_of_order: bool = False
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "event_key": self.event_key,
            "label": self.label,
            "timestamp": self.timestamp,
            "source_relative_path": self.source_relative_path,
            "presence": self.presence.value,
            "out_of_order": self.out_of_order,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class EvidenceCompletenessView:
    """Aggregate evidence completeness across the persisted record set."""

    state: CompletenessState
    present_records: tuple[str, ...]
    absent_records: tuple[str, ...]
    inconsistent_records: tuple[str, ...]
    missing_required: tuple[str, ...]
    notes: tuple[str, ...] = ()

    def to_json(self) -> dict:
        return {
            "state": self.state.value,
            "present_records": list(self.present_records),
            "absent_records": list(self.absent_records),
            "inconsistent_records": list(self.inconsistent_records),
            "missing_required": list(self.missing_required),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class RunSummary:
    """Compact list-view projection of a run."""

    run_id: str | None
    run_root: str
    canonical_classification: str | None
    canonical_classification_kind: ClassificationKind
    presentation_status: PresentationStatus
    product_verdict: ProductVerdict
    verdict_source: VerdictSource
    verdict_is_authoritative: bool
    verdict_consistent: bool
    truth_status: TruthStatus
    claimed_product_verdict: ProductVerdict
    verification_mode: VerificationMode
    human_disposition: HumanDisposition
    evidence_completeness: CompletenessState
    failing_boundary: FailingBoundary
    final_status_presence: PresenceState
    schema_version: str = RUN_SUMMARY_SCHEMA_VERSION

    def to_json(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "run_root": self.run_root,
            "canonical_classification": self.canonical_classification,
            "canonical_classification_kind": self.canonical_classification_kind.value,
            "presentation_status": self.presentation_status.value,
            # Effective authoritative product verdict (never a persisted claim).
            "product_verdict": self.product_verdict.value,
            "verdict_source": self.verdict_source.value,
            "verdict_is_authoritative": self.verdict_is_authoritative,
            "verdict_consistent": self.verdict_consistent,
            "truth_status": self.truth_status.value,
            # The unverified persisted claim, kept distinct from the verdict.
            "claimed_product_verdict": self.claimed_product_verdict.value,
            "verification_mode": self.verification_mode.value,
            "human_disposition": self.human_disposition.value,
            "evidence_completeness": self.evidence_completeness.value,
            "failing_boundary": self.failing_boundary.value,
            "final_status_presence": self.final_status_presence.value,
        }


@dataclass(frozen=True)
class RunDetail:
    """Full presentation model for a single run."""

    run_root: str
    identity: RunIdentityView
    authorization: AuthorizationView
    gate_clauses: GateClausesView
    canonical_classification: str | None
    canonical_classification_kind: ClassificationKind
    canary_success: bool | None
    final_status_detail: str | None
    failing_boundary: FailingBoundaryView
    process: ProcessView
    workspace_git: WorkspaceGitView
    material: MaterialView
    behavioral: BehavioralVerificationView
    checkpoint: CheckpointView
    product_verdict: ProductVerdictView
    human_disposition: HumanDispositionView
    evidence_completeness: EvidenceCompletenessView
    presentation_status: PresentationStatus
    timeline: tuple[EvidenceTimelineEntry, ...]
    artifacts: tuple[ArtifactView, ...]
    diagnostics: tuple[DiagnosticExcerpt, ...]
    read_notes: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = RUN_DETAIL_SCHEMA_VERSION

    def summary(self) -> RunSummary:
        """Project this detail to a compact ``RunSummary`` (no re-derivation)."""

        return RunSummary(
            run_id=self.identity.run_id,
            run_root=self.run_root,
            canonical_classification=self.canonical_classification,
            canonical_classification_kind=self.canonical_classification_kind,
            presentation_status=self.presentation_status,
            product_verdict=self.product_verdict.verdict,
            verdict_source=self.product_verdict.source,
            verdict_is_authoritative=self.product_verdict.verdict_is_authoritative,
            verdict_consistent=self.product_verdict.consistent,
            truth_status=self.product_verdict.truth_status,
            claimed_product_verdict=self.product_verdict.claimed_verdict,
            verification_mode=self.product_verdict.verification_mode,
            human_disposition=self.human_disposition.disposition,
            evidence_completeness=self.evidence_completeness.state,
            failing_boundary=self.failing_boundary.boundary,
            final_status_presence=self.identity.final_status_presence,
        )

    def to_json(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "run_root": self.run_root,
            "identity": self.identity.to_json(),
            "authorization": self.authorization.to_json(),
            "gate_clauses": self.gate_clauses.to_json(),
            "canonical_classification": self.canonical_classification,
            "canonical_classification_kind": self.canonical_classification_kind.value,
            "canary_success": self.canary_success,
            "final_status_detail": self.final_status_detail,
            "failing_boundary": self.failing_boundary.to_json(),
            "process": self.process.to_json(),
            "workspace_git": self.workspace_git.to_json(),
            "material": self.material.to_json(),
            "behavioral": self.behavioral.to_json(),
            "checkpoint": self.checkpoint.to_json(),
            "product_verdict": self.product_verdict.to_json(),
            "human_disposition": self.human_disposition.to_json(),
            "evidence_completeness": self.evidence_completeness.to_json(),
            "presentation_status": self.presentation_status.value,
            "timeline": [entry.to_json() for entry in self.timeline],
            "artifacts": [artifact.to_json() for artifact in self.artifacts],
            "diagnostics": [excerpt.to_json() for excerpt in self.diagnostics],
            "read_notes": list(self.read_notes),
        }
