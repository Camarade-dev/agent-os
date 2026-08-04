"""Versioned schema metadata for the pure paired-runner objects."""

from __future__ import annotations

from dataclasses import dataclass


SCHEMA_VERSION = 1
PACKAGE_PREFIX = "admissible.paired_runner"

SCHEMA_FINGERPRINT = f"{PACKAGE_PREFIX}.fingerprint"
SCHEMA_IDENTITY_REFERENCE = f"{PACKAGE_PREFIX}.identity_reference"
SCHEMA_RUN_IDENTITY = f"{PACKAGE_PREFIX}.run_identity"
SCHEMA_SESSION_IDENTITY = f"{PACKAGE_PREFIX}.session_identity"
SCHEMA_CONDITION = f"{PACKAGE_PREFIX}.condition_configuration"
SCHEMA_ALLOWED_DIFFERENCES = f"{PACKAGE_PREFIX}.allowed_condition_differences"
SCHEMA_BUDGET_STATE = f"{PACKAGE_PREFIX}.budget_state"
SCHEMA_CLOCK_OBSERVATION = f"{PACKAGE_PREFIX}.clock_observation"
SCHEMA_CAUSAL_PREDECESSOR = f"{PACKAGE_PREFIX}.causal_predecessor"
SCHEMA_EXPERIMENT = f"{PACKAGE_PREFIX}.experiment_specification"
SCHEMA_PROPOSAL = f"{PACKAGE_PREFIX}.canonical_proposal"
SCHEMA_MODE_DECISION = f"{PACKAGE_PREFIX}.mode_decision"
SCHEMA_RESERVATION = f"{PACKAGE_PREFIX}.effect_reservation"
SCHEMA_RECEIPT = f"{PACKAGE_PREFIX}.effect_receipt"
SCHEMA_INTERVENTION = f"{PACKAGE_PREFIX}.human_intervention_record"
SCHEMA_EVALUATOR = f"{PACKAGE_PREFIX}.evaluator_specification"
SCHEMA_TERMINAL = f"{PACKAGE_PREFIX}.terminal_manifest"
SCHEMA_COMPARATIVE = f"{PACKAGE_PREFIX}.comparative_manifest"
SCHEMA_PARITY_REPORT = f"{PACKAGE_PREFIX}.parity_report"

DIRECT = "DIRECT"
GOVERNED = "GOVERNED"
CONDITIONS = (DIRECT, GOVERNED)
DECISIONS = (
    "DIRECT_EXECUTION",
    "ALLOW",
    "REFUSE",
    "TERMINATE_RUN",
    "REQUIRE_CONTINUATION",
)
TOOL_NAMES = ("list_files", "read_file", "write_file", "run_command")
RECEIPT_STATUSES = (
    "PROPOSED",
    "RESERVED",
    "STARTED",
    "COMPLETED",
    "REFUSED",
    "FAILED",
    "CANCELLED",
    "TIMED_OUT",
    "AMBIGUOUS",
)
BUDGET_FIELDS = (
    "sessions",
    "turns",
    "proposals",
    "effects",
    "commands",
    "wall_time_ms",
    "model_active_time_ms",
    "output_bytes",
    "retries",
    "continuations",
    "human_interventions",
)


@dataclass(frozen=True)
class SchemaDescriptor:
    schema_id: str
    version: int
    implementation_type: str
    canonical_domain: str
    fingerprint_domain: str
    required_fields: tuple[str, ...]
    owning_module: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_id": self.schema_id,
            "version": self.version,
            "implementation_type": self.implementation_type,
            "canonical_domain": self.canonical_domain,
            "fingerprint_domain": self.fingerprint_domain,
            "required_fields": list(self.required_fields),
            "owning_module": self.owning_module,
        }


def _descriptor(
    schema_id: str,
    implementation_type: str,
    required_fields: tuple[str, ...],
    owning_module: str,
) -> SchemaDescriptor:
    return SchemaDescriptor(
        schema_id=schema_id,
        version=SCHEMA_VERSION,
        implementation_type=implementation_type,
        canonical_domain=f"{PACKAGE_PREFIX}.canonical",
        fingerprint_domain=f"{schema_id}.fingerprint",
        required_fields=required_fields,
        owning_module=owning_module,
    )


SCHEMA_CATALOG = {
    descriptor.schema_id: descriptor
    for descriptor in (
        _descriptor(
            SCHEMA_FINGERPRINT,
            "Fingerprint",
            ("algorithm", "domain", "value"),
            "admissible.paired_runner.canonical",
        ),
        _descriptor(
            SCHEMA_IDENTITY_REFERENCE,
            "IdentityReference",
            ("schema_id", "schema_version", "kind", "name", "version", "identity_semantics", "content_fingerprint", "identity_fingerprint"),
            "admissible.paired_runner.identities",
        ),
        _descriptor(
            SCHEMA_RUN_IDENTITY,
            "RunIdentity",
            ("schema_id", "schema_version", "experiment_id", "condition_id", "run_id", "identity_fingerprint"),
            "admissible.paired_runner.identities",
        ),
        _descriptor(
            SCHEMA_SESSION_IDENTITY,
            "SessionIdentity",
            ("schema_id", "schema_version", "experiment_id", "condition_id", "run_id", "session_id", "continuation_index", "predecessor_session_id", "identity_fingerprint"),
            "admissible.paired_runner.identities",
        ),
        _descriptor(
            SCHEMA_CONDITION,
            "ConditionConfiguration",
            ("schema_id", "schema_version", "condition_id", "admissible_decision_required", "owner_delegation_required", "governance_evidence", "condition_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_ALLOWED_DIFFERENCES,
            "AllowedConditionDifferences",
            ("schema_id", "schema_version", "allowed_condition_differences", "instance_binding_exceptions", "manifest_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_BUDGET_STATE,
            "BudgetState",
            ("schema_id", "schema_version", "limits", "used", "budget_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_CLOCK_OBSERVATION,
            "ClockObservation",
            ("schema_id", "schema_version", "clock_kind", "value", "semantics", "observation_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_CAUSAL_PREDECESSOR,
            "CausalPredecessor",
            ("schema_id", "schema_version", "sequence", "predecessor_fingerprint", "predecessor_kind", "causal_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_EXPERIMENT,
            "ExperimentSpecification",
            ("schema_id", "schema_version", "experiment_id", "task_prompt_fingerprint", "initial_state_fingerprint", "model_identity", "executable_identity", "executable_digest", "transport_identity", "tool_grammar_identity", "environment_identity", "dependency_toolchain_identity", "common_filesystem_network_process_policy_identity", "effect_executor_identity", "evaluator_identity", "common_budgets", "allowed_condition_differences", "condition", "run_identity", "specification_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_PROPOSAL,
            "CanonicalProposal",
            ("schema_id", "schema_version", "run_identity", "condition", "session_identity", "turn_id", "proposal_id", "tool_name", "canonical_arguments", "working_root_identity", "scope_identity", "causal_predecessor", "wall_clock_observation", "monotonic_observation", "model_identity", "transport_identity", "prompt_identity", "tool_grammar_identity", "effect_precondition", "proposal_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_MODE_DECISION,
            "ModeDecision",
            ("schema_id", "schema_version", "proposal_id", "proposal_fingerprint", "condition_id", "decision", "execution_prerequisite", "governance_decision_reference", "decision_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_RESERVATION,
            "EffectReservation",
            ("schema_id", "schema_version", "reservation_id", "proposal_id", "proposal_fingerprint", "mode_decision_fingerprint", "effect_executor_identity", "reservation_state", "reservation_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_RECEIPT,
            "EffectReceipt",
            ("schema_id", "schema_version", "receipt_id", "proposal_fingerprint", "reservation_fingerprint", "status", "effect_started", "effect_completed", "executed_effect", "process_exit_code", "task_acceptance", "outcome_reason", "receipt_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_INTERVENTION,
            "HumanInterventionRecord",
            ("schema_id", "schema_version", "intervention_id", "actor_class", "reason", "wall_clock_observation", "monotonic_observation", "run_identity", "session_id", "proposal_id", "allowed_policy_category", "comparability_disposition", "intervention_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_EVALUATOR,
            "EvaluatorSpecification",
            ("schema_id", "schema_version", "evaluator_id", "evaluator_version", "requirements_fingerprint", "scope_fingerprint", "test_plan_fingerprint", "environment_identity", "independent_of_model_claim", "process_success_is_not_acceptance", "evaluator_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_TERMINAL,
            "TerminalManifest",
            ("schema_id", "schema_version", "run_identity", "experiment_specification_fingerprint", "repository_state_fingerprint", "proposal_ledger_fingerprint", "effect_receipt_ledger_fingerprint", "budget_state_fingerprint", "evaluator_specification_fingerprint", "model_completion_claim", "process_result", "task_acceptance", "acceptance_basis", "reconciliation_complete", "terminal_manifest_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_COMPARATIVE,
            "ComparativeManifest",
            ("schema_id", "schema_version", "experiment_id", "experiment_specification_fingerprint", "direct_run_identity", "governed_run_identity", "parity_report_fingerprint", "direct_terminal_manifest_fingerprint", "governed_terminal_manifest_fingerprint", "comparative_manifest_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_PARITY_REPORT,
            "ParityReport",
            ("schema_id", "schema_version", "passed", "refusal_code", "experiment_id", "condition_ids", "mismatches", "normalization_paths", "report_fingerprint"),
            "admissible.paired_runner.comparison",
        ),
    )
}


def schema_descriptor(schema_id: str) -> SchemaDescriptor:
    try:
        return SCHEMA_CATALOG[schema_id]
    except KeyError as error:
        raise ValueError(f"unknown paired-runner schema {schema_id!r}") from error
