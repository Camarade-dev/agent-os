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

SCHEMA_LIST_FILES_REQUEST = f"{PACKAGE_PREFIX}.tool.list_files.request"
SCHEMA_LIST_FILES_RESULT = f"{PACKAGE_PREFIX}.tool.list_files.result"
SCHEMA_READ_FILE_REQUEST = f"{PACKAGE_PREFIX}.tool.read_file.request"
SCHEMA_READ_FILE_RESULT = f"{PACKAGE_PREFIX}.tool.read_file.result"
SCHEMA_WRITE_FILE_REQUEST = f"{PACKAGE_PREFIX}.tool.write_file.request"
SCHEMA_WRITE_FILE_RESULT = f"{PACKAGE_PREFIX}.tool.write_file.result"
SCHEMA_RUN_COMMAND_REQUEST = f"{PACKAGE_PREFIX}.tool.run_command.request"
SCHEMA_RUN_COMMAND_RESULT = f"{PACKAGE_PREFIX}.tool.run_command.result"
SCHEMA_TOOL_GRAMMAR_ENTRY = f"{PACKAGE_PREFIX}.tool_grammar_entry"
SCHEMA_TOOL_GRAMMAR = f"{PACKAGE_PREFIX}.tool_grammar_specification"

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
TOOL_REQUEST_SCHEMA_IDS = {
    "list_files": SCHEMA_LIST_FILES_REQUEST,
    "read_file": SCHEMA_READ_FILE_REQUEST,
    "write_file": SCHEMA_WRITE_FILE_REQUEST,
    "run_command": SCHEMA_RUN_COMMAND_REQUEST,
}
TOOL_RESULT_SCHEMA_IDS = {
    "list_files": SCHEMA_LIST_FILES_RESULT,
    "read_file": SCHEMA_READ_FILE_RESULT,
    "write_file": SCHEMA_WRITE_FILE_RESULT,
    "run_command": SCHEMA_RUN_COMMAND_RESULT,
}
TOOL_EFFECT_CLASSIFICATIONS = {
    "list_files": "READ_ONLY",
    "read_file": "READ_ONLY",
    "write_file": "FILE_MUTATION",
    "run_command": "PROCESS_EXECUTION",
}
EFFECT_CLASSIFICATIONS = ("READ_ONLY", "FILE_MUTATION", "PROCESS_EXECUTION")
PROCESS_EFFECT_CLASSIFICATION = "PROCESS_EXECUTION"
MUTATING_EFFECT_CLASSIFICATIONS = frozenset({"FILE_MUTATION", "PROCESS_EXECUTION"})
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
RESULT_BINDING_TOKENS = ("NONE", "OK", "REFUSED", "FAILED", "EXECUTION_FAILURE")
EXECUTION_FAILURE_CLASSES = (
    "EXECUTOR_START_FAILURE",
    "EXECUTOR_CRASHED",
    "RESULT_NOT_PRODUCED",
)
EFFECT_APPLICATIONS = ("NOT_APPLIED", "APPLIED", "PARTIAL_OR_UNKNOWN")


@dataclass(frozen=True)
class ReceiptStateRule:
    """Exhaustive lifecycle contract for one effect receipt status.

    ``process_exit_code`` states the policy for a ``PROCESS_EXECUTION`` tool
    only.  Every other effect classification forbids process-exit data in every
    status; see :func:`receipt_process_exit_policy`.  ``reconciliation_required``
    is the status floor: :func:`receipt_reconciliation_required` raises it when a
    mutating effect is left in a partial or unknown application state.
    """

    reservation: str
    effect_started: bool
    effect_completed: bool
    executed_effect: bool
    result_binding: tuple[str, ...]
    process_exit_code: str
    outcome_known: bool
    replay_forbidden: bool
    reconciliation_required: bool
    effect_application: str


RECEIPT_STATE_MATRIX = {
    "PROPOSED": ReceiptStateRule("FORBIDDEN", False, False, False, ("NONE",), "FORBIDDEN", False, True, False, "NOT_APPLIED"),
    "RESERVED": ReceiptStateRule("REQUIRED", False, False, False, ("NONE",), "FORBIDDEN", False, True, False, "NOT_APPLIED"),
    "STARTED": ReceiptStateRule("REQUIRED", True, False, False, ("NONE",), "FORBIDDEN", False, True, False, "PARTIAL_OR_UNKNOWN"),
    "COMPLETED": ReceiptStateRule("REQUIRED", True, True, True, ("OK",), "REQUIRED", True, True, False, "APPLIED"),
    "REFUSED": ReceiptStateRule("ALLOWED", False, False, False, ("NONE", "REFUSED"), "FORBIDDEN", True, True, False, "NOT_APPLIED"),
    "FAILED": ReceiptStateRule("REQUIRED", True, True, False, ("FAILED", "EXECUTION_FAILURE"), "ALLOWED", True, True, False, "PARTIAL_OR_UNKNOWN"),
    "CANCELLED": ReceiptStateRule("REQUIRED", True, True, False, ("NONE", "EXECUTION_FAILURE"), "ALLOWED", True, True, False, "PARTIAL_OR_UNKNOWN"),
    "TIMED_OUT": ReceiptStateRule("REQUIRED", True, False, False, ("NONE", "EXECUTION_FAILURE"), "ALLOWED", False, True, True, "PARTIAL_OR_UNKNOWN"),
    "AMBIGUOUS": ReceiptStateRule("REQUIRED", True, False, False, ("NONE",), "FORBIDDEN", False, True, True, "PARTIAL_OR_UNKNOWN"),
}


def receipt_state_rule(status: str) -> ReceiptStateRule:
    try:
        return RECEIPT_STATE_MATRIX[status]
    except KeyError as error:
        raise ValueError(f"unknown effect receipt status {status!r}") from error


def receipt_process_exit_policy(status: str, effect_classification: str) -> str:
    """Process-exit data exists only for a process-executing tool.

    ``list_files``, ``read_file``, and ``write_file`` never carry a process exit
    code, so no lifecycle state may require or accept one for them.
    """

    if effect_classification not in EFFECT_CLASSIFICATIONS:
        raise ValueError(f"unknown effect classification {effect_classification!r}")
    if effect_classification != PROCESS_EFFECT_CLASSIFICATION:
        return "FORBIDDEN"
    return receipt_state_rule(status).process_exit_code


def receipt_reconciliation_required(status: str, effect_classification: str) -> bool:
    """A partially applied or unknown mutation always requires reconciliation."""

    if effect_classification not in EFFECT_CLASSIFICATIONS:
        raise ValueError(f"unknown effect classification {effect_classification!r}")
    rule = receipt_state_rule(status)
    if rule.reconciliation_required:
        return True
    return (
        rule.effect_application == "PARTIAL_OR_UNKNOWN"
        and effect_classification in MUTATING_EFFECT_CLASSIFICATIONS
    )


@dataclass(frozen=True)
class TerminalStateRule:
    """Exhaustive terminal acceptance/reconciliation contract."""

    reconciliation_complete: bool
    acceptance_basis: str
    final_disposition: bool


TERMINAL_STATE_MATRIX = {
    "ACCEPTED": TerminalStateRule(True, "INDEPENDENT_EVALUATOR", True),
    "REJECTED": TerminalStateRule(True, "INDEPENDENT_EVALUATOR", True),
    "INCONCLUSIVE": TerminalStateRule(False, "INDEPENDENT_EVALUATOR", False),
    "NOT_EVALUATED": TerminalStateRule(False, "NONE", False),
}
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


@dataclass(frozen=True)
class ToolSchemaDescriptor(SchemaDescriptor):
    """Machine-readable contract metadata for one typed tool boundary."""

    optional_fields: tuple[str, ...]
    field_specs: tuple[tuple[str, str, bool], ...]
    path_representation: str
    bounds: tuple[str, ...]
    effect_classification: str
    result_representation: str
    exact_request_binding: str

    def to_dict(self) -> dict[str, object]:
        value = super().to_dict()
        value.update(
            {
                "optional_fields": list(self.optional_fields),
                "field_specs": [
                    {"name": name, "type": type_name, "required": required}
                    for name, type_name, required in self.field_specs
                ],
                "path_representation": self.path_representation,
                "bounds": list(self.bounds),
                "effect_classification": self.effect_classification,
                "result_representation": self.result_representation,
                "exact_request_binding": self.exact_request_binding,
            }
        )
        return value


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


def _tool_descriptor(
    schema_id: str,
    implementation_type: str,
    required_fields: tuple[str, ...],
    optional_fields: tuple[str, ...],
    field_specs: tuple[tuple[str, str, bool], ...],
    *,
    path_representation: str,
    bounds: tuple[str, ...],
    effect_classification: str,
    result_representation: str,
    exact_request_binding: str,
    owning_module: str = "admissible.paired_runner.tool_schemas",
) -> ToolSchemaDescriptor:
    return ToolSchemaDescriptor(
        schema_id=schema_id,
        version=SCHEMA_VERSION,
        implementation_type=implementation_type,
        canonical_domain=f"{PACKAGE_PREFIX}.canonical",
        fingerprint_domain=f"{schema_id}.fingerprint",
        required_fields=required_fields,
        owning_module=owning_module,
        optional_fields=optional_fields,
        field_specs=field_specs,
        path_representation=path_representation,
        bounds=bounds,
        effect_classification=effect_classification,
        result_representation=result_representation,
        exact_request_binding=exact_request_binding,
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
            ("schema_id", "schema_version", "experiment_id", "task_prompt_fingerprint", "initial_state_fingerprint", "model_identity", "executable_identity", "executable_digest", "transport_identity", "tool_grammar_identity", "tool_grammar", "environment_identity", "dependency_toolchain_identity", "common_filesystem_network_process_policy_identity", "working_root_identity", "scope_identity", "effect_executor_identity", "evaluator_identity", "evaluator_specification", "common_budgets", "allowed_condition_differences", "condition", "run_identity", "specification_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_PROPOSAL,
            "CanonicalProposal",
            ("schema_id", "schema_version", "experiment_specification_fingerprint", "run_identity", "condition", "session_identity", "turn_id", "proposal_id", "tool_name", "tool_request", "working_root_identity", "scope_identity", "causal_predecessor", "wall_clock_observation", "monotonic_observation", "model_identity", "transport_identity", "prompt_identity", "tool_grammar_identity", "effect_precondition", "proposal_fingerprint"),
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
            ("schema_id", "schema_version", "experiment_specification_fingerprint", "reservation_id", "proposal_id", "proposal_fingerprint", "mode_decision_fingerprint", "effect_executor_identity", "reservation_state", "reservation_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_RECEIPT,
            "EffectReceipt",
            ("schema_id", "schema_version", "receipt_id", "proposal_fingerprint", "reservation_fingerprint", "tool_name", "effect_classification", "tool_request_fingerprint", "tool_result", "execution_failure", "status", "effect_started", "effect_completed", "executed_effect", "effect_application", "process_exit_code", "outcome_known", "replay_forbidden", "reconciliation_required", "task_acceptance", "outcome_reason", "receipt_fingerprint"),
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
            ("schema_id", "schema_version", "experiment_id", "experiment_specification_fingerprint", "direct_specification_fingerprint", "governed_specification_fingerprint", "direct_run_identity", "governed_run_identity", "parity_report_fingerprint", "direct_terminal_manifest", "governed_terminal_manifest", "comparative_manifest_fingerprint"),
            "admissible.paired_runner.specification",
        ),
        _descriptor(
            SCHEMA_TOOL_GRAMMAR_ENTRY,
            "ToolGrammarEntry",
            ("schema_id", "schema_version", "tool_name", "request_schema_id", "request_schema_version", "result_schema_id", "result_schema_version", "effect_classification", "request_descriptor_fingerprint", "result_descriptor_fingerprint", "entry_fingerprint"),
            "admissible.paired_runner.tool_schemas",
        ),
        _descriptor(
            SCHEMA_TOOL_GRAMMAR,
            "ToolGrammarSpecification",
            ("schema_id", "schema_version", "grammar_id", "grammar_version", "tool_names", "entries", "grammar_fingerprint"),
            "admissible.paired_runner.tool_schemas",
        ),
        _descriptor(
            SCHEMA_PARITY_REPORT,
            "ParityReport",
            ("schema_id", "schema_version", "passed", "refusal_code", "experiment_id", "condition_ids", "mismatches", "normalization_paths", "report_fingerprint"),
            "admissible.paired_runner.comparison",
        ),
        _tool_descriptor(
            SCHEMA_LIST_FILES_REQUEST,
            "ListFilesRequest",
            (
                "schema_id", "schema_version", "tool_grammar_fingerprint", "path",
                "recursive", "max_entries", "request_fingerprint",
            ),
            (),
            (
                ("schema_id", "string", True), ("schema_version", "integer", True),
                ("tool_grammar_fingerprint", "Fingerprint", True), ("path", "relative-posix-path", True),
                ("recursive", "boolean", True), ("max_entries", "integer[1..10000]", True),
                ("request_fingerprint", "Fingerprint", True),
            ),
            path_representation="UTF-8 relative POSIX path; '.' is the only root form; no '..', backslash, NUL, or absolute path",
            bounds=("path <= 4096 UTF-8 bytes", "max_entries in [1, 10000]", "tool_grammar_fingerprint domain is exactly admissible.paired_runner.tool_grammar_specification.fingerprint"),
            effect_classification="READ_ONLY",
            result_representation="ListFilesResult: sorted unique relative paths plus truncation/outcome",
            exact_request_binding="ListFilesResult.validate_for_request refuses any result whose request fingerprint, entry count, entry scope, or truncation state does not match this exact request",
        ),
        _tool_descriptor(
            SCHEMA_LIST_FILES_RESULT,
            "ListFilesResult",
            (
                "schema_id", "schema_version", "request_fingerprint", "outcome", "entries",
                "truncated", "result_fingerprint",
            ),
            ("error_code",),
            (
                ("schema_id", "string", True), ("schema_version", "integer", True),
                ("request_fingerprint", "Fingerprint", True), ("outcome", "enum[OK,REFUSED,FAILED]", True),
                ("entries", "array[relative-posix-path]", True), ("truncated", "boolean", True),
                ("error_code", "string|null", False), ("result_fingerprint", "Fingerprint", True),
            ),
            path_representation="Result entries use the same relative POSIX path representation as the request",
            bounds=("entries <= 10000", "entry <= 4096 UTF-8 bytes", "entries <= the originating request max_entries", "truncated only when entries == request max_entries"),
            effect_classification="READ_ONLY",
            result_representation="Canonical sorted entry list; refusal/failure has no entries",
            exact_request_binding="Every entry must lie inside the exact requested path, a non-recursive request admits direct children only, and truncation is true only at the request entry bound",
        ),
        _tool_descriptor(
            SCHEMA_READ_FILE_REQUEST,
            "ReadFileRequest",
            (
                "schema_id", "schema_version", "tool_grammar_fingerprint", "path",
                "max_lines", "request_fingerprint",
            ),
            ("start_line",),
            (
                ("schema_id", "string", True), ("schema_version", "integer", True),
                ("tool_grammar_fingerprint", "Fingerprint", True), ("path", "relative-posix-path", True),
                ("start_line", "integer[1..1000000]|null", False), ("max_lines", "integer[1..10000]", True),
                ("request_fingerprint", "Fingerprint", True),
            ),
            path_representation="UTF-8 relative POSIX path; '.' is the only root form; no '..', backslash, NUL, or absolute path",
            bounds=("path <= 4096 UTF-8 bytes", "start_line null or in [1, 1000000]", "max_lines in [1, 10000]", "tool_grammar_fingerprint domain is exactly admissible.paired_runner.tool_grammar_specification.fingerprint"),
            effect_classification="READ_ONLY",
            result_representation="ReadFileResult: bounded UTF-8 content, byte count, truncation, and outcome",
            exact_request_binding="ReadFileResult.validate_for_request refuses any result whose request fingerprint, retained line count, byte count, or truncation state does not match this exact request",
        ),
        _tool_descriptor(
            SCHEMA_READ_FILE_RESULT,
            "ReadFileResult",
            (
                "schema_id", "schema_version", "request_fingerprint", "outcome", "content",
                "bytes_read", "truncated", "result_fingerprint",
            ),
            ("error_code",),
            (
                ("schema_id", "string", True), ("schema_version", "integer", True),
                ("request_fingerprint", "Fingerprint", True), ("outcome", "enum[OK,REFUSED,FAILED]", True),
                ("content", "UTF-8 string", True), ("bytes_read", "integer[0..1048576]", True),
                ("truncated", "boolean", True), ("error_code", "string|null", False),
                ("result_fingerprint", "Fingerprint", True),
            ),
            path_representation="The request path is retained by request_fingerprint; content has no path metadata",
            bounds=("content <= 1048576 UTF-8 bytes", "bytes_read <= 1048576", "retained lines <= the originating request max_lines"),
            effect_classification="READ_ONLY",
            result_representation="Bounded UTF-8 content with exact encoded byte count",
            exact_request_binding="Retained content must respect the exact request line bound; truncation is true only at that line bound or at the 1048576-byte content cap; refused or failed outcomes retain no content",
        ),
        _tool_descriptor(
            SCHEMA_WRITE_FILE_REQUEST,
            "WriteFileRequest",
            (
                "schema_id", "schema_version", "tool_grammar_fingerprint", "path", "content",
                "request_fingerprint",
            ),
            ("create_parents",),
            (
                ("schema_id", "string", True), ("schema_version", "integer", True),
                ("tool_grammar_fingerprint", "Fingerprint", True), ("path", "relative-posix-path", True),
                ("content", "UTF-8 string", True), ("create_parents", "boolean", False),
                ("request_fingerprint", "Fingerprint", True),
            ),
            path_representation="UTF-8 relative POSIX path; '.' is the only root form; no '..', backslash, NUL, or absolute path",
            bounds=("path <= 4096 UTF-8 bytes", "content <= 1048576 UTF-8 bytes", "tool_grammar_fingerprint domain is exactly admissible.paired_runner.tool_grammar_specification.fingerprint"),
            effect_classification="FILE_MUTATION",
            result_representation="WriteFileResult: applied byte count and written-content fingerprint",
            exact_request_binding="A successful WriteFileResult must report exactly the UTF-8 byte length of this request's content and the fixed-domain fingerprint of those exact bytes",
        ),
        _tool_descriptor(
            SCHEMA_WRITE_FILE_RESULT,
            "WriteFileResult",
            (
                "schema_id", "schema_version", "request_fingerprint", "outcome", "bytes_written",
                "result_fingerprint",
            ),
            ("error_code", "written_content_fingerprint"),
            (
                ("schema_id", "string", True), ("schema_version", "integer", True),
                ("request_fingerprint", "Fingerprint", True), ("outcome", "enum[OK,REFUSED,FAILED]", True),
                ("bytes_written", "integer[0..1048576]", True),
                ("written_content_fingerprint", "Fingerprint|null", False),
                ("error_code", "string|null", False), ("result_fingerprint", "Fingerprint", True),
            ),
            path_representation="The request path is retained by request_fingerprint; no path is echoed in the result",
            bounds=("bytes_written <= 1048576", "written content fingerprint is present only for OK", "written content fingerprint domain is exactly admissible.paired_runner.tool.write_file.written_content"),
            effect_classification="FILE_MUTATION",
            result_representation="Applied byte count and exact content fingerprint; refusal/failure writes zero bytes",
            exact_request_binding="WriteFileResult.validate_for_request requires bytes_written to equal the UTF-8 byte length of the exact requested content and the written-content fingerprint to equal the fixed-domain fingerprint of those bytes; refused or failed outcomes claim no mutation",
        ),
        _tool_descriptor(
            SCHEMA_RUN_COMMAND_REQUEST,
            "RunCommandRequest",
            (
                "schema_id", "schema_version", "tool_grammar_fingerprint", "argv", "cwd",
                "timeout_ms", "max_output_bytes", "request_fingerprint",
            ),
            (),
            (
                ("schema_id", "string", True), ("schema_version", "integer", True),
                ("tool_grammar_fingerprint", "Fingerprint", True), ("argv", "array[string]", True),
                ("cwd", "relative-posix-path", True), ("timeout_ms", "integer[1..60000]", True),
                ("max_output_bytes", "integer[1..1048576]", True), ("request_fingerprint", "Fingerprint", True),
            ),
            path_representation="cwd is a UTF-8 relative POSIX path; argv is an explicit argument array passed without shell interpolation, and a bare command string is refused",
            bounds=("argv length in [1, 128]", "argv[0] is a non-empty executable token", "argv total <= 65536 UTF-8 bytes", "each argv item <= 4096 UTF-8 bytes and NUL-free", "cwd <= 4096 UTF-8 bytes", "timeout_ms in [1, 60000]", "max_output_bytes in [1, 1048576]", "tool_grammar_fingerprint domain is exactly admissible.paired_runner.tool_grammar_specification.fingerprint"),
            effect_classification="PROCESS_EXECUTION",
            result_representation="RunCommandResult: bounded stdout/stderr, exit code, timeout/truncation, and outcome",
            exact_request_binding="RunCommandResult.validate_for_request refuses any result whose request fingerprint, retained output bound, truncation state, or process-start semantics do not match this exact request",
        ),
        _tool_descriptor(
            SCHEMA_RUN_COMMAND_RESULT,
            "RunCommandResult",
            (
                "schema_id", "schema_version", "request_fingerprint", "outcome", "process_started",
                "stdout", "stderr", "stdout_truncated", "stderr_truncated", "result_fingerprint",
            ),
            ("exit_code", "error_code"),
            (
                ("schema_id", "string", True), ("schema_version", "integer", True),
                ("request_fingerprint", "Fingerprint", True), ("outcome", "enum[OK,REFUSED,FAILED]", True),
                ("process_started", "boolean", True),
                ("stdout", "UTF-8 string", True), ("stderr", "UTF-8 string", True),
                ("stdout_truncated", "boolean", True), ("stderr_truncated", "boolean", True),
                ("exit_code", "integer[-128..255]|null", False), ("error_code", "string|null", False),
                ("result_fingerprint", "Fingerprint", True),
            ),
            path_representation="The request cwd/argv are retained by request_fingerprint; result contains no host path",
            bounds=("stdout <= 1048576 UTF-8 bytes", "stderr <= 1048576 UTF-8 bytes", "stdout and stderr <= the originating request max_output_bytes", "exit_code in [-128, 255]"),
            effect_classification="PROCESS_EXECUTION",
            result_representation="Bounded process result; process_started separates tool execution success from the command exit code, and exit-code semantics exist only for a started command",
            exact_request_binding="Retained stdout and stderr must respect the exact request output bound, truncation is true only at that bound, a result that never started the process carries no process observation, and outcome OK means the tool executed rather than that the command exited zero",
        ),
    )
}


def schema_descriptor(schema_id: str) -> SchemaDescriptor:
    try:
        return SCHEMA_CATALOG[schema_id]
    except KeyError as error:
        raise ValueError(f"unknown paired-runner schema {schema_id!r}") from error
