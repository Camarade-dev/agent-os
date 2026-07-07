"""Deterministic orchestrator goal intake scaffolding (no LLM or execution)."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from agent_os.paths import (
    CLARIFICATIONS_DIR,
    GOAL_INTAKE_FILE,
    ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_FILE,
    ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE_FILE,
    ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_FILE,
    ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_FILE,
    ORCHESTRATOR_CONTEXT_TRANSPORT_FILE,
    ORCHESTRATOR_CONTEXT_TRANSPORT_MD_FILE,
    ORCHESTRATOR_DRAFT_SCAFFOLD_NOTES_FILE,
    ORCHESTRATOR_PROVENANCE_FILE,
    READINESS_DECISIONS_DIR,
    REQUIREMENTS_EXTRACTION_DECISIONS_DIR,
    REQUIREMENTS_VALIDATION_DECISIONS_DIR,
    orchestrator_clarification_path,
    orchestrator_intake_path,
    orchestrator_readiness_decision_path,
    orchestrator_requirements_extraction_decision_path,
    orchestrator_requirements_validation_decision_path,
    parse_frontmatter,
    planning_path,
    section_body,
    workspace_path,
)
from agent_os.planning import init_planning_workspace, planning_templates_dir, validate_plan_id

INTAKE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
CLARIFICATION_ID_PATTERN = INTAKE_ID_PATTERN
READINESS_DECISION_ID_PATTERN = INTAKE_ID_PATTERN

GOAL_INTAKE_REQUIRED_FIELDS = (
    "artifact_type",
    "schema_version",
    "intake_id",
    "raw_goal",
    "normalized_goal",
    "user_visible_summary",
    "explicit_constraints",
    "inferred_assumptions",
    "open_questions",
    "non_goals",
    "risk_flags",
    "ambiguity_level",
    "planning_readiness",
    "created_at",
    "non_authority",
)

GOAL_INTAKE_NON_AUTHORITY_FLAGS = (
    "does_not_create_plan",
    "does_not_validate_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "generated_markdown_is_not_machine_authority",
)

GOAL_INTAKE_ARTIFACT_TYPE = "GOAL_INTAKE"
GOAL_INTAKE_SCHEMA_VERSION = "0.1"

GOAL_INTAKE_AMBIGUITY_LEVELS = frozenset({"LOW", "MEDIUM", "HIGH"})
GOAL_INTAKE_PLANNING_READINESS = frozenset(
    {"NOT_READY", "DRAFT_ALLOWED", "REQUIRES_CLARIFICATION"}
)

OWNER_CLARIFICATION_ARTIFACT_TYPE = "OWNER_CLARIFICATION"
OWNER_CLARIFICATION_SCHEMA_VERSION = "0.1"

OWNER_CLARIFICATION_REQUIRED_FIELDS = (
    "artifact_type",
    "schema_version",
    "intake_id",
    "clarification_id",
    "owner_answer",
    "applies_to_open_questions",
    "explicit_constraints_added",
    "non_goals_added",
    "risk_notes",
    "created_at",
    "non_authority",
)

OWNER_CLARIFICATION_NON_AUTHORITY_FLAGS = (
    "does_not_create_plan",
    "does_not_validate_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "does_not_mark_intake_draft_ready",
    "does_not_modify_goal_intake",
)

READINESS_REVIEW_NON_AUTHORITY_FLAGS = (
    "does_not_create_plan",
    "does_not_generate_planning_draft",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "does_not_mark_intake_draft_ready",
    "requires_future_owner_readiness_decision",
)

FORBIDDEN_READINESS_REVIEW_STATES = frozenset({"DRAFT_ALLOWED", "READY_FOR_DRAFT"})

OWNER_READINESS_DECISION_ARTIFACT_TYPE = "OWNER_READINESS_DECISION"
OWNER_READINESS_DECISION_SCHEMA_VERSION = "0.1"

OWNER_READINESS_DECISION_VALUES = frozenset(
    {
        "REQUEST_MORE_CLARIFICATION",
        "BLOCK_INTAKE",
        "AUTHORIZE_DRAFT_PREPARATION",
    }
)

AUTHORIZE_DRAFT_PREPARATION_ALLOWED_STATES = frozenset(
    {
        "OWNER_CLARIFICATION_PRESENT_REVIEW_REQUIRED",
        "OWNER_REVIEW_REQUIRED",
    }
)

AUTHORIZE_DRAFT_PREPARATION_FORBIDDEN_STATES = frozenset(
    {
        "BLOCKED_INVALID_INTAKE",
        "BLOCKED_REQUIRES_CLARIFICATION",
    }
)

OWNER_READINESS_DECISION_REQUIRED_FIELDS = (
    "artifact_type",
    "schema_version",
    "intake_id",
    "decision_id",
    "decision",
    "owner_summary",
    "readiness_review_state_at_decision",
    "next_required_action_at_decision",
    "owner_clarification_count_at_decision",
    "latest_clarification_id_at_decision",
    "created_at",
    "non_authority",
)

OWNER_READINESS_DECISION_NON_AUTHORITY_FLAGS = (
    "does_not_create_plan",
    "does_not_generate_planning_draft",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "does_not_approve_architecture",
    "does_not_modify_goal_intake",
    "does_not_modify_clarifications",
    "authorizes_future_draft_preparation_only_when_decision_is_authorize",
)

DRAFT_PREPARATION_PREFLIGHT_NON_AUTHORITY_FLAGS = (
    "does_not_create_plan",
    "does_not_generate_planning_draft",
    "does_not_create_planning_workspace",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_approve_architecture",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "does_not_modify_goal_intake",
    "does_not_modify_clarifications",
    "does_not_modify_readiness_decisions",
    "requires_separate_future_draft_preparation_command",
    "requires_future_independent_validation_before_plan_approval",
    "requires_future_owner_approval_before_run_proposals",
)

FORBIDDEN_DRAFT_PREPARATION_PREFLIGHT_STATES = frozenset(
    {"DRAFT_ALLOWED", "READY_FOR_DRAFT"}
)

DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE = (
    "DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED"
)
DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_NEXT_ACTION = (
    "FUTURE_DRAFT_PREPARATION_STEP_REQUIRES_SEPARATE_COMMAND"
)

ORCHESTRATOR_PLANNING_DRAFT_SOURCE_ARTIFACT_TYPE = "ORCHESTRATOR_PLANNING_DRAFT_SOURCE"
ORCHESTRATOR_PLANNING_DRAFT_SOURCE_SCHEMA_VERSION = "0.1"

ORCHESTRATOR_PLANNING_DRAFT_SOURCE_NON_AUTHORITY_FLAGS = (
    "does_not_generate_architecture",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "generated_workspace_is_draft_only",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

ORCHESTRATOR_CONTEXT_TRANSPORT_ARTIFACT_TYPE = "ORCHESTRATOR_CONTEXT_TRANSPORT"
ORCHESTRATOR_CONTEXT_TRANSPORT_SCHEMA_VERSION = "0.1"

ORCHESTRATOR_CONTEXT_TRANSPORT_NON_AUTHORITY_FLAGS = (
    "does_not_generate_architecture",
    "does_not_choose_stack",
    "does_not_choose_database",
    "does_not_choose_networking",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "transported_context_is_source_material_only",
    "requires_future_architecture_decision",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_ARTIFACT_TYPE = (
    "ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE"
)
ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_SCHEMA_VERSION = "0.1"
CONTEXT_PACK_DRAFT_STATUS = "DRAFT_NON_AUTHORITY"

ORCHESTRATOR_CONTEXT_PACK_DRAFT_NON_AUTHORITY_FLAGS = (
    "does_not_generate_architecture",
    "does_not_choose_stack",
    "does_not_choose_database",
    "does_not_choose_networking",
    "does_not_generate_local_agentic_spec",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "context_pack_is_draft_only",
    "context_pack_is_source_context_only",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
    "requires_future_architecture_decision",
    "requires_future_local_agentic_spec",
    "requires_future_implementation_plan",
)

LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_STATE = (
    "LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_NO_SPEC_GENERATED"
)
LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_NEXT_ACTION = (
    "FUTURE_LOCAL_AGENTIC_SPEC_DRAFT_REQUIRES_SEPARATE_COMMAND"
)

LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_NON_AUTHORITY_FLAGS = (
    "does_not_generate_local_agentic_spec",
    "does_not_mutate_local_agentic_spec",
    "does_not_generate_architecture",
    "does_not_choose_stack",
    "does_not_choose_database",
    "does_not_choose_networking",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "preflight_is_read_only",
    "future_spec_draft_requires_separate_command",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE_ARTIFACT_TYPE = (
    "ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE"
)
ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE_SCHEMA_VERSION = "0.1"
LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS = "SCAFFOLD_DRAFT_NON_AUTHORITY"

ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_NON_AUTHORITY_FLAGS = (
    "does_not_extract_requirements",
    "does_not_infer_requirements",
    "does_not_generate_user_stories",
    "does_not_generate_acceptance_criteria",
    "does_not_generate_architecture",
    "does_not_choose_stack",
    "does_not_choose_database",
    "does_not_choose_networking",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "local_agentic_spec_is_scaffold_only",
    "future_requirements_extraction_requires_separate_command",
    "future_architecture_decision_requires_separate_command",
    "future_implementation_plan_requires_separate_command",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE = (
    "REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NO_REQUIREMENTS_GENERATED"
)
REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NEXT_ACTION = (
    "FUTURE_REQUIREMENTS_EXTRACTION_REQUIRES_SEPARATE_COMMAND"
)

ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_ARTIFACT_TYPE = (
    "ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE"
)
ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_SCHEMA_VERSION = "0.1"
REQUIREMENTS_EXTRACTION_SCAFFOLD_STATUS = (
    "REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY"
)

ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY_FLAGS = (
    "does_not_extract_requirements",
    "does_not_infer_requirements",
    "does_not_generate_requirements_content",
    "does_not_generate_user_stories",
    "does_not_generate_acceptance_criteria",
    "does_not_generate_architecture",
    "does_not_choose_stack",
    "does_not_choose_database",
    "does_not_choose_networking",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "requirements_extraction_scaffold_only",
    "future_requirements_extraction_requires_separate_command",
    "future_architecture_decision_requires_separate_command",
    "future_implementation_plan_requires_separate_command",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

REQUIREMENTS_EXTRACTION_PREFLIGHT_NON_AUTHORITY_FLAGS = (
    "does_not_extract_requirements",
    "does_not_infer_requirements",
    "does_not_generate_user_stories",
    "does_not_generate_acceptance_criteria",
    "does_not_mutate_local_agentic_spec",
    "does_not_generate_architecture",
    "does_not_choose_stack",
    "does_not_choose_database",
    "does_not_choose_networking",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "preflight_is_read_only",
    "future_requirements_extraction_requires_separate_command",
    "future_architecture_decision_requires_separate_command",
    "future_implementation_plan_requires_separate_command",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

REQUIREMENTS_EXTRACTION_OWNER_DECISION_ARTIFACT_TYPE = (
    "REQUIREMENTS_EXTRACTION_OWNER_DECISION"
)
REQUIREMENTS_EXTRACTION_OWNER_DECISION_SCHEMA_VERSION = "0.1"

REQUIREMENTS_EXTRACTION_OWNER_DECISION_VALUES = frozenset(
    {
        "REQUEST_MORE_CONTEXT",
        "BLOCK_REQUIREMENTS_EXTRACTION",
        "AUTHORIZE_REQUIREMENTS_EXTRACTION",
    }
)

REQUIREMENTS_EXTRACTION_OWNER_DECISION_REQUIRED_FIELDS = (
    "artifact_type",
    "schema_version",
    "intake_id",
    "plan_id",
    "decision_id",
    "decision",
    "owner_summary",
    "created_at",
    "source_requirements_extraction_scaffold_provenance_path",
    "source_requirements_extraction_scaffold_status",
    "source_requirements_extraction_scaffold_created_at",
    "source_requirements_extraction_preflight_state",
    "source_requirements_extraction_preflight_next_action",
    "planning_workspace_status_at_decision",
    "non_authority",
)

REQUIREMENTS_EXTRACTION_OWNER_DECISION_NON_AUTHORITY_FLAGS = (
    "does_not_extract_requirements",
    "does_not_infer_requirements",
    "does_not_generate_requirements_content",
    "does_not_generate_requirement_ids",
    "does_not_generate_user_stories",
    "does_not_generate_acceptance_criteria",
    "does_not_generate_architecture",
    "does_not_choose_stack",
    "does_not_choose_database",
    "does_not_choose_networking",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_requirements",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "owner_decision_only",
    "authorization_is_not_extraction",
    "future_requirements_extraction_requires_separate_command",
    "future_requirements_validation_requires_separate_command",
    "future_architecture_decision_requires_separate_command",
    "future_implementation_plan_requires_separate_command",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_STATE = (
    "REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_NO_EXTRACTION_PERFORMED"
)
REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_NEXT_ACTION = (
    "FUTURE_REQUIREMENTS_EXTRACTION_COMMAND_MAY_BE_RUN_SEPARATELY"
)

REQUIREMENTS_DRAFT_STATUS = "REQUIREMENTS_DRAFT_NON_AUTHORITY"
DRAFT_REQUIREMENT_CANDIDATE_STATUS = "DRAFT_REQUIREMENT_CANDIDATE_NON_AUTHORITY"
DRAFT_REQUIREMENT_SOURCE_BOUNDED_MARKER = "SOURCE_BOUNDED"

ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_ARTIFACT_TYPE = (
    "ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE"
)
ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_SCHEMA_VERSION = "0.1"

REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_STATE = (
    "REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_NO_VALIDATION_PERFORMED"
)
REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_NEXT_ACTION = (
    "FUTURE_REQUIREMENTS_VALIDATION_REQUIRES_SEPARATE_COMMAND"
)

REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_NON_AUTHORITY_FLAGS = (
    "does_not_validate_requirements",
    "does_not_approve_requirements",
    "does_not_rewrite_requirements_draft",
    "does_not_promote_requirements_draft",
    "does_not_normalize_requirements_draft",
    "does_not_mutate_requirements_draft",
    "does_not_generate_user_stories",
    "does_not_generate_acceptance_criteria",
    "does_not_generate_architecture",
    "does_not_choose_stack",
    "does_not_choose_database",
    "does_not_choose_networking",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "preflight_only",
    "validation_preflight_is_not_validation",
    "future_requirements_validation_requires_separate_command",
    "future_architecture_decision_requires_separate_command",
    "future_implementation_plan_requires_separate_command",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

REQUIREMENTS_VALIDATION_OWNER_DECISION_ARTIFACT_TYPE = (
    "REQUIREMENTS_VALIDATION_OWNER_DECISION"
)
REQUIREMENTS_VALIDATION_OWNER_DECISION_SCHEMA_VERSION = "0.1"
REQUIREMENTS_VALIDATION_OWNER_DECISION_SOURCE_COMMAND = (
    "agent-os orchestrator decide-requirements-validation"
)
REQUIREMENTS_VALIDATION_OWNER_DECISION_RECORDED_STATE = (
    "REQUIREMENTS_VALIDATION_OWNER_DECISION_RECORDED_NO_VALIDATION_PERFORMED"
)
REQUIREMENTS_VALIDATION_AUTHORIZE_NEXT_ACTION = (
    "FUTURE_REQUIREMENTS_VALIDATION_EXECUTION_CHECK_REQUIRES_SEPARATE_COMMAND"
)
REQUIREMENTS_VALIDATION_REQUEST_NEXT_ACTION = (
    "FUTURE_REQUIREMENTS_DRAFT_REVISION_REQUIRES_SEPARATE_ACTION"
)
REQUIREMENTS_VALIDATION_BLOCK_NEXT_ACTION = (
    "REQUIREMENTS_VALIDATION_BLOCKED_BY_OWNER_DECISION"
)
REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_STATE = (
    "REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_NOT_REQUIRED_FOR_OWNER_DECISION"
)
REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_NEXT_ACTION = (
    "NO_FUTURE_REQUIREMENTS_VALIDATION_AUTHORIZED_BY_THIS_DECISION"
)

REQUIREMENTS_VALIDATION_OWNER_DECISION_VALUES = frozenset(
    {
        "REQUEST_REQUIREMENTS_DRAFT_REVISION",
        "BLOCK_REQUIREMENTS_VALIDATION",
        "AUTHORIZE_REQUIREMENTS_VALIDATION",
    }
)

REQUIREMENTS_VALIDATION_OWNER_DECISION_REQUIRED_FIELDS = (
    "artifact_type",
    "schema_version",
    "intake_id",
    "plan_id",
    "decision_id",
    "decision",
    "owner_summary",
    "created_at",
    "source_command",
    "status",
    "next_required_action",
    "source_requirements_draft_validation_preflight_state",
    "source_requirements_draft_validation_preflight_next_action",
    "source_requirements_draft_provenance_path",
    "source_requirements_draft_status",
    "source_requirements_draft_created_at",
    "planning_workspace_status_at_decision",
    "non_authority",
)

REQUIREMENTS_VALIDATION_OWNER_DECISION_NON_AUTHORITY_FLAGS = (
    "owner_decision_is_not_validation",
    "authorizes_future_validation_only_when_decision_is_authorize",
    "does_not_validate_requirements",
    "does_not_approve_requirements",
    "does_not_promote_draft_requirements",
    "does_not_generate_architecture",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "owner_decision_only",
    "authorization_is_not_validation",
    "authorization_is_not_approval",
    "future_requirements_validation_requires_separate_command",
    "future_architecture_decision_requires_separate_command",
    "future_implementation_plan_requires_separate_command",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

REQUIREMENTS_VALIDATION_EXECUTION_CHECK_CONFIRMED_STATE = (
    "REQUIREMENTS_VALIDATION_EXECUTION_CHECK_CONFIRMED_NO_VALIDATION_PERFORMED"
)
REQUIREMENTS_VALIDATION_EXECUTION_CHECK_CONFIRMED_NEXT_ACTION = (
    "FUTURE_REQUIREMENTS_VALIDATION_COMMAND_MAY_BE_RUN_SEPARATELY"
)

REQUIREMENTS_VALIDATION_EXECUTION_CHECK_NON_AUTHORITY_FLAGS = (
    "execution_check_is_not_validation",
    "owner_authorization_is_not_validation",
    "owner_authorization_is_not_approval",
    "does_not_validate_requirements",
    "does_not_approve_requirements",
    "does_not_promote_draft_requirements",
    "does_not_generate_architecture",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "does_not_write_artifacts",
    "pre_execution_check_only",
    "latest_owner_authorization_required",
    "future_requirements_validation_requires_separate_command",
    "future_architecture_decision_requires_separate_command",
    "future_implementation_plan_requires_separate_command",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

REQUIREMENTS_DRAFT_NON_AUTHORITY_FLAGS = (
    "requirements_are_draft",
    "requirements_are_not_approved",
    "requirements_are_not_validated",
    "requirements_are_source_bounded_candidates",
    "does_not_generate_user_stories",
    "does_not_generate_acceptance_criteria",
    "does_not_generate_architecture",
    "does_not_choose_stack",
    "does_not_choose_database",
    "does_not_choose_networking",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_requirements",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "future_requirements_validation_requires_separate_command",
    "future_architecture_decision_requires_separate_command",
    "future_implementation_plan_requires_separate_command",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_NON_AUTHORITY_FLAGS = (
    "does_not_extract_requirements",
    "does_not_infer_requirements",
    "does_not_generate_requirements_content",
    "does_not_generate_requirement_ids",
    "does_not_generate_user_stories",
    "does_not_generate_acceptance_criteria",
    "does_not_generate_architecture",
    "does_not_choose_stack",
    "does_not_choose_database",
    "does_not_choose_networking",
    "does_not_generate_implementation_plan",
    "does_not_generate_planning_run_slice",
    "does_not_validate_planning_workspace",
    "does_not_approve_requirements",
    "does_not_approve_plan",
    "does_not_transition_workspace",
    "does_not_create_runner_proposal",
    "does_not_create_run",
    "does_not_invoke_executor",
    "pre_execution_check_only",
    "authorization_check_is_not_extraction",
    "latest_owner_authorization_required",
    "future_requirements_extraction_requires_separate_command",
    "future_requirements_validation_requires_separate_command",
    "future_architecture_decision_requires_separate_command",
    "future_implementation_plan_requires_separate_command",
    "requires_future_independent_validation",
    "requires_future_owner_approval",
)

REQUIREMENTS_EXTRACTION_SCAFFOLD_REQUIRED_BOUNDARY_CHECKS: tuple[tuple[str, ...], ...] = (
    ("requirements extraction", "not performed"),
    ("architecture", "undecided"),
    ("implementation plan", "not generated"),
    ("planning_run_slice", "not generated"),
    ("not validated or approved",),
    ("runner", "not created or invoked"),
)

_IMPLEMENTATION_TASK_HEADING_PATTERN = re.compile(
    r"^##\s+Implementation Tasks\s*$",
    re.MULTILINE | re.IGNORECASE,
)
_PLANNING_RUN_SLICE_HEADING_PATTERN = re.compile(
    r"^##\s+PLANNING_RUN_SLICE\s*$",
    re.MULTILINE,
)

LOCAL_AGENTIC_SPEC_SCAFFOLD_REQUIRED_BOUNDARY_CHECKS: tuple[tuple[str, ...], ...] = (
    ("requirements extraction", "not performed"),
    ("architecture", "undecided"),
    ("implementation plan", "not generated"),
    ("planning_run_slice", "not generated"),
    ("not validated or approved",),
    ("runner", "not created or invoked"),
)

_FUNCTIONAL_REQUIREMENT_PATTERN = re.compile(r"\bthe system shall\b", re.IGNORECASE)
_FUNCTIONAL_REQUIREMENT_ID_PATTERN = re.compile(r"\bFR-\d+\b", re.IGNORECASE)
_NON_FUNCTIONAL_REQUIREMENT_ID_PATTERN = re.compile(r"\bNFR-\d+\b", re.IGNORECASE)
_REQUIREMENT_ID_PATTERN = re.compile(r"\bREQ-\d+\b", re.IGNORECASE)
_PROMOTED_REQUIREMENT_ID_PATTERN = re.compile(r"(?<!DRAFT-)REQ-\d+\b", re.IGNORECASE)
_DRAFT_REQUIREMENT_ID_PATTERN = re.compile(r"\bDRAFT-REQ-\d+\b", re.IGNORECASE)
_DRAFT_REQUIREMENT_HEADING_PATTERN = re.compile(
    r"^### (DRAFT-REQ-\d{3})\s*$",
    re.MULTILINE,
)
_REQUIREMENTS_DRAFT_CANDIDATES_HEADING = "## Draft requirement candidates"
_CANDIDATE_BACKTICK_FIELD_PATTERN = re.compile(
    r"- \*\*(?P<field>[a-z_]+):\*\* `(?P<value>[^`]+)`"
)
_CANDIDATE_TEXT_LINE_PATTERN = re.compile(
    r"- \*\*candidate_text:\*\* (?P<value>.+)"
)
_CANDIDATE_SOURCE_QUOTE_LINE_PATTERN = re.compile(
    r"- \*\*source_quote_or_reference:\*\* (?P<value>.+)"
)
_INFERRED_SLITHER_FEATURE_TERMS = (
    "websocket",
    "leaderboard",
    "accounts",
    "physics",
    "deployment",
    "rendering engine",
    "database",
    "realtime multiplayer",
    "multiplayer",
)
_USER_STORY_PATTERN = re.compile(r"\bas a user\b", re.IGNORECASE)
_USER_STORIES_HEADING_PATTERN = re.compile(r"^##\s+User Stories\s*$", re.MULTILINE)
_ACCEPTANCE_CRITERIA_GWT_PATTERN = re.compile(
    r"\bGiven\b.+\bWhen\b.+\bThen\b",
    re.IGNORECASE | re.DOTALL,
)
_ACCEPTANCE_CRITERIA_ID_PATTERN = re.compile(r"\bAC-\d+\b", re.IGNORECASE)
_ARCHITECTURE_DECISION_PATTERN = re.compile(
    r"\b(selected|recommended|chosen)\s+(backend|frontend|database|architecture)\b",
    re.IGNORECASE,
)
_STACK_CHOICE_PATTERN = re.compile(
    r"\b(backend|frontend|database|deployment):\s*(?!undecided|not\b)[a-z0-9]",
    re.IGNORECASE,
)

CONTEXT_PACK_REQUIRED_BOUNDARY_CHECKS: tuple[tuple[str, ...], ...] = (
    ("architecture", "undecided"),
    ("local agentic spec", "not generated"),
    ("implementation plan", "not generated"),
    ("planning_run_slice", "not generated"),
    ("not validated or approved",),
    ("runner", "not created or invoked"),
)

GOAL_INTAKE_REQUIRED_STRING_FIELDS = (
    "artifact_type",
    "schema_version",
    "intake_id",
    "raw_goal",
    "normalized_goal",
    "user_visible_summary",
    "created_at",
)

GOAL_INTAKE_REQUIRED_LIST_FIELDS = (
    "explicit_constraints",
    "inferred_assumptions",
    "open_questions",
    "non_goals",
    "risk_flags",
)

_BUILD_VERB_PATTERN = re.compile(r"\b(build|create|make|develop|implement|design)\b")
_BROAD_PRODUCT_PATTERN = re.compile(
    r"\b(game|app|application|platform|website|web\s+app|service|product)\b"
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def validate_intake_id(intake_id: str) -> None:
    """Reject unsafe or invalid intake identifiers."""
    if not intake_id:
        raise ValueError("intake id must not be empty")
    if intake_id != intake_id.strip():
        raise ValueError("intake id must not contain leading or trailing whitespace")
    if " " in intake_id:
        raise ValueError(f"invalid intake id: {intake_id!r}")
    if "/" in intake_id or "\\" in intake_id or ".." in intake_id:
        raise ValueError(f"invalid intake id: {intake_id!r}")
    if intake_id.startswith(".") or any(
        part.startswith(".") for part in re.split(r"[\\/]", intake_id)
    ):
        raise ValueError(f"invalid intake id: {intake_id!r}")
    if Path(intake_id).is_absolute():
        raise ValueError(f"invalid intake id: {intake_id!r}")
    if not INTAKE_ID_PATTERN.match(intake_id):
        raise ValueError(f"invalid intake id: {intake_id!r}")


def validate_readiness_decision_id(decision_id: str) -> None:
    """Reject unsafe or invalid readiness decision identifiers."""
    if not decision_id:
        raise ValueError("decision id must not be empty")
    if decision_id != decision_id.strip():
        raise ValueError(
            "decision id must not contain leading or trailing whitespace"
        )
    if " " in decision_id:
        raise ValueError(f"invalid decision id: {decision_id!r}")
    if "/" in decision_id or "\\" in decision_id or ".." in decision_id:
        raise ValueError(f"invalid decision id: {decision_id!r}")
    if decision_id.startswith(".") or any(
        part.startswith(".") for part in re.split(r"[\\/]", decision_id)
    ):
        raise ValueError(f"invalid decision id: {decision_id!r}")
    if Path(decision_id).is_absolute():
        raise ValueError(f"invalid decision id: {decision_id!r}")
    if not READINESS_DECISION_ID_PATTERN.match(decision_id):
        raise ValueError(f"invalid decision id: {decision_id!r}")


def validate_requirements_extraction_decision_id(decision_id: str) -> None:
    """Reject unsafe or invalid requirements-extraction decision identifiers."""
    validate_readiness_decision_id(decision_id)


def validate_requirements_validation_decision_id(decision_id: str) -> None:
    """Reject unsafe or invalid requirements-validation decision identifiers."""
    validate_readiness_decision_id(decision_id)


def validate_clarification_id(clarification_id: str) -> None:
    """Reject unsafe or invalid clarification identifiers."""
    if not clarification_id:
        raise ValueError("clarification id must not be empty")
    if clarification_id != clarification_id.strip():
        raise ValueError(
            "clarification id must not contain leading or trailing whitespace"
        )
    if " " in clarification_id:
        raise ValueError(f"invalid clarification id: {clarification_id!r}")
    if "/" in clarification_id or "\\" in clarification_id or ".." in clarification_id:
        raise ValueError(f"invalid clarification id: {clarification_id!r}")
    if clarification_id.startswith(".") or any(
        part.startswith(".") for part in re.split(r"[\\/]", clarification_id)
    ):
        raise ValueError(f"invalid clarification id: {clarification_id!r}")
    if Path(clarification_id).is_absolute():
        raise ValueError(f"invalid clarification id: {clarification_id!r}")
    if not CLARIFICATION_ID_PATTERN.match(clarification_id):
        raise ValueError(f"invalid clarification id: {clarification_id!r}")


def normalize_goal(raw_goal: str) -> str:
    """Collapse whitespace only; do not semantically rewrite the goal."""
    return re.sub(r"\s+", " ", raw_goal).strip()


def _is_broad_product_build_goal(normalized_goal: str) -> bool:
    lowered = normalized_goal.lower()
    if "slither.io" in lowered or "slither-like" in lowered:
        return True
    return bool(_BUILD_VERB_PATTERN.search(lowered) and _BROAD_PRODUCT_PATTERN.search(lowered))


def build_goal_intake_artifact(
    intake_id: str,
    raw_goal: str,
    *,
    created_at: str | None = None,
) -> dict:
    """Build the deterministic GOAL_INTAKE artifact payload."""
    validate_intake_id(intake_id)
    if not raw_goal or not raw_goal.strip():
        raise ValueError("goal must not be empty or whitespace-only")

    normalized_goal = normalize_goal(raw_goal)
    high_ambiguity = _is_broad_product_build_goal(normalized_goal)
    ambiguity_level = "HIGH" if high_ambiguity else "MEDIUM"
    planning_readiness = "REQUIRES_CLARIFICATION" if high_ambiguity else "NOT_READY"
    risk_flags = []
    if high_ambiguity:
        risk_flags.append(
            {
                "risk": "broad_product_goal_without_scope_boundaries",
                "basis": "deterministic keyword guard matched broad build/product language",
                "mitigation_planning_only": "Clarify scope before drafting planning artifacts",
            }
        )

    return {
        "artifact_type": "GOAL_INTAKE",
        "schema_version": "0.1",
        "intake_id": intake_id,
        "raw_goal": raw_goal,
        "normalized_goal": normalized_goal,
        "user_visible_summary": normalized_goal,
        "explicit_constraints": [],
        "inferred_assumptions": [],
        "open_questions": [
            {
                "question": "What concrete scope, constraints, and success criteria should constrain planning?",
                "impact": "Prevents treating goal intake as an approved plan.",
                "suggested_owner_action": "Clarify before any planning draft or run proposal is created.",
                "blocks_first_slice": True,
            }
        ],
        "non_goals": [],
        "risk_flags": risk_flags,
        "ambiguity_level": ambiguity_level,
        "planning_readiness": planning_readiness,
        "created_at": created_at or _utc_now(),
        "non_authority": {key: True for key in GOAL_INTAKE_NON_AUTHORITY_FLAGS},
    }


def _goal_intake_artifact_path(project: Path, intake_id: str) -> Path:
    return orchestrator_intake_path(project, intake_id) / GOAL_INTAKE_FILE


def _require_valid_goal_intake(project: Path, intake_id: str) -> tuple[Path, dict]:
    """Load a GOAL_INTAKE artifact and fail closed when structurally invalid."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = _goal_intake_artifact_path(project, intake_id)
    if not path.is_file():
        raise FileNotFoundError(f"goal intake artifact not found: {intake_id}")

    raw_text = path.read_text(encoding="utf-8")
    try:
        artifact = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid goal-intake.json for intake {intake_id}: {exc.msg}"
        ) from exc

    errors = _validate_goal_intake_payload(artifact, intake_id, raw_text=raw_text)
    if errors:
        raise ValueError(
            f"invalid goal intake artifact for {intake_id}: " + "; ".join(errors)
        )

    if not isinstance(artifact, dict):
        raise ValueError(
            f"invalid goal-intake.json for intake {intake_id}: expected object"
        )

    return path, artifact


def _parse_created_at(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def _non_empty_string(value: object, field_name: str) -> str | None:
    if not isinstance(value, str):
        return f"{field_name} must be a non-empty string"
    if not value.strip():
        return f"{field_name} must be a non-empty string"
    return None


def _validate_goal_intake_payload(
    artifact: object,
    intake_id: str,
    *,
    raw_text: str | None = None,
) -> list[str]:
    """Return structural validation errors for a loaded GOAL_INTAKE payload."""
    errors: list[str] = []

    if not isinstance(artifact, dict):
        return ["goal intake artifact must be a JSON object"]

    for field in GOAL_INTAKE_REQUIRED_FIELDS:
        if field not in artifact:
            errors.append(f"missing required field: {field}")

    for field in GOAL_INTAKE_REQUIRED_STRING_FIELDS:
        if field in artifact:
            error = _non_empty_string(artifact[field], field)
            if error:
                errors.append(error)

    for field in GOAL_INTAKE_REQUIRED_LIST_FIELDS:
        if field in artifact and not isinstance(artifact[field], list):
            errors.append(f"{field} must be a list")

    artifact_type = artifact.get("artifact_type")
    if artifact_type is not None and artifact_type != GOAL_INTAKE_ARTIFACT_TYPE:
        errors.append(
            f"wrong artifact_type: expected {GOAL_INTAKE_ARTIFACT_TYPE!r}, "
            f"found {artifact_type!r}"
        )

    schema_version = artifact.get("schema_version")
    if schema_version is not None and schema_version != GOAL_INTAKE_SCHEMA_VERSION:
        errors.append(
            f"unsupported schema_version: expected {GOAL_INTAKE_SCHEMA_VERSION!r}, "
            f"found {schema_version!r}"
        )

    artifact_intake_id = artifact.get("intake_id")
    if isinstance(artifact_intake_id, str) and artifact_intake_id != intake_id:
        errors.append(
            "intake_id mismatch: "
            f"path {intake_id!r}, artifact {artifact_intake_id!r}"
        )

    created_at = artifact.get("created_at")
    if created_at is not None and not _parse_created_at(created_at):
        errors.append("created_at must be a parseable ISO-8601 timestamp")

    non_authority = artifact.get("non_authority")
    if non_authority is None:
        errors.append("missing required field: non_authority")
    elif not isinstance(non_authority, dict):
        errors.append("non_authority must be an object")
    else:
        for flag in GOAL_INTAKE_NON_AUTHORITY_FLAGS:
            if flag not in non_authority:
                errors.append(f"missing non_authority flag: {flag}")
            elif non_authority[flag] is not True:
                errors.append(f"non_authority flag must be true: {flag}")

    ambiguity_level = artifact.get("ambiguity_level")
    if ambiguity_level is not None and ambiguity_level not in GOAL_INTAKE_AMBIGUITY_LEVELS:
        errors.append(f"invalid ambiguity_level: {ambiguity_level!r}")

    planning_readiness = artifact.get("planning_readiness")
    if (
        planning_readiness is not None
        and planning_readiness not in GOAL_INTAKE_PLANNING_READINESS
    ):
        errors.append(f"invalid planning_readiness: {planning_readiness!r}")

    if ambiguity_level == "HIGH":
        if planning_readiness == "DRAFT_ALLOWED":
            errors.append(
                "incoherent readiness: HIGH ambiguity must not be DRAFT_ALLOWED"
            )
        elif planning_readiness != "REQUIRES_CLARIFICATION":
            errors.append(
                "incoherent readiness: HIGH ambiguity should be REQUIRES_CLARIFICATION"
            )

    content = raw_text if raw_text is not None else json.dumps(artifact)
    if "PLANNING_RUN_SLICE" in content:
        errors.append("goal intake content must not contain PLANNING_RUN_SLICE")

    return errors


def load_goal_intake(project: Path, intake_id: str) -> dict:
    """Load a GOAL_INTAKE artifact from disk (read-only)."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = _goal_intake_artifact_path(project, intake_id)
    if not path.is_file():
        raise FileNotFoundError(f"goal intake artifact not found: {intake_id}")

    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid goal-intake.json for intake {intake_id}: {exc.msg}"
        ) from exc

    if not isinstance(artifact, dict):
        raise ValueError(
            f"invalid goal-intake.json for intake {intake_id}: expected object"
        )

    return artifact


@dataclass(frozen=True)
class GoalIntakeValidationReport:
    output: str
    valid: bool
    errors: tuple[str, ...]


@dataclass(frozen=True)
class GoalIntakeStatusReport:
    output: str
    validation_ok: bool


def _format_goal_intake_validation(
    path: Path,
    intake_id: str,
    errors: list[str],
) -> str:
    lines = [
        f"goal intake artifact: {path}",
        f"intake_id: {intake_id}",
        f"structural validation: {'OK' if not errors else 'INVALID'}",
    ]
    for error in errors:
        lines.append(f"  - {error}")
    lines.append(f"final validation result: {'OK' if not errors else 'INVALID'}")
    if not errors:
        lines.append(
            "note: validation is not approval, not planning generation, "
            "and no files were modified"
        )
    return "\n".join(lines)


def validate_goal_intake(project: Path, intake_id: str) -> GoalIntakeValidationReport:
    """Strict read-only structural validation of a GOAL_INTAKE artifact."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = _goal_intake_artifact_path(project, intake_id)
    if not path.is_file():
        raise FileNotFoundError(f"goal intake artifact not found: {intake_id}")

    raw_text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    try:
        artifact = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        errors = [f"malformed JSON: {exc.msg}"]
    else:
        errors = _validate_goal_intake_payload(artifact, intake_id, raw_text=raw_text)

    output = _format_goal_intake_validation(path, intake_id, errors)
    return GoalIntakeValidationReport(output, not errors, tuple(errors))


def _format_goal_intake_status(
    path: Path,
    artifact: dict,
    validation_errors: list[str],
    clarifications: tuple[OwnerClarificationRecord, ...] = (),
    readiness_decisions: tuple[OwnerReadinessDecisionRecord, ...] = (),
) -> str:
    goal_text = artifact.get("normalized_goal") or artifact.get("raw_goal") or "?"
    open_questions = artifact.get("open_questions")
    risk_flags = artifact.get("risk_flags")
    open_count = len(open_questions) if isinstance(open_questions, list) else "?"
    risk_count = len(risk_flags) if isinstance(risk_flags, list) else "?"

    lines = [
        f"goal intake artifact: {path}",
        f"intake_id: {artifact.get('intake_id', '?')}",
        f"artifact_type: {artifact.get('artifact_type', '?')}",
        f"schema_version: {artifact.get('schema_version', '?')}",
        f"goal: {goal_text}",
        f"ambiguity_level: {artifact.get('ambiguity_level', '?')}",
        f"planning_readiness: {artifact.get('planning_readiness', '?')}",
        f"open_questions: {open_count}",
        f"risk_flags: {risk_count}",
        f"owner_clarifications: {len(clarifications)}",
    ]
    if clarifications:
        latest = clarifications[-1]
        lines.append(f"latest_clarification_id: {latest.clarification_id}")
        lines.append(f"latest_clarification_created_at: {latest.created_at}")
    lines.append(f"owner_readiness_decisions: {len(readiness_decisions)}")
    if readiness_decisions:
        latest_decision = readiness_decisions[-1]
        lines.append(f"latest_readiness_decision_id: {latest_decision.decision_id}")
        lines.append(f"latest_readiness_decision: {latest_decision.decision}")
    lines.append(f"validation: {'OK' if not validation_errors else 'INVALID'}")
    for error in validation_errors:
        lines.append(f"  - {error}")
    lines.append("next step: no planning draft was created")
    lines.append(
        "note: owner clarifications are additive context only; "
        "they do not create a planning draft and do not change planning_readiness"
    )
    lines.append(
        "note: owner readiness decisions are owner-provided records only; "
        "they do not generate a planning draft"
    )
    lines.append(
        "note: read-only inspection; validation is not approval or planning generation"
    )
    return "\n".join(lines)


def goal_intake_status(project: Path, intake_id: str) -> GoalIntakeStatusReport:
    """Inspect an existing GOAL_INTAKE artifact (read-only)."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = _goal_intake_artifact_path(project, intake_id)
    if not path.is_file():
        raise FileNotFoundError(f"goal intake artifact not found: {intake_id}")

    raw_text = path.read_text(encoding="utf-8")
    try:
        artifact = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid goal-intake.json for intake {intake_id}: {exc.msg}"
        ) from exc

    if not isinstance(artifact, dict):
        raise ValueError(
            f"invalid goal-intake.json for intake {intake_id}: expected object"
        )

    validation_errors = _validate_goal_intake_payload(
        artifact,
        intake_id,
        raw_text=raw_text,
    )
    clarifications = list_owner_clarifications(project, intake_id)
    readiness_decisions = list_owner_readiness_decisions(project, intake_id)
    output = _format_goal_intake_status(
        path,
        artifact,
        validation_errors,
        clarifications,
        readiness_decisions,
    )
    return GoalIntakeStatusReport(output, not validation_errors)


@dataclass(frozen=True)
class OwnerClarificationRecord:
    clarification_id: str
    created_at: str
    path: Path


@dataclass(frozen=True)
class OwnerClarificationValidationReport:
    output: str
    valid: bool
    errors: tuple[str, ...]


def build_owner_clarification_artifact(
    intake_id: str,
    clarification_id: str,
    owner_answer: str,
    *,
    created_at: str | None = None,
) -> dict:
    """Build the deterministic OWNER_CLARIFICATION artifact payload."""
    validate_intake_id(intake_id)
    validate_clarification_id(clarification_id)
    if not owner_answer or not owner_answer.strip():
        raise ValueError("clarification answer must not be empty or whitespace-only")

    return {
        "artifact_type": OWNER_CLARIFICATION_ARTIFACT_TYPE,
        "schema_version": OWNER_CLARIFICATION_SCHEMA_VERSION,
        "intake_id": intake_id,
        "clarification_id": clarification_id,
        "owner_answer": owner_answer,
        "applies_to_open_questions": [],
        "explicit_constraints_added": [],
        "non_goals_added": [],
        "risk_notes": [],
        "created_at": created_at or _utc_now(),
        "non_authority": {
            key: True for key in OWNER_CLARIFICATION_NON_AUTHORITY_FLAGS
        },
    }


def _validate_owner_clarification_payload(
    artifact: object,
    intake_id: str,
    clarification_id: str,
) -> list[str]:
    """Return structural validation errors for a loaded OWNER_CLARIFICATION payload."""
    errors: list[str] = []

    if not isinstance(artifact, dict):
        return ["owner clarification artifact must be a JSON object"]

    for field in OWNER_CLARIFICATION_REQUIRED_FIELDS:
        if field not in artifact:
            errors.append(f"missing required field: {field}")

    artifact_type = artifact.get("artifact_type")
    if artifact_type is not None and artifact_type != OWNER_CLARIFICATION_ARTIFACT_TYPE:
        errors.append(
            f"wrong artifact_type: expected {OWNER_CLARIFICATION_ARTIFACT_TYPE!r}, "
            f"found {artifact_type!r}"
        )

    schema_version = artifact.get("schema_version")
    if schema_version is not None and schema_version != OWNER_CLARIFICATION_SCHEMA_VERSION:
        errors.append(
            f"unsupported schema_version: expected "
            f"{OWNER_CLARIFICATION_SCHEMA_VERSION!r}, found {schema_version!r}"
        )

    artifact_intake_id = artifact.get("intake_id")
    if isinstance(artifact_intake_id, str) and artifact_intake_id != intake_id:
        errors.append(
            "intake_id mismatch: "
            f"path {intake_id!r}, artifact {artifact_intake_id!r}"
        )

    artifact_clarification_id = artifact.get("clarification_id")
    if (
        isinstance(artifact_clarification_id, str)
        and artifact_clarification_id != clarification_id
    ):
        errors.append(
            "clarification_id mismatch: "
            f"path {clarification_id!r}, artifact {artifact_clarification_id!r}"
        )

    owner_answer = artifact.get("owner_answer")
    if owner_answer is not None:
        error = _non_empty_string(owner_answer, "owner_answer")
        if error:
            errors.append(error)

    for field in (
        "applies_to_open_questions",
        "explicit_constraints_added",
        "non_goals_added",
        "risk_notes",
    ):
        if field in artifact and not isinstance(artifact[field], list):
            errors.append(f"{field} must be a list")

    created_at = artifact.get("created_at")
    if created_at is not None and not _parse_created_at(created_at):
        errors.append("created_at must be a parseable ISO-8601 timestamp")

    non_authority = artifact.get("non_authority")
    if non_authority is None:
        errors.append("missing required field: non_authority")
    elif not isinstance(non_authority, dict):
        errors.append("non_authority must be an object")
    else:
        for flag in OWNER_CLARIFICATION_NON_AUTHORITY_FLAGS:
            if flag not in non_authority:
                errors.append(f"missing non_authority flag: {flag}")
            elif non_authority[flag] is not True:
                errors.append(f"non_authority flag must be true: {flag}")

    return errors


def create_owner_clarification(
    project: Path,
    intake_id: str,
    clarification_id: str,
    owner_answer: str,
) -> Path:
    """Create an OWNER_CLARIFICATION artifact without modifying goal-intake.json."""
    artifact = build_owner_clarification_artifact(
        intake_id,
        clarification_id,
        owner_answer,
    )
    _require_valid_goal_intake(project, intake_id)

    dest = orchestrator_clarification_path(project, intake_id, clarification_id)
    if dest.exists():
        raise FileExistsError(
            f"owner clarification artifact already exists: {clarification_id}"
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_json(dest, artifact)
    return dest


def load_owner_clarification(
    project: Path,
    intake_id: str,
    clarification_id: str,
) -> dict:
    """Load an OWNER_CLARIFICATION artifact from disk (read-only)."""
    validate_intake_id(intake_id)
    validate_clarification_id(clarification_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = orchestrator_clarification_path(project, intake_id, clarification_id)
    if not path.is_file():
        raise FileNotFoundError(
            f"owner clarification artifact not found: {clarification_id}"
        )

    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid clarification artifact for {clarification_id}: {exc.msg}"
        ) from exc

    if not isinstance(artifact, dict):
        raise ValueError(
            f"invalid clarification artifact for {clarification_id}: expected object"
        )

    return artifact


def list_owner_clarifications(
    project: Path,
    intake_id: str,
) -> tuple[OwnerClarificationRecord, ...]:
    """List owner clarification records for an intake (read-only)."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    clarifications_dir = orchestrator_intake_path(project, intake_id) / CLARIFICATIONS_DIR
    if not clarifications_dir.is_dir():
        return ()

    records: list[OwnerClarificationRecord] = []
    for path in sorted(clarifications_dir.glob("*.json")):
        clarification_id = path.stem
        try:
            artifact = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(artifact, dict):
            continue
        created_at = artifact.get("created_at")
        if not isinstance(created_at, str):
            created_at = ""
        records.append(
            OwnerClarificationRecord(
                clarification_id=clarification_id,
                created_at=created_at,
                path=path,
            )
        )

    records.sort(key=lambda record: (record.created_at, record.clarification_id))
    return tuple(records)


def validate_owner_clarification(
    project: Path,
    intake_id: str,
    clarification_id: str,
) -> OwnerClarificationValidationReport:
    """Strict read-only structural validation of an OWNER_CLARIFICATION artifact."""
    validate_intake_id(intake_id)
    validate_clarification_id(clarification_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = orchestrator_clarification_path(project, intake_id, clarification_id)
    if not path.is_file():
        raise FileNotFoundError(
            f"owner clarification artifact not found: {clarification_id}"
        )

    raw_text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    try:
        artifact = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        errors = [f"malformed JSON: {exc.msg}"]
    else:
        errors = _validate_owner_clarification_payload(
            artifact,
            intake_id,
            clarification_id,
        )

    lines = [
        f"owner clarification artifact: {path}",
        f"intake_id: {intake_id}",
        f"clarification_id: {clarification_id}",
        f"structural validation: {'OK' if not errors else 'INVALID'}",
    ]
    for error in errors:
        lines.append(f"  - {error}")
    lines.append(f"final validation result: {'OK' if not errors else 'INVALID'}")
    if not errors:
        lines.append(
            "note: clarification is owner-provided context only; "
            "not approval, not planning generation, and goal-intake.json was not modified"
        )

    output = "\n".join(lines)
    return OwnerClarificationValidationReport(output, not errors, tuple(errors))


def _validate_clarifications_for_readiness(
    project: Path,
    intake_id: str,
) -> tuple[tuple[OwnerClarificationRecord, ...], list[str]]:
    """Validate clarification artifacts for readiness review (read-only)."""
    clarifications_dir = orchestrator_intake_path(project, intake_id) / CLARIFICATIONS_DIR
    if not clarifications_dir.is_dir():
        return (), []

    records: list[OwnerClarificationRecord] = []
    errors: list[str] = []

    for path in sorted(clarifications_dir.glob("*.json")):
        clarification_id = path.stem
        raw_text = path.read_text(encoding="utf-8")
        try:
            artifact = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            errors.append(
                f"invalid clarification artifact {clarification_id}: malformed JSON: {exc.msg}"
            )
            continue

        payload_errors = _validate_owner_clarification_payload(
            artifact,
            intake_id,
            clarification_id,
        )
        if payload_errors:
            for error in payload_errors:
                errors.append(
                    f"invalid clarification artifact {clarification_id}: {error}"
                )
            continue

        created_at = artifact.get("created_at") if isinstance(artifact, dict) else ""
        if not isinstance(created_at, str):
            created_at = ""
        records.append(
            OwnerClarificationRecord(
                clarification_id=clarification_id,
                created_at=created_at,
                path=path,
            )
        )

    records.sort(key=lambda record: (record.created_at, record.clarification_id))
    return tuple(records), errors


def _determine_readiness_review(
    *,
    validation_errors: list[str],
    artifact: dict | None,
    clarifications: tuple[OwnerClarificationRecord, ...],
    clarification_errors: list[str],
) -> tuple[str, str, list[str]]:
    """Return readiness_review_state, next_required_action, blocking_reasons."""
    blocking: list[str] = list(validation_errors)
    if validation_errors:
        return "BLOCKED_INVALID_INTAKE", "FIX_GOAL_INTAKE_STRUCTURE", blocking

    blocking.extend(clarification_errors)
    if clarification_errors:
        return "BLOCKED_INVALID_INTAKE", "FIX_CLARIFICATION_STRUCTURE", blocking

    if artifact is None:
        return "BLOCKED_INVALID_INTAKE", "FIX_GOAL_INTAKE_STRUCTURE", blocking

    ambiguity_level = artifact.get("ambiguity_level")
    planning_readiness = artifact.get("planning_readiness")
    clarification_count = len(clarifications)

    if (
        ambiguity_level == "HIGH"
        and planning_readiness == "REQUIRES_CLARIFICATION"
    ):
        if clarification_count == 0:
            return "BLOCKED_REQUIRES_CLARIFICATION", "ADD_OWNER_CLARIFICATION", blocking
        return (
            "OWNER_CLARIFICATION_PRESENT_REVIEW_REQUIRED",
            "OWNER_READINESS_DECISION_REQUIRED",
            blocking,
        )

    return "OWNER_REVIEW_REQUIRED", "OWNER_READINESS_DECISION_REQUIRED", blocking


def _format_goal_intake_readiness(
    path: Path,
    intake_id: str,
    *,
    goal_intake_valid: bool,
    artifact: dict | None,
    clarifications: tuple[OwnerClarificationRecord, ...],
    readiness_decisions: tuple[OwnerReadinessDecisionRecord, ...],
    readiness_review_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
) -> str:
    ambiguity_level = (
        artifact.get("ambiguity_level", "?") if artifact is not None else "?"
    )
    planning_readiness = (
        artifact.get("planning_readiness", "?") if artifact is not None else "?"
    )
    latest_clarification_id = (
        clarifications[-1].clarification_id if clarifications else None
    )

    lines = [
        f"goal intake readiness review: {path}",
        f"intake_id: {intake_id}",
        f"goal_intake_valid: {'yes' if goal_intake_valid else 'no'}",
        f"ambiguity_level: {ambiguity_level}",
        f"planning_readiness: {planning_readiness}",
        f"owner_clarification_count: {len(clarifications)}",
    ]
    if latest_clarification_id is not None:
        lines.append(f"latest_clarification_id: {latest_clarification_id}")
    lines.append(f"owner_readiness_decision_count: {len(readiness_decisions)}")
    if readiness_decisions:
        latest_decision = readiness_decisions[-1]
        lines.append(f"latest_readiness_decision_id: {latest_decision.decision_id}")
        lines.append(f"latest_readiness_decision: {latest_decision.decision}")
    lines.append(f"readiness_review_state: {readiness_review_state}")
    lines.append(f"next_required_action: {next_required_action}")
    if blocking_reasons:
        lines.append("blocking_reasons:")
        for reason in blocking_reasons:
            lines.append(f"  - {reason}")
    lines.append("non_authority:")
    for flag in READINESS_REVIEW_NON_AUTHORITY_FLAGS:
        lines.append(f"  {flag}: true")
    lines.append(
        "note: readiness review is read-only; not owner readiness decision, "
        "not approval, not planning generation, and no files were modified"
    )
    lines.append(
        "note: owner clarifications do not automatically make an intake draft-ready"
    )
    lines.append(
        "note: owner readiness decisions do not generate a planning draft"
    )
    return "\n".join(lines)


@dataclass(frozen=True)
class GoalIntakeReadinessReport:
    output: str
    intake_id: str
    goal_intake_valid: bool
    ambiguity_level: str | None
    planning_readiness: str | None
    owner_clarification_count: int
    latest_clarification_id: str | None
    readiness_review_state: str
    next_required_action: str
    blocking_reasons: tuple[str, ...]
    non_authority: dict[str, bool]


def review_goal_intake_readiness(
    project: Path,
    intake_id: str,
) -> GoalIntakeReadinessReport:
    """Read-only readiness review for a GOAL_INTAKE and its clarifications."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = _goal_intake_artifact_path(project, intake_id)
    if not path.is_file():
        raise FileNotFoundError(f"goal intake artifact not found: {intake_id}")

    raw_text = path.read_text(encoding="utf-8")
    validation_errors: list[str] = []
    artifact: dict | None = None
    try:
        loaded = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        validation_errors = [f"malformed JSON: {exc.msg}"]
    else:
        validation_errors = _validate_goal_intake_payload(
            loaded,
            intake_id,
            raw_text=raw_text,
        )
        if isinstance(loaded, dict):
            artifact = loaded
        else:
            validation_errors.append("goal intake artifact must be a JSON object")

    clarifications, clarification_errors = _validate_clarifications_for_readiness(
        project,
        intake_id,
    )
    readiness_decisions = list_owner_readiness_decisions(project, intake_id)
    readiness_review_state, next_required_action, blocking_reasons = (
        _determine_readiness_review(
            validation_errors=validation_errors,
            artifact=artifact,
            clarifications=clarifications,
            clarification_errors=clarification_errors,
        )
    )

    if readiness_review_state in FORBIDDEN_READINESS_REVIEW_STATES:
        raise ValueError(
            f"forbidden readiness review state: {readiness_review_state}"
        )

    goal_intake_valid = not validation_errors
    ambiguity_level = (
        artifact.get("ambiguity_level") if artifact is not None else None
    )
    planning_readiness = (
        artifact.get("planning_readiness") if artifact is not None else None
    )
    latest_clarification_id = (
        clarifications[-1].clarification_id if clarifications else None
    )
    non_authority = {key: True for key in READINESS_REVIEW_NON_AUTHORITY_FLAGS}

    output = _format_goal_intake_readiness(
        path,
        intake_id,
        goal_intake_valid=goal_intake_valid,
        artifact=artifact,
        clarifications=clarifications,
        readiness_decisions=readiness_decisions,
        readiness_review_state=readiness_review_state,
        next_required_action=next_required_action,
        blocking_reasons=blocking_reasons,
    )
    return GoalIntakeReadinessReport(
        output=output,
        intake_id=intake_id,
        goal_intake_valid=goal_intake_valid,
        ambiguity_level=ambiguity_level,
        planning_readiness=planning_readiness,
        owner_clarification_count=len(clarifications),
        latest_clarification_id=latest_clarification_id,
        readiness_review_state=readiness_review_state,
        next_required_action=next_required_action,
        blocking_reasons=tuple(blocking_reasons),
        non_authority=non_authority,
    )


def _validate_readiness_decision_allowed(
    decision: str,
    readiness_report: GoalIntakeReadinessReport,
) -> None:
    """Enforce decision gating from the current readiness review snapshot."""
    if decision not in OWNER_READINESS_DECISION_VALUES:
        raise ValueError(f"unsupported decision value: {decision!r}")

    if not readiness_report.goal_intake_valid:
        raise ValueError("decision requires a valid goal intake artifact")

    state = readiness_report.readiness_review_state
    if decision == "AUTHORIZE_DRAFT_PREPARATION":
        if state in AUTHORIZE_DRAFT_PREPARATION_FORBIDDEN_STATES:
            raise ValueError(
                f"AUTHORIZE_DRAFT_PREPARATION is not allowed when "
                f"readiness_review_state is {state!r}"
            )
        if state not in AUTHORIZE_DRAFT_PREPARATION_ALLOWED_STATES:
            raise ValueError(
                f"AUTHORIZE_DRAFT_PREPARATION is not allowed when "
                f"readiness_review_state is {state!r}"
            )


@dataclass(frozen=True)
class OwnerReadinessDecisionRecord:
    decision_id: str
    decision: str
    created_at: str
    path: Path


@dataclass(frozen=True)
class OwnerReadinessDecisionValidationReport:
    output: str
    valid: bool
    errors: tuple[str, ...]


def build_owner_readiness_decision_artifact(
    intake_id: str,
    decision_id: str,
    decision: str,
    owner_summary: str,
    *,
    readiness_review_state_at_decision: str,
    next_required_action_at_decision: str,
    owner_clarification_count_at_decision: int,
    latest_clarification_id_at_decision: str | None,
    created_at: str | None = None,
) -> dict:
    """Build the deterministic OWNER_READINESS_DECISION artifact payload."""
    validate_intake_id(intake_id)
    validate_readiness_decision_id(decision_id)
    if decision not in OWNER_READINESS_DECISION_VALUES:
        raise ValueError(f"unsupported decision value: {decision!r}")
    if not owner_summary:
        raise ValueError("owner summary must not be empty")

    return {
        "artifact_type": OWNER_READINESS_DECISION_ARTIFACT_TYPE,
        "schema_version": OWNER_READINESS_DECISION_SCHEMA_VERSION,
        "intake_id": intake_id,
        "decision_id": decision_id,
        "decision": decision,
        "owner_summary": owner_summary,
        "readiness_review_state_at_decision": readiness_review_state_at_decision,
        "next_required_action_at_decision": next_required_action_at_decision,
        "owner_clarification_count_at_decision": owner_clarification_count_at_decision,
        "latest_clarification_id_at_decision": latest_clarification_id_at_decision,
        "created_at": created_at or _utc_now(),
        "non_authority": {
            key: True for key in OWNER_READINESS_DECISION_NON_AUTHORITY_FLAGS
        },
    }


def _validate_owner_readiness_decision_payload(
    artifact: object,
    intake_id: str,
    decision_id: str,
) -> list[str]:
    """Return structural validation errors for OWNER_READINESS_DECISION payload."""
    errors: list[str] = []

    if not isinstance(artifact, dict):
        return ["owner readiness decision artifact must be a JSON object"]

    for field in OWNER_READINESS_DECISION_REQUIRED_FIELDS:
        if field not in artifact:
            errors.append(f"missing required field: {field}")

    artifact_type = artifact.get("artifact_type")
    if (
        artifact_type is not None
        and artifact_type != OWNER_READINESS_DECISION_ARTIFACT_TYPE
    ):
        errors.append(
            f"wrong artifact_type: expected {OWNER_READINESS_DECISION_ARTIFACT_TYPE!r}, "
            f"found {artifact_type!r}"
        )

    schema_version = artifact.get("schema_version")
    if (
        schema_version is not None
        and schema_version != OWNER_READINESS_DECISION_SCHEMA_VERSION
    ):
        errors.append(
            f"unsupported schema_version: expected "
            f"{OWNER_READINESS_DECISION_SCHEMA_VERSION!r}, found {schema_version!r}"
        )

    artifact_intake_id = artifact.get("intake_id")
    if isinstance(artifact_intake_id, str) and artifact_intake_id != intake_id:
        errors.append(
            "intake_id mismatch: "
            f"path {intake_id!r}, artifact {artifact_intake_id!r}"
        )

    artifact_decision_id = artifact.get("decision_id")
    if isinstance(artifact_decision_id, str) and artifact_decision_id != decision_id:
        errors.append(
            "decision_id mismatch: "
            f"path {decision_id!r}, artifact {artifact_decision_id!r}"
        )

    decision = artifact.get("decision")
    if decision is not None and decision not in OWNER_READINESS_DECISION_VALUES:
        errors.append(f"invalid decision value: {decision!r}")

    owner_summary = artifact.get("owner_summary")
    if owner_summary is not None:
        error = _non_empty_string(owner_summary, "owner_summary")
        if error:
            errors.append(error)

    clarification_count = artifact.get("owner_clarification_count_at_decision")
    if clarification_count is not None and not isinstance(clarification_count, int):
        errors.append("owner_clarification_count_at_decision must be an integer")

    latest_clarification = artifact.get("latest_clarification_id_at_decision")
    if latest_clarification is not None and not isinstance(
        latest_clarification, (str, type(None))
    ):
        errors.append("latest_clarification_id_at_decision must be a string or null")

    created_at = artifact.get("created_at")
    if created_at is not None and not _parse_created_at(created_at):
        errors.append("created_at must be a parseable ISO-8601 timestamp")

    non_authority = artifact.get("non_authority")
    if non_authority is None:
        errors.append("missing required field: non_authority")
    elif not isinstance(non_authority, dict):
        errors.append("non_authority must be an object")
    else:
        for flag in OWNER_READINESS_DECISION_NON_AUTHORITY_FLAGS:
            if flag not in non_authority:
                errors.append(f"missing non_authority flag: {flag}")
            elif non_authority[flag] is not True:
                errors.append(f"non_authority flag must be true: {flag}")

    return errors


def create_owner_readiness_decision(
    project: Path,
    intake_id: str,
    decision_id: str,
    decision: str,
    owner_summary: str,
) -> Path:
    """Create an OWNER_READINESS_DECISION artifact without mutating intake or clarifications."""
    validate_readiness_decision_id(decision_id)
    if decision not in OWNER_READINESS_DECISION_VALUES:
        raise ValueError(f"unsupported decision value: {decision!r}")
    if not owner_summary:
        raise ValueError("owner summary must not be empty")

    _require_valid_goal_intake(project, intake_id)
    readiness_report = review_goal_intake_readiness(project, intake_id)
    _validate_readiness_decision_allowed(decision, readiness_report)

    artifact = build_owner_readiness_decision_artifact(
        intake_id,
        decision_id,
        decision,
        owner_summary,
        readiness_review_state_at_decision=readiness_report.readiness_review_state,
        next_required_action_at_decision=readiness_report.next_required_action,
        owner_clarification_count_at_decision=readiness_report.owner_clarification_count,
        latest_clarification_id_at_decision=readiness_report.latest_clarification_id,
    )

    dest = orchestrator_readiness_decision_path(project, intake_id, decision_id)
    if dest.exists():
        raise FileExistsError(
            f"owner readiness decision artifact already exists: {decision_id}"
        )

    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_json(dest, artifact)
    return dest


def load_owner_readiness_decision(
    project: Path,
    intake_id: str,
    decision_id: str,
) -> dict:
    """Load an OWNER_READINESS_DECISION artifact from disk (read-only)."""
    validate_intake_id(intake_id)
    validate_readiness_decision_id(decision_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = orchestrator_readiness_decision_path(project, intake_id, decision_id)
    if not path.is_file():
        raise FileNotFoundError(
            f"owner readiness decision artifact not found: {decision_id}"
        )

    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid readiness decision artifact for {decision_id}: {exc.msg}"
        ) from exc

    if not isinstance(artifact, dict):
        raise ValueError(
            f"invalid readiness decision artifact for {decision_id}: expected object"
        )

    return artifact


def list_owner_readiness_decisions(
    project: Path,
    intake_id: str,
) -> tuple[OwnerReadinessDecisionRecord, ...]:
    """List owner readiness decision records for an intake (read-only)."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    decisions_dir = (
        orchestrator_intake_path(project, intake_id) / READINESS_DECISIONS_DIR
    )
    if not decisions_dir.is_dir():
        return ()

    records: list[OwnerReadinessDecisionRecord] = []
    for path in sorted(decisions_dir.glob("*.json")):
        decision_id = path.stem
        try:
            artifact = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(artifact, dict):
            continue
        created_at = artifact.get("created_at")
        if not isinstance(created_at, str):
            created_at = ""
        decision = artifact.get("decision")
        if not isinstance(decision, str):
            decision = ""
        records.append(
            OwnerReadinessDecisionRecord(
                decision_id=decision_id,
                decision=decision,
                created_at=created_at,
                path=path,
            )
        )

    records.sort(key=lambda record: (record.created_at, record.decision_id))
    return tuple(records)


def validate_owner_readiness_decision(
    project: Path,
    intake_id: str,
    decision_id: str,
) -> OwnerReadinessDecisionValidationReport:
    """Strict read-only structural validation of an OWNER_READINESS_DECISION artifact."""
    validate_intake_id(intake_id)
    validate_readiness_decision_id(decision_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = orchestrator_readiness_decision_path(project, intake_id, decision_id)
    if not path.is_file():
        raise FileNotFoundError(
            f"owner readiness decision artifact not found: {decision_id}"
        )

    raw_text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    try:
        artifact = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        errors = [f"malformed JSON: {exc.msg}"]
    else:
        errors = _validate_owner_readiness_decision_payload(
            artifact,
            intake_id,
            decision_id,
        )

    lines = [
        f"owner readiness decision artifact: {path}",
        f"intake_id: {intake_id}",
        f"decision_id: {decision_id}",
        f"structural validation: {'OK' if not errors else 'INVALID'}",
    ]
    for error in errors:
        lines.append(f"  - {error}")
    lines.append(f"final validation result: {'OK' if not errors else 'INVALID'}")
    if not errors:
        lines.append(
            "note: readiness decision is owner-provided context only; "
            "not approval, not planning generation, and no intake files were modified"
        )

    output = "\n".join(lines)
    return OwnerReadinessDecisionValidationReport(output, not errors, tuple(errors))


@dataclass(frozen=True)
class _PreflightDecisionEntry:
    record: OwnerReadinessDecisionRecord
    artifact: dict | None
    validation_errors: tuple[str, ...]


def _collect_preflight_decision_entries(
    project: Path,
    intake_id: str,
) -> tuple[tuple[_PreflightDecisionEntry, ...], list[str]]:
    """Load readiness decision files with validation metadata (read-only)."""
    decisions_dir = (
        orchestrator_intake_path(project, intake_id) / READINESS_DECISIONS_DIR
    )
    if not decisions_dir.is_dir():
        return (), []

    entries: list[_PreflightDecisionEntry] = []
    blocking: list[str] = []

    for path in sorted(decisions_dir.glob("*.json")):
        decision_id = path.stem
        raw_text = path.read_text(encoding="utf-8")
        validation_errors: list[str] = []
        artifact: dict | None = None
        try:
            loaded = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            validation_errors = [f"malformed JSON: {exc.msg}"]
        else:
            validation_errors = _validate_owner_readiness_decision_payload(
                loaded,
                intake_id,
                decision_id,
            )
            if isinstance(loaded, dict):
                artifact = loaded
            else:
                validation_errors.append(
                    "owner readiness decision artifact must be a JSON object"
                )

        created_at = ""
        decision = ""
        if artifact is not None:
            created_at_value = artifact.get("created_at")
            if isinstance(created_at_value, str):
                created_at = created_at_value
            decision_value = artifact.get("decision")
            if isinstance(decision_value, str):
                decision = decision_value

        record = OwnerReadinessDecisionRecord(
            decision_id=decision_id,
            decision=decision,
            created_at=created_at,
            path=path,
        )
        if validation_errors:
            for error in validation_errors:
                blocking.append(f"invalid readiness decision {decision_id}: {error}")

        entries.append(
            _PreflightDecisionEntry(
                record=record,
                artifact=artifact,
                validation_errors=tuple(validation_errors),
            )
        )

    entries.sort(key=lambda entry: (entry.record.created_at, entry.record.decision_id))
    return tuple(entries), blocking


def _authorization_snapshot_coherent(
    artifact: dict,
    readiness_report: GoalIntakeReadinessReport,
) -> bool:
    """Return whether decision snapshot fields match the current readiness review."""
    snapshot_state = artifact.get("readiness_review_state_at_decision")
    snapshot_action = artifact.get("next_required_action_at_decision")
    snapshot_count = artifact.get("owner_clarification_count_at_decision")
    snapshot_latest = artifact.get("latest_clarification_id_at_decision")

    if snapshot_state != readiness_report.readiness_review_state:
        return False
    if snapshot_action != readiness_report.next_required_action:
        return False
    if snapshot_count != readiness_report.owner_clarification_count:
        return False
    if snapshot_latest != readiness_report.latest_clarification_id:
        return False
    return True


def _format_draft_preparation_preflight(
    path: Path,
    *,
    intake_id: str,
    goal_intake_valid: bool,
    current_readiness_review_state: str,
    current_next_required_action: str,
    owner_readiness_decision_count: int,
    latest_decision_id: str | None,
    latest_decision: str | None,
    latest_decision_created_at: str | None,
    latest_decision_snapshot_state: str | None,
    preflight_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
    non_authority: dict[str, bool],
) -> str:
    lines = [
        f"draft-preparation authorization preflight: {path}",
        f"intake_id: {intake_id}",
        f"goal_intake_valid: {'yes' if goal_intake_valid else 'no'}",
        f"current_readiness_review_state: {current_readiness_review_state}",
        f"current_next_required_action: {current_next_required_action}",
        f"owner_readiness_decision_count: {owner_readiness_decision_count}",
    ]
    if latest_decision_id is not None:
        lines.append(f"latest_decision_id: {latest_decision_id}")
    if latest_decision is not None:
        lines.append(f"latest_decision: {latest_decision}")
    if latest_decision_created_at is not None:
        lines.append(f"latest_decision_created_at: {latest_decision_created_at}")
    if latest_decision_snapshot_state is not None:
        lines.append(
            f"latest_decision_snapshot_state: {latest_decision_snapshot_state}"
        )
    lines.append(f"preflight_state: {preflight_state}")
    lines.append(f"next_required_action: {next_required_action}")
    if blocking_reasons:
        lines.append("blocking_reasons:")
        for reason in blocking_reasons:
            lines.append(f"  - {reason}")
    lines.append("non_authority:")
    for flag in DRAFT_PREPARATION_PREFLIGHT_NON_AUTHORITY_FLAGS:
        lines.append(f"  {flag}: true")
    lines.append(
        "note: draft-preparation preflight is read-only; "
        "not draft generation, not planning workspace creation, "
        "not architecture approval, not plan approval, and no files were modified"
    )
    if (
        preflight_state
        == "DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED"
    ):
        lines.append(
            "note: authorization confirmed for a future draft-preparation command only; "
            "no planning draft was generated"
        )
    return "\n".join(lines)


@dataclass(frozen=True)
class DraftPreparationPreflightReport:
    output: str
    intake_id: str
    goal_intake_valid: bool
    current_readiness_review_state: str
    current_next_required_action: str
    owner_readiness_decision_count: int
    latest_decision_id: str | None
    latest_decision: str | None
    latest_decision_created_at: str | None
    latest_decision_snapshot_state: str | None
    preflight_state: str
    next_required_action: str
    blocking_reasons: tuple[str, ...]
    non_authority: dict[str, bool]


def preflight_draft_preparation(
    project: Path,
    intake_id: str,
) -> DraftPreparationPreflightReport:
    """Read-only draft-preparation authorization preflight for an existing intake."""
    validate_intake_id(intake_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = _goal_intake_artifact_path(project, intake_id)
    if not path.is_file():
        raise FileNotFoundError(f"goal intake artifact not found: {intake_id}")

    readiness_report = review_goal_intake_readiness(project, intake_id)
    decision_entries, decision_blocking = _collect_preflight_decision_entries(
        project,
        intake_id,
    )
    non_authority = {
        key: True for key in DRAFT_PREPARATION_PREFLIGHT_NON_AUTHORITY_FLAGS
    }

    latest_decision_id: str | None = None
    latest_decision: str | None = None
    latest_decision_created_at: str | None = None
    latest_decision_snapshot_state: str | None = None
    blocking_reasons: list[str] = list(decision_blocking)
    preflight_state: str
    next_required_action: str

    if not readiness_report.goal_intake_valid:
        preflight_state = "BLOCKED_INVALID_INTAKE"
        next_required_action = "FIX_GOAL_INTAKE_STRUCTURE"
        blocking_reasons = list(readiness_report.blocking_reasons) + blocking_reasons
    elif not decision_entries:
        preflight_state = "BLOCKED_NO_READINESS_DECISION"
        next_required_action = "ADD_OWNER_READINESS_DECISION"
    else:
        latest_entry = decision_entries[-1]
        latest_decision_id = latest_entry.record.decision_id
        latest_decision = latest_entry.record.decision or None
        latest_decision_created_at = latest_entry.record.created_at or None
        if latest_entry.artifact is not None:
            snapshot_state = latest_entry.artifact.get(
                "readiness_review_state_at_decision"
            )
            if isinstance(snapshot_state, str):
                latest_decision_snapshot_state = snapshot_state

        if latest_entry.validation_errors:
            preflight_state = "BLOCKED_INVALID_READINESS_DECISION"
            next_required_action = "RESOLVE_OR_REPLACE_READINESS_DECISION"
        elif latest_decision == "REQUEST_MORE_CLARIFICATION":
            preflight_state = "BLOCKED_LATEST_DECISION_REQUESTS_CLARIFICATION"
            next_required_action = "ADD_OWNER_CLARIFICATION"
        elif latest_decision == "BLOCK_INTAKE":
            preflight_state = "BLOCKED_LATEST_DECISION_BLOCKS_INTAKE"
            next_required_action = "STOP_INTAKE"
        elif latest_decision == "AUTHORIZE_DRAFT_PREPARATION":
            if latest_entry.artifact is None or not _authorization_snapshot_coherent(
                latest_entry.artifact,
                readiness_report,
            ):
                preflight_state = "BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT"
                next_required_action = "RESOLVE_OR_REPLACE_READINESS_DECISION"
                blocking_reasons.append(
                    "authorization snapshot no longer matches current readiness review"
                )
            else:
                preflight_state = (
                    "DRAFT_PREPARATION_AUTHORIZATION_CONFIRMED_NO_DRAFT_GENERATED"
                )
                next_required_action = (
                    "FUTURE_DRAFT_PREPARATION_STEP_REQUIRES_SEPARATE_COMMAND"
                )
        elif latest_decision in OWNER_READINESS_DECISION_VALUES:
            preflight_state = "BLOCKED_LATEST_DECISION_NOT_AUTHORIZE"
            next_required_action = "RESOLVE_OR_REPLACE_READINESS_DECISION"
        else:
            preflight_state = "BLOCKED_INVALID_READINESS_DECISION"
            next_required_action = "RESOLVE_OR_REPLACE_READINESS_DECISION"

    if preflight_state in FORBIDDEN_DRAFT_PREPARATION_PREFLIGHT_STATES:
        raise ValueError(f"forbidden draft-preparation preflight state: {preflight_state}")

    output = _format_draft_preparation_preflight(
        path,
        intake_id=intake_id,
        goal_intake_valid=readiness_report.goal_intake_valid,
        current_readiness_review_state=readiness_report.readiness_review_state,
        current_next_required_action=readiness_report.next_required_action,
        owner_readiness_decision_count=len(decision_entries),
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
        latest_decision_created_at=latest_decision_created_at,
        latest_decision_snapshot_state=latest_decision_snapshot_state,
        preflight_state=preflight_state,
        next_required_action=next_required_action,
        blocking_reasons=blocking_reasons,
        non_authority=non_authority,
    )
    return DraftPreparationPreflightReport(
        output=output,
        intake_id=intake_id,
        goal_intake_valid=readiness_report.goal_intake_valid,
        current_readiness_review_state=readiness_report.readiness_review_state,
        current_next_required_action=readiness_report.next_required_action,
        owner_readiness_decision_count=len(decision_entries),
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
        latest_decision_created_at=latest_decision_created_at,
        latest_decision_snapshot_state=latest_decision_snapshot_state,
        preflight_state=preflight_state,
        next_required_action=next_required_action,
        blocking_reasons=tuple(blocking_reasons),
        non_authority=non_authority,
    )


def _build_orchestrator_provenance_artifact(
    *,
    plan_id: str,
    intake_id: str,
    source_goal_intake_path: Path,
    preflight_report: DraftPreparationPreflightReport,
    readiness_report: GoalIntakeReadinessReport,
    intake_artifact: dict,
    created_at: str,
) -> dict:
    normalized_goal = intake_artifact.get("normalized_goal")
    raw_goal = intake_artifact.get("raw_goal")
    if isinstance(normalized_goal, str) and normalized_goal.strip():
        goal_summary = normalized_goal
    elif isinstance(raw_goal, str) and raw_goal.strip():
        goal_summary = raw_goal
    else:
        goal_summary = ""

    return {
        "artifact_type": ORCHESTRATOR_PLANNING_DRAFT_SOURCE_ARTIFACT_TYPE,
        "schema_version": ORCHESTRATOR_PLANNING_DRAFT_SOURCE_SCHEMA_VERSION,
        "plan_id": plan_id,
        "intake_id": intake_id,
        "source_goal_intake_path": str(source_goal_intake_path),
        "source_goal_summary": goal_summary,
        "source_preflight_state": preflight_report.preflight_state,
        "source_authorize_decision_id": preflight_report.latest_decision_id,
        "source_authorize_decision_value": preflight_report.latest_decision,
        "source_readiness_review_state": readiness_report.readiness_review_state,
        "source_next_required_action": preflight_report.next_required_action,
        "owner_clarification_count": readiness_report.owner_clarification_count,
        "latest_clarification_id": readiness_report.latest_clarification_id,
        "created_at": created_at,
        "non_authority": {
            key: True for key in ORCHESTRATOR_PLANNING_DRAFT_SOURCE_NON_AUTHORITY_FLAGS
        },
    }


def _orchestrator_draft_scaffold_notes_markdown(
    *,
    intake_id: str,
    plan_id: str,
    goal_summary: str,
) -> str:
    return f"""\
# Orchestrator draft scaffold notes

> **Traceability only — not authority.** This file records orchestrator provenance
> boundaries for a DRAFT planning workspace scaffold. It does not approve work,
> validate planning artifacts, or authorize execution.

- **intake_id:** `{intake_id}`
- **plan_id:** `{plan_id}`
- **goal context (provenance only):** {goal_summary or "unavailable"}
- **architecture:** undecided — not generated by orchestrator
- **implementation plan:** not generated — template placeholders only
- **PLANNING_RUN_SLICE:** not generated
- **planning validation:** not performed by orchestrator
- **plan approval:** not granted
- **runner proposals / runs / executor:** not created or invoked

Future manual or agent planning, independent validation, and owner approval remain required.
"""


def _format_prepared_planning_workspace_draft(
    *,
    workspace_dest: Path,
    plan_id: str,
    intake_id: str,
    provenance_path: Path,
    scaffold_notes_path: Path,
    preflight_state: str,
    authorize_decision_id: str | None,
) -> str:
    lines = [
        f"planning workspace draft scaffold created: {workspace_dest}",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
        "workspace_status: DRAFT",
        f"orchestrator provenance: {provenance_path}",
        f"orchestrator scaffold notes: {scaffold_notes_path}",
        f"source_preflight_state: {preflight_state}",
    ]
    if authorize_decision_id is not None:
        lines.append(f"source_authorize_decision_id: {authorize_decision_id}")
    lines.append(
        "note: draft scaffold only; no architecture generation, "
        "no implementation plan generation, no PLANNING_RUN_SLICE"
    )
    lines.append(
        "note: planning workspace not validated or approved; "
        "no runner proposals, runs, or executor invocation"
    )
    lines.append(
        "note: orchestrator intake artifacts were not modified; "
        "future independent validation and owner approval remain required"
    )
    return "\n".join(lines)


@dataclass(frozen=True)
class PreparedPlanningWorkspaceDraftReport:
    output: str
    plan_id: str
    intake_id: str
    workspace_path: Path
    provenance_path: Path
    scaffold_notes_path: Path
    workspace_status: str
    preflight_state: str
    authorize_decision_id: str | None
    non_authority: dict[str, bool]


def prepare_planning_workspace_draft(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> PreparedPlanningWorkspaceDraftReport:
    """Create a DRAFT planning workspace scaffold after draft-preflight authorization."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    intake_path, intake_artifact = _require_valid_goal_intake(project, intake_id)

    preflight_report = preflight_draft_preparation(project, intake_id)
    if (
        preflight_report.preflight_state
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE
    ):
        raise ValueError(
            "draft-preparation preflight not confirmed: "
            f"{preflight_report.preflight_state}"
        )
    if (
        preflight_report.next_required_action
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_NEXT_ACTION
    ):
        raise ValueError(
            "draft-preparation preflight next action is not draft preparation: "
            f"{preflight_report.next_required_action}"
        )
    if preflight_report.latest_decision != "AUTHORIZE_DRAFT_PREPARATION":
        raise ValueError(
            "latest readiness decision is not AUTHORIZE_DRAFT_PREPARATION"
        )
    if preflight_report.latest_decision_id is None:
        raise ValueError("missing authorize decision id in preflight report")

    workspace_dest = planning_path(project, plan_id)
    if workspace_dest.exists():
        raise FileExistsError(f"planning workspace already exists: {plan_id}")

    provenance_path = workspace_dest / "evidence" / ORCHESTRATOR_PROVENANCE_FILE
    scaffold_notes_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_DRAFT_SCAFFOLD_NOTES_FILE
    )
    if provenance_path.exists() or scaffold_notes_path.exists():
        raise FileExistsError(
            f"orchestrator provenance would overwrite existing file for plan: {plan_id}"
        )

    readiness_report = review_goal_intake_readiness(project, intake_id)
    created_at = _utc_now()
    provenance_artifact = _build_orchestrator_provenance_artifact(
        plan_id=plan_id,
        intake_id=intake_id,
        source_goal_intake_path=intake_path,
        preflight_report=preflight_report,
        readiness_report=readiness_report,
        intake_artifact=intake_artifact,
        created_at=created_at,
    )
    goal_summary = provenance_artifact.get("source_goal_summary", "")
    scaffold_notes = _orchestrator_draft_scaffold_notes_markdown(
        intake_id=intake_id,
        plan_id=plan_id,
        goal_summary=str(goal_summary),
    )

    try:
        init_planning_workspace(project, plan_id)
        provenance_path.parent.mkdir(parents=True, exist_ok=True)
        _write_json(provenance_path, provenance_artifact)
        scaffold_notes_path.write_text(scaffold_notes, encoding="utf-8")
    except Exception:
        if workspace_dest.is_dir():
            shutil.rmtree(workspace_dest)
        raise

    non_authority = {
        key: True for key in ORCHESTRATOR_PLANNING_DRAFT_SOURCE_NON_AUTHORITY_FLAGS
    }
    output = _format_prepared_planning_workspace_draft(
        workspace_dest=workspace_dest,
        plan_id=plan_id,
        intake_id=intake_id,
        provenance_path=provenance_path,
        scaffold_notes_path=scaffold_notes_path,
        preflight_state=preflight_report.preflight_state,
        authorize_decision_id=preflight_report.latest_decision_id,
    )
    return PreparedPlanningWorkspaceDraftReport(
        output=output,
        plan_id=plan_id,
        intake_id=intake_id,
        workspace_path=workspace_dest,
        provenance_path=provenance_path,
        scaffold_notes_path=scaffold_notes_path,
        workspace_status="DRAFT",
        preflight_state=preflight_report.preflight_state,
        authorize_decision_id=preflight_report.latest_decision_id,
        non_authority=non_authority,
    )


def _load_planning_workspace_status(workspace_dest: Path, plan_id: str) -> str:
    manifest_path = workspace_dest / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"planning workspace manifest not found: {plan_id}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid manifest.json for planning workspace {plan_id}: {exc.msg}"
        ) from exc
    if not isinstance(manifest, dict):
        raise ValueError(
            f"invalid manifest.json for planning workspace {plan_id}: expected object"
        )
    status = manifest.get("status")
    if not isinstance(status, str) or not status.strip():
        raise ValueError(f"missing manifest status for planning workspace {plan_id}")
    return status


def _require_orchestrator_provenance_for_transport(
    provenance_path: Path,
    *,
    plan_id: str,
    intake_id: str,
    preflight_report: DraftPreparationPreflightReport,
) -> dict:
    if not provenance_path.is_file():
        raise FileNotFoundError(
            f"orchestrator provenance not found for planning workspace: {plan_id}"
        )

    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid orchestrator provenance for planning workspace {plan_id}: {exc.msg}"
        ) from exc

    if not isinstance(provenance, dict):
        raise ValueError(
            f"invalid orchestrator provenance for planning workspace {plan_id}: "
            "expected object"
        )

    provenance_plan_id = provenance.get("plan_id")
    if provenance_plan_id != plan_id:
        raise ValueError(
            f"orchestrator provenance plan_id mismatch: "
            f"expected {plan_id!r}, found {provenance_plan_id!r}"
        )

    provenance_intake_id = provenance.get("intake_id")
    if provenance_intake_id != intake_id:
        raise ValueError(
            f"orchestrator provenance intake_id mismatch: "
            f"expected {intake_id!r}, found {provenance_intake_id!r}"
        )

    source_preflight_state = provenance.get("source_preflight_state")
    if source_preflight_state != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE:
        raise ValueError(
            "orchestrator provenance source_preflight_state is not confirmed: "
            f"{source_preflight_state!r}"
        )

    source_authorize_decision_id = provenance.get("source_authorize_decision_id")
    if source_authorize_decision_id != preflight_report.latest_decision_id:
        raise ValueError(
            "orchestrator provenance source_authorize_decision_id mismatch: "
            f"expected {preflight_report.latest_decision_id!r}, "
            f"found {source_authorize_decision_id!r}"
        )

    return provenance


def _collect_owner_clarifications_for_transport(
    project: Path,
    intake_id: str,
) -> list[dict]:
    records = list_owner_clarifications(project, intake_id)
    clarifications: list[dict] = []
    for record in records:
        artifact = load_owner_clarification(
            project,
            intake_id,
            record.clarification_id,
        )
        owner_answer = artifact.get("owner_answer")
        if not isinstance(owner_answer, str):
            owner_answer = ""
        created_at = artifact.get("created_at")
        if not isinstance(created_at, str):
            created_at = record.created_at
        clarifications.append(
            {
                "clarification_id": record.clarification_id,
                "owner_answer": owner_answer,
                "created_at": created_at,
            }
        )
    return clarifications


def _latest_owner_readiness_decision_for_transport(
    project: Path,
    intake_id: str,
) -> dict:
    decisions = list_owner_readiness_decisions(project, intake_id)
    if not decisions:
        raise ValueError("owner readiness decision required for context transport")

    latest = decisions[-1]
    artifact = load_owner_readiness_decision(
        project,
        intake_id,
        latest.decision_id,
    )
    owner_summary = artifact.get("owner_summary")
    if not isinstance(owner_summary, str):
        owner_summary = ""
    created_at = artifact.get("created_at")
    if not isinstance(created_at, str):
        created_at = latest.created_at
    decision = artifact.get("decision")
    if not isinstance(decision, str):
        decision = latest.decision

    return {
        "decision_id": latest.decision_id,
        "decision": decision,
        "owner_summary": owner_summary,
        "created_at": created_at,
    }


def _build_orchestrator_context_transport_artifact(
    *,
    plan_id: str,
    intake_id: str,
    source_goal_intake_path: Path,
    intake_artifact: dict,
    owner_clarifications: list[dict],
    owner_readiness_decision: dict,
    preflight_report: DraftPreparationPreflightReport,
    provenance_path: Path,
    workspace_status: str,
    created_at: str,
) -> dict:
    return {
        "artifact_type": ORCHESTRATOR_CONTEXT_TRANSPORT_ARTIFACT_TYPE,
        "schema_version": ORCHESTRATOR_CONTEXT_TRANSPORT_SCHEMA_VERSION,
        "plan_id": plan_id,
        "intake_id": intake_id,
        "source_goal_intake_path": str(source_goal_intake_path),
        "source_context": {
            "raw_goal": intake_artifact.get("raw_goal"),
            "normalized_goal": intake_artifact.get("normalized_goal"),
            "user_visible_summary": intake_artifact.get("user_visible_summary"),
            "ambiguity_level": intake_artifact.get("ambiguity_level"),
            "planning_readiness": intake_artifact.get("planning_readiness"),
            "open_questions": intake_artifact.get("open_questions"),
            "risk_flags": intake_artifact.get("risk_flags"),
        },
        "owner_clarifications": owner_clarifications,
        "owner_readiness_decision": owner_readiness_decision,
        "draft_preflight": {
            "preflight_state": preflight_report.preflight_state,
            "next_required_action": preflight_report.next_required_action,
            "latest_decision_id": preflight_report.latest_decision_id,
        },
        "planning_workspace": {
            "status_at_transport": workspace_status,
            "provenance_path": str(provenance_path),
        },
        "created_at": created_at,
        "non_authority": {
            key: True for key in ORCHESTRATOR_CONTEXT_TRANSPORT_NON_AUTHORITY_FLAGS
        },
    }


def _orchestrator_context_transport_markdown(
    *,
    plan_id: str,
    intake_id: str,
    source_goal_intake_path: Path,
    intake_artifact: dict,
    owner_clarifications: list[dict],
    owner_readiness_decision: dict,
    preflight_report: DraftPreparationPreflightReport,
    provenance_path: Path,
    workspace_status: str,
) -> str:
    raw_goal = intake_artifact.get("raw_goal", "")
    normalized_goal = intake_artifact.get("normalized_goal", "")

    lines = [
        "# Orchestrator context transport",
        "",
        "> **Source material only — not authority.** This file copies owner-provided "
        "intake context into the planning workspace for review. It does not generate "
        "architecture, implementation plans, or PLANNING_RUN_SLICE; does not validate "
        "or approve the workspace; and does not authorize execution.",
        "",
        "## Source identifiers",
        "",
        f"- **plan_id:** `{plan_id}`",
        f"- **intake_id:** `{intake_id}`",
        f"- **source goal intake:** `{source_goal_intake_path}`",
        f"- **orchestrator provenance:** `{provenance_path}`",
        f"- **planning workspace status at transport:** `{workspace_status}`",
        "",
        "## Raw goal (verbatim)",
        "",
        "```",
        str(raw_goal),
        "```",
        "",
        "## Normalized goal (from GOAL_INTAKE)",
        "",
        str(normalized_goal),
        "",
    ]

    lines.append("## Owner clarifications (verbatim answers)")
    lines.append("")
    if owner_clarifications:
        for item in owner_clarifications:
            lines.append(
                f"- **{item['clarification_id']}** "
                f"(`{item.get('created_at', '')}`): {item['owner_answer']}"
            )
    else:
        lines.append("- (none)")
    lines.append("")

    lines.extend(
        [
            "## Owner readiness decision (verbatim summary)",
            "",
            f"- **decision_id:** `{owner_readiness_decision.get('decision_id', '')}`",
            f"- **decision:** `{owner_readiness_decision.get('decision', '')}`",
            f"- **owner_summary:** {owner_readiness_decision.get('owner_summary', '')}",
            "",
            "## Draft-preparation preflight snapshot",
            "",
            f"- **preflight_state:** `{preflight_report.preflight_state}`",
            f"- **next_required_action:** `{preflight_report.next_required_action}`",
            f"- **latest_decision_id:** `{preflight_report.latest_decision_id}`",
            "",
            "## Explicit boundaries",
            "",
            "- **architecture:** undecided — not generated by orchestrator",
            "- **implementation plan:** not generated — template placeholders only",
            "- **PLANNING_RUN_SLICE:** not generated",
            "- **planning workspace:** not validated or approved",
            "- **runner proposals / runs / executor:** not created or invoked",
            "",
            "Transported context is source material only. Future architecture decision, "
            "independent validation, and owner approval remain required.",
        ]
    )
    return "\n".join(lines) + "\n"


def _format_transported_planning_context(
    *,
    json_path: Path,
    markdown_path: Path,
    plan_id: str,
    intake_id: str,
    workspace_status: str,
) -> str:
    lines = [
        f"orchestrator context transport created: {json_path.parent}",
        f"context transport json: {json_path}",
        f"context transport markdown: {markdown_path}",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
        f"workspace_status: {workspace_status}",
        "note: context transport only; copied source context, no interpretation",
        "note: no architecture generation, no implementation plan generation, "
        "no PLANNING_RUN_SLICE",
        "note: planning workspace not validated or approved; "
        "no runner proposals, runs, or executor invocation",
        "note: orchestrator intake artifacts and provenance were not modified; "
        "future architecture decision, independent validation, and owner approval "
        "remain required",
    ]
    return "\n".join(lines)


@dataclass(frozen=True)
class TransportedPlanningContextReport:
    output: str
    plan_id: str
    intake_id: str
    json_path: Path
    markdown_path: Path
    workspace_status: str
    non_authority: dict[str, bool]


def transport_planning_context(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> TransportedPlanningContextReport:
    """Transport owner-provided intake context into an authorized DRAFT planning scaffold."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    intake_path, intake_artifact = _require_valid_goal_intake(project, intake_id)

    workspace_dest = planning_path(project, plan_id)
    if not workspace_dest.is_dir():
        raise FileNotFoundError(f"planning workspace not found: {plan_id}")

    workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    if workspace_status != "DRAFT":
        raise ValueError(
            f"planning workspace must be DRAFT for context transport, found: "
            f"{workspace_status!r}"
        )

    preflight_report = preflight_draft_preparation(project, intake_id)
    if (
        preflight_report.preflight_state
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE
    ):
        raise ValueError(
            "draft-preparation preflight not confirmed: "
            f"{preflight_report.preflight_state}"
        )
    if preflight_report.latest_decision != "AUTHORIZE_DRAFT_PREPARATION":
        raise ValueError(
            "latest readiness decision is not AUTHORIZE_DRAFT_PREPARATION"
        )
    if preflight_report.latest_decision_id is None:
        raise ValueError("missing authorize decision id in preflight report")

    provenance_path = workspace_dest / "evidence" / ORCHESTRATOR_PROVENANCE_FILE
    _require_orchestrator_provenance_for_transport(
        provenance_path,
        plan_id=plan_id,
        intake_id=intake_id,
        preflight_report=preflight_report,
    )

    json_path = workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_TRANSPORT_FILE
    markdown_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_TRANSPORT_MD_FILE
    )
    if json_path.exists() or markdown_path.exists():
        raise FileExistsError(
            f"context transport artifacts already exist for plan: {plan_id}"
        )

    owner_clarifications = _collect_owner_clarifications_for_transport(
        project,
        intake_id,
    )
    owner_readiness_decision = _latest_owner_readiness_decision_for_transport(
        project,
        intake_id,
    )
    created_at = _utc_now()
    transport_artifact = _build_orchestrator_context_transport_artifact(
        plan_id=plan_id,
        intake_id=intake_id,
        source_goal_intake_path=intake_path,
        intake_artifact=intake_artifact,
        owner_clarifications=owner_clarifications,
        owner_readiness_decision=owner_readiness_decision,
        preflight_report=preflight_report,
        provenance_path=provenance_path,
        workspace_status=workspace_status,
        created_at=created_at,
    )
    transport_markdown = _orchestrator_context_transport_markdown(
        plan_id=plan_id,
        intake_id=intake_id,
        source_goal_intake_path=intake_path,
        intake_artifact=intake_artifact,
        owner_clarifications=owner_clarifications,
        owner_readiness_decision=owner_readiness_decision,
        preflight_report=preflight_report,
        provenance_path=provenance_path,
        workspace_status=workspace_status,
    )

    json_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        _write_json(json_path, transport_artifact)
        markdown_path.write_text(transport_markdown, encoding="utf-8")
    except Exception:
        if json_path.is_file():
            json_path.unlink()
        if markdown_path.is_file():
            markdown_path.unlink()
        raise

    non_authority = {
        key: True for key in ORCHESTRATOR_CONTEXT_TRANSPORT_NON_AUTHORITY_FLAGS
    }
    output = _format_transported_planning_context(
        json_path=json_path,
        markdown_path=markdown_path,
        plan_id=plan_id,
        intake_id=intake_id,
        workspace_status=workspace_status,
    )
    return TransportedPlanningContextReport(
        output=output,
        plan_id=plan_id,
        intake_id=intake_id,
        json_path=json_path,
        markdown_path=markdown_path,
        workspace_status=workspace_status,
        non_authority=non_authority,
    )


def _is_context_pack_init_placeholder(content: str, plan_id: str) -> bool:
    """Return True when context-pack.md still matches the planning init template shape."""
    normalized_content = content.replace("\r\n", "\n").replace("\r", "\n")
    meta, body = parse_frontmatter(normalized_content)
    if meta.get("artifact_type") != "CONTEXT_PACK":
        return False
    if meta.get("author") != "PLACEHOLDER":
        return False
    if meta.get("plan_id") != plan_id:
        return False

    template_path = planning_templates_dir() / "context-pack.md"
    if not template_path.is_file():
        raise FileNotFoundError("planning template missing: context-pack.md")

    _, template_body = parse_frontmatter(
        template_path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    )
    return body == template_body


def _require_context_transport_for_draft(
    json_path: Path,
    *,
    plan_id: str,
    intake_id: str,
) -> dict:
    if not json_path.is_file():
        raise FileNotFoundError(
            f"context transport json not found for planning workspace: {plan_id}"
        )

    try:
        transport = json.loads(json_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid context transport json for planning workspace {plan_id}: {exc.msg}"
        ) from exc

    if not isinstance(transport, dict):
        raise ValueError(
            f"invalid context transport json for planning workspace {plan_id}: "
            "expected object"
        )

    artifact_type = transport.get("artifact_type")
    if artifact_type != ORCHESTRATOR_CONTEXT_TRANSPORT_ARTIFACT_TYPE:
        raise ValueError(
            f"context transport artifact_type mismatch: expected "
            f"{ORCHESTRATOR_CONTEXT_TRANSPORT_ARTIFACT_TYPE!r}, found {artifact_type!r}"
        )

    transport_plan_id = transport.get("plan_id")
    if transport_plan_id != plan_id:
        raise ValueError(
            f"context transport plan_id mismatch: "
            f"expected {plan_id!r}, found {transport_plan_id!r}"
        )

    transport_intake_id = transport.get("intake_id")
    if transport_intake_id != intake_id:
        raise ValueError(
            f"context transport intake_id mismatch: "
            f"expected {intake_id!r}, found {transport_intake_id!r}"
        )

    return transport


def _format_source_context_list(items: object) -> list[str]:
    if not isinstance(items, list) or not items:
        return ["- (none)"]
    lines: list[str] = []
    for item in items:
        if isinstance(item, dict):
            lines.append(f"- {json.dumps(item, sort_keys=True)}")
        else:
            lines.append(f"- {item}")
    return lines


def _build_context_pack_draft_markdown(
    *,
    plan_id: str,
    intake_id: str,
    transport: dict,
    source_goal_intake_path: Path,
    transport_json_path: Path,
    transport_md_path: Path,
    provenance_path: Path,
    created_at: str,
) -> str:
    source_context = transport.get("source_context")
    if not isinstance(source_context, dict):
        source_context = {}

    raw_goal = source_context.get("raw_goal", "")
    normalized_goal = source_context.get("normalized_goal", "")
    user_visible_summary = source_context.get("user_visible_summary", "")
    ambiguity_level = source_context.get("ambiguity_level", "")
    planning_readiness = source_context.get("planning_readiness", "")
    open_questions = source_context.get("open_questions")
    risk_flags = source_context.get("risk_flags")

    owner_clarifications = transport.get("owner_clarifications")
    if not isinstance(owner_clarifications, list):
        owner_clarifications = []

    owner_readiness_decision = transport.get("owner_readiness_decision")
    if not isinstance(owner_readiness_decision, dict):
        owner_readiness_decision = {}

    lines = [
        "---",
        f"plan_id: {plan_id}",
        "artifact_type: CONTEXT_PACK",
        f"context_pack_status: {CONTEXT_PACK_DRAFT_STATUS}",
        "draft_source: ORCHESTRATOR_CONTEXT_TRANSPORT",
        f"intake_id: {intake_id}",
        f"created_at: {created_at}",
        "author: ORCHESTRATOR_DRAFT_NON_AUTHORITY",
        "version: 1",
        "---",
        "",
        "# Context Pack (DRAFT — non-authority)",
        "",
        "> **Planning artifact type:** `CONTEXT_PACK`",
        "> **Status:** `DRAFT_NON_AUTHORITY` — source-context draft only; not an approved "
        "context pack, not architecture, not local agentic spec, not implementation plan.",
        "",
        "## Source identifiers",
        "",
        f"- **plan_id:** `{plan_id}`",
        f"- **intake_id:** `{intake_id}`",
        f"- **source goal intake:** `{source_goal_intake_path}`",
        f"- **orchestrator provenance:** `{provenance_path}`",
        f"- **context transport json:** `{transport_json_path}`",
        f"- **context transport markdown:** `{transport_md_path}`",
        "",
        "## Raw goal (verbatim)",
        "",
        "```",
        str(raw_goal),
        "```",
        "",
        "## Normalized goal (from GOAL_INTAKE / transport)",
        "",
        str(normalized_goal),
        "",
    ]

    if isinstance(user_visible_summary, str) and user_visible_summary.strip():
        lines.extend(
            [
                "## Owner-visible summary (from GOAL_INTAKE)",
                "",
                str(user_visible_summary),
                "",
            ]
        )

    lines.extend(
        [
            "## Ambiguity level",
            "",
            str(ambiguity_level),
            "",
            "## Planning readiness",
            "",
            str(planning_readiness),
            "",
            "## Open questions (copied from transport)",
            "",
            *_format_source_context_list(open_questions),
            "",
            "## Risk flags (copied from transport)",
            "",
            *_format_source_context_list(risk_flags),
            "",
            "## Owner clarifications (verbatim answers)",
            "",
        ]
    )

    if owner_clarifications:
        for item in owner_clarifications:
            if not isinstance(item, dict):
                continue
            lines.append(
                f"- **{item.get('clarification_id', '')}** "
                f"(`{item.get('created_at', '')}`): {item.get('owner_answer', '')}"
            )
    else:
        lines.append("- (none)")
    lines.append("")

    lines.extend(
        [
            "## Owner readiness decision (verbatim summary)",
            "",
            f"- **decision_id:** `{owner_readiness_decision.get('decision_id', '')}`",
            f"- **decision:** `{owner_readiness_decision.get('decision', '')}`",
            f"- **owner_summary:** {owner_readiness_decision.get('owner_summary', '')}",
            "",
            "## Explicit boundaries",
            "",
            "- **architecture:** undecided — not generated by orchestrator",
            "- **local agentic spec:** not generated",
            "- **implementation plan:** not generated",
            "- **PLANNING_RUN_SLICE:** not generated",
            "- **planning workspace:** not validated or approved",
            "- **runner proposals / runs / executor:** not created or invoked",
            "- **future independent validation:** required",
            "- **future owner approval:** required",
            "",
            "This context pack draft copies transported source context only. It does not "
            "define architecture, approve work, or authorize execution.",
        ]
    )
    return "\n".join(lines) + "\n"


def _build_context_pack_draft_provenance_artifact(
    *,
    plan_id: str,
    intake_id: str,
    source_goal_intake_path: Path,
    transport_json_path: Path,
    transport_md_path: Path,
    context_pack_path: Path,
    preflight_report: DraftPreparationPreflightReport,
    workspace_status: str,
    created_at: str,
) -> dict:
    return {
        "artifact_type": ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_ARTIFACT_TYPE,
        "schema_version": ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_SCHEMA_VERSION,
        "plan_id": plan_id,
        "intake_id": intake_id,
        "source_context_transport_json_path": str(transport_json_path),
        "source_context_transport_md_path": str(transport_md_path),
        "source_goal_intake_path": str(source_goal_intake_path),
        "source_preflight_state": preflight_report.preflight_state,
        "source_authorize_decision_id": preflight_report.latest_decision_id,
        "context_pack_path": str(context_pack_path),
        "context_pack_status": CONTEXT_PACK_DRAFT_STATUS,
        "planning_workspace_status_at_draft": workspace_status,
        "created_at": created_at,
        "non_authority": {
            key: True for key in ORCHESTRATOR_CONTEXT_PACK_DRAFT_NON_AUTHORITY_FLAGS
        },
    }


def _format_drafted_context_pack(
    *,
    context_pack_path: Path,
    provenance_path: Path,
    plan_id: str,
    intake_id: str,
    workspace_status: str,
) -> str:
    lines = [
        f"orchestrator context pack draft created: {context_pack_path.parent.parent}",
        f"context pack: {context_pack_path}",
        f"context pack draft provenance: {provenance_path}",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
        f"context_pack_status: {CONTEXT_PACK_DRAFT_STATUS}",
        f"workspace_status: {workspace_status}",
        "note: context pack draft only; copied source context from transport artifacts",
        "note: no architecture generation, no local agentic spec generation, "
        "no implementation plan generation, no PLANNING_RUN_SLICE",
        "note: planning workspace not validated or approved; "
        "no runner proposals, runs, or executor invocation",
        "note: orchestrator intake artifacts, transport artifacts, and provenance "
        "were not modified; future architecture decision, independent validation, "
        "and owner approval remain required",
    ]
    return "\n".join(lines)


@dataclass(frozen=True)
class DraftedContextPackReport:
    output: str
    plan_id: str
    intake_id: str
    context_pack_path: Path
    provenance_path: Path
    context_pack_status: str
    workspace_status: str
    non_authority: dict[str, bool]


def draft_context_pack_from_transport(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> DraftedContextPackReport:
    """Draft context-pack.md from transported orchestrator context in a DRAFT workspace."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    intake_path, _intake_artifact = _require_valid_goal_intake(project, intake_id)

    workspace_dest = planning_path(project, plan_id)
    if not workspace_dest.is_dir():
        raise FileNotFoundError(f"planning workspace not found: {plan_id}")

    workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    if workspace_status != "DRAFT":
        raise ValueError(
            f"planning workspace must be DRAFT for context pack draft, found: "
            f"{workspace_status!r}"
        )

    preflight_report = preflight_draft_preparation(project, intake_id)
    if (
        preflight_report.preflight_state
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE
    ):
        raise ValueError(
            "draft-preparation preflight not confirmed: "
            f"{preflight_report.preflight_state}"
        )
    if preflight_report.latest_decision != "AUTHORIZE_DRAFT_PREPARATION":
        raise ValueError(
            "latest readiness decision is not AUTHORIZE_DRAFT_PREPARATION"
        )
    if preflight_report.latest_decision_id is None:
        raise ValueError("missing authorize decision id in preflight report")

    provenance_path = workspace_dest / "evidence" / ORCHESTRATOR_PROVENANCE_FILE
    _require_orchestrator_provenance_for_transport(
        provenance_path,
        plan_id=plan_id,
        intake_id=intake_id,
        preflight_report=preflight_report,
    )

    transport_json_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_TRANSPORT_FILE
    )
    transport_md_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_TRANSPORT_MD_FILE
    )
    if not transport_md_path.is_file():
        raise FileNotFoundError(
            f"context transport markdown not found for planning workspace: {plan_id}"
        )

    transport = _require_context_transport_for_draft(
        transport_json_path,
        plan_id=plan_id,
        intake_id=intake_id,
    )

    context_pack_path = workspace_dest / "context-pack.md"
    if not context_pack_path.is_file():
        raise FileNotFoundError(
            f"context-pack.md missing in planning workspace: {plan_id}"
        )

    original_context_pack = context_pack_path.read_bytes()
    if not _is_context_pack_init_placeholder(
        context_pack_path.read_text(encoding="utf-8"),
        plan_id,
    ):
        raise FileExistsError(
            f"context-pack.md already drafted or modified for plan: {plan_id}"
        )

    draft_provenance_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_FILE
    )
    if draft_provenance_path.exists():
        raise FileExistsError(
            f"context pack draft provenance already exists for plan: {plan_id}"
        )

    created_at = _utc_now()
    context_pack_markdown = _build_context_pack_draft_markdown(
        plan_id=plan_id,
        intake_id=intake_id,
        transport=transport,
        source_goal_intake_path=intake_path,
        transport_json_path=transport_json_path,
        transport_md_path=transport_md_path,
        provenance_path=provenance_path,
        created_at=created_at,
    )
    provenance_artifact = _build_context_pack_draft_provenance_artifact(
        plan_id=plan_id,
        intake_id=intake_id,
        source_goal_intake_path=intake_path,
        transport_json_path=transport_json_path,
        transport_md_path=transport_md_path,
        context_pack_path=context_pack_path,
        preflight_report=preflight_report,
        workspace_status=workspace_status,
        created_at=created_at,
    )

    temp_context_pack = context_pack_path.with_suffix(".md.tmp")
    try:
        temp_context_pack.write_text(context_pack_markdown, encoding="utf-8")
        temp_context_pack.replace(context_pack_path)
        try:
            _write_json(draft_provenance_path, provenance_artifact)
        except Exception:
            context_pack_path.write_bytes(original_context_pack)
            if draft_provenance_path.is_file():
                draft_provenance_path.unlink()
            raise
    except Exception:
        if temp_context_pack.is_file():
            temp_context_pack.unlink()
        if context_pack_path.read_bytes() != original_context_pack:
            context_pack_path.write_bytes(original_context_pack)
        if draft_provenance_path.is_file():
            draft_provenance_path.unlink()
        raise

    non_authority = {
        key: True for key in ORCHESTRATOR_CONTEXT_PACK_DRAFT_NON_AUTHORITY_FLAGS
    }
    output = _format_drafted_context_pack(
        context_pack_path=context_pack_path,
        provenance_path=draft_provenance_path,
        plan_id=plan_id,
        intake_id=intake_id,
        workspace_status=workspace_status,
    )
    return DraftedContextPackReport(
        output=output,
        plan_id=plan_id,
        intake_id=intake_id,
        context_pack_path=context_pack_path,
        provenance_path=draft_provenance_path,
        context_pack_status=CONTEXT_PACK_DRAFT_STATUS,
        workspace_status=workspace_status,
        non_authority=non_authority,
    )


def _is_planning_artifact_init_placeholder(
    content: str,
    plan_id: str,
    template_name: str,
    *,
    artifact_type: str,
    identity_field: str = "author",
    identity_value: str = "PLACEHOLDER",
) -> bool:
    """Return True when a planning artifact still matches the init template shape."""
    normalized_content = content.replace("\r\n", "\n").replace("\r", "\n")
    meta, body = parse_frontmatter(normalized_content)
    if meta.get("artifact_type") != artifact_type:
        return False
    if meta.get(identity_field) != identity_value:
        return False
    if meta.get("plan_id") != plan_id:
        return False

    template_path = planning_templates_dir() / template_name
    if not template_path.is_file():
        raise FileNotFoundError(f"planning template missing: {template_name}")

    _, template_body = parse_frontmatter(
        template_path.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    )
    return body == template_body


def _is_context_pack_draft_non_authority(content: str, plan_id: str) -> bool:
    normalized_content = content.replace("\r\n", "\n").replace("\r", "\n")
    meta, _body = parse_frontmatter(normalized_content)
    if meta.get("artifact_type") != "CONTEXT_PACK":
        return False
    if meta.get("context_pack_status") != CONTEXT_PACK_DRAFT_STATUS:
        return False
    if meta.get("plan_id") != plan_id:
        return False
    if CONTEXT_PACK_DRAFT_STATUS not in normalized_content:
        return False
    return True


def _context_pack_boundary_notes_present(content: str) -> bool:
    lowered = content.lower()
    for required_parts in CONTEXT_PACK_REQUIRED_BOUNDARY_CHECKS:
        if not all(part.lower() in lowered for part in required_parts):
            return False
    return True


def _validate_context_pack_draft_provenance(
    provenance: dict,
    *,
    plan_id: str,
    intake_id: str,
) -> str | None:
    """Return a blocking reason when context-pack draft provenance is invalid."""
    artifact_type = provenance.get("artifact_type")
    if artifact_type != ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_ARTIFACT_TYPE:
        return (
            f"context pack draft provenance artifact_type mismatch: "
            f"expected {ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_ARTIFACT_TYPE!r}, "
            f"found {artifact_type!r}"
        )

    provenance_plan_id = provenance.get("plan_id")
    if provenance_plan_id != plan_id:
        return (
            f"context pack draft provenance plan_id mismatch: "
            f"expected {plan_id!r}, found {provenance_plan_id!r}"
        )

    provenance_intake_id = provenance.get("intake_id")
    if provenance_intake_id != intake_id:
        return (
            f"context pack draft provenance intake_id mismatch: "
            f"expected {intake_id!r}, found {provenance_intake_id!r}"
        )

    if provenance.get("context_pack_status") != CONTEXT_PACK_DRAFT_STATUS:
        return "context pack draft provenance context_pack_status is not DRAFT_NON_AUTHORITY"

    if provenance.get("planning_workspace_status_at_draft") != "DRAFT":
        return "context pack draft provenance planning_workspace_status_at_draft is not DRAFT"

    for field in (
        "source_context_transport_json_path",
        "source_context_transport_md_path",
    ):
        value = provenance.get(field)
        if not isinstance(value, str) or not value.strip():
            return f"context pack draft provenance missing {field}"

    non_authority = provenance.get("non_authority")
    if not isinstance(non_authority, dict):
        return "context pack draft provenance non_authority must be an object"
    for flag in ORCHESTRATOR_CONTEXT_PACK_DRAFT_NON_AUTHORITY_FLAGS:
        if non_authority.get(flag) is not True:
            return f"context pack draft provenance non_authority.{flag} must be true"

    return None


def _is_local_agentic_spec_scaffold_non_authority(content: str, plan_id: str) -> bool:
    normalized_content = content.replace("\r\n", "\n").replace("\r", "\n")
    meta, _body = parse_frontmatter(normalized_content)
    if meta.get("artifact_type") != "LOCAL_AGENTIC_SPEC":
        return False
    if meta.get("local_agentic_spec_status") != LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS:
        return False
    if meta.get("plan_id") != plan_id:
        return False
    if LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS not in normalized_content:
        return False
    return True


def _local_agentic_spec_scaffold_boundary_notes_present(content: str) -> bool:
    lowered = content.lower()
    for required_parts in LOCAL_AGENTIC_SPEC_SCAFFOLD_REQUIRED_BOUNDARY_CHECKS:
        if not all(part.lower() in lowered for part in required_parts):
            return False
    return True


def _local_agentic_spec_contains_only_scaffold_sections(content: str) -> bool:
    if "PENDING_FUTURE_REQUIREMENTS_EXTRACTION" not in content:
        return False
    if _FUNCTIONAL_REQUIREMENT_ID_PATTERN.search(content):
        return False
    if _NON_FUNCTIONAL_REQUIREMENT_ID_PATTERN.search(content):
        return False
    if _REQUIREMENT_ID_PATTERN.search(content):
        return False
    if _USER_STORIES_HEADING_PATTERN.search(content):
        return False
    return True


def _local_agentic_spec_has_generated_functional_requirements(content: str) -> bool:
    if _FUNCTIONAL_REQUIREMENT_PATTERN.search(content):
        return True
    if _FUNCTIONAL_REQUIREMENT_ID_PATTERN.search(content):
        return True
    if _NON_FUNCTIONAL_REQUIREMENT_ID_PATTERN.search(content):
        return True
    if _REQUIREMENT_ID_PATTERN.search(content):
        return True
    functional_section = section_body(content, "## Functional Requirements")
    if functional_section.strip():
        return True
    return False


def _local_agentic_spec_has_user_stories(content: str) -> bool:
    if _USER_STORY_PATTERN.search(content):
        return True
    if _USER_STORIES_HEADING_PATTERN.search(content):
        return True
    lowered = content.lower()
    if "user stories" in lowered and "not generated" not in lowered:
        return True
    return False


def _local_agentic_spec_has_generated_acceptance_criteria(content: str) -> bool:
    if _ACCEPTANCE_CRITERIA_GWT_PATTERN.search(content):
        return True
    if _ACCEPTANCE_CRITERIA_ID_PATTERN.search(content):
        return True
    criteria_section = section_body(content, "## Acceptance Criteria")
    if criteria_section.strip():
        return True
    return False


def _local_agentic_spec_has_architecture_decision_language(content: str) -> bool:
    if _ARCHITECTURE_DECISION_PATTERN.search(content):
        return True
    if _STACK_CHOICE_PATTERN.search(content):
        return True
    return False


def _is_local_agentic_spec_requirements_extraction_scaffold_non_authority(
    content: str,
    plan_id: str,
) -> bool:
    normalized_content = content.replace("\r\n", "\n").replace("\r", "\n")
    meta, _body = parse_frontmatter(normalized_content)
    if meta.get("artifact_type") != "LOCAL_AGENTIC_SPEC":
        return False
    if meta.get("local_agentic_spec_status") != REQUIREMENTS_EXTRACTION_SCAFFOLD_STATUS:
        return False
    if meta.get("plan_id") != plan_id:
        return False
    if REQUIREMENTS_EXTRACTION_SCAFFOLD_STATUS not in normalized_content:
        return False
    return True


def _requirements_extraction_scaffold_boundary_notes_present(content: str) -> bool:
    lowered = content.lower()
    for required_parts in REQUIREMENTS_EXTRACTION_SCAFFOLD_REQUIRED_BOUNDARY_CHECKS:
        if not all(part.lower() in lowered for part in required_parts):
            return False
    return True


def _local_agentic_spec_contains_only_requirements_extraction_scaffold_sections(
    content: str,
) -> bool:
    if "NO_REQUIREMENTS_EXTRACTED" not in content:
        return False
    if "NOT_GENERATED" not in content:
        return False
    if "UNDECIDED_NOT_GENERATED" not in content:
        return False
    if _FUNCTIONAL_REQUIREMENT_ID_PATTERN.search(content):
        return False
    if _NON_FUNCTIONAL_REQUIREMENT_ID_PATTERN.search(content):
        return False
    if _REQUIREMENT_ID_PATTERN.search(content):
        return False
    if _USER_STORIES_HEADING_PATTERN.search(content):
        return False
    return True


def _local_agentic_spec_has_implementation_tasks(content: str) -> bool:
    if _IMPLEMENTATION_TASK_HEADING_PATTERN.search(content):
        section = section_body(content, "## Implementation Tasks")
        if section.strip():
            return True
    return False


def _local_agentic_spec_has_planning_run_slice_content(content: str) -> bool:
    if '"artifact_type": "PLANNING_RUN_SLICE"' in content:
        return True
    if _PLANNING_RUN_SLICE_HEADING_PATTERN.search(content):
        section = section_body(content, "## PLANNING_RUN_SLICE")
        if section.strip():
            return True
    return False


def _validate_requirements_extraction_scaffold_provenance(
    provenance: dict,
    *,
    plan_id: str,
    intake_id: str,
) -> str | None:
    """Return a blocking reason when requirements-extraction scaffold provenance is invalid."""
    artifact_type = provenance.get("artifact_type")
    if artifact_type != ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_ARTIFACT_TYPE:
        return (
            f"requirements extraction scaffold provenance artifact_type mismatch: "
            f"expected {ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_ARTIFACT_TYPE!r}, "
            f"found {artifact_type!r}"
        )

    provenance_plan_id = provenance.get("plan_id")
    if provenance_plan_id != plan_id:
        return (
            f"requirements extraction scaffold provenance plan_id mismatch: "
            f"expected {plan_id!r}, found {provenance_plan_id!r}"
        )

    provenance_intake_id = provenance.get("intake_id")
    if provenance_intake_id != intake_id:
        return (
            f"requirements extraction scaffold provenance intake_id mismatch: "
            f"expected {intake_id!r}, found {provenance_intake_id!r}"
        )

    if (
        provenance.get("local_agentic_spec_status")
        != REQUIREMENTS_EXTRACTION_SCAFFOLD_STATUS
    ):
        return (
            "requirements extraction scaffold provenance local_agentic_spec_status is not "
            "REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY"
        )

    if provenance.get("planning_workspace_status_at_scaffold") != "DRAFT":
        return (
            "requirements extraction scaffold provenance "
            "planning_workspace_status_at_scaffold is not DRAFT"
        )

    if (
        provenance.get("source_requirements_extraction_preflight_state")
        != REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE
    ):
        return (
            "requirements extraction scaffold provenance "
            "source_requirements_extraction_preflight_state is not "
            "REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NO_REQUIREMENTS_GENERATED"
        )

    if (
        provenance.get("source_requirements_extraction_preflight_next_action")
        != REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NEXT_ACTION
    ):
        return (
            "requirements extraction scaffold provenance "
            "source_requirements_extraction_preflight_next_action is not "
            "FUTURE_REQUIREMENTS_EXTRACTION_REQUIRES_SEPARATE_COMMAND"
        )

    non_authority = provenance.get("non_authority")
    if not isinstance(non_authority, dict):
        return (
            "requirements extraction scaffold provenance non_authority must be an object"
        )
    for flag in ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY_FLAGS:
        if non_authority.get(flag) is not True:
            return (
                f"requirements extraction scaffold provenance non_authority.{flag} "
                "must be true"
            )

    return None


def _validate_requirements_extraction_post_scaffold_coherence(
    project: Path,
    intake_id: str,
    plan_id: str,
    *,
    scaffold_provenance: dict,
) -> None:
    """Fail closed when post-scaffold requirements extraction gates are no longer coherent."""
    workspace_dest = planning_path(project, plan_id)

    draft_preflight_report = preflight_draft_preparation(project, intake_id)
    if (
        draft_preflight_report.preflight_state
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE
    ):
        raise ValueError(
            "requirements extraction preflight not confirmed: "
            f"{draft_preflight_report.preflight_state}"
        )
    if draft_preflight_report.latest_decision == "REQUEST_MORE_CLARIFICATION":
        raise ValueError(
            "latest readiness decision requests clarification; "
            "requirements extraction preflight not confirmed"
        )
    if draft_preflight_report.latest_decision == "BLOCK_INTAKE":
        raise ValueError(
            "latest readiness decision blocks intake; "
            "requirements extraction preflight not confirmed"
        )
    if draft_preflight_report.latest_decision != "AUTHORIZE_DRAFT_PREPARATION":
        raise ValueError(
            "latest readiness decision is not AUTHORIZE_DRAFT_PREPARATION; "
            "requirements extraction preflight not confirmed"
        )

    if (
        scaffold_provenance.get("source_requirements_extraction_preflight_state")
        != REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE
    ):
        raise ValueError(
            "requirements extraction preflight not confirmed: "
            f"{scaffold_provenance.get('source_requirements_extraction_preflight_state')!r}"
        )
    if (
        scaffold_provenance.get("source_requirements_extraction_preflight_next_action")
        != REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NEXT_ACTION
    ):
        raise ValueError(
            "requirements extraction preflight next action not expected: "
            f"{scaffold_provenance.get('source_requirements_extraction_preflight_next_action')!r}"
        )

    workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    if workspace_status != "DRAFT":
        raise ValueError(
            f"planning workspace must be DRAFT for requirements extraction owner "
            f"decision, found: {workspace_status!r}"
        )

    local_agentic_spec_path = workspace_dest / "local-agentic-spec.md"
    if not local_agentic_spec_path.is_file():
        raise FileNotFoundError(
            f"local-agentic-spec.md missing in planning workspace: {plan_id}"
        )

    local_spec_content = local_agentic_spec_path.read_text(encoding="utf-8")
    if not _is_local_agentic_spec_requirements_extraction_scaffold_non_authority(
        local_spec_content,
        plan_id,
    ):
        raise ValueError(
            "local-agentic-spec.md is not REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY "
            f"for plan: {plan_id}"
        )
    if not _requirements_extraction_scaffold_boundary_notes_present(local_spec_content):
        raise ValueError(
            "requirements extraction scaffold is incoherent: "
            "local-agentic-spec.md missing required boundary notes "
            f"for plan: {plan_id}"
        )
    if not _local_agentic_spec_contains_only_requirements_extraction_scaffold_sections(
        local_spec_content
    ):
        raise ValueError(
            "requirements extraction scaffold is incoherent: "
            "local-agentic-spec.md no longer contains only scaffold/pending sections "
            f"for plan: {plan_id}"
        )
    if _local_agentic_spec_has_generated_functional_requirements(local_spec_content):
        raise ValueError(
            f"local-agentic-spec.md already contains requirements for plan: {plan_id}"
        )
    if _local_agentic_spec_has_user_stories(local_spec_content):
        raise ValueError(
            f"local-agentic-spec.md already contains user stories for plan: {plan_id}"
        )
    if _local_agentic_spec_has_generated_acceptance_criteria(local_spec_content):
        raise ValueError(
            "local-agentic-spec.md already contains acceptance criteria "
            f"for plan: {plan_id}"
        )
    if _local_agentic_spec_has_architecture_decision_language(local_spec_content):
        raise ValueError(
            "local-agentic-spec.md already contains architecture decision language "
            f"for plan: {plan_id}"
        )
    if _local_agentic_spec_has_implementation_tasks(local_spec_content):
        raise ValueError(
            f"local-agentic-spec.md already contains implementation tasks for plan: {plan_id}"
        )
    if _local_agentic_spec_has_planning_run_slice_content(local_spec_content):
        raise ValueError(
            f"local-agentic-spec.md already contains PLANNING_RUN_SLICE content "
            f"for plan: {plan_id}"
        )

    implementation_plan_path = workspace_dest / "implementation-plan.md"
    planning_audit_path = workspace_dest / "planning-audit.md"
    if not implementation_plan_path.is_file():
        raise FileNotFoundError(
            f"implementation-plan.md missing in planning workspace: {plan_id}"
        )
    if not planning_audit_path.is_file():
        raise FileNotFoundError(
            f"planning-audit.md missing in planning workspace: {plan_id}"
        )
    if not _is_planning_artifact_init_placeholder(
        implementation_plan_path.read_text(encoding="utf-8"),
        plan_id,
        "implementation-plan.md",
        artifact_type="IMPLEMENTATION_PLAN",
    ):
        raise ValueError(
            "requirements extraction scaffold is incoherent: "
            f"implementation-plan.md already modified for plan: {plan_id}"
        )
    if not _is_planning_artifact_init_placeholder(
        planning_audit_path.read_text(encoding="utf-8"),
        plan_id,
        "planning-audit.md",
        artifact_type="PLANNING_AUDIT",
        identity_field="auditor",
    ):
        raise ValueError(
            "requirements extraction scaffold is incoherent: "
            f"planning-audit.md already modified for plan: {plan_id}"
        )


def _validate_local_agentic_spec_scaffold_provenance(
    provenance: dict,
    *,
    plan_id: str,
    intake_id: str,
) -> str | None:
    """Return a blocking reason when local-agentic-spec scaffold provenance is invalid."""
    artifact_type = provenance.get("artifact_type")
    if artifact_type != ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE_ARTIFACT_TYPE:
        return (
            f"local agentic spec scaffold provenance artifact_type mismatch: "
            f"expected {ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE_ARTIFACT_TYPE!r}, "
            f"found {artifact_type!r}"
        )

    provenance_plan_id = provenance.get("plan_id")
    if provenance_plan_id != plan_id:
        return (
            f"local agentic spec scaffold provenance plan_id mismatch: "
            f"expected {plan_id!r}, found {provenance_plan_id!r}"
        )

    provenance_intake_id = provenance.get("intake_id")
    if provenance_intake_id != intake_id:
        return (
            f"local agentic spec scaffold provenance intake_id mismatch: "
            f"expected {intake_id!r}, found {provenance_intake_id!r}"
        )

    if provenance.get("local_agentic_spec_status") != LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS:
        return (
            "local agentic spec scaffold provenance local_agentic_spec_status is not "
            "SCAFFOLD_DRAFT_NON_AUTHORITY"
        )

    if provenance.get("planning_workspace_status_at_scaffold") != "DRAFT":
        return (
            "local agentic spec scaffold provenance "
            "planning_workspace_status_at_scaffold is not DRAFT"
        )

    if (
        provenance.get("source_preflight_state")
        != LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_STATE
    ):
        return (
            "local agentic spec scaffold provenance source_preflight_state is not "
            "LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_NO_SPEC_GENERATED"
        )

    if (
        provenance.get("source_preflight_next_action")
        != LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_NEXT_ACTION
    ):
        return (
            "local agentic spec scaffold provenance source_preflight_next_action is not "
            "FUTURE_LOCAL_AGENTIC_SPEC_DRAFT_REQUIRES_SEPARATE_COMMAND"
        )

    non_authority = provenance.get("non_authority")
    if not isinstance(non_authority, dict):
        return "local agentic spec scaffold provenance non_authority must be an object"
    for flag in ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_NON_AUTHORITY_FLAGS:
        if non_authority.get(flag) is not True:
            return f"local agentic spec scaffold provenance non_authority.{flag} must be true"

    return None


def _format_local_agentic_spec_draft_preflight(
    *,
    plan_id: str,
    intake_id: str,
    planning_workspace_status: str | None,
    context_pack_status: str | None,
    context_pack_path: Path | None,
    context_pack_provenance_path: Path | None,
    local_agentic_spec_path: Path | None,
    implementation_plan_path: Path | None,
    planning_audit_path: Path | None,
    latest_decision_id: str | None,
    latest_decision: str | None,
    source_preflight_state: str | None,
    preflight_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
    checked_at: str,
    non_authority: dict[str, bool],
) -> str:
    lines = [
        "local-agentic-spec draft preflight",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
    ]
    if planning_workspace_status is not None:
        lines.append(f"planning_workspace_status: {planning_workspace_status}")
    if context_pack_status is not None:
        lines.append(f"context_pack_status: {context_pack_status}")
    if context_pack_path is not None:
        lines.append(f"context_pack_path: {context_pack_path}")
    if context_pack_provenance_path is not None:
        lines.append(
            f"context_pack_provenance_path: {context_pack_provenance_path}"
        )
    if local_agentic_spec_path is not None:
        lines.append(f"local_agentic_spec_path: {local_agentic_spec_path}")
    if implementation_plan_path is not None:
        lines.append(f"implementation_plan_path: {implementation_plan_path}")
    if planning_audit_path is not None:
        lines.append(f"planning_audit_path: {planning_audit_path}")
    if latest_decision_id is not None:
        lines.append(f"latest_decision_id: {latest_decision_id}")
    if latest_decision is not None:
        lines.append(f"latest_decision: {latest_decision}")
    if source_preflight_state is not None:
        lines.append(f"source_preflight_state: {source_preflight_state}")
    lines.append(f"preflight_state: {preflight_state}")
    lines.append(f"next_required_action: {next_required_action}")
    lines.append(f"checked_at: {checked_at}")
    if blocking_reasons:
        lines.append("blocking_reasons:")
        for reason in blocking_reasons:
            lines.append(f"  - {reason}")
    lines.append("non_authority:")
    for flag in LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_NON_AUTHORITY_FLAGS:
        lines.append(f"  {flag}: true")
    lines.append(
        "note: local-agentic-spec draft preflight is read-only; "
        "not local agentic spec generation, not architecture decision, "
        "not implementation planning, not validation or approval, "
        "and no files were modified"
    )
    if preflight_state == LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_STATE:
        lines.append(
            "note: preflight confirmed for a future local-agentic-spec draft command "
            "only; no local agentic spec was generated"
        )
        lines.append(
            "note: context pack remains DRAFT_NON_AUTHORITY source context; "
            "architecture undecided; implementation plan not generated; "
            "PLANNING_RUN_SLICE not generated; workspace not validated or approved"
        )
    return "\n".join(lines)


@dataclass(frozen=True)
class LocalAgenticSpecDraftPreflightReport:
    output: str
    preflight_state: str
    next_required_action: str
    plan_id: str
    intake_id: str
    planning_workspace_status: str | None
    context_pack_status: str | None
    context_pack_path: Path | None
    context_pack_provenance_path: Path | None
    local_agentic_spec_path: Path | None
    implementation_plan_path: Path | None
    planning_audit_path: Path | None
    latest_decision_id: str | None
    latest_decision: str | None
    source_preflight_state: str | None
    checked_at: str
    blocking_reasons: tuple[str, ...]
    non_authority: dict[str, bool]


def _build_local_agentic_spec_preflight_report(
    *,
    plan_id: str,
    intake_id: str,
    planning_workspace_status: str | None = None,
    context_pack_status: str | None = None,
    context_pack_path: Path | None = None,
    context_pack_provenance_path: Path | None = None,
    local_agentic_spec_path: Path | None = None,
    implementation_plan_path: Path | None = None,
    planning_audit_path: Path | None = None,
    latest_decision_id: str | None = None,
    latest_decision: str | None = None,
    source_preflight_state: str | None = None,
    preflight_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
    checked_at: str,
    non_authority: dict[str, bool],
) -> LocalAgenticSpecDraftPreflightReport:
    output = _format_local_agentic_spec_draft_preflight(
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=planning_workspace_status,
        context_pack_status=context_pack_status,
        context_pack_path=context_pack_path,
        context_pack_provenance_path=context_pack_provenance_path,
        local_agentic_spec_path=local_agentic_spec_path,
        implementation_plan_path=implementation_plan_path,
        planning_audit_path=planning_audit_path,
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
        source_preflight_state=source_preflight_state,
        preflight_state=preflight_state,
        next_required_action=next_required_action,
        blocking_reasons=blocking_reasons,
        checked_at=checked_at,
        non_authority=non_authority,
    )
    return LocalAgenticSpecDraftPreflightReport(
        output=output,
        preflight_state=preflight_state,
        next_required_action=next_required_action,
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=planning_workspace_status,
        context_pack_status=context_pack_status,
        context_pack_path=context_pack_path,
        context_pack_provenance_path=context_pack_provenance_path,
        local_agentic_spec_path=local_agentic_spec_path,
        implementation_plan_path=implementation_plan_path,
        planning_audit_path=planning_audit_path,
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
        source_preflight_state=source_preflight_state,
        checked_at=checked_at,
        blocking_reasons=tuple(blocking_reasons),
        non_authority=non_authority,
    )


def preflight_local_agentic_spec_draft(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> LocalAgenticSpecDraftPreflightReport:
    """Read-only local-agentic-spec draft eligibility preflight for a DRAFT workspace."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    checked_at = _utc_now()
    non_authority = {
        key: True for key in LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_NON_AUTHORITY_FLAGS
    }
    workspace_dest = planning_path(project, plan_id)
    context_pack_path = workspace_dest / "context-pack.md"
    context_pack_provenance_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_FILE
    )
    local_agentic_spec_path = workspace_dest / "local-agentic-spec.md"
    implementation_plan_path = workspace_dest / "implementation-plan.md"
    planning_audit_path = workspace_dest / "planning-audit.md"
    provenance_path = workspace_dest / "evidence" / ORCHESTRATOR_PROVENANCE_FILE
    transport_json_path = workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_TRANSPORT_FILE
    transport_md_path = workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_TRANSPORT_MD_FILE

    def _blocked(
        state: str,
        next_action: str,
        *,
        blocking_reasons: list[str] | None = None,
        planning_workspace_status: str | None = None,
        context_pack_status: str | None = None,
        latest_decision_id: str | None = None,
        latest_decision: str | None = None,
        source_preflight_state: str | None = None,
    ) -> LocalAgenticSpecDraftPreflightReport:
        return _build_local_agentic_spec_preflight_report(
            plan_id=plan_id,
            intake_id=intake_id,
            planning_workspace_status=planning_workspace_status,
            context_pack_status=context_pack_status,
            context_pack_path=context_pack_path,
            context_pack_provenance_path=context_pack_provenance_path,
            local_agentic_spec_path=local_agentic_spec_path,
            implementation_plan_path=implementation_plan_path,
            planning_audit_path=planning_audit_path,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            preflight_state=state,
            next_required_action=next_action,
            blocking_reasons=blocking_reasons or [],
            checked_at=checked_at,
            non_authority=non_authority,
        )

    workspace = workspace_path(project)
    if not workspace.is_dir():
        return _blocked(
            "BLOCKED_MISSING_WORKSPACE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            blocking_reasons=["no workspace found (run `agent-os init` first)"],
        )

    intake_path = _goal_intake_artifact_path(project, intake_id)
    if not intake_path.is_file():
        return _blocked(
            "BLOCKED_INVALID_INTAKE",
            "FIX_GOAL_INTAKE_STRUCTURE",
            blocking_reasons=[f"goal intake artifact not found: {intake_id}"],
        )

    readiness_report = review_goal_intake_readiness(project, intake_id)
    if not readiness_report.goal_intake_valid:
        return _blocked(
            "BLOCKED_INVALID_INTAKE",
            "FIX_GOAL_INTAKE_STRUCTURE",
            blocking_reasons=list(readiness_report.blocking_reasons),
        )

    if not workspace_dest.is_dir():
        return _blocked(
            "BLOCKED_MISSING_PLANNING_WORKSPACE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            blocking_reasons=[f"planning workspace not found: {plan_id}"],
        )

    try:
        workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    except (FileNotFoundError, ValueError) as exc:
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            blocking_reasons=[str(exc)],
        )

    if workspace_status != "DRAFT":
        return _blocked(
            "BLOCKED_WORKSPACE_NOT_DRAFT",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            planning_workspace_status=workspace_status,
            blocking_reasons=[
                f"planning workspace must be DRAFT for local-agentic-spec draft "
                f"preflight, found: {workspace_status!r}"
            ],
        )

    draft_preflight_report = preflight_draft_preparation(project, intake_id)
    latest_decision_id = draft_preflight_report.latest_decision_id
    latest_decision = draft_preflight_report.latest_decision
    source_preflight_state = draft_preflight_report.preflight_state

    if latest_decision == "REQUEST_MORE_CLARIFICATION":
        return _blocked(
            "BLOCKED_LATEST_DECISION_REQUESTS_CLARIFICATION",
            "ADD_OWNER_CLARIFICATION",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )
    if latest_decision == "BLOCK_INTAKE":
        return _blocked(
            "BLOCKED_LATEST_DECISION_BLOCKS_INTAKE",
            "STOP_INTAKE",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )
    if (
        draft_preflight_report.preflight_state
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE
        or latest_decision != "AUTHORIZE_DRAFT_PREPARATION"
    ):
        return _blocked(
            "BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT",
            "RESOLVE_OR_REPLACE_READINESS_DECISION",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=list(draft_preflight_report.blocking_reasons),
        )

    if not provenance_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_ORCHESTRATOR_PROVENANCE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"invalid orchestrator provenance for planning workspace {plan_id}: "
                f"{exc.msg}"
            ],
        )

    if not isinstance(provenance, dict):
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"invalid orchestrator provenance for planning workspace {plan_id}: "
                "expected object"
            ],
        )

    provenance_plan_id = provenance.get("plan_id")
    if provenance_plan_id != plan_id:
        return _blocked(
            "BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT",
            "RESOLVE_OR_REPLACE_READINESS_DECISION",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"orchestrator provenance plan_id mismatch: "
                f"expected {plan_id!r}, found {provenance_plan_id!r}"
            ],
        )

    provenance_intake_id = provenance.get("intake_id")
    if provenance_intake_id != intake_id:
        return _blocked(
            "BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT",
            "RESOLVE_OR_REPLACE_READINESS_DECISION",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"orchestrator provenance intake_id mismatch: "
                f"expected {intake_id!r}, found {provenance_intake_id!r}"
            ],
        )

    try:
        _require_orchestrator_provenance_for_transport(
            provenance_path,
            plan_id=plan_id,
            intake_id=intake_id,
            preflight_report=draft_preflight_report,
        )
    except ValueError as exc:
        return _blocked(
            "BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT",
            "RESOLVE_OR_REPLACE_READINESS_DECISION",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[str(exc)],
        )

    if not transport_json_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_CONTEXT_TRANSPORT",
            "FIX_OR_RECREATE_CONTEXT_PACK_DRAFT",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"context transport json not found for planning workspace: {plan_id}"
            ],
        )

    if not transport_md_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_CONTEXT_TRANSPORT",
            "FIX_OR_RECREATE_CONTEXT_PACK_DRAFT",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"context transport markdown not found for planning workspace: {plan_id}"
            ],
        )

    try:
        transport = _require_context_transport_for_draft(
            transport_json_path,
            plan_id=plan_id,
            intake_id=intake_id,
        )
    except (ValueError, FileNotFoundError) as exc:
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_CONTEXT_PACK_DRAFT",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[str(exc)],
        )

    if not context_pack_provenance_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_CONTEXT_PACK_DRAFT_PROVENANCE",
            "FIX_OR_RECREATE_CONTEXT_PACK_DRAFT",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    try:
        draft_provenance = json.loads(
            context_pack_provenance_path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_CONTEXT_PACK_DRAFT",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"invalid context pack draft provenance for planning workspace "
                f"{plan_id}: {exc.msg}"
            ],
        )

    if not isinstance(draft_provenance, dict):
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_CONTEXT_PACK_DRAFT",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"invalid context pack draft provenance for planning workspace "
                f"{plan_id}: expected object"
            ],
        )

    provenance_error = _validate_context_pack_draft_provenance(
        draft_provenance,
        plan_id=plan_id,
        intake_id=intake_id,
    )
    if provenance_error is not None:
        mismatch = "mismatch" in provenance_error
        return _blocked(
            "BLOCKED_CONTEXT_PACK_PROVENANCE_MISMATCH"
            if mismatch
            else "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_CONTEXT_PACK_DRAFT",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[provenance_error],
        )

    if not context_pack_path.is_file():
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_CONTEXT_PACK_DRAFT",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[f"context-pack.md missing in planning workspace: {plan_id}"],
        )

    context_pack_content = context_pack_path.read_text(encoding="utf-8")
    if not _is_context_pack_draft_non_authority(context_pack_content, plan_id):
        return _blocked(
            "BLOCKED_CONTEXT_PACK_NOT_DRAFT_NON_AUTHORITY",
            "FIX_OR_RECREATE_CONTEXT_PACK_DRAFT",
            planning_workspace_status=workspace_status,
            context_pack_status=None,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    if not _context_pack_boundary_notes_present(context_pack_content):
        return _blocked(
            "BLOCKED_CONTEXT_PACK_BOUNDARY_NOTES_MISSING",
            "FIX_OR_RECREATE_CONTEXT_PACK_DRAFT",
            planning_workspace_status=workspace_status,
            context_pack_status=CONTEXT_PACK_DRAFT_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    if not local_agentic_spec_path.is_file():
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            context_pack_status=CONTEXT_PACK_DRAFT_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"local-agentic-spec.md missing in planning workspace: {plan_id}"
            ],
        )

    if not _is_planning_artifact_init_placeholder(
        local_agentic_spec_path.read_text(encoding="utf-8"),
        plan_id,
        "local-agentic-spec.md",
        artifact_type="LOCAL_AGENTIC_SPEC",
    ):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_MODIFIED",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            context_pack_status=CONTEXT_PACK_DRAFT_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    if not implementation_plan_path.is_file():
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            context_pack_status=CONTEXT_PACK_DRAFT_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"implementation-plan.md missing in planning workspace: {plan_id}"
            ],
        )

    if not _is_planning_artifact_init_placeholder(
        implementation_plan_path.read_text(encoding="utf-8"),
        plan_id,
        "implementation-plan.md",
        artifact_type="IMPLEMENTATION_PLAN",
    ):
        return _blocked(
            "BLOCKED_IMPLEMENTATION_PLAN_ALREADY_MODIFIED",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            context_pack_status=CONTEXT_PACK_DRAFT_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    if not planning_audit_path.is_file():
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            context_pack_status=CONTEXT_PACK_DRAFT_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"planning-audit.md missing in planning workspace: {plan_id}"
            ],
        )

    if not _is_planning_artifact_init_placeholder(
        planning_audit_path.read_text(encoding="utf-8"),
        plan_id,
        "planning-audit.md",
        artifact_type="PLANNING_AUDIT",
        identity_field="auditor",
    ):
        return _blocked(
            "BLOCKED_PLANNING_AUDIT_ALREADY_MODIFIED",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            context_pack_status=CONTEXT_PACK_DRAFT_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    return _build_local_agentic_spec_preflight_report(
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=workspace_status,
        context_pack_status=CONTEXT_PACK_DRAFT_STATUS,
        context_pack_path=context_pack_path,
        context_pack_provenance_path=context_pack_provenance_path,
        local_agentic_spec_path=local_agentic_spec_path,
        implementation_plan_path=implementation_plan_path,
        planning_audit_path=planning_audit_path,
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
        source_preflight_state=source_preflight_state,
        preflight_state=LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_STATE,
        next_required_action=LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_NEXT_ACTION,
        blocking_reasons=[],
        checked_at=checked_at,
        non_authority=non_authority,
    )


def _build_local_agentic_spec_scaffold_markdown(
    *,
    plan_id: str,
    intake_id: str,
    context_pack_path: Path,
    context_pack_provenance_path: Path,
    source_preflight_state: str,
    source_preflight_next_action: str,
    created_at: str,
) -> str:
    lines = [
        "---",
        f"plan_id: {plan_id}",
        "artifact_type: LOCAL_AGENTIC_SPEC",
        f"local_agentic_spec_status: {LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS}",
        f"intake_id: {intake_id}",
        f"created_at: {created_at}",
        "author: ORCHESTRATOR_SCAFFOLD_NON_AUTHORITY",
        "version: 1",
        "---",
        "",
        "# Local Agentic Spec (SCAFFOLD — DRAFT_NON_AUTHORITY)",
        "",
        "> **Planning artifact type:** `LOCAL_AGENTIC_SPEC`",
        "> **Status:** `SCAFFOLD_DRAFT_NON_AUTHORITY` — structure, provenance, and "
        "boundaries only; not functional requirements, not architecture, not "
        "implementation plan.",
        "",
        "## Source identifiers",
        "",
        f"- **plan_id:** `{plan_id}`",
        f"- **intake_id:** `{intake_id}`",
        f"- **source context-pack:** `{context_pack_path}`",
        (
            "- **source context-pack draft provenance:** "
            f"`{context_pack_provenance_path}`"
        ),
        "",
        "## Preflight reference",
        "",
        f"- **source_preflight_state:** `{source_preflight_state}`",
        f"- **source_preflight_next_action:** `{source_preflight_next_action}`",
        "",
        "## Explicit boundaries",
        "",
        "- **requirements extraction:** not performed",
        "- **architecture:** undecided — `UNDECIDED_NOT_GENERATED`",
        "- **implementation plan:** not generated — `NOT_GENERATED`",
        "- **PLANNING_RUN_SLICE:** not generated — `NOT_GENERATED`",
        "- **planning workspace:** not validated or approved",
        "- **runner proposals / runs / executor:** not created or invoked",
        "- **future independent validation:** required",
        "- **future owner approval:** required",
        "",
        "## Spec sections (pending future owner-authorized extraction)",
        "",
        "| Section | Status |",
        "|---------|--------|",
        "| Functional Requirements | PENDING_FUTURE_REQUIREMENTS_EXTRACTION |",
        "| Non-Functional Requirements | PENDING_FUTURE_REQUIREMENTS_EXTRACTION |",
        "| Constraints | PENDING_FUTURE_REQUIREMENTS_EXTRACTION |",
        "| Out of Scope | PENDING_FUTURE_REQUIREMENTS_EXTRACTION |",
        "| Interfaces | PENDING_FUTURE_REQUIREMENTS_EXTRACTION |",
        "| Acceptance Criteria | NOT_GENERATED |",
        "| Architecture | UNDECIDED_NOT_GENERATED |",
        "| Implementation Plan | NOT_GENERATED |",
        "| PLANNING_RUN_SLICE | NOT_GENERATED |",
        "",
        "This scaffold provides structure, provenance references, and boundaries only. "
        "It does not extract requirements, infer product scope, define architecture, or "
        "generate implementation tasks. Source artifacts are referenced by path only — "
        "no requirement content was copied from context-pack or intake material.",
    ]
    return "\n".join(lines) + "\n"


def _build_local_agentic_spec_scaffold_provenance_artifact(
    *,
    plan_id: str,
    intake_id: str,
    context_pack_path: Path,
    context_pack_provenance_path: Path,
    local_agentic_spec_path: Path,
    preflight_report: LocalAgenticSpecDraftPreflightReport,
    draft_preflight_report: DraftPreparationPreflightReport,
    workspace_status: str,
    created_at: str,
) -> dict:
    return {
        "artifact_type": ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE_ARTIFACT_TYPE,
        "schema_version": ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE_SCHEMA_VERSION,
        "plan_id": plan_id,
        "intake_id": intake_id,
        "source_context_pack_path": str(context_pack_path),
        "source_context_pack_draft_provenance_path": str(context_pack_provenance_path),
        "source_preflight_state": preflight_report.preflight_state,
        "source_preflight_next_action": preflight_report.next_required_action,
        "source_authorize_decision_id": draft_preflight_report.latest_decision_id,
        "local_agentic_spec_path": str(local_agentic_spec_path),
        "local_agentic_spec_status": LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
        "planning_workspace_status_at_scaffold": workspace_status,
        "created_at": created_at,
        "non_authority": {
            key: True for key in ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_NON_AUTHORITY_FLAGS
        },
    }


def _format_scaffolded_local_agentic_spec(
    *,
    local_agentic_spec_path: Path,
    provenance_path: Path,
    plan_id: str,
    intake_id: str,
    workspace_status: str,
) -> str:
    lines = [
        (
            "orchestrator local-agentic-spec scaffold created: "
            f"{local_agentic_spec_path.parent.parent}"
        ),
        f"local agentic spec: {local_agentic_spec_path}",
        f"local agentic spec scaffold provenance: {provenance_path}",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
        f"local_agentic_spec_status: {LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS}",
        f"workspace_status: {workspace_status}",
        "note: local-agentic-spec scaffold only; structure, provenance, and boundaries",
        "note: no requirements extraction, no architecture generation, "
        "no implementation plan generation, no PLANNING_RUN_SLICE",
        "note: planning workspace not validated or approved; "
        "no runner proposals, runs, or executor invocation",
        "note: orchestrator intake artifacts, transport artifacts, context-pack draft "
        "provenance, and context-pack.md were not modified; future requirements "
        "extraction, architecture decision, independent validation, and owner "
        "approval remain required",
    ]
    return "\n".join(lines)


@dataclass(frozen=True)
class ScaffoldedLocalAgenticSpecReport:
    output: str
    plan_id: str
    intake_id: str
    local_agentic_spec_path: Path
    provenance_path: Path
    local_agentic_spec_status: str
    workspace_status: str
    non_authority: dict[str, bool]


def scaffold_local_agentic_spec_from_context_pack(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> ScaffoldedLocalAgenticSpecReport:
    """Scaffold local-agentic-spec.md with structure/boundaries only (no requirements)."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    _require_valid_goal_intake(project, intake_id)

    workspace_dest = planning_path(project, plan_id)
    if not workspace_dest.is_dir():
        raise FileNotFoundError(f"planning workspace not found: {plan_id}")

    workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    if workspace_status != "DRAFT":
        raise ValueError(
            f"planning workspace must be DRAFT for local-agentic-spec scaffold, found: "
            f"{workspace_status!r}"
        )

    preflight_report = preflight_local_agentic_spec_draft(project, intake_id, plan_id)
    if (
        preflight_report.preflight_state
        != LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_STATE
    ):
        reasons = "; ".join(preflight_report.blocking_reasons)
        detail = f": {reasons}" if reasons else ""
        raise ValueError(
            "local-agentic-spec draft preflight not confirmed: "
            f"{preflight_report.preflight_state}{detail}"
        )
    if (
        preflight_report.next_required_action
        != LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_NEXT_ACTION
    ):
        raise ValueError(
            "local-agentic-spec draft preflight next action not expected: "
            f"{preflight_report.next_required_action!r} "
            f"(expected {LOCAL_AGENTIC_SPEC_DRAFT_PREFLIGHT_CONFIRMED_NEXT_ACTION!r})"
        )

    draft_preflight_report = preflight_draft_preparation(project, intake_id)
    if (
        draft_preflight_report.preflight_state
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE
    ):
        raise ValueError(
            "draft-preparation preflight not confirmed: "
            f"{draft_preflight_report.preflight_state}"
        )
    if draft_preflight_report.latest_decision != "AUTHORIZE_DRAFT_PREPARATION":
        raise ValueError(
            "latest readiness decision is not AUTHORIZE_DRAFT_PREPARATION"
        )
    if draft_preflight_report.latest_decision_id is None:
        raise ValueError("missing authorize decision id in preflight report")

    context_pack_path = workspace_dest / "context-pack.md"
    context_pack_provenance_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_FILE
    )
    local_agentic_spec_path = workspace_dest / "local-agentic-spec.md"
    implementation_plan_path = workspace_dest / "implementation-plan.md"
    planning_audit_path = workspace_dest / "planning-audit.md"

    if not context_pack_path.is_file():
        raise FileNotFoundError(
            f"context-pack.md missing in planning workspace: {plan_id}"
        )
    if not context_pack_provenance_path.is_file():
        raise FileNotFoundError(
            f"context pack draft provenance not found for planning workspace: {plan_id}"
        )
    if not local_agentic_spec_path.is_file():
        raise FileNotFoundError(
            f"local-agentic-spec.md missing in planning workspace: {plan_id}"
        )
    if not implementation_plan_path.is_file():
        raise FileNotFoundError(
            f"implementation-plan.md missing in planning workspace: {plan_id}"
        )
    if not planning_audit_path.is_file():
        raise FileNotFoundError(
            f"planning-audit.md missing in planning workspace: {plan_id}"
        )

    original_local_spec = local_agentic_spec_path.read_bytes()
    if not _is_planning_artifact_init_placeholder(
        original_local_spec.decode("utf-8"),
        plan_id,
        "local-agentic-spec.md",
        artifact_type="LOCAL_AGENTIC_SPEC",
    ):
        raise FileExistsError(
            f"local-agentic-spec.md already drafted or modified for plan: {plan_id}"
        )

    if not _is_planning_artifact_init_placeholder(
        implementation_plan_path.read_text(encoding="utf-8"),
        plan_id,
        "implementation-plan.md",
        artifact_type="IMPLEMENTATION_PLAN",
    ):
        raise FileExistsError(
            f"implementation-plan.md already modified for plan: {plan_id}"
        )

    if not _is_planning_artifact_init_placeholder(
        planning_audit_path.read_text(encoding="utf-8"),
        plan_id,
        "planning-audit.md",
        artifact_type="PLANNING_AUDIT",
        identity_field="auditor",
    ):
        raise FileExistsError(
            f"planning-audit.md already modified for plan: {plan_id}"
        )

    scaffold_provenance_path = (
        workspace_dest
        / "evidence"
        / ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE_FILE
    )
    if scaffold_provenance_path.exists():
        raise FileExistsError(
            f"local-agentic-spec scaffold provenance already exists for plan: {plan_id}"
        )

    created_at = _utc_now()
    scaffold_markdown = _build_local_agentic_spec_scaffold_markdown(
        plan_id=plan_id,
        intake_id=intake_id,
        context_pack_path=context_pack_path,
        context_pack_provenance_path=context_pack_provenance_path,
        source_preflight_state=preflight_report.preflight_state,
        source_preflight_next_action=preflight_report.next_required_action,
        created_at=created_at,
    )
    provenance_artifact = _build_local_agentic_spec_scaffold_provenance_artifact(
        plan_id=plan_id,
        intake_id=intake_id,
        context_pack_path=context_pack_path,
        context_pack_provenance_path=context_pack_provenance_path,
        local_agentic_spec_path=local_agentic_spec_path,
        preflight_report=preflight_report,
        draft_preflight_report=draft_preflight_report,
        workspace_status=workspace_status,
        created_at=created_at,
    )

    temp_local_spec = local_agentic_spec_path.with_suffix(".md.tmp")
    try:
        temp_local_spec.write_text(scaffold_markdown, encoding="utf-8")
        temp_local_spec.replace(local_agentic_spec_path)
        try:
            _write_json(scaffold_provenance_path, provenance_artifact)
        except Exception:
            local_agentic_spec_path.write_bytes(original_local_spec)
            if scaffold_provenance_path.is_file():
                scaffold_provenance_path.unlink()
            raise
    except Exception:
        if temp_local_spec.is_file():
            temp_local_spec.unlink()
        if local_agentic_spec_path.read_bytes() != original_local_spec:
            local_agentic_spec_path.write_bytes(original_local_spec)
        if scaffold_provenance_path.is_file():
            scaffold_provenance_path.unlink()
        raise

    non_authority = {
        key: True for key in ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_NON_AUTHORITY_FLAGS
    }
    output = _format_scaffolded_local_agentic_spec(
        local_agentic_spec_path=local_agentic_spec_path,
        provenance_path=scaffold_provenance_path,
        plan_id=plan_id,
        intake_id=intake_id,
        workspace_status=workspace_status,
    )
    return ScaffoldedLocalAgenticSpecReport(
        output=output,
        plan_id=plan_id,
        intake_id=intake_id,
        local_agentic_spec_path=local_agentic_spec_path,
        provenance_path=scaffold_provenance_path,
        local_agentic_spec_status=LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
        workspace_status=workspace_status,
        non_authority=non_authority,
    )


def _format_requirements_extraction_preflight(
    *,
    plan_id: str,
    intake_id: str,
    planning_workspace_status: str | None,
    local_agentic_spec_status: str | None,
    local_agentic_spec_path: Path | None,
    local_agentic_spec_scaffold_provenance_path: Path | None,
    context_pack_path: Path | None,
    context_pack_provenance_path: Path | None,
    implementation_plan_path: Path | None,
    planning_audit_path: Path | None,
    latest_decision_id: str | None,
    latest_decision: str | None,
    source_preflight_state: str | None,
    preflight_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
    checked_at: str,
    non_authority: dict[str, bool],
) -> str:
    lines = [
        "requirements extraction preflight",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
    ]
    if planning_workspace_status is not None:
        lines.append(f"planning_workspace_status: {planning_workspace_status}")
    if local_agentic_spec_status is not None:
        lines.append(f"local_agentic_spec_status: {local_agentic_spec_status}")
    if local_agentic_spec_path is not None:
        lines.append(f"local_agentic_spec_path: {local_agentic_spec_path}")
    if local_agentic_spec_scaffold_provenance_path is not None:
        lines.append(
            "local_agentic_spec_scaffold_provenance_path: "
            f"{local_agentic_spec_scaffold_provenance_path}"
        )
    if context_pack_path is not None:
        lines.append(f"context_pack_path: {context_pack_path}")
    if context_pack_provenance_path is not None:
        lines.append(f"context_pack_provenance_path: {context_pack_provenance_path}")
    if implementation_plan_path is not None:
        lines.append(f"implementation_plan_path: {implementation_plan_path}")
    if planning_audit_path is not None:
        lines.append(f"planning_audit_path: {planning_audit_path}")
    if latest_decision_id is not None:
        lines.append(f"latest_decision_id: {latest_decision_id}")
    if latest_decision is not None:
        lines.append(f"latest_decision: {latest_decision}")
    if source_preflight_state is not None:
        lines.append(f"source_preflight_state: {source_preflight_state}")
    lines.append(f"preflight_state: {preflight_state}")
    lines.append(f"next_required_action: {next_required_action}")
    lines.append(f"checked_at: {checked_at}")
    if blocking_reasons:
        lines.append("blocking_reasons:")
        for reason in blocking_reasons:
            lines.append(f"  - {reason}")
    lines.append("non_authority:")
    for flag in REQUIREMENTS_EXTRACTION_PREFLIGHT_NON_AUTHORITY_FLAGS:
        lines.append(f"  {flag}: true")
    lines.append(
        "note: requirements extraction preflight is read-only; "
        "not requirements extraction, not architecture decision, "
        "not implementation planning, not validation or approval, "
        "and no files were modified"
    )
    if preflight_state == REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE:
        lines.append(
            "note: preflight confirmed for a future requirements extraction command "
            "only; no requirements were extracted or generated"
        )
        lines.append(
            "note: local-agentic-spec remains SCAFFOLD_DRAFT_NON_AUTHORITY; "
            "architecture undecided; implementation plan not generated; "
            "PLANNING_RUN_SLICE not generated; workspace not validated or approved"
        )
    return "\n".join(lines)


@dataclass(frozen=True)
class RequirementsExtractionPreflightReport:
    output: str
    preflight_state: str
    next_required_action: str
    plan_id: str
    intake_id: str
    planning_workspace_status: str | None
    local_agentic_spec_status: str | None
    local_agentic_spec_path: Path | None
    local_agentic_spec_scaffold_provenance_path: Path | None
    context_pack_path: Path | None
    context_pack_provenance_path: Path | None
    implementation_plan_path: Path | None
    planning_audit_path: Path | None
    latest_decision_id: str | None
    latest_decision: str | None
    source_preflight_state: str | None
    checked_at: str
    blocking_reasons: tuple[str, ...]
    non_authority: dict[str, bool]


def _build_requirements_extraction_preflight_report(
    *,
    plan_id: str,
    intake_id: str,
    planning_workspace_status: str | None = None,
    local_agentic_spec_status: str | None = None,
    local_agentic_spec_path: Path | None = None,
    local_agentic_spec_scaffold_provenance_path: Path | None = None,
    context_pack_path: Path | None = None,
    context_pack_provenance_path: Path | None = None,
    implementation_plan_path: Path | None = None,
    planning_audit_path: Path | None = None,
    latest_decision_id: str | None = None,
    latest_decision: str | None = None,
    source_preflight_state: str | None = None,
    preflight_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
    checked_at: str,
    non_authority: dict[str, bool],
) -> RequirementsExtractionPreflightReport:
    output = _format_requirements_extraction_preflight(
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=planning_workspace_status,
        local_agentic_spec_status=local_agentic_spec_status,
        local_agentic_spec_path=local_agentic_spec_path,
        local_agentic_spec_scaffold_provenance_path=local_agentic_spec_scaffold_provenance_path,
        context_pack_path=context_pack_path,
        context_pack_provenance_path=context_pack_provenance_path,
        implementation_plan_path=implementation_plan_path,
        planning_audit_path=planning_audit_path,
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
        source_preflight_state=source_preflight_state,
        preflight_state=preflight_state,
        next_required_action=next_required_action,
        blocking_reasons=blocking_reasons,
        checked_at=checked_at,
        non_authority=non_authority,
    )
    return RequirementsExtractionPreflightReport(
        output=output,
        preflight_state=preflight_state,
        next_required_action=next_required_action,
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=planning_workspace_status,
        local_agentic_spec_status=local_agentic_spec_status,
        local_agentic_spec_path=local_agentic_spec_path,
        local_agentic_spec_scaffold_provenance_path=local_agentic_spec_scaffold_provenance_path,
        context_pack_path=context_pack_path,
        context_pack_provenance_path=context_pack_provenance_path,
        implementation_plan_path=implementation_plan_path,
        planning_audit_path=planning_audit_path,
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
        source_preflight_state=source_preflight_state,
        checked_at=checked_at,
        blocking_reasons=tuple(blocking_reasons),
        non_authority=non_authority,
    )


def preflight_requirements_extraction(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> RequirementsExtractionPreflightReport:
    """Read-only requirements extraction eligibility preflight for a DRAFT workspace."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    checked_at = _utc_now()
    non_authority = {
        key: True for key in REQUIREMENTS_EXTRACTION_PREFLIGHT_NON_AUTHORITY_FLAGS
    }
    workspace_dest = planning_path(project, plan_id)
    context_pack_path = workspace_dest / "context-pack.md"
    context_pack_provenance_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_FILE
    )
    local_agentic_spec_path = workspace_dest / "local-agentic-spec.md"
    local_agentic_spec_scaffold_provenance_path = (
        workspace_dest
        / "evidence"
        / ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE_FILE
    )
    implementation_plan_path = workspace_dest / "implementation-plan.md"
    planning_audit_path = workspace_dest / "planning-audit.md"
    provenance_path = workspace_dest / "evidence" / ORCHESTRATOR_PROVENANCE_FILE
    transport_json_path = workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_TRANSPORT_FILE
    transport_md_path = workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_TRANSPORT_MD_FILE

    def _blocked(
        state: str,
        next_action: str,
        *,
        blocking_reasons: list[str] | None = None,
        planning_workspace_status: str | None = None,
        local_agentic_spec_status: str | None = None,
        latest_decision_id: str | None = None,
        latest_decision: str | None = None,
        source_preflight_state: str | None = None,
    ) -> RequirementsExtractionPreflightReport:
        return _build_requirements_extraction_preflight_report(
            plan_id=plan_id,
            intake_id=intake_id,
            planning_workspace_status=planning_workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            local_agentic_spec_path=local_agentic_spec_path,
            local_agentic_spec_scaffold_provenance_path=local_agentic_spec_scaffold_provenance_path,
            context_pack_path=context_pack_path,
            context_pack_provenance_path=context_pack_provenance_path,
            implementation_plan_path=implementation_plan_path,
            planning_audit_path=planning_audit_path,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            preflight_state=state,
            next_required_action=next_action,
            blocking_reasons=blocking_reasons or [],
            checked_at=checked_at,
            non_authority=non_authority,
        )

    workspace = workspace_path(project)
    if not workspace.is_dir():
        return _blocked(
            "BLOCKED_MISSING_WORKSPACE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            blocking_reasons=["no workspace found (run `agent-os init` first)"],
        )

    intake_path = _goal_intake_artifact_path(project, intake_id)
    if not intake_path.is_file():
        return _blocked(
            "BLOCKED_INVALID_INTAKE",
            "FIX_GOAL_INTAKE_STRUCTURE",
            blocking_reasons=[f"goal intake artifact not found: {intake_id}"],
        )

    readiness_report = review_goal_intake_readiness(project, intake_id)
    if not readiness_report.goal_intake_valid:
        return _blocked(
            "BLOCKED_INVALID_INTAKE",
            "FIX_GOAL_INTAKE_STRUCTURE",
            blocking_reasons=list(readiness_report.blocking_reasons),
        )

    if not workspace_dest.is_dir():
        return _blocked(
            "BLOCKED_MISSING_PLANNING_WORKSPACE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            blocking_reasons=[f"planning workspace not found: {plan_id}"],
        )

    try:
        workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    except (FileNotFoundError, ValueError) as exc:
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            blocking_reasons=[str(exc)],
        )

    if workspace_status != "DRAFT":
        return _blocked(
            "BLOCKED_WORKSPACE_NOT_DRAFT",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            planning_workspace_status=workspace_status,
            blocking_reasons=[
                f"planning workspace must be DRAFT for requirements extraction "
                f"preflight, found: {workspace_status!r}"
            ],
        )

    draft_preflight_report = preflight_draft_preparation(project, intake_id)
    latest_decision_id = draft_preflight_report.latest_decision_id
    latest_decision = draft_preflight_report.latest_decision
    source_preflight_state = draft_preflight_report.preflight_state

    if latest_decision == "REQUEST_MORE_CLARIFICATION":
        return _blocked(
            "BLOCKED_LATEST_DECISION_REQUESTS_CLARIFICATION",
            "ADD_OWNER_CLARIFICATION",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )
    if latest_decision == "BLOCK_INTAKE":
        return _blocked(
            "BLOCKED_LATEST_DECISION_BLOCKS_INTAKE",
            "STOP_INTAKE",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )
    if (
        draft_preflight_report.preflight_state
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE
        or latest_decision != "AUTHORIZE_DRAFT_PREPARATION"
    ):
        return _blocked(
            "BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT",
            "RESOLVE_OR_REPLACE_READINESS_DECISION",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=list(draft_preflight_report.blocking_reasons),
        )

    if not provenance_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_ORCHESTRATOR_PROVENANCE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"invalid orchestrator provenance for planning workspace {plan_id}: "
                f"{exc.msg}"
            ],
        )

    if not isinstance(provenance, dict):
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"invalid orchestrator provenance for planning workspace {plan_id}: "
                "expected object"
            ],
        )

    provenance_plan_id = provenance.get("plan_id")
    if provenance_plan_id != plan_id:
        return _blocked(
            "BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT",
            "RESOLVE_OR_REPLACE_READINESS_DECISION",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"orchestrator provenance plan_id mismatch: "
                f"expected {plan_id!r}, found {provenance_plan_id!r}"
            ],
        )

    provenance_intake_id = provenance.get("intake_id")
    if provenance_intake_id != intake_id:
        return _blocked(
            "BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT",
            "RESOLVE_OR_REPLACE_READINESS_DECISION",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"orchestrator provenance intake_id mismatch: "
                f"expected {intake_id!r}, found {provenance_intake_id!r}"
            ],
        )

    try:
        _require_orchestrator_provenance_for_transport(
            provenance_path,
            plan_id=plan_id,
            intake_id=intake_id,
            preflight_report=draft_preflight_report,
        )
    except ValueError as exc:
        return _blocked(
            "BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT",
            "RESOLVE_OR_REPLACE_READINESS_DECISION",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[str(exc)],
        )

    if not transport_json_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_CONTEXT_TRANSPORT",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"context transport json not found for planning workspace: {plan_id}"
            ],
        )

    if not transport_md_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_CONTEXT_TRANSPORT",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"context transport markdown not found for planning workspace: {plan_id}"
            ],
        )

    try:
        _require_context_transport_for_draft(
            transport_json_path,
            plan_id=plan_id,
            intake_id=intake_id,
        )
    except (ValueError, FileNotFoundError) as exc:
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[str(exc)],
        )

    if not context_pack_provenance_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_CONTEXT_PACK_DRAFT_PROVENANCE",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    try:
        draft_provenance = json.loads(
            context_pack_provenance_path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"invalid context pack draft provenance for planning workspace "
                f"{plan_id}: {exc.msg}"
            ],
        )

    if not isinstance(draft_provenance, dict):
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"invalid context pack draft provenance for planning workspace "
                f"{plan_id}: expected object"
            ],
        )

    provenance_error = _validate_context_pack_draft_provenance(
        draft_provenance,
        plan_id=plan_id,
        intake_id=intake_id,
    )
    if provenance_error is not None:
        mismatch = "mismatch" in provenance_error
        return _blocked(
            "BLOCKED_CONTEXT_PACK_PROVENANCE_MISMATCH"
            if mismatch
            else "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[provenance_error],
        )

    if not local_agentic_spec_scaffold_provenance_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    try:
        scaffold_provenance = json.loads(
            local_agentic_spec_scaffold_provenance_path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"invalid local agentic spec scaffold provenance for planning workspace "
                f"{plan_id}: {exc.msg}"
            ],
        )

    if not isinstance(scaffold_provenance, dict):
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"invalid local agentic spec scaffold provenance for planning workspace "
                f"{plan_id}: expected object"
            ],
        )

    scaffold_provenance_error = _validate_local_agentic_spec_scaffold_provenance(
        scaffold_provenance,
        plan_id=plan_id,
        intake_id=intake_id,
    )
    if scaffold_provenance_error is not None:
        mismatch = "mismatch" in scaffold_provenance_error
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_PROVENANCE_MISMATCH"
            if mismatch
            else "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[scaffold_provenance_error],
        )

    if not context_pack_path.is_file():
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[f"context-pack.md missing in planning workspace: {plan_id}"],
        )

    if not local_agentic_spec_path.is_file():
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"local-agentic-spec.md missing in planning workspace: {plan_id}"
            ],
        )

    local_spec_content = local_agentic_spec_path.read_text(encoding="utf-8")
    if not _is_local_agentic_spec_scaffold_non_authority(local_spec_content, plan_id):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_NOT_SCAFFOLD_DRAFT_NON_AUTHORITY",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=None,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    if not _local_agentic_spec_scaffold_boundary_notes_present(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_BOUNDARY_NOTES_MISSING",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    if _local_agentic_spec_has_generated_functional_requirements(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_REQUIREMENTS",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    if _local_agentic_spec_has_user_stories(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_USER_STORIES",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    if _local_agentic_spec_has_generated_acceptance_criteria(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_ACCEPTANCE_CRITERIA",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    if not _local_agentic_spec_contains_only_scaffold_sections(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_REQUIREMENTS",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                "local-agentic-spec.md no longer contains only scaffold/pending sections"
            ],
        )

    if _local_agentic_spec_has_architecture_decision_language(local_spec_content):
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_OR_RECREATE_LOCAL_AGENTIC_SPEC_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                "local-agentic-spec appears to contain architecture decision language"
            ],
        )

    if not implementation_plan_path.is_file():
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"implementation-plan.md missing in planning workspace: {plan_id}"
            ],
        )

    if not _is_planning_artifact_init_placeholder(
        implementation_plan_path.read_text(encoding="utf-8"),
        plan_id,
        "implementation-plan.md",
        artifact_type="IMPLEMENTATION_PLAN",
    ):
        return _blocked(
            "BLOCKED_IMPLEMENTATION_PLAN_ALREADY_MODIFIED",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    if not planning_audit_path.is_file():
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
            blocking_reasons=[
                f"planning-audit.md missing in planning workspace: {plan_id}"
            ],
        )

    if not _is_planning_artifact_init_placeholder(
        planning_audit_path.read_text(encoding="utf-8"),
        plan_id,
        "planning-audit.md",
        artifact_type="PLANNING_AUDIT",
        identity_field="auditor",
    ):
        return _blocked(
            "BLOCKED_PLANNING_AUDIT_ALREADY_MODIFIED",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
            latest_decision_id=latest_decision_id,
            latest_decision=latest_decision,
            source_preflight_state=source_preflight_state,
        )

    return _build_requirements_extraction_preflight_report(
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=workspace_status,
        local_agentic_spec_status=LOCAL_AGENTIC_SPEC_SCAFFOLD_STATUS,
        local_agentic_spec_path=local_agentic_spec_path,
        local_agentic_spec_scaffold_provenance_path=local_agentic_spec_scaffold_provenance_path,
        context_pack_path=context_pack_path,
        context_pack_provenance_path=context_pack_provenance_path,
        implementation_plan_path=implementation_plan_path,
        planning_audit_path=planning_audit_path,
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
        source_preflight_state=source_preflight_state,
        preflight_state=REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE,
        next_required_action=REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NEXT_ACTION,
        blocking_reasons=[],
        checked_at=checked_at,
        non_authority=non_authority,
    )


def _build_requirements_extraction_scaffold_markdown(
    *,
    plan_id: str,
    intake_id: str,
    context_pack_path: Path,
    local_agentic_spec_scaffold_provenance_path: Path,
    source_preflight_state: str,
    source_preflight_next_action: str,
    created_at: str,
) -> str:
    lines = [
        "---",
        f"plan_id: {plan_id}",
        "artifact_type: LOCAL_AGENTIC_SPEC",
        f"local_agentic_spec_status: {REQUIREMENTS_EXTRACTION_SCAFFOLD_STATUS}",
        f"intake_id: {intake_id}",
        f"created_at: {created_at}",
        "author: ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY",
        "version: 1",
        "---",
        "",
        "# Local Agentic Spec (REQUIREMENTS_EXTRACTION_SCAFFOLD — DRAFT_NON_AUTHORITY)",
        "",
        "> **Planning artifact type:** `LOCAL_AGENTIC_SPEC`",
        "> **Status:** `REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY` — empty "
        "requirements-extraction containers, provenance, and boundaries only; not "
        "extracted requirements, not user stories, not acceptance criteria, not "
        "architecture, not implementation plan.",
        "",
        "## Source identifiers",
        "",
        f"- **plan_id:** `{plan_id}`",
        f"- **intake_id:** `{intake_id}`",
        f"- **source context-pack:** `{context_pack_path}`",
        (
            "- **source local-agentic-spec scaffold provenance:** "
            f"`{local_agentic_spec_scaffold_provenance_path}`"
        ),
        "",
        "## Requirements extraction preflight reference",
        "",
        f"- **source_requirements_extraction_preflight_state:** `{source_preflight_state}`",
        (
            "- **source_requirements_extraction_preflight_next_action:** "
            f"`{source_preflight_next_action}`"
        ),
        "",
        "## Explicit boundaries",
        "",
        "- **requirements extraction:** not performed",
        "- **future requirements extraction:** requires a separate command",
        "- **architecture:** undecided — `UNDECIDED_NOT_GENERATED`",
        "- **implementation plan:** not generated — `NOT_GENERATED`",
        "- **PLANNING_RUN_SLICE:** not generated — `NOT_GENERATED`",
        "- **planning workspace:** not validated or approved",
        "- **runner proposals / runs / executor:** not created or invoked",
        "- **future independent validation:** required",
        "- **future owner approval:** required",
        "",
        "## Requirements containers (empty — no extraction performed)",
        "",
        "| Section | Status |",
        "|---------|--------|",
        "| Functional Requirements | NO_REQUIREMENTS_EXTRACTED |",
        "| Non-Functional Requirements | NO_REQUIREMENTS_EXTRACTED |",
        "| Constraints | NO_REQUIREMENTS_EXTRACTED |",
        "| Out of Scope | NO_REQUIREMENTS_EXTRACTED |",
        "| Interfaces | NO_REQUIREMENTS_EXTRACTED |",
        "| User Stories | NOT_GENERATED |",
        "| Acceptance Criteria | NOT_GENERATED |",
        "| Architecture | UNDECIDED_NOT_GENERATED |",
        "| Implementation Plan | NOT_GENERATED |",
        "| PLANNING_RUN_SLICE | NOT_GENERATED |",
        "",
        "This requirements-extraction scaffold provides empty containers, provenance "
        "references, and boundaries only. It does not extract or infer requirements, "
        "generate user stories or acceptance criteria, define architecture, or "
        "generate implementation tasks. Source artifacts are referenced by path only — "
        "no requirement content was copied from context-pack, intake, or prior "
        "scaffold material. A future separate requirements extraction command is "
        "required before any requirements content may be added.",
    ]
    return "\n".join(lines) + "\n"


def _build_requirements_extraction_scaffold_provenance_artifact(
    *,
    plan_id: str,
    intake_id: str,
    context_pack_path: Path,
    local_agentic_spec_scaffold_provenance_path: Path,
    local_agentic_spec_path: Path,
    preflight_report: RequirementsExtractionPreflightReport,
    draft_preflight_report: DraftPreparationPreflightReport,
    workspace_status: str,
    created_at: str,
) -> dict:
    return {
        "artifact_type": ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_ARTIFACT_TYPE,
        "schema_version": ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_SCHEMA_VERSION,
        "plan_id": plan_id,
        "intake_id": intake_id,
        "source_local_agentic_spec_scaffold_provenance_path": str(
            local_agentic_spec_scaffold_provenance_path
        ),
        "source_context_pack_path": str(context_pack_path),
        "source_requirements_extraction_preflight_state": preflight_report.preflight_state,
        "source_requirements_extraction_preflight_next_action": (
            preflight_report.next_required_action
        ),
        "source_authorize_decision_id": draft_preflight_report.latest_decision_id,
        "local_agentic_spec_path": str(local_agentic_spec_path),
        "local_agentic_spec_status": REQUIREMENTS_EXTRACTION_SCAFFOLD_STATUS,
        "planning_workspace_status_at_scaffold": workspace_status,
        "created_at": created_at,
        "non_authority": {
            key: True
            for key in ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY_FLAGS
        },
    }


def _format_scaffolded_requirements_extraction(
    *,
    local_agentic_spec_path: Path,
    provenance_path: Path,
    plan_id: str,
    intake_id: str,
    workspace_status: str,
) -> str:
    lines = [
        (
            "orchestrator requirements-extraction scaffold created: "
            f"{local_agentic_spec_path.parent.parent}"
        ),
        f"local agentic spec: {local_agentic_spec_path}",
        (
            "requirements extraction scaffold provenance: "
            f"{provenance_path}"
        ),
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
        f"local_agentic_spec_status: {REQUIREMENTS_EXTRACTION_SCAFFOLD_STATUS}",
        f"workspace_status: {workspace_status}",
        (
            "note: requirements-extraction scaffold only; empty containers, "
            "provenance, and boundaries"
        ),
        "note: no requirements extraction, no user stories, no acceptance criteria, "
        "no architecture generation, no implementation plan generation, "
        "no PLANNING_RUN_SLICE",
        "note: planning workspace not validated or approved; "
        "no runner proposals, runs, or executor invocation",
        "note: orchestrator intake artifacts, transport artifacts, context-pack "
        "draft provenance, local-agentic-spec scaffold provenance, context-pack.md, "
        "implementation-plan.md, and planning-audit.md were not modified; future "
        "requirements extraction, architecture decision, independent validation, and "
        "owner approval remain required",
    ]
    return "\n".join(lines)


@dataclass(frozen=True)
class ScaffoldedRequirementsExtractionReport:
    output: str
    plan_id: str
    intake_id: str
    local_agentic_spec_path: Path
    provenance_path: Path
    local_agentic_spec_status: str
    workspace_status: str
    non_authority: dict[str, bool]


def scaffold_requirements_extraction(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> ScaffoldedRequirementsExtractionReport:
    """Scaffold local-agentic-spec.md with empty requirements containers only."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    _require_valid_goal_intake(project, intake_id)

    workspace_dest = planning_path(project, plan_id)
    if not workspace_dest.is_dir():
        raise FileNotFoundError(f"planning workspace not found: {plan_id}")

    workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    if workspace_status != "DRAFT":
        raise ValueError(
            f"planning workspace must be DRAFT for requirements-extraction scaffold, "
            f"found: {workspace_status!r}"
        )

    preflight_report = preflight_requirements_extraction(project, intake_id, plan_id)
    if (
        preflight_report.preflight_state
        != REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE
    ):
        reasons = "; ".join(preflight_report.blocking_reasons)
        detail = f": {reasons}" if reasons else ""
        raise ValueError(
            "requirements extraction preflight not confirmed: "
            f"{preflight_report.preflight_state}{detail}"
        )
    if (
        preflight_report.next_required_action
        != REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NEXT_ACTION
    ):
        raise ValueError(
            "requirements extraction preflight next action not expected: "
            f"{preflight_report.next_required_action!r} "
            f"(expected {REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NEXT_ACTION!r})"
        )

    draft_preflight_report = preflight_draft_preparation(project, intake_id)
    if (
        draft_preflight_report.preflight_state
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE
    ):
        raise ValueError(
            "draft-preparation preflight not confirmed: "
            f"{draft_preflight_report.preflight_state}"
        )
    if draft_preflight_report.latest_decision != "AUTHORIZE_DRAFT_PREPARATION":
        raise ValueError(
            "latest readiness decision is not AUTHORIZE_DRAFT_PREPARATION"
        )
    if draft_preflight_report.latest_decision_id is None:
        raise ValueError("missing authorize decision id in preflight report")

    context_pack_path = workspace_dest / "context-pack.md"
    context_pack_provenance_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_PACK_DRAFT_PROVENANCE_FILE
    )
    local_agentic_spec_path = workspace_dest / "local-agentic-spec.md"
    local_agentic_spec_scaffold_provenance_path = (
        workspace_dest
        / "evidence"
        / ORCHESTRATOR_LOCAL_AGENTIC_SPEC_SCAFFOLD_PROVENANCE_FILE
    )
    implementation_plan_path = workspace_dest / "implementation-plan.md"
    planning_audit_path = workspace_dest / "planning-audit.md"

    if not context_pack_path.is_file():
        raise FileNotFoundError(
            f"context-pack.md missing in planning workspace: {plan_id}"
        )
    if not context_pack_provenance_path.is_file():
        raise FileNotFoundError(
            f"context pack draft provenance not found for planning workspace: {plan_id}"
        )
    if not local_agentic_spec_path.is_file():
        raise FileNotFoundError(
            f"local-agentic-spec.md missing in planning workspace: {plan_id}"
        )
    if not local_agentic_spec_scaffold_provenance_path.is_file():
        raise FileNotFoundError(
            "local-agentic-spec scaffold provenance not found for planning workspace: "
            f"{plan_id}"
        )
    if not implementation_plan_path.is_file():
        raise FileNotFoundError(
            f"implementation-plan.md missing in planning workspace: {plan_id}"
        )
    if not planning_audit_path.is_file():
        raise FileNotFoundError(
            f"planning-audit.md missing in planning workspace: {plan_id}"
        )

    local_spec_content = local_agentic_spec_path.read_text(encoding="utf-8")
    if not _is_local_agentic_spec_scaffold_non_authority(local_spec_content, plan_id):
        raise ValueError(
            "local-agentic-spec.md is not SCAFFOLD_DRAFT_NON_AUTHORITY "
            f"for plan: {plan_id}"
        )
    if not _local_agentic_spec_scaffold_boundary_notes_present(local_spec_content):
        raise ValueError(
            "local-agentic-spec.md missing required scaffold boundary notes "
            f"for plan: {plan_id}"
        )
    if _local_agentic_spec_has_generated_functional_requirements(local_spec_content):
        raise ValueError(
            f"local-agentic-spec.md already contains requirements for plan: {plan_id}"
        )
    if _local_agentic_spec_has_user_stories(local_spec_content):
        raise ValueError(
            f"local-agentic-spec.md already contains user stories for plan: {plan_id}"
        )
    if _local_agentic_spec_has_generated_acceptance_criteria(local_spec_content):
        raise ValueError(
            "local-agentic-spec.md already contains acceptance criteria "
            f"for plan: {plan_id}"
        )
    if _local_agentic_spec_has_architecture_decision_language(local_spec_content):
        raise ValueError(
            "local-agentic-spec.md already contains architecture decision language "
            f"for plan: {plan_id}"
        )
    if not _local_agentic_spec_contains_only_scaffold_sections(local_spec_content):
        raise ValueError(
            "local-agentic-spec.md no longer contains only scaffold/pending sections "
            f"for plan: {plan_id}"
        )

    if not _is_planning_artifact_init_placeholder(
        implementation_plan_path.read_text(encoding="utf-8"),
        plan_id,
        "implementation-plan.md",
        artifact_type="IMPLEMENTATION_PLAN",
    ):
        raise FileExistsError(
            f"implementation-plan.md already modified for plan: {plan_id}"
        )

    if not _is_planning_artifact_init_placeholder(
        planning_audit_path.read_text(encoding="utf-8"),
        plan_id,
        "planning-audit.md",
        artifact_type="PLANNING_AUDIT",
        identity_field="auditor",
    ):
        raise FileExistsError(
            f"planning-audit.md already modified for plan: {plan_id}"
        )

    requirements_scaffold_provenance_path = (
        workspace_dest
        / "evidence"
        / ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_FILE
    )
    if requirements_scaffold_provenance_path.exists():
        raise FileExistsError(
            "requirements extraction scaffold provenance already exists for plan: "
            f"{plan_id}"
        )

    created_at = _utc_now()
    scaffold_markdown = _build_requirements_extraction_scaffold_markdown(
        plan_id=plan_id,
        intake_id=intake_id,
        context_pack_path=context_pack_path,
        local_agentic_spec_scaffold_provenance_path=local_agentic_spec_scaffold_provenance_path,
        source_preflight_state=preflight_report.preflight_state,
        source_preflight_next_action=preflight_report.next_required_action,
        created_at=created_at,
    )
    provenance_artifact = _build_requirements_extraction_scaffold_provenance_artifact(
        plan_id=plan_id,
        intake_id=intake_id,
        context_pack_path=context_pack_path,
        local_agentic_spec_scaffold_provenance_path=local_agentic_spec_scaffold_provenance_path,
        local_agentic_spec_path=local_agentic_spec_path,
        preflight_report=preflight_report,
        draft_preflight_report=draft_preflight_report,
        workspace_status=workspace_status,
        created_at=created_at,
    )

    original_local_spec = local_agentic_spec_path.read_bytes()
    temp_local_spec = local_agentic_spec_path.with_suffix(".md.tmp")
    try:
        temp_local_spec.write_text(scaffold_markdown, encoding="utf-8")
        temp_local_spec.replace(local_agentic_spec_path)
        try:
            _write_json(requirements_scaffold_provenance_path, provenance_artifact)
        except Exception:
            local_agentic_spec_path.write_bytes(original_local_spec)
            if requirements_scaffold_provenance_path.is_file():
                requirements_scaffold_provenance_path.unlink()
            raise
    except Exception:
        if temp_local_spec.is_file():
            temp_local_spec.unlink()
        if local_agentic_spec_path.read_bytes() != original_local_spec:
            local_agentic_spec_path.write_bytes(original_local_spec)
        if requirements_scaffold_provenance_path.is_file():
            requirements_scaffold_provenance_path.unlink()
        raise

    non_authority = {
        key: True
        for key in ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_NON_AUTHORITY_FLAGS
    }
    output = _format_scaffolded_requirements_extraction(
        local_agentic_spec_path=local_agentic_spec_path,
        provenance_path=requirements_scaffold_provenance_path,
        plan_id=plan_id,
        intake_id=intake_id,
        workspace_status=workspace_status,
    )
    return ScaffoldedRequirementsExtractionReport(
        output=output,
        plan_id=plan_id,
        intake_id=intake_id,
        local_agentic_spec_path=local_agentic_spec_path,
        provenance_path=requirements_scaffold_provenance_path,
        local_agentic_spec_status=REQUIREMENTS_EXTRACTION_SCAFFOLD_STATUS,
        workspace_status=workspace_status,
        non_authority=non_authority,
    )


@dataclass(frozen=True)
class RequirementsExtractionOwnerDecisionRecord:
    decision_id: str
    decision: str
    created_at: str
    path: Path


@dataclass(frozen=True)
class RequirementsExtractionOwnerDecisionValidationReport:
    output: str
    valid: bool
    errors: tuple[str, ...]


@dataclass(frozen=True)
class RequirementsExtractionOwnerDecisionReport:
    output: str
    decision_path: Path
    plan_id: str
    intake_id: str
    decision_id: str
    decision: str
    workspace_status: str
    latest_decision_id: str | None
    latest_decision: str | None
    non_authority: dict[str, bool]


def build_requirements_extraction_owner_decision_artifact(
    intake_id: str,
    plan_id: str,
    decision_id: str,
    decision: str,
    owner_summary: str,
    *,
    source_requirements_extraction_scaffold_provenance_path: str,
    source_requirements_extraction_scaffold_status: str,
    source_requirements_extraction_scaffold_created_at: str,
    source_requirements_extraction_preflight_state: str,
    source_requirements_extraction_preflight_next_action: str,
    planning_workspace_status_at_decision: str,
    created_at: str | None = None,
) -> dict:
    """Build the deterministic REQUIREMENTS_EXTRACTION_OWNER_DECISION artifact payload."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)
    validate_requirements_extraction_decision_id(decision_id)
    if decision not in REQUIREMENTS_EXTRACTION_OWNER_DECISION_VALUES:
        raise ValueError(f"unsupported decision value: {decision!r}")
    if not owner_summary:
        raise ValueError("owner summary must not be empty")

    return {
        "artifact_type": REQUIREMENTS_EXTRACTION_OWNER_DECISION_ARTIFACT_TYPE,
        "schema_version": REQUIREMENTS_EXTRACTION_OWNER_DECISION_SCHEMA_VERSION,
        "intake_id": intake_id,
        "plan_id": plan_id,
        "decision_id": decision_id,
        "decision": decision,
        "owner_summary": owner_summary,
        "created_at": created_at or _utc_now(),
        "source_requirements_extraction_scaffold_provenance_path": (
            source_requirements_extraction_scaffold_provenance_path
        ),
        "source_requirements_extraction_scaffold_status": (
            source_requirements_extraction_scaffold_status
        ),
        "source_requirements_extraction_scaffold_created_at": (
            source_requirements_extraction_scaffold_created_at
        ),
        "source_requirements_extraction_preflight_state": (
            source_requirements_extraction_preflight_state
        ),
        "source_requirements_extraction_preflight_next_action": (
            source_requirements_extraction_preflight_next_action
        ),
        "planning_workspace_status_at_decision": planning_workspace_status_at_decision,
        "non_authority": {
            key: True
            for key in REQUIREMENTS_EXTRACTION_OWNER_DECISION_NON_AUTHORITY_FLAGS
        },
    }


def _validate_requirements_extraction_owner_decision_payload(
    artifact: object,
    intake_id: str,
    plan_id: str,
    decision_id: str,
) -> list[str]:
    """Return structural validation errors for REQUIREMENTS_EXTRACTION_OWNER_DECISION."""
    errors: list[str] = []

    if not isinstance(artifact, dict):
        return ["requirements extraction owner decision artifact must be a JSON object"]

    for field in REQUIREMENTS_EXTRACTION_OWNER_DECISION_REQUIRED_FIELDS:
        if field not in artifact:
            errors.append(f"missing required field: {field}")

    artifact_type = artifact.get("artifact_type")
    if (
        artifact_type is not None
        and artifact_type != REQUIREMENTS_EXTRACTION_OWNER_DECISION_ARTIFACT_TYPE
    ):
        errors.append(
            f"wrong artifact_type: expected "
            f"{REQUIREMENTS_EXTRACTION_OWNER_DECISION_ARTIFACT_TYPE!r}, "
            f"found {artifact_type!r}"
        )

    schema_version = artifact.get("schema_version")
    if (
        schema_version is not None
        and schema_version != REQUIREMENTS_EXTRACTION_OWNER_DECISION_SCHEMA_VERSION
    ):
        errors.append(
            f"unsupported schema_version: expected "
            f"{REQUIREMENTS_EXTRACTION_OWNER_DECISION_SCHEMA_VERSION!r}, "
            f"found {schema_version!r}"
        )

    artifact_intake_id = artifact.get("intake_id")
    if isinstance(artifact_intake_id, str) and artifact_intake_id != intake_id:
        errors.append(
            "intake_id mismatch: "
            f"path {intake_id!r}, artifact {artifact_intake_id!r}"
        )

    artifact_plan_id = artifact.get("plan_id")
    if isinstance(artifact_plan_id, str) and artifact_plan_id != plan_id:
        errors.append(
            f"plan_id mismatch: path {plan_id!r}, artifact {artifact_plan_id!r}"
        )

    artifact_decision_id = artifact.get("decision_id")
    if isinstance(artifact_decision_id, str) and artifact_decision_id != decision_id:
        errors.append(
            "decision_id mismatch: "
            f"path {decision_id!r}, artifact {artifact_decision_id!r}"
        )

    decision = artifact.get("decision")
    if decision is not None and decision not in REQUIREMENTS_EXTRACTION_OWNER_DECISION_VALUES:
        errors.append(f"invalid decision value: {decision!r}")

    owner_summary = artifact.get("owner_summary")
    if owner_summary is not None:
        error = _non_empty_string(owner_summary, "owner_summary")
        if error:
            errors.append(error)

    created_at = artifact.get("created_at")
    if created_at is not None and not _parse_created_at(created_at):
        errors.append("created_at must be a parseable ISO-8601 timestamp")

    non_authority = artifact.get("non_authority")
    if non_authority is None:
        errors.append("missing required field: non_authority")
    elif not isinstance(non_authority, dict):
        errors.append("non_authority must be an object")
    else:
        for flag in REQUIREMENTS_EXTRACTION_OWNER_DECISION_NON_AUTHORITY_FLAGS:
            if flag not in non_authority:
                errors.append(f"missing non_authority flag: {flag}")
            elif non_authority[flag] is not True:
                errors.append(f"non_authority flag must be true: {flag}")

    return errors


def _format_requirements_extraction_owner_decision(
    *,
    decision_path: Path,
    plan_id: str,
    intake_id: str,
    decision_id: str,
    decision: str,
    workspace_status: str,
    latest_decision_id: str | None,
    latest_decision: str | None,
) -> str:
    lines = [
        f"created requirements extraction owner decision artifact: {decision_path}",
        f"artifact_type: {REQUIREMENTS_EXTRACTION_OWNER_DECISION_ARTIFACT_TYPE}",
        f"decision_id: {decision_id}",
        f"decision: {decision}",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
        f"planning_workspace_status: {workspace_status}",
    ]
    if latest_decision_id is not None:
        lines.append(f"latest_requirements_extraction_decision_id: {latest_decision_id}")
    if latest_decision is not None:
        lines.append(f"latest_requirements_extraction_decision: {latest_decision}")
    lines.extend(
        [
            "mode: owner-provided requirements extraction decision only",
            "note: no LLM, no requirements extraction, no requirements approval, "
            "no architecture decision, no implementation plan, no PLANNING_RUN_SLICE, "
            "no validation or approval, no runner proposals, no runs, "
            "no executor invocation",
            "note: does not mutate local-agentic-spec.md, context-pack.md, "
            "implementation-plan.md, planning-audit.md, or evidence artifacts",
        ]
    )
    if decision == "AUTHORIZE_REQUIREMENTS_EXTRACTION":
        lines.append(
            "note: AUTHORIZE_REQUIREMENTS_EXTRACTION authorizes only a future "
            "separate requirements extraction command; authorization is not extraction"
        )
    return "\n".join(lines)


def create_requirements_extraction_owner_decision(
    project: Path,
    intake_id: str,
    plan_id: str,
    decision_id: str,
    decision: str,
    owner_summary: str,
) -> RequirementsExtractionOwnerDecisionReport:
    """Record a REQUIREMENTS_EXTRACTION_OWNER_DECISION without mutating planning artifacts."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)
    validate_requirements_extraction_decision_id(decision_id)
    if decision not in REQUIREMENTS_EXTRACTION_OWNER_DECISION_VALUES:
        raise ValueError(f"unsupported decision value: {decision!r}")
    if not owner_summary:
        raise ValueError("owner summary must not be empty")

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    _require_valid_goal_intake(project, intake_id)

    workspace_dest = planning_path(project, plan_id)
    if not workspace_dest.is_dir():
        raise FileNotFoundError(f"planning workspace not found: {plan_id}")

    workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    if workspace_status != "DRAFT":
        raise ValueError(
            f"planning workspace must be DRAFT for requirements extraction owner "
            f"decision, found: {workspace_status!r}"
        )

    requirements_scaffold_provenance_path = (
        workspace_dest
        / "evidence"
        / ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_FILE
    )
    if not requirements_scaffold_provenance_path.is_file():
        raise FileNotFoundError(
            "requirements extraction scaffold provenance not found for planning "
            f"workspace: {plan_id}"
        )

    try:
        scaffold_provenance = json.loads(
            requirements_scaffold_provenance_path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid requirements extraction scaffold provenance for planning "
            f"workspace {plan_id}: {exc.msg}"
        ) from exc

    if not isinstance(scaffold_provenance, dict):
        raise ValueError(
            f"invalid requirements extraction scaffold provenance for planning "
            f"workspace {plan_id}: expected object"
        )

    provenance_error = _validate_requirements_extraction_scaffold_provenance(
        scaffold_provenance,
        plan_id=plan_id,
        intake_id=intake_id,
    )
    if provenance_error is not None:
        raise ValueError(provenance_error)

    _validate_requirements_extraction_post_scaffold_coherence(
        project,
        intake_id,
        plan_id,
        scaffold_provenance=scaffold_provenance,
    )

    dest = orchestrator_requirements_extraction_decision_path(
        project,
        intake_id,
        plan_id,
        decision_id,
    )
    if dest.exists():
        raise FileExistsError(
            f"requirements extraction owner decision artifact already exists: {decision_id}"
        )

    artifact = build_requirements_extraction_owner_decision_artifact(
        intake_id,
        plan_id,
        decision_id,
        decision,
        owner_summary,
        source_requirements_extraction_scaffold_provenance_path=str(
            requirements_scaffold_provenance_path
        ),
        source_requirements_extraction_scaffold_status=scaffold_provenance.get(
            "local_agentic_spec_status",
            REQUIREMENTS_EXTRACTION_SCAFFOLD_STATUS,
        ),
        source_requirements_extraction_scaffold_created_at=scaffold_provenance.get(
            "created_at",
            "",
        ),
        source_requirements_extraction_preflight_state=scaffold_provenance.get(
            "source_requirements_extraction_preflight_state",
            REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE,
        ),
        source_requirements_extraction_preflight_next_action=scaffold_provenance.get(
            "source_requirements_extraction_preflight_next_action",
            REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NEXT_ACTION,
        ),
        planning_workspace_status_at_decision=workspace_status,
    )

    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_json(dest, artifact)

    decisions = list_requirements_extraction_owner_decisions(
        project,
        intake_id,
        plan_id,
    )
    latest_decision_id = decisions[-1].decision_id if decisions else None
    latest_decision = decisions[-1].decision if decisions else None

    non_authority = {
        key: True
        for key in REQUIREMENTS_EXTRACTION_OWNER_DECISION_NON_AUTHORITY_FLAGS
    }
    output = _format_requirements_extraction_owner_decision(
        decision_path=dest,
        plan_id=plan_id,
        intake_id=intake_id,
        decision_id=decision_id,
        decision=decision,
        workspace_status=workspace_status,
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
    )
    return RequirementsExtractionOwnerDecisionReport(
        output=output,
        decision_path=dest,
        plan_id=plan_id,
        intake_id=intake_id,
        decision_id=decision_id,
        decision=decision,
        workspace_status=workspace_status,
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
        non_authority=non_authority,
    )


def load_requirements_extraction_owner_decision(
    project: Path,
    intake_id: str,
    plan_id: str,
    decision_id: str,
) -> dict:
    """Load a REQUIREMENTS_EXTRACTION_OWNER_DECISION artifact from disk (read-only)."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)
    validate_requirements_extraction_decision_id(decision_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = orchestrator_requirements_extraction_decision_path(
        project,
        intake_id,
        plan_id,
        decision_id,
    )
    if not path.is_file():
        raise FileNotFoundError(
            f"requirements extraction owner decision artifact not found: {decision_id}"
        )

    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid requirements extraction decision artifact for {decision_id}: "
            f"{exc.msg}"
        ) from exc

    if not isinstance(artifact, dict):
        raise ValueError(
            f"invalid requirements extraction decision artifact for {decision_id}: "
            "expected object"
        )

    return artifact


def list_requirements_extraction_owner_decisions(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> tuple[RequirementsExtractionOwnerDecisionRecord, ...]:
    """List requirements extraction owner decisions for an intake/plan (read-only)."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    decisions_dir = (
        orchestrator_intake_path(project, intake_id)
        / REQUIREMENTS_EXTRACTION_DECISIONS_DIR
        / plan_id
    )
    if not decisions_dir.is_dir():
        return ()

    records: list[RequirementsExtractionOwnerDecisionRecord] = []
    for path in sorted(decisions_dir.glob("*.json")):
        decision_id = path.stem
        try:
            artifact = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(artifact, dict):
            continue
        created_at = artifact.get("created_at")
        if not isinstance(created_at, str):
            created_at = ""
        decision = artifact.get("decision")
        if not isinstance(decision, str):
            decision = ""
        records.append(
            RequirementsExtractionOwnerDecisionRecord(
                decision_id=decision_id,
                decision=decision,
                created_at=created_at,
                path=path,
            )
        )

    records.sort(key=lambda record: (record.created_at, record.decision_id))
    return tuple(records)


def validate_requirements_extraction_owner_decision(
    project: Path,
    intake_id: str,
    plan_id: str,
    decision_id: str,
) -> RequirementsExtractionOwnerDecisionValidationReport:
    """Strict read-only validation of a REQUIREMENTS_EXTRACTION_OWNER_DECISION artifact."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)
    validate_requirements_extraction_decision_id(decision_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = orchestrator_requirements_extraction_decision_path(
        project,
        intake_id,
        plan_id,
        decision_id,
    )
    if not path.is_file():
        raise FileNotFoundError(
            f"requirements extraction owner decision artifact not found: {decision_id}"
        )

    raw_text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    try:
        artifact = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        errors = [f"malformed JSON: {exc.msg}"]
    else:
        errors = _validate_requirements_extraction_owner_decision_payload(
            artifact,
            intake_id,
            plan_id,
            decision_id,
        )

    output_lines = [
        f"requirements extraction owner decision validation: {path}",
        f"valid: {not errors}",
    ]
    if errors:
        output_lines.append("errors:")
        for error in errors:
            output_lines.append(f"  - {error}")

    return RequirementsExtractionOwnerDecisionValidationReport(
        output="\n".join(output_lines),
        valid=not errors,
        errors=tuple(errors),
    )


def _validate_requirements_extraction_owner_decision_coherence(
    artifact: dict,
    *,
    scaffold_provenance: dict,
    scaffold_provenance_path: Path,
) -> str | None:
    """Return a blocking reason when an owner decision references stale scaffold metadata."""
    expected_path = str(scaffold_provenance_path)
    artifact_path = artifact.get("source_requirements_extraction_scaffold_provenance_path")
    if artifact_path != expected_path:
        return (
            "requirements extraction owner decision references stale scaffold "
            f"provenance path: expected {expected_path!r}, found {artifact_path!r}"
        )

    expected_status = REQUIREMENTS_EXTRACTION_SCAFFOLD_STATUS
    artifact_status = artifact.get("source_requirements_extraction_scaffold_status")
    if artifact_status != expected_status:
        return (
            "requirements extraction owner decision references stale scaffold "
            f"status: expected {expected_status!r}, found {artifact_status!r}"
        )

    expected_created_at = scaffold_provenance.get("created_at")
    artifact_created_at = artifact.get("source_requirements_extraction_scaffold_created_at")
    if artifact_created_at != expected_created_at:
        return (
            "requirements extraction owner decision references stale scaffold "
            f"created_at: expected {expected_created_at!r}, found {artifact_created_at!r}"
        )

    if (
        artifact.get("source_requirements_extraction_preflight_state")
        != REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE
    ):
        return (
            "requirements extraction owner decision references stale preflight state: "
            f"expected {REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE!r}, "
            f"found {artifact.get('source_requirements_extraction_preflight_state')!r}"
        )

    if (
        artifact.get("source_requirements_extraction_preflight_next_action")
        != REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NEXT_ACTION
    ):
        return (
            "requirements extraction owner decision references stale preflight next action: "
            f"expected {REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NEXT_ACTION!r}, "
            f"found {artifact.get('source_requirements_extraction_preflight_next_action')!r}"
        )

    if artifact.get("planning_workspace_status_at_decision") != "DRAFT":
        return (
            "requirements extraction owner decision planning_workspace_status_at_decision "
            f"is not DRAFT: found {artifact.get('planning_workspace_status_at_decision')!r}"
        )

    return None


def _load_validated_requirements_extraction_owner_decisions(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> tuple[tuple[RequirementsExtractionOwnerDecisionRecord, ...], list[str]]:
    """Load and validate all plan-scoped requirements-extraction owner decisions."""
    decisions_dir = (
        orchestrator_intake_path(project, intake_id)
        / REQUIREMENTS_EXTRACTION_DECISIONS_DIR
        / plan_id
    )
    if not decisions_dir.is_dir():
        return (), []

    records: list[RequirementsExtractionOwnerDecisionRecord] = []
    errors: list[str] = []
    for path in sorted(decisions_dir.glob("*.json")):
        decision_id = path.stem
        try:
            artifact = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"malformed decision artifact {decision_id}: {exc.msg}")
            continue
        if not isinstance(artifact, dict):
            errors.append(
                f"malformed decision artifact {decision_id}: expected object"
            )
            continue
        payload_errors = _validate_requirements_extraction_owner_decision_payload(
            artifact,
            intake_id,
            plan_id,
            decision_id,
        )
        if payload_errors:
            errors.extend(
                f"decision artifact {decision_id}: {error}" for error in payload_errors
            )
            continue
        records.append(
            RequirementsExtractionOwnerDecisionRecord(
                decision_id=decision_id,
                decision=artifact["decision"],
                created_at=artifact["created_at"],
                path=path,
            )
        )

    records.sort(key=lambda record: (record.created_at, record.decision_id))
    return tuple(records), errors


def _format_requirements_extraction_execution_check(
    *,
    plan_id: str,
    intake_id: str,
    planning_workspace_status: str | None,
    local_agentic_spec_status: str | None,
    local_agentic_spec_path: Path | None,
    requirements_extraction_scaffold_provenance_path: Path | None,
    latest_requirements_extraction_decision_id: str | None,
    latest_requirements_extraction_decision: str | None,
    latest_requirements_extraction_decision_created_at: str | None,
    latest_requirements_extraction_decision_path: Path | None,
    latest_readiness_decision_id: str | None,
    latest_readiness_decision: str | None,
    source_requirements_extraction_preflight_state: str | None,
    source_requirements_extraction_preflight_next_action: str | None,
    check_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
    checked_at: str,
    non_authority: dict[str, bool],
) -> str:
    lines = [
        "requirements extraction execution check",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
    ]
    if planning_workspace_status is not None:
        lines.append(f"planning_workspace_status: {planning_workspace_status}")
    if local_agentic_spec_status is not None:
        lines.append(f"local_agentic_spec_status: {local_agentic_spec_status}")
    if local_agentic_spec_path is not None:
        lines.append(f"local_agentic_spec_path: {local_agentic_spec_path}")
    if requirements_extraction_scaffold_provenance_path is not None:
        lines.append(
            "requirements_extraction_scaffold_provenance_path: "
            f"{requirements_extraction_scaffold_provenance_path}"
        )
    if latest_requirements_extraction_decision_id is not None:
        lines.append(
            "latest_requirements_extraction_decision_id: "
            f"{latest_requirements_extraction_decision_id}"
        )
    if latest_requirements_extraction_decision is not None:
        lines.append(
            "latest_requirements_extraction_decision: "
            f"{latest_requirements_extraction_decision}"
        )
    if latest_requirements_extraction_decision_created_at is not None:
        lines.append(
            "latest_requirements_extraction_decision_created_at: "
            f"{latest_requirements_extraction_decision_created_at}"
        )
    if latest_requirements_extraction_decision_path is not None:
        lines.append(
            "latest_requirements_extraction_decision_path: "
            f"{latest_requirements_extraction_decision_path}"
        )
    if latest_readiness_decision_id is not None:
        lines.append(f"latest_readiness_decision_id: {latest_readiness_decision_id}")
    if latest_readiness_decision is not None:
        lines.append(f"latest_readiness_decision: {latest_readiness_decision}")
    if source_requirements_extraction_preflight_state is not None:
        lines.append(
            "source_requirements_extraction_preflight_state: "
            f"{source_requirements_extraction_preflight_state}"
        )
    if source_requirements_extraction_preflight_next_action is not None:
        lines.append(
            "source_requirements_extraction_preflight_next_action: "
            f"{source_requirements_extraction_preflight_next_action}"
        )
    lines.append(f"check_state: {check_state}")
    lines.append(f"next_required_action: {next_required_action}")
    lines.append(f"checked_at: {checked_at}")
    if blocking_reasons:
        lines.append("blocking_reasons:")
        for reason in blocking_reasons:
            lines.append(f"  - {reason}")
    lines.append("non_authority:")
    for flag in REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_NON_AUTHORITY_FLAGS:
        lines.append(f"  {flag}: true")
    lines.append(
        "note: requirements extraction execution check is read-only; "
        "not requirements extraction, not requirements approval, "
        "not architecture decision, not implementation planning, "
        "not validation or approval, and no files were modified"
    )
    if check_state == REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_STATE:
        lines.append(
            "note: execution check confirmed for a future requirements extraction "
            "command only; no requirements were extracted or generated"
        )
        lines.append(
            "note: successful check is not extraction, not requirements approval, "
            "not architecture decision, not implementation plan, not workspace "
            "validation or approval, and does not authorize runner or executor"
        )
    return "\n".join(lines)


@dataclass(frozen=True)
class RequirementsExtractionExecutionCheckReport:
    output: str
    check_state: str
    next_required_action: str
    plan_id: str
    intake_id: str
    planning_workspace_status: str | None
    local_agentic_spec_status: str | None
    local_agentic_spec_path: Path | None
    requirements_extraction_scaffold_provenance_path: Path | None
    latest_requirements_extraction_decision_id: str | None
    latest_requirements_extraction_decision: str | None
    latest_requirements_extraction_decision_created_at: str | None
    latest_requirements_extraction_decision_path: Path | None
    latest_readiness_decision_id: str | None
    latest_readiness_decision: str | None
    source_requirements_extraction_preflight_state: str | None
    source_requirements_extraction_preflight_next_action: str | None
    checked_at: str
    blocking_reasons: tuple[str, ...]
    non_authority: dict[str, bool]


def _build_requirements_extraction_execution_check_report(
    *,
    plan_id: str,
    intake_id: str,
    planning_workspace_status: str | None = None,
    local_agentic_spec_status: str | None = None,
    local_agentic_spec_path: Path | None = None,
    requirements_extraction_scaffold_provenance_path: Path | None = None,
    latest_requirements_extraction_decision_id: str | None = None,
    latest_requirements_extraction_decision: str | None = None,
    latest_requirements_extraction_decision_created_at: str | None = None,
    latest_requirements_extraction_decision_path: Path | None = None,
    latest_readiness_decision_id: str | None = None,
    latest_readiness_decision: str | None = None,
    source_requirements_extraction_preflight_state: str | None = None,
    source_requirements_extraction_preflight_next_action: str | None = None,
    check_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
    checked_at: str,
    non_authority: dict[str, bool],
) -> RequirementsExtractionExecutionCheckReport:
    output = _format_requirements_extraction_execution_check(
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=planning_workspace_status,
        local_agentic_spec_status=local_agentic_spec_status,
        local_agentic_spec_path=local_agentic_spec_path,
        requirements_extraction_scaffold_provenance_path=(
            requirements_extraction_scaffold_provenance_path
        ),
        latest_requirements_extraction_decision_id=latest_requirements_extraction_decision_id,
        latest_requirements_extraction_decision=latest_requirements_extraction_decision,
        latest_requirements_extraction_decision_created_at=(
            latest_requirements_extraction_decision_created_at
        ),
        latest_requirements_extraction_decision_path=(
            latest_requirements_extraction_decision_path
        ),
        latest_readiness_decision_id=latest_readiness_decision_id,
        latest_readiness_decision=latest_readiness_decision,
        source_requirements_extraction_preflight_state=(
            source_requirements_extraction_preflight_state
        ),
        source_requirements_extraction_preflight_next_action=(
            source_requirements_extraction_preflight_next_action
        ),
        check_state=check_state,
        next_required_action=next_required_action,
        blocking_reasons=blocking_reasons,
        checked_at=checked_at,
        non_authority=non_authority,
    )
    return RequirementsExtractionExecutionCheckReport(
        output=output,
        check_state=check_state,
        next_required_action=next_required_action,
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=planning_workspace_status,
        local_agentic_spec_status=local_agentic_spec_status,
        local_agentic_spec_path=local_agentic_spec_path,
        requirements_extraction_scaffold_provenance_path=(
            requirements_extraction_scaffold_provenance_path
        ),
        latest_requirements_extraction_decision_id=latest_requirements_extraction_decision_id,
        latest_requirements_extraction_decision=latest_requirements_extraction_decision,
        latest_requirements_extraction_decision_created_at=(
            latest_requirements_extraction_decision_created_at
        ),
        latest_requirements_extraction_decision_path=(
            latest_requirements_extraction_decision_path
        ),
        latest_readiness_decision_id=latest_readiness_decision_id,
        latest_readiness_decision=latest_readiness_decision,
        source_requirements_extraction_preflight_state=(
            source_requirements_extraction_preflight_state
        ),
        source_requirements_extraction_preflight_next_action=(
            source_requirements_extraction_preflight_next_action
        ),
        checked_at=checked_at,
        blocking_reasons=tuple(blocking_reasons),
        non_authority=non_authority,
    )


def check_requirements_extraction_execution_authorization(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> RequirementsExtractionExecutionCheckReport:
    """Read-only pre-execution check for future requirements extraction authorization."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    checked_at = _utc_now()
    non_authority = {
        key: True for key in REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_NON_AUTHORITY_FLAGS
    }
    workspace_dest = planning_path(project, plan_id)
    local_agentic_spec_path = workspace_dest / "local-agentic-spec.md"
    requirements_scaffold_provenance_path = (
        workspace_dest
        / "evidence"
        / ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_FILE
    )
    implementation_plan_path = workspace_dest / "implementation-plan.md"
    planning_audit_path = workspace_dest / "planning-audit.md"

    def _blocked(
        state: str,
        next_action: str,
        *,
        blocking_reasons: list[str] | None = None,
        planning_workspace_status: str | None = None,
        local_agentic_spec_status: str | None = None,
        latest_requirements_extraction_decision_id: str | None = None,
        latest_requirements_extraction_decision: str | None = None,
        latest_requirements_extraction_decision_created_at: str | None = None,
        latest_requirements_extraction_decision_path: Path | None = None,
        latest_readiness_decision_id: str | None = None,
        latest_readiness_decision: str | None = None,
        source_requirements_extraction_preflight_state: str | None = None,
        source_requirements_extraction_preflight_next_action: str | None = None,
    ) -> RequirementsExtractionExecutionCheckReport:
        return _build_requirements_extraction_execution_check_report(
            plan_id=plan_id,
            intake_id=intake_id,
            planning_workspace_status=planning_workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            local_agentic_spec_path=local_agentic_spec_path,
            requirements_extraction_scaffold_provenance_path=(
                requirements_scaffold_provenance_path
                if requirements_scaffold_provenance_path.is_file()
                else None
            ),
            latest_requirements_extraction_decision_id=(
                latest_requirements_extraction_decision_id
            ),
            latest_requirements_extraction_decision=latest_requirements_extraction_decision,
            latest_requirements_extraction_decision_created_at=(
                latest_requirements_extraction_decision_created_at
            ),
            latest_requirements_extraction_decision_path=(
                latest_requirements_extraction_decision_path
            ),
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=(
                source_requirements_extraction_preflight_state
            ),
            source_requirements_extraction_preflight_next_action=(
                source_requirements_extraction_preflight_next_action
            ),
            check_state=state,
            next_required_action=next_action,
            blocking_reasons=blocking_reasons or [],
            checked_at=checked_at,
            non_authority=non_authority,
        )

    workspace = workspace_path(project)
    if not workspace.is_dir():
        return _blocked(
            "BLOCKED_MISSING_WORKSPACE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            blocking_reasons=["no workspace found (run `agent-os init` first)"],
        )

    intake_path = _goal_intake_artifact_path(project, intake_id)
    if not intake_path.is_file():
        return _blocked(
            "BLOCKED_INVALID_INTAKE",
            "FIX_GOAL_INTAKE_STRUCTURE",
            blocking_reasons=[f"goal intake artifact not found: {intake_id}"],
        )

    readiness_report = review_goal_intake_readiness(project, intake_id)
    if not readiness_report.goal_intake_valid:
        return _blocked(
            "BLOCKED_INVALID_INTAKE",
            "FIX_GOAL_INTAKE_STRUCTURE",
            blocking_reasons=list(readiness_report.blocking_reasons),
        )

    if not workspace_dest.is_dir():
        return _blocked(
            "BLOCKED_MISSING_PLANNING_WORKSPACE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            blocking_reasons=[f"planning workspace not found: {plan_id}"],
        )

    try:
        workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    except (FileNotFoundError, ValueError) as exc:
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            blocking_reasons=[str(exc)],
        )

    if workspace_status != "DRAFT":
        return _blocked(
            "BLOCKED_WORKSPACE_NOT_DRAFT",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            planning_workspace_status=workspace_status,
            blocking_reasons=[
                f"planning workspace must be DRAFT for requirements extraction "
                f"execution check, found: {workspace_status!r}"
            ],
        )

    draft_preflight_report = preflight_draft_preparation(project, intake_id)
    latest_readiness_decision_id = draft_preflight_report.latest_decision_id
    latest_readiness_decision = draft_preflight_report.latest_decision
    source_preflight_state = REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE
    source_preflight_next_action = REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NEXT_ACTION

    if latest_readiness_decision == "REQUEST_MORE_CLARIFICATION":
        return _blocked(
            "BLOCKED_LATEST_READINESS_DECISION_REQUESTS_CLARIFICATION",
            "RESOLVE_OR_REPLACE_READINESS_DECISION",
            planning_workspace_status=workspace_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )
    if latest_readiness_decision == "BLOCK_INTAKE":
        return _blocked(
            "BLOCKED_LATEST_READINESS_DECISION_BLOCKS_INTAKE",
            "STOP_REQUIREMENTS_EXTRACTION",
            planning_workspace_status=workspace_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )
    if (
        draft_preflight_report.preflight_state
        != DRAFT_PREPARATION_PREFLIGHT_CONFIRMED_STATE
        or latest_readiness_decision != "AUTHORIZE_DRAFT_PREPARATION"
    ):
        return _blocked(
            "BLOCKED_AUTHORIZATION_STALE_OR_INCOHERENT",
            "RESOLVE_OR_REPLACE_READINESS_DECISION",
            planning_workspace_status=workspace_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=list(draft_preflight_report.blocking_reasons),
        )

    if not requirements_scaffold_provenance_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[
                "requirements extraction scaffold provenance not found for planning "
                f"workspace: {plan_id}"
            ],
        )

    try:
        scaffold_provenance = json.loads(
            requirements_scaffold_provenance_path.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        return _blocked(
            "BLOCKED_MALFORMED_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[
                f"invalid requirements extraction scaffold provenance for planning "
                f"workspace {plan_id}: {exc.msg}"
            ],
        )

    if not isinstance(scaffold_provenance, dict):
        return _blocked(
            "BLOCKED_MALFORMED_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[
                f"invalid requirements extraction scaffold provenance for planning "
                f"workspace {plan_id}: expected object"
            ],
        )

    provenance_error = _validate_requirements_extraction_scaffold_provenance(
        scaffold_provenance,
        plan_id=plan_id,
        intake_id=intake_id,
    )
    if provenance_error is not None:
        if "mismatch" in provenance_error:
            state = "BLOCKED_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_MISMATCH"
        elif "non_authority" in provenance_error:
            state = "BLOCKED_MALFORMED_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE"
        else:
            state = "BLOCKED_MALFORMED_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE"
        return _blocked(
            state,
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=scaffold_provenance.get(
                "source_requirements_extraction_preflight_state",
                source_preflight_state,
            ),
            source_requirements_extraction_preflight_next_action=scaffold_provenance.get(
                "source_requirements_extraction_preflight_next_action",
                source_preflight_next_action,
            ),
            blocking_reasons=[provenance_error],
        )

    source_preflight_state = scaffold_provenance.get(
        "source_requirements_extraction_preflight_state",
        REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE,
    )
    source_preflight_next_action = scaffold_provenance.get(
        "source_requirements_extraction_preflight_next_action",
        REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NEXT_ACTION,
    )

    if source_preflight_state != REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_STATE:
        return _blocked(
            "BLOCKED_REQUIREMENTS_EXTRACTION_PREFLIGHT_NOT_CONFIRMED",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[
                "requirements extraction preflight not confirmed: "
                f"{source_preflight_state!r}"
            ],
        )
    if source_preflight_next_action != REQUIREMENTS_EXTRACTION_PREFLIGHT_CONFIRMED_NEXT_ACTION:
        return _blocked(
            "BLOCKED_REQUIREMENTS_EXTRACTION_PREFLIGHT_NOT_CONFIRMED",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[
                "requirements extraction preflight next action not expected: "
                f"{source_preflight_next_action!r}"
            ],
        )

    if not local_agentic_spec_path.is_file():
        return _blocked(
            "BLOCKED_REQUIREMENTS_EXTRACTION_SCAFFOLD_NOT_COHERENT",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[
                f"local-agentic-spec.md missing in planning workspace: {plan_id}"
            ],
        )

    local_spec_content = local_agentic_spec_path.read_text(encoding="utf-8")
    if not _is_local_agentic_spec_requirements_extraction_scaffold_non_authority(
        local_spec_content,
        plan_id,
    ):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_NOT_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=None,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    local_agentic_spec_status = REQUIREMENTS_EXTRACTION_SCAFFOLD_STATUS

    if not _requirements_extraction_scaffold_boundary_notes_present(local_spec_content):
        return _blocked(
            "BLOCKED_REQUIREMENTS_EXTRACTION_SCAFFOLD_NOT_COHERENT",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[
                "requirements extraction scaffold is incoherent: "
                "local-agentic-spec.md missing required boundary notes"
            ],
        )

    if _REQUIREMENT_ID_PATTERN.search(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_REQUIREMENT_IDS",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    if _NON_FUNCTIONAL_REQUIREMENT_ID_PATTERN.search(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_REQUIREMENT_IDS",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    if _local_agentic_spec_has_generated_functional_requirements(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_REQUIREMENTS",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    if _local_agentic_spec_has_user_stories(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_USER_STORIES",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    if _local_agentic_spec_has_generated_acceptance_criteria(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_ACCEPTANCE_CRITERIA",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    if _local_agentic_spec_has_architecture_decision_language(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_ARCHITECTURE",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    if _local_agentic_spec_has_implementation_tasks(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_IMPLEMENTATION_TASKS",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    if _local_agentic_spec_has_planning_run_slice_content(local_spec_content):
        return _blocked(
            "BLOCKED_LOCAL_AGENTIC_SPEC_ALREADY_HAS_PLANNING_RUN_SLICE",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    if not _local_agentic_spec_contains_only_requirements_extraction_scaffold_sections(
        local_spec_content
    ):
        return _blocked(
            "BLOCKED_REQUIREMENTS_EXTRACTION_SCAFFOLD_NOT_COHERENT",
            "FIX_OR_RECREATE_REQUIREMENTS_EXTRACTION_SCAFFOLD",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[
                "requirements extraction scaffold is incoherent: "
                "local-agentic-spec.md no longer contains only empty containers"
            ],
        )

    if not implementation_plan_path.is_file():
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[
                f"implementation-plan.md missing in planning workspace: {plan_id}"
            ],
        )

    if not _is_planning_artifact_init_placeholder(
        implementation_plan_path.read_text(encoding="utf-8"),
        plan_id,
        "implementation-plan.md",
        artifact_type="IMPLEMENTATION_PLAN",
    ):
        return _blocked(
            "BLOCKED_IMPLEMENTATION_PLAN_ALREADY_MODIFIED",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    if not planning_audit_path.is_file():
        return _blocked(
            "BLOCKED_UNEXPECTED_STRUCTURE",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[
                f"planning-audit.md missing in planning workspace: {plan_id}"
            ],
        )

    if not _is_planning_artifact_init_placeholder(
        planning_audit_path.read_text(encoding="utf-8"),
        plan_id,
        "planning-audit.md",
        artifact_type="PLANNING_AUDIT",
        identity_field="auditor",
    ):
        return _blocked(
            "BLOCKED_PLANNING_AUDIT_ALREADY_MODIFIED",
            "RESTORE_PLANNING_INIT_PLACEHOLDERS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    decision_records, decision_errors = _load_validated_requirements_extraction_owner_decisions(
        project,
        intake_id,
        plan_id,
    )
    if decision_errors:
        return _blocked(
            "BLOCKED_MALFORMED_REQUIREMENTS_EXTRACTION_OWNER_DECISION",
            "FIX_REQUIREMENTS_EXTRACTION_OWNER_DECISION_ARTIFACTS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=decision_errors,
        )

    if not decision_records:
        return _blocked(
            "BLOCKED_NO_REQUIREMENTS_EXTRACTION_OWNER_DECISION",
            "CREATE_REQUIREMENTS_EXTRACTION_OWNER_DECISION",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[
                "no requirements extraction owner decision artifacts found "
                f"for intake {intake_id!r} and plan {plan_id!r}"
            ],
        )

    latest_record = decision_records[-1]
    latest_decision_id = latest_record.decision_id
    latest_decision = latest_record.decision
    latest_decision_created_at = latest_record.created_at
    latest_decision_path = latest_record.path

    if latest_decision == "REQUEST_MORE_CONTEXT":
        return _blocked(
            "BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_REQUESTS_MORE_CONTEXT",
            "ADD_MORE_CONTEXT_BEFORE_EXTRACTION",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_requirements_extraction_decision_id=latest_decision_id,
            latest_requirements_extraction_decision=latest_decision,
            latest_requirements_extraction_decision_created_at=latest_decision_created_at,
            latest_requirements_extraction_decision_path=latest_decision_path,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    if latest_decision == "BLOCK_REQUIREMENTS_EXTRACTION":
        return _blocked(
            "BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_BLOCKS_EXTRACTION",
            "STOP_REQUIREMENTS_EXTRACTION",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_requirements_extraction_decision_id=latest_decision_id,
            latest_requirements_extraction_decision=latest_decision,
            latest_requirements_extraction_decision_created_at=latest_decision_created_at,
            latest_requirements_extraction_decision_path=latest_decision_path,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        )

    if latest_decision != "AUTHORIZE_REQUIREMENTS_EXTRACTION":
        return _blocked(
            "BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_NOT_AUTHORIZE",
            "AUTHORIZE_REQUIREMENTS_EXTRACTION_WITH_OWNER_DECISION",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_requirements_extraction_decision_id=latest_decision_id,
            latest_requirements_extraction_decision=latest_decision,
            latest_requirements_extraction_decision_created_at=latest_decision_created_at,
            latest_requirements_extraction_decision_path=latest_decision_path,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[f"unsupported latest decision value: {latest_decision!r}"],
        )

    latest_artifact = json.loads(latest_decision_path.read_text(encoding="utf-8"))
    coherence_error = _validate_requirements_extraction_owner_decision_coherence(
        latest_artifact,
        scaffold_provenance=scaffold_provenance,
        scaffold_provenance_path=requirements_scaffold_provenance_path,
    )
    if coherence_error is not None:
        return _blocked(
            "BLOCKED_REQUIREMENTS_EXTRACTION_OWNER_DECISION_STALE_OR_INCOHERENT",
            "FIX_REQUIREMENTS_EXTRACTION_OWNER_DECISION_ARTIFACTS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_requirements_extraction_decision_id=latest_decision_id,
            latest_requirements_extraction_decision=latest_decision,
            latest_requirements_extraction_decision_created_at=latest_decision_created_at,
            latest_requirements_extraction_decision_path=latest_decision_path,
            latest_readiness_decision_id=latest_readiness_decision_id,
            latest_readiness_decision=latest_readiness_decision,
            source_requirements_extraction_preflight_state=source_preflight_state,
            source_requirements_extraction_preflight_next_action=source_preflight_next_action,
            blocking_reasons=[coherence_error],
        )

    return _build_requirements_extraction_execution_check_report(
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=workspace_status,
        local_agentic_spec_status=local_agentic_spec_status,
        local_agentic_spec_path=local_agentic_spec_path,
        requirements_extraction_scaffold_provenance_path=requirements_scaffold_provenance_path,
        latest_requirements_extraction_decision_id=latest_decision_id,
        latest_requirements_extraction_decision=latest_decision,
        latest_requirements_extraction_decision_created_at=latest_decision_created_at,
        latest_requirements_extraction_decision_path=latest_decision_path,
        latest_readiness_decision_id=latest_readiness_decision_id,
        latest_readiness_decision=latest_readiness_decision,
        source_requirements_extraction_preflight_state=source_preflight_state,
        source_requirements_extraction_preflight_next_action=source_preflight_next_action,
        check_state=REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_STATE,
        next_required_action=REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_NEXT_ACTION,
        blocking_reasons=[],
        checked_at=checked_at,
        non_authority=non_authority,
    )


@dataclass(frozen=True)
class DraftRequirementCandidate:
    id: str
    status: str
    source_bounded: str
    source_type: str
    source_path: str
    source_field: str
    source_quote_or_reference: str
    candidate_text: str
    validation_status: str
    approval_status: str
    architecture_status: str
    implementation_status: str


@dataclass(frozen=True)
class ExtractedRequirementsDraftReport:
    output: str
    plan_id: str
    intake_id: str
    local_agentic_spec_path: Path
    provenance_path: Path
    local_agentic_spec_status: str
    workspace_status: str
    requirement_candidate_count: int
    requirement_candidate_ids: tuple[str, ...]
    candidates: tuple[DraftRequirementCandidate, ...]
    non_authority: dict[str, bool]


def _format_draft_candidate_text(source_label: str, source_phrase: str) -> str:
    cleaned = source_phrase.strip().rstrip(".")
    if not cleaned:
        return ""
    return f"Draft candidate derived from source {source_label}: {cleaned}."


def _normalize_candidate_dedup_key(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _append_draft_requirement_candidate(
    candidates: list[DraftRequirementCandidate],
    seen: set[str],
    *,
    source_type: str,
    source_path: Path,
    source_field: str,
    source_quote_or_reference: str,
    source_label: str,
    source_phrase: str,
) -> None:
    if not isinstance(source_phrase, str) or not source_phrase.strip():
        return
    candidate_text = _format_draft_candidate_text(source_label, source_phrase)
    if not candidate_text:
        return
    dedup_key = _normalize_candidate_dedup_key(source_phrase)
    if dedup_key in seen:
        return
    seen.add(dedup_key)
    candidate_id = f"DRAFT-REQ-{len(candidates) + 1:03d}"
    candidates.append(
        DraftRequirementCandidate(
            id=candidate_id,
            status=DRAFT_REQUIREMENT_CANDIDATE_STATUS,
            source_bounded=DRAFT_REQUIREMENT_SOURCE_BOUNDED_MARKER,
            source_type=source_type,
            source_path=str(source_path),
            source_field=source_field,
            source_quote_or_reference=source_quote_or_reference,
            candidate_text=candidate_text,
            validation_status="NOT_VALIDATED",
            approval_status="NOT_APPROVED",
            architecture_status="NOT_DECIDED",
            implementation_status="NOT_PLANNED",
        )
    )


def _build_deterministic_requirement_candidates(
    *,
    transport: dict,
    transport_json_path: Path,
    owner_decision_artifact: dict,
    owner_decision_path: Path,
) -> tuple[DraftRequirementCandidate, ...]:
    """Build source-bounded draft requirement candidates from explicit source material only."""
    candidates: list[DraftRequirementCandidate] = []
    seen: set[str] = set()

    source_context = transport.get("source_context")
    if not isinstance(source_context, dict):
        source_context = {}

    raw_goal = source_context.get("raw_goal")
    normalized_goal = source_context.get("normalized_goal")
    if isinstance(raw_goal, str) and raw_goal.strip():
        _append_draft_requirement_candidate(
            candidates,
            seen,
            source_type="ORCHESTRATOR_CONTEXT_TRANSPORT",
            source_path=transport_json_path,
            source_field="source_context.raw_goal",
            source_quote_or_reference=raw_goal,
            source_label="goal",
            source_phrase=raw_goal,
        )
    if isinstance(normalized_goal, str) and normalized_goal.strip():
        normalized_key = _normalize_candidate_dedup_key(normalized_goal)
        raw_key = (
            _normalize_candidate_dedup_key(raw_goal)
            if isinstance(raw_goal, str)
            else ""
        )
        if normalized_key != raw_key:
            _append_draft_requirement_candidate(
                candidates,
                seen,
                source_type="ORCHESTRATOR_CONTEXT_TRANSPORT",
                source_path=transport_json_path,
                source_field="source_context.normalized_goal",
                source_quote_or_reference=normalized_goal,
                source_label="normalized goal",
                source_phrase=normalized_goal,
            )

    explicit_constraints = source_context.get("explicit_constraints")
    if isinstance(explicit_constraints, list):
        for index, item in enumerate(explicit_constraints):
            if isinstance(item, str) and item.strip():
                _append_draft_requirement_candidate(
                    candidates,
                    seen,
                    source_type="ORCHESTRATOR_CONTEXT_TRANSPORT",
                    source_path=transport_json_path,
                    source_field=f"source_context.explicit_constraints[{index}]",
                    source_quote_or_reference=item,
                    source_label=f"explicit constraint {index + 1}",
                    source_phrase=item,
                )

    non_goals = source_context.get("non_goals")
    if isinstance(non_goals, list):
        for index, item in enumerate(non_goals):
            if isinstance(item, str) and item.strip():
                _append_draft_requirement_candidate(
                    candidates,
                    seen,
                    source_type="ORCHESTRATOR_CONTEXT_TRANSPORT",
                    source_path=transport_json_path,
                    source_field=f"source_context.non_goals[{index}]",
                    source_quote_or_reference=item,
                    source_label=f"non-goal {index + 1}",
                    source_phrase=item,
                )

    owner_clarifications = transport.get("owner_clarifications")
    if isinstance(owner_clarifications, list):
        for item in owner_clarifications:
            if not isinstance(item, dict):
                continue
            clarification_id = str(item.get("clarification_id", "")).strip()
            owner_answer = item.get("owner_answer")
            if not isinstance(owner_answer, str) or not owner_answer.strip():
                continue
            label = (
                f"clarification {clarification_id}"
                if clarification_id
                else "clarification"
            )
            _append_draft_requirement_candidate(
                candidates,
                seen,
                source_type="ORCHESTRATOR_CONTEXT_TRANSPORT",
                source_path=transport_json_path,
                source_field=f"owner_clarifications.{clarification_id}.owner_answer",
                source_quote_or_reference=owner_answer,
                source_label=label,
                source_phrase=owner_answer,
            )

    owner_summary = owner_decision_artifact.get("owner_summary")
    if isinstance(owner_summary, str) and owner_summary.strip():
        _append_draft_requirement_candidate(
            candidates,
            seen,
            source_type="REQUIREMENTS_EXTRACTION_OWNER_DECISION",
            source_path=owner_decision_path,
            source_field="owner_summary",
            source_quote_or_reference=owner_summary,
            source_label="owner decision summary",
            source_phrase=owner_summary,
        )

    return tuple(candidates)


def _build_requirements_draft_markdown(
    *,
    plan_id: str,
    intake_id: str,
    transport_json_path: Path,
    context_pack_path: Path,
    requirements_scaffold_provenance_path: Path,
    owner_decision_id: str,
    owner_decision: str,
    owner_decision_path: Path,
    execution_check_state: str,
    execution_check_next_action: str,
    candidates: tuple[DraftRequirementCandidate, ...],
    created_at: str,
) -> str:
    lines = [
        "---",
        f"plan_id: {plan_id}",
        "artifact_type: LOCAL_AGENTIC_SPEC",
        f"local_agentic_spec_status: {REQUIREMENTS_DRAFT_STATUS}",
        f"intake_id: {intake_id}",
        f"created_at: {created_at}",
        "author: ORCHESTRATOR_REQUIREMENTS_DRAFT_NON_AUTHORITY",
        "version: 1",
        "---",
        "",
        "# Local Agentic Spec (REQUIREMENTS_DRAFT — DRAFT_NON_AUTHORITY)",
        "",
        "> **Planning artifact type:** `LOCAL_AGENTIC_SPEC`",
        "> **Status:** `REQUIREMENTS_DRAFT_NON_AUTHORITY` — draft requirement candidates "
        "only; not approved requirements, not validated requirements, not user stories, "
        "not acceptance criteria, not architecture, not implementation plan.",
        "",
        "## Source identifiers",
        "",
        f"- **plan_id:** `{plan_id}`",
        f"- **intake_id:** `{intake_id}`",
        f"- **source context transport json:** `{transport_json_path}`",
        f"- **source context-pack:** `{context_pack_path}`",
        (
            "- **source requirements-extraction scaffold provenance:** "
            f"`{requirements_scaffold_provenance_path}`"
        ),
        "",
        "## Requirements extraction execution check reference",
        "",
        f"- **execution_check_state:** `{execution_check_state}`",
        f"- **execution_check_next_action:** `{execution_check_next_action}`",
        "",
        "## Latest requirements-extraction owner decision",
        "",
        f"- **decision_id:** `{owner_decision_id}`",
        f"- **decision:** `{owner_decision}`",
        f"- **decision_path:** `{owner_decision_path}`",
        "",
        "## Explicit boundaries",
        "",
        "- **requirements:** draft, non-authority, unvalidated, unapproved",
        "- **requirement candidates:** source-bounded only; no inferred product scope",
        "- **requirements validation:** requires a separate command",
        "- **architecture:** undecided — `UNDECIDED_NOT_GENERATED`",
        "- **implementation plan:** not generated — `NOT_GENERATED`",
        "- **PLANNING_RUN_SLICE:** not generated — `NOT_GENERATED`",
        "- **planning workspace:** not validated or approved",
        "- **runner proposals / runs / executor:** not created or invoked",
        "- **future independent validation:** required",
        "- **future owner approval:** required",
        "",
        "## Draft requirement candidates (non-authority)",
        "",
    ]

    if candidates:
        for candidate in candidates:
            lines.extend(
                [
                    f"### {candidate.id}",
                    "",
                    f"- **status:** `{candidate.status}`",
                    f"- **source_bounded:** `{candidate.source_bounded}`",
                    f"- **source_type:** `{candidate.source_type}`",
                    f"- **source_path:** `{candidate.source_path}`",
                    f"- **source_field:** `{candidate.source_field}`",
                    f"- **source_quote_or_reference:** {candidate.source_quote_or_reference}",
                    f"- **candidate_text:** {candidate.candidate_text}",
                    f"- **validation_status:** `{candidate.validation_status}`",
                    f"- **approval_status:** `{candidate.approval_status}`",
                    f"- **architecture_status:** `{candidate.architecture_status}`",
                    f"- **implementation_status:** `{candidate.implementation_status}`",
                    "",
                ]
            )
    else:
        lines.extend(["- (no explicit source material produced candidates)", ""])

    lines.extend(
        [
            "## User Stories",
            "",
            "NOT_GENERATED",
            "",
            "## Acceptance Criteria",
            "",
            "NOT_GENERATED",
            "",
            "## Architecture",
            "",
            "UNDECIDED_NOT_GENERATED",
            "",
            "## Implementation Plan",
            "",
            "NOT_GENERATED",
            "",
            "## PLANNING_RUN_SLICE",
            "",
            "NOT_GENERATED",
            "",
            "This requirements draft contains deterministic source-bounded requirement "
            "candidates only. It does not approve or validate requirements, generate "
            "user stories or acceptance criteria, define architecture, or generate "
            "implementation tasks. Future requirements validation, architecture decision, "
            "implementation plan, independent validation, and owner approval remain "
            "required.",
        ]
    )
    return "\n".join(lines) + "\n"


def _build_requirements_draft_provenance_artifact(
    *,
    plan_id: str,
    intake_id: str,
    transport_json_path: Path,
    context_pack_path: Path,
    requirements_scaffold_provenance_path: Path,
    owner_decision_id: str,
    owner_decision_path: Path,
    execution_check_state: str,
    execution_check_next_action: str,
    local_agentic_spec_path: Path,
    candidates: tuple[DraftRequirementCandidate, ...],
    workspace_status: str,
    created_at: str,
) -> dict:
    return {
        "artifact_type": ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_ARTIFACT_TYPE,
        "schema_version": ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_SCHEMA_VERSION,
        "plan_id": plan_id,
        "intake_id": intake_id,
        "source_context_transport_path": str(transport_json_path),
        "source_context_pack_path": str(context_pack_path),
        "source_requirements_extraction_scaffold_provenance_path": str(
            requirements_scaffold_provenance_path
        ),
        "source_requirements_extraction_owner_decision_id": owner_decision_id,
        "source_requirements_extraction_owner_decision_path": str(owner_decision_path),
        "source_requirements_extraction_execution_check_state": execution_check_state,
        "source_requirements_extraction_execution_check_next_action": (
            execution_check_next_action
        ),
        "local_agentic_spec_path": str(local_agentic_spec_path),
        "local_agentic_spec_status": REQUIREMENTS_DRAFT_STATUS,
        "requirement_candidate_count": len(candidates),
        "requirement_candidate_ids": [candidate.id for candidate in candidates],
        "planning_workspace_status_at_draft": workspace_status,
        "created_at": created_at,
        "non_authority": {
            key: True for key in REQUIREMENTS_DRAFT_NON_AUTHORITY_FLAGS
        },
    }


def _format_extracted_requirements_draft(
    *,
    local_agentic_spec_path: Path,
    provenance_path: Path,
    plan_id: str,
    intake_id: str,
    workspace_status: str,
    requirement_candidate_count: int,
    requirement_candidate_ids: tuple[str, ...],
) -> str:
    ids_text = ", ".join(requirement_candidate_ids) if requirement_candidate_ids else "(none)"
    lines = [
        (
            "orchestrator requirements draft extracted: "
            f"{local_agentic_spec_path.parent.parent}"
        ),
        f"local agentic spec: {local_agentic_spec_path}",
        f"requirements draft provenance: {provenance_path}",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
        f"local_agentic_spec_status: {REQUIREMENTS_DRAFT_STATUS}",
        f"workspace_status: {workspace_status}",
        f"requirement_candidate_count: {requirement_candidate_count}",
        f"requirement_candidate_ids: {ids_text}",
        (
            "note: requirements draft only; draft/non-authority/not validated/"
            "not approved source-bounded candidates"
        ),
        "note: no requirements approval, no requirements validation, no user stories, "
        "no acceptance criteria, no architecture generation, no implementation plan "
        "generation, no PLANNING_RUN_SLICE",
        "note: planning workspace not validated or approved; "
        "no runner proposals, runs, or executor invocation",
        "note: future requirements validation, architecture decision, implementation "
        "plan, independent validation, and owner approval remain required",
    ]
    return "\n".join(lines)


def _local_agentic_spec_already_has_draft_requirements(content: str) -> bool:
    if _DRAFT_REQUIREMENT_ID_PATTERN.search(content):
        return True
    if "DRAFT_REQUIREMENT_CANDIDATE" in content:
        return True
    if REQUIREMENTS_DRAFT_STATUS in content:
        return True
    return False


def extract_requirements_draft(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> ExtractedRequirementsDraftReport:
    """Write deterministic source-bounded requirements draft candidates only."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    _require_valid_goal_intake(project, intake_id)

    workspace_dest = planning_path(project, plan_id)
    if not workspace_dest.is_dir():
        raise FileNotFoundError(f"planning workspace not found: {plan_id}")

    workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    if workspace_status != "DRAFT":
        raise ValueError(
            f"planning workspace must be DRAFT for requirements draft extraction, "
            f"found: {workspace_status!r}"
        )

    draft_provenance_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_FILE
    )
    if draft_provenance_path.exists():
        raise FileExistsError(
            f"requirements draft provenance already exists for plan: {plan_id}"
        )

    execution_report = check_requirements_extraction_execution_authorization(
        project,
        intake_id,
        plan_id,
    )
    if (
        execution_report.check_state
        != REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_STATE
    ):
        reasons = "; ".join(execution_report.blocking_reasons) or execution_report.check_state
        raise ValueError(
            "requirements extraction execution check not confirmed: "
            f"{reasons}"
        )

    local_agentic_spec_path = workspace_dest / "local-agentic-spec.md"
    requirements_scaffold_provenance_path = (
        workspace_dest
        / "evidence"
        / ORCHESTRATOR_REQUIREMENTS_EXTRACTION_SCAFFOLD_PROVENANCE_FILE
    )
    transport_json_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_CONTEXT_TRANSPORT_FILE
    )
    context_pack_path = workspace_dest / "context-pack.md"

    transport = _require_context_transport_for_draft(
        transport_json_path,
        plan_id=plan_id,
        intake_id=intake_id,
    )

    if not context_pack_path.is_file():
        raise FileNotFoundError(
            f"context-pack.md missing in planning workspace: {plan_id}"
        )

    local_spec_content = local_agentic_spec_path.read_text(encoding="utf-8")
    if _local_agentic_spec_already_has_draft_requirements(local_spec_content):
        raise FileExistsError(
            f"local-agentic-spec.md already contains requirements draft content "
            f"for plan: {plan_id}"
        )

    if (
        execution_report.latest_requirements_extraction_decision_id is None
        or execution_report.latest_requirements_extraction_decision_path is None
    ):
        raise ValueError(
            "missing latest requirements-extraction owner decision for draft extraction"
        )

    owner_decision_path = execution_report.latest_requirements_extraction_decision_path
    owner_decision_artifact = json.loads(
        owner_decision_path.read_text(encoding="utf-8")
    )
    if not isinstance(owner_decision_artifact, dict):
        raise ValueError("malformed requirements-extraction owner decision artifact")

    created_at = _utc_now()
    candidates = _build_deterministic_requirement_candidates(
        transport=transport,
        transport_json_path=transport_json_path,
        owner_decision_artifact=owner_decision_artifact,
        owner_decision_path=owner_decision_path,
    )

    draft_markdown = _build_requirements_draft_markdown(
        plan_id=plan_id,
        intake_id=intake_id,
        transport_json_path=transport_json_path,
        context_pack_path=context_pack_path,
        requirements_scaffold_provenance_path=requirements_scaffold_provenance_path,
        owner_decision_id=execution_report.latest_requirements_extraction_decision_id,
        owner_decision=execution_report.latest_requirements_extraction_decision or "",
        owner_decision_path=owner_decision_path,
        execution_check_state=execution_report.check_state,
        execution_check_next_action=execution_report.next_required_action,
        candidates=candidates,
        created_at=created_at,
    )
    provenance_artifact = _build_requirements_draft_provenance_artifact(
        plan_id=plan_id,
        intake_id=intake_id,
        transport_json_path=transport_json_path,
        context_pack_path=context_pack_path,
        requirements_scaffold_provenance_path=requirements_scaffold_provenance_path,
        owner_decision_id=execution_report.latest_requirements_extraction_decision_id,
        owner_decision_path=owner_decision_path,
        execution_check_state=execution_report.check_state,
        execution_check_next_action=execution_report.next_required_action,
        local_agentic_spec_path=local_agentic_spec_path,
        candidates=candidates,
        workspace_status=workspace_status,
        created_at=created_at,
    )

    original_local_spec = local_agentic_spec_path.read_bytes()
    temp_local_spec = local_agentic_spec_path.with_suffix(".md.tmp")
    try:
        temp_local_spec.write_text(draft_markdown, encoding="utf-8")
        temp_local_spec.replace(local_agentic_spec_path)
        try:
            _write_json(draft_provenance_path, provenance_artifact)
        except Exception:
            local_agentic_spec_path.write_bytes(original_local_spec)
            if draft_provenance_path.is_file():
                draft_provenance_path.unlink()
            raise
    except Exception:
        if temp_local_spec.is_file():
            temp_local_spec.unlink()
        if local_agentic_spec_path.read_bytes() != original_local_spec:
            local_agentic_spec_path.write_bytes(original_local_spec)
        if draft_provenance_path.is_file():
            draft_provenance_path.unlink()
        raise

    candidate_ids = tuple(candidate.id for candidate in candidates)
    non_authority = {key: True for key in REQUIREMENTS_DRAFT_NON_AUTHORITY_FLAGS}
    output = _format_extracted_requirements_draft(
        local_agentic_spec_path=local_agentic_spec_path,
        provenance_path=draft_provenance_path,
        plan_id=plan_id,
        intake_id=intake_id,
        workspace_status=workspace_status,
        requirement_candidate_count=len(candidates),
        requirement_candidate_ids=candidate_ids,
    )
    return ExtractedRequirementsDraftReport(
        output=output,
        plan_id=plan_id,
        intake_id=intake_id,
        local_agentic_spec_path=local_agentic_spec_path,
        provenance_path=draft_provenance_path,
        local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
        workspace_status=workspace_status,
        requirement_candidate_count=len(candidates),
        requirement_candidate_ids=candidate_ids,
        candidates=candidates,
        non_authority=non_authority,
    )


def _requirements_draft_candidate_region(content: str) -> str:
    marker = _REQUIREMENTS_DRAFT_CANDIDATES_HEADING
    start = content.find(marker)
    if start == -1:
        return ""
    after = content[start + len(marker) :]
    match = re.search(r"\n## (?!#)", after)
    if match:
        return after[: match.start()]
    return after


def _parse_requirements_draft_candidates_from_spec(
    content: str,
) -> tuple[DraftRequirementCandidate, ...] | str:
    region = _requirements_draft_candidate_region(content)
    headings = list(_DRAFT_REQUIREMENT_HEADING_PATTERN.finditer(region))
    if not headings:
        if "(no explicit source material produced candidates)" in region:
            return ()
        return "requirements draft contains no parseable DRAFT-REQ candidates"

    candidates: list[DraftRequirementCandidate] = []
    for index, heading in enumerate(headings):
        candidate_id = heading.group(1)
        section_start = heading.end()
        section_end = (
            headings[index + 1].start() if index + 1 < len(headings) else len(region)
        )
        section = region[section_start:section_end]
        fields: dict[str, str] = {}
        for match in _CANDIDATE_BACKTICK_FIELD_PATTERN.finditer(section):
            fields[match.group("field")] = match.group("value")
        text_match = _CANDIDATE_TEXT_LINE_PATTERN.search(section)
        quote_match = _CANDIDATE_SOURCE_QUOTE_LINE_PATTERN.search(section)
        candidate_text = text_match.group("value").strip() if text_match else ""
        source_quote = quote_match.group("value").strip() if quote_match else ""
        candidates.append(
            DraftRequirementCandidate(
                id=candidate_id,
                status=fields.get("status", ""),
                source_bounded=fields.get("source_bounded", ""),
                source_type=fields.get("source_type", ""),
                source_path=fields.get("source_path", ""),
                source_field=fields.get("source_field", ""),
                source_quote_or_reference=source_quote,
                candidate_text=candidate_text,
                validation_status=fields.get("validation_status", ""),
                approval_status=fields.get("approval_status", ""),
                architecture_status=fields.get("architecture_status", ""),
                implementation_status=fields.get("implementation_status", ""),
            )
        )
    return tuple(candidates)


def _is_local_agentic_spec_requirements_draft_non_authority(
    content: str,
    plan_id: str,
) -> bool:
    normalized_content = content.replace("\r\n", "\n").replace("\r", "\n")
    meta, _body = parse_frontmatter(normalized_content)
    if meta.get("artifact_type") != "LOCAL_AGENTIC_SPEC":
        return False
    if meta.get("local_agentic_spec_status") != REQUIREMENTS_DRAFT_STATUS:
        return False
    if meta.get("plan_id") != plan_id:
        return False
    if REQUIREMENTS_DRAFT_STATUS not in normalized_content:
        return False
    return True


def _local_agentic_spec_has_promoted_requirements_status(content: str) -> bool:
    promoted_markers = (
        "APPROVED_REQUIREMENTS",
        "VALIDATED_REQUIREMENTS",
        "REQUIREMENTS_APPROVED",
        "REQUIREMENTS_VALIDATED",
    )
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    for marker in promoted_markers:
        if marker in normalized:
            return True
    return False


def _requirements_draft_has_promoted_candidate_headings(content: str) -> bool:
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("### "):
            heading = stripped[4:].strip()
            if re.match(r"^(REQ|FR|NFR)-\d+$", heading, re.IGNORECASE):
                return True
    return False


def _requirements_draft_candidate_region_has_promoted_ids(region: str) -> bool:
    if _PROMOTED_REQUIREMENT_ID_PATTERN.search(region):
        return True
    if _FUNCTIONAL_REQUIREMENT_ID_PATTERN.search(region):
        return True
    if _NON_FUNCTIONAL_REQUIREMENT_ID_PATTERN.search(region):
        return True
    return False


def _requirements_draft_has_promoted_requirement_identifiers(content: str) -> bool:
    if _requirements_draft_has_promoted_candidate_headings(content):
        return True
    return _requirements_draft_candidate_region_has_promoted_ids(
        _requirements_draft_candidate_region(content)
    )


def _requirements_draft_has_forbidden_user_stories(content: str) -> bool:
    if _USER_STORY_PATTERN.search(content):
        return True
    section = section_body(content, "## User Stories").strip()
    if section and section != "NOT_GENERATED":
        return True
    return False


def _requirements_draft_has_forbidden_acceptance_criteria(content: str) -> bool:
    if _ACCEPTANCE_CRITERIA_GWT_PATTERN.search(content):
        return True
    if _ACCEPTANCE_CRITERIA_ID_PATTERN.search(content):
        return True
    section = section_body(content, "## Acceptance Criteria").strip()
    if section and section != "NOT_GENERATED":
        return True
    return False


def _requirements_draft_has_forbidden_architecture(content: str) -> bool:
    if _ARCHITECTURE_DECISION_PATTERN.search(content):
        return True
    if _STACK_CHOICE_PATTERN.search(content):
        return True
    section = section_body(content, "## Architecture").strip()
    if section and section != "UNDECIDED_NOT_GENERATED":
        return True
    return False


def _requirements_draft_has_forbidden_implementation_plan(content: str) -> bool:
    if _IMPLEMENTATION_TASK_HEADING_PATTERN.search(content):
        section = section_body(content, "## Implementation Tasks")
        if section.strip():
            return True
    if "allowed_paths" in content:
        return True
    section = section_body(content, "## Implementation Plan").strip()
    if section and section != "NOT_GENERATED":
        return True
    return False


def _requirements_draft_has_forbidden_planning_run_slice(content: str) -> bool:
    if '"artifact_type": "PLANNING_RUN_SLICE"' in content:
        return True
    section = section_body(content, "## PLANNING_RUN_SLICE").strip()
    if not section:
        return False
    if section == "NOT_GENERATED":
        return False
    if section.startswith("NOT_GENERATED\n") or section.startswith("NOT_GENERATED\r\n"):
        return False
    return True


def _requirements_draft_has_inferred_unsourced_details(
    candidates: tuple[DraftRequirementCandidate, ...],
) -> bool:
    for candidate in candidates:
        combined_candidate = candidate.candidate_text.lower()
        source_combined = candidate.source_quote_or_reference.lower()
        for term in _INFERRED_SLITHER_FEATURE_TERMS:
            if term not in source_combined and term in combined_candidate:
                return True
    return False


def _validate_requirements_draft_provenance_artifact(
    provenance: dict,
    *,
    plan_id: str,
    intake_id: str,
    candidates: tuple[DraftRequirementCandidate, ...],
    spec_content: str,
) -> list[str]:
    errors: list[str] = []
    artifact_type = provenance.get("artifact_type")
    if artifact_type != ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_ARTIFACT_TYPE:
        errors.append(
            "requirements draft provenance artifact_type mismatch: "
            f"expected {ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_ARTIFACT_TYPE!r}, "
            f"found {artifact_type!r}"
        )

    if provenance.get("plan_id") != plan_id:
        errors.append(
            f"requirements draft provenance plan_id mismatch: "
            f"expected {plan_id!r}, found {provenance.get('plan_id')!r}"
        )

    if provenance.get("intake_id") != intake_id:
        errors.append(
            f"requirements draft provenance intake_id mismatch: "
            f"expected {intake_id!r}, found {provenance.get('intake_id')!r}"
        )

    if provenance.get("local_agentic_spec_status") != REQUIREMENTS_DRAFT_STATUS:
        errors.append(
            "requirements draft provenance local_agentic_spec_status is not "
            "REQUIREMENTS_DRAFT_NON_AUTHORITY"
        )

    if (
        provenance.get("source_requirements_extraction_execution_check_state")
        != REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_STATE
    ):
        errors.append(
            "requirements draft provenance source_requirements_extraction_execution_check_state "
            "is not REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_NO_EXTRACTION_PERFORMED"
        )

    if (
        provenance.get("source_requirements_extraction_execution_check_next_action")
        != REQUIREMENTS_EXTRACTION_EXECUTION_CHECK_CONFIRMED_NEXT_ACTION
    ):
        errors.append(
            "requirements draft provenance source_requirements_extraction_execution_check_next_action "
            "is not FUTURE_REQUIREMENTS_EXTRACTION_COMMAND_MAY_BE_RUN_SEPARATELY"
        )

    provenance_count = provenance.get("requirement_candidate_count")
    if provenance_count != len(candidates):
        errors.append(
            "requirements draft provenance candidate count mismatch: "
            f"provenance={provenance_count!r}, spec={len(candidates)}"
        )

    provenance_ids = provenance.get("requirement_candidate_ids")
    spec_ids = [candidate.id for candidate in candidates]
    if provenance_ids != spec_ids:
        errors.append(
            "requirements draft provenance candidate id mismatch: "
            f"provenance={provenance_ids!r}, spec={spec_ids!r}"
        )

    for candidate_id in spec_ids:
        if candidate_id not in spec_content:
            errors.append(
                f"requirements draft provenance candidate {candidate_id!r} "
                "missing from local-agentic-spec.md"
            )

    non_authority = provenance.get("non_authority")
    if not isinstance(non_authority, dict):
        errors.append("requirements draft provenance non_authority must be an object")
    else:
        for flag in REQUIREMENTS_DRAFT_NON_AUTHORITY_FLAGS:
            if non_authority.get(flag) is not True:
                errors.append(
                    f"requirements draft provenance non_authority.{flag} must be true"
                )

    if provenance.get("planning_workspace_status_at_draft") != "DRAFT":
        errors.append(
            "requirements draft provenance planning_workspace_status_at_draft is not DRAFT"
        )

    return errors


def _validate_orchestrator_provenance_binds_intake(
    provenance_path: Path,
    *,
    plan_id: str,
    intake_id: str,
) -> str | None:
    if not provenance_path.is_file():
        return f"orchestrator provenance not found for planning workspace: {plan_id}"
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return f"invalid orchestrator provenance for planning workspace {plan_id}: {exc.msg}"
    if not isinstance(provenance, dict):
        return (
            f"invalid orchestrator provenance for planning workspace {plan_id}: "
            "expected object"
        )
    if provenance.get("plan_id") != plan_id:
        return (
            f"orchestrator provenance plan_id mismatch: expected {plan_id!r}, "
            f"found {provenance.get('plan_id')!r}"
        )
    if provenance.get("intake_id") != intake_id:
        return (
            f"orchestrator provenance intake_id mismatch: expected {intake_id!r}, "
            f"found {provenance.get('intake_id')!r}"
        )
    return None


def _format_requirements_draft_validation_preflight(
    *,
    plan_id: str,
    intake_id: str,
    planning_workspace_status: str | None,
    local_agentic_spec_status: str | None,
    local_agentic_spec_path: Path | None,
    requirements_draft_provenance_path: Path | None,
    requirement_candidate_count: int | None,
    requirement_candidate_ids: tuple[str, ...] | None,
    latest_requirements_extraction_decision_id: str | None,
    latest_requirements_extraction_decision: str | None,
    preflight_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
    checked_at: str,
    non_authority: dict[str, bool],
) -> str:
    lines = [
        "requirements draft validation preflight",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
    ]
    if planning_workspace_status is not None:
        lines.append(f"planning_workspace_status: {planning_workspace_status}")
    if local_agentic_spec_status is not None:
        lines.append(f"local_agentic_spec_status: {local_agentic_spec_status}")
    if local_agentic_spec_path is not None:
        lines.append(f"local_agentic_spec_path: {local_agentic_spec_path}")
    if requirements_draft_provenance_path is not None:
        lines.append(
            "requirements_draft_provenance_path: "
            f"{requirements_draft_provenance_path}"
        )
    if requirement_candidate_count is not None:
        lines.append(f"requirement_candidate_count: {requirement_candidate_count}")
    if requirement_candidate_ids is not None:
        ids_text = ", ".join(requirement_candidate_ids) if requirement_candidate_ids else "(none)"
        lines.append(f"requirement_candidate_ids: {ids_text}")
    if latest_requirements_extraction_decision_id is not None:
        lines.append(
            "latest_requirements_extraction_decision_id: "
            f"{latest_requirements_extraction_decision_id}"
        )
    if latest_requirements_extraction_decision is not None:
        lines.append(
            "latest_requirements_extraction_decision: "
            f"{latest_requirements_extraction_decision}"
        )
    lines.append(f"preflight_state: {preflight_state}")
    lines.append(f"next_required_action: {next_required_action}")
    lines.append(f"checked_at: {checked_at}")
    if blocking_reasons:
        lines.append("blocking_reasons:")
        for reason in blocking_reasons:
            lines.append(f"  - {reason}")
    lines.append("non_authority:")
    for flag in REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_NON_AUTHORITY_FLAGS:
        lines.append(f"  {flag}: true")
    lines.append(
        "note: requirements draft validation preflight is read-only; "
        "not requirements validation, not requirements approval, "
        "not architecture decision, not implementation planning, "
        "and no files were modified"
    )
    if preflight_state == REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_STATE:
        lines.append(
            "note: preflight confirmed for a future requirements validation command "
            "only; no requirements were validated or approved"
        )
        lines.append(
            "note: requirements draft remains DRAFT_NON_AUTHORITY; "
            "architecture undecided; implementation plan not generated; "
            "PLANNING_RUN_SLICE not generated; workspace not validated or approved"
        )
    return "\n".join(lines)


@dataclass(frozen=True)
class RequirementsDraftValidationPreflightReport:
    output: str
    preflight_state: str
    next_required_action: str
    plan_id: str
    intake_id: str
    planning_workspace_status: str | None
    local_agentic_spec_status: str | None
    local_agentic_spec_path: Path | None
    requirements_draft_provenance_path: Path | None
    requirement_candidate_count: int | None
    requirement_candidate_ids: tuple[str, ...] | None
    latest_requirements_extraction_decision_id: str | None
    latest_requirements_extraction_decision: str | None
    checked_at: str
    blocking_reasons: tuple[str, ...]
    non_authority: dict[str, bool]


def _build_requirements_draft_validation_preflight_report(
    *,
    plan_id: str,
    intake_id: str,
    planning_workspace_status: str | None = None,
    local_agentic_spec_status: str | None = None,
    local_agentic_spec_path: Path | None = None,
    requirements_draft_provenance_path: Path | None = None,
    requirement_candidate_count: int | None = None,
    requirement_candidate_ids: tuple[str, ...] | None = None,
    latest_requirements_extraction_decision_id: str | None = None,
    latest_requirements_extraction_decision: str | None = None,
    preflight_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
    checked_at: str,
    non_authority: dict[str, bool],
) -> RequirementsDraftValidationPreflightReport:
    output = _format_requirements_draft_validation_preflight(
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=planning_workspace_status,
        local_agentic_spec_status=local_agentic_spec_status,
        local_agentic_spec_path=local_agentic_spec_path,
        requirements_draft_provenance_path=requirements_draft_provenance_path,
        requirement_candidate_count=requirement_candidate_count,
        requirement_candidate_ids=requirement_candidate_ids,
        latest_requirements_extraction_decision_id=latest_requirements_extraction_decision_id,
        latest_requirements_extraction_decision=latest_requirements_extraction_decision,
        preflight_state=preflight_state,
        next_required_action=next_required_action,
        blocking_reasons=blocking_reasons,
        checked_at=checked_at,
        non_authority=non_authority,
    )
    return RequirementsDraftValidationPreflightReport(
        output=output,
        preflight_state=preflight_state,
        next_required_action=next_required_action,
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=planning_workspace_status,
        local_agentic_spec_status=local_agentic_spec_status,
        local_agentic_spec_path=local_agentic_spec_path,
        requirements_draft_provenance_path=requirements_draft_provenance_path,
        requirement_candidate_count=requirement_candidate_count,
        requirement_candidate_ids=requirement_candidate_ids,
        latest_requirements_extraction_decision_id=latest_requirements_extraction_decision_id,
        latest_requirements_extraction_decision=latest_requirements_extraction_decision,
        checked_at=checked_at,
        blocking_reasons=tuple(blocking_reasons),
        non_authority=non_authority,
    )


def requirements_draft_validation_preflight(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> RequirementsDraftValidationPreflightReport:
    """Read-only requirements draft validation eligibility preflight."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    checked_at = _utc_now()
    non_authority = {
        key: True for key in REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_NON_AUTHORITY_FLAGS
    }
    workspace_dest = planning_path(project, plan_id)
    local_agentic_spec_path = workspace_dest / "local-agentic-spec.md"
    draft_provenance_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_FILE
    )
    orchestrator_provenance_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_PROVENANCE_FILE
    )

    def _blocked(
        state: str,
        next_action: str,
        *,
        blocking_reasons: list[str] | None = None,
        planning_workspace_status: str | None = None,
        local_agentic_spec_status: str | None = None,
        requirement_candidate_count: int | None = None,
        requirement_candidate_ids: tuple[str, ...] | None = None,
        latest_requirements_extraction_decision_id: str | None = None,
        latest_requirements_extraction_decision: str | None = None,
    ) -> RequirementsDraftValidationPreflightReport:
        return _build_requirements_draft_validation_preflight_report(
            plan_id=plan_id,
            intake_id=intake_id,
            planning_workspace_status=planning_workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            local_agentic_spec_path=local_agentic_spec_path,
            requirements_draft_provenance_path=draft_provenance_path,
            requirement_candidate_count=requirement_candidate_count,
            requirement_candidate_ids=requirement_candidate_ids,
            latest_requirements_extraction_decision_id=(
                latest_requirements_extraction_decision_id
            ),
            latest_requirements_extraction_decision=latest_requirements_extraction_decision,
            preflight_state=state,
            next_required_action=next_action,
            blocking_reasons=blocking_reasons or [],
            checked_at=checked_at,
            non_authority=non_authority,
        )

    workspace = workspace_path(project)
    if not workspace.is_dir():
        return _blocked(
            "BLOCKED_MISSING_WORKSPACE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            blocking_reasons=["no workspace found (run `agent-os init` first)"],
        )

    intake_path = _goal_intake_artifact_path(project, intake_id)
    if not intake_path.is_file():
        return _blocked(
            "BLOCKED_INVALID_INTAKE",
            "FIX_GOAL_INTAKE_STRUCTURE",
            blocking_reasons=[f"goal intake artifact not found: {intake_id}"],
        )

    readiness_report = review_goal_intake_readiness(project, intake_id)
    if not readiness_report.goal_intake_valid:
        return _blocked(
            "BLOCKED_INVALID_INTAKE",
            "FIX_GOAL_INTAKE_STRUCTURE",
            blocking_reasons=list(readiness_report.blocking_reasons),
        )

    if not workspace_dest.is_dir():
        return _blocked(
            "BLOCKED_MISSING_PLANNING_WORKSPACE",
            "FIX_PLANNING_WORKSPACE_STRUCTURE",
            blocking_reasons=[f"planning workspace not found: {plan_id}"],
        )

    workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    if workspace_status != "DRAFT":
        return _blocked(
            "BLOCKED_PLANNING_WORKSPACE_NOT_DRAFT",
            "RESTORE_DRAFT_PLANNING_WORKSPACE",
            planning_workspace_status=workspace_status,
            blocking_reasons=[
                f"planning workspace must be DRAFT for requirements draft validation "
                f"preflight, found: {workspace_status!r}"
            ],
        )

    provenance_error = _validate_orchestrator_provenance_binds_intake(
        orchestrator_provenance_path,
        plan_id=plan_id,
        intake_id=intake_id,
    )
    if provenance_error is not None:
        return _blocked(
            "BLOCKED_MISSING_ORCHESTRATOR_PROVENANCE",
            "RESTORE_ORCHESTRATOR_PROVENANCE",
            planning_workspace_status=workspace_status,
            blocking_reasons=[provenance_error],
        )

    if not local_agentic_spec_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_LOCAL_AGENTIC_SPEC",
            "RESTORE_OR_GENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=workspace_status,
            blocking_reasons=[
                f"local-agentic-spec.md missing in planning workspace: {plan_id}"
            ],
        )

    if not draft_provenance_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_REQUIREMENTS_DRAFT_PROVENANCE",
            "RESTORE_OR_GENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=workspace_status,
            blocking_reasons=[
                "requirements draft provenance missing: "
                f"{ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_FILE}"
            ],
        )

    try:
        provenance = json.loads(draft_provenance_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return _blocked(
            "BLOCKED_MALFORMED_REQUIREMENTS_DRAFT_PROVENANCE",
            "FIX_REQUIREMENTS_DRAFT_PROVENANCE",
            planning_workspace_status=workspace_status,
            blocking_reasons=[f"malformed requirements draft provenance: {exc.msg}"],
        )
    if not isinstance(provenance, dict):
        return _blocked(
            "BLOCKED_MALFORMED_REQUIREMENTS_DRAFT_PROVENANCE",
            "FIX_REQUIREMENTS_DRAFT_PROVENANCE",
            planning_workspace_status=workspace_status,
            blocking_reasons=["malformed requirements draft provenance: expected object"],
        )

    local_spec_content = local_agentic_spec_path.read_text(encoding="utf-8")
    meta, _body = parse_frontmatter(local_spec_content.replace("\r\n", "\n").replace("\r", "\n"))
    local_agentic_spec_status = meta.get("local_agentic_spec_status")

    if not _is_local_agentic_spec_requirements_draft_non_authority(
        local_spec_content,
        plan_id,
    ):
        return _blocked(
            "BLOCKED_WRONG_LOCAL_AGENTIC_SPEC_STATUS",
            "RESTORE_OR_REGENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=str(local_agentic_spec_status or ""),
            blocking_reasons=[
                "local-agentic-spec.md must be REQUIREMENTS_DRAFT_NON_AUTHORITY "
                f"for validation preflight, found: {local_agentic_spec_status!r}"
            ],
        )

    if _local_agentic_spec_has_promoted_requirements_status(local_spec_content):
        return _blocked(
            "BLOCKED_WRONG_LOCAL_AGENTIC_SPEC_STATUS",
            "RESTORE_OR_REGENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=str(local_agentic_spec_status or ""),
            blocking_reasons=[
                "local-agentic-spec.md indicates promoted or approved requirements status"
            ],
        )

    parsed_candidates = _parse_requirements_draft_candidates_from_spec(local_spec_content)
    if isinstance(parsed_candidates, str):
        return _blocked(
            "BLOCKED_REQUIREMENTS_DRAFT_NOT_COHERENT",
            "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            blocking_reasons=[parsed_candidates],
        )
    candidates = parsed_candidates
    candidate_ids = tuple(candidate.id for candidate in candidates)

    if _requirements_draft_has_promoted_requirement_identifiers(local_spec_content):
        return _blocked(
            "BLOCKED_PROMOTED_REQUIREMENT_IDENTIFIER",
            "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            blocking_reasons=[
                "requirements draft contains promoted requirement identifiers "
                "(REQ-/FR-/NFR-); only DRAFT-REQ-* allowed"
            ],
        )

    for candidate in candidates:
        if candidate.status != DRAFT_REQUIREMENT_CANDIDATE_STATUS:
            return _blocked(
                "BLOCKED_CANDIDATE_NOT_DRAFT_NON_AUTHORITY",
                "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
                planning_workspace_status=workspace_status,
                local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
                requirement_candidate_count=len(candidates),
                requirement_candidate_ids=candidate_ids,
                blocking_reasons=[
                    f"candidate {candidate.id} status is not "
                    "DRAFT_REQUIREMENT_CANDIDATE_NON_AUTHORITY"
                ],
            )
        if candidate.source_bounded != DRAFT_REQUIREMENT_SOURCE_BOUNDED_MARKER:
            return _blocked(
                "BLOCKED_CANDIDATE_NOT_SOURCE_BOUNDED",
                "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
                planning_workspace_status=workspace_status,
                local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
                requirement_candidate_count=len(candidates),
                requirement_candidate_ids=candidate_ids,
                blocking_reasons=[
                    f"candidate {candidate.id} is missing SOURCE_BOUNDED marker"
                ],
            )
        if candidate.validation_status != "NOT_VALIDATED":
            return _blocked(
                "BLOCKED_CANDIDATE_NOT_VALIDATED",
                "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
                planning_workspace_status=workspace_status,
                local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
                requirement_candidate_count=len(candidates),
                requirement_candidate_ids=candidate_ids,
                blocking_reasons=[
                    f"candidate {candidate.id} validation_status is not NOT_VALIDATED"
                ],
            )
        if candidate.approval_status != "NOT_APPROVED":
            return _blocked(
                "BLOCKED_CANDIDATE_NOT_APPROVED",
                "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
                planning_workspace_status=workspace_status,
                local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
                requirement_candidate_count=len(candidates),
                requirement_candidate_ids=candidate_ids,
                blocking_reasons=[
                    f"candidate {candidate.id} approval_status is not NOT_APPROVED"
                ],
            )
        if candidate.architecture_status != "NOT_DECIDED":
            return _blocked(
                "BLOCKED_CANDIDATE_ARCHITECTURE_STATUS_NOT_UNDECIDED",
                "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
                planning_workspace_status=workspace_status,
                local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
                requirement_candidate_count=len(candidates),
                requirement_candidate_ids=candidate_ids,
                blocking_reasons=[
                    f"candidate {candidate.id} architecture_status is not NOT_DECIDED"
                ],
            )
        if candidate.implementation_status != "NOT_PLANNED":
            return _blocked(
                "BLOCKED_CANDIDATE_IMPLEMENTATION_STATUS_NOT_UNPLANNED",
                "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
                planning_workspace_status=workspace_status,
                local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
                requirement_candidate_count=len(candidates),
                requirement_candidate_ids=candidate_ids,
                blocking_reasons=[
                    f"candidate {candidate.id} implementation_status is not NOT_PLANNED"
                ],
            )

    provenance_errors = _validate_requirements_draft_provenance_artifact(
        provenance,
        plan_id=plan_id,
        intake_id=intake_id,
        candidates=candidates,
        spec_content=local_spec_content,
    )
    if provenance_errors:
        first_error = provenance_errors[0]
        if "candidate count mismatch" in first_error:
            state = "BLOCKED_PROVENANCE_CANDIDATE_COUNT_MISMATCH"
        elif "candidate id mismatch" in first_error:
            state = "BLOCKED_PROVENANCE_CANDIDATE_ID_MISMATCH"
        elif "plan_id mismatch" in first_error:
            state = "BLOCKED_PROVENANCE_PLAN_ID_MISMATCH"
        elif "intake_id mismatch" in first_error:
            state = "BLOCKED_PROVENANCE_INTAKE_ID_MISMATCH"
        else:
            state = "BLOCKED_MALFORMED_REQUIREMENTS_DRAFT_PROVENANCE"
        return _blocked(
            state,
            "FIX_REQUIREMENTS_DRAFT_PROVENANCE",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            blocking_reasons=provenance_errors,
        )

    if _requirements_draft_has_forbidden_user_stories(local_spec_content):
        return _blocked(
            "BLOCKED_REQUIREMENTS_DRAFT_HAS_USER_STORIES",
            "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            blocking_reasons=["requirements draft contains forbidden user story content"],
        )

    if _requirements_draft_has_forbidden_acceptance_criteria(local_spec_content):
        return _blocked(
            "BLOCKED_REQUIREMENTS_DRAFT_HAS_ACCEPTANCE_CRITERIA",
            "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            blocking_reasons=[
                "requirements draft contains forbidden acceptance criteria content"
            ],
        )

    if _requirements_draft_has_forbidden_architecture(local_spec_content):
        return _blocked(
            "BLOCKED_REQUIREMENTS_DRAFT_HAS_ARCHITECTURE",
            "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            blocking_reasons=["requirements draft contains forbidden architecture content"],
        )

    if _requirements_draft_has_forbidden_implementation_plan(local_spec_content):
        return _blocked(
            "BLOCKED_REQUIREMENTS_DRAFT_HAS_IMPLEMENTATION_PLAN",
            "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            blocking_reasons=[
                "requirements draft contains forbidden implementation plan content"
            ],
        )

    if _requirements_draft_has_forbidden_planning_run_slice(local_spec_content):
        return _blocked(
            "BLOCKED_REQUIREMENTS_DRAFT_HAS_PLANNING_RUN_SLICE",
            "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            blocking_reasons=[
                "requirements draft contains forbidden PLANNING_RUN_SLICE content"
            ],
        )

    if _requirements_draft_has_inferred_unsourced_details(candidates):
        return _blocked(
            "BLOCKED_REQUIREMENTS_DRAFT_HAS_INFERRED_UNSOURCED_DETAILS",
            "FIX_OR_REGENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            blocking_reasons=[
                "requirements draft candidate text contains inferred unsourced product details"
            ],
        )

    decision_records, decision_errors = _load_validated_requirements_extraction_owner_decisions(
        project,
        intake_id,
        plan_id,
    )
    if decision_errors:
        return _blocked(
            "BLOCKED_MALFORMED_REQUIREMENTS_EXTRACTION_OWNER_DECISION",
            "FIX_REQUIREMENTS_EXTRACTION_OWNER_DECISION_ARTIFACTS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            blocking_reasons=decision_errors,
        )

    if not decision_records:
        return _blocked(
            "BLOCKED_NO_REQUIREMENTS_EXTRACTION_OWNER_DECISION",
            "CREATE_REQUIREMENTS_EXTRACTION_OWNER_DECISION",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            blocking_reasons=[
                "no requirements extraction owner decision artifacts found "
                f"for intake {intake_id!r} and plan {plan_id!r}"
            ],
        )

    latest_record = decision_records[-1]
    latest_decision_id = latest_record.decision_id
    latest_decision = latest_record.decision

    if latest_decision == "REQUEST_MORE_CONTEXT":
        return _blocked(
            "BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_REQUESTS_MORE_CONTEXT",
            "ADD_MORE_CONTEXT_BEFORE_VALIDATION",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            latest_requirements_extraction_decision_id=latest_decision_id,
            latest_requirements_extraction_decision=latest_decision,
            blocking_reasons=[
                "latest requirements extraction owner decision is REQUEST_MORE_CONTEXT"
            ],
        )

    if latest_decision == "BLOCK_REQUIREMENTS_EXTRACTION":
        return _blocked(
            "BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_BLOCKS_EXTRACTION",
            "STOP_REQUIREMENTS_DRAFT_VALIDATION",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            latest_requirements_extraction_decision_id=latest_decision_id,
            latest_requirements_extraction_decision=latest_decision,
            blocking_reasons=[
                "latest requirements extraction owner decision is BLOCK_REQUIREMENTS_EXTRACTION"
            ],
        )

    if latest_decision != "AUTHORIZE_REQUIREMENTS_EXTRACTION":
        return _blocked(
            "BLOCKED_LATEST_REQUIREMENTS_EXTRACTION_DECISION_NOT_AUTHORIZE",
            "AUTHORIZE_REQUIREMENTS_EXTRACTION_WITH_OWNER_DECISION",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            latest_requirements_extraction_decision_id=latest_decision_id,
            latest_requirements_extraction_decision=latest_decision,
            blocking_reasons=[f"unsupported latest decision value: {latest_decision!r}"],
        )

    provenance_decision_id = provenance.get("source_requirements_extraction_owner_decision_id")
    if provenance_decision_id != latest_decision_id:
        return _blocked(
            "BLOCKED_REQUIREMENTS_DRAFT_DECISION_CHAIN_INCOHERENT",
            "FIX_REQUIREMENTS_EXTRACTION_OWNER_DECISION_ARTIFACTS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            latest_requirements_extraction_decision_id=latest_decision_id,
            latest_requirements_extraction_decision=latest_decision,
            blocking_reasons=[
                "requirements draft provenance owner decision id does not match "
                f"latest authorize decision: provenance={provenance_decision_id!r}, "
                f"latest={latest_decision_id!r}"
            ],
        )

    provenance_decision_path_value = provenance.get(
        "source_requirements_extraction_owner_decision_path"
    )
    if not isinstance(provenance_decision_path_value, str) or not provenance_decision_path_value:
        return _blocked(
            "BLOCKED_MALFORMED_REQUIREMENTS_DRAFT_PROVENANCE",
            "FIX_REQUIREMENTS_DRAFT_PROVENANCE",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            blocking_reasons=[
                "requirements draft provenance missing "
                "source_requirements_extraction_owner_decision_path"
            ],
        )

    provenance_decision_path = Path(provenance_decision_path_value)
    if not provenance_decision_path.is_file():
        return _blocked(
            "BLOCKED_REQUIREMENTS_DRAFT_DECISION_CHAIN_INCOHERENT",
            "FIX_REQUIREMENTS_EXTRACTION_OWNER_DECISION_ARTIFACTS",
            planning_workspace_status=workspace_status,
            local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
            requirement_candidate_count=len(candidates),
            requirement_candidate_ids=candidate_ids,
            latest_requirements_extraction_decision_id=latest_decision_id,
            latest_requirements_extraction_decision=latest_decision,
            blocking_reasons=[
                "requirements draft provenance owner decision path is missing on disk"
            ],
        )

    return _build_requirements_draft_validation_preflight_report(
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=workspace_status,
        local_agentic_spec_status=REQUIREMENTS_DRAFT_STATUS,
        local_agentic_spec_path=local_agentic_spec_path,
        requirements_draft_provenance_path=draft_provenance_path,
        requirement_candidate_count=len(candidates),
        requirement_candidate_ids=candidate_ids,
        latest_requirements_extraction_decision_id=latest_decision_id,
        latest_requirements_extraction_decision=latest_decision,
        preflight_state=REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_STATE,
        next_required_action=REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_NEXT_ACTION,
        blocking_reasons=[],
        checked_at=checked_at,
        non_authority=non_authority,
    )


@dataclass(frozen=True)
class RequirementsValidationOwnerDecisionRecord:
    decision_id: str
    decision: str
    created_at: str
    path: Path


@dataclass(frozen=True)
class RequirementsValidationOwnerDecisionValidationReport:
    output: str
    valid: bool
    errors: tuple[str, ...]


@dataclass(frozen=True)
class RequirementsValidationOwnerDecisionReport:
    output: str
    decision_path: Path
    plan_id: str
    intake_id: str
    decision_id: str
    decision: str
    status: str
    next_required_action: str
    workspace_status: str
    latest_decision_id: str | None
    latest_decision: str | None
    non_authority: dict[str, bool]


def _requirements_validation_owner_decision_next_action(decision: str) -> str:
    if decision == "AUTHORIZE_REQUIREMENTS_VALIDATION":
        return REQUIREMENTS_VALIDATION_AUTHORIZE_NEXT_ACTION
    if decision == "REQUEST_REQUIREMENTS_DRAFT_REVISION":
        return REQUIREMENTS_VALIDATION_REQUEST_NEXT_ACTION
    return REQUIREMENTS_VALIDATION_BLOCK_NEXT_ACTION


def build_requirements_validation_owner_decision_artifact(
    intake_id: str,
    plan_id: str,
    decision_id: str,
    decision: str,
    owner_summary: str,
    *,
    source_requirements_draft_validation_preflight_state: str,
    source_requirements_draft_validation_preflight_next_action: str,
    source_requirements_draft_provenance_path: str,
    source_requirements_draft_status: str,
    source_requirements_draft_created_at: str,
    planning_workspace_status_at_decision: str,
    created_at: str | None = None,
) -> dict:
    """Build the deterministic REQUIREMENTS_VALIDATION_OWNER_DECISION artifact payload."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)
    validate_requirements_validation_decision_id(decision_id)
    if decision not in REQUIREMENTS_VALIDATION_OWNER_DECISION_VALUES:
        raise ValueError(f"unsupported decision value: {decision!r}")
    if not owner_summary:
        raise ValueError("owner summary must not be empty")

    return {
        "artifact_type": REQUIREMENTS_VALIDATION_OWNER_DECISION_ARTIFACT_TYPE,
        "schema_version": REQUIREMENTS_VALIDATION_OWNER_DECISION_SCHEMA_VERSION,
        "intake_id": intake_id,
        "plan_id": plan_id,
        "decision_id": decision_id,
        "decision": decision,
        "owner_summary": owner_summary,
        "created_at": created_at or _utc_now(),
        "source_command": REQUIREMENTS_VALIDATION_OWNER_DECISION_SOURCE_COMMAND,
        "status": REQUIREMENTS_VALIDATION_OWNER_DECISION_RECORDED_STATE,
        "next_required_action": _requirements_validation_owner_decision_next_action(
            decision
        ),
        "source_requirements_draft_validation_preflight_state": (
            source_requirements_draft_validation_preflight_state
        ),
        "source_requirements_draft_validation_preflight_next_action": (
            source_requirements_draft_validation_preflight_next_action
        ),
        "source_requirements_draft_provenance_path": (
            source_requirements_draft_provenance_path
        ),
        "source_requirements_draft_status": source_requirements_draft_status,
        "source_requirements_draft_created_at": source_requirements_draft_created_at,
        "planning_workspace_status_at_decision": planning_workspace_status_at_decision,
        "non_authority": {
            key: True
            for key in REQUIREMENTS_VALIDATION_OWNER_DECISION_NON_AUTHORITY_FLAGS
        },
    }


def _validate_requirements_validation_owner_decision_payload(
    artifact: object,
    intake_id: str,
    plan_id: str,
    decision_id: str,
) -> list[str]:
    """Return structural validation errors for REQUIREMENTS_VALIDATION_OWNER_DECISION."""
    errors: list[str] = []

    if not isinstance(artifact, dict):
        return ["requirements validation owner decision artifact must be a JSON object"]

    for field in REQUIREMENTS_VALIDATION_OWNER_DECISION_REQUIRED_FIELDS:
        if field not in artifact:
            errors.append(f"missing required field: {field}")

    artifact_type = artifact.get("artifact_type")
    if (
        artifact_type is not None
        and artifact_type != REQUIREMENTS_VALIDATION_OWNER_DECISION_ARTIFACT_TYPE
    ):
        errors.append(
            f"wrong artifact_type: expected "
            f"{REQUIREMENTS_VALIDATION_OWNER_DECISION_ARTIFACT_TYPE!r}, "
            f"found {artifact_type!r}"
        )

    schema_version = artifact.get("schema_version")
    if (
        schema_version is not None
        and schema_version != REQUIREMENTS_VALIDATION_OWNER_DECISION_SCHEMA_VERSION
    ):
        errors.append(
            f"unsupported schema_version: expected "
            f"{REQUIREMENTS_VALIDATION_OWNER_DECISION_SCHEMA_VERSION!r}, "
            f"found {schema_version!r}"
        )

    artifact_intake_id = artifact.get("intake_id")
    if isinstance(artifact_intake_id, str) and artifact_intake_id != intake_id:
        errors.append(
            "intake_id mismatch: "
            f"path {intake_id!r}, artifact {artifact_intake_id!r}"
        )

    artifact_plan_id = artifact.get("plan_id")
    if isinstance(artifact_plan_id, str) and artifact_plan_id != plan_id:
        errors.append(
            f"plan_id mismatch: path {plan_id!r}, artifact {artifact_plan_id!r}"
        )

    artifact_decision_id = artifact.get("decision_id")
    if isinstance(artifact_decision_id, str) and artifact_decision_id != decision_id:
        errors.append(
            "decision_id mismatch: "
            f"path {decision_id!r}, artifact {artifact_decision_id!r}"
        )

    decision = artifact.get("decision")
    if decision is not None and decision not in REQUIREMENTS_VALIDATION_OWNER_DECISION_VALUES:
        errors.append(f"invalid decision value: {decision!r}")

    owner_summary = artifact.get("owner_summary")
    if owner_summary is not None:
        error = _non_empty_string(owner_summary, "owner_summary")
        if error:
            errors.append(error)

    created_at = artifact.get("created_at")
    if created_at is not None and not _parse_created_at(created_at):
        errors.append("created_at must be a parseable ISO-8601 timestamp")

    if artifact.get("status") != REQUIREMENTS_VALIDATION_OWNER_DECISION_RECORDED_STATE:
        errors.append(
            "status must be "
            f"{REQUIREMENTS_VALIDATION_OWNER_DECISION_RECORDED_STATE!r}"
        )

    non_authority = artifact.get("non_authority")
    if non_authority is None:
        errors.append("missing required field: non_authority")
    elif not isinstance(non_authority, dict):
        errors.append("non_authority must be an object")
    else:
        for flag in REQUIREMENTS_VALIDATION_OWNER_DECISION_NON_AUTHORITY_FLAGS:
            if flag not in non_authority:
                errors.append(f"missing non_authority flag: {flag}")
            elif non_authority[flag] is not True:
                errors.append(f"non_authority flag must be true: {flag}")

    return errors


def _format_requirements_validation_owner_decision(
    *,
    decision_path: Path,
    plan_id: str,
    intake_id: str,
    decision_id: str,
    decision: str,
    status: str,
    next_required_action: str,
    workspace_status: str,
    latest_decision_id: str | None,
    latest_decision: str | None,
) -> str:
    lines = [
        f"created requirements validation owner decision artifact: {decision_path}",
        f"artifact_type: {REQUIREMENTS_VALIDATION_OWNER_DECISION_ARTIFACT_TYPE}",
        f"status: {status}",
        f"next_required_action: {next_required_action}",
        f"decision_id: {decision_id}",
        f"decision: {decision}",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
        f"planning_workspace_status: {workspace_status}",
    ]
    if latest_decision_id is not None:
        lines.append(f"latest_requirements_validation_decision_id: {latest_decision_id}")
    if latest_decision is not None:
        lines.append(f"latest_requirements_validation_decision: {latest_decision}")
    lines.extend(
        [
            "mode: owner-provided requirements validation decision only",
            "note: no LLM, no requirements validation, no requirements approval, "
            "no draft promotion, no architecture decision, no implementation plan, "
            "no PLANNING_RUN_SLICE, no validation report, no runner proposals, "
            "no runs, no executor invocation",
            "note: does not mutate local-agentic-spec.md, context-pack.md, "
            "implementation-plan.md, planning-audit.md, or evidence artifacts",
        ]
    )
    if decision == "AUTHORIZE_REQUIREMENTS_VALIDATION":
        lines.append(
            "note: AUTHORIZE_REQUIREMENTS_VALIDATION authorizes only a future "
            "separate requirements validation command; authorization is not validation "
            "and is not approval"
        )
    elif decision == "REQUEST_REQUIREMENTS_DRAFT_REVISION":
        lines.append(
            "note: REQUEST_REQUIREMENTS_DRAFT_REVISION does not revise the draft; "
            "future revision requires separate action"
        )
    elif decision == "BLOCK_REQUIREMENTS_VALIDATION":
        lines.append(
            "note: BLOCK_REQUIREMENTS_VALIDATION blocks future validation authorization "
            "only; it does not delete, rewrite, validate, or approve anything"
        )
    return "\n".join(lines)


def _load_requirements_draft_snapshot_for_owner_decision(
    workspace_dest: Path,
) -> tuple[str, str, str]:
    """Return draft provenance path, status, and created_at when present."""
    draft_provenance_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_FILE
    )
    if not draft_provenance_path.is_file():
        return "", "NOT_PRESENT", ""

    try:
        provenance = json.loads(draft_provenance_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return str(draft_provenance_path), "MALFORMED", ""

    if not isinstance(provenance, dict):
        return str(draft_provenance_path), "MALFORMED", ""

    created_at = provenance.get("created_at")
    return (
        str(draft_provenance_path),
        str(provenance.get("local_agentic_spec_status", REQUIREMENTS_DRAFT_STATUS)),
        created_at if isinstance(created_at, str) else "",
    )


def create_requirements_validation_owner_decision(
    project: Path,
    intake_id: str,
    plan_id: str,
    decision_id: str,
    decision: str,
    summary: str,
) -> RequirementsValidationOwnerDecisionReport:
    """Record a REQUIREMENTS_VALIDATION_OWNER_DECISION without mutating planning artifacts."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)
    validate_requirements_validation_decision_id(decision_id)
    if decision not in REQUIREMENTS_VALIDATION_OWNER_DECISION_VALUES:
        raise ValueError(f"unsupported decision value: {decision!r}")
    if not summary:
        raise ValueError("owner summary must not be empty")

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    _require_valid_goal_intake(project, intake_id)

    workspace_dest = planning_path(project, plan_id)
    if not workspace_dest.is_dir():
        raise FileNotFoundError(f"planning workspace not found: {plan_id}")

    workspace_status = _load_planning_workspace_status(workspace_dest, plan_id)
    if workspace_status != "DRAFT":
        raise ValueError(
            f"planning workspace must be DRAFT for requirements validation owner "
            f"decision, found: {workspace_status!r}"
        )

    orchestrator_provenance_path = workspace_dest / "evidence" / ORCHESTRATOR_PROVENANCE_FILE
    provenance_error = _validate_orchestrator_provenance_binds_intake(
        orchestrator_provenance_path,
        plan_id=plan_id,
        intake_id=intake_id,
    )
    if provenance_error is not None:
        raise ValueError(provenance_error)

    draft_provenance_path, draft_status, draft_created_at = (
        _load_requirements_draft_snapshot_for_owner_decision(workspace_dest)
    )

    if decision == "AUTHORIZE_REQUIREMENTS_VALIDATION":
        preflight = requirements_draft_validation_preflight(project, intake_id, plan_id)
        if preflight.preflight_state != REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_STATE:
            if preflight.blocking_reasons:
                reason_text = "; ".join(preflight.blocking_reasons)
            else:
                reason_text = preflight.preflight_state
            raise ValueError(
                "requirements draft validation preflight not confirmed for "
                f"AUTHORIZE_REQUIREMENTS_VALIDATION: {reason_text}"
            )
        preflight_state = preflight.preflight_state
        preflight_next_action = preflight.next_required_action
        if preflight.requirements_draft_provenance_path is not None:
            draft_provenance_path = str(preflight.requirements_draft_provenance_path)
        draft_status = REQUIREMENTS_DRAFT_STATUS
        if preflight.requirements_draft_provenance_path is not None:
            try:
                provenance = json.loads(
                    preflight.requirements_draft_provenance_path.read_text(
                        encoding="utf-8"
                    )
                )
            except json.JSONDecodeError:
                provenance = {}
            if isinstance(provenance, dict):
                created_at = provenance.get("created_at")
                if isinstance(created_at, str):
                    draft_created_at = created_at
    else:
        preflight_state = REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_STATE
        preflight_next_action = REQUIREMENTS_VALIDATION_PREFLIGHT_NOT_REQUIRED_NEXT_ACTION

    dest = orchestrator_requirements_validation_decision_path(
        project,
        intake_id,
        plan_id,
        decision_id,
    )
    if dest.exists():
        raise FileExistsError(
            f"requirements validation owner decision artifact already exists: {decision_id}"
        )

    artifact = build_requirements_validation_owner_decision_artifact(
        intake_id,
        plan_id,
        decision_id,
        decision,
        summary,
        source_requirements_draft_validation_preflight_state=preflight_state,
        source_requirements_draft_validation_preflight_next_action=preflight_next_action,
        source_requirements_draft_provenance_path=draft_provenance_path,
        source_requirements_draft_status=draft_status,
        source_requirements_draft_created_at=draft_created_at,
        planning_workspace_status_at_decision=workspace_status,
    )

    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_json(dest, artifact)

    decisions = list_requirements_validation_owner_decisions(
        project,
        intake_id,
        plan_id,
    )
    latest_decision_id = decisions[-1].decision_id if decisions else None
    latest_decision = decisions[-1].decision if decisions else None

    non_authority = {
        key: True for key in REQUIREMENTS_VALIDATION_OWNER_DECISION_NON_AUTHORITY_FLAGS
    }
    next_required_action = _requirements_validation_owner_decision_next_action(decision)
    output = _format_requirements_validation_owner_decision(
        decision_path=dest,
        plan_id=plan_id,
        intake_id=intake_id,
        decision_id=decision_id,
        decision=decision,
        status=REQUIREMENTS_VALIDATION_OWNER_DECISION_RECORDED_STATE,
        next_required_action=next_required_action,
        workspace_status=workspace_status,
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
    )
    return RequirementsValidationOwnerDecisionReport(
        output=output,
        decision_path=dest,
        plan_id=plan_id,
        intake_id=intake_id,
        decision_id=decision_id,
        decision=decision,
        status=REQUIREMENTS_VALIDATION_OWNER_DECISION_RECORDED_STATE,
        next_required_action=next_required_action,
        workspace_status=workspace_status,
        latest_decision_id=latest_decision_id,
        latest_decision=latest_decision,
        non_authority=non_authority,
    )


def load_requirements_validation_owner_decision(
    project: Path,
    intake_id: str,
    plan_id: str,
    decision_id: str,
) -> dict:
    """Load a REQUIREMENTS_VALIDATION_OWNER_DECISION artifact from disk (read-only)."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)
    validate_requirements_validation_decision_id(decision_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = orchestrator_requirements_validation_decision_path(
        project,
        intake_id,
        plan_id,
        decision_id,
    )
    if not path.is_file():
        raise FileNotFoundError(
            f"requirements validation owner decision artifact not found: {decision_id}"
        )

    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid requirements validation decision artifact for {decision_id}: "
            f"{exc.msg}"
        ) from exc

    if not isinstance(artifact, dict):
        raise ValueError(
            f"invalid requirements validation decision artifact for {decision_id}: "
            "expected object"
        )

    return artifact


def list_requirements_validation_owner_decisions(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> tuple[RequirementsValidationOwnerDecisionRecord, ...]:
    """List requirements validation owner decisions for an intake/plan (read-only)."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    decisions_dir = (
        orchestrator_intake_path(project, intake_id)
        / REQUIREMENTS_VALIDATION_DECISIONS_DIR
        / plan_id
    )
    if not decisions_dir.is_dir():
        return ()

    records: list[RequirementsValidationOwnerDecisionRecord] = []
    for path in sorted(decisions_dir.glob("*.json")):
        decision_id = path.stem
        try:
            artifact = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(artifact, dict):
            continue
        created_at = artifact.get("created_at")
        if not isinstance(created_at, str):
            created_at = ""
        decision = artifact.get("decision")
        if not isinstance(decision, str):
            decision = ""
        records.append(
            RequirementsValidationOwnerDecisionRecord(
                decision_id=decision_id,
                decision=decision,
                created_at=created_at,
                path=path,
            )
        )

    records.sort(key=lambda record: (record.created_at, record.decision_id))
    return tuple(records)


def validate_requirements_validation_owner_decision(
    project: Path,
    intake_id: str,
    plan_id: str,
    decision_id: str,
) -> RequirementsValidationOwnerDecisionValidationReport:
    """Strict read-only validation of a REQUIREMENTS_VALIDATION_OWNER_DECISION artifact."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)
    validate_requirements_validation_decision_id(decision_id)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    path = orchestrator_requirements_validation_decision_path(
        project,
        intake_id,
        plan_id,
        decision_id,
    )
    if not path.is_file():
        raise FileNotFoundError(
            f"requirements validation owner decision artifact not found: {decision_id}"
        )

    raw_text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    try:
        artifact = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        errors = [f"malformed JSON: {exc.msg}"]
    else:
        errors = _validate_requirements_validation_owner_decision_payload(
            artifact,
            intake_id,
            plan_id,
            decision_id,
        )

    output_lines = [
        f"requirements validation owner decision validation: {path}",
        f"valid: {not errors}",
    ]
    if errors:
        output_lines.append("errors:")
        for error in errors:
            output_lines.append(f"  - {error}")

    return RequirementsValidationOwnerDecisionValidationReport(
        output="\n".join(output_lines),
        valid=not errors,
        errors=tuple(errors),
    )


def _load_validated_requirements_validation_owner_decisions(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> tuple[tuple[RequirementsValidationOwnerDecisionRecord, ...], list[str]]:
    """Load and validate all plan-scoped requirements-validation owner decisions."""
    decisions_dir = (
        orchestrator_intake_path(project, intake_id)
        / REQUIREMENTS_VALIDATION_DECISIONS_DIR
        / plan_id
    )
    if not decisions_dir.is_dir():
        return (), []

    records: list[RequirementsValidationOwnerDecisionRecord] = []
    errors: list[str] = []
    for path in sorted(decisions_dir.glob("*.json")):
        decision_id = path.stem
        try:
            artifact = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"malformed decision artifact {decision_id}: {exc.msg}")
            continue
        if not isinstance(artifact, dict):
            errors.append(
                f"malformed decision artifact {decision_id}: expected object"
            )
            continue
        payload_errors = _validate_requirements_validation_owner_decision_payload(
            artifact,
            intake_id,
            plan_id,
            decision_id,
        )
        if payload_errors:
            errors.extend(
                f"decision artifact {decision_id}: {error}" for error in payload_errors
            )
            continue
        records.append(
            RequirementsValidationOwnerDecisionRecord(
                decision_id=artifact["decision_id"],
                decision=artifact["decision"],
                created_at=artifact["created_at"],
                path=path,
            )
        )

    records.sort(key=lambda record: (record.created_at, record.decision_id))
    return tuple(records), errors


def _validate_requirements_validation_owner_decision_coherence(
    artifact: dict,
    *,
    preflight: RequirementsDraftValidationPreflightReport,
    draft_provenance_path: Path,
) -> str | None:
    """Return a blocking reason when an owner decision references stale draft metadata."""
    expected_path = str(draft_provenance_path)
    artifact_path = artifact.get("source_requirements_draft_provenance_path")
    if artifact_path != expected_path:
        return (
            "requirements validation owner decision references stale draft "
            f"provenance path: expected {expected_path!r}, found {artifact_path!r}"
        )

    expected_status = REQUIREMENTS_DRAFT_STATUS
    artifact_status = artifact.get("source_requirements_draft_status")
    if artifact_status != expected_status:
        return (
            "requirements validation owner decision references stale draft "
            f"status: expected {expected_status!r}, found {artifact_status!r}"
        )

    try:
        provenance = json.loads(draft_provenance_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return (
            "requirements validation owner decision references draft with "
            "malformed provenance"
        )
    if not isinstance(provenance, dict):
        return (
            "requirements validation owner decision references draft with "
            "malformed provenance: expected object"
        )

    expected_created_at = provenance.get("created_at")
    artifact_created_at = artifact.get("source_requirements_draft_created_at")
    if artifact_created_at != expected_created_at:
        return (
            "requirements validation owner decision references stale draft "
            f"created_at: expected {expected_created_at!r}, found {artifact_created_at!r}"
        )

    if (
        artifact.get("source_requirements_draft_validation_preflight_state")
        != REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_STATE
    ):
        return (
            "requirements validation owner decision references stale preflight state: "
            f"expected {REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_STATE!r}, "
            f"found {artifact.get('source_requirements_draft_validation_preflight_state')!r}"
        )

    if (
        artifact.get("source_requirements_draft_validation_preflight_next_action")
        != REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_NEXT_ACTION
    ):
        return (
            "requirements validation owner decision references stale preflight next "
            "action: "
            f"expected {REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_NEXT_ACTION!r}, "
            f"found {artifact.get('source_requirements_draft_validation_preflight_next_action')!r}"
        )

    if (
        artifact.get("source_requirements_draft_validation_preflight_state")
        != preflight.preflight_state
    ):
        return (
            "requirements validation owner decision preflight snapshot no longer "
            "matches current preflight state: "
            f"artifact={artifact.get('source_requirements_draft_validation_preflight_state')!r}, "
            f"current={preflight.preflight_state!r}"
        )

    if (
        artifact.get("source_requirements_draft_validation_preflight_next_action")
        != preflight.next_required_action
    ):
        return (
            "requirements validation owner decision preflight snapshot no longer "
            "matches current preflight next action: "
            f"artifact={artifact.get('source_requirements_draft_validation_preflight_next_action')!r}, "
            f"current={preflight.next_required_action!r}"
        )

    if artifact.get("planning_workspace_status_at_decision") != "DRAFT":
        return (
            "requirements validation owner decision planning_workspace_status_at_decision "
            f"is not DRAFT: found {artifact.get('planning_workspace_status_at_decision')!r}"
        )

    artifact_next_action = artifact.get("next_required_action")
    if artifact_next_action != REQUIREMENTS_VALIDATION_AUTHORIZE_NEXT_ACTION:
        return (
            "requirements validation owner decision has stale or incoherent "
            f"next_required_action: expected {REQUIREMENTS_VALIDATION_AUTHORIZE_NEXT_ACTION!r}, "
            f"found {artifact_next_action!r}"
        )

    return None


def _format_requirements_validation_execution_check(
    *,
    plan_id: str,
    intake_id: str,
    planning_workspace_status: str | None,
    local_agentic_spec_status: str | None,
    local_agentic_spec_path: Path | None,
    requirements_draft_provenance_path: Path | None,
    latest_requirements_validation_owner_decision_id: str | None,
    latest_requirements_validation_owner_decision: str | None,
    latest_requirements_validation_owner_decision_created_at: str | None,
    latest_requirements_validation_owner_decision_path: Path | None,
    source_requirements_draft_validation_preflight_state: str | None,
    source_requirements_draft_validation_preflight_next_action: str | None,
    execution_check_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
    checked_at: str,
    non_authority: dict[str, bool],
) -> str:
    lines = [
        "requirements validation execution check",
        f"plan_id: {plan_id}",
        f"intake_id: {intake_id}",
    ]
    if planning_workspace_status is not None:
        lines.append(f"planning_workspace_status: {planning_workspace_status}")
    if local_agentic_spec_status is not None:
        lines.append(f"local_agentic_spec_status: {local_agentic_spec_status}")
    if local_agentic_spec_path is not None:
        lines.append(f"local_agentic_spec_path: {local_agentic_spec_path}")
    if requirements_draft_provenance_path is not None:
        lines.append(
            "requirements_draft_provenance_path: "
            f"{requirements_draft_provenance_path}"
        )
    if latest_requirements_validation_owner_decision_id is not None:
        lines.append(
            "latest_requirements_validation_owner_decision_id: "
            f"{latest_requirements_validation_owner_decision_id}"
        )
    if latest_requirements_validation_owner_decision is not None:
        lines.append(
            "latest_requirements_validation_owner_decision: "
            f"{latest_requirements_validation_owner_decision}"
        )
    if latest_requirements_validation_owner_decision_created_at is not None:
        lines.append(
            "latest_requirements_validation_owner_decision_created_at: "
            f"{latest_requirements_validation_owner_decision_created_at}"
        )
    if latest_requirements_validation_owner_decision_path is not None:
        lines.append(
            "latest_requirements_validation_owner_decision_path: "
            f"{latest_requirements_validation_owner_decision_path}"
        )
    if source_requirements_draft_validation_preflight_state is not None:
        lines.append(
            "source_requirements_draft_validation_preflight_state: "
            f"{source_requirements_draft_validation_preflight_state}"
        )
    if source_requirements_draft_validation_preflight_next_action is not None:
        lines.append(
            "source_requirements_draft_validation_preflight_next_action: "
            f"{source_requirements_draft_validation_preflight_next_action}"
        )
    lines.append(f"execution_check_state: {execution_check_state}")
    lines.append(f"next_required_action: {next_required_action}")
    lines.append(f"checked_at: {checked_at}")
    if blocking_reasons:
        lines.append("blocking_reasons:")
        for reason in blocking_reasons:
            lines.append(f"  - {reason}")
    lines.append("non_authority:")
    for flag in REQUIREMENTS_VALIDATION_EXECUTION_CHECK_NON_AUTHORITY_FLAGS:
        lines.append(f"  {flag}: {str(non_authority.get(flag, False)).lower()}")
    lines.append(
        "note: requirements validation execution check is read-only; "
        "not requirements validation, not requirements approval, "
        "not architecture decision, not implementation planning, "
        "and no files were modified"
    )
    if execution_check_state == REQUIREMENTS_VALIDATION_EXECUTION_CHECK_CONFIRMED_STATE:
        lines.append(
            "note: execution check confirmed for a future requirements validation "
            "command only; no requirements were validated or approved"
        )
        lines.append(
            "note: successful check is not validation, not requirements approval, "
            "not architecture decision, not implementation plan, not workspace "
            "validation or approval, and does not authorize runner or executor"
        )
    return "\n".join(lines)


@dataclass(frozen=True)
class RequirementsValidationExecutionCheckReport:
    output: str
    execution_check_state: str
    next_required_action: str
    plan_id: str
    intake_id: str
    planning_workspace_status: str | None
    local_agentic_spec_status: str | None
    local_agentic_spec_path: Path | None
    requirements_draft_provenance_path: Path | None
    latest_requirements_validation_owner_decision_id: str | None
    latest_requirements_validation_owner_decision: str | None
    latest_requirements_validation_owner_decision_created_at: str | None
    latest_requirements_validation_owner_decision_path: Path | None
    source_requirements_draft_validation_preflight_state: str | None
    source_requirements_draft_validation_preflight_next_action: str | None
    checked_at: str
    blocking_reasons: tuple[str, ...]
    non_authority: dict[str, bool]


def _build_requirements_validation_execution_check_report(
    *,
    plan_id: str,
    intake_id: str,
    planning_workspace_status: str | None = None,
    local_agentic_spec_status: str | None = None,
    local_agentic_spec_path: Path | None = None,
    requirements_draft_provenance_path: Path | None = None,
    latest_requirements_validation_owner_decision_id: str | None = None,
    latest_requirements_validation_owner_decision: str | None = None,
    latest_requirements_validation_owner_decision_created_at: str | None = None,
    latest_requirements_validation_owner_decision_path: Path | None = None,
    source_requirements_draft_validation_preflight_state: str | None = None,
    source_requirements_draft_validation_preflight_next_action: str | None = None,
    execution_check_state: str,
    next_required_action: str,
    blocking_reasons: list[str],
    checked_at: str,
    non_authority: dict[str, bool],
) -> RequirementsValidationExecutionCheckReport:
    output = _format_requirements_validation_execution_check(
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=planning_workspace_status,
        local_agentic_spec_status=local_agentic_spec_status,
        local_agentic_spec_path=local_agentic_spec_path,
        requirements_draft_provenance_path=requirements_draft_provenance_path,
        latest_requirements_validation_owner_decision_id=(
            latest_requirements_validation_owner_decision_id
        ),
        latest_requirements_validation_owner_decision=(
            latest_requirements_validation_owner_decision
        ),
        latest_requirements_validation_owner_decision_created_at=(
            latest_requirements_validation_owner_decision_created_at
        ),
        latest_requirements_validation_owner_decision_path=(
            latest_requirements_validation_owner_decision_path
        ),
        source_requirements_draft_validation_preflight_state=(
            source_requirements_draft_validation_preflight_state
        ),
        source_requirements_draft_validation_preflight_next_action=(
            source_requirements_draft_validation_preflight_next_action
        ),
        execution_check_state=execution_check_state,
        next_required_action=next_required_action,
        blocking_reasons=blocking_reasons,
        checked_at=checked_at,
        non_authority=non_authority,
    )
    return RequirementsValidationExecutionCheckReport(
        output=output,
        execution_check_state=execution_check_state,
        next_required_action=next_required_action,
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=planning_workspace_status,
        local_agentic_spec_status=local_agentic_spec_status,
        local_agentic_spec_path=local_agentic_spec_path,
        requirements_draft_provenance_path=requirements_draft_provenance_path,
        latest_requirements_validation_owner_decision_id=(
            latest_requirements_validation_owner_decision_id
        ),
        latest_requirements_validation_owner_decision=(
            latest_requirements_validation_owner_decision
        ),
        latest_requirements_validation_owner_decision_created_at=(
            latest_requirements_validation_owner_decision_created_at
        ),
        latest_requirements_validation_owner_decision_path=(
            latest_requirements_validation_owner_decision_path
        ),
        source_requirements_draft_validation_preflight_state=(
            source_requirements_draft_validation_preflight_state
        ),
        source_requirements_draft_validation_preflight_next_action=(
            source_requirements_draft_validation_preflight_next_action
        ),
        checked_at=checked_at,
        blocking_reasons=tuple(blocking_reasons),
        non_authority=non_authority,
    )


def requirements_validation_execution_check(
    project: Path,
    intake_id: str,
    plan_id: str,
) -> RequirementsValidationExecutionCheckReport:
    """Read-only pre-execution check for future requirements validation authorization."""
    validate_intake_id(intake_id)
    validate_plan_id(plan_id)

    checked_at = _utc_now()
    non_authority = {
        key: True for key in REQUIREMENTS_VALIDATION_EXECUTION_CHECK_NON_AUTHORITY_FLAGS
    }
    workspace_dest = planning_path(project, plan_id)
    local_agentic_spec_path = workspace_dest / "local-agentic-spec.md"
    draft_provenance_path = (
        workspace_dest / "evidence" / ORCHESTRATOR_REQUIREMENTS_DRAFT_PROVENANCE_FILE
    )

    def _blocked(
        state: str,
        next_action: str,
        *,
        blocking_reasons: list[str] | None = None,
        planning_workspace_status: str | None = None,
        local_agentic_spec_status: str | None = None,
        latest_requirements_validation_owner_decision_id: str | None = None,
        latest_requirements_validation_owner_decision: str | None = None,
        latest_requirements_validation_owner_decision_created_at: str | None = None,
        latest_requirements_validation_owner_decision_path: Path | None = None,
        source_requirements_draft_validation_preflight_state: str | None = None,
        source_requirements_draft_validation_preflight_next_action: str | None = None,
    ) -> RequirementsValidationExecutionCheckReport:
        return _build_requirements_validation_execution_check_report(
            plan_id=plan_id,
            intake_id=intake_id,
            planning_workspace_status=planning_workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            local_agentic_spec_path=(
                local_agentic_spec_path if local_agentic_spec_path.is_file() else None
            ),
            requirements_draft_provenance_path=(
                draft_provenance_path if draft_provenance_path.is_file() else None
            ),
            latest_requirements_validation_owner_decision_id=(
                latest_requirements_validation_owner_decision_id
            ),
            latest_requirements_validation_owner_decision=(
                latest_requirements_validation_owner_decision
            ),
            latest_requirements_validation_owner_decision_created_at=(
                latest_requirements_validation_owner_decision_created_at
            ),
            latest_requirements_validation_owner_decision_path=(
                latest_requirements_validation_owner_decision_path
            ),
            source_requirements_draft_validation_preflight_state=(
                source_requirements_draft_validation_preflight_state
            ),
            source_requirements_draft_validation_preflight_next_action=(
                source_requirements_draft_validation_preflight_next_action
            ),
            execution_check_state=state,
            next_required_action=next_action,
            blocking_reasons=blocking_reasons or [],
            checked_at=checked_at,
            non_authority=non_authority,
        )

    preflight = requirements_draft_validation_preflight(project, intake_id, plan_id)
    preflight_state = preflight.preflight_state
    preflight_next_action = preflight.next_required_action
    planning_workspace_status = preflight.planning_workspace_status
    local_agentic_spec_status = preflight.local_agentic_spec_status
    draft_provenance_report_path = preflight.requirements_draft_provenance_path

    if preflight_state != REQUIREMENTS_DRAFT_VALIDATION_PREFLIGHT_CONFIRMED_STATE:
        return _blocked(
            preflight_state,
            preflight_next_action,
            planning_workspace_status=planning_workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            source_requirements_draft_validation_preflight_state=preflight_state,
            source_requirements_draft_validation_preflight_next_action=preflight_next_action,
            blocking_reasons=list(preflight.blocking_reasons),
        )

    decision_records, decision_errors = _load_validated_requirements_validation_owner_decisions(
        project,
        intake_id,
        plan_id,
    )
    if decision_errors:
        return _blocked(
            "BLOCKED_MALFORMED_REQUIREMENTS_VALIDATION_OWNER_DECISION",
            "FIX_REQUIREMENTS_VALIDATION_OWNER_DECISION_ARTIFACTS",
            planning_workspace_status=planning_workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            source_requirements_draft_validation_preflight_state=preflight_state,
            source_requirements_draft_validation_preflight_next_action=preflight_next_action,
            blocking_reasons=decision_errors,
        )

    if not decision_records:
        return _blocked(
            "BLOCKED_NO_REQUIREMENTS_VALIDATION_OWNER_DECISION",
            "CREATE_REQUIREMENTS_VALIDATION_OWNER_DECISION",
            planning_workspace_status=planning_workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            source_requirements_draft_validation_preflight_state=preflight_state,
            source_requirements_draft_validation_preflight_next_action=preflight_next_action,
            blocking_reasons=[
                "no requirements validation owner decision artifacts found "
                f"for intake {intake_id!r} and plan {plan_id!r}"
            ],
        )

    latest_record = decision_records[-1]
    latest_decision_id = latest_record.decision_id
    latest_decision = latest_record.decision
    latest_decision_created_at = latest_record.created_at
    latest_decision_path = latest_record.path

    if latest_decision == "REQUEST_REQUIREMENTS_DRAFT_REVISION":
        return _blocked(
            "BLOCKED_LATEST_REQUIREMENTS_VALIDATION_DECISION_REQUESTS_REVISION",
            "REVISE_REQUIREMENTS_DRAFT_BEFORE_VALIDATION",
            planning_workspace_status=planning_workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_requirements_validation_owner_decision_id=latest_decision_id,
            latest_requirements_validation_owner_decision=latest_decision,
            latest_requirements_validation_owner_decision_created_at=latest_decision_created_at,
            latest_requirements_validation_owner_decision_path=latest_decision_path,
            source_requirements_draft_validation_preflight_state=preflight_state,
            source_requirements_draft_validation_preflight_next_action=preflight_next_action,
        )

    if latest_decision == "BLOCK_REQUIREMENTS_VALIDATION":
        return _blocked(
            "BLOCKED_LATEST_REQUIREMENTS_VALIDATION_DECISION_BLOCKS_VALIDATION",
            "STOP_REQUIREMENTS_VALIDATION",
            planning_workspace_status=planning_workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_requirements_validation_owner_decision_id=latest_decision_id,
            latest_requirements_validation_owner_decision=latest_decision,
            latest_requirements_validation_owner_decision_created_at=latest_decision_created_at,
            latest_requirements_validation_owner_decision_path=latest_decision_path,
            source_requirements_draft_validation_preflight_state=preflight_state,
            source_requirements_draft_validation_preflight_next_action=preflight_next_action,
        )

    if latest_decision != "AUTHORIZE_REQUIREMENTS_VALIDATION":
        return _blocked(
            "BLOCKED_LATEST_REQUIREMENTS_VALIDATION_DECISION_NOT_AUTHORIZE",
            "AUTHORIZE_REQUIREMENTS_VALIDATION_WITH_OWNER_DECISION",
            planning_workspace_status=planning_workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_requirements_validation_owner_decision_id=latest_decision_id,
            latest_requirements_validation_owner_decision=latest_decision,
            latest_requirements_validation_owner_decision_created_at=latest_decision_created_at,
            latest_requirements_validation_owner_decision_path=latest_decision_path,
            source_requirements_draft_validation_preflight_state=preflight_state,
            source_requirements_draft_validation_preflight_next_action=preflight_next_action,
            blocking_reasons=[f"unsupported latest decision value: {latest_decision!r}"],
        )

    if draft_provenance_report_path is None or not draft_provenance_report_path.is_file():
        return _blocked(
            "BLOCKED_MISSING_REQUIREMENTS_DRAFT_PROVENANCE",
            "RESTORE_OR_GENERATE_REQUIREMENTS_DRAFT",
            planning_workspace_status=planning_workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_requirements_validation_owner_decision_id=latest_decision_id,
            latest_requirements_validation_owner_decision=latest_decision,
            latest_requirements_validation_owner_decision_created_at=latest_decision_created_at,
            latest_requirements_validation_owner_decision_path=latest_decision_path,
            source_requirements_draft_validation_preflight_state=preflight_state,
            source_requirements_draft_validation_preflight_next_action=preflight_next_action,
            blocking_reasons=[
                "requirements draft provenance missing for coherence check"
            ],
        )

    latest_artifact = json.loads(latest_decision_path.read_text(encoding="utf-8"))
    coherence_error = _validate_requirements_validation_owner_decision_coherence(
        latest_artifact,
        preflight=preflight,
        draft_provenance_path=draft_provenance_report_path,
    )
    if coherence_error is not None:
        return _blocked(
            "BLOCKED_REQUIREMENTS_VALIDATION_OWNER_DECISION_STALE_OR_INCOHERENT",
            "FIX_REQUIREMENTS_VALIDATION_OWNER_DECISION_ARTIFACTS",
            planning_workspace_status=planning_workspace_status,
            local_agentic_spec_status=local_agentic_spec_status,
            latest_requirements_validation_owner_decision_id=latest_decision_id,
            latest_requirements_validation_owner_decision=latest_decision,
            latest_requirements_validation_owner_decision_created_at=latest_decision_created_at,
            latest_requirements_validation_owner_decision_path=latest_decision_path,
            source_requirements_draft_validation_preflight_state=preflight_state,
            source_requirements_draft_validation_preflight_next_action=preflight_next_action,
            blocking_reasons=[coherence_error],
        )

    return _build_requirements_validation_execution_check_report(
        plan_id=plan_id,
        intake_id=intake_id,
        planning_workspace_status=planning_workspace_status,
        local_agentic_spec_status=local_agentic_spec_status,
        local_agentic_spec_path=local_agentic_spec_path,
        requirements_draft_provenance_path=draft_provenance_report_path,
        latest_requirements_validation_owner_decision_id=latest_decision_id,
        latest_requirements_validation_owner_decision=latest_decision,
        latest_requirements_validation_owner_decision_created_at=latest_decision_created_at,
        latest_requirements_validation_owner_decision_path=latest_decision_path,
        source_requirements_draft_validation_preflight_state=preflight_state,
        source_requirements_draft_validation_preflight_next_action=preflight_next_action,
        execution_check_state=REQUIREMENTS_VALIDATION_EXECUTION_CHECK_CONFIRMED_STATE,
        next_required_action=REQUIREMENTS_VALIDATION_EXECUTION_CHECK_CONFIRMED_NEXT_ACTION,
        blocking_reasons=[],
        checked_at=checked_at,
        non_authority=non_authority,
    )


def create_goal_intake(project: Path, intake_id: str, raw_goal: str) -> Path:
    """Create a goal intake artifact under .agent-os/orchestrator/intakes/<id>/."""
    artifact = build_goal_intake_artifact(intake_id, raw_goal)

    workspace = workspace_path(project)
    if not workspace.is_dir():
        raise FileNotFoundError("no workspace found (run `agent-os init` first)")

    dest = orchestrator_intake_path(project, intake_id) / GOAL_INTAKE_FILE
    if dest.exists():
        raise FileExistsError(f"goal intake artifact already exists: {intake_id}")

    dest.parent.mkdir(parents=True, exist_ok=True)
    _write_json(dest, artifact)
    return dest
