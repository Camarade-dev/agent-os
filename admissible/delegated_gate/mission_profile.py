"""Canonical, data-only native mission profiles (Gate L1C).

A :class:`NativeMissionProfile` is the single serializable authority for one
owner-defined native mission: mission text, gate contract inputs, checkpoint
command definitions, the complete behavioral-verifier source, required Git
facts, and every execution/output budget.  It is canonical data only — no
callable, class object, closure, filesystem handle, or environment-selected
behavior can be represented — and it is bound by one non-self-referential
fingerprint: ``profile_fingerprint`` is the SHA-256 of the canonical JSON
bytes of the complete validated profile body, computed with the fingerprint
field excluded from its own input.

Trusted executable mappings (``fixture_id`` -> builder, ``profile_id`` ->
profile) live in source-code registries in :mod:`native_canary`; this module
holds only the values those registries serve.  The complete validated profile
of a new run is persisted inside its v4 authorization payload, so evidence-only
reconstruction never consults a registry after execution.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

from admissible.delegated_gate.canonical import (
    fingerprint,
    require_bool,
    require_exact_keys,
    require_identifier,
    require_nonempty_text,
    require_safe_relative_path,
    require_sha256,
    require_strict_int,
    require_string_list,
)
from admissible.delegated_gate.models import EvidenceKind, VerificationCommand
from admissible.delegated_gate.native_executor import (
    PROMPT_TRANSPORT_ACP_STDIO,
    PROMPT_TRANSPORT_ARGV,
    require_prompt_transport,
)


MISSION_PROFILE_SCHEMA_VERSION = "admissible_native_mission_profile_v1"
MISSION_PROFILE_SCHEMA_VERSION_V2 = "admissible_native_mission_profile_v2"
MISSION_PROFILE_SCHEMA_VERSION_V3 = "admissible_native_mission_profile_v3"
MISSION_PROFILE_SCHEMA_VERSION_V4 = "admissible_native_mission_profile_v4"
MISSION_PROFILE_SCHEMA_VERSION_V5 = "admissible_native_mission_profile_v5"
MAX_CLAIMS_PER_AUTHORITY = 256
MAX_DEPENDENCIES_PER_CLAIM = 64
MAX_NON_CLAIMS_PER_CLAIM = 64
MAX_VERIFICATION_OBLIGATIONS = 256
MAX_CLAIM_REFERENCES_PER_OBLIGATION = 64
MAX_NON_CLAIMS_PER_VERIFICATION_OBLIGATION = 64
MAX_NEGATIVE_CONTROLS_PER_OBLIGATION = 64
MAX_REFERENCE_CASES_PER_OBLIGATION = 64
MAX_VERIFICATION_EVIDENCE_BINDINGS = 256
# The one authorized one-shot budget shape:
# (provider invocations, native attempts, repair rounds, auditors, retries).
ONE_SHOT_PROFILE_BUDGETS: tuple[int, int, int, int, int] = (1, 1, 0, 0, 0)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class WorkspaceSourceKind(str, Enum):
    REGISTERED_FIXTURE = "REGISTERED_FIXTURE"
    EXISTING_LOCAL_GIT_REPOSITORY = "EXISTING_LOCAL_GIT_REPOSITORY"


class VerificationMode(str, Enum):
    OBSERVED_ONLY = "OBSERVED_ONLY"
    FROZEN_BEHAVIORAL = "FROZEN_BEHAVIORAL"


class ClaimAuthorship(str, Enum):
    OWNER_AUTHORED = "OWNER_AUTHORED"
    TEMPLATE_AUTHORED = "TEMPLATE_AUTHORED"


class ClaimObligationLevel(str, Enum):
    MANDATORY = "MANDATORY"
    OPTIONAL = "OPTIONAL"
    ADVISORY = "ADVISORY"


class ClaimSetCoverageStatus(str, Enum):
    NOT_ASSESSED = "NOT_ASSESSED"


class VerificationPlanAuthorship(str, Enum):
    OWNER_AUTHORED = "OWNER_AUTHORED"
    TEMPLATE_AUTHORED = "TEMPLATE_AUTHORED"


class VerificationPlanCoverageStatus(str, Enum):
    NOT_ASSESSED = "NOT_ASSESSED"


class VerificationStrategy(str, Enum):
    CHECKPOINT_COMMAND = "CHECKPOINT_COMMAND"
    FROZEN_BEHAVIORAL_VERIFIER = "FROZEN_BEHAVIORAL_VERIFIER"
    HUMAN_RUBRIC_OBSERVATION = "HUMAN_RUBRIC_OBSERVATION"


class VerificationAcceptancePredicate(str, Enum):
    EXIT_CODE_ZERO = "EXIT_CODE_ZERO"
    HUMAN_RUBRIC_PASS = "HUMAN_RUBRIC_PASS"


class VerificationEvidenceBindingAuthorship(str, Enum):
    OWNER_AUTHORED = "OWNER_AUTHORED"
    TEMPLATE_AUTHORED = "TEMPLATE_AUTHORED"


class VerificationEvidenceBindingCoverageStatus(str, Enum):
    NOT_ASSESSED = "NOT_ASSESSED"


class VerificationEvidenceSourceAuthorityType(str, Enum):
    CHECKPOINT_COMMAND_AUTHORITY = "CHECKPOINT_COMMAND_AUTHORITY"
    FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY = "FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY"


@dataclass(frozen=True)
class ResultClaim:
    """One owner-ordered, inert result claim."""

    claim_id: str
    statement: str
    obligation_level: ClaimObligationLevel
    depends_on: tuple[str, ...]
    non_claims: tuple[str, ...]

    def validated(self) -> "ResultClaim":
        require_identifier(self.claim_id, "claim_id")
        require_nonempty_text(self.statement, "claim statement", max_bytes=4096)
        if not isinstance(self.obligation_level, ClaimObligationLevel):
            raise ValueError("claim obligation level is invalid")
        if not isinstance(self.depends_on, tuple):
            raise ValueError("claim dependencies must be an ordered tuple")
        if len(self.depends_on) > MAX_DEPENDENCIES_PER_CLAIM:
            raise ValueError(f"claim dependencies cannot exceed {MAX_DEPENDENCIES_PER_CLAIM}")
        for dependency in self.depends_on:
            require_identifier(dependency, "claim dependency")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise ValueError("claim dependencies must be unique")
        if self.claim_id in self.depends_on:
            raise ValueError("claim cannot depend on itself")
        if not isinstance(self.non_claims, tuple):
            raise ValueError("non-claims must be an ordered tuple")
        if len(self.non_claims) > MAX_NON_CLAIMS_PER_CLAIM:
            raise ValueError(f"non-claims cannot exceed {MAX_NON_CLAIMS_PER_CLAIM}")
        for statement in self.non_claims:
            require_nonempty_text(statement, "non-claim statement", max_bytes=4096)
        if len(set(self.non_claims)) != len(self.non_claims):
            raise ValueError("non-claims must be unique")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "statement": self.statement,
            "obligation_level": self.obligation_level.value,
            "depends_on": list(self.depends_on),
            "non_claims": list(self.non_claims),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ResultClaim":
        require_exact_keys(data, set(cls.__dataclass_fields__), "result claim")
        raw_dependencies = data["depends_on"]
        if not isinstance(raw_dependencies, list):
            raise ValueError("claim dependencies must be an ordered array")
        if len(raw_dependencies) > MAX_DEPENDENCIES_PER_CLAIM:
            raise ValueError(f"claim dependencies cannot exceed {MAX_DEPENDENCIES_PER_CLAIM}")
        raw_non_claims = data["non_claims"]
        if not isinstance(raw_non_claims, list):
            raise ValueError("non-claims must be an ordered array")
        if len(raw_non_claims) > MAX_NON_CLAIMS_PER_CLAIM:
            raise ValueError(f"non-claims cannot exceed {MAX_NON_CLAIMS_PER_CLAIM}")
        try:
            obligation_level = ClaimObligationLevel(data["obligation_level"])
        except (TypeError, ValueError) as exc:
            raise ValueError("claim obligation level is invalid") from exc
        return cls(
            claim_id=data["claim_id"],
            statement=data["statement"],
            obligation_level=obligation_level,
            depends_on=require_string_list(raw_dependencies, "claim dependencies"),
            non_claims=require_string_list(raw_non_claims, "non-claims"),
        ).validated()


@dataclass(frozen=True)
class ClaimAuthority:
    """Canonical, inert authority for an owner-ordered set of claims."""

    authorship: ClaimAuthorship
    coverage_status: ClaimSetCoverageStatus
    claims: tuple[ResultClaim, ...]

    def validated(self) -> "ClaimAuthority":
        if not isinstance(self.authorship, ClaimAuthorship):
            raise ValueError("claim authorship is invalid")
        if self.coverage_status is not ClaimSetCoverageStatus.NOT_ASSESSED:
            raise ValueError("claim coverage status must be NOT_ASSESSED")
        if not isinstance(self.claims, tuple) or not self.claims:
            raise ValueError("claims must be a non-empty ordered tuple")
        if len(self.claims) > MAX_CLAIMS_PER_AUTHORITY:
            raise ValueError(f"claims cannot exceed {MAX_CLAIMS_PER_AUTHORITY}")
        claim_ids: list[str] = []
        for claim in self.claims:
            if not isinstance(claim, ResultClaim):
                raise ValueError("claim has an invalid type")
            claim.validated()
            claim_ids.append(claim.claim_id)
        if len(set(claim_ids)) != len(claim_ids):
            raise ValueError("claim identities must be unique")
        known_ids = set(claim_ids)
        for claim in self.claims:
            if not set(claim.depends_on) <= known_ids:
                raise ValueError("claim dependency target is missing")
        index_by_id = {claim_id: index for index, claim_id in enumerate(claim_ids)}
        dependencies = tuple(
            tuple(index_by_id[dependency] for dependency in claim.depends_on)
            for claim in self.claims
        )
        # 0 = unseen, 1 = active, 2 = complete.  Both roots and dependency
        # edges retain owner-specified order; the indices are validation-only.
        state = [0] * len(self.claims)
        for root in range(len(self.claims)):
            if state[root] != 0:
                continue
            state[root] = 1
            stack: list[tuple[int, int]] = [(root, 0)]
            while stack:
                claim_index, dependency_offset = stack[-1]
                if dependency_offset == len(dependencies[claim_index]):
                    state[claim_index] = 2
                    stack.pop()
                    continue
                dependency_index = dependencies[claim_index][dependency_offset]
                stack[-1] = (claim_index, dependency_offset + 1)
                if state[dependency_index] == 1:
                    raise ValueError("claim dependency graph must be acyclic")
                if state[dependency_index] == 0:
                    state[dependency_index] = 1
                    stack.append((dependency_index, 0))
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorship": self.authorship.value,
            "coverage_status": self.coverage_status.value,
            "claims": [claim.to_dict() for claim in self.claims],
        }

    @property
    def identity_fingerprint(self) -> str:
        return fingerprint(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ClaimAuthority":
        require_exact_keys(data, set(cls.__dataclass_fields__), "claim authority")
        try:
            authorship = ClaimAuthorship(data["authorship"])
        except (TypeError, ValueError) as exc:
            raise ValueError("claim authorship is invalid") from exc
        try:
            coverage_status = ClaimSetCoverageStatus(data["coverage_status"])
        except (TypeError, ValueError) as exc:
            raise ValueError("claim coverage status must be NOT_ASSESSED") from exc
        raw_claims = data["claims"]
        if not isinstance(raw_claims, list):
            raise ValueError("claims must be an ordered array")
        if len(raw_claims) > MAX_CLAIMS_PER_AUTHORITY:
            raise ValueError(f"claims cannot exceed {MAX_CLAIMS_PER_AUTHORITY}")
        return cls(
            authorship=authorship,
            coverage_status=coverage_status,
            claims=tuple(ResultClaim.from_dict(claim) for claim in raw_claims),
        ).validated()


@dataclass(frozen=True)
class VerificationIndependenceRequirements:
    """Independence properties required by an inert verification plan."""

    temporal: bool
    artifact: bool
    process: bool
    information: bool
    model: bool
    organizational: bool

    def validated(self) -> "VerificationIndependenceRequirements":
        for name in self.__dataclass_fields__:
            require_bool(getattr(self, name), f"verification independence {name}")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerificationIndependenceRequirements":
        require_exact_keys(data, set(cls.__dataclass_fields__), "verification independence requirements")
        return cls(**dict(data)).validated()


@dataclass(frozen=True)
class VerificationNegativeControl:
    """One owner-ordered negative control, without execution semantics."""

    control_id: str
    description: str

    def validated(self) -> "VerificationNegativeControl":
        require_identifier(self.control_id, "verification negative control id")
        require_nonempty_text(self.description, "verification negative control description")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {"control_id": self.control_id, "description": self.description}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerificationNegativeControl":
        require_exact_keys(data, set(cls.__dataclass_fields__), "verification negative control")
        return cls(control_id=data["control_id"], description=data["description"]).validated()


@dataclass(frozen=True)
class VerificationObligation:
    """Canonical intended evidence-acquisition content; never an execution result."""

    obligation_id: str
    claim_ids: tuple[str, ...]
    strategy: VerificationStrategy
    procedure_reference: str
    acceptance_predicate: VerificationAcceptancePredicate
    declared_coverage: str
    non_claims: tuple[str, ...]
    oracle_disclosed_to_subject: bool
    independence_requirements: VerificationIndependenceRequirements
    negative_controls: tuple[VerificationNegativeControl, ...]
    reference_cases: tuple[str, ...]

    def validated(self) -> "VerificationObligation":
        require_identifier(self.obligation_id, "verification obligation id")
        if not isinstance(self.claim_ids, tuple) or not self.claim_ids:
            raise ValueError("verification obligation claim_ids must be a non-empty ordered tuple")
        if len(self.claim_ids) > MAX_CLAIM_REFERENCES_PER_OBLIGATION:
            raise ValueError(f"verification obligation claim_ids cannot exceed {MAX_CLAIM_REFERENCES_PER_OBLIGATION}")
        for claim_id in self.claim_ids:
            require_identifier(claim_id, "verification obligation claim id")
        if len(set(self.claim_ids)) != len(self.claim_ids):
            raise ValueError("verification obligation claim_ids must be unique")
        if not isinstance(self.strategy, VerificationStrategy):
            raise ValueError("verification strategy is invalid")
        require_identifier(self.procedure_reference, "verification procedure reference")
        if not isinstance(self.acceptance_predicate, VerificationAcceptancePredicate):
            raise ValueError("verification acceptance predicate is invalid")
        valid_pairs = {
            (VerificationStrategy.CHECKPOINT_COMMAND, VerificationAcceptancePredicate.EXIT_CODE_ZERO),
            (VerificationStrategy.FROZEN_BEHAVIORAL_VERIFIER, VerificationAcceptancePredicate.EXIT_CODE_ZERO),
            (VerificationStrategy.HUMAN_RUBRIC_OBSERVATION, VerificationAcceptancePredicate.HUMAN_RUBRIC_PASS),
        }
        if (self.strategy, self.acceptance_predicate) not in valid_pairs:
            raise ValueError("verification strategy and acceptance predicate are incompatible")
        require_nonempty_text(self.declared_coverage, "verification declared coverage")
        if not isinstance(self.non_claims, tuple):
            raise ValueError("verification non_claims must be an ordered tuple")
        if len(self.non_claims) > MAX_NON_CLAIMS_PER_VERIFICATION_OBLIGATION:
            raise ValueError(f"verification non_claims cannot exceed {MAX_NON_CLAIMS_PER_VERIFICATION_OBLIGATION}")
        for statement in self.non_claims:
            require_nonempty_text(statement, "verification non-claim")
        if len(set(self.non_claims)) != len(self.non_claims):
            raise ValueError("verification non_claims must be unique")
        require_bool(self.oracle_disclosed_to_subject, "oracle_disclosed_to_subject")
        if not isinstance(self.independence_requirements, VerificationIndependenceRequirements):
            raise ValueError("verification independence requirements are required")
        self.independence_requirements.validated()
        if self.oracle_disclosed_to_subject and self.independence_requirements.information:
            raise ValueError("oracle disclosure is incompatible with required information independence")
        if not isinstance(self.negative_controls, tuple):
            raise ValueError("verification negative_controls must be an ordered tuple")
        if len(self.negative_controls) > MAX_NEGATIVE_CONTROLS_PER_OBLIGATION:
            raise ValueError(f"verification negative_controls cannot exceed {MAX_NEGATIVE_CONTROLS_PER_OBLIGATION}")
        control_ids: list[str] = []
        for control in self.negative_controls:
            if not isinstance(control, VerificationNegativeControl):
                raise ValueError("verification negative control has an invalid type")
            control.validated()
            control_ids.append(control.control_id)
        if len(set(control_ids)) != len(control_ids):
            raise ValueError("verification negative control identities must be unique")
        if not isinstance(self.reference_cases, tuple):
            raise ValueError("verification reference_cases must be an ordered tuple")
        if len(self.reference_cases) > MAX_REFERENCE_CASES_PER_OBLIGATION:
            raise ValueError(f"verification reference_cases cannot exceed {MAX_REFERENCE_CASES_PER_OBLIGATION}")
        for reference in self.reference_cases:
            require_identifier(reference, "verification reference case")
        if len(set(self.reference_cases)) != len(self.reference_cases):
            raise ValueError("verification reference_cases must be unique")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "obligation_id": self.obligation_id,
            "claim_ids": list(self.claim_ids),
            "strategy": self.strategy.value,
            "procedure_reference": self.procedure_reference,
            "acceptance_predicate": self.acceptance_predicate.value,
            "declared_coverage": self.declared_coverage,
            "non_claims": list(self.non_claims),
            "oracle_disclosed_to_subject": self.oracle_disclosed_to_subject,
            "independence_requirements": self.independence_requirements.to_dict(),
            "negative_controls": [control.to_dict() for control in self.negative_controls],
            "reference_cases": list(self.reference_cases),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerificationObligation":
        require_exact_keys(data, set(cls.__dataclass_fields__), "verification obligation")
        for key, maximum in (
            ("claim_ids", MAX_CLAIM_REFERENCES_PER_OBLIGATION),
            ("non_claims", MAX_NON_CLAIMS_PER_VERIFICATION_OBLIGATION),
            ("negative_controls", MAX_NEGATIVE_CONTROLS_PER_OBLIGATION),
            ("reference_cases", MAX_REFERENCE_CASES_PER_OBLIGATION),
        ):
            if not isinstance(data[key], list):
                raise ValueError(f"verification {key} must be an ordered array")
            if len(data[key]) > maximum:
                raise ValueError(f"verification {key} cannot exceed {maximum}")
        try:
            strategy = VerificationStrategy(data["strategy"])
        except (TypeError, ValueError) as exc:
            raise ValueError("verification strategy is invalid") from exc
        try:
            predicate = VerificationAcceptancePredicate(data["acceptance_predicate"])
        except (TypeError, ValueError) as exc:
            raise ValueError("verification acceptance predicate is invalid") from exc
        if not isinstance(data["independence_requirements"], Mapping):
            raise ValueError("verification independence requirements must be a canonical object")
        return cls(
            obligation_id=data["obligation_id"],
            claim_ids=require_string_list(data["claim_ids"], "verification claim_ids"),
            strategy=strategy,
            procedure_reference=data["procedure_reference"],
            acceptance_predicate=predicate,
            declared_coverage=data["declared_coverage"],
            non_claims=require_string_list(data["non_claims"], "verification non_claims"),
            oracle_disclosed_to_subject=data["oracle_disclosed_to_subject"],
            independence_requirements=VerificationIndependenceRequirements.from_dict(data["independence_requirements"]),
            negative_controls=tuple(VerificationNegativeControl.from_dict(item) for item in data["negative_controls"]),
            reference_cases=require_string_list(data["reference_cases"], "verification reference_cases"),
        ).validated()


@dataclass(frozen=True)
class ClaimVerificationPlanAuthority:
    """Canonical inert authority for owner-ordered claim verification obligations."""

    authorship: VerificationPlanAuthorship
    coverage_status: VerificationPlanCoverageStatus
    verification_obligations: tuple[VerificationObligation, ...]

    def validated(self) -> "ClaimVerificationPlanAuthority":
        if not isinstance(self.authorship, VerificationPlanAuthorship):
            raise ValueError("verification plan authorship is invalid")
        if self.coverage_status is not VerificationPlanCoverageStatus.NOT_ASSESSED:
            raise ValueError("verification plan coverage status must be NOT_ASSESSED")
        if not isinstance(self.verification_obligations, tuple) or not self.verification_obligations:
            raise ValueError("verification obligations must be a non-empty ordered tuple")
        if len(self.verification_obligations) > MAX_VERIFICATION_OBLIGATIONS:
            raise ValueError(f"verification obligations cannot exceed {MAX_VERIFICATION_OBLIGATIONS}")
        obligation_ids: list[str] = []
        for obligation in self.verification_obligations:
            if not isinstance(obligation, VerificationObligation):
                raise ValueError("verification obligation has an invalid type")
            obligation.validated()
            obligation_ids.append(obligation.obligation_id)
        if len(set(obligation_ids)) != len(obligation_ids):
            raise ValueError("verification obligation identities must be unique")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorship": self.authorship.value,
            "coverage_status": self.coverage_status.value,
            "verification_obligations": [item.to_dict() for item in self.verification_obligations],
        }

    @property
    def identity_fingerprint(self) -> str:
        return fingerprint(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ClaimVerificationPlanAuthority":
        require_exact_keys(data, set(cls.__dataclass_fields__), "claim verification plan authority")
        try:
            authorship = VerificationPlanAuthorship(data["authorship"])
        except (TypeError, ValueError) as exc:
            raise ValueError("verification plan authorship is invalid") from exc
        try:
            coverage = VerificationPlanCoverageStatus(data["coverage_status"])
        except (TypeError, ValueError) as exc:
            raise ValueError("verification plan coverage status must be NOT_ASSESSED") from exc
        raw = data["verification_obligations"]
        if not isinstance(raw, list):
            raise ValueError("verification obligations must be an ordered array")
        if len(raw) > MAX_VERIFICATION_OBLIGATIONS:
            raise ValueError(f"verification obligations cannot exceed {MAX_VERIFICATION_OBLIGATIONS}")
        return cls(authorship, coverage, tuple(VerificationObligation.from_dict(item) for item in raw)).validated()


@dataclass(frozen=True)
class VerificationEvidenceBinding:
    """One inert authorization to present an in-profile source against one obligation."""

    binding_id: str
    obligation_id: str
    source_authority_type: VerificationEvidenceSourceAuthorityType
    source_authority_reference: str

    def validated(self) -> "VerificationEvidenceBinding":
        require_identifier(self.binding_id, "verification evidence binding id")
        require_identifier(self.obligation_id, "verification evidence binding obligation id")
        if not isinstance(self.source_authority_type, VerificationEvidenceSourceAuthorityType):
            raise ValueError("verification evidence source authority type is invalid")
        if self.source_authority_type is VerificationEvidenceSourceAuthorityType.CHECKPOINT_COMMAND_AUTHORITY:
            require_identifier(self.source_authority_reference, "checkpoint command authority reference")
        else:
            require_sha256(self.source_authority_reference, "frozen behavioral verifier authority reference")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "obligation_id": self.obligation_id,
            "source_authority_type": self.source_authority_type.value,
            "source_authority_reference": self.source_authority_reference,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerificationEvidenceBinding":
        require_exact_keys(data, set(cls.__dataclass_fields__), "verification evidence binding")
        try:
            source_type = VerificationEvidenceSourceAuthorityType(data["source_authority_type"])
        except (TypeError, ValueError) as exc:
            raise ValueError("verification evidence source authority type is invalid") from exc
        return cls(
            binding_id=data["binding_id"],
            obligation_id=data["obligation_id"],
            source_authority_type=source_type,
            source_authority_reference=data["source_authority_reference"],
        ).validated()


@dataclass(frozen=True)
class VerificationEvidenceBindingAuthority:
    """Canonical inert authority for ordered verification-evidence bindings."""

    authorship: VerificationEvidenceBindingAuthorship
    coverage_status: VerificationEvidenceBindingCoverageStatus
    bindings: tuple[VerificationEvidenceBinding, ...]

    def validated(self) -> "VerificationEvidenceBindingAuthority":
        if not isinstance(self.authorship, VerificationEvidenceBindingAuthorship):
            raise ValueError("verification evidence binding authorship is invalid")
        if self.coverage_status is not VerificationEvidenceBindingCoverageStatus.NOT_ASSESSED:
            raise ValueError("verification evidence binding coverage status must be NOT_ASSESSED")
        if not isinstance(self.bindings, tuple) or not self.bindings:
            raise ValueError("verification evidence bindings must be a non-empty ordered tuple")
        if len(self.bindings) > MAX_VERIFICATION_EVIDENCE_BINDINGS:
            raise ValueError(f"verification evidence bindings cannot exceed {MAX_VERIFICATION_EVIDENCE_BINDINGS}")
        binding_ids: list[str] = []
        obligation_ids: list[str] = []
        for binding in self.bindings:
            if not isinstance(binding, VerificationEvidenceBinding):
                raise ValueError("verification evidence binding has an invalid type")
            binding.validated()
            binding_ids.append(binding.binding_id)
            obligation_ids.append(binding.obligation_id)
        if len(set(binding_ids)) != len(binding_ids):
            raise ValueError("verification evidence binding identities must be unique")
        if len(set(obligation_ids)) != len(obligation_ids):
            raise ValueError("verification evidence binding obligation identities must be unique")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorship": self.authorship.value,
            "coverage_status": self.coverage_status.value,
            "bindings": [binding.to_dict() for binding in self.bindings],
        }

    @property
    def identity_fingerprint(self) -> str:
        return fingerprint(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerificationEvidenceBindingAuthority":
        require_exact_keys(data, set(cls.__dataclass_fields__), "verification evidence binding authority")
        try:
            authorship = VerificationEvidenceBindingAuthorship(data["authorship"])
        except (TypeError, ValueError) as exc:
            raise ValueError("verification evidence binding authorship is invalid") from exc
        try:
            coverage = VerificationEvidenceBindingCoverageStatus(data["coverage_status"])
        except (TypeError, ValueError) as exc:
            raise ValueError("verification evidence binding coverage status must be NOT_ASSESSED") from exc
        raw = data["bindings"]
        if not isinstance(raw, list):
            raise ValueError("verification evidence bindings must be an ordered array")
        if len(raw) > MAX_VERIFICATION_EVIDENCE_BINDINGS:
            raise ValueError(f"verification evidence bindings cannot exceed {MAX_VERIFICATION_EVIDENCE_BINDINGS}")
        return cls(authorship, coverage, tuple(VerificationEvidenceBinding.from_dict(item) for item in raw)).validated()


@dataclass(frozen=True)
class WorkspaceSourceAuthority:
    """Immutable authority for the only two v0 workspace-source kinds."""

    kind: WorkspaceSourceKind
    fixture_id: str | None = None
    fixture_version: int | None = None
    local_repository_path: str | None = None

    def validated(self) -> "WorkspaceSourceAuthority":
        if not isinstance(self.kind, WorkspaceSourceKind):
            raise ValueError("workspace source kind is invalid")
        if self.kind is WorkspaceSourceKind.REGISTERED_FIXTURE:
            require_identifier(self.fixture_id, "workspace source fixture_id")
            require_strict_int(
                self.fixture_version,
                "workspace source fixture_version",
                minimum=1,
                maximum=1_000_000,
            )
            if self.local_repository_path is not None:
                raise ValueError("registered fixture source cannot carry a local repository path")
        else:
            if self.fixture_id is not None or self.fixture_version is not None:
                raise ValueError("local repository source cannot carry fixture authority")
            if not isinstance(self.local_repository_path, str) or not self.local_repository_path:
                raise ValueError("local repository source path is required")
            path = Path(self.local_repository_path)
            canonical = Path(os.path.abspath(os.fspath(path)))
            if not path.is_absolute() or str(canonical) != self.local_repository_path:
                raise ValueError("local repository source path must be canonical and absolute")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "fixture_id": self.fixture_id,
            "fixture_version": self.fixture_version,
            "local_repository_path": self.local_repository_path,
        }

    @property
    def identity_fingerprint(self) -> str:
        return fingerprint(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "WorkspaceSourceAuthority":
        require_exact_keys(
            data,
            {"kind", "fixture_id", "fixture_version", "local_repository_path"},
            "workspace source authority",
        )
        try:
            kind = WorkspaceSourceKind(data["kind"])
        except (TypeError, ValueError) as exc:
            raise ValueError("workspace source kind is invalid") from exc
        return cls(
            kind=kind,
            fixture_id=data["fixture_id"],
            fixture_version=data["fixture_version"],
            local_repository_path=data["local_repository_path"],
        ).validated()


@dataclass(frozen=True)
class GitEndStatePolicy:
    """Profile-owned Git/material eligibility policy for one strict attempt."""

    required_commits_added: int
    required_complete_commit_message: str | None
    final_worktree_clean: bool
    final_index_clean: bool
    final_remotes_absent: bool
    required_material_paths: tuple[str, ...]

    def validated(self) -> "GitEndStatePolicy":
        # G1 deliberately does not broaden native execution to arbitrary
        # histories: every runtime mission still requires exactly one commit.
        require_strict_int(
            self.required_commits_added,
            "required commits added",
            minimum=1,
            maximum=1,
        )
        if self.required_complete_commit_message is not None:
            require_nonempty_text(
                self.required_complete_commit_message,
                "required complete commit message",
                max_bytes=1024,
            )
            if "\n" in self.required_complete_commit_message or "\r" in self.required_complete_commit_message:
                raise ValueError("required complete commit message must be one exact single line")
        for name in ("final_worktree_clean", "final_index_clean", "final_remotes_absent"):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be a boolean")
        if not isinstance(self.required_material_paths, tuple) or not self.required_material_paths:
            raise ValueError("required material paths must be a non-empty ordered tuple")
        for path in self.required_material_paths:
            require_safe_relative_path(path, "required material path")
        if len(set(self.required_material_paths)) != len(self.required_material_paths):
            raise ValueError("required material paths must be unique")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "required_commits_added": self.required_commits_added,
            "required_complete_commit_message": self.required_complete_commit_message,
            "final_worktree_clean": self.final_worktree_clean,
            "final_index_clean": self.final_index_clean,
            "final_remotes_absent": self.final_remotes_absent,
            "required_material_paths": list(self.required_material_paths),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GitEndStatePolicy":
        require_exact_keys(data, set(cls.__dataclass_fields__), "Git end-state policy")
        return cls(
            required_commits_added=data["required_commits_added"],
            required_complete_commit_message=data["required_complete_commit_message"],
            final_worktree_clean=data["final_worktree_clean"],
            final_index_clean=data["final_index_clean"],
            final_remotes_absent=data["final_remotes_absent"],
            required_material_paths=require_string_list(
                data["required_material_paths"], "required material paths"
            ),
        ).validated()


@dataclass(frozen=True)
class VerificationAuthority:
    """Explicit observed-only or owner-frozen behavioral authority."""

    mode: VerificationMode
    verifier_source: str | None
    verifier_source_sha256: str | None
    verifier_timeout_seconds: int | None
    verifier_output_limit_bytes: int | None
    disclose_complete_source: bool

    def validated(self) -> "VerificationAuthority":
        if not isinstance(self.mode, VerificationMode):
            raise ValueError("verification mode is invalid")
        if not isinstance(self.disclose_complete_source, bool):
            raise ValueError("verifier disclosure policy must be boolean")
        values = (
            self.verifier_source,
            self.verifier_source_sha256,
            self.verifier_timeout_seconds,
            self.verifier_output_limit_bytes,
        )
        if self.mode is VerificationMode.OBSERVED_ONLY:
            if any(value is not None for value in values) or self.disclose_complete_source:
                raise ValueError("observed-only verification cannot carry behavioral verifier authority")
            return self
        if any(value is None for value in values):
            raise ValueError("frozen behavioral verification requires source, digest, and bounds")
        require_nonempty_text(self.verifier_source, "verifier source", max_bytes=262144)
        require_sha256(self.verifier_source_sha256, "verifier source digest")
        if self.verifier_source_sha256 != _sha256_text(self.verifier_source):
            raise ValueError("verifier source digest contradicts the embedded source")
        require_strict_int(
            self.verifier_timeout_seconds, "verifier timeout", minimum=1, maximum=600
        )
        require_strict_int(
            self.verifier_output_limit_bytes,
            "verifier output limit",
            minimum=1,
            maximum=1024 * 1024,
        )
        if not self.disclose_complete_source:
            raise ValueError("runtime frozen behavioral verifier source must be owner-visible")
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "verifier_source": self.verifier_source,
            "verifier_source_sha256": self.verifier_source_sha256,
            "verifier_timeout_seconds": self.verifier_timeout_seconds,
            "verifier_output_limit_bytes": self.verifier_output_limit_bytes,
            "disclose_complete_source": self.disclose_complete_source,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "VerificationAuthority":
        require_exact_keys(data, set(cls.__dataclass_fields__), "verification authority")
        try:
            mode = VerificationMode(data["mode"])
        except (TypeError, ValueError) as exc:
            raise ValueError("verification mode is invalid") from exc
        return cls(
            mode=mode,
            verifier_source=data["verifier_source"],
            verifier_source_sha256=data["verifier_source_sha256"],
            verifier_timeout_seconds=data["verifier_timeout_seconds"],
            verifier_output_limit_bytes=data["verifier_output_limit_bytes"],
            disclose_complete_source=data["disclose_complete_source"],
        ).validated()


@dataclass(frozen=True)
class RuntimePromptAuthority:
    """Execution-relevant effect and stop authority rendered to the agent."""

    permitted_effects: tuple[str, ...]
    forbidden_effects: tuple[str, ...]
    stop_clause: str

    def validated(self) -> "RuntimePromptAuthority":
        for name in ("permitted_effects", "forbidden_effects"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or not values:
                raise ValueError(f"{name} must be a non-empty ordered tuple")
            for value in values:
                require_nonempty_text(value, name, max_bytes=2048)
            if len(set(values)) != len(values):
                raise ValueError(f"{name} must be unique")
        require_nonempty_text(self.stop_clause, "runtime stop clause", max_bytes=4096)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "permitted_effects": list(self.permitted_effects),
            "forbidden_effects": list(self.forbidden_effects),
            "stop_clause": self.stop_clause,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RuntimePromptAuthority":
        require_exact_keys(data, set(cls.__dataclass_fields__), "runtime prompt authority")
        return cls(
            permitted_effects=require_string_list(data["permitted_effects"], "permitted effects"),
            forbidden_effects=require_string_list(data["forbidden_effects"], "forbidden effects"),
            stop_clause=data["stop_clause"],
        ).validated()


@dataclass(frozen=True)
class ProfileCheckpointCommand:
    """One canonical checkpoint verification-command definition."""

    command_id: str
    argv: tuple[str, ...]
    timeout_seconds: int
    max_capture_bytes: int

    def validated(self) -> "ProfileCheckpointCommand":
        # VerificationCommand owns the protocol bounds (<=300 s, <=1 MiB);
        # constructing it applies them without duplicating the limits here.
        self.to_verification_command()
        return self

    def to_verification_command(self) -> VerificationCommand:
        if not isinstance(self.argv, tuple):
            raise ValueError("checkpoint command argv must be an ordered tuple")
        return VerificationCommand(
            command_id=self.command_id,
            argv=self.argv,
            timeout_seconds=self.timeout_seconds,
            max_capture_bytes=self.max_capture_bytes,
        ).validated()

    def to_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "argv": list(self.argv),
            "timeout_seconds": self.timeout_seconds,
            "max_capture_bytes": self.max_capture_bytes,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ProfileCheckpointCommand":
        require_exact_keys(
            data,
            {"command_id", "argv", "timeout_seconds", "max_capture_bytes"},
            "profile checkpoint command",
        )
        return cls(
            command_id=data["command_id"],
            argv=require_string_list(data["argv"], "profile checkpoint argv"),
            timeout_seconds=data["timeout_seconds"],
            max_capture_bytes=data["max_capture_bytes"],
        ).validated()


@dataclass(frozen=True)
class NativeMissionProfile:
    """One immutable, canonically fingerprinted native mission definition."""

    schema_version: str
    profile_id: str
    fixture_id: str | None
    fixture_version: int | None
    run_id: str
    session_id: str
    gate_id: str
    mission_id: str
    mission_text: str
    gate_objective: str
    gate_clauses: tuple[tuple[str, str], ...]
    required_evidence_kinds: tuple[str, ...]
    checkpoint_commands: tuple[ProfileCheckpointCommand, ...]
    required_commit_message: str | None
    required_material_paths: tuple[str, ...]
    completion_conditions_text: str
    verifier_source: str | None
    verifier_source_sha256: str | None
    verifier_timeout_seconds: int | None
    verifier_output_limit_bytes: int | None
    budgets: tuple[int, int, int, int, int]
    timeout_seconds: int
    stdout_byte_limit: int
    stderr_byte_limit: int
    model: str
    fixture_initial_commit_message: str | None
    profile_fingerprint: str
    workspace_source: WorkspaceSourceAuthority | None = None
    git_end_state_policy: GitEndStatePolicy | None = None
    verification: VerificationAuthority | None = None
    runtime_prompt: RuntimePromptAuthority | None = None
    claim_authority: ClaimAuthority | None = None
    claim_verification_plan_authority: ClaimVerificationPlanAuthority | None = None
    verification_evidence_binding_authority: VerificationEvidenceBindingAuthority | None = None
    # How the exact prompt bytes reach the provider process.  Bound here so the
    # transport is authority *before* owner authorization, never inferred after
    # it and never derived from prompt length.
    #
    # Serialization is omit-when-default: a profile on the historical
    # ``ARGV_PROMPT`` transport produces byte-identical canonical bytes to the
    # pre-transport schema, so every persisted document still parses and every
    # historical ``profile_fingerprint`` is unchanged.
    prompt_transport: str = PROMPT_TRANSPORT_ARGV

    def _body(self) -> dict[str, Any]:
        """The complete canonical profile body, fingerprint field excluded."""

        data = dict(self.__dict__)
        if self.prompt_transport == PROMPT_TRANSPORT_ARGV:
            data.pop("prompt_transport")
        if self.schema_version in {MISSION_PROFILE_SCHEMA_VERSION_V2, MISSION_PROFILE_SCHEMA_VERSION_V3, MISSION_PROFILE_SCHEMA_VERSION_V4, MISSION_PROFILE_SCHEMA_VERSION_V5}:
            for key in (
                "fixture_id",
                "fixture_version",
                "required_commit_message",
                "required_material_paths",
                "verifier_source",
                "verifier_source_sha256",
                "verifier_timeout_seconds",
                "verifier_output_limit_bytes",
                "fixture_initial_commit_message",
            ):
                data.pop(key)
            data["workspace_source"] = self.workspace_source.to_dict()
            data["git_end_state_policy"] = self.git_end_state_policy.to_dict()
            data["verification"] = self.verification.to_dict()
            data["runtime_prompt"] = self.runtime_prompt.to_dict()
            if self.schema_version in {MISSION_PROFILE_SCHEMA_VERSION_V3, MISSION_PROFILE_SCHEMA_VERSION_V4, MISSION_PROFILE_SCHEMA_VERSION_V5}:
                data["claim_authority"] = self.claim_authority.to_dict()
            else:
                data.pop("claim_authority")
            if self.schema_version in {MISSION_PROFILE_SCHEMA_VERSION_V4, MISSION_PROFILE_SCHEMA_VERSION_V5}:
                data["claim_verification_plan_authority"] = self.claim_verification_plan_authority.to_dict()
            else:
                data.pop("claim_verification_plan_authority")
            if self.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5:
                data["verification_evidence_binding_authority"] = self.verification_evidence_binding_authority.to_dict()
            else:
                data.pop("verification_evidence_binding_authority")
        else:
            for key in (
                "workspace_source",
                "git_end_state_policy",
                "verification",
                "runtime_prompt",
                "claim_authority",
                "claim_verification_plan_authority",
                "verification_evidence_binding_authority",
            ):
                data.pop(key)
        data["gate_clauses"] = [list(clause) for clause in self.gate_clauses]
        data["required_evidence_kinds"] = list(self.required_evidence_kinds)
        data["checkpoint_commands"] = [command.to_dict() for command in self.checkpoint_commands]
        if self.schema_version == MISSION_PROFILE_SCHEMA_VERSION:
            data["required_material_paths"] = list(self.required_material_paths)
        data["budgets"] = list(self.budgets)
        data.pop("profile_fingerprint")
        return data

    @property
    def has_nested_runtime_authority(self) -> bool:
        return self.schema_version in {
            MISSION_PROFILE_SCHEMA_VERSION_V2,
            MISSION_PROFILE_SCHEMA_VERSION_V3,
            MISSION_PROFILE_SCHEMA_VERSION_V4,
            MISSION_PROFILE_SCHEMA_VERSION_V5,
        }

    @property
    def is_launchable_runtime_profile(self) -> bool:
        return self.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V2

    @property
    def is_runtime_profile(self) -> bool:
        """Compatibility alias for the historically V2-only runtime boundary."""

        return self.is_launchable_runtime_profile

    @property
    def effective_workspace_source(self) -> WorkspaceSourceAuthority:
        if self.workspace_source is not None:
            return self.workspace_source.validated()
        return WorkspaceSourceAuthority(
            kind=WorkspaceSourceKind.REGISTERED_FIXTURE,
            fixture_id=self.fixture_id,
            fixture_version=self.fixture_version,
        ).validated()

    @property
    def effective_git_end_state_policy(self) -> GitEndStatePolicy:
        if self.git_end_state_policy is not None:
            return self.git_end_state_policy.validated()
        return GitEndStatePolicy(
            required_commits_added=1,
            required_complete_commit_message=self.required_commit_message,
            final_worktree_clean=True,
            final_index_clean=True,
            final_remotes_absent=True,
            required_material_paths=self.required_material_paths,
        ).validated()

    @property
    def verification_mode(self) -> VerificationMode:
        return self.verification.mode if self.verification is not None else VerificationMode.FROZEN_BEHAVIORAL

    def validated(self) -> "NativeMissionProfile":
        if self.schema_version not in {
            MISSION_PROFILE_SCHEMA_VERSION,
            MISSION_PROFILE_SCHEMA_VERSION_V2,
            MISSION_PROFILE_SCHEMA_VERSION_V3,
            MISSION_PROFILE_SCHEMA_VERSION_V4,
            MISSION_PROFILE_SCHEMA_VERSION_V5,
        }:
            raise ValueError("unsupported native mission profile schema")
        # Unknown transports are rejected outright rather than defaulted.
        require_prompt_transport(self.prompt_transport, "profile prompt transport")
        if self.prompt_transport != PROMPT_TRANSPORT_ARGV and not self.is_launchable_runtime_profile:
            # Historical V1/V3/V4/V5 documents keep their exact previous
            # transport semantics and stay non-launchable; only the launchable
            # runtime-v2 schema may carry a non-argv transport.
            raise ValueError("only a launchable runtime-v2 profile may select a non-argv prompt transport")
        require_identifier(self.profile_id, "profile_id")
        if self.schema_version == MISSION_PROFILE_SCHEMA_VERSION:
            require_identifier(self.fixture_id, "profile fixture_id")
            require_strict_int(
                self.fixture_version, "profile fixture_version", minimum=1, maximum=1_000_000
            )
            if any(
                value is not None
                for value in (
                    self.workspace_source,
                    self.git_end_state_policy,
                    self.verification,
                    self.runtime_prompt,
                    self.claim_authority,
                    self.claim_verification_plan_authority,
                    self.verification_evidence_binding_authority,
                )
            ):
                raise ValueError("v1 profile cannot carry nested runtime or claim authority")
        else:
            if not isinstance(self.workspace_source, WorkspaceSourceAuthority):
                raise ValueError("v2 profile must carry workspace source authority")
            if not isinstance(self.git_end_state_policy, GitEndStatePolicy):
                raise ValueError("v2 profile must carry Git end-state authority")
            if not isinstance(self.verification, VerificationAuthority):
                raise ValueError("v2 profile must carry verification authority")
            if not isinstance(self.runtime_prompt, RuntimePromptAuthority):
                raise ValueError("runtime profile must carry runtime prompt authority")
            if self.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V2:
                if self.claim_authority is not None or self.claim_verification_plan_authority is not None or self.verification_evidence_binding_authority is not None:
                    raise ValueError("v2 profile cannot carry claim or claim verification plan authority")
            elif not isinstance(self.claim_authority, ClaimAuthority):
                raise ValueError("v3/v4 profile must carry claim authority")
            elif self.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V3:
                if self.claim_verification_plan_authority is not None or self.verification_evidence_binding_authority is not None:
                    raise ValueError("v3 profile cannot carry claim verification plan authority")
            elif not isinstance(self.claim_verification_plan_authority, ClaimVerificationPlanAuthority):
                raise ValueError("v4/v5 profile must carry claim verification plan authority")
            elif self.schema_version == MISSION_PROFILE_SCHEMA_VERSION_V4:
                if self.verification_evidence_binding_authority is not None:
                    raise ValueError("v4 profile cannot carry verification evidence binding authority")
            elif not isinstance(self.verification_evidence_binding_authority, VerificationEvidenceBindingAuthority):
                raise ValueError("v5 profile must carry verification evidence binding authority")
            source = self.workspace_source.validated()
            policy = self.git_end_state_policy.validated()
            verification = self.verification.validated()
            self.runtime_prompt.validated()
            if self.claim_authority is not None:
                self.claim_authority.validated()
            if self.claim_verification_plan_authority is not None:
                self.claim_verification_plan_authority.validated()
                known_claim_ids = {claim.claim_id for claim in self.claim_authority.claims}
                if any(
                    claim_id not in known_claim_ids
                    for obligation in self.claim_verification_plan_authority.verification_obligations
                    for claim_id in obligation.claim_ids
                ):
                    raise ValueError("verification obligation claim reference is missing from claim authority")
            if self.verification_evidence_binding_authority is not None:
                self.verification_evidence_binding_authority.validated()
            if self.fixture_id != source.fixture_id or self.fixture_version != source.fixture_version:
                raise ValueError("internal v2 fixture mirrors contradict workspace source authority")
            if self.required_commit_message != policy.required_complete_commit_message:
                raise ValueError("internal v2 commit-message mirror contradicts Git policy")
            if self.required_material_paths != policy.required_material_paths:
                raise ValueError("internal v2 material-path mirror contradicts Git policy")
            expected_verifier = (
                verification.verifier_source,
                verification.verifier_source_sha256,
                verification.verifier_timeout_seconds,
                verification.verifier_output_limit_bytes,
            )
            if (
                self.verifier_source,
                self.verifier_source_sha256,
                self.verifier_timeout_seconds,
                self.verifier_output_limit_bytes,
            ) != expected_verifier:
                raise ValueError("internal v2 verifier mirrors contradict verification authority")
            if self.fixture_initial_commit_message is not None:
                raise ValueError("v2 initialized commit identity is observed into the payload, not profile-supplied")
        require_identifier(self.run_id, "profile run_id")
        require_identifier(self.session_id, "profile session_id")
        require_identifier(self.gate_id, "profile gate_id")
        require_identifier(self.mission_id, "profile mission_id")
        require_nonempty_text(self.mission_text, "profile mission text")
        require_nonempty_text(self.gate_objective, "profile gate objective", max_bytes=8192)
        if not isinstance(self.gate_clauses, tuple) or not self.gate_clauses:
            raise ValueError("profile gate clauses must be a non-empty ordered tuple")
        clause_ids: list[str] = []
        for clause in self.gate_clauses:
            if not isinstance(clause, tuple) or len(clause) != 2:
                raise ValueError("profile gate clause must be an ordered (id, text) pair")
            clause_id, text = clause
            require_identifier(clause_id, "profile gate clause id")
            require_nonempty_text(text, "profile gate clause text", max_bytes=4096)
            clause_ids.append(clause_id)
        if len(set(clause_ids)) != len(clause_ids):
            raise ValueError("profile gate clause identities must be unique")
        if not isinstance(self.required_evidence_kinds, tuple) or not self.required_evidence_kinds:
            raise ValueError("profile evidence kinds must be a non-empty ordered tuple")
        known_kinds = {kind.value for kind in EvidenceKind}
        for kind in self.required_evidence_kinds:
            if not isinstance(kind, str) or kind not in known_kinds:
                raise ValueError("profile evidence kind is not a known evidence kind")
        if len(set(self.required_evidence_kinds)) != len(self.required_evidence_kinds):
            raise ValueError("profile evidence kinds must be unique")
        if not isinstance(self.checkpoint_commands, tuple):
            raise ValueError("profile checkpoint commands must be an ordered tuple")
        if self.schema_version == MISSION_PROFILE_SCHEMA_VERSION and not self.checkpoint_commands:
            raise ValueError("profile checkpoint commands must be a non-empty ordered tuple")
        command_ids: list[str] = []
        for command in self.checkpoint_commands:
            if not isinstance(command, ProfileCheckpointCommand):
                raise ValueError("profile checkpoint command has an invalid type")
            command.validated()
            command_ids.append(command.command_id)
        if len(set(command_ids)) != len(command_ids):
            raise ValueError("profile checkpoint command identities must be unique")
        if self.verification_evidence_binding_authority is not None:
            obligations = {
                obligation.obligation_id: obligation
                for obligation in self.claim_verification_plan_authority.verification_obligations
            }
            for binding in self.verification_evidence_binding_authority.bindings:
                obligation = obligations.get(binding.obligation_id)
                if obligation is None:
                    raise ValueError("verification evidence binding obligation reference is missing")
                if obligation.strategy is VerificationStrategy.HUMAN_RUBRIC_OBSERVATION:
                    raise ValueError("human-rubric verification obligations cannot be evidence-bound in v5")
                expected_type = (
                    VerificationEvidenceSourceAuthorityType.CHECKPOINT_COMMAND_AUTHORITY
                    if obligation.strategy is VerificationStrategy.CHECKPOINT_COMMAND
                    else VerificationEvidenceSourceAuthorityType.FROZEN_BEHAVIORAL_VERIFIER_AUTHORITY
                )
                if binding.source_authority_type is not expected_type:
                    raise ValueError("verification evidence source authority type is incompatible with obligation strategy")
                if expected_type is VerificationEvidenceSourceAuthorityType.CHECKPOINT_COMMAND_AUTHORITY:
                    if binding.source_authority_reference not in command_ids:
                        raise ValueError("checkpoint command authority reference is missing from profile")
                else:
                    if self.verification.mode is not VerificationMode.FROZEN_BEHAVIORAL:
                        raise ValueError("frozen behavioral verifier binding requires frozen behavioral verification authority")
                    if binding.source_authority_reference != self.verification.verifier_source_sha256:
                        raise ValueError("frozen behavioral verifier authority reference contradicts profile verification authority")
        has_command_evidence = EvidenceKind.VERIFICATION_COMMAND.value in self.required_evidence_kinds
        if bool(self.checkpoint_commands) != has_command_evidence:
            raise ValueError(
                "profile checkpoint commands and verification-command evidence authority must agree"
            )
        if self.required_commit_message is not None:
            require_nonempty_text(self.required_commit_message, "profile commit message", max_bytes=1024)
            if "\n" in self.required_commit_message or "\r" in self.required_commit_message:
                raise ValueError("profile commit message must be one exact single line")
        if not isinstance(self.required_material_paths, tuple) or not self.required_material_paths:
            raise ValueError("profile material paths must be a non-empty ordered tuple")
        for path in self.required_material_paths:
            require_safe_relative_path(path, "profile material path")
        if len(set(self.required_material_paths)) != len(self.required_material_paths):
            raise ValueError("profile material paths must be unique")
        require_nonempty_text(self.completion_conditions_text, "profile completion conditions", max_bytes=16384)
        if self.schema_version == MISSION_PROFILE_SCHEMA_VERSION:
            require_nonempty_text(self.verifier_source, "profile verifier source", max_bytes=262144)
            require_sha256(self.verifier_source_sha256, "profile verifier source digest")
            if self.verifier_source_sha256 != _sha256_text(self.verifier_source):
                raise ValueError("profile verifier source digest contradicts the embedded source")
            require_strict_int(
                self.verifier_timeout_seconds, "profile verifier timeout", minimum=1, maximum=600
            )
            require_strict_int(
                self.verifier_output_limit_bytes,
                "profile verifier output limit",
                minimum=1,
                maximum=1024 * 1024,
            )
        if not isinstance(self.budgets, tuple) or len(self.budgets) != 5:
            raise ValueError("profile budgets must be a five-item ordered tuple")
        for value in self.budgets:
            require_strict_int(value, "profile budget", minimum=0, maximum=1)
        if self.budgets != ONE_SHOT_PROFILE_BUDGETS:
            raise ValueError("profile budgets must be the exact one-shot budgets")
        require_strict_int(self.timeout_seconds, "profile timeout", minimum=1, maximum=3600)
        require_strict_int(self.stdout_byte_limit, "profile stdout limit", minimum=1, maximum=16 * 1024 * 1024)
        require_strict_int(self.stderr_byte_limit, "profile stderr limit", minimum=1, maximum=16 * 1024 * 1024)
        require_nonempty_text(self.model, "profile model", max_bytes=256)
        if self.schema_version == MISSION_PROFILE_SCHEMA_VERSION:
            require_nonempty_text(
                self.fixture_initial_commit_message,
                "profile fixture initial commit message",
                max_bytes=1024,
            )
            if "\n" in self.fixture_initial_commit_message or "\r" in self.fixture_initial_commit_message:
                raise ValueError("profile fixture initial commit message must be one exact single line")
        require_sha256(self.profile_fingerprint, "profile fingerprint")
        if fingerprint(self._body()) != self.profile_fingerprint:
            raise ValueError("native mission profile fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        data = self._body()
        data["profile_fingerprint"] = self.profile_fingerprint
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "NativeMissionProfile":
        if not isinstance(data, Mapping):
            raise ValueError("native mission profile must be a JSON object")
        if "schema_version" not in data:
            raise ValueError("native mission profile keys are incomplete")
        schema = data.get("schema_version")
        v2_fields = {
            "schema_version",
            "profile_id",
            "run_id",
            "session_id",
            "gate_id",
            "mission_id",
            "mission_text",
            "gate_objective",
            "gate_clauses",
            "required_evidence_kinds",
            "checkpoint_commands",
            "completion_conditions_text",
            "budgets",
            "timeout_seconds",
            "stdout_byte_limit",
            "stderr_byte_limit",
            "model",
            "workspace_source",
            "git_end_state_policy",
            "verification",
            "runtime_prompt",
            "profile_fingerprint",
        }
        v1_fields = set(cls.__dataclass_fields__) - {
            "workspace_source",
            "git_end_state_policy",
            "verification",
            "runtime_prompt",
            "claim_authority",
            "claim_verification_plan_authority",
            "verification_evidence_binding_authority",
            "prompt_transport",
        }
        # ``prompt_transport`` is omitted whenever it is the historical
        # ARGV_PROMPT default, so every persisted document keeps parsing with
        # its original exact key set.  Only the launchable runtime-v2 schema may
        # carry the key at all.
        transport_key = {"prompt_transport"} if "prompt_transport" in data else set()
        if transport_key and data.get("prompt_transport") == PROMPT_TRANSPORT_ARGV:
            # Omit-when-default is a canonical *form*, not merely an encoding
            # convenience: allowing the redundant key would let two distinct
            # documents share one profile fingerprint.
            raise ValueError(
                "the default ARGV_PROMPT transport must be omitted so each profile "
                "has exactly one canonical document"
            )
        if schema == MISSION_PROFILE_SCHEMA_VERSION:
            require_exact_keys(data, v1_fields, "native mission profile v1")
        elif schema == MISSION_PROFILE_SCHEMA_VERSION_V2:
            require_exact_keys(data, v2_fields | transport_key, "native mission profile v2")
        elif schema == MISSION_PROFILE_SCHEMA_VERSION_V3:
            require_exact_keys(data, v2_fields | {"claim_authority"}, "native mission profile v3")
        elif schema == MISSION_PROFILE_SCHEMA_VERSION_V4:
            require_exact_keys(data, v2_fields | {"claim_authority", "claim_verification_plan_authority"}, "native mission profile v4")
        elif schema == MISSION_PROFILE_SCHEMA_VERSION_V5:
            require_exact_keys(data, v2_fields | {"claim_authority", "claim_verification_plan_authority", "verification_evidence_binding_authority"}, "native mission profile v5")
        else:
            raise ValueError("unsupported native mission profile schema")
        values = dict(data)
        raw_clauses = data["gate_clauses"]
        if not isinstance(raw_clauses, list) or any(
            not isinstance(clause, list) or len(clause) != 2 or any(not isinstance(part, str) for part in clause)
            for clause in raw_clauses
        ):
            raise ValueError("profile gate clauses must be an ordered array of [id, text] pairs")
        values["gate_clauses"] = tuple((clause[0], clause[1]) for clause in raw_clauses)
        values["required_evidence_kinds"] = require_string_list(
            data["required_evidence_kinds"], "profile evidence kinds"
        )
        raw_commands = data["checkpoint_commands"]
        if not isinstance(raw_commands, list) or (
            schema == MISSION_PROFILE_SCHEMA_VERSION and not raw_commands
        ):
            raise ValueError("profile checkpoint commands must be an ordered array")
        values["checkpoint_commands"] = tuple(
            ProfileCheckpointCommand.from_dict(item) for item in raw_commands
        )
        raw_budgets = data["budgets"]
        if not isinstance(raw_budgets, list) or len(raw_budgets) != 5:
            raise ValueError("profile budgets must be a five-item ordered array")
        values["budgets"] = tuple(raw_budgets)
        if schema == MISSION_PROFILE_SCHEMA_VERSION:
            values["required_material_paths"] = require_string_list(
                data["required_material_paths"], "profile material paths"
            )
            values.update(
                workspace_source=None,
                git_end_state_policy=None,
                verification=None,
                runtime_prompt=None,
                claim_authority=None,
                claim_verification_plan_authority=None,
                verification_evidence_binding_authority=None,
            )
        else:
            for key in (
                "workspace_source",
                "git_end_state_policy",
                "verification",
                "runtime_prompt",
            ):
                if not isinstance(data[key], Mapping):
                    raise ValueError(f"profile {key} must be a canonical object")
            source = WorkspaceSourceAuthority.from_dict(data["workspace_source"])
            policy = GitEndStatePolicy.from_dict(data["git_end_state_policy"])
            verification = VerificationAuthority.from_dict(data["verification"])
            runtime_prompt = RuntimePromptAuthority.from_dict(data["runtime_prompt"])
            claim_authority = (
                ClaimAuthority.from_dict(data["claim_authority"])
                if schema in {MISSION_PROFILE_SCHEMA_VERSION_V3, MISSION_PROFILE_SCHEMA_VERSION_V4, MISSION_PROFILE_SCHEMA_VERSION_V5}
                else None
            )
            claim_verification_plan_authority = (
                ClaimVerificationPlanAuthority.from_dict(data["claim_verification_plan_authority"])
                if schema in {MISSION_PROFILE_SCHEMA_VERSION_V4, MISSION_PROFILE_SCHEMA_VERSION_V5}
                else None
            )
            verification_evidence_binding_authority = (
                VerificationEvidenceBindingAuthority.from_dict(data["verification_evidence_binding_authority"])
                if schema == MISSION_PROFILE_SCHEMA_VERSION_V5
                else None
            )
            values.update(
                workspace_source=source,
                git_end_state_policy=policy,
                verification=verification,
                runtime_prompt=runtime_prompt,
                claim_authority=claim_authority,
                claim_verification_plan_authority=claim_verification_plan_authority,
                verification_evidence_binding_authority=verification_evidence_binding_authority,
                fixture_id=source.fixture_id,
                fixture_version=source.fixture_version,
                required_commit_message=policy.required_complete_commit_message,
                required_material_paths=policy.required_material_paths,
                verifier_source=verification.verifier_source,
                verifier_source_sha256=verification.verifier_source_sha256,
                verifier_timeout_seconds=verification.verifier_timeout_seconds,
                verifier_output_limit_bytes=verification.verifier_output_limit_bytes,
                fixture_initial_commit_message=None,
            )
        return cls(**values).validated()


def create_native_mission_profile(**values: Any) -> NativeMissionProfile:
    """Build one canonically fingerprinted, validated mission profile.

    ``profile_fingerprint`` is derived from the complete body with the
    fingerprint field excluded, so it can never participate in its own input.
    """

    schema_version = values.pop("schema_version", MISSION_PROFILE_SCHEMA_VERSION)
    if schema_version in {MISSION_PROFILE_SCHEMA_VERSION_V2, MISSION_PROFILE_SCHEMA_VERSION_V3, MISSION_PROFILE_SCHEMA_VERSION_V4, MISSION_PROFILE_SCHEMA_VERSION_V5}:
        source = values.get("workspace_source")
        policy = values.get("git_end_state_policy")
        verification = values.get("verification")
        runtime_prompt = values.get("runtime_prompt")
        claim_authority = values.get("claim_authority")
        claim_verification_plan_authority = values.get("claim_verification_plan_authority")
        verification_evidence_binding_authority = values.get("verification_evidence_binding_authority")
        if isinstance(source, Mapping):
            source = WorkspaceSourceAuthority.from_dict(source)
        if isinstance(policy, Mapping):
            policy = GitEndStatePolicy.from_dict(policy)
        if isinstance(verification, Mapping):
            verification = VerificationAuthority.from_dict(verification)
        if isinstance(runtime_prompt, Mapping):
            runtime_prompt = RuntimePromptAuthority.from_dict(runtime_prompt)
        if isinstance(claim_authority, Mapping):
            claim_authority = ClaimAuthority.from_dict(claim_authority)
        if isinstance(claim_verification_plan_authority, Mapping):
            claim_verification_plan_authority = ClaimVerificationPlanAuthority.from_dict(claim_verification_plan_authority)
        if isinstance(verification_evidence_binding_authority, Mapping):
            verification_evidence_binding_authority = VerificationEvidenceBindingAuthority.from_dict(verification_evidence_binding_authority)
        if not all(
            (
                isinstance(source, WorkspaceSourceAuthority),
                isinstance(policy, GitEndStatePolicy),
                isinstance(verification, VerificationAuthority),
                isinstance(runtime_prompt, RuntimePromptAuthority),
            )
        ):
            raise ValueError("v2 profile requires complete nested runtime authority")
        if schema_version == MISSION_PROFILE_SCHEMA_VERSION_V2 and (
            claim_authority is not None or claim_verification_plan_authority is not None or verification_evidence_binding_authority is not None
        ):
            raise ValueError("v2 profile cannot carry claim or claim verification plan authority")
        if schema_version == MISSION_PROFILE_SCHEMA_VERSION_V3 and not isinstance(
            claim_authority, ClaimAuthority
        ):
            raise ValueError("v3 profile requires claim authority")
        if schema_version == MISSION_PROFILE_SCHEMA_VERSION_V3 and (claim_verification_plan_authority is not None or verification_evidence_binding_authority is not None):
            raise ValueError("v3 profile cannot carry claim verification plan authority")
        if schema_version == MISSION_PROFILE_SCHEMA_VERSION_V4 and not all((
            isinstance(claim_authority, ClaimAuthority),
            isinstance(claim_verification_plan_authority, ClaimVerificationPlanAuthority),
        )):
            raise ValueError("v4 profile requires claim and claim verification plan authority")
        if schema_version == MISSION_PROFILE_SCHEMA_VERSION_V4 and verification_evidence_binding_authority is not None:
            raise ValueError("v4 profile cannot carry verification evidence binding authority")
        if schema_version == MISSION_PROFILE_SCHEMA_VERSION_V5 and not all((
            isinstance(claim_authority, ClaimAuthority),
            isinstance(claim_verification_plan_authority, ClaimVerificationPlanAuthority),
            isinstance(verification_evidence_binding_authority, VerificationEvidenceBindingAuthority),
        )):
            raise ValueError("v5 profile requires claim, claim verification plan, and verification evidence binding authority")
        values.update(
            workspace_source=source,
            git_end_state_policy=policy,
            verification=verification,
            runtime_prompt=runtime_prompt,
            claim_authority=claim_authority,
            claim_verification_plan_authority=claim_verification_plan_authority,
            verification_evidence_binding_authority=verification_evidence_binding_authority,
            fixture_id=source.fixture_id,
            fixture_version=source.fixture_version,
            required_commit_message=policy.required_complete_commit_message,
            required_material_paths=policy.required_material_paths,
            verifier_source=verification.verifier_source,
            verifier_source_sha256=verification.verifier_source_sha256,
            verifier_timeout_seconds=verification.verifier_timeout_seconds,
            verifier_output_limit_bytes=verification.verifier_output_limit_bytes,
            fixture_initial_commit_message=None,
        )
    elif schema_version != MISSION_PROFILE_SCHEMA_VERSION:
        raise ValueError("unsupported native mission profile schema")
    provisional = NativeMissionProfile(
        schema_version=schema_version,
        profile_fingerprint="0" * 64,
        **values,
    )
    return NativeMissionProfile(
        **{**provisional.__dict__, "profile_fingerprint": fingerprint(provisional._body())}
    ).validated()


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_native_mission_profile_document(document_path: str | Path) -> NativeMissionProfile:
    """Load one exact, immutable runtime-profile JSON document fail closed."""

    path = Path(document_path)
    if not path.is_absolute():
        raise ValueError("profile document path must be absolute")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"profile document is unreadable: {exc}") from exc
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"profile document is not exact UTF-8 JSON: {exc}") from exc
    if not isinstance(parsed, Mapping):
        raise ValueError("profile document root must be one JSON object")
    profile = NativeMissionProfile.from_dict(parsed)
    if profile.schema_version != MISSION_PROFILE_SCHEMA_VERSION_V2:
        raise ValueError("runtime profile document must use the v2 schema")
    # Canonical validation is intentionally semantic: the supplied document
    # bytes remain immutable, while the parsed object's fingerprint is derived
    # from exact canonical JSON and must already match.
    return profile


# ---------------------------------------------------------------------------
# Flagship profile: incident-replay-v1 (Gate L1B owner contract, accepted).
# ---------------------------------------------------------------------------

FLAGSHIP_MISSION_TEXT = """Add deterministic, versioned incident replay and durable local persistence to
this local-first incident-response board.

Implement an append-only event log covering every supported incident mutation
(incident creation, status change, severity change, note addition).
Reconstruct board state deterministically by replaying that log from an empty
board. Add durable local persistence through the injected storage adapter,
validated export and import of the event log, duplicate-event-ID handling,
and fail-closed rejection of malformed or unsupported event data with no
partial mutation of the current board state or its stored log.

Add a visible event timeline and manual replay controls to the browser UI
that can move through the recorded history without mutating, truncating,
reordering, or appending to the authoritative persisted log.

Preserve the existing incident-board behavior and public interfaces where
reasonable. Add comprehensive tests using the existing Node test runner,
update the README, run the complete `npm test` suite, and create exactly one
local Git commit with the exact message `feat: add deterministic incident
replay`.

Do not add a remote. Do not push. Do not deploy. Stop only after the
complete `npm test` suite passes and the exact local commit has been
created; do not continue with optional polish after that commit."""

FLAGSHIP_REQUIRED_COMMIT_MESSAGE = "feat: add deterministic incident replay"

FLAGSHIP_COMPLETION_CONDITIONS_TEXT = f"""Required completion conditions:
- run the complete `npm test` suite and require it to pass;
- create exactly one intended local feature commit with complete message `{FLAGSHIP_REQUIRED_COMMIT_MESSAGE}`;
- use no `--trailer` when creating or amending the commit;
- add no commit-message body, `Co-authored-by`, sign-off, attribution, or other trailer;
- before stopping, run `git log -1 --format=%B` and verify that its complete output, after removing terminal newline characters only, is exactly `{FLAGSHIP_REQUIRED_COMMIT_MESSAGE}`;
- if the complete message is not exact, amend that same commit during this native invocation, do not create a second commit, and run the exact `%B` verification again;
- do not add or modify a Git remote;
- do not push;
- do not deploy;
- do not continue with optional polish after the final commit;
- stop immediately only after the complete `npm test` suite has passed and the exact full-message verification passes."""

# Deterministic Node behavioral verifier for incident-replay-v1.  It imports
# only the final public modules through file:// URLs, uses injected memory
# storage exclusively, performs no network access, mutates nothing in the
# workspace, and exits zero only when every assertion passes.
FLAGSHIP_VERIFIER_SOURCE = r"""import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const root = process.argv[2];
const load = (relative) => import(pathToFileURL(join(root, ...relative.split('/'))).href);
const { createApp } = await load('src/app.js');
const { createMemoryStorage } = await load('src/storage/memory-storage.js');
const eventLog = await load('src/domain/event-log.js');

const canonical = (board) => JSON.stringify(board);

// 1. A multi-step incident history can be created through the public app.
const storage = createMemoryStorage();
const app = createApp(storage);
app.controller.createIncident({ id: 'inc-1', title: 'Checkout latency spike', severity: 'high' });
app.controller.updateStatus('inc-1', 'acknowledged');
app.controller.updateSeverity('inc-1', 'critical');
app.controller.addNote('inc-1', 'rollback started');
app.controller.createIncident({ id: 'inc-2', title: 'Login error rate', severity: 'medium' });
const finalBoard = canonical(app.controller.board());
const eventTotal = app.controller.eventCount();
assert.equal(eventTotal, 5);

// 2. Export followed by import reconstructs the same canonical state, twice.
const exported = app.controller.exportLog();
const freshA = createApp(createMemoryStorage());
freshA.controller.importLog(exported);
assert.equal(canonical(freshA.controller.board()), finalBoard);
const freshB = createApp(createMemoryStorage());
freshB.controller.importLog(exported);
assert.equal(canonical(freshB.controller.board()), canonical(freshA.controller.board()));

// 3. A fresh instance over the same injected storage restores the history.
const restored = createApp(storage);
assert.equal(canonical(restored.controller.board()), finalBoard);
assert.equal(restored.controller.eventCount(), eventTotal);

// 4. Replay to beginning, an intermediate event, and the final event.
assert.equal(restored.controller.replayAt(0).incidents.length, 0);
const midway = restored.controller.replayAt(2);
assert.equal(midway.incidents.length, 1);
assert.equal(midway.incidents[0].status, 'acknowledged');
assert.equal(midway.incidents[0].severity, 'high');
assert.equal(canonical(restored.controller.replayAt(eventTotal)), finalBoard);

// 5. Duplicate event IDs cannot apply the same mutation twice.
const events = JSON.parse(exported);
assert.throws(() => eventLog.appendEvent(events, events[0]));
assert.throws(() => freshA.controller.importLog(JSON.stringify([...events, events[0]])));

// 6. Malformed, unsupported, and broken-reference events are rejected.
assert.throws(() => eventLog.validateEvent({ id: 'evt-x', version: 999, type: 'incident-created', payload: {} }));
assert.throws(() => eventLog.validateEvent({ id: 'evt-x', version: 1, type: 'unsupported-type', payload: {} }));
assert.throws(() => eventLog.replayEvents([
  { id: 'evt-x', version: 1, type: 'status-changed', payload: { id: 'missing', status: 'resolved' } },
]));

// 7. A failed import leaves the previous state and the stored log unchanged.
const beforeBoard = canonical(freshA.controller.board());
const beforeLog = freshA.controller.exportLog();
assert.throws(() => freshA.controller.importLog('not json at all'));
const broken = JSON.parse(exported);
broken[1] = { id: 'evt-broken', version: 999, type: 'status-changed', payload: {} };
assert.throws(() => freshA.controller.importLog(JSON.stringify(broken)));
assert.equal(canonical(freshA.controller.board()), beforeBoard);
assert.equal(freshA.controller.exportLog(), beforeLog);

// 8. Replay navigation never mutates the authoritative event log.
const logBefore = restored.controller.exportLog();
restored.controller.replayAt(0);
restored.controller.replayAt(3);
restored.controller.replayAt(eventTotal);
assert.equal(restored.controller.exportLog(), logBefore);
assert.equal(canonical(restored.controller.board()), finalBoard);

console.log('incident-replay behavioral verifier passed');
"""

FLAGSHIP_INCIDENT_REPLAY_PROFILE = create_native_mission_profile(
    profile_id="incident-replay-v1",
    fixture_id="local-incident-board",
    fixture_version=1,
    run_id="native-cursor-longrun-001",
    session_id="native-cursor-longrun-001",
    gate_id="native-longrun-gate",
    mission_id="native-longrun-incident-replay",
    mission_text=FLAGSHIP_MISSION_TEXT,
    gate_objective=(
        "Complete and locally commit deterministic incident replay with durable "
        "local persistence in the assigned incident-board repository."
    ),
    gate_clauses=(
        (
            "native-longrun.material",
            "The committed material implements deterministic, versioned incident replay "
            "with durable injected-storage persistence, validated export and import, "
            "duplicate-event handling, and fail-closed rejection of invalid event data.",
        ),
        (
            "native-longrun.tests",
            "The complete npm test suite passes independently at checkpoint capture.",
        ),
        (
            "native-longrun.behavior",
            "The independent behavioral verifier passes against the final public modules.",
        ),
        (
            "native-longrun.git",
            "The exact local commit exists, the worktree is clean, and no remote exists.",
        ),
    ),
    required_evidence_kinds=(
        EvidenceKind.TARGET_TREE.value,
        EvidenceKind.GIT_STATE.value,
        EvidenceKind.VERIFICATION_COMMAND.value,
    ),
    checkpoint_commands=(
        ProfileCheckpointCommand(
            command_id="npm-test",
            argv=("npm.cmd", "test"),
            timeout_seconds=300,
            max_capture_bytes=1024 * 1024,
        ),
    ),
    required_commit_message=FLAGSHIP_REQUIRED_COMMIT_MESSAGE,
    required_material_paths=(
        "README.md",
        "index.html",
        "src/app.js",
        "src/domain/event-log.js",
        "src/storage/event-store.js",
        "src/ui/render.js",
        "test/event-replay.test.js",
    ),
    completion_conditions_text=FLAGSHIP_COMPLETION_CONDITIONS_TEXT,
    verifier_source=FLAGSHIP_VERIFIER_SOURCE,
    verifier_source_sha256=_sha256_text(FLAGSHIP_VERIFIER_SOURCE),
    verifier_timeout_seconds=60,
    verifier_output_limit_bytes=262144,
    budgets=ONE_SHOT_PROFILE_BUDGETS,
    timeout_seconds=3600,
    stdout_byte_limit=8_388_608,
    stderr_byte_limit=1_048_576,
    model="auto",
    fixture_initial_commit_message="chore: initialize incident board fixture",
)


# ---------------------------------------------------------------------------
# Replacement flagship profile: workflow-recovery-v1.
# ---------------------------------------------------------------------------

WORKFLOW_RECOVERY_MISSION_TEXT = """Extend the existing local-first workflow console with a deterministic, durable
and resumable workflow execution engine. Preserve all existing
workflow-definition, task-editing, configuration-persistence,
configuration-export and browser behavior.

Work only inside the exact assigned workspace. Do not read or modify the source
repository, sibling run roots, sibling workspaces, evidence directories,
authorization records or prior-run artifacts.

Implement the following externally observable behavior:

1. Validate every workflow dependency graph before starting a run. Reject
missing dependencies, self-dependencies and cycles without persisting partial
run state. Produce a deterministic topological order. When multiple tasks are
otherwise equivalent, task ID ascending is the deterministic tie-breaker.

2. Represent task execution with explicit queued, running, succeeded, failed,
retry-wait and cancelled states. A terminal upstream failure must prevent
dependent work from starting; an explicit blocked representation may be used.
Enforce a configurable positive maximum-concurrency limit.

3. Expose `createWorkflowEngine({ storage, clock, outcomes, maxConcurrency })`
from `src/execution/engine.js`. The engine must expose `startRun`,
`advanceRun`, `cancelRun`, `recoverRun`, `run`, `listRuns`, `exportRuns` and
`importRuns`. One `advanceRun` call represents one complete deterministic
scheduler cycle: it starts eligible tasks until the configured concurrency
limit is filled and consults the injected outcome adapter for currently running
attempts during that cycle. `advanceRun` must not sleep.

4. The injected clock exposes `now()` returning a non-negative integer
timestamp. The injected outcome adapter exposes
`next({ runId, taskId, attempt })` and returns either
`{ status: "succeeded", result }`, `{ status: "failed", error }`, or `null`
to leave that attempt in progress.

5. Treat each task's maximum-attempt value as including its initial attempt.
For a failure at time `failureTime`, calculate the next attempt as
`failureTime + backoffMs * 2 ** (attempt - 1)`. Persist that timestamp, expose
it on the task entry returned by `run()` and `listRuns()` as `nextAttemptAt`, do
not retry early, and enter terminal failure after exhausting attempts.

6. Cancellation must cancel queued and retry-wait tasks, prevent new dependent
work from starting, preserve completed results and be idempotent. Repeating
cancellation must not add timeline entries or change deterministic export.

7. Persist workflow-run state through the injected storage adapter. Recover
state after a simulated process restart. A persisted running attempt must be
marked interrupted and made safely recoverable. Already succeeded attempts and
results must never be duplicated. Repeated recovery must be idempotent.

8. Use current run-state schema version `1`. Import the supplied version-0
legacy fixture by mapping completed tasks to succeeded, running tasks to
recoverable queued work with an interrupted attempt, and pending tasks to
queued. Reject unsupported future versions. Migration or import failure must
leave the previously valid stored state byte-for-byte unchanged.

9. Export run state deterministically. Validate the complete import before
mutation. Reject malformed relationships and duplicate run, task or attempt
identities atomically. Equivalent logical state must produce byte-identical
export independent of insertion order.

10. Integrate the engine through the existing
`createApp(storage, options = {})` composition boundary without breaking
existing public behavior. Display workflow-run status, task state, attempt
count and a chronological execution timeline. Expose start, cancel and
resume/recover controls. UI-facing summaries must be testable in Node without
a browser dependency.

11. Add comprehensive Node tests covering success, failure, negative
validation, retry exhaustion, cancellation, migration and restart recovery.
Do not use wall-clock sleeps. Update README documentation.

The following hard material paths must be created or materially modified by the
task commit:

- README.md
- index.html
- src/app.js
- src/execution/engine.js
- src/storage/run-store.js
- src/ui/render.js

Do not install dependencies, access the network, launch external commands as
workflow tasks, add a remote, push, deploy or modify anything outside the
assigned workspace."""

WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE = "feat: add resumable workflow execution"

WORKFLOW_RECOVERY_V2_INTEROPERABILITY_TEXT = """The behavioral verifier interacts only through the following public interface.
Implement these exact calling conventions:

- `createWorkflowEngine({ storage, clock, outcomes, maxConcurrency })`
  returns the engine;

- `startRun({ runId, workflow })` accepts one object argument containing the
  non-empty run identifier and the complete workflow definition object;

- `advanceRun(runId)` performs one complete deterministic scheduler cycle and
  returns the current run-state object;

- `cancelRun(runId)` cancels the identified run and returns its current
  run-state object;

- `recoverRun(runId)` recovers the identified persisted run and returns its
  current run-state object;

- `run(runId)` returns the current run-state object for that identifier;

- `listRuns()` returns an array of current run-state objects;

- `exportRuns()` returns the complete deterministic run-state export as JSON
  text;

- `importRuns(serializedText)` accepts that JSON text as one positional string
  argument, validates it completely before mutation, and returns the imported
  run-state collection.

These are public interoperability requirements only. Internal architecture,
state representation, graph algorithm, scheduler implementation, persistence
layout, class structure and module decomposition remain implementation
choices."""

_WORKFLOW_RECOVERY_ENGINE_REQUIREMENT = """3. Expose `createWorkflowEngine({ storage, clock, outcomes, maxConcurrency })`
from `src/execution/engine.js`. The engine must expose `startRun`,
`advanceRun`, `cancelRun`, `recoverRun`, `run`, `listRuns`, `exportRuns` and
`importRuns`. One `advanceRun` call represents one complete deterministic
scheduler cycle: it starts eligible tasks until the configured concurrency
limit is filled and consults the injected outcome adapter for currently running
attempts during that cycle. `advanceRun` must not sleep."""

# workflow-recovery-v2 exists because the persisted v1 mission named startRun
# but did not disclose the one-object public calling convention already enforced
# by the frozen verifier. V2 changes disclosure only; it does not change the
# fixture, verifier or workflow semantics.
WORKFLOW_RECOVERY_V2_MISSION_TEXT = WORKFLOW_RECOVERY_MISSION_TEXT.replace(
    _WORKFLOW_RECOVERY_ENGINE_REQUIREMENT,
    _WORKFLOW_RECOVERY_ENGINE_REQUIREMENT
    + "\n\n"
    + WORKFLOW_RECOVERY_V2_INTEROPERABILITY_TEXT,
)

WORKFLOW_RECOVERY_COMPLETION_CONDITIONS_TEXT = f"""Required completion conditions:
- satisfy every mission requirement and gate clause;

- run the complete `npm test` suite and require it to pass;

- confirm that each hard material path below is created or materially modified
  in the task commit:

  - README.md
  - index.html
  - src/app.js
  - src/execution/engine.js
  - src/storage/run-store.js
  - src/ui/render.js

- create exactly one intended local task commit after the fixture baseline with
  the exact complete message `{WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE}`;

- use no `--trailer` when creating or amending the commit;

- add no commit-message body, `Co-authored-by`, sign-off, attribution or other
  trailer;

- before stopping, run `git log -1 --format=%B` and verify that its complete
  output, after removing terminal newline characters only, is exactly
  `{WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE}`;

- if the complete message is not exact, amend that same task commit during this
  native invocation, do not create a second task commit, and run the exact
  `%B` verification again;

- confirm the worktree and index are clean;

- confirm no Git remotes exist;

- do not amend, replace or recreate the fixture baseline commit;

- do not read or modify the source repository, sibling run roots, sibling
  workspaces, evidence directories, authorization records or prior-run
  artifacts;

- do not install dependencies, access the network, launch external workflow
  commands, add a remote, push or deploy;

- do not continue with optional polish after the final verification.

Stop immediately only after the complete npm test suite passes, every required
material path is present in the single intended task commit, the exact complete
commit message has been verified with `git log -1 --format=%B`, the worktree
and index are clean, and the repository has zero remotes. Do not perform
further exploration or changes after those checks."""

# Independent public-behavior verifier.  Project imports are limited to the
# three authored interoperability boundaries; Node built-ins provide only
# assertions, path conversion, and read-only access to the supplied v0 fixture.
WORKFLOW_RECOVERY_VERIFIER_SOURCE = r"""import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const root = process.argv[2];
const load = (relative) => import(pathToFileURL(join(root, ...relative.split('/'))).href);
const { createApp } = await load('src/app.js');
const { createWorkflowEngine } = await load('src/execution/engine.js');
const { createMemoryStorage } = await load('src/storage/memory-storage.js');

const clone = (value) => JSON.parse(JSON.stringify(value));
const workflow = (id, tasks) => ({ id, name: id, tasks });
const task = (id, dependsOn = [], policy = {}) => ({
  id,
  title: id,
  description: `${id} description`,
  dependsOn,
  maxAttempts: policy.maxAttempts ?? 1,
  backoffMs: policy.backoffMs ?? 0,
});

function manualClock(initial = 0) {
  let value = initial;
  return {
    now: () => value,
    set(next) { value = next; },
    advance(delta) { value += delta; },
  };
}

function scriptedOutcomes(script = {}) {
  const calls = [];
  const queues = new Map(Object.entries(script).map(([id, values]) => [id, [...values]]));
  return {
    calls,
    next(context) {
      calls.push(clone(context));
      const queue = queues.get(context.taskId) ?? [];
      return queue.length ? queue.shift() : null;
    },
  };
}

function start(engine, runId, definition) {
  return engine.startRun({ runId, workflow: definition });
}

function runs(engine) {
  const value = engine.listRuns();
  assert.ok(Array.isArray(value), 'listRuns() must return an array');
  return value;
}

function current(engine, runId) {
  const value = runs(engine).find((candidate) => candidate.id === runId || candidate.runId === runId);
  assert.ok(value, `run ${runId} must be listed`);
  return value;
}

function tasksOf(run) {
  if (Array.isArray(run.tasks)) return run.tasks;
  assert.ok(run.tasks && typeof run.tasks === 'object', 'run tasks must be inspectable');
  return Object.values(run.tasks);
}

function taskOf(run, taskId) {
  const value = tasksOf(run).find((candidate) => candidate.id === taskId || candidate.taskId === taskId);
  assert.ok(value, `task ${taskId} must be inspectable`);
  return value;
}

function stateOf(value) {
  return value.state ?? value.status;
}

function attemptCount(value) {
  if (Array.isArray(value.attempts)) return value.attempts.length;
  return value.attemptCount ?? value.attempt ?? value.attempts ?? 0;
}

function terminal(run) {
  return ['succeeded', 'failed', 'cancelled'].includes(stateOf(run));
}

function drive(engine, runId, limit = 30) {
  for (let index = 0; index < limit && !terminal(current(engine, runId)); index += 1) {
    engine.advanceRun(runId);
  }
  return current(engine, runId);
}

function canonicalExport(engine) {
  const value = engine.exportRuns();
  assert.equal(typeof value, 'string', 'exportRuns() must return text');
  JSON.parse(value);
  return value;
}

function assertRequiredSurface(engine) {
  for (const name of ['startRun', 'advanceRun', 'cancelRun', 'recoverRun', 'run', 'listRuns', 'exportRuns', 'importRuns']) {
    assert.equal(typeof engine[name], 'function', `${name} must be a public engine method`);
  }
}

// Invalid graphs fail before any run-state mutation.
{
  const storage = createMemoryStorage();
  const engine = createWorkflowEngine({ storage, clock: manualClock(), outcomes: scriptedOutcomes(), maxConcurrency: 2 });
  assertRequiredSurface(engine);
  const before = canonicalExport(engine);
  assert.throws(() => start(engine, 'missing-run', workflow('missing', [task('a', ['absent'])])));
  assert.equal(canonicalExport(engine), before);
  assert.throws(() => start(engine, 'self-run', workflow('self', [task('a', ['a'])])));
  assert.equal(canonicalExport(engine), before);
  assert.throws(() => start(engine, 'cycle-run', workflow('cycle', [task('a', ['b']), task('b', ['a'])])));
  assert.equal(canonicalExport(engine), before);
}

// Canonical ordering is independent of definition insertion order.
function orderedCalls(tasks) {
  const outcomes = scriptedOutcomes({
    'root-a': [{ status: 'succeeded', result: 'a' }],
    'root-b': [{ status: 'succeeded', result: 'b' }],
    child: [{ status: 'succeeded', result: 'child' }],
  });
  const engine = createWorkflowEngine({ storage: createMemoryStorage(), clock: manualClock(10), outcomes, maxConcurrency: 1 });
  start(engine, 'ordered', workflow('ordered-workflow', tasks));
  drive(engine, 'ordered');
  return outcomes.calls.map((call) => call.taskId);
}
const orderingA = orderedCalls([task('root-b'), task('child', ['root-b', 'root-a']), task('root-a')]);
const orderingB = orderedCalls([task('root-a'), task('root-b'), task('child', ['root-a', 'root-b'])]);
assert.deepEqual(orderingA, ['root-a', 'root-b', 'child']);
assert.deepEqual(orderingB, orderingA);

// Bounded concurrency and deterministic runnable selection.
{
  const outcomes = scriptedOutcomes();
  const engine = createWorkflowEngine({ storage: createMemoryStorage(), clock: manualClock(20), outcomes, maxConcurrency: 2 });
  start(engine, 'concurrency', workflow('concurrency-workflow', [task('c'), task('a'), task('b')]));
  engine.advanceRun('concurrency');
  const visible = current(engine, 'concurrency');
  assert.equal(tasksOf(visible).filter((entry) => stateOf(entry) === 'running').length, 2);
  assert.deepEqual(outcomes.calls.slice(0, 2).map((call) => call.taskId), ['a', 'b']);
  assert.ok(tasksOf(visible).filter((entry) => stateOf(entry) === 'running').length <= 2);
}

// Retry timing, no early retry, success after the boundary, and exhaustion.
{
  const clock = manualClock(1_000);
  const outcomes = scriptedOutcomes({ flaky: [
    { status: 'failed', error: 'temporary' },
    { status: 'succeeded', result: 'recovered' },
  ] });
  const engine = createWorkflowEngine({ storage: createMemoryStorage(), clock, outcomes, maxConcurrency: 1 });
  start(engine, 'retry-success', workflow('retry-workflow', [task('flaky', [], { maxAttempts: 2, backoffMs: 50 })]));
  engine.advanceRun('retry-success');
  let visible = taskOf(current(engine, 'retry-success'), 'flaky');
  assert.equal(stateOf(visible), 'retry-wait');
  assert.equal(visible.nextAttemptAt, 1_050);
  assert.equal(attemptCount(visible), 1);
  clock.set(1_049);
  engine.advanceRun('retry-success');
  assert.equal(outcomes.calls.length, 1);
  clock.set(1_050);
  drive(engine, 'retry-success');
  visible = taskOf(current(engine, 'retry-success'), 'flaky');
  assert.equal(stateOf(visible), 'succeeded');
  assert.equal(attemptCount(visible), 2);

  const exhausted = scriptedOutcomes({ upstream: [
    { status: 'failed', error: 'first' },
    { status: 'failed', error: 'last' },
  ] });
  const exhaustedClock = manualClock(2_000);
  const failedEngine = createWorkflowEngine({ storage: createMemoryStorage(), clock: exhaustedClock, outcomes: exhausted, maxConcurrency: 1 });
  start(failedEngine, 'retry-failed', workflow('failed-workflow', [
    task('upstream', [], { maxAttempts: 2, backoffMs: 10 }),
    task('dependent', ['upstream']),
  ]));
  failedEngine.advanceRun('retry-failed');
  exhaustedClock.set(2_010);
  drive(failedEngine, 'retry-failed');
  const failed = current(failedEngine, 'retry-failed');
  assert.equal(stateOf(taskOf(failed, 'upstream')), 'failed');
  assert.notEqual(stateOf(taskOf(failed, 'dependent')), 'succeeded');
  assert.ok(!exhausted.calls.some((call) => call.taskId === 'dependent'));
}

// Cancellation preserves completed work and is byte-idempotent.
{
  const outcomes = scriptedOutcomes({
    done: [{ status: 'succeeded', result: { value: 7 } }],
    waiting: [{ status: 'failed', error: 'retry later' }],
  });
  const engine = createWorkflowEngine({ storage: createMemoryStorage(), clock: manualClock(3_000), outcomes, maxConcurrency: 1 });
  start(engine, 'cancelled', workflow('cancel-workflow', [
    task('done'),
    task('waiting', ['done'], { maxAttempts: 3, backoffMs: 100 }),
    task('downstream', ['waiting']),
  ]));
  engine.advanceRun('cancelled');
  engine.advanceRun('cancelled');
  assert.equal(stateOf(taskOf(current(engine, 'cancelled'), 'waiting')), 'retry-wait');
  engine.cancelRun('cancelled');
  const once = canonicalExport(engine);
  const cancelled = current(engine, 'cancelled');
  assert.equal(stateOf(taskOf(cancelled, 'done')), 'succeeded');
  assert.deepEqual(taskOf(cancelled, 'done').result, { value: 7 });
  assert.equal(stateOf(taskOf(cancelled, 'waiting')), 'cancelled');
  assert.equal(stateOf(taskOf(cancelled, 'downstream')), 'cancelled');
  engine.cancelRun('cancelled');
  assert.equal(canonicalExport(engine), once);
  engine.advanceRun('cancelled');
  assert.ok(!outcomes.calls.some((call) => call.taskId === 'downstream'));
}

// Restart recovery interrupts only in-progress work and never repeats success.
{
  const storage = createMemoryStorage();
  const clock = manualClock(4_000);
  const firstOutcomes = scriptedOutcomes({
    complete: [{ status: 'succeeded', result: 'kept' }],
    interrupted: [null],
  });
  const first = createWorkflowEngine({ storage, clock, outcomes: firstOutcomes, maxConcurrency: 1 });
  start(first, 'recovery', workflow('recovery-workflow', [task('complete'), task('interrupted', ['complete'])]));
  first.advanceRun('recovery');
  first.advanceRun('recovery');
  const completedAttempts = attemptCount(taskOf(current(first, 'recovery'), 'complete'));
  assert.equal(stateOf(taskOf(current(first, 'recovery'), 'interrupted')), 'running');

  const resumedOutcomes = scriptedOutcomes({ interrupted: [{ status: 'succeeded', result: 'resumed' }] });
  const second = createWorkflowEngine({ storage, clock, outcomes: resumedOutcomes, maxConcurrency: 1 });
  second.recoverRun('recovery');
  const recovered = current(second, 'recovery');
  assert.equal(stateOf(taskOf(recovered, 'complete')), 'succeeded');
  assert.equal(attemptCount(taskOf(recovered, 'complete')), completedAttempts);
  assert.notEqual(stateOf(taskOf(recovered, 'interrupted')), 'succeeded');
  assert.match(JSON.stringify(recovered).toLowerCase(), /interrupt/);
  drive(second, 'recovery');
  const finished = current(second, 'recovery');
  assert.equal(stateOf(taskOf(finished, 'interrupted')), 'succeeded');
  assert.equal(resumedOutcomes.calls.filter((call) => call.taskId === 'interrupted').length, 1);
  const stable = canonicalExport(second);
  second.recoverRun('recovery');
  assert.equal(canonicalExport(second), stable);
}

// Version-0 migration and fail-closed import validation.
{
  const legacyText = await readFile(join(root, 'test', 'fixtures', 'legacy-run-state-v0.json'), 'utf8');
  const storage = createMemoryStorage();
  const engine = createWorkflowEngine({ storage, clock: manualClock(5_000), outcomes: scriptedOutcomes(), maxConcurrency: 2 });
  engine.importRuns(legacyText);
  const migrated = JSON.parse(canonicalExport(engine));
  assert.equal(migrated.schemaVersion, 1);
  const legacy = current(engine, 'legacy-run-001');
  assert.equal(stateOf(taskOf(legacy, 'prepare')), 'succeeded');
  assert.deepEqual(taskOf(legacy, 'prepare').result, { artifact: 'prepared.json' });
  assert.equal(stateOf(taskOf(legacy, 'publish')), 'queued');
  assert.match(JSON.stringify(taskOf(legacy, 'publish')).toLowerCase(), /interrupt/);
  assert.equal(stateOf(taskOf(legacy, 'notify')), 'queued');

  const before = canonicalExport(engine);
  assert.throws(() => engine.importRuns(JSON.stringify({ schemaVersion: 99, runs: [] })));
  assert.equal(canonicalExport(engine), before);

  const duplicateRun = JSON.parse(before);
  assert.ok(Array.isArray(duplicateRun.runs) && duplicateRun.runs.length > 0);
  duplicateRun.runs.push(clone(duplicateRun.runs[0]));
  assert.throws(() => engine.importRuns(JSON.stringify(duplicateRun)));
  assert.equal(canonicalExport(engine), before);

  const duplicateTask = JSON.parse(before);
  assert.ok(Array.isArray(duplicateTask.runs[0].tasks) && duplicateTask.runs[0].tasks.length > 0);
  duplicateTask.runs[0].tasks.push(clone(duplicateTask.runs[0].tasks[0]));
  assert.throws(() => engine.importRuns(JSON.stringify(duplicateTask)));
  assert.equal(canonicalExport(engine), before);

  const duplicateAttempt = JSON.parse(before);
  const attemptedTask = duplicateAttempt.runs[0].tasks.find((entry) => Array.isArray(entry.attempts) && entry.attempts.length > 0);
  assert.ok(attemptedTask, 'migrated state must expose attempt identities');
  attemptedTask.attempts.push(clone(attemptedTask.attempts[0]));
  assert.throws(() => engine.importRuns(JSON.stringify(duplicateAttempt)));
  assert.equal(canonicalExport(engine), before);

  const brokenRelationship = JSON.parse(before);
  brokenRelationship.runs[0].tasks[0].dependsOn = ['absent-task'];
  assert.throws(() => engine.importRuns(JSON.stringify(brokenRelationship)));
  assert.equal(canonicalExport(engine), before);
}

// Equivalent completed runs export identically despite definition insertion order.
function deterministicExport(tasks) {
  const outcomes = scriptedOutcomes({ a: [{ status: 'succeeded', result: 'a' }], b: [{ status: 'succeeded', result: 'b' }] });
  const engine = createWorkflowEngine({ storage: createMemoryStorage(), clock: manualClock(6_000), outcomes, maxConcurrency: 1 });
  start(engine, 'deterministic', workflow('deterministic-workflow', tasks));
  drive(engine, 'deterministic');
  return canonicalExport(engine);
}
assert.equal(deterministicExport([task('b'), task('a')]), deterministicExport([task('a'), task('b')]));

// Existing definition operations and Node-testable run UI remain integrated.
{
  const storage = createMemoryStorage();
  const outcomes = scriptedOutcomes({ ui: [{ status: 'succeeded', result: 'shown' }] });
  const engine = createWorkflowEngine({ storage, clock: manualClock(7_000), outcomes, maxConcurrency: 1 });
  start(engine, 'ui-run', workflow('ui-workflow', [task('ui')]));
  drive(engine, 'ui-run');
  const app = createApp(storage, { clock: manualClock(7_000), outcomes: scriptedOutcomes(), maxConcurrency: 1 });
  app.controller.createWorkflow({ id: 'definition', name: 'Definition remains usable', description: 'existing behavior' });
  app.controller.addTask('definition', task('definition-task'));
  app.controller.updateTask('definition', 'definition-task', { title: 'Updated task' });
  assert.equal(app.controller.workflow('definition').tasks[0].title, 'Updated task');
  assert.equal(typeof app.controller.exportConfiguration(), 'string');
  const rendered = Object.entries(app)
    .filter(([name, value]) => name.startsWith('render') && typeof value === 'function')
    .map(([, render]) => render())
    .filter((value) => typeof value === 'string')
    .join('\n');
  for (const expected of ['ui-run', 'succeeded', 'attempt', 'timeline', 'start', 'cancel']) {
    assert.match(rendered.toLowerCase(), new RegExp(expected));
  }
  assert.match(rendered.toLowerCase(), /recover|resume/);
}

console.log('workflow-recovery behavioral verifier passed');
"""

WORKFLOW_RECOVERY_PROFILE = create_native_mission_profile(
    profile_id="workflow-recovery-v1",
    fixture_id="local-workflow-console",
    fixture_version=1,
    run_id="native-cursor-flagship-002",
    session_id="native-cursor-flagship-002",
    gate_id="workflow-recovery-gate",
    mission_id="native-flagship-workflow-recovery",
    mission_text=WORKFLOW_RECOVERY_MISSION_TEXT,
    gate_objective=(
        "Deliver a deterministic, durable and resumable workflow engine while preserving "
        "existing workflow-definition behavior and satisfying the one-commit offline contract."
    ),
    gate_clauses=(
        (
            "workflow-recovery.graph",
            "Dependency validation and deterministic topological ordering reject invalid "
            "graphs before mutation.",
        ),
        (
            "workflow-recovery.execution",
            "Scheduling, concurrency, retries, dependency blocking and cancellation obey "
            "deterministic state-transition rules.",
        ),
        (
            "workflow-recovery.persistence",
            "Versioned storage, migration, atomic import/export and restart recovery "
            "preserve durable identity without duplicate completion.",
        ),
        (
            "workflow-recovery.ui",
            "Existing definition behavior remains compatible while run summaries, task "
            "attempts, timelines and controls are integrated.",
        ),
        (
            "workflow-recovery.tests",
            "The complete offline Node test suite covers positive, negative and recovery "
            "behavior without wall-clock sleeps.",
        ),
        (
            "workflow-recovery.git",
            "The result is exactly one clean local task commit with the required message and "
            "zero remotes.",
        ),
    ),
    required_evidence_kinds=(
        EvidenceKind.TARGET_TREE.value,
        EvidenceKind.GIT_STATE.value,
        EvidenceKind.VERIFICATION_COMMAND.value,
    ),
    checkpoint_commands=(
        ProfileCheckpointCommand(
            command_id="npm-test",
            argv=("npm.cmd", "test"),
            timeout_seconds=300,
            max_capture_bytes=1024 * 1024,
        ),
    ),
    required_commit_message=WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE,
    required_material_paths=(
        "README.md",
        "index.html",
        "src/app.js",
        "src/execution/engine.js",
        "src/storage/run-store.js",
        "src/ui/render.js",
    ),
    completion_conditions_text=WORKFLOW_RECOVERY_COMPLETION_CONDITIONS_TEXT,
    verifier_source=WORKFLOW_RECOVERY_VERIFIER_SOURCE,
    verifier_source_sha256=_sha256_text(WORKFLOW_RECOVERY_VERIFIER_SOURCE),
    verifier_timeout_seconds=120,
    verifier_output_limit_bytes=524_288,
    budgets=ONE_SHOT_PROFILE_BUDGETS,
    timeout_seconds=3600,
    stdout_byte_limit=8_388_608,
    stderr_byte_limit=1_048_576,
    model="auto",
    fixture_initial_commit_message="chore: initialize workflow console fixture",
)

WORKFLOW_RECOVERY_V2_PROFILE = create_native_mission_profile(
    **{
        **{
            key: value
            for key, value in WORKFLOW_RECOVERY_PROFILE.__dict__.items()
            if key not in {"schema_version", "profile_fingerprint"}
        },
        "profile_id": "workflow-recovery-v2",
        "run_id": "native-cursor-flagship-003",
        "session_id": "native-cursor-flagship-003",
        "mission_id": "native-flagship-workflow-recovery-v2",
        "gate_id": "workflow-recovery-v2-gate",
        "mission_text": WORKFLOW_RECOVERY_V2_MISSION_TEXT,
    }
)


# ---------------------------------------------------------------------------
# Comparison-experiment profile: neon-siege-v1.
# ---------------------------------------------------------------------------

from admissible.delegated_gate.fixture_registry import (  # noqa: E402
    NEON_SIEGE_FIXTURE_ID,
    NEON_SIEGE_FIXTURE_VERSION,
    NEON_SIEGE_INITIAL_COMMIT_MESSAGE,
)
from admissible.delegated_gate.neon_siege_mission import (  # noqa: E402
    NEON_SIEGE_COMPLETION_CONDITIONS_TEXT,
    NEON_SIEGE_EXACT_USER_PROMPT,
    NEON_SIEGE_REQUIRED_COMMIT_MESSAGE,
    NEON_SIEGE_REQUIRED_MATERIAL_PATHS,
    NEON_SIEGE_VERIFIER_SOURCE,
    NEON_SIEGE_VERIFIER_SOURCE_SHA256,
)

NEON_SIEGE_PROFILE = create_native_mission_profile(
    profile_id="neon-siege-v1",
    fixture_id=NEON_SIEGE_FIXTURE_ID,
    fixture_version=NEON_SIEGE_FIXTURE_VERSION,
    run_id="native-cursor-neon-siege-001",
    session_id="native-cursor-neon-siege-001",
    gate_id="neon-siege-gate",
    mission_id="native-neon-siege",
    mission_text=NEON_SIEGE_EXACT_USER_PROMPT,
    gate_objective=(
        "Deliver a complete, dependency-free, statically deployable Neon Siege browser "
        "game that satisfies the immutable mission text and the one-commit offline contract."
    ),
    gate_clauses=(
        (
            "neon-siege.material",
            "Required material paths exist, the project is free of external runtime or test "
            "dependencies, and the tree is suitable for static deployment.",
        ),
        (
            "neon-siege.tests",
            "The complete npm test suite passes independently at checkpoint capture and "
            "covers core game-state logic rather than only file existence.",
        ),
        (
            "neon-siege.behavior",
            "The independent behavioral verifier observes core gameplay and lifecycle "
            "behavior, including start, pause/resume, game-over, restart, waves, upgrades, "
            "health/damage, score, high score, dash, enemy archetype diversity, and a "
            "bounded local-start probe with proven cleanup.",
        ),
        (
            "neon-siege.git",
            "Exactly one clean local task commit exists with the required complete message "
            "and zero remotes.",
        ),
    ),
    required_evidence_kinds=(
        EvidenceKind.TARGET_TREE.value,
        EvidenceKind.GIT_STATE.value,
        EvidenceKind.VERIFICATION_COMMAND.value,
    ),
    checkpoint_commands=(
        ProfileCheckpointCommand(
            command_id="npm-test",
            argv=("npm.cmd", "test"),
            timeout_seconds=300,
            max_capture_bytes=1024 * 1024,
        ),
    ),
    required_commit_message=NEON_SIEGE_REQUIRED_COMMIT_MESSAGE,
    required_material_paths=NEON_SIEGE_REQUIRED_MATERIAL_PATHS,
    completion_conditions_text=NEON_SIEGE_COMPLETION_CONDITIONS_TEXT,
    verifier_source=NEON_SIEGE_VERIFIER_SOURCE,
    verifier_source_sha256=NEON_SIEGE_VERIFIER_SOURCE_SHA256,
    verifier_timeout_seconds=60,
    verifier_output_limit_bytes=262144,
    budgets=ONE_SHOT_PROFILE_BUDGETS,
    timeout_seconds=3600,
    stdout_byte_limit=8_388_608,
    stderr_byte_limit=1_048_576,
    model="auto",
    fixture_initial_commit_message=NEON_SIEGE_INITIAL_COMMIT_MESSAGE,
)


# ---------------------------------------------------------------------------
# Runtime-v2 mission profile: neon-relay-v1.
#
# This is the first registered profile whose workspace source is an existing
# ordinary local Git repository rather than a registered fixture builder.  The
# absolute fixture path below is the immutable blank Neon Relay fixture; its
# exact HEAD is not a field of the accepted ``WorkspaceSourceAuthority`` schema,
# so it is bound instead by the committed profile tests and, at authorization
# time, by the independently observed ``initialized_workspace`` identity inside
# the canonical v4 authorization payload.
# ---------------------------------------------------------------------------

from admissible.delegated_gate.neon_relay_mission import (  # noqa: E402
    NEON_RELAY_COMPLETION_CONDITIONS_TEXT,
    NEON_RELAY_MISSION_TEXT,
    NEON_RELAY_REQUIRED_COMMIT_MESSAGE,
    NEON_RELAY_REQUIRED_MATERIAL_PATHS,
    NEON_RELAY_VERIFIER_SOURCE,
    NEON_RELAY_VERIFIER_SOURCE_SHA256,
)

NEON_RELAY_FIXTURE_REPOSITORY_PATH = (
    r"C:\Users\stris\Documents\Projets\ENTRE\admissible-neon-relay-source"
)
NEON_RELAY_VERIFIER_TIMEOUT_SECONDS = 180
NEON_RELAY_VERIFIER_OUTPUT_LIMIT_BYTES = 262144

NEON_RELAY_PROFILE = create_native_mission_profile(
    schema_version=MISSION_PROFILE_SCHEMA_VERSION_V2,
    profile_id="neon-relay-v1",
    run_id="native-cursor-neon-relay-001",
    session_id="native-cursor-neon-relay-001",
    gate_id="neon-relay-gate",
    mission_id="native-neon-relay",
    mission_text=NEON_RELAY_MISSION_TEXT,
    gate_objective=(
        "Deliver a complete, dependency-free, browser-playable Neon Relay game whose "
        "seeded domain layer satisfies the owner-frozen behavioral contract under the "
        "one-shot, one-commit offline law."
    ),
    gate_clauses=(
        (
            "neon-relay.material",
            "Every one of the fourteen required material paths exists and is created or "
            "materially changed between the fixture initial commit and the task commit.",
        ),
        (
            "neon-relay.git",
            "Exactly one clean local task commit exists with the exact required complete "
            "message, a clean worktree and index, no untracked file and zero remotes.",
        ),
        (
            "neon-relay.checkpoint",
            "The public npm-test checkpoint command runs to termination and exits zero "
            "inside its configured timeout and capture bound.",
        ),
        (
            "neon-relay.behavior",
            "The owner-frozen independent behavioral verifier reports every clause from "
            "C01_required_paths through C18_enemy_archetypes satisfied and emits its exact "
            "final success line.",
        ),
        (
            "neon-relay.nonclaims",
            "The bounded non-claims are reported rather than silently assumed: visual "
            "quality, control feel and complete human playability are not established, no "
            "browser was launched, and no server or network access was attempted.",
        ),
        (
            "neon-relay.human-visual-review",
            "Visual quality, product coherence and playability remain reserved for a "
            "separate human review and are established by no automated step in this run.",
        ),
    ),
    required_evidence_kinds=(
        EvidenceKind.TARGET_TREE.value,
        EvidenceKind.GIT_STATE.value,
        EvidenceKind.VERIFICATION_COMMAND.value,
    ),
    checkpoint_commands=(
        ProfileCheckpointCommand(
            command_id="npm-test",
            argv=("npm.cmd", "test"),
            timeout_seconds=300,
            max_capture_bytes=1024 * 1024,
        ),
    ),
    completion_conditions_text=NEON_RELAY_COMPLETION_CONDITIONS_TEXT,
    budgets=ONE_SHOT_PROFILE_BUDGETS,
    timeout_seconds=2700,
    stdout_byte_limit=8 * 1024 * 1024,
    stderr_byte_limit=1 * 1024 * 1024,
    model="auto",
    workspace_source=WorkspaceSourceAuthority(
        kind=WorkspaceSourceKind.EXISTING_LOCAL_GIT_REPOSITORY,
        local_repository_path=NEON_RELAY_FIXTURE_REPOSITORY_PATH,
    ),
    git_end_state_policy=GitEndStatePolicy(
        required_commits_added=1,
        required_complete_commit_message=NEON_RELAY_REQUIRED_COMMIT_MESSAGE,
        final_worktree_clean=True,
        final_index_clean=True,
        final_remotes_absent=True,
        required_material_paths=NEON_RELAY_REQUIRED_MATERIAL_PATHS,
    ),
    verification=VerificationAuthority(
        mode=VerificationMode.FROZEN_BEHAVIORAL,
        verifier_source=NEON_RELAY_VERIFIER_SOURCE,
        verifier_source_sha256=NEON_RELAY_VERIFIER_SOURCE_SHA256,
        verifier_timeout_seconds=NEON_RELAY_VERIFIER_TIMEOUT_SECONDS,
        verifier_output_limit_bytes=NEON_RELAY_VERIFIER_OUTPUT_LIMIT_BYTES,
        disclose_complete_source=True,
    ),
    runtime_prompt=RuntimePromptAuthority(
        permitted_effects=(
            "Create, edit and locally commit files only inside the assigned workspace.",
            "Run local dependency-free commands such as node, npm test and git inside the "
            "assigned workspace.",
        ),
        forbidden_effects=(
            "Do not install any production or development dependency and do not create "
            "node_modules.",
            "Do not use the network, a CDN, an external asset, a server, a port or a "
            "browser subprocess.",
            "Do not add a Git remote, push, deploy or touch anything outside the assigned "
            "workspace.",
            "Do not add a start script, a watch command or a development server.",
        ),
        stop_clause=(
            "Stop immediately after npm test has terminated successfully and exactly one "
            "local commit exists whose complete message is exactly "
            f"`{NEON_RELAY_REQUIRED_COMMIT_MESSAGE}`, the worktree and index are clean, no "
            "untracked file remains and zero remotes exist. Perform no push, no deployment "
            "and no optional polish after that commit."
        ),
    ),
)


# ---------------------------------------------------------------------------
# Runtime-v2 mission profile: neon-relay-v2 (ACP_STDIO transport).
#
# neon-relay-v1's argv transport is mathematically unspawnable on Windows: its
# exact prompt is 64660 characters and CreateProcessW accepts at most 32766
# serialized command-line characters, so no argv-based launch of this mission
# can ever exist.  v2 changes exactly two things -- the run identity (v1's
# single native attempt is durably consumed by the PROCESS_SPAWN_FAILED run) and
# the prompt transport.
#
# Every mission-bearing field below is taken *from the v1 profile object* rather
# than restated, so the mission text, completion conditions, frozen verifier and
# its SHA-256, required material paths, fixture, budgets, model, timeouts,
# checkpoint command and required commit message are byte-identical by
# construction.  The profile fingerprint and canonical document necessarily
# differ because the identity and transport differ.
# ---------------------------------------------------------------------------

NEON_RELAY_V2_PROFILE = create_native_mission_profile(
    schema_version=MISSION_PROFILE_SCHEMA_VERSION_V2,
    profile_id="neon-relay-v2",
    run_id="native-cursor-neon-relay-002",
    session_id="native-cursor-neon-relay-002",
    gate_id=NEON_RELAY_PROFILE.gate_id,
    mission_id=NEON_RELAY_PROFILE.mission_id,
    mission_text=NEON_RELAY_PROFILE.mission_text,
    gate_objective=NEON_RELAY_PROFILE.gate_objective,
    gate_clauses=NEON_RELAY_PROFILE.gate_clauses,
    required_evidence_kinds=NEON_RELAY_PROFILE.required_evidence_kinds,
    checkpoint_commands=NEON_RELAY_PROFILE.checkpoint_commands,
    completion_conditions_text=NEON_RELAY_PROFILE.completion_conditions_text,
    budgets=NEON_RELAY_PROFILE.budgets,
    timeout_seconds=NEON_RELAY_PROFILE.timeout_seconds,
    stdout_byte_limit=NEON_RELAY_PROFILE.stdout_byte_limit,
    stderr_byte_limit=NEON_RELAY_PROFILE.stderr_byte_limit,
    model=NEON_RELAY_PROFILE.model,
    workspace_source=NEON_RELAY_PROFILE.workspace_source,
    git_end_state_policy=NEON_RELAY_PROFILE.git_end_state_policy,
    verification=NEON_RELAY_PROFILE.verification,
    runtime_prompt=NEON_RELAY_PROFILE.runtime_prompt,
    prompt_transport=PROMPT_TRANSPORT_ACP_STDIO,
)


# ---------------------------------------------------------------------------
# Runtime-v2 mission profile: neon-relay-v3 (ACP_STDIO transport).
#
# v2's single native attempt is durably consumed: the authorized run reserved
# it, spawned a real ACP provider and then raised inside backend-drift
# observation, so ``native-cursor-neon-relay-002`` can never be reused.  v3
# changes exactly one thing -- the run identity.  The transport stays ACP_STDIO
# and every mission-bearing field is taken from the v2 profile object rather
# than restated, so mission text, completion conditions, frozen verifier and its
# SHA-256, required material paths, fixture, budgets, model, timeouts,
# checkpoint command and required commit message are byte-identical to v2 (and
# therefore to v1) by construction.  The profile fingerprint and canonical
# document necessarily differ because the identity differs.
# ---------------------------------------------------------------------------

NEON_RELAY_V3_PROFILE = create_native_mission_profile(
    schema_version=MISSION_PROFILE_SCHEMA_VERSION_V2,
    profile_id="neon-relay-v3",
    run_id="native-cursor-neon-relay-003",
    session_id="native-cursor-neon-relay-003",
    gate_id=NEON_RELAY_V2_PROFILE.gate_id,
    mission_id=NEON_RELAY_V2_PROFILE.mission_id,
    mission_text=NEON_RELAY_V2_PROFILE.mission_text,
    gate_objective=NEON_RELAY_V2_PROFILE.gate_objective,
    gate_clauses=NEON_RELAY_V2_PROFILE.gate_clauses,
    required_evidence_kinds=NEON_RELAY_V2_PROFILE.required_evidence_kinds,
    checkpoint_commands=NEON_RELAY_V2_PROFILE.checkpoint_commands,
    completion_conditions_text=NEON_RELAY_V2_PROFILE.completion_conditions_text,
    budgets=NEON_RELAY_V2_PROFILE.budgets,
    timeout_seconds=NEON_RELAY_V2_PROFILE.timeout_seconds,
    stdout_byte_limit=NEON_RELAY_V2_PROFILE.stdout_byte_limit,
    stderr_byte_limit=NEON_RELAY_V2_PROFILE.stderr_byte_limit,
    model=NEON_RELAY_V2_PROFILE.model,
    workspace_source=NEON_RELAY_V2_PROFILE.workspace_source,
    git_end_state_policy=NEON_RELAY_V2_PROFILE.git_end_state_policy,
    verification=NEON_RELAY_V2_PROFILE.verification,
    runtime_prompt=NEON_RELAY_V2_PROFILE.runtime_prompt,
    prompt_transport=NEON_RELAY_V2_PROFILE.prompt_transport,
)


# ---------------------------------------------------------------------------
# Runtime-v2 mission profile: neon-relay-v4 (ACP_STDIO transport).
#
# v3's single native attempt is durably consumed.  Its authorized run reserved
# the attempt, spawned a real ACP provider, and then died on the client side of
# the protocol: ``cursor/update_todos`` was unanswerable, every permission
# request had already been granted with ``allow_always``, and the child
# environment omitted SystemDrive/ProgramData/ALLUSERSPROFILE, so Windows
# resolved ``%SystemDrive%`` literally inside the work workspace.
#
# The repair is entirely in the client and the backend attestation -- an
# explicit server-request table, a deny-by-default permission policy, durable
# permission evidence and a derived shell-folder environment.  None of that is a
# profile field, so v4 changes exactly one thing here: the run identity.  Every
# mission-bearing field is taken from the v3 profile object rather than
# restated, so mission text, completion conditions, frozen verifier and its
# SHA-256, required material paths, fixture, budgets, model, timeouts,
# checkpoint command, human-review non-claims and required commit message are
# byte-identical to v3 (and therefore to v2 and v1) by construction.
# ---------------------------------------------------------------------------

NEON_RELAY_V4_PROFILE = create_native_mission_profile(
    schema_version=MISSION_PROFILE_SCHEMA_VERSION_V2,
    profile_id="neon-relay-v4",
    run_id="native-cursor-neon-relay-004",
    session_id="native-cursor-neon-relay-004",
    gate_id=NEON_RELAY_V3_PROFILE.gate_id,
    mission_id=NEON_RELAY_V3_PROFILE.mission_id,
    mission_text=NEON_RELAY_V3_PROFILE.mission_text,
    gate_objective=NEON_RELAY_V3_PROFILE.gate_objective,
    gate_clauses=NEON_RELAY_V3_PROFILE.gate_clauses,
    required_evidence_kinds=NEON_RELAY_V3_PROFILE.required_evidence_kinds,
    checkpoint_commands=NEON_RELAY_V3_PROFILE.checkpoint_commands,
    completion_conditions_text=NEON_RELAY_V3_PROFILE.completion_conditions_text,
    budgets=NEON_RELAY_V3_PROFILE.budgets,
    timeout_seconds=NEON_RELAY_V3_PROFILE.timeout_seconds,
    stdout_byte_limit=NEON_RELAY_V3_PROFILE.stdout_byte_limit,
    stderr_byte_limit=NEON_RELAY_V3_PROFILE.stderr_byte_limit,
    model=NEON_RELAY_V3_PROFILE.model,
    workspace_source=NEON_RELAY_V3_PROFILE.workspace_source,
    git_end_state_policy=NEON_RELAY_V3_PROFILE.git_end_state_policy,
    verification=NEON_RELAY_V3_PROFILE.verification,
    runtime_prompt=NEON_RELAY_V3_PROFILE.runtime_prompt,
    prompt_transport=NEON_RELAY_V3_PROFILE.prompt_transport,
)


__all__ = [
    "FLAGSHIP_COMPLETION_CONDITIONS_TEXT",
    "FLAGSHIP_INCIDENT_REPLAY_PROFILE",
    "FLAGSHIP_MISSION_TEXT",
    "FLAGSHIP_REQUIRED_COMMIT_MESSAGE",
    "FLAGSHIP_VERIFIER_SOURCE",
    "MISSION_PROFILE_SCHEMA_VERSION",
    "MISSION_PROFILE_SCHEMA_VERSION_V2",
    "MISSION_PROFILE_SCHEMA_VERSION_V3",
    "MISSION_PROFILE_SCHEMA_VERSION_V4",
    "MISSION_PROFILE_SCHEMA_VERSION_V5",
    "MAX_CLAIMS_PER_AUTHORITY",
    "MAX_DEPENDENCIES_PER_CLAIM",
    "MAX_NON_CLAIMS_PER_CLAIM",
    "MAX_VERIFICATION_OBLIGATIONS",
    "MAX_CLAIM_REFERENCES_PER_OBLIGATION",
    "MAX_NON_CLAIMS_PER_VERIFICATION_OBLIGATION",
    "MAX_NEGATIVE_CONTROLS_PER_OBLIGATION",
    "MAX_REFERENCE_CASES_PER_OBLIGATION",
    "MAX_VERIFICATION_EVIDENCE_BINDINGS",
    "NEON_RELAY_FIXTURE_REPOSITORY_PATH",
    "NEON_RELAY_PROFILE",
    "NEON_RELAY_V2_PROFILE",
    "NEON_RELAY_V3_PROFILE",
    "NEON_RELAY_V4_PROFILE",
    "PROMPT_TRANSPORT_ACP_STDIO",
    "PROMPT_TRANSPORT_ARGV",
    "NEON_RELAY_VERIFIER_OUTPUT_LIMIT_BYTES",
    "NEON_RELAY_VERIFIER_TIMEOUT_SECONDS",
    "NEON_SIEGE_PROFILE",
    "ONE_SHOT_PROFILE_BUDGETS",
    "WORKFLOW_RECOVERY_COMPLETION_CONDITIONS_TEXT",
    "WORKFLOW_RECOVERY_MISSION_TEXT",
    "WORKFLOW_RECOVERY_PROFILE",
    "WORKFLOW_RECOVERY_REQUIRED_COMMIT_MESSAGE",
    "WORKFLOW_RECOVERY_V2_INTEROPERABILITY_TEXT",
    "WORKFLOW_RECOVERY_V2_MISSION_TEXT",
    "WORKFLOW_RECOVERY_V2_PROFILE",
    "WORKFLOW_RECOVERY_VERIFIER_SOURCE",
    "NativeMissionProfile",
    "ClaimAuthority",
    "ClaimAuthorship",
    "ClaimObligationLevel",
    "ClaimSetCoverageStatus",
    "ClaimVerificationPlanAuthority",
    "GitEndStatePolicy",
    "ProfileCheckpointCommand",
    "RuntimePromptAuthority",
    "ResultClaim",
    "VerificationAuthority",
    "VerificationAcceptancePredicate",
    "VerificationIndependenceRequirements",
    "VerificationNegativeControl",
    "VerificationObligation",
    "VerificationMode",
    "VerificationPlanAuthorship",
    "VerificationPlanCoverageStatus",
    "VerificationStrategy",
    "VerificationEvidenceBinding",
    "VerificationEvidenceBindingAuthority",
    "VerificationEvidenceBindingAuthorship",
    "VerificationEvidenceBindingCoverageStatus",
    "VerificationEvidenceSourceAuthorityType",
    "WorkspaceSourceAuthority",
    "WorkspaceSourceKind",
    "create_native_mission_profile",
    "load_native_mission_profile_document",
]
