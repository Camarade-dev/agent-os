"""Strict, immutable persisted objects for Milestone 1.

This module is intentionally a data model.  It does not launch a model,
evaluate a policy, reserve a real effect, mutate a workspace, or contact an
authority.  ``EffectReservation`` and ``EffectReceipt`` describe future
boundaries and validate their causal relationships only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import Fingerprint, canonical_bytes, fingerprint, require_exact_keys
from .identities import IdentityReference, RunIdentity, SessionIdentity
from .schemas import (
    BUDGET_FIELDS,
    CONDITIONS,
    DECISIONS,
    DIRECT,
    GOVERNED,
    RECEIPT_STATUSES,
    SCHEMA_ALLOWED_DIFFERENCES,
    SCHEMA_BUDGET_STATE,
    SCHEMA_CAUSAL_PREDECESSOR,
    SCHEMA_CLOCK_OBSERVATION,
    SCHEMA_COMPARATIVE,
    SCHEMA_CONDITION,
    SCHEMA_EVALUATOR,
    SCHEMA_EXPERIMENT,
    SCHEMA_INTERVENTION,
    SCHEMA_MODE_DECISION,
    SCHEMA_PROPOSAL,
    SCHEMA_RECEIPT,
    SCHEMA_RESERVATION,
    SCHEMA_SESSION_IDENTITY,
    SCHEMA_TERMINAL,
    SCHEMA_VERSION,
    TOOL_NAMES,
)


MAX_COUNTER = 2**63 - 1
_IDENTIFIER_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-")
COMMON_EXPERIMENT_FINGERPRINT_DOMAIN = "admissible.paired_runner.experiment_common.fingerprint"


def _identifier(value: Any, label: str, *, max_length: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > max_length
        or value[0] not in _IDENTIFIER_CHARS
        or any(character not in _IDENTIFIER_CHARS for character in value)
    ):
        raise ValueError(f"{label} must be a stable identifier")
    return value


def _text(value: Any, label: str, *, max_bytes: int = 65536) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{label} must be non-empty text without NUL")
    if len(value.encode("utf-8")) > max_bytes:
        raise ValueError(f"{label} exceeds its byte bound")
    return value


def _strict_bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be a boolean")
    return value


def _counter(value: Any, label: str, *, allow_none: bool = False) -> int | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_COUNTER:
        raise ValueError(f"{label} must be an integer in [0, {MAX_COUNTER}]")
    return value


def _fp(value: Any, label: str) -> Fingerprint:
    if not isinstance(value, Fingerprint):
        raise ValueError(f"{label} must be a Fingerprint")
    return value.validated()


def _identity(value: Any, label: str) -> IdentityReference:
    if not isinstance(value, IdentityReference):
        raise ValueError(f"{label} must be an IdentityReference")
    return value.validated()


def _identity_of_kind(value: Any, label: str, expected_kind: str) -> IdentityReference:
    identity = _identity(value, label)
    if identity.kind != expected_kind:
        raise ValueError(f"{label} has the wrong identity kind")
    return identity


def _run(value: Any, label: str = "run_identity") -> RunIdentity:
    if not isinstance(value, RunIdentity):
        raise ValueError(f"{label} must be a RunIdentity")
    return value.validated()


def _session(value: Any, label: str = "session_identity") -> SessionIdentity:
    if not isinstance(value, SessionIdentity):
        raise ValueError(f"{label} must be a SessionIdentity")
    return value.validated()


def _tuple_strings(value: Any, label: str, *, allowed: frozenset[str] | None = None) -> tuple[str, ...]:
    if not isinstance(value, tuple):
        raise ValueError(f"{label} must be an immutable tuple")
    result = tuple(_text(item, f"{label} item", max_bytes=256) for item in value)
    if tuple(sorted(result)) != result:
        raise ValueError(f"{label} must be in canonical sorted order")
    if len(set(result)) != len(result):
        raise ValueError(f"{label} must not contain duplicates")
    if allowed is not None and any(item not in allowed for item in result):
        raise ValueError(f"{label} contains an unknown value")
    return result


def _list_to_tuple_strings(value: Any, label: str, *, allowed: frozenset[str] | None = None) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be an array of strings")
    return _tuple_strings(tuple(value), label, allowed=allowed)


def _fp_from_dict(value: Any, label: str) -> Fingerprint:
    return Fingerprint.from_dict(value, label=label)


def _schema(data: Any, expected_id: str, label: str, fields: set[str]) -> None:
    require_exact_keys(data, fields, label=label)
    if data["schema_id"] != expected_id or data["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported {label} schema")


def _object_fp(body: dict[str, Any], schema_id: str) -> Fingerprint:
    return fingerprint(body, domain=f"{schema_id}.fingerprint")


def _canonical_body(obj: Any) -> bytes:
    return canonical_bytes(obj.to_dict())


@dataclass(frozen=True)
class ConditionConfiguration:
    schema_id: str
    schema_version: int
    condition_id: str
    admissible_decision_required: bool
    owner_delegation_required: bool
    governance_evidence: tuple[str, ...]
    condition_fingerprint: Fingerprint

    @classmethod
    def create(cls, condition_id: str) -> "ConditionConfiguration":
        if condition_id == DIRECT:
            values = (False, False, ("none",))
        elif condition_id == GOVERNED:
            values = (True, True, ("admissible_decision", "owner_delegation", "policy_decision"))
        else:
            raise ValueError("condition_id must be DIRECT or GOVERNED")
        body = {
            "schema_id": SCHEMA_CONDITION,
            "schema_version": SCHEMA_VERSION,
            "condition_id": condition_id,
            "admissible_decision_required": values[0],
            "owner_delegation_required": values[1],
            "governance_evidence": list(values[2]),
        }
        return cls(
            schema_id=body["schema_id"],
            schema_version=body["schema_version"],
            condition_id=body["condition_id"],
            admissible_decision_required=body["admissible_decision_required"],
            owner_delegation_required=body["owner_delegation_required"],
            governance_evidence=values[2],
            condition_fingerprint=_object_fp(body, SCHEMA_CONDITION),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "condition_id": self.condition_id,
            "admissible_decision_required": self.admissible_decision_required,
            "owner_delegation_required": self.owner_delegation_required,
            "governance_evidence": list(self.governance_evidence),
        }

    def validated(self) -> "ConditionConfiguration":
        if self.schema_id != SCHEMA_CONDITION or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported condition schema")
        if self.condition_id not in CONDITIONS:
            raise ValueError("unknown condition")
        _strict_bool(self.admissible_decision_required, "admissible_decision_required")
        _strict_bool(self.owner_delegation_required, "owner_delegation_required")
        evidence = _tuple_strings(self.governance_evidence, "governance_evidence")
        if self.condition_id == DIRECT:
            if self.admissible_decision_required or self.owner_delegation_required or evidence != ("none",):
                raise ValueError("DIRECT condition contains governance requirements")
        else:
            required = ("admissible_decision", "owner_delegation", "policy_decision")
            if not self.admissible_decision_required or not self.owner_delegation_required or evidence != required:
                raise ValueError("GOVERNED condition must explicitly require governance")
        _fp(self.condition_fingerprint, "condition_fingerprint")
        if self.condition_fingerprint.domain != f"{SCHEMA_CONDITION}.fingerprint":
            raise ValueError("condition fingerprint has the wrong domain")
        if _object_fp(self._body(), SCHEMA_CONDITION) != self.condition_fingerprint:
            raise ValueError("condition fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "condition_fingerprint": self.condition_fingerprint.to_dict()}

    def normative_dict(self) -> dict[str, Any]:
        return self._body()

    @classmethod
    def from_dict(cls, data: Any) -> "ConditionConfiguration":
        fields = {
            "schema_id", "schema_version", "condition_id", "admissible_decision_required",
            "owner_delegation_required", "governance_evidence", "condition_fingerprint",
        }
        _schema(data, SCHEMA_CONDITION, "condition", fields)
        evidence = _list_to_tuple_strings(data["governance_evidence"], "governance_evidence")
        return cls(
            schema_id=data["schema_id"],
            schema_version=data["schema_version"],
            condition_id=data["condition_id"],
            admissible_decision_required=data["admissible_decision_required"],
            owner_delegation_required=data["owner_delegation_required"],
            governance_evidence=evidence,
            condition_fingerprint=_fp_from_dict(data["condition_fingerprint"], "condition_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class AllowedConditionDifferences:
    schema_id: str
    schema_version: int
    allowed_condition_differences: tuple[str, ...]
    instance_binding_exceptions: tuple[str, ...]
    manifest_fingerprint: Fingerprint

    SEMANTIC_PATHS = (
        "condition.admissible_decision_required",
        "condition.condition_id",
        "condition.governance_evidence",
        "condition.owner_delegation_required",
    )
    INSTANCE_PATHS = (
        "run_identity.condition_id",
        "run_identity.run_id",
    )

    @classmethod
    def create(cls) -> "AllowedConditionDifferences":
        body = {
            "schema_id": SCHEMA_ALLOWED_DIFFERENCES,
            "schema_version": SCHEMA_VERSION,
            "allowed_condition_differences": list(cls.SEMANTIC_PATHS),
            "instance_binding_exceptions": list(cls.INSTANCE_PATHS),
        }
        return cls(
            schema_id=body["schema_id"],
            schema_version=body["schema_version"],
            allowed_condition_differences=cls.SEMANTIC_PATHS,
            instance_binding_exceptions=cls.INSTANCE_PATHS,
            manifest_fingerprint=_object_fp(body, SCHEMA_ALLOWED_DIFFERENCES),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "allowed_condition_differences": list(self.allowed_condition_differences),
            "instance_binding_exceptions": list(self.instance_binding_exceptions),
        }

    def validated(self) -> "AllowedConditionDifferences":
        if self.schema_id != SCHEMA_ALLOWED_DIFFERENCES or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported allowed-differences schema")
        if self.allowed_condition_differences != self.SEMANTIC_PATHS:
            raise ValueError("unknown or broadened semantic condition difference category")
        if self.instance_binding_exceptions != self.INSTANCE_PATHS:
            raise ValueError("unknown or incomplete instance binding exceptions")
        _fp(self.manifest_fingerprint, "manifest_fingerprint")
        if self.manifest_fingerprint.domain != f"{SCHEMA_ALLOWED_DIFFERENCES}.fingerprint":
            raise ValueError("allowed-differences fingerprint has the wrong domain")
        if _object_fp(self._body(), SCHEMA_ALLOWED_DIFFERENCES) != self.manifest_fingerprint:
            raise ValueError("allowed-differences fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "manifest_fingerprint": self.manifest_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "AllowedConditionDifferences":
        fields = {
            "schema_id", "schema_version", "allowed_condition_differences",
            "instance_binding_exceptions", "manifest_fingerprint",
        }
        _schema(data, SCHEMA_ALLOWED_DIFFERENCES, "allowed condition differences", fields)
        return cls(
            schema_id=data["schema_id"],
            schema_version=data["schema_version"],
            allowed_condition_differences=_list_to_tuple_strings(data["allowed_condition_differences"], "allowed_condition_differences"),
            instance_binding_exceptions=_list_to_tuple_strings(data["instance_binding_exceptions"], "instance_binding_exceptions"),
            manifest_fingerprint=_fp_from_dict(data["manifest_fingerprint"], "manifest_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class BudgetLimits:
    """Finite cumulative limits; ``None`` means explicitly unbounded."""

    sessions: int | None = None
    turns: int | None = None
    proposals: int | None = None
    effects: int | None = None
    commands: int | None = None
    wall_time_ms: int | None = None
    model_active_time_ms: int | None = None
    output_bytes: int | None = None
    retries: int | None = None
    continuations: int | None = None
    human_interventions: int | None = None

    def validated(self) -> "BudgetLimits":
        for name in BUDGET_FIELDS:
            _counter(getattr(self, name), f"budget limit {name}", allow_none=True)
        return self

    def to_dict(self) -> dict[str, int | None]:
        self.validated()
        return {name: getattr(self, name) for name in BUDGET_FIELDS}

    @classmethod
    def from_dict(cls, data: Any) -> "BudgetLimits":
        if not isinstance(data, dict) or set(data) != set(BUDGET_FIELDS):
            raise ValueError("budget limits fields are not exact")
        return cls(**{name: data[name] for name in BUDGET_FIELDS}).validated()


@dataclass(frozen=True)
class BudgetUsage:
    sessions: int = 0
    turns: int = 0
    proposals: int = 0
    effects: int = 0
    commands: int = 0
    wall_time_ms: int = 0
    model_active_time_ms: int = 0
    output_bytes: int = 0
    retries: int = 0
    continuations: int = 0
    human_interventions: int = 0

    def validated(self) -> "BudgetUsage":
        for name in BUDGET_FIELDS:
            _counter(getattr(self, name), f"budget usage {name}")
        return self

    def to_dict(self) -> dict[str, int]:
        self.validated()
        return {name: getattr(self, name) for name in BUDGET_FIELDS}

    @classmethod
    def from_dict(cls, data: Any) -> "BudgetUsage":
        if not isinstance(data, dict) or set(data) != set(BUDGET_FIELDS):
            raise ValueError("budget usage fields are not exact")
        return cls(**{name: data[name] for name in BUDGET_FIELDS}).validated()


@dataclass(frozen=True)
class BudgetState:
    schema_id: str
    schema_version: int
    limits: BudgetLimits
    used: BudgetUsage
    budget_fingerprint: Fingerprint

    @classmethod
    def create(cls, *, limits: BudgetLimits) -> "BudgetState":
        limits.validated()
        body = {
            "schema_id": SCHEMA_BUDGET_STATE,
            "schema_version": SCHEMA_VERSION,
            "limits": limits.to_dict(),
            "used": BudgetUsage().to_dict(),
        }
        return cls(
            schema_id=body["schema_id"],
            schema_version=body["schema_version"],
            limits=limits,
            used=BudgetUsage(),
            budget_fingerprint=_object_fp(body, SCHEMA_BUDGET_STATE),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "limits": self.limits.to_dict(),
            "used": self.used.to_dict(),
        }

    def validated(self) -> "BudgetState":
        if self.schema_id != SCHEMA_BUDGET_STATE or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported budget state schema")
        self.limits.validated()
        self.used.validated()
        for name in BUDGET_FIELDS:
            limit = getattr(self.limits, name)
            used = getattr(self.used, name)
            if limit is not None and used > limit:
                raise ValueError(f"budget usage exceeds {name} limit")
        _fp(self.budget_fingerprint, "budget_fingerprint")
        if self.budget_fingerprint.domain != f"{SCHEMA_BUDGET_STATE}.fingerprint":
            raise ValueError("budget fingerprint has the wrong domain")
        if _object_fp(self._body(), SCHEMA_BUDGET_STATE) != self.budget_fingerprint:
            raise ValueError("budget fingerprint mismatch")
        return self

    def advance(self, **increments: int) -> "BudgetState":
        unknown = set(increments) - set(BUDGET_FIELDS)
        if unknown:
            raise ValueError(f"unknown budget counters: {sorted(unknown)}")
        values = self.used.to_dict()
        for name, increment in increments.items():
            if isinstance(increment, bool) or not isinstance(increment, int) or increment < 0:
                raise ValueError(f"budget increment {name} must be a non-negative integer")
            old = values[name]
            if increment > MAX_COUNTER - old:
                raise OverflowError(f"budget counter {name} would overflow")
            new = old + increment
            limit = getattr(self.limits, name)
            if limit is not None and new > limit:
                raise ValueError(f"budget counter {name} exceeds its limit")
            values[name] = new
        return BudgetState.create_with_usage(limits=self.limits, used=BudgetUsage.from_dict(values))

    @classmethod
    def create_with_usage(cls, *, limits: BudgetLimits, used: BudgetUsage) -> "BudgetState":
        limits.validated()
        used.validated()
        body = {
            "schema_id": SCHEMA_BUDGET_STATE,
            "schema_version": SCHEMA_VERSION,
            "limits": limits.to_dict(),
            "used": used.to_dict(),
        }
        return cls(
            schema_id=body["schema_id"],
            schema_version=body["schema_version"],
            limits=limits,
            used=used,
            budget_fingerprint=_object_fp(body, SCHEMA_BUDGET_STATE),
        ).validated()

    def remaining(self, name: str) -> int | None:
        if name not in BUDGET_FIELDS:
            raise ValueError(f"unknown budget counter {name}")
        limit = getattr(self.limits, name)
        return None if limit is None else limit - getattr(self.used, name)

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "budget_fingerprint": self.budget_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "BudgetState":
        fields = {"schema_id", "schema_version", "limits", "used", "budget_fingerprint"}
        _schema(data, SCHEMA_BUDGET_STATE, "budget state", fields)
        return cls(
            schema_id=data["schema_id"],
            schema_version=data["schema_version"],
            limits=BudgetLimits.from_dict(data["limits"]),
            used=BudgetUsage.from_dict(data["used"]),
            budget_fingerprint=_fp_from_dict(data["budget_fingerprint"], "budget_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class ClockObservation:
    schema_id: str
    schema_version: int
    clock_kind: str
    value: int | None
    semantics: str
    observation_fingerprint: Fingerprint

    @classmethod
    def wall_clock(cls, unix_ms: int) -> "ClockObservation":
        return cls._create("WALL_CLOCK_UNIX_MS", unix_ms, "UTC Unix milliseconds; no datetime formatting is implied")

    @classmethod
    def monotonic_ns(cls, value: int) -> "ClockObservation":
        return cls._create("MONOTONIC_NS", value, "monotonic nanoseconds from one future runtime clock")

    @classmethod
    def future_runtime_placeholder(cls) -> "ClockObservation":
        return cls._create(
            "FUTURE_RUNTIME_MONOTONIC_NS",
            None,
            "value is intentionally absent until a later runtime records the monotonic clock; it is not zero",
        )

    @classmethod
    def _create(cls, clock_kind: str, value: int | None, semantics: str) -> "ClockObservation":
        body = {
            "schema_id": SCHEMA_CLOCK_OBSERVATION,
            "schema_version": SCHEMA_VERSION,
            "clock_kind": clock_kind,
            "value": value,
            "semantics": semantics,
        }
        return cls(
            **body,
            observation_fingerprint=_object_fp(body, SCHEMA_CLOCK_OBSERVATION),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "clock_kind": self.clock_kind,
            "value": self.value,
            "semantics": self.semantics,
        }

    def validated(self) -> "ClockObservation":
        if self.schema_id != SCHEMA_CLOCK_OBSERVATION or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported clock observation schema")
        if self.clock_kind not in {"WALL_CLOCK_UNIX_MS", "MONOTONIC_NS", "FUTURE_RUNTIME_MONOTONIC_NS"}:
            raise ValueError("unknown clock observation kind")
        _text(self.semantics, "clock semantics", max_bytes=512)
        if self.clock_kind == "FUTURE_RUNTIME_MONOTONIC_NS":
            if self.value is not None or "absent" not in self.semantics:
                raise ValueError("future monotonic placeholder semantics are not explicit")
        else:
            _counter(self.value, "clock value")
        _fp(self.observation_fingerprint, "observation_fingerprint")
        if _object_fp(self._body(), SCHEMA_CLOCK_OBSERVATION) != self.observation_fingerprint:
            raise ValueError("clock observation fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "observation_fingerprint": self.observation_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "ClockObservation":
        fields = {"schema_id", "schema_version", "clock_kind", "value", "semantics", "observation_fingerprint"}
        _schema(data, SCHEMA_CLOCK_OBSERVATION, "clock observation", fields)
        return cls(
            schema_id=data["schema_id"],
            schema_version=data["schema_version"],
            clock_kind=data["clock_kind"],
            value=data["value"],
            semantics=data["semantics"],
            observation_fingerprint=_fp_from_dict(data["observation_fingerprint"], "observation_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class CausalPredecessor:
    schema_id: str
    schema_version: int
    sequence: int
    predecessor_fingerprint: Fingerprint | None
    predecessor_kind: str
    causal_fingerprint: Fingerprint

    @classmethod
    def root(cls) -> "CausalPredecessor":
        return cls._create(0, None, "ROOT")

    @classmethod
    def after(cls, sequence: int, predecessor_fingerprint: Fingerprint) -> "CausalPredecessor":
        if sequence <= 0:
            raise ValueError("non-root causal sequence must be positive")
        _fp(predecessor_fingerprint, "predecessor_fingerprint")
        return cls._create(sequence, predecessor_fingerprint, "PREVIOUS_OBJECT")

    @classmethod
    def _create(cls, sequence: int, predecessor_fingerprint: Fingerprint | None, kind: str) -> "CausalPredecessor":
        body = {
            "schema_id": SCHEMA_CAUSAL_PREDECESSOR,
            "schema_version": SCHEMA_VERSION,
            "sequence": sequence,
            "predecessor_fingerprint": predecessor_fingerprint.to_dict() if predecessor_fingerprint else None,
            "predecessor_kind": kind,
        }
        return cls(
            schema_id=SCHEMA_CAUSAL_PREDECESSOR,
            schema_version=SCHEMA_VERSION,
            sequence=sequence,
            predecessor_fingerprint=predecessor_fingerprint,
            predecessor_kind=kind,
            causal_fingerprint=_object_fp(body, SCHEMA_CAUSAL_PREDECESSOR),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "predecessor_fingerprint": self.predecessor_fingerprint.to_dict() if self.predecessor_fingerprint else None,
            "predecessor_kind": self.predecessor_kind,
        }

    def validated(self) -> "CausalPredecessor":
        if self.schema_id != SCHEMA_CAUSAL_PREDECESSOR or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported causal predecessor schema")
        _counter(self.sequence, "causal sequence")
        if self.sequence == 0:
            if self.predecessor_fingerprint is not None or self.predecessor_kind != "ROOT":
                raise ValueError("root causal predecessor is malformed")
        else:
            _fp(self.predecessor_fingerprint, "predecessor_fingerprint")
            if self.predecessor_kind != "PREVIOUS_OBJECT":
                raise ValueError("non-root causal predecessor is malformed")
        _fp(self.causal_fingerprint, "causal_fingerprint")
        if _object_fp(self._body(), SCHEMA_CAUSAL_PREDECESSOR) != self.causal_fingerprint:
            raise ValueError("causal predecessor fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "causal_fingerprint": self.causal_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "CausalPredecessor":
        fields = {"schema_id", "schema_version", "sequence", "predecessor_fingerprint", "predecessor_kind", "causal_fingerprint"}
        _schema(data, SCHEMA_CAUSAL_PREDECESSOR, "causal predecessor", fields)
        return cls(
            schema_id=data["schema_id"],
            schema_version=data["schema_version"],
            sequence=data["sequence"],
            predecessor_fingerprint=(None if data["predecessor_fingerprint"] is None else _fp_from_dict(data["predecessor_fingerprint"], "predecessor_fingerprint")),
            predecessor_kind=data["predecessor_kind"],
            causal_fingerprint=_fp_from_dict(data["causal_fingerprint"], "causal_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class ExperimentSpecification:
    schema_id: str
    schema_version: int
    experiment_id: str
    task_prompt_fingerprint: Fingerprint
    initial_state_fingerprint: Fingerprint
    model_identity: IdentityReference
    executable_identity: IdentityReference
    executable_digest: Fingerprint
    transport_identity: IdentityReference
    tool_grammar_identity: IdentityReference
    environment_identity: IdentityReference
    dependency_toolchain_identity: IdentityReference
    common_filesystem_network_process_policy_identity: IdentityReference
    effect_executor_identity: IdentityReference
    evaluator_identity: IdentityReference
    common_budgets: BudgetState
    allowed_condition_differences: AllowedConditionDifferences
    condition: ConditionConfiguration
    run_identity: RunIdentity
    specification_fingerprint: Fingerprint

    @classmethod
    def create(
        cls,
        *,
        experiment_id: str,
        task_prompt_fingerprint: Fingerprint,
        initial_state_fingerprint: Fingerprint,
        model_identity: IdentityReference,
        executable_identity: IdentityReference,
        executable_digest: Fingerprint,
        transport_identity: IdentityReference,
        tool_grammar_identity: IdentityReference,
        environment_identity: IdentityReference,
        dependency_toolchain_identity: IdentityReference,
        common_filesystem_network_process_policy_identity: IdentityReference,
        effect_executor_identity: IdentityReference,
        evaluator_identity: IdentityReference,
        common_budgets: BudgetState,
        allowed_condition_differences: AllowedConditionDifferences,
        condition: ConditionConfiguration,
        run_identity: RunIdentity,
    ) -> "ExperimentSpecification":
        body = {
            "schema_id": SCHEMA_EXPERIMENT,
            "schema_version": SCHEMA_VERSION,
            "experiment_id": experiment_id,
            "task_prompt_fingerprint": task_prompt_fingerprint.to_dict(),
            "initial_state_fingerprint": initial_state_fingerprint.to_dict(),
            "model_identity": model_identity.to_dict(),
            "executable_identity": executable_identity.to_dict(),
            "executable_digest": executable_digest.to_dict(),
            "transport_identity": transport_identity.to_dict(),
            "tool_grammar_identity": tool_grammar_identity.to_dict(),
            "environment_identity": environment_identity.to_dict(),
            "dependency_toolchain_identity": dependency_toolchain_identity.to_dict(),
            "common_filesystem_network_process_policy_identity": common_filesystem_network_process_policy_identity.to_dict(),
            "effect_executor_identity": effect_executor_identity.to_dict(),
            "evaluator_identity": evaluator_identity.to_dict(),
            "common_budgets": common_budgets.to_dict(),
            "allowed_condition_differences": allowed_condition_differences.to_dict(),
            "condition": condition.to_dict(),
            "run_identity": run_identity.to_dict(),
        }
        return cls(
            schema_id=body["schema_id"],
            schema_version=body["schema_version"],
            experiment_id=experiment_id,
            task_prompt_fingerprint=task_prompt_fingerprint,
            initial_state_fingerprint=initial_state_fingerprint,
            model_identity=model_identity,
            executable_identity=executable_identity,
            executable_digest=executable_digest,
            transport_identity=transport_identity,
            tool_grammar_identity=tool_grammar_identity,
            environment_identity=environment_identity,
            dependency_toolchain_identity=dependency_toolchain_identity,
            common_filesystem_network_process_policy_identity=common_filesystem_network_process_policy_identity,
            effect_executor_identity=effect_executor_identity,
            evaluator_identity=evaluator_identity,
            common_budgets=common_budgets,
            allowed_condition_differences=allowed_condition_differences,
            condition=condition,
            run_identity=run_identity,
            specification_fingerprint=_object_fp(body, SCHEMA_EXPERIMENT),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "task_prompt_fingerprint": self.task_prompt_fingerprint.to_dict(),
            "initial_state_fingerprint": self.initial_state_fingerprint.to_dict(),
            "model_identity": self.model_identity.to_dict(),
            "executable_identity": self.executable_identity.to_dict(),
            "executable_digest": self.executable_digest.to_dict(),
            "transport_identity": self.transport_identity.to_dict(),
            "tool_grammar_identity": self.tool_grammar_identity.to_dict(),
            "environment_identity": self.environment_identity.to_dict(),
            "dependency_toolchain_identity": self.dependency_toolchain_identity.to_dict(),
            "common_filesystem_network_process_policy_identity": self.common_filesystem_network_process_policy_identity.to_dict(),
            "effect_executor_identity": self.effect_executor_identity.to_dict(),
            "evaluator_identity": self.evaluator_identity.to_dict(),
            "common_budgets": self.common_budgets.to_dict(),
            "allowed_condition_differences": self.allowed_condition_differences.to_dict(),
            "condition": self.condition.to_dict(),
            "run_identity": self.run_identity.to_dict(),
        }

    def normative_dict(self) -> dict[str, Any]:
        """Return all normative inputs, excluding derived object fingerprints.

        Run IDs and run-condition bindings remain visible; ``comparison.py``
        normalizes only their explicitly listed instance paths.  All content
        fingerprints (algorithm/domain/value) remain normative inputs.
        """

        identities = {
            "model_identity": self.model_identity.normative_dict(),
            "executable_identity": self.executable_identity.normative_dict(),
            "transport_identity": self.transport_identity.normative_dict(),
            "tool_grammar_identity": self.tool_grammar_identity.normative_dict(),
            "environment_identity": self.environment_identity.normative_dict(),
            "dependency_toolchain_identity": self.dependency_toolchain_identity.normative_dict(),
            "common_filesystem_network_process_policy_identity": self.common_filesystem_network_process_policy_identity.normative_dict(),
            "effect_executor_identity": self.effect_executor_identity.normative_dict(),
            "evaluator_identity": self.evaluator_identity.normative_dict(),
        }
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "experiment_id": self.experiment_id,
            "task_prompt_fingerprint": self.task_prompt_fingerprint.to_dict(),
            "initial_state_fingerprint": self.initial_state_fingerprint.to_dict(),
            "model_identity": identities["model_identity"],
            "executable_identity": identities["executable_identity"],
            "executable_digest": self.executable_digest.to_dict(),
            "transport_identity": identities["transport_identity"],
            "tool_grammar_identity": identities["tool_grammar_identity"],
            "environment_identity": identities["environment_identity"],
            "dependency_toolchain_identity": identities["dependency_toolchain_identity"],
            "common_filesystem_network_process_policy_identity": identities["common_filesystem_network_process_policy_identity"],
            "effect_executor_identity": identities["effect_executor_identity"],
            "evaluator_identity": identities["evaluator_identity"],
            "common_budgets": {
                "schema_id": self.common_budgets.schema_id,
                "schema_version": self.common_budgets.schema_version,
                "limits": self.common_budgets.limits.to_dict(),
                "used": self.common_budgets.used.to_dict(),
            },
            "allowed_condition_differences": {
                "schema_id": self.allowed_condition_differences.schema_id,
                "schema_version": self.allowed_condition_differences.schema_version,
                "allowed_condition_differences": list(self.allowed_condition_differences.allowed_condition_differences),
                "instance_binding_exceptions": list(self.allowed_condition_differences.instance_binding_exceptions),
            },
            "condition": self.condition.normative_dict(),
            "run_identity": self.run_identity.normative_dict(),
        }

    def common_normative_dict(self) -> dict[str, Any]:
        """Return the experiment inputs shared by both condition instances."""

        body = self.normative_dict()
        body.pop("condition")
        body.pop("run_identity")
        return body

    def validated(self) -> "ExperimentSpecification":
        if self.schema_id != SCHEMA_EXPERIMENT or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported experiment specification schema")
        _identifier(self.experiment_id, "experiment_id")
        _fp(self.task_prompt_fingerprint, "task_prompt_fingerprint")
        _fp(self.initial_state_fingerprint, "initial_state_fingerprint")
        for name, expected_kind in (
            ("model_identity", "model"),
            ("executable_identity", "executable"),
            ("transport_identity", "transport"),
            ("tool_grammar_identity", "tool_grammar"),
            ("environment_identity", "environment"),
            ("dependency_toolchain_identity", "dependency_toolchain"),
            ("common_filesystem_network_process_policy_identity", "filesystem_network_process_policy"),
            ("effect_executor_identity", "effect_executor"),
            ("evaluator_identity", "evaluator"),
        ):
            _identity_of_kind(getattr(self, name), name, expected_kind)
        _fp(self.executable_digest, "executable_digest")
        self.common_budgets.validated()
        if any(getattr(self.common_budgets.used, name) != 0 for name in BUDGET_FIELDS):
            raise ValueError("experiment common_budgets must start with zero usage")
        self.allowed_condition_differences.validated()
        self.condition.validated()
        self.run_identity.validated()
        if self.run_identity.experiment_id != self.experiment_id or self.run_identity.condition_id != self.condition.condition_id:
            raise ValueError("run identity is not bound to this experiment condition")
        _fp(self.specification_fingerprint, "specification_fingerprint")
        if self.specification_fingerprint.domain != f"{SCHEMA_EXPERIMENT}.fingerprint":
            raise ValueError("specification fingerprint has the wrong domain")
        if _object_fp(self._body(), SCHEMA_EXPERIMENT) != self.specification_fingerprint:
            raise ValueError("specification fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "specification_fingerprint": self.specification_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "ExperimentSpecification":
        fields = {
            "schema_id", "schema_version", "experiment_id", "task_prompt_fingerprint", "initial_state_fingerprint",
            "model_identity", "executable_identity", "executable_digest", "transport_identity", "tool_grammar_identity",
            "environment_identity", "dependency_toolchain_identity", "common_filesystem_network_process_policy_identity",
            "effect_executor_identity", "evaluator_identity", "common_budgets", "allowed_condition_differences", "condition", "run_identity",
            "specification_fingerprint",
        }
        _schema(data, SCHEMA_EXPERIMENT, "experiment specification", fields)
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"], experiment_id=data["experiment_id"],
            task_prompt_fingerprint=_fp_from_dict(data["task_prompt_fingerprint"], "task_prompt_fingerprint"),
            initial_state_fingerprint=_fp_from_dict(data["initial_state_fingerprint"], "initial_state_fingerprint"),
            model_identity=IdentityReference.from_dict(data["model_identity"]),
            executable_identity=IdentityReference.from_dict(data["executable_identity"]),
            executable_digest=_fp_from_dict(data["executable_digest"], "executable_digest"),
            transport_identity=IdentityReference.from_dict(data["transport_identity"]),
            tool_grammar_identity=IdentityReference.from_dict(data["tool_grammar_identity"]),
            environment_identity=IdentityReference.from_dict(data["environment_identity"]),
            dependency_toolchain_identity=IdentityReference.from_dict(data["dependency_toolchain_identity"]),
            common_filesystem_network_process_policy_identity=IdentityReference.from_dict(data["common_filesystem_network_process_policy_identity"]),
            effect_executor_identity=IdentityReference.from_dict(data["effect_executor_identity"]),
            evaluator_identity=IdentityReference.from_dict(data["evaluator_identity"]),
            common_budgets=BudgetState.from_dict(data["common_budgets"]),
            allowed_condition_differences=AllowedConditionDifferences.from_dict(data["allowed_condition_differences"]),
            condition=ConditionConfiguration.from_dict(data["condition"]),
            run_identity=RunIdentity.from_dict(data["run_identity"]),
            specification_fingerprint=_fp_from_dict(data["specification_fingerprint"], "specification_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class CanonicalProposal:
    schema_id: str
    schema_version: int
    run_identity: RunIdentity
    condition: ConditionConfiguration
    session_identity: SessionIdentity
    turn_id: str
    proposal_id: str
    tool_name: str
    canonical_arguments: dict[str, Any]
    working_root_identity: IdentityReference
    scope_identity: IdentityReference
    causal_predecessor: CausalPredecessor
    wall_clock_observation: ClockObservation
    monotonic_observation: ClockObservation
    model_identity: IdentityReference
    transport_identity: IdentityReference
    prompt_identity: IdentityReference
    tool_grammar_identity: IdentityReference
    effect_precondition: str
    proposal_fingerprint: Fingerprint

    @classmethod
    def create(
        cls,
        *,
        run_identity: RunIdentity,
        condition: ConditionConfiguration,
        session_identity: SessionIdentity,
        turn_id: str,
        proposal_id: str,
        tool_name: str,
        canonical_arguments: dict[str, Any],
        working_root_identity: IdentityReference,
        scope_identity: IdentityReference,
        causal_predecessor: CausalPredecessor,
        wall_clock_observation: ClockObservation,
        monotonic_observation: ClockObservation,
        model_identity: IdentityReference,
        transport_identity: IdentityReference,
        prompt_identity: IdentityReference,
        tool_grammar_identity: IdentityReference,
    ) -> "CanonicalProposal":
        body = {
            "schema_id": SCHEMA_PROPOSAL,
            "schema_version": SCHEMA_VERSION,
            "run_identity": run_identity.to_dict(),
            "condition": condition.to_dict(),
            "session_identity": session_identity.to_dict(),
            "turn_id": turn_id,
            "proposal_id": proposal_id,
            "tool_name": tool_name,
            "canonical_arguments": canonical_arguments,
            "working_root_identity": working_root_identity.to_dict(),
            "scope_identity": scope_identity.to_dict(),
            "causal_predecessor": causal_predecessor.to_dict(),
            "wall_clock_observation": wall_clock_observation.to_dict(),
            "monotonic_observation": monotonic_observation.to_dict(),
            "model_identity": model_identity.to_dict(),
            "transport_identity": transport_identity.to_dict(),
            "prompt_identity": prompt_identity.to_dict(),
            "tool_grammar_identity": tool_grammar_identity.to_dict(),
            "effect_precondition": "PROPOSAL_BEFORE_EFFECT",
        }
        return cls(
            schema_id=SCHEMA_PROPOSAL,
            schema_version=SCHEMA_VERSION,
            run_identity=run_identity,
            condition=condition,
            session_identity=session_identity,
            turn_id=turn_id,
            proposal_id=proposal_id,
            tool_name=tool_name,
            canonical_arguments=canonical_arguments,
            working_root_identity=working_root_identity,
            scope_identity=scope_identity,
            causal_predecessor=causal_predecessor,
            wall_clock_observation=wall_clock_observation,
            monotonic_observation=monotonic_observation,
            model_identity=model_identity,
            transport_identity=transport_identity,
            prompt_identity=prompt_identity,
            tool_grammar_identity=tool_grammar_identity,
            effect_precondition="PROPOSAL_BEFORE_EFFECT",
            proposal_fingerprint=_object_fp(body, SCHEMA_PROPOSAL),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "run_identity": self.run_identity.to_dict(),
            "condition": self.condition.to_dict(),
            "session_identity": self.session_identity.to_dict(),
            "turn_id": self.turn_id,
            "proposal_id": self.proposal_id,
            "tool_name": self.tool_name,
            "canonical_arguments": self.canonical_arguments,
            "working_root_identity": self.working_root_identity.to_dict(),
            "scope_identity": self.scope_identity.to_dict(),
            "causal_predecessor": self.causal_predecessor.to_dict(),
            "wall_clock_observation": self.wall_clock_observation.to_dict(),
            "monotonic_observation": self.monotonic_observation.to_dict(),
            "model_identity": self.model_identity.to_dict(),
            "transport_identity": self.transport_identity.to_dict(),
            "prompt_identity": self.prompt_identity.to_dict(),
            "tool_grammar_identity": self.tool_grammar_identity.to_dict(),
            "effect_precondition": self.effect_precondition,
        }

    def validated(self) -> "CanonicalProposal":
        if self.schema_id != SCHEMA_PROPOSAL or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported canonical proposal schema")
        self.run_identity.validated()
        self.condition.validated()
        self.session_identity.validate_for_run(self.run_identity)
        if self.condition.condition_id != self.run_identity.condition_id:
            raise ValueError("proposal condition and run identity differ")
        _identifier(self.turn_id, "turn_id")
        _identifier(self.proposal_id, "proposal_id")
        if self.tool_name not in TOOL_NAMES:
            raise ValueError("unknown tool name")
        if not isinstance(self.canonical_arguments, dict):
            raise ValueError("canonical_arguments must be an object")
        # canonical_bytes rejects floats, non-string keys, and unsupported values.
        canonical_bytes(self.canonical_arguments)
        for name, expected_kind in (
            ("working_root_identity", "working_root"),
            ("scope_identity", "scope"),
            ("model_identity", "model"),
            ("transport_identity", "transport"),
            ("prompt_identity", "prompt"),
            ("tool_grammar_identity", "tool_grammar"),
        ):
            _identity_of_kind(getattr(self, name), name, expected_kind)
        self.causal_predecessor.validated()
        self.wall_clock_observation.validated()
        self.monotonic_observation.validated()
        if self.wall_clock_observation.clock_kind != "WALL_CLOCK_UNIX_MS":
            raise ValueError("proposal wall clock must be an explicit Unix millisecond observation")
        if self.monotonic_observation.clock_kind not in {"MONOTONIC_NS", "FUTURE_RUNTIME_MONOTONIC_NS"}:
            raise ValueError("proposal monotonic observation is not monotonic or explicit placeholder")
        if self.effect_precondition != "PROPOSAL_BEFORE_EFFECT":
            raise ValueError("a canonical proposal must be recorded before any effect")
        _fp(self.proposal_fingerprint, "proposal_fingerprint")
        if self.proposal_fingerprint.domain != f"{SCHEMA_PROPOSAL}.fingerprint":
            raise ValueError("proposal fingerprint has the wrong domain")
        if _object_fp(self._body(), SCHEMA_PROPOSAL) != self.proposal_fingerprint:
            raise ValueError("proposal fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "proposal_fingerprint": self.proposal_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "CanonicalProposal":
        fields = {
            "schema_id", "schema_version", "run_identity", "condition", "session_identity", "turn_id", "proposal_id",
            "tool_name", "canonical_arguments", "working_root_identity", "scope_identity", "causal_predecessor",
            "wall_clock_observation", "monotonic_observation", "model_identity", "transport_identity", "prompt_identity",
            "tool_grammar_identity", "effect_precondition", "proposal_fingerprint",
        }
        _schema(data, SCHEMA_PROPOSAL, "canonical proposal", fields)
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"],
            run_identity=RunIdentity.from_dict(data["run_identity"]),
            condition=ConditionConfiguration.from_dict(data["condition"]),
            session_identity=SessionIdentity.from_dict(data["session_identity"]),
            turn_id=data["turn_id"], proposal_id=data["proposal_id"], tool_name=data["tool_name"],
            canonical_arguments=data["canonical_arguments"],
            working_root_identity=IdentityReference.from_dict(data["working_root_identity"]),
            scope_identity=IdentityReference.from_dict(data["scope_identity"]),
            causal_predecessor=CausalPredecessor.from_dict(data["causal_predecessor"]),
            wall_clock_observation=ClockObservation.from_dict(data["wall_clock_observation"]),
            monotonic_observation=ClockObservation.from_dict(data["monotonic_observation"]),
            model_identity=IdentityReference.from_dict(data["model_identity"]),
            transport_identity=IdentityReference.from_dict(data["transport_identity"]),
            prompt_identity=IdentityReference.from_dict(data["prompt_identity"]),
            tool_grammar_identity=IdentityReference.from_dict(data["tool_grammar_identity"]),
            effect_precondition=data["effect_precondition"],
            proposal_fingerprint=_fp_from_dict(data["proposal_fingerprint"], "proposal_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class ModeDecision:
    schema_id: str
    schema_version: int
    proposal_id: str
    proposal_fingerprint: Fingerprint
    condition_id: str
    decision: str
    execution_prerequisite: str
    governance_decision_reference: str | None
    decision_fingerprint: Fingerprint

    @classmethod
    def direct(cls, proposal: CanonicalProposal) -> "ModeDecision":
        proposal.validated()
        if proposal.condition.condition_id != DIRECT:
            raise ValueError("DIRECT_EXECUTION is valid only for DIRECT")
        return cls._create(proposal, "DIRECT_EXECUTION", None)

    @classmethod
    def governed(
        cls,
        proposal: CanonicalProposal,
        decision: str,
        *,
        governance_decision_reference: str,
    ) -> "ModeDecision":
        proposal.validated()
        if proposal.condition.condition_id != GOVERNED:
            raise ValueError("governed decisions require GOVERNED condition")
        if decision not in {"ALLOW", "REFUSE", "TERMINATE_RUN", "REQUIRE_CONTINUATION"}:
            raise ValueError("invalid governed decision")
        return cls._create(proposal, decision, governance_decision_reference)

    @classmethod
    def _create(cls, proposal: CanonicalProposal, decision: str, reference: str | None) -> "ModeDecision":
        condition_id = proposal.condition.condition_id
        body = {
            "schema_id": SCHEMA_MODE_DECISION,
            "schema_version": SCHEMA_VERSION,
            "proposal_id": proposal.proposal_id,
            "proposal_fingerprint": proposal.proposal_fingerprint.to_dict(),
            "condition_id": condition_id,
            "decision": decision,
            "execution_prerequisite": "NONE" if condition_id == DIRECT else "ADMISSIBLE_DECISION",
            "governance_decision_reference": reference,
        }
        return cls(
            schema_id=SCHEMA_MODE_DECISION,
            schema_version=SCHEMA_VERSION,
            proposal_id=proposal.proposal_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            condition_id=condition_id,
            decision=decision,
            execution_prerequisite=body["execution_prerequisite"],
            governance_decision_reference=reference,
            decision_fingerprint=_object_fp(body, SCHEMA_MODE_DECISION),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "proposal_id": self.proposal_id,
            "proposal_fingerprint": self.proposal_fingerprint.to_dict(),
            "condition_id": self.condition_id,
            "decision": self.decision,
            "execution_prerequisite": self.execution_prerequisite,
            "governance_decision_reference": self.governance_decision_reference,
        }

    def validated(self) -> "ModeDecision":
        if self.schema_id != SCHEMA_MODE_DECISION or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported mode decision schema")
        _identifier(self.proposal_id, "proposal_id")
        _fp(self.proposal_fingerprint, "proposal_fingerprint")
        if self.condition_id not in CONDITIONS or self.decision not in DECISIONS:
            raise ValueError("unknown condition or decision")
        if self.condition_id == DIRECT:
            if self.decision != "DIRECT_EXECUTION" or self.execution_prerequisite != "NONE" or self.governance_decision_reference is not None:
                raise ValueError("DIRECT mode cannot contain an Admissible decision prerequisite")
        else:
            if self.decision == "DIRECT_EXECUTION" or self.execution_prerequisite != "ADMISSIBLE_DECISION":
                raise ValueError("GOVERNED mode cannot execute without a governance decision")
            _identifier(self.governance_decision_reference, "governance_decision_reference")
        _fp(self.decision_fingerprint, "decision_fingerprint")
        if _object_fp(self._body(), SCHEMA_MODE_DECISION) != self.decision_fingerprint:
            raise ValueError("mode decision fingerprint mismatch")
        return self

    @property
    def permits_effect(self) -> bool:
        return self.decision in {"DIRECT_EXECUTION", "ALLOW"}

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "decision_fingerprint": self.decision_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "ModeDecision":
        fields = {
            "schema_id", "schema_version", "proposal_id", "proposal_fingerprint", "condition_id", "decision",
            "execution_prerequisite", "governance_decision_reference", "decision_fingerprint",
        }
        _schema(data, SCHEMA_MODE_DECISION, "mode decision", fields)
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"], proposal_id=data["proposal_id"],
            proposal_fingerprint=_fp_from_dict(data["proposal_fingerprint"], "proposal_fingerprint"),
            condition_id=data["condition_id"], decision=data["decision"],
            execution_prerequisite=data["execution_prerequisite"],
            governance_decision_reference=data["governance_decision_reference"],
            decision_fingerprint=_fp_from_dict(data["decision_fingerprint"], "decision_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class EffectReservation:
    schema_id: str
    schema_version: int
    reservation_id: str
    proposal_id: str
    proposal_fingerprint: Fingerprint
    mode_decision_fingerprint: Fingerprint
    effect_executor_identity: IdentityReference
    reservation_state: str
    reservation_fingerprint: Fingerprint

    @classmethod
    def for_decision(
        cls,
        *,
        reservation_id: str,
        proposal: CanonicalProposal,
        decision: ModeDecision,
        effect_executor_identity: IdentityReference,
    ) -> "EffectReservation":
        proposal.validated()
        decision.validated()
        if proposal.proposal_id != decision.proposal_id or proposal.proposal_fingerprint != decision.proposal_fingerprint:
            raise ValueError("reservation proposal and mode decision are not causally bound")
        if not decision.permits_effect:
            raise ValueError("a refused, terminated, or continuation decision cannot reserve an effect")
        _identifier(reservation_id, "reservation_id")
        _identity_of_kind(effect_executor_identity, "effect_executor_identity", "effect_executor")
        body = {
            "schema_id": SCHEMA_RESERVATION,
            "schema_version": SCHEMA_VERSION,
            "reservation_id": reservation_id,
            "proposal_id": proposal.proposal_id,
            "proposal_fingerprint": proposal.proposal_fingerprint.to_dict(),
            "mode_decision_fingerprint": decision.decision_fingerprint.to_dict(),
            "effect_executor_identity": effect_executor_identity.to_dict(),
            "reservation_state": "RESERVED_NOT_STARTED",
        }
        return cls(
            schema_id=SCHEMA_RESERVATION,
            schema_version=SCHEMA_VERSION,
            reservation_id=reservation_id,
            proposal_id=proposal.proposal_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            mode_decision_fingerprint=decision.decision_fingerprint,
            effect_executor_identity=effect_executor_identity,
            reservation_state="RESERVED_NOT_STARTED",
            reservation_fingerprint=_object_fp(body, SCHEMA_RESERVATION),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "reservation_id": self.reservation_id,
            "proposal_id": self.proposal_id,
            "proposal_fingerprint": self.proposal_fingerprint.to_dict(),
            "mode_decision_fingerprint": self.mode_decision_fingerprint.to_dict(),
            "effect_executor_identity": self.effect_executor_identity.to_dict(),
            "reservation_state": self.reservation_state,
        }

    def validated(self) -> "EffectReservation":
        if self.schema_id != SCHEMA_RESERVATION or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported effect reservation schema")
        _identifier(self.reservation_id, "reservation_id")
        _identifier(self.proposal_id, "proposal_id")
        _fp(self.proposal_fingerprint, "proposal_fingerprint")
        _fp(self.mode_decision_fingerprint, "mode_decision_fingerprint")
        _identity_of_kind(self.effect_executor_identity, "effect_executor_identity", "effect_executor")
        if self.reservation_state != "RESERVED_NOT_STARTED":
            raise ValueError("M1 reservations cannot claim that an effect started")
        _fp(self.reservation_fingerprint, "reservation_fingerprint")
        if _object_fp(self._body(), SCHEMA_RESERVATION) != self.reservation_fingerprint:
            raise ValueError("effect reservation fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "reservation_fingerprint": self.reservation_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "EffectReservation":
        fields = {
            "schema_id", "schema_version", "reservation_id", "proposal_id", "proposal_fingerprint",
            "mode_decision_fingerprint", "effect_executor_identity", "reservation_state", "reservation_fingerprint",
        }
        _schema(data, SCHEMA_RESERVATION, "effect reservation", fields)
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"], reservation_id=data["reservation_id"],
            proposal_id=data["proposal_id"], proposal_fingerprint=_fp_from_dict(data["proposal_fingerprint"], "proposal_fingerprint"),
            mode_decision_fingerprint=_fp_from_dict(data["mode_decision_fingerprint"], "mode_decision_fingerprint"),
            effect_executor_identity=IdentityReference.from_dict(data["effect_executor_identity"]),
            reservation_state=data["reservation_state"],
            reservation_fingerprint=_fp_from_dict(data["reservation_fingerprint"], "reservation_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class EffectReceipt:
    schema_id: str
    schema_version: int
    receipt_id: str
    proposal_fingerprint: Fingerprint
    reservation_fingerprint: Fingerprint | None
    status: str
    effect_started: bool
    effect_completed: bool
    executed_effect: bool
    process_exit_code: int | None
    task_acceptance: None
    outcome_reason: str
    receipt_fingerprint: Fingerprint

    @classmethod
    def create(
        cls,
        *,
        receipt_id: str,
        proposal_fingerprint: Fingerprint,
        status: str,
        reservation_fingerprint: Fingerprint | None = None,
        effect_started: bool = False,
        effect_completed: bool = False,
        executed_effect: bool = False,
        process_exit_code: int | None = None,
        outcome_reason: str,
    ) -> "EffectReceipt":
        body = {
            "schema_id": SCHEMA_RECEIPT,
            "schema_version": SCHEMA_VERSION,
            "receipt_id": receipt_id,
            "proposal_fingerprint": proposal_fingerprint.to_dict(),
            "reservation_fingerprint": reservation_fingerprint.to_dict() if reservation_fingerprint else None,
            "status": status,
            "effect_started": effect_started,
            "effect_completed": effect_completed,
            "executed_effect": executed_effect,
            "process_exit_code": process_exit_code,
            "task_acceptance": None,
            "outcome_reason": outcome_reason,
        }
        return cls(
            schema_id=SCHEMA_RECEIPT,
            schema_version=SCHEMA_VERSION,
            receipt_id=receipt_id,
            proposal_fingerprint=proposal_fingerprint,
            reservation_fingerprint=reservation_fingerprint,
            status=status,
            effect_started=effect_started,
            effect_completed=effect_completed,
            executed_effect=executed_effect,
            process_exit_code=process_exit_code,
            task_acceptance=None,
            outcome_reason=outcome_reason,
            receipt_fingerprint=_object_fp(body, SCHEMA_RECEIPT),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id,
            "schema_version": self.schema_version,
            "receipt_id": self.receipt_id,
            "proposal_fingerprint": self.proposal_fingerprint.to_dict(),
            "reservation_fingerprint": self.reservation_fingerprint.to_dict() if self.reservation_fingerprint else None,
            "status": self.status,
            "effect_started": self.effect_started,
            "effect_completed": self.effect_completed,
            "executed_effect": self.executed_effect,
            "process_exit_code": self.process_exit_code,
            "task_acceptance": self.task_acceptance,
            "outcome_reason": self.outcome_reason,
        }

    def validated(self) -> "EffectReceipt":
        if self.schema_id != SCHEMA_RECEIPT or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported effect receipt schema")
        _identifier(self.receipt_id, "receipt_id")
        _fp(self.proposal_fingerprint, "proposal_fingerprint")
        if self.reservation_fingerprint is not None:
            _fp(self.reservation_fingerprint, "reservation_fingerprint")
        if self.status not in RECEIPT_STATUSES:
            raise ValueError("unknown effect receipt status")
        for name in ("effect_started", "effect_completed", "executed_effect"):
            _strict_bool(getattr(self, name), name)
        if self.effect_completed and not self.effect_started:
            raise ValueError("an effect cannot complete before it starts")
        if self.process_exit_code is not None and (
            isinstance(self.process_exit_code, bool)
            or not isinstance(self.process_exit_code, int)
            or not -128 <= self.process_exit_code <= 255
        ):
            raise ValueError("process_exit_code is outside the explicit signed byte range")
        if self.task_acceptance is not None:
            raise ValueError("effect receipts never carry task acceptance")
        _text(self.outcome_reason, "outcome_reason", max_bytes=4096)
        if self.status in {"PROPOSED", "REFUSED"}:
            if self.effect_started or self.effect_completed or self.executed_effect or self.reservation_fingerprint is not None:
                raise ValueError("proposed/refused receipt cannot represent an executed effect")
        if self.status == "RESERVED" and (self.reservation_fingerprint is None or self.effect_started or self.executed_effect):
            raise ValueError("reserved receipt must be pre-start and reservation-bound")
        if self.status in {"STARTED", "FAILED", "COMPLETED", "AMBIGUOUS", "TIMED_OUT", "CANCELLED"} and self.reservation_fingerprint is None:
            raise ValueError("post-reservation receipt must bind an effect reservation")
        if self.status == "COMPLETED" and not (self.effect_started and self.effect_completed and self.executed_effect):
            raise ValueError("completed receipt flags are inconsistent")
        if self.status == "AMBIGUOUS" and not self.effect_started:
            raise ValueError("ambiguous outcome requires an attempted start")
        if self.status == "REFUSED" and self.executed_effect:
            raise ValueError("refusal cannot simultaneously represent an executed effect")
        _fp(self.receipt_fingerprint, "receipt_fingerprint")
        if _object_fp(self._body(), SCHEMA_RECEIPT) != self.receipt_fingerprint:
            raise ValueError("effect receipt fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "receipt_fingerprint": self.receipt_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "EffectReceipt":
        fields = {
            "schema_id", "schema_version", "receipt_id", "proposal_fingerprint", "reservation_fingerprint", "status",
            "effect_started", "effect_completed", "executed_effect", "process_exit_code", "task_acceptance",
            "outcome_reason", "receipt_fingerprint",
        }
        _schema(data, SCHEMA_RECEIPT, "effect receipt", fields)
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"], receipt_id=data["receipt_id"],
            proposal_fingerprint=_fp_from_dict(data["proposal_fingerprint"], "proposal_fingerprint"),
            reservation_fingerprint=(None if data["reservation_fingerprint"] is None else _fp_from_dict(data["reservation_fingerprint"], "reservation_fingerprint")),
            status=data["status"], effect_started=data["effect_started"], effect_completed=data["effect_completed"],
            executed_effect=data["executed_effect"], process_exit_code=data["process_exit_code"],
            task_acceptance=data["task_acceptance"], outcome_reason=data["outcome_reason"],
            receipt_fingerprint=_fp_from_dict(data["receipt_fingerprint"], "receipt_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class HumanInterventionRecord:
    schema_id: str
    schema_version: int
    intervention_id: str
    actor_class: str
    reason: str
    wall_clock_observation: ClockObservation
    monotonic_observation: ClockObservation
    run_identity: RunIdentity
    session_id: str | None
    proposal_id: str | None
    allowed_policy_category: str
    comparability_disposition: str
    intervention_fingerprint: Fingerprint

    @classmethod
    def create(
        cls,
        *,
        intervention_id: str,
        actor_class: str,
        reason: str,
        wall_clock_observation: ClockObservation,
        monotonic_observation: ClockObservation,
        run_identity: RunIdentity,
        session_id: str | None,
        proposal_id: str | None,
        allowed_policy_category: str,
        comparability_disposition: str,
    ) -> "HumanInterventionRecord":
        body = {
            "schema_id": SCHEMA_INTERVENTION,
            "schema_version": SCHEMA_VERSION,
            "intervention_id": intervention_id,
            "actor_class": actor_class,
            "reason": reason,
            "wall_clock_observation": wall_clock_observation.to_dict(),
            "monotonic_observation": monotonic_observation.to_dict(),
            "run_identity": run_identity.to_dict(),
            "session_id": session_id,
            "proposal_id": proposal_id,
            "allowed_policy_category": allowed_policy_category,
            "comparability_disposition": comparability_disposition,
        }
        return cls(
            schema_id=SCHEMA_INTERVENTION,
            schema_version=SCHEMA_VERSION,
            intervention_id=intervention_id,
            actor_class=actor_class,
            reason=reason,
            wall_clock_observation=wall_clock_observation,
            monotonic_observation=monotonic_observation,
            run_identity=run_identity,
            session_id=session_id,
            proposal_id=proposal_id,
            allowed_policy_category=allowed_policy_category,
            comparability_disposition=comparability_disposition,
            intervention_fingerprint=_object_fp(body, SCHEMA_INTERVENTION),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version, "intervention_id": self.intervention_id,
            "actor_class": self.actor_class, "reason": self.reason,
            "wall_clock_observation": self.wall_clock_observation.to_dict(),
            "monotonic_observation": self.monotonic_observation.to_dict(),
            "run_identity": self.run_identity.to_dict(), "session_id": self.session_id, "proposal_id": self.proposal_id,
            "allowed_policy_category": self.allowed_policy_category,
            "comparability_disposition": self.comparability_disposition,
        }

    def validated(self) -> "HumanInterventionRecord":
        if self.schema_id != SCHEMA_INTERVENTION or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported human intervention schema")
        _identifier(self.intervention_id, "intervention_id")
        if self.actor_class not in {"OPERATOR", "OWNER", "EVALUATOR", "SYSTEM"}:
            raise ValueError("unknown actor class")
        _text(self.reason, "intervention reason", max_bytes=4096)
        self.wall_clock_observation.validated()
        self.monotonic_observation.validated()
        self.run_identity.validated()
        if self.session_id is not None:
            _identifier(self.session_id, "session_id")
        if self.proposal_id is not None:
            _identifier(self.proposal_id, "proposal_id")
        if self.allowed_policy_category not in {"NONE", "PREDECLARED_ASSISTANCE", "RECOVERY", "OWNER_CEREMONY"}:
            raise ValueError("unknown human intervention policy category")
        if self.comparability_disposition not in {"NONE", "QUALIFY", "INVALIDATE"}:
            raise ValueError("unknown comparability disposition")
        if self.allowed_policy_category == "NONE" and self.comparability_disposition != "INVALIDATE":
            raise ValueError("unallowed intervention must invalidate comparability")
        _fp(self.intervention_fingerprint, "intervention_fingerprint")
        if _object_fp(self._body(), SCHEMA_INTERVENTION) != self.intervention_fingerprint:
            raise ValueError("human intervention fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "intervention_fingerprint": self.intervention_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "HumanInterventionRecord":
        fields = {
            "schema_id", "schema_version", "intervention_id", "actor_class", "reason", "wall_clock_observation",
            "monotonic_observation", "run_identity", "session_id", "proposal_id", "allowed_policy_category",
            "comparability_disposition", "intervention_fingerprint",
        }
        _schema(data, SCHEMA_INTERVENTION, "human intervention", fields)
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"], intervention_id=data["intervention_id"],
            actor_class=data["actor_class"], reason=data["reason"],
            wall_clock_observation=ClockObservation.from_dict(data["wall_clock_observation"]),
            monotonic_observation=ClockObservation.from_dict(data["monotonic_observation"]),
            run_identity=RunIdentity.from_dict(data["run_identity"]), session_id=data["session_id"], proposal_id=data["proposal_id"],
            allowed_policy_category=data["allowed_policy_category"], comparability_disposition=data["comparability_disposition"],
            intervention_fingerprint=_fp_from_dict(data["intervention_fingerprint"], "intervention_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class EvaluatorSpecification:
    schema_id: str
    schema_version: int
    evaluator_id: str
    evaluator_version: str
    requirements_fingerprint: Fingerprint
    scope_fingerprint: Fingerprint
    test_plan_fingerprint: Fingerprint
    environment_identity: IdentityReference
    independent_of_model_claim: bool
    process_success_is_not_acceptance: bool
    evaluator_fingerprint: Fingerprint

    @classmethod
    def create(
        cls,
        *,
        evaluator_id: str,
        evaluator_version: str,
        requirements_fingerprint: Fingerprint,
        scope_fingerprint: Fingerprint,
        test_plan_fingerprint: Fingerprint,
        environment_identity: IdentityReference,
    ) -> "EvaluatorSpecification":
        body = {
            "schema_id": SCHEMA_EVALUATOR, "schema_version": SCHEMA_VERSION,
            "evaluator_id": evaluator_id, "evaluator_version": evaluator_version,
            "requirements_fingerprint": requirements_fingerprint.to_dict(), "scope_fingerprint": scope_fingerprint.to_dict(),
            "test_plan_fingerprint": test_plan_fingerprint.to_dict(), "environment_identity": environment_identity.to_dict(),
            "independent_of_model_claim": True, "process_success_is_not_acceptance": True,
        }
        return cls(
            schema_id=SCHEMA_EVALUATOR,
            schema_version=SCHEMA_VERSION,
            evaluator_id=evaluator_id,
            evaluator_version=evaluator_version,
            requirements_fingerprint=requirements_fingerprint,
            scope_fingerprint=scope_fingerprint,
            test_plan_fingerprint=test_plan_fingerprint,
            environment_identity=environment_identity,
            independent_of_model_claim=True,
            process_success_is_not_acceptance=True,
            evaluator_fingerprint=_object_fp(body, SCHEMA_EVALUATOR),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version,
            "evaluator_id": self.evaluator_id, "evaluator_version": self.evaluator_version,
            "requirements_fingerprint": self.requirements_fingerprint.to_dict(), "scope_fingerprint": self.scope_fingerprint.to_dict(),
            "test_plan_fingerprint": self.test_plan_fingerprint.to_dict(), "environment_identity": self.environment_identity.to_dict(),
            "independent_of_model_claim": self.independent_of_model_claim,
            "process_success_is_not_acceptance": self.process_success_is_not_acceptance,
        }

    def validated(self) -> "EvaluatorSpecification":
        if self.schema_id != SCHEMA_EVALUATOR or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported evaluator specification schema")
        _identifier(self.evaluator_id, "evaluator_id")
        _text(self.evaluator_version, "evaluator_version", max_bytes=128)
        for name in ("requirements_fingerprint", "scope_fingerprint", "test_plan_fingerprint"):
            _fp(getattr(self, name), name)
        _identity_of_kind(self.environment_identity, "environment_identity", "environment")
        if self.independent_of_model_claim is not True or self.process_success_is_not_acceptance is not True:
            raise ValueError("evaluator independence and acceptance separation are mandatory")
        _fp(self.evaluator_fingerprint, "evaluator_fingerprint")
        if _object_fp(self._body(), SCHEMA_EVALUATOR) != self.evaluator_fingerprint:
            raise ValueError("evaluator fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "evaluator_fingerprint": self.evaluator_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "EvaluatorSpecification":
        fields = {
            "schema_id", "schema_version", "evaluator_id", "evaluator_version", "requirements_fingerprint", "scope_fingerprint",
            "test_plan_fingerprint", "environment_identity", "independent_of_model_claim", "process_success_is_not_acceptance", "evaluator_fingerprint",
        }
        _schema(data, SCHEMA_EVALUATOR, "evaluator specification", fields)
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"], evaluator_id=data["evaluator_id"], evaluator_version=data["evaluator_version"],
            requirements_fingerprint=_fp_from_dict(data["requirements_fingerprint"], "requirements_fingerprint"),
            scope_fingerprint=_fp_from_dict(data["scope_fingerprint"], "scope_fingerprint"),
            test_plan_fingerprint=_fp_from_dict(data["test_plan_fingerprint"], "test_plan_fingerprint"),
            environment_identity=IdentityReference.from_dict(data["environment_identity"]),
            independent_of_model_claim=data["independent_of_model_claim"], process_success_is_not_acceptance=data["process_success_is_not_acceptance"],
            evaluator_fingerprint=_fp_from_dict(data["evaluator_fingerprint"], "evaluator_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class TerminalManifest:
    schema_id: str
    schema_version: int
    run_identity: RunIdentity
    experiment_specification_fingerprint: Fingerprint
    repository_state_fingerprint: Fingerprint
    proposal_ledger_fingerprint: Fingerprint
    effect_receipt_ledger_fingerprint: Fingerprint
    budget_state_fingerprint: Fingerprint
    evaluator_specification_fingerprint: Fingerprint
    model_completion_claim: str
    process_result: str
    task_acceptance: str
    acceptance_basis: str
    reconciliation_complete: bool
    terminal_manifest_fingerprint: Fingerprint

    @classmethod
    def create(
        cls,
        *,
        run_identity: RunIdentity,
        experiment_specification_fingerprint: Fingerprint,
        repository_state_fingerprint: Fingerprint,
        proposal_ledger_fingerprint: Fingerprint,
        effect_receipt_ledger_fingerprint: Fingerprint,
        budget_state_fingerprint: Fingerprint,
        evaluator_specification_fingerprint: Fingerprint,
        model_completion_claim: str,
        process_result: str,
        task_acceptance: str,
        reconciliation_complete: bool,
    ) -> "TerminalManifest":
        acceptance_basis = "INDEPENDENT_EVALUATOR" if task_acceptance != "NOT_EVALUATED" else "NONE"
        body = {
            "schema_id": SCHEMA_TERMINAL, "schema_version": SCHEMA_VERSION, "run_identity": run_identity.to_dict(),
            "experiment_specification_fingerprint": experiment_specification_fingerprint.to_dict(), "repository_state_fingerprint": repository_state_fingerprint.to_dict(),
            "proposal_ledger_fingerprint": proposal_ledger_fingerprint.to_dict(), "effect_receipt_ledger_fingerprint": effect_receipt_ledger_fingerprint.to_dict(),
            "budget_state_fingerprint": budget_state_fingerprint.to_dict(), "evaluator_specification_fingerprint": evaluator_specification_fingerprint.to_dict(),
            "model_completion_claim": model_completion_claim, "process_result": process_result, "task_acceptance": task_acceptance,
            "acceptance_basis": acceptance_basis, "reconciliation_complete": reconciliation_complete,
        }
        return cls(
            schema_id=SCHEMA_TERMINAL,
            schema_version=SCHEMA_VERSION,
            run_identity=run_identity,
            experiment_specification_fingerprint=experiment_specification_fingerprint,
            repository_state_fingerprint=repository_state_fingerprint,
            proposal_ledger_fingerprint=proposal_ledger_fingerprint,
            effect_receipt_ledger_fingerprint=effect_receipt_ledger_fingerprint,
            budget_state_fingerprint=budget_state_fingerprint,
            evaluator_specification_fingerprint=evaluator_specification_fingerprint,
            model_completion_claim=model_completion_claim,
            process_result=process_result,
            task_acceptance=task_acceptance,
            acceptance_basis=acceptance_basis,
            reconciliation_complete=reconciliation_complete,
            terminal_manifest_fingerprint=_object_fp(body, SCHEMA_TERMINAL),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version, "run_identity": self.run_identity.to_dict(),
            "experiment_specification_fingerprint": self.experiment_specification_fingerprint.to_dict(), "repository_state_fingerprint": self.repository_state_fingerprint.to_dict(),
            "proposal_ledger_fingerprint": self.proposal_ledger_fingerprint.to_dict(), "effect_receipt_ledger_fingerprint": self.effect_receipt_ledger_fingerprint.to_dict(),
            "budget_state_fingerprint": self.budget_state_fingerprint.to_dict(), "evaluator_specification_fingerprint": self.evaluator_specification_fingerprint.to_dict(),
            "model_completion_claim": self.model_completion_claim, "process_result": self.process_result, "task_acceptance": self.task_acceptance,
            "acceptance_basis": self.acceptance_basis, "reconciliation_complete": self.reconciliation_complete,
        }

    def validated(self) -> "TerminalManifest":
        if self.schema_id != SCHEMA_TERMINAL or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported terminal manifest schema")
        self.run_identity.validated()
        for name in (
            "experiment_specification_fingerprint", "repository_state_fingerprint", "proposal_ledger_fingerprint",
            "effect_receipt_ledger_fingerprint", "budget_state_fingerprint", "evaluator_specification_fingerprint",
        ):
            _fp(getattr(self, name), name)
        if self.model_completion_claim not in {"CLAIMED_COMPLETE", "CLAIMED_INCOMPLETE", "NOT_CLAIMED"}:
            raise ValueError("unknown model completion claim")
        if self.process_result not in {"SUCCESS", "FAILURE", "TIMEOUT", "CANCELLED", "UNKNOWN"}:
            raise ValueError("unknown process result")
        if self.task_acceptance not in {"ACCEPTED", "REJECTED", "INCONCLUSIVE", "NOT_EVALUATED"}:
            raise ValueError("unknown task acceptance")
        expected_basis = "INDEPENDENT_EVALUATOR" if self.task_acceptance != "NOT_EVALUATED" else "NONE"
        if self.acceptance_basis != expected_basis:
            raise ValueError("task acceptance must be separately attributed to the evaluator")
        _strict_bool(self.reconciliation_complete, "reconciliation_complete")
        if self.reconciliation_complete and self.task_acceptance == "NOT_EVALUATED":
            raise ValueError("a reconciled terminal manifest requires an evaluator disposition")
        _fp(self.terminal_manifest_fingerprint, "terminal_manifest_fingerprint")
        if _object_fp(self._body(), SCHEMA_TERMINAL) != self.terminal_manifest_fingerprint:
            raise ValueError("terminal manifest fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "terminal_manifest_fingerprint": self.terminal_manifest_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "TerminalManifest":
        fields = {
            "schema_id", "schema_version", "run_identity", "experiment_specification_fingerprint", "repository_state_fingerprint",
            "proposal_ledger_fingerprint", "effect_receipt_ledger_fingerprint", "budget_state_fingerprint", "evaluator_specification_fingerprint",
            "model_completion_claim", "process_result", "task_acceptance", "acceptance_basis", "reconciliation_complete", "terminal_manifest_fingerprint",
        }
        _schema(data, SCHEMA_TERMINAL, "terminal manifest", fields)
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"], run_identity=RunIdentity.from_dict(data["run_identity"]),
            experiment_specification_fingerprint=_fp_from_dict(data["experiment_specification_fingerprint"], "experiment_specification_fingerprint"),
            repository_state_fingerprint=_fp_from_dict(data["repository_state_fingerprint"], "repository_state_fingerprint"),
            proposal_ledger_fingerprint=_fp_from_dict(data["proposal_ledger_fingerprint"], "proposal_ledger_fingerprint"),
            effect_receipt_ledger_fingerprint=_fp_from_dict(data["effect_receipt_ledger_fingerprint"], "effect_receipt_ledger_fingerprint"),
            budget_state_fingerprint=_fp_from_dict(data["budget_state_fingerprint"], "budget_state_fingerprint"),
            evaluator_specification_fingerprint=_fp_from_dict(data["evaluator_specification_fingerprint"], "evaluator_specification_fingerprint"),
            model_completion_claim=data["model_completion_claim"], process_result=data["process_result"], task_acceptance=data["task_acceptance"],
            acceptance_basis=data["acceptance_basis"], reconciliation_complete=data["reconciliation_complete"],
            terminal_manifest_fingerprint=_fp_from_dict(data["terminal_manifest_fingerprint"], "terminal_manifest_fingerprint"),
        ).validated()


@dataclass(frozen=True)
class ComparativeManifest:
    schema_id: str
    schema_version: int
    experiment_id: str
    experiment_specification_fingerprint: Fingerprint
    direct_run_identity: RunIdentity
    governed_run_identity: RunIdentity
    parity_report_fingerprint: Fingerprint
    direct_terminal_manifest_fingerprint: Fingerprint
    governed_terminal_manifest_fingerprint: Fingerprint
    comparative_manifest_fingerprint: Fingerprint

    @classmethod
    def create(
        cls,
        *,
        direct_specification: ExperimentSpecification,
        governed_specification: ExperimentSpecification,
        parity_report: Any,
        direct_terminal_manifest_fingerprint: Fingerprint,
        governed_terminal_manifest_fingerprint: Fingerprint,
    ) -> "ComparativeManifest":
        """Create only from two validated specs and a passing parity report."""

        direct_specification.validated()
        governed_specification.validated()
        from .comparison import ParityReport, check_parity

        if not isinstance(parity_report, ParityReport):
            raise ValueError("comparative manifest requires a typed parity report")
        computed_report = check_parity(direct_specification, governed_specification)
        if not computed_report.passed:
            raise ValueError(
                f"comparative manifest requires parity-compatible specs: {computed_report.refusal_code}"
            )
        if parity_report.report_fingerprint != computed_report.report_fingerprint:
            raise ValueError("comparative manifest parity report does not match its specifications")
        experiment_specification_fingerprint = fingerprint(
            direct_specification.common_normative_dict(),
            domain=COMMON_EXPERIMENT_FINGERPRINT_DOMAIN,
        )
        body = {
            "schema_id": SCHEMA_COMPARATIVE, "schema_version": SCHEMA_VERSION,
            "experiment_id": direct_specification.experiment_id,
            "experiment_specification_fingerprint": experiment_specification_fingerprint.to_dict(),
            "direct_run_identity": direct_specification.run_identity.to_dict(),
            "governed_run_identity": governed_specification.run_identity.to_dict(),
            "parity_report_fingerprint": parity_report.report_fingerprint.to_dict(),
            "direct_terminal_manifest_fingerprint": direct_terminal_manifest_fingerprint.to_dict(),
            "governed_terminal_manifest_fingerprint": governed_terminal_manifest_fingerprint.to_dict(),
        }
        return cls(
            schema_id=SCHEMA_COMPARATIVE,
            schema_version=SCHEMA_VERSION,
            experiment_id=direct_specification.experiment_id,
            experiment_specification_fingerprint=experiment_specification_fingerprint,
            direct_run_identity=direct_specification.run_identity,
            governed_run_identity=governed_specification.run_identity,
            parity_report_fingerprint=parity_report.report_fingerprint,
            direct_terminal_manifest_fingerprint=direct_terminal_manifest_fingerprint,
            governed_terminal_manifest_fingerprint=governed_terminal_manifest_fingerprint,
            comparative_manifest_fingerprint=_object_fp(body, SCHEMA_COMPARATIVE),
        ).validated()

    def _body(self) -> dict[str, Any]:
        return {
            "schema_id": self.schema_id, "schema_version": self.schema_version, "experiment_id": self.experiment_id,
            "experiment_specification_fingerprint": self.experiment_specification_fingerprint.to_dict(),
            "direct_run_identity": self.direct_run_identity.to_dict(), "governed_run_identity": self.governed_run_identity.to_dict(),
            "parity_report_fingerprint": self.parity_report_fingerprint.to_dict(),
            "direct_terminal_manifest_fingerprint": self.direct_terminal_manifest_fingerprint.to_dict(),
            "governed_terminal_manifest_fingerprint": self.governed_terminal_manifest_fingerprint.to_dict(),
        }

    def validated(self) -> "ComparativeManifest":
        if self.schema_id != SCHEMA_COMPARATIVE or self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported comparative manifest schema")
        _identifier(self.experiment_id, "experiment_id")
        self.direct_run_identity.validated()
        self.governed_run_identity.validated()
        if self.direct_run_identity.condition_id != DIRECT or self.governed_run_identity.condition_id != GOVERNED:
            raise ValueError("comparative manifest must contain exactly one DIRECT and one GOVERNED run")
        if self.direct_run_identity.experiment_id != self.experiment_id or self.governed_run_identity.experiment_id != self.experiment_id:
            raise ValueError("comparative manifest contains an unrelated experiment")
        if self.direct_run_identity.run_id == self.governed_run_identity.run_id:
            raise ValueError("comparative manifest requires two distinct run identities")
        for name in (
            "experiment_specification_fingerprint", "parity_report_fingerprint", "direct_terminal_manifest_fingerprint", "governed_terminal_manifest_fingerprint",
        ):
            _fp(getattr(self, name), name)
        if self.experiment_specification_fingerprint.domain != COMMON_EXPERIMENT_FINGERPRINT_DOMAIN:
            raise ValueError("comparative manifest must bind the common experiment specification")
        _fp(self.comparative_manifest_fingerprint, "comparative_manifest_fingerprint")
        if _object_fp(self._body(), SCHEMA_COMPARATIVE) != self.comparative_manifest_fingerprint:
            raise ValueError("comparative manifest fingerprint mismatch")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validated()
        return {**self._body(), "comparative_manifest_fingerprint": self.comparative_manifest_fingerprint.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> "ComparativeManifest":
        fields = {
            "schema_id", "schema_version", "experiment_id", "experiment_specification_fingerprint", "direct_run_identity", "governed_run_identity",
            "parity_report_fingerprint", "direct_terminal_manifest_fingerprint", "governed_terminal_manifest_fingerprint", "comparative_manifest_fingerprint",
        }
        _schema(data, SCHEMA_COMPARATIVE, "comparative manifest", fields)
        return cls(
            schema_id=data["schema_id"], schema_version=data["schema_version"], experiment_id=data["experiment_id"],
            experiment_specification_fingerprint=_fp_from_dict(data["experiment_specification_fingerprint"], "experiment_specification_fingerprint"),
            direct_run_identity=RunIdentity.from_dict(data["direct_run_identity"]), governed_run_identity=RunIdentity.from_dict(data["governed_run_identity"]),
            parity_report_fingerprint=_fp_from_dict(data["parity_report_fingerprint"], "parity_report_fingerprint"),
            direct_terminal_manifest_fingerprint=_fp_from_dict(data["direct_terminal_manifest_fingerprint"], "direct_terminal_manifest_fingerprint"),
            governed_terminal_manifest_fingerprint=_fp_from_dict(data["governed_terminal_manifest_fingerprint"], "governed_terminal_manifest_fingerprint"),
            comparative_manifest_fingerprint=_fp_from_dict(data["comparative_manifest_fingerprint"], "comparative_manifest_fingerprint"),
        ).validated()


def validate_unique_proposal_ids(proposals: tuple[CanonicalProposal, ...]) -> tuple[CanonicalProposal, ...]:
    """Pure duplicate proposal check for a future proposal ledger."""

    seen: set[tuple[str, str]] = set()
    for proposal in proposals:
        proposal.validated()
        key = (proposal.run_identity.run_id, proposal.proposal_id)
        if key in seen:
            raise ValueError("duplicate proposal identity in one run")
        seen.add(key)
    return proposals


def canonical_object_bytes(obj: Any) -> bytes:
    """Canonical bytes for any M1 persisted object."""

    if not hasattr(obj, "to_dict"):
        raise TypeError("object does not implement the persisted-object contract")
    return _canonical_body(obj)
