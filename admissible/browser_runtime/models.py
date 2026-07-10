"""Durable schemas for bounded browser-runtime verification (PART A).

Runtime evidence is intentionally its own family of schemas, kept separate
from proposal evidence, admission decisions, write evidence, static
verification evidence, and human observation evidence (PART A.2).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def bounded_collect(items: list[Any], max_len: int) -> tuple[list[Any], dict[str, Any]]:
    """Deterministically truncate a diagnostic collection and record the cut.

    Always keeps the first ``max_len`` items (deterministic: arrival order),
    and records original/retained counts so a truncation is never silent
    (PART A.3).
    """

    original = len(items)
    retained = items[:max_len] if max_len >= 0 else list(items)
    meta = {
        "original_count": original,
        "retained_count": len(retained),
        "truncated": len(retained) < original,
    }
    return retained, meta


@dataclass
class BrowserRuntimeCapabilityReport:
    """Whether a real, allowlisted local browser runtime is available."""

    provider_id: str
    provider_version: str
    available: bool
    executable_path: str | None
    executable_basename: str | None
    browser_version: str | None
    supported_features: list[str] = field(default_factory=list)
    unsupported_features: list[str] = field(default_factory=list)
    discovery_source: str | None = None
    safety_policy_version: str = ""
    unavailable_reason: str | None = None
    detected_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id,
            "provider_version": self.provider_version,
            "available": self.available,
            "executable_path": self.executable_path,
            "executable_basename": self.executable_basename,
            "browser_version": self.browser_version,
            "supported_features": list(self.supported_features),
            "unsupported_features": list(self.unsupported_features),
            "discovery_source": self.discovery_source,
            "safety_policy_version": self.safety_policy_version,
            "unavailable_reason": self.unavailable_reason,
            "detected_at": self.detected_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BrowserRuntimeCapabilityReport":
        return cls(
            provider_id=str(data.get("provider_id") or ""),
            provider_version=str(data.get("provider_version") or ""),
            available=bool(data.get("available")),
            executable_path=data.get("executable_path"),
            executable_basename=data.get("executable_basename"),
            browser_version=data.get("browser_version"),
            supported_features=list(data.get("supported_features") or []),
            unsupported_features=list(data.get("unsupported_features") or []),
            discovery_source=data.get("discovery_source"),
            safety_policy_version=str(data.get("safety_policy_version") or ""),
            unavailable_reason=data.get("unavailable_reason"),
            detected_at=str(data.get("detected_at") or now_iso()),
        )


@dataclass
class BrowserRuntimeCriterionPlan:
    """One Mission Contract criterion projected onto the runtime plan."""

    criterion_id: str
    disposition: str
    assertion_ids: list[str] = field(default_factory=list)
    required_observables: list[str] = field(default_factory=list)
    supported: bool = True
    unsupported_reason: str | None = None
    human_observation_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "criterion_id": self.criterion_id,
            "disposition": self.disposition,
            "assertion_ids": list(self.assertion_ids),
            "required_observables": list(self.required_observables),
            "supported": self.supported,
            "unsupported_reason": self.unsupported_reason,
            "human_observation_required": self.human_observation_required,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BrowserRuntimeCriterionPlan":
        return cls(
            criterion_id=str(data.get("criterion_id") or ""),
            disposition=str(data.get("disposition") or ""),
            assertion_ids=list(data.get("assertion_ids") or []),
            required_observables=list(data.get("required_observables") or []),
            supported=bool(data.get("supported", True)),
            unsupported_reason=data.get("unsupported_reason"),
            human_observation_required=bool(data.get("human_observation_required")),
        )


@dataclass
class BrowserRuntimeVerificationPlan:
    """A strict, allowlisted, bounded browser-runtime verification plan."""

    plan_version: str
    mission_contract_sha256: str
    workspace_root: str
    entrypoint_path: str
    entrypoint_query: str
    target_origin_policy: str
    debug_interface: str | None
    max_duration_ms: int
    max_steps: int
    max_input_events: int
    max_snapshots: int
    max_screenshots: int
    max_console_entries: int
    max_network_events: int
    criteria: list[BrowserRuntimeCriterionPlan] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    generated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_version": self.plan_version,
            "mission_contract_sha256": self.mission_contract_sha256,
            "workspace_root": self.workspace_root,
            "entrypoint_path": self.entrypoint_path,
            "entrypoint_query": self.entrypoint_query,
            "target_origin_policy": self.target_origin_policy,
            "debug_interface": self.debug_interface,
            "max_duration_ms": self.max_duration_ms,
            "max_steps": self.max_steps,
            "max_input_events": self.max_input_events,
            "max_snapshots": self.max_snapshots,
            "max_screenshots": self.max_screenshots,
            "max_console_entries": self.max_console_entries,
            "max_network_events": self.max_network_events,
            "criteria": [c.to_dict() for c in self.criteria],
            "steps": [dict(step) for step in self.steps],
            "generated_at": self.generated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BrowserRuntimeVerificationPlan":
        return cls(
            plan_version=str(data.get("plan_version") or ""),
            mission_contract_sha256=str(data.get("mission_contract_sha256") or ""),
            workspace_root=str(data.get("workspace_root") or ""),
            entrypoint_path=str(data.get("entrypoint_path") or ""),
            entrypoint_query=str(data.get("entrypoint_query") or ""),
            target_origin_policy=str(data.get("target_origin_policy") or ""),
            debug_interface=data.get("debug_interface"),
            max_duration_ms=int(data.get("max_duration_ms") or 0),
            max_steps=int(data.get("max_steps") or 0),
            max_input_events=int(data.get("max_input_events") or 0),
            max_snapshots=int(data.get("max_snapshots") or 0),
            max_screenshots=int(data.get("max_screenshots") or 0),
            max_console_entries=int(data.get("max_console_entries") or 0),
            max_network_events=int(data.get("max_network_events") or 0),
            criteria=[
                BrowserRuntimeCriterionPlan.from_dict(c) for c in data.get("criteria") or []
            ],
            steps=[dict(step) for step in data.get("steps") or []],
            generated_at=str(data.get("generated_at") or now_iso()),
        )


_BOUNDED_FIELDS = (
    "console_entries",
    "page_exceptions",
    "network_events",
    "external_request_attempts",
    "dialogs",
    "popups",
    "downloads",
    "dom_observations",
    "debug_snapshots",
    "input_events",
    "screenshots",
)


@dataclass
class BrowserRuntimeEvidence:
    """One bounded browser-runtime verification run and its collected evidence.

    Kept separate from proposal/admission/write/static/human evidence
    families (PART A.2). Every diagnostic collection is bounded and its
    truncation, if any, is recorded deterministically (PART A.3).
    """

    evidence_id: str
    plan_sha256: str
    mission_contract_sha256: str
    workspace_root: str
    entrypoint_path: str
    provider: dict[str, Any]
    started_at: str
    completed_at: str | None
    duration_ms: int
    termination_reason: str
    page_load: dict[str, Any] = field(default_factory=dict)
    console_entries: list[dict[str, Any]] = field(default_factory=list)
    page_exceptions: list[dict[str, Any]] = field(default_factory=list)
    network_events: list[dict[str, Any]] = field(default_factory=list)
    external_request_attempts: list[dict[str, Any]] = field(default_factory=list)
    dialogs: list[dict[str, Any]] = field(default_factory=list)
    popups: list[dict[str, Any]] = field(default_factory=list)
    downloads: list[dict[str, Any]] = field(default_factory=list)
    dom_observations: list[dict[str, Any]] = field(default_factory=list)
    debug_snapshots: list[dict[str, Any]] = field(default_factory=list)
    input_events: list[dict[str, Any]] = field(default_factory=list)
    screenshots: list[dict[str, Any]] = field(default_factory=list)
    assertions: list[dict[str, Any]] = field(default_factory=list)
    criterion_results: list[dict[str, Any]] = field(default_factory=list)
    resource_cleanup: dict[str, Any] = field(default_factory=dict)
    policy_violations: list[dict[str, Any]] = field(default_factory=list)
    status: str = "unknown"
    truncation: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "admissible_browser_runtime_evidence_v1",
            "evidence_id": self.evidence_id,
            "plan_sha256": self.plan_sha256,
            "mission_contract_sha256": self.mission_contract_sha256,
            "workspace_root": self.workspace_root,
            "entrypoint_path": self.entrypoint_path,
            "provider": dict(self.provider),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "termination_reason": self.termination_reason,
            "page_load": dict(self.page_load),
            "console_entries": list(self.console_entries),
            "page_exceptions": list(self.page_exceptions),
            "network_events": list(self.network_events),
            "external_request_attempts": list(self.external_request_attempts),
            "dialogs": list(self.dialogs),
            "popups": list(self.popups),
            "downloads": list(self.downloads),
            "dom_observations": list(self.dom_observations),
            "debug_snapshots": list(self.debug_snapshots),
            "input_events": list(self.input_events),
            "screenshots": list(self.screenshots),
            "assertions": list(self.assertions),
            "criterion_results": list(self.criterion_results),
            "resource_cleanup": dict(self.resource_cleanup),
            "policy_violations": list(self.policy_violations),
            "status": self.status,
            "truncation": dict(self.truncation),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BrowserRuntimeEvidence":
        kwargs = {name: list(data.get(name) or []) for name in _BOUNDED_FIELDS}
        return cls(
            evidence_id=str(data.get("evidence_id") or ""),
            plan_sha256=str(data.get("plan_sha256") or ""),
            mission_contract_sha256=str(data.get("mission_contract_sha256") or ""),
            workspace_root=str(data.get("workspace_root") or ""),
            entrypoint_path=str(data.get("entrypoint_path") or ""),
            provider=dict(data.get("provider") or {}),
            started_at=str(data.get("started_at") or ""),
            completed_at=data.get("completed_at"),
            duration_ms=int(data.get("duration_ms") or 0),
            termination_reason=str(data.get("termination_reason") or ""),
            page_load=dict(data.get("page_load") or {}),
            assertions=list(data.get("assertions") or []),
            criterion_results=list(data.get("criterion_results") or []),
            resource_cleanup=dict(data.get("resource_cleanup") or {}),
            status=str(data.get("status") or "unknown"),
            truncation=dict(data.get("truncation") or {}),
            **kwargs,
        )

    def new_evidence_id_if_missing(self) -> None:
        if not self.evidence_id:
            self.evidence_id = new_id("runtime_evidence")
