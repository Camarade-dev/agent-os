"""Deterministic, loss-aware mission contract extraction and completion safety."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

MISSION_CONTRACT_VERSION = "admissible_mission_contract_v1"

_HEADINGS = {
    "deliverables": ("mandatory deliverables", "required files", "deliverables", "livrables obligatoires"),
    "acceptance": ("acceptance criteria", "completion criteria", "critères d'acceptation"),
    "requirements": ("requirements", "mandatory behavior", "robustness", "observability", "documentation"),
    "architecture": ("architecture", "scope and architecture are already authorized", "technical choices"),
    "boundaries": ("constraints", "authorized scope", "execution boundaries", "working method"),
    "non_goals": ("non-goals", "non goals", "out of scope"),
    "completion": ("completion",),
}
_PATH_RE = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:html?|css|js|mjs|cjs|ts|tsx|py|json|ya?ml|md|txt|csv|sql)(?![\w.-])", re.I)
_BULLET_RE = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)(.+?)\s*$")
_NUMBERED_RE = re.compile(r"^\s*(\d+)[.)]\s+(.+?)\s*$")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalize_goal(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").strip().split("\n"))


def _heading(line: str) -> str | None:
    value = re.sub(r"^[#\s]+|[:\s]+$", "", line).strip().lower()
    for role, names in _HEADINGS.items():
        if value in names:
            return role
    return None


def _entry(identifier: str, text: str, *, source: str, order: int, **extra: Any) -> dict[str, Any]:
    return {"id": identifier, "source_text": text.strip(), "source": source, "order": order, **extra}


@dataclass(frozen=True)
class MissionContract:
    contract_version: str
    raw_goal: str
    raw_goal_sha256: str
    normalized_goal_sha256: str
    task_intent: str
    deliverables: list[dict[str, Any]]
    mandatory_paths: list[str]
    optional_paths: list[str]
    explicit_architecture_decisions: list[dict[str, Any]]
    explicit_dependency_policy: dict[str, Any] | None
    explicit_execution_boundaries: list[dict[str, Any]]
    explicit_non_goals: list[dict[str, Any]]
    mandatory_requirements: list[dict[str, Any]]
    explicit_acceptance_criteria: list[dict[str, Any]]
    inferred_acceptance_criteria: list[dict[str, Any]]
    ambiguities: list[dict[str, Any]]
    unsupported_or_unparsed_fragments: list[dict[str, Any]]
    extraction_diagnostics: dict[str, Any]
    contract_completeness: bool
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_mission_contract(raw_goal: str, *, created_at: str | None = None) -> MissionContract:
    if not isinstance(raw_goal, str) or not raw_goal.strip():
        raise ValueError("raw_goal must be a non-empty string")
    sections: list[tuple[str | None, str]] = []
    role: str | None = None
    for line in raw_goal.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        detected = _heading(line)
        if detected:
            role = detected
            continue
        if line.strip():
            sections.append((role, line))

    paths: list[str] = []
    deliverables: list[dict[str, Any]] = []
    requirements: list[dict[str, Any]] = []
    criteria: list[dict[str, Any]] = []
    architecture: list[dict[str, Any]] = []
    boundaries: list[dict[str, Any]] = []
    non_goals: list[dict[str, Any]] = []
    ambiguities: list[dict[str, Any]] = []
    dep_policy: dict[str, Any] | None = None
    counters = {k: 0 for k in ("deliverable", "requirement", "criterion", "architecture", "boundary", "non_goal", "ambiguity")}

    for section, line in sections:
        bullet = _BULLET_RE.match(line)
        text = bullet.group(1).strip() if bullet else line.strip()
        found_paths = [p.replace("\\", "/") for p in _PATH_RE.findall(text)]
        if section == "deliverables":
            for path in found_paths:
                if path not in paths:
                    paths.append(path)
                    counters["deliverable"] += 1
                    deliverables.append(_entry(f"deliverable_{counters['deliverable']:03d}", path, source="explicit", order=counters["deliverable"], exact_path=path))
        numbered = _NUMBERED_RE.match(line)
        if section == "acceptance" and numbered:
            counters["criterion"] += 1
            criteria.append(_entry(f"explicit_ac_{counters['criterion']:03d}", numbered.group(2), source="explicit", order=counters["criterion"], source_number=int(numbered.group(1)), mandatory=True))
        elif section == "acceptance" and bullet:
            counters["criterion"] += 1
            criteria.append(_entry(f"explicit_ac_{counters['criterion']:03d}", text, source="explicit", order=counters["criterion"], mandatory=True))
        elif section in ("requirements", "completion") and bullet:
            counters["requirement"] += 1
            requirements.append(_entry(f"requirement_{counters['requirement']:03d}", text, source="explicit", order=counters["requirement"], mandatory=True))
        elif section == "architecture" and bullet:
            counters["architecture"] += 1
            architecture.append(_entry(f"architecture_{counters['architecture']:03d}", text, source="explicit", order=counters["architecture"]))
        elif section == "boundaries" and bullet:
            counters["boundary"] += 1
            boundaries.append(_entry(f"boundary_{counters['boundary']:03d}", text, source="explicit", order=counters["boundary"]))
        elif section == "non_goals" and bullet:
            counters["non_goal"] += 1
            non_goals.append(_entry(f"non_goal_{counters['non_goal']:03d}", text, source="explicit", order=counters["non_goal"]))
        if re.search(r"\b(?:zero|no) dependencies\b|\bno framework\b|\bno (?:npm|package manager|install)\b", text, re.I):
            dep_policy = {"value": "zero_dependencies", "source_text": text, "source": "explicit"}
        if re.search(r"\bplain\s+html(?:/|,\s*)css(?:/|,?\s*(?:and\s+)?)javascript\b|\bcanvas\s*2d\b|\bno framework\b", text, re.I) and not any(a["source_text"] == text for a in architecture):
            counters["architecture"] += 1
            architecture.append(_entry(f"architecture_{counters['architecture']:03d}", text, source="explicit", order=counters["architecture"]))
        if re.search(r"\b(?:do not|no|never|local-only|local only|only write)\b", text, re.I) and section != "non_goals" and not any(b["source_text"] == text for b in boundaries):
            counters["boundary"] += 1
            boundaries.append(_entry(f"boundary_{counters['boundary']:03d}", text, source="explicit", order=counters["boundary"]))
        if re.search(r"\b(?:ambiguous|to be decided|tbd|unspecified)\b", text, re.I):
            counters["ambiguity"] += 1
            ambiguities.append(_entry(f"ambiguity_{counters['ambiguity']:03d}", text, source="explicit", order=counters["ambiguity"]))

    # Paths named inside explicit criteria/requirements are also exact contract paths.
    for item in criteria + requirements:
        for path in _PATH_RE.findall(item["source_text"]):
            path = path.replace("\\", "/")
            if path not in paths:
                paths.append(path)
    first = next((line.strip() for line in raw_goal.splitlines() if line.strip()), "")
    intent = "software_build" if re.search(r"\b(build|create|implement|develop)\b", first, re.I) else "general_task"
    inferred: list[dict[str, Any]] = []
    if not criteria:
        # Backward-compatible generic templates remain deterministic inference,
        # never substitutes for explicit criteria. This preserves the proven
        # Pixel Wanderer eight-check contract without shaping richer missions.
        from admissible.governed_run import derive_acceptance_criteria_from_goal
        for index, item in enumerate(derive_acceptance_criteria_from_goal(raw_goal), start=1):
            inferred.append(_entry(str(item["criterion_id"]), str(item["source_text"]), source="deterministic_inference", order=index, mandatory=True, verification=list(item.get("verification") or [])))
    if not criteria and not requirements and not inferred and first:
        inferred.append(_entry("inferred_ac_001", first, source="deterministic_inference", order=1, mandatory=True))
    # Retain exact paths even when they occur in compact prose rather than a
    # dedicated deliverables section.
    for path in _PATH_RE.findall(raw_goal):
        path = path.replace("\\", "/")
        if path not in paths:
            paths.append(path)
    completeness = not ambiguities and bool(criteria or requirements or deliverables or inferred)
    diagnostics = {
        "parser": "structural_heading_first_v1",
        "recognized_section_roles": sorted({r for r, _ in sections if r}),
        "explicit_numbered_criterion_count": len([c for c in criteria if "source_number" in c]),
        "mandatory_path_count": len(paths),
        "quantity_fragments": re.findall(r"\b(?:at least|at most|exactly|minimum|maximum)\s+\d+\b", raw_goal, re.I),
        "conjunction_preservation": "source_text_verbatim",
    }
    return MissionContract(MISSION_CONTRACT_VERSION, raw_goal, _sha(raw_goal), _sha(_normalize_goal(raw_goal)), intent, deliverables, paths, [], architecture, dep_policy, boundaries, non_goals, requirements, criteria, inferred, ambiguities, [], diagnostics, completeness, created_at or _now())


def contract_acceptance_ledger(contract: MissionContract | dict[str, Any]) -> list[dict[str, Any]]:
    data = contract.to_dict() if isinstance(contract, MissionContract) else contract
    sources = list(data.get("explicit_acceptance_criteria") or [])
    if not sources:
        sources = list(data.get("inferred_acceptance_criteria") or [])
    if not sources:
        sources = list(data.get("mandatory_requirements") or [])
    ledger = []
    for item in sources:
        checks = list(item.get("verification") or [])
        ledger.append({"criterion_id": item["id"], "source_text": item["source_text"], "source_type": item.get("source", "explicit_user_requirement"), "mandatory": True, "status": "open", "evidence_refs": [], "verification_notes": [], "verification": checks, "verification_disposition": "deterministic_structural" if checks else infer_verification_disposition(item["source_text"])})
    return ledger


def infer_verification_disposition(text: str) -> str:
    lower = text.lower()
    if any(x in lower for x in ("smooth", "visual", "readable", "polished", "approximately", "fps")):
        return "human_observation_required"
    if any(x in lower for x in ("runtime", "restart", "collision", "active", "live ", "camera", "respawn")):
        return "unsupported_verifier"
    if _PATH_RE.search(text) or any(x in lower for x in ("contains", "section", "schema", "cross-link")):
        return "deterministic_structural"
    return "evidence_required"


def ledger_coverage_report(contract: dict[str, Any], ledger: list[dict[str, Any]]) -> dict[str, Any]:
    reqs = list(contract.get("mandatory_requirements") or [])
    criteria = list(contract.get("explicit_acceptance_criteria") or [])
    represented = {str(i.get("criterion_id")) for i in ledger}
    requirement_ids = [i["id"] for i in reqs]
    criterion_ids = [i["id"] for i in criteria]
    paths = list(contract.get("mandatory_paths") or [])
    # Path coverage is a parallel contract projection, not criterion-verifier
    # availability. Exact paths retained in the contract are represented.
    represented_paths = list(paths) if contract.get("contract_version") else []
    arch = list(contract.get("explicit_architecture_decisions") or [])
    inferred_projection = bool(contract.get("inferred_acceptance_criteria")) and not criteria
    omitted_req = [] if inferred_projection and ledger else [x for x in requirement_ids if x not in represented]
    omitted_ac = [x for x in criterion_ids if x not in represented]
    omitted_paths = [x for x in paths if x not in represented_paths]
    total = len(requirement_ids) + len(criterion_ids) + len(paths) + len(arch)
    represented_total = len(requirement_ids)-len(omitted_req) + len(criterion_ids)-len(omitted_ac) + len(paths)-len(omitted_paths) + len(arch)
    return {"explicit_requirement_count": len(reqs), "represented_requirement_count": len(reqs)-len(omitted_req), "omitted_requirement_ids": omitted_req, "explicit_acceptance_criterion_count": len(criteria), "represented_acceptance_criterion_count": len(criteria)-len(omitted_ac), "omitted_acceptance_criterion_ids": omitted_ac, "mandatory_path_count": len(paths), "represented_path_count": len(paths)-len(omitted_paths), "omitted_paths": omitted_paths, "architecture_decision_count": len(arch), "represented_architecture_decision_count": len(arch), "omitted_architecture_decisions": [], "coverage_ratio": represented_total / total if total else 1.0, "coverage_complete": represented_total == total}


def verification_plan_coverage_report(ledger: list[dict[str, Any]]) -> dict[str, Any]:
    mandatory = [x for x in ledger if x.get("mandatory", True)]
    with_disp = [x for x in mandatory if x.get("verification_disposition")]
    executable = [x for x in mandatory if x.get("verification")]
    unsupported = [x["criterion_id"] for x in mandatory if x.get("verification_disposition") == "unsupported_verifier"]
    human = [x["criterion_id"] for x in mandatory if x.get("verification_disposition") == "human_observation_required"]
    ambiguous = [x["criterion_id"] for x in mandatory if x.get("verification_disposition") == "ambiguous_requirement"]
    return {"mandatory_criterion_count": len(mandatory), "criteria_with_disposition_count": len(with_disp), "criteria_with_executable_checks_count": len(executable), "unsupported_criterion_ids": unsupported, "human_observation_criterion_ids": human, "ambiguous_criterion_ids": ambiguous, "coverage_complete": len(with_disp) == len(mandatory)}


def proposal_contract_conformance(contract: dict[str, Any], proposed_paths: list[str], *, criteria_addressed: list[str] | None = None) -> dict[str, Any]:
    required = list(contract.get("mandatory_paths") or [])
    proposed = [posixpath.normpath(p.replace("\\", "/")) for p in proposed_paths]
    exact = [p for p in required if p in proposed]
    missing = [p for p in required if p not in proposed]
    additional = [p for p in proposed if p not in required]
    substitutes = []
    for extra in additional:
        matches = [need for need in missing if PurePosixPath(need).name == PurePosixPath(extra).name]
        if matches:
            substitutes.append({"proposed_path": extra, "required_path": matches[0], "reason": "same_basename_different_directory"})
    all_criteria = [x["id"] for x in contract.get("explicit_acceptance_criteria") or []]
    addressed = list(criteria_addressed or [])
    return {"required_paths": required, "exact_required_paths_proposed": exact, "exact_required_paths_satisfied": exact, "missing_required_paths": missing, "additional_paths": additional, "conflicting_paths": [x["proposed_path"] for x in substitutes], "likely_misplaced_substitutes": substitutes, "architecture_constraints_satisfied": [], "architecture_constraints_violated": [], "criteria_addressed": addressed, "criteria_unaddressed": [x for x in all_criteria if x not in addressed], "conformance_complete": not missing and not substitutes and set(all_criteria) <= set(addressed)}


def instruction_fidelity_report(contract: dict[str, Any], packet_text: str, *, artifact_path: str = ".admissible/mission-contract.json") -> dict[str, Any]:
    criteria = [x["id"] for x in contract.get("explicit_acceptance_criteria") or []]
    paths = list(contract.get("mandatory_paths") or [])
    arch = [x["id"] for x in contract.get("explicit_architecture_decisions") or []]
    artifact_available = artifact_path in packet_text and contract.get("raw_goal_sha256") in packet_text
    omitted = [] if artifact_available else ["mission_contract_reference"]
    return {"contract_sha": _sha(json.dumps(contract, ensure_ascii=False, sort_keys=True, separators=(",", ":"))), "raw_goal_sha": contract.get("raw_goal_sha256"), "criterion_ids_included": criteria if artifact_available else [x for x in criteria if x in packet_text], "mandatory_paths_included": paths if artifact_available else [x for x in paths if x in packet_text], "architecture_decisions_included": arch if artifact_available else [x for x in arch if x in packet_text], "omitted_packet_fields": omitted, "fidelity_complete": not omitted}


def evaluate_completion_eligibility(state: dict[str, Any], mission_contract: dict[str, Any]) -> dict[str, Any]:
    ledger = list(state.get("acceptance_criteria") or [])
    coverage = state.get("contract_ledger_coverage_report") or ledger_coverage_report(mission_contract, ledger)
    verification = state.get("verification_plan_coverage_report") or verification_plan_coverage_report(ledger)
    unverified = [x["criterion_id"] for x in ledger if x.get("mandatory", True) and x.get("status") not in ("verified_pass", "waived", "policy_terminal")]
    unsupported = [x["criterion_id"] for x in ledger if x.get("verification_disposition") == "unsupported_verifier" and x.get("status") != "waived"]
    missing_paths = list(coverage.get("omitted_paths") or [])
    failures = []
    checks = ((mission_contract.get("contract_completeness"), "contract_incomplete"), (coverage.get("coverage_complete"), "acceptance_ledger_incomplete"), (verification.get("coverage_complete"), "verification_plan_incomplete"), (not unverified, "mandatory_criteria_unverified"), (not unsupported, "verification_capability_gap"), (not mission_contract.get("ambiguities"), "unresolved_ambiguity"), (not state.get("active_blockers"), "active_blocker"), (not state.get("pending_useful_operations"), "pending_useful_operation"), (not state.get("unresolved_likely_substitutes"), "unresolved_likely_substitute"))
    failures.extend(name for ok, name in checks if not ok)
    return {"eligible": not failures, "failed_invariants": failures, "omitted_requirements": list(coverage.get("omitted_requirement_ids") or []) + list(coverage.get("omitted_acceptance_criterion_ids") or []), "unverified_criteria": unverified, "unsupported_criteria": unsupported, "missing_paths": missing_paths, "architecture_violations": list(state.get("architecture_violations") or []), "active_blockers": list(state.get("active_blockers") or []), "pending_operations": list(state.get("pending_useful_operations") or []), "generated_at": _now()}


def canonical_outcome_for_report(report: dict[str, Any]) -> str:
    if report.get("eligible"):
        return "completed"
    failures = set(report.get("failed_invariants") or [])
    if "contract_incomplete" in failures or "acceptance_ledger_incomplete" in failures:
        return "contract_incomplete"
    if "verification_capability_gap" in failures:
        return "verification_capability_gap"
    if "verification_plan_incomplete" in failures:
        return "verification_plan_incomplete"
    return "incomplete"


def migrate_legacy_false_completion(session_data: dict[str, Any]) -> dict[str, Any]:
    """Re-evaluate imported legacy completion while preserving audit history."""
    data = dict(session_data)
    intake = dict(data.get("goal_intake") or {})
    goal = str(intake.get("prompt") or data.get("goal_text") or "")
    if not goal:
        return data
    contract = dict(data.get("mission_contract") or build_mission_contract(goal).to_dict())
    data["mission_contract"] = contract
    high = dict(data.get("high_autonomy_run") or {})
    if high.get("outcome") != "completed":
        return data
    historical_ledger = list(high.get("acceptance_criteria") or [])
    ledger = contract_acceptance_ledger(contract)
    terminal_count = sum(1 for item in historical_ledger if item.get("status") in ("verified_pass", "waived"))
    for item in ledger[:terminal_count]:
        item["status"] = "verified_pass"
        item["verification_notes"] = ["Migrated legacy terminal check by ordinal audit history; contract re-evaluation still required."]
    coverage = ledger_coverage_report(contract, ledger)
    verification = verification_plan_coverage_report(ledger)
    eligibility_state = dict(high)
    eligibility_state.update({"acceptance_criteria": ledger, "contract_ledger_coverage_report": coverage, "verification_plan_coverage_report": verification})
    report = evaluate_completion_eligibility(eligibility_state, contract)
    report["legacy_false_completion_repaired"] = True
    high["historical_outcome"] = "completed"
    high["historical_acceptance_criteria"] = historical_ledger
    high["acceptance_criteria"] = ledger
    high["contract_ledger_coverage_report"] = coverage
    high["verification_plan_coverage_report"] = verification
    high["completion_eligibility_report"] = report
    high["outcome"] = canonical_outcome_for_report(report)
    high["outcome_reason"] = f"Legacy completion repaired: {terminal_count}/{len(historical_ledger)} legacy checks passed, but the {len(ledger)}-criterion mission contract was not fully verified."
    metrics = dict(high.get("metrics") or {})
    metrics["legacy_false_completion_repair_count"] = 1
    metrics["raw_human_decision_count"] = len(data.get("human_decisions") or [])
    metrics["genuine_human_intervention_count"] = 0
    high["metrics"] = metrics
    data["high_autonomy_run"] = high
    return data
