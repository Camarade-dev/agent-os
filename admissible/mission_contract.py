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

# The canonical verification-disposition vocabulary (PART H.37, RUN_043).
# ``deterministic_static`` and ``deterministic_runtime`` were added in
# RUN_043 alongside the pre-existing dispositions; every criterion's
# disposition (however derived) must be one of these.
VERIFICATION_DISPOSITIONS = frozenset(
    {
        "deterministic_static",
        "deterministic_structural",
        "deterministic_runtime",
        "human_observation_required",
        "evidence_required",
        "unsupported_verifier",
        "ambiguous_requirement",
    }
)

_HEADINGS = {
    "deliverables": ("mandatory deliverables", "required files", "mandatory files", "deliverables", "livrables obligatoires"),
    "requirements": ("requirements", "mandatory behavior", "robustness", "observability", "documentation"),
    "architecture": ("architecture", "scope and architecture are already authorized", "technical choices"),
    "boundaries": ("constraints", "authorized scope", "execution boundaries", "working method"),
    "non_goals": ("non-goals", "non goals", "out of scope"),
    "completion": ("completion",),
}

# Acceptance-heading recognition (RUN_049 PART A) is structural, not an exact
# string list -- an operator heading like "MANDATORY ACCEPTANCE CRITERIA" or
# "Final verification criteria" must be recognized generically, across any
# domain (CLI tool, data pipeline, docs, browser app, repair task), not just
# the exact spellings a prior goal happened to use.
_ACCEPTANCE_HEADING_QUALIFIERS = frozenset(
    {"mandatory", "required", "final", "minimum", "functional", "technical"}
)
_ACCEPTANCE_HEADING_CORE_PHRASES = frozenset(
    {
        "acceptance criteria",
        "completion criteria",
        "verification criteria",
        "critères d'acceptation",
    }
)


def _singularize_heading_word(word: str) -> str:
    if word in ("criterion", "criterions"):
        return "criteria"
    return word


def _is_acceptance_heading(value: str) -> bool:
    """True when a normalized heading line structurally means "acceptance criteria".

    Handles case, a trailing colon, markdown `#` markers, surrounding
    whitespace (all stripped by the caller before this is invoked),
    singular/plural criterion(s)/criteria, and leading qualifier words
    (mandatory/required/final/minimum/functional/technical) in any position.
    """

    if not value:
        return False
    words = [_singularize_heading_word(w) for w in value.split(" ") if w]
    stripped = " ".join(w for w in words if w not in _ACCEPTANCE_HEADING_QUALIFIERS)
    return stripped in _ACCEPTANCE_HEADING_CORE_PHRASES
_PATH_RE = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:html?|css|js|mjs|cjs|ts|tsx|py|json|ya?ml|md|txt|csv|sql)(?![\w.-])", re.I)
_BULLET_RE = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)(.+?)\s*$")
_NUMBERED_RE = re.compile(r"^\s*(\d+)[.)]\s+(.+?)\s*$")
_PLAIN_BULLET_RE = re.compile(r"^\s*[-*+]\s+(.+?)\s*$")
_MARKDOWN_HEADING_RE = re.compile(r"^#{1,6}\s+\S")
# Polarity cues that mark a sentence as a negated/rejected statement: paths
# mentioned inside such a sentence are rejected substitutes or non-goals,
# never positive mandatory declarations. Deliberately narrower than every
# possible English negation ("no"/"only" alone are far too broad) -- these
# are the cue shapes that reject a previously named artifact.
_NEGATION_CUE_RE = re.compile(
    r"\b(?:do(?:es)?\s+not|must\s+not|may\s+not|shall\s+not|cannot|can\s+not|never|"
    r"is\s+not|are\s+not|isn'?t|aren'?t|doesn'?t|don'?t|won'?t|"
    r"instead\s+of|rather\s+than|forbidden|prohibited|rejected)\b",
    re.I,
)
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.;!?])\s+")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalize_goal(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").strip().split("\n"))


def _strip_trailing_line_punctuation(text: str) -> str:
    """Strip harmless trailing `;`/`,`/`.` from one heading-scoped line.

    Never alters interior punctuation or semantic content -- only a single
    run of these three characters (and any trailing whitespace) at the very
    end of the line, e.g. the ``;`` separators a plain (non-bulleted) list
    of requirements often uses between lines.
    """

    return re.sub(r"[;,.]+\s*$", "", text).strip()


def _heading(line: str) -> str | None:
    value = re.sub(r"^[#\s]+|[:\s]+$", "", line).strip().lower()
    value = re.sub(r"\s+", " ", value)
    if _is_acceptance_heading(value):
        return "acceptance"
    for role, names in _HEADINGS.items():
        if value in names:
            return role
    return None


def _is_section_boundary_heading(lines: list[str], index: int) -> bool:
    """True when a line is structurally a top-level section heading.

    RUN_050: a heading the role vocabulary does not recognize (e.g.
    "IMPLEMENTATION PROCESS", "VERIFICATION AND REPAIR", "FINAL REPORT",
    "WORKING METHOD") must still TERMINATE the current section, or every
    later section's bullets get absorbed into the acceptance criteria.
    Recognition is structural, never an exact string list: a Markdown
    ``#`` heading at the margin, or a short standalone ALL-CAPS line
    separated by blank lines / document edges. An indented line is never
    a heading -- it is a continuation of the current numbered item.
    """

    line = lines[index]
    stripped = line.strip()
    if not stripped or line != line.lstrip():
        return False
    if _MARKDOWN_HEADING_RE.match(stripped):
        return True
    prev_blank = index == 0 or not lines[index - 1].strip()
    next_blank = index == len(lines) - 1 or not lines[index + 1].strip()
    if not (prev_blank and next_blank):
        return False
    if len(stripped) > 60 or stripped.endswith((".", ";", ",", "?", "!")):
        return False
    if _BULLET_RE.match(stripped):
        return False
    if not any(ch.isalpha() for ch in stripped) or any(ch.islower() for ch in stripped):
        return False
    return 1 <= len(stripped.split()) <= 8


def _negated_path_mentions(text: str) -> set[str]:
    """Exact paths that appear only inside negated/rejected sentences.

    Wrapped physical lines are re-joined paragraph-by-paragraph before
    sentence splitting so a negation cue and the paths it rejects cannot
    be separated by a mid-sentence line wrap. Callers must still let a
    positively scoped declaration (a mandatory-files/deliverables bullet)
    win over a negated mention elsewhere.
    """

    negated: set[str] = set()
    for paragraph in re.split(r"\n\s*\n", text):
        joined = " ".join(part.strip() for part in paragraph.split("\n") if part.strip())
        for sentence in _SENTENCE_SPLIT_RE.split(joined):
            if _NEGATION_CUE_RE.search(sentence):
                negated.update(p.replace("\\", "/") for p in _PATH_RE.findall(sentence))
    return negated


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
    lines = raw_goal.replace("\r\n", "\n").replace("\r", "\n").split("\n")

    # Pass 1 (RUN_050): assign section roles. A recognized heading selects its
    # role; an unrecognized *structural* heading (see
    # _is_section_boundary_heading) terminates the current section so later
    # sections (e.g. an implementation-process or final-report section) are
    # never absorbed into acceptance parsing. Blank lines are kept -- pass 2
    # needs them to tell a wrapped continuation from a new standalone line.
    labeled: list[tuple[str | None, str]] = []
    role: str | None = None
    for index, line in enumerate(lines):
        detected = _heading(line)
        if detected:
            role = detected
            continue
        if _is_section_boundary_heading(lines, index):
            role = None
            continue
        labeled.append((role, line))

    # Pass 2 (RUN_050): group physical lines into logical units. A numbered
    # acceptance item owns every following line until the next numbered
    # sibling at the same indent level or the next section heading:
    # indented lines are nested supporting content (bullets there become the
    # criterion's subrequirements), and a non-blank margin line directly
    # under it is an ordinary wrapped continuation. A blank line only
    # terminates the item when the following content is back at the margin
    # (clearly-nested indented content continues it). Every other section
    # keeps the pre-existing one-line-per-unit semantics.
    units: list[tuple[str | None, dict[str, Any]]] = []
    active: dict[str, Any] | None = None
    blank_gap = False

    def _flush() -> None:
        nonlocal active
        if active is not None:
            units.append((active["role"], active))
            active = None

    for line_role, line in labeled:
        stripped = line.strip()
        if not stripped:
            blank_gap = True
            continue
        numbered = _NUMBERED_RE.match(line)
        indent = len(line) - len(line.lstrip())
        if active is not None:
            if line_role != active["role"] or (numbered and indent <= active["indent"]):
                _flush()
            elif indent > active["indent"]:
                nested_bullet = _PLAIN_BULLET_RE.match(line)
                if nested_bullet:
                    active["nested_bullets"].append(nested_bullet.group(1).strip())
                    active["text_parts"].append(nested_bullet.group(1).strip())
                else:
                    active["text_parts"].append(stripped)
                blank_gap = False
                continue
            elif not blank_gap and not _BULLET_RE.match(line):
                active["text_parts"].append(stripped)
                blank_gap = False
                continue
            else:
                _flush()
        if line_role == "acceptance" and numbered:
            active = {
                "role": line_role,
                "kind": "numbered",
                "number": int(numbered.group(1)),
                "indent": indent,
                "text_parts": [numbered.group(2).strip()],
                "nested_bullets": [],
            }
        else:
            units.append((line_role, {"role": line_role, "kind": "line", "line": line, "nested_bullets": []}))
        blank_gap = False
    _flush()

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
    # RUN_050 path polarity: a path mentioned only inside a negated/rejected
    # sentence must never become mandatory. Positive scoped declarations
    # (deliverables-section bullets) always win over a negated mention
    # elsewhere in the goal.
    negated_paths = _negated_path_mentions(raw_goal)

    for section, unit in units:
        if unit["kind"] == "numbered":
            bullet = None
            numbered = None
            text = " ".join(unit["text_parts"]).strip()
        else:
            line = unit["line"]
            bullet = _BULLET_RE.match(line)
            numbered = _NUMBERED_RE.match(line)
            text = bullet.group(1).strip() if bullet else line.strip()
        found_paths = [p.replace("\\", "/") for p in _PATH_RE.findall(text)]
        if section == "deliverables":
            rejected_here = [] if bullet else [p for p in dict.fromkeys(found_paths) if p in negated_paths]
            for path in found_paths:
                if path in rejected_here:
                    continue
                if path not in paths:
                    paths.append(path)
                    counters["deliverable"] += 1
                    deliverables.append(_entry(f"deliverable_{counters['deliverable']:03d}", path, source="explicit", order=counters["deliverable"], exact_path=path))
            if rejected_here:
                counters["non_goal"] += 1
                non_goals.append(
                    _entry(
                        f"non_goal_{counters['non_goal']:03d}",
                        text,
                        source="explicit",
                        order=counters["non_goal"],
                        kind="rejected_path_substitute",
                        rejected_paths=rejected_here,
                    )
                )
        if section == "acceptance" and unit["kind"] == "numbered":
            counters["criterion"] += 1
            entry = _entry(f"explicit_ac_{counters['criterion']:03d}", text, source="explicit", order=counters["criterion"], source_number=unit["number"], mandatory=True)
            if unit["nested_bullets"]:
                entry["subrequirements"] = [
                    {
                        "id": f"{entry['id']}_sub_{sub_index:03d}",
                        "source_text": sub_text,
                        "source": "explicit",
                        "order": sub_index,
                        "mandatory": True,
                    }
                    for sub_index, sub_text in enumerate(unit["nested_bullets"], start=1)
                ]
            criteria.append(entry)
        elif section == "acceptance" and bullet:
            counters["criterion"] += 1
            criteria.append(_entry(f"explicit_ac_{counters['criterion']:03d}", text, source="explicit", order=counters["criterion"], mandatory=True))
        elif section == "acceptance":
            # RUN_045 PART I: a heading-scoped line under "Acceptance
            # criteria:" is a separate explicit requirement even without a
            # -/*/numeric prefix -- never silently dropped. Recorded as an
            # explicit *requirement* rather than an *acceptance criterion*
            # so it never displaces the generic verification-check wiring
            # `derive_acceptance_criteria_from_goal` already attaches when a
            # goal has no bulleted/numbered acceptance criteria at all
            # (contract_acceptance_ledger prefers explicit acceptance
            # criteria, then inferred ones, then requirements last) --
            # RUN_038-044 replay fixtures rely on that inferred path.
            counters["requirement"] += 1
            requirements.append(
                _entry(
                    f"requirement_{counters['requirement']:03d}",
                    _strip_trailing_line_punctuation(text),
                    source="explicit",
                    order=counters["requirement"],
                    mandatory=True,
                )
            )
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

    # Paths named inside explicit criteria/requirements are also exact contract
    # paths -- unless they only ever appear in negated/rejected sentences.
    for item in criteria + requirements:
        for path in _PATH_RE.findall(item["source_text"]):
            path = path.replace("\\", "/")
            if path not in paths and path not in negated_paths:
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
    # dedicated deliverables section. Negated mentions (rejected substitutes,
    # non-goals) never make a path mandatory; a path declared positively
    # elsewhere is already in ``paths`` and stays.
    for path in _PATH_RE.findall(raw_goal):
        path = path.replace("\\", "/")
        if path not in paths and path not in negated_paths:
            paths.append(path)
    completeness = not ambiguities and bool(criteria or requirements or deliverables or inferred)
    diagnostics = {
        "parser": "structural_heading_first_v2",
        "recognized_section_roles": sorted({r for r, _ in units if r}),
        "explicit_numbered_criterion_count": len([c for c in criteria if "source_number" in c]),
        "mandatory_path_count": len(paths),
        "quantity_fragments": re.findall(r"\b(?:at least|at most|exactly|minimum|maximum)\s+\d+\b", raw_goal, re.I),
        "conjunction_preservation": "source_text_verbatim",
    }
    return MissionContract(MISSION_CONTRACT_VERSION, raw_goal, _sha(raw_goal), _sha(_normalize_goal(raw_goal)), intent, deliverables, paths, [], architecture, dep_policy, boundaries, non_goals, requirements, criteria, inferred, ambiguities, [], diagnostics, completeness, created_at or _now())


_EXISTENCE_ASSERTION_RE = re.compile(r"\bexists?\b|\bis\s+present\b|\bpresent\b", re.I)


def select_verification_for_criterion_text(source_text: str, mandatory_paths: list[str]) -> list[dict[str, Any]]:
    """Select concrete allowlisted verification checks for one criterion's own text.

    RUN_049 PART B: once RUN_049 PART A recognizes an operator's own
    acceptance-heading section, ``build_mission_contract`` no longer falls
    back to ``derive_acceptance_criteria_from_goal``'s generic whole-goal
    template -- so an explicit criterion needs its OWN path to a concrete
    check, or it silently degrades to an unverifiable disposition forever.
    This mirrors that template's keyword/path-pattern heuristics, but is
    driven by one criterion's own ``source_text`` plus the contract's
    already-extracted ``mandatory_paths`` (never a hard-coded product/game
    name), and never displaces or duplicates the still-independent
    goal-level inferred template. Returns ``[]`` when the text does not
    structurally imply a supported check -- callers must not treat that as
    a pass.
    """

    lower = (source_text or "").lower()
    html_targets = [p for p in mandatory_paths if p.lower().endswith((".html", ".htm"))]
    js_targets = [p for p in mandatory_paths if p.lower().endswith(".js")]
    doc_targets = [
        p
        for p in mandatory_paths
        if p.lower().endswith(".md") or "dev" in p.lower() or "usage" in p.lower()
    ]
    mentioned_paths = [
        p for p in mandatory_paths if p in source_text or PurePosixPath(p).name in source_text
    ]
    # RUN_050: a dynamic/runtime-shaped criterion (collision, respawn,
    # restart, live-state, camera ...) must keep its unsupported_verifier
    # disposition so it is routed to the RUN_042/044 browser-runtime plan
    # builder -- a GENERIC keyword proxy (controls/score/doc-usage below) must
    # not claim it as deterministic_structural just because its full text also
    # mentions a static keyword. Dedicated verifiers stay available:
    # file_exists (existence is static regardless of phrasing) and the
    # unambiguous "R key" game_restart_check branch (RUN_049 PART B) below.
    runtime_shaped = infer_verification_disposition(source_text or "") == "unsupported_verifier"

    if mentioned_paths and _EXISTENCE_ASSERTION_RE.search(lower):
        return [{"check_id": "file_exists", "target_paths": mentioned_paths[:1]}]
    if not runtime_shaped and js_targets and ("arrow" in lower or "wasd" in lower or "movement" in lower):
        return [{"check_id": "game_controls_check", "target_paths": js_targets[:1]}]
    if not runtime_shaped and js_targets and ("collectible" in lower or "collecting" in lower or "score" in lower):
        return [{"check_id": "file_contains", "target_paths": js_targets[:1], "contains": ["score"]}]
    # Deliberately narrower than derive_acceptance_criteria_from_goal's
    # goal-level "restart" OR-branch: a bare "restart" keyword is also how
    # RUN_042/044's browser-runtime plan builder recognizes a *dynamic*
    # restart-control criterion (e.g. "Press Z to restart" temporal/loop
    # requirements) that must stay unsupported_verifier so it is routed to
    # that live runtime plan builder instead -- see
    # test_admissible_runtime_plan_builder.py /
    # test_admissible_neon_runtime_regression.py. The unambiguous "R key"
    # phrasing this static local-file check actually targets never collides
    # with that dynamic phrasing.
    if js_targets and (" r key" in lower or "press `r`" in lower):
        return [{"check_id": "game_restart_check", "target_paths": js_targets[:1]}]
    # RUN_050: the local-usage documentation check applies only to a criterion
    # that is actually ABOUT the documentation deliverable -- it must name the
    # doc path itself. Bare substrings like "local"/"run" ("loads locally",
    # "running") used to attach this unrelated check to gameplay criteria
    # whenever their continuation text was truncated or merely mentioned
    # locality; that mis-selection is a false structural proxy, not a verifier.
    doc_mentioned = [
        p for p in doc_targets if p in source_text or PurePosixPath(p).name in source_text
    ]
    if not runtime_shaped and doc_mentioned and re.search(r"\b(?:usage|local(?:ly)?|open(?:ing|s)?|run(?:ning)?|document\w*)\b", lower):
        contains = ["open"] + (html_targets[:1] if html_targets else ["index.html"])
        return [{"check_id": "local_usage_check", "target_paths": doc_mentioned[:1], "contains": contains}]
    return []


def contract_acceptance_ledger(contract: MissionContract | dict[str, Any]) -> list[dict[str, Any]]:
    data = contract.to_dict() if isinstance(contract, MissionContract) else contract
    sources = list(data.get("explicit_acceptance_criteria") or [])
    if not sources:
        sources = list(data.get("inferred_acceptance_criteria") or [])
    if not sources:
        sources = list(data.get("mandatory_requirements") or [])
    mandatory_paths = list(data.get("mandatory_paths") or [])
    ledger = []
    for item in sources:
        checks = list(item.get("verification") or [])
        # RUN_050: disposition/check selection runs on the criterion's COMPLETE
        # reconstructed text. A criterion whose own full text requires human
        # observation must never be handed a keyword-matched static check that
        # would silently reclassify it as deterministic_structural.
        # (Runtime-shaped criteria are handled inside
        # select_verification_for_criterion_text itself: generic keyword
        # proxies skip them, while dedicated static verifiers such as
        # game_restart_check still apply -- RUN_049 PART B.)
        disposition = infer_verification_disposition(item["source_text"])
        if not checks and disposition != "human_observation_required":
            checks = select_verification_for_criterion_text(item["source_text"], mandatory_paths)
        ledger.append({"criterion_id": item["id"], "source_text": item["source_text"], "source_type": item.get("source", "explicit_user_requirement"), "mandatory": True, "status": "open", "evidence_refs": [], "verification_notes": [], "verification": checks, "verification_disposition": "deterministic_structural" if checks else disposition})
    return ledger


def infer_human_observation_subaspect(text: str) -> bool:
    """True when the text carries a subjective smoothness/polish aspect."""

    lower = text.lower()
    return any(x in lower for x in ("smooth", "visual", "readable", "polished", "approximately", "fps"))


def infer_verification_disposition(text: str) -> str:
    lower = text.lower()
    # Objective pointer-steering checks stay runtime-shaped even when the same
    # criterion also mentions subjective smoothness (Neon criterion 4).
    if _POINTER_STEERING_RE.search(text):
        return "evidence_required"
    if infer_human_observation_subaspect(text):
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
    # RUN_045 PART I: the ledger criterion count actually driving verification
    # is often *inferred* (derive_acceptance_criteria_from_goal), not
    # explicit -- "explicit_acceptance_criterion_count" alone reads as "0/0"
    # even when the ledger is fully populated and being verified. Report the
    # inferred and total-ledger counts alongside it so a caller/UI can show
    # the real picture instead of a bare, misleading 0/0.
    inferred = list(contract.get("inferred_acceptance_criteria") or [])
    return {"explicit_requirement_count": len(reqs), "represented_requirement_count": len(reqs)-len(omitted_req), "omitted_requirement_ids": omitted_req, "explicit_acceptance_criterion_count": len(criteria), "represented_acceptance_criterion_count": len(criteria)-len(omitted_ac), "omitted_acceptance_criterion_ids": omitted_ac, "inferred_acceptance_criterion_count": len(inferred), "total_ledger_criterion_count": len(ledger), "criteria_are_inferred": inferred_projection, "mandatory_path_count": len(paths), "represented_path_count": len(paths)-len(omitted_paths), "omitted_paths": omitted_paths, "architecture_decision_count": len(arch), "represented_architecture_decision_count": len(arch), "omitted_architecture_decisions": [], "coverage_ratio": represented_total / total if total else 1.0, "coverage_complete": represented_total == total}


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


_DEBUG_INTERFACE_MENTION_RE = re.compile(r"\b(window\.__[A-Za-z_][A-Za-z0-9_]*__)\b")
_SNAPSHOT_FIELDS_RE = re.compile(r"\bsnapshot\s+returning\s+at\s+least\s*:?\s*(.+)", re.I)
_QUERY_FLAG_RE = re.compile(r"\benabled\s+with\s+(\?[A-Za-z0-9_=]+)", re.I)
_QUANTITY_SUBJECT = r"((?:[a-zA-Z][a-zA-Z\-]*\s*){1,3})"
_AT_LEAST_RE = re.compile(rf"\bat\s+least\s+(\d+)\s+{_QUANTITY_SUBJECT}", re.I)
_AT_MOST_RE = re.compile(rf"\bat\s+most\s+(\d+)\s+{_QUANTITY_SUBJECT}", re.I)
_EXACTLY_RE = re.compile(rf"\bexactly\s+(\d+)\s+{_QUANTITY_SUBJECT}", re.I)
_PRESS_KEY_RE = re.compile(r"\bpress\s+([A-Za-z0-9])\s+to\s+([a-zA-Z][a-zA-Z \-]*?)(?=[.,;]|$)", re.I)
_PAUSE_RESUME_RE = re.compile(r"\bpause\s+and\s+resume\s+with\s+([A-Za-z0-9])\b", re.I)
_DOM_TOKEN_RE = re.compile(r"(?<![\w])([#.][A-Za-z_][A-Za-z0-9_\-]*)")
_NO_DUPLICATE_LOOPS_RE = re.compile(r"\bmust\s+not\s+create\s+duplicate\s+animation\s+loops?\b", re.I)
_NO_UNCAUGHT_ERRORS_RE = re.compile(
    r"\bno\s+uncaught\s+errors?\b"
    r"|\buncaught\s+page\s+exceptions?\b"
    r"|\bmaterial\s+console\s+errors?\b",
    re.I,
)
_SUBREQUIREMENT_FIELD_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*:", re.M)
_POINTER_STEERING_RE = re.compile(
    r"\bpointer[\-\s]driven\b|\bmoving the mouse\b|\bpointer changes\b|\bcontinuous.*\bsteering\b",
    re.I,
)
_REPEATED_RESTART_RE = re.compile(r"\bremain\s+playable\s+after\s+repeated\s+restart\s+cycles\b", re.I)
_LEADERBOARD_UPDATES_RE = re.compile(r"\bleaderboard\s+updates?\s+during\s+play\b", re.I)
_DEBUG_FLAG_OVERLAY_RE = re.compile(r"\?debug=1\b")

_LIFECYCLE_KEYWORDS = (
    "restart",
    "pause",
    "resume",
    "respawn",
    "collision",
    "death",
    "dropped",
    "growth",
    "boost",
)


def extract_runtime_observability_intent(contract: dict[str, Any] | "MissionContract") -> dict[str, Any]:
    """Deterministic, non-LLM extraction of typed runtime-observability intent.

    Parses structurally-recognizable English patterns (PART F.27) out of the
    raw goal and mandatory requirement/criterion text. Never hard-codes a
    game name, field name, selector, or control -- every pattern here is a
    generic phrase shape ("press X to Y", "at least N ...", "window.__X__",
    ...), and every list below stays empty when the goal text does not
    contain a matching phrase.
    """

    data = contract.to_dict() if isinstance(contract, MissionContract) else dict(contract)
    raw_goal = str(data.get("raw_goal") or "")
    fragment_texts = [
        str(item.get("source_text") or "")
        for item in list(data.get("mandatory_requirements") or []) + list(data.get("explicit_acceptance_criteria") or [])
    ]
    # raw_goal already contains every requirement/criterion line verbatim;
    # matching only the deduplicated fragment set (falling back to raw_goal
    # when there are no structured fragments) avoids double-counting the
    # same sentence once from the whole goal and once per parsed bullet.
    texts = list(dict.fromkeys(fragment_texts)) if fragment_texts else [raw_goal]
    joined = "\n".join(texts)

    def _dedupe(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for entry in entries:
            key = entry.get("source_text") or json.dumps(entry, sort_keys=True)
            if key not in seen:
                seen.add(key)
                unique.append(entry)
        return unique

    debug_interface_matches = _DEBUG_INTERFACE_MENTION_RE.findall(joined)
    declared_debug_interface = debug_interface_matches[0] if debug_interface_matches else None

    required_snapshot_fields: list[str] = []
    snapshot_match = _SNAPSHOT_FIELDS_RE.search(joined)
    declared_snapshot_method = bool(snapshot_match) or "snapshot()" in joined
    if snapshot_match:
        fragment = snapshot_match.group(1).split(".")[0]
        for field_name in re.split(r",|\band\b", fragment):
            cleaned = field_name.strip().strip(".").strip()
            cleaned = re.sub(r"^[`']|[`']$", "", cleaned)
            if cleaned:
                required_snapshot_fields.append(cleaned)
    for criterion in list(data.get("explicit_acceptance_criteria") or []):
        for sub in list(criterion.get("subrequirements") or []):
            sub_text = str(sub.get("source_text") or "").strip()
            field_match = _SUBREQUIREMENT_FIELD_RE.match(sub_text)
            if field_match:
                required_snapshot_fields.append(field_match.group(1))
    required_snapshot_fields = list(dict.fromkeys(required_snapshot_fields))

    query_flags = sorted(set(_QUERY_FLAG_RE.findall(joined)))
    if _DEBUG_FLAG_OVERLAY_RE.search(joined) and "?debug=1" not in query_flags:
        query_flags.append("?debug=1")

    def _trim_subject(subject: str) -> str:
        trimmed = re.sub(r"\s+(?:must|will|shall|should|may|can|is|are|do|does)\b.*$", "", subject.strip(), flags=re.I)
        return trimmed.strip().lower()

    numeric_thresholds: list[dict[str, Any]] = []
    for operator, pattern in (("gte", _AT_LEAST_RE), ("lte", _AT_MOST_RE), ("eq", _EXACTLY_RE)):
        for match in pattern.finditer(joined):
            numeric_thresholds.append(
                {
                    "operator": operator,
                    "value": int(match.group(1)),
                    "subject": _trim_subject(match.group(2)),
                    "source_text": match.group(0).strip(),
                }
            )
    numeric_thresholds = _dedupe(numeric_thresholds)

    named_controls: list[dict[str, Any]] = []
    for match in _PRESS_KEY_RE.finditer(joined):
        named_controls.append({"key": match.group(1), "action": match.group(2).strip().lower(), "source_text": match.group(0).strip()})
    for match in _PAUSE_RESUME_RE.finditer(joined):
        named_controls.append({"key": match.group(1), "action": "pause_resume", "source_text": match.group(0).strip()})
    named_controls = _dedupe(named_controls)

    lifecycle_transitions = sorted({kw for kw in _LIFECYCLE_KEYWORDS if re.search(rf"\b{kw}\b", joined, re.I)})

    temporal_requirements: list[str] = []
    if _NO_DUPLICATE_LOOPS_RE.search(joined):
        temporal_requirements.append("no_duplicate_animation_loops")
    if _REPEATED_RESTART_RE.search(joined):
        temporal_requirements.append("stable_after_repeated_restart_cycles")
    if _LEADERBOARD_UPDATES_RE.search(joined):
        temporal_requirements.append("leaderboard_updates_during_play")

    dom_requirements = sorted(set(_DOM_TOKEN_RE.findall(joined)))

    runtime_stability_requirements: list[str] = []
    if _NO_UNCAUGHT_ERRORS_RE.search(joined):
        runtime_stability_requirements.append("no_uncaught_errors")

    human_observation_texts = [
        text for text in texts if text and infer_verification_disposition(text) == "human_observation_required"
    ]

    entrypoint_candidates = [p for p in list(data.get("mandatory_paths") or []) if p.lower().endswith((".html", ".htm"))]
    browser_entrypoint = entrypoint_candidates[0] if entrypoint_candidates else None

    return {
        "browser_entrypoint": browser_entrypoint,
        "query_flags": query_flags,
        "declared_debug_interface": declared_debug_interface,
        "declared_snapshot_method": declared_snapshot_method,
        "required_snapshot_fields": required_snapshot_fields,
        "numeric_thresholds": numeric_thresholds,
        "named_controls": named_controls,
        "lifecycle_transitions": lifecycle_transitions,
        "temporal_requirements": temporal_requirements,
        "dom_requirements": dom_requirements,
        "runtime_stability_requirements": runtime_stability_requirements,
        "human_observation_requirement_count": len(human_observation_texts),
    }


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
