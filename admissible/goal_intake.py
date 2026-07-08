"""Goal Intake v0 — deterministic, offline analysis of a user prompt.

Turns a free-text goal/prompt into a structured, auditable `GoalIntake`
record: task type, deliverable, project maturity, architecture-choice
burden, complexity, risk, likely side-effect classes, missing context,
clarifying questions, a recommended autonomy ceiling, and an initial
non-execution boundary.

This module does not call Cursor, Claude Code, Codex, Gemini, or any
network provider. It does not execute anything. It is a pure keyword/
heuristic classifier over the prompt text, and every field on
`GoalIntake` traces back to the `signals` dict so a human can audit why
a given classification was produced. It does not need to be perfect —
it needs to be auditable and conservative.

See docs/admissible-goal-intake-and-plan-audit.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any

# Stable v0 autonomy ceiling values. Kept as plain strings (not an import
# from admissible.control_surface) so this module has no dependency on the
# control surface — goal intake must work standalone and be testable in
# isolation.
AUTONOMY_CEILING_L1 = "L1_PROPOSE_ONLY"
AUTONOMY_CEILING_L2 = "L2_LOCAL_BATCH_APPROVAL"
AUTONOMY_CEILING_L3 = "L3_LOCAL_AUTO_ADMIT_WITH_INTERRUPTS"

_BURDEN_LEVELS = ("low", "medium", "high")
_COMPLEXITY_LEVELS = ("low", "medium", "high")
_RISK_LEVELS = ("low", "medium", "high")
_MATURITY_VALUES = ("new_project", "existing_project", "unknown")

# Canonical, stable ordering for likely_side_effect_classes output so the
# same prompt always produces the same list order (auditability).
_SIDE_EFFECT_ORDER = (
    "file_create",
    "file_edit",
    "possible_dependency_install",
    "possible_server_run",
    "possible_network_call",
    "possible_deploy",
    "possible_destructive_file_op",
)

_NEGATION_PREFIXES = ("do not", "don't", "do n't", "never", "without", "avoid")

_BUILD_VERBS = ("build", "create", "implement", "write", "make", "develop", "design")
_BUGFIX_WORDS = ("fix", "bug", "broken", "crash", "not working", "doesn't work", "error")
_REFACTOR_WORDS = ("refactor", "restructure", "clean up", "reorganize")
_EXPLAIN_WORDS = ("explain", "what is", "how does", "why does", "describe")
_DEPLOY_WORDS = ("deploy", "publish", "release", "ship it", "go live")

_DELIVERABLE_NOUNS = (
    "game", "app", "application", "website", "site", "api", "service",
    "script", "tool", "cli", "dashboard", "extension", "bot", "page",
    "library", "package", "plugin",
)

_EXISTING_PROJECT_WORDS = (
    "existing codebase", "existing project", "existing repo", "current codebase",
    "this repo", "this repository", "this project", "our app", "the existing",
    "add to", "extend",
)
_NEW_PROJECT_WORDS = ("new", "from scratch", "greenfield", "build a", "create a")

_EXPLICIT_STACK_WORDS = (
    "react", "vue", "angular", "svelte", "phaser", "vanilla", "no framework",
    "plain javascript", "plain js", "using django", "using flask", "using express",
    "next.js", "nextjs", "typescript", "using canvas api",
)

_HIGH_COMPLEXITY_WORDS = (
    "production", "scalable", "multiplayer", "real-time", "realtime",
    "database", "authentication", "auth system", "payment", "distributed",
    "microservice", "enterprise", "concurrent users", "load balanc",
)
_SIMPLICITY_WORDS = ("simple", "small", "minimal", "basic", "local-only", "local only")

_HIGH_RISK_WORDS = (
    "production", "payment", "delete", "drop table", "public", "credentials",
    "secret", "send email", "external api", "database migration", "publish",
)
_MEDIUM_RISK_WORDS = ("install", "dependency", "dependencies", "server", "download", "package manager")
_LOW_RISK_SCOPE_WORDS = ("local-only", "local only", "no deployment", "offline")

_DEPENDENCY_WORDS = (
    "install", "dependency", "dependencies", "npm", "pip", "package", "library", "framework",
)
_NO_DEPENDENCY_WORDS = ("no dependencies", "dependency-free", "vanilla js only", "without any dependencies")
_SERVER_WORDS = ("server", "backend", "api")
_BROWSER_WORDS = ("browser", "web-based", "web based", "website", "webpage", "web page")
_NETWORK_WORDS = ("api", "network", "online", "fetch data", "backend service", "multiplayer")
_DELETE_WORDS = ("delete", "remove", "erase", "wipe")


@dataclass
class GoalIntake:
    """Deterministic, auditable analysis of one user prompt (v0)."""

    prompt: str
    task_type: str
    deliverable: str
    project_maturity: str
    architecture_choice_burden: str
    global_complexity: str
    global_risk: str
    risk_scope: str
    likely_side_effect_classes: list[str]
    missing_context: list[str]
    clarifying_questions: list[str]
    recommended_autonomy_ceiling: str
    initial_non_execution_boundary: str
    signals: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _lower(text: str) -> str:
    return text.lower()


def _find_matches(text_lower: str, words: tuple[str, ...]) -> list[str]:
    return [w for w in words if w in text_lower]


def _is_negated(text_lower: str, word: str) -> bool:
    """Return True if `word` is immediately governed by a negation phrase.

    Looks at up to 4 words before the first occurrence of `word`.
    Conservative: only suppresses on explicit negation ("do not", "don't",
    "never", "without", "avoid"), not on hedged/gated language like
    "ask before" (which still means the action is plausible).
    """
    idx = text_lower.find(word)
    if idx == -1:
        return False
    window = text_lower[max(0, idx - 40) : idx]
    return any(neg in window for neg in _NEGATION_PREFIXES)


def _detect_task_type(text_lower: str, signals: dict[str, list[str]]) -> str:
    bugfix_hits = _find_matches(text_lower, _BUGFIX_WORDS)
    if bugfix_hits:
        signals["task_type"] = bugfix_hits
        return "bug_fix"

    refactor_hits = _find_matches(text_lower, _REFACTOR_WORDS)
    if refactor_hits:
        signals["task_type"] = refactor_hits
        return "refactor"

    explain_hits = _find_matches(text_lower, _EXPLAIN_WORDS)
    if explain_hits:
        signals["task_type"] = explain_hits
        return "explanation"

    deploy_hits = [w for w in _DEPLOY_WORDS if w in text_lower and not _is_negated(text_lower, w)]
    build_hits = _find_matches(text_lower, _BUILD_VERBS)
    if deploy_hits and not build_hits:
        signals["task_type"] = deploy_hits
        return "deployment"

    if build_hits:
        signals["task_type"] = build_hits
        return "software_build"

    signals["task_type"] = []
    return "general_task"


def _detect_deliverable(text_lower: str, signals: dict[str, list[str]]) -> str:
    nouns = _find_matches(text_lower, _DELIVERABLE_NOUNS)
    if not nouns:
        signals["deliverable"] = []
        return "unspecified software artifact"

    signals["deliverable"] = nouns
    noun = nouns[0]
    modifiers = []
    if any(w in text_lower for w in _BROWSER_WORDS):
        modifiers.append("browser")
    elif "mobile" in text_lower:
        modifiers.append("mobile")
    elif "desktop" in text_lower:
        modifiers.append("desktop")
    if any(w in text_lower for w in ("local-only", "local only", "locally")):
        modifiers.append("local")
    modifiers.append(noun)
    return " ".join(modifiers)


def _detect_project_maturity(text_lower: str, signals: dict[str, list[str]]) -> str:
    existing_hits = _find_matches(text_lower, _EXISTING_PROJECT_WORDS)
    new_hits = _find_matches(text_lower, _NEW_PROJECT_WORDS)
    signals["project_maturity"] = existing_hits + new_hits
    if existing_hits and not new_hits:
        return "existing_project"
    if new_hits and not existing_hits:
        return "new_project"
    if new_hits and existing_hits:
        return "new_project"
    return "unknown"


def _detect_architecture_choice_burden(
    text_lower: str, task_type: str, signals: dict[str, list[str]]
) -> str:
    if task_type not in ("software_build", "general_task"):
        signals["architecture_choice_burden"] = []
        return "low"

    explicit_stack = _find_matches(text_lower, _EXPLICIT_STACK_WORDS)
    if explicit_stack:
        signals["architecture_choice_burden"] = explicit_stack
        return "low"

    high_words = ("microservice", "distributed", "multiple services", "backend and frontend")
    high_hits = _find_matches(text_lower, high_words)
    if high_hits:
        signals["architecture_choice_burden"] = high_hits
        return "high"

    if task_type == "software_build":
        signals["architecture_choice_burden"] = ["no explicit framework/stack named"]
        return "medium"

    signals["architecture_choice_burden"] = []
    return "low"


def _count_features(text_lower: str) -> int:
    # Rough, deterministic feature count: split the prompt on commas and
    # " and " to approximate the number of distinct requirements listed.
    parts = re.split(r",| and ", text_lower)
    return len([p for p in parts if p.strip()])


def _detect_complexity(
    text_lower: str, task_type: str, signals: dict[str, list[str]]
) -> str:
    complexity_hits = _find_matches(text_lower, _HIGH_COMPLEXITY_WORDS)
    simplicity_hits = _find_matches(text_lower, _SIMPLICITY_WORDS)
    feature_count = _count_features(text_lower)
    signals["global_complexity"] = complexity_hits + simplicity_hits + [
        f"feature_count={feature_count}"
    ]

    if task_type == "bug_fix" and not complexity_hits:
        return "low"

    if complexity_hits:
        return "high"

    score = feature_count - (2 * len(simplicity_hits))
    if score >= 6:
        return "high"
    if score >= 3 or feature_count >= 4:
        return "medium"
    return "low"


def _detect_risk(
    text_lower: str, signals: dict[str, list[str]]
) -> tuple[str, str]:
    high_hits = [w for w in _HIGH_RISK_WORDS if w in text_lower and not _is_negated(text_lower, w)]
    medium_hits = _find_matches(text_lower, _MEDIUM_RISK_WORDS)
    low_scope_hits = _find_matches(text_lower, _LOW_RISK_SCOPE_WORDS)
    signals["global_risk"] = high_hits + medium_hits + low_scope_hits

    risk_scope = "local" if low_scope_hits else "unspecified"

    if high_hits and risk_scope != "local":
        return "high", risk_scope
    if high_hits and risk_scope == "local":
        return "medium", risk_scope
    if medium_hits:
        return "medium", risk_scope
    return "low", risk_scope


def _detect_side_effects(
    text_lower: str,
    task_type: str,
    project_maturity: str,
    architecture_choice_burden: str,
    signals: dict[str, list[str]],
) -> list[str]:
    effects: set[str] = set()
    notes: list[str] = []

    if task_type == "software_build":
        effects.update({"file_create", "file_edit"})
    elif task_type in ("bug_fix", "refactor"):
        effects.add("file_edit")
    elif task_type == "deployment":
        effects.add("possible_deploy")
        notes.append("task_type=deployment")

    no_dep_hits = [w for w in _NO_DEPENDENCY_WORDS if w in text_lower]
    dep_hits = [w for w in _DEPENDENCY_WORDS if w in text_lower and not _is_negated(text_lower, w)]
    if no_dep_hits:
        notes.append(f"dependency-free requested: {no_dep_hits}")
    elif dep_hits or architecture_choice_burden != "low":
        effects.add("possible_dependency_install")
        notes.append(f"dependency signals: {dep_hits or ['ambiguous architecture']}")

    browser_hits = _find_matches(text_lower, _BROWSER_WORDS)
    server_hits = [w for w in _SERVER_WORDS if w in text_lower and not _is_negated(text_lower, w)]
    if browser_hits or server_hits:
        effects.add("possible_server_run")
        notes.append(f"server/browser signals: {browser_hits + server_hits}")

    network_hits = [w for w in _NETWORK_WORDS if w in text_lower and not _is_negated(text_lower, w)]
    if network_hits:
        effects.add("possible_network_call")
        notes.append(f"network signals: {network_hits}")

    deploy_hits = [w for w in _DEPLOY_WORDS if w in text_lower and not _is_negated(text_lower, w)]
    if deploy_hits:
        effects.add("possible_deploy")
        notes.append(f"deploy signals: {deploy_hits}")

    delete_hits = [w for w in _DELETE_WORDS if w in text_lower and not _is_negated(text_lower, w)]
    if delete_hits and project_maturity != "new_project":
        effects.add("possible_destructive_file_op")
        notes.append(f"delete signals: {delete_hits}")

    signals["likely_side_effect_classes"] = notes
    return [e for e in _SIDE_EFFECT_ORDER if e in effects]


def _missing_context_and_questions(
    task_type: str,
    project_maturity: str,
    architecture_choice_burden: str,
    deliverable: str,
) -> tuple[list[str], list[str]]:
    missing: list[str] = []
    questions: list[str] = []

    if task_type == "software_build" and architecture_choice_burden in ("medium", "high"):
        missing.append("dependency preference (framework vs. no framework / vanilla)")
        questions.append(
            "Should this use a specific framework/library, or a plain/vanilla "
            "implementation with no dependencies?"
        )
        missing.append("deployment boundary (confirm local-only vs. eventual hosting)")
        questions.append(
            "Should this remain strictly local-only, or is any future hosting/"
            "deployment step expected?"
        )

    if project_maturity == "unknown":
        missing.append("project maturity (new project vs. existing codebase)")
        questions.append(
            "Is this a brand-new project, or should it build on an existing codebase?"
        )

    if deliverable == "unspecified software artifact":
        missing.append("target deliverable format")
        questions.append("What concrete artifact should this produce (app, script, page, service, ...)?")

    return missing, questions


def _recommend_autonomy_ceiling(
    global_risk: str,
    architecture_choice_burden: str,
    global_complexity: str,
    project_maturity: str,
) -> str:
    # v0 never recommends L4_HIGH_AUTONOMY_HARD_GATES automatically: L4 is
    # reserved for well-specified, previously-reviewed workflows, not a
    # first-pass goal-intake classification.
    if global_risk == "high" or architecture_choice_burden == "high":
        return AUTONOMY_CEILING_L1
    if global_complexity == "high":
        return AUTONOMY_CEILING_L2
    if architecture_choice_burden == "medium" or project_maturity != "existing_project":
        return AUTONOMY_CEILING_L2
    if global_risk == "low" and architecture_choice_burden == "low":
        return AUTONOMY_CEILING_L3
    return AUTONOMY_CEILING_L2


def _initial_non_execution_boundary(side_effects: list[str]) -> str:
    gated = [s for s in side_effects if s.startswith("possible_")]
    if not gated:
        return (
            "No side effects identified in this prompt; treat any proposed "
            "side-effecting action as requiring human review before proceeding."
        )
    readable = ", ".join(s.replace("possible_", "").replace("_", " ") for s in gated)
    return (
        f"Do not perform {readable} without explicit human authorization; "
        "remain local-only unless the human operator authorizes otherwise."
    )


def analyze_goal(prompt: str) -> GoalIntake:
    """Deterministically analyze a free-text prompt into a `GoalIntake`.

    Offline, keyword/heuristic only. Never calls a model or network
    provider. Every derived field can be traced back to `signals`.
    """
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")

    text_lower = _lower(prompt)
    signals: dict[str, list[str]] = {}

    task_type = _detect_task_type(text_lower, signals)
    deliverable = _detect_deliverable(text_lower, signals)
    project_maturity = _detect_project_maturity(text_lower, signals)
    architecture_choice_burden = _detect_architecture_choice_burden(text_lower, task_type, signals)
    global_complexity = _detect_complexity(text_lower, task_type, signals)
    global_risk, risk_scope = _detect_risk(text_lower, signals)
    likely_side_effect_classes = _detect_side_effects(
        text_lower, task_type, project_maturity, architecture_choice_burden, signals
    )
    missing_context, clarifying_questions = _missing_context_and_questions(
        task_type, project_maturity, architecture_choice_burden, deliverable
    )
    recommended_autonomy_ceiling = _recommend_autonomy_ceiling(
        global_risk, architecture_choice_burden, global_complexity, project_maturity
    )
    initial_non_execution_boundary = _initial_non_execution_boundary(likely_side_effect_classes)

    return GoalIntake(
        prompt=prompt,
        task_type=task_type,
        deliverable=deliverable,
        project_maturity=project_maturity,
        architecture_choice_burden=architecture_choice_burden,
        global_complexity=global_complexity,
        global_risk=global_risk,
        risk_scope=risk_scope,
        likely_side_effect_classes=likely_side_effect_classes,
        missing_context=missing_context,
        clarifying_questions=clarifying_questions,
        recommended_autonomy_ceiling=recommended_autonomy_ceiling,
        initial_non_execution_boundary=initial_non_execution_boundary,
        signals=signals,
    )
