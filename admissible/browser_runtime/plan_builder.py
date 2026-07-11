"""Mission Contract -> BrowserRuntimeVerificationPlan (PART F, PART N).

Deterministic, pattern-driven, and generic: nothing here names a game, a
bot field, a selector, or an acceptance criterion. Every step this module
emits is derived from a Mission Contract's own text (via
``admissible.mission_contract.extract_runtime_observability_intent``) or
from a criterion's own source text. When no safe observable can be derived
for a criterion, the criterion is still represented -- as
``unsupported_verifier`` or ``human_observation_required`` -- and never
silently dropped or auto-passed (PART F.29).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from admissible import mission_contract as mc
from admissible.browser_runtime import limits
from admissible.browser_runtime.models import BrowserRuntimeCriterionPlan, BrowserRuntimeVerificationPlan, now_iso

_STOPWORDS = {"the", "a", "an", "of", "must", "will", "shall", "should", "may", "can", "is", "are", "to", "and"}
_MIN_TOKEN_LEN = 2

_RUNTIME_CHECKABLE_HINT_RE = re.compile(
    r"\bno uncaught errors?\b"
    r"|\bexternal\b.*\b(?:network|request|api|access)\b|\bno external\b"
    r"|\?debug=1\b|\bdebug(?:ging)? interface\b|\bdebug overlay\b",
    re.I,
)


def _tokenize_field(name: str) -> set[str]:
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return {t.lower() for t in re.split(r"[_\-\s]+", spaced) if t}


def _singular(word: str) -> str:
    return word[:-1] if word.endswith("s") and len(word) > 3 else word


def _subject_words(subject: str) -> set[str]:
    return {
        _singular(w)
        for w in re.split(r"\s+", subject.lower())
        if w and w not in _STOPWORDS and len(w) >= _MIN_TOKEN_LEN
    }


def _find_matching_field(words: set[str], candidate_fields: list[str]) -> str | None:
    for field_name in candidate_fields:
        tokens = _tokenize_field(field_name)
        for word in words:
            if word in tokens or any(word in t or t in word for t in tokens):
                return field_name
    return None


def _extract_signals_for_text(text: str) -> dict[str, Any]:
    fake_contract = {"raw_goal": text, "mandatory_requirements": [], "explicit_acceptance_criteria": [], "mandatory_paths": []}
    return mc.extract_runtime_observability_intent(fake_contract)


def _plan_sha256(mission_contract: dict[str, Any]) -> str:
    payload = json.dumps(mission_contract, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class _Builder:
    def __init__(self, contract: dict[str, Any], ledger: list[dict[str, Any]]) -> None:
        self.contract = contract
        self.ledger = ledger
        self.intent = mc.extract_runtime_observability_intent(contract)
        self.debug_interface = self.intent.get("declared_debug_interface")
        self.required_fields: list[str] = list(self.intent.get("required_snapshot_fields") or [])
        self.steps: list[dict[str, Any]] = []
        self.criteria: list[BrowserRuntimeCriterionPlan] = []
        self._contract_snapshot_taken = False
        self.missing_debug_fields: list[str] = []
        self.missing_dom_observables: list[str] = []
        self.missing_control_mappings: list[str] = []

    def _ensure_contract_snapshot(self) -> None:
        if self._contract_snapshot_taken or not self.debug_interface:
            return
        try:
            limits.validate_debug_interface(self.debug_interface)
        except ValueError:
            self.debug_interface = None
            return
        self.steps.append({"type": "debug_snapshot", "name": "contract"})
        self._contract_snapshot_taken = True

    def _bootstrap(self) -> None:
        self.steps.append({"type": "navigate_local"})
        self.steps.append({"type": "wait_for_load"})

    def _classify(self, criterion: dict[str, Any]) -> None:
        cid = criterion["criterion_id"]
        text = criterion["source_text"]
        current_disposition = criterion.get("verification_disposition")

        # RUN_042's own classifier already marks "unsupported_verifier" for
        # anything it recognized as needing dynamic behavior -- that is
        # exactly the pre-existing set this module's job is to try to make
        # concretely checkable. "evidence_required" criteria are a broader,
        # unopinionated bucket; only attempt those whose text matches one of
        # the generic, high-confidence patterns below (debug interface,
        # external-network prohibition, "no uncaught errors"), since
        # upgrading a criterion that has no executable check today to a real
        # runtime assertion is strictly additive rigor, never a regression.
        # Everything else passes through with its settled disposition.
        #
        # "deterministic_runtime" is also always re-attempted: RUN_044
        # rebuilds this plan from scratch on every attempt/retry against the
        # same durable ledger, and a criterion this module itself already
        # wrote that disposition onto (via apply_runtime_plan_to_ledger) must
        # keep regenerating its real steps on rebuild, never fall through to
        # the zero-step passthrough branch below just because the ledger
        # already carries the disposition it produced last time.
        should_attempt = current_disposition in ("unsupported_verifier", "deterministic_runtime") or (
            current_disposition == "evidence_required" and _RUNTIME_CHECKABLE_HINT_RE.search(text)
        )
        if not should_attempt:
            self.criteria.append(
                BrowserRuntimeCriterionPlan(
                    criterion_id=cid,
                    disposition=current_disposition or "evidence_required",
                    assertion_ids=[],
                    required_observables=[],
                    supported=True,
                    unsupported_reason=None,
                    human_observation_required=current_disposition == "human_observation_required",
                )
            )
            return

        if mc.infer_verification_disposition(text) == "human_observation_required":
            self.criteria.append(
                BrowserRuntimeCriterionPlan(
                    criterion_id=cid,
                    disposition="human_observation_required",
                    assertion_ids=[],
                    required_observables=[],
                    supported=True,
                    unsupported_reason=None,
                    human_observation_required=True,
                )
            )
            return

        signals = _extract_signals_for_text(text)
        assertion_ids: list[str] = []
        required_observables: list[str] = []
        supported = False
        unsupported_reason: str | None = None

        if signals.get("runtime_stability_requirements"):
            aid = f"{cid}_no_uncaught_errors"
            self.steps.append({"type": "assert_no_page_exceptions", "criterion_id": cid, "assertion_id": aid})
            self.steps.append({"type": "assert_console_clean", "criterion_id": cid, "assertion_id": f"{cid}_console_clean"})
            assertion_ids += [aid, f"{cid}_console_clean"]
            supported = True

        elif re.search(r"\bexternal\b.*\b(network|request|api|access)\b|\bno external\b", text, re.I):
            aid = f"{cid}_no_external_requests"
            self.steps.append({"type": "assert_no_external_requests", "criterion_id": cid, "assertion_id": aid})
            assertion_ids.append(aid)
            supported = True

        elif signals.get("numeric_thresholds"):
            for i, threshold in enumerate(signals["numeric_thresholds"]):
                words = _subject_words(threshold["subject"])
                field = _find_matching_field(words, self.required_fields)
                required_observables.append(threshold["subject"])
                if field is None:
                    unsupported_reason = "threshold_subject_not_mapped_to_declared_snapshot_field"
                    self.missing_debug_fields.append(threshold["subject"])
                    continue
                self._ensure_contract_snapshot()
                if not self._contract_snapshot_taken:
                    unsupported_reason = "no_debug_interface_declared"
                    continue
                step_type = {"gte": "assert_json_path_gte", "lte": "assert_json_path_lte", "eq": "assert_json_path_equals"}[threshold["operator"]]
                aid = f"{cid}_threshold_{i}"
                step: dict[str, Any] = {
                    "type": step_type,
                    "snapshot": "contract",
                    "path": field,
                    "expected": threshold["value"],
                    "criterion_id": cid,
                    "assertion_id": aid,
                }
                self.steps.append(step)
                assertion_ids.append(aid)
                supported = True

        elif signals.get("named_controls") and signals.get("temporal_requirements") and any(
            t in ("no_duplicate_animation_loops", "stable_after_repeated_restart_cycles") for t in signals["temporal_requirements"]
        ):
            restart_controls = [c for c in signals["named_controls"] if c["action"] == "restart"]
            loop_field = _find_matching_field({"loop", "animation"}, self.required_fields)
            if not restart_controls or loop_field is None:
                unsupported_reason = "loop_counter_field_or_restart_control_not_declared"
                required_observables.append("restart_key_and_loop_counter_field")
                self.missing_control_mappings.append(cid)
            else:
                self._ensure_contract_snapshot()
                key = restart_controls[0]["key"]
                snapshot_names = []
                for i in range(3):
                    self.steps.append({"type": "key_press", "key": key, "criterion_id": cid})
                    self.steps.append({"type": "wait_bounded", "duration_ms": 200, "criterion_id": cid})
                    name = f"{cid}_restart_{i}"
                    self.steps.append({"type": "debug_snapshot", "name": name})
                    snapshot_names.append(name)
                aid = f"{cid}_loop_count_bounded"
                self.steps.append(
                    {
                        "type": "assert_json_path_lte",
                        "snapshot": snapshot_names[-1],
                        "path": loop_field,
                        "expected": 1,
                        "criterion_id": cid,
                        "assertion_id": aid,
                    }
                )
                assertion_ids.append(aid)
                supported = True

        elif signals.get("named_controls"):
            control = signals["named_controls"][0]
            field = _find_matching_field(set(control["action"].split("_")), self.required_fields)
            self.steps.append({"type": "key_press", "key": control["key"], "criterion_id": cid, "assertion_id": f"{cid}_control_dispatch"})
            assertion_ids.append(f"{cid}_control_dispatch")
            if field is None:
                unsupported_reason = "control_effect_not_mapped_to_declared_snapshot_field"
                required_observables.append(f"{control['action']}_state_field")
                self.missing_control_mappings.append(cid)
            else:
                self._ensure_contract_snapshot()
                after_name = f"{cid}_after_control"
                self.steps.append({"type": "debug_snapshot", "name": after_name})
                aid = f"{cid}_control_effect"
                self.steps.append(
                    {
                        "type": "compare_snapshot_path_changed",
                        "before_snapshot": "contract",
                        "after_snapshot": after_name,
                        "path": field,
                        "criterion_id": cid,
                        "assertion_id": aid,
                    }
                )
                assertion_ids.append(aid)
                supported = True

        elif re.search(r"\?debug=1\b|\bdebug(?:ging)? interface\b|\bdebug overlay\b", text, re.I) and self.debug_interface is not None:
            query_flag = "debug=1" if "?debug=1" in (signals.get("query_flags") or self.intent.get("query_flags") or []) else ""
            if query_flag:
                self.steps.append({"type": "navigate_local", "query": query_flag, "criterion_id": cid})
                self.steps.append({"type": "wait_for_load", "criterion_id": cid})
            aid = f"{cid}_debug_interface_present"
            self.steps.append({"type": "debug_snapshot", "name": f"{cid}_debug_overlay", "criterion_id": cid, "assertion_id": aid})
            assertion_ids.append(aid)
            if self.required_fields:
                field_aid = f"{cid}_debug_overlay_fields"
                self.steps.append(
                    {
                        "type": "assert_json_path_present",
                        "snapshot": f"{cid}_debug_overlay",
                        "path": self.required_fields[0],
                        "criterion_id": cid,
                        "assertion_id": field_aid,
                    }
                )
                assertion_ids.append(field_aid)
            supported = True

        else:
            unsupported_reason = "no_safe_observable_derivable"

        if supported:
            # Fully or partially successful: keep unsupported_reason (if any
            # sub-requirement still failed) so partial observability stays
            # visible even though the criterion itself is now runtime-backed.
            final_disposition = "deterministic_runtime"
        elif current_disposition == "unsupported_verifier":
            final_disposition = "unsupported_verifier"
        else:
            # This "evidence_required" criterion matched a runtime-checkable
            # hint but the attempt still failed (e.g. no debug interface
            # declared) -- leave its original disposition untouched rather
            # than manufacturing a capability gap RUN_042 never flagged.
            final_disposition = current_disposition
            unsupported_reason = None

        if final_disposition == "unsupported_verifier":
            self.missing_dom_observables.append(cid)

        self.criteria.append(
            BrowserRuntimeCriterionPlan(
                criterion_id=cid,
                disposition=final_disposition,
                assertion_ids=assertion_ids,
                required_observables=required_observables,
                supported=final_disposition != "unsupported_verifier",
                unsupported_reason=unsupported_reason,
                human_observation_required=False,
            )
        )

    def build(self, *, workspace_root: str, entrypoint_path: str, entrypoint_query: str, max_duration_ms: int, max_steps: int) -> BrowserRuntimeVerificationPlan:
        self._bootstrap()
        mandatory = [item for item in self.ledger if item.get("mandatory", True)]
        for criterion in mandatory:
            self._classify(criterion)
        # Global stability/network checks always run once, tagged to any
        # criteria whose text specifically called them out; if the contract
        # never mentions them, they still run untagged as run-health context.
        if not any(step.get("type") in ("assert_console_clean", "assert_no_page_exceptions") for step in self.steps):
            self.steps.append({"type": "assert_console_clean"})
            self.steps.append({"type": "assert_no_page_exceptions"})
        if not any(step.get("type") == "assert_no_external_requests" for step in self.steps):
            self.steps.append({"type": "assert_no_external_requests"})

        effective_max_steps = max_steps
        if len(self.steps) > effective_max_steps:
            effective_max_steps = min(len(self.steps), limits.ABSOLUTE_MAX_STEPS)

        mission_contract_sha256 = self.contract.get("raw_goal_sha256") or _plan_sha256(self.contract)
        return BrowserRuntimeVerificationPlan(
            plan_version=limits.BROWSER_RUNTIME_PLAN_VERSION,
            mission_contract_sha256=mission_contract_sha256,
            workspace_root=workspace_root,
            entrypoint_path=entrypoint_path,
            entrypoint_query=entrypoint_query,
            target_origin_policy="loopback_only",
            debug_interface=self.debug_interface,
            max_duration_ms=max_duration_ms,
            max_steps=effective_max_steps,
            max_input_events=limits.ABSOLUTE_MAX_INPUT_EVENTS,
            max_snapshots=limits.ABSOLUTE_MAX_SNAPSHOTS,
            max_screenshots=limits.ABSOLUTE_MAX_SCREENSHOTS,
            max_console_entries=limits.DEFAULT_MAX_CONSOLE_ENTRIES,
            max_network_events=limits.DEFAULT_MAX_NETWORK_EVENTS,
            criteria=self.criteria,
            steps=self.steps,
            generated_at=now_iso(),
        )


def build_runtime_verification_plan(
    contract: dict[str, Any],
    ledger: list[dict[str, Any]],
    *,
    workspace_root: str,
    entrypoint_path: str | None = None,
    entrypoint_query: str = "",
    max_duration_ms: int = limits.DEFAULT_MAX_DURATION_MS,
    max_steps: int = limits.DEFAULT_MAX_STEPS,
) -> tuple[BrowserRuntimeVerificationPlan, dict[str, Any]]:
    """Build a contract-derived runtime plan plus its observability coverage report.

    ``entrypoint_path`` overrides the contract-derived entrypoint (falls
    back to the first mandatory ``.html``/``.htm`` path, then ``index.html``).
    """

    builder = _Builder(contract, ledger)
    entrypoint = entrypoint_path or builder.intent.get("browser_entrypoint") or "index.html"
    plan = builder.build(
        workspace_root=workspace_root,
        entrypoint_path=entrypoint,
        entrypoint_query=entrypoint_query,
        max_duration_ms=max_duration_ms,
        max_steps=max_steps,
    )
    coverage = runtime_observability_coverage_report(builder.ledger, plan, builder)
    return plan, coverage


def runtime_observability_coverage_report(
    ledger: list[dict[str, Any]],
    plan: BrowserRuntimeVerificationPlan,
    builder: "_Builder",
) -> dict[str, Any]:
    """PART F.28: RuntimeObservabilityCoverageReport."""

    mandatory = [item for item in ledger if item.get("mandatory", True)]
    runtime_criteria = [c for c in plan.criteria if c.disposition in ("deterministic_runtime", "unsupported_verifier") or c.human_observation_required]
    observable = [c for c in plan.criteria if c.supported]
    executable = [c for c in plan.criteria if c.disposition == "deterministic_runtime" and c.supported]
    # A criterion is "partially observable" when it has at least one working
    # runtime assertion but also carries an unsupported_reason -- i.e. some
    # (but not all) of its sub-requirements were derivable.
    partially_observable = [c.criterion_id for c in plan.criteria if c.supported and c.assertion_ids and c.unsupported_reason]
    unobservable = [c.criterion_id for c in plan.criteria if not c.supported and not c.human_observation_required]
    human_ids = [c.criterion_id for c in plan.criteria if c.human_observation_required]

    return {
        "runtime_criterion_count": len(runtime_criteria),
        "observable_criterion_count": len(observable),
        "executable_runtime_criterion_count": len(executable),
        "partially_observable_criterion_ids": partially_observable,
        "unobservable_criterion_ids": unobservable,
        "missing_debug_fields": sorted(set(builder.missing_debug_fields)),
        "missing_dom_observables": sorted(set(builder.missing_dom_observables)),
        "missing_control_mappings": sorted(set(builder.missing_control_mappings)),
        "human_observation_criterion_ids": human_ids,
        "coverage_complete": len(unobservable) == 0,
        "total_mandatory_criteria": len(mandatory),
    }
