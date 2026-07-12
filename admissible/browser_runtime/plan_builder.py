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
    r"|\?debug=1\b|\bdebug(?:ging)? interface\b|\bdebug overlay\b"
    r"|\buncaught\s+page\s+exceptions?\b|\bmaterial\s+console\s+errors?\b",
    re.I,
)
_POINTER_STEERING_RE = re.compile(
    r"\bpointer[\-\s]driven\b|\bmoving the mouse\b|\bpointer changes\b|\bcontinuous.*\bsteering\b",
    re.I,
)
# RUN_053: word-boundary matched -- never a bare substring, so a criterion
# whose text merely NAMES a nested field called "boosting" (e.g. the debug
# interface's own "player: object containing ... boosting" subrequirement)
# is never misclassified as a dynamic boost-control criterion itself.
_BOOST_WORD_RE = re.compile(r"\bboost\b", re.I)
_PAUSE_RESUME_WORD_RE = re.compile(r"\b(?:pause|resume)\b", re.I)
_RESTART_WORD_RE = re.compile(r"\brestart\b", re.I)


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
    def __init__(self, contract: dict[str, Any], ledger: list[dict[str, Any]], *, workspace_root: str | None = None) -> None:
        self.contract = contract
        self.ledger = ledger
        self.intent = mc.extract_runtime_observability_intent(contract)
        self.debug_interface = self.intent.get("declared_debug_interface")
        self.required_fields: list[str] = list(self.intent.get("required_snapshot_fields") or [])
        # RUN_053: nested sub-fields (e.g. "player.boosting") kept separate
        # from `required_fields` -- callers that assert "exactly these
        # top-level fields exist" (the debug-overlay presence loop) must
        # never also see a nested path as if it were its own top-level field.
        # Used only via `_nested_field_candidates()` in the boost/pause
        # classify branches below.
        self.nested_fields: list[str] = list(self.intent.get("nested_snapshot_fields") or [])
        self.steps: list[dict[str, Any]] = []
        self.criteria: list[BrowserRuntimeCriterionPlan] = []
        self._contract_snapshot_taken = False
        self.missing_debug_fields: list[str] = []
        self.missing_dom_observables: list[str] = []
        self.missing_control_mappings: list[str] = []
        # RUN_053: a Mission Contract criterion often only says a control
        # must be "documented" without naming the literal key -- the actual
        # binding lives in the deliverable the agent already wrote (e.g. a
        # LOCAL_DEV.md controls table). Read-only, best-effort; empty when no
        # workspace/doc is available yet (matches every pre-existing test
        # fixture, none of which write a real controls doc).
        self.documented_controls: list[dict[str, Any]] = mc.extract_documented_control_bindings(
            workspace_root, list(contract.get("mandatory_paths") or [])
        )

    def _controls_for_text(self, text: str) -> list[dict[str, Any]]:
        """Documented controls whose action keyword also appears in this
        criterion's own text -- never offered to an unrelated criterion."""

        lower = text.lower()
        matches = []
        for control in self.documented_controls:
            action = control.get("action")
            if action == "boost" and _BOOST_WORD_RE.search(lower):
                matches.append(control)
            elif action == "pause_resume" and _PAUSE_RESUME_WORD_RE.search(lower):
                matches.append(control)
            elif action == "restart" and _RESTART_WORD_RE.search(lower):
                matches.append(control)
        return matches

    def _nested_field_candidates(self) -> list[str]:
        """Top-level fields first (so an existing exact top-level match, e.g.
        ac_004's "player", is never displaced), then nested sub-fields."""

        return self.required_fields + self.nested_fields

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
            current_disposition == "evidence_required"
            and (
                _RUNTIME_CHECKABLE_HINT_RE.search(text)
                or (
                    self.required_fields
                    and (
                        _extract_signals_for_text(text).get("numeric_thresholds")
                        or _POINTER_STEERING_RE.search(text)
                    )
                )
            )
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

        if mc.infer_verification_disposition(text) == "human_observation_required" and not _POINTER_STEERING_RE.search(text):
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
        # RUN_053: fall back to documented controls (discovered from the
        # deliverable's own docs, e.g. a LOCAL_DEV.md controls table) only
        # when this criterion's own text carries no "press X to Y" phrasing
        # of its own -- contract-text-derived controls always take priority.
        if not signals.get("named_controls"):
            doc_controls = self._controls_for_text(text)
            if doc_controls:
                signals = dict(signals)
                signals["named_controls"] = doc_controls
        assertion_ids: list[str] = []
        required_observables: list[str] = []
        supported = False
        unsupported_reason: str | None = None
        human_subaspect = mc.infer_human_observation_subaspect(text)

        boost_controls = [c for c in signals.get("named_controls") or [] if c.get("action") == "boost"]
        pause_resume_controls = [c for c in signals.get("named_controls") or [] if c.get("action") == "pause_resume"]

        # RUN_053: a boost/pause-resume-shaped criterion is always claimed by
        # its dedicated branch below -- including when no documented control
        # was discoverable -- so it is explicitly flagged as a control-mapping
        # gap instead of silently falling through to a later, unrelated
        # generic branch (e.g. the "any declared field mentioned by name"
        # fallback, which would otherwise weakly "pass" boost merely because
        # its sentence happens to contain the word "player").
        if _BOOST_WORD_RE.search(text):
            # PART 2.A: Space (or whatever key is documented) key_down/key_up
            # establishes the boolean boost-state transition. A boolean alone
            # never proves "visibly increases speed" or "bounded cost" (the
            # rest of criterion 7's text) -- when no distinct speed/cost
            # field is declared, that sub-aspect is recorded as a genuine
            # instrumentation gap rather than folded into a false pass.
            if not boost_controls:
                unsupported_reason = "control_effect_not_mapped_to_declared_snapshot_field"
                required_observables.append("boosting_control_key")
                self.missing_control_mappings.append(cid)
            else:
                key = boost_controls[0]["key"]
                boost_field = _find_matching_field({"boost", "boosting"}, self._nested_field_candidates())
                self.steps.append({"type": "key_down", "key": key, "criterion_id": cid})
                self.steps.append({"type": "wait_bounded", "duration_ms": 150, "criterion_id": cid})
                if boost_field is not None:
                    self._ensure_contract_snapshot()
                down_snap = f"{cid}_boost_down"
                self.steps.append({"type": "debug_snapshot", "name": down_snap, "criterion_id": cid})
                self.steps.append({"type": "key_up", "key": key, "criterion_id": cid})
                self.steps.append({"type": "wait_bounded", "duration_ms": 150, "criterion_id": cid})
                up_snap = f"{cid}_boost_up"
                self.steps.append({"type": "debug_snapshot", "name": up_snap, "criterion_id": cid})
                if boost_field is not None and self._contract_snapshot_taken:
                    down_aid = f"{cid}_boost_active"
                    up_aid = f"{cid}_boost_released"
                    self.steps.append(
                        {"type": "assert_json_path_equals", "snapshot": down_snap, "path": boost_field, "expected": True, "criterion_id": cid, "assertion_id": down_aid}
                    )
                    self.steps.append(
                        {"type": "assert_json_path_equals", "snapshot": up_snap, "path": boost_field, "expected": False, "criterion_id": cid, "assertion_id": up_aid}
                    )
                    assertion_ids += [down_aid, up_aid]
                    supported = True
                    cost_field = _find_matching_field({"speed", "cost"}, self.required_fields)
                    if cost_field is None:
                        # A real gap, not a silent pass: the boolean toggle is
                        # verified, but "visibly increases speed" / "bounded
                        # gameplay cost" has no declared observable yet.
                        unsupported_reason = "threshold_subject_not_mapped_to_declared_snapshot_field"
                        required_observables.append("boost_speed_or_cost_field")
                        self.missing_debug_fields.append("boost_speed_or_cost")
                else:
                    unsupported_reason = "control_effect_not_mapped_to_declared_snapshot_field"
                    required_observables.append("boosting_state_field")
                    self.missing_control_mappings.append(cid)

        elif (
            _PAUSE_RESUME_WORD_RE.search(text)
            and signals.get("temporal_requirements")
            and "no_duplicate_animation_loops" in signals["temporal_requirements"]
        ):
            # PART 2.B: pause/resume + loop-liveness are safely, deterministically
            # triggerable. Restart-after-death is deliberately NOT attempted here
            # (it requires the player to already be dead, and forcing death is
            # explicitly prohibited) -- that sub-aspect is routed to human
            # observation while the pause/resume/loop-alive evidence is kept.
            phase_field = _find_matching_field({"phase", "state"}, self.required_fields)
            loop_field = _find_matching_field({"loop", "animation"}, self.required_fields)
            if not pause_resume_controls:
                unsupported_reason = "control_effect_not_mapped_to_declared_snapshot_field"
                required_observables.append("pause_resume_control_key")
                self.missing_control_mappings.append(cid)
            elif phase_field is None or loop_field is None:
                unsupported_reason = "loop_counter_field_or_restart_control_not_declared"
                required_observables.append("phase_and_loop_counter_field")
                self.missing_control_mappings.append(cid)
            else:
                key = pause_resume_controls[0]["key"]
                self._ensure_contract_snapshot()
                paused_snap = f"{cid}_paused"
                resumed_snap = f"{cid}_resumed"
                self.steps.append({"type": "key_press", "key": key, "criterion_id": cid})
                self.steps.append({"type": "wait_bounded", "duration_ms": 150, "criterion_id": cid})
                self.steps.append({"type": "debug_snapshot", "name": paused_snap, "criterion_id": cid})
                self.steps.append({"type": "key_press", "key": key, "criterion_id": cid})
                self.steps.append({"type": "wait_bounded", "duration_ms": 200, "criterion_id": cid})
                self.steps.append({"type": "debug_snapshot", "name": resumed_snap, "criterion_id": cid})
                # The criterion's own text names the literal lifecycle state
                # words when it does ("running, paused, dead, ..."); use them
                # verbatim as expected values only when present, otherwise
                # fall back to a weaker (still real) "changed" assertion
                # rather than guessing an enum spelling the contract never
                # stated.
                has_paused_word = bool(re.search(r"\bpaused\b", text, re.I))
                has_running_word = bool(re.search(r"\brunning\b", text, re.I))
                pause_aid = f"{cid}_phase_paused"
                resume_aid = f"{cid}_phase_running"
                if has_paused_word and has_running_word:
                    self.steps.append(
                        {"type": "assert_json_path_equals", "snapshot": paused_snap, "path": phase_field, "expected": "paused", "criterion_id": cid, "assertion_id": pause_aid}
                    )
                    self.steps.append(
                        {"type": "assert_json_path_equals", "snapshot": resumed_snap, "path": phase_field, "expected": "running", "criterion_id": cid, "assertion_id": resume_aid}
                    )
                else:
                    self.steps.append(
                        {"type": "compare_snapshot_path_changed", "before_snapshot": "contract", "after_snapshot": paused_snap, "path": phase_field, "criterion_id": cid, "assertion_id": pause_aid}
                    )
                    self.steps.append(
                        {"type": "compare_snapshot_path_changed", "before_snapshot": paused_snap, "after_snapshot": resumed_snap, "path": phase_field, "criterion_id": cid, "assertion_id": resume_aid}
                    )
                loop_aid = f"{cid}_loop_alive_across_pause"
                self.steps.append(
                    {"type": "compare_snapshot_path_increased", "before_snapshot": "contract", "after_snapshot": resumed_snap, "path": loop_field, "criterion_id": cid, "assertion_id": loop_aid}
                )
                assertion_ids += [pause_aid, resume_aid, loop_aid]
                supported = True
                # Restart-after-death always stays a human-observation
                # sub-aspect of this criterion (never silently dropped, never
                # blocking the pause/resume evidence above from being kept).
                # Only set once real pause/resume evidence exists -- when no
                # phase/loop field was even found, this stays a plain
                # instrumentation gap instead of a misleading human-review
                # routing for a criterion nothing was ever observed about.
                human_subaspect = True

        elif signals.get("runtime_stability_requirements"):
            aid = f"{cid}_no_uncaught_errors"
            self.steps.append({"type": "assert_no_page_exceptions", "criterion_id": cid, "assertion_id": aid})
            self.steps.append({"type": "assert_console_clean", "criterion_id": cid, "assertion_id": f"{cid}_console_clean"})
            assertion_ids += [aid, f"{cid}_console_clean"]
            supported = True
            if re.search(r"\bexternal\b.*\b(network|request|api|access)\b|\bno external\b", text, re.I):
                ext_aid = f"{cid}_no_external_requests"
                self.steps.append({"type": "assert_no_external_requests", "criterion_id": cid, "assertion_id": ext_aid})
                assertion_ids.append(ext_aid)

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

        elif _POINTER_STEERING_RE.search(text):
            field = _find_matching_field({"player", "heading", "x", "y"}, self.required_fields)
            self.steps.append({"type": "pointer_move", "x": 200, "y": 200, "criterion_id": cid, "assertion_id": f"{cid}_pointer_move"})
            assertion_ids.append(f"{cid}_pointer_move")
            if field is None:
                unsupported_reason = "control_effect_not_mapped_to_declared_snapshot_field"
                required_observables.append("player_heading_or_position_field")
                self.missing_control_mappings.append(cid)
            else:
                self._ensure_contract_snapshot()
                after_name = f"{cid}_after_pointer"
                self.steps.append({"type": "debug_snapshot", "name": after_name, "criterion_id": cid})
                aid = f"{cid}_pointer_effect"
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
                for field_name in self.required_fields:
                    field_aid = f"{cid}_debug_field_{field_name}"
                    self.steps.append(
                        {
                            "type": "assert_json_path_present",
                            "snapshot": f"{cid}_debug_overlay",
                            "path": field_name,
                            "criterion_id": cid,
                            "assertion_id": field_aid,
                        }
                    )
                    assertion_ids.append(field_aid)
            if "loopCount" in self.required_fields and re.search(r"\bloopCount\b.*\bmust increase\b|\bmust increase\b.*\bloop\b", text, re.I):
                self.steps.append({"type": "wait_bounded", "duration_ms": 300, "criterion_id": cid})
                loop_after = f"{cid}_loop_tick"
                self.steps.append({"type": "debug_snapshot", "name": loop_after, "criterion_id": cid})
                loop_aid = f"{cid}_loop_count_increased"
                self.steps.append(
                    {
                        "type": "compare_snapshot_path_increased",
                        "before_snapshot": f"{cid}_debug_overlay",
                        "after_snapshot": loop_after,
                        "path": "loopCount",
                        "criterion_id": cid,
                        "assertion_id": loop_aid,
                    }
                )
                assertion_ids.append(loop_aid)
            if "debugVisible" in self.required_fields and "?debug=1" in text:
                vis_aid = f"{cid}_debug_visible"
                self.steps.append(
                    {
                        "type": "assert_json_path_equals",
                        "snapshot": f"{cid}_debug_overlay",
                        "path": "debugVisible",
                        "expected": True,
                        "criterion_id": cid,
                        "assertion_id": vis_aid,
                    }
                )
                assertion_ids.append(vis_aid)
            supported = True

        elif self.required_fields and self.debug_interface is not None:
            mentioned_fields = [
                field_name
                for field_name in self.required_fields
                if re.search(rf"\b{re.escape(field_name)}\b", text, re.I)
            ]
            mentioned_field = max(mentioned_fields, key=len) if mentioned_fields else None
            if mentioned_field is not None:
                self._ensure_contract_snapshot()
                aid = f"{cid}_field_{mentioned_field}"
                self.steps.append(
                    {
                        "type": "assert_json_path_present",
                        "snapshot": "contract",
                        "path": mentioned_field,
                        "criterion_id": cid,
                        "assertion_id": aid,
                    }
                )
                assertion_ids.append(aid)
                supported = True
            else:
                # RUN_053: entering this branch (required_fields + a debug
                # interface exist) must not silently swallow a criterion that
                # turned out to mention none of the declared fields -- without
                # this, `unsupported_reason` stayed None and the final `else`
                # below was unreachable, so a genuinely unsupported criterion
                # could keep `unsupported_verifier` disposition but no reason
                # at all, which the repair-vs-finalize decision then could
                # never classify as instrumentation-fixable.
                unsupported_reason = "no_safe_observable_derivable"

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
                human_observation_required=human_subaspect,
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

    builder = _Builder(contract, ledger, workspace_root=workspace_root)
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
