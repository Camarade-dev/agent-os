from admissible.mission_contract import build_mission_contract, extract_runtime_observability_intent


def _intent_for(goal_text: str) -> dict:
    contract = build_mission_contract(goal_text).to_dict()
    return extract_runtime_observability_intent(contract)


def test_extracts_debug_interface_and_snapshot_fields_generically():
    intent = _intent_for(
        """Build a widget dashboard.

Requirements:
- Expose a read-only debugging interface: window.__DASH__ with a snapshot returning at least: widgetCount, refreshRate.
"""
    )
    assert intent["declared_debug_interface"] == "window.__DASH__"
    assert intent["declared_snapshot_method"] is True
    assert intent["required_snapshot_fields"] == ["widgetCount", "refreshRate"]


def test_extracts_query_flag_for_debug_overlay():
    intent = _intent_for("Requirements:\n- The overlay is enabled with ?debug=1.\n")
    assert "?debug=1" in intent["query_flags"]


def test_extracts_numeric_thresholds_without_hardcoding_a_subject():
    intent = _intent_for("Requirements:\n- At least 7 widgets must render on screen.\n")
    assert len(intent["numeric_thresholds"]) == 1
    threshold = intent["numeric_thresholds"][0]
    assert threshold["operator"] == "gte"
    assert threshold["value"] == 7
    assert threshold["subject"] == "widgets"


def test_extracts_at_most_and_exactly_thresholds():
    intent = _intent_for("Requirements:\n- At most 3 popups may appear.\n- Exactly 1 header must render.\n")
    operators = {t["operator"] for t in intent["numeric_thresholds"]}
    assert operators == {"lte", "eq"}


def test_extracts_named_controls_generically():
    intent = _intent_for("Requirements:\n- Press Z to zoom.\n- Pause and resume with Q.\n")
    controls = {(c["key"], c["action"]) for c in intent["named_controls"]}
    assert ("Z", "zoom") in controls
    assert ("Q", "pause_resume") in controls


def test_extracts_temporal_and_stability_requirements():
    intent = _intent_for(
        "Requirements:\n"
        "- The widget must not create duplicate animation loops.\n"
        "- No uncaught errors may occur.\n"
        "- The app must remain playable after repeated restart cycles.\n"
    )
    assert "no_duplicate_animation_loops" in intent["temporal_requirements"]
    assert "stable_after_repeated_restart_cycles" in intent["temporal_requirements"]
    assert "no_uncaught_errors" in intent["runtime_stability_requirements"]


def test_extracts_dom_tokens_when_present():
    intent = _intent_for("Requirements:\n- The #widget-list and .status-badge must be visible.\n")
    assert "#widget-list" in intent["dom_requirements"]
    assert ".status-badge" in intent["dom_requirements"]


def test_counts_human_observation_requirements_without_dropping_them():
    intent = _intent_for("Requirements:\n- The animation must look smooth and polished.\n")
    assert intent["human_observation_requirement_count"] >= 1


def test_empty_goal_yields_all_empty_lists_not_errors():
    intent = _intent_for("Build a thing.\n\nRequirements:\n- Do the thing.\n")
    assert intent["query_flags"] == []
    assert intent["declared_debug_interface"] is None
    assert intent["numeric_thresholds"] == []
    assert intent["named_controls"] == []


def test_no_duplicate_matches_when_a_requirement_line_also_appears_in_raw_goal():
    # The bullet text is naturally present in raw_goal too; extraction must
    # not double-count the same sentence.
    intent = _intent_for("Requirements:\n- At least 12 active bots must move.\n")
    assert len(intent["numeric_thresholds"]) == 1


def test_extracts_snapshot_fields_from_structured_subrequirements():
    goal = (
        "Build a demo.\n\n"
        "Acceptance criteria:\n"
        "1. Expose window.__DEMO__.snapshot() returning exactly these fields:\n"
        "   - alpha: number\n"
        "   - beta: string\n"
    )
    intent = _intent_for(goal)
    assert intent["required_snapshot_fields"] == ["alpha", "beta"]


def test_extraction_never_hardcodes_a_specific_game_or_field_name():
    # The same generic patterns fire regardless of the domain noun used.
    dashboard_intent = _intent_for("Requirements:\n- At least 5 charts must render.\n")
    game_intent = _intent_for("Requirements:\n- At least 5 bots must move.\n")
    assert dashboard_intent["numeric_thresholds"][0]["value"] == 5
    assert game_intent["numeric_thresholds"][0]["value"] == 5
    assert dashboard_intent["numeric_thresholds"][0]["subject"] != game_intent["numeric_thresholds"][0]["subject"]
