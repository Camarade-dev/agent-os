"""Slice ADMISSIBLE_EVIDENCE_007_STRUCTURED_EVIDENCE_PACKETS tests."""

from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import ControlSurfaceController
from admissible.run_loop import (
    EvidenceRecord,
    LIFECYCLE_BLOCKED_BY_NON_EVIDENCE_GATE,
    LIFECYCLE_EVIDENCE_INSUFFICIENT_STILL_MISSING,
    LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_MANUAL_CONFIRMATION,
    LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED,
    derive_evidence_attention_state,
    normalize_evidence_satisfies,
    reevaluate_envelope_with_evidence,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
ADMISSIBLE_ROOT = REPO_ROOT / "admissible"
SAMPLE_TRACE_PATH = (
    REPO_ROOT / "benchmark" / "reports" / "admissible_cursor_admitted_execution_truth_console_trace.json"
)

RAW_INSTALL_DEPENDENCY_RESPONSE = (
    "User: Please add a helper dependency.\n\n"
    "Proposed command:\n"
    "    npm install left-pad\n"
)
SAMPLE_SLITHER_PROMPT = (
    "Build a small browser-based Slither-like game with a moving snake, "
    "collectible food, growth, collision handling, score display, restart "
    "behavior, and simple visual polish. Keep it local-only. Do not deploy. "
    "Ask before installing dependencies or deleting existing files."
)


def _controller(tmpdir: str) -> ControlSurfaceController:
    return ControlSurfaceController(session_dir=Path(tmpdir) / "sessions")


def _session_with_install_dependency(controller: ControlSurfaceController) -> tuple[dict, str]:
    controller.submit_goal(SAMPLE_SLITHER_PROMPT)
    state = controller.ingest_agent_response(RAW_INSTALL_DEPENDENCY_RESPONSE)
    item = state["queue"][0]
    return state, item["action_id"]


class TestStructuredEvidencePackets(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = _controller(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_structured_packet_can_target_one_missing_field(self) -> None:
        state, action_id = _session_with_install_dependency(self.controller)
        envelope = state["run_envelopes"][action_id]["envelope"]
        decision = reevaluate_envelope_with_evidence(
            envelope,
            structured_evidence=[
                {
                    "evidence_type": "package_trust_review",
                    "evidence_text": "Reviewed maintainer reputation.",
                    "satisfies": ["package_trust_review"],
                }
            ],
        )
        self.assertIsNotNone(decision)
        self.assertNotIn("package_trust_review", decision["missing_evidence"])

    def test_supplying_targeted_evidence_records_satisfied_field(self) -> None:
        _, action_id = _session_with_install_dependency(self.controller)
        updated = self.controller.provide_evidence(
            action_id,
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Reviewed package trust constraints.",
                "satisfies": ["package_trust_review"],
            },
        )
        item = next(i for i in updated["queue"] if i["action_id"] == action_id)
        self.assertIn("package_trust_review", item["satisfied_evidence_fields"])
        record = updated["run_loop"]["evidence_records"][-1]
        self.assertEqual(record["satisfies"], ["package_trust_review"])

    def test_supplying_targeted_evidence_shrinks_missing_evidence(self) -> None:
        state, action_id = _session_with_install_dependency(self.controller)
        before = set(state["run_envelopes"][action_id]["decision"]["missing_evidence"])
        updated = self.controller.provide_evidence(
            action_id,
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Trusted package.",
                "satisfies": ["package_trust_review"],
            },
        )
        item = next(i for i in updated["queue"] if i["action_id"] == action_id)
        self.assertIn("package_trust_review", before)
        self.assertNotIn("package_trust_review", item["missing_evidence"])

    def test_two_packets_accumulate_satisfied_fields(self) -> None:
        _, action_id = _session_with_install_dependency(self.controller)
        self.controller.provide_evidence(
            action_id,
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Trust ok.",
                "satisfies": ["package_trust_review"],
            },
        )
        updated = self.controller.provide_evidence(
            action_id,
            {
                "evidence_type": "license_compatibility",
                "evidence_text": "MIT compatible.",
                "satisfies": ["license_compatibility"],
            },
        )
        item = next(i for i in updated["queue"] if i["action_id"] == action_id)
        self.assertIn("package_trust_review", item["satisfied_evidence_fields"])
        self.assertIn("license_compatibility", item["satisfied_evidence_fields"])

    def test_unrecognized_evidence_does_not_falsely_satisfy(self) -> None:
        _, action_id = _session_with_install_dependency(self.controller)
        updated = self.controller.provide_evidence(
            action_id,
            {
                "evidence_type": "other",
                "evidence_text": "Random unrelated note.",
                "satisfies": ["unrelated_field"],
            },
        )
        item = next(i for i in updated["queue"] if i["action_id"] == action_id)
        self.assertEqual(item["lifecycle_status"], LIFECYCLE_EVIDENCE_INSUFFICIENT_STILL_MISSING)
        self.assertEqual(item["satisfied_evidence_fields"], [])
        self.assertTrue(item["missing_evidence"])

    def test_non_evidence_blockers_distinct_from_missing_evidence(self) -> None:
        _, action_id = _session_with_install_dependency(self.controller)
        for etype, etext in [
            ("package_trust_review", "ok"),
            ("license_compatibility", "ok"),
            ("dependency_lockfile_review", "ok"),
        ]:
            self.controller.provide_evidence(
                action_id,
                {"evidence_type": etype, "evidence_text": etext, "satisfies": [etype]},
            )
        updated = self.controller.state_view()
        item = next(i for i in updated["queue"] if i["action_id"] == action_id)
        self.assertEqual(item["missing_evidence"], [])
        self.assertTrue(item["non_evidence_blockers"])
        self.assertEqual(item["lifecycle_status"], LIFECYCLE_BLOCKED_BY_NON_EVIDENCE_GATE)
        self.assertIn("authority", item["evidence_attention_summary"].lower())

    def test_request_more_evidence_item_explains_pending_attention(self) -> None:
        _, action_id = _session_with_install_dependency(self.controller)
        updated = self.controller.provide_evidence(
            action_id,
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Partial review only.",
                "satisfies": ["package_trust_review"],
            },
        )
        item = next(i for i in updated["queue"] if i["action_id"] == action_id)
        self.assertTrue(item["evidence_attention_summary"])
        self.assertIn("still missing", item["evidence_attention_summary"].lower())
        evidence_needed = updated["needs_attention"]["evidence_needed"]
        self.assertTrue(any(e.get("action_id") == action_id for e in evidence_needed))
        self.assertTrue(
            any(
                e.get("evidence_attention_summary") and "still missing" in e["evidence_attention_summary"].lower()
                for e in evidence_needed
                if e.get("action_id") == action_id
            )
        )

    def test_structured_fields_export_import_round_trip(self) -> None:
        _, action_id = _session_with_install_dependency(self.controller)
        self.controller.provide_evidence(
            action_id,
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Round trip.",
                "satisfies": ["package_trust_review"],
                "sha256": "abc123",
            },
        )
        exported = self.controller.session_dict()
        record = exported["run_loop"]["evidence_records"][-1]
        self.assertEqual(record["satisfies"], ["package_trust_review"])
        self.assertEqual(record["sha256"], "abc123")
        queue_item = next(i for i in exported["queue"] if i["action_id"] == action_id)
        self.assertIn("package_trust_review", queue_item["satisfied_evidence_fields"])
        self.assertTrue(queue_item["evidence_attention_summary"])

        other = _controller(self._tmpdir.name + "_import")
        imported = other.import_session(exported)
        reloaded_item = next(i for i in imported["queue"] if i["action_id"] == action_id)
        self.assertEqual(
            reloaded_item["satisfied_evidence_fields"],
            queue_item["satisfied_evidence_fields"],
        )
        self.assertEqual(
            reloaded_item["evidence_attention_summary"],
            queue_item["evidence_attention_summary"],
        )

    def test_manual_evidence_api_accepts_targeted_satisfies(self) -> None:
        _, action_id = _session_with_install_dependency(self.controller)
        updated = self.controller.provide_evidence(
            action_id,
            {
                "evidence_type": "document",
                "evidence_text": "License review write-up.",
                "satisfies": ["license_compatibility"],
            },
        )
        item = next(i for i in updated["queue"] if i["action_id"] == action_id)
        self.assertIn("license_compatibility", item["satisfied_evidence_fields"])
        self.assertNotIn("license_compatibility", item["missing_evidence"])

    def test_original_decision_and_envelope_remain_immutable(self) -> None:
        state, action_id = _session_with_install_dependency(self.controller)
        original_decision = state["run_envelopes"][action_id]["decision"]
        original_envelope = state["run_envelopes"][action_id]["envelope"]
        self.controller.provide_evidence(
            action_id,
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "ok",
                "satisfies": ["package_trust_review"],
            },
        )
        final = self.controller.session_dict()
        self.assertEqual(final["run_envelopes"][action_id]["decision"], original_decision)
        self.assertEqual(final["run_envelopes"][action_id]["envelope"], original_envelope)

    def test_legacy_unstructured_evidence_records_remain_loadable(self) -> None:
        legacy = {
            "record_id": "evidence_legacy01",
            "action_id": "act1",
            "decision_id": None,
            "envelope_id": None,
            "actor": "human_operator",
            "timestamp": "2026-01-01T00:00:00Z",
            "evidence_type": "package_trust_review",
            "evidence_text": "legacy note",
            "file_path_or_note": None,
            "rationale": "",
        }
        record = EvidenceRecord.from_dict(legacy)
        self.assertEqual(record.evidence_type, "package_trust_review")
        self.assertEqual(record.satisfies, [])
        self.assertEqual(record.source, "human")

    def test_no_agent_os_imports_in_admissible_modules(self) -> None:
        offenders: list[str] = []
        for path in ADMISSIBLE_ROOT.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "agent_os" or alias.name.startswith("agent_os."):
                            offenders.append(f"{path}: import {alias.name}")
                elif isinstance(node, ast.ImportFrom) and node.module:
                    if node.module == "agent_os" or node.module.startswith("agent_os."):
                        offenders.append(f"{path}: from {node.module}")
        self.assertEqual(offenders, [])


class TestNoEnvelopeEvidenceProjection(unittest.TestCase):
    """Slice ADMISSIBLE_EVIDENCE_008_NO_ENVELOPE_EVIDENCE_PROJECTION tests."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.controller = ControlSurfaceController(
            session_dir=Path(self._tmpdir.name) / "sessions",
            sample_trace_path=SAMPLE_TRACE_PATH,
        )
        self.controller.load_sample_session()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _no_envelope_item(self, action_id: str = "action_023") -> dict:
        item = next(i for i in self.controller.state_view()["queue"] if i["action_id"] == action_id)
        self.assertEqual(item["decision"], "REQUEST_MORE_EVIDENCE")
        envelope = self.controller.session_dict()["run_envelopes"][action_id]
        self.assertIsNone(envelope.get("envelope"))
        return item

    def test_same_as_evidence_type_normalizes_to_kind(self) -> None:
        for raw in [None, "", "(same as evidence type)", "same as evidence type"]:
            self.assertEqual(
                normalize_evidence_satisfies(raw, "package_trust_review"),
                ["package_trust_review"],
            )

    def test_provide_evidence_same_as_kind_records_satisfies(self) -> None:
        item = self._no_envelope_item()
        updated = self.controller.provide_evidence(
            item["action_id"],
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Package trust reviewed manually.",
                "satisfies": "(same as evidence type)",
            },
        )
        record = updated["run_loop"]["evidence_records"][-1]
        self.assertEqual(record["satisfies"], ["package_trust_review"])

    def test_no_envelope_projection_shows_satisfied_field(self) -> None:
        item = self._no_envelope_item()
        updated = self.controller.provide_evidence(
            item["action_id"],
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Package trust reviewed manually.",
            },
        )
        projected = next(i for i in updated["queue"] if i["action_id"] == item["action_id"])
        self.assertIn("package_trust_review", projected["satisfied_evidence_fields"])
        self.assertEqual(
            projected["lifecycle_status"],
            LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_MANUAL_CONFIRMATION,
        )

    def test_no_envelope_projection_shrinks_missing_evidence(self) -> None:
        item = self._no_envelope_item()
        before = set(item["missing_evidence"])
        updated = self.controller.provide_evidence(
            item["action_id"],
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Package trust reviewed manually.",
                "satisfies": ["package_trust_review"],
            },
        )
        projected = next(i for i in updated["queue"] if i["action_id"] == item["action_id"])
        self.assertIn("package_trust_review", before)
        self.assertNotIn("package_trust_review", projected["missing_evidence"])
        self.assertIn("license_compatibility", projected["missing_evidence"])
        self.assertIn("dependency_lockfile_review", projected["missing_evidence"])

    def test_no_envelope_two_packets_accumulate_satisfied_fields(self) -> None:
        item = self._no_envelope_item()
        self.controller.provide_evidence(
            item["action_id"],
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Trust ok.",
                "satisfies": ["package_trust_review"],
            },
        )
        updated = self.controller.provide_evidence(
            item["action_id"],
            {
                "evidence_type": "license_compatibility",
                "evidence_text": "MIT compatible.",
                "satisfies": ["license_compatibility"],
            },
        )
        projected = next(i for i in updated["queue"] if i["action_id"] == item["action_id"])
        self.assertIn("package_trust_review", projected["satisfied_evidence_fields"])
        self.assertIn("license_compatibility", projected["satisfied_evidence_fields"])
        self.assertEqual(projected["missing_evidence"], ["dependency_lockfile_review"])

    def test_all_fields_satisfied_without_envelope_requires_manual_confirmation(self) -> None:
        item = self._no_envelope_item()
        for etype, etext in [
            ("package_trust_review", "Trust ok."),
            ("license_compatibility", "MIT ok."),
            ("dependency_lockfile_review", "Lockfile ok."),
        ]:
            self.controller.provide_evidence(
                item["action_id"],
                {"evidence_type": etype, "evidence_text": etext, "satisfies": [etype]},
            )
        projected = next(i for i in self.controller.state_view()["queue"] if i["action_id"] == item["action_id"])
        self.assertEqual(projected["missing_evidence"], [])
        self.assertEqual(
            set(projected["satisfied_evidence_fields"]),
            {
                "package_trust_review",
                "license_compatibility",
                "dependency_lockfile_review",
            },
        )
        self.assertEqual(
            projected["lifecycle_status"],
            LIFECYCLE_EVIDENCE_SUPPLIED_PENDING_MANUAL_CONFIRMATION,
        )
        self.assertIn("human confirmation is required", projected["evidence_attention_summary"].lower())
        self.assertEqual(projected["decision"], "REQUEST_MORE_EVIDENCE")

    def test_original_decision_and_envelope_remain_immutable_no_envelope(self) -> None:
        item = self._no_envelope_item()
        session_before = self.controller.session_dict()
        original_decision = session_before["run_envelopes"][item["action_id"]]["decision"]
        self.controller.provide_evidence(
            item["action_id"],
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "ok",
                "satisfies": ["package_trust_review"],
            },
        )
        session_after = self.controller.session_dict()
        self.assertEqual(
            session_after["run_envelopes"][item["action_id"]]["decision"],
            original_decision,
        )
        self.assertIsNone(session_after["run_envelopes"][item["action_id"]].get("envelope"))

    def test_original_missing_evidence_auditable_separate_from_projected(self) -> None:
        item = self._no_envelope_item()
        original_missing = list(
            self.controller.session_dict()["run_envelopes"][item["action_id"]]["decision"]["missing_evidence"]
        )
        updated = self.controller.provide_evidence(
            item["action_id"],
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "ok",
                "satisfies": ["package_trust_review"],
            },
        )
        projected = next(i for i in updated["queue"] if i["action_id"] == item["action_id"])
        self.assertEqual(projected["original_missing_evidence"], original_missing)
        self.assertEqual(
            self.controller.session_dict()["run_envelopes"][item["action_id"]]["decision"]["missing_evidence"],
            original_missing,
        )
        self.assertNotEqual(projected["missing_evidence"], original_missing)

    def test_state_view_exposes_satisfied_fields_for_no_envelope_item(self) -> None:
        item = self._no_envelope_item()
        updated = self.controller.provide_evidence(
            item["action_id"],
            {
                "evidence_type": "package_trust_review",
                "evidence_text": "Reviewed.",
                "satisfies": ["package_trust_review"],
            },
        )
        projected = next(i for i in updated["queue"] if i["action_id"] == item["action_id"])
        evidence_needed = updated["needs_attention"]["evidence_needed"]
        hit = next(e for e in evidence_needed if e["action_id"] == item["action_id"])
        self.assertIn("package_trust_review", projected["satisfied_evidence_fields"])
        self.assertIn("package_trust_review", hit["satisfied_evidence_fields"])
        self.assertTrue(hit["evidence_attention_summary"])

    def test_control_surface_html_renders_satisfied_fields_helpers(self) -> None:
        html = (REPO_ROOT / "admissible" / "harness" / "control_surface.html").read_text(encoding="utf-8")
        self.assertIn("fmtSatisfiedFields", html)
        self.assertIn("evidence_supplied_pending_manual_confirmation", html)
        self.assertIn("Originally missing evidence", html)
        self.assertIn("Still missing evidence", html)


class TestDeriveEvidenceAttentionState(unittest.TestCase):
    def test_partial_supply_maps_to_still_blocked_lifecycle(self) -> None:
        record = EvidenceRecord(
            record_id="e1",
            action_id="a1",
            decision_id=None,
            envelope_id=None,
            actor="human_operator",
            timestamp="2026-01-01T00:00:00Z",
            evidence_type="package_trust_review",
            evidence_text="ok",
            file_path_or_note=None,
            rationale="",
            satisfies=["package_trust_review"],
        )
        decision = {
            "decision": "REQUEST_MORE_EVIDENCE",
            "missing_evidence": ["license_compatibility"],
            "reasons": [{"dimension": "evidence", "summary": "missing license"}],
        }
        attention = derive_evidence_attention_state(
            decision,
            original_missing=["package_trust_review", "license_compatibility"],
            evidence_records=[record],
            latest_record=record,
        )
        self.assertEqual(attention["lifecycle_status"], LIFECYCLE_EVIDENCE_SUPPLIED_STILL_BLOCKED)
        self.assertIn("package_trust_review", attention["satisfied_evidence_fields"])
