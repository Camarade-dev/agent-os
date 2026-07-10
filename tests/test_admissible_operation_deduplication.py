from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.control_surface import ControlSurfaceController


def _block(path: str, content: str) -> str:
    return "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n" + json.dumps(
        {"operation": "write_file", "path": path, "content": content}
    ) + "\n```\n"


class TestAdmissibleOperationDeduplication(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.workspace = root / "workspace"
        self.workspace.mkdir()
        self.controller = ControlSurfaceController(session_dir=root / "sessions")
        self.controller.submit_goal("Create LOCAL_DEV.md in the local workspace.")
        self.controller.set_bounded_executor_workspace(self.workspace)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_identical_local_dev_proposal_becomes_duplicate_noop(self) -> None:
        raw = _block("LOCAL_DEV.md", "Open index.html locally — no server required.\n")
        first = self.controller.ingest_agent_response(raw)
        first_id = first["run_loop"]["response_records"][-1]["action_ids"][0]
        self.controller.execute_bounded_local(first_id, {})

        second = self.controller.ingest_agent_response(raw)
        second_id = second["run_loop"]["response_records"][-1]["action_ids"][0]
        item = next(row for row in second["queue"] if row["action_id"] == second_id)
        self.assertEqual(item["operation_outcome"], "duplicate_noop")
        duplicate = self.controller.session_dict()["operation_records"][-1]
        self.assertEqual(duplicate["outcome"], "duplicate_noop")
        self.assertIsNotNone(duplicate["original_execution_record_id"])
        self.assertEqual(
            sum(
                1
                for record in self.controller.session_dict()["operation_records"]
                if record["outcome"] == "executed_mutation"
            ),
            1,
        )

    def test_same_on_disk_sha_without_run_evidence_is_already_satisfied(self) -> None:
        content = "local usage\n"
        (self.workspace / "LOCAL_DEV.md").write_text(
            content, encoding="utf-8", newline=""
        )
        state = self.controller.ingest_agent_response(_block("LOCAL_DEV.md", content))
        action_id = state["run_loop"]["response_records"][-1]["action_ids"][0]
        item = next(row for row in state["queue"] if row["action_id"] == action_id)
        self.assertEqual(item["operation_outcome"], "already_satisfied_noop")
        self.assertEqual(
            self.controller.session_dict()["operation_records"][-1]["outcome"],
            "already_satisfied_noop",
        )

    def test_pre_run_file_with_different_sha_requires_human_review(self) -> None:
        (self.workspace / "LOCAL_DEV.md").write_text(
            "pre-run content\n", encoding="utf-8", newline=""
        )
        state = self.controller.ingest_agent_response(
            _block("LOCAL_DEV.md", "replacement\n")
        )
        action_id = state["run_loop"]["response_records"][-1]["action_ids"][0]
        item = next(row for row in state["queue"] if row["action_id"] == action_id)
        self.assertTrue(item["safe_overwrite_review_required"])
        with self.assertRaisesRegex(ValueError, "requires human review"):
            self.controller.execute_bounded_local(action_id, {})
        self.assertEqual(
            self.controller.session_dict()["operation_records"][-1]["outcome"],
            "blocked",
        )


if __name__ == "__main__":
    unittest.main()
