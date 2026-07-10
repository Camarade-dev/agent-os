from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from admissible.agent_transport import FixtureAgentTransport
from admissible.control_surface import ControlSurfaceController
from admissible.governed_run import validate_coherent_batch_limits


class TestAdmissibleCoherentBatching(unittest.TestCase):
    def test_default_accepts_four_independent_pixel_wanderer_files(self) -> None:
        result = validate_coherent_batch_limits(
            [
                {"operation": "write_file", "path": name, "content": "local"}
                for name in ("index.html", "style.css", "game.js", "LOCAL_DEV.md")
            ]
        )
        self.assertEqual(result["operation_count"], 4)

    def test_count_and_utf8_byte_limits_are_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "configured maximum"):
            validate_coherent_batch_limits(
                [{"operation": "write_file", "path": f"{i}.txt", "content": "x"} for i in range(3)],
                max_operations=2,
            )
        with self.assertRaisesRegex(ValueError, "UTF-8 byte"):
            validate_coherent_batch_limits(
                [{"operation": "write_file", "path": "fr.txt", "content": "éé"}],
                max_total_write_bytes=3,
            )

    def test_first_and_continuation_prompts_carry_concise_progress_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal("Create index.html and style.css as a local-only batch.")
            transport = FixtureAgentTransport()
            controller.start_high_autonomy_run(
                workspace_path=str(workspace), transport=transport, max_turns=6
            )
            controller.tick_high_autonomy_run()
            prompt = transport.written_instructions[0]
            self.assertIn("next smallest coherent bounded batch", prompt)
            self.assertIn("STRUCTURED PROGRESS LEDGER", prompt)
            self.assertIn("current_final_file_hashes", prompt)
            self.assertNotIn("full historical transcript", prompt.lower())


if __name__ == "__main__":
    unittest.main()
