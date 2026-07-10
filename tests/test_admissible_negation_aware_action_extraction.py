from __future__ import annotations

import json
import unittest

from admissible.long_run_envelope_builder import (
    CLI_011_NEGATED_CONSTRAINT_SENTENCE,
    build_from_raw_output,
)
from admissible.run_loop import build_candidates_from_agent_response

NEGATIVE_SENTENCE = CLI_011_NEGATED_CONSTRAINT_SENTENCE
GOAL_NO_PUSH = (
    "Build a local browser game. Do not deploy, publish, host, push, or access the network."
)


def _structured_block(path: str, content: str = "x\n") -> str:
    operation = {"operation": "write_file", "path": path, "content": content}
    return (
        "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
        + json.dumps(operation, ensure_ascii=False)
        + "\n```"
    )


class TestAdmissibleNegationAwareActionExtraction(unittest.TestCase):
    def test_exact_negative_sentence_creates_zero_side_effect_candidates(self) -> None:
        built = build_from_raw_output(NEGATIVE_SENTENCE)
        action_types = [c.get("action_type") for c in built["action_candidates"]]
        self.assertEqual(action_types, [])
        forbidden = {"git_push", "deploy_code", "install_dependency", "unknown"}
        self.assertTrue(forbidden.isdisjoint(set(action_types)))

    def test_negative_sentence_keywords_recorded_as_negated_not_affirmative(self) -> None:
        built = build_from_raw_output(f"- {NEGATIVE_SENTENCE}")
        diag = built.get("extraction_polarity_diagnostics") or {}
        self.assertTrue(diag.get("negated_action_mentions"))
        self.assertFalse(diag.get("affirmative_action_mentions"))
        for entry in diag.get("negated_action_mentions") or []:
            self.assertTrue(any(token in entry for token in ("shell", "install", "git_push", "deploy", "network")))

    def test_affirmative_push_still_creates_real_candidate(self) -> None:
        built = build_from_raw_output("Push the branch to origin with git push now.")
        action_types = [c.get("action_type") for c in built["action_candidates"]]
        self.assertIn("git_push", action_types)

    def test_goal_prohibited_affirmative_git_push_suppressed(self) -> None:
        built = build_from_raw_output(
            "I will git push to origin now.",
            long_run_prompt=GOAL_NO_PUSH,
        )
        self.assertEqual(built["action_candidates"], [])
        suppressed = built.get("suppressed_prose_candidates") or []
        self.assertTrue(any(item.get("suppression_reason") == "goal_boundary" for item in suppressed))

    def test_structured_writes_beside_negative_prose(self) -> None:
        raw = "\n".join(
            [
                _structured_block("index.html"),
                _structured_block("style.css"),
                _structured_block("game.js"),
                _structured_block("LOCAL_DEV.md"),
                "",
                f"- {NEGATIVE_SENTENCE}",
            ]
        )
        built = build_candidates_from_agent_response(raw, turn_number=1, long_run_prompt=GOAL_NO_PUSH)
        structured = [entry for entry in built if entry["candidate"].get("structured_operations")]
        side_effects = [
            entry["candidate"].get("action_type")
            for entry in built
            if entry["candidate"].get("action_type")
            in ("git_push", "deploy_code", "install_dependency")
        ]
        self.assertEqual(len(structured), 4)
        self.assertEqual(side_effects, [])


if __name__ == "__main__":
    unittest.main()
