from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from admissible.agent_backend import _safe_environment_paths
from admissible.control_surface import ControlSurfaceController
from admissible.governed_run import (
    canonicalize_environment_paths,
    canonicalize_session_export_payload,
    validate_portable_json_no_case_colliding_keys,
)


class TestAdmissiblePortableSessionJson(unittest.TestCase):
    def test_environment_paths_canonicalized_without_case_collisions(self) -> None:
        raw = {"SYSTEMROOT": "C:\\WINDOWS", "SystemRoot": "C:\\WINDOWS", "TEMP": "C:\\Temp"}
        canonical, aliases = canonicalize_environment_paths(raw)
        self.assertIn("SystemRoot", canonical)
        self.assertNotIn("SYSTEMROOT", canonical)
        self.assertIn("SYSTEMROOT", aliases.get("SystemRoot", []))

    def test_export_has_no_case_insensitive_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            controller = ControlSurfaceController(session_dir=Path(tmp) / "sessions")
            controller.submit_goal("Portable JSON export test")
            session = controller.session_dict()
            ha = dict(session.get("high_autonomy_run") or {})
            ha["invocation_history"] = [
                {
                    "invocation_id": "inv_1",
                    "environment_paths": {"SYSTEMROOT": "C:\\WINDOWS", "SystemRoot": "C:\\WINDOWS"},
                }
            ]
            session["high_autonomy_run"] = ha
            exported = canonicalize_session_export_payload(session)
            collisions = validate_portable_json_no_case_colliding_keys(exported)
            self.assertEqual(collisions, [])

    def test_powershell_compatible_validator_accepts_canonical_export(self) -> None:
        payload = {
            "session_id": "sess_1",
            "high_autonomy_run": {
                "invocation_history": [
                    {
                        "environment_paths": {"SystemRoot": "C:\\WINDOWS"},
                        "environment_path_aliases": {"SystemRoot": ["SYSTEMROOT"]},
                    }
                ]
            },
        }
        collisions = validate_portable_json_no_case_colliding_keys(payload)
        self.assertEqual(collisions, [])
        json.dumps(payload)

    def test_backend_capture_pre_canonicalizes_environment_paths(self) -> None:
        paths = _safe_environment_paths({"SYSTEMROOT": "C:\\WINDOWS", "SystemRoot": "C:\\WINDOWS"})
        keys_lower = [key.lower() for key in paths]
        self.assertEqual(len(keys_lower), len(set(keys_lower)))


if __name__ == "__main__":
    unittest.main()
