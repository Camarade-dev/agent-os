from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from types import SimpleNamespace

from admissible.agent_backend import (
    AGENT_INVOKE_SUCCESS,
    AgentInvocationRequest,
    CursorCliAgentBackend,
    CursorCliConfig,
)
from admissible.control_surface import ControlSurfaceController
from admissible.runner.control_surface import make_server


UTF8_TEXT = "em dash — arrow → curly apostrophe ’ français très aéré"


class TestAdmissibleUtf8RoundTrip(unittest.TestCase):
    def test_cursor_capture_requests_explicit_utf8_with_replacement_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / "cursor-agent.cmd"
            fake.write_text("@echo off\n", encoding="utf-8", newline="")
            target = root / "target"
            agent_ws = root / "agent"
            target.mkdir()
            agent_ws.mkdir()
            captured: dict = {}

            ndjson_stdout = json.dumps(
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "result": (
                        UTF8_TEXT
                        + '\nADMISSIBLE_STRUCTURED_OPERATION:\n'
                        '{"operation": "write_file", "path": "a.txt", "content": "x"}'
                    ),
                }
            )

            def runner(argv, **kwargs):
                captured.update(kwargs)
                return SimpleNamespace(returncode=0, stdout=ndjson_stdout, stderr="")

            backend = CursorCliAgentBackend(
                config=CursorCliConfig.cursor_agent_preset(command=str(fake)),
                runner=runner,
            )
            result = backend.invoke(
                AgentInvocationRequest(
                    instruction_text="Répondre — puis → terminer.",
                    target_workspace_path=str(target),
                    agent_workspace_path=str(agent_ws),
                )
            )
            self.assertEqual(result.status, AGENT_INVOKE_SUCCESS)
            self.assertIn(UTF8_TEXT, result.response_text)
            self.assertEqual(captured["encoding"], "utf-8")
            self.assertEqual(captured["errors"], "replace")
            self.assertFalse(captured["shell"])

    def test_session_json_http_and_ui_round_trip_utf8_without_mojibake(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            controller = ControlSurfaceController(session_dir=root / "sessions")
            controller.submit_goal("Créer une page — navigation → résultat français.")
            raw = (
                "ADMISSIBLE_STRUCTURED_OPERATION:\n```json\n"
                + json.dumps(
                    {"operation": "write_file", "path": "utf8.txt", "content": UTF8_TEXT},
                    ensure_ascii=False,
                )
                + "\n```\n"
            )
            controller.ingest_agent_response(raw)
            persisted = controller.session_file.read_text(encoding="utf-8")
            self.assertIn(UTF8_TEXT, persisted)
            self.assertNotIn("â€", persisted)
            self.assertNotIn("Â", persisted)

            server = make_server(controller, host="127.0.0.1", port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with urllib.request.urlopen(
                    f"http://{server.server_address[0]}:{server.server_address[1]}/api/session/export",
                    timeout=5,
                ) as response:
                    payload = response.read().decode("utf-8")
                    self.assertIn("charset=utf-8", response.headers["Content-Type"].lower())
                self.assertIn(UTF8_TEXT, payload)
                self.assertNotIn("â€", payload)
            finally:
                server.shutdown()
                thread.join(timeout=2)

            html = (Path(__file__).resolve().parents[1] / "admissible/harness/control_surface.html").read_text(
                encoding="utf-8"
            )
            self.assertIn('<meta charset="utf-8">', html)


if __name__ == "__main__":
    unittest.main()
