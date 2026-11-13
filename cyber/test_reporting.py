"""Regression checks for text-only sessions and verifiable report artifacts."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from cyber.console import Backend, Console, error_message, main, write_json
from cyber.report import build_report, collect_screenshots, parse_engagement_details
from cyber.report_layout import report_filename, desktop_report_folder
from cyber.test_console import args


class ReportingRegressionTests(unittest.TestCase):
    def test_auth_metadata_does_not_turn_image_400_into_auth_failure(self):
        metadata = "OpenAI-compatible auth: OPENAI_COMPAT_API_KEY status: 400 Bad Request "
        self.assertIn("image input", error_message(metadata + "This model does not support image inputs"))
        self.assertIn("request format", error_message(metadata + "invalid request"))
        self.assertIn("authentication failed", error_message("status: 401 Unauthorized"))
        self.assertIn("tool calling", error_message(metadata + "This model does not support tool calling"))

    def test_all_tasks_set_engine_guard_and_never_read_screenshots(self):
        with tempfile.TemporaryDirectory() as folder:
            console = Console(Path(folder), args())
            self.assertEqual(console.backend.environment()["JCODE_DISABLE_IMAGE_INPUT"], "1")
            self.assertIn("agent-textonly-v1.sock", " ".join(console.backend.command()))
            self.assertIn("NEVER read, view, attach", console.prompt("Inspect file"))
            full = console.prompt("Recon", "PENTEST")
            self.assertIn("ABSOLUTE SCREENSHOT RULE", full)
            self.assertIn("Word tables without broken layout", full)

    def test_history_preserves_active_session_and_hides_raw_model_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            console = Console(state, args())
            console.session_id, console.target, console.last_path = "active", "active-target", "last"
            write_json(state / "results/20261113.json", {
                "target": "archived-target", "label": "TASK", "tools": [],
                "summary": {"status": "ok", "findings": ["Archived result"], "flags": [], "next": []},
                "raw_text": "PRIVATE_REASONING", "messages": ["PRIVATE_REASONING"]})
            with patch.object(console, "ask", return_value="1"), contextlib.redirect_stdout(io.StringIO()) as output:
                console.session_history()
            self.assertIn("Archived result", output.getvalue())
            self.assertNotIn("PRIVATE_REASONING", output.getvalue())
            self.assertEqual((console.session_id, console.target, console.last_path), ("active", "active-target", "last"))

    def test_sessions_opens_from_shell_without_running_the_model(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"CYBER_JCODE_HOME": folder}), \
                patch.object(Console, "session_history") as browse, patch.object(Backend, "run") as run:
            self.assertEqual(main(["sessions"]), 0)
            self.assertEqual(main(["--sessions"]), 0)
            self.assertEqual(browse.call_count, 2)
            run.assert_not_called()

    def test_report_folder_and_filename_are_safe_and_isolated(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"CYBER_JCODE_REPORT_DIR": folder}):
            self.assertEqual(desktop_report_folder(), Path(folder))
        name = report_filename("https://user:secret@example.test/path?token=private", "20261113T010203Z")
        self.assertEqual(name, "Cyber-Jcode_Pentest_example.test_20261113T010203Z.docx")

    def test_rich_report_fields_and_exact_evidence_survive_parser(self):
        details = {"findings": [{"title": "Finding", "description": "a" * 900,
                    "impact": "b" * 800, "evidence_excerpt": "line one\nline two",
                    "reproduction_steps": ["First", "Second"], "retest": "Repeat the request"}],
                   "limitations": ["Partial scope"]}
        parsed = parse_engagement_details("[CYBER_FINDINGS]" + json.dumps(details) + "[/CYBER_FINDINGS]")
        self.assertEqual(len(parsed["findings"][0]["description"]), 900)
        self.assertEqual(parsed["findings"][0]["evidence_excerpt"], "line one\nline two")
        self.assertEqual(parsed["findings"][0]["reproduction_steps"], ["First", "Second"])

    @unittest.skipUnless(shutil.which("chromium"), "local Chromium required")
    def test_real_capture_embeds_only_with_verified_metadata_and_matching_hash(self):
        from cyber.capture import capture
        from docx import Document
        with tempfile.TemporaryDirectory(prefix="cyber-capture-test-") as folder:
            root = Path(folder)
            page = root / "page.html"
            page.write_text("<html><title>Local capture fixture</title><h1>Local evidence fixture</h1></html>")
            record = capture(page.as_uri(), root / "capture.png", no_sandbox=True)
            tool = {"id": "capture-1", "name": "bash", "command": f"python3 cyber/capture.py --output {root / 'capture.png'}",
                    "output": json.dumps(record), "error": False}
            accepted = collect_screenshots([tool], root)
            self.assertEqual(len(accepted), 1)
            report = build_report({"target": "local-fixture", "tools": [tool], "screenshots": accepted}, root / "report.docx")
            doc = Document(report)
            self.assertEqual(len(doc.inline_shapes), 1)
            self.assertNotIn("{{", "\n".join(p.text for p in doc.paragraphs))
            self.assertTrue(doc.tables[0].rows[0].cells[0].paragraphs[0].runs[0].bold)
            self.assertIn("capture-1", report.with_suffix(".transcript.txt").read_text())
            # Metadata outside the per-run directory, failed execution, and mutated bytes are rejected.
            self.assertEqual(collect_screenshots([tool], root / "other"), [])
            self.assertEqual(collect_screenshots([dict(tool, error=True)], root), [])
            (root / "capture.png").write_bytes(b"changed")
            self.assertEqual(collect_screenshots([tool], root), [])
            report = build_report({"tools": [tool], "screenshots": accepted}, root / "changed.docx")
            self.assertEqual(len(Document(report).inline_shapes), 0)


if __name__ == "__main__":
    unittest.main()
