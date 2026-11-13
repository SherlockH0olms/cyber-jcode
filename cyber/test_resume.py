"""Checkpoints, history restoration and report continuity using synthetic lab evidence."""
import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cyber.console import Console, PENTEST_PHASES, read_json, write_json
from cyber.engagement import checkpoint_for, next_phase
from cyber.test_console import args


def result(phase, error=None):
    return {"session_id": "session_local_test", "phase": phase, "error": error, "elapsed": 1,
            "summary": {"status": "partial" if error else "ok", "findings": [f"{phase} evidence retained"],
                        "flags": [], "next": []},
            "tools": [{"id": f"{phase}-{'partial' if error else 'done'}", "name": "bash",
                       "command": f"printf {phase.upper()}_EVIDENCE", "output": f"{phase.upper()}_EVIDENCE",
                       "error": False}], "engagement_findings": []}


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="cyber-resume-test-")
        self.addCleanup(self.folder.cleanup)
        self.state = Path(self.folder.name) / "state"
        self.export = Path(self.folder.name) / "exports"
        guard = patch.dict(os.environ, {"CYBER_JCODE_REPORT_DIR": str(self.export)})
        guard.start()
        self.addCleanup(guard.stop)
        self.console = Console(self.state, args())
        self.console.target = "lab.example.test"

    def pause(self):
        with patch.object(self.console, "ask", side_effect=["y", "y"]) as ask, \
                patch.object(self.console, "execute", side_effect=[result("recon"), result("services", "Operation stopped.")]), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(self.console.run_pentest())
        self.assertEqual(ask.call_count, 2)  # stopping does not ask to abandon the interrupted phase
        path = Path(self.console.engagement_path)
        return path, read_json(path)

    def test_reopened_console_resumes_interrupted_phase_with_same_session_and_report(self):
        path, before = self.pause()
        self.assertEqual(before["next_phase"], 1)
        self.assertEqual(before["progress_state"], "paused")
        reopened = Console(self.state, args())
        observed = []
        def finish(task, label, **kwargs):
            observed.append((reopened.session_id, kwargs))
            return result("services")
        with patch.object(reopened, "execute", side_effect=finish) as execute, \
                patch.object(reopened, "ask", return_value="n"), contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(reopened.run_pentest(resume=True))
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(observed[0][0], "session_local_test")
        self.assertEqual(observed[0][1]["phase"], "services")
        context = observed[0][1]["extra_context"]
        self.assertIn("RESUME THE INTERRUPTED PHASE", context)
        self.assertIn("recon evidence retained", context)
        self.assertIn(str(path), context)
        after = read_json(path)
        self.assertEqual(after["next_phase"], 2)
        self.assertEqual(after["evidence_dir"], before["evidence_dir"])
        self.assertEqual(after["started"], before["started"])
        self.assertEqual(after["docx_path"], before["docx_path"])
        self.assertEqual(len(after["phases"]), 2)
        self.assertEqual(after["phases"][1]["attempts"], 2)
        self.assertEqual(len(after["tools"]), 3)
        self.assertEqual(len(list((self.state / "results").glob("pentest-*.json"))), 1)
        self.assertEqual(len(list(self.export.glob("*.docx"))), 1)
        transcript = Path(after["docx_path"]).with_suffix(".transcript.txt").read_text()
        self.assertIn("RECON_EVIDENCE", transcript)
        self.assertIn("SERVICES_EVIDENCE", transcript)

    def test_menu_ten_offers_resume_and_skips_completed_phases(self):
        self.pause()
        with patch.object(self.console, "ask", side_effect=["1", "n"]), \
                patch.object(self.console, "execute", return_value=result("services")) as execute, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.console.run_pentest()
        self.assertEqual(execute.call_args.kwargs["phase"], "services")
        self.assertIn("Saved progress: phase 2/7", output.getvalue())

    def test_ctrl_c_at_phase_question_checkpoints_the_next_phase(self):
        with patch.object(self.console, "ask", side_effect=["y", KeyboardInterrupt]), \
                patch.object(self.console, "execute", return_value=result("recon")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.console.run_pentest()
        saved = read_json(Path(self.console.engagement_path))
        self.assertEqual(saved["next_phase"], 1)
        self.assertEqual(saved["progress_state"], "paused")
        self.assertTrue(Path(saved["docx_path"]).is_file())

    def test_phase_question_clue_is_checkpointed_and_reaches_the_next_phase(self):
        prompts = []
        def execute(task, label, **kwargs):
            prompts.append(self.console.prompt(task, label))
            return result(kwargs["phase"])
        with patch.object(self.console, "ask", side_effect=["y", "Use the new local clue DEMO42", "n"]), \
                patch.object(self.console, "execute", side_effect=execute), contextlib.redirect_stdout(io.StringIO()):
            self.console.run_pentest()
        self.assertIn("Use the new local clue DEMO42", prompts[1])
        saved = read_json(Path(self.console.engagement_path))
        self.assertIn("Use the new local clue DEMO42", saved["pending_instructions"])

    def test_history_explicit_open_restores_target_session_and_checkpoint(self):
        path, _record = self.pause()
        other = Console(self.state, args(target="other.example.test"))
        with patch.object(other, "ask", side_effect=["1", "r"]), contextlib.redirect_stdout(io.StringIO()):
            other.session_history()
        self.assertEqual(other.target, "lab.example.test")
        self.assertEqual(other.session_id, "session_local_test")
        self.assertEqual(other.engagement_path, str(path))
        self.assertEqual(Console(self.state, args()).engagement_path, str(path))

    def test_other_target_and_new_session_do_not_reuse_old_engagement(self):
        self.pause()
        self.console.set_target("other.example.test")
        self.assertIsNone(checkpoint_for(self.console, PENTEST_PHASES))
        self.assertIsNone(self.console.engagement_path)
        self.console.target = "lab.example.test"
        with patch.object(self.console, "ask", side_effect=["9", "0"]), contextlib.redirect_stdout(io.StringIO()):
            self.console.loop()
        self.assertIsNone(checkpoint_for(self.console, PENTEST_PHASES))

    def test_switching_target_after_history_open_uses_the_new_targets_workspace(self):
        path, record = self.pause()
        with contextlib.redirect_stdout(io.StringIO()):
            self.console.open_session(path, record)
            old_workspace = self.console.workspace()
            self.console.set_target("other.example.test")
        self.assertNotEqual(self.console.workspace(), old_workspace)

    def test_history_sorts_iso_engagements_and_compact_task_timestamps_together(self):
        from cyber.history import saved_results
        task = self.state / "results/20261112T010203.000000Z.json"
        newer = self.state / "results/pentest-20261113T010203.000000Z.json"
        write_json(task, {"tools": [], "summary": {}})
        write_json(newer, {"started": "2026-11-13T01:02:03+00:00", "tools": [], "phases": []})
        self.assertEqual(saved_results(self.state)[0][0], newer)

    def test_legacy_report_resumes_first_partial_phase_and_preserves_later_completed_work(self):
        legacy = {"target": "lab.example.test", "session_id": "session_local_test",
                  "started": "2026-11-12T01:02:03Z", "phases": [
                      {"phase": "recon", "status": "ok"}, {"phase": "services", "status": "partial"},
                      {"phase": "web", "status": "ok"}],
                  "tools": [dict(result("recon")["tools"][0], phase="recon")],
                  "findings": [], "flags": [], "limitations": [], "screenshots": []}
        path = self.state / "results/pentest-20261112T010203Z.json"
        write_json(path, legacy)
        self.assertEqual(next_phase(legacy, PENTEST_PHASES), 1)
        self.console.open_session(path, legacy)
        with patch.object(self.console, "ask", side_effect=["y", "n"]), \
                patch.object(self.console, "execute", side_effect=[result("services"), result("vulns")]) as execute, \
                contextlib.redirect_stdout(io.StringIO()):
            self.console.run_pentest(resume=True)
        self.assertEqual([call.kwargs["phase"] for call in execute.call_args_list], ["services", "vulns"])
        self.assertIn("RECON_EVIDENCE", read_json(path)["tools"][0]["output"])

    def test_report_export_failure_keeps_resume_checkpoint(self):
        with patch.object(self.console, "ask", side_effect=["y", "n"]), \
                patch.object(self.console, "execute", return_value=result("recon")), \
                patch("cyber.report.build_report", side_effect=OSError("Word file is open")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.console.run_pentest()
        reopened = Console(self.state, args())
        saved = checkpoint_for(reopened, PENTEST_PHASES)
        self.assertIsNotNone(saved)
        self.assertEqual(saved[1]["next_phase"], 1)
        self.assertEqual(reopened.last_path, str(saved[0]))

    def test_resume_command_routes_to_checkpoint_flow(self):
        with patch.object(self.console, "ask", side_effect=["resume", "0"]), \
                patch.object(self.console, "run_pentest") as execute, contextlib.redirect_stdout(io.StringIO()):
            self.console.loop()
        execute.assert_called_once_with(resume=True)


if __name__ == "__main__":
    unittest.main()
