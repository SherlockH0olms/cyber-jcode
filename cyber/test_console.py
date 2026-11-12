"""Behavior checks for hidden streams, real process transport and isolation."""
import argparse
import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cyber.console import Backend, Console, cells, clean, fit, parse_result, read_json
from cyber.install import import_settings, link_launcher, snapshot


FINAL = '[CYBER_RESULT]\n{"status":"ok","findings":["Dosya incelendi."],"flags":["THM{test_only}"],"next":[]}\n[/CYBER_RESULT]'
FAKE_ENGINE = '''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
mode = os.environ.get("CYBER_TEST_MODE", "normal")
Path(os.environ["JCODE_HOME"]).mkdir(parents=True, exist_ok=True)
Path(os.environ["JCODE_HOME"], "invocation.json").write_text(json.dumps({"argv":sys.argv[1:], "cwd":os.getcwd(), "env":{k:v for k,v in os.environ.items() if k.startswith("JCODE_") or k.startswith("XDG_")}}))
if mode == "hang":
    Path(os.environ["JCODE_HOME"], "pid").write_text(str(os.getpid()))
    time.sleep(60)
    sys.exit(0)
def emit(event):
    print(json.dumps(event), flush=True)
emit({"type":"start","session_id":"session_test"})
emit({"type":"text_delta","text":"HIDDEN_REASONING_AND_CHAT"})
emit({"type":"status_detail","detail":"HIDDEN_STATUS"})
emit({"type":"tool_input","delta":"HIDDEN_TOOL_INPUT"})
emit({"type":"tool_done","name":"think","output":"HIDDEN_THINK_TOOL"})
sys.stderr.write("HIDDEN_STDERR" * 20000)
sys.stderr.flush()
if mode == "error":
    emit({"type":"error","message":"401 Authorization Bearer SECRET_TOKEN"})
    sys.exit(1)
if mode == "missing_done":
    sys.exit(0)
emit({"type":"tool_done","name":"bash","output":"scan output\\nTHM{test_only}","error":False})
emit({"type":"tool_done","name":"read","output":"X" * 100000,"error":False})
emit({"type":"done","session_id":"session_test","text":"HIDDEN_REASONING_AND_CHAT\\n[CYBER_RESULT]\\n" + json.dumps({"status":"ok","findings":["Dosya incelendi."],"flags":["THM{test_only}","THM{invented}"],"next":[]}) + "\\n[/CYBER_RESULT]"})
'''


def args(**overrides):
    values = dict(target=None, provider=None, model=None, cwd=None, no_color=True,
                  full_output=False, menu=False, check=False, run=None)
    values.update(overrides)
    return argparse.Namespace(**values)


class RenderingTests(unittest.TestCase):
    def test_only_explicit_final_result_survives(self):
        data = parse_result("secret planning\n" + FINAL + "\nsecret conversation")
        self.assertEqual(data["findings"], ["Dosya incelendi."])
        self.assertNotIn("secret", json.dumps(data))
        fallback = parse_result("No markers. Hidden conversational explanation.")
        self.assertEqual(fallback["status"], "partial")
        self.assertNotIn("Hidden", json.dumps(fallback))
        self.assertEqual(parse_result("<think>" + FINAL + "</think>")["status"], "partial")

    def test_last_valid_result_and_limits(self):
        data = {"status":"blocked", "findings":["a" * 1000] * 50, "flags":[], "next":["x"] * 20}
        text = FINAL + "[CYBER_RESULT]" + json.dumps(data) + "[/CYBER_RESULT]"
        result = parse_result(text)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(len(result["findings"]), 4)
        self.assertEqual(len(result["next"]), 1)
        self.assertLessEqual(cells(result["findings"][0]), 150)

    def test_ansi_and_control_sequences_never_reach_terminal(self):
        self.assertEqual(clean("\x1b[31mred\x1b[0m\x1b]0;evil\x07\r\b!"), "red!")
        for width in (8, 20, 40):
            self.assertLessEqual(cells(fit("旗 e\u0301 " * 20, width)), width)

    def test_chrome_fits_narrow_terminal(self):
        with tempfile.TemporaryDirectory() as folder:
            console = Console(Path(folder), args(menu=True))
            console.width = 24
            console.target = "http://very-long-lab-host.example/path"
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                console.banner()
                console.menu()
            for row in output.getvalue().splitlines():
                self.assertLessEqual(cells(row), 24)


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.binary = self.folder / "fake-engine"
        self.binary.write_text(FAKE_ENGINE)
        self.binary.chmod(0o755)
        self.backend = Backend(self.folder / "state", self.binary)

    async def asyncTearDown(self):
        self.temp.cleanup()

    async def test_process_pipes_large_output_and_session_resume(self):
        workspace = self.folder / "lab"
        workspace.mkdir(mode=0o755)
        workspace.chmod(0o755)
        with patch.dict(os.environ, {"JCODE_SOCKET":"/original.sock", "JCODE_HOME":"/original-home", "JCODE_DEBUG_CMD_PATH":"/original-debug"}):
            result = await asyncio.wait_for(self.backend.run("task with 'quotes'; $(literal)", self.folder / "lab", "prior_session", "auto", ""), 10)
        self.assertIsNone(result.error)
        self.assertEqual(result.session_id, "session_test")
        self.assertEqual(result.summary["flags"], ["THM{test_only}"])
        self.assertEqual([t["name"] for t in result.tools], ["bash", "read"])
        self.assertEqual(len(result.tools[1]["output"]), 100000)
        invocation = read_json(self.folder / "state/engine/invocation.json")
        self.assertIn("prior_session", invocation["argv"])
        self.assertIn("task with 'quotes'; $(literal)", invocation["argv"])
        self.assertEqual(invocation["env"]["JCODE_HOME"], str(self.folder / "state/engine"))
        self.assertNotIn("JCODE_DEBUG_CMD_PATH", invocation["env"])
        self.assertEqual(invocation["env"]["XDG_CONFIG_HOME"], str(self.folder / "state/engine/config"))
        self.assertEqual(workspace.stat().st_mode & 0o777, 0o755)

    async def test_error_is_short_and_does_not_leak_credentials(self):
        with patch.dict(os.environ, {"CYBER_TEST_MODE":"error"}):
            result = await self.backend.run("task", self.folder / "lab", None, "auto", "")
        self.assertIn("doğrulanamadı", result.error)
        self.assertNotIn("SECRET_TOKEN", result.error)

    async def test_previously_observed_flag_can_be_recalled(self):
        result = await self.backend.run("task", self.folder / "lab", "prior_session",
                                        "auto", "", verified_flags=["THM{invented}"])
        self.assertEqual(result.summary["flags"], ["THM{test_only}", "THM{invented}"])

    async def test_missing_terminal_event_is_failure(self):
        with patch.dict(os.environ, {"CYBER_TEST_MODE":"missing_done"}):
            result = await self.backend.run("task", self.folder / "lab", None, "auto", "")
        self.assertIsNotNone(result.error)

    async def test_cancel_terminates_only_owned_process(self):
        with patch.dict(os.environ, {"CYBER_TEST_MODE":"hang"}):
            task = asyncio.create_task(self.backend.run("task", self.folder / "lab", None, "auto", ""))
            pid_file = self.folder / "state/engine/pid"
            for _ in range(100):
                if pid_file.exists():
                    break
                await asyncio.sleep(0.01)
            self.assertTrue(pid_file.exists())
            pid = int(pid_file.read_text())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


class ConsoleTests(unittest.TestCase):
    def test_existing_launcher_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "cyber-jcode"
            path.write_text("existing tool")
            with self.assertRaises(ValueError):
                link_launcher(path, Path(folder) / "new-tool")
            self.assertEqual(path.read_text(), "existing tool")

    def test_connection_check_requires_tool_evidence(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            console = Console(Path(folder), args())
            with patch.object(console, "execute", return_value=True):
                self.assertFalse(console.check_connection())

    def test_number_menu_and_free_prompt_share_input(self):
        with tempfile.TemporaryDirectory() as folder:
            console = Console(Path(folder), args())
            with patch.object(console, "ask", side_effect=["1", "10.10.10.10", "2", "özel görev", "123", "0"]), patch.object(console, "execute", return_value=True) as execute, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(console.loop(), 0)
            self.assertEqual(execute.call_count, 2)
            self.assertEqual(execute.call_args_list[1].args[0], "özel görev")

    def test_target_change_resets_session(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            console = Console(Path(folder), args())
            console.target = "10.10.10.1"
            console.session_id = "previous_target_session"
            console.verified_flags = ["THM{previous_target}"]
            first_workspace = console.workspace()
            console.set_target("10.10.10.2")
            self.assertIsNone(console.session_id)
            self.assertEqual(console.verified_flags, [])
            self.assertNotEqual(console.workspace(), first_workspace)

    def test_frontend_and_result_file_exclude_hidden_streams(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            binary = folder / "fake-engine"
            binary.write_text(FAKE_ENGINE)
            binary.chmod(0o755)
            console = Console(folder / "state", args())
            console.backend = Backend(console.state, binary)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertTrue(console.execute("inspect local file"))
            saved = Path(console.last_path).read_text()
            for forbidden in ("HIDDEN_REASONING", "HIDDEN_STDERR", "HIDDEN_THINK", "HIDDEN_TOOL_INPUT", "HIDDEN_STATUS", "THM{invented}"):
                self.assertNotIn(forbidden, saved + output.getvalue())
            self.assertIn("[FLAG] THM{test_only}", output.getvalue())
            self.assertEqual(Path(console.last_path).stat().st_mode & 0o777, 0o600)

    def test_config_import_is_copy_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder) / "home"
            source = home / ".config/jcode/openai-compatible.env"
            source.parent.mkdir(parents=True)
            source.write_text("PRIVATE_TEST_KEY=not-a-real-key\n")
            before = snapshot(home)
            state = home / ".cyber-jcode"
            import_settings(home, state)
            target = state / "engine/config/jcode/openai-compatible.env"
            self.assertEqual(target.read_text(), source.read_text())
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            target.write_text("PRIVATE_TEST_KEY=independent\n")
            import_settings(home, state)
            self.assertIn("independent", target.read_text())
            self.assertEqual(snapshot(home), before)


if __name__ == "__main__":
    unittest.main()
