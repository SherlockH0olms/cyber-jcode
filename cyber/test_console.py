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
from cyber.console import (Backend, Console, ProgressDisplay, RunProgress, cells,
                           clean, display_tool, fit, forward_command, main, parse_result,
                           read_json, write_json)
from cyber.install import import_settings, link_launcher, snapshot


FINAL = '[CYBER_RESULT]\n{"status":"ok","findings":["File inspected."],"flags":["THM{test_only}"],"next":[]}\n[/CYBER_RESULT]'
BG_OUTPUT = ("Background task finished.\n\nTask: task-123\nName: HIDDEN_INTERNAL_TASK_LABEL\n"
             "Tool: bash\nStatus: completed\nSession: HIDDEN_SESSION\nDuration: 29.26s\n"
             "Exit code: 0\nNotify: true\nWake: false\nRecent events:\n- Completed\n"
             "\nOutput preview:\n```text\nPORT STATE SERVICE\n445/tcp open microsoft-ds\n"
             "--- Command finished with exit code: 0 ---\n```\n")
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
if "--tool-profile" in sys.argv and sys.argv[sys.argv.index("--tool-profile") + 1] == "none":
    emit({"type":"done","session_id":"greeting_session","text":"[CYBER_RESULT]" + json.dumps({"status":"ok","findings":["Hello there."],"flags":[],"next":[]}) + "[/CYBER_RESULT]"})
    sys.exit(0)
emit({"type":"tool_start","id":"scan","name":"bash"})
emit({"type":"tool_exec","id":"scan","name":"bash"})
if mode == "delayed":
    time.sleep(1.2)
if mode == "background":
    emit({"type":"tool_done","id":"scan","name":"bash","output":"Tool 'bash' was moved to background automatically after 3 seconds (task_id: bg123).\\n\\nHIDDEN_SYSTEM_GUIDANCE"})
    time.sleep(1.2)
    emit({"type":"tool_done","id":"wait","name":"bg","output":"Background task finished.\\n\\nTask: bg123\\nTool: bash\\nStatus: completed\\n\\nOutput preview:\\n```text\\nscan output\\n```\\n"})
emit({"type":"tool_done","id":"scan","name":"bash","output":"scan output\\nTHM{test_only}","error":False})
emit({"type":"tool_done","name":"read","output":"X" * 100000,"error":False})
emit({"type":"done","session_id":"session_test","text":"HIDDEN_REASONING_AND_CHAT\\n[CYBER_RESULT]\\n" + json.dumps({"status":"ok","findings":["File inspected."],"flags":["THM{test_only}","THM{invented}"],"next":[]}) + "\\n[/CYBER_RESULT]"})
'''


def args(**overrides):
    values = dict(target=None, provider=None, model=None, provider_profile=None, cwd=None, no_color=True,
                  full_output=False, menu=False, check=False, run=None)
    values.update(overrides)
    return argparse.Namespace(**values)


class RenderingTests(unittest.TestCase):
    def test_only_explicit_final_result_survives(self):
        data = parse_result("secret planning\n" + FINAL + "\nsecret conversation")
        self.assertEqual(data["findings"], ["File inspected."])
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

    def test_progress_rendering_is_sparse_and_fits_terminal_cells(self):
        output = io.StringIO()
        progress = RunProgress(active={"id": "旗" * 20})
        with contextlib.redirect_stdout(output):
            display = ProgressDisplay(24)
            for second in range(31):
                progress.elapsed = second
                display(progress)
            display.finish()
        self.assertEqual(len(output.getvalue().splitlines()), 4)
        self.assertTrue(all(cells(row) <= 24 for row in output.getvalue().splitlines()))
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(output, "isatty", return_value=True):
            display = ProgressDisplay(24)
            display(progress)
            display.finish()
        self.assertTrue(output.getvalue().startswith("\r"))
        self.assertTrue(output.getvalue().endswith("\n"))

    def test_background_output_unwraps_actual_results_and_keeps_failures(self):
        result = display_tool({"name": "bg", "output": BG_OUTPUT})
        self.assertEqual(result, {"name": "bash", "error": False,
                                 "output": "PORT STATE SERVICE\n445/tcp open microsoft-ds"})
        self.assertIsNone(display_tool({"name": "bash", "output":
            "Command started in background as requested.\n\nTask ID: test123\n"}))
        self.assertIsNone(display_tool({"name": "bash", "output":
            "Tool 'bash' was moved to background automatically after 3 seconds (task_id: test123).\n"}))
        failed = display_tool({"name": "bg", "output": BG_OUTPUT.replace("Exit code: 0", "Exit code: 1")})
        self.assertTrue(failed["error"])
        self.assertIn("445/tcp", failed["output"])
        unknown = "Actual command output mentions Output preview: and should survive."
        self.assertEqual(display_tool({"name": "bash", "output": unknown})["output"], unknown)

    def test_result_summary_precedes_outputs_without_losing_long_findings(self):
        finding = "TCP ports: 80, 135, 139, 445, 5040, 5985, 47001, 49666, 49667; Windows 11/Server 2025 Build 26100."
        with tempfile.TemporaryDirectory() as folder:
            console = Console(Path(folder), args())
            console.width = 40
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                console.show_result({"target": "10.10.10.10", "elapsed": 958.6,
                    "summary": {"status": "ok", "findings": [finding]},
                    "tools": [{"name": "bg", "output": BG_OUTPUT}, {"name": "bash", "output":
                        "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<!doctype html><html>\n"
                        "<title>Lab application</title>\n<style>HIDDEN_PAGE_SOURCE</style></html>"}]})
            rendered = output.getvalue()
            for row in rendered.splitlines():
                self.assertLessEqual(cells(row), 40)
            self.assertLess(rendered.index("TCP ports"), rendered.index("TOOL OUTPUTS"))
            for token in ("49667", "26100", "445/tcp", "Lab application", "15m 58s"):
                self.assertIn(token, rendered)
            for forbidden in ("HIDDEN_INTERNAL", "HIDDEN_SESSION", "Recent events", "HIDDEN_PAGE_SOURCE"):
                self.assertNotIn(forbidden, rendered)

    def test_written_notes_remain_visible_as_real_tool_output(self):
        with tempfile.TemporaryDirectory() as folder:
            console = Console(Path(folder), args())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                console.show_result({"summary": {"status": "ok", "findings": []},
                    "tools": [{"name": "write", "output": "Created /tmp/lab/notes.md (3 lines):\n"
                               "1+ # Service discovery\n2+ | Port | Service |\n3+ | 445/tcp | SMB |\n"
                               "\nFile diff:\n```diff\n+| 445/tcp | SMB |\n```"}]})
            for text in ("notes.md", "Service discovery", "Port | Service", "445/tcp | SMB"):
                self.assertIn(text, output.getvalue())
            self.assertEqual(output.getvalue().count("445/tcp | SMB"), 1)

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
        self.assertIn("authentication failed", result.error)
        self.assertNotIn("SECRET_TOKEN", result.error)

    async def test_previously_observed_flag_can_be_recalled(self):
        result = await self.backend.run("task", self.folder / "lab", "prior_session",
                                        "auto", "", verified_flags=["THM{invented}"])
        self.assertEqual(result.summary["flags"], ["THM{test_only}", "THM{invented}"])

    async def test_missing_terminal_event_is_failure(self):
        with patch.dict(os.environ, {"CYBER_TEST_MODE":"missing_done"}):
            result = await self.backend.run("task", self.folder / "lab", None, "auto", "")
        self.assertIsNotNone(result.error)

    async def test_progress_continues_while_tool_waits_and_hides_payloads(self):
        snapshots = []
        def observe(progress):
            snapshots.append((progress.elapsed, progress.row()))
        with patch.dict(os.environ, {"CYBER_TEST_MODE": "delayed"}):
            result = await self.backend.run("task", self.folder / "lab", None,
                                            "auto", "", progress=observe)
        self.assertIsNone(result.error)
        self.assertTrue(any(elapsed >= 1 and "Running: bash" in row for elapsed, row in snapshots))
        self.assertTrue(any("1 done / 0 active" in row for _, row in snapshots))
        self.assertTrue(any("2 done / 0 active" in row for _, row in snapshots))
        self.assertNotIn("HIDDEN", str(snapshots))
        size = len(snapshots)
        await asyncio.sleep(1.1)
        self.assertEqual(len(snapshots), size, "Ticker must finish with its process")

    async def test_background_tool_stays_active_until_completion(self):
        snapshots = []
        with patch.dict(os.environ, {"CYBER_TEST_MODE": "background"}):
            result = await self.backend.run("task", self.folder / "lab", None,
                "auto", "", progress=lambda progress: snapshots.append((progress.elapsed, progress.row())))
        self.assertIsNone(result.error)
        self.assertTrue(any(elapsed >= 1 and "Running: bash" in row and "1 active" in row
                            for elapsed, row in snapshots))
        self.assertIn("0 active", snapshots[-1][1])
        self.assertNotIn("HIDDEN_SYSTEM", str(snapshots))
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
    def test_greeting_calls_model_without_tools_or_changing_lab_state(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            binary = folder / "fake-engine"
            binary.write_text(FAKE_ENGINE)
            binary.chmod(0o755)
            console = Console(folder / "state", args())
            console.backend = Backend(console.state, binary)
            console.target = "10.10.10.10"
            console.session_id = "existing_lab_session"
            console.last_path = "existing_result"
            console.verified_flags = ["THM{already_verified}"]
            console.persist()
            before = (console.state / "console.json").read_bytes()
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertTrue(console.execute("HI!"))
            self.assertIn("[+] Hello there.", output.getvalue())
            self.assertNotIn("File inspected", output.getvalue())
            invocation = read_json(console.state / "engine/invocation.json")
            self.assertIn("--tool-profile", invocation["argv"])
            self.assertIn("none", invocation["argv"])
            self.assertNotIn("--resume", invocation["argv"])
            self.assertNotIn(console.target, invocation["argv"][-1])
            self.assertEqual(invocation["env"]["JCODE_RUN_AUTO_POKE"], "0")
            self.assertEqual((console.state / "console.json").read_bytes(), before)
            self.assertEqual(console.session_id, "existing_lab_session")
            self.assertFalse((console.state / "results").exists())

    def test_provider_cli_preserves_arguments_stdin_and_isolates_default(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            write_json(state / "console.json", {"target": "10.10.10.10", "provider": "auto",
                       "model": "old-model", "profile": "old-profile", "session_id": "lab",
                       "verified_flags": ["THM{prior}"]})
            command = ["provider", "add", "my-api", "--base-url", "http://localhost:1234/v1",
                       "--model", "new-model", "--api-key-stdin", "--set-default"]
            with patch("cyber.console.subprocess.run") as run:
                run.return_value.returncode = 0
                self.assertEqual(forward_command(state, command), 0)
            self.assertEqual(run.call_args.args[0][-len(command):], command)
            self.assertNotIn("stdin", run.call_args.kwargs)
            self.assertEqual(run.call_args.kwargs["env"]["JCODE_HOME"], str(state / "engine"))
            self.assertEqual(run.call_args.kwargs["env"]["XDG_CONFIG_HOME"], str(state / "engine/config"))
            settings = read_json(state / "console.json")
            self.assertEqual(settings["target"], "10.10.10.10")
            self.assertEqual(settings["model"], "")
            self.assertEqual(settings["profile"], "")
            self.assertIsNone(settings["session_id"])
            before = (state / "console.json").read_bytes()
            with patch("cyber.console.subprocess.run") as run:
                run.return_value.returncode = 1
                self.assertEqual(forward_command(state, command), 1)
            self.assertEqual((state / "console.json").read_bytes(), before)

    def test_provider_help_dispatches_without_starting_console(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {"CYBER_JCODE_HOME": folder}):
            with patch("cyber.console.forward_command", return_value=0) as forward:
                self.assertEqual(main(["provider", "add", "--help"]), 0)
            self.assertEqual(forward.call_args.args, (Path(folder), ["provider", "add", "--help"]))

    def test_model_header_uses_private_defaults_and_selected_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            (state / "engine").mkdir()
            (state / "engine/config.toml").write_text(
                '[provider]\ndefault_provider="my-api"\ndefault_model="current-model"\n'
                '[providers.other]\ndefault_model="other-model"\napi_key="HIDDEN_KEY"\n')
            console = Console(state, args())
            self.assertEqual(console.model_label(), "current-model")
            console.profile = "other"
            self.assertEqual(console.model_label(), "other-model")
            console.model = "explicit-model"
            self.assertEqual(console.model_label(), "explicit-model")

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

    def test_all_menu_tasks_and_free_prompts_use_the_common_execution_flow(self):
        with tempfile.TemporaryDirectory() as folder:
            sample = Path(folder) / "sample.txt"
            sample.write_text("local lab note")
            console = Console(Path(folder) / "state", args(target="10.10.10.10"))
            choices = ["2", "3", "4", "5", "6", str(sample), "inspect another service", "0"]
            with patch.object(console, "ask", side_effect=choices), \
                    patch.object(console, "execute", return_value=True) as execute, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(console.loop(), 0)
            self.assertEqual(execute.call_count, 6)
            self.assertEqual([call.args[1] for call in execute.call_args_list[:5]],
                             ["SERVICE DISCOVERY", "WEB DISCOVERY", "VULNERABILITY REVIEW", "FLAG SEARCH", "FILE"])
            self.assertEqual(execute.call_args_list[-1].args[0], "inspect another service")

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
