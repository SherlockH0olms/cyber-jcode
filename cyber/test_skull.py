"""Skull routing, native terminal handoff and per-child isolation."""
import contextlib
import io
import os
import signal
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cyber.console import Backend, Console, main, read_json, write_json
from cyber.test_console import args


class SkullTests(unittest.TestCase):
    def test_environment_is_scoped_and_preserves_text_only_guard(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
            "JCODE_TUI_HIDE_THINKING": "inherited", "JCODE_SOCKET": "original.sock"
        }):
            backend = Backend(Path(folder))
            normal = backend.environment()
            skull = backend.skull_environment()
            self.assertNotIn("JCODE_TUI_HIDE_THINKING", normal)
            self.assertEqual(skull["JCODE_TUI_HIDE_THINKING"], "1")
            self.assertNotEqual(skull["JCODE_SOCKET"], normal["JCODE_SOCKET"])
            self.assertEqual(skull["JCODE_HOME"], normal["JCODE_HOME"])
            self.assertEqual(skull["JCODE_DISABLE_IMAGE_INPUT"], "1")
            self.assertEqual(os.environ["JCODE_SOCKET"], "original.sock")
            self.assertEqual(os.environ["JCODE_TUI_HIDE_THINKING"], "inherited")

    def test_native_command_keeps_connection_without_headless_options(self):
        backend = Backend(Path("/tmp/cyber-skull-test"))
        command = backend.skull_command("openai-compatible", "my-model", "my-profile", Path("/tmp/chat"))
        self.assertEqual(command[0], str(backend.binary))
        self.assertIn("--no-selfdev", command)
        self.assertIn("--no-update", command)
        for flag, value in (("--provider", "openai-compatible"), ("--model", "my-model"),
                            ("--provider-profile", "my-profile"), ("--cwd", "/tmp/chat")):
            self.assertEqual(command[command.index(flag) + 1], value)
        for forbidden in ("run", "--json", "--quiet", "--resume", "--tool-profile"):
            self.assertNotIn(forbidden, command)

    def test_terminal_handoff_preserves_active_pentest(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            settings = {"target": "lab.test", "session_id": "pentest-session",
                        "engagement_path": "checkpoint.json", "last_result": "result.json",
                        "last_docx": "report.docx", "pending_instructions": ["existing clue"]}
            write_json(state / "console.json", settings)
            console = Console(state, args())
            binary = state / "engine-test"
            binary.touch()
            console.backend.binary = binary
            previous_sigint = signal.getsignal(signal.SIGINT)
            with contextlib.redirect_stdout(io.StringIO()), \
                 patch("sys.stdin.isatty", return_value=True), patch("sys.stdout.isatty", return_value=True), \
                 patch("cyber.console.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
                self.assertEqual(console.skull(), 0)
            self.assertIs(signal.getsignal(signal.SIGINT), previous_sigint)
            self.assertEqual(console.session_id, "pentest-session")
            saved = read_json(state / "console.json")
            for key, value in settings.items():
                self.assertEqual(saved[key], value)
            handoff = run.call_args_list[0]
            command = handoff.args[0]
            self.assertEqual(command[command.index("--cwd") + 1], str(state / "skull/workspace"))
            self.assertNotIn("capture_output", handoff.kwargs)
            self.assertNotIn("stdin", handoff.kwargs)
            self.assertEqual(handoff.kwargs["env"]["JCODE_TUI_HIDE_THINKING"], "1")
            socket = command[command.index("--socket") + 1]
            self.assertEqual(socket, handoff.kwargs["env"]["JCODE_SOCKET"])
            self.assertEqual(run.call_args_list[1].args[0], command + ["server", "stop"])

    def test_number_and_name_return_to_menu(self):
        for choice in ("12", "skull"):
            with self.subTest(choice=choice), tempfile.TemporaryDirectory() as folder:
                console = Console(Path(folder), args())
                with patch.object(console, "ask", side_effect=[choice, "0"]), \
                     patch.object(console, "skull", return_value=0) as skull, \
                     patch.object(console, "execute") as execute, \
                     contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(console.loop(), 0)
                skull.assert_called_once_with()
                execute.assert_not_called()

    def test_each_launch_uses_a_fresh_daemon_and_current_model(self):
        with tempfile.TemporaryDirectory() as folder:
            console = Console(Path(folder), args())
            console.backend.binary = Path(folder) / "engine-test"
            console.backend.binary.touch()
            with contextlib.redirect_stdout(io.StringIO()), \
                 patch("sys.stdin.isatty", return_value=True), patch("sys.stdout.isatty", return_value=True), \
                 patch("cyber.console.subprocess.run", return_value=subprocess.CompletedProcess([], 0)) as run:
                console.skull()
                console.provider, console.model, console.profile = "openai-compatible", "updated-model", "updated-profile"
                console.skull()
            first, second = run.call_args_list[0], run.call_args_list[2]
            self.assertNotEqual(first.kwargs["env"]["JCODE_SOCKET"], second.kwargs["env"]["JCODE_SOCKET"])
            self.assertEqual(second.args[0][second.args[0].index("--model") + 1], "updated-model")
            self.assertEqual(second.args[0][second.args[0].index("--provider-profile") + 1], "updated-profile")

    def test_cli_alias_and_flag(self):
        for argv in (["skull"], ["--skull"]):
            with self.subTest(argv=argv), tempfile.TemporaryDirectory() as folder, \
                 patch.dict(os.environ, {"CYBER_JCODE_HOME": folder}), \
                 patch.object(Console, "skull", return_value=0) as skull, \
                 patch.object(Console, "loop") as loop:
                self.assertEqual(main(argv), 0)
                skull.assert_called_once_with()
                loop.assert_not_called()

    def test_requires_terminal_and_handles_missing_engine(self):
        with tempfile.TemporaryDirectory() as folder:
            console = Console(Path(folder), args())
            console.backend.binary = Path(folder) / "missing"
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(console.skull(), 1)
            self.assertIn("Engine missing", output.getvalue())
            console.backend.binary.touch()
            with patch("sys.stdin.isatty", return_value=False), \
                 patch("cyber.console.subprocess.run") as run, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(console.skull(), 1)
            self.assertIn("interactive terminal", output.getvalue())
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
