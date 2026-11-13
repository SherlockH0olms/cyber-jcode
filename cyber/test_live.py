"""Live input and phase instructions must preserve the active work and evidence."""
import asyncio
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from prompt_toolkit import PromptSession
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

from cyber.console import Console, ProgressDisplay, RunResult, tool_action
from cyber.live import run_with_input
from cyber.test_console import args


class ToolActionTests(unittest.TestCase):
    def test_tool_heading_is_english_and_hides_transport_identifier(self):
        tool = {"id": "chatcmpl-tool-86dda3d619e9ca09", "name": "bash",
                "command": "sudo nmap -sV 10.10.10.10", "output": "80/tcp open", "error": False}
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()) as output:
            console = Console(Path(folder), args())
            console.show_tool(tool)
            console.show_result({"tools": [tool], "summary": {"status": "ok"}})
        self.assertIn("Nmap | Port and service scan", output.getvalue())
        self.assertNotIn("chatcmpl-tool", output.getvalue())
        self.assertEqual(tool_action({"name": "write"}), "File | Save evidence")

    def test_phase_instruction_continues_and_reaches_next_prompt(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            console = Console(Path(folder), args())
            with patch.object(console, "ask", return_value="New clue: Alice / DEMO42"):
                self.assertEqual(console.phase_answer("phase > "), "y")
            self.assertIn("Alice / DEMO42", console.prompt("Next phase", "PENTEST"))
            console.set_target("new-target")
            self.assertEqual(console.pending_instructions, [])


class TtyText(io.StringIO):
    def isatty(self):
        return True


class LiveInputTests(unittest.IsolatedAsyncioTestCase):
    async def test_stop_explicitly_cancels_only_the_running_task(self):
        with tempfile.TemporaryDirectory() as folder, create_pipe_input() as pipe:
            console = Console(Path(folder), args())
            console._prompt_session = PromptSession(input=pipe, output=DummyOutput())
            started = asyncio.Event()
            cancelled = asyncio.Event()
            async def engine(*unused, **kwargs):
                started.set()
                try:
                    await asyncio.sleep(30)
                except asyncio.CancelledError:
                    cancelled.set()
                    raise
            console.backend.run = engine
            async def stop():
                await started.wait()
                pipe.send_text("/stop\n")
            producer = asyncio.create_task(stop())
            with patch.object(sys, "stdin", TtyText()), contextlib.redirect_stdout(TtyText()):
                with self.assertRaises(KeyboardInterrupt):
                    await run_with_input(console, "Task", "TASK", "", ProgressDisplay(100), lambda _: None)
            await producer
            self.assertTrue(cancelled.is_set())

    async def test_input_is_sent_while_engine_runs_without_cancellation(self):
        with tempfile.TemporaryDirectory() as folder, create_pipe_input() as pipe:
            console = Console(Path(folder), args())
            console._prompt_session = PromptSession(input=pipe, output=DummyOutput())
            started = asyncio.Event()
            observed = []
            async def engine(prompt, workspace, session_id, *unused, instructions=None, on_instruction=None, **kwargs):
                started.set()
                text = await asyncio.wait_for(instructions.get(), 5)
                observed.append(text)
                on_instruction("queued")
                await asyncio.sleep(0.05)  # active work finishes normally
                on_instruction("applied")
                return RunResult(session_id="same-session", tools=[{"name": "bash", "output": "OWNED_TOOL_COMPLETED"}],
                                 summary={"status": "ok", "findings": ["Done"], "flags": [], "next": []})
            console.backend.run = engine
            async def send():
                await started.wait()
                pipe.send_text("Use this additional clue\n")
            producer = asyncio.create_task(send())
            with patch.object(sys, "stdin", TtyText()), contextlib.redirect_stdout(TtyText()) as output:
                result = await run_with_input(console, "Continue task", "TASK", "", ProgressDisplay(100), lambda _: None)
            await producer
            self.assertEqual(observed, ["Use this additional clue"])
            self.assertIsNone(result.error)
            self.assertEqual(result.session_id, "same-session")
            self.assertIn("OWNED_TOOL_COMPLETED", result.tools[0]["output"])
            self.assertIn("Instruction applied", output.getvalue())

    async def test_late_instruction_continues_same_session_and_merges_evidence(self):
        with tempfile.TemporaryDirectory() as folder, create_pipe_input() as pipe:
            console = Console(Path(folder), args())
            console._prompt_session = PromptSession(input=pipe, output=DummyOutput())
            calls = []
            async def engine(prompt, workspace, session_id, *unused, **kwargs):
                calls.append((prompt, session_id))
                await asyncio.sleep(0.05)
                return RunResult(session_id="same-session", tools=[{"name": "bash", "output": f"tool-{len(calls)}"}],
                    summary={"status": "ok", "findings": [], "flags": [], "next": []},
                    pending_instructions=["Late clue"] if len(calls) == 1 else [])
            console.backend.run = engine
            with patch.object(sys, "stdin", TtyText()), contextlib.redirect_stdout(TtyText()):
                result = await run_with_input(console, "Initial task", "TASK", "", ProgressDisplay(100), lambda _: None)
            self.assertEqual(len(calls), 2)
            self.assertEqual(calls[1][1], "same-session")
            self.assertIn("Late clue", calls[1][0])
            self.assertEqual(len(result.tools), 2)


if __name__ == "__main__":
    unittest.main()
