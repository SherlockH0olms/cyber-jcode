"""Opt-in native TUI test: real engine, PTY and local fake model only.

Install the optional terminal emulator with: pip install pyte
CYBER_JCODE_TEST_ENGINE=1 python3 -m unittest cyber.test_skull_engine -v
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import shlex
import signal
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from cyber.console import Backend, ROOT, read_json, write_json


@unittest.skipUnless(os.environ.get("CYBER_JCODE_TEST_ENGINE") == "1", "opt-in compiled-engine test")
class SkullEngineTests(unittest.TestCase):
    def test_native_chat_hides_reasoning_keeps_tools_and_returns_to_menu(self):
        import fcntl
        import pty
        import termios
        import pyte

        requests = []
        evidence = None
        reasoning = "PRIVATE_SKULL_REASONING"
        answer = "SKULL_ASSISTANT_ANSWER"
        tool_output = "SKULL_REAL_TOOL_OUTPUT"

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *unused):
                pass

            def do_GET(self):
                self.respond({"data": [{"id": "skull-test-model", "object": "model"}]})

            def respond(self, data):
                body = json.dumps(data).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append(data)
                has_result = any(message.get("role") == "tool" for message in data.get("messages", []))
                if data.get("tools") and not has_result:
                    delta = {"tool_calls": [{"index": 0, "id": "call_skull_shell", "type": "function",
                        "function": {"name": "bash", "arguments": json.dumps({"command": "cat " + shlex.quote(str(evidence))})}}]}
                    finish = "tool_calls"
                else:
                    delta = {"content": answer}
                    finish = "stop"
                if not data.get("stream"):
                    self.respond({"id": "skull-test", "model": "skull-test-model",
                        "choices": [{"message": dict(delta, role="assistant"), "finish_reason": finish}]})
                    return
                chunks = [{"id": "skull-test", "object": "chat.completion.chunk", "model": "skull-test-model",
                    "choices": [{"index": 0, "delta": part, "finish_reason": reason}]} for part, reason in (
                        ({"reasoning_content": reasoning + "\n"}, None), (delta, None), ({}, finish))]
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                for chunk in chunks:
                    self.wfile.write(("data: " + json.dumps(chunk) + "\n\n").encode())
                    self.wfile.flush()
                    # Give the normal TUI enough time to actually render reasoning.
                    time.sleep(0.35)
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

        with tempfile.TemporaryDirectory(prefix="cyber-skull-engine-") as folder:
            root = Path(folder)
            evidence = root / "evidence.txt"
            evidence.write_text(tool_output + "\n")
            backend = Backend(root / "state")
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                setup = subprocess.run(backend.command() + ["provider", "add", "skull-test",
                    "--base-url", f"http://127.0.0.1:{server.server_port}/v1", "--model", "skull-test-model",
                    "--no-api-key", "--set-default"], env=backend.environment(),
                    capture_output=True, text=True, timeout=30)
                self.assertEqual(setup.returncode, 0, setup.stderr[:1000])
                config = backend.state / "engine/config.toml"
                config.write_text(config.read_text() + "\n[display]\nreasoning_display = 'full'\nshow_bash_output = true\n")
                config_before = config.read_bytes()

                def drive(command, env, menu=False):
                    env = dict(env, TERM="xterm-256color", COLUMNS="140", LINES="48")
                    pid, fd = pty.fork()
                    if pid == 0:
                        os.execvpe(command[0], command, env)
                    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 48, 140, 0, 0))
                    screen = pyte.Screen(140, 48)
                    stream = pyte.ByteStream(screen)
                    frames = []

                    def drain(duration):
                        deadline = time.monotonic() + duration
                        while time.monotonic() < deadline:
                            ready, _, _ = select.select([fd], [], [], min(0.1, max(0, deadline - time.monotonic())))
                            if ready:
                                try:
                                    chunk = os.read(fd, 65536)
                                except OSError:
                                    break
                                if not chunk:
                                    break
                                stream.feed(chunk)
                                frames.append("\n".join(screen.display))
                                if b"\x1b[6n" in chunk:
                                    os.write(fd, b"\x1b[1;1R")
                        return "\n".join(frames)

                    try:
                        drain(3)
                        if menu:
                            os.write(fd, b"12\r")
                            drain(3)
                        if "How would you like to begin?" in "\n".join(screen.display):
                            # Pick the native first-run "New session" action.
                            os.write(fd, b"\x1b[C\r")
                            drain(1)
                        os.write(fd, f"\x1b[200~Read the local file {evidence} and reply briefly.\x1b[201~\r".encode())
                        deadline = time.monotonic() + 35
                        while time.monotonic() < deadline:
                            rendered = drain(0.3)
                            if answer in rendered and tool_output in rendered:
                                break
                        self.assertTrue(answer in rendered, rendered[-1600:])
                        self.assertTrue(tool_output in rendered, rendered[-1600:])
                        # A restored answer may already be on screen. Let the
                        # new stream finish before testing /quit and daemon cleanup.
                        rendered = drain(1.2)
                        if menu:
                            os.write(fd, b"/thinking-display full\r")
                            rendered = drain(1)
                            self.assertIn("Skull keeps thinking text hidden", rendered)
                        os.write(fd, b"/quit\r")
                        rendered = drain(3)
                        if menu:
                            self.assertIn("Returned to Cyber-Jcode", rendered)
                            os.write(fd, b"0\r")
                            drain(1)
                        return rendered
                    finally:
                        try:
                            waited, _ = os.waitpid(pid, os.WNOHANG)
                            if waited == 0:
                                os.kill(pid, signal.SIGTERM)
                                os.waitpid(pid, 0)
                        except ProcessLookupError:
                            pass
                        os.close(fd)

                normal = backend.command("openai-compatible", "skull-test-model", "skull-test")
                normal += ["--cwd", str(root)]
                ordinary = drive(normal, backend.environment())
                self.assertIn(reasoning, ordinary, "normal Jcode must still render configured thinking")
                # Select 12 through the installed Python frontend, with an existing lab session.
                settings = {"target": "preserved.test", "session_id": "existing-pentest",
                            "engagement_path": "checkpoint.json", "provider": "openai-compatible",
                            "model": "skull-test-model", "profile": "skull-test"}
                write_json(backend.state / "console.json", settings)
                skull_env = dict(backend.environment(), CYBER_JCODE_HOME=str(backend.state))
                skull = drive([str(ROOT / "cyber-jcode")], skull_env, menu=True)
                self.assertNotIn(reasoning, skull)
                self.assertEqual(config.read_bytes(), config_before, "Skull must not change saved display settings")
                saved = read_json(backend.state / "console.json")
                for key, value in settings.items():
                    self.assertEqual(saved[key], value)
                # The normal TUI session contains retained reasoning. Reopen it
                # in Skull to verify history does not bypass the display override.
                sessions = sorted((backend.state / "engine/sessions").glob("*.json"))
                retained = next(path for path in sessions if reasoning in path.read_text())
                resumed_command = backend.skull_command("openai-compatible", "skull-test-model", "skull-test", root)
                resumed = drive(resumed_command + ["--resume", retained.stem], backend.skull_environment())
                self.assertNotIn(reasoning, resumed, "resumed thinking must stay hidden")
                self.assertTrue(any(tool_output in json.dumps(request) for request in requests))
                self.assertNotIn("[CYBER_RESULT]", json.dumps(requests), "Skull uses ordinary chat prompts")
            finally:
                # Stop only the test daemons on their private sockets.
                for command, env in ((backend.command(), backend.environment()),
                                     (backend.skull_command("auto", "", "", root), backend.skull_environment())):
                    subprocess.run(command + ["server", "stop"], env=env, capture_output=True, timeout=20)
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
