"""Opt-in integration: compiled engine, local fake API, no lab or real model calls.

CYBER_JCODE_TEST_ENGINE=1 python3 -m unittest cyber.test_engine_textonly -v
"""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

from cyber.console import Backend, ROOT


@unittest.skipUnless(os.environ.get("CYBER_JCODE_TEST_ENGINE") == "1", "opt-in compiled-engine test")
class EngineTextOnlyTests(unittest.TestCase):
    def test_image_tool_and_resumed_image_history_never_reach_api(self):
        requests = []
        image_path = None
        emitted_read = False

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *unused):
                pass

            def do_GET(self):
                body = json.dumps({"data": [{"id": "text-only-test-model", "object": "model"}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                nonlocal emitted_read
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append(data)
                if data.get("tools") and not emitted_read:
                    emitted_read = True
                    message = {"role": "assistant", "content": None, "tool_calls": [{
                        "id": "call_image_read", "type": "function", "function": {
                            "name": "read", "arguments": json.dumps({"file_path": str(image_path)})}}]}
                    delta = {"tool_calls": [dict(message["tool_calls"][0], index=0)]}
                    finish = "tool_calls"
                else:
                    text = '[CYBER_RESULT]{"status":"ok","findings":["Text-only context retained."],"flags":[],"next":[]}[/CYBER_RESULT]'
                    message = {"role": "assistant", "content": text}
                    delta = {"content": text}
                    finish = "stop"
                if data.get("stream"):
                    chunks = [
                        {"id": "test", "object": "chat.completion.chunk", "model": "text-only-test-model",
                         "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
                        {"id": "test", "object": "chat.completion.chunk", "model": "text-only-test-model",
                         "choices": [{"index": 0, "delta": {}, "finish_reason": finish}]}]
                    body = ("".join("data: " + json.dumps(chunk) + "\n\n" for chunk in chunks) + "data: [DONE]\n\n").encode()
                    mime = "text/event-stream"
                else:
                    body = json.dumps({"id": "test", "object": "chat.completion", "model": "text-only-test-model",
                        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 10}}).encode()
                    mime = "application/json"
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        with tempfile.TemporaryDirectory(prefix="cyber-engine-test-") as folder:
            root = Path(folder)
            image_path = root / "evidence.png"
            from PIL import Image
            Image.new("RGB", (20, 20), "white").save(image_path)
            backend = Backend(root / "state")
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                setup = subprocess.run(backend.command() + ["provider", "add", "local-image-test",
                    "--base-url", f"http://127.0.0.1:{server.server_port}/v1", "--model", "text-only-test-model",
                    "--no-api-key", "--set-default"], env=backend.environment(), capture_output=True, text=True, timeout=30)
                self.assertEqual(setup.returncode, 0, setup.stderr[:1000])
                async def run(session=None):
                    return await asyncio.wait_for(backend.run("Read the local evidence file and return the short result. TEXT_CONTEXT_MARKER",
                        root / "workspace", session, "openai-compatible", "text-only-test-model", "local-image-test"), timeout=90)
                result = asyncio.run(run())
                self.assertIsNone(result.error, result.error)
                self.assertTrue(emitted_read)
                self.assertTrue(any("Image reading is disabled" in tool.get("output", "") for tool in result.tools))
                path = backend.state / "engine/sessions" / f"{result.session_id}.json"
                saved = json.loads(path.read_text())
                self.assertTrue(saved["messages"])
                # Simulate a legacy persisted screenshot while retaining text and tool context.
                saved["messages"][0]["content"].append({"type": "image", "media_type": "image/png", "data": "PRIVATE_LEGACY_IMAGE"})
                path.write_text(json.dumps(saved))
                resumed = asyncio.run(run(result.session_id))
                self.assertIsNone(resumed.error, resumed.error)
                self.assertEqual(resumed.session_id, result.session_id)
                encoded = json.dumps(requests)
                self.assertNotIn('"type": "image_url"', encoded)
                self.assertNotIn("data:image/", encoded)
                self.assertNotIn("PRIVATE_LEGACY_IMAGE", encoded)
                self.assertIn("TEXT_CONTEXT_MARKER", encoded)
                self.assertIn("Screenshot retained on disk", encoded)
                # Projection must not delete the historical evidence or reset the assessment.
                persisted = json.loads(path.read_text())
                self.assertTrue(any(block.get("data") == "PRIVATE_LEGACY_IMAGE"
                    for message in persisted["messages"] for block in message["content"]))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
