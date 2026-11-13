"""A menu terminal over Jcode's real headless agent, with isolated state."""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from html import unescape
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from typing import Callable
import unicodedata
import uuid

VERSION = "0.5.0"
ROOT = Path(__file__).resolve().parent.parent
ANSI = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|"
    r"[PX^_].*?\x1b\\|[@-_])", re.DOTALL
)
HIDDEN_TOOLS = {"think", "thinking", "reasoning", "plan", "todo", "todowrite",
                "todoread", "memory", "skill", "goals", "goal", "set_goal",
                "swarm", "delegate", "subagent", "agent", "spawn_agent"}
TASKS = {
    "2": ("SERVICE DISCOVERY", "Discover the target's open ports and services using real tools. "
          "Record service versions; do not run exploits at this stage."),
    "3": ("WEB DISCOVERY", "Inspect the target's web services. Record HTTP responses, "
          "application details, accessible paths and useful lab findings."),
    "4": ("VULNERABILITY REVIEW", "Review this lab's services and prior findings to identify "
          "verifiable vulnerabilities. A version number alone does not confirm a vulnerability."),
    "5": ("FLAG SEARCH", "Use existing discoveries and session access to find the requested "
          "flags in this TryHackMe/CTF lab using real tools. Preserve observed flags exactly. "
          "Briefly report any missing information or access."),
}
GREETINGS = {"hi", "hello", "hey", "ping"}

# A quiet motto on the menu instead of the engine identity: no fingerprints.
MOTTO = "Fighting in the shadows so others may live in the sun"

# Full pentest engagement phases, executed in order until blocked or stopped.
PENTEST_PHASES = (
    ("recon", "RECON", "Conduct full reconnaissance of the target: ping/host discovery, "
     "a fast all-TCP-port scan (masscan or nmap -p-), then version and script "
     "enumeration on every discovered port. Record open ports, service names and "
     "versions, and the operating system guess in the workspace."),
    ("services", "SERVICE ENUMERATION", "Enumerate each discovered service in depth and look "
     "for credentials: anonymous FTP/SMB shares, SNMP/LDAP dumps, DNS zone data, "
     "default or leaked credentials, and password spraying only with valid "
     "discovered usernames. Preserve all discovered credentials and notes in the "
     "workspace for later phases."),
    ("web", "WEB ANALYSIS", "Analyze every web service: fingerprint with whatweb, "
     "capture real browser screenshots and inspect pages through HTTP/DOM text, enumerate directories and files with "
     "feroxbuster/ffuf/gobuster, review robots.txt, identify frameworks/CMS and "
     "their versions, examine forms, uploads and APIs. Note every interesting "
     "endpoint, file, parameter and technology."),
    ("vulns", "VULNERABILITY VERIFICATION", "Using prior discoveries, verify real "
     "vulnerabilities: nuclei and nikto scans, CMS-specific checks (wpscan), "
     "searchsploit against exact service versions, and targeted manual probes for "
     "weak spots found in web analysis (SQLi, command injection, LFI, misconfig, "
     "default creds). Report only what a real tool or probe confirmed. A version "
     "number alone is not a finding."),
    ("exploit", "EXPLOITATION / INITIAL ACCESS", "Exploit the verified vulnerabilities to "
     "gain an initial foothold on the target. Prefer working public exploits for "
     "the exact verified versions; verify success with a real command result "
     "(id/whoami). Record the access level obtained and any new discoveries. If "
     "multiple paths exist, use the safest reliable one."),
    ("privesc", "PRIVILEGE ESCALATION", "From the current foothold, escalate to the "
     "highest privilege (root on Linux, SYSTEM/Administrator on Windows): local "
     "enumeration (sudo -l, SUID, cron, services, tokens, registry, scheduled "
     "tasks), searchsploit for local exploits matching the kernel/OS version, "
     "and stored credentials. Verify the final privilege with whoami/id. Capture "
     "the root flag if accessible."),
    ("post", "POST-EXPLOITATION", "Perform final post-exploitation: collect remaining "
     "flags and evidence, capture interesting files and configuration, summarize "
     "the full attack chain from first access to highest privilege, and write a "
     "complete summary of the engagement into the workspace notes."),
)


def is_greeting(task: str) -> bool:
    return task.strip().lower().rstrip(".!?") in GREETINGS


def clean(value: object) -> str:
    text = ANSI.sub("", str(value))
    return "".join(c for c in text if c in "\n\t" or
                   not unicodedata.category(c).startswith("C"))


def cells(text: str) -> int:
    return sum(0 if unicodedata.combining(c) else
               2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in text)


def fit(text: object, width: int) -> str:
    text = clean(text).replace("\n", " ").replace("\t", " ")
    if cells(text) <= width:
        return text
    out = ""
    for char in text:
        if cells(out + char) > max(0, width - 1):
            break
        out += char
    return out + ("…" if width else "")


def wrap_rows(text: str, width: int):
    """Result prose may wrap; preserve information instead of truncating it."""
    for paragraph in clean(text).replace("\t", " ").splitlines():
        remaining = paragraph.strip()
        while remaining:
            used = end = 0
            for char in remaining:
                size = cells(char)
                if used + size > width:
                    break
                used += size
                end += 1
            if end == len(remaining):
                yield remaining
                break
            if end == 0:
                yield fit(remaining[0], width)
                remaining = remaining[1:]
                continue
            space = remaining.rfind(" ", 0, end + 1)
            if space > 0:
                end = space
            yield remaining[:end]
            remaining = remaining[end:].lstrip()


def background_started(output: str) -> str | None:
    if output.startswith("Command started in background as requested."):
        match = re.search(r"^Task ID: ([\w-]+)$", output, re.M | re.ASCII)
    elif output.startswith("Tool '") and "was moved to background automatically" in output.splitlines()[0]:
        match = re.search(r"\(task_id: ([\w-]+)\)", output, re.ASCII)
    else:
        return None
    return match.group(1) if match else None


def display_tool(tool: dict) -> dict | None:
    """Unwrap Jcode background envelopes, retaining actual output and failures."""
    name = str(tool.get("name", "tool"))
    output = clean(tool.get("output", ""))
    error = bool(tool.get("error"))
    if background_started(output) and not error:
        return None
    if name == "bg":
        envelope, marker, preview = output.partition("\nOutput preview:\n```text\n")
        status = re.search(r"^Status: (\w+)$", envelope, re.M)
        real_tool = re.search(r"^Tool: ([\w.:/-]{1,64})$", envelope, re.M | re.ASCII)
        task_id = re.search(r"^Task: ([\w-]+)$", envelope, re.M | re.ASCII)
        if status and real_tool and task_id:
            name = real_tool.group(1)
            exit_code = re.search(r"^Exit code: (-?\d+)$", envelope, re.M)
            error |= status.group(1) == "failed" or bool(exit_code and int(exit_code.group(1)))
            if marker:
                output = preview.rstrip().removesuffix("```").rstrip()
            elif error:
                output = "Background command failed" + (f" (exit {exit_code.group(1)})" if exit_code else "") + "."
            else:
                return None
        elif output.startswith(("Background Tasks:", "No matching background tasks found.",
                                "Updated background task delivery", "Waited for background tasks")) and not error:
            return None
    finished = re.search(r"\n?--- Command finished with exit code: (-?\d+) ---\s*$", output)
    if finished:
        error |= int(finished.group(1)) != 0
        output = output[:finished.start()].rstrip()
        if error:
            output += f"\nExit code: {finished.group(1)}"
    return {"name": name, "output": output, "error": error}


def preview_rows(tool: dict) -> list[str]:
    rows = tool["output"].splitlines()
    if tool["name"] == "write" and rows and rows[0].startswith(("Created ", "Updated ", "Wrote ")):
        listing, marker, _ = tool["output"].partition("\nFile diff:\n```diff\n")
        if marker:
            return listing.rstrip().splitlines()
    for index, row in enumerate(rows):
        if re.search(r"<!doctype\s+html|<html(?:\s|>)", row, re.I):
            title = re.search(r"<title[^>]*>(.*?)</title>", tool["output"], re.S | re.I)
            label = unescape(re.sub(r"<[^>]+>", "", title.group(1))) if title else "page source"
            return rows[:index] + [f"HTML response: {fit(label, 80)}", "Full captured output: save"]
    return rows


def tool_action(tool: dict) -> str:
    """Plain action names; opaque model call identifiers stay in saved evidence."""
    name = str(tool.get("name", "tool")).lower()
    command = str(tool.get("command", ""))
    if name in ("bash", "shell", "terminal", "bg"):
        if "capture.py" in command:
            return "Browser | Capture screenshot"
        programs = {
            "nmap": "Nmap | Port and service scan", "masscan": "Masscan | Port discovery",
            "curl": "HTTP | Check response", "wget": "HTTP | Download resource",
            "ffuf": "Ffuf | Discover web paths", "feroxbuster": "Feroxbuster | Discover web paths",
            "gobuster": "Gobuster | Discover web paths", "whatweb": "WhatWeb | Identify web technologies",
            "nuclei": "Nuclei | Check vulnerability templates", "nikto": "Nikto | Check web configuration",
            "smbclient": "SMB | Enumerate shares", "enum4linux": "SMB | Enumerate host information",
            "nxc": "NetExec | Check network service access", "netexec": "NetExec | Check network service access",
            "searchsploit": "Searchsploit | Search exploit references", "whoami": "Identity | Check current user",
        }
        for program, label in programs.items():
            if re.search(r"(?:^|[\s;&|])(?:/[\w./-]+/)?" + re.escape(program) + r"(?=[\s;&|]|$)", command):
                return label
        if str(tool.get("output", "")).startswith("Starting Nmap"):
            return programs["nmap"]
        return "Background | Task results" if name == "bg" else "Shell | Run command"
    return {"read": "File | Read evidence", "write": "File | Save evidence",
            "edit": "File | Update evidence", "grep": "Files | Search content",
            "glob": "Files | Search names", "webfetch": "HTTP | Fetch page",
            "websearch": "Search | Find references"}.get(name, "Tool | " + clean(name))


def private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def write_json(path: Path, value: object) -> None:
    private_dir(path.parent)
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def short_list(value: object, count: int, length: int = 150) -> list[str]:
    if not isinstance(value, list):
        return []
    return [fit(item, length) for item in value[:count]
            if isinstance(item, str) and item.strip()]


def parse_result(text: str) -> dict:
    """Only an explicit final result may be printed; never fall back to prose."""
    text = re.sub(r"<(think|thinking|reasoning)>.*?(?:</\1>|$)", "", text,
                  flags=re.S | re.I)
    matches = list(re.finditer(r"\[CYBER_RESULT\](.*?)\[/CYBER_RESULT\]", text, re.S))
    for match in reversed(matches):
        try:
            data = json.loads(match.group(1).strip())
        except ValueError:
            continue
        if isinstance(data, dict) and data.get("status") in {"ok", "partial", "blocked"}:
            return {
                "status": data["status"],
                "findings": short_list(data.get("findings"), 4),
                "flags": short_list(data.get("flags"), 20, 2048),
                "next": short_list(data.get("next"), 1),
            }
    return {"status": "partial", "findings": ["No short result received; check the tool outputs."],
            "flags": [], "next": []}


def error_message(text: str) -> str:
    text = text.lower()
    if any(part in text for part in ("does not support image", "unsupported image", "image inputs are not supported")):
        return "Model rejects image input. Text-only protection is required; rebuild Cyber-Jcode's engine."
    if re.search(r"\b(?:status(?:\s+code)?\s*[:=]?\s*)?(401|403)\b", text) or any(
            part in text for part in ("invalid api key", "incorrect api key", "missing api key", "unauthorized", "authentication failed")):
        return "Model authentication failed. Settings > Login / connection."
    if any(part in text for part in ("429", "rate limit", "quota", "credit", "balance")):
        return "Model usage limit reached. Try again later."
    if any(part in text for part in ("timeout", "timed out")):
        return "Operation timed out."
    if any(part in text for part in ("does not support tool", "unsupported tool", "tool calling is not supported")):
        return "Model does not support tool calling. Select a tool-capable model."
    if "400 bad request" in text or re.search(r"status\s*:\s*400\b", text):
        return "Model rejected the request format. Check model compatibility and connection settings."
    if any(part in text for part in ("connection refused", "connection error", "dns", "network", "resolve", "502", "503")):
        return "Model server unreachable. Check the connection."
    return "Operation failed. Settings > Connection check."


def visible_tool(name: str) -> bool:
    name = name.lower()
    return name not in HIDDEN_TOOLS and not name.startswith(
        ("think", "reasoning", "todo", "plan_", "memory_", "skill_", "goal_", "subagent", "delegate")
    )


@dataclass
class RunResult:
    session_id: str | None = None
    tools: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    error: str | None = None
    elapsed: float = 0.0
    raw_text: str = ""
    pending_instructions: list[str] = field(default_factory=list)


@dataclass
class RunProgress:
    phase: str = "Connecting"
    active: dict[str, str] = field(default_factory=dict)
    background: dict[str, str] = field(default_factory=dict)
    completed: int = 0
    elapsed: float = 0.0

    def row(self) -> str:
        seconds = int(self.elapsed)
        names = list(dict.fromkeys([*self.active.values(), *self.background.values()]))
        phase = f"Running: {', '.join(names)}" if names else self.phase
        return (f"[*] {seconds // 60:02d}:{seconds % 60:02d} | {phase} | "
                f"Tools: {self.completed} done / {len(self.active) + len(self.background)} active")


class ProgressDisplay:
    """One terminal row; sparse updates for redirected output. No model text."""
    def __init__(self, width: int):
        self.width = width
        self.tty = sys.stdout.isatty()
        self.last_at = -10.0
        self.drawn = False

    def __call__(self, progress: RunProgress):
        if not self.tty and progress.elapsed - self.last_at < 10:
            return
        row = fit(progress.row(), self.width)
        if self.tty:
            print("\r" + row + " " * (self.width - cells(row)), end="", flush=True)
        else:
            print(row, flush=True)
        self.last_at = progress.elapsed
        self.drawn = True

    def finish(self):
        if self.tty and self.drawn:
            print(flush=True)
        self.drawn = False


class Backend:
    def __init__(self, state: Path, binary: Path | None = None):
        self.state = state
        self.binary = binary or ROOT / "target/selfdev/jcode"
        self.interrupted_result = None

    def environment(self) -> dict[str, str]:
        # A parent Jcode session may export its socket and self-dev paths.
        env = {k: v for k, v in os.environ.items() if not k.startswith("JCODE_")}
        env.update({
            "JCODE_HOME": str(self.state / "engine"),
            "JCODE_RUNTIME_DIR": str(self.state / "run"),
            "JCODE_SOCKET": str(self.state / "run/agent-textonly-v1.sock"),
            "JCODE_INSTALL_DIR": str(self.state / "engine/builds"),
            "JCODE_RUN_AUTO_POKE_MAX_TURNS": "6",
            "JCODE_DISABLE_IMAGE_INPUT": "1",
            "XDG_CONFIG_HOME": str(self.state / "engine/config"),
            "XDG_CACHE_HOME": str(self.state / "engine/cache"),
            "XDG_DATA_HOME": str(self.state / "engine/data"),
            "NO_COLOR": "1",
        })
        return env

    def command(self, provider: str = "auto", model: str = "", profile: str = "") -> list[str]:
        cmd = [str(self.binary), "--no-update", "--no-selfdev", "--quiet",
               "--socket", str(self.state / "run/agent-textonly-v1.sock"), "--provider", provider]
        if model:
            cmd.extend(["--model", model])
        if profile:
            cmd.extend(["--provider-profile", profile])
        return cmd

    def skull_environment(self, socket: Path | None = None) -> dict[str, str]:
        env = self.environment()
        env["JCODE_SOCKET"] = str(socket or self.state / "run/skull-textonly-v1.sock")
        env["JCODE_TUI_HIDE_THINKING"] = "1"
        # The native TUI controls its own colors; respect an explicit user setting.
        if "NO_COLOR" not in os.environ:
            env.pop("NO_COLOR", None)
        return env

    def skull_command(self, provider: str, model: str, profile: str, workspace: Path,
                      socket: Path | None = None) -> list[str]:
        cmd = self.command(provider, model, profile)
        cmd.remove("--quiet")
        cmd[cmd.index("--socket") + 1] = str(socket or self.state / "run/skull-textonly-v1.sock")
        return cmd + ["--cwd", str(workspace)]

    async def run(self, prompt: str, workspace: Path, session_id: str | None,
                  provider: str, model: str, profile: str = "",
                  verified_flags: list[str] | None = None,
                  progress: Callable[[RunProgress], None] | None = None,
                  greeting: bool = False,
                  on_tool: Callable[[dict], None] | None = None,
                  capture_tools: bool = False,
                  instructions: asyncio.Queue[str] | None = None,
                  on_instruction: Callable[[str], None] | None = None) -> RunResult:
        result = RunResult(session_id=session_id)
        self.interrupted_result = None
        if not self.binary.is_file():
            result.error = "Engine missing. Complete setup with cyber/install.py."
            return result
        for path in (self.state / "engine", self.state / "run"):
            private_dir(path)
        # A user-supplied workspace retains its existing permissions.
        workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        cmd = self.command(provider, model, profile)
        env = self.environment()
        if instructions is not None:
            env["JCODE_RUN_STDIN_STEERING"] = "1"
        if greeting:
            cmd.extend(["--tool-profile", "none"])
            env["JCODE_RUN_AUTO_POKE"] = "0"
        cmd.extend(["--cwd", str(workspace)])
        if session_id:
            cmd.extend(["--resume", session_id])
        cmd.extend(["run", "--ndjson", prompt])
        start = time.monotonic()
        activity = RunProgress()

        def update():
            activity.elapsed = time.monotonic() - start
            if progress:
                progress(activity)

        async def tick():
            while True:
                await asyncio.sleep(1)
                update()

        update()
        process = await asyncio.create_subprocess_exec(
            *cmd, env=env, cwd=workspace,
            stdin=asyncio.subprocess.PIPE if instructions is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True,
            limit=16 * 1024 * 1024,
        )
        stderr_tail = ""
        done = False
        input_id = None
        tool_inputs = {}
        background_commands = {}
        sent_instructions = {}

        async def send_instructions():
            while True:
                text = await instructions.get()
                identifier = "cyber-stdin-" + uuid.uuid4().hex
                sent_instructions[identifier] = text
                process.stdin.write((json.dumps({"type": "steer", "id": identifier, "text": text}, ensure_ascii=False) + "\n").encode())
                try:
                    await process.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    return

        sender = asyncio.create_task(send_instructions()) if instructions is not None else None

        async def drain_errors():
            nonlocal stderr_tail
            while chunk := await process.stderr.read(8192):
                stderr_tail = (stderr_tail + chunk.decode("utf-8", "replace"))[-8192:]

        drain = asyncio.create_task(drain_errors())
        ticker = asyncio.create_task(tick())
        try:
            while line := await process.stdout.readline():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(event, dict):
                    continue
                kind = event.get("type")
                if kind == "steering_queued" and on_instruction:
                    on_instruction("queued")
                elif kind == "soft_interrupt_injected":
                    applied = False
                    for identifier in event.get("client_ids", []):
                        applied |= sent_instructions.pop(identifier, None) is not None
                    if applied and on_instruction:
                        on_instruction("applied")
                if capture_tools and kind == "tool_start":
                    input_id = str(event.get("id") or event.get("name", "tool")) if visible_tool(str(event.get("name", ""))) else None
                    if input_id:
                        tool_inputs[input_id] = ""
                elif capture_tools and kind == "tool_input" and input_id:
                    tool_inputs[input_id] = (tool_inputs[input_id] + str(event.get("delta", "")))[:32768]
                if kind == "start":
                    activity.phase = "Waiting for model"
                    update()
                if kind in ("tool_start", "tool_exec", "tool_done"):
                    name = str(event.get("name", "tool"))
                    if visible_tool(name):
                        # Names are labels, never tool inputs or arbitrary status text.
                        label = name if re.fullmatch(r"[\w.:/-]{1,64}", name, re.ASCII) else "tool"
                        tool_id = str(event.get("id") or label)
                        if kind == "tool_done":
                            activity.active.pop(tool_id, None)
                            output = str(event.get("output", ""))
                            bg_id = background_started(output)
                            if bg_id:
                                activity.background[bg_id] = label
                            elif name == "bg":
                                bg_task = re.search(r"^Task: ([\w-]+)$", output, re.M | re.ASCII)
                                if bg_task and re.search(r"^Status: (completed|failed|superseded)$", output, re.M):
                                    activity.background.pop(bg_task.group(1), None)
                            activity.completed += 1
                            activity.phase = "Waiting for next step"
                        else:
                            activity.active[tool_id] = label
                        update()
                if kind in ("start", "session", "done"):
                    sid = event.get("session_id")
                    if isinstance(sid, str) and re.fullmatch(r"[\w.-]{1,180}", sid):
                        result.session_id = sid
                if kind == "tool_done":
                    name = str(event.get("name", "tool"))
                    if visible_tool(name):
                        output = clean(event.get("output", ""))
                        tool = {"id": str(event.get("id") or f"tool-{len(result.tools) + 1}"),
                                "name": clean(name), "output": output[:262144],
                                "error": bool(event.get("error")), "elapsed": round(time.monotonic() - start, 1),
                                "truncated": len(output) > 262144}
                        if capture_tools and name in ("bash", "shell", "terminal"):
                            try:
                                parameters = json.loads(tool_inputs.get(str(event.get("id") or name), "{}"))
                                if isinstance(parameters, dict) and isinstance(parameters.get("command"), str):
                                    tool["command"] = clean(parameters["command"])[:16000]
                            except ValueError:
                                pass
                        bg_id = background_started(output)
                        if bg_id and tool.get("command"):
                            background_commands[bg_id] = tool["command"]
                        if name == "bg":
                            task = re.search(r"^Task: ([\w-]+)$", output, re.M)
                            if task and task[1] in background_commands:
                                tool["command"] = background_commands[task[1]]
                        result.tools.append(tool)
                        if not capture_tools:
                            result.tools = result.tools[-200:]
                        if on_tool:
                            on_tool(tool)
                elif kind == "done":
                    result.summary = parse_result(str(event.get("text", "")))
                    result.raw_text = clean(str(event.get("text", "")))[:262144]
                    done = True
                    activity.active.clear()
                    activity.background.clear()
                    activity.phase = "Finishing"
                    update()
                elif kind == "error":
                    result.error = error_message(str(event.get("message", "")))
                # All deltas, reasoning, tool inputs, status, metadata and usage
                # stay off-screen and are not written to frontend result files.
            code = await process.wait()
            await drain
            if code and not result.error:
                result.error = error_message(stderr_tail)
            elif not done and not result.error:
                result.error = "Engine exited without a result. Try again."
        except asyncio.CancelledError:
            result.error = "Operation stopped."
            result.summary = {"status": "partial", "findings": ["Phase interrupted; recorded outputs retained."], "flags": [], "next": []}
            result.elapsed = time.monotonic() - start
            self.interrupted_result = result
            raise
        finally:
            if sender:
                sender.cancel()
                await asyncio.gather(sender, return_exceptions=True)
                result.pending_instructions = list(sent_instructions.values())
                while not instructions.empty():
                    result.pending_instructions.append(instructions.get_nowait())
                if process.stdin:
                    process.stdin.close()
            ticker.cancel()
            await asyncio.gather(ticker, return_exceptions=True)
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                    await asyncio.wait_for(process.wait(), 5)
                except (ProcessLookupError, asyncio.TimeoutError):
                    if process.returncode is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        await process.wait()
            drain.cancel()
            await asyncio.gather(drain, return_exceptions=True)
        result.elapsed = time.monotonic() - start
        # Only flags backed by actual tool output receive the FLAG label.
        observed = "\n".join(tool["output"] for tool in result.tools)
        if result.summary:
            result.summary["flags"] = [flag for flag in result.summary["flags"]
                                       if flag in observed or flag in (verified_flags or [])]
        return result


class Console:
    def __init__(self, state: Path, args: argparse.Namespace):
        self.state = state
        self.args = args
        self.settings = read_json(state / "console.json")
        self.target = args.target if args.target is not None else self.settings.get("target", "")
        self.provider = args.provider or self.settings.get("provider", "auto")
        self.model = args.model if args.model is not None else self.settings.get("model", "")
        self.profile = getattr(args, "provider_profile", None) or self.settings.get("profile", "")
        self.session_id = self.settings.get("session_id")
        self.verified_flags = short_list(self.settings.get("verified_flags"), 40, 2048)
        if args.target is not None and args.target != self.settings.get("target", ""):
            self.session_id = None
            self.verified_flags = []
        if args.provider or args.model is not None or getattr(args, "provider_profile", None):
            self.session_id = None
            self.verified_flags = []
        self.backend = Backend(state)
        self.color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
        self.width = max(8, shutil.get_terminal_size((80, 24)).columns - 1)
        self.last_path = self.settings.get("last_result")
        self.last_docx = self.settings.get("last_docx")
        self.engagement_path = self.settings.get("engagement_path")
        self.pending_instructions = short_list(self.settings.get("pending_instructions"), 40, 16000)
        self._prompt_session = None
        self._input_draft = ""
        self._restored_workspace = False
        if args.target is not None and args.target != self.settings.get("target", ""):
            self.pending_instructions = []
            self.engagement_path = None
        if args.provider or args.model is not None or getattr(args, "provider_profile", None):
            self.engagement_path = None

    def line(self, text: str = "", color: str = ""):
        text = fit(text, self.width)
        if self.color and color:
            print(f"\033[{color}m{text}\033[0m", flush=True)
        else:
            print(text, flush=True)

    def prose(self, text: str, prefix: str = "[+] ", color: str = ""):
        prefix = fit(prefix, self.width - 1)
        for index, row in enumerate(wrap_rows(text, max(1, self.width - cells(prefix)))):
            self.line((prefix if index == 0 else " " * cells(prefix)) + row, color)

    def workspace(self) -> Path:
        if self.args.cwd:
            return Path(self.args.cwd).expanduser().resolve()
        key = hashlib.sha256(self.target.encode()).hexdigest()[:10] if self.target else "default"
        return self.state / "labs" / key

    def persist(self):
        write_json(self.state / "console.json", {
            "target": self.target, "provider": self.provider, "model": self.model,
            "profile": self.profile, "session_id": self.session_id, "last_result": self.last_path,
            "verified_flags": self.verified_flags,
            "last_docx": self.last_docx,
            "pending_instructions": self.pending_instructions,
            "engagement_path": self.engagement_path,
        })

    def banner(self):
        if self.width >= 58:
            for row in (
                r"   ________  ______  __________        ________  ____  ____",
                r"  / ____/\ \/ / __ )/ ____/ __ \      / / ____/ / __ \/ __ \ ",
                r" / /      \  / __  / __/ / /_/ / __  / / /   / / / / / / / /",
                r"/ /___    / / /_/ / /___/ _, _/ / /_/ / /___/ / /_/ / /_/ /",
                r"\____/   /_/_____/_____/_/ |_|  \____/\____/_/\____/\____/",
            ):
                self.line(row, "32")
        else:
            self.line("[ CYBER-JCODE ]", "32")
        self.line(f"  CYBER-JCODE  v{VERSION}  |  LAB CONSOLE", "32")
        self.line()

    def menu(self):
        self.line("=" * min(62, self.width), "32")
        self.line(f"  TARGET: {self.target or 'not set'}")
        self.prose(MOTTO, "  ", "36")
        self.line("-" * min(62, self.width), "32")
        for row in (
            "  [1] Set target", "  [2] Port / service discovery", "  [3] Web discovery",
            "  [4] Review vulnerabilities", "  [5] Find flags", "  [6] Analyze file",
            "  [7] Show last result", "  [8] Settings", "  [9] New session",
            "  [10] Full pentest (recon to root) + DOCX report",
            "  [11] Session history", "  [12] Skull (native chat, thinking hidden)", "  [0] Exit",
        ):
            self.line(row)
        self.line("-" * min(62, self.width), "32")
        self.line("  Enter a number or task.  menu | result | save | clear")
        self.line("  Continue pentest: resume  |  Saved sessions: sessions")
        self.line("=" * min(62, self.width), "32")

    def ask(self, label: str) -> str:
        if self._prompt_session is not None and sys.stdin.isatty():
            draft, self._input_draft = self._input_draft, ""
            return self._prompt_session.prompt(fit(label, self.width), default=draft).strip()
        return input(fit(label, self.width)).strip()

    def skull(self) -> int:
        if not self.backend.binary.is_file():
            self.line("[!] Engine missing. Complete setup with cyber/install.py.", "33")
            return 1
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            self.line("[!] Skull requires an interactive terminal.", "33")
            return 1
        for path in (self.state / "engine", self.state / "run"):
            private_dir(path)
        workspace = (Path(self.args.cwd).expanduser().resolve() if self.args.cwd
                     else self.state / "skull/workspace")
        workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.persist()
        self.line("[*] Skull: native chat. Thinking hidden; tools and answers visible.", "36")
        self.line("[*] Use /quit to return to Cyber-Jcode. Use /resume for chat history.", "36")
        # Each launch starts with the current connection settings. Reusing a
        # native daemon would silently ignore later provider/model CLI options.
        socket = self.state / "run" / f"skull-{uuid.uuid4().hex[:10]}.sock"
        env = self.backend.skull_environment(socket)
        command = self.backend.skull_command(self.provider, self.model, self.profile, workspace, socket)
        if self.args.no_color:
            env["NO_COLOR"] = "1"
        previous_sigint = signal.getsignal(signal.SIGINT)
        # Let the native UI handle Ctrl+C. The waiting menu must not regain the
        # terminal while Jcode is still stopping a turn or restoring the screen.
        signal.signal(signal.SIGINT, lambda *_: None)
        try:
            # Pass the terminal directly to Jcode. No headless/JSON result policy.
            code = subprocess.run(command, env=env, check=False).returncode
        except KeyboardInterrupt:
            code = 130
        except OSError:
            self.line("[!] Could not start the Skull interface.", "33")
            return 1
        finally:
            try:
                # This socket belongs only to this Skull launch, never to a lab
                # operation or an independently opened Skull interface.
                subprocess.run(command + ["server", "stop"], env=env, check=False,
                               capture_output=True, timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                pass
            signal.signal(signal.SIGINT, previous_sigint)
        self.line("[*] Returned to Cyber-Jcode.", "36")
        if code not in (0, 130, -signal.SIGINT):
            self.line(f"[!] Skull exited with status {code}.", "33")
        return code

    def phase_answer(self, label: str) -> str:
        answer = self.ask(label)
        if answer.lower() in ("y", "yes", "evet", "", "n", "no", "s"):
            return answer.lower()
        self.pending_instructions.append(answer)
        self.persist()
        self.line("[+] Instruction saved; continuing to the next phase.", "32")
        return "y"

    def set_target(self, value: str):
        value = clean(value).strip()
        if not value or len(value) > 512 or any(char.isspace() for char in value):
            self.line("[!] Enter an IP, hostname or URL.", "33")
            return
        if self.target != value:
            if self._restored_workspace:
                self.args.cwd = None
                self._restored_workspace = False
            self.target = value
            self.session_id = None
            self.verified_flags = []
            self.last_path = None
            self.pending_instructions = []
            self.engagement_path = None
        self.persist()
        self.line(f"[+] Target: {self.target}", "32")

    def prompt(self, task: str, task_label: str = "") -> str:
        filename = "policy-pentest.txt" if task_label.startswith("PENTEST") else "policy.txt"
        policy = (ROOT / "cyber" / filename).read_text(encoding="utf-8")
        policy += ("\nSCREENSHOT RULE (all tasks): NEVER read, view, attach, decode, OCR or visually "
                   "inspect screenshot/image files. Never send them to the model, even to verify a report. "
                   "Use HTTP/DOM/text command output for analysis. Capture files using the terminal helper; "
                   "read only its JSON metadata. The local Word exporter embeds the images. "
                   "If image reading is blocked, continue the assessment without retrying it.")
        context = f"Target: {self.target or '(not set)'}\nWorkspace: {self.workspace()}"
        if self.verified_flags:
            context += "\nVerified flags so far: " + ", ".join(self.verified_flags)
        if self.pending_instructions:
            context += "\nADDITIONAL USER INSTRUCTIONS (apply within the current lab scope):\n" + "\n".join(self.pending_instructions)
        if task_label.startswith("PENTEST"):
            policy += "\n\nMANDATORY REPORTING HANDBOOK — apply before writing report data:\n" + (
                ROOT / "cyber/reporting-handbook.md").read_text(encoding="utf-8")
            context += (f"\nReal screenshot command: python3 {ROOT / 'cyber/capture.py'} "
                        "--url http://LAB_TARGET/ --output /absolute/evidence/path/new-file.png"
                        "\nTemplate: enterprise-pentest.docx (used by the exporter; do not open the binary in model tools).")
            context += "\nREFERENCE HANDBOOKS (read relevant sections as needed):"
            for filename in ("pentest.txt", "dehset_pentest_araclari.txt"):
                path = self.state / "references" / filename
                if path.is_file():
                    context += f"\n{path}"
        return (f"{policy}\n\nLAB CONTEXT\n{context}\n\nUSER TASK\n{task}\n\n"
                "Finish with the delimited CYBER_RESULT JSON. No conversational output.")

    def execute(self, task: str, label: str = "TASK", phase: str = "",
                extra_context: str = "") -> dict | None:
        """Run one task. Returns the report dict, or None if it never started."""
        if is_greeting(task):
            self.greet(task)
            return None
        self.line(f"[*] {label} running...  Ctrl+C: stop", "36")
        display = ProgressDisplay(self.width)
        prompt = self.prompt(task, label)
        if extra_context:
            # Insert engagement continuity between the policy and the user task.
            prompt = prompt.replace("\n\nUSER TASK\n",
                                    f"\n\nENGAGEMENT CONTEXT (from earlier phases)\n{extra_context}\n\nUSER TASK\n")
        def on_tool(tool):
            display.finish()
            self.show_tool(tool)
        try:
            from cyber.live import run_with_input
            result = asyncio.run(run_with_input(self, prompt, label, phase, display, on_tool))
        except KeyboardInterrupt:
            display.finish()
            self.line("[!] Operation stopped.", "33")
            result = self.backend.interrupted_result or RunResult(error="Operation stopped.")
        except (OSError, ValueError):
            display.finish()
            self.line("[!] Could not start. Check the connection / workspace.", "31")
            if not phase:
                return None
            result = RunResult(error="Could not start the phase.")
        display.finish()
        if not result.error:
            self.pending_instructions = result.pending_instructions
        else:
            self.pending_instructions.extend(result.pending_instructions)
        self.session_id = result.session_id
        self.verified_flags = list(dict.fromkeys(
            self.verified_flags + result.summary.get("flags", [])
        ))[-40:]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        report = {"target": self.target, "task": task, "label": label, "session_id": result.session_id,
                  "workspace": str(self.workspace()),
                  "tools": result.tools, "summary": result.summary, "error": result.error,
                  "elapsed": round(result.elapsed, 1)}
        if phase:
            report["phase"] = phase
            try:
                from cyber.report import parse_engagement_details, link_findings, verified_access
                details = parse_engagement_details(result.raw_text)
                report["engagement_findings"] = link_findings(details["findings"], result.tools)
                report["access"] = verified_access(details["access"], result.tools, self.target)
                report["limitations"] = details["limitations"]
                report["screenshots"] = details["screenshots"]
            except ImportError:
                report["engagement_findings"] = []
        path = self.state / "results" / f"{stamp}.json"
        write_json(path, report)
        self.last_path = str(path)
        self.persist()
        self.show_result(report, hide_tools=bool(phase))
        return report

    def greet(self, task: str) -> bool:
        # A real, tool-free model turn must not replace the lab session or report.
        prompt = ("This is a brief model connection check. No lab task is requested. "
                  "Reply to the user's greeting in English, at most three words. "
                  "Use no tools. Return only [CYBER_RESULT] followed by JSON with "
                  "status=ok, findings=[your short greeting], flags=[], next=[], "
                  "then [/CYBER_RESULT]. For ping, reply Pong.\nUser: " + task)
        self.line("[*] MODEL CHECK running...  Ctrl+C: stop", "36")
        display = ProgressDisplay(self.width)
        try:
            result = asyncio.run(self.backend.run(
                prompt, self.state / "checks", None, self.provider, self.model,
                self.profile, progress=display, greeting=True,
            ))
        except KeyboardInterrupt:
            display.finish()
            self.line("[!] Operation stopped.", "33")
            return False
        except (OSError, ValueError):
            display.finish()
            self.line("[!] Could not start the model check.", "31")
            return False
        display.finish()
        if result.error:
            self.line(f"[!] {result.error}", "31")
            return False
        findings = result.summary.get("findings", [])
        if result.summary.get("status") != "ok" or not findings:
            self.line("[!] No greeting received from the model.", "33")
            return False
        self.line(f"[+] {fit(' '.join(findings[0].split()[:3]), 60)}", "32")
        return True

    def show_tool(self, tool: dict):
        visible = display_tool(tool)
        if visible is None:
            return
        action = tool_action(dict(tool, name=visible["name"], output=visible["output"]))
        self.line(f"[{'!' if visible['error'] else '+'}] {action}", "33" if visible["error"] else "32")
        rows = visible["output"].splitlines() if self.args.full_output else preview_rows(visible)
        for row in (rows if self.args.full_output else rows[:16]):
            self.line("    " + row)
        if not self.args.full_output and len(rows) > 16:
            self.line(f"    … {len(rows) - 16} more lines saved.")

    def show_result(self, report: dict, all_outputs: bool = False, hide_tools: bool = False):
        self.line()
        summary = report.get("summary", {})
        status = ("STOPPED" if report.get("error") == "Operation stopped." else
                  "FAILED" if report.get("error") else str(summary.get("status", "partial")).upper())
        elapsed = report.get("elapsed", 0)
        duration = f"{int(elapsed) // 60}m {int(elapsed) % 60:02d}s" if elapsed >= 60 else f"{elapsed:.1f}s"
        self.line("=" * min(62, self.width), "32")
        self.line(f"  RESULT | {status} | {duration}")
        self.line(f"  TARGET: {report.get('target') or 'not set'}")
        self.line("-" * min(62, self.width), "32")
        if report.get("error"):
            self.prose(report["error"], "[!] ", "31")
        for flag in summary.get("flags", []):
            self.prose(flag, "[FLAG] ", "32")
        for finding in summary.get("findings", []):
            self.prose(finding, "[+] " if summary.get("status") == "ok" else "[!] ")
        for next_step in summary.get("next", []):
            self.prose(next_step, "[>] ")
        findings = report.get("engagement_findings") or []
        if findings:
            self.line("-" * min(62, self.width), "32")
            self.line(f"  ENGAGEMENT FINDINGS | {len(findings)}", "36")
            for finding in findings:
                self.prose(f"{finding['severity'].upper()}: {finding['title']} "
                           f"({finding['category']})", "[V] ", "35")
        tools = [] if hide_tools else [dict(visible, action=tool_action(dict(tool, name=visible["name"], output=visible["output"])))
                                      for tool in report.get("tools", []) if (visible := display_tool(tool)) is not None]
        if tools:
            self.line("-" * min(62, self.width), "32")
            self.line(f"  TOOL OUTPUTS | {len(tools)} results", "36")
        shown = tools if (self.args.full_output or all_outputs) else tools[-8:]
        for tool in shown:
            self.line(f"[{'!' if tool['error'] else '+'}] {tool['action']}", "33" if tool["error"] else "32")
            rows = tool["output"].splitlines() if (self.args.full_output or all_outputs) else preview_rows(tool)
            visible = rows if (self.args.full_output or all_outputs) else rows[:16]
            for row in visible:
                self.line(f"    {row}")
            if len(visible) < len(rows):
                self.line(f"    … {len(rows) - len(visible)} more lines. Full captured output: save")
        if len(shown) < len(tools):
            self.line(f"[*] {len(tools) - len(shown)} earlier outputs saved.")
        self.line("=" * min(62, self.width), "32")
        self.line()

    def last_result(self):
        if not self.last_path:
            self.line("[!] No results yet.", "33")
            return
        report = read_json(Path(self.last_path))
        if report:
            self.show_result(report)
            if report.get("docx_path"):
                self.prose(report["docx_path"], "[+] DOCX: ", "32")
        else:
            self.line("[!] Result file not found.", "33")

    def save_result(self):
        if not self.last_path:
            self.line("[!] No results yet.", "33")
            return
        # The complete tool outputs already exist in this private local file.
        self.line(f"[+] Saved: {self.last_path}", "32")
        if self.last_docx:
            self.prose(self.last_docx, "[+] DOCX: ", "32")

    def session_history(self):
        from cyber.history import saved_results
        records = saved_results(self.state)
        if not records:
            self.line("[!] No saved sessions or reports yet.", "33")
            return
        self.line("  SESSION HISTORY | saved results", "36")
        for index, (path, record) in enumerate(records, 1):
            label = "PENTEST REPORT" if "phases" in record else record.get("label", "TASK")
            self.prose(f"[{index}] {path.stem} | {record.get('target') or 'not set'} | {label}", "  ")
        choice = self.ask("history number (0: back) > ")
        if not choice.isdecimal() or not 1 <= int(choice) <= len(records):
            return
        path, record = records[int(choice) - 1]
        action = self.ask("[Enter/v] View result | [r] Open session | [0] Back > ").lower()
        if action == "0":
            return
        if action in ("r", "resume", "open"):
            self.open_session(path, record)
            return
        if "phases" in record:
            self.prose(f"{record.get('target')} | {len(record.get('phases', []))}/7 phases | "
                       f"{len(record.get('findings', []))} findings", "[+] ")
            for finding in record.get("findings", []):
                self.prose(f"{finding.get('severity', 'info').upper()}: {finding.get('title', '')}", "[V] ")
            if record.get("docx_path"):
                self.prose(record["docx_path"], "[+] DOCX: ", "32")
            else:
                stamp = path.stem.removeprefix("pentest-")
                legacy = self.state / "reports" / f"pentest-{stamp}.docx"
                if legacy.is_file():
                    self.prose(str(legacy), "[+] DOCX: ", "32")
            for tool in record.get("tools", []):
                if visible_tool(str(tool.get("name", ""))):
                    self.show_tool(tool)
        else:
            self.show_result(record)
        self.prose(str(path), "[+] Saved data: ", "32")

    def open_session(self, path: Path, record: dict):
        """Restore explicit history selection; browsing alone never changes state."""
        self.target = str(record.get("target") or "")
        self.session_id = record.get("session_id")
        self.verified_flags = short_list(record.get("flags") or record.get("summary", {}).get("flags"), 40, 2048)
        self.pending_instructions = short_list(record.get("pending_instructions"), 40, 16000)
        self.last_path = str(path)
        self.last_docx = record.get("docx_path")
        self.engagement_path = str(path) if "phases" in record else None
        self.args.cwd = record.get("workspace")
        self._restored_workspace = bool(self.args.cwd)
        self.persist()
        self.line(f"[+] Session opened. Target: {self.target or 'not set'}", "32")
        if not self.session_id:
            self.line("[*] Evidence restored; no engine session ID was recorded.", "36")
        if "phases" in record:
            from cyber.engagement import next_phase
            cursor = next_phase(record, PENTEST_PHASES)
            if cursor < len(PENTEST_PHASES):
                self.line(f"[+] Continue phase {cursor + 1}/7: {PENTEST_PHASES[cursor][1]}. Type 10 or resume.", "32")
            else:
                self.line("[*] All phases were processed. Enter a task or start a new engagement.", "36")

    def check_connection(self) -> bool:
        report = self.execute("Connection check: use bash to run only printf CYBER_OK. "
                               "Do not scan the network. Report Connection ready.", "CONNECTION")
        success = bool(report) and not report.get("error") \
            and report.get("summary", {}).get("status") == "ok"
        confirmed = bool(report) and any(
            tool.get("name") == "bash" and "CYBER_OK" in tool.get("output", "")
            and not tool.get("error") for tool in report.get("tools", []))
        if success and not confirmed:
            self.line("[!] Tool connection could not be verified.", "33")
        return success and confirmed

    def run_pentest(self, resume: bool = False):
        """Run or continue a checkpointed engagement, then export its cumulative report."""
        if not self.target:
            self.line("[!] Set a target with [1] first.", "33")
            return False
        from cyber import report as report_module
        from cyber.engagement import checkpoint_for, next_phase, prepare_resume, retain_phase
        saved = checkpoint_for(self, PENTEST_PHASES)
        if resume and saved is None:
            self.line("[!] No unfinished pentest in this session. Open one through sessions.", "33")
            return False
        self.line("=" * min(62, self.width), "36")
        self.line("  FULL PENTEST ENGAGEMENT", "36")
        self.line(f"  Target : {self.target}")
        self.line("  Phases : recon -> services -> web -> vulns -> exploit ->")
        self.line("           privesc -> post, then the DOCX report.")
        self.line("  Each phase can be stopped with Ctrl+C.", "36")
        self.line("=" * min(62, self.width), "36")
        if saved and not resume:
            cursor = next_phase(saved[1], PENTEST_PHASES)
            self.line(f"[+] Saved progress: phase {cursor + 1}/7, {PENTEST_PHASES[cursor][1]}.", "32")
            answer = self.ask("[Enter/1] Resume | [2] New engagement | [0] Back > ").lower()
            if answer in ("0", "n", "no"):
                return False
            if answer in ("2", "new"):
                saved = None
                self.session_id = None
                self.verified_flags = []
                self.pending_instructions = []
            elif answer not in ("", "1", "y", "yes", "resume"):
                self.pending_instructions.append(answer)
        if saved:
            engagement_path, previous = saved
            engagement = prepare_resume(previous, engagement_path, self.workspace(), PENTEST_PHASES)
            self.session_id = engagement.get("session_id") or self.session_id
            self.verified_flags = list(dict.fromkeys(self.verified_flags + engagement.get("flags", [])))
            self.pending_instructions = list(dict.fromkeys(
                engagement.get("pending_instructions", []) + self.pending_instructions))
            self.args.cwd = engagement["workspace"]
            self._restored_workspace = True
            self.line("[+] Continuing the saved engagement; completed phases retained.", "32")
        else:
            answer = self.ask("Start the engagement? (y/n) > ")
            if answer.lower() not in ("y", "yes", "evet", "start", "baslat", "başlat"):
                self.line("[*] Engagement cancelled.", "36")
                return False
            run_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            engagement_path = self.state / "results" / f"pentest-{run_stamp}.json"
            engagement = {"target": self.target, "started": datetime.now(timezone.utc).isoformat(),
                          "run_stamp": run_stamp, "workspace": str(self.workspace()),
                          "evidence_dir": str(self.workspace() / "evidence" / run_stamp),
                          "phases": [], "phase_reports": [], "next_phase": 0, "skipped_phases": [],
                          "findings": [], "tools": [], "screenshots": [], "flags": [], "limitations": []}
        run_stamp = engagement["run_stamp"]
        evidence = Path(engagement["evidence_dir"])
        private_dir(evidence)
        self.engagement_path = str(engagement_path)
        phase_reports = engagement["phase_reports"]
        status_by_phase = {p["phase"]: p.get("status", "partial") for p in engagement["phases"]}

        def checkpoint(state="running"):
            engagement.update(checkpoint_version=1, progress_state=state, status="partial",
                              session_id=self.session_id, pending_instructions=list(self.pending_instructions),
                              updated=datetime.now(timezone.utc).isoformat())
            write_json(engagement_path, engagement)
            self.persist()

        checkpoint()
        skip_next_phase = False
        start_index = engagement["next_phase"]
        for offset in range(start_index, len(PENTEST_PHASES)):
            phase, label, description = PENTEST_PHASES[offset]
            index = offset + 1
            if phase in engagement["skipped_phases"] or (saved and status_by_phase.get(phase) == "ok"):
                engagement["next_phase"] = index
                checkpoint()
                continue
            if skip_next_phase:
                # The user answered "s" to skip this phase entirely.
                skip_next_phase = False
                self.line(f"[*] Phase {index}/{len(PENTEST_PHASES)} skipped: {label}", "36")
                engagement["skipped_phases"].append(phase)
                engagement["next_phase"] = index
                checkpoint()
                continue
            engagement["next_phase"] = offset
            checkpoint()
            self.line()
            self.line(f"[PHASE {index}/{len(PENTEST_PHASES)}] {label}", "36")
            # Continuity: earlier phases' compact outputs are the engagement context.
            context_parts = ["Prior verified flags: " + (", ".join(self.verified_flags) or "none")]
            context_parts.append(f"Saved engagement JSON (text evidence only): {engagement_path}")
            context_parts.append(f"Capture real screenshot files only under: {evidence}. "
                                 "Never read the images. Capture helper JSON is the only model-visible result.")
            for prior in phase_reports:
                prior_phase = prior.get("phase") or "prior"
                context_parts.append(f"{prior_phase} phase status: {status_by_phase.get(prior_phase, 'partial')}; "
                                     f"key results: " + "; ".join(prior.get("summary", {}).get("findings", [])))
            if any(p.get("phase") == phase for p in engagement["phases"]):
                context_parts.append(
                    "RESUME THE INTERRUPTED PHASE from its last unfinished step. Review the saved "
                    "session, workspace notes and engagement JSON for exact recorded tool outputs. "
                    "Do not repeat completed scans or steps with usable evidence. Previous processes "
                    "may have stopped: verify any referenced shell, connection or background task "
                    "before reusing it. Restore only lost access or unfinished commands as needed; "
                    "do not restart reconnaissance. Images remain forbidden.")
            extra = "\n".join(context_parts)
            task = (f"Engagement phase: {label}. {description} "
                    "This phase is part of a larger authorized pentest engagement; previous "
                    "phases' results are summarized in the engagement context and files in "
                    "the workspace. Perform this phase completely with real tools.")
            try:
                report = self.execute(task, f"PENTEST {index}/{len(PENTEST_PHASES)}: {label}",
                                      phase=phase, extra_context=extra)
            except (KeyboardInterrupt, EOFError):
                checkpoint("paused")
                break
            failed_to_start = report is None
            if failed_to_start:
                report = {"error": "Phase did not start.", "elapsed": 0,
                          "summary": {"status": "stopped"}, "tools": []}
            if report.get("session_id"):
                self.session_id = report["session_id"]
            retain_phase(engagement, report, phase, label)
            status_by_phase[phase] = next(p["status"] for p in engagement["phases"] if p["phase"] == phase)
            engagement["flags"] = list(dict.fromkeys(
                self.verified_flags + report.get("summary", {}).get("flags", [])))
            engagement["screenshots"].extend(report_module.collect_screenshots(
                report.get("tools", []), evidence, phase=phase))
            status = report.get("summary", {}).get("status", "partial")
            retry_current = bool(report.get("error")) or status == "blocked"
            engagement["next_phase"] = offset if retry_current else index
            checkpoint("paused")  # Save BEFORE asking; Ctrl+C at the question loses nothing.
            if report.get("error") == "Operation stopped.":
                self.line("[+] Pentest paused. Type 10 or resume to continue this phase.", "32")
                break
            try:
                if retry_current:
                    if index == len(PENTEST_PHASES):
                        break
                    answer = self.phase_answer("Phase blocked/stopped. Advance to the next phase? (y/n or instruction) > ")
                elif index < len(PENTEST_PHASES):
                    answer = self.phase_answer(f"Phase complete. Run phase {index + 1}/{len(PENTEST_PHASES)}: "
                                              f"{PENTEST_PHASES[index][1]}? (y/n/s or instruction) > ")
                else:
                    answer = "y"
            except (KeyboardInterrupt, EOFError):
                checkpoint("paused")
                break
            if answer == "s":
                skip_next_phase = True
            elif answer not in ("y", "yes", "evet", ""):
                break
            engagement["next_phase"] = index
            checkpoint()
        levels = {"user": 1, "administrator": 2, "root": 3, "system": 3}
        accesses = [p["access"] for p in phase_reports if p.get("access")]
        access = max(accesses, key=lambda item: levels.get(item["level"], 0), default=None)
        final_access = (f"Verified {access['level']} access on {access['target']}" if access
                        else "No verified target access recorded")
        checkpoint("finished" if engagement["next_phase"] == len(PENTEST_PHASES) else "paused")
        engagement["finished"] = datetime.now(timezone.utc).isoformat()
        engagement["final_access"] = final_access
        engagement["session_id"] = self.session_id
        engagement["status"] = "complete" if len(engagement["phases"]) == 7 and all(
            p["status"] == "ok" for p in engagement["phases"]) else "partial"
        stamp = run_stamp
        self.last_path = str(engagement_path)
        self.persist()
        write_json(engagement_path, engagement)
        try:
            docx_path = report_module.build_report(engagement, self.state / "reports" / f"pentest-{stamp}.docx")
            self.line(f"[+] Engagement data: {engagement_path}", "32")
            self.line(f"[+] DOCX report    : {docx_path}", "32")
            from cyber.report_layout import desktop_report_folder, report_filename
            destination = desktop_report_folder()
            if destination is None:
                destination = Path.home() / "Desktop/raport"
            private_dir(destination)
            copied = destination / report_filename(self.target, stamp)
            shutil.copyfile(docx_path, copied)
            shutil.copyfile(docx_path.with_suffix(".transcript.txt"), copied.with_suffix(".transcript.txt"))
            self.last_docx = str(copied)
            self.last_path = str(engagement_path)
            engagement["docx_path"] = str(copied)
            write_json(engagement_path, engagement)
            self.persist()
            self.prose(str(copied), "[+] Report: ", "32")
        except ImportError:
            self.line("[!] python-docx / Pillow missing: pip install python-docx pillow", "31")
            self.line(f"[+] Engagement data: {engagement_path}", "32")
        except (OSError, ValueError) as error:
            self.prose(str(error), "[!] Report export failed: ", "31")
            self.prose(str(engagement_path), "[+] Engagement data preserved: ")
        return True

    def settings_menu(self):
        while True:
            self.line(f"  Provider: {self.provider}  Model: {self.model or 'provider default'}")
            for row in ("  [1] Change provider", "  [2] Change model",
                        "  [3] Connection check", "  [4] Login / connection",
                        "  [5] List models", "  [6] Provider profile", "  [0] Back"):
                self.line(row)
            choice = self.ask("settings > ")
            if choice in ("0", "back", "geri", "exit"):
                break
            if choice in ("1", "2", "6"):
                field_name = {"1": "provider", "2": "model", "6": "profile"}[choice]
                value = self.ask("value (empty: default) > ")
                setattr(self, field_name, value or ("auto" if choice == "1" else ""))
                self.session_id = None
                self.verified_flags = []
                self.engagement_path = None
                self.persist()
                self.line("[+] Saved.", "32")
            elif choice == "3":
                self.check_connection()
            elif choice == "4":
                self.line("[*] API setup: cyber-jcode provider add --help", "36")
                provider = self.ask("provider (empty: current) > ") or self.provider
                if provider == "auto":
                    self.line("[!] Enter the provider to log in to.", "33")
                    continue
                import subprocess
                try:
                    subprocess.run(self.backend.command(provider) + ["login", provider],
                                   env=self.backend.environment(), check=False)
                except OSError:
                    self.line("[!] Could not start login.", "31")
            elif choice == "5":
                self.list_models()
            else:
                self.line("[!] Invalid selection.", "33")

    def list_models(self):
        import subprocess
        self.line("[*] Loading model list...", "36")
        try:
            completed = subprocess.run(self.backend.command(self.provider, self.model, self.profile)
                                       + ["model", "list", "--json"],
                                       env=self.backend.environment(), capture_output=True,
                                       text=True, timeout=90)
            data = json.loads(completed.stdout)
            if completed.returncode:
                raise ValueError
            self.print_models(data)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.line("[!] Could not load models.", "33")

    def print_models(self, data):
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    self.line(f"  {item}")
                elif isinstance(item, dict):
                    name = item.get("id") or item.get("name") or item.get("model")
                    if name:
                        self.line(f"  {name}")
        elif isinstance(data, dict):
            for key in ("models", "providers", "available", "groups"):
                if key in data:
                    self.print_models(data[key])
                    return
            for key, value in data.items():
                if isinstance(value, (list, dict)):
                    self.line(f"  [{key}]")
                    self.print_models(value)

    def loop(self) -> int:
        if getattr(self.args, "sessions", False):
            self.session_history()
            return 0
        self.banner()
        self.menu()
        if self.args.menu:
            return 0
        if self.args.check:
            return 0 if self.check_connection() else 1
        if self.args.run:
            if is_greeting(self.args.run):
                return 0 if self.greet(self.args.run) else 1
            result = self.execute(self.args.run)
            return 0 if result and not result.get("error") and result.get("summary", {}).get("status") == "ok" else 1
        while True:
            try:
                choice = self.ask("cyber > ")
                if not choice:
                    continue
                if choice in ("0", "exit", "quit", "cikis", "çıkış"):
                    self.persist()
                    self.line("[*] Session closed.", "36")
                    return 0
                if choice in ("menu", "help", "yardim", "yardım", "?"):
                    self.menu()
                elif choice == "1":
                    self.set_target(self.ask("target > "))
                elif choice.startswith(("target ", "hedef ")):
                    self.set_target(choice.split(" ", 1)[1])
                elif choice in TASKS:
                    if not self.target:
                        self.line("[!] Set a target with [1] first.", "33")
                        continue
                    label, task = TASKS[choice]
                    self.execute(task, label)
                elif choice == "6":
                    filename = self.ask("file path > ")
                    path = Path(filename).expanduser().resolve()
                    if not filename or not path.is_file():
                        self.line("[!] File not found.", "33")
                        continue
                    self.execute(f"Analyze this local lab file using tools: {json.dumps(str(path))}. "
                                 "Identify its type, useful information and any observed flags.", "FILE")
                elif choice in ("7", "result", "sonuc", "sonuç"):
                    self.last_result()
                elif choice == "8":
                    self.settings_menu()
                elif choice in ("9", "new", "yeni"):
                    self.session_id = None
                    self.verified_flags = []
                    self.last_path = None
                    self.pending_instructions = []
                    self.engagement_path = None
                    self.persist()
                    self.line("[+] New session ready.", "32")
                elif choice in ("10", "pentest", "full", "tam"):
                    self.run_pentest()
                elif choice in ("resume", "continue", "devam"):
                    self.run_pentest(resume=True)
                elif choice in ("11", "sessions", "history"):
                    self.session_history()
                elif choice in ("12", "skull"):
                    self.skull()
                    self.menu()
                elif choice in ("save", "kaydet"):
                    self.save_result()
                elif choice in ("clear", "temizle"):
                    if sys.stdout.isatty():
                        print("\033[2J\033[H", end="")
                    self.banner()
                    self.menu()
                elif choice.isdecimal():
                    self.line("[!] Invalid selection. Menu: menu", "33")
                else:
                    self.execute(choice)
            except EOFError:
                self.line()
                return 0
            except KeyboardInterrupt:
                self.line("\n[!] Input cancelled. Exit: 0", "33")


def forward_command(state: Path, argv: list[str]) -> int:
    """Reuse Jcode's existing configuration CLI in Cyber-Jcode's private state."""
    backend = Backend(state)
    settings = read_json(state / "console.json")
    if not backend.binary.is_file():
        print("[!] Engine missing. Complete setup with cyber/install.py.", file=sys.stderr)
        return 1
    for path in (state / "engine", state / "run"):
        private_dir(path)
    command = backend.command(settings.get("provider", "auto"),
                              settings.get("model", ""), settings.get("profile", ""))
    # Inherit stdin so upstream --api-key-stdin and login work as documented.
    code = subprocess.run(command + argv, env=backend.environment(), check=False).returncode
    if (code == 0 and argv[:2] == ["provider", "add"]
            and any(flag in argv for flag in ("--set-default", "--default"))
            and not any(flag in argv for flag in ("--help", "-h"))):
        settings.update(provider="auto", model="", profile="", session_id=None, verified_flags=[])
        write_json(state / "console.json", settings)
    return code


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ["sessions"]:
        argv = ["--sessions"]
    elif argv == ["skull"]:
        argv = ["--skull"]
    parser = argparse.ArgumentParser(
        prog="cyber-jcode", description="TryHackMe lab terminal",
        epilog="Jcode configuration commands: cyber-jcode provider|model|auth|login ...",
    )
    parser.add_argument("--version", action="version", version=f"cyber-jcode {VERSION}")
    parser.add_argument("--target", help="Lab IP, hostname or URL")
    parser.add_argument("--provider", help="Model provider")
    parser.add_argument("--model", help="Model ID")
    parser.add_argument("--provider-profile", help="Named provider profile")
    parser.add_argument("--cwd", "-C", help="Lab workspace")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--full-output", action="store_true", help="Show every tool output line")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--menu", action="store_true", help="Show the menu and exit")
    mode.add_argument("--check", action="store_true", help="Check the model and actual tool execution")
    mode.add_argument("--run", help="Run one task and exit")
    mode.add_argument("--pentest", action="store_true",
                      help="Run the full phased pentest engagement and produce a DOCX report")
    mode.add_argument("--sessions", action="store_true", help="Browse saved sessions and report paths")
    mode.add_argument("--skull", action="store_true", help="Open native Jcode chat with thinking hidden")
    forwarded = bool(argv and argv[0] in ("provider", "model", "auth", "login"))
    args = None if forwarded else parser.parse_args(argv)
    state = Path(os.environ.get("CYBER_JCODE_HOME", str(Path.home() / ".cyber-jcode"))).expanduser().resolve()
    protected = [(Path.home() / name).resolve() for name in (".jcode", ".config/jcode")]
    if any(state.is_relative_to(path) or path.is_relative_to(state) for path in protected):
        parser.error("Choose a separate Cyber-Jcode data directory.")
    os.umask(0o077)
    try:
        if forwarded:
            return forward_command(state, argv)
        console = Console(state, args)
        if args.skull:
            return console.skull()
        if args.pentest:
            return 0 if console.run_pentest() else 1
        return console.loop()
    except KeyboardInterrupt:
        print("\n[!] Operation stopped.", file=sys.stderr)
        return 130
    except OSError:
        print("[!] Could not access the Cyber-Jcode data directory.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
