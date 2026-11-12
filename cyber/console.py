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
import tomllib
from typing import Callable
import unicodedata

VERSION = "0.2.0"
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
    if any(part in text for part in ("401", "403", "api key", "api_key", "credential", "unauthorized", "auth")):
        return "Model authentication failed. Settings > Login / connection."
    if any(part in text for part in ("429", "rate limit", "quota", "credit", "balance")):
        return "Model usage limit reached. Try again later."
    if any(part in text for part in ("timeout", "timed out")):
        return "Operation timed out."
    if any(part in text for part in ("connect", "dns", "network", "resolve", "502", "503")):
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

    def environment(self) -> dict[str, str]:
        # A parent Jcode session may export its socket and self-dev paths.
        env = {k: v for k, v in os.environ.items() if not k.startswith("JCODE_")}
        env.update({
            "JCODE_HOME": str(self.state / "engine"),
            "JCODE_RUNTIME_DIR": str(self.state / "run"),
            "JCODE_SOCKET": str(self.state / "run/agent.sock"),
            "JCODE_INSTALL_DIR": str(self.state / "engine/builds"),
            "JCODE_RUN_AUTO_POKE_MAX_TURNS": "6",
            "XDG_CONFIG_HOME": str(self.state / "engine/config"),
            "XDG_CACHE_HOME": str(self.state / "engine/cache"),
            "XDG_DATA_HOME": str(self.state / "engine/data"),
            "NO_COLOR": "1",
        })
        return env

    def command(self, provider: str = "auto", model: str = "", profile: str = "") -> list[str]:
        cmd = [str(self.binary), "--no-update", "--no-selfdev", "--quiet",
               "--socket", str(self.state / "run/agent.sock"), "--provider", provider]
        if model:
            cmd.extend(["--model", model])
        if profile:
            cmd.extend(["--provider-profile", profile])
        return cmd

    async def run(self, prompt: str, workspace: Path, session_id: str | None,
                  provider: str, model: str, profile: str = "",
                  verified_flags: list[str] | None = None,
                  progress: Callable[[RunProgress], None] | None = None,
                  greeting: bool = False) -> RunResult:
        result = RunResult(session_id=session_id)
        if not self.binary.is_file():
            result.error = "Engine missing. Complete setup with cyber/install.py."
            return result
        for path in (self.state / "engine", self.state / "run"):
            private_dir(path)
        # A user-supplied workspace retains its existing permissions.
        workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        cmd = self.command(provider, model, profile)
        env = self.environment()
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
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True,
            limit=16 * 1024 * 1024,
        )
        stderr_tail = ""
        done = False

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
                        result.tools.append({"name": clean(name),
                                             "output": clean(event.get("output", ""))[:262144],
                                             "error": bool(event.get("error"))})
                        result.tools = result.tools[-200:]
                elif kind == "done":
                    result.summary = parse_result(str(event.get("text", "")))
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
        finally:
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
        })

    def model_label(self) -> str:
        if self.model:
            return self.model
        try:
            with (self.state / "engine/config.toml").open("rb") as stream:
                config = tomllib.load(stream)
            defaults = config.get("provider", {})
            selected = self.profile or (defaults.get("default_provider", "")
                                        if self.provider == "auto" else self.provider)
            named = config.get("providers", {}).get(selected, {})
            return str(named.get("default_model") or
                       (defaults.get("default_model") if self.provider == "auto" else "") or
                       "provider default")
        except (OSError, ValueError, TypeError, AttributeError):
            return "provider default"

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
        self.line(f"  MODEL : {self.model_label()}")
        self.line("-" * min(62, self.width), "32")
        for row in (
            "  [1] Set target", "  [2] Port / service discovery", "  [3] Web discovery",
            "  [4] Review vulnerabilities", "  [5] Find flags", "  [6] Analyze file",
            "  [7] Show last result", "  [8] Settings", "  [9] New session", "  [0] Exit",
        ):
            self.line(row)
        self.line("-" * min(62, self.width), "32")
        self.line("  Enter a number or task.  menu | result | save | clear")
        self.line("=" * min(62, self.width), "32")

    def ask(self, label: str) -> str:
        return input(fit(label, self.width)).strip()

    def set_target(self, value: str):
        value = clean(value).strip()
        if not value or len(value) > 512 or any(char.isspace() for char in value):
            self.line("[!] Enter an IP, hostname or URL.", "33")
            return
        if self.target != value:
            self.target = value
            self.session_id = None
            self.verified_flags = []
            self.last_path = None
        self.persist()
        self.line(f"[+] Target: {self.target}", "32")

    def prompt(self, task: str) -> str:
        policy = (ROOT / "cyber/policy.txt").read_text(encoding="utf-8")
        return (f"{policy}\n\nLAB CONTEXT\nTarget: {self.target or '(not set)'}\n"
                f"Workspace: {self.workspace()}\n\nUSER TASK\n{task}\n\n"
                "Finish with the delimited CYBER_RESULT JSON. No conversational output.")

    def execute(self, task: str, label: str = "TASK") -> bool:
        if is_greeting(task):
            return self.greet(task)
        self.line(f"[*] {label} running...  Ctrl+C: stop", "36")
        display = ProgressDisplay(self.width)
        try:
            result = asyncio.run(self.backend.run(
                self.prompt(task), self.workspace(), self.session_id,
                self.provider, self.model, self.profile,
                self.verified_flags, progress=display,
            ))
        except KeyboardInterrupt:
            display.finish()
            self.line("[!] Operation stopped.", "33")
            return False
        except (OSError, ValueError):
            display.finish()
            self.line("[!] Could not start. Check the connection / workspace.", "31")
            return False
        display.finish()
        self.session_id = result.session_id
        self.verified_flags = list(dict.fromkeys(
            self.verified_flags + result.summary.get("flags", [])
        ))[-40:]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        report = {"target": self.target, "task": task, "label": label, "session_id": result.session_id,
                  "tools": result.tools, "summary": result.summary, "error": result.error,
                  "elapsed": round(result.elapsed, 1)}
        path = self.state / "results" / f"{stamp}.json"
        write_json(path, report)
        self.last_path = str(path)
        self.persist()
        self.show_result(report)
        return not result.error and result.summary.get("status") == "ok"

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

    def show_result(self, report: dict):
        self.line()
        summary = report.get("summary", {})
        status = "FAILED" if report.get("error") else str(summary.get("status", "partial")).upper()
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
        tools = [visible for tool in report.get("tools", []) if (visible := display_tool(tool)) is not None]
        if tools:
            self.line("-" * min(62, self.width), "32")
            self.line(f"  TOOL OUTPUTS | {len(tools)} results", "36")
        shown = tools if self.args.full_output else tools[-8:]
        for tool in shown:
            self.line(f"[{'!' if tool['error'] else '+'}] {tool['name']}", "33" if tool["error"] else "32")
            rows = tool["output"].splitlines() if self.args.full_output else preview_rows(tool)
            visible = rows if self.args.full_output else rows[:16]
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
        else:
            self.line("[!] Result file not found.", "33")

    def save_result(self):
        if not self.last_path:
            self.line("[!] No results yet.", "33")
            return
        # The complete tool outputs already exist in this private local file.
        self.line(f"[+] Saved: {self.last_path}", "32")

    def check_connection(self) -> bool:
        success = self.execute("Connection check: use bash to run only printf CYBER_OK. "
                               "Do not scan the network. Report Connection ready.", "CONNECTION")
        report = read_json(Path(self.last_path)) if self.last_path else {}
        confirmed = any(tool.get("name") == "bash" and "CYBER_OK" in tool.get("output", "")
                        and not tool.get("error") for tool in report.get("tools", []))
        if success and not confirmed:
            self.line("[!] Tool connection could not be verified.", "33")
        return success and confirmed

    def settings_menu(self):
        while True:
            self.line(f"  Provider: {self.provider}  Model: {self.model_label()}")
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
        self.banner()
        self.menu()
        if self.args.menu:
            return 0
        if self.args.check:
            return 0 if self.check_connection() else 1
        if self.args.run:
            return 0 if self.execute(self.args.run) else 1
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
                    self.persist()
                    self.line("[+] New session ready.", "32")
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
        return Console(state, args).loop()
    except KeyboardInterrupt:
        print("\n[!] Operation stopped.", file=sys.stderr)
        return 130
    except OSError:
        print("[!] Could not access the Cyber-Jcode data directory.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
