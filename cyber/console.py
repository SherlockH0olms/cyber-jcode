"""A menu terminal over Jcode's real headless agent, with isolated state."""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
import time
import unicodedata

VERSION = "0.1.0"
ROOT = Path(__file__).resolve().parent.parent
ANSI = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|"
    r"[PX^_].*?\x1b\\|[@-_])", re.DOTALL
)
HIDDEN_TOOLS = {"think", "thinking", "reasoning", "plan", "todo", "todowrite",
                "todoread", "memory", "skill", "goals", "goal", "set_goal",
                "swarm", "delegate", "subagent", "agent", "spawn_agent"}
TASKS = {
    "2": ("SERVİS KEŞFİ", "Hedefin açık portlarını ve servislerini gerçek araçlarla keşfet. "
          "Servis sürümlerini kaydet; bu aşamada istismar çalıştırma."),
    "3": ("WEB KEŞFİ", "Hedefin web servislerini incele. HTTP yanıtlarını, uygulama "
          "bilgilerini, erişilebilir yolları ve lab için yararlı bulguları kaydet."),
    "4": ("ZAFİYET İNCELEME", "Bu lab hedefindeki servisleri ve önceki bulguları "
          "inceleyerek kanıtlanabilir zafiyetleri belirle. Yalnızca sürüm numarasına "
          "dayanarak bir zafiyetin doğrulandığını iddia etme."),
    "5": ("FLAG ARAMA", "Bu TryHackMe/CTF labında mevcut keşif ve oturum bilgilerini "
          "kullanarak istenen flagları gerçek araçlarla bulmaya çalış. Bulduğun "
          "flagları aynen ver. Eksik bilgi veya erişim varsa bunu kısa belirt."),
}


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
    return {"status": "partial", "findings": ["Kısa sonuç alınamadı; araç çıktılarını kontrol et."],
            "flags": [], "next": []}


def error_message(text: str) -> str:
    text = text.lower()
    if any(part in text for part in ("401", "403", "api key", "api_key", "credential", "unauthorized", "auth")):
        return "Model bağlantısı doğrulanamadı. Ayarlar > Giriş / bağlantı."
    if any(part in text for part in ("429", "rate limit", "quota", "credit", "balance")):
        return "Model kullanım sınırı aşıldı. Daha sonra tekrar dene."
    if any(part in text for part in ("timeout", "timed out")):
        return "İşlem zaman aşımına uğradı."
    if any(part in text for part in ("connect", "dns", "network", "resolve", "502", "503")):
        return "Model sunucusuna ulaşılamadı. Bağlantıyı kontrol et."
    return "İşlem başarısız. Ayarlar > Bağlantı kontrolü."


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
                  verified_flags: list[str] | None = None) -> RunResult:
        result = RunResult(session_id=session_id)
        if not self.binary.is_file():
            result.error = "Motor bulunamadı. cyber/install.py ile kurulumu tamamla."
            return result
        for path in (self.state / "engine", self.state / "run"):
            private_dir(path)
        # A user-supplied workspace retains its existing permissions.
        workspace.mkdir(parents=True, exist_ok=True, mode=0o700)
        cmd = self.command(provider, model, profile)
        cmd.extend(["--cwd", str(workspace)])
        if session_id:
            cmd.extend(["--resume", session_id])
        cmd.extend(["run", "--ndjson", prompt])
        start = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *cmd, env=self.environment(), cwd=workspace,
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
        try:
            while line := await process.stdout.readline():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(event, dict):
                    continue
                kind = event.get("type")
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
                elif kind == "error":
                    result.error = error_message(str(event.get("message", "")))
                # All deltas, reasoning, tool inputs, status, metadata and usage
                # stay off-screen and are not written to frontend result files.
            code = await process.wait()
            await drain
            if code and not result.error:
                result.error = error_message(stderr_tail)
            elif not done and not result.error:
                result.error = "Motor sonuç vermeden kapandı. Tekrar dene."
        finally:
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
        self.profile = self.settings.get("profile", "")
        self.session_id = self.settings.get("session_id")
        self.verified_flags = short_list(self.settings.get("verified_flags"), 40, 2048)
        if args.target is not None and args.target != self.settings.get("target", ""):
            self.session_id = None
            self.verified_flags = []
        if args.provider or args.model is not None:
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
        self.line(f"  HEDEF : {self.target or 'ayarlanmadı'}")
        self.line(f"  MODEL : {self.model or 'bağlantı varsayılanı'}")
        self.line("-" * min(62, self.width), "32")
        for row in (
            "  [1] Hedef ayarla", "  [2] Port / servis keşfi", "  [3] Web keşfi",
            "  [4] Zafiyet incele", "  [5] Flag bul", "  [6] Dosya incele",
            "  [7] Son sonucu göster", "  [8] Ayarlar", "  [9] Yeni oturum", "  [0] Çıkış",
        ):
            self.line(row)
        self.line("-" * min(62, self.width), "32")
        self.line("  Numara veya görev yaz.  menu | sonuc | kaydet | temizle")
        self.line("=" * min(62, self.width), "32")

    def ask(self, label: str) -> str:
        return input(fit(label, self.width)).strip()

    def set_target(self, value: str):
        value = clean(value).strip()
        if not value or len(value) > 512 or any(char.isspace() for char in value):
            self.line("[!] IP, alan adı veya URL gir.", "33")
            return
        if self.target != value:
            self.target = value
            self.session_id = None
            self.verified_flags = []
            self.last_path = None
        self.persist()
        self.line(f"[+] Hedef: {self.target}", "32")

    def prompt(self, task: str) -> str:
        policy = (ROOT / "cyber/policy.txt").read_text(encoding="utf-8")
        return (f"{policy}\n\nLAB CONTEXT\nTarget: {self.target or '(not set)'}\n"
                f"Workspace: {self.workspace()}\n\nUSER TASK\n{task}\n\n"
                "Finish with the delimited CYBER_RESULT JSON. No conversational output.")

    def execute(self, task: str, label: str = "GÖREV") -> bool:
        self.line(f"[*] {label} çalışıyor…  Ctrl+C: durdur", "36")
        try:
            result = asyncio.run(self.backend.run(
                self.prompt(task), self.workspace(), self.session_id,
                self.provider, self.model, self.profile,
                self.verified_flags,
            ))
        except KeyboardInterrupt:
            self.line("[!] İşlem durduruldu.", "33")
            return False
        except (OSError, ValueError):
            self.line("[!] İşlem başlatılamadı. Bağlantı / çalışma klasörünü kontrol et.", "31")
            return False
        self.session_id = result.session_id
        self.verified_flags = list(dict.fromkeys(
            self.verified_flags + result.summary.get("flags", [])
        ))[-40:]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        report = {"target": self.target, "task": task, "session_id": result.session_id,
                  "tools": result.tools, "summary": result.summary, "error": result.error,
                  "elapsed": round(result.elapsed, 1)}
        path = self.state / "results" / f"{stamp}.json"
        write_json(path, report)
        self.last_path = str(path)
        self.persist()
        self.show_result(report)
        return not result.error and result.summary.get("status") == "ok"

    def show_result(self, report: dict):
        self.line()
        tools = report.get("tools", [])
        for tool in tools[-8:]:
            self.line(f"[{'!' if tool.get('error') else '+'}] {tool.get('name', 'tool')}",
                      "33" if tool.get("error") else "32")
            rows = clean(tool.get("output", "")).splitlines()
            visible = rows if self.args.full_output else rows[:16]
            for row in visible:
                self.line(f"    {row}")
            if len(visible) < len(rows):
                self.line(f"    … {len(rows) - len(visible)} satır daha. Tam çıktı: kaydet")
        if len(tools) > 8:
            self.line(f"[*] {len(tools) - 8} önceki araç çıktısı kayıtta.")
        if report.get("error"):
            self.line(f"[!] {report['error']}", "31")
        summary = report.get("summary", {})
        for flag in summary.get("flags", []):
            self.line(f"[FLAG] {flag}", "32")
        for finding in summary.get("findings", []):
            self.line(f"[+] {finding}" if summary.get("status") == "ok" else f"[!] {finding}")
        for next_step in summary.get("next", []):
            self.line(f"[>] {next_step}")
        self.line(f"[*] Süre: {report.get('elapsed', 0):.1f}s", "36")
        self.line()

    def last_result(self):
        if not self.last_path:
            self.line("[!] Henüz sonuç yok.", "33")
            return
        report = read_json(Path(self.last_path))
        if report:
            self.show_result(report)
        else:
            self.line("[!] Sonuç kaydı bulunamadı.", "33")

    def save_result(self):
        if not self.last_path:
            self.line("[!] Henüz sonuç yok.", "33")
            return
        # The complete tool outputs already exist in this private local file.
        self.line(f"[+] Kayıt: {self.last_path}", "32")

    def check_connection(self) -> bool:
        success = self.execute("Bağlantı kontrolü: bash aracıyla yalnızca printf CYBER_OK "
                               "çalıştır. Ağ taraması yapma. Sonuçta Bağlantı hazır yaz.", "BAĞLANTI")
        report = read_json(Path(self.last_path)) if self.last_path else {}
        confirmed = any(tool.get("name") == "bash" and "CYBER_OK" in tool.get("output", "")
                        and not tool.get("error") for tool in report.get("tools", []))
        if success and not confirmed:
            self.line("[!] Araç bağlantısı doğrulanamadı.", "33")
        return success and confirmed

    def settings_menu(self):
        while True:
            self.line(f"  Sağlayıcı: {self.provider}  Model: {self.model or 'varsayılan'}")
            for row in ("  [1] Sağlayıcı değiştir", "  [2] Model değiştir",
                        "  [3] Bağlantı kontrolü", "  [4] Giriş / bağlantı",
                        "  [5] Model listesi", "  [6] Sağlayıcı profili", "  [0] Geri"):
                self.line(row)
            choice = self.ask("ayar > ")
            if choice in ("0", "geri", "exit"):
                break
            if choice in ("1", "2", "6"):
                field_name = {"1": "provider", "2": "model", "6": "profile"}[choice]
                value = self.ask("değer (boş: varsayılan) > ")
                setattr(self, field_name, value or ("auto" if choice == "1" else ""))
                self.session_id = None
                self.verified_flags = []
                self.persist()
                self.line("[+] Kaydedildi.", "32")
            elif choice == "3":
                self.check_connection()
            elif choice == "4":
                provider = self.ask("sağlayıcı (boş: mevcut) > ") or self.provider
                if provider == "auto":
                    self.line("[!] Giriş yapılacak sağlayıcı adını gir.", "33")
                    continue
                import subprocess
                try:
                    subprocess.run(self.backend.command(provider) + ["login", provider],
                                   env=self.backend.environment(), check=False)
                except OSError:
                    self.line("[!] Giriş başlatılamadı.", "31")
            elif choice == "5":
                self.list_models()
            else:
                self.line("[!] Geçersiz seçim.", "33")

    def list_models(self):
        import subprocess
        self.line("[*] Model listesi alınıyor…", "36")
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
            self.line("[!] Model listesi alınamadı.", "33")

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
                    self.line("[*] Oturum kapandı.", "36")
                    return 0
                if choice in ("menu", "help", "yardim", "yardım", "?"):
                    self.menu()
                elif choice == "1":
                    self.set_target(self.ask("hedef > "))
                elif choice.startswith("hedef "):
                    self.set_target(choice[6:])
                elif choice in TASKS:
                    if not self.target:
                        self.line("[!] Önce [1] ile hedef ayarla.", "33")
                        continue
                    label, task = TASKS[choice]
                    self.execute(task, label)
                elif choice == "6":
                    filename = self.ask("dosya yolu > ")
                    path = Path(filename).expanduser().resolve()
                    if not filename or not path.is_file():
                        self.line("[!] Dosya bulunamadı.", "33")
                        continue
                    self.execute(f"Şu yerel lab dosyasını araçlarla incele: {json.dumps(str(path))}. "
                                 "Dosyanın türünü, yararlı bilgileri ve varsa flagları belirle.", "DOSYA")
                elif choice in ("7", "sonuc", "sonuç"):
                    self.last_result()
                elif choice == "8":
                    self.settings_menu()
                elif choice in ("9", "yeni"):
                    self.session_id = None
                    self.verified_flags = []
                    self.last_path = None
                    self.persist()
                    self.line("[+] Yeni oturum hazır.", "32")
                elif choice == "kaydet":
                    self.save_result()
                elif choice == "temizle":
                    if sys.stdout.isatty():
                        print("\033[2J\033[H", end="")
                    self.banner()
                    self.menu()
                elif choice.isdecimal():
                    self.line("[!] Geçersiz seçim. Menü: menu", "33")
                else:
                    self.execute(choice)
            except EOFError:
                self.line()
                return 0
            except KeyboardInterrupt:
                self.line("\n[!] Giriş iptal edildi. Çıkış: 0", "33")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cyber-jcode", description="TryHackMe lab terminali")
    parser.add_argument("--version", action="version", version=f"cyber-jcode {VERSION}")
    parser.add_argument("--target", help="Lab IP, alan adı veya URL")
    parser.add_argument("--provider", help="Model sağlayıcısı")
    parser.add_argument("--model", help="Model adı")
    parser.add_argument("--cwd", "-C", help="Lab çalışma klasörü")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--full-output", action="store_true", help="Araçların tüm satırlarını göster")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--menu", action="store_true", help="Menüyü göster ve çık")
    mode.add_argument("--check", action="store_true", help="Model ve gerçek araç bağlantısını kontrol et")
    mode.add_argument("--run", help="Tek görev çalıştır ve çık")
    args = parser.parse_args(argv)
    state = Path(os.environ.get("CYBER_JCODE_HOME", str(Path.home() / ".cyber-jcode"))).expanduser().resolve()
    protected = [(Path.home() / name).resolve() for name in (".jcode", ".config/jcode")]
    if any(state.is_relative_to(path) or path.is_relative_to(state) for path in protected):
        parser.error("Cyber-Jcode için ayrı bir veri klasörü seç.")
    os.umask(0o077)
    try:
        return Console(state, args).loop()
    except OSError:
        print("[!] Cyber-Jcode kayıt klasörüne erişilemiyor.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
