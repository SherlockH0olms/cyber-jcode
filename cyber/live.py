"""Keep an editable prompt open while the headless engine uses safe steering."""
import asyncio
import sys


def merge_runs(first, later):
    """Retain evidence if a last-moment instruction needs another model turn."""
    from cyber.console import RunResult
    from cyber.report import parse_engagement_details
    import json
    details = [parse_engagement_details(run.raw_text) for run in (first, later)]
    merged = {"findings": details[0]["findings"] + details[1]["findings"],
              "access": details[1]["access"] or details[0]["access"],
              "limitations": details[0]["limitations"] + details[1]["limitations"],
              "screenshots": details[0]["screenshots"] + details[1]["screenshots"]}
    summary = dict(later.summary)
    summary["flags"] = list(dict.fromkeys(first.summary.get("flags", []) + later.summary.get("flags", [])))
    return RunResult(session_id=later.session_id, tools=first.tools + later.tools, summary=summary,
        error=later.error, elapsed=first.elapsed + later.elapsed,
        raw_text="[CYBER_FINDINGS]" + json.dumps(merged) + "[/CYBER_FINDINGS]",
        pending_instructions=later.pending_instructions)


async def run_with_input(console, prompt, label, phase, display, on_tool):
    from cyber.console import RunResult
    parameters = dict(progress=display, on_tool=on_tool if phase else None, capture_tools=bool(phase))
    async def run(task, session, instructions=None, notice=None):
        if instructions is not None:
            return await console.backend.run(task, console.workspace(), session, console.provider,
                console.model, console.profile, console.verified_flags, **parameters,
                instructions=instructions, on_instruction=notice)
        return await console.backend.run(task, console.workspace(), session, console.provider,
            console.model, console.profile, console.verified_flags, **parameters)
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return await run(prompt, console.session_id)

    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.patch_stdout import patch_stdout
    except ImportError:
        return RunResult(error="Live prompt dependency missing: sudo apt install python3-prompt-toolkit")
    if console._prompt_session is None:
        console._prompt_session = PromptSession()
    session = console._prompt_session
    queue = asyncio.Queue()
    display.tty = False  # patch_stdout redraws input; avoid carriage-return status overwrites.
    console.line("[*] Add instructions at cyber > while tools run. Ctrl+C or /stop: stop.", "36")
    engine = None

    def notice(state):
        console.line("[+] Instruction applied; task continues." if state == "applied"
                     else "[+] Instruction queued for the next safe point.", "32")

    async def read_input():
        while True:
            try:
                text = (await session.prompt_async("cyber > ", default=console._input_draft)).strip()
                console._input_draft = ""
            except EOFError:
                return
            except KeyboardInterrupt:
                engine.cancel()
                return
            if text == "/stop":
                engine.cancel()
                return
            if text == "/help":
                console.line("[*] Text adds instructions to this task. /stop or Ctrl+C stops it.")
                continue
            if not text:
                continue
            if len(text.encode()) > 32 * 1024:
                console.line("[!] Instruction too long; use at most 32 KB of text.", "33")
                continue
            await queue.put(text)
            console.line("[+] Instruction received.", "32")

    with patch_stdout(raw=True):
        engine = asyncio.create_task(run(prompt, console.session_id, queue, notice))
        reader = asyncio.create_task(read_input())
        try:
            result = await engine
            # If input arrived after the last safe point, continue in the SAME
            # session. Never silently discard it at phase completion.
            while result.pending_instructions and not result.error:
                followup = console.prompt("Continue the current task with these additional user instructions:\n" +
                                          "\n".join(result.pending_instructions), label)
                console.line("[*] Applying additional instructions in the same session.", "36")
                engine = asyncio.create_task(run(followup, result.session_id, queue, notice))
                result = merge_runs(result, await engine)
            return result
        except asyncio.CancelledError:
            raise KeyboardInterrupt from None
        finally:
            console._input_draft = session.default_buffer.text
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
