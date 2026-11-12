# Cyber-Jcode

An independent English terminal console for TryHackMe/CTF labs, using Jcode's
real model and tool engine behind a classic numbered menu.

```bash
cyber-jcode
```

Set the target with `1`. Choose `2` for service discovery, `3` for web discovery,
`4` for vulnerability review, `5` for flag search, or `6` for local file analysis.
Choose `10` for a **full pentest engagement**: seven methodology phases (recon,
service enumeration, web analysis, vulnerability verification, exploitation,
privilege escalation, post-exploitation) run in order toward the highest
privilege, with an enterprise-English **DOCX report** at the end. Enter any other
task directly at `cyber >`. Type `hi`, `hello`, `hey` or `ping`
for a short **real model response** without tools or changes to your lab session.

During a task, one status row shows elapsed time, the current phase or tool name,
and completed/active tool counts. Redirected output gets a status line every
ten seconds. This is activity information, not a completion estimate. Reasoning,
chat streams and tool inputs stay hidden. Up to four short English findings
appear first, followed by actual tool outputs, including written notes and
port/service tables. Background task envelopes are removed; their actual
output is retained. HTML source gets a compact preview. Use `--full-output`
to show all captured output blocks and lines. `save` gives the raw captured
output file. Only verified flags receive the `[FLAG]` label.

`menu` shows the menu; `result` shows the last result; `save` prints the local
JSON path containing full tool outputs; `clear` clears the screen. `9` or `new`
starts a new session; `0` exits. `Ctrl+C` stops the current operation and returns
to the console. Changing targets resets the lab session. Existing Turkish
command aliases remain accepted.

`8` opens provider/model selection, connection checks, login and model lists.
The model list comes from Jcode's existing provider discovery.

```bash
cyber-jcode --check
cyber-jcode --target 10.10.10.10
cyber-jcode --run 'Inspect /tmp/lab-notes.txt'
cyber-jcode --pentest
cyber-jcode --model MODEL_ID
cyber-jcode --provider-profile my-api
cyber-jcode --full-output
```

## Full pentest engagement

`10` (or `--pentest`) runs an authorized-lab engagement through seven ordered
phases. Each phase is a real agent turn: prior phase results travel forward as
engagement context, and the console asks before each next phase (Enter or y =
run, n = stop and report, s = skip that phase). Ctrl+C mid-phase keeps the
partial tool outputs and records the phase as partial; the engagement report is
still produced. Every phase must report only tool-verified vulnerabilities, each
with title, severity, category, evidence, impact and remediation. The goal is
maximum progress to root/SYSTEM, not the first flag; the report documents the
full attack surface and chain.

During each phase the console streams every tool invocation and its result as it
completes (bash commands are shown with their command line). The full recorded
transcript, per-tool command/output pairs and evidence identifiers are kept in
the engagement JSON, and the DOCX appendix reproduces each recorded tool result.

The engagement ends with `~/.cyber-jcode/results/pentest-<stamp>.json` (all
data), `~/.cyber-jcode/reports/pentest-<stamp>.docx` and a copy on the Windows
Desktop. The report contains: cover, executive summary, methodology table,
findings overview and detail tables sorted by severity (with evidence-linked
validation and reproduction steps), tool activity log, embedded terminal-style
evidence images per phase, conclusion with observed flags, and an appendix with
each recorded tool invocation and output. Requirements: `pip install python-docx
pillow`.

The installer also copies `pentest.txt` and `dehset_pentest_araclari.txt` from
the Windows Desktop into `~/.cyber-jcode/references` (once; never overwritten).
Full pentest phases reference these handbooks as optional methodology guidance.

## OpenAI-compatible connection

The first installation copies existing Jcode model settings and credentials
into Cyber-Jcode's private directories. A working copied connection needs no
reconfiguration. Later changes to original Jcode settings are not synchronized.

Cyber-Jcode forwards the existing Jcode configuration commands with its private
environment. It uses Jcode's provider writer, authentication and option handling.
Add a new connection **from your shell**, after exiting `cyber >`:

```bash
python3 -c 'import getpass; print(getpass.getpass("API key: "))' | \
  cyber-jcode provider add my-api \
  --base-url https://gateway.example/v1 \
  --model MODEL_ID \
  --api-key-stdin \
  --set-default
cyber-jcode
```

Replace the URL and model ID with your gateway's values. `--set-default` selects
the new profile for the next console launch and clears old frontend model/session
overrides. Use `--overwrite` to replace an existing profile. For a local endpoint
that requires no key, use `--no-api-key` instead of `--api-key-stdin`.

```bash
cyber-jcode provider add --help
cyber-jcode provider current
cyber-jcode provider list
cyber-jcode model list --json
cyber-jcode auth status
```

## Installation and isolation

```bash
cd ~/cyber-jcode
python3 cyber/install.py
```

Requires Python 3.11+ and the Rust toolchain for the initial engine build.
The engine is built from this repository as `target/selfdev/jcode`. The installer
creates `~/.local/bin/cyber-jcode`. If that directory is absent from PATH,
`sudo python3 cyber/install.py --link-system` additionally links
`/usr/local/bin/cyber-jcode`; it refuses to overwrite a different existing command.
Original Jcode settings, credentials and launcher are preserved.

Cyber-Jcode data lives in `~/.cyber-jcode`: `engine` holds private model settings
and backend sessions, `run` holds the isolated socket, `labs` holds workspaces,
and `results` holds tool output and short results. Use `--cwd PATH` for a custom
lab workspace or `CYBER_JCODE_HOME` for a separate data directory. Backend session
logs stay in the background; frontend result files exclude reasoning/chat streams.
The actual home environment variable is preserved.

Python/interface updates take effect when the console is reopened. An operation
already running continues with the code loaded by that process.

```bash
python3 -m unittest cyber.test_console -v
python3 cyber/install.py --verify-original
cyber-jcode --check
```
