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
ten seconds. This is activity information, not a completion estimate. The menu
shows the target and a motto instead of the engine or model identity.
Explicit provider/model configuration commands show their own metadata.
Reasoning and chat streams stay hidden; normal tasks also hide tool inputs.
Up to four short English findings
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

During task execution, the `cyber >` input stays editable. Enter a clue or
instruction normally; do not press Ctrl+C to add information. The headless
engine receives text through its non-urgent soft-interrupt queue and applies
it at the next safe point while keeping active commands running. The console
prints a short acknowledgement when queued and applied. Last-moment messages
continue in the same session rather than being discarded at task completion.
`/stop` or Ctrl+C explicitly stops execution and retains captured output.
`python3-prompt-toolkit` provides input editing and output redrawing.

Phase questions accept y/Enter, n and s as before. Any other text is preserved
as an additional instruction and the engagement continues to the next phase.
Opaque model call IDs are kept in evidence files; terminal headings display
actions such as `Nmap | Port and service scan` and `File | Save evidence`.

`10` (or `--pentest`) runs an authorized-lab engagement through seven ordered
phases. Each phase is a real agent turn: prior phase results travel forward as
engagement context, and the console asks before each next phase (Enter or y =
run, n = pause and report, s = skip that phase). Ctrl+C mid-phase keeps the
partial tool outputs, saves a checkpoint and returns to the console; a partial
engagement report is still produced. Every phase must report only tool-verified vulnerabilities, each
with title, severity, category, evidence, impact and remediation. The goal is
maximum progress to root/SYSTEM, not the first flag; the report documents the
full attack surface and chain.

Type `resume`, or choose `10` and Resume, to continue an unfinished pentest in
the same target/session. Checkpoints are saved before execution, after each
phase and before phase questions, and survive reopening the console. Completed
phases and all prior evidence are retained. The model receives the interrupted
phase's context and reads saved text evidence as needed to avoid repeating
completed work. A terminated command cannot resume its operating-system process;
unfinished commands or lost shell connections may need restoring. The same
engagement JSON, evidence directory, DOCX and transcript are updated on each run.
`10` also offers New engagement; changing targets or `[9]` detaches old progress
while preserving its archived record.

The underlying Jcode agent still performs its supported automatic context
compaction and recovery in the background. Compaction summaries belong to the
private engine session; recorded pentest tool evidence is kept separately.

During each phase the console streams every tool invocation and its result as it
completes (bash commands are shown with their command line). The full recorded
transcript, per-tool command/output pairs and evidence identifiers are kept in
the engagement JSON, and the DOCX appendix reproduces each recorded tool result.

The engagement saves a private JSON record and DOCX in `~/.cyber-jcode/results`
and `~/.cyber-jcode/reports`. Its user-facing DOCX and full `.transcript.txt`
are saved **inside Desktop/raport**, never at the Desktop root. WSL discovers
the Windows Desktop; Linux uses `~/Desktop/raport`. Names include assessment
type, target and UTC timestamp. The console prints the path; `save`, `result`
and session history expose it again. `CYBER_JCODE_REPORT_DIR` overrides the
export folder for custom environments and automated tests.

The supplied [Word template](templates/enterprise-pentest.docx) controls the
restrained grayscale layout. Every full-pentest phase receives the mandatory
[reporting handbook](reporting-handbook.md): enterprise English, traceable
findings, reproduction/remediation/retest, coverage limitations, Word styles,
tables, evidence captions and document review. Every recorded tool appears in
the activity log and appendix with a concise excerpt; the companion transcript
keeps full captured text. Execution success alone never proves target access.

### Real screenshots and text-only model protection

Chromium captures real browser pixels. Use the official helper through `bash`:

```bash
python3 /path/to/cyber-jcode/cyber/capture.py \
  --url http://LAB_TARGET/ \
  --output /absolute/per-run/evidence/path/web-home.png
```

The helper refuses to overwrite evidence and returns text JSON containing path,
time, hash, dimensions and capture method. Full-pentest prompts specify the
per-run evidence directory. The exporter checks successful capture output, the
metadata sidecar, hash and PNG before embedding. A captured browser error page
is still an error page; confirm page behavior from HTTP/DOM text. Missing capture
evidence is disclosed rather than replaced with a rendered terminal image.

**Models must never read, view, attach, decode or OCR screenshot files.** This
applies to all tasks and models, including report previews. Cyber-Jcode sets
`JCODE_DISABLE_IMAGE_INPUT=1`: the engine blocks image reads/computer viewing,
removes image attachments from tool responses, and projects old session images
as short text placeholders. Persisted evidence and text history are preserved.
The exporter loads image files locally; the model sees only capture metadata.
After upgrading from 0.3, rebuild via `python3 cyber/install.py` and reopen the
console. The isolated socket separates any optional tool server from older sessions.
Do not restart an assessment solely because a screenshot read was blocked.

### Session history

Type `sessions` / `history` or choose `[11]` to list saved task results and
pentest reports. Select a number, then Enter/v to view findings, tool output and
report paths, or `r` to open the saved target/session. Opening a pentest restores
its checkpoint; use `10` or `resume` to continue. Earlier reports without a
checkpoint start from their first recorded unfinished/missing phase and retain
their evidence; they cannot recreate unrecorded results.
From the Linux shell, `cyber-jcode sessions` or `cyber-jcode --sessions` opens it directly.
Viewing is read-only and preserves the active session, target and last result;
AI conversations/reasoning are never shown. `[9]` still starts a new session.

Report dependencies are `python-docx`, Pillow and Chromium; the
[installation guide](../README.md#install-on-kali--debian--ubuntu--wsl)
installs distribution packages.

The installer also copies `pentest.txt` and `dehset_pentest_araclari.txt` from
`/mnt/c/Users/ASUS/Desktop` into `~/.cyber-jcode/references` when available
(once; never overwritten). On another machine, place the files directly in
that private references directory. Full pentest phases reference these
handbooks as optional methodology guidance; they are not required for setup.

## OpenAI-compatible connection

The first installation copies available existing Jcode model settings and
credentials into Cyber-Jcode's private directories. Original Jcode does not
need to be installed. A working copied connection needs no
reconfiguration. Later changes to original Jcode settings are not synchronized.

On a fresh computer, configure your connection from the Linux shell:

```bash
cyber-jcode login openai-compatible \
  --api-base https://ornek.com/v1 \
  --api-key SK-XXXX \
  --model MODEL_ID
cyber-jcode --check
```

Replace the example endpoint, key and model. Omitting `--api-key` opens a
secure prompt. This login sets the initial provider/model default on a fresh
installation. For an existing configuration, the named profile command below
with `--set-default` explicitly selects the new connection.

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

Follow the [root README installation guide](../README.md#install-on-kali--debian--ubuntu--wsl)
for cloning, OS/report dependencies, Rust, setup and PATH. It is the
authoritative Cyber-Jcode setup procedure for Linux/WSL, requiring Python
3.11+ and current stable Rust for the initial engine build.

The engine is built from this repository as `target/selfdev/jcode`. The installer
creates `~/.local/bin/cyber-jcode`; it refuses to overwrite a different existing
command. That symlink requires the checkout to remain at its installed path.
`--skip-build` requires an already built local engine. `--link-system` only
creates the system symlink; it does not install or build Cyber-Jcode.
Original Jcode settings, credentials and launcher are preserved. The original
Jcode shell installers and `cargo install --path .` are not Cyber-Jcode setup.

Cyber-Jcode data lives in `~/.cyber-jcode`: `engine` holds private model settings
and backend sessions, `run` holds the isolated socket, `labs` holds workspaces,
and `results` holds tool output and short results. Use `--cwd PATH` for a custom
lab workspace or `CYBER_JCODE_HOME` for a separate data directory. Backend session
logs stay in the background; frontend result files exclude reasoning/chat streams.
The actual home environment variable is preserved.

Python/interface updates take effect when the console is reopened. An operation
already running continues with the code loaded by that process.

```bash
python3 cyber/install.py --verify-original
cyber-jcode --check
```

`--verify-original` compares the original Jcode files, links, permissions and
timestamps against the first setup snapshot. Later user changes to original
Jcode can make this check fail without indicating a Cyber-Jcode conflict.
