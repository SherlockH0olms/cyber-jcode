# Cyber-Jcode

An English, numbered terminal console for TryHackMe and CTF labs. Jcode's
model and tool engine runs behind the console; the interface shows short
findings, actual tool output and task progress. Full pentest mode records
the assessment in a plain enterprise-English DOCX report.

## Install on Kali / Debian / Ubuntu / WSL

Run these commands **inside Linux or your WSL distribution**, as your normal
user. The console requires Python 3.11 or newer. Native Windows installation
is not supported by this launcher.

Install the build tools and report dependencies:

```bash
sudo apt update
sudo apt install -y git curl ca-certificates build-essential pkg-config \
  libssl-dev perl cmake python3 python3-docx python3-pil python3-prompt-toolkit \
  fonts-dejavu-core chromium
```

Install the current stable Rust toolchain if Rust is not already installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
  sh -s -- -y --profile minimal --default-toolchain stable
. "$HOME/.cargo/env"
```

An existing older Rust toolchain can be updated with `rustup update stable`.
The source engine has been built with Rust 1.95.0. Python report dependencies
are installed with `apt` above, so no system-wide `pip` installation is needed.

Clone the Cyber-Jcode repository:

```bash
git clone https://github.com/SherlockH0olms/cyber-jcode.git ~/cyber-jcode
cd ~/cyber-jcode
python3 cyber/install.py
export PATH="$HOME/.local/bin:$PATH"
cyber-jcode --version
cyber-jcode --menu
```

Add the `export PATH=...` line to `~/.zshrc` (Kali's usual shell) or
`~/.bashrc` to keep it for new terminals. The installer builds the local
engine with `cargo build --locked --profile selfdev --bin jcode -j 2` and
links `~/.local/bin/cyber-jcode` to this checkout. The first build can take
several minutes; keep the checkout at its installed path.

An existing Jcode installation is **not required**. If one exists, setup
copies available connection settings into private Cyber-Jcode storage.
Original files and the `jcode` launcher are preserved. A fresh computer
needs its own model connection configured below; credentials and generated
build files are not included in a Git clone.

This fork's installer is `python3 cyber/install.py`. The upstream
`https://jcode.sh/install`, `scripts/install.sh`, `scripts/install_release.sh`,
`scripts/install.ps1` and `cargo install --path .` install original Jcode
commands, so they are not the Cyber-Jcode setup procedure.

## Connect an OpenAI-compatible model

Run connection commands in your **Linux shell**, after leaving `cyber >`:

```bash
cyber-jcode login openai-compatible \
  --api-base https://ornek.com/v1 \
  --api-key SK-XXXX \
  --model MODEL_ID
```

Replace the URL, key and model ID with your endpoint's values. Omitting
`--api-key` prompts for it securely. On a fresh installation this login
sets the initial provider/model default. `--no-validate` saves credentials
without checking the endpoint; normal login validates the connection.

Check the connection, then open the console:

```bash
cyber-jcode --check
cyber-jcode
```

At `cyber >`, type `hi` for a short real model response without tools.
`--check` also verifies a harmless local tool invocation. For lab work,
choose a model that supports tool calling and ensure the required tools
are installed in Linux; setup installs the console, engine and reporting
dependencies, not every pentest utility or your lab VPN.

To add a named connection and make it the default even when an older
connection was copied, use:

```bash
python3 -c 'import getpass; print(getpass.getpass("API key: "))' | \
  cyber-jcode provider add my-api \
  --base-url https://ornek.com/v1 \
  --model MODEL_ID \
  --api-key-stdin \
  --set-default
```

`provider add` uses `--base-url`; `login` uses `--api-base`.
Add `--overwrite` to replace an existing named profile. For a local
endpoint without authentication, use `--no-api-key` instead of
`--api-key-stdin`.

```bash
cyber-jcode provider current
cyber-jcode provider list
cyber-jcode model list --json
cyber-jcode auth status
cyber-jcode login openai-compatible --help
cyber-jcode provider add --help
```

The forwarded configuration command (`login`, `provider`, `model` or `auth`)
must come immediately after `cyber-jcode`. Its help may say `jcode` because
it comes from the embedded engine; it still uses Cyber-Jcode's private state.

## Use the console

Choose `1` to set a target, `2` for service discovery, `3` for web discovery,
`4` for vulnerability review, `5` for flags, `6` for local files or `10` for
the seven-phase full pentest and DOCX report. Enter a custom task at the
same `cyber >` prompt. `menu`, `result`, `save`, `clear` and `new` are also
available. Choose `0` to exit; `Ctrl+C` stops the current task.

While a task runs, an editable `cyber >` prompt stays open. Type additional
instructions and press Enter; the engine applies them in the same session at
the next safe point without cancelling active tools. `/stop` or Ctrl+C explicitly
stops the task. Text entered at a phase transition becomes an instruction for
the next phase; it does not end the engagement. Tool headings use plain English
action names, while complete source identifiers remain in the saved evidence.

```bash
cyber-jcode --target 10.10.10.10
cyber-jcode --run 'Inspect /tmp/lab-notes.txt'
cyber-jcode --target 10.10.10.10 --pentest
cyber-jcode --provider-profile my-api
cyber-jcode --full-output
```

Full mode asks before starting and between phases. It saves recorded tool
activity privately in `~/.cyber-jcode/results`. User-facing DOCX reports and
their full text transcripts go inside **Desktop/raport**, including the Windows
Desktop under WSL. Report filenames include the target and UTC timestamp.
The exporter uses the [Word template](cyber/templates/enterprise-pentest.docx)
and every phase receives the mandatory [reporting handbook](cyber/reporting-handbook.md).
Real Chromium captures are embedded only after artifact verification; terminal
text is kept as text. Screenshot/image inputs are disabled for all models and
tasks, including resumed history. Type `sessions` or choose `[11]` to browse
saved results without changing the active session. See [the console guide](cyber/README.md).

## Isolation and updates

The public command is `cyber-jcode`. The internal binary remains named
`target/selfdev/jcode` and is launched directly from this checkout with
updates and self-development mode disabled. It does not resolve the
installed `jcode` command from PATH.

Configuration, copied credentials, sessions, workspaces and the socket
live under `~/.cyber-jcode`. Later changes to original Jcode settings are
not synchronized. `CYBER_JCODE_HOME` selects another private data directory.

After updating source, run setup again to rebuild the engine if necessary:

```bash
cd ~/cyber-jcode
git pull --ff-only
python3 cyber/install.py
```

For Python/docs-only changes with an existing `target/selfdev/jcode`, use
`python3 cyber/install.py --skip-build`. A fresh clone requires the build;
`--skip-build` does not download an engine. Reopen the console to load
Python changes. `--link-system` only adds `/usr/local/bin/cyber-jcode` and
does not perform a full installation.

Cyber-Jcode is a fork of [Jcode by 1jehuang](https://github.com/1jehuang/jcode).
The original engine source and [license](LICENSE) are retained.
