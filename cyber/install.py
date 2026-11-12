#!/usr/bin/env python3
"""Install only the Cyber-Jcode launcher and private copies of model settings."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cyber.console import ROOT, private_dir, read_json, write_json


def snapshot(home: Path) -> dict:
    paths = [home / ".local/bin/jcode", home / ".jcode/config.toml",
             home / ".jcode/builds/stable/jcode", home / ".jcode/builds/current/jcode",
             home / ".jcode/builds/shared-server/jcode"]
    paths.extend(sorted((home / ".config/jcode").glob("*.env")))
    result = {}
    for path in paths:
        if not path.exists() and not path.is_symlink():
            continue
        item = {"link": os.readlink(path) if path.is_symlink() else None,
                "mode": path.lstat().st_mode, "modified": path.lstat().st_mtime_ns}
        if path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
            item["sha256"] = digest.hexdigest()
        result[str(path)] = item
    return result


def copy_private(source: Path, destination: Path):
    if source.is_file() and not destination.exists():
        private_dir(destination.parent)
        # copyfile does not chmod, rename or write the original credential file.
        shutil.copyfile(source, destination)
        destination.chmod(0o600)


REFERENCE_FILES = ("pentest.txt", "dehset_pentest_araclari.txt")


def import_references(state: Path, sources: Path | None = None):
    """Copy the user's pentest handbooks into the private state, never overwrite."""
    folder = sources or Path("/mnt/c/Users/ASUS/Desktop")
    for name in REFERENCE_FILES:
        source = folder / name
        if source.is_file():
            copy_private(source, state / "references" / name)


def import_settings(home: Path, state: Path):
    engine = state / "engine"
    copy_private(home / ".jcode/config.toml", engine / "config.toml")
    for source in sorted((home / ".config/jcode").glob("*.env")):
        copy_private(source, engine / "config/jcode" / source.name)
    for source in sorted((home / ".jcode").glob("*auth*.json")):
        copy_private(source, engine / source.name)
    copy_private(home / ".jcode/account-pool.json", engine / "account-pool.json")
    for name in (".codex/auth.json", ".claude/.credentials.json", ".claude.json",
                 ".gemini/oauth_creds.json", ".gemini/google_accounts.json"):
        copy_private(home / name, engine / "external" / name)


def link_launcher(link: Path, launcher: Path):
    if link.is_symlink():
        if link.resolve() != launcher.resolve():
            raise ValueError("The cyber-jcode command belongs to another installation; not overwritten.")
    elif link.exists():
        raise ValueError("The cyber-jcode command already exists; not overwritten.")
    else:
        link.symlink_to(launcher)


def install(home: Path, state: Path, build: bool = True):
    protected = [(home / name).resolve() for name in (".jcode", ".config/jcode")]
    if any(state.resolve().is_relative_to(path) or path.is_relative_to(state.resolve()) for path in protected):
        raise ValueError("Choose a separate Cyber-Jcode data directory.")
    private_dir(state)
    baseline = snapshot(home)
    if not (state / "original-install-snapshot.json").exists():
        write_json(state / "original-install-snapshot.json", baseline)
    if build:
        subprocess.run(["cargo", "build", "--locked", "--profile", "selfdev",
                        "--bin", "jcode", "-j", "2"], cwd=ROOT, check=True)
    binary = ROOT / "target/selfdev/jcode"
    if not binary.is_file():
        raise ValueError("Build the source engine first: cargo build --profile selfdev --bin jcode")
    import_settings(home, state)
    import_references(state)
    for path in (state / "engine", state / "engine/config/jcode", state / "run", state / "results"):
        private_dir(path)
    launcher = ROOT / "cyber-jcode"
    launcher.chmod(0o755)
    bindir = home / ".local/bin"
    bindir.mkdir(parents=True, exist_ok=True)
    link = bindir / "cyber-jcode"
    link_launcher(link, launcher)
    if snapshot(home) != baseline:
        raise ValueError("Existing jcode files changed; verification failed.")
    print("[+] cyber-jcode installed.")
    print("[+] Connection settings copied independently.")
    print("[+] Existing jcode unchanged.")


def main():
    parser = argparse.ArgumentParser(description="Independent Cyber-Jcode setup")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--verify-original", action="store_true")
    parser.add_argument("--link-system", action="store_true",
                        help="Create only /usr/local/bin/cyber-jcode (root)")
    args = parser.parse_args()
    os.umask(0o077)
    home = Path.home()
    state = Path(os.environ.get("CYBER_JCODE_HOME", str(home / ".cyber-jcode"))).expanduser().resolve()
    try:
        if args.link_system:
            link_launcher(Path("/usr/local/bin/cyber-jcode"), ROOT / "cyber-jcode")
            print("[+] /usr/local/bin/cyber-jcode ready.")
        elif args.verify_original:
            baseline = read_json(state / "original-install-snapshot.json")
            if not baseline or snapshot(home) != baseline:
                print("[!] Existing installation verification failed.")
                return 1
            print("[+] Existing jcode files and links unchanged.")
        else:
            install(home, state, build=not args.skip_build)
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
