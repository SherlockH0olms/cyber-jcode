#!/usr/bin/env python3
"""Capture a real Chromium page; emit text metadata instead of image input."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit


def capture(url: str, output: Path, browser: str | None = None,
            no_sandbox: bool = False, timeout: int = 60) -> dict:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https", "file") or parsed.username or parsed.password:
        raise ValueError("Use an HTTP(S) page or local file URL without embedded credentials.")
    browser = browser or next((path for name in ("chromium", "chromium-browser", "google-chrome")
                               if (path := shutil.which(name))), None)
    if not browser:
        raise ValueError("Chromium is missing. Kali/Ubuntu: sudo apt install chromium")
    output = output.expanduser().resolve()
    if output.suffix.lower() != ".png" or output.exists():
        raise ValueError("Choose a new .png output filename; existing evidence is never overwritten.")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cyber-browser-") as profile:
        command = [browser, "--headless", "--disable-gpu", "--hide-scrollbars",
                   "--no-first-run", "--no-default-browser-check", "--window-size=1440,1000",
                   "--virtual-time-budget=5000", f"--user-data-dir={profile}",
                   f"--screenshot={output}"]
        if no_sandbox:
            command.append("--no-sandbox")
        command.append(url)
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if completed.returncode or not output.is_file():
        raise ValueError("Browser capture failed. Check Chromium, the URL and browser sandbox support.")
    from PIL import Image
    with Image.open(output) as image:
        if image.format != "PNG":
            raise ValueError("Browser did not produce a PNG image.")
        width, height = image.size
        image.verify()
    output.chmod(0o600)
    record = {"kind": "browser_screenshot", "path": str(output), "url": url,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "width": width, "height": height,
            "capture_method": "chromium-headless", "capture_command": command,
            "note": "Actual browser viewport capture; file verified, page content not visually reviewed."}
    manifest = output.with_suffix(".capture.json")
    with manifest.open("x", encoding="utf-8") as stream:
        json.dump(record, stream)
    manifest.chmod(0o600)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--no-sandbox", action="store_true",
                        help="For isolated environments where the browser sandbox cannot initialize")
    args = parser.parse_args()
    try:
        print(json.dumps(capture(args.url, args.output, no_sandbox=args.no_sandbox)))
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"error": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
