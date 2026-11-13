"""English report records, evidence linkage and genuine capture verification."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re

from cyber.console import clean, private_dir, wrap_rows

# DejaVu Sans Mono ships with most Linux distributions and WSL setups.
MONO_FONT_HINTS = ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
                   "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
                   "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
                   "/usr/share/fonts/TTF/DejaVuSansMono.ttf")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

PHASE_NAMES = {
    "recon": "Reconnaissance and Port Discovery",
    "services": "Service and Credential Enumeration",
    "web": "Web Application Analysis",
    "vulns": "Vulnerability Verification",
    "exploit": "Exploitation and Initial Access",
    "privesc": "Privilege Escalation",
    "post": "Post-Exploitation and Evidence Collection",
}


def sanitize_field(value: object, limit: int = 300) -> str:
    text = " ".join(clean(value or "").split())
    return text[:limit]


def parse_engagement_details(text: str) -> dict:
    """Only explicit final blocks outside hidden reasoning are report data."""
    text = re.sub(r"<(think|thinking|reasoning)>.*?(?:</\1>|$)", "", text,
                  flags=re.S | re.I)
    matches = list(re.finditer(r"\[CYBER_FINDINGS\](.*?)\[/CYBER_FINDINGS\]", text, re.S))
    for match in reversed(matches):
        try:
            import json
            data = json.loads(match.group(1).strip())
        except ValueError:
            continue
        if not isinstance(data, dict):
            continue
        raw = data.get("findings")
        if not isinstance(raw, list):
            continue
        findings = []
        for item in raw[:200]:
            if not isinstance(item, dict):
                continue
            severity = str(item.get("severity", "info")).lower()
            if severity not in SEVERITY_ORDER:
                severity = "info"
            findings.append({
                "title": sanitize_field(item.get("title"), 160) or "Untitled finding",
                "severity": severity,
                "category": sanitize_field(item.get("category"), 60) or "General",
                "evidence": sanitize_field(item.get("evidence")),
                "impact": sanitize_field(item.get("impact"), 3000),
                "remediation": sanitize_field(item.get("remediation"), 3000),
                "description": sanitize_field(item.get("description"), 3000),
                "prerequisites": sanitize_field(item.get("prerequisites"), 1500),
                "severity_rationale": sanitize_field(item.get("severity_rationale"), 1500),
                "retest": sanitize_field(item.get("retest"), 2000),
                "reproduction_steps": [sanitize_field(step, 1500) for step in item.get("reproduction_steps", [])[:20]]
                                      if isinstance(item.get("reproduction_steps"), list) else [],
                "references": [sanitize_field(ref, 512) for ref in item.get("references", [])[:10]]
                              if isinstance(item.get("references"), list) else [],
                "asset": sanitize_field(item.get("asset"), 512),
                "reproduction": sanitize_field(item.get("reproduction"), 3000),
                "evidence_excerpt": clean(item.get("evidence_excerpt", ""))[:3000],
                "tool_ids": [str(value) for value in item.get("tool_ids", [])[:20]]
                            if isinstance(item.get("tool_ids"), list) else [],
            })
        return {"findings": findings, "access": data.get("access", {}),
                "screenshots": data.get("screenshots", []) if isinstance(data.get("screenshots"), list) else [],
                "limitations": [sanitize_field(value, 1000) for value in data.get("limitations", [])[:20]]
                                if isinstance(data.get("limitations"), list) else []}
    return {"findings": [], "access": {}, "limitations": [], "screenshots": []}


def capture_artifact_valid(record: dict) -> bool:
    """Local renderer checks bytes; the model receives only text metadata."""
    import hashlib
    from PIL import Image
    try:
        path = Path(record["path"])
        if record.get("kind") != "browser_screenshot" or record.get("capture_method") != "chromium-headless":
            return False
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != record.get("sha256"):
            return False
        with Image.open(path) as image:
            if image.format != "PNG" or list(image.size) != [record.get("width"), record.get("height")]:
                return False
            image.verify()
        return True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def collect_screenshots(tools: list[dict], evidence: Path, phase: str = "") -> list[dict]:
    """Accept capture-helper metadata from successful recorded commands only."""
    import json
    from cyber.console import display_tool
    records = []
    seen = set()
    for index, tool in enumerate(tools, 1):
        visible = display_tool(tool)
        if not visible or visible["error"] or visible["name"] != "bash":
            continue
        for line in visible["output"].splitlines():
            try:
                record = json.loads(line)
                if not isinstance(record, dict) or record.get("kind") != "browser_screenshot":
                    continue
                path = Path(record["path"]).resolve()
                if not path.is_relative_to(evidence.resolve()) or str(path) in seen:
                    continue
                manifest = json.loads(path.with_suffix(".capture.json").read_text(encoding="utf-8"))
                if manifest != record or not capture_artifact_valid(record):
                    continue
                # Background completion may carry metadata while the starting bash call carries the command.
                if not any("capture.py" in str(t.get("command", "")) and str(path) in str(t.get("command", ""))
                           and not t.get("error") for t in tools):
                    continue
                record.update(validation="artifact-verified", phase=phase,
                              title=f"{phase.upper() or 'WEB'} — browser capture",
                              tool_ids=[str(tool.get("id", index))])
                records.append(record)
                seen.add(str(path))
            except (OSError, ValueError, KeyError, TypeError):
                continue
    return records


def parse_engagement_findings(text: str) -> list[dict]:
    return parse_engagement_details(text)["findings"]


def link_findings(findings: list[dict], tools: list[dict]) -> list[dict]:
    linked = []
    for item in findings:
        finding = dict(item)
        quote = finding.get("evidence_excerpt") or finding.get("evidence", "")
        matches = [str(tool.get("id", index)) for index, tool in enumerate(tools, 1)
                   if len(quote.strip()) >= 12 and quote in tool.get("output", "")
                   and not tool.get("error")
                   and (not finding.get("tool_ids") or str(tool.get("id", index)) in finding["tool_ids"])]
        finding["validation"] = "evidence-linked" if matches else "unverified"
        finding["tool_ids"] = matches
        linked.append(finding)
    return linked


def verified_access(access: object, tools: list[dict], target: str) -> dict | None:
    if not isinstance(access, dict) or access.get("target") != target:
        return None
    level = str(access.get("level", "")).lower()
    quote = clean(access.get("evidence_excerpt", ""))
    if len(quote) < 8 or not any(quote in tool.get("output", "") and not tool.get("error") for tool in tools):
        return None
    if level == "root" and not re.search(r"\buid=0(?:\(root\))?", quote):
        return None
    if level == "system" and "nt authority\\system" not in quote.lower():
        return None
    if level not in ("root", "system", "administrator", "user"):
        return None
    return {"level": level, "target": target, "evidence_excerpt": quote}


def _monospace_font(size: int):
    from PIL import ImageFont
    for hint in MONO_FONT_HINTS:
        path = Path(hint)
        if path.is_file():
            try:
                return ImageFont.truetype(str(path), size)
            except OSError:
                continue
    return ImageFont.load_default()


def _find_ansi_escape(text: str) -> str:
    return re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|[\x00-\x08\x0b\x0c\x0e-\x1f]").sub("", text)


def render_terminal_png(text: str, destination: Path, title: str = "",
                        width: int = 960, line_height: int = 19,
                        max_lines: int = 40) -> Path | None:
    """A plain capture rendered from recorded text, not a simulated live screen."""
    from PIL import Image, ImageDraw
    lines = list(wrap_rows(clean(text), max(10, (width - 28) // 9)))[:max_lines]
    if not lines:
        return None
    font = _monospace_font(14)
    padding = 14
    bar = 34 if title else 0
    height = bar + padding * 2 + line_height * len(lines)
    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)
    if title:
        draw.rectangle([0, 0, width, bar], fill=(235, 235, 235))
        title_font = _monospace_font(13)
        draw.text((padding, 9), title[:90], font=title_font, fill="black")
    y = bar + padding
    for row in lines:
        draw.text((padding, y), row, font=font, fill="black")
        y += line_height
    private_dir(destination.parent)
    image.save(destination, format="PNG")
    destination.chmod(0o600)
    return destination


def build_report(engagement: dict, destination: Path) -> Path:
    """Render the professional template without flooding Word with raw output."""
    from cyber.docx_report import render_report
    return render_report(engagement, destination)
