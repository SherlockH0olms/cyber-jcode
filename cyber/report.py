"""Corporate English DOCX engagement reports with terminal-style screenshots."""
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
                "impact": sanitize_field(item.get("impact")),
                "remediation": sanitize_field(item.get("remediation")),
                "asset": sanitize_field(item.get("asset"), 512),
                "reproduction": sanitize_field(item.get("reproduction"), 3000),
                "evidence_excerpt": clean(item.get("evidence_excerpt", ""))[:3000],
                "tool_ids": [str(value) for value in item.get("tool_ids", [])[:20]]
                            if isinstance(item.get("tool_ids"), list) else [],
            })
        return {"findings": findings, "access": data.get("access", {}),
                "limitations": [sanitize_field(value, 1000) for value in data.get("limitations", [])[:20]]
                                if isinstance(data.get("limitations"), list) else []}
    return {"findings": [], "access": {}, "limitations": []}


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


def _docx():
    from docx import Document
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Inches, Pt, RGBColor
    return Document, WD_TABLE_ALIGNMENT, WD_ALIGN_PARAGRAPH, OxmlElement, qn, Inches, Pt, RGBColor


def _shade_cell(cell, hex_color: str):
    _, _, _, OxmlElement, qn, _, _, _ = _docx()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:val"), "clear")
    shading.set(qn("w:fill"), hex_color)
    cell._tc.get_or_add_tcPr().append(shading)


def _no_table_borders(table):
    """Apply thin light-gray borders to every cell of a table."""
    _, _, _, OxmlElement, qn, _, _, _ = _docx()
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        element = OxmlElement(f"w:{edge}")
        element.set(qn("w:val"), "single")
        element.set(qn("w:sz"), "4")
        element.set(qn("w:color"), "BFBFBF")
        borders.append(element)
    table._tbl.tblPr.append(borders)


def _cell_text(cell, text: str, bold: bool = False, size: int = 9,
               color: str | None = None):
    _, _, _, _, _, _, Pt, RGBColor = _docx()
    paragraph = cell.paragraphs[0]
    paragraph.text = ""
    run = paragraph.add_run(text)
    run.font.size = Pt(size)
    run.font.name = "Calibri"
    run.bold = bold
    if color:
        run.font.color.rgb = RGBColor.from_string(color)
    return paragraph


def build_report(engagement: dict, destination: Path) -> Path:
    """Build the corporate English DOCX pentest engagement report."""
    Document, _, WD_ALIGN_PARAGRAPH, _, _, Inches, Pt, RGBColor = _docx()
    document = Document()
    # Sane corporate page geometry for a bound report.
    for section in document.sections:
        section.left_margin = Inches(0.9)
        section.right_margin = Inches(0.9)
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
    styles = document.styles
    styles["Normal"].font.name = "Calibri"
    styles["Normal"].font.size = Pt(10.5)
    styles["Title"].font.name = "Calibri"
    styles["Title"].font.size = Pt(18)
    styles["Title"].font.color.rgb = RGBColor(0, 0, 0)
    styles["Heading 1"].font.name = "Calibri"
    styles["Heading 1"].font.size = Pt(13)
    styles["Heading 1"].font.color.rgb = RGBColor(0, 0, 0)
    styles["Heading 2"].font.name = "Calibri"
    styles["Heading 2"].font.size = Pt(11)
    styles["Heading 2"].font.color.rgb = RGBColor(0, 0, 0)

    target = engagement.get("target") or "(not set)"
    started = engagement.get("started") or datetime.now(timezone.utc).isoformat()
    finished = engagement.get("finished") or started
    phases = engagement.get("phases", [])
    all_findings = link_findings(engagement.get("findings", []), engagement.get("tools", []))
    linked_count = sum(finding["validation"] == "evidence-linked" for finding in all_findings)

    # ---- Cover ----
    document.add_paragraph("PENETRATION TEST REPORT", style="Title")
    meta = document.add_paragraph()
    meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = meta.add_run(f"Engagement target: {target}")
    run.font.size = Pt(13)
    document.add_paragraph()
    cover = document.add_table(rows=5, cols=2)
    _no_table_borders(cover)
    rows = (
        ("Classification", "Confidential - Authorized Lab Engagement"),
        ("Prepared by", "Cyber-Jcode Automated Assessment"),
        ("Engagement start", started[:19].replace("T", " ") + " UTC"),
        ("Engagement end", finished[:19].replace("T", " ") + " UTC"),
        ("Report generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M") + " UTC"),
    )
    for index, (key, value) in enumerate(rows):
        _cell_text(cover.rows[index].cells[0], key, bold=True)
        _cell_text(cover.rows[index].cells[1], value)
    document.add_page_break()

    # ---- 1. Executive Summary ----
    document.add_heading("1. Executive Summary", level=1)
    counts = {level: 0 for level in SEVERITY_ORDER}
    for finding in all_findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    reached = engagement.get("final_access") or "No access level recorded"
    summary_sentences = [
        f"This report presents the results of an authorized penetration test "
        f"performed against the lab target {target}.",
        f"The assessment covered {len(phases)} engagement phases and identified "
        f"{len(all_findings)} reported finding(s), of which {linked_count} are linked to "
        "recorded tool evidence. Severity distribution: "
        + (", ".join(f"{count} {level}" for level, count in counts.items() if count) or "none") + ".",
        f"The engagement reached the following access level: {reached}.",
    ]
    for sentence in summary_sentences:
        document.add_paragraph(sentence)
    document.add_paragraph(
        "Evidence-linked findings reference matching recorded tool output. This "
        "supports traceability; technical validation and severity still require "
        "review. Observations without matching evidence are explicitly marked unverified.")
    document.add_paragraph(f"Engagement outcome: {engagement.get('status', 'not recorded')}.")

    # ---- 2. Scope and Methodology ----
    document.add_heading("2. Scope and Methodology", level=1)
    document.add_paragraph(
        "The assessment followed a phased methodology aligned with industry "
        "practice: reconnaissance, service enumeration, web application analysis, "
        "vulnerability verification, exploitation, and privilege escalation.")
    document.add_paragraph(f"In-scope target: {target}. Additional assets were not implicitly in scope.")
    document.add_paragraph("Limitations and incomplete coverage:")
    limits = engagement.get("limitations", [])
    for limitation in limits or ["No additional limitations were recorded. This is not a guarantee of complete coverage."]:
        document.add_paragraph(str(limitation))
    method = document.add_table(rows=1 + len(phases), cols=4)
    method.style = "Table Grid"
    _no_table_borders(method)
    headers = ("Phase", "Description", "Duration", "Result")
    for index, header in enumerate(headers):
        _cell_text(method.rows[0].cells[index], header, bold=True)
        _shade_cell(method.rows[0].cells[index], "EDEDED")
    for row, phase in enumerate(phases, start=1):
        duration = phase.get("elapsed", 0)
        text = f"{int(duration) // 60}m {int(duration) % 60:02d}s" if duration >= 60 else f"{duration:.1f}s"
        status = str(phase.get("status", "partial")).upper()
        _cell_text(method.rows[row].cells[0], PHASE_NAMES.get(phase.get("phase", ""), phase.get("phase", "-")))
        _cell_text(method.rows[row].cells[1], phase.get("label", "-"))
        _cell_text(method.rows[row].cells[2], text)
        _cell_text(method.rows[row].cells[3], status)

    # ---- 3. Findings ----
    document.add_heading("3. Findings and Recommendations", level=1)
    if all_findings:
        overview = document.add_table(rows=1 + len(all_findings), cols=4)
        _no_table_borders(overview)
        for index, header in enumerate(("#", "Finding", "Severity", "Category")):
            _cell_text(overview.rows[0].cells[index], header, bold=True)
            _shade_cell(overview.rows[0].cells[index], "EDEDED")
        ordered = sorted(all_findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["title"]))
        for row, finding in enumerate(ordered, start=1):
            cells = overview.rows[row].cells
            _cell_text(cells[0], str(row))
            _cell_text(cells[1], finding["title"])
            _cell_text(cells[2], finding["severity"].upper(), bold=True)
            _cell_text(cells[3], finding["category"])
        document.add_paragraph()
        for row, finding in enumerate(ordered, start=1):
            document.add_heading(f"3.{row} {finding['title']}", level=2)
            detail = document.add_table(rows=9, cols=2)
            _no_table_borders(detail)
            pairs = (("Severity", finding["severity"].upper()),
                     ("Category", finding["category"]),
                     ("Evidence", finding["evidence"] or "Not recorded"),
                     ("Impact", finding["impact"] or "Not recorded"),
                     ("Remediation", finding["remediation"] or "Not recorded"),
                     ("Affected asset", finding.get("asset") or target),
                     ("Validation", finding["validation"]),
                     ("Evidence references", ", ".join(finding.get("tool_ids", [])) or "No matching output"),
                     ("Reproduction", finding.get("reproduction") or "Not recorded"))
            for index, (key, value) in enumerate(pairs):
                _cell_text(detail.rows[index].cells[0], key, bold=True)
                _cell_text(detail.rows[index].cells[1], value)
            document.add_paragraph()
    else:
        document.add_paragraph(
            "No vulnerability findings were recorded during this engagement. "
            "This does not guarantee the absence of vulnerabilities.")

    # ---- 4. Tool Activity Log ----
    document.add_heading("4. Tool Activity Log", level=1)
    document.add_paragraph(
        "The table below lists each tool executed during the engagement, its "
        "phase, and the observed outcome. Complete raw outputs are preserved in "
        "the engagement JSON files in the results directory.")
    tools = engagement.get("tools", [])
    if tools:
        log = document.add_table(rows=1 + len(tools), cols=4)
        _no_table_borders(log)
        for index, header in enumerate(("#", "Phase", "Tool", "Outcome")):
            _cell_text(log.rows[0].cells[index], header, bold=True)
            _shade_cell(log.rows[0].cells[index], "EDEDED")
        for row, tool in enumerate(tools, start=1):
            cells = log.rows[row].cells
            _cell_text(cells[0], str(tool.get("id", row)))
            _cell_text(cells[1], tool.get("phase", "-"))
            _cell_text(cells[2], tool.get("name", "tool"))
            from cyber.console import background_started, display_tool
            visible = display_tool(tool)
            outcome = "background started" if background_started(tool.get("output", "")) else (
                "failed" if tool.get("error") or (visible and visible.get("error")) else "returned")
            lines = str(tool.get("output", "")).splitlines()
            outcome += f" ({len(lines)} lines)" if lines else ""
            _cell_text(cells[3], outcome)
    else:
        document.add_paragraph("No tool activity was recorded.")

    # ---- 5. Evidence Screenshots ----
    document.add_heading("5. Evidence", level=1)
    document.add_paragraph(
        "The following images are output captures rendered from recorded tool "
        "results. They are not screenshots of a live desktop or browser. Source "
        "outputs and evidence identifiers are preserved in the engagement record.")
    screenshots = engagement.get("screenshots", [])
    if screenshots:
        for shot in screenshots:
            document.add_heading(shot.get("title", "Evidence"), level=2)
            path = Path(shot.get("path", ""))
            if path.is_file():
                from PIL import Image
                with Image.open(path) as capture:
                    image_width, image_height = capture.size
                # Both dimensions fit on one page; never clip a tall evidence image.
                image_inches = min(6.2, 7.5 * image_width / max(1, image_height))
                document.add_picture(str(path), width=Inches(image_inches))
            else:
                document.add_paragraph(f"[Evidence file missing: {path}]")
    else:
        document.add_paragraph("No evidence captures were recorded.")

    # ---- 6. Conclusion ----
    document.add_heading("6. Conclusion", level=1)
    document.add_paragraph(
        f"The engagement progressed through {len(phases)} phase(s) and reached: "
        f"{reached}. Remediation of the identified findings, ordered by severity, "
        "is recommended. Retesting after remediation is advised.")
    flags = engagement.get("flags", [])
    if flags:
        document.add_paragraph("Observed lab flags:")
        for flag in flags:
            document.add_paragraph(flag, style="List Bullet")

    document.add_heading("Appendix A. Recorded Tool Results", level=1)
    for index, tool in enumerate(tools, 1):
        document.add_heading(f"{tool.get('id', index)}. {tool.get('phase', '')} / {tool.get('name', 'tool')}", level=2)
        if tool.get("command"):
            document.add_paragraph("Invocation:")
            document.add_paragraph(str(tool["command"])[:4000])
        visible = display_tool(tool)
        output = visible["output"] if visible else (
            "Background execution acknowledgement; see the subsequent background result."
            if background_started(tool.get("output", "")) else tool.get("output", ""))
        document.add_paragraph("Observed output:")
        excerpt = clean(output)[:6000]
        for line in wrap_rows(excerpt, 95):
            paragraph = document.add_paragraph()
            run = paragraph.add_run(line)
            run.font.name = "Consolas"
            run.font.size = Pt(8)
        if len(output) > len(excerpt):
            document.add_paragraph("Excerpt truncated. The full captured output is available in the engagement JSON record.")
    private_dir(destination.parent)
    document.save(destination)
    destination.chmod(0o600)
    return destination
