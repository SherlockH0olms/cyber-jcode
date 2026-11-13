"""Evidence-led report content rendered into the enterprise Word template."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import re

from cyber.report_layout import new_document, table


def _text(document, value, label: str = ""):
    from cyber.console import clean
    value = clean(value or "").strip()
    if not value:
        value = "Not recorded."
    if label:
        paragraph = document.add_paragraph()
        paragraph.add_run(label + ": ").bold = True
        paragraph.add_run(value)
    else:
        for paragraph in re.split(r"\n\s*\n", value):
            document.add_paragraph(paragraph)


def _code(document, value: str, max_lines: int = 10, max_chars: int = 1500):
    from cyber.console import clean, wrap_rows
    original = clean(value or "").strip()
    rows = list(wrap_rows(original[:max_chars], 100))
    document.add_paragraph("\n".join(rows[:max_lines]) or "No output recorded.", "Report Code")
    if len(rows) > max_lines or len(original) > max_chars:
        document.add_paragraph("Excerpt shown; full captured text is in the accompanying transcript.",
                               "Report Caption")


def _time(value) -> str:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(
            timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return "Not recorded"


def _ordered_findings(engagement):
    from cyber.report import link_findings, SEVERITY_ORDER
    findings = link_findings(engagement.get("findings", []), engagement.get("tools", []))
    unique = {}
    for finding in findings:
        key = (finding.get("title", "").casefold(), finding.get("asset", "").casefold())
        if key not in unique:
            unique[key] = finding
        else:
            previous = unique[key]
            previous["tool_ids"] = list(dict.fromkeys(previous.get("tool_ids", []) + finding.get("tool_ids", [])))
            if finding.get("validation") == "evidence-linked":
                previous["validation"] = "evidence-linked"
    return sorted(unique.values(), key=lambda f: (SEVERITY_ORDER.get(f.get("severity"), 4), f.get("title", "")))


def render_report(engagement: dict, destination: Path) -> Path:
    from cyber.console import clean, private_dir, background_started, display_tool
    from cyber.report import PHASE_NAMES, capture_artifact_valid
    from docx.shared import Inches
    from PIL import Image
    document = new_document()
    target = str(engagement.get("target") or "Not recorded")
    phases = engagement.get("phases", [])
    tools = engagement.get("tools", [])
    findings = _ordered_findings(engagement)
    linked = [f for f in findings if f.get("validation") == "evidence-linked"]
    complete = len(phases) == len(PHASE_NAMES) and all(p.get("status") == "ok" for p in phases)
    status = engagement.get("status") or ("complete" if complete else "partial")
    reached = engagement.get("final_access") or "No verified target access recorded"
    evidence_ids = {}
    for index, tool in enumerate(tools, 1):
        evidence_ids.setdefault(str(tool.get("id", index)), f"E{index:03d}")
    document.core_properties.title = f"Penetration Test Report - {target}"
    document.core_properties.subject = "Authorized lab assessment and recorded evidence"
    document.core_properties.author = "Cyber-Jcode"
    document.sections[0].header.paragraphs[0].text = f"PENETRATION TEST REPORT  |  {target}"

    document.add_paragraph("PENETRATION\nTEST REPORT", "Title")
    document.add_paragraph(target, "Subtitle")
    document.add_paragraph("CONFIDENTIAL  |  AUTHORIZED LAB ASSESSMENT", "Report Small")
    table(document, ("Document control", "Assessment details"), (
        ("Assessment status", str(status).upper()),
        ("Assessment period", f"{_time(engagement.get('started'))} - {_time(engagement.get('finished'))}"),
        ("Report identifier", destination.stem),
        ("Prepared by / version", "Cyber-Jcode / " + str(engagement.get("report_version", "1.0"))),
        ("Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))), (1, 3))
    _text(document, "This document contains assessment evidence for the named lab target. "
          "Distribute it only to the intended recipient and retain the accompanying evidence record.")
    document.add_page_break()

    document.add_heading("1. Executive Summary", 1)
    _text(document, f"The assessment of {target} recorded {len(phases)} of seven methodology phases "
          f"and {len(tools)} tool invocations. Assessment status: {str(status).upper()}.")
    _text(document, f"The record contains {len(findings)} distinct findings or observations. "
          f"{len(linked)} have exact links to successful recorded tool output; "
          f"{len(findings) - len(linked)} require evidence review before being treated as confirmed findings.")
    _text(document, reached, "Verified access")
    if findings:
        priorities = [f.get("remediation", "") for f in linked[:3] if f.get("remediation")]
        _text(document, " ".join(priorities) if priorities else
              "Review the recorded observations and validate the missing evidence references before "
              "prioritizing corrective changes.", "Priority actions")
    if not complete:
        _text(document, "The assessment was not completed across all phases. The untested areas below "
              "remain outside the demonstrated coverage; no absence-of-vulnerability conclusion is supported.")

    document.add_heading("2. Scope and Methodology", 1)
    _text(document, target, "In-scope target")
    _text(document, "The recorded phases follow reconnaissance, enumeration, web analysis, vulnerability "
          "verification, initial access, privilege escalation and post-exploitation. Phase status records "
          "execution coverage; it does not by itself establish exploitability or access.")
    rows = []
    recorded = {p.get("phase") for p in phases}
    for phase in phases:
        duration = float(phase.get("elapsed") or 0)
        rows.append((PHASE_NAMES.get(phase.get("phase"), phase.get("label", "Unknown")),
                     f"{int(duration) // 60}m {int(duration) % 60:02d}s", str(phase.get("status", "partial")).upper()))
    for key, label in PHASE_NAMES.items():
        if key not in recorded:
            rows.append((label, "-", "NOT TESTED"))
    table(document, ("Assessment phase", "Duration", "Coverage"), rows, (5, 1, 1.5))
    document.add_heading("Coverage limitations", 2)
    limits = list(dict.fromkeys(str(v) for v in engagement.get("limitations", []) if v))
    if not complete:
        missing = [label for key, label in PHASE_NAMES.items() if key not in recorded]
        if missing:
            limits.append("Not performed: " + "; ".join(missing) + ".")
    for limitation in limits or ["No additional assessment conditions were recorded."]:
        _text(document, limitation)

    document.add_heading("3. Findings and Recommendations", 1)
    if findings:
        table(document, ("ID", "Finding / observation", "Severity", "Evidence status"),
              [(f"F{index:03d}", f.get("title", "Untitled"), f.get("severity", "info").upper(),
                "Linked" if f.get("validation") == "evidence-linked" else "Review required")
               for index, f in enumerate(findings, 1)], (0.7, 4.5, 1.1, 1.6))
        _text(document, "Evidence linkage is a traceability check. Severity and the technical "
              "interpretation still need to be supported by the described prerequisites and result.")
        for index, finding in enumerate(findings, 1):
            document.add_heading(f"F{index:03d}  {finding.get('title', 'Untitled finding')}", 2)
            table(document, ("Attribute", "Recorded value"), (
                ("Affected asset", finding.get("asset") or target),
                ("Severity / category", f"{finding.get('severity', 'info').upper()} / {finding.get('category', 'General')}"),
                ("Evidence status", finding.get("validation", "unverified")),
                ("Source references", ", ".join(evidence_ids.get(str(value), str(value))
                                                for value in finding.get("tool_ids", [])) or "No exact source link recorded")), (1.2, 4))
            _text(document, finding.get("description") or finding.get("evidence"), "Observation")
            if finding.get("prerequisites"):
                _text(document, finding["prerequisites"], "Prerequisites")
            _text(document, finding.get("impact"), "Impact")
            if finding.get("severity_rationale"):
                _text(document, finding["severity_rationale"], "Severity rationale")
            if finding.get("evidence_excerpt"):
                _text(document, "Exact recorded excerpt", "Evidence")
                _code(document, finding["evidence_excerpt"], max_lines=14)
            steps = finding.get("reproduction_steps") or []
            if steps:
                _text(document, "Reproduction procedure")
                for step in steps:
                    document.add_paragraph(clean(step), "List Number")
            else:
                _text(document, finding.get("reproduction") or "A complete reproduction procedure was not recorded.",
                      "Reproduction")
            _text(document, finding.get("remediation"), "Remediation")
            _text(document, finding.get("retest") or "Retest criteria were not recorded.", "Retest criteria")
            if finding.get("references"):
                _text(document, "\n".join(finding["references"]), "References")
    else:
        _text(document, "No structured vulnerability findings were recorded. Consult the coverage "
              "limitations and evidence; this is not a clean bill of health for the target.")

    document.add_heading("4. Tool Activity Log", 1)
    _text(document, "Every captured invocation is listed below. E-identifiers map to the original "
          "tool IDs in the appendix and the full accompanying transcript.")
    if tools:
        table(document, ("Evidence", "Phase", "Tool", "Observed outcome"),
              [(f"E{index:03d}", tool.get("phase", "-"), tool.get("name", "tool"),
                "Failed" if tool.get("error") else (
                    "Background started" if background_started(tool.get("output", "")) else "Output returned"))
               for index, tool in enumerate(tools, 1)], (1, 1.3, 1, 2))
    else:
        _text(document, "No tool activity was recorded.")

    document.add_heading("5. Evidence", 1)
    captures = [shot for shot in engagement.get("screenshots", [])
                if shot.get("kind") in ("browser_screenshot", "desktop_screenshot", "terminal_screenshot")
                and shot.get("validation") == "artifact-verified" and capture_artifact_valid(shot)]
    if not captures:
        _text(document, "No verified original screenshot artifact was recorded for this export. "
              "The report therefore relies on the recorded terminal evidence. Rendered transcript images "
              "are not presented as browser or desktop screenshots.")
    for index, shot in enumerate(captures, 1):
        image_path = Path(shot.get("path", ""))
        if not image_path.is_file():
            _text(document, f"Capture file unavailable: {image_path}")
            continue
        document.add_heading(shot.get("title", f"Capture {index}"), 2)
        with Image.open(image_path) as image:
            width, height = image.size
        document.add_picture(str(image_path), width=Inches(min(6.5, 7 * width / max(height, 1))))
        refs = ", ".join(evidence_ids.get(str(value), str(value)) for value in shot.get("tool_ids", []))
        document.add_paragraph(f"Figure {index}. {shot.get('caption') or shot.get('title', 'Browser viewport capture')}. "
                               f"Source: {refs or 'capture record'}. Captured: {_time(shot.get('captured_at'))}.",
                               "Report Caption")
        document.add_paragraph(f"SHA-256: {shot.get('sha256', 'Not recorded')}", "Report Small")

    document.add_heading("6. Conclusion", 1)
    _text(document, f"Recorded assessment status: {str(status).upper()}. {reached}.")
    _text(document, "Validate the outstanding observations, apply the evidenced corrective actions, "
          "and retest the affected controls. Complete the untested phases before making a broader "
          "statement about the target's security posture.")
    if engagement.get("flags"):
        _text(document, "Observed lab flags (retained as evidence, not a coverage measure):")
        for flag in engagement["flags"]:
            document.add_paragraph(str(flag), "Report Code")

    document.add_page_break()
    document.add_heading("Appendix A. Recorded Tool Results", 1)
    _text(document, "The following excerpts preserve each recorded invocation. Complete captured output "
          "is retained in the companion .transcript.txt and original engagement JSON. Display excerpts "
          "may be shorter than that record; background acknowledgements are identified explicitly.")
    transcript = []
    for index, tool in enumerate(tools, 1):
        identifier = str(tool.get("id", index))
        heading = f"E{index:03d}  |  {tool.get('phase', '-')} / {tool.get('name', 'tool')}"
        document.add_heading(heading, 2)
        document.add_paragraph("Original tool ID: " + identifier, "Report Small")
        command = clean(tool.get("command", ""))
        if command:
            _code(document, "$ " + command, max_lines=4, max_chars=1200)
        visible = display_tool(tool)
        output = visible["output"] if visible else (
            "Background execution acknowledgement; completion is a separate record."
            if background_started(tool.get("output", "")) else clean(tool.get("output", "")))
        _code(document, output, max_lines=8, max_chars=1200)
        transcript.append(f"{heading}\nOriginal tool ID: {identifier}\nCOMMAND:\n{command or '(not captured)'}\n"
                          f"RECORDED OUTPUT:\n{clean(tool.get('output', ''))}\n")
    private_dir(destination.parent)
    document.save(destination)
    destination.chmod(0o600)
    source = destination.with_suffix(".transcript.txt")
    source.write_text("\n\n".join(transcript), encoding="utf-8")
    source.chmod(0o600)
    return destination
