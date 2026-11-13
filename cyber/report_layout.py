"""Reusable Word template and report destination rules."""
from __future__ import annotations

from pathlib import Path
import os
import re
import shutil
import subprocess
from urllib.parse import urlsplit

TEMPLATE = Path(__file__).resolve().parent / "templates/enterprise-pentest.docx"


def field(paragraph, instruction: str):
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    element = OxmlElement("w:fldSimple")
    element.set(qn("w:instr"), instruction)
    paragraph._p.append(element)


def configure_document(document):
    from docx.enum.style import WD_STYLE_TYPE
    from docx.shared import Mm, Pt, RGBColor
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    # Themes in the stock Word template can override explicit fonts and colors.
    for fonts in document.styles.element.iter(qn("w:rFonts")):
        for key in ("asciiTheme", "hAnsiTheme", "eastAsiaTheme", "cstheme"):
            fonts.attrib.pop(qn("w:" + key), None)
    for color in document.styles.element.iter(qn("w:color")):
        for key in ("themeColor", "themeTint", "themeShade"):
            color.attrib.pop(qn("w:" + key), None)
    defaults = document.styles.element.find(qn("w:docDefaults"))
    if defaults is not None:
        for fonts in defaults.iter(qn("w:rFonts")):
            for key in ("ascii", "hAnsi", "eastAsia", "cs"):
                fonts.set(qn("w:" + key), "Arial")
    section = document.sections[0]
    section.page_width, section.page_height = Mm(210), Mm(297)
    section.left_margin = section.right_margin = Mm(20)
    section.top_margin = section.bottom_margin = Mm(19)
    section.header_distance = section.footer_distance = Mm(9)
    normal = document.styles["Normal"]
    normal.font.name, normal.font.size = "Arial", Pt(11)
    normal.font.color.rgb = RGBColor.from_string("202020")
    normal.paragraph_format.line_spacing = 1.12
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.widow_control = True
    for name, size in (("Title", 28), ("Subtitle", 14), ("Heading 1", 15),
                       ("Heading 2", 12), ("Heading 3", 11)):
        style = document.styles[name]
        style.font.name, style.font.size = "Arial", Pt(size)
        style.font.color.rgb = RGBColor.from_string("202020")
        style.font.bold = name != "Subtitle"
        style.font.italic = False
        paragraph_props = style.element.find(qn("w:pPr"))
        if paragraph_props is not None:
            for tag in ("pBdr", "numPr"):
                unwanted = paragraph_props.find(qn("w:" + tag))
                if unwanted is not None:
                    paragraph_props.remove(unwanted)
        style.paragraph_format.space_before = Pt(14 if name.startswith("Heading") else 8)
        style.paragraph_format.space_after = Pt(6)
        style.paragraph_format.keep_with_next = True
    for name in ("Report Code", "Report Caption", "Report Small"):
        if name not in document.styles:
            document.styles.add_style(name, WD_STYLE_TYPE.PARAGRAPH)
        style = document.styles[name]
        style.base_style = normal
        style.font.size = Pt(9)
        style.paragraph_format.space_after = Pt(3)
        style.paragraph_format.space_before = Pt(0)
        style.paragraph_format.line_spacing = 1
    code = document.styles["Report Code"]
    code.font.name = "Courier New"
    code.paragraph_format.space_after = Pt(5)
    code.paragraph_format.keep_together = True
    document.styles["Report Caption"].font.italic = True
    document.styles["Report Caption"].font.color.rgb = RGBColor.from_string("555555")
    section.different_first_page_header_footer = True
    header = section.header.paragraphs[0]
    header.style = document.styles["Report Small"]
    header.text = "PENETRATION TEST REPORT"
    footer = section.footer.paragraphs[0]
    footer.style = document.styles["Report Small"]
    footer.text = "CONFIDENTIAL  |  Page "
    field(footer, "PAGE")
    footer.add_run(" of ")
    field(footer, "NUMPAGES")
    settings = document.settings.element
    if settings.find(qn("w:updateFields")) is None:
        update = OxmlElement("w:updateFields")
        update.set(qn("w:val"), "true")
        settings.append(update)


def new_document():
    from docx import Document
    if not TEMPLATE.is_file():
        raise ValueError("Report template missing: cyber/templates/enterprise-pentest.docx")
    document = Document(str(TEMPLATE))
    for element in list(document.element.body):
        if element.tag.endswith("}sectPr"):
            continue
        document.element.body.remove(element)
    configure_document(document)
    return document


def table(document, headers: tuple[str, ...], rows, ratios=None):
    """Fixed widths, repeated header, modest borders; body rows may paginate."""
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    from docx.shared import Pt
    result = document.add_table(rows=1, cols=len(headers))
    result.autofit = False
    result.style = "Table Grid"
    section = document.sections[0]
    usable = section.page_width - section.left_margin - section.right_margin
    ratios = ratios or [1] * len(headers)
    widths = [int(usable * ratio / sum(ratios)) for ratio in ratios]
    for column, width in zip(result.columns, widths):
        column.width = width
    header = result.rows[0]
    repeat = OxmlElement("w:tblHeader")
    header._tr.get_or_add_trPr().append(repeat)
    for index, value in enumerate(headers):
        header.cells[index].text = str(value)
        shade = OxmlElement("w:shd")
        shade.set(qn("w:fill"), "EFEFEF")
        header.cells[index]._tc.get_or_add_tcPr().append(shade)
    for values in rows:
        cells = result.add_row().cells
        for cell, value in zip(cells, values):
            cell.text = str(value if value is not None else "")
    for row_index, row in enumerate(result.rows):
        for index, cell in enumerate(row.cells):
            cell.width = widths[index]
            for paragraph in cell.paragraphs:
                paragraph.paragraph_format.space_after = Pt(3)
                paragraph.paragraph_format.keep_with_next = row_index == 0
                for run in paragraph.runs:
                    run.font.name = "Arial"
                    run.font.size = Pt(9)
                    run.bold = row_index == 0
    return result


def create_template(destination: Path = TEMPLATE) -> Path:
    from docx import Document
    document = Document()
    configure_document(document)
    document.add_paragraph("PENETRATION TEST REPORT", "Title")
    document.add_paragraph("{{CLIENT_OR_LAB}}  |  {{TARGET}}", "Subtitle")
    document.add_paragraph("CONFIDENTIAL", "Report Small")
    table(document, ("Document control", "Value"), (
        ("Assessment period", "{{START_DATE}} - {{END_DATE}} UTC"),
        ("Report identifier", "{{REPORT_ID}}"),
        ("Assessment status", "{{COMPLETE_OR_PARTIAL}}"),
        ("Prepared for", "{{REPORT_RECIPIENT}}"),
        ("Prepared by / version", "{{AUTHOR}} / {{VERSION}}")), (1, 3))
    document.add_page_break()
    for heading, guidance in (
        ("1. Executive Summary", "{{BUSINESS_IMPACT_AND_PRIORITY_ACTIONS}}"),
        ("2. Scope and Methodology", "{{AUTHORIZED_ASSETS_COVERAGE_AND_LIMITATIONS}}"),
        ("3. Findings and Recommendations", "{{FINDING_RECORDS_WITH_EVIDENCE_AND_RETEST_CRITERIA}}"),
        ("4. Tool Activity Log", "{{ONE_ROW_PER_RECORDED_INVOCATION}}"),
        ("5. Evidence", "{{REAL_SCREENSHOTS_AND_CAPTIONS_OR_EXPLICIT_CAPTURE_LIMITATION}}"),
        ("6. Conclusion", "{{VERIFIED_ACCESS_RESIDUAL_UNCERTAINTY_AND_NEXT_STEPS}}"),
        ("Appendix A. Recorded Tool Results", "{{CONCISE_COMMAND_OUTPUT_PAIRS_AND_SOURCE_REFERENCES}}")):
        document.add_heading(heading, 1)
        document.add_paragraph(guidance)
    destination.parent.mkdir(parents=True, exist_ok=True)
    document.save(destination)
    return destination


def desktop_report_folder() -> Path | None:
    """Always export inside Desktop/raport, or an explicit report directory."""
    override = os.environ.get("CYBER_JCODE_REPORT_DIR")
    if override:
        return Path(override).expanduser().resolve()
    powershell = shutil.which("powershell.exe")
    if powershell:
        try:
            result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-Command",
                                     "[Environment]::GetFolderPath('Desktop')"],
                                    capture_output=True, text=True, timeout=10)
            windows = result.stdout.strip()
            match = re.fullmatch(r"([A-Za-z]):\\(.+)", windows)
            if result.returncode == 0 and match:
                desktop = Path("/mnt") / match[1].lower() / Path(match[2].replace("\\", "/"))
                if desktop.is_dir():
                    return desktop / "raport"
        except (OSError, subprocess.TimeoutExpired):
            pass
    desktop = Path.home() / "Desktop"
    if desktop.is_dir():
        return desktop / "raport"
    # Existing installations may omit Windows interop binaries from PATH.
    original = Path("/mnt/c/Users/ASUS/Desktop")
    return original / "raport" if original.is_dir() else None


def report_filename(target: str, stamp: str, suffix: str = "") -> str:
    parsed = urlsplit(target if "://" in target else "//" + target)
    name = parsed.hostname or target or "unassigned"
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip(".-")[:64] or "unassigned"
    stamp = re.sub(r"[^0-9A-Za-z_-]", "", stamp)
    suffix = re.sub(r"[^0-9A-Za-z_-]", "", suffix)
    return f"Cyber-Jcode_Pentest_{name}_{stamp}{'_' + suffix if suffix else ''}.docx"


if __name__ == "__main__":
    print(create_template())
