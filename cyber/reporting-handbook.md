# Cyber-Jcode: professional assessment and Word reporting handbook

Version 1.1. Mandatory reading before authoring full-pentest findings or a report.
All report prose must be English. This handbook applies to the user's authorized
lab assessment and its evidence; it does not authorize additional targets.

ABSOLUTE SCREENSHOT RULE — EVERY MODEL, EVERY PHASE:
NEVER read, view, attach, decode, OCR or visually inspect screenshot/image files.
This includes the screenshots inside a DOCX or rendered report PDF. Never call
read on a PNG/JPEG, image-viewing/computer tools, or request inline image output.
Never retry a blocked image read. Continue the same assessment using HTTP/DOM
text, command output and the capture helper's JSON metadata. A failed visual
operation must not cause restarting the assessment or discarding the session.
The application embeds screenshot files into Word without sending them to you.
Human/application document rendering review is separate from your model work.

## 1. Understand the production pipeline

Writing good prose and creating a good Word file are separate jobs. There is no
magic Word capability hidden inside a language model. A reliable document is
produced through explicit operations: inspect the evidence, author structured
content, apply a reusable template with python-docx, handle Word's OOXML layout,
render the result with Word or LibreOffice, inspect the pages, and correct defects.

Cyber-Jcode already provides this pipeline. You supply structured finding data;
the application fills `cyber/templates/enterprise-pentest.docx`. Its layout is
implemented in `cyber/report_layout.py`; its content renderer is
`cyber/docx_report.py`. Do not improvise a different template or overwrite the
master template. Create reports from a fresh copy. Never paste Python source,
tool protocol envelopes, internal reasoning, or this handbook into the report.

The terminal's short final findings are NOT the report. Keep the terminal concise,
but give the structured report fields enough detail to reproduce and fix the issue.
The old 300-character restriction on every report field is no longer appropriate.

## 2. The report's reader and purpose

The executive reader needs a defensible statement of business exposure and the
next decisions. The technical owner needs a precise affected asset, prerequisites,
reproduction steps, evidence, remediation, and a retest procedure. A reviewer needs
to trace every material assertion to a recorded action. Serve all three readers.

Use a calm, factual voice. Prefer “The endpoint returned device configuration
without authentication” to “We discovered an incredibly dangerous vulnerability.”
Avoid “comprehensive,” “robust,” “seamless,” and “successfully” unless the evidence
and scope justify the word. Do not repeat generic security slogans in every finding.
Do not describe a partial run as a complete assessment. Do not equate discovering
a flag with covering the attack surface. A report is a record, not a victory story.

## 3. Establish the document control and scope first

Record the target, approved scope, assessment period, time zone, report identifier,
version, recipient when supplied, and status. Use UTC consistently for machine
timestamps; label another time zone explicitly if the user requests it. Do not
invent a client company, assessor name, approval date, or retest date.

Separate complete, partial, blocked, skipped, and not tested. An attempted scan is
not a completed test. List phases not performed. State why execution ended when
the reason is recorded. Model/API failure is a coverage limitation, not evidence
that the target is secure. A failed scan may reflect connectivity, privileges,
firewall behavior, tool incompatibility, or a bad command; identify the observed
condition instead of guessing.

An out-of-scope hostname found in a response is a discovery, not permission to
scan it. Keep scope statements tied to the lab target. A root command on the
local Kali machine does not prove root access on the target. Privilege claims
must identify the target and cite output from the target context.

## 4. Required report structure

1. Cover and document control: title, target, period, status, classification.
2. Executive summary: observed exposure, evidenced access, priority actions,
   and incomplete coverage. Keep it understandable without raw shell commands.
3. Scope and methodology: assets, phases performed, limitations, relevant
   assumptions, and assessment conditions.
4. Findings: concise overview followed by complete individual finding records.
5. Tool activity log: every recorded invocation, phase, result and evidence ID.
6. Evidence: relevant authentic screenshots with captions; concise terminal
   excerpts remain valid evidence even when no screenshot was obtained.
7. Conclusion: verified outcome, remediation priorities, and retest conditions.
8. Appendix: command/output pairs with exact source references. Preserve the
   complete captured transcript separately instead of flooding the narrative.

Do not add decorative dashboards, rainbow severity cards, emoji, stock icons,
gradient covers, invented scores, or filler sections. “Simple” means restrained
typography, clear hierarchy, useful whitespace, and consistent tables. It does
not mean dumping all text into equal-width cells or thousands of paragraphs.

## 5. Write complete findings

For each finding, provide the following when supported by the record:

- Title: the security failure and its asset, rather than a tool name.
- Asset: host/IP, port, protocol and affected path or component.
- Category: authentication, authorization, disclosure, configuration, etc.
- Description: what control failed and under which conditions.
- Preconditions: authenticated/unauthenticated access, role, network position.
- Observation: precisely what the probe returned.
- Evidence excerpt: an exact, short quote from successful recorded tool output.
- Evidence references: the actual tool IDs; the document also gives them compact
  labels such as E001 without losing the original identifiers.
- Reproduction: ordered steps, inputs and the expected/observed behavior.
- Impact: the consequence demonstrated, followed by clearly bounded potential
  consequences where those have not been demonstrated.
- Severity and rationale: explain exposure, privileges, consequence and confidence.
- Remediation: a concrete corrective change, not only “follow best practices.”
- Retest criteria: what must change and what response will demonstrate the fix.
- References: authoritative URLs or identifiers when known; never fabricate them.

Do not force a report into one sentence per finding. Use paragraphs and short
ordered procedures. Keep raw output out of the description. A finding's prose
must stand alone even if the screenshot is not displayed.

## 6. Validation and severity discipline

A service version is a lead, not a confirmed vulnerability. An open management
port is an exposed service, not automatically a critical finding. A permissive
CORS header alone does not prove authenticated cross-origin data theft. A string
that looks like a password does not prove it authenticates to Windows. A redirect
alone does not prove the resulting session has administrative privileges.

Use the smallest repeatable proof that establishes the reported consequence.
Differentiate observation, evidence-linked finding, and unverified hypothesis.
An exact excerpt matching a tool result establishes traceability; it is not by
itself a guarantee that the security interpretation or severity is correct.

Critical requires an exceptional, credible consequence and prerequisites that
justify it. High requires a substantial demonstrated or well-supported exposure.
Medium and low still need an explanation. Informational observations may be
useful without being exploitable. Do not increase severity because a scanner's
headline is alarming, the lab has a flag, or the title sounds severe.

Only include a CVSS score when you provide a valid vector, version and rationale.
Do not invent a score, a CVE, a CWE or a vendor advisory. If scoring was not
performed, leave it unscored and explain the qualitative rationale. Avoid counting
the same root cause repeatedly across phases; consolidate evidence under one
finding while preserving its source references.

## 7. Evidence integrity and confidentiality

Keep commands, timestamps, exit outcomes, target context and source tool IDs.
Preserve the complete recorded transcript in the private engagement JSON and
text file. Never modify source evidence to make it match a finding. Quoting a
small exact excerpt is preferable to paraphrasing it as if it were raw evidence.

Use short document labels E001, E002, etc. A mapping table ties these labels to
the original tool IDs and phases. Use these labels in the findings, screenshot
captions, log and appendix. For a combined observation, cite all required records.

Keep secrets out of filenames. The report and evidence are confidential lab
artifacts, not source code to publish to GitHub. Prefer a masked credential in
ordinary narrative; preserve the original in the restricted evidence record
when needed for reproducibility. Mark any redaction explicitly. Do not alter a
lab flag when the user requested its exact value. Do not expose API keys.

## 8. Authentic screenshots: capture, do not draw

An image created by Pillow from shell text is a RENDERED TRANSCRIPT, not a real
terminal screenshot. It may be labeled as such, but never call it a browser or
desktop capture. Do not make an image of invented output. Do not use generated
illustrations as assessment evidence. File existence alone does not establish
the authenticity or security meaning of a screenshot.

For an actual browser screenshot, use the provided capture utility. It runs a
real Chromium browser, captures its viewport and prints text metadata:

```bash
python3 /path/to/cyber-jcode/cyber/capture.py \
  --url http://LAB_TARGET/ \
  --output /path/to/lab/evidence/web-home-20261113T120000Z.png
```

Replace paths and URL with the authorized lab context. Discover the installation
path from the REPORT REFERENCES in your prompt. The output filename must be new.
If Chromium is missing, the Kali package is `sudo apt install chromium`; report
the missing dependency instead of claiming a screenshot was taken. The helper
uses a temporary browser profile and emits the real file path, SHA-256, capture
time, dimensions and method. A browser error page can also produce an image:
confirm the endpoint with HTTP/DOM evidence and caption the image honestly.

The equivalent direct Chromium invocation is:

```bash
chromium --headless --disable-gpu --hide-scrollbars \
  --window-size=1440,1000 --virtual-time-budget=5000 \
  --screenshot=/absolute/path/evidence/web-home.png http://LAB_TARGET/
```

Use the helper for report integration because its metadata is standardized.
Keep the browser sandbox enabled normally. The helper's `--no-sandbox` option
exists for an isolated browser environment whose sandbox cannot initialize;
do not treat it as a fix for any unrelated browser error.

For authenticated pages or multi-step browser interactions, Playwright is useful.
Use a virtual environment, install Playwright and its Chromium browser, and
capture the page after verifying the response. An example capture script is:

```python
from playwright.sync_api import sync_playwright
from pathlib import Path
import hashlib, json

output = Path("evidence/dashboard.png").resolve()
output.parent.mkdir(parents=True, exist_ok=True)
with sync_playwright() as runtime:
    browser = runtime.chromium.launch(headless=True)
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    # Load only a legitimately obtained lab storage_state if authentication
    # is required. Do not fabricate cookies or claim an unauthenticated view.
    page = context.new_page()
    response = page.goto("http://LAB_TARGET/", wait_until="domcontentloaded")
    print(json.dumps({"url": page.url, "status": response.status if response else None,
                      "title": page.title()}))
    page.screenshot(path=str(output), full_page=True)
    print(json.dumps({"path": str(output),
                      "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}))
    browser.close()
```

Playwright's image is an authentic capture, but the provided capture helper is
the supported automatic evidence route. Custom captures need their method,
artifact hash and actual successful tool record documented explicitly.

A real graphical terminal capture requires a graphical session. Examples:

```bash
# X11: select the actual terminal window; DISPLAY must point to its X server.
scrot --select /absolute/path/evidence/terminal-window.png
# GNOME graphical desktop:
gnome-screenshot --file=/absolute/path/evidence/desktop.png
# A compatible wlroots Wayland session:
grim /absolute/path/evidence/desktop.png
```

These commands do not work merely because a headless SSH/WSL shell exists.
If no appropriate display is available, preserve terminal output as text and
state that a graphical capture was not obtained. Never substitute a drawn
terminal image while describing it as a genuine desktop screenshot.

## 9. A text-only model can capture without seeing

The browser or desktop tool takes the image; the model does not need vision to
request that operation. The tool can save the PNG and return a path, HTTP status,
DOM text, dimensions and hash. The report renderer embeds the file separately.

For every model, DO NOT call image-viewing tools, attach
the PNG to the conversation, read it through an image-aware tool, or request an
inline screenshot response. Use bash with the capture helper so the model sees
only its JSON metadata. Use HTTP/DOM results to interpret the page. A non-vision
model cannot claim to have inspected visual details such as a button color or
screen layout. The old API error “This model does not support image inputs”
is a request-compatibility failure, not a bad API key.

Add supported screenshot records to your CYBER_FINDINGS block:

```json
{
  "screenshots": [{
    "title": "Management portal landing page",
    "path": "/absolute/path/evidence/web-home-20261113T120000Z.png",
    "kind": "browser_screenshot",
    "tool_ids": ["ACTUAL_SUCCESSFUL_CAPTURE_TOOL_ID"],
    "sha256": "EXACT_SHA256_PRINTED_BY_CAPTURE_HELPER",
    "url": "http://LAB_TARGET/",
    "captured_at": "2026-11-13T12:00:00+00:00",
    "caption": "Captured browser viewport. HTTP/DOM evidence is recorded in E012."
  }]
}
```

Do not copy these placeholders into a real finding. The application checks the
artifact against recorded capture metadata and hashes before accepting it.

## 10. Caption and place evidence

A good caption says what was captured, which target/page it concerns, why it
supports the nearby finding, and the source evidence reference. State when an
image is a browser viewport, a full-page capture, or a rendered transcript.
Do not caption an image “Proof of root” without target-context proof of root.

Keep screenshots readable at their final printed size. Fit both width and
height inside the usable page area and preserve the aspect ratio. Split an
extremely tall capture into documented sections or retain its original as an
attachment; do not shrink it until all text is unreadable. Cropping must not
remove context that changes the interpretation. Retain the original file and
state any crop/redaction. An image without a meaningful caption is not useful.

## 11. Word typography and page geometry

The supplied template uses A4, 20 mm horizontal margins, 19 mm vertical margins,
Arial 11 pt body text, restrained black/gray headings, and compact monospace
code. It has running headers and page-number fields. Reuse its named styles:
Normal, Title, Subtitle, Heading 1/2/3, Report Code, Report Caption, Report Small.

Style paragraphs instead of manually formatting every run. A heading must have
the appropriate heading style, not just bold text. This supports navigation and
consistent spacing. Set heading keep-with-next, body widow control, and measured
space-before/after. Do not insert dozens of empty paragraphs to move content to
another page. Use a page break or an intentional section break.

Avoid full justification for short technical text. Long URLs, paths, hashes and
tool IDs need deliberate wrapping; abbreviated display IDs can map to complete
values in an appendix. Use a readable code font. Do not rely on color alone for
severity. Do not use emoji as bullets. Use ordinary punctuation and list styles.

## 12. Word tables without broken layout

Allocate column widths according to content, not an equal-width default. A
finding title needs more space than its ID or severity. A two-column document
control table should give the value column most of the width. The sum of column
widths must not exceed page width minus margins. Set fixed table layout, the
table grid and each cell's width consistently.

Repeat header rows when a table spans pages. Allow long body rows to paginate;
do not put an entire multi-page finding in one unbreakable cell. Use prose for
long explanations and tables for parallel metadata. Use light-gray header
shading and thin borders. Keep cell text around 9-10 pt, with modest paragraph
spacing. A header cannot be identified by Python wrapper-object identity;
use its row index when applying bold formatting.

Relevant python-docx/OOXML operations include:

```python
from docx import Document
from docx.shared import Mm, Pt
from docx.oxml import OxmlElement

doc = Document("enterprise-pentest.docx")
doc.styles["Normal"].font.size = Pt(11)
doc.sections[0].left_margin = Mm(20)
table = doc.add_table(rows=1, cols=3)
table.autofit = False
header = OxmlElement("w:tblHeader")
table.rows[0]._tr.get_or_add_trPr().append(header)
```

`w:tblLayout`, `w:tblGrid`, `w:tcW`, `w:tblHeader`, `w:keepNext`,
`w:keepLines`, `w:widowControl` and `w:sectPr` are useful layout controls.
Use OOXML selectively; python-docx handles most operations. Do not corrupt the
ZIP package by concatenating XML strings or replacing arbitrary byte sequences.

## 13. Code and transcript layout

Preserve line breaks inside a monospace paragraph or a small code block. Do not
create a Normal-style paragraph for every console line: its paragraph spacing
can turn a short transcript into scores of pages. Split large blocks at useful
boundaries. Keep each code block short enough to fit on a page.

The report should show every recorded tool invocation with a useful excerpt,
but its main body should not reproduce megabytes of HTML, minified JavaScript,
background-task envelopes or repeated debug output. Preserve the full captured
data in the private JSON/text record. Mark excerpt truncation explicitly and
provide the corresponding source ID. Never let excerpting change the result.

## 14. Images, headers, footers and fields

Use `document.add_picture()` with an explicit size constrained to the content
rectangle. Preserve the image aspect ratio. Use the caption style below the
image. Distinguish the first-page header/footer from the running pages.

PAGE and NUMPAGES are Word fields, not manually typed numbers. A contents list
or TOC must match the real headings; update fields using Word/LibreOffice when
rendering. Do not promise that python-docx computes page numbers: pagination is
done by a layout engine. Avoid macros and external linked objects in a report.

## 15. Saving and report names

On this installation, user-facing reports belong in `Desktop/raport`. NEVER
copy generated reports directly into the Desktop root. The private working
copy and transcript remain under `~/.cyber-jcode`. The application discovers
the Desktop path; `CYBER_JCODE_REPORT_DIR` can explicitly select another folder
on a machine without a graphical Desktop.

Use filenames such as:

`Cyber-Jcode_Pentest_10.129.175.137_2026-11-13_120000_UTC.docx`

Include the target, report type and timestamp. Use a revision suffix for a
reworked report. Never overwrite an earlier report or the source evidence.
Never put passwords, tokens, flags, query strings, or raw URLs in filenames.
Name screenshots by asset/page and capture time, and keep them in a per-run
evidence folder. Never reuse `phase-1.png` across engagements.

## 16. Rendering and quality assurance

Saving a valid DOCX proves only that a package was written. Inspect it with
python-docx, render it to PDF using Word or LibreOffice, and inspect representative
pages: cover, executive summary, methodology table, a long finding, screenshots,
tool log and appendix. Check the document's final page for spills or blank pages.

Examples of validation operations:

```bash
python3 -c 'from docx import Document; d=Document("report.docx"); print(len(d.paragraphs), len(d.tables))'
libreoffice --headless --convert-to pdf --outdir preview report.docx
mutool draw -o preview/page-%03d.png -r 100 preview/report.pdf
```

LibreOffice needs its own temporary user profile when another instance is
running. Microsoft Word automation can update fields, repaginate and export a
PDF; open the document read-only for inspection and do not alter the user's
existing Word session. python-docx does not render a page and cannot prove
that a table fits. Do not claim visual review when only XML was inspected.

QA checklist:

- Are the target, dates, report status and classification consistent?
- Are unfinished phases named and access claims supported by target evidence?
- Does every substantive finding have source references and a justified severity?
- Are unverified observations clearly distinct from evidenced findings?
- Are remediation and retest steps specific enough for a technical owner?
- Are any placeholders, template instructions or model reasoning still visible?
- Do headings, page breaks, table widths and repeated headers work on the PDF?
- Are code excerpts readable and reasonably short without changing the evidence?
- Are screenshots authentic, correctly labeled, readable and captioned?
- Does every tool record appear in the log/appendix with a full-source reference?
- Are secrets handled appropriately and files saved inside the required folder?

## 17. The structured output contract

Always emit BOTH final blocks: CYBER_RESULT for the terminal and CYBER_FINDINGS
for the report. Do not replace CYBER_RESULT with another block. Do not put prose
around either block. Terminal findings stay short; report fields may be detailed.

CYBER_FINDINGS accepts findings, access, limitations and screenshots. A finding
can contain title, severity, category, asset, description, prerequisites,
evidence, evidence_excerpt, tool_ids, reproduction_steps, impact,
severity_rationale, remediation, retest, and references. Use exact tool IDs and
an exact evidence excerpt. Use an empty findings array when no supported finding
was established; preserve useful observations in the phase's compact results.

An access record must state the target, level and exact identity output from the
target context. `uid=0(root)` printed by a local helper is not sufficient. Record
why a test could not be completed in limitations. A screenshot record must point
to an actual captured artifact and successful capture output, not a fabricated
file path. The renderer controls layout; you control the factual content.

## 18. Final professional review

Read your own report fields as a skeptical technical reviewer. Remove unsupported
claims, duplicated findings, generic filler, unexplained risk labels and ambiguous
references. Ask whether someone with the same authorized access can reproduce
the result and verify the fix without guessing. If the record is insufficient,
say what is missing. Do not conceal model/API failures or incomplete coverage.

The finished report should feel like careful professional work: organized,
legible, restrained and accountable to evidence. It must remain useful when
printed in black and white and understood by a reader who never saw the console.
