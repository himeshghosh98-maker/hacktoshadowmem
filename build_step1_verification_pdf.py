"""
build_step1_verification_pdf.py
================================
Generates the verification PDF report:
"ShadowMem — Step 1 Closure Verification"
Auditing ERR-09 and the retirement of server.py.
"""

import os
import sys
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)
from reportlab.pdfgen import canvas

OUTPUT_PDF = "ShadowMem_Step1_Closure_Verification.pdf"
GENERATED_AT = datetime.now().strftime("%B %d, %Y - %H:%M")

PAGE_W, PAGE_H = letter
MARGIN = 0.55 * inch
USABLE_W = PAGE_W - (2 * MARGIN)

# Palette
PRIMARY = colors.HexColor("#0B3954")       # Navy
SECONDARY = colors.HexColor("#087E8B")     # Dark Cyan
DARK = colors.HexColor("#0F172A")          # Slate 900
TEXT_MUTED = colors.HexColor("#475569")    # Slate 600
LIGHT_BG = colors.HexColor("#F8FAFC")      # Slate 50
ALT_ROW = colors.HexColor("#F1F5F9")       # Slate 100
BORDER_COL = colors.HexColor("#CBD5E1")    # Slate 300

# Status Pill Colors
PASS_BG = colors.HexColor("#DCFCE7")
PASS_TXT = colors.HexColor("#166534")
FAIL_BG = colors.HexColor("#FEE2E2")
FAIL_TXT = colors.HexColor("#991B1B")
WARN_BG = colors.HexColor("#FEF3C7")
WARN_TXT = colors.HexColor("#92400E")

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        self.saveState()
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(TEXT_MUTED)

        # Header (Pages > 1)
        if self._pageNumber > 1:
            self.drawString(
                MARGIN,
                PAGE_H - 0.38 * inch,
                "SHADOWMEM — STEP 1 CLOSURE VERIFICATION",
            )
            self.drawRightString(
                PAGE_W - MARGIN,
                PAGE_H - 0.38 * inch,
                "ERR-09 & SERVER.PY RETIREMENT AUDIT",
            )
            self.setStrokeColor(BORDER_COL)
            self.setLineWidth(0.5)
            self.line(MARGIN, PAGE_H - 0.44 * inch, PAGE_W - MARGIN, PAGE_H - 0.44 * inch)

        # Footer (All pages)
        self.setFont("Helvetica", 7.5)
        self.setStrokeColor(BORDER_COL)
        self.setLineWidth(0.5)
        self.line(MARGIN, 0.45 * inch, PAGE_W - MARGIN, 0.45 * inch)

        self.drawString(
            MARGIN,
            0.32 * inch,
            f"SHADOWMEM DEFENSE LABS | Audit Timestamp: {GENERATED_AT}",
        )
        self.drawRightString(
            PAGE_W - MARGIN,
            0.32 * inch,
            f"Page {self._pageNumber} of {total_pages}",
        )
        self.restoreState()


STYLES = getSampleStyleSheet()

S_TITLE = ParagraphStyle(
    "DocTitle",
    parent=STYLES["Title"],
    fontName="Helvetica-Bold",
    fontSize=19,
    leading=23,
    textColor=PRIMARY,
    alignment=TA_LEFT,
    spaceAfter=3,
)

S_SUBTITLE = ParagraphStyle(
    "DocSub",
    parent=STYLES["Normal"],
    fontName="Helvetica-Bold",
    fontSize=9.5,
    leading=13,
    textColor=SECONDARY,
    spaceAfter=5,
)

S_META = ParagraphStyle(
    "DocMeta",
    parent=STYLES["Normal"],
    fontName="Helvetica",
    fontSize=8,
    leading=11,
    textColor=TEXT_MUTED,
    spaceAfter=8,
)

S_H1 = ParagraphStyle(
    "SectionH1",
    parent=STYLES["Heading1"],
    fontName="Helvetica-Bold",
    fontSize=11.5,
    leading=15,
    textColor=PRIMARY,
    spaceBefore=10,
    spaceAfter=4,
    keepWithNext=True,
)

S_H2 = ParagraphStyle(
    "SectionH2",
    parent=STYLES["Heading2"],
    fontName="Helvetica-Bold",
    fontSize=9,
    leading=12,
    textColor=SECONDARY,
    spaceBefore=7,
    spaceAfter=3,
    keepWithNext=True,
)

S_BODY = ParagraphStyle(
    "Body",
    parent=STYLES["Normal"],
    fontName="Helvetica",
    fontSize=8,
    leading=11.2,
    textColor=DARK,
    spaceAfter=3.5,
)

S_BULLET = ParagraphStyle(
    "Bullet",
    parent=S_BODY,
    leftIndent=10,
    bulletIndent=2,
    spaceAfter=2,
)

S_CALLOUT = ParagraphStyle(
    "Callout",
    parent=STYLES["Normal"],
    fontName="Helvetica-Oblique",
    fontSize=7.8,
    leading=10.8,
    textColor=PRIMARY,
)

S_TH = ParagraphStyle(
    "TableHeader",
    parent=STYLES["Normal"],
    fontName="Helvetica-Bold",
    fontSize=7.5,
    leading=9.5,
    textColor=colors.white,
    alignment=TA_LEFT,
)

S_TD = ParagraphStyle(
    "TableCell",
    parent=STYLES["Normal"],
    fontName="Helvetica",
    fontSize=7.2,
    leading=9.2,
    textColor=DARK,
)

S_TD_BOLD = ParagraphStyle(
    "TableCellBold",
    parent=STYLES["Normal"],
    fontName="Helvetica-Bold",
    fontSize=7.2,
    leading=9.2,
    textColor=DARK,
)

S_TD_CODE = ParagraphStyle(
    "TableCellCode",
    parent=STYLES["Normal"],
    fontName="Courier",
    fontSize=6.8,
    leading=8.5,
    textColor=DARK,
)


def callout_box(text, border_color=PRIMARY, bg_color=LIGHT_BG):
    p = Paragraph(text, S_CALLOUT)
    t = Table([[p]], colWidths=[USABLE_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg_color),
        ("BOX", (0, 0), (-1, -1), 0.75, border_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def generate_pdf():
    story = []

    # Title & Metadata
    story.append(Paragraph("ShadowMem — Step 1 Closure Verification", S_TITLE))
    story.append(Paragraph("Formal Audit Report: ERR-09 Resolution & server.py Retirement", S_SUBTITLE))
    story.append(Paragraph(
        f"<b>Target Codebase:</b> C:\\Users\\Himesh\\Desktop\\ShadowMem &nbsp;|&nbsp; "
        f"<b>Audit Date:</b> {GENERATED_AT} &nbsp;|&nbsp; "
        f"<b>Status:</b> Verification & Quality Assurance Audit",
        S_META
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=6))

    # Executive Verdict
    story.append(Paragraph("1. Executive Verdict: Is Step 1 100% Complete?", S_H1))
    story.append(Paragraph(
        "<b>VERDICT: 95% COMPLETE — CORE ENGINEERING PASS, DOCUMENTATION CONTRADICTIONS IDENTIFIED.</b><br/>"
        "The core technical migration is a complete success: <code>app.py</code> is established as the single authoritative server, "
        "real-time memory map streaming is live, scan diffing is operational, input validation is active on <code>/simulate/alert</code>, "
        "and <code>server.py</code> was safely isolated into <code>tests/mocks/server.py</code> with its port rebound to 8082 to eliminate runtime port collisions. "
        "However, Step 1 closure is <b>not yet 100% complete</b> because <b><code>make_pdf.py</code> was left half-updated and contains 6 internal contradictions</b> "
        "that still describe <code>server.py</code> as an active demo stack conflicting on port 8000.",
        S_BODY
    ))

    story.append(Spacer(1, 4))

    # Table of 7 Checks
    story.append(Paragraph("2. Full Pass/Fail Verification Matrix (7 Key Checks)", S_H1))

    table_data = [
        [
            Paragraph("Check # / Scope", S_TH),
            Paragraph("Status", S_TH),
            Paragraph("File & Line Reference", S_TH),
            Paragraph("Concrete Findings & Runtime Verification Evidence", S_TH),
        ],
        # Check 1
        [
            Paragraph("<b>Check 1</b><br/><code>tests/mocks/server.py</code> Port Rebinding", S_TD_BOLD),
            Paragraph("<font color='#166534'><b>PASS</b></font>", S_TD),
            Paragraph("<code>tests/mocks/server.py</code><br/>Lines 32 & 290", S_TD_CODE),
            Paragraph(
                "• Line 32: Updated to <code>uvicorn server:app --reload --port 8082</code>.<br/>"
                "• Line 290: Updated to <code>uvicorn.run(app, host='0.0.0.0', port=8082)</code>.<br/>"
                "• Line 29 added clarifying comment: <i>'(from tests/mocks/, standalone, for index.html testing only)'</i>.<br/>"
                "• Verified via git diff: <b>Zero other lines or logic altered</b>.",
                S_TD
            ),
        ],
        # Check 2
        [
            Paragraph("<b>Check 2</b><br/>PDF Scripts Text & Contradiction Check", S_TD_BOLD),
            Paragraph("<font color='#991B1B'><b>FAIL</b></font><br/>(Contradictions)", S_TD),
            Paragraph("<code>make_pdf.py</code><br/>Lines 222, 316, 326, 445, 465, 540, 559, 563<br/><code>make_summary_pdf.py</code><br/>Lines 114, 181", S_TD_CODE),
            Paragraph(
                "• <b><code>make_summary_pdf.py</code>: PASS.</b> Lines 114 and 181 correctly state WebSocket streaming is in <code>app.py</code> and <code>server.py</code> is a mock fixture.<br/>"
                "• <b><code>make_pdf.py</code>: FAIL (Half-Updated).</b> While Section 3.2 (L316) and fact row (L559) were updated, <b>Lines 222, 326-332, 445, 463-467, 540, and 563 directly contradict this</b>, asserting the two stacks are unmerged and still conflict on port 8000.",
                S_TD
            ),
        ],
        # Check 3
        [
            Paragraph("<b>Check 3</b><br/><code>app.py</code> Startup & Clean Imports", S_TD_BOLD),
            Paragraph("<font color='#166534'><b>PASS</b></font>", S_TD),
            Paragraph("<code>app.py</code><br/>Lines 1-60, 257-270", S_TD_CODE),
            Paragraph(
                "• Direct Python import executed cleanly: <code>from app import app</code>.<br/>"
                "• Zero import errors or lingering references from the <code>server.py</code> move.<br/>"
                "• Exactly 13 routes registered; programmatic route inspection confirmed <b>zero duplicate route registrations</b>.",
                S_TD
            ),
        ],
        # Check 4
        [
            Paragraph("<b>Check 4</b><br/><code>/api/scan</code> Real Data Execution", S_TD_BOLD),
            Paragraph("<font color='#166534'><b>PASS</b></font>", S_TD),
            Paragraph("<code>app.py</code><br/>Lines 272-343<br/><code>memoryscanner.py</code><br/>Lines 90-174", S_TD_CODE),
            Paragraph(
                "• <code>api_scan(BackgroundTasks())</code> executed across all active system processes.<br/>"
                "• Returned HTTP 200 with 133 real Windows processes inspected.<br/>"
                "• Summary verified: <code>total_scanned: 133, anomalies: 2, malicious: 2, clean: 94, jit: 37, posture: 'Threat Detected'</code>.",
                S_TD
            ),
        ],
        # Check 5
        [
            Paragraph("<b>Check 5</b><br/><code>/ws/alerts</code> Real Diffs & Memory Map", S_TD_BOLD),
            Paragraph("<font color='#166534'><b>PASS</b></font>", S_TD),
            Paragraph("<code>app.py</code><br/>Lines 887-985, 994-1065, 1068-1103", S_TD_CODE),
            Paragraph(
                "• Dead <code>sleep(60)</code> loop replaced with <code>_scan_ticker_loop()</code> and <code>receive_text()</code>.<br/>"
                "• <b>Live Diffs Verified:</b> Caught 0 changes on identical scan, 1 change on new threat, 1 change on Suspicious&rarr;Malicious escalation.<br/>"
                "• <b>Real Memory Map Verified:</b> <code>_build_memory_map()</code> extracted 4 real MEM_PRIVATE executable regions from PID 22704 (<code>Freebuff.exe</code>) with real 64-bit addresses (e.g. <code>0x000002159A1D9000</code>).",
                S_TD
            ),
        ],
        # Check 6
        [
            Paragraph("<b>Check 6</b><br/><code>/simulate/alert</code> Input Validation", S_TD_BOLD),
            Paragraph("<font color='#166534'><b>PASS</b></font>", S_TD),
            Paragraph("<code>app.py</code><br/>Lines 1112-1208", S_TD_CODE),
            Paragraph(
                "• Accepts typed <code>SimulateAlertRequest(scenario, severity)</code>.<br/>"
                "• Live tested: <code>cobalt_strike_...</code> returned T1620 frame; <code>process_hollowing</code> returned T1055.012 frame; <code>dll_injection</code> returned T1055.001 frame.<br/>"
                "• Rejections confirmed: Invalid scenario <code>fake_attack</code> &rarr; HTTP 400; Invalid severity <code>ultra</code> &rarr; HTTP 400; Missing severity &rarr; HTTP 422.",
                S_TD
            ),
        ],
        # Check 7
        [
            Paragraph("<b>Check 7</b><br/>Full Codebase Live Server Reference Scan", S_TD_BOLD),
            Paragraph("<font color='#92400E'><b>PARTIAL</b></font><br/>(Confined to PDF)", S_TD),
            Paragraph("<code>malware_simulator.py</code><br/><code>README_sandbox.md</code><br/><code>index.html</code><br/><code>launch_shadowmem.bat</code><br/><code>make_pdf.py</code>", S_TD_CODE),
            Paragraph(
                "• <b>Production & Test Code: PASS.</b> <code>launch_shadowmem.bat</code>, <code>malware_simulator.py</code> (L38), <code>README_sandbox.md</code> (L338), and <code>index.html</code> (L2) all cleanly updated.<br/>"
                "• <b>Documentation Scripts: FAIL.</b> <code>make_pdf.py</code> still contains 6 references describing <code>server.py</code> as a live demo server running on port 8000.",
                S_TD
            ),
        ],
    ]

    t_matrix = Table(table_data, colWidths=[1.3 * inch, 0.85 * inch, 1.85 * inch, 3.0 * inch])
    t_matrix.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ALT_ROW]),
    ]))
    story.append(t_matrix)
    story.append(Spacer(1, 6))

    # Detailed Analysis of Check 2 Contradictions
    story.append(Paragraph("3. Deep-Dive: Specific Contradictions in make_pdf.py", S_H1))
    story.append(Paragraph(
        "While freebuff AI updated lines 316 and 559 in <code>make_pdf.py</code>, it failed to update the rest of the file. "
        "The following exact lines in <code>make_pdf.py</code> directly contradict the retirement of <code>server.py</code>:",
        S_BODY
    ))

    contradiction_items = [
        "<b>Line 222 (Section 1):</b> <code>'There are two parallel stacks in the repo: a REAL stack ... and a DEMO stack (server.py + index.html ...). They are not yet merged - that is the single biggest architectural TODO (Section 6).'</code> &rarr; <i>Contradicts line 316 which states streaming lives in app.py.</i>",
        "<b>Lines 326–332 (Section 3.3):</b> <code>'3.3 Intended (not yet built) unified architecture ... merging them is the top structural TODO (Section 6, item A).'</code> &rarr; <i>Describes unified architecture as not yet built.</i>",
        "<b>Line 445 (Section 5 Inventory):</b> <code>['Synthetic streaming demo', 'server.py + index.html: WebSocket telemetry/alert/memory-map protocol...']</code> &rarr; <i>Lists server.py under active achieved demo modules.</i>",
        "<b>Lines 463–467 (Section 6 Backlog):</b> <code>['P0', 'B. Unify the two backends', 'app.py ... and server.py ... are separate apps that even conflict on port 8000. Merge: add /ws/alerts to app.py ... retire or clearly demote server.py to demo-only.']</code> &rarr; <i>Maintains unifying the backends as an open P0 backlog item.</i>",
        "<b>Line 540 (Quick-Run Table):</b> <code>['Mock demo stack', 'cd tests/mocks && python -m uvicorn server:app --port 8000...']</code> &rarr; <i>Directly instructs running server.py on port 8000 instead of 8082!</i>",
        "<b>Line 563 (Quick-Reference Fact Table):</b> <code>['Ports', 'Both stacks default 8000 - conflict to resolve during unification (6B)']</code> &rarr; <i>States that both stacks default to port 8000.</i>",
    ]
    for c in contradiction_items:
        story.append(Paragraph(f"• {c}", S_BULLET))

    story.append(Spacer(1, 6))

    # Actionable Rectification Checklist
    story.append(Paragraph("4. Actionable Rectification Steps to Reach 100% Closure", S_H1))
    story.append(Paragraph(
        "To bring Step 1 from 95% to 100% verified closure, the following edits in <code>make_pdf.py</code> are required:",
        S_BODY
    ))

    rect_items = [
        "<b>1. Update Section 1 (Line 222):</b> Reword to state that the demo WebSocket stack has been successfully unified into <code>app.py</code> and <code>server.py</code> has been retired to <code>tests/mocks/</code>.",
        "<b>2. Retire Section 3.3 (Lines 326–332):</b> Update heading to <i>'3.3 Completed unified architecture'</i> and confirm <code>app.py</code> now handles real scan diffing and memory maps.",
        "<b>3. Mark Backlog Item B Complete (Lines 463–467):</b> Move 'Unify the two backends' from the P0 Backlog into Section 5 (Achieved capabilities).",
        "<b>4. Fix Quick-Run Command (Line 540):</b> Change <code>--port 8000</code> to <code>--port 8082</code> to match the updated mock server binding.",
        "<b>5. Update Fact Table (Line 563):</b> Update ports entry to reflect <code>app.py = 8000 (primary) | tests/mocks/server.py = 8082 (test mock only)</code>.",
    ]
    for r in rect_items:
        story.append(Paragraph(r, S_BULLET))

    story.append(Spacer(1, 6))
    story.append(callout_box(
        "<b>Conclusion:</b> All technical code modifications for Step 1 (Win32 extraction, memory mapping, live ticker diffs, "
        "FastAPI routes, Pydantic simulation bodies, and port 8082 isolation) are verified and functioning flawlessly. "
        "Once the 6 documentation text strings in <code>make_pdf.py</code> are harmonized, Step 1 can be formally certified at 100% completion.",
        border_color=SECONDARY,
        bg_color=LIGHT_BG,
    ))

    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=letter,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=0.55 * inch,
        bottomMargin=0.55 * inch,
    )

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Successfully generated: {OUTPUT_PDF}")


if __name__ == "__main__":
    generate_pdf()
