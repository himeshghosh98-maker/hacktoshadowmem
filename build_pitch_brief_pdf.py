"""
build_pitch_brief_pdf.py
========================
Builds ShadowMem_Hackathon_Defense_Brief.pdf from the judge-ready pitch brief.
Target: Crisp, 2-page executive format with professional styling and typography.
"""

import sys
import os
import re
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

# Reconfigure stdout for utf-8
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

OUTPUT_PDF = "ShadowMem_Hackathon_Defense_Brief.pdf"
GENERATED_AT = datetime.now().strftime("%B %d, %Y - %H:%M")

PAGE_W, PAGE_H = letter
MARGIN = 0.45 * inch
USABLE_W = PAGE_W - (2 * MARGIN)

# Palette
PRIMARY = colors.HexColor("#1A1A1A")       # Obsidian
ORANGE = colors.HexColor("#E8793C")        # Signature Accent
TEAL = colors.HexColor("#166534")          # Green / Clean
TEXT_MAIN = colors.HexColor("#1E293B")     # Slate 800
TEXT_MUTED = colors.HexColor("#475569")    # Slate 600
LIGHT_BG = colors.HexColor("#F8FAFC")      # Slate 50
CARD_BG = colors.HexColor("#FAF7F2")       # Soft Warm Tint
BORDER_COL = colors.HexColor("#CBD5E1")    # Slate 300


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
        self.setFont("Helvetica-Bold", 7)
        self.setFillColor(TEXT_MUTED)

        # Header (Pages > 1)
        if self._pageNumber > 1:
            self.drawString(
                MARGIN,
                PAGE_H - 0.32 * inch,
                "SHADOWMEM — HACKATHON ROUND 1 DEFENSE BRIEF",
            )
            self.drawRightString(
                PAGE_W - MARGIN,
                PAGE_H - 0.32 * inch,
                "EXECUTIVE & TECHNICAL EVALUATION SHEET",
            )
            self.setStrokeColor(BORDER_COL)
            self.setLineWidth(0.5)
            self.line(MARGIN, PAGE_H - 0.35 * inch, PAGE_W - MARGIN, PAGE_H - 0.35 * inch)

        # Footer (All pages)
        self.setFont("Helvetica", 7)
        self.drawString(
            MARGIN,
            0.30 * inch,
            f"Generated: {GENERATED_AT} | ShadowMem User-Mode Volatile Memory Forensics",
        )
        self.drawRightString(
            PAGE_W - MARGIN,
            0.30 * inch,
            f"Page {self._pageNumber} of {total_pages}",
        )
        self.setStrokeColor(BORDER_COL)
        self.setLineWidth(0.5)
        self.line(MARGIN, 0.38 * inch, PAGE_W - MARGIN, 0.38 * inch)
        self.restoreState()


def build_pdf():
    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=letter,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=0.45 * inch,
        bottomMargin=0.45 * inch,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=21,
        textColor=PRIMARY,
        spaceAfter=2,
    )
    subtitle_style = ParagraphStyle(
        "CoverSubTitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=ORANGE,
        spaceAfter=6,
    )
    h1_style = ParagraphStyle(
        "H1",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=13,
        textColor=PRIMARY,
        spaceBefore=7,
        spaceAfter=3,
        keepWithNext=True,
    )
    h2_style = ParagraphStyle(
        "H2",
        parent=styles["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=ORANGE,
        spaceBefore=4,
        spaceAfter=2,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        textColor=TEXT_MAIN,
        spaceAfter=2,
    )
    bullet_style = ParagraphStyle(
        "Bullet",
        parent=body_style,
        leftIndent=8,
        firstLineIndent=-6,
        spaceAfter=1.5,
    )
    pitch_style = ParagraphStyle(
        "PitchBox",
        parent=body_style,
        fontName="Helvetica-Oblique",
        fontSize=8,
        leading=11,
        textColor=TEXT_MAIN,
    )
    table_cell = ParagraphStyle(
        "TableCell",
        parent=body_style,
        fontSize=6.5,
        leading=8.5,
    )
    table_hdr = ParagraphStyle(
        "TableHdr",
        parent=body_style,
        fontName="Helvetica-Bold",
        fontSize=7,
        leading=9,
        textColor=colors.white,
    )

    story = []

    # Title & Subtitle Banner
    story.append(Paragraph("ShadowMem — Hackathon Round 1 Defense Brief", title_style))
    story.append(Paragraph("Verifiable Pitch Script, Live Demo Assets, Differentiation & Judge Q&A", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.2, color=ORANGE, spaceAfter=5))

    # SECTION 1: 30-Second Pitch Box
    story.append(Paragraph("1. THE 30-SECOND PITCH (Spoken Out Loud)", h1_style))
    p30 = Paragraph(
        '<i>"Traditional antivirus scans files sitting on your hard drive, but modern attacks live entirely inside memory without saving a single file to disk. '
        '<b>ShadowMem</b> is a lightweight, agentless volatile memory inspection tool for Windows. It uses standard user-mode Win32 calls to walk the private memory spaces of running processes, detects malicious executable allocations and unbacked threads, filters out harmless browser runtimes, and scores threats with a trained machine-learning model. If an attack is detected, an analyst can freeze the process in place with one click."</i>',
        pitch_style,
    )
    box30 = Table([[p30]], colWidths=[USABLE_W])
    box30.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
        ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#DCD6CE")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(box30)
    story.append(Spacer(1, 4))

    # SECTION 2: 90-Second Pitch
    story.append(Paragraph("2. THE 90-SECOND VERSION", h1_style))
    story.append(Paragraph("<b>a. Problem:</b> Attackers increasingly use <b>fileless malware and process injection</b> (reflective DLL injection, shellcode). Because execution lives in RAM and never touches disk, file-based antiviruses miss them entirely.", body_style))
    story.append(Paragraph("<b>b. Solution:</b> ShadowMem is an agentless, user-mode cyber defense tool that inspects the volatile RAM of active Windows processes and classifies in-memory threats using ML.", body_style))
    story.append(Paragraph("<b>c. How It Works (Pipeline):</b> Enumerates PIDs via <code>psutil</code> &rarr; opens handles via <code>OpenProcess</code> &rarr; traverses allocated pages with <code>VirtualQueryEx</code> &rarr; flags private executable regions (<code>MEM_COMMIT</code> + <code>MEM_PRIVATE</code>) and RW&rarr;RX protection flips &rarr; inspects thread entry points via <code>NtQueryInformationThread</code> &rarr; allowlists JIT runtimes (Chrome, Brave, Node.js) &rarr; scores via <code>HistGradientBoostingClassifier</code>.", body_style))
    story.append(Paragraph("<b>d. Live Demo Ready Now:</b> Live memory audit (~130 PIDs in 4-6s), process containment (freeze/resume threads via <code>SuspendThread</code> / <code>ResumeThread</code>), 2D polar radar scope, simulated WebSocket alert trigger (<code>/api/v1/simulate/alert</code>), CSV/PDF export.", body_style))
    story.append(Paragraph("<b>e. Innovation:</b> Non-destructive, zero-driver user-mode triage. Eliminates Blue Screen (BSOD) risks while automating JIT false-positive suppression.", body_style))
    story.append(Paragraph("<b>f. Tech Stack:</b> FastAPI (Python 3.14, ctypes Win32), Next.js 14 (React, TypeScript, Tailwind, Recharts), scikit-learn (HistGradientBoosting, 7 features), WebSockets.", body_style))
    story.append(Paragraph("<b>g. Roadmap (In Progress):</b> Containerized Docker sandbox for untrusted binaries and supply-chain dependency scanner are currently architectural scaffolding.", body_style))
    story.append(Spacer(1, 4))

    # SECTION 3: Comparison Table
    story.append(Paragraph("3. HOW SHADOWMEM IS DIFFERENT", h1_style))
    comp_data = [
        [
            Paragraph("<b>Capability</b>", table_hdr),
            Paragraph("<b>Traditional Antivirus</b>", table_hdr),
            Paragraph("<b>Enterprise EDR (CrowdStrike)</b>", table_hdr),
            Paragraph("<b>Memory Forensics (Volatility)</b>", table_hdr),
            Paragraph("<b>ShadowMem</b>", table_hdr),
        ],
        [
            Paragraph("<b>Primary Scope</b>", table_cell),
            Paragraph("Static files on disk", table_cell),
            Paragraph("System calls & event streams", table_cell),
            Paragraph("Offline post-mortem RAM dump files", table_cell),
            Paragraph("<b>Live volatile process RAM in user space</b>", table_cell),
        ],
        [
            Paragraph("<b>Driver Footprint</b>", table_cell),
            Paragraph("Kernel driver (Ring-0)", table_cell),
            Paragraph("Heavy kernel sensor (Ring-0)", table_cell),
            Paragraph("None (offline dump file)", table_cell),
            Paragraph("<b>Zero drivers (100% user-mode Win32)</b>", table_cell),
        ],
        [
            Paragraph("<b>Crash Risk (BSOD)</b>", table_cell),
            Paragraph("Medium", table_cell),
            Paragraph("High (kernel updates risk outages)", table_cell),
            Paragraph("None", table_cell),
            Paragraph("<b>Zero (cannot crash OS kernel)</b>", table_cell),
        ],
        [
            Paragraph("<b>Triage Speed</b>", table_cell),
            Paragraph("Minutes (disk bound)", table_cell),
            Paragraph("Continuous telemetry stream", table_cell),
            Paragraph("Hours (analyzing multi-GB dumps)", table_cell),
            Paragraph("<b>Seconds (~4–6s full memory sweep)</b>", table_cell),
        ],
        [
            Paragraph("<b>Containment</b>", table_cell),
            Paragraph("Quarantines file on disk", table_cell),
            Paragraph("Network isolation / process kill", table_cell),
            Paragraph("Read-only analysis (no response)", table_cell),
            Paragraph("<b>User-mode thread suspend (freezes RAM)</b>", table_cell),
        ],
    ]
    comp_table = Table(comp_data, colWidths=[1.1 * inch, 1.4 * inch, 1.6 * inch, 1.5 * inch, 1.6 * inch])
    comp_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ("PADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(comp_table)
    story.append(Spacer(1, 4))

    # SECTION 4: Relevance to Real-World Attacks
    story.append(Paragraph("4. RELEVANCE TO RECENT ATTACKS", h1_style))
    story.append(Paragraph("• <b>Reflective DLL Injection (Cobalt Strike, Ransomware)</b>: Payloads inject directly into memory pages marked RWX without touching disk. ShadowMem identifies these unbacked allocations immediately.", bullet_style))
    story.append(Paragraph("• <b>Living-off-the-Land (LOLBins)</b>: Attackers hollow or inject into signed Windows processes (<code>svchost.exe</code>, <code>explorer.exe</code>). Disk scanners see a valid signature; ShadowMem spots unbacked execution threads.", bullet_style))
    story.append(Paragraph("• <b>Memory Protection Flips (VirtualProtect Abuse)</b>: Attackers bypass DEP by allocating memory as Read-Write and flipping it to Executable right before execution. ShadowMem explicitly tracks VAD protection anomalies.", bullet_style))
    story.append(Spacer(1, 4))

    # SECTION 5: Honest Limitations
    story.append(Paragraph("5. HONEST LIMITATIONS & READY ANSWERS", h1_style))
    lim_data = [
        [Paragraph("<b>Weak Spot / Question</b>", table_hdr), Paragraph("<b>Your Confident, Honest Answer</b>", table_hdr)],
        [
            Paragraph("<b>User-Mode Only (No Kernel Hooking)</b>", table_cell),
            Paragraph('<i>"ShadowMem runs strictly in user mode to guarantee non-crashing operational safety and rapid deployment. It leaves kernel pool analysis to specialized EDR sensors."</i>', table_cell),
        ],
        [
            Paragraph("<b>Protected Processes Light (PPL Blindspot)</b>", table_cell),
            Paragraph('<i>"Processes like Windows Defender (MsMpEng.exe) enforce kernel protections that return Access Denied to user-mode handles. ShadowMem safely logs and skips them."</i>', table_cell),
        ],
        [
            Paragraph("<b>Sandbox & Supply Chain Incomplete</b>", table_cell),
            Paragraph('<i>"Those two modules are currently architectural scaffolding on our roadmap. Our working core today is volatile memory forensics and live process containment."</i>', table_cell),
        ],
        [
            Paragraph("<b>Unauthenticated Local Endpoints</b>", table_cell),
            Paragraph('<i>"The current REST/WebSocket APIs run unauthenticated for fast hackathon demo evaluation. In enterprise deployment, they would be secured behind mTLS and OAuth2."</i>', table_cell),
        ],
    ]
    lim_table = Table(lim_data, colWidths=[2.2 * inch, 5.0 * inch])
    lim_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
        ("PADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(lim_table)
    story.append(Spacer(1, 4))

    # SECTION 6: Likely Judge Questions
    story.append(Paragraph("6. TEN LIKELY JUDGE QUESTIONS (Under 30 Words Each)", h1_style))
    qa_list = [
        ("1. How is this different from antivirus?", "Antivirus scans files on disk. ShadowMem inspects live virtual address spaces in RAM to catch fileless code that never writes to storage."),
        ("2. What is your false positive rate?", "Our training evaluation achieved under 0.2% false positives by explicitly using a JIT allowlist that caps browser JavaScript engines below threat thresholds."),
        ("3. Why does process count change between scans?", "Windows continuously starts and stops background tasks (telemetry, update workers, browser tabs). The count reflects actual processes opened successfully during that specific scan."),
        ("4. Does ShadowMem require Admin rights?", "Yes. As a standard user it only scans your own user-session (~40 PIDs). Admin rights (SeDebugPrivilege) allow it to inspect all system processes (~130+)."),
        ("5. What happens when a threat is found?", "It flags the PID, assigns a MITRE classification, and allows one-click thread suspension (SuspendThread) to freeze execution without destroying memory evidence."),
        ("6. Is this production-ready?", "It is a functional working prototype. The memory traversal, ML classification, and thread containment work live today, while authentication and container sandboxing are roadmap items."),
        ("7. Can your containment tool crash Windows?", "No. Our containment service enforces safety checks refusing to isolate critical operating system processes like csrss.exe, smss.exe, or lsass.exe."),
        ("8. What machine learning model is loaded?", "A scikit-learn HistGradientBoostingClassifier with RobustScaler, evaluating 7 volatile memory features across 9 classes (5 benign types, 4 injection techniques)."),
        ("9. Why not build a kernel driver?", "Kernel drivers require Microsoft signing, introduce kernel attack surfaces, and risk BSOD crashes. User-mode VirtualQueryEx provides fast, reliable, non-destructive triage."),
        ("10. What are the 7 features evaluated?", "RWX page count, unbacked executable pages, total RWX bytes, active thread count, threads starting in unbacked memory, JIT runtime flag, and protection-flip anomalies."),
    ]

    for q, a in qa_list:
        story.append(Paragraph(f"<b>{q}</b> {a}", bullet_style))

    # Build PDF
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated {OUTPUT_PDF} ({os.path.getsize(OUTPUT_PDF):,} bytes)")


if __name__ == "__main__":
    build_pdf()
