"""
build_backend_audit_pdf.py
===========================
Generates a comprehensive, professional PDF report:
"ShadowMem Backend Architecture & Security Audit: Comprehensive Findings and Prioritized Upgrade Roadmap"
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

# ---------------------------------------------------------------------------
# Output configuration
# ---------------------------------------------------------------------------
OUTPUT_PDF = "ShadowMem_Backend_Audit_Report.pdf"
GENERATED_AT = datetime.now().strftime("%B %d, %Y - %H:%M")

PAGE_W, PAGE_H = letter
MARGIN = 0.55 * inch
USABLE_W = PAGE_W - (2 * MARGIN)

# ---------------------------------------------------------------------------
# Color Palette (Corporate SOC / Security Engineering)
# ---------------------------------------------------------------------------
PRIMARY = colors.HexColor("#0B3954")       # Deep Navy
SECONDARY = colors.HexColor("#087E8B")     # Dark Cyan / Teal
ACCENT = colors.HexColor("#BF3100")        # Rust Red
DARK = colors.HexColor("#0F172A")          # Slate 900
TEXT_MUTED = colors.HexColor("#475569")    # Slate 600
LIGHT_BG = colors.HexColor("#F8FAFC")      # Slate 50
ALT_ROW = colors.HexColor("#F1F5F9")       # Slate 100
BORDER_COL = colors.HexColor("#CBD5E1")    # Slate 300

# Status Pill Colors
SEV_CRIT_BG = colors.HexColor("#FEE2E2")
SEV_CRIT_TXT = colors.HexColor("#991B1B")
SEV_HIGH_BG = colors.HexColor("#FFEDD5")
SEV_HIGH_TXT = colors.HexColor("#9A3412")
SEV_MED_BG = colors.HexColor("#FEF3C7")
SEV_MED_TXT = colors.HexColor("#92400E")
SEV_OK_BG = colors.HexColor("#DCFCE7")
SEV_OK_TXT = colors.HexColor("#166534")

# ---------------------------------------------------------------------------
# Numbered Canvas for Two-Pass "Page X of Y"
# ---------------------------------------------------------------------------
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
                "SHADOWMEM BACKEND ARCHITECTURE & SECURITY AUDIT",
            )
            self.drawRightString(
                PAGE_W - MARGIN,
                PAGE_H - 0.38 * inch,
                "TECHNICAL FINDINGS & UPGRADE ROADMAP",
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
            f"CONFIDENTIAL & PROPRIETARY | Evaluated: {GENERATED_AT}",
        )
        self.drawRightString(
            PAGE_W - MARGIN,
            0.32 * inch,
            f"Page {self._pageNumber} of {total_pages}",
        )
        self.restoreState()


# ---------------------------------------------------------------------------
# Typography & Styles
# ---------------------------------------------------------------------------
STYLES = getSampleStyleSheet()

S_TITLE = ParagraphStyle(
    "DocTitle",
    parent=STYLES["Title"],
    fontName="Helvetica-Bold",
    fontSize=20,
    leading=24,
    textColor=PRIMARY,
    alignment=TA_LEFT,
    spaceAfter=4,
)

S_SUBTITLE = ParagraphStyle(
    "DocSub",
    parent=STYLES["Normal"],
    fontName="Helvetica-Bold",
    fontSize=10,
    leading=14,
    textColor=SECONDARY,
    spaceAfter=6,
)

S_META = ParagraphStyle(
    "DocMeta",
    parent=STYLES["Normal"],
    fontName="Helvetica",
    fontSize=8,
    leading=11,
    textColor=TEXT_MUTED,
    spaceAfter=10,
)

S_H1 = ParagraphStyle(
    "SectionH1",
    parent=STYLES["Heading1"],
    fontName="Helvetica-Bold",
    fontSize=12.5,
    leading=16,
    textColor=PRIMARY,
    spaceBefore=12,
    spaceAfter=4,
    keepWithNext=True,
)

S_H2 = ParagraphStyle(
    "SectionH2",
    parent=STYLES["Heading2"],
    fontName="Helvetica-Bold",
    fontSize=9.5,
    leading=13,
    textColor=SECONDARY,
    spaceBefore=8,
    spaceAfter=3,
    keepWithNext=True,
)

S_BODY = ParagraphStyle(
    "Body",
    parent=STYLES["Normal"],
    fontName="Helvetica",
    fontSize=8.2,
    leading=11.5,
    textColor=DARK,
    spaceAfter=4,
)

S_BULLET = ParagraphStyle(
    "Bullet",
    parent=S_BODY,
    leftIndent=12,
    bulletIndent=2,
    spaceAfter=2.5,
)

S_CALLOUT = ParagraphStyle(
    "Callout",
    parent=STYLES["Normal"],
    fontName="Helvetica-Oblique",
    fontSize=8,
    leading=11,
    textColor=PRIMARY,
)

S_CODE = ParagraphStyle(
    "CodeText",
    parent=STYLES["Normal"],
    fontName="Courier",
    fontSize=7.2,
    leading=9.2,
    textColor=DARK,
)

S_TH = ParagraphStyle(
    "TableHeader",
    parent=STYLES["Normal"],
    fontName="Helvetica-Bold",
    fontSize=7.8,
    leading=10,
    textColor=colors.white,
    alignment=TA_LEFT,
)

S_TD = ParagraphStyle(
    "TableCell",
    parent=STYLES["Normal"],
    fontName="Helvetica",
    fontSize=7.5,
    leading=9.8,
    textColor=DARK,
)

S_TD_BOLD = ParagraphStyle(
    "TableCellBold",
    parent=STYLES["Normal"],
    fontName="Helvetica-Bold",
    fontSize=7.5,
    leading=9.8,
    textColor=DARK,
)

S_TD_CODE = ParagraphStyle(
    "TableCellCode",
    parent=STYLES["Normal"],
    fontName="Courier",
    fontSize=7,
    leading=9,
    textColor=DARK,
)


def pill(text, bg, fg):
    return (
        f"<font color='{fg.hexval()}'><b>{text}</b></font>"
    )


def code_block(code_str):
    escaped = code_str.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").strip()
    p = Paragraph(escaped.replace("\n", "<br/>"), S_CODE)
    t = Table([[p]], colWidths=[USABLE_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
        ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COL),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def callout_box(text, border_color=PRIMARY, bg_color=LIGHT_BG):
    p = Paragraph(text, S_CALLOUT)
    t = Table([[p]], colWidths=[USABLE_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg_color),
        ("BOX", (0, 0), (-1, -1), 0.75, border_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


# ---------------------------------------------------------------------------
# Main Document Generator
# ---------------------------------------------------------------------------
def generate_pdf():
    story = []

    # Title & Metadata
    story.append(Paragraph("ShadowMem Backend Audit & Upgrade Roadmap", S_TITLE))
    story.append(Paragraph("System Architecture, Security Findings, and Incremental Modernization Plan", S_SUBTITLE))
    story.append(Paragraph(
        f"<b>Target Codebase:</b> C:\\Users\\Himesh\\Desktop\\ShadowMem &nbsp;|&nbsp; "
        f"<b>Audit Date:</b> {GENERATED_AT} &nbsp;|&nbsp; "
        f"<b>Scope:</b> Backend Services, Core Engine, ML Inference & API Layer",
        S_META
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=8))

    # Executive Scorecard
    story.append(Paragraph("1. Executive Summary & Assessment Scorecard", S_H1))
    story.append(Paragraph(
        "ShadowMem provides an impressive, technically sound foundation for volatile Windows memory forensics, "
        "leveraging user-mode Win32 memory introspection (VirtualQueryEx, NtQueryInformationThread) paired with a 7-feature "
        "machine learning classification pipeline. However, the current backend implementation exhibits significant architectural "
        "debt, tight coupling, and security vulnerabilities that inhibit enterprise reliability and scalability. "
        "Most critically, the codebase is anchored around a monolithic 3,434-line <code>app.py</code> (including ~2,478 lines of inline HTML/JS), "
        "an unresolved dual-server conflict (<code>server.py</code> vs. <code>app.py</code>), unauthenticated process-manipulation endpoints, "
        "and zero automated test scaffolding for core Win32 subsystems.",
        S_BODY
    ))

    scorecard_data = [
        [
            Paragraph("Subsystem / Domain", S_TH),
            Paragraph("Health Rating", S_TH),
            Paragraph("Key Finding / Root Limitation", S_TH),
            Paragraph("Target State", S_TH),
        ],
        [
            Paragraph("<b>Architecture & Modularity</b>", S_TD_BOLD),
            Paragraph(f"<font color='{SEV_CRIT_TXT.hexval()}'><b>CRITICAL</b></font>", S_TD),
            Paragraph("3,434-line monolithic <code>app.py</code> with 2,478 lines of embedded HTML; duplicated Win32 logic across 4 files.", S_TD),
            Paragraph("Clean 4-tier layer: Routers &rarr; Services &rarr; Models &rarr; Core Engine.", S_TD),
        ],
        [
            Paragraph("<b>Server Architecture (ERR-09)</b>", S_TD_BOLD),
            Paragraph(f"<font color='{SEV_HIGH_TXT.hexval()}'><b>HIGH RISK</b></font>", S_TD),
            Paragraph("<code>server.py</code> and <code>app.py</code> both bind port 8000; dead WebSocket loop in <code>app.py</code>; divergent payloads.", S_TD),
            Paragraph("Single authoritative FastAPI server with live alert broadcaster; <code>server.py</code> fully retired.", S_TD),
        ],
        [
            Paragraph("<b>API Design & Typing</b>", S_TD_BOLD),
            Paragraph(f"<font color='{SEV_HIGH_TXT.hexval()}'><b>HIGH RISK</b></font>", S_TD),
            Paragraph("No API versioning; no Pydantic request/response models; <code>POST /api/isolate</code> uses query param for reason.", S_TD),
            Paragraph("Standardized <code>/api/v1/</code> REST API with strict Pydantic schemas and OpenAPI documentation.", S_TD),
        ],
        [
            Paragraph("<b>Security & Containment</b>", S_TD_BOLD),
            Paragraph(f"<font color='{SEV_CRIT_TXT.hexval()}'><b>CRITICAL</b></font>", S_TD),
            Paragraph("Unauthenticated <code>/api/isolate</code> allows arbitrary thread suspension; permissive CORS (<code>*</code> + credentials).", S_TD),
            Paragraph("Local token/API-key authorization, strict CORS whitelist, loopback-only binding.", S_TD),
        ],
        [
            Paragraph("<b>Configuration & Secrets</b>", S_TD_BOLD),
            Paragraph(f"<font color='{SEV_MED_TXT.hexval()}'><b>MODERATE</b></font>", S_TD),
            Paragraph("Hardcoded ports, file paths, JIT allowlists, and ML thresholds scattered throughout Python files.", S_TD),
            Paragraph("Centralized <code>config.py</code> leveraging <code>pydantic-settings</code> and <code>.env</code> file support.", S_TD),
        ],
        [
            Paragraph("<b>Performance & Concurrency</b>", S_TD_BOLD),
            Paragraph(f"<font color='{SEV_HIGH_TXT.hexval()}'><b>HIGH RISK</b></font>", S_TD),
            Paragraph("Linear process scan loops block async event loop for 2-10+ seconds; global mutable cache race conditions.", S_TD),
            Paragraph("Offloaded CPU-bound scans via <code>asyncio.to_thread</code> or background worker queue.", S_TD),
        ],
        [
            Paragraph("<b>Test Scaffolding & CI</b>", S_TD_BOLD),
            Paragraph(f"<font color='{SEV_CRIT_TXT.hexval()}'><b>CRITICAL</b></font>", S_TD),
            Paragraph("Zero unit test framework; tests are standalone scripts requiring live Windows admin processes.", S_TD),
            Paragraph("Pytest suite with mocked ctypes/Win32 APIs runnable on any platform and CI/CD pipelines.", S_TD),
        ],
    ]

    t_scorecard = Table(scorecard_data, colWidths=[1.3 * inch, 0.9 * inch, 2.8 * inch, 2.0 * inch])
    t_scorecard.setStyle(TableStyle([
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
    story.append(t_scorecard)
    story.append(Spacer(1, 8))

    # Section 2: Codebase Mapping
    story.append(Paragraph("2. Detailed Codebase Mapping & Component Roles", S_H1))
    story.append(Paragraph(
        "The ShadowMem backend currently consists of 18 Python scripts in the root directory alongside the Next.js frontend. "
        "The functional responsibilities of key modules are cataloged below:",
        S_BODY
    ))

    module_map_data = [
        [
            Paragraph("Module / File", S_TH),
            Paragraph("Lines / Size", S_TH),
            Paragraph("Actual Functional Responsibility", S_TH),
            Paragraph("Architectural Flaws / Issues Identified", S_TH),
        ],
        [
            Paragraph("<code>app.py</code>", S_TD_CODE),
            Paragraph("3,434 lines<br/>147.3 KB", S_TD),
            Paragraph("Main FastAPI application. Serves Next.js static files and fallback HTML; exposes <code>/api/scan</code>, <code>/api/isolate/{pid}</code>, <code>/api/resume/{pid}</code>, <code>/api/audit</code>, and WebSocket alerts.", S_TD),
            Paragraph("Massive monolith: embeds 2,478 lines of raw HTML; duplicates Win32 declarations; stores unpersisted mutable global state (<code>all_processes</code>); dead WebSocket loop.", S_TD),
        ],
        [
            Paragraph("<code>server.py</code>", S_TD_CODE),
            Paragraph("290 lines<br/>10.9 KB", S_TD),
            Paragraph("Legacy/mock FastAPI server built for early hackathon demos. Emits synthetic telemetry heartbeats, randomized alerts, and mock memory maps over <code>/ws/alerts</code>.", S_TD),
            Paragraph("<b>ERR-09 root cause:</b> Hardcodes port 8000; lacks memory scanning and isolation; divergent schema on <code>/simulate/alert</code> compared to <code>app.py</code>.", S_TD),
        ],
        [
            Paragraph("<code>memoryscanner.py</code>", S_TD_CODE),
            Paragraph("185 lines<br/>6.8 KB", S_TD),
            Paragraph("Low-level memory forensics engine using <code>ctypes</code> (kernel32, ntdll) and <code>psutil</code>. Performs linear VAD region walk, detects RWX pages, checks RW&rarr;RX flips, and extracts thread start addresses.", S_TD),
            Paragraph("Synchronous blocking execution; incomplete 64-bit address space ceiling check; no handle leak recovery on unexpected ctypes exceptions; lacks abstraction for testing.", S_TD),
        ],
        [
            Paragraph("<code>detecter.py</code>", S_TD_CODE),
            Paragraph("136 lines<br/>5.0 KB", S_TD),
            Paragraph("Command-line forensic scanning tool. Imports <code>memoryscanner</code>, loads pickled ML model, extracts 7 features, applies JIT suppression, and prints terminal summary.", S_TD),
            Paragraph("Redundant copy of JIT allowlist logic and feature vector assembly that also exists verbatim inside <code>app.py</code>.", S_TD),
        ],
        [
            Paragraph("<code>train_model.py</code>", S_TD_CODE),
            Paragraph("615 lines<br/>30.1 KB", S_TD),
            Paragraph("Advanced ML training pipeline. Generates 6,000 synthetic forensic vectors across 9 subclasses (5 benign, 4 malicious), fits <code>HistGradientBoostingClassifier</code> with <code>RobustScaler</code>, verifies canary profiles, and dumps pickle.", S_TD),
            Paragraph("Produces an unvalidated Python pickle artifact (code execution risk); synthetic distributions have hardcoded parameters not derived from real telemetry baselines.", S_TD),
        ],
        [
            Paragraph("<code>technique_docs.py</code>", S_TD_CODE),
            Paragraph("154 lines<br/>7.5 KB", S_TD),
            Paragraph("Static MITRE ATT&CK reference data. Maps multi-class indices (5-8) to display names, MITRE IDs (T1055.001, T1055.012, T1620, T1055.003), indicators, and response playbooks.", S_TD),
            Paragraph("Coupled tightly to index order in <code>train_model.py</code>; hardcoded dictionaries without schema validation or internationalization.", S_TD),
        ],
        [
            Paragraph("<code>malware_simulator.py</code>", S_TD_CODE),
            Paragraph("498 lines<br/>19.8 KB", S_TD),
            Paragraph("Safe user-mode attack harness. Allocates RWX buffers with NOP sleds, spawns worker threads, performs VirtualProtect flips, and registers threats with the prototype.", S_TD),
            Paragraph("Documentation instructs users to launch <code>server.py</code> on port 8000, perpetuating developer confusion and port collisions.", S_TD),
        ],
        [
            Paragraph("<code>test_master_suite.py</code><br/><code>test_sandbox.py</code>", S_TD_CODE),
            Paragraph("270 lines<br/>275 lines", S_TD),
            Paragraph("Validation suites executing simulated attacks, live server scans, process isolation, and PDF generation.", S_TD),
            Paragraph("Not integrated into standard testing runners (e.g. pytest); requires admin privileges and live running servers; non-reproducible in CI.", S_TD),
        ],
    ]

    t_modules = Table(module_map_data, colWidths=[1.2 * inch, 0.8 * inch, 2.5 * inch, 2.5 * inch])
    t_modules.setStyle(TableStyle([
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
    story.append(t_modules)
    story.append(Spacer(1, 8))

    # Section 3: Deep Technical Audits
    story.append(Paragraph("3. In-Depth Technical Audits & Vulnerability Analysis", S_H1))

    # 3.1 The app.py vs server.py Conflict
    story.append(Paragraph("A. Deep Dive: The ERR-09 Dual-Server Conflict (Current Reality)", S_H2))
    story.append(Paragraph(
        "<b>Historical Context:</b> ShadowMem originally emerged with two disjoint backends: <code>server.py</code> was designed as a lightweight "
        "WebSocket mock streaming synthetic telemetry for early UI design, while <code>app.py</code> was created as the authoritative forensics engine. "
        "A previous bug ticket (ERR-09) documented that running both servers produced port binding collisions on port 8000.",
        S_BODY
    ))
    story.append(Paragraph(
        "<b>Audit Verification — Does ERR-09 Still Exist?</b><br/>"
        "<b>YES. While partially mitigated by migrating route declarations into <code>app.py</code>, the conflict remains fundamentally active:</b>",
        S_BODY
    ))
    story.append(Paragraph(
        "1. <b>Port Collision Hazard:</b> Both <code>app.py</code> and <code>server.py</code> retain <code>uvicorn.run(app, host='0.0.0.0', port=8000)</code> "
        "at their entry points. Any developer or script running <code>server.py</code> while <code>launch_shadowmem.bat</code> is active triggers an immediate "
        "<code>WinError 10048 (WSAEADDRINUSE)</code>.",
        S_BULLET
    ))
    story.append(Paragraph(
        "2. <b>Dead WebSocket Loop in <code>app.py</code>:</b> In <code>app.py</code>, <code>/ws/alerts</code> was added, but it only sends a single static "
        "welcome JSON and then executes <code>while True: await asyncio.sleep(60)</code>. Live scan results from <code>/api/scan</code> are <b>never broadcast</b> "
        "to connected WebSocket clients. In contrast, <code>server.py</code> actually streams continuous heartbeats and memory maps.",
        S_BULLET
    ))
    story.append(Paragraph(
        "3. <b>Divergent API Signatures on <code>/simulate/alert</code>:</b> In <code>server.py</code>, <code>POST /simulate/alert</code> expects a JSON body "
        "validated by Pydantic (<code>SimulateAlertRequest(scenario, severity)</code>). In <code>app.py</code>, line 875 defines "
        "<code>async def simulate_alert():</code> with <b>no parameters</b>, hardcoding Cobalt Strike Beacon strings and ignoring caller parameters.",
        S_BULLET
    ))
    story.append(Paragraph(
        "4. <b>Stale Documentation and Script References:</b> <code>malware_simulator.py</code> (line 38) explicitly tells the operator to start <code>server.py</code> "
        "for WebSocket alerts. Meanwhile, <code>restart_server.py</code> relies on aggressive <code>taskkill /F /PID</code> commands against port 8000 to recover from deadlocks.",
        S_BULLET
    ))

    # 3.2 Win32 Memory Forensics & Data Flow
    story.append(Paragraph("B. Win32 & psutil Memory Telemetry Flow (Collection &rarr; Inference &rarr; Response)", S_H2))
    story.append(Paragraph(
        "The collection pipeline in <code>memoryscanner.py</code> operates as follows:",
        S_BODY
    ))
    story.append(Paragraph(
        "1. <b>Process Discovery:</b> <code>scan_all_processes()</code> iterates across all active processes via <code>psutil.process_iter(['pid'])</code>. "
        "For each PID, it acquires basic metadata (process name, exe path, thread count).",
        S_BULLET
    ))
    story.append(Paragraph(
        "2. <b>Process Handle Acquisition:</b> Invokes <code>kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)</code>. "
        "Protected system processes (e.g. LSASS, CSRSS) fail gracefully with Access Denied.",
        S_BULLET
    ))
    story.append(Paragraph(
        "3. <b>Linear VAD Region Walking:</b> Starting at virtual address <code>0x0</code>, the engine iteratively calls <code>kernel32.VirtualQueryEx()</code>. "
        "For every committed private region (<code>MEM_COMMIT</code> & <code>MEM_PRIVATE</code>), it checks for executable permissions (<code>PAGE_EXECUTE_READ</code>, "
        "<code>PAGE_EXECUTE_READWRITE</code>). If found, <code>unbacked_exec_count</code> increments. If RWX, <code>rwx_count</code> and total byte sizes increment.",
        S_BULLET
    ))
    story.append(Paragraph(
        "4. <b>VAD Protection Anomaly Detection:</b> Flags allocations whose current protection is executable but whose initial allocation was non-executable data "
        "(<code>AllocationProtect == PAGE_READWRITE</code>). This is the hallmark signature of runtime payload staging and <code>VirtualProtect</code> flips.",
        S_BULLET
    ))
    story.append(Paragraph(
        "5. <b>Thread Start Address Resolution:</b> Queries active threads using undocumented <code>ntdll.NtQueryInformationThread(ThreadQuerySetWin32StartAddress)</code>. "
        "If a thread's start address falls inside an unbacked private executable region, <code>thread_unbacked_start</code> increments (indicating shellcode/remote execution).",
        S_BULLET
    ))
    story.append(Paragraph(
        "6. <b>ML Inference & Serialization:</b> Telemetry is passed to <code>evaluate_process()</code> in <code>app.py</code>, which runs the 7-feature vector through "
        "<code>model.predict_proba()</code>, evaluates JIT allowlists, and aggregates JSON results.",
        S_BULLET
    ))

    # 3.3 Security, Concurrency & API Critique
    story.append(Paragraph("C. Security Vulnerabilities, Concurrency & API Architecture", S_H2))
    story.append(Paragraph(
        "• <b>Severe Security Hole in Process Containment:</b> <code>POST /api/isolate/{pid}</code> and <code>POST /api/resume/{pid}</code> accept arbitrary PIDs "
        "and suspend process threads on the host Windows system. These endpoints have <b>no authentication</b>, <b>no authorization</b>, and <b>no CSRF tokens</b>. "
        "Because <code>app.py</code> binds <code>0.0.0.0</code>, any attacker on the local network or any malicious website running in the analyst's browser (via DNS rebinding or CSRF) "
        "can suspend arbitrary user processes.",
        S_BODY
    ))
    story.append(Paragraph(
        "• <b>CORS Specification Violation:</b> In <code>app.py</code> lines 252-256, CORS is configured with <code>allow_origins=['*']</code> and "
        "<code>allow_credentials=True</code>. Under W3C CORS specifications, browsers reject requests where wildcard origins are paired with credentialed requests.",
        S_BODY
    ))
    story.append(Paragraph(
        "• <b>Event Loop Blocking (Async Starvation):</b> <code>api_scan()</code> is defined as a synchronous route that invokes <code>memoryscanner.scan_all_processes()</code>. "
        "This function executes a synchronous, CPU-intensive loop querying hundreds of processes and thousands of memory regions via Win32 syscalls. "
        "During this 2-10 second execution, concurrent API calls or WebSocket frames can suffer severe latency spikes.",
        S_BODY
    ))
    story.append(Paragraph(
        "• <b>Unsafe State Mutation & Global Leakage:</b> <code>app.py</code> uses global in-memory variables (<code>all_processes: list</code> and <code>_isolation_audit: list</code>). "
        "Concurrent requests create race conditions, and all forensic state and audit trails are lost when the Uvicorn process restarts.",
        S_BODY
    ))
    story.append(Paragraph(
        "• <b>Insecure ML Model Loading:</b> <code>shadowmem_model.pkl</code> is deserialized using Python's standard <code>pickle.load()</code> without signature verification. "
        "If a malicious model file is substituted, arbitrary code execution occurs inside the backend supervisor.",
        S_BODY
    ))
    story.append(Spacer(1, 8))

    # Section 4: Future Integrations
    story.append(Paragraph("4. Clean Integration Points for Upcoming Capabilities", S_H1))
    story.append(Paragraph(
        "ShadowMem has two planned major extensions: a <b>Docker-based dynamic analysis sandbox (via WSL2)</b> and a <b>Supply Chain Security Scanner</b>. "
        "Currently, there is no modular architecture to support them without severely polluting <code>app.py</code>. The recommended integration architecture is detailed below:",
        S_BODY
    ))

    integration_data = [
        [
            Paragraph("Planned Extension", S_TH),
            Paragraph("Current Codebase Readiness", S_TH),
            Paragraph("Recommended Integration Architecture", S_TH),
            Paragraph("Interface / Contract Design", S_TH),
        ],
        [
            Paragraph("<b>Docker Sandbox (via WSL2)</b><br/>Safe detonator for unknown binaries and memory dump analysis.", S_TD_BOLD),
            Paragraph(f"<font color='{SEV_CRIT_TXT.hexval()}'><b>Zero Readiness</b></font><br/>All scanning is hardcoded to the local Windows host address space.", S_TD),
            Paragraph("Create <code>backend/services/sandbox_service.py</code> communicating with Docker daemon via WSL2 socket or Docker SDK. Isolates detonated processes in lightweight Linux/Windows containers, dumps memory pages, and streams execution artifacts back to the main engine.", S_TD),
            Paragraph("<code>BaseSandboxProvider</code>:<br/>• <code>detonate_sample(file_bytes)</code><br/>• <code>capture_memory_snapshot()</code><br/>• <code>stream_sandbox_logs()</code><br/>• <code>terminate_sandbox()</code>", S_TD_CODE),
        ],
        [
            Paragraph("<b>Supply Chain Scanner</b><br/>Analyzes dependencies, requirements, lockfiles, and imports for malicious packages.", S_TD_BOLD),
            Paragraph(f"<font color='{SEV_CRIT_TXT.hexval()}'><b>Zero Readiness</b></font><br/>No concept of static package analysis, lockfile parsing, or vulnerability databases.", S_TD),
            Paragraph("Create <code>backend/services/supply_chain_service.py</code>. Parses <code>requirements.txt</code>, <code>package.json</code>, and PE import tables (via <code>pefile</code>). Queries OSV/PyPI advisory APIs and checks package hashes against known malicious packages.", S_TD),
            Paragraph("<code>SupplyChainScanner</code>:<br/>• <code>scan_python_manifest()</code><br/>• <code>scan_npm_manifest()</code><br/>• <code>inspect_pe_imports(file_path)</code><br/>• <code>check_advisories(pkg_spec)</code>", S_TD_CODE),
        ],
    ]

    t_integration = Table(integration_data, colWidths=[1.4 * inch, 1.2 * inch, 2.5 * inch, 1.9 * inch])
    t_integration.setStyle(TableStyle([
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
    story.append(t_integration)
    story.append(Spacer(1, 8))

    # Section 5: Prioritized Upgrade Roadmap
    story.append(Paragraph("5. Prioritized Backend Upgrade Recommendations", S_H1))
    story.append(Paragraph(
        "To ensure incremental delivery without breaking existing frontend interfaces or demo flows, "
        "the modernization plan is divided into four sequential phases. Each phase can be implemented and validated independently.",
        S_BODY
    ))

    roadmap_data = [
        [
            Paragraph("Phase / Step", S_TH),
            Paragraph("Upgrade Recommendation", S_TH),
            Paragraph("What It Fixes / Value Delivered", S_TH),
            Paragraph("Effort", S_TH),
            Paragraph("Risk", S_TH),
        ],
        # Phase 1
        [
            Paragraph("<b>PHASE 1.1</b><br/>Immediate", S_TD_BOLD),
            Paragraph("<b>Permanently Resolve ERR-09 & Retire <code>server.py</code></b><br/>Migrate live alert broadcasting to <code>app.py</code>; wire real scan detections into WebSockets; archive or repurpose <code>server.py</code> into an explicit test mock in <code>tests/mocks/</code>.", S_TD),
            Paragraph("Eliminates port 8000 collisions permanently; fixes dead WebSocket loop; ensures frontend receives real alerts during live scans.", S_TD),
            Paragraph("Small", S_TD),
            Paragraph("Low", S_TD),
        ],
        [
            Paragraph("<b>PHASE 1.2</b><br/>Immediate", S_TD_BOLD),
            Paragraph("<b>Introduce Pydantic Schemas & Versioned REST Routes</b><br/>Define request/response schemas (<code>ProcessScanResponse</code>, <code>IsolateRequest</code>, <code>AuditResponse</code>, <code>WebSocketAlertSchema</code>); mount under <code>/api/v1/</code> while maintaining temporary backward-compatibility aliases.", S_TD),
            Paragraph("Provides runtime input validation, eliminates ad-hoc JSON errors, generates automatic OpenAPI/Swagger docs, and stabilizes frontend contracts.", S_TD),
            Paragraph("Medium", S_TD),
            Paragraph("Low", S_TD),
        ],
        [
            Paragraph("<b>PHASE 1.3</b><br/>Immediate", S_TD_BOLD),
            Paragraph("<b>Centralized Settings & Configuration (<code>config.py</code>)</b><br/>Implement <code>Settings(BaseSettings)</code> via <code>pydantic-settings</code>. Manage port, host, paths, thresholds (70/35), JIT allowlists, and CORS origins via environment variables and <code>.env</code> file.", S_TD),
            Paragraph("Eliminates hardcoded ports and thresholds scattered across 5+ files; enables seamless multi-environment deployment.", S_TD),
            Paragraph("Small", S_TD),
            Paragraph("Very Low", S_TD),
        ],
        # Phase 2
        [
            Paragraph("<b>PHASE 2.1</b><br/>Refactor", S_TD_BOLD),
            Paragraph("<b>Modular Package Layering (De-monolith <code>app.py</code>)</b><br/>Split backend into standard layers: <code>api/v1/endpoints/</code> (routers), <code>services/</code> (business logic), <code>core/</code> (Win32 ctypes engine & ML), and <code>models/</code> (schemas).", S_TD),
            Paragraph("Reduces <code>app.py</code> from 3,434 lines to a clean ~60-line bootstrap script; ends duplicated Win32 and JIT logic.", S_TD),
            Paragraph("Medium", S_TD),
            Paragraph("Low", S_TD),
        ],
        [
            Paragraph("<b>PHASE 2.2</b><br/>Refactor", S_TD_BOLD),
            Paragraph("<b>Decouple Embedded HTML Fallback</b><br/>Extract <code>INDEX_HTML</code> (2,478 lines) out of Python code into a dedicated static template directory (<code>templates/fallback.html</code>). Mount cleanly via FastAPI static/template engine.", S_TD),
            Paragraph("Restores Python file cleanliness, improves IDE syntax highlighting and linting, reduces backend memory overhead.", S_TD),
            Paragraph("Small", S_TD),
            Paragraph("Very Low", S_TD),
        ],
        [
            Paragraph("<b>PHASE 2.3</b><br/>Quality", S_TD_BOLD),
            Paragraph("<b>Structured JSON Logging & Standardized Error Handling</b><br/>Implement centralized exception handlers (HTTPException, Win32Error, ValidationError) and structured logging with timestamp, correlation ID, and level.", S_TD),
            Paragraph("Guarantees clean, demo-safe error responses; eliminates raw Python stack trace leaks to the client; simplifies log analysis.", S_TD),
            Paragraph("Medium", S_TD),
            Paragraph("Low", S_TD),
        ],
        [
            Paragraph("<b>PHASE 2.4</b><br/>Testing", S_TD_BOLD),
            Paragraph("<b>Pytest Scaffolding & Win32 Mocking</b><br/>Establish <code>tests/</code> with <code>conftest.py</code>, FastAPI <code>TestClient</code>, and mock fixtures for <code>kernel32.VirtualQueryEx</code> and <code>ntdll.NtQueryInformationThread</code>.", S_TD),
            Paragraph("Enables automated regression testing in Linux CI/CD environments without requiring live Windows admin credentials.", S_TD),
            Paragraph("Medium", S_TD),
            Paragraph("Low", S_TD),
        ],
        # Phase 3
        [
            Paragraph("<b>PHASE 3.1</b><br/>Security", S_TD_BOLD),
            Paragraph("<b>API Security Hardening & Process Isolation Controls</b><br/>Bind server to <code>127.0.0.1</code> by default; correct CORS to explicit origins; require local bearer token or session header for <code>/api/v1/isolate</code>.", S_TD),
            Paragraph("Prevents unauthorized remote network clients and malicious web pages from weaponizing ShadowMem to suspend Windows processes.", S_TD),
            Paragraph("Small", S_TD),
            Paragraph("Medium", S_TD),
        ],
        [
            Paragraph("<b>PHASE 3.2</b><br/>Performance", S_TD_BOLD),
            Paragraph("<b>Non-Blocking Async Memory Scanning</b><br/>Wrap CPU-bound <code>scan_all_processes()</code> in <code>asyncio.to_thread()</code> or background worker pool. Add scan progress events over WebSocket.", S_TD),
            Paragraph("Prevents event loop starvation during full system scans; delivers responsive UI feedback with real-time scan progress percentages.", S_TD),
            Paragraph("Medium", S_TD),
            Paragraph("Low", S_TD),
        ],
        [
            Paragraph("<b>PHASE 3.3</b><br/>Reliability", S_TD_BOLD),
            Paragraph("<b>Lightweight SQLite Persistence Layer</b><br/>Replace ephemeral global lists (<code>all_processes</code>, <code>_isolation_audit</code>) with embedded SQLite database (via SQLModel or SQLAlchemy).", S_TD),
            Paragraph("Persists scan history, forensic snapshots, and tamper-resistant containment audit trails across server restarts.", S_TD),
            Paragraph("Medium", S_TD),
            Paragraph("Low", S_TD),
        ],
        # Phase 4
        [
            Paragraph("<b>PHASE 4.1</b><br/>Extension", S_TD_BOLD),
            Paragraph("<b>WSL2 / Docker Sandbox Integration Service</b><br/>Implement <code>SandboxService</code> following the abstract provider interface. Orchestrate container detonation, snapshotting, and telemetry streaming.", S_TD),
            Paragraph("Enables automated, isolated detonation of suspect samples without putting the host machine at risk.", S_TD),
            Paragraph("Large", S_TD),
            Paragraph("Medium", S_TD),
        ],
        [
            Paragraph("<b>PHASE 4.2</b><br/>Extension", S_TD_BOLD),
            Paragraph("<b>Software Supply Chain Security Scanner</b><br/>Implement <code>SupplyChainService</code> to scan manifests (requirements.txt, package.json) and inspect PE import tables for suspicious unbacked imports.", S_TD),
            Paragraph("Expands ShadowMem's defense envelope from pure in-memory runtime execution to proactive dependency vulnerability detection.", S_TD),
            Paragraph("Large", S_TD),
            Paragraph("Low", S_TD),
        ],
    ]

    t_roadmap = Table(roadmap_data, colWidths=[1.1 * inch, 2.3 * inch, 2.3 * inch, 0.65 * inch, 0.65 * inch])
    t_roadmap.setStyle(TableStyle([
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
    story.append(t_roadmap)
    story.append(Spacer(1, 8))

    # Section 6: Architecture Comparison
    story.append(Paragraph("6. Architecture Comparison: Current Monolith vs. Target Modular Blueprint", S_H1))
    story.append(Paragraph(
        "The side-by-side comparison below illustrates the structural transformation from the current monolithic repository "
        "to the recommended enterprise architecture:",
        S_BODY
    ))

    arch_compare_data = [
        [
            Paragraph("Current Monolithic Layout (Debt-Heavy)", S_TH),
            Paragraph("Target Clean Architecture (Modular & Scalable)", S_TH),
        ],
        [
            Paragraph("""
<b>Root Directory Monolith:</b><br/>
<code>ShadowMem/</code><br/>
├── <b>app.py</b> (3,434 lines: API + Win32 + ML + HTML)<br/>
├── <b>server.py</b> (290 lines: Orphan mock on port 8000)<br/>
├── <b>memoryscanner.py</b> (185 lines: Win32 ctypes)<br/>
├── <b>detecter.py</b> (136 lines: CLI duplicator)<br/>
├── <b>technique_docs.py</b> (154 lines: Static dicts)<br/>
├── <b>train_model.py</b> (615 lines: ML pipeline)<br/>
├── <b>malware_simulator.py</b> (498 lines: Test harness)<br/>
├── <b>restart_server.py</b> (Taskkill port-killer)<br/>
├── <b>index.html</b> (Legacy standalone HTML)<br/>
├── <b>run.txt</b> / <b>launch_shadowmem.bat</b> (Port 8001/8000)<br/>
└── <b>frontend/</b> (Next.js app exporting to out/)<br/>
<br/>
<b>Flaws:</b><br/>
• No separation of concerns (HTML, Win32, routes entangled)<br/>
• Dual server port conflict (ERR-09)<br/>
• Unpersisted global state in memory<br/>
• No automated testing infrastructure
            """, S_TD),
            Paragraph("""
<b>Structured Layered Package:</b><br/>
<code>ShadowMem/</code><br/>
├── <b>main.py</b> (~60 lines: Application entry & lifecycle)<br/>
├── <b>config.py</b> (Pydantic-Settings & env variables)<br/>
├── <b>backend/</b><br/>
│   ├── <b>api/</b> (API Layer)<br/>
│   │   ├── <b>deps.py</b> (Dependency injection: auth, db, engine)<br/>
│   │   └── <b>v1/</b><br/>
│   │       ├── <b>router.py</b> (Aggregates routers)<br/>
│   │       ├── <b>endpoints/</b> (scan, isolate, audit, ws)<br/>
│   │       └── <b>schemas/</b> (Pydantic DTOs)<br/>
│   ├── <b>services/</b> (Domain Logic)<br/>
│   │   ├── <b>forensics_service.py</b> (Coordinates scan & ML)<br/>
│   │   ├── <b>containment_service.py</b> (Process isolation)<br/>
│   │   ├── <b>alert_broadcaster.py</b> (Live WebSocket hub)<br/>
│   │   ├── <b>sandbox_service.py</b> (Docker / WSL2 interface)<br/>
│   │   └── <b>supply_chain_service.py</b> (Dependency scanner)<br/>
│   ├── <b>core/</b> (Low-Level Systems)<br/>
│   │   ├── <b>win32/</b> (VirtualQueryEx, NtQuery wrappers)<br/>
│   │   ├── <b>ml/</b> (Model loader, feature extraction, ONNX)<br/>
│   │   └── <b>security.py</b> (Auth tokens, CORS policies)<br/>
│   └── <b>db/</b> (Persistence)<br/>
│       ├── <b>session.py</b> (SQLite engine)<br/>
│       └── <b>models.py</b> (ScanHistory, AuditLog tables)<br/>
├── <b>frontend/</b> (Next.js static export)<br/>
├── <b>tests/</b> (Pytest suite with Win32 mocks)<br/>
└── <b>docs/</b> (OpenAPI specs & architecture guides)
            """, S_TD),
        ],
    ]

    t_arch = Table(arch_compare_data, colWidths=[3.5 * inch, 3.5 * inch])
    t_arch.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#FFF7ED")),
        ("BACKGROUND", (1, 1), (1, 1), colors.HexColor("#F0FDF4")),
    ]))
    story.append(t_arch)
    story.append(Spacer(1, 8))

    # Section 7: Conclusion & Immediate Next Steps
    story.append(Paragraph("7. Summary & Immediate Next Steps", S_H1))
    story.append(Paragraph(
        "ShadowMem possesses an exceptional defensive engineering core: its low-level memory traversal and thread-start "
        "heuristics accurately expose stealthy in-memory injection techniques (Reflective DLL, Process Hollowing, Shellcode beacons) "
        "that evade traditional file-based endpoint tools. By executing the phased upgrade roadmap outlined herein, the platform "
        "will transition from an ad-hoc hackathon prototype into an enterprise-grade, extensible cyber defense operations platform.",
        S_BODY
    ))
    story.append(callout_box(
        "<b>Recommended Immediate Action:</b> Proceed with <b>Phase 1.1 through Phase 1.3</b>. This permanently resolves the ERR-09 "
        "dual-server issue, stabilizes WebSocket alert broadcasting with live detection telemetry, introduces type-safe Pydantic schemas, "
        "and centralizes configuration—all without altering the core forensic algorithms or requiring a complete codebase rewrite.",
        border_color=SECONDARY,
        bg_color=LIGHT_BG,
    ))

    # Build the document
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
