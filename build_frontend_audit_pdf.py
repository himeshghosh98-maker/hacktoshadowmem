"""
build_frontend_audit_pdf.py
===========================
Generates a publication-grade, comprehensive PDF report:
"ShadowMem — Frontend Architectural Audit & Modernization Roadmap"
Analysis of Next.js App Router frontend, Tailwind styling, state management,
REST/WS communication, SOC tool UX compliance, readiness for sandbox and supply chain,
and staged implementation recommendations.
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

OUTPUT_PDF = "ShadowMem_Frontend_Audit_Report.pdf"
GENERATED_AT = datetime.now().strftime("%B %d, %Y - %H:%M")

PAGE_W, PAGE_H = letter
MARGIN = 0.55 * inch
USABLE_W = PAGE_W - (2 * MARGIN)

# Palette
PRIMARY = colors.HexColor("#0B3954")       # Deep Navy
SECONDARY = colors.HexColor("#087E8B")     # Dark Cyan / Teal
ACCENT = colors.HexColor("#BF3100")        # Rust Red
DARK = colors.HexColor("#0F172A")          # Slate 900
TEXT_MUTED = colors.HexColor("#475569")    # Slate 600
LIGHT_BG = colors.HexColor("#F8FAFC")      # Slate 50
ALT_ROW = colors.HexColor("#F1F5F9")       # Slate 100
BORDER_COL = colors.HexColor("#CBD5E1")    # Slate 300
CODE_BG = colors.HexColor("#1E293B")       # Dark code box
CODE_TXT = colors.HexColor("#F8FAFC")

PASS_BG = colors.HexColor("#DCFCE7")
PASS_TXT = colors.HexColor("#166534")
WARN_BG = colors.HexColor("#FEF3C7")
WARN_TXT = colors.HexColor("#92400E")
FAIL_BG = colors.HexColor("#FEE2E2")
FAIL_TXT = colors.HexColor("#991B1B")


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
                "SHADOWMEM FRONTEND ARCHITECTURAL AUDIT & ROADMAP",
            )
            self.drawRightString(
                PAGE_W - MARGIN,
                PAGE_H - 0.38 * inch,
                "NEXT.JS / TAILWIND / REST / WEBSOCKET EVALUATION",
            )
            self.setStrokeColor(BORDER_COL)
            self.setLineWidth(0.5)
            self.line(MARGIN, PAGE_H - 0.44 * inch, PAGE_W - MARGIN, PAGE_H - 0.44 * inch)

        # Footer (all pages)
        self.setStrokeColor(BORDER_COL)
        self.setLineWidth(0.5)
        self.line(MARGIN, 0.45 * inch, PAGE_W - MARGIN, 0.45 * inch)

        self.drawString(
            MARGIN,
            0.32 * inch,
            f"CONFIDENTIAL & PROPRIETARY  |  SHADOWMEM SECURITY ARCHITECTURE  |  RUN DATE: {GENERATED_AT}",
        )
        self.drawRightString(
            PAGE_W - MARGIN,
            0.32 * inch,
            f"Page {self._pageNumber} of {total_pages}",
        )
        self.restoreState()


def get_styles():
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=PRIMARY,
        spaceAfter=4,
    )

    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=13.5,
        textColor=SECONDARY,
        spaceAfter=9,
    )

    h1_style = ParagraphStyle(
        "ReportH1",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11.5,
        leading=14.5,
        textColor=PRIMARY,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    )

    h2_style = ParagraphStyle(
        "ReportH2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.2,
        leading=12,
        textColor=SECONDARY,
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.2,
        leading=11.2,
        textColor=DARK,
        alignment=TA_JUSTIFY,
        spaceAfter=4,
    )

    code_snip_style = ParagraphStyle(
        "CodeSnip",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.0,
        leading=9.0,
        textColor=CODE_TXT,
    )

    meta_key = ParagraphStyle(
        "MetaKey",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=10,
        textColor=TEXT_MUTED,
    )

    meta_val = ParagraphStyle(
        "MetaVal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        textColor=DARK,
    )

    verdict_badge = ParagraphStyle(
        "VerdictBadge",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.0,
        leading=11.0,
        textColor=WARN_TXT,
        alignment=TA_CENTER,
    )

    callout_text = ParagraphStyle(
        "CalloutText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.0,
        leading=10.8,
        textColor=DARK,
    )

    return {
        "title": title_style,
        "subtitle": subtitle_style,
        "h1": h1_style,
        "h2": h2_style,
        "body": body_style,
        "code": code_snip_style,
        "meta_k": meta_key,
        "meta_v": meta_val,
        "verdict": verdict_badge,
        "callout": callout_text,
    }


def make_code_box(snippet_text, styles):
    p = Paragraph(snippet_text.replace("\n", "<br/>").replace(" ", "&nbsp;"), styles["code"])
    t = Table([[p]], colWidths=[USABLE_W])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), CODE_BG),
                ("TOPPADDING", (0, 0), (-1, -1), 3.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
            ]
        )
    )
    return t


def make_callout(text, styles, bg=LIGHT_BG, border=SECONDARY):
    p = Paragraph(text, styles["callout"])
    t = Table([[p]], colWidths=[USABLE_W])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("BOX", (0, 0), (-1, -1), 0.5, border),
                ("LINELEFT", (0, 0), (0, 0), 3.0, border),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 7),
                ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return t


def build_pdf():
    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=letter,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
    )

    styles = get_styles()
    story = []

    # -----------------------------------------------------------------------
    # Document Header
    # -----------------------------------------------------------------------
    story.append(Paragraph("ShadowMem — Frontend Architectural Audit", styles["title"]))
    story.append(
        Paragraph(
            "In-Depth Evaluation: Next.js App Router, State Architecture, SOC Ergonomics, & Backend Alignment",
            styles["subtitle"],
        )
    )

    # Metadata & Verdict Banner
    meta_data = [
        [
            Paragraph("Target Application:", styles["meta_k"]),
            Paragraph("ShadowMem Frontend (Next.js 14.2 / TypeScript / Tailwind CSS / Recharts)", styles["meta_v"]),
            Paragraph("Audit Timestamp:", styles["meta_k"]),
            Paragraph(GENERATED_AT, styles["meta_v"]),
        ],
        [
            Paragraph("Delivery Mode:", styles["meta_k"]),
            Paragraph("Static Export (<code>output: 'export'</code>) served via FastAPI (<code>app.py</code>)", styles["meta_v"]),
            Paragraph("Backend Version:", styles["meta_k"]),
            Paragraph("FastAPI 5-Step Modernized Architecture (/api/v1)", styles["meta_v"]),
        ],
        [
            Paragraph("Current Architecture:", styles["meta_k"]),
            Paragraph("6 App Routes, 12 Custom Components, Local Component State", styles["meta_v"]),
            Paragraph("OVERALL RATING:", styles["meta_k"]),
            Paragraph("<b>GRADE B- (NEEDS MODERNIZATION)</b>", styles["verdict"]),
        ],
    ]
    meta_table = Table(
        meta_data,
        colWidths=[1.2 * inch, 2.8 * inch, 1.2 * inch, 1.8 * inch],
    )
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), LIGHT_BG),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COL),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("BACKGROUND", (3, 2), (3, 2), WARN_BG),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 6))

    # -----------------------------------------------------------------------
    # 1. Executive Summary & Audit Context
    # -----------------------------------------------------------------------
    story.append(Paragraph("1. Executive Summary & Audit Context", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=4))
    story.append(
        Paragraph(
            "The ShadowMem frontend was successfully migrated from an embedded monolithic HTML file into a modern <b>Next.js 14 App Router</b> project utilizing TypeScript and Tailwind CSS. The production application builds to a static export in <code>frontend/out/</code> and is hosted directly by the FastAPI backend. While the application presents a functional, cohesive interface with custom radar and analytics visualizations, our deep code audit identified significant architectural debt, backward alignment lags, and state fragmentation that must be resolved to support upcoming capabilities (WSL2 sandbox detonation and supply chain scanning).",
            styles["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Key Findings:</b> (1) <i>Endpoint Lag:</i> The frontend communicates entirely with legacy unversioned endpoints (<code>/api/scan</code>, <code>/api/isolate?reason=...</code>) and does not consume the newly verified <code>/api/v1/*</code> schemas. (2) <i>State Fragmentation:</i> Forensics telemetry is siloed in local component state; navigating between tabs resets all scan results. (3) <i>Theme Incongruity:</i> While expected to reflect a CrowdStrike-style dark navy palette, the active theme is a warm parchment light mode (<code>#FAF7F2</code>) where orange (<code>#E8793C</code>) is confusingly aliased as 'lime'. (4) <i>WebSocket Duplication:</i> Up to three redundant WebSocket links are spawned simultaneously, while incoming <code>memory_map</code> frames are actively dropped. (5) <i>Simulated Artifacts:</i> Legacy timers continue to generate fake kernel logs on an interval.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 4))

    # -----------------------------------------------------------------------
    # 2. Scorecard Table
    # -----------------------------------------------------------------------
    story.append(Paragraph("2. Frontend Subsystem Health Scorecard", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=4))

    scorecard_data = [
        [
            Paragraph("<b>Subsystem Area</b>", styles["meta_k"]),
            Paragraph("<b>Current Implementation State</b>", styles["meta_k"]),
            Paragraph("<b>Deficiencies & Observations</b>", styles["meta_k"]),
            Paragraph("<b>Health Rating</b>", styles["meta_k"]),
        ],
        [
            Paragraph("<b>API & Backend Alignment</b>", styles["body"]),
            Paragraph("Uses <code>src/lib/api.ts</code> with relative URLs", styles["body"]),
            Paragraph("Lags behind backend: calls unversioned endpoints (<code>/api/scan</code>), uses query params for isolation, misses <code>/api/v1/*</code> schemas.", styles["body"]),
            Paragraph("<font color='#991B1B'><b>POOR (C)</b></font>", styles["callout"]),
        ],
        [
            Paragraph("<b>State Management</b>", styles["body"]),
            Paragraph("Local <code>useState</code> in each page; 3 light Contexts", styles["body"]),
            Paragraph("No global scan store. Switching tabs (e.g. from Overview to Live Map) erases scan data. Redundant scans required per page.", styles["body"]),
            Paragraph("<font color='#92400E'><b>FAIR (C+)</b></font>", styles["callout"]),
        ],
        [
            Paragraph("<b>WebSocket Handling</b>", styles["body"]),
            Paragraph("Linear backoff reconnect in <code>api.ts</code>", styles["body"]),
            Paragraph("Multiple concurrent connections spawned (Context + Page); actively discards <code>memory_map</code> telemetry frames.", styles["body"]),
            Paragraph("<font color='#92400E'><b>FAIR (B-)</b></font>", styles["callout"]),
        ],
        [
            Paragraph("<b>Design & Styling</b>", styles["body"]),
            Paragraph("Tailwind CSS with custom extend palette", styles["body"]),
            Paragraph("Warm parchment theme (<code>#FAF7F2</code>) conflicts with SOC expectations; 'lime' is aliased to orange (<code>#E8793C</code>); no dark mode toggle.", styles["body"]),
            Paragraph("<font color='#92400E'><b>FAIR (B-)</b></font>", styles["callout"]),
        ],
        [
            Paragraph("<b>Component Architecture</b>", styles["body"]),
            Paragraph("12 feature components in <code>components/dashboard</code>", styles["body"]),
            Paragraph("Zero shared UI primitives (Button, Card, Badge, Modal). Inline Tailwind classes copy-pasted; modal logic duplicated across 4 pages.", styles["body"]),
            Paragraph("<font color='#166534'><b>GOOD (B)</b></font>", styles["callout"]),
        ],
        [
            Paragraph("<b>Static Export & Delivery</b>", styles["body"]),
            Paragraph("Next.js <code>output: 'export'</code> served by <code>app.py</code>", styles["body"]),
            Paragraph("Flawless production delivery. Dev proxy has hardcoded port 8000 in <code>next.config.mjs</code>, but production relative paths survive port changes.", styles["body"]),
            Paragraph("<font color='#166534'><b>EXCELLENT (A)</b></font>", styles["callout"]),
        ],
        [
            Paragraph("<b>Step 5 Feature Readiness</b>", styles["body"]),
            Paragraph("No sandbox or supply chain routes exist", styles["body"]),
            Paragraph("Completely lacks UI structures, types, or API clients for Docker sandbox or PE supply chain scanner.", styles["body"]),
            Paragraph("<font color='#991B1B'><b>INCOMPLETE (D)</b></font>", styles["callout"]),
        ],
    ]

    scorecard_table = Table(
        scorecard_data,
        colWidths=[1.6 * inch, 1.8 * inch, 2.7 * inch, 0.9 * inch],
    )
    scorecard_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COL),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ALT_ROW]),
                ("ALIGN", (3, 0), (3, -1), "CENTER"),
            ]
        )
    )
    story.append(scorecard_table)
    story.append(Spacer(1, 6))

    # -----------------------------------------------------------------------
    # 3. Detailed Architectural Findings
    # -----------------------------------------------------------------------
    story.append(Paragraph("3. Detailed Technical Audit Findings", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=4))

    # Finding 1
    story.append(Paragraph("A. Backend Alignment: Unversioned Legacy Endpoint Lock-In", styles["h2"]))
    story.append(
        Paragraph(
            "While the FastAPI backend was upgraded to versioned <code>/api/v1/*</code> schemas with typed Pydantic request bodies, <code>src/lib/api.ts</code> remains tied to legacy endpoints. Specifically: (1) <code>fetchScan()</code> calls <code>GET /api/scan</code> rather than <code>/api/v1/scan</code>. (2) <code>isolateProcess()</code> encodes justification into the query string (<code>?reason=...</code>) rather than passing a JSON payload (<code>IsolateRequest</code>). (3) <code>AlertsPage</code> executes an unmanaged, inline raw <code>fetch('/simulate/alert')</code>. Fortunately, because <code>getApiBaseUrl()</code> returns an empty string in the browser, all API paths are relative and will survive backend port modifications in production, though dev-mode rewrites in <code>next.config.mjs</code> remain pinned to port 8000.",
            styles["body"],
        )
    )
    f1_code = (
        "// src/lib/api.ts (lines 59, 92-94) -- Current Legacy Calls\n"
        "const res = await fetch(`${base}/api/scan`, { method: 'GET' });\n"
        "const query = reason ? `?reason=${encodeURIComponent(reason)}` : '';\n"
        "const res = await fetch(`${base}/api/isolate/${pid}${query}`, { method: 'POST' });\n\n"
        "// Target Modern Architecture (/api/v1/ with JSON body)\n"
        "await fetch(`${base}/api/v1/isolate/${pid}`, {\n"
        "  method: 'POST',\n"
        "  headers: { 'Content-Type': 'application/json' },\n"
        "  body: JSON.stringify({ reason }),\n"
        "});"
    )
    story.append(make_code_box(f1_code, styles))
    story.append(Spacer(1, 4))

    # Finding 2
    story.append(Paragraph("B. State Management Fragmentation & Discarded Telemetry", styles["h2"]))
    story.append(
        Paragraph(
            "The frontend lacks a global forensic scan store. <code>processes</code>, <code>summary</code>, <code>hasScanned</code>, and <code>isolatedPids</code> are re-declared locally using <code>useState</code> in five separate page files (<code>app/page.tsx</code>, <code>process-table/page.tsx</code>, <code>live-map/page.tsx</code>, <code>alerts/page.tsx</code>, and <code>analytics/page.tsx</code>). Navigating between dashboard tabs destroys all existing scan state, forcing the analyst to re-trigger a 12-second volatile memory scan each time. Furthermore, in <code>src/lib/api.ts</code> (line 199), incoming WebSocket frames with <code>type !== 'alert'</code> are discarded, meaning the backend's real-time <code>memory_map</code> broadcast is completely ignored by the client.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 4))

    # Finding 3
    story.append(Paragraph("C. Redundant WebSocket Connections & Artificial Ambient Tickers", styles["h2"]))
    story.append(
        Paragraph(
            "Inspection revealed that <code>ConnectionContext.tsx</code>, <code>app/page.tsx</code>, <code>alerts/page.tsx</code>, and <code>kernel-log/page.tsx</code> each independently invoke <code>connectAlertsWebSocket()</code>. When an analyst browses the application, up to three concurrent WebSocket links are held open with the backend. Concurrently, <code>app/page.tsx</code> (lines 142–174) and <code>kernel-log/page.tsx</code> retain legacy demo tickers that execute <code>setInterval</code> loops with <code>Math.random() > 0.45</code>, injecting fabricated kernel strings (e.g. <i>'Walking active thread list via PsGetProcessThreads...'</i>). These synthetic logs confuse live incident response and must be retired.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 4))

    # Finding 4
    story.append(Paragraph("D. Design Token Incongruity: The 'Lime Orange' Dilemma & Dark Mode Absence", styles["h2"]))
    story.append(
        Paragraph(
            "The original single-file dashboard was styled with an authentic dark SOC palette (<code>#0A0E1A</code> background, <code>#151B2B</code> cards, and <code>#C6FF3D</code> lime green). During the Next.js rebuild, the theme was converted to a warm light parchment palette (<code>#FAF7F2</code> background, <code>#FFFFFF</code> cards). In <code>tailwind.config.ts</code>, the color key <code>lime</code> was re-mapped to orange (<code>#E8793C</code>). This produces severe cognitive disconnect: classes named <code>bg-lime</code> render orange elements, and alerts styled with yellow warnings clash with the primary orange branding. Furthermore, while <code>darkMode: 'class'</code> is configured, zero <code>dark:</code> variant classes exist in the codebase, and no theme toggle is present.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 4))

    # -----------------------------------------------------------------------
    # 4. SOC Tool UX & Accessibility Evaluation
    # -----------------------------------------------------------------------
    story.append(Paragraph("4. SOC Tool UI/UX & Information Architecture Audit", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=4))

    soc_eval = [
        [
            Paragraph("<b>UX Dimension</b>", styles["meta_k"]),
            Paragraph("<b>Current State in ShadowMem</b>", styles["meta_k"]),
            Paragraph("<b>SOC Standard & Recommended Remediation</b>", styles["meta_k"]),
        ],
        [
            Paragraph("Information Hierarchy", styles["body"]),
            Paragraph("Process table is hidden on a separate page (<code>/process-table</code>). Dashboard shows only aggregate stat cards and recent alerts.", styles["body"]),
            Paragraph("SOC tools (CrowdStrike, Sentinel) prioritize immediate process anomaly visibility on the main console. Add a high-risk process drawer directly to the Overview.", styles["body"]),
        ],
        [
            Paragraph("Threat Visual Coding", styles["body"]),
            Paragraph("4 distinct status colors: Red (malicious), Amber (suspicious), Blue (JIT), Emerald (clean). High visual distinction.", styles["body"]),
            Paragraph("Adheres well to MITRE ATT&CK visual conventions. Ensure color-blind accessible icons (e.g. ShieldAlert vs CheckCircle) accompany every score pill.", styles["body"]),
        ],
        [
            Paragraph("State Feedback", styles["body"]),
            Paragraph("Basic spinners on buttons; generic connection banner on disconnect; scan error text banner.", styles["body"]),
            Paragraph("Lacks non-blocking toast alerts, granular retry actions, and partial-isolation progress indicators during multi-thread containment.", styles["body"]),
        ],
        [
            Paragraph("Accessibility & Ergonomics", styles["body"]),
            Paragraph("Canvas radar on <code>/live-map</code> only reacts to mouse hover; text contrast is 4.6:1; no keyboard focus rings.", styles["body"]),
            Paragraph("Radar nodes are completely unreachable via keyboard navigation (Tab/Enter). Canvas must be paired with an accessible, keyboard-focusable DOM tree.", styles["body"]),
        ],
    ]

    soc_table = Table(
        soc_eval,
        colWidths=[1.5 * inch, 2.6 * inch, 2.9 * inch],
    )
    soc_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COL),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ALT_ROW]),
            ]
        )
    )
    story.append(soc_table)
    story.append(Spacer(1, 6))

    # -----------------------------------------------------------------------
    # 5. Readiness for Upcoming Features (Sandbox & Supply Chain)
    # -----------------------------------------------------------------------
    story.append(Paragraph("5. Step 5 Feature Readiness: Sandbox & Supply Chain Architecture", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=4))
    story.append(
        Paragraph(
            "With the backend Step 5 verification officially certified, the frontend must now ingest two rich data contracts without undergoing another structural rewrite. Below is the proposed component and route architecture informed by the actual backend response schemas:",
            styles["body"],
        )
    )

    prop_arch = (
        "frontend/src/\n"
        "├── types/\n"
        "│   ├── sandbox.ts            # Mirrors SandboxExecutionResult & SandboxHealthResponse\n"
        "│   └── supply_chain.ts       # Mirrors SupplyChainScanResponse & ModuleIntegrityFinding\n"
        "├── lib/api/\n"
        "│   ├── sandbox.ts            # submitSample(), getJobStatus(uuid), getSandboxHealth()\n"
        "│   └── supplyChain.ts        # scanProcessModules(pid), scanDirectoryPath(path)\n"
        "├── app/\n"
        "│   ├── sandbox/page.tsx      # Detonation Console (File Uploader, CLI Args, Job Poller)\n"
        "│   └── supply-chain/page.tsx # Authenticode & Module Integrity Inspector\n"
        "└── components/\n"
        "    ├── sandbox/\n"
        "    │   ├── DetonationSubmitForm.tsx   # File/Base64 input, arguments, timeout settings\n"
        "    │   ├── JobStatusTracker.tsx       # Live UUID poller with status badge (disabled/failed/completed)\n"
        "    │   └── ExecutionResultViewer.tsx  # Exit code, stdout/stderr console, artifacts drawer\n"
        "    └── supply-chain/\n"
        "        ├── ModuleIntegrityTable.tsx   # DLL list, signed badge, Authenticode cert, SHA-256 copy\n"
        "        ├── PathScanControls.tsx       # Directory selector with quick targets (.venv, System32)\n"
        "        └── SupplyChainPostureCard.tsx # Posture pill (Protected, Suspicious, Vulnerable)"
    )
    story.append(make_code_box(prop_arch, styles))
    story.append(Spacer(1, 4))

    # -----------------------------------------------------------------------
    # 6. Current vs. Target Architecture Comparison
    # -----------------------------------------------------------------------
    story.append(Paragraph("6. Current vs. Target Architectural Comparison", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=4))

    target_comp = [
        [
            Paragraph("<b>Architectural Vector</b>", styles["meta_k"]),
            Paragraph("<b>Current State (As-Is)</b>", styles["meta_k"]),
            Paragraph("<b>Target Modern Architecture (To-Be)</b>", styles["meta_k"]),
        ],
        [
            Paragraph("API Route Binding", styles["body"]),
            Paragraph("Legacy <code>/api/scan</code>, query string isolation", styles["body"]),
            Paragraph("Versioned <code>/api/v1/*</code> schemas with typed Pydantic JSON bodies", styles["body"]),
        ],
        [
            Paragraph("Forensic State Storage", styles["body"]),
            Paragraph("Local <code>useState</code> isolated inside each page", styles["body"]),
            Paragraph("Global <code>ForensicsProvider</code> context / Zustand store persisting across tabs", styles["body"]),
        ],
        [
            Paragraph("WebSocket Subsystem", styles["body"]),
            Paragraph("3 redundant connections; drops memory map", styles["body"]),
            Paragraph("Single managed WebSocket singleton multiplexing alerts & memory maps", styles["body"]),
        ],
        [
            Paragraph("Theme & Palette", styles["body"]),
            Paragraph("Warm parchment light mode; 'lime' is orange", styles["body"]),
            Paragraph("CrowdStrike deep navy (<code>#0A0E1A</code> / <code>#C6FF3D</code>) with dark/light CSS variables", styles["body"]),
        ],
        [
            Paragraph("UI Primitives", styles["body"]),
            Paragraph("Inline copy-pasted Tailwind utility classes", styles["body"]),
            Paragraph("Shared UI primitives (<code>Button</code>, <code>Badge</code>, <code>Card</code>, <code>Modal</code>, <code>CodeBox</code>)", styles["body"]),
        ],
        [
            Paragraph("Kernel Telemetry Feed", styles["body"]),
            Paragraph("Simulated ambient strings on <code>setInterval</code>", styles["body"]),
            Paragraph("Pure live backend event feed driven exclusively by WebSocket frames", styles["body"]),
        ],
    ]

    target_table = Table(
        target_comp,
        colWidths=[1.5 * inch, 2.7 * inch, 2.8 * inch],
    )
    target_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BOX", (0, 0), (-1, -1), 0.5, BORDER_COL),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, ALT_ROW]),
            ]
        )
    )
    story.append(target_table)
    story.append(Spacer(1, 6))

    # -----------------------------------------------------------------------
    # 7. Staged Upgrade Recommendations
    # -----------------------------------------------------------------------
    story.append(Paragraph("7. Prioritized, Staged Modernization Roadmap", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=4))

    story.append(Paragraph("Stage 1: Quick Wins & Backend Alignment (Low Effort — 1 to 2 Days)", styles["h2"]))
    story.append(
        Paragraph(
            "• <b>Upgrade API Client to /api/v1:</b> Update <code>src/lib/api.ts</code> to consume <code>/api/v1/scan</code>, <code>/api/v1/audit</code>, and <code>/api/v1/isolate/{pid}</code> passing JSON bodies.<br/>"
            "• <b>Consolidate WebSocket Connections:</b> Deprecate ad-hoc calls in pages; manage a single persistent socket inside <code>ConnectionContext</code> with event listener dispatching.<br/>"
            "• <b>Retire Artificial Tickers:</b> Remove the ambient <code>setInterval</code> fake log generator in <code>app/page.tsx</code> and <code>kernel-log/page.tsx</code>.<br/>"
            "• <b>Color Token Rectification:</b> Rename the orange token to <code>brandOrange</code> and restore <code>lime</code> to authentic SOC neon-green (<code>#C6FF3D</code>).",
            styles["body"],
        )
    )
    story.append(Spacer(1, 3))

    story.append(Paragraph("Stage 2: State Unification & Design System Primitives (Medium Effort — 3 to 4 Days)", styles["h2"]))
    story.append(
        Paragraph(
            "• <b>Implement Global Forensics Store:</b> Build <code>ForensicsContext</code> to hold active process scans, summary metrics, and isolated PIDs so navigation preserves analysis state.<br/>"
            "• <b>Wire Live Memory Map Feed:</b> Update the WebSocket listener to parse <code>type === 'memory_map'</code> frames and project real virtual address blocks onto the Live Process Map.<br/>"
            "• <b>Extract Shared UI Primitives:</b> Create reusable components for <code>Button</code>, <code>Card</code>, <code>StatusBadge</code>, <code>DataGrid</code>, and <code>Modal</code> to eliminate code duplication.<br/>"
            "• <b>Full Dark / SOC Theme Support:</b> Restore the signature <code>#0A0E1A</code> palette as the default dark mode with seamless light/dark toggling via CSS custom properties.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 3))

    story.append(Paragraph("Stage 3: Advanced Capabilities & Feature Panels (Large Effort — 4 to 6 Days)", styles["h2"]))
    story.append(
        Paragraph(
            "• <b>Build Docker Sandbox Panel:</b> Implement <code>src/app/sandbox/page.tsx</code> supporting binary submission, job UUID tracking, polling, and execution logs.<br/>"
            "• <b>Build Supply Chain Scanner Panel:</b> Implement <code>src/app/supply-chain/page.tsx</code> displaying live process DLL tables, Authenticode certificates, and SHA-256 copy helpers.<br/>"
            "• <b>Accessible Radar Navigation:</b> Pair the HTML5 canvas radar on <code>/live-map</code> with an accessible, keyboard-focusable DOM tree to ensure full keyboard navigation.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 6))

    # -----------------------------------------------------------------------
    # 8. Final Audit Sign-Off
    # -----------------------------------------------------------------------
    story.append(Paragraph("8. Final Audit Sign-Off", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=4))

    callout_box = (
        "<b>AUDIT VERDICT & CONCLUSION:</b><br/>"
        "The ShadowMem Next.js frontend has a clean build and static deployment pipeline, but suffers from significant architectural drift relative to the newly modernized backend. By following the staged 3-phase roadmap—aligning REST/WS protocols to <code>/api/v1</code>, unifying forensic state across routes, and implementing the proposed Sandbox and Supply Chain feature structures—the frontend can achieve true enterprise-grade SOC tool operational readiness."
    )
    story.append(make_callout(callout_box, styles, bg=LIGHT_BG, border=PRIMARY))

    # Build the document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Successfully generated: {OUTPUT_PDF}")


if __name__ == "__main__":
    build_pdf()
