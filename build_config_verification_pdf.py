"""
build_config_verification_pdf.py
================================
Generates a comprehensive, professional PDF report:
"ShadowMem — Config & Logging Deep Verification Report"
Documents the direct audit of core/config.py, core/logging.py, cross-check usage,
duplicate definitions in detecter.py, and live port override proof.
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
    Preformatted,
)
from reportlab.pdfgen import canvas

# ---------------------------------------------------------------------------
# Output configuration
# ---------------------------------------------------------------------------
OUTPUT_PDF = "ShadowMem_Config_Logging_Verification_Report.pdf"
GENERATED_AT = datetime.now().strftime("%B %d, %Y - %H:%M")

PAGE_W, PAGE_H = letter
MARGIN = 0.55 * inch
USABLE_W = PAGE_W - (2 * MARGIN)

PRIMARY = colors.HexColor("#0B3954")       # Deep Navy
SECONDARY = colors.HexColor("#087E8B")     # Dark Cyan / Teal
ACCENT = colors.HexColor("#BF3100")        # Rust Red
DARK = colors.HexColor("#0F172A")          # Slate 900
TEXT_MUTED = colors.HexColor("#475569")    # Slate 600
LIGHT_BG = colors.HexColor("#F8FAFC")      # Slate 50
ALT_ROW = colors.HexColor("#F1F5F9")       # Slate 100
BORDER_COL = colors.HexColor("#CBD5E1")    # Slate 300

PASS_BG = colors.HexColor("#DCFCE7")
PASS_TXT = colors.HexColor("#166534")
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
                "SHADOWMEM CORE CONFIG & LOGGING AUDIT REPORT",
            )
            self.drawRightString(
                PAGE_W - MARGIN,
                PAGE_H - 0.38 * inch,
                "DIRECT CODEBASE VERIFICATION & USAGE CHECK",
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
            f"CONFIDENTIAL & PROPRIETARY  |  Generated {GENERATED_AT}",
        )
        self.drawRightString(
            PAGE_W - MARGIN,
            0.32 * inch,
            f"Page {self._pageNumber} of {total_pages}",
        )
        self.restoreState()


def build_pdf():
    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=letter,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN,
    )

    base = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CoverTitle",
        parent=base["Title"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=PRIMARY,
        alignment=TA_LEFT,
    )
    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=11,
        leading=15,
        textColor=SECONDARY,
        alignment=TA_LEFT,
    )
    h1_style = ParagraphStyle(
        "Heading1_Custom",
        parent=base["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=PRIMARY,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True,
    )
    h2_style = ParagraphStyle(
        "Heading2_Custom",
        parent=base["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=SECONDARY,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "Body_Custom",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=8.0,
        leading=11.5,
        textColor=DARK,
        alignment=TA_JUSTIFY,
    )
    code_block_style = ParagraphStyle(
        "CodeBlock",
        parent=base["Normal"],
        fontName="Courier",
        fontSize=6.5,
        leading=8.5,
        textColor=DARK,
    )
    th_style = ParagraphStyle(
        "TableHeader",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.white,
    )
    td_style = ParagraphStyle(
        "TableCell",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=7.5,
        leading=10,
        textColor=DARK,
    )
    td_code = ParagraphStyle(
        "TableCellCode",
        parent=base["Normal"],
        fontName="Courier",
        fontSize=7.0,
        leading=9,
        textColor=DARK,
    )
    pass_style = ParagraphStyle(
        "PassCell",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9,
        textColor=PASS_TXT,
        alignment=TA_CENTER,
    )
    fail_style = ParagraphStyle(
        "FailCell",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=9,
        textColor=FAIL_TXT,
        alignment=TA_CENTER,
    )

    story = []

    # =========================================================================
    # HEADER BANNER
    # =========================================================================
    banner_data = [
        [Paragraph("<b>SHADOWMEM — CONFIG & LOGGING DEEP AUDIT REPORT</b>", title_style)],
        [Paragraph("Direct Codebase Verification: core/config.py, core/logging.py, Cross-Check Usage & Live Overrides", subtitle_style)],
        [Paragraph(f"<b>Audit Date:</b> {GENERATED_AT}  |  <b>Target Files:</b> core/config.py, core/logging.py, detecter.py  |  <b>Auditor:</b> Security Engineering", body_style)],
    ]
    banner_table = Table(banner_data, colWidths=[USABLE_W])
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 1.5, PRIMARY),
        ('PADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 3),
        ('BOTTOMPADDING', (0, 1), (-1, 1), 5),
    ]))
    story.append(banner_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 1. SCORECARD & EXECUTIVE VERDICT
    # =========================================================================
    story.append(Paragraph("1. Audit Scorecard & Executive Findings", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=6, spaceBefore=2))

    score_headers = [
        Paragraph("Check #", th_style),
        Paragraph("Verification Requirement", th_style),
        Paragraph("Observed Implementation State", th_style),
        Paragraph("Verdict", th_style),
    ]
    score_rows = [
        score_headers,
        [
            Paragraph("<b>Check 1</b>", td_style),
            Paragraph("core/config.py definitions & pydantic-settings BaseSettings", td_style),
            Paragraph("Contains all 19 configuration fields and .env / SHADOWMEM_* parsing, but inherits from <b>pydantic.BaseModel</b> rather than <code>pydantic_settings.BaseSettings</code> because pydantic-settings is not installed.", td_style),
            Paragraph("FAIL", fail_style),
        ],
        [
            Paragraph("<b>Check 2</b>", td_style),
            Paragraph("core/logging.py real structured logger setup", td_style),
            Paragraph("Configures formal root and app loggers, dedicated StreamHandler(sys.stdout), custom Formatter, and duplicate handler suppression.", td_style),
            Paragraph("PASS", pass_style),
        ],
        [
            Paragraph("<b>Check 3</b>", td_style),
            Paragraph("Codebase cross-check for hardcoded values", td_style),
            Paragraph("Production files (app.py, services/, routers/) are migrated; however, <b>detecter.py</b>, memoryscanner.py, and test scripts still contain hardcoded values.", td_style),
            Paragraph("FAIL", fail_style),
        ],
        [
            Paragraph("<b>Check 4</b>", td_style),
            Paragraph("Zero leftover duplicate definitions", td_style),
            Paragraph("<b>detecter.py</b> retains duplicate inline copies of JIT_ENGINE_ALLOWLIST, MANAGED_RUNTIME_NAMES, JIT_SCORE_CAP (25), and thresholds (70/35).", td_style),
            Paragraph("FAIL", fail_style),
        ],
        [
            Paragraph("<b>Check 5</b>", td_style),
            Paragraph("Live app startup with .env & env var override", td_style),
            Paragraph("Server dynamically bound to port <b>8765</b> via SHADOWMEM_PORT and port <b>8877</b> via .env file, returning HTTP 200 OK responses.", td_style),
            Paragraph("PASS", pass_style),
        ],
    ]
    score_table = Table(score_rows, colWidths=[0.7 * inch, 2.0 * inch, 3.8 * inch, 0.7 * inch])
    score_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COL),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COL),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('BACKGROUND', (3, 1), (3, 1), FAIL_BG),
        ('BACKGROUND', (3, 2), (3, 2), PASS_BG),
        ('BACKGROUND', (3, 3), (3, 3), FAIL_BG),
        ('BACKGROUND', (3, 4), (3, 4), FAIL_BG),
        ('BACKGROUND', (3, 5), (3, 5), PASS_BG),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, ALT_ROW]),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 2. CHECK 1: CORE/CONFIG.PY ANALYSIS
    # =========================================================================
    story.append(Paragraph("2. Check 1 Analysis: core/config.py Implementation", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=6, spaceBefore=2))

    c1_desc = (
        "<b>Direct Inspection Finding:</b> <code>core/config.py</code> implements a comprehensive "
        "configuration catalog covering 19 parameters across server, forensics, alert streaming, "
        "and future extensions. However, it <b>FAILS</b> the strict requirement to inherit from "
        "<code>pydantic_settings.BaseSettings</code>."
        "<br/><br/>"
        "• <b>BaseModel vs. BaseSettings:</b> The class is defined as <code>class Settings(BaseModel):</code>. "
        "The reason is that the <code>pydantic-settings</code> package is not installed in the virtual environment "
        "(only <code>pydantic 2.13.5</code> is present). To avoid a runtime crash, the module was implemented using "
        "standard Pydantic 2.x <code>BaseModel</code> coupled with custom loader functions.<br/>"
        "• <b>.env Loading Mechanism:</b> Implemented in <code>_load_env_file()</code> (lines 15–38), which parses "
        "the repo root <code>.env</code> file on initial module import and injects values into <code>os.environ</code>.<br/>"
        "• <b>Environment Variable Overrides:</b> Implemented in <code>_get_env()</code> (lines 45–52) and "
        "<code>Settings.load()</code> (lines 191–236), which searches for <code>SHADOWMEM_&lt;KEY&gt;</code> overrides."
    )
    story.append(Paragraph(c1_desc, body_style))
    story.append(Spacer(1, 6))

    # Catalog Table
    story.append(Paragraph("<b>Catalog of All 19 Configuration Parameters in core/config.py:</b>", h2_style))
    cat_headers = [Paragraph("Parameter Name", th_style), Paragraph("Type", th_style), Paragraph("Default Value", th_style), Paragraph("SHADOWMEM_ Override", th_style)]
    cat_rows = [
        cat_headers,
        [Paragraph("app_title / app_version", td_style), Paragraph("str", td_code), Paragraph("'ShadowMem' / '1.0.0'", td_code), Paragraph("SHADOWMEM_APP_TITLE", td_code)],
        [Paragraph("host / port", td_style), Paragraph("str / int", td_code), Paragraph("'0.0.0.0' / 8000", td_code), Paragraph("SHADOWMEM_HOST / PORT", td_code)],
        [Paragraph("reload / api_prefix", td_style), Paragraph("bool / str", td_code), Paragraph("False / '/api/v1'", td_code), Paragraph("SHADOWMEM_RELOAD / API_PREFIX", td_code)],
        [Paragraph("cors_origins", td_style), Paragraph("List[str]", td_code), Paragraph("['*']", td_code), Paragraph("SHADOWMEM_CORS_ORIGINS", td_code)],
        [Paragraph("frontend_dir", td_style), Paragraph("Path", td_code), Paragraph("frontend/out", td_code), Paragraph("Default path relative to root", td_code)],
        [Paragraph("model_path", td_style), Paragraph("Path", td_code), Paragraph("shadowmem_model.pkl", td_code), Paragraph("SHADOWMEM_MODEL_PATH", td_code)],
        [Paragraph("threshold_malicious", td_style), Paragraph("float", td_code), Paragraph("70.0", td_code), Paragraph("SHADOWMEM_THRESHOLD_MALICIOUS", td_code)],
        [Paragraph("threshold_suspicious", td_style), Paragraph("float", td_code), Paragraph("35.0", td_code), Paragraph("SHADOWMEM_THRESHOLD_SUSPICIOUS", td_code)],
        [Paragraph("jit_score_cap", td_style), Paragraph("float", td_code), Paragraph("25.0", td_code), Paragraph("SHADOWMEM_JIT_SCORE_CAP", td_code)],
        [Paragraph("jit_engine_allowlist", td_style), Paragraph("Set[str]", td_code), Paragraph("12 runtimes (chrome, msedge, code...)", td_style), Paragraph("SHADOWMEM_JIT_ENGINE_ALLOWLIST", td_code)],
        [Paragraph("managed_runtime_names", td_style), Paragraph("Set[str]", td_code), Paragraph("{powershell, pwsh, dotnet}", td_code), Paragraph("Hardcoded default set", td_code)],
        [Paragraph("managed_runtime_path_prefixes", td_style), Paragraph("Tuple[str]", td_code), Paragraph("('c:\\windows\\',)", td_code), Paragraph("Hardcoded default tuple", td_code)],
        [Paragraph("critical_system_processes", td_style), Paragraph("Set[str]", td_code), Paragraph("13 OS binaries (csrss, lsass, smss...)", td_style), Paragraph("Hardcoded default set", td_code)],
        [Paragraph("scan_interval_seconds", td_style), Paragraph("float", td_code), Paragraph("30.0", td_code), Paragraph("SHADOWMEM_SCAN_INTERVAL_SECONDS", td_code)],
        [Paragraph("threat_statuses", td_style), Paragraph("Tuple[str]", td_code), Paragraph("('Malicious (Injected)', 'Suspicious')", td_style), Paragraph("Hardcoded default tuple", td_code)],
        [Paragraph("max_region_details", td_style), Paragraph("int", td_code), Paragraph("16", td_code), Paragraph("Hardcoded default integer", td_code)],
        [Paragraph("log_level / log_format", td_style), Paragraph("str / str", td_code), Paragraph("'INFO' / Timestamped format", td_code), Paragraph("SHADOWMEM_LOG_LEVEL", td_code)],
        [Paragraph("docker_sandbox_enabled", td_style), Paragraph("bool", td_code), Paragraph("False", td_code), Paragraph("SHADOWMEM_DOCKER_SANDBOX_ENABLED", td_code)],
        [Paragraph("docker_sandbox_wsl_distro", td_style), Paragraph("str", td_code), Paragraph("'Ubuntu'", td_code), Paragraph("SHADOWMEM_DOCKER_WSL_DISTRO", td_code)],
        [Paragraph("supply_chain_scanner_enabled", td_style), Paragraph("bool", td_code), Paragraph("False", td_code), Paragraph("SHADOWMEM_SUPPLY_CHAIN_SCANNER_ENABLED", td_code)],
    ]
    cat_table = Table(cat_rows, colWidths=[1.8 * inch, 0.9 * inch, 2.3 * inch, 2.2 * inch])
    cat_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COL),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COL),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 2.5),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, ALT_ROW]),
    ]))
    story.append(cat_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 3. CHECK 2: CORE/LOGGING.PY ANALYSIS
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("3. Check 2 Analysis: core/logging.py Structured Logger", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=6, spaceBefore=2))

    c2_desc = (
        "<b>Direct Inspection Finding: PASS.</b> <code>core/logging.py</code> sets up a real structured "
        "logging pipeline rather than a bare <code>logging.basicConfig()</code> one-liner.<br/>"
        "• <b>Custom Stream Handler:</b> Explicitly instantiates a <code>logging.StreamHandler(sys.stdout)</code> "
        "and binds a uniform timestamped formatter: <code>%(asctime)s [ShadowMem] %(levelname)s [%(name)s] %(message)s</code>.<br/>"
        "• <b>Duplicate Handler Prevention:</b> Inspects <code>root_logger.handlers</code>. If handlers already exist "
        "(e.g. during Uvicorn reload or secondary module imports), it updates their level and format rather than "
        "stacking duplicate handlers that cause doubled log lines.<br/>"
        "• <b>Logger Namespace:</b> Exposes <code>logger = logging.getLogger('shadowmem')</code> and <code>get_logger(name)</code>."
    )
    story.append(Paragraph(c2_desc, body_style))
    story.append(Spacer(1, 8))

    # Full code of logging.py
    story.append(Paragraph("<b>Complete Code of core/logging.py (50 lines):</b>", h2_style))
    logging_code = (
        'import logging\n'
        'import sys\n'
        'from typing import Optional\n'
        'from core.config import settings\n\n'
        'def setup_logging(log_level: Optional[str] = None, log_format: Optional[str] = None) -> logging.Logger:\n'
        '    """Configure and return the root ShadowMem logger."""\n'
        '    level_name = (log_level or settings.log_level).upper()\n'
        '    level = getattr(logging, level_name, logging.INFO)\n'
        '    fmt = log_format or settings.log_format\n\n'
        '    root_logger = logging.getLogger()\n'
        '    root_logger.setLevel(level)\n\n'
        '    if not root_logger.handlers:\n'
        '        handler = logging.StreamHandler(sys.stdout)\n'
        '        handler.setLevel(level)\n'
        '        formatter = logging.Formatter(fmt)\n'
        '        handler.setFormatter(formatter)\n'
        '        root_logger.addHandler(handler)\n'
        '    else:\n'
        '        for handler in root_logger.handlers:\n'
        '            handler.setLevel(level)\n'
        '            handler.setFormatter(logging.Formatter(fmt))\n\n'
        '    app_logger = logging.getLogger("shadowmem")\n'
        '    app_logger.setLevel(level)\n'
        '    return app_logger\n\n'
        'def get_logger(name: str = "shadowmem") -> logging.Logger:\n'
        '    return logging.getLogger(name)\n\n'
        'logger = setup_logging()\n'
    )
    log_box = Table([[Preformatted(logging_code, code_block_style)]], colWidths=[USABLE_W])
    log_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COL),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(log_box)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 4. CHECKS 3 & 4: CROSS-CHECK USAGE & DUPLICATE DEFINITIONS
    # =========================================================================
    story.append(Paragraph("4. Checks 3 & 4 Analysis: Codebase Usage & Duplicate Definitions", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=6, spaceBefore=2))

    c3_desc = (
        "<b>Direct Inspection Finding: FAIL.</b> While all primary server and service files were successfully "
        "migrated to import from <code>core/config.py</code>, standalone tools and test harnesses were <b>NOT</b> "
        "migrated, resulting in leftover hardcoded values and duplicate definitions across the repository."
    )
    story.append(Paragraph(c3_desc, body_style))
    story.append(Spacer(1, 6))

    # Table of Unmigrated Hardcoded Values
    story.append(Paragraph("<b>Inventory of Unmigrated Files with Hardcoded Inline Values:</b>", h2_style))
    unmig_headers = [
        Paragraph("File Path", th_style),
        Paragraph("Line Numbers", th_style),
        Paragraph("Hardcoded Values / Definitions", th_style),
        Paragraph("Architectural Impact & Risk", th_style),
    ]
    unmig_rows = [
        unmig_headers,
        [
            Paragraph("<b>detecter.py</b><br/>(CLI Detection Tool)", td_style),
            Paragraph("Lines 8, 11–24, 26, 31–32, 111, 114", td_style),
            Paragraph(
                "• <code>MODEL_PATH = 'shadowmem_model.pkl'</code><br/>"
                "• <code>JIT_ENGINE_ALLOWLIST = { ... }</code> (13 browsers/tools)<br/>"
                "• <code>JIT_SCORE_CAP = 25</code><br/>"
                "• <code>MANAGED_RUNTIME_NAMES / PATH_PREFIXES</code><br/>"
                "• <code>threat_score &gt;= 70</code> and <code>&gt;= 35</code> (thresholds)",
                td_style
            ),
            Paragraph("<b>High Divergence Risk:</b> CLI detection tool operates on hardcoded constants and does not respect .env or SHADOWMEM_* overrides.", td_style),
        ],
        [
            Paragraph("<b>memoryscanner.py</b>", td_style),
            Paragraph("Line 33", td_style),
            Paragraph("<code>_MAX_REGION_DETAILS = 64</code>", td_code),
            Paragraph("Inconsistent cap: config.py defines <code>max_region_details = 16</code>, while memoryscanner.py caps at 64.", td_style),
        ],
        [
            Paragraph("<b>train_model.py</b>", td_style),
            Paragraph("Line 605", td_style),
            Paragraph("<code>output_path = 'shadowmem_model.pkl'</code>", td_code),
            Paragraph("Hardcoded artifact output path instead of referencing <code>settings.model_path</code>.", td_style),
        ],
        [
            Paragraph("<b>malware_simulator.py</b>", td_style),
            Paragraph("Lines 119–121", td_style),
            Paragraph("<code>PROTOTYPE_URL = 'http://localhost:8000'</code><br/><code>WEBSOCKET_URL = 'ws://localhost:8000/ws/alerts'</code>", td_code),
            Paragraph("Test harness cannot target dynamic ports configured via <code>SHADOWMEM_PORT</code> without manual file edits.", td_style),
        ],
        [
            Paragraph("<b>tests/mocks/server.py</b>", td_style),
            Paragraph("Lines 31, 290", td_style),
            Paragraph("<code>port = 8082</code>", td_code),
            Paragraph("Expected mock port, but hardcoded inline instead of via test configuration.", td_style),
        ],
        [
            Paragraph("<b>launch_shadowmem.bat</b>", td_style),
            Paragraph("Lines 14, 17", td_style),
            Paragraph("<code>http://127.0.0.1:8000</code> and <code>--port 8000</code>", td_code),
            Paragraph("Windows launcher batch script does not inspect <code>.env</code> file before launching browser.", td_style),
        ],
    ]
    unmig_table = Table(unmig_rows, colWidths=[1.5 * inch, 1.1 * inch, 2.7 * inch, 1.9 * inch])
    unmig_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), PRIMARY),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COL),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, BORDER_COL),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('PADDING', (0, 0), (-1, -1), 3.5),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, ALT_ROW]),
    ]))
    story.append(unmig_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 5. CHECK 5: LIVE STARTUP & PORT OVERRIDE VERIFICATION
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("5. Check 5 Analysis: Live Startup & Port Override Proof", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=6, spaceBefore=2))

    c5_desc = (
        "<b>Direct Inspection Finding: PASS.</b> The server was executed in live background processes under two "
        "distinct override conditions to prove that configuration loading is fully operational and binds dynamically."
    )
    story.append(Paragraph(c5_desc, body_style))
    story.append(Spacer(1, 6))

    # Test A Box
    story.append(Paragraph("<b>Test A: Environment Variable Override (SHADOWMEM_PORT=8765)</b>", h2_style))
    test_a_code = (
        "[COMMAND] python app.py  (with env SHADOWMEM_PORT=8765)\n"
        "[UVICORN LOGS]\n"
        "  INFO:     Started server process [3108]\n"
        "  INFO:     Waiting for application startup.\n"
        "  INFO:     Application startup complete.\n"
        "  INFO:     Uvicorn running on http://0.0.0.0:8765 (Press CTRL+C to quit)\n\n"
        "[HTTP REQUEST] GET http://127.0.0.1:8765/api/v1/sandbox/health\n"
        "[HTTP STATUS]  200 OK\n"
        "[RESPONSE BODY]\n"
        "  {\n"
        '    "enabled": false,\n'
        '    "wsl_distro": "Ubuntu",\n'
        '    "wsl_available": true,\n'
        '    "docker_ready": false,\n'
        '    "message": "Docker sandbox is disabled in configuration (SHADOWMEM_DOCKER_SANDBOX_ENABLED=false)."\n'
        "  }\n"
    )
    box_a = Table([[Preformatted(test_a_code, code_block_style)]], colWidths=[USABLE_W])
    box_a.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COL),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(box_a)
    story.append(Spacer(1, 8))

    # Test B Box
    story.append(Paragraph("<b>Test B: .env File Loading (SHADOWMEM_PORT=8877, SHADOWMEM_HOST=127.0.0.1)</b>", h2_style))
    test_b_code = (
        "[FILE CREATED] .env in repository root:\n"
        "  SHADOWMEM_PORT=8877\n"
        "  SHADOWMEM_HOST=127.0.0.1\n\n"
        "[COMMAND] python app.py\n"
        "[UVICORN LOGS]\n"
        "  INFO:     Started server process [11976]\n"
        "  INFO:     Waiting for application startup.\n"
        "  INFO:     Application startup complete.\n"
        "  INFO:     Uvicorn running on http://127.0.0.1:8877 (Press CTRL+C to quit)\n\n"
        "[HTTP REQUEST] GET http://127.0.0.1:8877/api/v1/supply-chain/health\n"
        "[HTTP STATUS]  200 OK\n"
        "[RESPONSE BODY]\n"
        "  {\n"
        '    "enabled": true,\n'
        '    "pefile_available": true,\n'
        '    "message": "Supply chain and module integrity scanner is active."\n'
        "  }\n"
    )
    box_b = Table([[Preformatted(test_b_code, code_block_style)]], colWidths=[USABLE_W])
    box_b.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), LIGHT_BG),
        ('BOX', (0, 0), (-1, -1), 0.5, BORDER_COL),
        ('PADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(box_b)
    story.append(Spacer(1, 10))

    # =========================================================================
    # 6. ACTIONABLE REMEDIATION RECOMMENDATIONS
    # =========================================================================
    story.append(Paragraph("6. Remediation Plan to Achieve 100% Pass", h1_style))
    story.append(HRFlowable(width="100%", thickness=1, color=PRIMARY, spaceAfter=6, spaceBefore=2))

    remed_desc = (
        "To resolve the three failed checks and bring configuration management to complete consistency:"
        "<br/><br/>"
        "1. <b>Install <code>pydantic-settings</code> and Refactor <code>Settings</code> (Fixes Check 1):</b><br/>"
        "   Execute <code>pip install pydantic-settings</code> and update <code>core/config.py</code> to use "
        "   <code>from pydantic_settings import BaseSettings, SettingsConfigDict</code> with "
        "   <code>model_config = SettingsConfigDict(env_prefix='SHADOWMEM_', env_file='.env', extra='ignore')</code>.<br/>"
        "2. <b>Migrate <code>detecter.py</code> to Import from <code>core/config.py</code> (Fixes Checks 3 & 4):</b><br/>"
        "   Replace hardcoded <code>JIT_ENGINE_ALLOWLIST</code>, <code>MANAGED_RUNTIME_NAMES</code>, "
        "   <code>JIT_SCORE_CAP</code>, and thresholds <code>70 / 35</code> in <code>detecter.py</code> with "
        "   <code>from core.config import settings</code> and reference <code>settings.threshold_malicious</code>, etc.<br/>"
        "3. <b>Synchronize <code>_MAX_REGION_DETAILS</code> in <code>memoryscanner.py</code> (Fixes Check 3):</b><br/>"
        "   Bind <code>_MAX_REGION_DETAILS</code> to <code>settings.max_region_details</code>.<br/>"
        "4. <b>Update <code>malware_simulator.py</code> & Launcher Scripts (Fixes Check 3):</b><br/>"
        "   Allow <code>malware_simulator.py</code> to read target port from <code>settings.port</code> rather than hardcoding port 8000."
    )
    story.append(Paragraph(remed_desc, body_style))

    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Report generated successfully: {OUTPUT_PDF}")


if __name__ == "__main__":
    build_pdf()
