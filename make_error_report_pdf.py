"""
make_error_report_pdf.py -- ShadowMem Actionable Errors & Rectification Guide Generator
========================================================================================
Generates `ShadowMem_Errors_To_Fix.pdf`: a professional, publication-quality PDF
document detailing strictly the actionable errors/bugs found in the ShadowMem
codebase, along with their root causes, failure traces, and copy-paste ready code fixes.

Run:
    .venv/Scripts/python.exe make_error_report_pdf.py

Output:
    ShadowMem_Errors_To_Fix.pdf
"""

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    KeepTogether,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# ---------------------------------------------------------------------------
# Configuration & Palette
# ---------------------------------------------------------------------------

OUTPUT_PDF = "ShadowMem_Errors_To_Fix.pdf"
GENERATED_AT = datetime.now().strftime("%Y-%m-%d %H:%M")
PAGE_W, PAGE_H = letter
MARGIN = 0.55 * inch
USABLE_W = PAGE_W - 2 * MARGIN

# Colors
DARK = colors.HexColor("#0F172A")          # Slate 900
PRIMARY = colors.HexColor("#0B5394")       # Deep Tech Blue
PRIMARY_LIGHT = colors.HexColor("#EBF3FA") # Soft Blue tint
TEXT_MAIN = colors.HexColor("#1E293B")     # Slate 800
TEXT_MUTED = colors.HexColor("#64748B")    # Slate 500
BORDER = colors.HexColor("#CBD5E1")        # Slate 300
ROW_ALT = colors.HexColor("#F8FAFC")       # Slate 50

# Severity Colors
SEV_CRITICAL = colors.HexColor("#DC2626")  # Crimson Red
SEV_HIGH = colors.HexColor("#EA580C")      # Deep Amber/Orange
SEV_MEDIUM = colors.HexColor("#D97706")    # Warm Amber
SEV_LOW = colors.HexColor("#2563EB")       # Royal Blue
SEV_BG_CRIT = colors.HexColor("#FEF2F2")
CODE_BG = colors.HexColor("#F1F5F9")
CODE_BORDER = colors.HexColor("#CBD5E1")

# Styles
STYLES = getSampleStyleSheet()

S_TITLE = ParagraphStyle(
    "DocTitle",
    parent=STYLES["Title"],
    fontName="Helvetica-Bold",
    fontSize=18,
    leading=22,
    textColor=DARK,
    alignment=TA_LEFT,
    spaceAfter=2,
)

S_SUBTITLE = ParagraphStyle(
    "DocSub",
    parent=STYLES["Normal"],
    fontName="Helvetica-Bold",
    fontSize=9.5,
    leading=13,
    textColor=PRIMARY,
    spaceAfter=6,
)

S_META = ParagraphStyle(
    "DocMeta",
    parent=STYLES["Normal"],
    fontName="Helvetica",
    fontSize=7.8,
    leading=11,
    textColor=TEXT_MUTED,
    spaceAfter=8,
)

S_H1 = ParagraphStyle(
    "SectionH1",
    parent=STYLES["Heading1"],
    fontName="Helvetica-Bold",
    fontSize=12,
    leading=15,
    textColor=DARK,
    spaceBefore=10,
    spaceAfter=4,
)

S_H2 = ParagraphStyle(
    "ErrorH2",
    parent=STYLES["Heading2"],
    fontName="Helvetica-Bold",
    fontSize=10,
    leading=13,
    textColor=PRIMARY,
    spaceBefore=8,
    spaceAfter=3,
)

S_BODY = ParagraphStyle(
    "BodyTextCustom",
    parent=STYLES["Normal"],
    fontName="Helvetica",
    fontSize=8,
    leading=11.2,
    textColor=TEXT_MAIN,
    spaceAfter=3,
)

S_BULLET = ParagraphStyle(
    "BulletCustom",
    parent=S_BODY,
    leftIndent=12,
    bulletIndent=3,
    spaceAfter=2,
)

S_CODE = ParagraphStyle(
    "CodeBlock",
    parent=STYLES["Normal"],
    fontName="Courier",
    fontSize=7.2,
    leading=9.5,
    textColor=colors.HexColor("#0F172A"),
)

S_TRACE = ParagraphStyle(
    "TraceBlock",
    parent=STYLES["Normal"],
    fontName="Courier",
    fontSize=7,
    leading=9.2,
    textColor=colors.HexColor("#991B1B"),
)

S_CELL = ParagraphStyle(
    "TableCell",
    parent=STYLES["Normal"],
    fontName="Helvetica",
    fontSize=7.5,
    leading=9.8,
)

S_CELL_BOLD = ParagraphStyle(
    "TableCellB",
    parent=S_CELL,
    fontName="Helvetica-Bold",
)

S_CELL_HEADER = ParagraphStyle(
    "TableCellH",
    parent=S_CELL,
    fontName="Helvetica-Bold",
    textColor=colors.white,
)

# ---------------------------------------------------------------------------
# Flowable Helper Functions
# ---------------------------------------------------------------------------

def P(text, style=S_BODY):
    return Paragraph(text, style)

def H1(title):
    return [
        Paragraph(title, S_H1),
        HRFlowable(width="100%", thickness=1.0, color=PRIMARY, spaceBefore=2, spaceAfter=6),
    ]

def code_box(code_text, is_trace=False):
    style = S_TRACE if is_trace else S_CODE
    bg = colors.HexColor("#FFF5F5") if is_trace else CODE_BG
    border_col = colors.HexColor("#FECACA") if is_trace else CODE_BORDER
    
    lines = code_text.strip().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").split("\n")
    p_content = "<br/>".join(lines)
    p = Paragraph(p_content, style)
    
    t = Table([[p]], colWidths=[USABLE_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 0.5, border_col),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t

def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(TEXT_MUTED)
    canvas.drawString(MARGIN, 0.35 * inch, f"ShadowMem Actionable Errors & Rectification Report | Generated: {GENERATED_AT}")
    canvas.drawRightString(PAGE_W - MARGIN, 0.35 * inch, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf():
    story = []

    # -----------------------------------------------------------------------
    # Document Header
    # -----------------------------------------------------------------------
    story.append(P("ShadowMem — Codebase Errors & Actionable Rectification Guide", S_TITLE))
    story.append(P("Technical Root Causes, Reproduction Failures, and Copy-Paste Ready Fixes", S_SUBTITLE))
    story.append(P(
        f"<b>Target Repository:</b> c:\\Users\\Himesh\\Desktop\\ShadowMem &nbsp;|&nbsp; "
        f"<b>Audit Date:</b> {GENERATED_AT} &nbsp;|&nbsp; <b>Scope:</b> Rectification Guide Only",
        S_META
    ))
    story.append(HRFlowable(width="100%", thickness=1.2, color=PRIMARY, spaceBefore=0, spaceAfter=8))

    story.append(P(
        "This engineering report outlines all diagnosed bugs, runtime exceptions, handle leaks, test suite logic errors, "
        "and architectural inconsistencies identified in the ShadowMem repository. Each item includes the exact target file, "
        "line numbers, root cause explanation, exception trace, and copy-paste ready rectified code.",
        S_BODY
    ))
    story.append(Spacer(1, 4))

    # -----------------------------------------------------------------------
    # 1. Executive Error Summary Matrix
    # -----------------------------------------------------------------------
    story += H1("1. Executive Actionable Errors Matrix")

    summary_headers = ["ID", "Severity", "Target File & Lines", "Issue Description", "Runtime Impact"]
    summary_data = [
        [
            "ERR-01",
            "CRITICAL",
            "app.py<br/>388, 406, 477, 534,<br/>599, 603, 642, 694,<br/>757, 761",
            "wintypes.INVALID_HANDLE_VALUE &amp; NTSTATUS AttributeError. Neither attribute exists in ctypes.wintypes.",
            "Isolate/Resume crashes on real PIDs; handle cleanup in finally blocks fails silently, causing permanent kernel handle leaks."
        ],
        [
            "ERR-02",
            "CRITICAL",
            "app.py<br/>386",
            "for tid in proc.num_threads(): iterates over an integer instead of thread objects.",
            "Raises TypeError: 'int' object is not iterable on every containment call; breaks primary thread enumeration."
        ],
        [
            "ERR-03",
            "HIGH",
            "app.py<br/>2123",
            "CSS class 'pointer-events-none' added to modalIsolateBtn when process is suspended.",
            "Completely disables mouse clicks on 'Resume Process' button; operator is permanently locked out from resuming processes."
        ],
        [
            "ERR-04",
            "HIGH",
            "test_sandbox.py<br/>1-5, 185, 249-263",
            "Variable shadowing 'for _, passed in results', dict.get() NoneType AttributeError, and OpenMP thread explosion.",
            "Test runner reports '5 TESTS FAILED' and exits code 1 even when all tests pass; Test 6 crashes on clean scans."
        ],
        [
            "ERR-05",
            "MEDIUM",
            "test_fixes.py: 6<br/>malware_simulator.py: 366",
            "Hardcoded timeout=30 in urllib.request.urlopen for /api/scan endpoint.",
            "Full memory scan of 120+ processes takes ~33-36s; client aborts prematurely with TimeoutError: timed out."
        ],
        [
            "ERR-06",
            "MEDIUM",
            "malware_simulator.py<br/>104, 107, 341",
            "REFRESH_INTERVAL=5.0 triggers overlapping 33s scans; calls missing route /simulate/alert on app.py.",
            "Pins CPU at 100% due to accumulated concurrent scans; prints continuous HTTP 404 errors."
        ],
        [
            "ERR-07",
            "MEDIUM",
            "detecter.py: 118, 131<br/>make_guide.py: 246",
            "Windows Console UnicodeEncodeError on checkmark character (\\u2713 / ✓) in cp1252.",
            "CLI detection script and guide builder crash with UnicodeEncodeError upon completion on default Windows terminal."
        ],
        [
            "ERR-08",
            "LOW",
            "test_injector.py<br/>298-302",
            "Missing kernel32.CloseHandle(spin_thread) after thread termination in finally block.",
            "Open kernel thread handle is leaked during test execution until python process termination."
        ],
        [
            "ERR-09",
            "MEDIUM",
            "server.py vs app.py<br/>index.html, trigger_test_event.py",
            "Two disconnected server architectures: standalone mock WebSocket server vs real Win32 forensics engine.",
            "trigger_test_event.py and standalone index.html fail when launch_shadowmem.bat starts app.py."
        ],
    ]

    col_w = [42, 54, 105, 145, 156]
    table_rows = [[Paragraph(h, S_CELL_HEADER) for h in summary_headers]]
    for row in summary_data:
        sev_color = SEV_CRITICAL if row[1] == "CRITICAL" else (
            SEV_HIGH if row[1] == "HIGH" else (
                SEV_MEDIUM if row[1] == "MEDIUM" else SEV_LOW
            )
        )
        sev_style = ParagraphStyle("Sev", parent=S_CELL_BOLD, textColor=sev_color)
        table_rows.append([
            Paragraph(row[0], S_CELL_BOLD),
            Paragraph(row[1], sev_style),
            Paragraph(row[2], S_CELL),
            Paragraph(row[3], S_CELL),
            Paragraph(row[4], S_CELL),
        ])

    summary_table = Table(table_rows, colWidths=col_w, repeatRows=1)
    t_style = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]
    for r in range(1, len(table_rows)):
        if r % 2 == 0:
            t_style.append(("BACKGROUND", (0, r), (-1, r), ROW_ALT))
    summary_table.setStyle(TableStyle(t_style))
    story.append(summary_table)
    story.append(Spacer(1, 10))

    # -----------------------------------------------------------------------
    # 2. Deep Technical Breakdown & Rectification Guide
    # -----------------------------------------------------------------------
    story += H1("2. Technical Breakdown & Copy-Paste Ready Code Rectifications")

    # --- ERR-01 ---
    err1 = [
        Paragraph("ERR-01 [CRITICAL]: Invalid wintypes.INVALID_HANDLE_VALUE & NTSTATUS AttributeError Crash + Handle Leaks", S_H2),
        Paragraph("<b>Target File:</b> <font color='#0B5394'>app.py</font> (Lines 388, 406, 477, 534, 599, 603, 642, 694, 757, 761)", S_BODY),
        Paragraph(
            "<b>Root Cause:</b> Python's <code>ctypes.wintypes</code> module does NOT define <code>INVALID_HANDLE_VALUE</code> or <code>NTSTATUS</code>. "
            "When a valid process or thread handle is acquired, testing <code>handle == wintypes.INVALID_HANDLE_VALUE</code> immediately raises "
            "<code>AttributeError: module 'ctypes.wintypes' has no attribute 'INVALID_HANDLE_VALUE'</code>. "
            "In lines 599, 603, 757, and 761 (inside the <code>finally:</code> block), this error is swallowed by <code>except Exception: pass</code>, "
            "causing <code>_CLOSE_HANDLE(h)</code> to NEVER execute, permanently leaking kernel handles! "
            "Furthermore, lines 534 and 694 set <code>.restype = wintypes.NTSTATUS</code> which crashes, and improperly evaluate "
            "<code>if status &lt;= 0:</code> (in NTSTATUS, <code>0</code> is <code>STATUS_SUCCESS</code>, so success was treated as failure).",
            S_BODY
        ),
        Paragraph("<b>Reproduction Trace:</b>", S_BODY),
        code_box(
            "Traceback (most recent call last):\n"
            "  File \"app.py\", line 477, in api_isolate\n"
            "    if not handle or handle == wintypes.INVALID_HANDLE_VALUE:\n"
            "                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n"
            "AttributeError: module 'ctypes.wintypes' has no attribute 'INVALID_HANDLE_VALUE'",
            is_trace=True
        ),
        Spacer(1, 3),
        Paragraph("<b>Rectified Code for app.py:</b>", S_BODY),
        code_box(
            "# 1. In app.py around line 301, define INVALID_HANDLE_VALUE:\n"
            "from ctypes import wintypes\n"
            "INVALID_HANDLE_VALUE = -1  # or ctypes.c_void_p(-1).value\n\n"
            "# 2. In lines 477 and 642, check handle validity safely:\n"
            "handle = _OPEN_PROCESS(PROCESS_SUSPEND_RESUME, False, pid)\n"
            "if not handle or handle == INVALID_HANDLE_VALUE:\n"
            "    err = _K32.GetLastError()\n"
            "    # ... error handling ...\n\n"
            "# 3. In finally blocks (lines 598-605, 755-765), clean up handles without crashing:\n"
            "finally:\n"
            "    for h in handles:\n"
            "        try:\n"
            "            if h and h != INVALID_HANDLE_VALUE:\n"
            "                _CLOSE_HANDLE(h)\n"
            "        except Exception:\n"
            "            pass\n"
            "    if handle and handle != INVALID_HANDLE_VALUE:\n"
            "        try:\n"
            "            _CLOSE_HANDLE(handle)\n"
            "        except Exception:\n"
            "            pass\n\n"
            "# 4. In lines 533-536 and 693-696, fix NTSTATUS signature and check:\n"
            "_NtSuspendProcess.argtypes = (wintypes.HANDLE,)\n"
            "_NtSuspendProcess.restype = ctypes.c_long  # Use c_long instead of wintypes.NTSTATUS\n"
            "status = _NtSuspendProcess(handle)\n"
            "if status != 0:  # 0 is STATUS_SUCCESS in NTSTATUS\n"
            "    pass\n"
            "else:\n"
            "    suspended = max(suspended, 1)"
        ),
    ]
    story.append(KeepTogether(err1))
    story.append(Spacer(1, 8))

    # --- ERR-02 ---
    err2 = [
        Paragraph("ERR-02 [CRITICAL]: TypeError on Thread Enumeration (proc.num_threads() in for loop)", S_H2),
        Paragraph("<b>Target File:</b> <font color='#0B5394'>app.py</font> (Line 386 in _iter_threads)", S_BODY),
        Paragraph(
            "<b>Root Cause:</b> Line 386 attempts to iterate over <code>proc.num_threads()</code>: "
            "<code>for tid in proc.num_threads():</code>. The psutil method <code>proc.num_threads()</code> returns a single integer "
            "(e.g., <code>14</code>). In Python, integers are not iterable. This triggers an immediate <code>TypeError</code> on every call, "
            "completely breaking primary thread enumeration.",
            S_BODY
        ),
        Paragraph("<b>Reproduction Trace:</b>", S_BODY),
        code_box(
            "TypeError: 'int' object is not iterable\n"
            "  File \"app.py\", line 386, in _iter_threads\n"
            "    for tid in proc.num_threads():",
            is_trace=True
        ),
        Spacer(1, 3),
        Paragraph("<b>Rectified Code for app.py (lines 383-394):</b>", S_BODY),
        code_box(
            "    if _psutil is not None:\n"
            "        try:\n"
            "            proc = _psutil.Process(pid)\n"
            "            for td in proc.threads():  # Iterate over thread objects, NOT proc.num_threads()\n"
            "                h = _OPEN_THREAD(THREAD_SUSPEND_RESUME, False, td.id)\n"
            "                if h and h != INVALID_HANDLE_VALUE:\n"
            "                    yield td.id, h\n"
            "                    continue\n"
            "        except Exception:\n"
            "            pass"
        ),
    ]
    story.append(KeepTogether(err2))
    story.append(Spacer(1, 8))

    # --- ERR-03 ---
    err3 = [
        Paragraph("ERR-03 [HIGH]: Process Containment Button UI Lockout (app.py)", S_H2),
        Paragraph("<b>Target File:</b> <font color='#0B5394'>app.py</font> (Line 2123 in setIsolateUI)", S_BODY),
        Paragraph(
            "<b>Root Cause:</b> When an operator suspends an anomalous process from the web dashboard, <code>setIsolateUI(pid, true)</code> executes. "
            "Line 2123 applies the Tailwind CSS utility class <code>pointer-events-none</code> to <code>modalIsolateBtn</code> while changing "
            "its label to 'Resume Process'. The <code>pointer-events-none</code> rule disables all mouse click events. As a result, the operator "
            "is permanently locked out from clicking 'Resume Process' until they refresh the browser page.",
            S_BODY
        ),
        Paragraph("<b>Rectified Code for app.py (lines 2119-2139):</b>", S_BODY),
        code_box(
            "function setIsolateUI(pid, suspended) {\n"
            "  if (suspended) {\n"
            "    isolatedPids.add(pid);\n"
            "    modalIsolatedBadge.classList.remove('hidden');\n"
            "    modalIsolateBtn.classList.remove('pointer-events-none'); // DO NOT disable pointer-events\n"
            "    modalIsolateBtn.innerHTML =\n"
            "      '<svg class=\"w-3.5 h-3.5 text-ok\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\" stroke-width=\"2\">'\n"
            "      + '<path stroke-linecap=\"round\" stroke-linejoin=\"round\" d=\"M5 13l4 4L19 7\" />'\n"
            "      + '</svg>'\n"
            "      + '<span>Resume Process</span>';\n"
            "  } else {\n"
            "    isolatedPids.delete(pid);\n"
            "    modalIsolatedBadge.classList.add('hidden');\n"
            "    modalIsolateBtn.classList.remove('opacity-50', 'pointer-events-none');\n"
            "    modalIsolateBtn.innerHTML =\n"
            "      '<svg class=\"w-3.5 h-3.5 text-warn\" fill=\"none\" viewBox=\"0 0 24 24\" stroke=\"currentColor\" stroke-width=\"2\">'\n"
            "      + '<path stroke-linecap=\"round\" stroke-linejoin=\"round\" d=\"M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636\" />'\n"
            "      + '</svg>'\n"
            "      + '<span>Isolate Process</span>';\n"
            "  }\n"
            "}"
        ),
    ]
    story.append(KeepTogether(err3))
    story.append(Spacer(1, 8))

    # --- ERR-04 ---
    err4 = [
        Paragraph("ERR-04 [HIGH]: Variable Shadowing, AttributeError & Thread Count Inflation (test_sandbox.py)", S_H2),
        Paragraph("<b>Target File:</b> <font color='#0B5394'>test_sandbox.py</font> (Lines 1-5, 185, 249-263)", S_BODY),
        Paragraph(
            "<b>Root Cause 1 (Shadowing):</b> In <code>main()</code>, line 249 calculates <code>passed = sum(...)</code>. Line 252 reuses <code>passed</code>: "
            "<code>for test_name, passed in results:</code>. This overwrites the integer tally with a boolean (<code>True</code>). At line 258, "
            "<code>if passed == total:</code> evaluates <code>True == 6</code> (False), reporting <code>'*** 5 TESTS FAILED'</code> and exiting with code 1.<br/>"
            "<b>Root Cause 2 (NoneType):</b> In Test 6, <code>result.get('classification', {})</code> returns <code>None</code> because the key exists with "
            "a <code>None</code> value. Calling <code>classification.get(...)</code> raises <code>AttributeError: 'NoneType' object has no attribute 'get'</code>.<br/>"
            "<b>Root Cause 3 (Thread Accumulation):</b> Running tests sequentially accumulates NumPy/OpenMP worker threads up to 45 threads in the runner PID. "
            "The ML model treats processes with &gt;35 threads as benign, suppressing the threat score to 9% and setting <code>classification: None</code>.",
            S_BODY
        ),
        Paragraph("<b>Rectified Code for test_sandbox.py:</b>", S_BODY),
        code_box(
            "# 1. Add at top of test_sandbox.py (before importing numpy/sklearn/app):\n"
            "import os\n"
            "os.environ['OMP_NUM_THREADS'] = '1'\n"
            "os.environ['OPENBLAS_NUM_THREADS'] = '1'\n"
            "os.environ['MKL_NUM_THREADS'] = '1'\n\n"
            "# 2. In line 185 (test_technique_classification):\n"
            "classification = result.get('classification') or {}\n\n"
            "# 3. In lines 249-263 (fix shadowing):\n"
            "passed_count = sum(1 for _, p in results if p)\n"
            "total_count = len(results)\n"
            "for test_name, test_status in results:  # Renamed loop variable to avoid shadowing\n"
            "    status = 'PASS' if test_status else 'FAIL'\n"
            "    print(f'  [{status}] {test_name}')\n"
            "print(f'\\nTotal: {passed_count}/{total_count} test suites passed')\n"
            "if passed_count == total_count:\n"
            "    print('\\n*** ALL TESTS PASSED - Sandbox is working correctly ***')\n"
            "    return 0\n"
            "else:\n"
            "    print(f'\\n*** {total_count - passed_count} TESTS FAILED - Review needed ***')\n"
            "    return 1"
        ),
    ]
    story.append(KeepTogether(err4))
    story.append(Spacer(1, 8))

    # --- ERR-05 ---
    err5 = [
        Paragraph("ERR-05 [MEDIUM]: Premature Socket Timeout on Full Memory Scans (test_fixes.py & malware_simulator.py)", S_H2),
        Paragraph("<b>Target Files:</b> <font color='#0B5394'>test_fixes.py</font> (Line 6), <font color='#0B5394'>malware_simulator.py</font> (Line 366)", S_BODY),
        Paragraph(
            "<b>Root Cause:</b> Both files configure <code>timeout=30</code> in <code>urllib.request.urlopen</code>. "
            "On a live Windows 11 system with 120-150 active processes, walking all process address spaces via Win32 VirtualQueryEx "
            "and NtQueryInformationThread requires approximately 33 to 36 seconds. The client triggers a premature <code>TimeoutError: timed out</code> "
            "even though the backend API is working normally.",
            S_BODY
        ),
        Paragraph("<b>Rectified Code:</b>", S_BODY),
        code_box(
            "# In test_fixes.py line 6:\n"
            "r = urllib.request.urlopen('http://127.0.0.1:8000/api/scan', timeout=60)\n\n"
            "# In malware_simulator.py line 366:\n"
            "with urllib.request.urlopen(req, timeout=60) as resp:"
        ),
    ]
    story.append(KeepTogether(err5))
    story.append(Spacer(1, 8))

    # --- ERR-06 ---
    err6 = [
        Paragraph("ERR-06 [MEDIUM]: Scan Flooding (5s Interval) & Missing /simulate/alert Route (malware_simulator.py)", S_H2),
        Paragraph("<b>Target File:</b> <font color='#0B5394'>malware_simulator.py</font> (Lines 104, 107, 341-357)", S_BODY),
        Paragraph(
            "<b>Root Cause:</b> <code>REFRESH_INTERVAL = 5.0</code> spawns a scan every 5 seconds. Because full memory scans take ~33s, "
            "6 to 7 scans accumulate concurrently, driving CPU usage to 100% and starving the Uvicorn server. "
            "Additionally, <code>DISPLAY_MODE = 'both'</code> attempts to POST to <code>/simulate/alert</code>, which does not exist on app.py, "
            "spitting out continuous HTTP 404 errors.",
            S_BODY
        ),
        Paragraph("<b>Rectified Code for malware_simulator.py (lines 104-107):</b>", S_BODY),
        code_box(
            "# Set DISPLAY_MODE to 'scanner' for app.py prototype (or 'alerts' for server.py mock):\n"
            "DISPLAY_MODE = 'scanner'\n\n"
            "# Set interval greater than the 33s scan duration to prevent thread pile-up:\n"
            "REFRESH_INTERVAL = 45.0"
        ),
    ]
    story.append(KeepTogether(err6))
    story.append(Spacer(1, 8))

    # --- ERR-07 ---
    err7 = [
        Paragraph("ERR-07 [MEDIUM]: Windows Console UnicodeEncodeError on Checkmark Character (\\u2713 / ✓)", S_H2),
        Paragraph("<b>Target Files:</b> <font color='#0B5394'>detecter.py</font> (Lines 118, 131), <font color='#0B5394'>make_guide.py</font> (Line 246)", S_BODY),
        Paragraph(
            "<b>Root Cause:</b> On Microsoft Windows, stdout in cmd.exe/PowerShell defaults to Code Page 1252 (cp1252). "
            "The Unicode checkmark character <code>\\u2713</code> ('✓') cannot be mapped to any cp1252 byte value. "
            "When a scan completes with 0 threats detected, <code>detecter.py</code> executes <code>print('\\n[✓] Scan complete...')</code>, "
            "crashing with <code>UnicodeEncodeError: 'charmap' codec can't encode character '\\u2713'</code>. <code>make_guide.py</code> has the exact same crash.",
            S_BODY
        ),
        Paragraph("<b>Rectified Code:</b>", S_BODY),
        code_box(
            "# In detecter.py line 118:\n"
            "    verdict = \"[OK] CLEAN\"\n\n"
            "# In detecter.py line 131:\n"
            "    if threat_count == 0:\n"
            "        print(\"\\n[+] Scan complete: No active fileless injections detected.\")\n\n"
            "# In make_guide.py line 246:\n"
            "print(\"[+] Updated presentation_guide.html with complete master guide!\")"
        ),
    ]
    story.append(KeepTogether(err7))
    story.append(Spacer(1, 8))

    # --- ERR-08 ---
    err8 = [
        Paragraph("ERR-08 [LOW]: Kernel Thread Handle Leak in test_injector.py", S_H2),
        Paragraph("<b>Target File:</b> <font color='#0B5394'>test_injector.py</font> (Lines 298-302)", S_BODY),
        Paragraph(
            "<b>Root Cause:</b> <code>spin_thread = kernel32.CreateThread(...)</code> creates a raw thread handle. "
            "In the <code>finally:</code> block, <code>kernel32.TerminateThread(spin_thread, 0)</code> is called, but "
            "<code>kernel32.CloseHandle(spin_thread)</code> is omitted, leaving an unclosed kernel handle open in Windows kernel memory.",
            S_BODY
        ),
        Paragraph("<b>Rectified Code for test_injector.py (lines 298-303):</b>", S_BODY),
        code_box(
            "        try:\n"
            "            if kernel32.TerminateThread(spin_thread, 0):\n"
            "                print(\"[*] Raw spin thread terminated.\")\n"
            "            kernel32.CloseHandle(spin_thread)  # Close the open kernel handle\n"
            "        except Exception:\n"
            "            pass"
        ),
    ]
    story.append(KeepTogether(err8))
    story.append(Spacer(1, 8))

    # --- ERR-09 ---
    err9 = [
        Paragraph("ERR-09 [MEDIUM]: Dual Divergent Server Architectures (server.py vs app.py)", S_H2),
        Paragraph("<b>Target Files:</b> <font color='#0B5394'>server.py</font>, <font color='#0B5394'>app.py</font>, <font color='#0B5394'>index.html</font>, <font color='#0B5394'>trigger_test_event.py</font>", S_BODY),
        Paragraph(
            "<b>Root Cause:</b> The repository contains two incompatible backend servers:<br/>"
            "1. <b>Real Engine (app.py):</b> Runs genuine Win32 VirtualQueryEx memory scanning, scikit-learn ML inference, "
            "thread isolation/containment endpoints, and serves an embedded single-page UI at GET /.<br/>"
            "2. <b>Mock Server (server.py):</b> Synthetic alert generator broadcasting JSON events over WebSocket (/ws/alerts) "
            "for the standalone index.html, with a /simulate/alert endpoint.<br/>"
            "Because launch_shadowmem.bat runs app.py, running trigger_test_event.py fails with HTTP 404, and index.html fails to connect to WebSockets.",
            S_BODY
        ),
        Paragraph("<b>Rectification Recommendation:</b>", S_BODY),
        Paragraph(
            "• Establish <b>app.py</b> as the single authoritative application.<br/>"
            "• If WebSocket alerts are desired in the main UI, migrate <code>server.py</code>'s <code>/ws/alerts</code> and <code>/simulate/alert</code> routes into <code>app.py</code>.<br/>"
            "• Clarify in documentation and scripts that <code>server.py</code> is a mock testing stub.",
            S_BODY
        ),
    ]
    story.append(KeepTogether(err9))
    story.append(Spacer(1, 10))

    # -----------------------------------------------------------------------
    # 3. Step-by-Step Verification Checklist
    # -----------------------------------------------------------------------
    story += H1("3. Verification Checklist After Applying Fixes")
    checklist_items = [
        "<b>1. Console Script Check:</b> Run <code>.\\.venv\\Scripts\\python.exe detecter.py</code>. Ensure it completes with <code>[+] Scan complete</code> without UnicodeEncodeError.",
        "<b>2. Sandbox Test Suite:</b> Run <code>.\\.venv\\Scripts\\python.exe test_sandbox.py</code>. All 6 test suites must PASS and exit with code 0.",
        "<b>3. Live Scan &amp; Containment Test:</b> With <code>app.py</code> running, run <code>.\\.venv\\Scripts\\python.exe test_fixes.py</code>. The memory scan must complete within 60s without socket timeouts.",
        "<b>4. Real Process Isolation Test:</b> Test isolating a non-critical test process via <code>POST /api/isolate/{pid}</code>. Verify that handles are closed properly and no <code>AttributeError</code> is raised.",
        "<b>5. UI Resume Button Test:</b> Open <code>http://127.0.0.1:8000</code>, scan, inspect an anomaly, click 'Isolate Process'. Confirm the button updates to 'Resume Process' and remains clickable.",
    ]
    for item in checklist_items:
        story.append(Paragraph(item, S_BULLET, bulletText="[ ]"))
        story.append(Spacer(1, 2))

    # -----------------------------------------------------------------------
    # Build Document
    # -----------------------------------------------------------------------
    doc = BaseDocTemplate(
        OUTPUT_PDF,
        pagesize=letter,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=0.5 * inch,
        bottomMargin=0.55 * inch,
        title="ShadowMem - Actionable Codebase Errors & Rectification Guide",
        author="ShadowMem AI Engineering",
    )
    frame = Frame(MARGIN, 0.55 * inch, USABLE_W, PAGE_H - 1.05 * inch, id="normal")
    template = PageTemplate(id="main_template", frames=frame, onPage=footer)
    doc.addPageTemplates([template])

    doc.build(story)
    size_kb = os.path.getsize(OUTPUT_PDF) / 1024.0
    print(f"[+] Successfully generated {OUTPUT_PDF} ({size_kb:.1f} KB, {doc.page} pages).")


if __name__ == "__main__":
    build_pdf()
