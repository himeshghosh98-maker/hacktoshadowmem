"""Generate a focused summary PDF of the ShadowMem prototype."""

import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

OUTPUT = "ShadowMem_Summary.pdf"
NOW = datetime.now().strftime("%Y-%m-%d %H:%M")
PAGE_W, PAGE_H = letter
MARGIN = 0.62 * inch

ACCENT = colors.HexColor("#0B5394")
DARK = colors.HexColor("#0F172A")
GREY = colors.HexColor("#475569")
ROW_ALT = colors.HexColor("#F5F8FB")
BORDER = colors.HexColor("#C9D4E0")

SS = getSampleStyleSheet()

S_TITLE = ParagraphStyle("T", parent=SS["Title"], fontName="Helvetica-Bold",
    fontSize=20, leading=24, textColor=DARK, spaceAfter=2, alignment=TA_LEFT)
S_SUB = ParagraphStyle("Sub", parent=SS["Normal"], fontName="Helvetica",
    fontSize=10, leading=13, textColor=ACCENT, spaceAfter=8)
S_H1 = ParagraphStyle("H1", parent=SS["Heading1"], fontName="Helvetica-Bold",
    fontSize=13, leading=16, textColor=DARK, spaceBefore=12, spaceAfter=4)
S_H2 = ParagraphStyle("H2", parent=SS["Heading2"], fontName="Helvetica-Bold",
    fontSize=10.5, leading=13, textColor=ACCENT, spaceBefore=8, spaceAfter=3)
S_BODY = ParagraphStyle("Body", parent=SS["Normal"], fontName="Helvetica",
    fontSize=9, leading=12, textColor=DARK, spaceAfter=4)
S_BULLET = ParagraphStyle("Bul", parent=S_BODY, leftIndent=14, bulletIndent=4, spaceAfter=2.5)
S_CELL = ParagraphStyle("Cell", parent=S_BODY, fontSize=8, leading=10, spaceAfter=0)
S_CELL_B = ParagraphStyle("CellB", parent=S_CELL, fontName="Helvetica-Bold")
S_CELL_H = ParagraphStyle("CellH", parent=S_CELL, fontName="Helvetica-Bold", textColor=colors.white)


def P(text, style=S_BODY):
    return Paragraph(text, style)


def H1(text):
    return [Paragraph(text, S_H1),
            HRFlowable(width="100%", thickness=1.1, color=ACCENT, spaceAfter=6)]


def bullets(items):
    return [Paragraph(t, S_BULLET, bulletText="\u2022") for t in items]


def make_table(header, rows, col_widths):
    data = [[Paragraph(str(h), S_CELL_H) for h in header]]
    for row in rows:
        data.append([Paragraph(str(c), S_CELL if i else S_CELL_B) for i, c in enumerate(row)])
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]
    for r in range(2, len(data), 2):
        style.append(("BACKGROUND", (0, r), (-1, r), ROW_ALT))
    t.setStyle(TableStyle(style))
    return t


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(GREY)
    canvas.drawString(MARGIN, 0.38 * inch, f"ShadowMem Prototype Summary - {NOW}")
    canvas.drawRightString(PAGE_W - MARGIN, 0.38 * inch, f"Page {doc.page}")
    canvas.restoreState()


# ── Build story ──────────────────────────────────────────────────────────────
story = []

story.append(P("ShadowMem", S_TITLE))
story.append(P("Volatile Memory Forensics &amp; Fileless Malware Detection - Prototype Summary", S_SUB))

# 1. What it is
story += H1("1. What It Is")
story.append(P(
    "ShadowMem is a <b>Windows volatile memory forensics and fileless malware detection</b> "
    "prototype built with Python (FastAPI + scikit-learn). It scans all running processes' "
    "virtual address space to detect injection-based attacks without relying on disk artifacts."
))

# 2. Architecture
story += H1("2. Architecture")
arch_rows = [
    ["Scanner", "memoryscanner.py", "Uses Win32 APIs (VirtualQueryEx, NtQueryInformationThread) via ctypes to walk every process's VAD tree, counting RWX pages, unbacked executable regions, threads starting in unbacked memory, and VAD protection flips (RW->RX/RWX)."],
    ["ML Model", "train_model.py -> shadowmem_model.pkl", "Trains a 9-class HistGradientBoostingClassifier (RobustScaler + HGB pipeline) on synthetic forensic data. 7-feature vector: [rwx_count, unbacked_exec_count, total_rwx_bytes, num_threads, thread_unbacked_start, is_known_jit_parent, vad_protection_anomaly]. Includes canary sanity gates before saving."],
    ["Detection Engine", "app.py (evaluate_process)", "Feeds scanner output into the model, applies JIT allowlist suppression (browsers/Electron capped at 25%), managed runtime path validation (PowerShell only if under C:\\Windows), and classifies into Clean / Suspicious (>=35%) / Malicious (>=70%)."],
    ["SOC Dashboard", "app.py (embedded HTML) + index.html", "Cyberpunk-styled web UI with live scan results, threat posture gauge, VAD radar scope, process table with isolate/resume controls, and export-to-JSON."],
    ["WebSocket Streaming", "app.py (mock: tests/mocks/server.py)", "Live alerts and memory_map broadcasts are hosted entirely in app.py; server.py is preserved only as a mock fixture under tests/mocks/ for testing purposes, not a live server."],
]
story.append(make_table(["Layer", "File(s)", "Role"], arch_rows, [1.1*inch, 2.0*inch, 3.9*inch]))

# 3. ML Feature Vector
story += H1("3. ML Feature Vector (7 Features)")
feat_rows = [
    ["0", "rwx_count", "Count of PAGE_EXECUTE_READWRITE regions"],
    ["1", "unbacked_exec_count", "MEM_PRIVATE executable regions with no backing file"],
    ["2", "total_rwx_bytes", "Aggregate byte size of RWX allocations"],
    ["3", "num_threads", "Total active threads in the process"],
    ["4", "thread_unbacked_start", "# threads whose start address resolves into unbacked/private memory"],
    ["5", "is_known_jit_parent", "1 if process is a known JIT-capable runtime, else 0"],
    ["6", "vad_protection_anomaly", "Count of VAD regions transitioning RW -> RX/RWX"],
]
story.append(make_table(["#", "Feature", "Description"], feat_rows, [0.35*inch, 1.7*inch, 4.95*inch]))

# 4. Multi-Class Model
story += H1("4. Multi-Class Model (9 Classes)")
story.append(P("The model classifies processes into 5 benign and 4 malicious subclasses:"))
cls_rows = [
    ["benign_daemon (0)", "Benign", "Ordinary background system daemons/services"],
    ["benign_gui (1)", "Benign", "Multi-threaded GUI applications (office, IDEs)"],
    ["benign_jit (2)", "Benign", "JIT-compiling runtimes (Chromium/V8, Electron, JVM)"],
    ["benign_managed (3)", "Benign", "Managed .NET runtimes (PowerShell, pwsh, dotnet)"],
    ["benign_desktop (4)", "Benign", "Desktop apps outside JIT allowlist"],
    ["mal_reflective (5)", "Malicious", "Reflective DLL Injection - T1055.001"],
    ["mal_hollow (6)", "Malicious", "Process Hollowing - T1055.012"],
    ["mal_shellcode (7)", "Malicious", "Shellcode / C2 Beacon - T1620"],
    ["mal_hijack (8)", "Malicious", "Thread / APC Execution Hijacking - T1055.003"],
]
story.append(make_table(["Class", "Category", "Description"], cls_rows, [1.6*inch, 0.85*inch, 4.55*inch]))

# 5. Detection Signatures
story += H1("5. Malicious Technique Forensic Signatures")
sig_rows = [
    ["mal_reflective", "T1055.001", "3-5 unbacked regions, 1-2 unbacked thread starts, moderate VAD flips"],
    ["mal_hollow", "T1055.012", "5-10 unbacked regions, large RWX bytes (full PE unpack), 5-8 VAD flips"],
    ["mal_shellcode", "T1620", "1-3 small RWX regions, exactly 1 unbacked thread start, near-zero VAD flips"],
    ["mal_hijack", "T1055.003", "Minimal RWX, zero unbacked threads (reuses existing thread), 2-4 VAD flips"],
]
story.append(make_table(["Technique", "MITRE ID", "Key Forensic Signature"], sig_rows, [1.4*inch, 0.9*inch, 4.7*inch]))

# 6. Process Containment
story += H1("6. Process Containment")
story += bullets([
    "<b>Real suspend/resume</b> via POST /api/isolate/{pid} and POST /api/resume/{pid}",
    "Uses OpenThread + SuspendThread/ResumeThread (with NtSuspendProcess fallback)",
    "Blocklist protects critical system processes (csrss, lsass, services, etc.)",
    "In-memory audit trail logs every isolation action with timestamp",
])

# 7. Test Harnesses
story += H1("7. Test Harnesses")
harness_rows = [
    ["test_injector.py", "Safe in-process simulator: allocates RWX memory, performs RW->RWX VAD flip, spawns thread into unbacked memory (NOP sled + RET only, no actual shellcode)"],
    ["malware_simulator.py", "Extended simulator with 4 attack modes (shellcode, reflective DLL, process hollowing, thread hijack) that self-registers into live prototype via WebSocket/API"],
    ["test_sandbox.py", "Automated validation suite verifying detection accuracy across all attack modes and the 7-vector breakdown"],
]
story.append(make_table(["File", "Description"], harness_rows, [1.6*inch, 5.4*inch]))

# 8. Limitations
story += H1("8. Prototype Limitations")
story += bullets([
    "Trained entirely on <b>synthetic data</b> - no real malware samples used",
    "<b>Windows-only</b> (Win32 ctypes calls, VAD walking requires Windows kernel structures)",
    "Suspend/resume requires sufficient process privileges (non-admin cannot suspend SYSTEM processes)",
    "server.py is retired as a live server: it survives only as a <b>mock fixture</b> under tests/mocks/ for testing, while all WebSocket streaming (live alerts and memory_map broadcasts) runs in app.py",
    "Snapshot semantics: a single scan can miss transient beacons",
])

# 9. Tech Stack
story += H1("9. Technology Stack")
stack_rows = [
    ["Language", "Python 3.14 (Windows)"],
    ["Web Framework", "FastAPI + Uvicorn"],
    ["ML Library", "scikit-learn (HistGradientBoostingClassifier)"],
    ["System APIs", "Win32 via ctypes (VirtualQueryEx, NtQueryInformationThread, OpenThread)"],
    ["Process Info", "psutil"],
    ["Frontend", "Tailwind CSS CDN, JavaScript (WebSocket, Canvas API)"],
    ["PDF Generation", "reportlab"],
]
story.append(make_table(["Component", "Technology"], stack_rows, [1.5*inch, 5.5*inch]))

# 10. How to run
story += H1("10. How to Run")
run_rows = [
    ["Launch dashboard", "launch_shadowmem.bat (or: .venv\\Scripts\\activate && python -m uvicorn app:app --reload)"],
    ["Scan via API", "curl http://127.0.0.1:8000/api/scan"],
    ["CLI scan", "python detecter.py"],
    ["Retrain model", "python train_model.py"],
    ["Live-fire demo", "Terminal 1: python test_injector.py. Terminal 2: python detecter.py"],
    ["Safe malware sim", "python malware_simulator.py"],
]
story.append(make_table(["Task", "Command"], run_rows, [1.4*inch, 5.6*inch]))

# Build
doc = BaseDocTemplate(OUTPUT, pagesize=letter,
    leftMargin=MARGIN, rightMargin=MARGIN,
    topMargin=0.55*inch, bottomMargin=0.65*inch,
    title="ShadowMem Prototype Summary",
    author="ShadowMem")

frame = Frame(MARGIN, 0.65*inch, PAGE_W - 2*MARGIN, PAGE_H - 0.55*inch - 0.65*inch, id="main")
doc.addPageTemplates([PageTemplate(id="page", frames=[frame], onPage=footer)])
doc.build(story)

size_kb = os.path.getsize(OUTPUT) / 1024.0
print(f"[+] Wrote {OUTPUT} ({size_kb:.0f} KB, {doc.page} pages)")
