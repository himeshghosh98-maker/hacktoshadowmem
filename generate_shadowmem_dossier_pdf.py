"""
generate_shadowmem_dossier_pdf.py
==================================
Generates an executive, publication-grade PDF report of ShadowMem:
Architecture, Win32 Memory Forensics, ML Pipeline, Explainability, MITRE ATT&CK,
and Evaluation Demo Playbook.
"""

import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether,
)
from reportlab.pdfgen import canvas

OUTPUT_PDF = "ShadowMem_Complete_Architecture_Dossier.pdf"

# Color Palette (Refined SOC Warm Theme)
PRIMARY = colors.HexColor("#1A202C")
SECONDARY = colors.HexColor("#E8793C")  # Warm Orange Accent
ACCENT_BLUE = colors.HexColor("#2B6CB0")
BG_CARD = colors.HexColor("#FAF7F2")
BG_HIGHLIGHT = colors.HexColor("#FFF8F3")
BORDER_COLOR = colors.HexColor("#E2E8F0")
TEXT_MUTED = colors.HexColor("#718096")
THREAT_MALICIOUS = colors.HexColor("#D6453D")
THREAT_SUSPICIOUS = colors.HexColor("#E68A2E")
THREAT_CLEAN = colors.HexColor("#3D8B60")


class NumberedCanvas(canvas.Canvas):
    """Canvas that performs a two-pass rendering to dynamically compute total pages."""
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

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(TEXT_MUTED)

        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, letter[1] - 36, "ShadowMem — Volatile Memory Forensics & Fileless Malware Detection")
            self.setStrokeColor(BORDER_COLOR)
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)

        # Footer
        footer_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 54, 34, footer_text)
        self.drawString(54, 34, "CONFIDENTIAL — CYBER DEFENSE OPERATIONS & FORENSIC SPECIFICATION")
        self.setStrokeColor(BORDER_COLOR)
        self.setLineWidth(0.5)
        self.line(54, 46, letter[0] - 54, 46)
        self.restoreState()


def build_pdf():
    pdf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), OUTPUT_PDF)
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom Typography
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=PRIMARY,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=SECONDARY,
        spaceAfter=15,
    )
    meta_style = ParagraphStyle(
        "DocMeta",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=TEXT_MUTED,
    )
    h1_style = ParagraphStyle(
        "Heading1_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=18,
        textColor=PRIMARY,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )
    h2_style = ParagraphStyle(
        "Heading2_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=15,
        textColor=SECONDARY,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=14,
        textColor=PRIMARY,
        spaceAfter=6,
    )
    bullet_style = ParagraphStyle(
        "Bullet_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13.5,
        textColor=PRIMARY,
        leftIndent=15,
        spaceAfter=4,
    )
    code_style = ParagraphStyle(
        "Code_Custom",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=11.5,
        textColor=colors.HexColor("#2D3748"),
    )
    table_cell = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11.5,
        textColor=PRIMARY,
    )
    table_header = ParagraphStyle(
        "TableHeader",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11.5,
        textColor=colors.white,
    )

    story = []

    # Title & Header Block
    story.append(Paragraph("ShadowMem 🛡️", title_style))
    story.append(Paragraph("Automated Volatile Memory Forensics & Fileless Malware Detection", subtitle_style))
    story.append(
        Paragraph(
            f"<b>Platform:</b> Windows 10/11 x64 &nbsp;|&nbsp; <b>Backend:</b> FastAPI & Python 3.13 &nbsp;|&nbsp; <b>Frontend:</b> Next.js 14 SOC &nbsp;|&nbsp; <b>Generated:</b> {datetime.now().strftime('%B %d, %Y')}",
            meta_style,
        )
    )
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=SECONDARY, spaceAfter=14))

    # 1. Executive Summary
    story.append(Paragraph("1. Executive Summary & Problem Space", h1_style))
    story.append(
        Paragraph(
            "Modern threat actors, advanced persistent threats (APTs), and ransomware operators increasingly employ "
            "<b>fileless attack techniques</b>—operating entirely inside system RAM without writing a single binary to disk. "
            "Conventional signature-based endpoint detection mechanisms that rely on file hashes and disk traversal "
            "remain blind to these techniques. ShadowMem bridges this security chasm by directly introspecting 64-bit "
            "Windows process Virtual Address Descriptors (VAD), thread start addresses, and memory protection transitions in real-time.",
            body_style,
        )
    )

    # 2. System Architecture
    story.append(Paragraph("2. System Architecture & Dual-Tier Design", h1_style))
    story.append(
        Paragraph(
            "ShadowMem is architected as an authoritative, dual-tier platform engineered for speed, low overhead, and forensic rigor:",
            body_style,
        )
    )
    story.append(Paragraph("• <b>Authoritative FastAPI Kernel:</b> Exposes RESTful forensic endpoints, real-time WebSocket feeds, and Win32 ctypes memory bindings.", bullet_style))
    story.append(Paragraph("• <b>Compiled Next.js 14 Dashboard:</b> Pre-rendered to pure static assets, hosted directly by FastAPI on port 8000 with zero separate Node.js server required at runtime.", bullet_style))
    story.append(Paragraph("• <b>Parallel Introspection Engine:</b> Thread-pooled VirtualQueryEx traversal scanning 150+ processes across all user-space memory in ~21 seconds.", bullet_style))

    # Architecture Overview Table
    arch_data = [
        [Paragraph("Component", table_header), Paragraph("Technology / Module", table_header), Paragraph("Key Role in Forensic Pipeline", table_header)],
        [Paragraph("VAD Walker", table_cell), Paragraph("<code>memoryscanner.py</code> (Win32 ctypes)", table_cell), Paragraph("Traverses process virtual address space via VirtualQueryEx; detects unbacked private executable allocations.", table_cell)],
        [Paragraph("Thread Inspector", table_cell), Paragraph("<code>ntdll.dll</code> (ThreadQuerySetWin32StartAddress)", table_cell), Paragraph("Queries thread instruction entry points; detects execution spawned in dynamic memory buffers.", table_cell)],
        [Paragraph("Classifier Pipeline", table_cell), Paragraph("<code>services/forensics.py</code> & ML model", table_cell), Paragraph("Evaluates 7-dimensional forensic telemetry vector; applies JIT compiler false-positive suppression.", table_cell)],
        [Paragraph("Explainable AI (XAI)", table_cell), Paragraph("Feature Attribution Engine", table_cell), Paragraph("Calculates percentage contribution of each feature to threat score with forensic rationale.", table_cell)],
        [Paragraph("Memory Hex Dumper", table_cell), Paragraph("<code>ReadProcessMemory</code> API", table_cell), Paragraph("Extracts 256-byte slice of suspect memory; computes Shannon entropy and detects shellcode preambles.", table_cell)],
        [Paragraph("Surgical Containment", table_cell), Paragraph("<code>services/containment.py</code>", table_cell), Paragraph("Executes thread-level suspension via SuspendThread without crashing system stability.", table_cell)],
    ]
    arch_table = Table(arch_data, colWidths=[1.3 * inch, 2.2 * inch, 3.5 * inch])
    arch_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_CARD]),
        ])
    )
    story.append(Spacer(1, 4))
    story.append(arch_table)
    story.append(Spacer(1, 10))

    # 3. Low-Level Win32 Memory Forensics
    story.append(Paragraph("3. Low-Level Win32 Memory Forensics Engine", h1_style))
    story.append(
        Paragraph(
            "The memory inspection subsystem directly queries the Windows kernel subsystem via Win32 C APIs:",
            body_style,
        )
    )
    story.append(Paragraph("• <b>Unbacked Executable Memory:</b> When memory allocations have <code>MEM_COMMIT</code> + <code>MEM_PRIVATE</code> with execution privileges (<code>PAGE_EXECUTE_READWRITE</code> or <code>PAGE_EXECUTE_READ</code>), they lack backing from an on-disk image file. This is the primary indicator of staged payloads and reflective DLLs.", bullet_style))
    story.append(Paragraph("• <b>Protection Transition Anomaly:</b> Malware commonly allocates <code>PAGE_READWRITE</code> memory, copies encrypted shellcode, then flips the region to executable via <code>VirtualProtect</code>. ShadowMem flags allocations where <code>AllocationProtect == PAGE_READWRITE</code> but <code>Protect</code> is executable.", bullet_style))
    story.append(Paragraph("• <b>Thread Start Verification:</b> Queries <code>NtQueryInformationThread</code> class 9. If a thread's start address resolves within an unbacked dynamic memory page, execution hijacking is confirmed.", bullet_style))
    story.append(Paragraph("• <b>Shannon Entropy Slicing:</b> Safely reads 256 bytes via <code>ReadProcessMemory</code> and computes entropy <i>H(X)</i>. Values approaching 8.0 confirm encrypted or compressed shellcode (e.g. Cobalt Strike beacon headers).", bullet_style))

    # 4. Machine Learning & Explainability
    story.append(Paragraph("4. 7-Feature ML Model & Explainable AI (XAI)", h1_style))
    story.append(
        Paragraph(
            "ShadowMem constructs a 7-dimensional forensic telemetry vector per process for inference:",
            body_style,
        )
    )

    vector_data = [
        [Paragraph("Feature", table_header), Paragraph("Type", table_header), Paragraph("Forensic Description", table_header), Paragraph("Adversarial Signal", table_header)],
        [Paragraph("<code>rwx_count</code>", table_cell), Paragraph("Integer", table_cell), Paragraph("Number of PAGE_EXECUTE_READWRITE committed memory allocations", table_cell), Paragraph("Permissive code+data buffer", table_cell)],
        [Paragraph("<code>unbacked_exec_count</code>", table_cell), Paragraph("Integer", table_cell), Paragraph("Count of private executable memory allocations without disk backing", table_cell), Paragraph("Injected shellcode buffer", table_cell)],
        [Paragraph("<code>total_rwx_bytes</code>", table_cell), Paragraph("Integer", table_cell), Paragraph("Aggregate byte volume mapped with RWX memory permissions", table_cell), Paragraph("Payload size indicator", table_cell)],
        [Paragraph("<code>num_threads</code>", table_cell), Paragraph("Integer", table_cell), Paragraph("Total active threads belonging to the target process", table_cell), Paragraph("Process activity baseline", table_cell)],
        [Paragraph("<code>thread_unbacked_start</code>", table_cell), Paragraph("Integer", table_cell), Paragraph("Threads whose initial Win32 start address resides in unbacked memory", table_cell), Paragraph("Thread execution hijack", table_cell)],
        [Paragraph("<code>is_jit_flag</code>", table_cell), Paragraph("Float (0/1)", table_cell), Paragraph("Indicator for legitimate JIT engines (Chrome, Edge, .NET CLR, Electron)", table_cell), Paragraph("False-positive dampening", table_cell)],
        [Paragraph("<code>vad_protection_anomaly</code>", table_cell), Paragraph("Integer", table_cell), Paragraph("Allocations created as PAGE_READWRITE and flipped to executable", table_cell), Paragraph("Self-injection transition", table_cell)],
    ]
    vector_table = Table(vector_data, colWidths=[1.6 * inch, 0.9 * inch, 3.1 * inch, 1.4 * inch])
    vector_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_CARD]),
        ])
    )
    story.append(Spacer(1, 4))
    story.append(vector_table)
    story.append(Spacer(1, 10))

    # 5. MITRE ATT&CK Mapping
    story.append(Paragraph("5. MITRE ATT&CK Adversary Technique Mapping", h1_style))
    mitre_data = [
        [Paragraph("MITRE ID", table_header), Paragraph("Technique Name", table_header), Paragraph("Forensic Indicators Observed", table_header), Paragraph("Recommended Response", table_header)],
        [Paragraph("<b>T1055.001</b>", table_cell), Paragraph("DLL Injection", table_cell), Paragraph("Unlinked library in PEB, foreign thread creation in target process.", table_cell), Paragraph("Suspend process threads; isolate host.", table_cell)],
        [Paragraph("<b>T1055.002</b>", table_cell), Paragraph("Reflective Code Loading", table_cell), Paragraph("DOS 'MZ' header (0x4D 0x5A) detected in unbacked MEM_PRIVATE memory.", table_cell), Paragraph("Freeze threads via NtSuspendProcess; dump hex.", table_cell)],
        [Paragraph("<b>T1055.003</b>", table_cell), Paragraph("Thread Execution Hijacking", table_cell), Paragraph("Thread entry point residing directly inside unbacked executable buffer.", table_cell), Paragraph("Immediate thread-level suspension.", table_cell)],
        [Paragraph("<b>T1055.012</b>", table_cell), Paragraph("Process Hollowing", table_cell), Paragraph("Process PE header entry point modified; .text virtual size mismatch.", table_cell), Paragraph("Terminate hollowed process; inspect parent.", table_cell)],
    ]
    mitre_table = Table(mitre_data, colWidths=[1.1 * inch, 1.8 * inch, 2.5 * inch, 1.6 * inch])
    mitre_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COLOR),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BG_CARD]),
        ])
    )
    story.append(Spacer(1, 4))
    story.append(mitre_table)
    story.append(Spacer(1, 10))

    # 6. Next.js 14 SOC Dashboard
    story.append(Paragraph("6. Next.js 14 SOC Dashboard & Generative UI", h1_style))
    story.append(
        Paragraph(
            "The SOC Cyber Defense Dashboard features a refined Warm SOC aesthetic engineered for high-alert clarity:",
            body_style,
        )
    )
    story.append(Paragraph("• <b>Threat Posture Radial Ring:</b> SVG circular progress indicator computing real-time clearance rate with color-coded posture metrics.", bullet_style))
    story.append(Paragraph("• <b>Live Process Allocation Grid:</b> Interactive spatial map with category filters (ALL, THREATS, JIT, CLEAN) and real-time VAD telemetry tooltips.", bullet_style))
    story.append(Paragraph("• <b>Process Forensic Dossier Modal:</b> 3-tab deep-dive investigation interface: (1) Explainable AI Feature Attribution, (2) VAD Memory Regions breakdown, and (3) Live Hex & ASCII Disassembly Inspector with Shannon entropy gauge.", bullet_style))
    story.append(Paragraph("• <b>Streaming Activity Terminal:</b> Monospaced kernel activity feed with auto-scroll and WebSocket-driven telemetry frame logging.", bullet_style))

    # 7. Demo Playbook
    story.append(Paragraph("7. Evaluation & Judge Presentation Playbook", h1_style))
    story.append(
        Paragraph(
            "When presenting ShadowMem to hackathon judges or technical evaluators, execute this 4-step sequence:",
            body_style,
        )
    )
    story.append(Paragraph("<b>Step 1 — Real Workstation Audit:</b> Click <i>'Run Volatile Scan'</i>. Demonstrate how 150+ live Windows processes and their thread contexts are evaluated via low-level Win32 calls in ~21s.", bullet_style))
    story.append(Paragraph("<b>Step 2 — Live Attack Demo:</b> Click <i>'Live Attack Demo'</i>. A simulated Cobalt Strike reflective injection alert broadcasts over WebSocket, elevating the posture meter and opening the dossier.", bullet_style))
    story.append(Paragraph("<b>Step 3 — Forensic Proof (Hex Inspector):</b> Switch to the <i>'Live Hex & Buffer Disassembly'</i> tab in the dossier. Show judges the 16-byte raw hex rows, ASCII decode, and 8.0/8.0 Shannon entropy score.", bullet_style))
    story.append(Paragraph("<b>Step 4 — Active Containment:</b> Click <i>'Isolate Target Process'</i>. Demonstrate surgical Win32 user-mode thread suspension and verify the audit trail in the Activity Feed.", bullet_style))

    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    return pdf_path


if __name__ == "__main__":
    path = build_pdf()
    print(f"PDF successfully generated at: {path}")
