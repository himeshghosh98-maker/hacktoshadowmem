"""
build_ui_guide_pdf.py
=====================
Builds ShadowMem_UI_Guide.pdf from the contents of ShadowMem_UI_Guide.md.
Uses ReportLab with high-quality styling, callouts, tables, and numbered pages.
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

OUTPUT_PDF = "ShadowMem_UI_Guide.pdf"
GENERATED_AT = datetime.now().strftime("%B %d, %Y - %H:%M")

PAGE_W, PAGE_H = letter
MARGIN = 0.55 * inch
USABLE_W = PAGE_W - (2 * MARGIN)

# Palette
PRIMARY = colors.HexColor("#1A1A1A")       # Obsidian / Dark Charcoal
ORANGE = colors.HexColor("#E8793C")        # ShadowMem Signature Orange
TEAL = colors.HexColor("#166534")          # Clean Green
WARN = colors.HexColor("#E68A2E")          # Warning Amber
DANGER = colors.HexColor("#D6453D")        # Threat Red
TEXT_MAIN = colors.HexColor("#1E293B")     # Slate 800
TEXT_MUTED = colors.HexColor("#475569")    # Slate 600
LIGHT_BG = colors.HexColor("#F8FAFC")      # Slate 50
CARD_BG = colors.HexColor("#FAF7F2")       # Soft Warm Tint
BORDER_COL = colors.HexColor("#E2E8F0")    # Slate 200


def md_to_xml(text: str) -> str:
    """Safely converts markdown formatting to ReportLab XML tags."""
    if not text:
        return ""
    # 1. Escape HTML special characters
    t = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # 2. Bold: **text** -> <b>text</b>
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    # 3. Italics: *text* -> <i>text</i>
    t = re.sub(r"(?<!\*)\*([^*]+?)\*(?!\*)", r"<i>\1</i>", t)
    # 4. Code: `text` -> Courier font
    t = re.sub(r"`(.+?)`", r'<font face="Courier" size="7.5" color="#0F172A"><b>\1</b></font>', t)
    # 5. Markdown Links: [label](url) -> label
    t = re.sub(r"\[(.+?)\]\([^)]+\)", r"<u>\1</u>", t)
    return t


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
                "SHADOWMEM — HACKATHON DEFENSE & UI GUIDE",
            )
            self.drawRightString(
                PAGE_W - MARGIN,
                PAGE_H - 0.38 * inch,
                "SCREEN-BY-SCREEN OPERATIONAL WALKTHROUGH",
            )
            self.setStrokeColor(BORDER_COL)
            self.setLineWidth(0.5)
            self.line(MARGIN, PAGE_H - 0.42 * inch, PAGE_W - MARGIN, PAGE_H - 0.42 * inch)

        # Footer (All pages)
        self.setFont("Helvetica", 7.5)
        self.drawString(
            MARGIN,
            0.36 * inch,
            f"Generated: {GENERATED_AT} | ShadowMem User-Mode Volatile Memory Forensics",
        )
        self.drawRightString(
            PAGE_W - MARGIN,
            0.36 * inch,
            f"Page {self._pageNumber} of {total_pages}",
        )
        self.setStrokeColor(BORDER_COL)
        self.setLineWidth(0.5)
        self.line(MARGIN, 0.46 * inch, PAGE_W - MARGIN, 0.46 * inch)
        self.restoreState()


def build_pdf():
    doc = SimpleDocTemplate(
        OUTPUT_PDF,
        pagesize=letter,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=0.55 * inch,
        bottomMargin=0.55 * inch,
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=PRIMARY,
        alignment=TA_LEFT,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "CoverSubTitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10.5,
        leading=15,
        textColor=ORANGE,
        alignment=TA_LEFT,
        spaceAfter=10,
    )
    h1_style = ParagraphStyle(
        "H1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=PRIMARY,
        spaceBefore=12,
        spaceAfter=4,
        keepWithNext=True,
    )
    h2_style = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=10.5,
        leading=14,
        textColor=ORANGE,
        spaceBefore=8,
        spaceAfter=3,
        keepWithNext=True,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=8,
        leading=11.5,
        textColor=TEXT_MAIN,
        spaceAfter=3,
    )
    bullet_style = ParagraphStyle(
        "Bullet",
        parent=body_style,
        leftIndent=10,
        firstLineIndent=-8,
        spaceAfter=2,
    )
    callout_style = ParagraphStyle(
        "Callout",
        parent=body_style,
        fontName="Helvetica",
        fontSize=8,
        leading=11.5,
        textColor=TEXT_MAIN,
    )
    table_cell = ParagraphStyle(
        "TableCell",
        parent=body_style,
        fontSize=7,
        leading=9.5,
    )
    table_header = ParagraphStyle(
        "TableHeader",
        parent=body_style,
        fontName="Helvetica-Bold",
        fontSize=7.5,
        leading=10,
        textColor=colors.white,
    )

    story = []

    # Title Banner
    story.append(Paragraph("ShadowMem — Hackathon Defense & UI Guide", title_style))
    story.append(Paragraph("Plain-Language Screen-by-Screen Walkthrough, Formulas, and Live Evaluator QA", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=ORANGE, spaceAfter=8))

    # Introduction Callout Box
    intro_p = Paragraph(
        "<b>Who this guide is for:</b> Presenters defending ShadowMem to hackathon judges. "
        "Every UI element, button, metric, badge, and modal is explained in plain English with zero unexplained jargon. "
        "Every item is tagged with its real operating status: <b>REAL</b>, <b>DERIVED</b>, <b>DECORATIVE</b>, <b>NOT WIRED</b>, or <b>HARDCODED</b>.",
        callout_style,
    )
    intro_table = Table([[intro_p]], colWidths=[USABLE_W])
    intro_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#DCD6CE")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(intro_table)
    story.append(Spacer(1, 8))

    # Read markdown and build sections
    with open("ShadowMem_UI_Guide.md", "r", encoding="utf-8") as f:
        md_text = f.read()

    lines = md_text.splitlines()
    in_table = False
    table_rows = []

    for line in lines:
        sline = line.strip()

        # Skip main title since we already rendered it nicely
        if sline.startswith("# ShadowMem Hackathon Defense"):
            continue
        if sline.startswith("> **Audience**") or sline.startswith("> **Philosophy**"):
            continue
        if sline == "---":
            story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER_COL, spaceBefore=4, spaceAfter=4))
            continue

        # Table detection
        if sline.startswith("|") and sline.endswith("|"):
            parts = [p.strip() for p in sline.split("|")[1:-1]]
            # check if separator
            if all(set(p).issubset({"-", ":"}) for p in parts):
                continue
            in_table = True
            table_rows.append(parts)
            continue
        elif in_table:
            # End of table, render it
            if table_rows:
                num_cols = len(table_rows[0])
                if num_cols == 4:
                    col_w = [1.2 * inch, 2.5 * inch, 2.3 * inch, 1.0 * inch]
                elif num_cols == 5:
                    col_w = [0.55 * inch, 1.7 * inch, 1.05 * inch, 2.1 * inch, 1.6 * inch]
                else:
                    col_w = [USABLE_W / num_cols] * num_cols

                formatted_table_data = []
                for r_idx, row in enumerate(table_rows):
                    row_cells = []
                    for c in row:
                        cell_st = table_header if r_idx == 0 else table_cell
                        c_fmt = md_to_xml(c)
                        row_cells.append(Paragraph(c_fmt, cell_st))
                    formatted_table_data.append(row_cells)

                t = Table(formatted_table_data, colWidths=col_w)
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_BG]),
                    ("PADDING", (0, 0), (-1, -1), 3),
                ]))
                story.append(t)
                story.append(Spacer(1, 5))
            in_table = False
            table_rows = []

        if not sline:
            continue

        # Headings
        if sline.startswith("## "):
            heading_text = md_to_xml(sline[3:].strip())
            story.append(Spacer(1, 4))
            story.append(Paragraph(heading_text, h1_style))
            story.append(HRFlowable(width="100%", thickness=0.8, color=ORANGE, spaceAfter=4))
        elif sline.startswith("### "):
            story.append(Paragraph(md_to_xml(sline[4:].strip()), h2_style))
        elif sline.startswith("#### "):
            story.append(Paragraph(f"<b>{md_to_xml(sline[5:].strip())}</b>", body_style))
        elif sline.startswith("* ") or sline.startswith("- "):
            bullet_text = md_to_xml(sline[2:].strip())
            story.append(Paragraph(f"• {bullet_text}", bullet_style))
        elif re.match(r"^\d+\.\s", sline):
            num_text = md_to_xml(sline)
            story.append(Paragraph(num_text, bullet_style))
        else:
            text = md_to_xml(sline)
            story.append(Paragraph(text, body_style))

    # Flush any remaining table
    if in_table and table_rows:
        num_cols = len(table_rows[0])
        col_w = [USABLE_W / num_cols] * num_cols
        formatted_table_data = []
        for r_idx, row in enumerate(table_rows):
            row_cells = []
            for c in row:
                cell_st = table_header if r_idx == 0 else table_cell
                row_cells.append(Paragraph(md_to_xml(c), cell_st))
            formatted_table_data.append(row_cells)
        t = Table(formatted_table_data, colWidths=col_w)
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), PRIMARY),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER_COL),
            ("PADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(t)

    # Build PDF
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated {OUTPUT_PDF} ({os.path.getsize(OUTPUT_PDF):,} bytes)")


if __name__ == "__main__":
    build_pdf()
