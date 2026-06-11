"""Generate simple printable PDFs from delivery Markdown documents."""

from __future__ import annotations

import re
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
OUT = DOCS / "pdf"


def convert(path: Path) -> None:
    pdfmetrics.registerFont(UnicodeCIDFont("STSong-Light"))
    styles = getSampleStyleSheet()
    base = ParagraphStyle("Chinese", parent=styles["BodyText"], fontName="STSong-Light", fontSize=9, leading=14)
    heading = ParagraphStyle("ChineseHeading", parent=styles["Heading2"], fontName="STSong-Light", fontSize=14, leading=20)
    title = ParagraphStyle("ChineseTitle", parent=styles["Title"], fontName="STSong-Light", fontSize=20, leading=26)
    story = []
    in_code = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if not line:
            story.append(Spacer(1, 3 * mm))
            continue
        escaped = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        escaped = re.sub(r"\*\*(.*?)\*\*", r"<b>\1</b>", escaped)
        if escaped.startswith("# "):
            story.append(Paragraph(escaped[2:], title))
        elif escaped.startswith("## "):
            story.append(Paragraph(escaped[3:], heading))
        elif in_code:
            story.append(Paragraph(f"<font name='Courier'>{escaped}</font>", base))
        else:
            story.append(Paragraph(escaped, base))
    target = OUT / f"{path.stem}.pdf"
    SimpleDocTemplate(str(target), pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm, topMargin=16 * mm, bottomMargin=16 * mm).build(story)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for path in sorted(DOCS.glob("[0-9][0-9]-*.md")):
        convert(path)
        print(f"Generated {OUT / (path.stem + '.pdf')}")


if __name__ == "__main__":
    main()
