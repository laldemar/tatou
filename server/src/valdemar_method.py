# server/src/valdemar_method.py
from __future__ import annotations
from pathlib import Path
import fitz  # PyMuPDF
from watermarking_method import WatermarkingMethod  # <-- absolute import

class ValdemarMethod(WatermarkingMethod):
    name = "valdemar"                       # lowercase slug
    description = "Diagonal text watermark on each page"

    @staticmethod
    def get_usage() -> str:
        return "Embeds the 'secret' as faint diagonal text on each page. Position/key ignored."

    def is_watermark_applicable(self, pdf_path: Path, position=None) -> bool:
        try:
            with fitz.open(pdf_path):
                return True
        except Exception:
            return False

    def add_watermark(self, pdf_path: Path, secret: str, key: str, position=None) -> bytes:
        doc = fitz.open(pdf_path)
        for page in doc:
            rect = page.rect
            page.insert_textbox(
                rect,
                secret,
                fontsize=max(24, int(rect.width * 0.04)),
                rotate=45,
                fontname="helv",
                align=fitz.TEXT_ALIGN_CENTER,
                fill_opacity=0.15,
            )
        out = doc.tobytes()
        doc.close()
        return out

    def read_secret(self, pdf_path: Path, key: str) -> str:
        # Minimal placeholder (you can later store/read from metadata to round-trip)
        return ""
