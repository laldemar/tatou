from __future__ import annotations
from pathlib import Path
import fitz  # PyMuPDF
from watermarking_method import WatermarkingMethod, PdfSource, load_pdf_bytes

WATERMARK_TEXT = "Watermarked by TheoMethod"

class TheoMethod(WatermarkingMethod):
    name = "theo"
    description = "Semi-transparent diagonal text watermark across each page."

    @staticmethod
    def get_usage() -> str:
        return "Embeds a faint diagonal text watermark on all pages. Ignores key/position."

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        try:
            load_pdf_bytes(pdf)   # validate it's a PDF
            return True
        except Exception:
            return False

    def add_watermark(
        self, pdf: PdfSource, secret: str, key: str, position: str | None = None
    ) -> bytes:
        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")
        try:
            for page in doc:
                rect = page.rect
                page.insert_textbox(
                    rect,
                    WATERMARK_TEXT,
                    fontsize=max(24, int(rect.width * 0.04)),
                    rotate=45,
                    fontname="helv",
                    align=fitz.TEXT_ALIGN_CENTER,
                    fill_opacity=0.15,
                )
            # store secret in metadata so read_secret can round-trip
            md = doc.metadata or {}
            md["custom:theo_secret"] = secret
            doc.set_metadata(md)
            return doc.tobytes()
        finally:
            doc.close()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        doc = fitz.open(stream=data, filetype="pdf")
        try:
            md = doc.metadata or {}
            return md.get("custom:theo_secret", "")
        finally:
            doc.close()
