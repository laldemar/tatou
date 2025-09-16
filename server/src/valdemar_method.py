# server/src/valdemar_method.py
from __future__ import annotations
from pathlib import Path
import fitz  # PyMuPDF
from watermarking_method import WatermarkingMethod

# Mapping bits to zero-width chars
ZW_CHARS = {"0": "\u200B", "1": "\u200C"}
REV_ZW = {v: k for k, v in ZW_CHARS.items()}


class ValdemarMethod(WatermarkingMethod):
    name = "valdemar"
    description = "Zero-width character watermark in text layer"

    @staticmethod
    def get_usage() -> str:
        return "Embeds the 'secret' as zero-width characters hidden in text. Position/key ignored."

    def is_watermark_applicable(self, pdf_path: Path, position=None) -> bool:
        try:
            with fitz.open(pdf_path):
                return True
        except Exception:
            return False

    def add_watermark(self, pdf_path: Path, secret: str, key: str, position=None) -> bytes:
        # Convert secret string -> bits -> zero-width chars
        bitstring = "".join(format(ord(c), "08b") for c in secret)
        zw_payload = "".join(ZW_CHARS[b] for b in bitstring)

        doc = fitz.open(pdf_path)
        first_page = doc[0]

        # Put invisible payload at end of page text (off-screen)
        rect = first_page.rect
        hidden_rect = fitz.Rect(rect.x1 - 1, rect.y1 - 1, rect.x1, rect.y1)  # tiny box in corner
        first_page.insert_textbox(hidden_rect, zw_payload, fontsize=1, fontname="helv")

        out = doc.tobytes()
        doc.close()
        return out

    def read_secret(self, pdf_path: Path, key: str) -> str:
        doc = fitz.open(pdf_path)
        text = ""
        for page in doc:
            text += page.get_text("text")  # plain extracted text
        doc.close()

        # Collect only zero-width chars
        zw_chars = [ch for ch in text if ch in REV_ZW]
        bitstring = "".join(REV_ZW[ch] for ch in zw_chars)

        # Decode bitstring to text
        chars = [chr(int(bitstring[i:i+8], 2)) for i in range(0, len(bitstring), 8)]
        return "".join(chars)
