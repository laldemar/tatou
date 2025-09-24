from __future__ import annotations
from typing import Optional, Iterable
import hmac, hashlib
import fitz  # PyMuPDF
from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    InvalidKeyError,
    WatermarkingError,
)

class TheoMethod(WatermarkingMethod):
    name = "theo"
    description = "Semi-transparent diagonal text watermark across each page."

    def embed(self, pdf: PdfSource, *, secret: Optional[bytes] = None, **kwargs) -> bytes:
        pdf_bytes = load_pdf_bytes(pdf)

        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        for page in doc:
            rect = page.rect
            text = "Watermarked by TheoMethod"
            fontsize = 50

            # Draw text diagonally across the page, semi-transparent
            page.insert_text(
                point=(rect.width / 4, rect.height / 2),
                text=text,
                fontsize=fontsize,
                rotate=45,  # diagonal
                render_mode=2,  # fill text with opacity
                color=(0.7, 0.7, 0.7),  # light gray
                overlay=True,
            )

        out_bytes = doc.write()
        doc.close()
        return out_bytes

    def extract(self, pdf: PdfSource, *, secret: Optional[bytes] = None, **kwargs) -> dict:
        pdf_bytes = load_pdf_bytes(pdf)

        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        found = False
        for page in doc:
            text = page.get_text()
            if "Watermarked by TheoMethod" in text:
                found = True
                break

        doc.close()
        return {"found": found}


# Your method, once you are finished and or want to try it out go to the 
# atermarking_utils.py file and uncomment the import statement for your method and add it to the METHODS dictionary.
