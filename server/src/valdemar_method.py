from __future__ import annotations
from typing import Optional
import fitz  # PyMuPDF
from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    InvalidKeyError,
    WatermarkingError,
)

# Bit <-> zero-width mapping
ZW_FOR_BIT = {"0": "\u200B", "1": "\u200C"}         # ZWSP / ZWNJ
BIT_FOR_ZW = {v: k for k, v in ZW_FOR_BIT.items()}


class ValdemarMethod(WatermarkingMethod):
    """Embed the secret in the text layer using zero-width Unicode characters."""
    name = "valdemar"

    @staticmethod
    def get_usage() -> str:
        return ("Embeds the secret as zero-width Unicode characters in the text layer. "
                "Key/position are ignored.")

    # --- helpers -------------------------------------------------------------

    @staticmethod
    def _str_to_bits(s: str) -> str:
        if not isinstance(s, str) or s == "":
            raise ValueError("secret must be a non-empty string")
        return "".join(format(ord(c), "08b") for c in s)

    @staticmethod
    def _bits_to_str(bits: str) -> str:
        # drop trailing partial byte if any
        n = (len(bits) // 8) * 8
        return "".join(chr(int(bits[i:i+8], 2)) for i in range(0, n, 8))

    @staticmethod
    def _encode_zw(s: str) -> str:
        return "".join(ZW_FOR_BIT[b] for b in ValdemarMethod._str_to_bits(s))

    @staticmethod
    def _decode_zw(text: str) -> str:
        bits = "".join(BIT_FOR_ZW.get(ch, "") for ch in text)
        return ValdemarMethod._bits_to_str(bits)

    # --- contract methods ----------------------------------------------------

    def is_watermark_applicable(self, pdf: PdfSource, position: Optional[str] = None) -> bool:
        # Accept any real PDF we can open
        data = load_pdf_bytes(pdf)
        try:
            fitz.open(stream=data, filetype="pdf").close()
            return True
        except Exception:
            return False

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """Insert a tiny, invisible textbox containing the ZW payload on each page."""
        data = load_pdf_bytes(pdf)
        try:
            payload = self._encode_zw(secret)
            doc = fitz.open(stream=data, filetype="pdf")

            for page in doc:
                r = page.rect
                # a 1x1pt box tucked in bottom-right; fontsize 1 so nothing visible
                box = fitz.Rect(r.x1 - 2, r.y1 - 2, r.x1 - 1, r.y1 - 1)
                page.insert_textbox(box, payload, fontsize=1, fontname="helv")

            out = doc.tobytes()
            doc.close()
            if not out:
                raise WatermarkingError("render produced empty PDF")
            return out
        except ValueError as e:
            # invalid inputs -> 400 by the API layer
            raise e
        except Exception as e:
            # other embed failures -> 400 with message
            raise WatermarkingError(f"embedding failed: {e}")

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """Extract all text and recover ZW payload from it."""
        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")
            text = "".join(page.get_text("text") for page in doc)  # keeps ZW chars
            doc.close()

            decoded = self._decode_zw(text)
            if decoded == "":
                raise SecretNotFoundError("no zero-width payload found")
            return decoded
        except SecretNotFoundError:
            raise
        except Exception as e:
            # treat everything else as extraction failure
            raise WatermarkingError(f"decode failed: {e}")
