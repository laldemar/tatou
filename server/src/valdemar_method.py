from __future__ import annotations
from typing import Optional, Iterable
import fitz  # PyMuPDF
from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    WatermarkingError,
)

# --- Zero-width encoding -----------------------------------------------------

# bit <-> zw char mapping
ZW_FOR_BIT = {"0": "\u200B", "1": "\u200C"}  # ZWSP / ZWNJ
BIT_FOR_ZW = {v: k for k, v in ZW_FOR_BIT.items()}

# sentinels (to delimit our payload inside any other text)
SENT_START = "\u200D\u200D\u200D\u200D"  # ZWJ x4
SENT_END = "\u2060\u2060\u2060\u2060"    # WJ  x4


def _str_to_bits(s: str) -> str:
    if not isinstance(s, str) or s == "":
        raise ValueError("secret must be a non-empty string")
    return "".join(format(ord(c), "08b") for c in s)


def _bits_to_str(bits: str) -> str:
    n = (len(bits) // 8) * 8  # drop partial byte
    return "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, n, 8))


def _encode_zw(s: str) -> str:
    bits = _str_to_bits(s)
    return "".join(ZW_FOR_BIT[b] for b in bits)


def _decode_zw(text: str) -> str:
    """Decode any ZW chars present to a string (no sentinels assumed)."""
    bits = "".join(BIT_FOR_ZW.get(ch, "") for ch in text)
    return _bits_to_str(bits)


def _between_sentinels(s: str) -> str | None:
    """Return substring between first SENT_START and subsequent SENT_END, else None."""
    i = s.find(SENT_START)
    if i == -1:
        return None
    j = s.find(SENT_END, i + len(SENT_START))
    if j == -1:
        return None
    return s[i + len(SENT_START) : j]


# --- Method ------------------------------------------------------------------


class ValdemarMethod(WatermarkingMethod):
    """Embed the secret in the text layer using zero-width Unicode characters."""
    name = "valdemar"

    @staticmethod
    def get_usage() -> str:
        return (
            "Embeds the secret as zero-width Unicode characters hidden in the text layer. "
            "Key/position are ignored."
        )

    # -------------------------- contract: applicability ----------------------

    def is_watermark_applicable(
        self, pdf: PdfSource, position: Optional[str] = None
    ) -> bool:
        data = load_pdf_bytes(pdf)
        try:
            fitz.open(stream=data, filetype="pdf").close()
            return True
        except Exception:
            return False

    # ------------------------------ embedding --------------------------------

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: Optional[str] = None,
    ) -> bytes:
        """
        Insert tiny (1pt) invisible text boxes containing:
            SENT_START + payload + SENT_END
        on each page, tucked in the bottom-right corner.
        """
        data = load_pdf_bytes(pdf)
        try:
            payload = SENT_START + _encode_zw(secret) + SENT_END

            doc = fitz.open(stream=data, filetype="pdf")
            for page in doc:  # distribute onto every page for robustness
                r = page.rect
                # 1x1 pt box near bottom-right (off-visual flow)
                box = fitz.Rect(r.x1 - 2, r.y1 - 2, r.x1 - 1, r.y1 - 1)
                page.insert_textbox(box, payload, fontsize=1, fontname="helv")

            out = doc.tobytes()
            doc.close()
            if not out:
                raise WatermarkingError("render produced empty PDF")
            return out

        except ValueError:
            raise  # invalid input => handled by API as 400
        except Exception as e:
            raise WatermarkingError(f"embedding failed: {e}")

    # ------------------------------- reading ---------------------------------

    def _extract_text_variants(self, doc: fitz.Document) -> Iterable[str]:
        """
        Yield text from several PyMuPDF extractors; some preserve ZW chars
        better than others depending on PDF structure.
        Order: rawdict/spans -> raw -> text
        """
        # A) rawdict spans (closest to content stream)
        parts: list[str] = []
        for page in doc:
            rd = page.get_text("rawdict")
            for b in rd.get("blocks", []):
                for l in b.get("lines", []):
                    for s in l.get("spans", []):
                        t = s.get("text", "")
                        if t:
                            parts.append(t)
        yield "".join(parts)

        # B) raw text
        doc.rewind()
        yield "".join(page.get_text("raw") for page in doc)

        # C) plain text
        doc.rewind()
        yield "".join(page.get_text("text") for page in doc)

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """
        Extract text via multiple modes, locate our sentinel-delimited payload,
        and decode it. If no sentinels found, fall back to decoding any ZW
        chars seen (for backwards compatibility).
        """
        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")

            # try multiple extraction modes until one yields payload
            for txt in self._extract_text_variants(doc):
                if not txt:
                    continue
                middle = _between_sentinels(txt)
                if middle is not None:
                    decoded = _decode_zw(middle)
                    if decoded:
                        doc.close()
                        return decoded

            # fallback: decode any ZW anywhere (may be noisy)
            doc.rewind()
            fallback_text = "".join(page.get_text("raw") for page in doc)
            doc.close()
            decoded_any = _decode_zw(fallback_text)
            if decoded_any:
                return decoded_any

            raise SecretNotFoundError("no zero-width payload found")

        except SecretNotFoundError:
            raise
        except Exception as e:
            raise WatermarkingError(f"decode failed: {e}")
