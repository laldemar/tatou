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

# bit <-> zero-width chars
ZW_FOR_BIT = {"0": "\u200B", "1": "\u200C"}  # ZWSP / ZWNJ
BIT_FOR_ZW = {v: k for k, v in ZW_FOR_BIT.items()}

# sentinels to delimit our payload
SENT_START = "\u200D\u200D\u200D\u200D"  # ZWJ x4
SENT_END   = "\u2060\u2060\u2060\u2060"  # WJ  x4


def _str_to_bits(s: str) -> str:
    if not isinstance(s, str) or s == "":
        raise ValueError("secret must be a non-empty string")
    return "".join(format(ord(c), "08b") for c in s)


def _bits_to_str(bits: str) -> str:
    n = (len(bits) // 8) * 8
    return "".join(chr(int(bits[i:i+8], 2)) for i in range(0, n, 8))


def _encode_zw(s: str) -> str:
    return "".join(ZW_FOR_BIT[b] for b in _str_to_bits(s))


def _decode_zw(text: str) -> str:
    bits = "".join(BIT_FOR_ZW.get(ch, "") for ch in text)
    return _bits_to_str(bits)


def _between_sentinels(s: str) -> str | None:
    i = s.find(SENT_START)
    if i == -1:
        return None
    j = s.find(SENT_END, i + len(SENT_START))
    if j == -1:
        return None
    return s[i + len(SENT_START): j]


class ValdemarMethod(WatermarkingMethod):
    name = "valdemar"
    description = "Embeds the secret as zero-width Unicode. Key/position ignored."

    @staticmethod
    def get_usage() -> str:
        return "Embeds the secret as zero-width Unicode in tiny text boxes on each page."

    def is_watermark_applicable(self, pdf: PdfSource, position: Optional[str] = None) -> bool:
        data = load_pdf_bytes(pdf)
        try:
            fitz.open(stream=data, filetype="pdf").close()
            return True
        except Exception:
            return False

    def add_watermark(
        self, pdf: PdfSource, secret: str, key: str, position: Optional[str] = None
    ) -> bytes:
        data = load_pdf_bytes(pdf)
        try:
            payload = SENT_START + _encode_zw(secret) + SENT_END
            doc = fitz.open(stream=data, filetype="pdf")
            for page in doc:
                r = page.rect
                box = fitz.Rect(r.x1 - 2, r.y1 - 2, r.x1 - 1, r.y1 - 1)  # 1x1 pt near bottom-right
                page.insert_textbox(box, payload, fontsize=1, fontname="helv")
            out = doc.tobytes()
            doc.close()
            if not out:
                raise WatermarkingError("render produced empty PDF")
            return out
        except ValueError:
            raise
        except Exception as e:
            raise WatermarkingError(f"embedding failed: {e}")

    # -------- reading helpers (no .rewind; reload pages each pass) --------

    def _extract_text_variants(self, doc: fitz.Document) -> Iterable[str]:
        # A) rawdict spans
        spans: list[str] = []
        for i in range(len(doc)):
            rd = doc.load_page(i).get_text("rawdict")
            for b in rd.get("blocks", []):
                for l in b.get("lines", []):
                    for s in l.get("spans", []):
                        t = s.get("text", "")
                        if t:
                            spans.append(t)
        yield "".join(spans)

        # B) raw
        yield "".join(doc.load_page(i).get_text("raw") for i in range(len(doc)))

        # C) plain text
        yield "".join(doc.load_page(i).get_text("text") for i in range(len(doc)))

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")

            # try multiple extraction modes
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
            fallback_text = "".join(doc.load_page(i).get_text("raw") for i in range(len(doc)))
            doc.close()
            decoded_any = _decode_zw(fallback_text)
            if decoded_any:
                return decoded_any

            raise SecretNotFoundError("no zero-width payload found")
        except SecretNotFoundError:
            raise
        except Exception as e:
            raise WatermarkingError(f"decode failed: {e}")
