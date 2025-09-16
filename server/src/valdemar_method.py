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

# ---------------- Zero-width encoding ----------------

ZW_FOR_BIT = {"0": "\u200B", "1": "\u200C"}  # ZWSP / ZWNJ
BIT_FOR_ZW = {v: k for k, v in ZW_FOR_BIT.items()}

# Two distinct sentinel pairs so we can store secret and tag separately
S_S = "\u200D\u200D\u200D\u200D"  # start secret (ZWJ x4)
E_S = "\u2060\u2060\u2060\u2060"  # end   secret (WJ  x4)
S_T = "\u200E\u200E\u200E\u200E"  # start tag    (LRM x4)
E_T = "\u200F\u200F\u200F\u200F"  # end   tag    (RLM x4)


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


def _decode_zw(s: str) -> str:
    bits = "".join(BIT_FOR_ZW.get(ch, "") for ch in s)
    return _bits_to_str(bits)


def _slice_between(s: str, start: str, end: str) -> str | None:
    i = s.find(start)
    if i == -1:
        return None
    j = s.find(end, i + len(start))
    if j == -1:
        return None
    return s[i + len(start) : j]


def _hmac_tag(key: str, secret: str) -> str:
    # 16 hex chars (~64 bits) is plenty for integrity in this coursework setting
    return hmac.new(key.encode("utf-8"), secret.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


class ValdemarMethod(WatermarkingMethod):
    name = "valdemar"
    description = "Zero-width character watermark with HMAC key check. Key/position ignored."

    @staticmethod
    def get_usage() -> str:
        return ("Embeds the secret using zero-width Unicode. "
                "Requires the same key to read back (HMAC verification).")

    # ---------------- applicability ----------------

    def is_watermark_applicable(self, pdf: PdfSource, position: Optional[str] = None) -> bool:
        data = load_pdf_bytes(pdf)
        try:
            fitz.open(stream=data, filetype="pdf").close()
            return True
        except Exception:
            return False

    # ---------------- embedding ----------------

    def add_watermark(
        self, pdf: PdfSource, secret: str, key: str, position: Optional[str] = None
    ) -> bytes:
        data = load_pdf_bytes(pdf)
        try:
            # prepare payloads
            tag = _hmac_tag(key or "", secret)
            zw_secret = _encode_zw(secret)
            zw_tag = _encode_zw(tag)

            # write both payloads with distinct sentinels
            payload_secret = S_S + zw_secret + E_S
            payload_tag = S_T + zw_tag + E_T

            doc = fitz.open(stream=data, filetype="pdf")
            for page in doc:
                r = page.rect
                # 1x1 pt boxes tucked at bottom-right
                box1 = fitz.Rect(r.x1 - 2, r.y1 - 2, r.x1 - 1, r.y1 - 1)
                box2 = fitz.Rect(r.x1 - 4, r.y1 - 2, r.x1 - 3, r.y1 - 1)
                page.insert_textbox(box1, payload_secret, fontsize=1, fontname="helv")
                page.insert_textbox(box2, payload_tag, fontsize=1, fontname="helv")

            out = doc.tobytes()
            doc.close()
            if not out:
                raise WatermarkingError("render produced empty PDF")
            return out

        except ValueError:
            raise  # input validation -> API returns 400 with our message
        except Exception as e:
            raise WatermarkingError(f"embedding failed: {e!r}")

    # ---------------- reading ----------------

    def _extract_text_variants(self, doc: fitz.Document) -> Iterable[str]:
        # A) rawdict spans (closest to content stream)
        parts: list[str] = []
        for i in range(len(doc)):
            rd = doc.load_page(i).get_text("rawdict")
            for b in rd.get("blocks", []):
                for l in b.get("lines", []):
                    for s in l.get("spans", []):
                        t = s.get("text", "")
                        if t:
                            parts.append(t)
        yield "".join(parts)

        # B) raw
        yield "".join(doc.load_page(i).get_text("raw") for i in range(len(doc)))

        # C) plain text
        yield "".join(doc.load_page(i).get_text("text") for i in range(len(doc)))

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")

            # try multiple extraction modes until we find both secret & tag
            for txt in self._extract_text_variants(doc):
                if not txt:
                    continue

                sec_chunk = _slice_between(txt, S_S, E_S)
                tag_chunk = _slice_between(txt, S_T, E_T)
                if sec_chunk is None or tag_chunk is None:
                    continue  # try next extractor

                # decode both
                secret = _decode_zw(sec_chunk)
                tag = _decode_zw(tag_chunk)

                if not secret:
                    continue  # malformed; try next
                # verify key/tag
                expected = _hmac_tag(key or "", secret)
                if tag != expected:
                    raise InvalidKeyError("invalid key for this watermark")

                doc.close()
                return secret

            # no sentinels found in any extractor
            doc.close()
            raise SecretNotFoundError("no zero-width payload found")

        except (SecretNotFoundError, InvalidKeyError):
            raise
        except Exception as e:
            # include repr so the message is never empty
            raise WatermarkingError(f"decode failed: {e!r}")
