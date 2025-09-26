from __future__ import annotations
from typing import Optional
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

# --- zero-width alphabet ---
ZW0 = "\u200B"  # ZERO WIDTH SPACE -> bit 0
ZW1 = "\u200C"  # ZERO WIDTH NON-JOINER -> bit 1

# sentinels to locate payloads (secret/tag)
S_S = "\u200D" * 4  # ZWJ×4
E_S = "\u2060" * 4  # WORD JOINER×4
S_T = "\u200E" * 4  # LRM×4
E_T = "\u200F" * 4  # RLM×4

def _bits_from_bytes(b: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in b)

def _bytes_from_bits(bits: str) -> bytes:
    n = len(bits) // 8 * 8
    return bytes(int(bits[i:i+8], 2) for i in range(0, n, 8))

def _encode_zw_text(s: str) -> str:
    bits = _bits_from_bytes(s.encode("utf-8"))
    return "".join(ZW1 if b == "1" else ZW0 for b in bits)

def _decode_zw_text(enc: str) -> str:
    # keep only our two codepoints, map back to bits
    bits = []
    for ch in enc:
        if ch == ZW0:
            bits.append("0")
        elif ch == ZW1:
            bits.append("1")
    data = _bytes_from_bits("".join(bits))
    return data.decode("utf-8", errors="strict")

def _hmac_hex16(key: str, msg: str) -> str:
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).hexdigest()[:16]

def _slice_between(s: str, start: str, end: str) -> Optional[str]:
    i = s.find(start)
    if i == -1:
        return None
    j = s.find(end, i + len(start))
    if j == -1:
        return None
    return s[i + len(start) : j]

class UnicodeWhitespaceMethod(WatermarkingMethod):
    name = "unicode-whitespace"
    description = "Zero-width Unicode watermark (ZWSP/ZWNJ) with HMAC verification."

    @staticmethod
    def get_usage() -> str:
        return ("Embeds an invisible payload using zero-width Unicode (ZWSP/ZWNJ). "
                "Payload is stored in metadata and a tiny text run. "
                "Use the same key to verify via HMAC(tag).")

    # ---------- applicability ----------
    def is_watermark_applicable(self, pdf: PdfSource, position: Optional[str] = None) -> bool:
        data = load_pdf_bytes(pdf)
        try:
            with fitz.open(stream=data, filetype="pdf") as doc:
                return len(doc) > 0
        except Exception:
            return False

    # ------------ embedding ------------
    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: Optional[str] = None) -> bytes:
        if not isinstance(secret, str) or not secret:
            raise ValueError("secret must be a non-empty string")
        data = load_pdf_bytes(pdf)
        try:
            tag = _hmac_hex16(key or "", secret)
            payload = (
                S_S + _encode_zw_text(secret) + E_S +
                S_T + _encode_zw_text(tag)    + E_T
            )
            with fitz.open(stream=data, filetype="pdf") as doc:
                # (1) metadata (robust to many edits)
                md = dict(doc.metadata or {})
                md["subject"] = (md.get("subject") or "") + payload
                doc.set_metadata(md)
                # (2) tiny text run on each page (extra redundancy)
                for page in doc:
                    r = page.rect
                    page.insert_text(fitz.Point(r.x1 - 12, r.y0 + 12),
                                     payload, fontsize=1, fontname="helv")
                out = doc.tobytes(deflate=True)
            if not out:
                raise WatermarkingError("embedding produced empty output")
            return out
        except Exception as e:
            raise WatermarkingError(f"embedding failed: {e!r}")

    # ------------- reading -------------
    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        try:
            with fitz.open(stream=data, filetype="pdf") as doc:
                md = doc.metadata or {}
                buckets = [
                    (md.get("subject") or "") + (md.get("keywords") or "") + (md.get("title") or ""),
                    "".join(page.get_text("raw")  for page in doc),
                    "".join(page.get_text("text") for page in doc),
                ]
                saw_payload = False
                for txt in buckets:
                    if not txt:
                        continue
                    sec_chunk = _slice_between(txt, S_S, E_S)
                    tag_chunk = _slice_between(txt, S_T, E_T)
                    if sec_chunk is None or tag_chunk is None:
                        continue
                    saw_payload = True
                    secret = _decode_zw_text(sec_chunk)
                    tag    = _decode_zw_text(tag_chunk)
                    if tag == _hmac_hex16(key or "", secret):
                        return secret
                if saw_payload:
                    raise InvalidKeyError("payload found, but key invalid")
                raise SecretNotFoundError("no zero-width payload found")
        except (SecretNotFoundError, InvalidKeyError):
            raise
        except Exception as e:
            raise WatermarkingError(f"decode failed: {e.__class__.__name__}: {e}")
