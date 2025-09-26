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

# ------- zero-width encoding (samma modell som den fungerande metoden) -------
ZW_FOR_BIT = {"0": "\u200B", "1": "\u200C"}  # ZWSP / ZWNJ
BIT_FOR_ZW = {v: k for k, v in ZW_FOR_BIT.items()}

# Distinkta "sentinel"-markörer för secret respektive HMAC-tag
S_S = "\u200D\u200D\u200D\u200D"  # ZWJ x4
E_S = "\u2060\u2060\u2060\u2060"  # WJ  x4
S_T = "\u200E\u200E\u200E\u200E"  # LRM x4
E_T = "\u200F\u200F\u200F\u200F"  # RLM x4

def _str_to_bits(s: str) -> str:
    if not isinstance(s, str) or s == "":
        raise ValueError("secret must be a non-empty string")
    return "".join(format(ord(c), "08b") for c in s)

def _bits_to_str(bits: str) -> str:
    n = (len(bits) // 8) * 8
    return "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, n, 8))

def _encode_zw(s: str) -> str:
    return "".join(ZW_FOR_BIT[b] for b in _str_to_bits(s))

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
    return s[i + len(start): j]

def _hmac_tag_hex16(key: str, secret: str) -> str:
    # 16 hex-tecken (64 bit) räcker för etikett/jämförelse och matchar den fungerande metoden
    return hmac.new(key.encode(), secret.encode(), hashlib.sha256).hexdigest()[:16]


class MathewosMethod(WatermarkingMethod):
    name = "mathewos"
    description = "Zero-width watermark (secret + HMAC) in content and metadata subject. Position ignored."

    @staticmethod
    def get_usage() -> str:
        return ("Embeds the secret using zero-width Unicode and also stashes it in metadata (subject). "
                "Use the same key on read to verify via HMAC(secret, key). Position is accepted but ignored.")

    # ---------- applicability ----------
    def is_watermark_applicable(self, pdf: PdfSource, position: Optional[str] = None) -> bool:
        data = load_pdf_bytes(pdf)
        try:
            fitz.open(stream=data, filetype="pdf").close()
            return True
        except Exception:
            return False

    # ------------ embedding ------------
    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: Optional[str] = None) -> bytes:
        data = load_pdf_bytes(pdf)
        try:
            tag = _hmac_tag_hex16(key or "", secret)
            zw_secret = _encode_zw(secret)
            zw_tag    = _encode_zw(tag)

            payload_secret = S_S + zw_secret + E_S
            payload_tag    = S_T + zw_tag    + E_T

            doc = fitz.open(stream=data, filetype="pdf")

            # A) tiny boxes på varje sida (som i fungerande metod)
            for page in doc:
                r = page.rect
                # Flytta in några punkter från kanten för att undvika out-of-bounds
                x1, y1 = r.x1 - 20, r.y1 - 20
                # smala rutor; zero-width-tecken tar nästan ingen plats visuellt
                page.insert_textbox(fitz.Rect(x1-10, y1-5, x1, y1), payload_secret, fontsize=1, fontname="helv")
                page.insert_textbox(fitz.Rect(x1-20, y1-5, x1-10, y1), payload_tag,    fontsize=1, fontname="helv")

            # B) även i metadata: använd endast tillåtna fält → 'subject'
            md = dict(doc.metadata or {})
            md["subject"] = (md.get("subject") or "") + payload_secret + payload_tag
            doc.set_metadata(md)

            out = doc.tobytes()
            doc.close()
            if not out:
                raise WatermarkingError("render produced empty PDF")
            return out
        except ValueError:
            raise
        except Exception as e:
            raise WatermarkingError(f"embedding failed: {e!r}")

    # ------------- reading -------------
    def _safe_load_page(self, doc: fitz.Document, i: int):
        try:
            return doc.load_page(i)
        except Exception:
            return None

    def _safe_get_text(self, page: fitz.Page, mode: str) -> str:
        try:
            t = page.get_text(mode)
            return t if isinstance(t, str) else ""
        except Exception:
            return ""

    def _extract_text_variants(self, doc: fitz.Document) -> Iterable[str]:
        # 0) metadata först (ofta orörd)
        md = doc.metadata or {}
        meta = (md.get("subject") or "") + (md.get("keywords") or "") + (md.get("title") or "")
        if meta:
            yield meta

        # 1) raw (bevarar ofta dolda tecken)
        yield "".join(
            self._safe_get_text(p, "raw") for p in (self._safe_load_page(doc, i) for i in range(len(doc))) if p
        )
        # 2) plain text
        yield "".join(
            self._safe_get_text(p, "text") for p in (self._safe_load_page(doc, i) for i in range(len(doc))) if p
        )
        # 3) rawdict-spans (mest troget men kan krascha på vissa filer → därför try/except)
        parts: list[str] = []
        for i in range(len(doc)):
            p = self._safe_load_page(doc, i)
            if not p:
                continue
            try:
                rd = p.get_text("rawdict")
                for b in (rd.get("blocks", []) or []):
                    for l in (b.get("lines", []) or []):
                        for s in (l.get("spans", []) or []):
                            t = s.get("text", "")
                            if t:
                                parts.append(t)
            except Exception:
                continue
        yield "".join(parts)

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        try:
            for txt in self._extract_text_variants(doc):
                if not txt:
                    continue

                sec_chunk = _slice_between(txt, S_S, E_S)
                tag_chunk = _slice_between(txt, S_T, E_T)
                if sec_chunk is None or tag_chunk is None:
                    continue

                secret = _decode_zw(sec_chunk)
                tag    = _decode_zw(tag_chunk)
                if not secret:
                    continue

                if tag != _hmac_tag_hex16(key or "", secret):
                    raise InvalidKeyError("invalid key for this watermark")

                doc.close()
                return secret

            doc.close()
            raise SecretNotFoundError("no zero-width payload found")

        except (SecretNotFoundError, InvalidKeyError):
            raise
        except Exception as e:
            msg = f"{e.__class__.__name__}: {e.args[0] if getattr(e, 'args', None) else ''}"
            raise WatermarkingError(f"decode failed: {msg}")