from __future__ import annotations
from typing import Tuple
import hmac, hashlib, base64
import fitz  # PyMuPDF

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    InvalidKeyError,
    WatermarkingError,
)

# --- helpers ---
def _hmac_b64(key: str, msg: str) -> str:
    mac = hmac.new(key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")

def _resolve_pos(page: "fitz.Page", position: str | None) -> Tuple[float, float]:
    p = (position or "").strip().lower()
    w, h = page.rect.width, page.rect.height
    if "," in p:
        try:
            x, y = [float(v) for v in p.split(",", 1)]
            return x, y
        except Exception:
            pass
    mapping = {
        "top-left": (36, 36),
        "top-right": (w - 36, 36),
        "bottom-left": (36, h - 36),
        "bottom-right": (w - 36, h - 36),
        "center": (w / 2, h / 2),
        "": (50, h - 30),  # default
    }
    return mapping.get(p, mapping[""])

class MathewosMethod(WatermarkingMethod):
    name = "mathewos"
    description = "Invisible micro-text + metadata HMAC (custom metadata). Uses key/secret/position."

    @staticmethod
    def get_usage() -> str:
        return ("Embeds secret in PDF metadata (custom fields) with HMAC(key, secret) "
                "and draws a very small, faint marker text on each page. "
                "Position can be a name ('top-left', 'center', ...) or 'x,y' in points.")

    # ---- applicability ----
    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        try:
            load_pdf_bytes(pdf)  # validates PDF header
            return True
        except Exception:
            return False

    # ---- embed ----
    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        try:
            tag_b64 = _hmac_b64(key, secret)

            # Store under metadata["custom"] to avoid "bad dict key(s)".
            meta = dict(doc.metadata or {})
            custom = dict(meta.get("custom") or {})
            custom.update({
                "tatou_secret": secret,
                "tatou_hmac": tag_b64,
                "tatou_method": self.name,
            })
            meta["custom"] = custom
            # optional human-readable hint
            meta["subject"] = (meta.get("subject") or "") + " tatou"
            doc.set_metadata(meta)

            # very short page marker (nearly white text)
            marker = hashlib.sha256((tag_b64 + secret).encode()).hexdigest()[:12]

            for page in doc:
                x, y = _resolve_pos(page, position)
                try:
                    page.insert_text((x, y), marker, fontsize=2, fontname="helv",
                                     color=(0.98, 0.98, 0.98))
                except Exception:
                    # fallback: tiny textbox if insert_text misbehaves on some versions
                    try:
                        page.insert_textbox(fitz.Rect(x, y, x + 12, y + 6), marker,
                                            fontsize=1, fontname="helv")
                    except Exception:
                        pass  # metadata already holds the watermark—continue

            out = doc.tobytes()
            if not out:
                raise WatermarkingError("render produced empty PDF")
            return out
        finally:
            try:
                doc.close()
            except Exception:
                pass

    # ---- read ----
    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        try:
            meta = doc.metadata or {}
            cust = meta.get("custom") or {}
            emb_secret = cust.get("tatou_secret") or meta.get("tatou_secret")
            emb_tag    = cust.get("tatou_hmac")   or meta.get("tatou_hmac")

            if not emb_secret or not emb_tag:
                raise SecretNotFoundError("No watermark found")

            if _hmac_b64(key, emb_secret) != emb_tag:
                raise InvalidKeyError("Invalid watermark (HMAC mismatch)")

            return emb_secret
        finally:
            try:
                doc.close()
            except Exception:
                pass