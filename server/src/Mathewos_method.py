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

def _hmac_b64(key: str, msg: str) -> str:
    mac = hmac.new(key.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")

def _resolve_pos(page: "fitz.Page", position: str | None) -> Tuple[float, float]:
    """Map common names or 'x,y' to a point in page coordinates."""
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
    description = "Invisible micro-text + metadata HMAC. Uses key/secret/position."

    @staticmethod
    def get_usage() -> str:
        return ("Embeds secret in PDF metadata with HMAC(key, secret) and draws very "
                "small, faint marker text on each page. position may be a name "
                "('top-left', 'center', ...) or 'x,y' in points.")

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        try:
            load_pdf_bytes(pdf)  # validates PDF header
            return True
        except Exception:
            return False

    def add_watermark(
        self,
        pdf: PdfSource,
        secret: str,
        key: str,
        position: str | None = None,
    ) -> bytes:
        """Embed secret + HMAC in metadata and add tiny low-opacity marker text."""
        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        try:
            tag_b64 = _hmac_b64(key, secret)
            # store in metadata for robust readback
            meta = dict(doc.metadata or {})
            meta["tatou_method"] = self.name
            meta["tatou_secret"] = secret
            meta["tatou_hmac"] = tag_b64
            doc.set_metadata(meta)

            marker = hashlib.sha256((tag_b64 + secret).encode()).hexdigest()[:12]

            for page in doc:
                x, y = _resolve_pos(page, position)
                with page.wrap_contents():
                    page.insert_text(
                        (x, y),
                        marker,
                        fontsize=2,
                        fontname="helv",
                        color=(0.98, 0.98, 0.98)  # nästan vit text
                    )

            return doc.tobytes()
        finally:
            doc.close()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        """Validate HMAC with provided key and return the embedded secret."""
        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        try:
            meta = doc.metadata or {}
            emb_secret = meta.get("tatou_secret")
            emb_tag = meta.get("tatou_hmac")

            if not emb_secret or not emb_tag:
                raise SecretNotFoundError("No watermark found")

            if _hmac_b64(key, emb_secret) != emb_tag:
                raise InvalidKeyError("Invalid watermark (HMAC mismatch)")

            return emb_secret
        finally:
            doc.close()