from __future__ import annotations
from typing import Tuple
import hmac, hashlib, base64
import fitz  # PyMuPDF test

from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    InvalidKeyError,
    WatermarkingError,
)

# ---------- helpers ----------
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

# ---------- method ----------
class MathewosMethod(WatermarkingMethod):
    name = "mathewos"
    description = "Invisible micro-text + HMAC watermark stored in PDF 'subject'. Uses key/secret/position."

    @staticmethod
    def get_usage() -> str:
        return ("Embeds a watermark payload in PDF metadata (subject) as "
                "[TATOU]<method>|<hmac>|<secret>[/TATOU] and draws a tiny, faint "
                "marker text on each page. Position can be a name ('top-right', "
                "'center', ...) or 'x,y' in points.")

    # ---- applicability ----
    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        try:
            load_pdf_bytes(pdf)  # validates PDF header / bytes
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
        """Embed secret + HMAC in metadata(subject) and add tiny marker text."""
        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        try:
            # Build payload placed in 'subject' (allowed field in PyMuPDF)
            tag_b64 = _hmac_b64(key, secret)
            payload = f"[TATOU]{self.name}|{tag_b64}|{secret}[/TATOU]"

            meta = dict(doc.metadata or {})
            prev = (meta.get("subject") or "").strip()
            meta["subject"] = (prev + " " + payload).strip()
            doc.set_metadata(meta)

            # Tiny page marker (almost white) – robustness hint only
            marker = hashlib.sha256((tag_b64 + secret).encode()).hexdigest()[:12]
            for page in doc:
                x, y = _resolve_pos(page, position)
                try:
                    page.insert_text((x, y), marker, fontsize=2, fontname="helv",
                                     color=(0.98, 0.98, 0.98))
                except Exception:
                    # Fallback on older builds
                    try:
                        page.insert_textbox(fitz.Rect(x, y, x + 12, y + 6), marker,
                                            fontsize=1, fontname="helv")
                    except Exception:
                        pass  # metadata already carries the watermark

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
        """Read payload from 'subject', verify HMAC(key, secret), return secret."""
        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        try:
            subject = (doc.metadata or {}).get("subject") or ""
            start = subject.find("[TATOU]")
            end = subject.find("[/TATOU]", start + 7)
            if start == -1 or end == -1:
                raise SecretNotFoundError("No watermark found")

            inside = subject[start + 7:end]
            try:
                method_name, tag_b64, emb_secret = inside.split("|", 2)
            except ValueError:
                raise WatermarkingError("Corrupted watermark payload")

            # Optional sanity check: method name
            # if method_name != self.name: pass

            if _hmac_b64(key, emb_secret) != tag_b64:
                raise InvalidKeyError("Invalid watermark (HMAC mismatch)")

            return emb_secret
        finally:
            try:
                doc.close()
            except Exception:
                pass