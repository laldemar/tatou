from __future__ import annotations
from typing import Optional, Iterable
import hmac
import hashlib
import io
import base64

import fitz  # PyMuPDF
from watermarking_method import (
    WatermarkingMethod,
    PdfSource,
    load_pdf_bytes,
    SecretNotFoundError,
    InvalidKeyError,
    WatermarkingError,
)


class MathewosMethod(WatermarkingMethod):
    name = "mathewos"
    description = (
        "Invisible micro-text + metadata HMAC. "
        "Uses key/secret/position/intended_for."
    )

    def _hmac_b64(self, key: str, secret: str) -> str:
        mac = hmac.new(key.encode(), secret.encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode().rstrip("=")

    def _resolve_pos(self, page, position: str):
        """
        Determine watermark position.

        position: "", "top-left", "top-right", "bottom-left",
                  "bottom-right", "center"
        or "x,y" in points (e.g., "72,72")
        """
        w, h = page.rect.width, page.rect.height
        p = (position or "").strip().lower()

        if "," in p:
            try:
                x, y = [float(v) for v in p.split(",", 1)]
                return x, y
            except Exception:
                pass

        map_ = {
            "top-left": (36, 36),
            "top-right": (w - 36, 36),
            "bottom-left": (36, h - 36),
            "bottom-right": (w - 36, h - 36),
            "center": (w / 2, h / 2),
            "": (50, h - 30),  # default
        }
        return map_.get(p, map_[""])

    def embed(
        self,
        source: PdfSource,
        key: str,
        secret: str,
        position: str,
        intended_for: str = "",
    ) -> bytes:
        doc = fitz.open(stream=source.read(), filetype="pdf")

        tag_b64 = self._hmac_b64(key, secret)
        meta = dict(doc.metadata or {})
        meta["tatou_method"] = self.name
        meta["tatou_secret"] = secret
        meta["tatou_hmac"] = tag_b64
        if intended_for:
            meta["tatou_intended_for"] = intended_for
        doc.set_metadata(meta)

        marker = hashlib.sha256((tag_b64 + secret).encode()).hexdigest()[:12]
        for page in doc:
            x, y = self._resolve_pos(page, position)
            with page.wrap_contents():
                page.insert_text(
                    (x, y),
                    marker,
                    fontsize=2,
                    fontname="helv",
                    fill=(0.98, 0.98, 0.98),
                    fill_opacity=0.03,
                    render_mode=0,
                )

        out = io.BytesIO()
        doc.save(out)
        doc.close()
        return out.getvalue()

    def read(self, source: PdfSource, key: str, secret: str, position: str):
        doc = fitz.open(stream=source.read(), filetype="pdf")
        meta = doc.metadata or {}
        doc.close()

        emb_secret = meta.get("tatou_secret")
        emb_tag = meta.get("tatou_hmac")
        intended_for = meta.get("tatou_intended_for", "")

        if not emb_secret or not emb_tag:
            raise Exception("No watermark found")

        if self._hmac_b64(key, emb_secret) != emb_tag:
            raise Exception("Invalid watermark (HMAC mismatch)")

        return {
            "secret": emb_secret,
            "intended_for": intended_for,
            "method": self.name,
            "position": position or "",
        }
