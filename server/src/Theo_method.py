# server/src/theo_method.py
from __future__ import annotations
from typing import Optional
import base64, hashlib, hmac, json
import fitz  # PyMuPDF
from watermarking_method import (
    WatermarkingMethod, PdfSource, load_pdf_bytes,
    WatermarkingError, InvalidKeyError, SecretNotFoundError
)

WATERMARK_CONTEXT = b"wm:theo:v1:"
VISIBLE_TAG = "TheoMethod"

class TheoMethod(WatermarkingMethod):
    name = "theo"
    description = "Semi-transparent diagonal text on each page, with hidden payload authenticated by HMAC(key, secret)."

    @staticmethod
    def get_usage() -> str:
        return ("Embeds faint diagonal text. Stores a hidden payload (secret+MAC). "
                "position may be topleft/topright/bottomleft/bottomright/center; "
                "key is required to verify.")

    def is_watermark_applicable(self, pdf: PdfSource, position: str | None = None) -> bool:
        try:
            load_pdf_bytes(pdf)  # just validate it looks like a PDF
            return True
        except Exception:
            return False

    def add_watermark(self, pdf: PdfSource, secret: str, key: str, position: str | None = None) -> bytes:
        if not secret or not key:
            raise WatermarkingError("Both secret and key are required")

        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        try:
            # HMAC(secret) with context binding
            mac_hex = hmac.new(key.encode("utf-8"), WATERMARK_CONTEXT + secret.encode("utf-8"), hashlib.sha256).hexdigest()

            # Visible text line (no secret in clear)
            visible = f"{VISIBLE_TAG} | MAC={mac_hex[:8]}"

            # Tiny hidden payload (base64-secret + MAC) that we can parse back
            hidden_payload = json.dumps({
                "theo_secret_b64": base64.b64encode(secret.encode("utf-8")).decode("ascii"),
                "theo_mac_hex": mac_hex
            })

            for page in doc:
                rect = page.rect
                # position selection
                x, y = rect.width/4, rect.height/2
                p = (position or "").lower()
                if p == "topleft": x, y = 50, 100
                elif p == "topright": x, y = rect.width - 300, 100
                elif p == "bottomleft": x, y = 50, rect.height - 100
                elif p == "bottomright": x, y = rect.width - 300, rect.height - 100
                elif p == "center": x, y = rect.width/2 - 100, rect.height/2

                # visible diagonal overlay
                page.insert_text((x, y), text=visible, fontsize=40, rotate=45,
                                 render_mode=2, color=(0.7, 0.7, 0.7), overlay=True)

                # very small, very faint payload (still extractable via get_text)
                page.insert_text((1, 1), text=hidden_payload, fontsize=1,
                                 color=(1, 1, 1), render_mode=3, overlay=True)

            return doc.tobytes()
        finally:
            doc.close()

    def read_secret(self, pdf: PdfSource, key: str) -> str:
        data = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=data, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        try:
            # scan for our hidden payload
            for page in doc:
                txt = page.get_text() or ""
                if VISIBLE_TAG in txt and "theo_secret_b64" in txt and "theo_mac_hex" in txt:
                    # crude but effective parse: find the JSON object boundaries
                    start = txt.find('{"theo_secret_b64"')
                    if start == -1:
                        continue
                    end = txt.find("}", start)
                    if end == -1:
                        continue
                    payload = json.loads(txt[start:end+1])
                    secret = base64.b64decode(payload["theo_secret_b64"]).decode("utf-8")
                    mac_hex = payload["theo_mac_hex"]

                    expected = hmac.new(key.encode("utf-8"),
                                        WATERMARK_CONTEXT + secret.encode("utf-8"),
                                        hashlib.sha256).hexdigest()
                    if not hmac.compare_digest(mac_hex, expected):
                        raise InvalidKeyError("Provided key failed to authenticate the watermark")
                    return secret

            raise SecretNotFoundError("No Theo watermark found")
        finally:
            doc.close()
