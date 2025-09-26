import base64
import hashlib
import hmac
import json
import fitz
from typing import Optional
from watermarking_method import (
    WatermarkingError,
    InvalidKeyError,
    SecretNotFoundError,
    WatermarkingMethod,
    load_pdf_bytes,
)


class TheoMethod(WatermarkingMethod):
    name = "theo"
    description = "Semi-transparent diagonal text watermark across each page."

    _CONTEXT = b"wm:theo:v1:"

    def embed(
        self,
        pdf,
        *,
        secret: Optional[str] = None,
        key: Optional[str] = None,
        position: Optional[str] = None,
        intended_for: Optional[str] = None,
        **kwargs,
    ) -> bytes:
        pdf_bytes = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        # Require a secret + key for integrity
        if not secret or not key:
            raise WatermarkingError("Both secret and key are required")

        # Compute HMAC(secret) with the key
        secret_bytes = secret.encode("utf-8")
        mac_hex = hmac.new(
            key.encode("utf-8"),
            self._CONTEXT + secret_bytes,
            hashlib.sha256,
        ).hexdigest()

        # Visible watermark text (no secret here!)
        wm_parts = ["TheoMethod"]
        wm_parts.append(f"MAC={mac_hex[:8]}")  # show short fingerprint for debugging
        if intended_for:
            wm_parts.append(f"For={intended_for}")
        text = " | ".join(wm_parts)

        # Place visible text on each page
        for page in doc:
            rect = page.rect
            fontsize = 40
            x, y = rect.width / 4, rect.height / 2

            if position:
                pos = position.lower()
                if pos == "topleft":
                    x, y = 50, 100
                elif pos == "topright":
                    x, y = rect.width - 300, 100
                elif pos == "bottomleft":
                    x, y = 50, rect.height - 100
                elif pos == "bottomright":
                    x, y = rect.width - 300, rect.height - 100
                elif pos == "center":
                    x, y = rect.width / 2 - 100, rect.height / 2

            page.insert_text(
                (x, y),
                text=text,
                fontsize=fontsize,
                rotate=45,
                render_mode=2,
                color=(0.7, 0.7, 0.7),
                overlay=True,
            )

            # Also embed the *secret* invisibly
            hidden_payload = json.dumps({
                "secret": base64.b64encode(secret_bytes).decode(),
                "mac": mac_hex
            })
            page.insert_text(
                (1, 1),  # tiny, corner
                text=hidden_payload,
                fontsize=1,
                color=(1, 1, 1),
                render_mode=3,  # invisible
                overlay=True,
            )

        out_bytes = doc.write()
        doc.close()
        return out_bytes

    def extract(self, pdf, *, key: Optional[str] = None, **kwargs) -> dict:
        pdf_bytes = load_pdf_bytes(pdf)
        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        except Exception as e:
            raise WatermarkingError(f"Failed to open PDF: {e}")

        for page in doc:
            text = page.get_text()
            if "TheoMethod" in text:
                # Try to recover hidden payload
                if "secret" in text:
                    try:
                        payload_str = text.split("secret")[1]  # crude parse
                        payload_json = (
                            "{" + "secret" + payload_str.split("}")[0] + "}"
                        )
                        payload = json.loads(payload_json)
                        secret = base64.b64decode(payload["secret"]).decode()
                        mac = payload["mac"]

                        # Verify MAC with provided key
                        if key:
                            expected = hmac.new(
                                key.encode("utf-8"),
                                self._CONTEXT + secret.encode(),
                                hashlib.sha256,
                            ).hexdigest()
                            if not hmac.compare_digest(mac, expected):
                                raise InvalidKeyError(
                                    "Provided key failed to authenticate the watermark"
                                )

                        return {
                            "found": True,
                            "secret": secret,
                            "method": self.name,
                            "position": kwargs.get("position"),
                        }
                    except Exception:
                        continue

        return {"found": False}
