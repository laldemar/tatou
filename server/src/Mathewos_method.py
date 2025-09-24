from __future__ import annotations
from typing import Optional, Iterable
import hmac, hashlib, io, base64
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
    description = "Invisible content marks + metadata HMAC. Robust against common manipulations."

    def _hmac(self, key: str, secret: str) -> bytes:
        return hmac.new(key.encode(), secret.encode(), hashlib.sha256).digest()

    def _tag_b64(self, mac: bytes) -> str:
        return base64.urlsafe_b64encode(mac).decode().rstrip("=")

    def _short_id(self, mac: bytes) -> str:
        return hashlib.sha256(mac).hexdigest()[:12]

    def _page_positions(self, page_rect, page_index: int, mac: bytes, count=3):
        # Deterministiska men "pseudorandom" positioner per sida utifrån HMAC + sidnummer
        w, h = page_rect.width, page_rect.height
        pos = []
        for k in range(count):
            seed = hashlib.sha256(mac + f":{page_index}:{k}".encode()).digest()
            x = (int.from_bytes(seed[:4], "big") % int(w*1000-100)) / 1000 + 50
            y = (int.from_bytes(seed[4:8], "big") % int(h*1000-100)) / 1000 + 50
            pos.append((x, y))
        return pos

    def embed(self, source: PdfSource, key: str, secret: str, position: str) -> bytes:
        mac = self._hmac(key, secret)
        tag_b64 = self._tag_b64(mac)
        short_id = self._short_id(mac)  # går in i de "osynliga" markörerna

        doc = fitz.open(stream=source.read(), filetype="pdf")

        # 1) Metadata (osynlig, verifierbar)
        meta = dict(doc.metadata or {})
        meta["tatou_method"]  = self.name
        meta["tatou_secret"]  = secret
        meta["tatou_hmac"]    = tag_b64
        doc.set_metadata(meta)

        # 2) Osynliga markörer i innehållet (svag text på svårgissade platser)
        for i, page in enumerate(doc):
            with page.wrap_contents():
                for (x, y) in self._page_positions(page.rect, i, mac, count=3):
                    page.insert_text(
                        (x, y),
                        short_id,
                        fontsize=3,              # väldigt liten
                        fontname="helv",
                        rotate=0,
                        fill=(0.98, 0.98, 0.98), # nästan vit
                        fill_opacity=0.03,       # mycket låg opacitet
                    )

        out = io.BytesIO()
        doc.save(out)
        doc.close()
        return out.getvalue()

    def read(self, source: PdfSource, key: str, secret: str, position: str) -> str:
        # Läs och verifiera via metadata (de osynliga markörerna är för robusthet i innehållet)
        doc = fitz.open(stream=source.read(), filetype="pdf")
        meta = doc.metadata or {}
        doc.close()

        embedded_secret = meta.get("tatou_secret")
        embedded_tag    = meta.get("tatou_hmac")
        if not embedded_secret or not embedded_tag:
            raise Exception("No watermark found")

        tag_check = base64.urlsafe_b64encode(
            hmac.new(key.encode(), embedded_secret.encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")

        if tag_check != embedded_tag:
            raise Exception("Invalid watermark (HMAC mismatch)")

        return embedded_secret

# Your method, once you are finished and or want to try it out go to the 
# atermarking_utils.py file and uncomment the import statement for your method and add it to the METHODS dictionary.