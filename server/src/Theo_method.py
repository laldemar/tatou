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

class TheoMethod(WatermarkingMethod):
    name = "theo"
    description = "explain what the method does here"