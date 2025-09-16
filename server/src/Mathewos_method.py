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

class MathewosMethod(WatermarkingMethod):
    name = "Mathewos"
    description = "Explain waht your method does here"

# Your method, once you are finished and or want to try it out go to the 
# atermarking_utils.py file and uncomment the import statement for your method and add it to the METHODS dictionary.