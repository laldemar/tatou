# pytest plockar automatiskt upp fixtures i conftest.py
import pytest
import fitz  # PyMuPDF

@pytest.fixture
def sample_pdf_bytes():
    """Skapa en minimal 1-sides PDF i minnet och returnera bytes."""
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Hello Tatou!")
    data = doc.tobytes()
    doc.close()
    return data