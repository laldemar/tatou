import sys
from pathlib import Path
import pytest

repo_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(repo_root / "server" / "src"))
sys.path.insert(0, str(repo_root))

@pytest.fixture(scope="session")
def sample_pdf_path(tmp_path_factory) -> Path:
    import fitz
    p = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Watermark test")
    doc.save(p)
    doc.close()
    return p