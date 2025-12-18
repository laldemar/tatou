# server/test/conftest.py

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "server" / "src"

sys.path.insert(0, str(SRC))


@pytest.fixture(scope="session")
def sample_pdf_path(tmp_path_factory) -> Path:
    pdf = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    pdf.write_bytes(
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"%%EOF\n"
    )
    return pdf


@pytest.fixture(scope="session")
def secret() -> str:
    return "unit-test-secret"


@pytest.fixture(scope="session")
def key() -> str:
    return "unit-test-key"