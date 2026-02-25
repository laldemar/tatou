import pytest


@pytest.fixture(scope="session")
def sample_pdf_path(tmp_path_factory):
    import fitz

    p = tmp_path_factory.mktemp("pdfs") / "sample.pdf"
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), "Watermark test")
    doc.save(p)
    doc.close()

    return p