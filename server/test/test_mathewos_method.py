import pytest
import watermarking_utils as WM
import fitz  # för ett litet debug-steg (valfritt)

METHOD = "mathewos"

def test_roundtrip_success(sample_pdf_bytes, tmp_path):
    # 1) skapa input.pdf
    pdf_path = tmp_path / "input.pdf"
    pdf_path.write_bytes(sample_pdf_bytes)

    # 2) applicera watermark → få tillbaka bytes
    wm_bytes = WM.apply_watermark(
        pdf=str(pdf_path),
        secret="TopSecret123",
        key="abc123",
        method=METHOD,
        position="bottom-right",
    )
    assert isinstance(wm_bytes, (bytes, bytearray)) and len(wm_bytes) > 0

    # 3) spara vattenmärkt PDF och LÄS FRÅN DEN
    wm_path = tmp_path / "watermarked.pdf"
    wm_path.write_bytes(wm_bytes)

    # (valfritt debug) kontrollera att subject faktiskt innehåller vår tagg
    with fitz.open(wm_path) as d:
        subj = (d.metadata or {}).get("subject") or ""
        assert "[TATOU]" in subj and "[/TATOU]" in subj

    secret = WM.read_watermark(
        method=METHOD,
        pdf=str(wm_path),   # <-- VIKTIGT: använd vattenmärkta filen
        key="abc123",
    )
    assert secret == "TopSecret123"


def test_invalid_key_fails(sample_pdf_bytes, tmp_path):
    pdf_path = tmp_path / "input.pdf"
    pdf_path.write_bytes(sample_pdf_bytes)

    wm_bytes = WM.apply_watermark(
        pdf=str(pdf_path),
        secret="S3cr3t",
        key="right-key",
        method=METHOD,
        position=None,
    )
    wm_path = tmp_path / "watermarked.pdf"
    wm_path.write_bytes(wm_bytes)

    with pytest.raises(Exception):
        WM.read_watermark(method=METHOD, pdf=str(wm_path), key="wrong-key")


def test_is_applicable(sample_pdf_bytes, tmp_path):
    pdf_path = tmp_path / "input.pdf"
    pdf_path.write_bytes(sample_pdf_bytes)
    ok = WM.is_watermarking_applicable(
        method=METHOD, pdf=str(pdf_path), position=None
    )
    assert ok is True