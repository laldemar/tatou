import pytest
import watermarking_utils as WM

METHOD = "mathewos"

def test_roundtrip_success(sample_pdf_bytes, tmp_path):
    # skriv PDF till disk om utils förväntar sig filpath
    pdf_path = tmp_path / "input.pdf"
    pdf_path.write_bytes(sample_pdf_bytes)

    wm_bytes = WM.apply_watermark(
        pdf=str(pdf_path),
        secret="TopSecret123",
        key="abc123",
        method=METHOD,
        position="bottom-right",
    )
    assert isinstance(wm_bytes, (bytes, bytearray)) and len(wm_bytes) > 0

    # läs tillbaka (antingen från bytes eller via fil beroende på era utils)
    # Om WM.read_watermark tar filväg:
    secret = WM.read_watermark(
        method=METHOD,
        pdf=str(pdf_path),     # eller skriv wm_bytes till fil och läs därifrån
        key="abc123",
    )
    assert secret == "TopSecret123"

def test_invalid_key_fails(sample_pdf_bytes, tmp_path):
    pdf_path = tmp_path / "input.pdf"
    pdf_path.write_bytes(sample_pdf_bytes)

    WM.apply_watermark(
        pdf=str(pdf_path),
        secret="S3cr3t",
        key="right-key",
        method=METHOD,
        position=None,
    )
    with pytest.raises(Exception):
        WM.read_watermark(method=METHOD, pdf=str(pdf_path), key="wrong-key")

def test_is_applicable(sample_pdf_bytes, tmp_path):
    pdf_path = tmp_path / "input.pdf"
    pdf_path.write_bytes(sample_pdf_bytes)
    ok = WM.is_watermarking_applicable(method=METHOD, pdf=str(pdf_path), position=None)
    assert ok is True