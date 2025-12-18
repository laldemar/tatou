# server/test/test_watermarking_wrappers.py
from __future__ import annotations
from pathlib import Path
import pytest
import watermarking_utils as WM


@pytest.fixture(scope="session")
def secret() -> str:
    return "unit-test-secret"


@pytest.fixture(scope="session")
def key() -> str:
    return "unit-test-key"


def test_wrappers_roundtrip(sample_pdf_path: Path, secret: str, key: str, tmp_path: Path):
    """Test that all watermarking methods work correctly through the wrapper functions."""
    assert WM.METHODS, "No watermarking methods registered"
    for name, impl in WM.METHODS.items():
        # skip unsafe or non-applicable methods
        if name == "UnsafeBashBridgeAppendEOF":
            continue
        if hasattr(impl, "is_watermark_applicable") and not impl.is_watermark_applicable(sample_pdf_path, position=None):
            continue

        # Apply watermark via wrapper (method is the first param; pass by name to avoid ambiguity)
        out_bytes = WM.apply_watermark(
            method=name,
            pdf=sample_pdf_path,
            secret=secret,
            key=key,
            position=None,
        )
        assert isinstance(out_bytes, (bytes, bytearray))

        # Write to temporary file and test reading via wrapper
        out_pdf = tmp_path / f"{name}.pdf"
        out_pdf.write_bytes(out_bytes)
        extracted = WM.read_watermark(
            method=name,
            pdf=out_pdf,
            key=key,
        )
        assert extracted == secret, f"{name}: roundtrip failed"


def test_explore_pdf_runs(sample_pdf_path: Path):
    """Test that explore_pdf returns a valid structure."""
    tree = WM.explore_pdf(sample_pdf_path)
    assert isinstance(tree, dict)
    assert tree, "explore_pdf should not return an empty result"