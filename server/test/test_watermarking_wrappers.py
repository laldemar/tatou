# server/test/test_watermarking_wrappers.py

from __future__ import annotations

from pathlib import Path

import pytest
import watermarking_utils as WM


def test_wrappers_roundtrip(
    sample_pdf_path: Path,
    secret: str,
    key: str,
    tmp_path: Path,
):
    """Test that all watermarking methods work correctly through the wrapper functions."""
    assert WM.METHODS, "No watermarking methods registered"

    for name, impl in WM.METHODS.items():
        # Skip unsafe or non-applicable methods
        if name == "UnsafeBashBridgeAppendEOF":
            continue

        if hasattr(impl, "is_watermark_applicable") and not impl.is_watermark_applicable(
            sample_pdf_path, position=None
        ):
            continue

        try:
            out_bytes = WM.apply_watermark(
                method=name,
                pdf=sample_pdf_path,
                secret=secret,
                key=key,
                position=None,
            )
        except ValueError as e:
            if "cannot save with zero pages" in str(e).lower():
                pytest.skip(f"{name}: skipped (sample PDF too minimal)")
            raise

        assert isinstance(
            out_bytes, (bytes, bytearray)
        ), f"{name}: apply_watermark must return bytes"

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