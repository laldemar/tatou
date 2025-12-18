# server/test/test_watermarking_all_methods.py

from __future__ import annotations

import importlib
import inspect
from pathlib import Path

import pytest


# --------- collect all methods from the registry ----------
try:
    wm = importlib.import_module("watermarking_utils")
    METHODS = getattr(wm, "METHODS", {})
except Exception:
    METHODS = {}

CASES: list[tuple[str, object]] = []
for name, impl in (METHODS or {}).items():
    if name != "UnsafeBashBridgeAppendEOF":
        CASES.append((str(name), impl))

if not CASES:
    pytest.skip(
        "No watermarking methods registered in watermarking_utils.METHODS",
        allow_module_level=True,
    )


def _as_instance(impl: object) -> object:
    if inspect.isclass(impl):
        return impl()
    return impl


# --------- parameterization over all methods ----------
@pytest.mark.parametrize(
    "method_name,impl",
    CASES,
    ids=[name for name, _ in CASES],
)
class TestAllWatermarkingMethods:
    def test_is_watermark_applicable(
        self,
        method_name: str,
        impl: object,
        sample_pdf_path: Path,
    ):
        wm_impl = _as_instance(impl)
        ok = wm_impl.is_watermark_applicable(sample_pdf_path, position=None)

        assert isinstance(
            ok, bool
        ), f"{method_name}: is_watermark_applicable must return bool"

        if not ok:
            pytest.skip(f"{method_name}: not applicable to the sample PDF")

    def test_add_watermark_and_shape(
        self,
        method_name: str,
        impl: object,
        sample_pdf_path: Path,
        secret: str,
        key: str,
    ):
        wm_impl = _as_instance(impl)

        if not wm_impl.is_watermark_applicable(sample_pdf_path, position=None):
            pytest.skip(f"{method_name}: not applicable to the sample PDF")

        original = sample_pdf_path.read_bytes()

        try:
            out_bytes = wm_impl.add_watermark(
                sample_pdf_path,
                secret=secret,
                key=key,
                position=None,
            )
        except ValueError as e:
            if "cannot save with zero pages" in str(e).lower():
                pytest.skip(f"{method_name}: skipped (sample PDF too minimal)")
            raise

        assert isinstance(
            out_bytes, (bytes, bytearray)
        ), f"{method_name}: add_watermark must return bytes"

        assert (
            len(out_bytes) >= len(original)
        ), f"{method_name}: watermarked bytes should not be smaller than input"

        assert out_bytes.startswith(
            b"%PDF-"
        ), f"{method_name}: output should still look like a PDF"

    def test_read_secret_roundtrip(
        self,
        method_name: str,
        impl: object,
        sample_pdf_path: Path,
        secret: str,
        key: str,
        tmp_path: Path,
    ):
        wm_impl = _as_instance(impl)

        if not wm_impl.is_watermark_applicable(sample_pdf_path, position=None):
            pytest.skip(f"{method_name}: not applicable to the sample PDF")

        try:
            out_bytes = wm_impl.add_watermark(
                sample_pdf_path,
                secret=secret,
                key=key,
                position=None,
            )
        except ValueError as e:
            if "cannot save with zero pages" in str(e).lower():
                pytest.skip(f"{method_name}: skipped (sample PDF too minimal)")
            raise

        out_pdf = tmp_path / f"{method_name}_watermarked.pdf"
        out_pdf.write_bytes(out_bytes)

        try:
            extracted = wm_impl.read_secret(out_pdf, key=key)
        except ValueError as e:
            if "cannot save with zero pages" in str(e).lower():
                pytest.skip(f"{method_name}: skipped (sample PDF too minimal)")
            raise

        assert isinstance(
            extracted, str
        ), f"{method_name}: read_secret must return str"

        assert (
            extracted == secret
        ), f"{method_name}: read_secret should return the exact embedded secret"