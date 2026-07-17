"""Test CLI chẩn đoán ``python -m core.platform --diagnose``."""

from __future__ import annotations

import pytest

from core.platform.__main__ import main


def test_diagnose_runs(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["--diagnose"])
    out = capsys.readouterr().out
    assert code in (0, 1)
    assert "CHẨN ĐOÁN TẦNG PLATFORM" in out
    assert "Host arch" in out
    assert "Module PKCS#11" in out


def test_diagnose_default_no_flag(capsys: pytest.CaptureFixture[str]) -> None:
    code = main([])
    assert code in (0, 1)
    assert "vn-esign-suite" in capsys.readouterr().out
