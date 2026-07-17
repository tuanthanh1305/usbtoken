"""Bảo vệ QUY TẮC KIẾN TRÚC: mọi ``platform.system()`` chỉ nằm trong core/platform/."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_PLATFORM_DIR = REPO_ROOT / "core" / "platform"
_FORBIDDEN = re.compile(r"platform\s*\.\s*system\s*\(")


def _scanned_files() -> list[Path]:
    files: list[Path] = []
    for base in ("core", "service", "tools"):
        for path in (REPO_ROOT / base).rglob("*.py"):
            if _PLATFORM_DIR in path.parents:
                continue
            files.append(path)
    return files


def test_no_platform_system_outside_platform_layer() -> None:
    offenders = [
        str(p.relative_to(REPO_ROOT))
        for p in _scanned_files()
        if _FORBIDDEN.search(p.read_text(encoding="utf-8"))
    ]
    assert not offenders, f"platform.system() chỉ được ở core/platform/. Vi phạm: {offenders}"


def test_business_modules_do_not_import_os_adapters() -> None:
    """engine/discovery/trust không import trực tiếp windows/macos/linux."""
    for module in ("engine.py", "discovery.py", "trust/validator.py"):
        text = (REPO_ROOT / "core" / module).read_text(encoding="utf-8")
        for banned in ("platform.windows", "platform.macos", "platform.linux"):
            assert banned not in text, f"{module} không được import core.{banned}"
