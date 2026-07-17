"""Định vị & nạp dữ liệu tĩnh của dự án (OS-agnostic).

Gồm: đường dẫn thư mục ``data/``, nạp ``vendor_intel.yaml`` (bảng Track A/B),
và đường dẫn tới kho neo tin cậy + bảng Phụ lục I/II.
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml


def repo_root() -> Path:
    """Thư mục gốc repo (core/config.py -> lùi 2 cấp)."""
    return Path(__file__).resolve().parents[1]


def data_dir() -> Path:
    return repo_root() / "data"


def trust_store_dir() -> Path:
    return data_dir() / "trust_store"


def compliance_dir() -> Path:
    return data_dir() / "compliance"


def vendor_intel_path() -> Path:
    return data_dir() / "vendor_intel.yaml"


def appendix_i_path() -> Path:
    return compliance_dir() / "appendix_I.yaml"


def appendix_ii_path() -> Path:
    return compliance_dir() / "appendix_II.yaml"


def _load_yaml(path: Path) -> dict[str, Any]:
    """Nạp một file YAML thành dict (rỗng nếu thiếu/không hợp lệ)."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


@functools.lru_cache(maxsize=1)
def load_vendor_intel() -> dict[str, Any]:
    """Nạp bảng thông tin nhà cung cấp (Track A theo chip + Track B CA rebrand)."""
    return _load_yaml(vendor_intel_path())


def load_appendix_i() -> dict[str, Any]:
    """Nạp Phụ lục I (tiêu chuẩn kỹ thuật) — PHẢI được điền từ bản gốc TT 15/2025."""
    return _load_yaml(appendix_i_path())


def load_appendix_ii() -> dict[str, Any]:
    """Nạp Phụ lục II (yêu cầu hợp lệ chứng thư) — PHẢI được điền từ bản gốc."""
    return _load_yaml(appendix_ii_path())


__all__ = [
    "repo_root",
    "data_dir",
    "trust_store_dir",
    "compliance_dir",
    "vendor_intel_path",
    "appendix_i_path",
    "appendix_ii_path",
    "load_vendor_intel",
    "load_appendix_i",
    "load_appendix_ii",
]
