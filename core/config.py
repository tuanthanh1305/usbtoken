"""Định vị & nạp dữ liệu tĩnh của dự án (OS-agnostic).

Gồm: đường dẫn thư mục ``data/``, nạp ``vendor_intel.yaml`` (bảng Track A/B),
và đường dẫn tới kho neo tin cậy + bảng Phụ lục I/II.
"""

from __future__ import annotations

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


def current_trust_store_dir() -> Path:
    """Kho neo tin cậy ĐANG DÙNG (đã được áp dụng & ký)."""
    return trust_store_dir() / "current"


def trust_store_staging_dir() -> Path:
    """Nơi công cụ sync ghi tạm trước khi người vận hành xác nhận áp dụng."""
    return trust_store_dir() / "_staging"


def trust_store_internal_dir() -> Path:
    """Neo tin cậy nội bộ do người vận hành thêm (CA chuyên dùng)."""
    return trust_store_dir() / "internal"


def trust_sources_path() -> Path:
    """Danh mục URL nguồn chính thức (rootca.gov.vn) để tải kho."""
    return trust_store_dir() / "sources.yaml"


def ca_registry_path() -> Path:
    """Danh sách 26 CA công cộng làm MỐC ĐỐI SOÁT (không dùng nhận diện)."""
    return trust_store_dir() / "ca_registry.yaml"


def trust_audit_log_path() -> Path:
    """Nhật ký thay đổi kho tin cậy (áp dụng sync / thêm neo nội bộ)."""
    return trust_store_dir() / "audit.log"


def trust_signing_pub_path() -> Path:
    """Khoá CÔNG KHAI ghim sẵn (phía code) để verify chữ ký kho tin cậy.

    Đặt NGOÀI thư mục kho có thể thay đổi — coi như một phần của mã nguồn tin
    cậy. Khoá bí mật tương ứng do người vận hành/build giữ.
    """
    return data_dir() / "trust_signing_pub.pem"


def compliance_dir() -> Path:
    return data_dir() / "compliance"


def vendor_intel_path() -> Path:
    return data_dir() / "vendor_intel.yaml"


def atr_table_path() -> Path:
    """Bảng ATR -> gợi ý chip (cập nhật từ smartcard_list.txt của L. Rousseau)."""
    return data_dir() / "atr_table.yaml"


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


# Ghi chú: bảng vàng vendor_intel.yaml được nạp qua ``core/intel.py`` (có
# validate schema + ghi đè). Không đọc trực tiếp ở đây nữa.


def load_ca_registry() -> dict[str, Any]:
    """Nạp danh sách 26 CA công cộng (mốc đối soát)."""
    return _load_yaml(ca_registry_path())


def ca_registry_names() -> list[str]:
    """Tên 26 CA công cộng (từ ca_registry.yaml)."""
    reg = load_ca_registry()
    names = reg.get("public_cas") or []
    return [str(n) for n in names] if isinstance(names, list) else []


# Từ khoá chung để lọc gói/phần mềm CA (ngoài tên 26 CA). Cố ý KHÔNG dùng bare
# "ca" (quá rộng, gây dương tính giả) — ưu tiên độ chính xác cho dự án quốc gia.
_GENERIC_CA_KEYWORDS = (
    "token", "pkcs", "smartcard", "smart card", "esign", "e-sign",
    "ký số", "chữ ký số", "chu ky so", "chukyso",
)


def ca_discovery_keywords() -> list[str]:
    """Danh sách từ khoá (viết thường) để dò gói/phần mềm CA ở Tầng 1."""
    kws = [n.lower() for n in ca_registry_names()]
    kws.extend(_GENERIC_CA_KEYWORDS)
    # Khử trùng lặp giữ thứ tự.
    seen: dict[str, None] = {}
    for k in kws:
        seen.setdefault(k.strip(), None)
    return [k for k in seen if k]


def text_matches_ca_keyword(text: str) -> bool:
    """True nếu ``text`` (không phân biệt hoa thường) chứa một từ khoá CA."""
    low = text.lower()
    return any(kw in low for kw in ca_discovery_keywords())


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
    "current_trust_store_dir",
    "trust_store_staging_dir",
    "trust_store_internal_dir",
    "trust_sources_path",
    "ca_registry_path",
    "trust_audit_log_path",
    "trust_signing_pub_path",
    "compliance_dir",
    "vendor_intel_path",
    "atr_table_path",
    "appendix_i_path",
    "appendix_ii_path",
    "load_ca_registry",
    "ca_registry_names",
    "ca_discovery_keywords",
    "text_matches_ca_keyword",
    "load_appendix_i",
    "load_appendix_ii",
]
