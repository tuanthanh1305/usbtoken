"""Chính sách tuân thủ — nạp Phụ lục I (tiêu chuẩn kỹ thuật) & Phụ lục II
(yêu cầu hợp lệ chứng thư) của TT 15/2025.

⚠️ NGUYÊN TẮC: KHÔNG suy đoán thuật toán/độ dài khoá/định dạng. Mọi tham số phải
được TRANSCRIBE từ bản gốc:
    https://rootca.gov.vn/VanBan/Thongtu_So15_2025_TT_BKHCN.pdf
vào ``data/compliance/appendix_I.yaml`` và ``appendix_II.yaml``. Trước khi hai
file này ở trạng thái ``status: filled``, mọi kiểm tra "chặt" theo Phụ lục sẽ
BỊ TỪ CHỐI (fail-safe) thay vì đoán bừa và tạo ra kết quả sai về pháp lý.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.config import load_appendix_i, load_appendix_ii
from core.errors import PolicyNotConfiguredError

# Các giá trị hợp lệ của trường ``status`` để coi phụ lục là ĐÃ điền & xác minh.
_FILLED_STATES = {"filled", "verified", "reviewed", "done"}


@dataclass(slots=True)
class PolicyStatus:
    """Trạng thái cấu hình của hai phụ lục."""

    appendix_i_filled: bool
    appendix_ii_filled: bool

    @property
    def fully_configured(self) -> bool:
        return self.appendix_i_filled and self.appendix_ii_filled


class CompliancePolicy:
    """Bọc dữ liệu Phụ lục I/II + các guard fail-safe.

    Đọc dữ liệu lười khi khởi tạo. Nếu phụ lục chưa điền, các hàm ``require_*``
    ném :class:`PolicyNotConfiguredError` — buộc phải hoàn tất transcribe trước
    khi bật kiểm tra chặt (PROMPT 9 & 12).
    """

    def __init__(self) -> None:
        self._app_i: dict[str, Any] = load_appendix_i()
        self._app_ii: dict[str, Any] = load_appendix_ii()

    @staticmethod
    def _is_filled(doc: dict[str, Any]) -> bool:
        return str(doc.get("status", "")).strip().lower() in _FILLED_STATES

    def status(self) -> PolicyStatus:
        return PolicyStatus(
            appendix_i_filled=self._is_filled(self._app_i),
            appendix_ii_filled=self._is_filled(self._app_ii),
        )

    @property
    def is_configured(self) -> bool:
        return self.status().fully_configured

    def require_configured(self) -> None:
        """Ném lỗi nếu Phụ lục I/II chưa điền (fail-safe pháp lý)."""
        st = self.status()
        if st.fully_configured:
            return
        missing = []
        if not st.appendix_i_filled:
            missing.append("Phụ lục I (data/compliance/appendix_I.yaml)")
        if not st.appendix_ii_filled:
            missing.append("Phụ lục II (data/compliance/appendix_II.yaml)")
        raise PolicyNotConfiguredError(
            "Chưa điền/duyệt " + " và ".join(missing) + " từ bản gốc TT 15/2025. "
            "Không thể kiểm tra hợp lệ chứng thư theo Phụ lục cho tới khi hoàn tất.",
            detail="Tải bản gốc: https://rootca.gov.vn/VanBan/Thongtu_So15_2025_TT_BKHCN.pdf",
        )

    # -- Truy vấn tham số Phụ lục (chỉ dùng SAU khi require_configured) ---- #
    def allowed_signature_algorithms(self) -> list[str]:
        """Danh sách thuật toán ký hợp lệ (Phụ lục I)."""
        self.require_configured()
        value = self._app_i.get("signature_algorithms") or []
        return [str(v) for v in value] if isinstance(value, list) else []

    def min_key_sizes(self) -> dict[str, int]:
        """Độ dài khoá tối thiểu theo hệ (Phụ lục I), vd. {"RSA": 2048, "EC": 256}."""
        self.require_configured()
        value = self._app_i.get("min_key_sizes") or {}
        return {str(k): int(v) for k, v in value.items()} if isinstance(value, dict) else {}

    def hash_algorithms(self) -> list[str]:
        """Hàm băm hợp lệ (Phụ lục I)."""
        self.require_configured()
        value = self._app_i.get("hash_algorithms") or []
        return [str(v) for v in value] if isinstance(value, list) else []

    def signature_formats(self) -> list[str]:
        """Định dạng chữ ký hợp lệ (Phụ lục I): CAdES | PAdES | XAdES."""
        self.require_configured()
        value = self._app_i.get("signature_formats") or []
        return [str(v) for v in value] if isinstance(value, list) else []

    def timestamp_policy(self) -> dict[str, Any]:
        """Chính sách dấu thời gian (Phụ lục I): {required_when, tsa_profile}."""
        self.require_configured()
        value = self._app_i.get("timestamp") or {}
        return dict(value) if isinstance(value, dict) else {}

    def certificate_requirements(self) -> dict[str, Any]:
        """Yêu cầu hợp lệ chứng thư (Phụ lục II)."""
        self.require_configured()
        reqs = self._app_ii.get("certificate_requirements") or {}
        return dict(reqs) if isinstance(reqs, dict) else {}


__all__ = ["CompliancePolicy", "PolicyStatus"]
