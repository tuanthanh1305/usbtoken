"""Client kết nối Cổng eSign (scaffold).

⚠️ Endpoint/giao thức CHÍNH THỨC của Cổng eSign PHẢI lấy từ tài liệu tích hợp do
NEAC/Bộ KH&CN cung cấp — KHÔNG hardcode/suy đoán URL hay định dạng ở đây. Client
này chỉ dựng khung: đọc cấu hình (base_url, xác thực, TLS) và cung cấp các thao
tác dạng hợp đồng. Khi chưa cấu hình ``base_url`` -> mọi lời gọi mạng bị từ chối.

Cấu hình đọc từ ``<config_dir>/esign_gateway.yaml`` hoặc biến môi trường
``VN_ESIGN_GATEWAY_URL``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.errors import ESignGatewayError


@dataclass(slots=True)
class ESignGatewayConfig:
    """Cấu hình kết nối Cổng eSign."""

    base_url: str = ""
    timeout: float = 30.0
    verify_tls: bool = True
    # Thông tin xác thực (API key / mTLS) — nạp từ cấu hình an toàn, KHÔNG commit.
    api_key: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.base_url)

    @classmethod
    def load(cls) -> "ESignGatewayConfig":
        """Nạp cấu hình từ file YAML trong config_dir + override bằng biến môi trường."""
        import os

        from core.platform import get_adapter

        data: dict[str, Any] = {}
        cfg_path = get_adapter().config_dir() / "esign_gateway.yaml"
        try:
            if cfg_path.is_file():
                import yaml

                loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = loaded
        except Exception:  # noqa: BLE001
            data = {}

        base_url = os.environ.get("VN_ESIGN_GATEWAY_URL", str(data.get("base_url", "")))
        return cls(
            base_url=base_url.strip(),
            timeout=float(data.get("timeout", 30.0)),
            verify_tls=bool(data.get("verify_tls", True)),
            api_key=os.environ.get("VN_ESIGN_GATEWAY_API_KEY", str(data.get("api_key", ""))),
        )


class ESignGatewayClient:
    """Client HTTP tới Cổng eSign (các thao tác dạng hợp đồng, endpoint chờ spec)."""

    def __init__(self, config: ESignGatewayConfig | None = None) -> None:
        self.config = config or ESignGatewayConfig.load()

    def _require_configured(self) -> None:
        if not self.config.configured:
            raise ESignGatewayError(
                "Chưa cấu hình Cổng eSign (thiếu base_url).",
                detail="Đặt VN_ESIGN_GATEWAY_URL hoặc điền config_dir/esign_gateway.yaml "
                "theo tài liệu tích hợp chính thức của NEAC.",
            )

    def health(self) -> bool:
        """Kiểm tra kết nối tới Cổng (nếu đã cấu hình)."""
        self._require_configured()
        try:
            import httpx

            resp = httpx.get(
                self.config.base_url,
                timeout=self.config.timeout,
                verify=self.config.verify_tls,
            )
            return resp.status_code < 500
        except Exception as exc:  # noqa: BLE001
            raise ESignGatewayError("Không kết nối được Cổng eSign.", detail=str(exc)) from exc

    def fetch_trust_list(self) -> bytes:
        """Tải danh sách chứng thư tin cậy (NEAC + CA + nước ngoài).

        Endpoint cụ thể theo tài liệu tích hợp chính thức — hiện là chỗ dành sẵn.
        """
        self._require_configured()
        raise ESignGatewayError(
            "fetch_trust_list: endpoint chính thức của Cổng eSign chưa được cấu hình "
            "(chờ tài liệu tích hợp NEAC).",
        )

    def request_timestamp(self, digest: bytes, *, hash_alg: str = "") -> bytes:
        """Yêu cầu dấu thời gian (TSA) cho một digest — theo Phụ lục I.

        ``hash_alg`` để trống vì thuật toán băm hợp lệ phải lấy từ Phụ lục I
        (không suy đoán). Trả token dấu thời gian (RFC 3161) khi có spec.
        """
        self._require_configured()
        raise ESignGatewayError(
            "request_timestamp: cần thuật toán băm từ Phụ lục I + endpoint TSA chính thức."
        )


__all__ = ["ESignGatewayClient", "ESignGatewayConfig"]
