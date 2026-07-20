"""CHAIN BUILDING — nhận diện CA bằng MẬT MÃ, tuyệt đối KHÔNG bằng regex.

Dựng đường dẫn tin cậy từ chứng thư người ký (leaf) lên tới một neo gốc trong
:class:`TrustAnchorStore`. Mỗi bước xác thực chữ ký "cha phát hành con" bằng
``Certificate.verify_directly_issued_by`` (kiểm tên phát hành + chữ ký số).

Kết quả cho biết CA phát hành (TRỤC 3) một cách CÓ GIÁ TRỊ PHÁP LÝ — khác hẳn
việc đoán mò bằng chuỗi Issuer.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from core.models import CAInfo, TrustPathNode

from .anchors import TrustAnchorStore

# Số mắt xích tối đa để chặn vòng lặp/chuỗi bất thường.
_MAX_DEPTH = 16


def _rfc4514(name: x509.Name) -> str:
    return name.rfc4514_string()


def _fingerprint_hex(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _to_node(cert: x509.Certificate, *, is_anchor: bool) -> TrustPathNode:
    return TrustPathNode(
        subject=_rfc4514(cert.subject),
        issuer=_rfc4514(cert.issuer),
        serial_hex=format(cert.serial_number, "x"),
        is_trust_anchor=is_anchor,
        fingerprint_sha256=_fingerprint_hex(cert),
    )


@dataclass(slots=True)
class ChainResult:
    """Kết quả dựng chuỗi."""

    path: list[x509.Certificate] = field(default_factory=list)
    verified: bool = False  # dựng được tới neo gốc + mọi chữ ký hợp lệ
    reached_anchor: bool = False
    reasons_vi: list[str] = field(default_factory=list)

    def nodes(self, store: TrustAnchorStore) -> list[TrustPathNode]:
        """Chuyển path thành danh sách node để lưu làm bằng chứng."""
        return [_to_node(c, is_anchor=store.is_trust_anchor(c)) for c in self.path]

    def ca_info(self) -> CAInfo:
        """Nhận diện CA phát hành (TRỤC 3) từ chuỗi đã dựng."""
        if len(self.path) < 2:
            return CAInfo(chain_verified=self.verified)
        issuer_cert = self.path[1]  # chứng thư phát hành trực tiếp leaf
        anchor_subject = ""
        if self.reached_anchor and self.path:
            anchor_subject = _rfc4514(self.path[-1].subject)
        # Tên CA lấy từ CN của chứng thư CA (không parse chuỗi Issuer của leaf).
        try:
            cn = issuer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            ca_name = cn[0].value if cn else _rfc4514(issuer_cert.subject)
        except Exception:  # noqa: BLE001
            ca_name = _rfc4514(issuer_cert.subject)
        return CAInfo(
            ca_name=str(ca_name),
            ca_cert_subject=_rfc4514(issuer_cert.subject),
            chain_verified=self.verified,
            trust_anchor=anchor_subject,
        )


class ChainBuilder:
    """Dựng & xác thực đường dẫn tin cậy dựa trên :class:`TrustAnchorStore`."""

    def __init__(self, store: TrustAnchorStore) -> None:
        self.store = store

    def build(self, leaf: x509.Certificate) -> ChainResult:
        """Dựng chuỗi từ ``leaf`` lên neo gốc, xác thực từng chữ ký."""
        result = ChainResult(path=[leaf])
        if self.store.is_empty:
            result.reasons_vi.append(
                "Kho neo tin cậy rỗng — chưa nạp chứng thư gốc NEAC + các CA. "
                "Không thể xác định CA hay hiệu lực."
            )
            return result

        current = leaf
        seen: set[str] = {_fingerprint_hex(current)}

        for _ in range(_MAX_DEPTH):
            if self.store.is_trust_anchor(current):
                result.reached_anchor = True
                result.verified = True
                result.reasons_vi.append("Đã dựng đường dẫn tin cậy tới neo gốc.")
                return result

            parent = self._find_issuer(current)
            if parent is None:
                result.reasons_vi.append(
                    "Không tìm được chứng thư phát hành hợp lệ trong kho tin cậy "
                    "(chuỗi bị đứt hoặc chữ ký không khớp)."
                )
                return result

            fp = _fingerprint_hex(parent)
            if fp in seen:
                result.reasons_vi.append("Phát hiện vòng lặp trong chuỗi chứng thư.")
                return result
            seen.add(fp)
            result.path.append(parent)
            current = parent

            if self.store.is_trust_anchor(parent):
                result.reached_anchor = True
                result.verified = True
                result.reasons_vi.append("Đã dựng đường dẫn tin cậy tới neo gốc.")
                return result

        result.reasons_vi.append(f"Chuỗi vượt quá độ sâu tối đa ({_MAX_DEPTH}).")
        return result

    def _find_issuer(self, cert: x509.Certificate) -> x509.Certificate | None:
        """Tìm chứng thư cha THẬT SỰ đã ký ``cert`` (xác thực bằng mật mã)."""
        for candidate in self.store.issuers_of(cert):
            try:
                # Kiểm tên phát hành khớp + xác thực chữ ký số của cha lên con.
                cert.verify_directly_issued_by(candidate)
            except Exception:  # noqa: BLE001 - chữ ký/tên không khớp -> thử cha khác
                continue
            return candidate
        return None


__all__ = ["ChainBuilder", "ChainResult"]
