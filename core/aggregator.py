"""Gộp chứng thư từ MỌI nguồn — CHUNG 3 OS, kết quả ĐỒNG NHẤT.

``merge_all_sources()`` hợp nhất chứng thư đọc được qua nhiều đường:

    PKCS11   — đọc trực tiếp từ token, module nạp in-process (ưu tiên cao nhất).
    BRIDGE   — đọc từ token nhưng module lệch arch, phải qua cầu nối.
    P11KIT   — đọc qua p11-kit-proxy.
    PACKAGE  — module Track B (gói CA rebrand: vendor_intel / tự dò C_GetInfo).
    fallback — CHỨNG THƯ TRONG KHO HỆ ĐIỀU HÀNH (CertStore/Keychain/NSS), KHÔNG
               đọc trực tiếp từ token. Dùng khi PKCS#11 không dò ra module nhưng
               cert vẫn nằm trong kho OS (nhiều middleware CA VN tự đẩy vào).

QUY TẮC GỘP:
    * KHỬ TRÙNG LẶP theo ``sha256_thumbprint`` (vân tay DER — mật mã, không đoán).
    * Ưu tiên bản có ``has_private_key=True`` (ký được), rồi theo thứ tự nguồn:
      PKCS11 > BRIDGE > P11KIT > PACKAGE > fallback OS.

⭐ Với MỖI chứng thư duy nhất: gọi TRUST VALIDATOR (Điều 6 TT 15/2025) để đính
:class:`ValidationResult` (bằng chứng pháp lý) + :class:`CAInfo` (CA lấy TỪ chain
building, KHÔNG regex). Có mặt trong kho OS KHÔNG có nghĩa là hợp lệ — mọi chứng
thư đều phải qua validator; nguồn fallback được ĐÁNH DẤU RÕ.

CLI: ``python -m core.aggregator --json``.
"""

from __future__ import annotations

import base64
import hashlib
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from core.models import (
    AggregateResult,
    CAInfo,
    CertInfo,
    CertRecord,
    TokenBundle,
    TokenInfo,
    ValidationResult,
    ValidationStatusCode,
)
from core.platform import (
    FALLBACK_LINUX_NSS,
    FALLBACK_MAC_KEYCHAIN,
    FALLBACK_WIN_CERTSTORE,
    FallbackCert,
    PlatformAdapter,
    get_adapter,
)

# Thứ tự ưu tiên nguồn (số NHỎ = ưu tiên CAO). Fallback OS xếp cuối.
SOURCE_PKCS11 = "PKCS11"
SOURCE_BRIDGE = "BRIDGE"
SOURCE_P11KIT = "P11KIT"
SOURCE_PACKAGE = "PACKAGE"

_SOURCE_RANK: dict[str, int] = {
    SOURCE_PKCS11: 0,
    SOURCE_BRIDGE: 1,
    SOURCE_P11KIT: 2,
    SOURCE_PACKAGE: 3,
    FALLBACK_WIN_CERTSTORE: 4,
    FALLBACK_MAC_KEYCHAIN: 4,
    FALLBACK_LINUX_NSS: 4,
}
_RANK_FALLBACK = 9  # nguồn lạ -> xếp sau cùng


def _rank(source: str) -> int:
    return _SOURCE_RANK.get(source, _RANK_FALLBACK)


# --------------------------------------------------------------------------- #
# Giao diện tiêm (cho phép test không cần token/mạng)                           #
# --------------------------------------------------------------------------- #
class _Validator(Protocol):
    def validate(self, cert_der: bytes, at_time: Any = None) -> ValidationResult: ...


# (token, pin_callback) -> CertReadResult-like (có .certificates, .warnings)
CertReaderFn = Callable[..., Any]
# () -> (list[TokenInfo], list[str] cảnh báo)
TokenEnumerator = Callable[[], tuple[list[TokenInfo], list[str]]]
FallbackProvider = Callable[[], list[FallbackCert]]
PinCallback = Callable[[], "bytes | bytearray | str"]


# --------------------------------------------------------------------------- #
# Phân loại nguồn của một token (TRỤC 1 — cách nạp, KHÔNG dính chip/CA)          #
# --------------------------------------------------------------------------- #
def classify_token_source(token: TokenInfo) -> str:
    """Suy nhãn nguồn từ cách token được liệt kê (transport + gốc module).

    Chỉ phản ánh ĐƯỜNG đọc chứng thư (để xếp ưu tiên khi trùng lặp), KHÔNG phải
    kết luận về chip (TRỤC 2) hay CA (TRỤC 3).
    """
    name = token.module_path.lower()
    if "p11-kit-proxy" in name:
        return SOURCE_P11KIT
    if token.via_bridge:
        return SOURCE_BRIDGE
    # Track B (CA rebrand) dò qua vendor_intel/glob_probe -> gói PACKAGE.
    if token.source in ("vendor_intel", "glob_probe"):
        return SOURCE_PACKAGE
    return SOURCE_PKCS11


# --------------------------------------------------------------------------- #
# CAInfo suy TỪ ValidationResult (chain building, KHÔNG regex)                  #
# --------------------------------------------------------------------------- #
def ca_info_from_validation(result: ValidationResult) -> CAInfo:
    """Dựng :class:`CAInfo` từ đường dẫn tin cậy đã xác thực bằng mật mã."""
    path = result.trust_path
    anchor = ""
    ca_subject = ""
    if len(path) >= 2:
        ca_subject = path[1].subject  # CA phát hành trực tiếp
    if path and path[-1].is_trust_anchor:
        anchor = path[-1].subject
    # chain_verified: đã dựng được tới một neo gốc (root/nước-ngoài tự phát hành).
    chain_verified = bool(path) and path[-1].is_trust_anchor and result.status in (
        ValidationStatusCode.VALID,
        ValidationStatusCode.EXPIRED,
        ValidationStatusCode.REVOKED,
        ValidationStatusCode.UNKNOWN,
        ValidationStatusCode.FOREIGN_RECOGNIZED,
    )
    return CAInfo(
        ca_name=result.ca_name,
        ca_cert_subject=ca_subject,
        chain_verified=chain_verified,
        trust_anchor=anchor,
    )


# --------------------------------------------------------------------------- #
# Ứng viên thô nội bộ (trước khử trùng lặp)                                     #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class _Raw:
    der: bytes
    thumb: str
    cert: CertInfo
    source: str
    from_token: bool
    token_key: str  # khoá gộp về token nguồn ("" nếu fallback)

    @property
    def has_key(self) -> bool:
        return bool(self.cert.key and self.cert.key.has_private_key)


def _thumb(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _better(candidate: _Raw, current: _Raw) -> bool:
    """``candidate`` có nên thay ``current`` làm bản đại diện không?"""
    if candidate.has_key != current.has_key:
        return candidate.has_key  # ưu tiên bản ký được
    return _rank(candidate.source) < _rank(current.source)  # rồi tới thứ tự nguồn


# --------------------------------------------------------------------------- #
# API chính                                                                    #
# --------------------------------------------------------------------------- #
def merge_all_sources(
    adapter: PlatformAdapter | None = None,
    *,
    pin_callback: PinCallback | None = None,
    validator: _Validator | None = None,
    token_enumerator: TokenEnumerator | None = None,
    cert_reader: CertReaderFn | None = None,
    fallback_provider: FallbackProvider | None = None,
    include_fallback: bool = True,
) -> AggregateResult:
    """Gộp mọi nguồn -> :class:`AggregateResult` (đồng nhất 3 OS).

    Mọi collaborator đều tiêm được để chạy CI không cần token/mạng.
    """
    ad = adapter or get_adapter()
    val = validator if validator is not None else _default_validator()
    enum = token_enumerator or (lambda: _default_enumerate(ad))
    read = cert_reader or _default_reader
    fb = fallback_provider or ad.certstore_fallback

    warnings: list[str] = []
    tokens, enum_warnings = enum()
    warnings.extend(enum_warnings)

    # Giữ thứ tự token + khoá gộp ổn định.
    token_keys: list[str] = [_token_key(i, t) for i, t in enumerate(tokens)]
    bundles: dict[str, TokenBundle] = {
        k: TokenBundle(token=t) for k, t in zip(token_keys, tokens, strict=False)
    }

    raws: list[_Raw] = []

    # -- Nguồn token (PKCS11/BRIDGE/P11KIT/PACKAGE) --------------------- #
    for key, token in zip(token_keys, tokens, strict=False):
        source = classify_token_source(token)
        try:
            res = read(token, pin_callback)
        except Exception as exc:  # noqa: BLE001 - cô lập: 1 token lỗi không chặn nguồn khác
            warnings.append(f"Đọc chứng thư token thất bại ({source}): {exc}")
            continue
        for w in getattr(res, "warnings", []) or []:
            warnings.append(w)
        err = getattr(res, "error", None)
        if err is not None:
            warnings.append(getattr(err, "message_vi", str(err)))
        for cert in getattr(res, "certificates", []) or []:
            raw = _raw_from_certinfo(cert, source=source, from_token=True, token_key=key)
            if raw is not None:
                raws.append(raw)

    # -- Fallback kho OS (CertStore/Keychain/NSS) ---------------------- #
    sources_scanned = {classify_token_source(t) for t in tokens}
    if include_fallback:
        try:
            fallbacks = fb()
        except Exception as exc:  # noqa: BLE001
            fallbacks = []
            warnings.append(f"Đọc kho chứng thư hệ điều hành thất bại: {exc}")
        for fc in fallbacks:
            sources_scanned.add(fc.source)
            raw = _raw_from_fallback(fc)
            if raw is not None:
                raws.append(raw)

    # -- KHỬ TRÙNG LẶP theo sha256 (ưu tiên has_key, rồi thứ tự nguồn) -- #
    winners: dict[str, _Raw] = {}
    for raw in raws:
        cur = winners.get(raw.thumb)
        if cur is None or _better(raw, cur):
            winners[raw.thumb] = raw

    # -- LÀM GIÀU: validator + CAInfo cho từng chứng thư duy nhất ------- #
    fallback_records: list[CertRecord] = []
    for raw in winners.values():
        result = val.validate(raw.der)
        record = CertRecord(
            cert=raw.cert,
            ca=ca_info_from_validation(result),
            validation=result,
            source=raw.source,
            from_token=raw.from_token,
            token_ref=raw.token_key,
        )
        if raw.from_token and raw.token_key in bundles:
            bundles[raw.token_key].certificates.append(record)
        else:
            fallback_records.append(record)

    return AggregateResult(
        tokens=[bundles[k] for k in token_keys],
        fallback_certificates=fallback_records,
        sources_scanned=sorted(sources_scanned, key=_rank),
        warnings=warnings,
    )


# --------------------------------------------------------------------------- #
# Dựng _Raw từ CertInfo / FallbackCert                                          #
# --------------------------------------------------------------------------- #
def _raw_from_certinfo(
    cert: CertInfo, *, source: str, from_token: bool, token_key: str
) -> _Raw | None:
    if not cert.der_b64:
        return None
    try:
        der = base64.b64decode(cert.der_b64)
    except (ValueError, TypeError):
        return None
    return _Raw(
        der=der, thumb=cert.sha256_thumbprint or _thumb(der), cert=cert,
        source=source, from_token=from_token, token_key=token_key,
    )


def _raw_from_fallback(fc: FallbackCert) -> _Raw | None:
    from core import x509_parser

    try:
        cert = x509_parser.parse(fc.der)
    except Exception:  # noqa: BLE001 - der rác trong kho OS không được làm sập gộp
        cert = CertInfo(der_b64=base64.b64encode(fc.der).decode("ascii"))
    cert.warnings.append(
        f"Chứng thư đọc từ KHO HỆ ĐIỀU HÀNH ({fc.source}"
        + (f":{fc.origin}" if fc.origin else "")
        + ") — KHÔNG đọc trực tiếp từ token; vẫn phải qua kiểm tra hiệu lực."
    )
    return _Raw(
        der=fc.der, thumb=cert.sha256_thumbprint or _thumb(fc.der), cert=cert,
        source=fc.source, from_token=False, token_key="",
    )


def _token_key(index: int, token: TokenInfo) -> str:
    return f"{index}:{token.module_path}|slot={token.slot_id}|sn={token.serial}"


# --------------------------------------------------------------------------- #
# Collaborator mặc định (thật)                                                  #
# --------------------------------------------------------------------------- #
def _default_validator() -> _Validator:
    from core.trust.validator import CertificateValidator

    return CertificateValidator()


def _default_enumerate(adapter: PlatformAdapter) -> tuple[list[TokenInfo], list[str]]:
    from core.pkcs11_engine import enumerate_detailed

    result = enumerate_detailed(adapter=adapter)
    warns: list[str] = []
    for rep in result.reports:
        if rep.error is not None:
            warns.append(f"[{rep.module_path}] {rep.error.message_vi}")
    return result.tokens, warns


def _default_reader(token: TokenInfo, pin_callback: PinCallback | None) -> Any:
    from core.cert_reader import read_certificates

    return read_certificates(token, pin_callback)


# --------------------------------------------------------------------------- #
# CLI: python -m core.aggregator --json                                        #
# --------------------------------------------------------------------------- #
def _print_summary(result: AggregateResult) -> None:
    total = sum(len(b.certificates) for b in result.tokens) + len(result.fallback_certificates)
    print(f"Nguồn đã quét: {', '.join(result.sources_scanned) or '(không)'}")
    print(f"Token: {len(result.tokens)} · chứng thư (đã khử trùng lặp): {total}")
    print("=" * 78)
    for b in result.tokens:
        t = b.token
        print(f"■ TOKEN: {t.label or '(không nhãn)'} · CHIP THẬT={t.manufacturer_id or '-'} "
              f"· slot {t.slot_id} · {'via-bridge' if t.via_bridge else 'in-process'}")
        _print_records(b.certificates)
    if result.fallback_certificates:
        print("-" * 78)
        print("KHO HỆ ĐIỀU HÀNH (KHÔNG đọc trực tiếp từ token):")
        _print_records(result.fallback_certificates)
    for w in result.warnings:
        print(f"  ⚠ {w}")


def _print_records(records: list[CertRecord]) -> None:
    for r in records:
        st = r.validation.status.value
        key = "CÓ-KHOÁ" if (r.cert.key and r.cert.key.has_private_key) else "no-key"
        print(f"   • [{r.source}·{key}] {r.cert.subject_raw}")
        print(f"       CA={r.ca.ca_name or '?'} (chain={'✓' if r.ca.chain_verified else '✗'}) "
              f"· hiệu lực={st}")


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m core.aggregator")
    parser.add_argument("--json", action="store_true", help="Xuất JSON đầy đủ.")
    parser.add_argument("--no-fallback", action="store_true", help="Bỏ nguồn kho OS.")
    args = parser.parse_args(argv)

    result = merge_all_sources(include_fallback=not args.no_fallback)
    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        _print_summary(result)
    total = sum(len(b.certificates) for b in result.tokens) + len(result.fallback_certificates)
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())


__all__ = [
    "merge_all_sources",
    "classify_token_source",
    "ca_info_from_validation",
    "SOURCE_PKCS11",
    "SOURCE_BRIDGE",
    "SOURCE_P11KIT",
    "SOURCE_PACKAGE",
]
