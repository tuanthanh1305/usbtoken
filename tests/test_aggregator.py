"""Test core/aggregator.merge_all_sources — gộp đa nguồn, đồng nhất 3 OS.

Tập trung LOGIC GỘP (khử trùng lặp theo sha256, ưu tiên has_private_key + thứ tự
nguồn, làm giàu bằng validator/CAInfo, đánh dấu fallback). Mọi collaborator được
TIÊM để chạy CI không cần token/mạng.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from core import x509_parser
from core.aggregator import (
    SOURCE_BRIDGE,
    SOURCE_P11KIT,
    SOURCE_PACKAGE,
    SOURCE_PKCS11,
    ca_info_from_validation,
    classify_token_source,
    merge_all_sources,
)
from core.cert_reader import CertReadResult
from core.models import (
    KeyInfo,
    TokenInfo,
    TrustPathNode,
    ValidationResult,
    ValidationStatusCode,
)
from core.platform import FALLBACK_LINUX_NSS, FallbackCert
from tests.certs import make_chain


# --------------------------------------------------------------------------- #
# Tiện ích dựng dữ liệu giả                                                     #
# --------------------------------------------------------------------------- #
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _certinfo(issued, *, with_key: bool):  # type: ignore[no-untyped-def]
    ci = x509_parser.parse(issued.der)
    if with_key:
        ci.key = KeyInfo(has_private_key=True, key_class="private", usable_for_signing=True)
    return ci


def _token(slot: int, *, module="/usr/lib/libtoken.so", via_bridge=False, source="system", serial=""):  # type: ignore[no-untyped-def]
    return TokenInfo(module_path=module, slot_id=slot, serial=serial, via_bridge=via_bridge, source=source)


class StubValidator:
    """Validator giả: ghi lại lời gọi, trả ValidationResult định trước."""

    def __init__(self, factory=None) -> None:  # type: ignore[no-untyped-def]
        self.calls: list[bytes] = []
        self._factory = factory

    def validate(self, cert_der: bytes, at_time=None):  # type: ignore[no-untyped-def]
        self.calls.append(cert_der)
        if self._factory is not None:
            return self._factory(cert_der)
        now = _now()
        return ValidationResult(status=ValidationStatusCode.UNKNOWN, checked_at=now, at_time=now)


def _enum(tokens, warnings=()):  # type: ignore[no-untyped-def]
    return lambda: (list(tokens), list(warnings))


def _reader(mapping):  # type: ignore[no-untyped-def]
    """cert_reader giả: token.slot_id -> CertReadResult."""

    def read(token, pin_callback=None):  # type: ignore[no-untyped-def]
        return mapping.get(token.slot_id, CertReadResult())

    return read


# --------------------------------------------------------------------------- #
# classify_token_source                                                        #
# --------------------------------------------------------------------------- #
def test_classify_source_pkcs11_default() -> None:
    assert classify_token_source(_token(0)) == SOURCE_PKCS11


def test_classify_source_bridge() -> None:
    assert classify_token_source(_token(0, via_bridge=True)) == SOURCE_BRIDGE


def test_classify_source_p11kit_wins_over_bridge() -> None:
    tok = _token(0, module="/usr/lib/p11-kit-proxy.so", via_bridge=True)
    assert classify_token_source(tok) == SOURCE_P11KIT


def test_classify_source_package_from_vendor_intel() -> None:
    assert classify_token_source(_token(0, source="vendor_intel")) == SOURCE_PACKAGE
    assert classify_token_source(_token(0, source="glob_probe")) == SOURCE_PACKAGE


# --------------------------------------------------------------------------- #
# ca_info_from_validation                                                      #
# --------------------------------------------------------------------------- #
def test_ca_info_from_validation() -> None:
    result = ValidationResult(
        status=ValidationStatusCode.VALID, checked_at=_now(), at_time=_now(),
        ca_name="VN Test Public CA",
        trust_path=[
            TrustPathNode(subject="CN=leaf", issuer="CN=ca", serial_hex="01"),
            TrustPathNode(subject="CN=VN Test Public CA", issuer="CN=root", serial_hex="02"),
            TrustPathNode(subject="CN=root", issuer="CN=root", serial_hex="03", is_trust_anchor=True),
        ],
    )
    ca = ca_info_from_validation(result)
    assert ca.ca_name == "VN Test Public CA"
    assert ca.ca_cert_subject == "CN=VN Test Public CA"  # phát hành TRỰC TIẾP
    assert ca.trust_anchor == "CN=root"
    assert ca.chain_verified is True


def test_ca_info_no_chain() -> None:
    result = ValidationResult(
        status=ValidationStatusCode.INVALID, checked_at=_now(), at_time=_now()
    )
    ca = ca_info_from_validation(result)
    assert ca.chain_verified is False and ca.trust_anchor == ""


# --------------------------------------------------------------------------- #
# merge_all_sources — nhánh cơ bản                                             #
# --------------------------------------------------------------------------- #
def test_merge_token_cert_enriched_with_validation() -> None:
    _, _, leaf = make_chain()
    tok = _token(1)
    reader = _reader({1: CertReadResult(certificates=[_certinfo(leaf, with_key=True)])})
    val = StubValidator()

    res = merge_all_sources(
        token_enumerator=_enum([tok]), cert_reader=reader,
        fallback_provider=lambda: [], validator=val,
    )
    assert len(res.tokens) == 1
    bundle = res.tokens[0]
    assert len(bundle.certificates) == 1
    rec = bundle.certificates[0]
    assert rec.from_token is True
    assert rec.source == SOURCE_PKCS11
    assert rec.validation is not None  # đã qua validator
    assert len(val.calls) == 1  # validator gọi đúng 1 lần cho 1 cert duy nhất


def test_merge_dedup_prefers_private_key() -> None:
    # Cùng 1 cert: bản token CÓ khoá private + bản fallback KHÔNG khoá.
    _, _, leaf = make_chain()
    tok = _token(1)
    reader = _reader({1: CertReadResult(certificates=[_certinfo(leaf, with_key=True)])})
    fallback = [FallbackCert(der=leaf.der, source=FALLBACK_LINUX_NSS, origin="nick")]

    res = merge_all_sources(
        token_enumerator=_enum([tok]), cert_reader=reader,
        fallback_provider=lambda: fallback, validator=StubValidator(),
    )
    # Chỉ còn 1 bản (khử trùng lặp), thuộc token, có khoá.
    assert len(res.tokens[0].certificates) == 1
    assert res.fallback_certificates == []
    rec = res.tokens[0].certificates[0]
    assert rec.from_token is True and rec.cert.key.has_private_key is True


def test_merge_source_priority_pkcs11_over_bridge() -> None:
    # Cùng cert (KHÔNG khoá) xuất hiện ở token bridge và token pkcs11 -> pkcs11 thắng.
    _, _, leaf = make_chain()
    pk = _token(1, module="/usr/lib/libA.so", via_bridge=False)  # PKCS11
    br = _token(2, module="/usr/lib/libB.so", via_bridge=True)   # BRIDGE
    reader = _reader({
        1: CertReadResult(certificates=[_certinfo(leaf, with_key=False)]),
        2: CertReadResult(certificates=[_certinfo(leaf, with_key=False)]),
    })
    res = merge_all_sources(
        token_enumerator=_enum([pk, br]), cert_reader=reader,
        fallback_provider=lambda: [], validator=StubValidator(),
    )
    counts = {b.token.slot_id: len(b.certificates) for b in res.tokens}
    assert counts == {1: 1, 2: 0}  # bản pkcs11 (slot 1) thắng, bridge rớt
    assert res.tokens[0].certificates[0].source == SOURCE_PKCS11


def test_merge_fallback_only_marked_not_from_token() -> None:
    _, _, leaf = make_chain()
    fallback = [FallbackCert(der=leaf.der, source=FALLBACK_LINUX_NSS, origin="Nguyen Van A")]
    res = merge_all_sources(
        token_enumerator=_enum([]), cert_reader=_reader({}),
        fallback_provider=lambda: fallback, validator=StubValidator(),
    )
    assert res.tokens == []
    assert len(res.fallback_certificates) == 1
    rec = res.fallback_certificates[0]
    assert rec.from_token is False
    assert rec.source == FALLBACK_LINUX_NSS
    # Cảnh báo rõ: không đọc trực tiếp từ token.
    assert any("KHO HỆ ĐIỀU HÀNH" in w for w in rec.cert.warnings)


def test_merge_empty_token_still_bundled() -> None:
    tok = _token(1)
    res = merge_all_sources(
        token_enumerator=_enum([tok]), cert_reader=_reader({}),  # không cert
        fallback_provider=lambda: [], validator=StubValidator(),
    )
    assert len(res.tokens) == 1 and res.tokens[0].certificates == []


def test_merge_validator_called_once_per_unique_cert() -> None:
    root, inter, leaf = make_chain()
    tok = _token(1)
    reader = _reader({1: CertReadResult(certificates=[
        _certinfo(leaf, with_key=True), _certinfo(inter, with_key=False),
    ])})
    val = StubValidator()
    merge_all_sources(
        token_enumerator=_enum([tok]), cert_reader=reader,
        fallback_provider=lambda: [], validator=val,
    )
    assert len(val.calls) == 2  # 2 cert khác nhau -> 2 lần validate


def test_merge_warnings_from_reader_and_enumerator() -> None:
    tok = _token(1)
    reader = _reader({1: CertReadResult(certificates=[], warnings=["cần đăng nhập PIN"])})
    res = merge_all_sources(
        token_enumerator=_enum([tok], warnings=["module X lỗi"]),
        cert_reader=reader, fallback_provider=lambda: [], validator=StubValidator(),
    )
    assert "module X lỗi" in res.warnings
    assert "cần đăng nhập PIN" in res.warnings


def test_merge_sources_scanned_includes_fallback() -> None:
    _, _, leaf = make_chain()
    tok = _token(1)
    reader = _reader({1: CertReadResult(certificates=[_certinfo(leaf, with_key=True)])})
    fallback = [FallbackCert(der=make_chain()[2].der, source=FALLBACK_LINUX_NSS)]
    res = merge_all_sources(
        token_enumerator=_enum([tok]), cert_reader=reader,
        fallback_provider=lambda: fallback, validator=StubValidator(),
    )
    assert SOURCE_PKCS11 in res.sources_scanned
    assert FALLBACK_LINUX_NSS in res.sources_scanned


def test_merge_include_fallback_false_skips_os_store() -> None:
    _, _, leaf = make_chain()
    called = {"n": 0}

    def fb():  # type: ignore[no-untyped-def]
        called["n"] += 1
        return [FallbackCert(der=leaf.der, source=FALLBACK_LINUX_NSS)]

    res = merge_all_sources(
        token_enumerator=_enum([]), cert_reader=_reader({}),
        fallback_provider=fb, validator=StubValidator(), include_fallback=False,
    )
    assert called["n"] == 0  # KHÔNG gọi kho OS
    assert res.fallback_certificates == []


# --------------------------------------------------------------------------- #
# Tích hợp: validator THẬT (kho rỗng -> INVALID) — vẫn đính bằng chứng          #
# --------------------------------------------------------------------------- #
def test_merge_with_real_validator_empty_store(tmp_path: Path) -> None:
    from core.trust.store import TrustStore
    from core.trust.policy import CompliancePolicy
    from core.trust.validator import CertificateValidator

    _, _, leaf = make_chain()
    validator = CertificateValidator(
        store=TrustStore(store_dir=tmp_path), policy=CompliancePolicy()
    )
    tok = _token(1)
    reader = _reader({1: CertReadResult(certificates=[_certinfo(leaf, with_key=True)])})
    res = merge_all_sources(
        token_enumerator=_enum([tok]), cert_reader=reader,
        fallback_provider=lambda: [], validator=validator,
    )
    rec = res.tokens[0].certificates[0]
    # Kho rỗng -> INVALID (fail-closed) nhưng vẫn có bằng chứng + lý do tiếng Việt.
    assert rec.validation.status is ValidationStatusCode.INVALID
    assert rec.validation.reasons_vi
