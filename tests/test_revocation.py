"""Test kiểm THU HỒI (core/trust/revocation.py) — độ tươi CRL online.

REGRESSION: một CRL đã HẾT HẠN (nextUpdate quá khứ) tuy còn chữ ký hợp lệ nhưng
KHÔNG được kết luận GOOD — vì nó có thể được chụp TRƯỚC khi chứng thư bị thu hồi.
Kết quả phải là UNKNOWN (fail-closed).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from core.models import RevocationStatus
from core.trust import revocation as rev
from tests.certs import make_chain


def _crl(issuer, *, last_days_ago: int, next_days_ago: int, revoked_serials=()):  # type: ignore[no-untyped-def]
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.cert.subject)
        .last_update(now - timedelta(days=last_days_ago))
        .next_update(now - timedelta(days=next_days_ago))
    )
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(serial)
            .revocation_date(now - timedelta(days=last_days_ago))
            .build()
        )
    crl = builder.sign(private_key=issuer.key, algorithm=hashes.SHA256())
    return crl.public_bytes(Encoding.DER)


def _patch(monkeypatch, crl_der):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(rev, "_crl_urls", lambda cert: ["https://ca.example.vn/crl"])
    monkeypatch.setattr(rev.RevocationChecker, "_download", lambda self, url: crl_der)


def test_expired_crl_is_unknown_not_good(monkeypatch: pytest.MonkeyPatch) -> None:
    _, inter, leaf = make_chain()
    # CRL hết hạn (nextUpdate cách đây 5 ngày), leaf KHÔNG có trong danh sách.
    _patch(monkeypatch, _crl(inter, last_days_ago=10, next_days_ago=5))
    outcome = rev.RevocationChecker().check(leaf.cert, inter.cert, allow_network=True)
    assert outcome.status is RevocationStatus.UNKNOWN  # KHÔNG được là GOOD
    assert outcome.next_update is not None and outcome.next_update < datetime.now(timezone.utc)
    assert any("HẾT HẠN" in r for r in outcome.reasons_vi)


def test_fresh_crl_absent_serial_is_good(monkeypatch: pytest.MonkeyPatch) -> None:
    _, inter, leaf = make_chain()
    _patch(monkeypatch, _crl(inter, last_days_ago=1, next_days_ago=-7))  # còn hạn 7 ngày nữa
    outcome = rev.RevocationChecker().check(leaf.cert, inter.cert, allow_network=True)
    assert outcome.status is RevocationStatus.GOOD


def test_fresh_crl_revoked_serial_is_revoked(monkeypatch: pytest.MonkeyPatch) -> None:
    _, inter, leaf = make_chain()
    _patch(monkeypatch, _crl(inter, last_days_ago=1, next_days_ago=-7,
                             revoked_serials=[leaf.cert.serial_number]))
    outcome = rev.RevocationChecker().check(leaf.cert, inter.cert, allow_network=True)
    assert outcome.status is RevocationStatus.REVOKED
