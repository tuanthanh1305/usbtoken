"""Test TRỌNG TÂM PHÁP LÝ: chain building (nhận diện CA bằng mật mã, KHÔNG regex)
và kết quả kiểm tra hiệu lực (fail-safe theo Phụ lục & kho tin cậy)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.models import ValidationStatusCode
from core.trust.anchors import TrustAnchorStore
from core.trust.chain import ChainBuilder
from core.trust.policy import CompliancePolicy
from core.trust.validator import CertificateValidator
from tests.certs import make_chain


def _store_with(tmp_path: Path, *certs) -> TrustAnchorStore:  # type: ignore[no-untyped-def]
    for i, c in enumerate(certs):
        (tmp_path / f"cert_{i}.der").write_bytes(c.der)
    return TrustAnchorStore(store_dir=tmp_path)


def test_chain_verified_to_anchor(tmp_path: Path) -> None:
    root, inter, leaf = make_chain()
    store = _store_with(tmp_path, root, inter)  # neo gốc + trung gian
    result = ChainBuilder(store).build(leaf.cert)
    assert result.verified is True
    assert result.reached_anchor is True
    assert len(result.path) == 3  # leaf -> inter -> root
    ca = result.ca_info()
    assert ca.chain_verified is True
    assert ca.ca_name == "VN Test Public CA"  # từ chứng thư CA, KHÔNG từ regex


def test_chain_untrusted_when_root_missing(tmp_path: Path) -> None:
    root, inter, leaf = make_chain()
    store = _store_with(tmp_path, inter)  # THIẾU neo gốc
    _ = root
    result = ChainBuilder(store).build(leaf.cert)
    assert result.verified is False
    assert result.reached_anchor is False


def test_chain_empty_store(tmp_path: Path) -> None:
    _, _, leaf = make_chain()
    store = TrustAnchorStore(store_dir=tmp_path)  # rỗng
    result = ChainBuilder(store).build(leaf.cert)
    assert result.verified is False
    assert any("rỗng" in r.lower() for r in result.reasons_vi)


def test_validator_untrusted_when_store_empty(tmp_path: Path) -> None:
    _, _, leaf = make_chain()
    validator = CertificateValidator(
        store=TrustAnchorStore(store_dir=tmp_path), policy=CompliancePolicy()
    )
    res = validator.validate(leaf.der)
    assert res.status is ValidationStatusCode.UNTRUSTED
    assert res.reasons_vi  # có diễn giải tiếng Việt


def test_validator_policy_not_configured_even_if_chain_ok(tmp_path: Path) -> None:
    # Chuỗi hợp lệ nhưng Phụ lục I/II CHƯA điền -> KHÔNG được tuyên VALID.
    root, inter, leaf = make_chain()
    store = _store_with(tmp_path, root, inter)
    res = CertificateValidator(store=store, policy=CompliancePolicy()).validate(leaf.der)
    assert res.status is ValidationStatusCode.POLICY_NOT_CONFIGURED
    assert len(res.trust_path) == 3  # vẫn lưu đường dẫn tin cậy làm bằng chứng


def test_validator_expired_cert(tmp_path: Path) -> None:
    from datetime import datetime, timedelta, timezone

    from tests.certs import _make

    root = _make("VN Test Root CA", None, is_ca=True)
    inter = _make("VN Test Public CA", root, is_ca=True)
    past = datetime.now(timezone.utc) - timedelta(days=10)
    leaf = _make(
        "Nguyen Van B", inter, is_ca=False,
        not_before=past - timedelta(days=5), not_after=past,
    )
    store = _store_with(tmp_path, root, inter)
    res = CertificateValidator(store=store, policy=CompliancePolicy()).validate(leaf.der)
    assert res.status is ValidationStatusCode.EXPIRED
