"""Test TRỌNG TÂM PHÁP LÝ: chain building (nhận diện CA bằng mật mã, KHÔNG regex).

Kiểm tra hiệu lực đầy đủ (VALID/EXPIRED/REVOKED/UNKNOWN/FOREIGN...) nằm ở
``tests/test_validator.py``.
"""

from __future__ import annotations

from pathlib import Path

from core.trust.anchors import TrustAnchorStore
from core.trust.chain import ChainBuilder
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
