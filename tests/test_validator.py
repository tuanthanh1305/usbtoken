"""Test MODULE PHÁP LÝ QUAN TRỌNG NHẤT — ``core/trust/validator.py``.

Bao phủ đúng yêu cầu của đề bài:
    * cert HỢP LỆ            -> VALID
    * HẾT HẠN                -> EXPIRED
    * BỊ THU HỒI             -> REVOKED
    * CHAIN ĐỨT / chữ ký sai -> INVALID
    * CRL HẾT HẠN            -> UNKNOWN (fail-closed, KHÔNG VALID)
    * KHÔNG CÓ MẠNG          -> UNKNOWN (fail-closed, KHÔNG VALID)
    * kho RỖNG               -> INVALID
    * CHƯA điền Phụ lục II   -> UNKNOWN (dù chain hoàn hảo — fail-closed)
    * DS tin cậy nước ngoài  -> FOREIGN_RECOGNIZED
    * assert_signable        -> ném lỗi nếu != VALID

Toàn bộ dùng CHUỖI CHỨNG THƯ GIẢ TỰ SINH trong bộ nhớ (không mạng, hợp CI).
Mọi kết quả PHẢI kèm lý do tiếng Việt.

⚠️ VALID chỉ đạt được khi TIÊM chính sách ĐÃ cấu hình (``_FakePolicy``): với
``CompliancePolicy`` thật + Phụ lục II CHƯA điền, VALID là BẤT KHẢ THI — đúng
thiết kế fail-closed.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.errors import SigningNotAllowedError
from core.models import (
    RevocationEvidence,
    RevocationStatus,
    ValidationStatusCode,
)
from core.trust import signing
from core.trust import store as store_mod
from core.trust.policy import CompliancePolicy
from core.trust.validator import (
    CertificateValidator,
    ValidatorConfig,
)
from tests.certs import _make, make_chain


# --------------------------------------------------------------------------- #
# Chính sách & kiểm thu hồi GIẢ (tiêm để cô lập từng nhánh)                     #
# --------------------------------------------------------------------------- #
class _FakePolicy:
    """Phụ lục II coi như ĐÃ điền — CHỈ dùng trong test để chạm được VALID."""

    def __init__(self, *, configured: bool = True, reqs: dict | None = None) -> None:
        self._configured = configured
        self._reqs = reqs or {}

    @property
    def is_configured(self) -> bool:
        return self._configured

    def certificate_requirements(self) -> dict:
        return self._reqs


class _FakeRevChecker:
    """Trả trạng thái thu hồi CỐ ĐỊNH (không đụng mạng)."""

    def __init__(self, status: RevocationStatus, *, next_update: datetime | None = None) -> None:
        self.status = status
        self.next_update = next_update

    def check(self, cert, issuer, cert_info, *, mode, allow_network) -> RevocationEvidence:  # type: ignore[no-untyped-def]
        return RevocationEvidence(
            status=self.status,
            method="CRL",
            checked_at=datetime.now(timezone.utc),
            next_update=self.next_update,
            reasons_vi=["(giả lập test) trạng thái thu hồi cố định."],
        )


# --------------------------------------------------------------------------- #
# Helpers dựng kho neo tin cậy (TrustStore thật, nạp từ đĩa)                    #
# --------------------------------------------------------------------------- #
def _write(dir_: Path, rel: str, data: bytes) -> Path:
    p = dir_ / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


def _layout(roots: tuple, cas: tuple, foreign: tuple) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for i, c in enumerate(roots):
        files[f"root/root_{i}.der"] = c.der
    for i, c in enumerate(cas):
        files[f"ca/ca_{i}.der"] = c.der
    for i, c in enumerate(foreign):
        files[f"foreign/foreign_{i}.der"] = c.der
    return files


def _unsigned_store(
    tmp_path: Path, *, roots: tuple = (), cas: tuple = (), foreign: tuple = ()
):
    """Kho CHƯA ký (verified=False) — dùng cho các nhánh không cần VALID."""
    store_dir = tmp_path / "current"
    for rel, data in _layout(roots, cas, foreign).items():
        _write(store_dir, rel, data)
    return store_mod.load(store_dir, verify_signature=False)


def _signed_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    roots: tuple = (),
    cas: tuple = (),
    foreign: tuple = (),
    synced_at: datetime | None = None,
):
    """Kho ĐÃ ký Ed25519 (verified=True, đồng bộ vừa xong) — cần cho VALID."""
    priv, pub = signing.generate_keypair()
    pub_path = tmp_path / "pub.pem"
    signing.save_public_key(pub, pub_path)
    monkeypatch.setattr(store_mod, "trust_signing_pub_path", lambda: pub_path)

    store_dir = tmp_path / "current"
    files_meta = []
    for rel, data in _layout(roots, cas, foreign).items():
        _write(store_dir, rel, data)
        files_meta.append(
            {"name": rel, "role": rel.split("/")[0], "sha256": hashlib.sha256(data).hexdigest()}
        )
    manifest = {
        "version": 1,
        "synced_at": (synced_at or datetime.now(timezone.utc)).isoformat(),
        "source": "https://rootca.gov.vn",
        "files": files_meta,
    }
    raw = signing.canonical_bytes(manifest)
    (store_dir / "manifest.json").write_bytes(raw)
    (store_dir / "manifest.sig").write_bytes(signing.sign(priv, raw))
    return store_mod.load(store_dir, verify_signature=True)


def _good_validator(store, **cfg):  # type: ignore[no-untyped-def]
    """Validator với chính sách + thu hồi GIẢ 'tốt' — chỉ để cô lập nhánh test."""
    return CertificateValidator(
        store=store,
        policy=_FakePolicy(configured=True),
        revocation_checker=_FakeRevChecker(RevocationStatus.GOOD),
        config=ValidatorConfig(**cfg),
    )


# --------------------------------------------------------------------------- #
# 1) CERT HỢP LỆ -> VALID (chỉ đạt được khi tiêm chính sách đã cấu hình)         #
# --------------------------------------------------------------------------- #
def test_valid_certificate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, inter, leaf = make_chain()
    store = _signed_store(tmp_path, monkeypatch, roots=(root,), cas=(inter,))
    res = _good_validator(store, allow_network=True).validate(leaf.der)

    assert res.status is ValidationStatusCode.VALID
    assert res.reasons_vi  # luôn có diễn giải tiếng Việt
    assert len(res.trust_path) == 3  # leaf -> inter -> root (bằng chứng)
    assert res.trust_path[-1].is_trust_anchor is True
    assert res.ca_name == "VN Test Public CA"  # CA phát hành trực tiếp, TỪ chứng thư
    assert res.trust_store_synced_at is not None


def test_valid_requires_configured_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Cùng chuỗi hoàn hảo NHƯNG chính sách thật (Phụ lục II chưa điền) -> KHÔNG VALID.
    root, inter, leaf = make_chain()
    store = _signed_store(tmp_path, monkeypatch, roots=(root,), cas=(inter,))
    res = CertificateValidator(
        store=store,
        policy=CompliancePolicy(),  # thật: chưa điền Phụ lục II
        revocation_checker=_FakeRevChecker(RevocationStatus.GOOD),
        config=ValidatorConfig(allow_network=True),
    ).validate(leaf.der)

    assert res.status is ValidationStatusCode.UNKNOWN  # fail-closed, KHÔNG VALID
    assert any("Phụ lục II" in r for r in res.reasons_vi)
    assert len(res.trust_path) == 3  # vẫn lưu đường dẫn tin cậy làm bằng chứng


# --------------------------------------------------------------------------- #
# 2) HẾT HẠN -> EXPIRED                                                         #
# --------------------------------------------------------------------------- #
def test_expired_certificate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _make("VN Test Root CA", None, is_ca=True)
    inter = _make("VN Test Public CA", root, is_ca=True)
    past = datetime.now(timezone.utc) - timedelta(days=10)
    leaf = _make(
        "Nguyen Van B", inter, is_ca=False,
        not_before=past - timedelta(days=5), not_after=past,
    )
    store = _signed_store(tmp_path, monkeypatch, roots=(root,), cas=(inter,))
    res = _good_validator(store).validate(leaf.der)

    assert res.status is ValidationStatusCode.EXPIRED
    assert any("HẾT HẠN" in r for r in res.reasons_vi)


# --------------------------------------------------------------------------- #
# 3) BỊ THU HỒI -> REVOKED                                                      #
# --------------------------------------------------------------------------- #
def test_revoked_certificate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, inter, leaf = make_chain()
    store = _signed_store(tmp_path, monkeypatch, roots=(root,), cas=(inter,))
    validator = CertificateValidator(
        store=store,
        policy=_FakePolicy(configured=True),
        revocation_checker=_FakeRevChecker(RevocationStatus.REVOKED),
        config=ValidatorConfig(allow_network=True),
    )
    res = validator.validate(leaf.der)

    assert res.status is ValidationStatusCode.REVOKED
    assert any("THU HỒI" in r for r in res.reasons_vi)
    assert res.revocations  # bằng chứng thu hồi được lưu


# --------------------------------------------------------------------------- #
# 4) CHAIN ĐỨT / CHỮ KÝ SAI -> INVALID                                          #
# --------------------------------------------------------------------------- #
def test_chain_broken_missing_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Kho có CA trung gian nhưng THIẾU neo gốc NEAC -> không dựng được đường dẫn.
    root, inter, leaf = make_chain()
    _ = root
    store = _signed_store(tmp_path, monkeypatch, cas=(inter,))  # không có root
    res = _good_validator(store, allow_network=True).validate(leaf.der)

    assert res.status is ValidationStatusCode.INVALID
    assert any("chain đứt" in r.lower() or "gốc NEAC" in r for r in res.reasons_vi)


def test_chain_bad_signature(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Kho chứa một CA TRÙNG TÊN nhưng KHÁC khoá -> chữ ký leaf không khớp -> INVALID.
    root_a = _make("VN Test Root CA", None, is_ca=True)
    inter_a = _make("VN Test Public CA", root_a, is_ca=True)
    leaf = _make("Nguyen Van A", inter_a, is_ca=False)  # ký bởi inter_a

    root_b = _make("VN Test Root CA", None, is_ca=True)
    inter_b = _make("VN Test Public CA", root_b, is_ca=True)  # cùng DN, khác khoá
    store = _signed_store(tmp_path, monkeypatch, roots=(root_b,), cas=(inter_b,))
    res = _good_validator(store, allow_network=True).validate(leaf.der)

    assert res.status is ValidationStatusCode.INVALID
    assert any("khớp" in r.lower() or "hợp lệ" in r.lower() for r in res.reasons_vi)


# --------------------------------------------------------------------------- #
# 5) CRL HẾT HẠN -> UNKNOWN (fail-closed)                                       #
# --------------------------------------------------------------------------- #
def test_crl_expired_gives_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root, inter, leaf = make_chain()
    store = _signed_store(tmp_path, monkeypatch, roots=(root,), cas=(inter,))
    stale_crl = datetime.now(timezone.utc) - timedelta(days=3)  # nextUpdate quá khứ
    validator = CertificateValidator(
        store=store,
        policy=_FakePolicy(configured=True),
        revocation_checker=_FakeRevChecker(RevocationStatus.GOOD, next_update=stale_crl),
        config=ValidatorConfig(allow_network=True),
    )
    res = validator.validate(leaf.der)

    assert res.status is ValidationStatusCode.UNKNOWN
    assert any("HẾT HẠN" in r and ("CRL" in r or "OCSP" in r) for r in res.reasons_vi)


# --------------------------------------------------------------------------- #
# 6) KHÔNG CÓ MẠNG -> UNKNOWN (KHÔNG phải VALID) — nhánh fail-closed cốt lõi     #
# --------------------------------------------------------------------------- #
def test_offline_revocation_gives_unknown_not_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, inter, leaf = make_chain()
    store = _signed_store(tmp_path, monkeypatch, roots=(root,), cas=(inter,))
    # Dùng bộ kiểm thu hồi THẬT (mặc định) + offline -> không xác định thu hồi.
    validator = CertificateValidator(
        store=store,
        policy=_FakePolicy(configured=True),
        config=ValidatorConfig(allow_network=False),  # offline
    )
    res = validator.validate(leaf.der)

    assert res.status is ValidationStatusCode.UNKNOWN  # TUYỆT ĐỐI không VALID
    assert res.status is not ValidationStatusCode.VALID
    assert any("thu hồi" in r.lower() for r in res.reasons_vi)


# --------------------------------------------------------------------------- #
# 7) KHO RỖNG -> INVALID                                                        #
# --------------------------------------------------------------------------- #
def test_empty_store_gives_invalid(tmp_path: Path) -> None:
    _, _, leaf = make_chain()
    store = _unsigned_store(tmp_path)  # rỗng
    res = CertificateValidator(store=store, policy=CompliancePolicy()).validate(leaf.der)

    assert res.status is ValidationStatusCode.INVALID
    assert any("RỖNG" in r or "rỗng" in r for r in res.reasons_vi)


# --------------------------------------------------------------------------- #
# 8) FAIL-CLOSED: kho CHƯA ký -> không được khẳng định VALID                     #
# --------------------------------------------------------------------------- #
def test_unsigned_store_cannot_be_valid(tmp_path: Path) -> None:
    root, inter, leaf = make_chain()
    store = _unsigned_store(tmp_path, roots=(root,), cas=(inter,))  # verified=False
    validator = CertificateValidator(
        store=store,
        policy=_FakePolicy(configured=True),
        revocation_checker=_FakeRevChecker(RevocationStatus.GOOD),
        config=ValidatorConfig(allow_network=True),
    )
    res = validator.validate(leaf.der)

    assert res.status is ValidationStatusCode.UNKNOWN  # chain OK nhưng kho chưa ký
    assert any("ký" in r for r in res.reasons_vi)


# --------------------------------------------------------------------------- #
# 9) DANH SÁCH TIN CẬY NƯỚC NGOÀI -> FOREIGN_RECOGNIZED                          #
# --------------------------------------------------------------------------- #
def test_foreign_recognized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    foreign_root = _make("Foreign Recognized Root CA", None, is_ca=True)
    leaf = _make("Overseas Signer", foreign_root, is_ca=False)
    store = _signed_store(tmp_path, monkeypatch, foreign=(foreign_root,))
    res = _good_validator(store, allow_network=True).validate(leaf.der)

    assert res.status is ValidationStatusCode.FOREIGN_RECOGNIZED
    assert any("NƯỚC NGOÀI" in r for r in res.reasons_vi)


def test_foreign_dn_forgery_not_recognized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # REGRESSION: cert GIẢ MẠO chép Subject DN của neo nước ngoài (khác khoá, không
    # do neo đó cấp) KHÔNG được coi là FOREIGN_RECOGNIZED — phải INVALID. Nếu chỉ so
    # Subject DN (không kiểm mật mã) thì cert giả sẽ lọt.
    foreign_root = _make("Foreign Recognized Root CA", None, is_ca=True)
    other = _make("Some Other CA", None, is_ca=True)  # không có trong kho
    forged = _make("Foreign Recognized Root CA", other, is_ca=True)  # trùng DN, khác khoá
    store = _signed_store(tmp_path, monkeypatch, foreign=(foreign_root,))
    res = _good_validator(store, allow_network=True).validate(forged.der)
    assert res.status is not ValidationStatusCode.FOREIGN_RECOGNIZED
    assert res.status is ValidationStatusCode.INVALID


# --------------------------------------------------------------------------- #
# 10) assert_signable — Điều 5: chỉ cho ký khi VALID                            #
# --------------------------------------------------------------------------- #
def test_assert_signable_blocks_when_not_valid(tmp_path: Path) -> None:
    _, _, leaf = make_chain()
    store = _unsigned_store(tmp_path)  # rỗng -> INVALID
    validator = CertificateValidator(store=store, policy=CompliancePolicy())
    with pytest.raises(SigningNotAllowedError) as exc:
        validator.assert_signable(leaf.der)
    assert exc.value.result is not None
    assert exc.value.result.status is ValidationStatusCode.INVALID


def test_assert_signable_returns_result_when_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, inter, leaf = make_chain()
    store = _signed_store(tmp_path, monkeypatch, roots=(root,), cas=(inter,))
    res = _good_validator(store, allow_network=True).assert_signable(leaf.der)
    assert res.status is ValidationStatusCode.VALID


# --------------------------------------------------------------------------- #
# 11) Đầu vào rác -> INVALID (không nổ)                                          #
# --------------------------------------------------------------------------- #
def test_garbage_input_invalid(tmp_path: Path) -> None:
    store = _unsigned_store(tmp_path, roots=(_make("VN Test Root CA", None, is_ca=True),))
    res = CertificateValidator(store=store, policy=CompliancePolicy()).validate(b"not-a-cert")
    assert res.status is ValidationStatusCode.INVALID
    assert res.reasons_vi
