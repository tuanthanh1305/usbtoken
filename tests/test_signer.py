"""Test KÝ SỐ (core/signer.py) — Điều 5 TT 15/2025.

Trọng tâm:
    * TRÌNH TỰ: assert_signable TRƯỚC, mới ký. Cert HẾT HẠN / BỊ THU HỒI -> TỪ
      CHỐI KÝ (không hề gọi C_Sign).
    * Fail-closed: Phụ lục I CHƯA điền -> không ký được (không đoán thuật toán).
    * Chọn cơ chế = token hỗ trợ ∩ Phụ lục I; không giao nhau -> từ chối, báo rõ.
    * Băm-ngoài dựng DigestInfo DER đúng chuẩn.
    * CMS detached hợp lệ (chữ ký kiểm được, nhúng cert + chain).
    * Tích hợp SoftHSM2 (token ảo) — chạy nếu có, bỏ qua nếu thiếu.

Phần lớn dùng SESSION GIẢ (khoá RSA thật) -> CI chạy không cần phần cứng.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timezone

import pytest
from asn1crypto import cms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from core.errors import MechanismUnavailableError, SigningNotAllowedError
from core.models import TokenInfo, ValidationResult, ValidationStatusCode
from core.signer import _DIGESTINFO_PREFIX, Signer
from core.trust.policy import CompliancePolicy
from tests.certs import make_chain


# --------------------------------------------------------------------------- #
# Fakes                                                                        #
# --------------------------------------------------------------------------- #
class FakeSession:
    """Token giả: khoá RSA thật để chữ ký kiểm được; ghi lại lời gọi."""

    def __init__(self, key, mechanisms):  # type: ignore[no-untyped-def]
        self.key = key
        self.mechanisms = list(mechanisms)
        self.sign_calls: list[tuple] = []
        self.mech_calls = 0

    def get_mechanisms(self, slot_id):  # type: ignore[no-untyped-def]
        self.mech_calls += 1
        return self.mechanisms

    def sign(self, slot_id, key_id, mechanism, data, pin=None):  # type: ignore[no-untyped-def]
        self.sign_calls.append((mechanism, data))
        if mechanism == "SHA256_RSA_PKCS":
            return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        # RSA_PKCS (băm-ngoài): data là DigestInfo; ở test chỉ trả chữ ký giả.
        return b"\x00raw-signature"

    def close(self):  # type: ignore[no-untyped-def]
        pass


class OkValidator:
    def __init__(self):
        self.calls = 0

    def assert_signable(self, cert_der, at_time=None):  # type: ignore[no-untyped-def]
        self.calls += 1
        now = datetime.now(timezone.utc)
        return ValidationResult(
            status=ValidationStatusCode.VALID, checked_at=now, at_time=now,
            subject="CN=Nguyen Van A", ca_name="VN Test Public CA",
        )


class RefuseValidator:
    """Mô phỏng assert_signable thật: ném khi status != VALID."""

    def __init__(self, status):  # type: ignore[no-untyped-def]
        self.status = status

    def assert_signable(self, cert_der, at_time=None):  # type: ignore[no-untyped-def]
        now = datetime.now(timezone.utc)
        result = ValidationResult(status=self.status, checked_at=now, at_time=now,
                                  reasons_vi=[f"trạng thái {self.status.value}"])
        raise SigningNotAllowedError(
            f"Không được phép ký: chứng thư ở trạng thái {self.status.value}.",
            detail=self.status.value, result=result,
        )


class FakePolicy:
    is_configured = True

    def __init__(self, *, algos=("RSASSA-PKCS1-v1_5-SHA256",), min_sizes=None):  # type: ignore[no-untyped-def]
        self._algos = list(algos)
        self._min = min_sizes or {"RSA": 2048}

    def allowed_signature_algorithms(self):  # type: ignore[no-untyped-def]
        return self._algos

    def min_key_sizes(self):  # type: ignore[no-untyped-def]
        return self._min


def _signer(validator, policy, session, **kw):  # type: ignore[no-untyped-def]
    return Signer(
        validator=validator, policy=policy, store=None,
        session_factory=lambda t: session, **kw,
    )


def _tok():
    return TokenInfo(module_path="/x.so", slot_id=0, serial="SN")


# --------------------------------------------------------------------------- #
# TRÌNH TỰ Điều 5: cert HẾT HẠN / THU HỒI -> TỪ CHỐI KÝ (bắt buộc)              #
# --------------------------------------------------------------------------- #
def test_refuse_signing_expired_certificate() -> None:
    _, _, leaf = make_chain()
    session = FakeSession(leaf.key, ["SHA256_RSA_PKCS"])
    signer = _signer(RefuseValidator(ValidationStatusCode.EXPIRED), FakePolicy(), session)
    with pytest.raises(SigningNotAllowedError) as exc:
        signer.sign(token=_tok(), key_id="aa", cert_der=leaf.der, payload=b"d", fmt="cms")
    assert exc.value.result.status is ValidationStatusCode.EXPIRED
    # ⭐ C_Sign KHÔNG được gọi (gate chạy TRƯỚC).
    assert session.sign_calls == [] and session.mech_calls == 0


def test_refuse_signing_revoked_certificate() -> None:
    _, _, leaf = make_chain()
    session = FakeSession(leaf.key, ["SHA256_RSA_PKCS"])
    signer = _signer(RefuseValidator(ValidationStatusCode.REVOKED), FakePolicy(), session)
    with pytest.raises(SigningNotAllowedError):
        signer.sign(token=_tok(), key_id="aa", cert_der=leaf.der, payload=b"d", fmt="cms")
    assert session.sign_calls == []  # TUYỆT ĐỐI không ký khi bị thu hồi


# --------------------------------------------------------------------------- #
# Fail-closed: Phụ lục I CHƯA điền -> không ký được                              #
# --------------------------------------------------------------------------- #
def test_refuse_when_appendix_i_not_filled() -> None:
    _, _, leaf = make_chain()
    session = FakeSession(leaf.key, ["SHA256_RSA_PKCS"])
    # CompliancePolicy thật đọc appendix_I.yaml (status: not_filled) -> require_configured ném.
    signer = _signer(OkValidator(), CompliancePolicy(), session)
    with pytest.raises(MechanismUnavailableError) as exc:
        signer.sign(token=_tok(), key_id="aa", cert_der=leaf.der, payload=b"d", fmt="cms")
    assert "Phụ lục I" in exc.value.message
    assert session.sign_calls == []


# --------------------------------------------------------------------------- #
# Chọn cơ chế: giao nhau rỗng / độ dài khoá                                     #
# --------------------------------------------------------------------------- #
def test_no_common_mechanism_refused() -> None:
    _, _, leaf = make_chain()
    session = FakeSession(leaf.key, ["ECDSA_SHA256"])  # token KHÔNG hỗ trợ RSA
    signer = _signer(OkValidator(), FakePolicy(), session)
    with pytest.raises(MechanismUnavailableError) as exc:
        signer.select_mechanism(_tok(), leaf.der)
    assert "token" in exc.value.message.lower()


def test_min_key_size_enforced() -> None:
    _, _, leaf = make_chain()  # RSA 2048
    session = FakeSession(leaf.key, ["SHA256_RSA_PKCS"])
    signer = _signer(OkValidator(), FakePolicy(min_sizes={"RSA": 4096}), session)
    with pytest.raises(MechanismUnavailableError):
        signer.select_mechanism(_tok(), leaf.der)


def test_select_mechanism_prefers_hash_in_token() -> None:
    _, _, leaf = make_chain()
    session = FakeSession(leaf.key, ["RSA_PKCS", "SHA256_RSA_PKCS"])
    signer = _signer(OkValidator(), FakePolicy(), session)
    spec = signer.select_mechanism(_tok(), leaf.der)
    assert spec.id == "RSASSA-PKCS1-v1_5-SHA256"


# --------------------------------------------------------------------------- #
# Băm-ngoài: DigestInfo DER đúng chuẩn                                          #
# --------------------------------------------------------------------------- #
def test_hash_outside_builds_correct_digestinfo() -> None:
    _, _, leaf = make_chain()
    session = FakeSession(leaf.key, ["RSA_PKCS"])  # CHỈ băm-ngoài
    signer = _signer(OkValidator(), FakePolicy(), session)
    spec = signer.select_mechanism(_tok(), leaf.der)
    tbs = b"noi dung can ky"
    signer._sign_tbs(_tok(), "aa", spec, tbs, pin=None)
    mech, payload = session.sign_calls[0]
    assert mech == "RSA_PKCS"
    assert payload == _DIGESTINFO_PREFIX["sha256"] + hashlib.sha256(tbs).digest()


# --------------------------------------------------------------------------- #
# CMS detached hợp lệ (chữ ký kiểm được, nhúng cert + chain)                    #
# --------------------------------------------------------------------------- #
def test_cms_detached_signature_verifies(tmp_path) -> None:  # type: ignore[no-untyped-def]
    root, inter, leaf = make_chain()
    session = FakeSession(leaf.key, ["SHA256_RSA_PKCS"])
    validator = OkValidator()
    signer = _signer(validator, FakePolicy(), session, evidence_dir=tmp_path)
    data = b"hop dong dien tu 2026"

    res = signer.sign(token=_tok(), key_id="aa", cert_der=leaf.der, payload=data,
                      fmt="cms", chain=[inter.der, root.der])
    assert validator.calls == 1  # gate chạy đúng 1 lần TRƯỚC khi ký
    assert res.mechanism == "SHA256_RSA_PKCS" and res.evidence_id
    assert res.validation.status is ValidationStatusCode.VALID

    ci = cms.ContentInfo.load(base64.b64decode(res.signed_document_b64))
    sd = ci["content"]
    assert sd["encap_content_info"]["content"].native is None  # DETACHED
    assert len(sd["certificates"]) == 3  # leaf + inter + root nhúng kèm
    si = sd["signer_infos"][0]
    # messageDigest = sha256(data)
    md = next(a["values"][0].native for a in si["signed_attrs"] if a["type"].native == "message_digest")
    assert md == hashlib.sha256(data).digest()
    # Chữ ký kiểm được trên SignedAttributes (SET OF).
    tbs = si["signed_attrs"].untag().dump()
    leaf.cert.public_key().verify(si["signature"].native, tbs, padding.PKCS1v15(), hashes.SHA256())

    # Bằng chứng đã lưu, KHÔNG chứa DER/pin.
    ev = (tmp_path / f"sign_{res.evidence_id}.json").read_text(encoding="utf-8")
    assert "pin" not in ev.lower() and hashlib.sha256(leaf.der).hexdigest() in ev


def test_cms_timestamp_attached_when_tsa_returns_token(tmp_path) -> None:  # type: ignore[no-untyped-def]
    _, _, leaf = make_chain()
    session = FakeSession(leaf.key, ["SHA256_RSA_PKCS"])
    # TSA giả trả một ContentInfo hợp lệ (không phải token thật, chỉ kiểm nối dây).
    fake_token = cms.ContentInfo({"content_type": "data", "content": b"ts"}).dump()
    signer = _signer(OkValidator(), FakePolicy(), session, evidence_dir=tmp_path,
                     tsa_client=lambda imprint, url: fake_token)
    res = signer.sign(token=_tok(), key_id="aa", cert_der=leaf.der, payload=b"d",
                      fmt="cms", chain=[], tsa_url="https://tsa.example.vn")
    assert res.timestamped is True
    ci = cms.ContentInfo.load(base64.b64decode(res.signed_document_b64))
    si = ci["content"]["signer_infos"][0]
    assert si["unsigned_attrs"] is not None  # có signatureTimeStampToken


def test_pades_and_xades_fail_closed() -> None:
    from core.errors import SigningFormatUnavailableError

    _, _, leaf = make_chain()
    session = FakeSession(leaf.key, ["SHA256_RSA_PKCS"])
    signer = _signer(OkValidator(), FakePolicy(), session)
    for fmt in ("pades", "xades"):
        with pytest.raises(SigningFormatUnavailableError):
            signer.sign(token=_tok(), key_id="aa", cert_der=leaf.der, payload=b"%PDF", fmt=fmt)


# --------------------------------------------------------------------------- #
# Tích hợp SoftHSM2 — token ảo (chạy nếu có; bỏ qua nếu thiếu)                  #
# --------------------------------------------------------------------------- #
def _softhsm_lib() -> str | None:
    import shutil
    from pathlib import Path

    if shutil.which("softhsm2-util") is None:
        return None
    for cand in (
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
    ):
        if Path(cand).is_file():
            return cand
    return None


def _setup_softhsm(tmp_path, issued):  # type: ignore[no-untyped-def]
    """Khởi tạo token SoftHSM2, nạp khoá private + cert. Trả (lib, slot_id, pin, id_hex)."""
    import os
    import subprocess

    lib = _softhsm_lib()
    assert lib is not None
    tokendir = tmp_path / "tokens"
    tokendir.mkdir()
    conf = tmp_path / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tokendir}\nobjectstore.backend = file\n")
    os.environ["SOFTHSM2_CONF"] = str(conf)
    pin = "1234"
    subprocess.run(
        ["softhsm2-util", "--init-token", "--free", "--label", "vntest",
         "--pin", pin, "--so-pin", "5678"],
        check=True, capture_output=True,
    )

    import PyKCS11

    pk = PyKCS11.PyKCS11Lib()
    pk.load(lib)
    slot = pk.getSlotList(tokenPresent=True)[0]
    session = pk.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
    session.login(pin)

    priv = issued.key.private_numbers()
    pub = priv.public_numbers

    def i2b(x: int) -> list[int]:
        return list(x.to_bytes((x.bit_length() + 7) // 8 or 1, "big"))

    id_bytes = [0xAB, 0xCD]
    session.createObject([
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
        (PyKCS11.CKA_TOKEN, True), (PyKCS11.CKA_PRIVATE, True), (PyKCS11.CKA_SIGN, True),
        (PyKCS11.CKA_LABEL, "signer"), (PyKCS11.CKA_ID, id_bytes),
        (PyKCS11.CKA_MODULUS, i2b(pub.n)), (PyKCS11.CKA_PUBLIC_EXPONENT, i2b(pub.e)),
        (PyKCS11.CKA_PRIVATE_EXPONENT, i2b(priv.d)),
        (PyKCS11.CKA_PRIME_1, i2b(priv.p)), (PyKCS11.CKA_PRIME_2, i2b(priv.q)),
        (PyKCS11.CKA_EXPONENT_1, i2b(priv.dmp1)), (PyKCS11.CKA_EXPONENT_2, i2b(priv.dmq1)),
        (PyKCS11.CKA_COEFFICIENT, i2b(priv.iqmp)),
    ])
    session.createObject([
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
        (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509),
        (PyKCS11.CKA_TOKEN, True), (PyKCS11.CKA_LABEL, "signer"), (PyKCS11.CKA_ID, id_bytes),
        (PyKCS11.CKA_SUBJECT, list(issued.cert.subject.public_bytes())),
        (PyKCS11.CKA_VALUE, list(issued.der)),
    ])
    session.logout()
    session.closeSession()
    pk.unload()
    return lib, int(slot), pin, "abcd"


@pytest.mark.skipif(_softhsm_lib() is None, reason="SoftHSM2 chưa cài — bỏ qua test phần cứng ảo")
def test_softhsm_full_cms_flow(tmp_path) -> None:  # type: ignore[no-untyped-def]
    root, inter, leaf = make_chain()
    lib, slot, pin, id_hex = _setup_softhsm(tmp_path, leaf)

    token = TokenInfo(module_path=lib, slot_id=slot, serial="softhsm")
    signer = Signer(
        validator=OkValidator(), policy=FakePolicy(), store=None, evidence_dir=tmp_path,
    )  # session_factory mặc định -> ModuleSession THẬT (in-process)
    data = b"tai lieu ky bang SoftHSM"
    res = signer.sign(token=token, key_id=id_hex, cert_der=leaf.der, payload=data,
                      fmt="cms", pin=pin, chain=[inter.der, root.der])

    ci = cms.ContentInfo.load(base64.b64decode(res.signed_document_b64))
    si = ci["content"]["signer_infos"][0]
    tbs = si["signed_attrs"].untag().dump()
    # Chữ ký do SoftHSM tạo phải kiểm được bằng khoá công khai trong chứng thư.
    leaf.cert.public_key().verify(si["signature"].native, tbs, padding.PKCS1v15(), hashes.SHA256())
    assert res.mechanism == "SHA256_RSA_PKCS"
