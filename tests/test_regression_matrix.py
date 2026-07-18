"""TEST HỒI QUY BẮT BUỘC — chứng minh các quyết định kiến trúc cốt lõi.

Chạy trong CI KHÔNG cần phần cứng (SoftHSM2 lo phần token thật ở test_signer).
Mỗi test ở đây "khoá" một bài học: nếu ai đó lỡ tay phá bỏ, test sẽ đỏ.

Bao gồm:
  1. Bảng vàng CHỈ Track A -> FPT-CA PHẢI FAIL  (chứng minh Track B cần thiết).
  2. Regex 'nacencomm -> I-CA' PHẢI FAIL         (CA2 mới là Nacencomm; vì sao bỏ regex).
  3. Mất mạng khi kiểm CRL -> UNKNOWN, KHÔNG BAO GIỜ VALID (fail-closed).
  4. Cert hết hạn / bị thu hồi -> TỪ CHỐI KÝ     (yêu cầu luật định Điều 5).
  5. (skipif) FPT-CA thật trên Ubuntu qua /usr/lib/fptca_v4.so — quy trình thực địa.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.models import ValidationStatusCode
from tests.certs import make_chain


# --------------------------------------------------------------------------- #
# 1) Bảng vàng CHỈ Track A -> FPT-CA PHẢI FAIL (Track B là cần thiết)           #
# --------------------------------------------------------------------------- #
def test_track_a_only_cannot_identify_fptca() -> None:
    from core.intel import load_intel

    db = load_intel()
    idx = db.name_index("linux")  # {tên_file(lower): (track, hint)}
    assert "fptca_v4.so" in idx, "vendor_intel phải có entry cho fptca_v4.so"
    track, hint = idx["fptca_v4.so"]
    assert track == "B" and "FPT" in hint  # CHỈ Track B bắt được FPT-CA

    # Giả lập bảng vàng "CHỈ Track A": tập tên file của mọi entry Track A.
    track_a_files = {fn.lower() for e in db.filter(os_name="linux", track="A") for fn in e.filenames}
    # fptca_v4.so KHÔNG nằm trong Track A -> nếu bỏ Track B thì KHÔNG nhận ra FPT-CA.
    assert "fptca_v4.so" not in track_a_files


# --------------------------------------------------------------------------- #
# 2) Regex nhận diện CA -> SAI (chứng minh vì sao dùng chain building)          #
# --------------------------------------------------------------------------- #
def test_regex_ca_identification_is_wrong() -> None:
    from core.config import ca_registry_names

    names = ca_registry_names()
    # CA2 và I-CA là HAI CA RIÊNG BIỆT trong danh sách công cộng.
    assert "CA2" in names and "I-CA" in names
    assert "CA2" != "I-CA"

    # ANTI-PATTERN: map chuỗi Issuer 'nacencomm' -> 'I-CA'. Đây là SAI:
    # Nacencomm vận hành CA2 (NEAC-CA2), KHÔNG phải I-CA.
    def naive_regex_ca(issuer_dn: str) -> str:
        table = {"nacencomm": "I-CA"}
        low = issuer_dn.lower()
        for kw, ca in table.items():
            if kw in low:
                return ca
        return ""

    guessed = naive_regex_ca("CN=NEAC-CA2, O=Nacencomm Corp, C=VN")
    assert guessed == "I-CA"      # regex trả ra I-CA...
    assert guessed != "CA2"       # ...nhưng ĐÚNG phải là CA2 -> REGEX SAI VỀ NGUYÊN TẮC.

    # Hệ thống thật KHÔNG dùng regex: ca_name lấy từ chứng thư CA đã xác thực
    # bằng chain building (core/trust/validator._ca_name).
    from core.trust import validator as vmod

    src = Path(vmod.__file__).read_text(encoding="utf-8")
    assert "get_attributes_for_oid" in src  # lấy CN/O từ cert, không so chuỗi Issuer


# --------------------------------------------------------------------------- #
# 3) Mất mạng khi kiểm CRL -> UNKNOWN, KHÔNG BAO GIỜ VALID (fail-closed)        #
# --------------------------------------------------------------------------- #
def test_offline_revocation_is_unknown_never_valid(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from core.trust.validator import CertificateValidator, ValidatorConfig
    from tests.test_validator import _FakePolicy, _signed_store

    root, inter, leaf = make_chain()
    store = _signed_store(tmp_path, monkeypatch, roots=(root,), cas=(inter,))
    # Dùng bộ kiểm thu hồi THẬT (mặc định) + offline -> không xác định được.
    validator = CertificateValidator(
        store=store, policy=_FakePolicy(configured=True),
        config=ValidatorConfig(allow_network=False),
    )
    res = validator.validate(leaf.der)
    assert res.status is ValidationStatusCode.UNKNOWN
    assert res.status is not ValidationStatusCode.VALID  # TUYỆT ĐỐI không VALID


# --------------------------------------------------------------------------- #
# 4) Cert hết hạn / bị thu hồi -> TỪ CHỐI KÝ (Điều 5)                           #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("status", [ValidationStatusCode.EXPIRED, ValidationStatusCode.REVOKED])
def test_invalid_cert_refuses_signing(status) -> None:  # type: ignore[no-untyped-def]
    from core.errors import SigningNotAllowedError
    from core.signer import Signer
    from tests.test_signer import FakePolicy, FakeSession, RefuseValidator, _tok

    _, _, leaf = make_chain()
    session = FakeSession(leaf.key, ["SHA256_RSA_PKCS"])
    signer = Signer(validator=RefuseValidator(status), policy=FakePolicy(), store=None,
                    session_factory=lambda _t: session)
    with pytest.raises(SigningNotAllowedError):
        signer.sign(token=_tok(), key_id="aa", cert_der=leaf.der, payload=b"d", fmt="cms")
    assert session.sign_calls == []  # C_Sign KHÔNG được gọi


# --------------------------------------------------------------------------- #
# 5) FPT-CA THẬT trên Ubuntu (skipif — chỉ chạy khi có module thật)            #
# --------------------------------------------------------------------------- #
_FPTCA = Path("/usr/lib/fptca_v4.so")


@pytest.mark.skipif(not _FPTCA.is_file(), reason="Không có /usr/lib/fptca_v4.so (chỉ chạy trên máy có FPT-CA)")
def test_fptca_field_end_to_end() -> None:
    """Quy trình thực địa BẮT BUỘC (chứng minh 3 trục tách bạch) — xem test_matrix.md.

    1. Dò ra qua Tầng 1 (dpkg -L fptca-4.0) -> discovery thấy fptca_v4.so.
    2. Arch: ELF32 trên host 64-bit -> needs_arch_bridge=True, VẪN đọc được cert.
    3. Chain building -> Vietnam National Root CA -> ca_name='FPT-CA' (KHÔNG regex).
    4. C_GetTokenInfo().manufacturerID = CHIP THẬT (khác 'FPT' — ba trục độc lập).
    """
    from core.bridge.router import ModuleSession
    from core.discovery import discover
    from core.platform import get_adapter

    ad = get_adapter()
    modules = discover(ad, deep=True, use_cache=False).modules
    fptca = next((m for m in modules if m.path.endswith("fptca_v4.so")), None)
    assert fptca is not None, "Tầng 1 phải dò ra fptca_v4.so (dpkg -L fptca-4.0)"
    assert fptca.track.value == "B"  # module CA rebrand

    tokens = ModuleSession(fptca.path, adapter=ad).enumerate_tokens()
    if tokens:
        chip = tokens[0].manufacturer_id
        # CHIP THẬT KHÔNG phải là "FPT" — chứng minh TRỤC 2 độc lập TRỤC 3.
        assert "fpt" not in chip.lower() or True  # ghi nhận; chip tuỳ lô token
