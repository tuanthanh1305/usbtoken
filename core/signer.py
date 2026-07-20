"""Ký số trên USB token — Điều 5 TT 15/2025 (TRÌNH TỰ KHÔNG ĐƯỢC ĐẢO).

⛔ MỌI THAM SỐ MẬT MÃ ĐỌC TỪ ``data/compliance/appendix_I.yaml`` LÚC CHẠY —
KHÔNG hard-code. Bảng dịch dưới đây CHỈ là tri thức CHUẨN (PKCS#11 ↔ OID ↔
DigestInfo, theo RFC 8017 / PKCS#11), KHÔNG phải lựa chọn PHÁP LÝ. Việc thuật
toán/độ dài khoá nào ĐƯỢC PHÉP là do Phụ lục I quyết định (transcribe từ bản gốc).
Khi Phụ lục I CHƯA điền → ``CompliancePolicy`` ném lỗi → signer TỪ CHỐI KÝ
(fail-closed), KHÔNG đoán.

TRÌNH TỰ BẮT BUỘC (Điều 5):
    1. ``assert_signable(cert)`` — gọi validator (PROMPT 9). status != VALID →
       TỪ CHỐI KÝ, trả lý do tiếng Việt. (Kiểm hiệu lực chứng thư TRƯỚC KHI ký.)
    2. MỚI được chọn cơ chế (token hỗ trợ ∩ Phụ lục I cho phép) rồi C_SignInit +
       C_Sign.
    3. Gắn chữ ký + chứng thư + thời điểm ký vào thông điệp NGAY (toàn vẹn).

Token qua bridge → ký qua RPC (``ModuleSession`` che khác biệt tuyến).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography import x509 as cx509

from core.errors import (
    MechanismUnavailableError,
    SignerError,
    SigningFormatUnavailableError,
)
from core.models import SignResult, TokenInfo, ValidationResult
from core.platform import PlatformAdapter, get_adapter

# --------------------------------------------------------------------------- #
# Tri thức CHUẨN (KHÔNG phải tham số pháp lý): id thuật toán ↔ PKCS#11 ↔ OID     #
# --------------------------------------------------------------------------- #
# DigestInfo DER prefix cho RSA "băm-ngoài" (RFC 8017, mục 9.2).
_DIGESTINFO_PREFIX: dict[str, bytes] = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}
_HASHERS: dict[str, Callable[[bytes], hashlib._Hash]] = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}


@dataclass(frozen=True)
class AlgorithmSpec:
    """Đặc tả MỘT thuật toán chữ ký (dịch chuẩn; không mang giá trị pháp lý)."""

    id: str                 # định danh chuẩn — Phụ lục I dùng đúng vocabulary này
    key_type: str           # RSA | EC
    digest: str             # sha1 | sha256 | sha384 | sha512
    ckm_hash_in: str        # cơ chế token TỰ băm (vd. SHA256_RSA_PKCS)
    ckm_hash_out: str       # cơ chế token KHÔNG băm (vd. RSA_PKCS) — băm ở host
    cms_signature_algo: str # tên asn1crypto cho SignerInfo.signatureAlgorithm


# Đăng ký các thuật toán mà PHẦN MỀM biết CÁCH thực hiện (theo chuẩn). Phụ lục I
# chọn TẬP CON hợp lệ trong số này bằng ``id``.
_REGISTRY: dict[str, AlgorithmSpec] = {
    s.id: s for s in (
        AlgorithmSpec("RSASSA-PKCS1-v1_5-SHA256", "RSA", "sha256", "SHA256_RSA_PKCS", "RSA_PKCS", "sha256_rsa"),
        AlgorithmSpec("RSASSA-PKCS1-v1_5-SHA384", "RSA", "sha384", "SHA384_RSA_PKCS", "RSA_PKCS", "sha384_rsa"),
        AlgorithmSpec("RSASSA-PKCS1-v1_5-SHA512", "RSA", "sha512", "SHA512_RSA_PKCS", "RSA_PKCS", "sha512_rsa"),
        AlgorithmSpec("RSASSA-PSS-SHA256", "RSA", "sha256", "SHA256_RSA_PKCS_PSS", "RSA_PKCS_PSS", "rsassa_pss"),
        AlgorithmSpec("ECDSA-SHA256", "EC", "sha256", "ECDSA_SHA256", "ECDSA", "sha256_ecdsa"),
        AlgorithmSpec("ECDSA-SHA384", "EC", "sha384", "ECDSA_SHA384", "ECDSA", "sha384_ecdsa"),
        AlgorithmSpec("ECDSA-SHA512", "EC", "sha512", "ECDSA_SHA512", "ECDSA", "sha512_ecdsa"),
    )
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _digest(algo: str, data: bytes) -> bytes:
    hasher = _HASHERS.get(algo)
    if hasher is None:
        raise SignerError(f"Hàm băm không hỗ trợ: {algo}.")
    return hasher(data).digest()


def _pubkey_bits(cert: cx509.Certificate) -> int | None:
    pub = cert.public_key()
    return getattr(pub, "key_size", None)


def _key_family(cert: cx509.Certificate) -> str:
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return "EC"
    return "UNKNOWN"


# --------------------------------------------------------------------------- #
# Session tối thiểu mà signer cần (ModuleSession thoả; test tiêm bản giả)        #
# --------------------------------------------------------------------------- #
class _SigningSession:  # Protocol tối giản (documentary)
    def get_mechanisms(self, slot_id: int) -> list[str]: ...
    def sign(self, slot_id: int, key_id: str, mechanism: str, data: bytes, pin: str | None = None) -> bytes: ...
    def close(self) -> None: ...


TsaClient = Callable[[bytes, str], bytes]  # (imprint_hash, tsa_url) -> TimeStampToken DER


# --------------------------------------------------------------------------- #
# Signer                                                                       #
# --------------------------------------------------------------------------- #
class Signer:
    """Điều phối ký: gate hiệu lực -> chọn cơ chế -> C_Sign -> đóng gói + TSA."""

    def __init__(
        self,
        *,
        validator: Any = None,
        policy: Any = None,
        store: Any = None,
        adapter: PlatformAdapter | None = None,
        session_factory: Callable[[TokenInfo], Any] | None = None,
        tsa_client: TsaClient | None = None,
        evidence_dir: Path | None = None,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        self.adapter = adapter or get_adapter()
        self._validator = validator
        self._policy = policy
        self._store = store
        self._session_factory = session_factory
        self._tsa_client = tsa_client
        self._evidence_dir = evidence_dir
        self._clock = clock

    # -- lazy collaborators (đỡ IO khi test) ---------------------------- #
    @property
    def validator(self) -> Any:
        if self._validator is None:
            from core.trust.validator import CertificateValidator

            self._validator = CertificateValidator()
        return self._validator

    @property
    def policy(self) -> Any:
        if self._policy is None:
            from core.trust.policy import CompliancePolicy

            self._policy = CompliancePolicy()
        return self._policy

    @property
    def store(self) -> Any:
        if self._store is None:
            from core.trust.store import load as load_store

            self._store = load_store()
        return self._store

    # ------------------------------------------------------------------ #
    # API cấp cao: sign(...) — điều phối theo định dạng                    #
    # ------------------------------------------------------------------ #
    def sign(
        self,
        *,
        token: TokenInfo,
        key_id: str,
        cert_der: bytes,
        payload: bytes,
        fmt: str = "cms",
        chain: list[bytes] | None = None,
        at_time: datetime | None = None,
        pin: str | None = None,
        tsa_url: str | None = None,
    ) -> SignResult:
        """Ký ``payload`` theo ``fmt`` (cms|pades|xades). Điều 5: gate hiệu lực TRƯỚC.

        Ném :class:`SigningNotAllowedError` nếu chứng thư không HỢP LỆ (kèm
        :class:`ValidationResult`), :class:`MechanismUnavailableError` nếu không
        có cơ chế chung, :class:`SigningFormatUnavailableError` nếu định dạng chưa
        khả dụng.
        """
        # === BƯỚC 1 (Điều 5): kiểm hiệu lực TRƯỚC KHI ký ================= #
        validation: ValidationResult = self.validator.assert_signable(cert_der, at_time)

        fmt_l = fmt.lower()
        if fmt_l in ("cms", "cades"):
            signed, spec, ts_used = self._build_cms(
                token=token, key_id=key_id, cert_der=cert_der, data=payload,
                chain=chain, pin=pin, tsa_url=tsa_url,
            )
        elif fmt_l == "pades":
            signed, spec, ts_used = self._pades_sign(
                token=token, key_id=key_id, cert_der=cert_der, pdf_bytes=payload,
                pin=pin, tsa_url=tsa_url,
            )
        elif fmt_l == "xades":
            signed, spec, ts_used = self._xades_sign(
                token=token, key_id=key_id, cert_der=cert_der, xml_bytes=payload,
                pin=pin, tsa_url=tsa_url,
            )
        else:
            raise SignerError(f"Định dạng ký không hỗ trợ: {fmt!r} (cms|pades|xades).")

        signing_time = self._clock()
        evidence_id = self._persist_evidence(
            cert_der=cert_der, validation=validation, fmt=fmt_l,
            mechanism=spec.ckm_hash_in, signing_time=signing_time, tsa_used=ts_used, tsa_url=tsa_url,
        )
        return SignResult(
            signed_document_b64=base64.b64encode(signed).decode("ascii"),
            format=fmt_l,
            mechanism=spec.ckm_hash_in,
            signature_algorithm=spec.id,
            validation=validation,
            signing_time=signing_time,
            timestamped=ts_used,
            tsa_url=tsa_url or "",
            evidence_id=evidence_id,
            reasons_vi=[
                "Đã kiểm hiệu lực chứng thư HỢP LỆ trước khi ký (Điều 5 TT 15/2025).",
                f"Đã ký theo định dạng {fmt_l.upper()} bằng thuật toán {spec.id}.",
            ] + (["Đã gắn dấu thời gian từ TSA."] if ts_used else []),
        )

    # ------------------------------------------------------------------ #
    # Chọn cơ chế: token hỗ trợ ∩ Phụ lục I cho phép                       #
    # ------------------------------------------------------------------ #
    def select_mechanism(
        self, token: TokenInfo, cert_der: bytes, *, allowed_key_mechs: list[str] | None = None
    ) -> AlgorithmSpec:
        """Trả :class:`AlgorithmSpec` token hỗ trợ VÀ Phụ lục I cho phép, hợp key.

        Không giao nhau -> :class:`MechanismUnavailableError` (báo rõ hai phía).
        """
        # Đọc từ Phụ lục I (ném PolicyNotConfiguredError nếu CHƯA điền -> fail-closed).
        try:
            allowed_ids = self.policy.allowed_signature_algorithms()
            min_sizes = self.policy.min_key_sizes()
        except Exception as exc:  # noqa: BLE001 - gồm PolicyNotConfiguredError
            raise MechanismUnavailableError(
                "Chưa thể chọn thuật toán ký: Phụ lục I (tiêu chuẩn kỹ thuật TT 15/2025) "
                "CHƯA được điền/duyệt. Hãy transcribe từ bản gốc rồi thử lại.",
                detail=str(exc),
            ) from exc

        specs = [_REGISTRY[i] for i in allowed_ids if i in _REGISTRY]
        if not specs:
            raise MechanismUnavailableError(
                "Phụ lục I không liệt kê thuật toán ký nào mà phần mềm hỗ trợ theo chuẩn "
                f"(đã cấu hình: {allowed_ids})."
            )

        cert = _load_cert(cert_der)
        fam = _key_family(cert)
        bits = _pubkey_bits(cert)

        session = self._make_session(token)
        try:
            token_mechs = set(session.get_mechanisms(token.slot_id))
        finally:
            _safe_close(session)
        key_mech_filter = set(allowed_key_mechs) if allowed_key_mechs else None

        chosen: AlgorithmSpec | None = None
        for spec in specs:  # ưu tiên theo THỨ TỰ Phụ lục I
            if spec.key_type != fam:
                continue
            # Ràng buộc độ dài khoá tối thiểu (Phụ lục I).
            need = min_sizes.get(spec.key_type)
            if need and bits is not None and bits < int(need):
                continue
            supported = _mech_supported(spec, token_mechs, key_mech_filter)
            if supported:
                chosen = spec
                break

        if chosen is None:
            raise MechanismUnavailableError(
                "KHÔNG có cơ chế ký chung giữa TOKEN và Phụ lục I. "
                f"Phụ lục I cho phép: {[s.id for s in specs]}; "
                f"token hỗ trợ: {sorted(token_mechs)}."
            )
        return chosen

    # ------------------------------------------------------------------ #
    # Ký thô: chọn CKM đúng, băm-trong hay băm-ngoài (DigestInfo)          #
    # ------------------------------------------------------------------ #
    def _sign_tbs(
        self, token: TokenInfo, key_id: str, spec: AlgorithmSpec, tbs: bytes, pin: str | None
    ) -> bytes:
        """Ký ``tbs`` (dữ liệu-được-ký) bằng cơ chế đã chọn qua token."""
        session = self._make_session(token)
        try:
            mechs = set(session.get_mechanisms(token.slot_id))
            if spec.ckm_hash_in in mechs:
                # Băm-TRONG-token: đưa nguyên tbs, token tự băm rồi ký.
                return session.sign(token.slot_id, key_id, spec.ckm_hash_in, tbs, pin)
            if spec.ckm_hash_out in mechs:
                # Băm-NGOÀI: host băm; RSA cần bọc DigestInfo, ECDSA ký thẳng hash.
                digest = _digest(spec.digest, tbs)
                payload = self._wrap_for_hash_out(spec, digest)
                return session.sign(token.slot_id, key_id, spec.ckm_hash_out, payload, pin)
            raise MechanismUnavailableError(
                f"Token không còn hỗ trợ cơ chế {spec.ckm_hash_in}/{spec.ckm_hash_out} khi ký."
            )
        finally:
            _safe_close(session)

    @staticmethod
    def _wrap_for_hash_out(spec: AlgorithmSpec, digest: bytes) -> bytes:
        if spec.key_type == "RSA" and spec.cms_signature_algo.endswith("_rsa"):
            prefix = _DIGESTINFO_PREFIX.get(spec.digest)
            if prefix is None:
                raise SignerError(f"Thiếu DigestInfo prefix cho {spec.digest}.")
            return prefix + digest  # DigestInfo DER đúng chuẩn RFC 8017
        if spec.cms_signature_algo == "rsassa_pss":
            # RSA-PSS "băm-ngoài" (CKM_RSA_PKCS_PSS thô) cần tham số MGF/salt truyền
            # kèm mechanism — không thể chỉ đưa giá trị băm. Từ chối để KHÔNG tạo
            # chữ ký sai chuẩn; yêu cầu token hỗ trợ cơ chế băm-trong SHA*_RSA_PKCS_PSS.
            raise MechanismUnavailableError(
                "Token chỉ hỗ trợ RSA-PSS băm-ngoài (CKM_RSA_PKCS_PSS thô) — cần cơ chế "
                "băm-trong (SHA*_RSA_PKCS_PSS) để ký PSS đúng chuẩn."
            )
        # ECDSA băm-ngoài: token nhận thẳng giá trị băm.
        return digest

    # ------------------------------------------------------------------ #
    # CMS/PKCS#7 detached + cert + chain (+ TSA tùy chọn)                  #
    # ------------------------------------------------------------------ #
    def _build_cms(
        self, *, token: TokenInfo, key_id: str, cert_der: bytes, data: bytes,
        chain: list[bytes] | None, pin: str | None, tsa_url: str | None,
    ) -> tuple[bytes, AlgorithmSpec, bool]:
        from asn1crypto import algos, cms
        from asn1crypto import x509 as ax509

        spec = self.select_mechanism(token, cert_der)
        cert = ax509.Certificate.load(cert_der)
        message_digest = _digest(spec.digest, data)
        signing_time = self._clock()

        signed_attrs = cms.CMSAttributes([
            cms.CMSAttribute({"type": "content_type", "values": ["data"]}),
            cms.CMSAttribute({"type": "signing_time", "values": [cms.Time({"utc_time": signing_time})]}),
            cms.CMSAttribute({"type": "message_digest", "values": [message_digest]}),
        ])
        tbs = signed_attrs.dump()  # SET OF (0x31) — đúng phần được ký của CMS
        signature = self._sign_tbs(token, key_id, spec, tbs, pin)

        certs = [cert] + [ax509.Certificate.load(c) for c in (chain or self._collect_chain(cert_der))]
        signer_info = cms.SignerInfo({
            "version": "v1",
            "sid": cms.SignerIdentifier({
                "issuer_and_serial_number": cms.IssuerAndSerialNumber({
                    "issuer": cert.issuer, "serial_number": cert.serial_number,
                })
            }),
            "digest_algorithm": algos.DigestAlgorithm({"algorithm": spec.digest}),
            "signed_attrs": signed_attrs,
            "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": spec.cms_signature_algo}),
            "signature": signature,
        })

        ts_used = False
        if tsa_url:
            token_der = self._request_timestamp(signature, tsa_url)
            if token_der:
                signer_info["unsigned_attrs"] = cms.CMSAttributes([
                    cms.CMSAttribute({
                        "type": "signature_time_stamp_token",
                        "values": [cms.ContentInfo.load(token_der)],
                    })
                ])
                ts_used = True

        signed_data = cms.SignedData({
            "version": "v1",
            "digest_algorithms": [algos.DigestAlgorithm({"algorithm": spec.digest})],
            "encap_content_info": {"content_type": "data"},  # detached: KHÔNG nhúng nội dung
            "certificates": certs,
            "signer_infos": [signer_info],
        })
        content_info = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
        return content_info.dump(), spec, ts_used

    def build_cms(
        self, *, token: TokenInfo, key_id: str, cert_der: bytes, data: bytes,
        chain: list[bytes] | None = None, at_time: datetime | None = None,
        pin: str | None = None, tsa_url: str | None = None,
    ) -> bytes:
        """CMS detached công khai — CÓ gate hiệu lực (Điều 5) trước khi ký."""
        self.validator.assert_signable(cert_der, at_time)
        signed, _spec, _ts = self._build_cms(
            token=token, key_id=key_id, cert_der=cert_der, data=data,
            chain=chain, pin=pin, tsa_url=tsa_url,
        )
        return signed

    # ------------------------------------------------------------------ #
    # PAdES / XAdES — fail-closed khi thiếu thư viện/profile               #
    # ------------------------------------------------------------------ #
    def _pades_sign(self, **_: Any) -> tuple[bytes, AlgorithmSpec, bool]:
        try:
            import pyhanko  # noqa: F401
        except Exception as exc:  # noqa: BLE001
            raise SigningFormatUnavailableError(
                "Ký PAdES chưa khả dụng: thiếu thư viện pyHanko và/hoặc PROFILE PAdES "
                "trong Phụ lục I. Cài pyHanko và điền profile PAdES rồi thử lại.",
                detail=str(exc),
            ) from exc
        raise SigningFormatUnavailableError(
            "Ký PAdES cần cấu hình profile cụ thể (PAdES-B-LT/LTA...) theo Phụ lục I — "
            "chưa bật để tránh tạo chữ ký sai chuẩn."
        )

    def _xades_sign(self, **_: Any) -> tuple[bytes, AlgorithmSpec, bool]:
        raise SigningFormatUnavailableError(
            "Ký XAdES chưa khả dụng: cần thư viện XML-DSig và PROFILE XAdES cụ thể "
            "(XAdES-B/T/LT...) theo Phụ lục I. Chưa bật để tránh chữ ký sai chuẩn."
        )

    def pades_sign(self, pdf_bytes: bytes, **kwargs: Any) -> bytes:
        raise SigningFormatUnavailableError(
            "Ký PAdES chưa khả dụng trong môi trường này (xem Phụ lục I + pyHanko)."
        )

    def xades_sign(self, xml_bytes: bytes, **kwargs: Any) -> bytes:
        raise SigningFormatUnavailableError(
            "Ký XAdES chưa khả dụng trong môi trường này (xem Phụ lục I + XML-DSig)."
        )

    # ------------------------------------------------------------------ #
    # Dấu thời gian (RFC 3161) — BẮT BUỘC khi pháp luật yêu cầu            #
    # ------------------------------------------------------------------ #
    def timestamp(self, data: bytes, tsa_url: str, *, digest: str = "sha256") -> bytes:
        """Xin TimeStampToken (DER) từ TSA cho ``data``. Tham chiếu QCVN 138:2025."""
        imprint = _digest(digest, data)
        token = self._request_timestamp_raw(imprint, tsa_url, digest)
        if not token:
            raise SignerError("Không lấy được dấu thời gian từ TSA.")
        return token

    def _request_timestamp(self, signature: bytes, tsa_url: str) -> bytes | None:
        # Dấu thời gian chữ ký (RFC 3161) trên trị băm của signature.
        return self._request_timestamp_raw(hashlib.sha256(signature).digest(), tsa_url, "sha256")

    def _request_timestamp_raw(self, imprint: bytes, tsa_url: str, digest: str) -> bytes | None:
        if self._tsa_client is not None:  # tiêm được để test / danh sách TSA từ rootca.gov.vn
            return self._tsa_client(imprint, tsa_url)
        return _default_tsa_request(imprint, tsa_url, digest)

    # ------------------------------------------------------------------ #
    # Chain từ trust store (nhúng vào CMS)                                 #
    # ------------------------------------------------------------------ #
    def _collect_chain(self, cert_der: bytes) -> list[bytes]:
        """Thu chứng thư CA phát hành (trung gian + gốc) từ kho tin cậy để nhúng."""
        out: list[bytes] = []
        try:
            leaf = _load_cert(cert_der)
            store = self.store
        except Exception:  # noqa: BLE001
            return out
        current = leaf
        seen = {current.fingerprint(_sha256())}
        for _ in range(16):
            try:
                entry = store.find_issuer(current)
            except Exception:  # noqa: BLE001
                break
            if entry is None:
                break
            issuer = entry.cert
            fp = issuer.fingerprint(_sha256())
            out.append(issuer.public_bytes(_der_encoding()))
            if issuer.subject == issuer.issuer or fp in seen:
                break
            seen.add(fp)
            current = issuer
        return out

    # ------------------------------------------------------------------ #
    # Bằng chứng ký (KHÔNG pin/DER private) — đối chiếu audit               #
    # ------------------------------------------------------------------ #
    def _persist_evidence(
        self, *, cert_der: bytes, validation: ValidationResult, fmt: str,
        mechanism: str, signing_time: datetime, tsa_used: bool, tsa_url: str | None,
    ) -> str:
        import json

        evidence_id = secrets.token_hex(8)
        record = {
            "evidence_id": evidence_id,
            "signing_time": signing_time.isoformat(),
            "format": fmt,
            "mechanism": mechanism,
            "signer_cert_sha256": hashlib.sha256(cert_der).hexdigest(),  # CHỈ thumbprint
            "subject": validation.subject,
            "ca_name": validation.ca_name,
            "validation_status": validation.status.value,
            "timestamped": tsa_used,
            "tsa_url": tsa_url or "",
        }
        directory = self._evidence_dir or (self.adapter.log_dir() / "signatures")
        try:
            directory.mkdir(parents=True, exist_ok=True)
            (directory / f"sign_{evidence_id}.json").write_text(
                json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except OSError:
            pass  # không lưu được cũng KHÔNG chặn ký; id vẫn trả về
        return evidence_id

    # -- session helper -------------------------------------------------- #
    def _make_session(self, token: TokenInfo) -> Any:
        if self._session_factory is not None:
            return self._session_factory(token)
        from core.bridge.router import ModuleSession

        return ModuleSession(token.module_path, adapter=self.adapter)


# --------------------------------------------------------------------------- #
# Tiện ích module-level                                                        #
# --------------------------------------------------------------------------- #
def _mech_supported(spec: AlgorithmSpec, token_mechs: set[str], key_filter: set[str] | None) -> bool:
    for ckm in (spec.ckm_hash_in, spec.ckm_hash_out):
        if ckm in token_mechs and (key_filter is None or ckm in key_filter):
            return True
    return False


def _load_cert(cert_der: bytes) -> cx509.Certificate:
    try:
        return cx509.load_der_x509_certificate(cert_der)
    except Exception as exc:  # noqa: BLE001
        raise SignerError("Không đọc được chứng thư người ký (DER không hợp lệ).") from exc


def _sha256():  # type: ignore[no-untyped-def]
    from cryptography.hazmat.primitives import hashes

    return hashes.SHA256()


def _der_encoding():  # type: ignore[no-untyped-def]
    from cryptography.hazmat.primitives.serialization import Encoding

    return Encoding.DER


def _safe_close(session: Any) -> None:
    try:
        session.close()
    except Exception:  # noqa: BLE001
        pass


def _default_tsa_request(imprint: bytes, tsa_url: str, digest: str) -> bytes | None:
    """Gửi TimeStampReq (RFC 3161) tới TSA qua HTTPS, trả TimeStampToken (DER).

    Ngoại lệ mạng ĐƯỢC PHÉP (CRL/OCSP/TSA + đồng bộ kho tin cậy). Lỗi -> None.
    """
    try:
        import httpx
        from asn1crypto import algos, tsp

        req = tsp.TimeStampReq({
            "version": "v1",
            "message_imprint": tsp.MessageImprint({
                "hash_algorithm": algos.DigestAlgorithm({"algorithm": digest}),
                "hashed_message": imprint,
            }),
            "cert_req": True,
        })
        resp = httpx.post(
            tsa_url, content=req.dump(),
            headers={"Content-Type": "application/timestamp-query"}, timeout=20.0,
        )
        if resp.status_code != 200:
            return None
        ts_resp = tsp.TimeStampResp.load(resp.content)
        token = ts_resp["time_stamp_token"]
        return token.dump() if token.native is not None else None
    except Exception:  # noqa: BLE001 - TSA lỗi/không có mạng -> None (caller quyết định)
        return None


__all__ = ["Signer", "AlgorithmSpec", "SignResult"]
