"""Endpoint chính của daemon vn-esign (ký số + kiểm tra chữ ký số).

Mọi collaborator lấy từ ``request.app.state.deps`` (:class:`ServiceDeps`) nên
test được mà không cần token/mạng. Nguyên tắc bảo mật (xem thêm
``service/security.py`` và ``service/app.py``):

    * KHÔNG endpoint nào trả private key. PIN chỉ đi MỘT CHIỀU vào token.
    * Chứng thư fallback (kho OS) được validator kiểm như mọi cert khác và ĐÁNH
      DẤU rõ ``from_token=false``.
    * Log chỉ thumbprint — KHÔNG log PIN, KHÔNG log DER đầy đủ.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from core import __version__
from core.aggregator import ca_info_from_validation, classify_token_source
from core.discovery import diagnose_no_modules, discover_modules
from core.engine import get_platform_info
from core.errors import (
    MechanismUnavailableError,
    SignerError,
    SigningFormatUnavailableError,
    SigningNotAllowedError,
)
from core.models import (
    CertInfo,
    CertRecord,
    TokenInfo,
    ValidationResult,
    ValidationStatusCode,
)
from core.signature_verify import verify_detached
from service.runtime import LOGGER_NAME
from service.security import connection_allowed
from service.sessions import _to_bytearray

router = APIRouter()
_log = logging.getLogger(LOGGER_NAME)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Danh tính token (ổn định theo module+slot+serial, KHÔNG lộ bí mật)            #
# --------------------------------------------------------------------------- #
def token_public_id(token: TokenInfo) -> str:
    import hashlib

    raw = f"{token.module_path}|{token.slot_id}|{token.serial}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _trust_store_health() -> dict[str, object]:
    from core.trust.store import load as load_store

    try:
        store = load_store()
    except Exception:  # noqa: BLE001 - fail-closed
        return {"synced_at": None, "stale": True, "verified": False, "empty": True,
                "reasons_vi": ["Không nạp được kho neo tin cậy."]}
    stale, reasons = store.is_stale()
    return {
        "synced_at": store.synced_at.isoformat() if store.synced_at else None,
        "stale": stale,
        "verified": store.verified,
        "empty": store.is_empty,
        "reasons_vi": reasons,
    }


# --------------------------------------------------------------------------- #
# Dựng "view" cho chứng thư (KHÔNG bao giờ chứa private key)                    #
# --------------------------------------------------------------------------- #
def _blank_result() -> ValidationResult:
    now = _now()
    return ValidationResult(
        status=ValidationStatusCode.INVALID, checked_at=now, at_time=now,
        reasons_vi=["Thiếu dữ liệu DER để kiểm tra."],
    )


def _enrich(
    certs: list[CertInfo], *, source: str, from_token: bool, token_ref: str, validator: object
) -> list[CertRecord]:
    """Chạy validator + dựng CAInfo cho từng CertInfo -> CertRecord (bằng chứng)."""
    out: list[CertRecord] = []
    for ci in certs:
        der = base64.b64decode(ci.der_b64) if ci.der_b64 else b""
        result = validator.validate(der) if der else _blank_result()  # type: ignore[attr-defined]
        out.append(CertRecord(
            cert=ci, ca=ca_info_from_validation(result), validation=result,
            source=source, from_token=from_token, token_ref=token_ref,
        ))
    return out


def _token_bundle_view(token: TokenInfo, records: list[CertRecord]) -> dict[str, object]:
    return {
        "id": token_public_id(token),
        "token": token.model_dump(mode="json"),
        "certificates": [r.model_dump(mode="json") for r in records],
    }


def _find_token(deps, token_id: str) -> TokenInfo | None:  # type: ignore[no-untyped-def]
    for token in deps.enumerate_fn():
        if token_public_id(token) == token_id:
            return token
    return None


# --------------------------------------------------------------------------- #
# GET /health                                                                  #
# --------------------------------------------------------------------------- #
@router.get("/health", summary="Trạng thái daemon + nền tảng + kho tin cậy")
def health(request: Request) -> dict[str, object]:
    deps = request.app.state.deps
    pi = get_platform_info(deps.adapter)
    return {
        "ok": True,
        "version": __version__,
        "platform": {
            "os": pi.name,
            "arch": pi.machine,
            "bits": pi.bits,
            "rosetta": pi.rosetta,
            "bridge_active": deps.bridge_active(),
        },
        "trust_store": _trust_store_health(),
    }


# --------------------------------------------------------------------------- #
# GET /diagnose                                                                #
# --------------------------------------------------------------------------- #
@router.get("/diagnose", summary="Chẩn đoán đầy đủ theo OS + remediation tiếng Việt")
def diagnose(request: Request) -> dict[str, object]:
    deps = request.app.state.deps
    ad = deps.adapter
    pi = get_platform_info(ad)
    try:
        modules = discover_modules(ad)
    except Exception:  # noqa: BLE001
        modules = []
    diagnostics = diagnose_no_modules(ad)  # luôn kèm hướng dẫn (theo thứ tự xác suất)
    return {
        "platform": pi.model_dump(mode="json"),
        "pcsc_ready": pi.pcsc_ready,
        "pcsc_remediation": pi.pcsc_remediation,
        "modules_found": len(modules),
        "modules": [m.model_dump(mode="json") for m in modules],
        "trust_store": _trust_store_health(),
        "diagnostics": [d.model_dump(mode="json") for d in diagnostics],
        "note": "Daemon chỉ PHÁT HIỆN & HƯỚNG DẪN — không tự tải/chạy installer bên thứ ba.",
    }


# --------------------------------------------------------------------------- #
# GET /tokens  (thử KHÔNG cần PIN trước)                                        #
# --------------------------------------------------------------------------- #
@router.get("/tokens", summary="Liệt kê token + chứng thư công khai + hiệu lực")
def tokens(request: Request) -> dict[str, object]:
    deps = request.app.state.deps
    agg = deps.aggregate_fn(validator=deps.validator_factory(), include_fallback=True)
    return {
        "tokens": [
            _token_bundle_view(b.token, b.certificates) for b in agg.tokens
        ],
        "fallback_certificates": [r.model_dump(mode="json") for r in agg.fallback_certificates],
        "sources_scanned": agg.sources_scanned,
        "warnings": agg.warnings,
    }


# --------------------------------------------------------------------------- #
# GET /tokens/{id}/certs  (dùng phiên PIN nếu có -> đọc cả cert private)         #
# --------------------------------------------------------------------------- #
@router.get("/tokens/{token_id}/certs", summary="Chứng thư trên một token")
def token_certs(token_id: str, request: Request, session_id: str | None = None) -> dict[str, object]:
    deps = request.app.state.deps
    token = _find_token(deps, token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy token với id đã cho.")

    pin_cb = None
    logged_in = False
    if session_id:
        session = deps.sessions.get(session_id)
        if session is not None and session.token_id == token_id:
            pin_cb = session.pin_bytes  # callable trả bytes -> đẩy MỘT CHIỀU vào token
            logged_in = True

    result = deps.read_fn(token, pin_cb)
    source = classify_token_source(token)
    records = _enrich(
        list(getattr(result, "certificates", []) or []),
        source=source, from_token=True, token_ref=token_id,
        validator=deps.validator_factory(),
    )
    err = getattr(result, "error", None)
    return {
        "token_id": token_id,
        "logged_in": logged_in,
        "certificates": [r.model_dump(mode="json") for r in records],
        "warnings": list(getattr(result, "warnings", []) or []),
        "error": err.model_dump(mode="json") if err is not None else None,
    }


# --------------------------------------------------------------------------- #
# POST /login  (rate-limit, PIN vào RAM, TTL, zeroize)                          #
# --------------------------------------------------------------------------- #
class LoginBody(BaseModel):
    token_id: str
    pin: str = Field(..., max_length=256, description="PIN token (nhạy cảm — không log, không lưu).")


@router.post("/login", summary="Đăng nhập token bằng PIN -> phiên RAM có TTL")
def login(body: LoginBody, request: Request) -> dict[str, object]:
    deps = request.app.state.deps

    if not deps.login_limiter.allow(body.token_id):
        raise HTTPException(
            status_code=429,
            detail="Quá nhiều lần thử đăng nhập — vui lòng chờ rồi thử lại (chống dò PIN).",
        )

    token = _find_token(deps, body.token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy token với id đã cho.")

    pin_ba = _to_bytearray(body.pin)  # sang bytearray NGAY (str từ JSON là thoáng qua)
    try:
        result = deps.read_fn(token, lambda: bytes(pin_ba))
    except Exception as exc:  # noqa: BLE001
        _zeroize(pin_ba)
        _log.info("login token=%s: lỗi đọc", body.token_id)
        raise HTTPException(status_code=500, detail=f"Lỗi khi đăng nhập token: {exc}") from exc

    err = getattr(result, "error", None)
    if err is not None:
        _zeroize(pin_ba)
        _log.info("login token=%s: %s", body.token_id, getattr(err, "code", ""))
        # 401 cho PIN sai/khoá; giữ nguyên thông báo tiếng Việt.
        raise HTTPException(status_code=401, detail=err.model_dump(mode="json"))

    session = deps.sessions.login(body.token_id, pin_ba)  # store giữ bản copy riêng
    _zeroize(pin_ba)
    deps.login_limiter.reset(body.token_id)  # đăng nhập OK -> gỡ giới hạn cho token này

    records = _enrich(
        list(getattr(result, "certificates", []) or []),
        source=classify_token_source(token), from_token=True, token_ref=body.token_id,
        validator=deps.validator_factory(),
    )
    _log.info("login token=%s: OK, %d cert", body.token_id, len(records))
    return {
        "session_id": session.id,
        "token_id": body.token_id,
        "expires_in": deps.sessions.ttl,
        "certificates": [r.model_dump(mode="json") for r in records],
        "warnings": list(getattr(result, "warnings", []) or []),
    }


# --------------------------------------------------------------------------- #
# POST /logout  (zeroize phiên)                                                 #
# --------------------------------------------------------------------------- #
class LogoutBody(BaseModel):
    session_id: str


@router.post("/logout", summary="Đăng xuất -> zeroize PIN trong RAM")
def logout(body: LogoutBody, request: Request) -> dict[str, object]:
    deps = request.app.state.deps
    ok = deps.sessions.logout(body.session_id)
    return {"logged_out": ok}


# --------------------------------------------------------------------------- #
# POST /validate  (phần mềm KIỂM TRA CHỮ KÝ SỐ)                                 #
# --------------------------------------------------------------------------- #
class SignatureCheck(BaseModel):
    data_b64: str = Field(..., description="Dữ liệu gốc đã ký (base64).")
    signature_b64: str = Field(..., description="Chữ ký cần kiểm (base64).")
    algorithm: str = Field(default="sha256", description="Hàm băm: sha256|sha384|sha512|sha1.")
    rsa_scheme: str = Field(default="pkcs1v15", description="RSA: pkcs1v15|pss.")


class ValidateBody(BaseModel):
    certificate_b64: str = Field(..., description="Chứng thư người ký (DER, base64).")
    at_time: datetime | None = Field(default=None, description="Mốc thời gian đối chiếu hiệu lực.")
    signature: SignatureCheck | None = Field(default=None, description="Kiểm chữ ký tách rời (tuỳ chọn).")


@router.post("/validate", summary="Kiểm tra hiệu lực chứng thư + (tuỳ chọn) chữ ký số")
def validate(body: ValidateBody, request: Request) -> dict[str, object]:
    deps = request.app.state.deps
    try:
        der = base64.b64decode(body.certificate_b64)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="certificate_b64 không phải base64 hợp lệ.") from None

    result: ValidationResult = deps.validator_factory().validate(der, body.at_time)
    _log.info("validate cert sha256=%s -> %s", result_subject_thumb(der), result.status.value)

    resp: dict[str, object] = {"validation": result.model_dump(mode="json")}
    if body.signature is not None:
        try:
            data = base64.b64decode(body.signature.data_b64)
            sig = base64.b64decode(body.signature.signature_b64)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="data_b64/signature_b64 không hợp lệ.") from None
        ok, reason = verify_detached(
            der, data, sig,
            algorithm=body.signature.algorithm, rsa_scheme=body.signature.rsa_scheme,
        )
        resp["signature_valid"] = ok
        resp["signature_reason_vi"] = reason
    return resp


def result_subject_thumb(der: bytes) -> str:
    import hashlib

    return hashlib.sha256(der).hexdigest()  # CHỈ thumbprint vào log, không bao giờ DER đầy đủ


# --------------------------------------------------------------------------- #
# POST /sign  (CHỈ khi phiên login hợp lệ; Điều 5: validate TRƯỚC khi ký)        #
# --------------------------------------------------------------------------- #
class SignBody(BaseModel):
    token_id: str
    key_id: str = Field(..., description="CKA_ID (hex) của khoá private cần ký.")
    format: str = Field(default="cms", description="cms | pades | xades.")
    payload_base64: str = Field(
        ..., max_length=96_000_000, description="Thông điệp cần ký (base64; trần ~72MB nhị phân)."
    )
    session_id: str = Field(..., description="Phiên đăng nhập hợp lệ (bắt buộc để ký).")
    tsa_url: str | None = Field(default=None, description="URL TSA (tuỳ chọn/bắt buộc theo luật).")


def _find_signing_cert(certs: list[CertInfo], key_id: str) -> CertInfo | None:
    """Chọn chứng thư có khoá private khớp ``key_id`` (CKA_ID hex)."""
    kid = key_id.lower()
    for ci in certs:
        has_key = bool(ci.key and ci.key.has_private_key)
        cand_ids = {ci.key_id_hex.lower(), (ci.key.id_hex.lower() if ci.key else "")}
        if has_key and kid in cand_ids:
            return ci
    return None


@router.post("/sign", summary="Ký số thông điệp (Điều 5: kiểm hiệu lực TRƯỚC khi ký)")
def sign(body: SignBody, request: Request) -> dict[str, object]:
    deps = request.app.state.deps

    # 1) CHỈ ký khi phiên login hợp lệ cho đúng token.
    session = deps.sessions.get(body.session_id)
    if session is None or session.token_id != body.token_id:
        raise HTTPException(status_code=401, detail="Phiên đăng nhập không hợp lệ hoặc đã hết hạn.")

    token = _find_token(deps, body.token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="Không tìm thấy token với id đã cho.")

    try:
        payload = base64.b64decode(body.payload_base64)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="payload_base64 không phải base64 hợp lệ.") from None

    # 2) Lấy chứng thư người ký từ token (đăng nhập bằng PIN của phiên).
    read_result = deps.read_fn(token, session.pin_bytes)
    signer_cert = _find_signing_cert(list(getattr(read_result, "certificates", []) or []), body.key_id)
    if signer_cert is None or not signer_cert.der_b64:
        raise HTTPException(
            status_code=404,
            detail="Không tìm thấy chứng thư có khoá private khớp key_id trên token.",
        )
    cert_der = base64.b64decode(signer_cert.der_b64)
    pin_str = session.pin_bytes().decode("utf-8", "ignore")  # PIN đi MỘT CHIỀU vào token

    # 3) Ký — Signer.sign gọi assert_signable TRƯỚC (Điều 5). status != VALID -> từ chối.
    signer = deps.signer_factory()
    try:
        result = signer.sign(
            token=token, key_id=body.key_id, cert_der=cert_der, payload=payload,
            fmt=body.format, pin=pin_str, tsa_url=body.tsa_url,
        )
    except SigningNotAllowedError as exc:
        _log.info("sign REFUSED token=%s: %s", body.token_id, getattr(exc, "detail", ""))
        vr = exc.result.model_dump(mode="json") if getattr(exc, "result", None) is not None else None
        raise HTTPException(status_code=422, detail={
            "message_vi": exc.message,
            "reason": "Chứng thư KHÔNG hợp lệ — TỪ CHỐI KÝ (Điều 5 TT 15/2025).",
            "validation_result": vr,
        }) from exc
    except (MechanismUnavailableError, SigningFormatUnavailableError) as exc:
        raise HTTPException(status_code=409, detail={"message_vi": exc.message, "detail": exc.detail}) from exc
    except SignerError as exc:
        raise HTTPException(status_code=400, detail={"message_vi": exc.message, "detail": exc.detail}) from exc

    _log.info(
        "sign OK token=%s fmt=%s mech=%s evidence=%s",
        body.token_id, result.format, result.mechanism, result.evidence_id,
    )
    return {
        "signed_document_base64": result.signed_document_b64,
        "validation_result": result.validation.model_dump(mode="json"),
        "evidence_id": result.evidence_id,
        "format": result.format,
        "mechanism": result.mechanism,
        "signature_algorithm": result.signature_algorithm,
        "signing_time": result.signing_time.isoformat(),
        "timestamped": result.timestamped,
        "reasons_vi": result.reasons_vi,
    }


# --------------------------------------------------------------------------- #
# WS /events  (cắm/rút token realtime)                                         #
# --------------------------------------------------------------------------- #
@router.websocket("/events")
async def events(websocket: WebSocket) -> None:
    deps = websocket.app.state.deps
    # WebSocket KHÔNG đi qua middleware HTTP -> kiểm Host/Origin thủ công.
    if not connection_allowed(websocket.headers, deps.allowed_hosts, deps.allowed_origins):
        await websocket.close(code=1008)  # policy violation
        return
    await websocket.accept()
    source = deps.events_source_factory()
    try:
        await websocket.send_json({"type": "ready", "readers": source.readers()})
        while True:
            await asyncio.sleep(deps.event_poll_interval)
            for event in source.poll():
                await websocket.send_json({"type": "token_event", **event})
    except WebSocketDisconnect:
        return
    except Exception:  # noqa: BLE001 - kết nối lỗi -> đóng êm
        try:
            await websocket.close(code=1011)
        except Exception:  # noqa: BLE001
            pass


def _zeroize(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


__all__ = ["router", "token_public_id"]
