"""Thu thập "intel report" THỰC ĐỊA — ẨN DANH, chỉ ghi file LOCAL.

MỤC ĐÍCH: gom dữ liệu tương thích thiết bị (module/token/chip/profile chứng thư)
trên MÁY CỦA CHÍNH NGƯỜI DÙNG để hoàn thiện bảng vàng + xác minh profile định
danh (mục 1.8 chưa chốt). CHẠY ĐƯỢC trên cả 3 OS (đi qua PlatformAdapter).

⭐⭐ QUYỀN RIÊNG TƯ — TUYỆT ĐỐI (dữ liệu công dân, dự án quốc gia):
    * KHÔNG thu Subject DN nguyên văn; KHÔNG thu MST/CCCD/số định danh (giá trị);
      KHÔNG thu serial chứng thư; KHÔNG thu DER; KHÔNG thu serial token; KHÔNG PIN.
    * Subject DN chỉ giữ CẤU TRÚC đã ẩn danh: OID/tên RDN + "hình dạng" (chữ→a,
      số→X) — đủ để biết ĐỊNH DẠNG, KHÔNG lộ nội dung.
    * KHÔNG tự gửi báo cáo đi đâu — chỉ ghi file local.
    * IN RA mọi trường sắp ghi + HỎI XÁC NHẬN trước khi ghi.
    * Xem đánh giá tác động quyền riêng tư: docs/compliance/DPIA.md

    python -m tools.harvest_intel [--output report.json] [--yes]
"""

from __future__ import annotations

import hashlib
import json
import platform as _platform
import re
import sys
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- #
# Ẩn danh                                                                      #
# --------------------------------------------------------------------------- #
_OID_NAME = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC",
}


def _shape(value: str) -> str:
    """Giữ CẤU TRÚC, xoá NỘI DUNG: chữ→'a', số→'X', ký tự khác giữ nguyên.

    Vd. 'MST:0101234567-001' -> 'aaa:XXXXXXXXXX-XXX' (lộ định dạng, không lộ số).
    """
    out = []
    for ch in value:
        if ch.isdigit():
            out.append("X")
        elif ch.isalpha():
            out.append("a")
        else:
            out.append(ch)
    return "".join(out)


def _mask_path(path: str) -> str:
    """Xoá tên người dùng khỏi đường dẫn (thư mục home -> <HOME>)."""
    try:
        home = str(Path.home())
        if home and path.startswith(home):
            path = "<HOME>" + path[len(home):]
    except Exception:  # noqa: BLE001
        pass
    # Windows: C:\Users\<name>\...  |  *nix: /home/<name>/, /Users/<name>/
    path = re.sub(r"([/\\](?:Users|home)[/\\])[^/\\]+", r"\1<user>", path)
    return path


def _sha256_file(path: str) -> str:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return ""


# --------------------------------------------------------------------------- #
# Thu thập                                                                     #
# --------------------------------------------------------------------------- #
def _host() -> dict[str, Any]:
    from core.platform import get_adapter

    ad = get_adapter()
    arch = ad.host_arch()
    return {
        "os": ad.name(),                       # tên OS lấy TỪ adapter (không rẽ nhánh OS ở đây)
        "os_release": _platform.release(),
        "os_version": _platform.version(),
        "machine": arch["machine"],
        "bits": arch["bits"],
        "rosetta": arch["rosetta"],
    }


def _modules() -> list[dict[str, Any]]:
    from core.bridge.router import ModuleSession
    from core.discovery import discover
    from core.platform import get_adapter

    ad = get_adapter()
    out: list[dict[str, Any]] = []
    try:
        result = discover(ad, deep=True, use_cache=False)
    except Exception as exc:  # noqa: BLE001
        return [{"error": f"discover thất bại: {exc}"}]

    for m in result.modules:
        entry: dict[str, Any] = {
            "path_masked": _mask_path(m.path),
            "sha256": _sha256_file(m.path),
            "track": m.track.value,
            "arch": m.arch,
            "needs_arch_bridge": m.needs_arch_bridge,
            "tier": m.tier,
            "source": m.source,
            "chip_hint": m.chip_hint,     # gợi ý từ tên file (không phải kết luận)
            "confidence_label": m.confidence_label,
        }
        # C_GetInfo (metadata thư viện — không định danh cá nhân).
        try:
            info = ModuleSession(m.path, adapter=ad).get_info()
            cver = info.get("cryptoki_version")
            entry["cryptoki"] = {
                "manufacturerID": info.get("manufacturer", ""),
                "libraryDescription": info.get("library_description", ""),
                "version": cver,
                "ok": info.get("ok", False),
            }
        except Exception as exc:  # noqa: BLE001
            entry["cryptoki"] = {"error": str(exc)}
        out.append(entry)
    return out


def _flags_decoded(token: Any) -> dict[str, bool]:
    ps = token.pin_state
    return {
        "login_required": ps.login_required, "pin_count_low": ps.count_low,
        "pin_final_try": ps.final_try, "pin_locked": ps.locked,
        "protected_auth_path": ps.protected_auth_path,
    }


def _tokens_and_certs() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Token (chip thật, KHÔNG serial) + cert (chỉ Issuer/CA/profile ẩn danh)."""
    from core.aggregator import merge_all_sources

    tokens_out: list[dict[str, Any]] = []
    certs_out: list[dict[str, Any]] = []
    try:
        agg = merge_all_sources(include_fallback=True)  # KHÔNG PIN
    except Exception as exc:  # noqa: BLE001
        return [{"error": f"merge_all_sources thất bại: {exc}"}], []

    for bundle in agg.tokens:
        t = bundle.token
        tokens_out.append({
            "label": t.label,                          # nhãn token (do người dùng đặt)
            "manufacturerID_chip": t.manufacturer_id,  # ⭐ CHIP THẬT (C_GetTokenInfo)
            "model": t.model,
            "flags_decoded": _flags_decoded(t),
            "track": t.track, "arch": t.arch, "via_bridge": t.via_bridge,
            # ⭐ KHÔNG có serial token (định danh thiết bị).
        })
        for rec in bundle.certificates:
            certs_out.append(_anon_cert(rec))
    for rec in agg.fallback_certificates:
        certs_out.append(_anon_cert(rec, from_os_store=True))
    return tokens_out, certs_out


def _anon_cert(rec: Any, *, from_os_store: bool = False) -> dict[str, Any]:
    cert = rec.cert
    # Cấu trúc Subject DN ẩn danh (OID/tên + hình dạng — KHÔNG nội dung).
    subject_structure = [
        {
            "oid": r.get("oid", ""),
            "name": _OID_NAME.get(r.get("oid", ""), r.get("oid", "")),
            "shape": _shape(r.get("value", "")),
            "length": len(r.get("value", "")),
        }
        for r in cert.subject_rdns
    ]
    sig_algo = _signature_algorithm(cert.der_b64)
    return {
        "issuer_dn": cert.issuer_raw,                       # Issuer = CA, không phải cá nhân
        "ca_name_from_chain": rec.ca.ca_name,               # ⭐ TỪ CHAIN (không regex)
        "chain_verified": rec.ca.chain_verified,
        "validation_status": rec.validation.status.value,
        "public_key_algo": cert.public_key_algo,
        "key_size": cert.key_size,
        "signature_algorithm": sig_algo,
        "subject_structure": subject_structure,
        "vn_id_types_present": sorted(cert.vn_ids.keys()),  # LOẠI id (không giá trị)
        "profile_confidence": cert.profile_confidence,
        "key_usage": cert.key_usage,
        "from_os_store": from_os_store,
        # ⭐ KHÔNG subject_raw, KHÔNG serial, KHÔNG DER, KHÔNG giá trị vn_ids.
    }


def _signature_algorithm(der_b64: str) -> str:
    if not der_b64:
        return ""
    try:
        import base64

        from cryptography import x509

        cert = x509.load_der_x509_certificate(base64.b64decode(der_b64))
        return cert.signature_algorithm_oid._name  # tên thuật toán ký (công khai)
    except Exception:  # noqa: BLE001
        return ""


def _atrs() -> list[str]:
    """ATR của thẻ đang cắm (định danh LOẠI thẻ, không định danh người dùng)."""
    try:
        from core.pcsc_probe import PCSCProbe

        probe = PCSCProbe()
        ready, _ = probe.readiness()
        if not ready:
            return []
        out = []
        for reader in probe.list_readers():
            atr = probe.read_atr(reader)
            if atr:
                out.append(atr.hex())
        return out
    except Exception:  # noqa: BLE001
        return []


def build_report() -> dict[str, Any]:
    tokens, certs = _tokens_and_certs()
    return {
        "report_version": 1,
        "kind": "vn-esign field intel (ẨN DANH)",
        "privacy_note": "KHÔNG chứa Subject DN nguyên văn/MST/CCCD/serial/DER/PIN. "
                        "Chỉ metadata thiết bị + cấu trúc profile đã ẩn danh.",
        "host": _host(),
        "modules": _modules(),
        "tokens": tokens,
        "certificates": certs,
        "atrs": _atrs(),
    }


# --------------------------------------------------------------------------- #
# Xác nhận + ghi                                                              #
# --------------------------------------------------------------------------- #
def _confirm(report: dict[str, Any], assume_yes: bool) -> bool:
    print("=" * 74)
    print("BÁO CÁO INTEL (ẨN DANH) — MỌI TRƯỜNG SẮP GHI:")
    print("=" * 74)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("=" * 74)
    print("⭐ KIỂM TRA QUYỀN RIÊNG TƯ trước khi ghi:")
    print("   • KHÔNG có Subject DN nguyên văn, MST/CCCD, serial, DER, PIN.")
    print("   • 'subject_structure' chỉ là HÌNH DẠNG (chữ→a, số→X).")
    print("   • 'label' token do người dùng đặt — hãy tự rà nếu chứa tên.")
    print("   • File chỉ ghi LOCAL; KHÔNG tự gửi đi đâu.")
    print("=" * 74)
    if assume_yes:
        print("--yes: bỏ qua hỏi (bạn tự chịu trách nhiệm rà soát).")
        return True
    try:
        ans = input("Ghi báo cáo này ra file? [y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes", "c", "co", "có")


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="python -m tools.harvest_intel")
    p.add_argument("--output", default="intel_report.json", help="File JSON đích (local).")
    p.add_argument("--yes", action="store_true", help="Bỏ qua hỏi xác nhận (tự chịu trách nhiệm).")
    args = p.parse_args(argv)

    report = build_report()
    if not _confirm(report, args.yes):
        print("Đã HUỶ — không ghi gì.")
        return 1

    out = Path(args.output)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        import os

        os.chmod(out, 0o600)  # chỉ chủ sở hữu đọc
    except OSError:
        pass
    print(f"✓ Đã ghi (chmod 600): {out.resolve()}")
    print("  Bạn có thể tự rà lại file rồi mới chia sẻ (nếu muốn) — công cụ KHÔNG tự gửi.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
