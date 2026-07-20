"""Phát hiện module PKCS#11 — CHUNG 3 OS. Đặc thù đi qua PlatformAdapter.

TRIẾT LÝ: HỎI HỆ ĐIỀU HÀNH, ĐỪNG ĐOÁN TÊN FILE.

:func:`discover` chạy 4 TẦNG theo ưu tiên, gộp & khử trùng lặp theo realpath:

    TẦNG 1  adapter.discover_from_system()      (confirmed) — dpkg/rpm/Registry/apps
    TẦNG 2  adapter.discover_from_user_config() (confirmed) — p11-kit, NSS
    TẦNG 3  vendor_intel.yaml theo OS (Track A/B) — entry hypothesis KHÔNG quét
            bằng tên file (tên là đoán), chỉ cấp glob_hints cho Tầng 4.
    TẦNG 4  GLOB RỘNG + XÁC THỰC C_GetInfo trong TIẾN TRÌNH CON CÔ LẬP.
            Module rác/hỏng không được làm sập daemon -> validate qua subprocess.
            cryptokiVersion hợp lệ -> nhận (confirmed); không -> loại. Đây là cơ
            chế TỰ PHÁT HIỆN module Track B của 25 CA chưa biết tên file.

Sau 4 tầng, mỗi :class:`ModuleCandidate`: check_binary_arch -> needs_arch_bridge
(ĐÁNH CỜ, KHÔNG loại) -> Linux ldd ghi dependency thiếu.

CLI: ``python -m core.discovery --scan --verbose``.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel

from core.errors import BridgeUnavailableError
from core.intel import IntelDatabase, IntelEntry, load_intel
from core.models import ErrorCode, ErrorInfo, ModuleCandidate, ModuleTrack
from core.platform import BinaryArch, PlatformAdapter, get_adapter

_TRACK_MAP = {"A": ModuleTrack.A_CHIP, "B": ModuleTrack.B_CA_REBRAND}

# Giới hạn số file được XÁC THỰC ở Tầng 4 (mỗi lần validate là một subprocess).
MAX_PROBE = 80
# TTL cache mặc định (giây).
DEFAULT_CACHE_TTL = 300.0


# --------------------------------------------------------------------------- #
# Kết quả xác thực module (Tầng 4)                                             #
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class ProbeResult:
    ok: bool = False
    cryptoki_version: tuple[int, int] | None = None
    manufacturer: str = ""
    library_description: str = ""
    token_slots: int = 0
    error: str = ""

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> ProbeResult:
        cver = raw.get("cryptoki_version")
        version = (int(cver[0]), int(cver[1])) if isinstance(cver, list | tuple) and len(cver) >= 2 else None
        return cls(
            ok=bool(raw.get("ok")),
            cryptoki_version=version,
            manufacturer=str(raw.get("manufacturer", "")),
            library_description=str(raw.get("library_description", "")),
            token_slots=int(raw.get("token_slots", 0) or 0),
            error=str(raw.get("error", "")),
        )


class ModuleValidator(Protocol):
    """Giao diện xác thực module (cho phép tiêm bản giả khi test)."""

    def validate(self, path: Path, needs_bridge: bool) -> ProbeResult: ...
    def close(self) -> None: ...


class SubprocessValidator:
    """Xác thực C_GetInfo qua bridge helper (tiến trình con cô lập).

    Cùng arch -> tái dùng MỘT helper local (spawn lại nếu nó chết vì module rác).
    Lệch arch -> spawn helper đúng arch qua adapter (Rosetta/qemu), đóng sau mỗi lần.
    """

    def __init__(self, adapter: PlatformAdapter, *, timeout: float = 15.0) -> None:
        self.adapter = adapter
        self.timeout = timeout
        self._local: Any = None

    def validate(self, path: Path, needs_bridge: bool) -> ProbeResult:
        try:
            if needs_bridge:
                client = self.adapter.spawn_bridge_helper(path)
                try:
                    raw = client.validate_module(str(path), timeout=self.timeout)
                finally:
                    client.close()
            else:
                raw = self._local_client().validate_module(str(path), timeout=self.timeout)
            return ProbeResult.from_raw(raw)
        except BridgeUnavailableError as exc:
            return ProbeResult(ok=False, error=str(exc))
        except Exception as exc:  # noqa: BLE001 - helper có thể đã chết -> reset
            self._reset_local()
            return ProbeResult(ok=False, error=str(exc))

    def _local_client(self) -> Any:
        if self._local is None:
            from core.bridge.client import BridgeClient

            self._local = BridgeClient(
                [sys.executable, "-m", "core.bridge.helper"],
                cwd=str(_repo_root()),
                name="probe-local",
            )
        return self._local

    def _reset_local(self) -> None:
        if self._local is not None:
            try:
                self._local.close()
            except Exception:  # noqa: BLE001
                pass
            self._local = None

    def close(self) -> None:
        self._reset_local()


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# Kết quả discovery                                                            #
# --------------------------------------------------------------------------- #
class DiscoveryResult(BaseModel):
    modules: list[ModuleCandidate] = []
    diagnostics: list[ErrorInfo] = []  # chỉ khi KHÔNG ra module
    tiers_run: list[int] = []
    used_p11kit_shortcut: bool = False
    probe_capped: int = 0
    from_cache: bool = False


# --------------------------------------------------------------------------- #
# Gom & khử trùng lặp                                                          #
# --------------------------------------------------------------------------- #
class _Collector:
    def __init__(self, adapter: PlatformAdapter) -> None:
        self.adapter = adapter
        self._by_path: dict[Path, ModuleCandidate] = {}

    def paths(self) -> set[Path]:
        return set(self._by_path.keys())

    def add(
        self,
        raw: Path,
        *,
        track: ModuleTrack,
        chip_hint: str,
        source: str,
        confidence: float,
        tier: int,
        confidence_label: str,
        validated: bool = False,
        warnings: tuple[str, ...] = (),
    ) -> None:
        try:
            resolved = Path(raw).resolve()
        except OSError:
            return
        if not resolved.is_file():
            return
        existing = self._by_path.get(resolved)
        if existing is not None:
            # Tầng nhỏ hơn = ưu tiên cao hơn (nguồn xác thực hơn).
            if tier and (existing.tier == 0 or tier < existing.tier):
                existing.tier = tier
                existing.source = source
                existing.confidence_label = confidence_label
                existing.track = track
            if confidence > existing.confidence:
                existing.confidence = confidence
            if not existing.chip_hint and chip_hint:
                existing.chip_hint = chip_hint
            existing.validated = existing.validated or validated
            for w in warnings:
                if w and w not in existing.warnings:
                    existing.warnings.append(w)
            return
        self._by_path[resolved] = ModuleCandidate(
            path=str(resolved),
            track=track,
            chip_hint=chip_hint,
            source=source,
            tier=tier,
            confidence=confidence,
            confidence_label=confidence_label,
            validated=validated,
            warnings=[w for w in warnings if w],
        )

    def finalize(self) -> list[ModuleCandidate]:
        for cand in self._by_path.values():
            path = Path(cand.path)
            try:
                arch = self.adapter.check_binary_arch(path)
            except OSError:
                arch = BinaryArch.UNKNOWN
            cand.arch = arch.value
            try:
                cand.needs_arch_bridge = self.adapter.needs_arch_bridge(path)  # ĐÁNH CỜ
            except (OSError, NotImplementedError):
                cand.needs_arch_bridge = False
            for w in self.adapter.library_warnings(path):  # Linux: ldd deps thiếu
                if w not in cand.warnings:
                    cand.warnings.append(w)
            if arch is not BinaryArch.UNKNOWN:
                cand.validated = cand.validated or True
        return sorted(
            self._by_path.values(),
            key=lambda c: (c.tier or 9, c.track is ModuleTrack.B_CA_REBRAND, -c.confidence),
        )


# --------------------------------------------------------------------------- #
# Helper tầng                                                                  #
# --------------------------------------------------------------------------- #
def _dirs_for(
    adapter: PlatformAdapter, db: IntelDatabase, os_name: str, entry: IntelEntry
) -> list[Path]:
    raw = [
        *adapter.library_search_paths(),
        *(Path(p) for p in db.search_paths_for(os_name)),
        *(Path(p) for p in entry.search_paths),
    ]
    seen: dict[Path, None] = {}
    for p in raw:
        seen.setdefault(p, None)
    return [p for p in seen if p.is_dir()]


def _classify_add(
    collector: _Collector,
    db: IntelDatabase,
    os_name: str,
    path: Path,
    *,
    tier: int,
    source: str,
    confidence: float,
) -> None:
    """Thêm file từ Tầng 1/2 — phân loại track/hint theo bảng vàng."""
    track_s, hint = db.name_index(os_name).get(path.name.lower(), ("A", ""))
    collector.add(
        path, track=_TRACK_MAP[track_s], chip_hint=hint, source=source,
        confidence=confidence, tier=tier, confidence_label="confirmed",
    )


def _tier4_patterns(adapter: PlatformAdapter, db: IntelDatabase, os_name: str) -> list[str]:
    """Ghép glob_hints (ca/token/pkcs...) với đuôi file đúng OS của adapter."""
    hints = db.glob_hints_for(os_name)
    exts = [p[1:] if p.startswith("*") else p for p in adapter.glob_patterns()]  # ".so",".dll"...
    if not hints:
        return list(adapter.glob_patterns())
    stems = {h.rsplit(".", 1)[0] if "." in h else h for h in hints}
    patterns = [f"{stem}{ext}" for stem in stems for ext in exts]
    # Khử trùng lặp giữ thứ tự.
    seen: dict[str, None] = {}
    for p in patterns:
        seen.setdefault(p, None)
    return list(seen)


def _glob_candidates(
    adapter: PlatformAdapter, db: IntelDatabase, os_name: str, existing: set[Path]
) -> list[Path]:
    patterns = _tier4_patterns(adapter, db, os_name)
    dirs = [
        *adapter.library_search_paths(),
        *(Path(p) for p in db.search_paths_for(os_name)),
    ]
    out: list[Path] = []
    seen: set[Path] = set(existing)
    for directory in dirs:
        if not directory.is_dir():
            continue
        for pattern in patterns:
            for hit in directory.glob(pattern):
                if not hit.is_file():
                    continue
                try:
                    resolved = hit.resolve()
                except OSError:
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                out.append(resolved)
    return out


def _find_proxy(collector: _Collector) -> ModuleCandidate | None:
    for cand in collector._by_path.values():
        if "p11-kit-proxy" in Path(cand.path).name:
            return cand
    return None


# --------------------------------------------------------------------------- #
# API chính                                                                    #
# --------------------------------------------------------------------------- #
def discover(
    adapter: PlatformAdapter | None = None,
    *,
    force_scan: bool = False,
    deep: bool = True,
    validator: ModuleValidator | None = None,
    use_cache: bool = False,
    cache_ttl: float = DEFAULT_CACHE_TTL,
) -> DiscoveryResult:
    """Chạy 4 tầng phát hiện module, trả :class:`DiscoveryResult`."""
    ad = adapter or get_adapter()
    os_name = ad.name()

    if use_cache and not force_scan:
        cached = _read_cache(ad, cache_ttl)
        if cached is not None:
            cached.from_cache = True
            return cached

    db = load_intel()
    collector = _Collector(ad)
    tiers_run: list[int] = []

    # TẦNG 1 — hệ điều hành (chính xác nhất)
    tiers_run.append(1)
    for p in ad.discover_from_system():
        _classify_add(collector, db, os_name, p, tier=1, source="system", confidence=0.98)

    # TẦNG 2 — cấu hình người dùng / p11-kit / NSS
    tiers_run.append(2)
    for p in ad.discover_from_user_config():
        _classify_add(collector, db, os_name, p, tier=2, source="user_config", confidence=0.98)

    # TẦNG 3 — vendor_intel (chỉ entry CÓ filenames; hypothesis để Tầng 4)
    tiers_run.append(3)
    for entry in db.filter(os_name=os_name):
        if not entry.filenames:
            continue
        track = _TRACK_MAP[entry.track]
        warns = (entry.arch_warning,) if entry.arch_warning else ()
        for directory in _dirs_for(ad, db, os_name, entry):
            for fn in entry.filenames:
                collector.add(
                    directory / fn, track=track, chip_hint=entry.display_hint,
                    source="vendor_intel", confidence=entry.confidence_score, tier=3,
                    confidence_label=entry.confidence, warnings=warns,
                )

    # TẦNG 4 — glob rộng + xác thực C_GetInfo (tiến trình con cô lập)
    used_shortcut = False
    probe_capped = 0
    val = validator or SubprocessValidator(ad)
    try:
        # Tối ưu p11-kit-proxy: ra token thì có thể bỏ dò thủ công (trừ --force-scan).
        # Chỉ chạy ở chế độ deep (Tầng 4) — đường nhanh không spawn subprocess.
        if deep and os_name in ("linux", "macos") and not force_scan:
            proxy = _find_proxy(collector)
            if proxy is not None:
                pr = val.validate(Path(proxy.path), proxy.needs_arch_bridge)
                if pr.ok and pr.token_slots > 0:
                    used_shortcut = True

        if deep and not (used_shortcut and not force_scan):
            tiers_run.append(4)
            candidates = _glob_candidates(ad, db, os_name, collector.paths())
            probe_capped = max(0, len(candidates) - MAX_PROBE)
            for path in candidates[:MAX_PROBE]:
                needs_bridge = _safe_needs_bridge(ad, path)
                pr = val.validate(path, needs_bridge)
                if pr.ok and pr.cryptoki_version is not None:
                    note = (
                        f"Xác thực C_GetInfo: Cryptoki v{pr.cryptoki_version[0]}."
                        f"{pr.cryptoki_version[1]}"
                        + (f", {pr.manufacturer}" if pr.manufacturer else "")
                    )
                    collector.add(
                        path, track=ModuleTrack.B_CA_REBRAND, chip_hint="",
                        source="glob_probe", confidence=0.95, tier=4,
                        confidence_label="confirmed", validated=True, warnings=(note,),
                    )
    finally:
        val.close()

    modules = collector.finalize()
    diagnostics = diagnose_no_modules(ad) if not modules else []
    result = DiscoveryResult(
        modules=modules,
        diagnostics=diagnostics,
        tiers_run=tiers_run,
        used_p11kit_shortcut=used_shortcut,
        probe_capped=probe_capped,
    )
    if use_cache:
        _write_cache(ad, result)
    return result


def discover_modules(adapter: PlatformAdapter | None = None) -> list[ModuleCandidate]:
    """API NHANH (Tầng 1-3, KHÔNG spawn subprocess) — cho service/web.

    Tầng 4 (glob + C_GetInfo) chỉ chạy khi gọi :func:`discover` (vd. CLI --scan).
    """
    return discover(adapter, deep=False, use_cache=False).modules


def _safe_needs_bridge(adapter: PlatformAdapter, path: Path) -> bool:
    try:
        return adapter.needs_arch_bridge(path)
    except (OSError, NotImplementedError):
        return False


# --------------------------------------------------------------------------- #
# Chẩn đoán thông minh (theo thứ tự xác suất)                                   #
# --------------------------------------------------------------------------- #
def diagnose_no_modules(adapter: PlatformAdapter) -> list[ErrorInfo]:
    """Khi KHÔNG ra module, giải thích nguyên nhân theo thứ tự xác suất (a-f)."""
    name = adapter.name()
    diags: list[ErrorInfo] = []

    # (a) Lệch kiến trúc.
    diags.append(ErrorInfo(
        code=ErrorCode.ARCH_MISMATCH,
        message_vi="Có thể module tồn tại nhưng LỆCH KIẾN TRÚC với host nên không "
                   "nạp/xác thực được (Win 32/64 · mac arm64/x86_64 · Linux ELF32/64).",
        remediation=adapter.arch_bridge_hint(),
        platform=name,  # type: ignore[arg-type]
    ))
    # (b) Chưa cài middleware CA.
    diags.append(ErrorInfo(
        code=ErrorCode.NO_MODULE_FOUND,
        message_vi="Chưa tìm thấy module PKCS#11 nào của middleware/CA.",
        remediation="Cài phần mềm token/middleware đi kèm USB token của CA (hoặc gói "
                    "CA rebrand, vd. fptca-4.0). Có thể nạp thủ công qua VN_ESIGN_EXTRA_MODULES.",
        platform=name,  # type: ignore[arg-type]
    ))
    # (c) PC/SC chưa sẵn sàng.
    ready, remediation = adapter.pcsc_backend_ready()
    if not ready:
        diags.append(ErrorInfo(
            code=ErrorCode.PCSC_NOT_READY,
            message_vi="Tầng PC/SC chưa sẵn sàng (không giao tiếp được reader/token).",
            remediation=remediation, platform=name,  # type: ignore[arg-type]
        ))
    # (d)+(e) Ghi chú riêng OS (Linux udev/plugdev · macOS Rosetta/quarantine/LibVal).
    for note in adapter.platform_notes():
        diags.append(ErrorInfo(
            code=ErrorCode.INTERNAL_ERROR, message_vi="Ghi chú nền tảng.",
            remediation=note, platform=name,  # type: ignore[arg-type]
        ))
    # (f) Chứng thư private -> cần login.
    diags.append(ErrorInfo(
        code=ErrorCode.LOGIN_REQUIRED,
        message_vi="Nếu module có nhưng không thấy chứng thư, có thể chứng thư ở dạng "
                   "PRIVATE — chỉ lộ ra sau khi đăng nhập PIN.",
        remediation="Đăng nhập token bằng PIN (chức năng này ở giai đoạn sau).",
        platform=name,  # type: ignore[arg-type]
    ))
    return diags


# --------------------------------------------------------------------------- #
# Cache (config_dir + TTL)                                                     #
# --------------------------------------------------------------------------- #
def _cache_path(adapter: PlatformAdapter) -> Path:
    return adapter.config_dir() / "discovery_cache.json"


def _host_key(adapter: PlatformAdapter) -> str:
    a = adapter.host_arch()
    return f"{adapter.name()}-{a['machine']}-{a['bits']}"


def _read_cache(adapter: PlatformAdapter, ttl: float) -> DiscoveryResult | None:
    path = _cache_path(adapter)
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if blob.get("host") != _host_key(adapter):
        return None
    ts = blob.get("ts", 0)
    now = datetime.now(timezone.utc).timestamp()
    if now - float(ts) > ttl:
        return None
    try:
        return DiscoveryResult.model_validate(blob.get("result", {}))
    except Exception:  # noqa: BLE001
        return None


def _write_cache(adapter: PlatformAdapter, result: DiscoveryResult) -> None:
    path = _cache_path(adapter)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        blob = {
            "ts": datetime.now(timezone.utc).timestamp(),
            "host": _host_key(adapter),
            "result": result.model_dump(mode="json"),
        }
        path.write_text(json.dumps(blob, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# CLI: python -m core.discovery --scan --verbose                              #
# --------------------------------------------------------------------------- #
def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m core.discovery")
    parser.add_argument("--scan", action="store_true", help="Quét 4 tầng (mặc định).")
    parser.add_argument("--verbose", action="store_true", help="In cảnh báo + chẩn đoán.")
    parser.add_argument("--force-scan", action="store_true", help="Bỏ tối ưu p11-kit + bỏ cache.")
    parser.add_argument("--no-deep", action="store_true", help="Bỏ Tầng 4 (không subprocess).")
    parser.add_argument("--no-cache", action="store_true", help="Không dùng cache.")
    args = parser.parse_args(argv)

    result = discover(
        force_scan=args.force_scan,
        deep=not args.no_deep,
        use_cache=not (args.no_cache or args.force_scan),
    )

    tiers = "+".join(str(t) for t in result.tiers_run)
    print(f"Module PKCS#11 phát hiện: {len(result.modules)} "
          f"(tầng {tiers}{' · cache' if result.from_cache else ''}"
          f"{' · p11-kit shortcut' if result.used_p11kit_shortcut else ''})")
    if result.probe_capped:
        print(f"⚠️  Tầng 4 đã giới hạn: bỏ qua {result.probe_capped} file vượt ngưỡng {MAX_PROBE}.")

    print("-" * 78)
    for m in result.modules:
        flag = " ⚠️LỆCH-ARCH" if m.needs_arch_bridge else ""
        print(f"  • [T{m.tier}/{m.confidence_label or '?'}] Track {m.track.value} · "
              f"{m.chip_hint or '(chưa rõ)'} · {m.arch}{flag}")
        print(f"      {m.path}  (nguồn={m.source}, tin cậy={m.confidence:.2f})")
        if args.verbose:
            for w in m.warnings:
                for line in w.splitlines():
                    print(f"        ⚠ {line}")

    if not result.modules and result.diagnostics:
        print("\nCHẨN ĐOÁN (theo thứ tự xác suất):")
        for i, d in enumerate(result.diagnostics, 1):
            print(f"  {i}. [{d.code.value}] {d.message_vi}")
            if args.verbose and d.remediation:
                for line in d.remediation.splitlines():
                    print(f"       {line}")

    return 0 if result.modules else 1


if __name__ == "__main__":
    sys.exit(_main())


__all__ = [
    "discover",
    "discover_modules",
    "diagnose_no_modules",
    "DiscoveryResult",
    "ProbeResult",
    "SubprocessValidator",
    "ModuleValidator",
]
