"""Phát hiện module PKCS#11 — HAI NHÁNH (Track A theo chip, Track B CA rebrand).

TRỤC 1 (MODULE): đây là "CÁCH nạp". Kết quả là danh sách :class:`ModuleCandidate`.

    * Track A — theo CHIP: tên file middleware của nhà sản xuất chip
      (eTPKCS11.dll, libcastle.so, WDPKCS.dll, aetpkss1.dll, opensc-pkcs11.so...).
    * Track B — CA REBRAND: module do một CA phát hành riêng, KHÔNG mang tên
      chip. Ví dụ ĐÃ XÁC NHẬN: ``/usr/lib/fptca_v4.so`` (gói dpkg fptca-4.0).
      Hệ thống chỉ quét Track A sẽ KHÔNG BAO GIỜ dò ra FPT-CA trên Linux.

Bảng dữ liệu ở ``data/vendor_intel.yaml`` (BIẾN ĐỘNG được, không hardcode trong
code). Module này HOÀN TOÀN OS-agnostic: mọi thứ đặc thù đi qua adapter.

LƯU Ý: ``chip_hint`` chỉ là gợi ý suy từ tên file — KHÔNG chuẩn xác, KHÔNG thay
cho TRỤC 2 (chip thật) hay TRỤC 3 (CA, xác định bằng chain building).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from core.config import load_vendor_intel
from core.models import ModuleCandidate, ModuleTrack
from core.platform import BinaryArch, PlatformAdapter, get_adapter


def _names_for(entry: dict[str, Any], os_name: str) -> list[str]:
    """Danh sách tên file cho OS từ một mục vendor_intel."""
    value = entry.get(os_name) or []
    return [str(v) for v in value] if isinstance(value, list) else []


def _abs_paths_for(entry: dict[str, Any], os_name: str) -> list[str]:
    """Danh sách đường dẫn TUYỆT ĐỐI cho OS (khoá ``<os>_paths``)."""
    value = entry.get(f"{os_name}_paths") or []
    return [str(v) for v in value] if isinstance(value, list) else []


def _extra_dirs_for(entry: dict[str, Any], os_name: str) -> list[Path]:
    dirs = entry.get("extra_dirs") or {}
    if isinstance(dirs, dict):
        vals = dirs.get(os_name) or []
        if isinstance(vals, list):
            return [Path(str(v)) for v in vals]
    return []


class _Collector:
    """Gom ứng viên, khử trùng lặp theo realpath, gắn metadata."""

    def __init__(self, adapter: PlatformAdapter) -> None:
        self.adapter = adapter
        self.os_name = adapter.name()
        self._by_path: dict[Path, ModuleCandidate] = {}

    def add(
        self,
        raw: Path,
        *,
        track: ModuleTrack,
        chip_hint: str,
        source: str,
        confidence: float,
    ) -> None:
        try:
            resolved = Path(raw).resolve()
        except OSError:
            return
        if not resolved.is_file():
            return
        if resolved in self._by_path:
            # Ưu tiên confidence cao hơn / chip_hint cụ thể hơn.
            existing = self._by_path[resolved]
            if confidence > existing.confidence:
                existing.confidence = confidence
            if not existing.chip_hint and chip_hint:
                existing.chip_hint = chip_hint
            return
        self._by_path[resolved] = ModuleCandidate(
            path=str(resolved),
            track=track,
            chip_hint=chip_hint,
            source=source,
            confidence=confidence,
        )

    def finalize(self) -> list[ModuleCandidate]:
        """Gắn arch / needs_arch_bridge / validated / warnings và sắp xếp."""
        for cand in self._by_path.values():
            path = Path(cand.path)
            try:
                arch = self.adapter.check_binary_arch(path)
            except OSError:
                arch = BinaryArch.UNKNOWN
            cand.arch = arch.value
            try:
                cand.needs_arch_bridge = self.adapter.needs_arch_bridge(path)
            except (OSError, NotImplementedError):
                cand.needs_arch_bridge = False
            cand.warnings = list(self.adapter.library_warnings(path))
            cand.validated = arch is not BinaryArch.UNKNOWN
        # Track A trước Track B, trong mỗi nhóm xếp theo confidence giảm dần.
        return sorted(
            self._by_path.values(),
            key=lambda c: (c.track is ModuleTrack.B_CA_REBRAND, -c.confidence),
        )


def _known_name_index(intel: dict[str, Any], os_name: str) -> dict[str, tuple[ModuleTrack, str]]:
    """Map tên_file(lower) -> (track, chip_hint) để phân loại file rời rạc."""
    index: dict[str, tuple[ModuleTrack, str]] = {}
    for entry in intel.get("track_a") or []:
        for name in _names_for(entry, os_name):
            index[name.lower()] = (ModuleTrack.A_CHIP, str(entry.get("vendor", "")))
    for entry in intel.get("track_b") or []:
        hint = str(entry.get("ca_hint", ""))
        for name in _names_for(entry, os_name):
            index[name.lower()] = (ModuleTrack.B_CA_REBRAND, hint)
        for ap in _abs_paths_for(entry, os_name):
            index[Path(ap).name.lower()] = (ModuleTrack.B_CA_REBRAND, hint)
    return index


def discover_modules(adapter: PlatformAdapter | None = None) -> list[ModuleCandidate]:
    """Quét & trả danh sách :class:`ModuleCandidate` (Track A + Track B).

    Kết hợp: bảng vendor_intel (theo tên/đường dẫn) × đường dẫn tìm kiếm của
    adapter, cộng thư viện do hệ thống đăng ký và người dùng khai báo thêm.
    """
    ad = adapter or get_adapter()
    os_name = ad.name()
    intel = load_vendor_intel()
    collector = _Collector(ad)

    search_dirs = [d for d in ad.library_search_paths() if d.is_dir()]

    # --- Track A: theo chip (tên file trong các thư mục tìm kiếm) --------- #
    for entry in intel.get("track_a") or []:
        vendor = str(entry.get("vendor", ""))
        names = _names_for(entry, os_name)
        dirs = [*search_dirs, *(d for d in _extra_dirs_for(entry, os_name) if d.is_dir())]
        for directory in dirs:
            for name in names:
                collector.add(
                    directory / name,
                    track=ModuleTrack.A_CHIP,
                    chip_hint=vendor,
                    source="vendor_intel",
                    confidence=0.9,
                )

    # --- Track B: CA rebrand (đường dẫn tuyệt đối + tên trong search dirs) - #
    for entry in intel.get("track_b") or []:
        hint = str(entry.get("ca_hint", ""))
        for ap in _abs_paths_for(entry, os_name):
            collector.add(
                Path(ap),
                track=ModuleTrack.B_CA_REBRAND,
                chip_hint=hint,
                source="vendor_intel",
                confidence=0.95,
            )
        names = _names_for(entry, os_name)
        for directory in search_dirs:
            for name in names:
                collector.add(
                    directory / name,
                    track=ModuleTrack.B_CA_REBRAND,
                    chip_hint=hint,
                    source="vendor_intel",
                    confidence=0.9,
                )

    # --- Module do hệ thống đăng ký / người dùng khai báo ---------------- #
    name_index = _known_name_index(intel, os_name)
    for sys_path in ad.discover_from_system():
        track, hint = name_index.get(sys_path.name.lower(), (ModuleTrack.A_CHIP, ""))
        collector.add(sys_path, track=track, chip_hint=hint, source="system", confidence=0.7)
    for user_path in ad.discover_from_user_config():
        track, hint = name_index.get(user_path.name.lower(), (ModuleTrack.A_CHIP, ""))
        collector.add(
            user_path, track=track, chip_hint=hint, source="user_config", confidence=0.8
        )

    return collector.finalize()


__all__ = ["discover_modules"]
