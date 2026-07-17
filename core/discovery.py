"""Phát hiện module PKCS#11 — HAI NHÁNH (Track A theo chip, Track B CA rebrand).

TRỤC 1 (MODULE): "CÁCH nạp". Kết quả là danh sách :class:`ModuleCandidate`.

Dữ liệu đến TỪ BẢNG VÀNG (``core/intel.py`` đọc ``data/vendor_intel.yaml``) — code
này KHÔNG nhúng tên file. Module HOÀN TOÀN OS-agnostic: mọi thứ đặc thù đi qua
adapter.

Lưu ý pháp lý: entry ``hypothesis`` (25 CA chưa biết tên file) có ``filenames``
rỗng nên KHÔNG được dò theo tên ở đây — chúng để dành cho Tầng 4 (glob +
C_GetInfo). ``chip_hint``/``ca_hint`` chỉ là GỢI Ý, không thay TRỤC 2 (chip
thật) hay TRỤC 3 (CA, xác định bằng chain building).
"""

from __future__ import annotations

from pathlib import Path

from core.intel import IntelDatabase, IntelEntry, load_intel
from core.models import ModuleCandidate, ModuleTrack
from core.platform import BinaryArch, PlatformAdapter, get_adapter

_TRACK_MAP = {"A": ModuleTrack.A_CHIP, "B": ModuleTrack.B_CA_REBRAND}


class _Collector:
    """Gom ứng viên, khử trùng lặp theo realpath, gắn metadata."""

    def __init__(self, adapter: PlatformAdapter) -> None:
        self.adapter = adapter
        self._by_path: dict[Path, ModuleCandidate] = {}

    def add(
        self,
        raw: Path,
        *,
        track: ModuleTrack,
        chip_hint: str,
        source: str,
        confidence: float,
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
            if confidence > existing.confidence:
                existing.confidence = confidence
            if not existing.chip_hint and chip_hint:
                existing.chip_hint = chip_hint
            for w in warnings:
                if w and w not in existing.warnings:
                    existing.warnings.append(w)
            return
        self._by_path[resolved] = ModuleCandidate(
            path=str(resolved),
            track=track,
            chip_hint=chip_hint,
            source=source,
            confidence=confidence,
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
                cand.needs_arch_bridge = self.adapter.needs_arch_bridge(path)
            except (OSError, NotImplementedError):
                cand.needs_arch_bridge = False
            for w in self.adapter.library_warnings(path):
                if w not in cand.warnings:
                    cand.warnings.append(w)
            cand.validated = arch is not BinaryArch.UNKNOWN
        # Track A trước Track B; trong nhóm xếp theo confidence giảm dần.
        return sorted(
            self._by_path.values(),
            key=lambda c: (c.track is ModuleTrack.B_CA_REBRAND, -c.confidence),
        )


def _dirs_for(
    adapter: PlatformAdapter, db: IntelDatabase, os_name: str, entry: IntelEntry
) -> list[Path]:
    """Gộp thư mục tìm kiếm: adapter + mặc định bảng vàng + đặc thù entry."""
    raw = [
        *adapter.library_search_paths(),
        *(Path(p) for p in db.search_paths_for(os_name)),
        *(Path(p) for p in entry.search_paths),
    ]
    seen: dict[Path, None] = {}
    for p in raw:
        seen.setdefault(p, None)
    return [p for p in seen if p.is_dir()]


def discover_modules(adapter: PlatformAdapter | None = None) -> list[ModuleCandidate]:
    """Quét & trả danh sách :class:`ModuleCandidate` (Track A + Track B).

    Chỉ dò các entry CÓ ``filenames`` (confirmed/documented). Entry hypothesis
    (filenames rỗng) được bỏ qua ở đây — dành cho Tầng 4.
    """
    ad = adapter or get_adapter()
    os_name = ad.name()
    db = load_intel()
    collector = _Collector(ad)

    for entry in db.filter(os_name=os_name):
        if not entry.filenames:
            continue  # hypothesis / chưa xác nhận tên -> để Tầng 4
        track = _TRACK_MAP[entry.track]
        warns = (entry.arch_warning,) if entry.arch_warning else ()
        for directory in _dirs_for(ad, db, os_name, entry):
            for filename in entry.filenames:
                collector.add(
                    directory / filename,
                    track=track,
                    chip_hint=entry.display_hint,
                    source="vendor_intel",
                    confidence=entry.confidence_score,
                    warnings=warns,
                )

    # Module do hệ thống đăng ký / người dùng khai báo -> phân loại theo tên.
    name_index = db.name_index(os_name)
    for sys_path in ad.discover_from_system():
        track_s, hint = name_index.get(sys_path.name.lower(), ("A", ""))
        collector.add(
            sys_path, track=_TRACK_MAP[track_s], chip_hint=hint,
            source="system", confidence=0.7,
        )
    for user_path in ad.discover_from_user_config():
        track_s, hint = name_index.get(user_path.name.lower(), ("A", ""))
        collector.add(
            user_path, track=_TRACK_MAP[track_s], chip_hint=hint,
            source="user_config", confidence=0.8,
        )

    return collector.finalize()


__all__ = ["discover_modules"]
