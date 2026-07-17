"""Loader BẢNG VÀNG (vendor_intel.yaml) — nạp + validate schema + index.

Bảng vàng TÁCH KHỎI CODE: module này chỉ ĐỌC dữ liệu, không nhúng tri thức nhà
cung cấp. Hỗ trợ ghi đè theo thứ tự ưu tiên:
    1. File cơ sở         : ``data/vendor_intel.yaml``
    2. File người dùng    : ``<config_dir>/vendor_intel.yaml``
    3. Biến môi trường    : ``VN_TOKEN_INTEL_FILE`` (ưu tiên cao nhất)
Ghi đè theo ``id``: entry cùng id ở tầng sau thay entry tầng trước; id mới được
thêm vào.

OS-agnostic: không rẽ nhánh theo hệ điều hành; ``config_dir`` lấy qua adapter.

CLI: ``python -m core.intel --list --os linux --track B``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml

from core.config import vendor_intel_path

ENV_INTEL_FILE = "VN_TOKEN_INTEL_FILE"

TrackT = Literal["A", "B"]
OSValue = Literal["windows", "macos", "linux", "any"]
ConfidenceT = Literal["confirmed", "documented", "hypothesis"]

_VALID_OS = {"windows", "macos", "linux", "any"}
_VALID_TRACK = {"A", "B"}
_VALID_CONFIDENCE = {"confirmed", "documented", "hypothesis"}

# Xếp hạng độ tin cậy -> điểm số [0..1] cho tầng discovery.
_CONFIDENCE_SCORE = {"confirmed": 0.98, "documented": 0.9, "hypothesis": 0.3}


@dataclass(frozen=True, slots=True)
class IntelEntry:
    """Một mục bảng vàng (đã validate)."""

    id: str
    track: TrackT
    os: OSValue
    chip_vendor: str = ""
    ca_hint: str = ""
    filenames: tuple[str, ...] = ()
    search_paths: tuple[str, ...] = ()
    glob_hints: tuple[str, ...] = ()
    package_name: str = ""
    confidence: ConfidenceT = "hypothesis"
    evidence: str = ""
    arch_warning: str = ""

    @property
    def confidence_score(self) -> float:
        return _CONFIDENCE_SCORE.get(self.confidence, 0.3)

    @property
    def display_hint(self) -> str:
        """Gợi ý hiển thị: chip_vendor (track A) hoặc ca_hint (track B)."""
        return self.chip_vendor if self.track == "A" else self.ca_hint


@dataclass(slots=True)
class IntelDatabase:
    """Bảng vàng đã nạp + chỉ mục truy vấn."""

    entries: list[IntelEntry] = field(default_factory=list)
    default_search_paths: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    # -- Truy vấn / index ---------------------------------------------- #
    def filter(
        self,
        *,
        os_name: str | None = None,
        track: str | None = None,
        confidence: str | None = None,
    ) -> list[IntelEntry]:
        """Lọc entry theo os (kèm 'any'), track, confidence."""
        result = []
        for e in self.entries:
            if os_name is not None and e.os != os_name and e.os != "any":
                continue
            if track is not None and e.track != track:
                continue
            if confidence is not None and e.confidence != confidence:
                continue
            result.append(e)
        return result

    def search_paths_for(self, os_name: str) -> list[str]:
        """Đường dẫn tìm kiếm mặc định cho OS (từ bảng vàng)."""
        return list(self.default_search_paths.get(os_name, []))

    def name_index(self, os_name: str) -> dict[str, tuple[str, str]]:
        """Map tên_file(lower) -> (track, hint) cho OS này (để phân loại file rời)."""
        index: dict[str, tuple[str, str]] = {}
        for e in self.filter(os_name=os_name):
            for fn in e.filenames:
                index[fn.lower()] = (e.track, e.display_hint)
        return index

    def glob_hints_for(self, os_name: str) -> list[str]:
        """Gom mọi glob_hints áp dụng cho OS (dùng cho Tầng 4)."""
        hints: list[str] = []
        for e in self.filter(os_name=os_name):
            for g in e.glob_hints:
                if g not in hints:
                    hints.append(g)
        return hints


# --------------------------------------------------------------------------- #
# Parse & validate                                                             #
# --------------------------------------------------------------------------- #
def _as_str_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(v) for v in value)
    return ()


def _parse_entry(raw: dict[str, Any]) -> tuple[IntelEntry | None, str | None]:
    """Validate một entry thô -> (IntelEntry, None) hoặc (None, lỗi)."""
    eid = str(raw.get("id", "")).strip()
    if not eid:
        return None, "entry thiếu 'id'"
    track = str(raw.get("track", "")).strip()
    if track not in _VALID_TRACK:
        return None, f"[{eid}] track không hợp lệ: {track!r} (cần A|B)"
    os_value = str(raw.get("os", "any")).strip()
    if os_value not in _VALID_OS:
        return None, f"[{eid}] os không hợp lệ: {os_value!r}"
    confidence = str(raw.get("confidence", "hypothesis")).strip()
    if confidence not in _VALID_CONFIDENCE:
        return None, f"[{eid}] confidence không hợp lệ: {confidence!r}"

    chip_vendor = str(raw.get("chip_vendor", "")).strip()
    ca_hint = str(raw.get("ca_hint", "")).strip()
    if track == "A" and not chip_vendor:
        return None, f"[{eid}] track A cần 'chip_vendor'"
    if track == "B" and not ca_hint:
        return None, f"[{eid}] track B cần 'ca_hint'"

    filenames = _as_str_tuple(raw.get("filenames"))
    # Bất biến an toàn: hypothesis KHÔNG được có filenames (chống đoán mò).
    if confidence == "hypothesis" and filenames:
        return None, f"[{eid}] confidence=hypothesis nhưng có filenames (cấm đoán tên file)"

    return (
        IntelEntry(
            id=eid,
            track=track,  # type: ignore[arg-type]
            os=os_value,  # type: ignore[arg-type]
            chip_vendor=chip_vendor,
            ca_hint=ca_hint,
            filenames=filenames,
            search_paths=_as_str_tuple(raw.get("search_paths")),
            glob_hints=_as_str_tuple(raw.get("glob_hints")),
            package_name=str(raw.get("package_name", "")).strip(),
            confidence=confidence,  # type: ignore[arg-type]
            evidence=str(raw.get("evidence", "")).strip(),
            arch_warning=str(raw.get("arch_warning", "")).strip(),
        ),
        None,
    )


def _expand_hypothesis(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Sinh entry thô cho các CA hypothesis (filenames RỖNG + glob_hints chung)."""
    block = doc.get("hypothesis_cas")
    if not isinstance(block, dict):
        return []
    glob_hints = block.get("glob_hints") or []
    evidence = str(block.get("evidence", ""))
    out: list[dict[str, Any]] = []
    for name in block.get("names") or []:
        slug = "".join(c.lower() if c.isalnum() else "_" for c in str(name)).strip("_")
        out.append(
            {
                "id": f"hypothesis_{slug}",
                "track": "B",
                "os": "any",
                "ca_hint": str(name),
                "filenames": [],  # KHÔNG đoán
                "glob_hints": glob_hints,
                "confidence": "hypothesis",
                "evidence": evidence,
            }
        )
    return out


def _load_doc(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def _user_intel_path() -> Path | None:
    """File bảng vàng của người dùng tại config_dir (nếu có)."""
    try:
        from core.platform import get_adapter

        return get_adapter().config_dir() / "vendor_intel.yaml"
    except Exception:  # noqa: BLE001
        return None


def _override_paths() -> list[Path]:
    """Các file ghi đè theo thứ tự ưu tiên tăng dần."""
    paths: list[Path] = []
    user = _user_intel_path()
    if user is not None and user.is_file():
        paths.append(user)
    env = os.environ.get(ENV_INTEL_FILE, "").strip()
    if env and Path(env).is_file():
        paths.append(Path(env))
    return paths


def load_intel(base_path: Path | None = None) -> IntelDatabase:
    """Nạp bảng vàng (cơ sở + ghi đè), validate, dựng index.

    Entry lỗi bị BỎ QUA và ghi vào ``IntelDatabase.errors`` (không làm sập tải).
    """
    db = IntelDatabase()
    by_id: dict[str, IntelEntry] = {}

    docs: list[dict[str, Any]] = [_load_doc(base_path or vendor_intel_path())]
    docs.extend(_load_doc(p) for p in _override_paths())

    for doc in docs:
        if not doc:
            continue
        # Đường dẫn tìm kiếm mặc định (tầng sau thay thế theo OS nếu khai báo).
        sp = doc.get("search_paths")
        if isinstance(sp, dict):
            for os_name, paths in sp.items():
                if isinstance(paths, list):
                    db.default_search_paths[str(os_name)] = [str(x) for x in paths]

        raw_entries = list(doc.get("entries") or [])
        raw_entries.extend(_expand_hypothesis(doc))
        for raw in raw_entries:
            if not isinstance(raw, dict):
                db.errors.append(f"entry không phải dict: {raw!r}")
                continue
            entry, err = _parse_entry(raw)
            if err:
                db.errors.append(err)
                continue
            assert entry is not None
            by_id[entry.id] = entry  # ghi đè theo id

    db.entries = list(by_id.values())
    return db


# --------------------------------------------------------------------------- #
# CLI: python -m core.intel --list --os linux --track B                       #
# --------------------------------------------------------------------------- #
def _main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m core.intel")
    parser.add_argument("--list", action="store_true", help="Liệt kê entry.")
    parser.add_argument("--os", choices=sorted(_VALID_OS), help="Lọc theo OS.")
    parser.add_argument("--track", choices=["A", "B"], help="Lọc theo track.")
    parser.add_argument(
        "--confidence", choices=sorted(_VALID_CONFIDENCE), help="Lọc theo độ tin cậy."
    )
    args = parser.parse_args(argv)

    db = load_intel()
    entries = db.filter(os_name=args.os, track=args.track, confidence=args.confidence)

    print(f"Bảng vàng: {len(db.entries)} entry · lọc ra {len(entries)}")
    if db.errors:
        print(f"⚠️  {len(db.errors)} entry lỗi (đã bỏ qua):")
        for e in db.errors:
            print(f"     - {e}")

    if args.os:
        print(f"Đường dẫn tìm kiếm ({args.os}): {db.search_paths_for(args.os)}")
        gh = db.glob_hints_for(args.os)
        if gh:
            print(f"glob_hints ({args.os}): {gh}")

    if args.list or entries:
        for e in sorted(entries, key=lambda x: (x.track, x.os, x.id)):
            files = ", ".join(e.filenames) if e.filenames else "(chưa xác nhận)"
            print(f"  • [{e.track}/{e.confidence}] {e.id} · os={e.os} · {e.display_hint}")
            print(f"      files: {files}")
            if e.package_name:
                print(f"      package: {e.package_name}")
            if e.arch_warning:
                print(f"      ⚠ arch: {e.arch_warning}")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(_main())


__all__ = ["IntelEntry", "IntelDatabase", "load_intel", "ENV_INTEL_FILE"]
