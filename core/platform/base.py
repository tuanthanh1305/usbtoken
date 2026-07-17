"""Interface (hợp đồng) trừu tượng cho tầng platform — ranh giới cô lập OS.

NGUYÊN TẮC BẤT KHẢ XÂM PHẠM (điều 3 của đặc tả dự án):
    * Mọi hành vi phụ thuộc hệ điều hành PHẢI nằm trong một lớp con của
      :class:`PlatformAdapter` (``windows.py`` / ``macos.py`` / ``linux.py``).
    * Toàn bộ phần còn lại của ``core/`` (engine, trust, esign...) TUYỆT ĐỐI
      không gọi ``platform.system()`` hay chứa nhánh ``if os == ...``. Nó chỉ
      làm việc qua interface này và factory ``get_adapter()``.

Tầng này thuộc TRỤC 1 (MODULE) — "CÁCH nạp thư viện". Nó KHÔNG dính tới TRỤC 2
(CHIP thật, đọc qua ``C_GetTokenInfo``) hay TRỤC 3 (CA, xác định bằng chain
building trong ``core/trust``). Ba trục độc lập, không suy ra nhau.
"""

from __future__ import annotations

import abc
import os
import platform as _platform  # chỉ dùng cho arch (KHÔNG dùng .system() ở base)
import struct
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Literal, TypedDict

if TYPE_CHECKING:
    from core.bridge.client import BridgeClient

# Tên OS chuẩn hoá dùng xuyên suốt hệ thống. Chỉ 3 giá trị này được phép.
PlatformName = Literal["windows", "macos", "linux"]

# Biến môi trường cho phép người dùng nạp thêm module thủ công.
ENV_EXTRA_MODULES = "VN_ESIGN_EXTRA_MODULES"


class HostArch(TypedDict):
    """Kiến trúc của tiến trình Python host hiện tại.

    Attributes:
        bits:    Độ rộng con trỏ tiến trình (64 hoặc 32).
        machine: Họ CPU đã chuẩn hoá ("arm64" hoặc "x86_64").
        rosetta: True nếu tiến trình x86_64 đang chạy DƯỚI Rosetta 2 trên phần
                 cứng Apple Silicon (chỉ có thể True trên macOS).
    """

    bits: Literal[64, 32]
    machine: Literal["arm64", "x86_64"]
    rosetta: bool


class BinaryArch(str, Enum):
    """Kiến trúc của MỘT file thư viện native (.dll/.dylib/.so).

    Đọc trực tiếp từ header của file (PE / Mach-O / ELF).
    """

    X86_64 = "x86_64"
    X86_32 = "x86_32"
    ARM64 = "arm64"
    ARM_32 = "arm_32"
    UNIVERSAL = "universal"  # macOS fat binary chứa nhiều slice
    UNKNOWN = "unknown"


@dataclass(slots=True)
class ModuleCandidateRaw:
    """Ứng viên module PKCS#11 tìm được ở tầng platform (mức thô, chưa validate).

    Đây là bản ghi nội bộ của tầng platform; ``core/discovery`` sẽ chuyển thành
    :class:`core.models.ModuleCandidate` (có track A/B, confidence...).
    """

    path: Path
    source: str  # "search_path" | "system" | "user_config"
    arch: BinaryArch = BinaryArch.UNKNOWN
    warnings: list[str] = field(default_factory=list)


def normalize_machine(raw: str) -> Literal["arm64", "x86_64"]:
    """Chuẩn hoá chuỗi machine thô của các OS về hai họ CPU thống nhất."""
    token = raw.lower()
    if token in {"arm64", "aarch64", "arm64e"} or token.startswith("armv8"):
        return "arm64"
    return "x86_64"


def detect_host_arch(*, rosetta: bool = False) -> HostArch:
    """Phát hiện kiến trúc tiến trình Python host (dùng chung, an toàn ở base).

    ``rosetta`` mặc định False; chỉ adapter macOS mới xác định được giá trị thật
    qua ``sysctl.proc_translated`` và truyền vào.
    """
    bits: Literal[64, 32] = 64 if sys.maxsize > 2**32 else 32
    return HostArch(bits=bits, machine=normalize_machine(_platform.machine()), rosetta=rosetta)


class PlatformAdapter(abc.ABC):
    """Hợp đồng mà mỗi hệ điều hành phải hiện thực.

    Cả ba OS đều là công dân hạng nhất: mọi method dưới đây phải được hiện thực
    nghiêm túc, không OS nào bị coi là "hạng hai".
    """

    # ------------------------------------------------------------------ #
    # Nhận diện nền tảng                                                  #
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def name(self) -> PlatformName:
        """Tên OS chuẩn hoá: ``"windows"`` | ``"macos"`` | ``"linux"``."""

    @abc.abstractmethod
    def host_arch(self) -> HostArch:
        """Kiến trúc tiến trình host (bits / machine / rosetta)."""

    # ------------------------------------------------------------------ #
    # Định vị module PKCS#11 (TRỤC 1)                                     #
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def library_search_paths(self) -> list[Path]:
        """Các thư mục nên quét để tìm module PKCS#11 trên OS này."""

    @abc.abstractmethod
    def glob_patterns(self) -> list[str]:
        """Glob-pattern tên file thư viện hợp lệ (``*.dll``/``*.dylib``/``*.so``)."""

    @abc.abstractmethod
    def discover_from_system(self) -> list[Path]:
        """Hỏi dịch vụ đăng ký của OS (Registry / p11-kit / system_profiler)."""

    def discover_from_user_config(self) -> list[Path]:
        """Đọc module nạp thêm do người dùng khai báo (OS-agnostic, dùng chung).

        Hai nguồn:
            * Biến môi trường ``VN_ESIGN_EXTRA_MODULES`` (ngăn bằng ``os.pathsep``).
            * File ``<config_dir>/extra_modules.txt`` (mỗi dòng một đường dẫn,
              ``#`` để chú thích).
        """
        paths: list[Path] = []

        env = os.environ.get(ENV_EXTRA_MODULES, "")
        for part in env.split(os.pathsep):
            part = part.strip()
            if part:
                paths.append(Path(part))

        cfg = self.config_dir() / "extra_modules.txt"
        try:
            if cfg.is_file():
                for line in cfg.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        paths.append(Path(line))
        except OSError:
            pass

        return paths

    # ------------------------------------------------------------------ #
    # Kiến trúc & cầu nối (TRỤC 1)                                        #
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def check_binary_arch(self, path: Path) -> BinaryArch:
        """Đọc header native của ``path`` (PE/Mach-O/ELF) -> kiến trúc thật."""

    @abc.abstractmethod
    def needs_arch_bridge(self, lib_path: Path) -> bool:
        """True nếu ``lib_path`` lệch bitness/arch với host -> phải qua bridge."""

    @abc.abstractmethod
    def spawn_bridge_helper(self, lib_path: Path) -> "BridgeClient":
        """Spawn helper CÙNG ARCH với ``lib_path`` và trả client IPC (JSON-RPC).

        Ném :class:`~core.errors.BridgeUnavailableError` nếu môi trường chưa đủ
        điều kiện cầu nối (thiếu Rosetta / Python khác-arch / emulator).
        """

    def arch_bridge_hint(self) -> str:
        """Gợi ý khắc phục khi lệch kiến trúc (override per-OS)."""
        return (
            "Module PKCS#11 lệch kiến trúc với tiến trình host; cần một helper "
            "cùng arch với module."
        )

    # ------------------------------------------------------------------ #
    # Backend thẻ thông minh & fallback                                  #
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def pcsc_backend_ready(self) -> tuple[bool, str]:
        """``(ready, remediation)`` — remediation rỗng nếu PC/SC đã sẵn sàng."""

    @abc.abstractmethod
    def certstore_fallback(self) -> list[bytes]:
        """Chứng thư (DER) từ kho OS: CertStore MY | Keychain | NSS DB."""

    # ------------------------------------------------------------------ #
    # Thư mục chuẩn & chạy nền                                            #
    # ------------------------------------------------------------------ #
    @abc.abstractmethod
    def config_dir(self) -> Path:
        """Thư mục cấu hình chuẩn của ứng dụng theo OS."""

    @abc.abstractmethod
    def log_dir(self) -> Path:
        """Thư mục log/bằng-chứng chuẩn theo OS (nơi lưu ValidationResult...)."""

    @abc.abstractmethod
    def service_install_hint(self) -> str:
        """Hướng dẫn (nhiều dòng) chạy daemon dưới nền cho OS này."""

    # ------------------------------------------------------------------ #
    # Tiện ích dùng chung                                                 #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _repo_root() -> Path:
        """Thư mục gốc repo (base.py ở core/platform/base.py -> lùi 2 cấp)."""
        return Path(__file__).resolve().parents[2]

    def library_warnings(self, path: Path) -> list[str]:
        """Cảnh báo mức-file cho một module (mặc định rỗng; macOS override)."""
        return []

    def platform_notes(self) -> list[str]:
        """Ghi chú mức-hệ-thống cho chẩn đoán (mặc định rỗng)."""
        return []

    # -- Parse header thuần bytes (tái sử dụng bởi lớp con) -------------- #
    @staticmethod
    def _read_magic(path: Path, size: int = 4) -> bytes:
        try:
            with path.open("rb") as fh:
                return fh.read(size)
        except OSError:
            return b""

    @staticmethod
    def _parse_elf_arch(path: Path) -> BinaryArch:
        """Parse ELF header (Linux): magic \\x7fELF, EI_CLASS, e_machine."""
        try:
            with path.open("rb") as fh:
                header = fh.read(20)
        except OSError:
            return BinaryArch.UNKNOWN
        if len(header) < 20 or header[:4] != b"\x7fELF":
            return BinaryArch.UNKNOWN
        ei_class = header[4]
        ei_data = header[5]
        endian = "<" if ei_data == 1 else ">"
        (e_machine,) = struct.unpack_from(f"{endian}H", header, 18)
        if e_machine == 0x3E:
            return BinaryArch.X86_64
        if e_machine == 0x03:
            return BinaryArch.X86_32
        if e_machine == 0xB7:
            return BinaryArch.ARM64
        if e_machine == 0x28:
            return BinaryArch.ARM_32
        return BinaryArch.X86_64 if ei_class == 2 else BinaryArch.X86_32

    @staticmethod
    def _parse_pe_arch(path: Path) -> BinaryArch:
        """Parse PE header (Windows .dll): DOS -> e_lfanew -> COFF Machine."""
        try:
            with path.open("rb") as fh:
                dos = fh.read(64)
                if len(dos) < 64 or dos[:2] != b"MZ":
                    return BinaryArch.UNKNOWN
                (e_lfanew,) = struct.unpack_from("<I", dos, 0x3C)
                fh.seek(e_lfanew)
                if fh.read(4) != b"PE\x00\x00":
                    return BinaryArch.UNKNOWN
                (machine,) = struct.unpack("<H", fh.read(2))
        except (OSError, struct.error):
            return BinaryArch.UNKNOWN
        return {
            0x8664: BinaryArch.X86_64,
            0x014C: BinaryArch.X86_32,
            0xAA64: BinaryArch.ARM64,
            0x01C0: BinaryArch.ARM_32,
        }.get(machine, BinaryArch.UNKNOWN)

    @staticmethod
    def _parse_macho_arch(path: Path) -> BinaryArch:
        """Parse Mach-O / fat header (macOS): fat -> UNIVERSAL; thin -> cputype."""
        magic = PlatformAdapter._read_magic(path, 4)
        if len(magic) < 4:
            return BinaryArch.UNKNOWN
        if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            return BinaryArch.UNIVERSAL
        try:
            with path.open("rb") as fh:
                head = fh.read(8)
        except OSError:
            return BinaryArch.UNKNOWN
        if len(head) < 8:
            return BinaryArch.UNKNOWN
        little = magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe")
        endian = "<" if little else ">"
        (cputype,) = struct.unpack_from(f"{endian}I", head, 4)
        CPU_ARCH_ABI64 = 0x01000000
        base = cputype & ~CPU_ARCH_ABI64
        if base == 7:
            return BinaryArch.X86_64 if cputype & CPU_ARCH_ABI64 else BinaryArch.X86_32
        if base == 12:
            return BinaryArch.ARM64 if cputype & CPU_ARCH_ABI64 else BinaryArch.ARM_32
        return BinaryArch.UNKNOWN

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} name={self.name()!r}>"


__all__ = [
    "PlatformName",
    "ENV_EXTRA_MODULES",
    "HostArch",
    "BinaryArch",
    "ModuleCandidateRaw",
    "normalize_machine",
    "detect_host_arch",
    "PlatformAdapter",
]
