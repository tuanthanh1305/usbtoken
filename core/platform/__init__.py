"""Tầng platform — ranh giới cô lập hệ điều hành.

Module ``__init__`` này là NƠI DUY NHẤT trong toàn bộ codebase được phép gọi
``platform.system()`` và rẽ nhánh theo hệ điều hành. Mọi nơi khác dùng
:func:`get_adapter` để lấy :class:`PlatformAdapter` và làm việc qua interface.
"""

from __future__ import annotations

import functools
import platform

from .base import (
    FALLBACK_LINUX_NSS,
    FALLBACK_MAC_KEYCHAIN,
    FALLBACK_WIN_CERTSTORE,
    BinaryArch,
    FallbackCert,
    HostArch,
    ModuleCandidateRaw,
    PlatformAdapter,
    PlatformName,
    detect_host_arch,
    normalize_machine,
)


class UnsupportedPlatformError(RuntimeError):
    """Nền tảng hiện tại không nằm trong ba OS được hỗ trợ."""


@functools.lru_cache(maxsize=1)
def get_adapter() -> PlatformAdapter:
    """Factory: chọn đúng adapter theo hệ điều hành (điểm rẽ nhánh OS DUY NHẤT)."""
    system = platform.system()  # "Windows" | "Darwin" | "Linux"
    if system == "Windows":
        from .windows import WindowsAdapter

        return WindowsAdapter()
    if system == "Darwin":
        from .macos import MacOSAdapter

        return MacOSAdapter()
    if system == "Linux":
        from .linux import LinuxAdapter

        return LinuxAdapter()
    raise UnsupportedPlatformError(
        f"Hệ điều hành {system!r} chưa được hỗ trợ. vn-esign-suite hỗ trợ "
        "Windows, macOS (Intel & Apple Silicon), Linux."
    )


__all__ = [
    "get_adapter",
    "UnsupportedPlatformError",
    "PlatformAdapter",
    "PlatformName",
    "HostArch",
    "BinaryArch",
    "ModuleCandidateRaw",
    "FallbackCert",
    "FALLBACK_WIN_CERTSTORE",
    "FALLBACK_MAC_KEYCHAIN",
    "FALLBACK_LINUX_NSS",
    "detect_host_arch",
    "normalize_machine",
]
