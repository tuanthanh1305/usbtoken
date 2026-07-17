"""Adapter macOS — TRỤC 1. Kỹ về Apple Silicon (Rosetta 2). Keychain là fallback."""

from __future__ import annotations

import base64
import os
import plistlib
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from core.errors import BridgeUnavailableError

from .base import (
    BinaryArch,
    HostArch,
    PlatformAdapter,
    PlatformName,
    detect_host_arch,
)

if TYPE_CHECKING:
    from core.bridge.client import BridgeClient


class MacOSAdapter(PlatformAdapter):
    """Hiện thực :class:`PlatformAdapter` cho macOS (Intel & Apple Silicon)."""

    def name(self) -> PlatformName:
        return "macos"

    def host_arch(self) -> HostArch:
        """Kiến trúc tiến trình + cờ Rosetta (sysctl.proc_translated == 1)."""
        return detect_host_arch(rosetta=self._proc_translated())

    # -- Định vị module ------------------------------------------------- #
    def library_search_paths(self) -> list[Path]:
        """OpenSC, Homebrew (Intel /usr/local & Apple Silicon /opt/homebrew),
        watchdata, các framework, và trong .app. BỎ QUA /usr/lib (SIP khoá)."""
        paths: list[Path] = [
            Path("/Library/OpenSC/lib"),
            Path("/usr/local/lib"),
            Path("/opt/homebrew/lib"),
            Path("/usr/local/lib/watchdata/lib"),
            Path.home() / "lib",
        ]
        fw_root = Path("/Library/Frameworks")
        if fw_root.is_dir():
            paths.extend(fw_root.glob("*.framework/Versions/A"))
        apps = Path("/Applications")
        if apps.is_dir():
            for app in apps.glob("*.app"):
                for sub in ("MacOS", "Frameworks", "PlugIns"):
                    d = app / "Contents" / sub
                    if d.is_dir():
                        paths.append(d)
        return paths

    def glob_patterns(self) -> list[str]:
        # OpenSC trên macOS vẫn dùng đuôi .so, nên chấp nhận cả hai.
        return ["*.dylib", "*.so"]

    def discover_from_system(self) -> list[Path]:
        found: list[Path] = []
        raw = self._run(["system_profiler", "-xml", "SPSmartCardsDataType"])
        if raw:
            try:
                found.extend(self._paths_from_plist(plistlib.loads(raw)))
            except plistlib.InvalidFileException:
                pass
        tokend = Path("/Library/Security/tokend")
        if tokend.is_dir():
            found.extend(tokend.glob("*/Contents/MacOS/*"))
        return [p for p in found if p]

    @staticmethod
    def _paths_from_plist(data: object) -> list[Path]:
        out: list[Path] = []

        def _walk(node: object) -> None:
            if isinstance(node, dict):
                for v in node.values():
                    _walk(v)
            elif isinstance(node, list):
                for it in node:
                    _walk(it)
            elif isinstance(node, str) and node.endswith((".dylib", ".so")):
                out.append(Path(node))

        _walk(data)
        return out

    # -- Kiến trúc & cầu nối -------------------------------------------- #
    def check_binary_arch(self, path: Path) -> BinaryArch:
        """Ưu tiên ``lipo -archs``; fallback đọc Mach-O magic + fat header."""
        archs = self._lipo_archs(path)
        if archs is not None:
            return self._archs_to_binaryarch(archs)
        return self._parse_macho_arch(path)

    def _lipo_archs(self, path: Path) -> list[str] | None:
        if not path.exists():
            return None
        proc = self._run_proc(["lipo", "-archs", str(path)])
        if proc is None or proc.returncode != 0:
            return None
        return proc.stdout.split()

    @staticmethod
    def _archs_to_binaryarch(archs: list[str]) -> BinaryArch:
        if not archs:
            return BinaryArch.UNKNOWN
        if len(archs) > 1:
            return BinaryArch.UNIVERSAL
        a = archs[0].lower()
        if a in ("arm64", "arm64e"):
            return BinaryArch.ARM64
        if a == "x86_64":
            return BinaryArch.X86_64
        if a in ("i386", "i486", "i586", "i686"):
            return BinaryArch.X86_32
        if a.startswith("armv"):
            return BinaryArch.ARM_32
        return BinaryArch.UNKNOWN

    def needs_arch_bridge(self, lib_path: Path) -> bool:
        """True nếu host arm64 mà dylib CHỈ có x86_64 (phổ biến với token VN)."""
        arch = self.check_binary_arch(lib_path)
        if arch in (BinaryArch.UNIVERSAL, BinaryArch.UNKNOWN):
            return False
        lib_machine = "arm64" if arch in (BinaryArch.ARM64, BinaryArch.ARM_32) else "x86_64"
        return lib_machine != self.host_arch()["machine"]

    def spawn_bridge_helper(self, lib_path: Path) -> "BridgeClient":
        from core.bridge.client import BridgeClient

        if not self._rosetta_available():
            raise BridgeUnavailableError(
                "Cần Rosetta 2 để chạy helper x86_64 trên Apple Silicon nhưng "
                "Rosetta chưa được cài.",
                detail=self.arch_bridge_hint(),
            )
        bridge_python = os.environ.get("VN_ESIGN_BRIDGE_PYTHON", sys.executable)
        command = ["arch", "-x86_64", bridge_python, "-m", "core.bridge.helper"]
        return BridgeClient(
            command, cwd=str(self._repo_root()), env=os.environ.copy(),
            name=f"mac-bridge:{lib_path.name}",
        )

    def _rosetta_available(self) -> bool:
        if Path("/Library/Apple/usr/libexec/oah/libRosettaRuntime").exists():
            return True
        proc = self._run_proc(["arch", "-x86_64", "/usr/bin/true"])
        return proc is not None and proc.returncode == 0

    def arch_bridge_hint(self) -> str:
        return (
            "Dylib chỉ có bản x86_64 nhưng host là arm64 (Apple Silicon).\n"
            "  • Cài Rosetta 2: softwareupdate --install-rosetta --agree-to-license\n"
            "  • Cung cấp Python x86_64/universal2 qua VN_ESIGN_BRIDGE_PYTHON.\n"
            "  • Kiểm dylib không bị quarantine: xattr -d com.apple.quarantine <path>."
        )

    # -- Chẩn đoán ------------------------------------------------------ #
    def platform_notes(self) -> list[str]:
        notes: list[str] = []
        if self._proc_translated():
            notes.append(
                "Python đang chạy DƯỚI Rosetta 2 (tiến trình x86_64 trên phần cứng "
                "arm64). Nạp trực tiếp .dylib x86_64 được; muốn native dùng Python arm64."
            )
        elif self._hardware_is_arm64():
            notes.append(
                "Phần cứng Apple Silicon: middleware token thường chỉ có .dylib "
                "x86_64 -> cần helper cầu nối qua Rosetta 2 (arch -x86_64)."
            )
        return notes

    def library_warnings(self, path: Path) -> list[str]:
        proc = self._run_proc(["xattr", "-p", "com.apple.quarantine", str(path)])
        if proc is not None and proc.returncode == 0 and proc.stdout.strip():
            return [
                "Thư viện bị cờ quarantine (Gatekeeper có thể chặn nạp). Gỡ bằng:\n"
                f"    xattr -d com.apple.quarantine '{path}'"
            ]
        return []

    # -- PC/SC & fallback ----------------------------------------------- #
    def pcsc_backend_ready(self) -> tuple[bool, str]:
        try:
            from smartcard.System import readers  # type: ignore[import-untyped]

            readers()
            return True, ""
        except Exception:  # noqa: BLE001
            return False, (
                "Chưa truy cập được PC/SC trên macOS. Kiểm tra token đã cắm; nếu "
                "cần driver CCID bên thứ ba, cài rồi thử lại. Liệt kê token: "
                "pluginkit -m -p com.apple.ctk-tokens"
            )

    def certstore_fallback(self) -> list[bytes]:
        raw = self._run(["security", "find-certificate", "-a", "-p"])
        return _pem_blocks_to_der(raw.decode("utf-8", "ignore")) if raw else []

    # -- Thư mục chuẩn & chạy nền --------------------------------------- #
    def config_dir(self) -> Path:
        return Path.home() / "Library" / "Application Support" / "vn-esign-suite"

    def log_dir(self) -> Path:
        return Path.home() / "Library" / "Logs" / "vn-esign-suite"

    def service_install_hint(self) -> str:
        return (
            "Chạy daemon vn-esign dưới nền trên macOS:\n"
            "  • launchd: đặt plist vào ~/Library/LaunchAgents/ rồi launchctl load.\n"
            "  • Đóng gói universal2 (lipo x86_64 + arm64) để chạy chung Intel & Apple Silicon.\n"
            "  • Service chỉ bind 127.0.0.1."
        )

    # -- Helper subprocess & sysctl ------------------------------------- #
    @staticmethod
    def _run_proc(cmd: list[str]) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(cmd, capture_output=True, timeout=15, check=False, text=True)
        except (FileNotFoundError, OSError):
            return None

    @staticmethod
    def _run(cmd: list[str]) -> bytes:
        try:
            return subprocess.run(cmd, capture_output=True, timeout=15, check=False).stdout
        except (FileNotFoundError, OSError):
            return b""

    def _sysctl_int(self, key: str) -> int | None:
        proc = self._run_proc(["sysctl", "-n", key])
        if proc is None or proc.returncode != 0:
            return None
        try:
            return int(proc.stdout.strip())
        except ValueError:
            return None

    def _proc_translated(self) -> bool:
        return self._sysctl_int("sysctl.proc_translated") == 1

    def _hardware_is_arm64(self) -> bool:
        return self._sysctl_int("hw.optional.arm64") == 1


def _pem_blocks_to_der(pem_text: str) -> list[bytes]:
    out: list[bytes] = []
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    idx = 0
    while True:
        s = pem_text.find(begin, idx)
        if s == -1:
            break
        e = pem_text.find(end, s)
        if e == -1:
            break
        body = "".join(pem_text[s + len(begin) : e].split())
        try:
            out.append(base64.b64decode(body))
        except (ValueError, TypeError):
            pass
        idx = e + len(end)
    return out
