"""Adapter macOS — TRỤC 1. Kỹ nhất về Apple Silicon (Rosetta 2). Keychain là fallback."""

from __future__ import annotations

import base64
import os
import plistlib
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from core.config import text_matches_ca_keyword
from core.errors import BridgeUnavailableError

from .base import (
    FALLBACK_MAC_KEYCHAIN,
    BinaryArch,
    FallbackCert,
    HostArch,
    PlatformAdapter,
    PlatformName,
    detect_host_arch,
)

if TYPE_CHECKING:
    from core.bridge.client import BridgeClient

# Keychain hệ thống — nơi middleware/CTK có thể đẩy chứng thư khi cắm token.
_SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"

# pcsc-lite từ Homebrew — xung đột với PCSC.framework sẵn có của macOS.
_HOMEBREW_PCSCD = (Path("/opt/homebrew/bin/pcscd"), Path("/usr/local/bin/pcscd"))


class MacOSAdapter(PlatformAdapter):
    """Hiện thực :class:`PlatformAdapter` cho macOS (Intel & Apple Silicon)."""

    def name(self) -> PlatformName:
        return "macos"

    def host_arch(self) -> HostArch:
        """Kiến trúc tiến trình + cờ Rosetta (sysctl.proc_translated == 1)."""
        return detect_host_arch(rosetta=self._proc_translated())

    # -- Định vị module ------------------------------------------------- #
    def library_search_paths(self) -> list[Path]:
        """OpenSC, Homebrew (Intel /usr/local & Apple Silicon /opt/homebrew — ĐỔI
        PREFIX, cực hay quên), watchdata, các framework. BỎ /usr/lib (SIP khoá)."""
        paths: list[Path] = [
            Path("/Library/OpenSC/lib"),
            Path("/usr/local/lib"),
            Path("/opt/homebrew/lib"),  # APPLE SILICON!
            Path("/usr/local/lib/watchdata/lib"),
            Path.home() / "lib",
        ]
        fw_root = Path("/Library/Frameworks")
        if fw_root.is_dir():
            paths.extend(fw_root.glob("*.framework/Versions/A"))
        return paths

    def glob_patterns(self) -> list[str]:
        # OpenSC trên macOS vẫn dùng đuôi .so, nên chấp nhận cả hai.
        return ["*.dylib", "*.so"]

    def discover_from_system(self) -> list[Path]:
        """TẦNG 1 — công cụ hệ thống macOS.

        * ``system_profiler SPSmartCardsDataType`` (plist, có thể chứa path).
        * Bundle ``tokend``.
        * Quét ``/Applications/*.app`` mà TÊN app khớp từ khoá CA -> tìm .dylib/.so
          trong Contents/{MacOS,Frameworks,Resources}.
        Chỉ trả file TỒN TẠI THỰC TẾ.
        """
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

        found.extend(self._scan_ca_applications())
        return [p for p in found if p.is_file()]

    @staticmethod
    def _scan_ca_applications() -> list[Path]:
        """Quét các .app của CA (tên khớp từ khoá) tìm module PKCS#11."""
        out: list[Path] = []
        apps = Path("/Applications")
        if not apps.is_dir():
            return out
        for app in apps.glob("*.app"):
            if not text_matches_ca_keyword(app.stem):
                continue
            for sub in ("MacOS", "Frameworks", "Resources"):
                d = app / "Contents" / sub
                if d.is_dir():
                    for pat in ("*.dylib", "*.so"):
                        out.extend(d.glob(pat))
        return out

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
        """True nếu host arm64 NATIVE mà dylib CHỈ có x86_64 (phổ biến nhất với
        middleware CA Việt Nam). Universal (có cả hai slice) KHÔNG cần cầu nối."""
        arch = self.check_binary_arch(lib_path)
        if arch in (BinaryArch.UNIVERSAL, BinaryArch.UNKNOWN):
            return False
        lib_machine = "arm64" if arch in (BinaryArch.ARM64, BinaryArch.ARM_32) else "x86_64"
        return lib_machine != self.host_arch()["machine"]

    def spawn_bridge_helper(self, lib_path: Path) -> BridgeClient:
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
        # Library Validation (thường gặp khi dlopen dylib x86_64/ký khác team).
        notes.append(
            "Library Validation: nếu dlopen báo 'code signature not valid for use in "
            "process', tiến trình host thiếu entitlement "
            "com.apple.security.cs.disable-library-validation. Bản đóng gói phải bật "
            "entitlement này để nạp module PKCS#11 của bên thứ ba."
        )
        # Xung đột pcsc-lite từ Homebrew.
        conflict = self._homebrew_pcscd()
        if conflict is not None:
            notes.append(
                f"Phát hiện pcscd của Homebrew tại {conflict} — có thể XUNG ĐỘT với "
                "PCSC.framework sẵn có của macOS. Cân nhắc gỡ: brew uninstall pcsc-lite."
            )
        # Số token CryptoTokenKit.
        ctk = self._run(["pluginkit", "-m", "-p", "com.apple.ctk-tokens"])
        if ctk and ctk.strip():
            count = len([ln for ln in ctk.decode("utf-8", "ignore").splitlines() if ln.strip()])
            notes.append(f"CryptoTokenKit: {count} token extension đã đăng ký.")
        return notes

    def library_warnings(self, path: Path) -> list[str]:
        warns: list[str] = []
        proc = self._run_proc(["xattr", "-p", "com.apple.quarantine", str(path)])
        if proc is not None and proc.returncode == 0 and proc.stdout.strip():
            warns.append(
                "Thư viện bị cờ quarantine (Gatekeeper có thể chặn nạp). Gỡ bằng:\n"
                f"    xattr -d com.apple.quarantine '{path}'"
            )
        return warns

    @staticmethod
    def _homebrew_pcscd() -> Path | None:
        for p in _HOMEBREW_PCSCD:
            if p.exists():
                return p
        return None

    # -- PC/SC & fallback ----------------------------------------------- #
    def pcsc_backend_ready(self) -> tuple[bool, str]:
        conflict = self._homebrew_pcscd()
        conflict_note = (
            f"\n⚠️ Có pcscd Homebrew ({conflict}) có thể xung đột PCSC.framework."
            if conflict else ""
        )
        try:
            from smartcard.System import readers  # type: ignore[import-untyped]

            readers()
            return True, conflict_note.strip()
        except Exception:  # noqa: BLE001
            return False, (
                "Chưa truy cập được PC/SC trên macOS. Kiểm tra token đã cắm; nếu "
                "cần driver CCID bên thứ ba, cài rồi thử lại. Liệt kê token: "
                "pluginkit -m -p com.apple.ctk-tokens" + conflict_note
            )

    def certstore_fallback(self) -> list[FallbackCert]:
        """Xuất chứng thư từ Keychain (login + System) qua ``security``.

        ``security find-certificate -a -p`` trả PEM; đổi sang DER. Quét cả
        keychain mặc định (login) lẫn System — nơi CTK/middleware có thể đẩy
        chứng thư của token vào. Khử trùng lặp theo DER (giữ nguồn đầu tiên).
        """
        out: list[FallbackCert] = []
        seen: set[bytes] = set()
        # (origin, argv): login/mặc định trước, rồi System keychain.
        scans = [
            ("login", ["security", "find-certificate", "-a", "-p"]),
            ("System", ["security", "find-certificate", "-a", "-p", _SYSTEM_KEYCHAIN]),
        ]
        for origin, argv in scans:
            raw = self._run(argv)
            if not raw:
                continue
            for der in _pem_blocks_to_der(raw.decode("utf-8", "ignore")):
                if der in seen:
                    continue
                seen.add(der)
                out.append(FallbackCert(der=der, source=FALLBACK_MAC_KEYCHAIN, origin=origin))
        return out

    def list_smartcards(self) -> list[str]:
        """Liệt kê token CTK do macOS thấy (``security list-smartcards``).

        Chỉ để CHẨN ĐOÁN (biết có thẻ nhưng chưa dò ra module) — KHÔNG kết luận
        CA. Trả rỗng nếu lệnh không có/không token.
        """
        raw = self._run(["security", "list-smartcards"])
        if not raw:
            return []
        return [ln.strip() for ln in raw.decode("utf-8", "ignore").splitlines() if ln.strip()]

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
