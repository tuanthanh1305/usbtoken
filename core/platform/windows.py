"""Adapter Windows — TRỤC 1 (cách nạp module). CryptoAPI/CNG chỉ là fallback."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from core.config import text_matches_ca_keyword

from .base import (
    FALLBACK_WIN_CERTSTORE,
    BinaryArch,
    FallbackCert,
    HostArch,
    PlatformAdapter,
    PlatformName,
    detect_host_arch,
)

if TYPE_CHECKING:
    from core.bridge.client import BridgeClient


class WindowsAdapter(PlatformAdapter):
    """Hiện thực :class:`PlatformAdapter` cho Windows (x86_64 và arm64)."""

    def name(self) -> PlatformName:
        return "windows"

    def host_arch(self) -> HostArch:
        return detect_host_arch(rosetta=False)  # Rosetta là khái niệm của macOS

    # -- Định vị module ------------------------------------------------- #
    def library_search_paths(self) -> list[Path]:
        """System32 (64-bit) + SysWOW64 (32-BIT — BẮT BUỘC) + Program Files."""
        paths: list[Path] = []
        windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
        paths.append(windir / "System32")
        paths.append(windir / "SysWOW64")
        for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            root = os.environ.get(env)
            if root:
                paths.append(Path(root))
        paths.append(Path(r"C:\Program Files"))
        paths.append(Path(r"C:\Program Files (x86)"))
        seen: dict[Path, None] = {}
        for p in paths:
            seen.setdefault(p, None)
        return list(seen)

    def glob_patterns(self) -> list[str]:
        return ["*.dll"]

    def discover_from_system(self) -> list[Path]:
        """TẦNG 1 — đọc Windows Registry (winreg).

        * ``...\\Uninstall\\*`` (+ WOW6432Node): LỌC ``DisplayName`` chứa từ khoá
          CA (26 tên CA + "token"/"ký số"/...) -> ``InstallLocation`` -> quét *.dll.
        * ``...\\Cryptography\\Defaults\\Provider``: đường dẫn CSP/KSP đã đăng ký.
        Chỉ trả file .dll TỒN TẠI THỰC TẾ.
        """
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError:
            return []

        found: list[Path] = []
        windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
        system32 = windir / "System32"

        # (1) Uninstall -> lọc theo DisplayName -> InstallLocation -> *.dll
        for subkey in (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ):
            for install_dir in self._enum_ca_install_locations(winreg, subkey):
                if install_dir.is_dir():
                    found.extend(install_dir.rglob("*.dll"))

        # (2) Cryptography Defaults Provider -> Image Path
        for subkey in (
            r"SOFTWARE\Microsoft\Cryptography\Defaults\Provider",
            r"SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider",
        ):
            for image in self._enum_provider_images(winreg, subkey):
                p = Path(image)
                found.append(p if p.is_absolute() else system32 / p.name)

        return found

    @staticmethod
    def _enum_ca_install_locations(winreg_mod, subkey: str) -> list[Path]:  # type: ignore[no-untyped-def]
        """Duyệt Uninstall, chỉ lấy InstallLocation của phần mềm CA/token.

        Lọc bằng ``DisplayName`` (hoặc ``Publisher``) khớp từ khoá CA — tránh
        quét toàn bộ phần mềm cài trên máy (nhiễu + chậm).
        """
        out: list[Path] = []
        try:
            root = winreg_mod.OpenKey(winreg_mod.HKEY_LOCAL_MACHINE, subkey)
        except OSError:
            return out
        with root:
            idx = 0
            while True:
                try:
                    child_name = winreg_mod.EnumKey(root, idx)
                except OSError:
                    break
                idx += 1
                try:
                    with winreg_mod.OpenKey(root, child_name) as child:
                        display = _query(winreg_mod, child, "DisplayName")
                        publisher = _query(winreg_mod, child, "Publisher")
                        location = _query(winreg_mod, child, "InstallLocation")
                except OSError:
                    continue
                if not location:
                    continue
                if text_matches_ca_keyword(display) or text_matches_ca_keyword(publisher):
                    out.append(Path(location.strip()))
        return out

    @staticmethod
    def _enum_provider_images(winreg_mod, subkey: str) -> list[str]:  # type: ignore[no-untyped-def]
        out: list[str] = []
        try:
            root = winreg_mod.OpenKey(winreg_mod.HKEY_LOCAL_MACHINE, subkey)
        except OSError:
            return out
        with root:
            idx = 0
            while True:
                try:
                    child_name = winreg_mod.EnumKey(root, idx)
                except OSError:
                    break
                idx += 1
                try:
                    with winreg_mod.OpenKey(root, child_name) as child:
                        image = _query(winreg_mod, child, "Image Path")
                except OSError:
                    continue
                if image.strip():
                    out.append(image.strip())
        return out

    # -- Kiến trúc & cầu nối -------------------------------------------- #
    def check_binary_arch(self, path: Path) -> BinaryArch:
        """Đọc PE header (IMAGE_FILE_MACHINE) bằng struct — không lib ngoài.

        0x014c=x86(32), 0x8664=x64(64), 0xAA64=arm64.
        """
        return self._parse_pe_arch(path)

    def needs_arch_bridge(self, lib_path: Path) -> bool:
        host = self.host_arch()
        lib = self.check_binary_arch(lib_path)
        if lib in (BinaryArch.UNKNOWN, BinaryArch.UNIVERSAL):
            return False
        lib_bits = 64 if lib in (BinaryArch.X86_64, BinaryArch.ARM64) else 32
        if lib_bits != host["bits"]:
            return True
        lib_machine = "arm64" if lib in (BinaryArch.ARM64, BinaryArch.ARM_32) else "x86_64"
        return lib_machine != host["machine"]

    def spawn_bridge_helper(self, lib_path: Path) -> BridgeClient:
        from core.bridge.client import BridgeClient
        from core.errors import BridgeUnavailableError

        helper_exe = os.environ.get("VN_ESIGN_BRIDGE_HELPER")
        bridge_python = os.environ.get("VN_ESIGN_BRIDGE_PYTHON")
        if helper_exe:
            command = [helper_exe]
        elif bridge_python:
            command = [bridge_python, "-m", "core.bridge.helper"]
        else:
            raise BridgeUnavailableError(
                "Cần helper cùng bitness với DLL nhưng chưa cấu hình.",
                detail=self.arch_bridge_hint(),
            )
        return BridgeClient(
            command, cwd=str(self._repo_root()), env=os.environ.copy(),
            name=f"win-bridge:{lib_path.name}",
        )

    def arch_bridge_hint(self) -> str:
        return (
            "DLL lệch bitness với host (vd. host 64-bit, DLL 32-bit ở SysWOW64). "
            "Đặt VN_ESIGN_BRIDGE_PYTHON (python 32-bit) hoặc VN_ESIGN_BRIDGE_HELPER "
            "(helper 32-bit đã đóng gói), hoặc chạy service bằng Python cùng bitness."
        )

    # -- PC/SC & fallback ----------------------------------------------- #
    def pcsc_backend_ready(self) -> tuple[bool, str]:
        try:
            from smartcard.System import readers  # type: ignore[import-untyped]

            readers()
            return True, ""
        except ImportError:
            pass
        except Exception:  # noqa: BLE001
            pass
        state = self._service_state("SCardSvr")
        if state == "RUNNING":
            return True, ""
        remediation = (
            "Dịch vụ Smart Card (SCardSvr) chưa chạy"
            + (f" (trạng thái: {state})" if state else "")
            + ". Mở CMD/PowerShell quyền Administrator:\n"
            "    sc start SCardSvr\n    sc config SCardSvr start= auto"
        )
        return False, remediation

    @staticmethod
    def _service_state(service: str) -> str:
        try:
            proc = subprocess.run(
                ["sc", "query", service], capture_output=True, timeout=10,
                check=False, text=True,
            )
        except (FileNotFoundError, OSError):
            return ""
        for line in proc.stdout.splitlines():
            if "STATE" in line.upper():
                tokens = line.replace(":", " ").split()
                if tokens:
                    return tokens[-1].upper()
        return ""

    def certstore_fallback(self) -> list[FallbackCert]:
        """Đọc chứng thư từ Windows CertStore "MY" (crypt32, đóng store đúng cách).

        LÝ DO: nhiều middleware CA Việt Nam TỰ ĐẨY chứng thư vào store "MY" khi
        cắm token — nhờ đó đọc được cert cả khi KHÔNG dò ra DLL PKCS#11.
        """
        certs: list[FallbackCert] = []
        store = "MY"
        try:
            import ctypes
        except ImportError:
            return certs
        try:
            crypt32 = ctypes.WinDLL("crypt32.dll")  # type: ignore[attr-defined]
        except (OSError, AttributeError):
            return certs
        h_store = crypt32.CertOpenSystemStoreW(None, store)
        if not h_store:
            return certs
        try:
            p_ctx = crypt32.CertEnumCertificatesInStore(h_store, None)
            while p_ctx:
                ctx = ctypes.cast(p_ctx, ctypes.POINTER(_CERT_CONTEXT)).contents
                der = ctypes.string_at(ctx.pbCertEncoded, ctx.cbCertEncoded)
                certs.append(FallbackCert(der=der, source=FALLBACK_WIN_CERTSTORE, origin=store))
                p_ctx = crypt32.CertEnumCertificatesInStore(h_store, p_ctx)
        finally:
            crypt32.CertCloseStore(h_store, 0)  # đóng store đúng cách (không rò handle)
        return certs

    # -- Thư mục chuẩn & chạy nền --------------------------------------- #
    def config_dir(self) -> Path:
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "vn-esign-suite"

    def log_dir(self) -> Path:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "vn-esign-suite" / "logs"

    def service_install_hint(self) -> str:
        return (
            "Chạy daemon vn-esign dưới nền trên Windows:\n"
            "  • Đăng ký Windows Service (NSSM hoặc sc.exe):\n"
            '      sc.exe create VNeSign binPath= "...\\vn-esign-service.exe" start= auto\n'
            "  • Service chỉ lắng nghe 127.0.0.1."
        )


def _query(winreg_mod, key, value_name: str) -> str:  # type: ignore[no-untyped-def]
    """Đọc một giá trị REG_SZ; trả chuỗi rỗng nếu không có."""
    try:
        val, _ = winreg_mod.QueryValueEx(key, value_name)
    except OSError:
        return ""
    return val if isinstance(val, str) else ""


try:  # pragma: no cover - chỉ có ý nghĩa trên Windows
    import ctypes

    class _CERT_CONTEXT(ctypes.Structure):
        _fields_ = [
            ("dwCertEncodingType", ctypes.c_uint32),
            ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
            ("cbCertEncoded", ctypes.c_uint32),
            ("pCertInfo", ctypes.c_void_p),
            ("hCertStore", ctypes.c_void_p),
        ]
except Exception:  # noqa: BLE001
    _CERT_CONTEXT = None  # type: ignore[assignment,misc]
