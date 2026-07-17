"""Adapter Linux — TRỤC 1. p11-kit + NSS DB là fallback.

TRACK B (CA rebrand): FPT-CA phát hành ``/usr/lib/fptca_v4.so`` (gói dpkg
``fptca-4.0``). ``dpkg -L fptca-4.0`` cho đường dẫn CHÍNH XÁC TUYỆT ĐỐI — vì vậy
Tầng 1 (dpkg/rpm/.desktop) là ưu tiên cao nhất. Logic Track A/B nằm ở
``core/discovery.py``; adapter chỉ cung cấp nguồn phát hiện.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from core.config import text_matches_ca_keyword

from .base import (
    FALLBACK_LINUX_NSS,
    BinaryArch,
    FallbackCert,
    HostArch,
    PlatformAdapter,
    PlatformName,
    detect_host_arch,
)

if TYPE_CHECKING:
    from core.bridge.client import BridgeClient

_UDEV_RULES_CONTENT = (
    "# /etc/udev/rules.d/99-vn-token.rules\n"
    "# Cấp quyền USB token ký số cho nhóm plugdev + uaccess.\n"
    'SUBSYSTEM=="usb", ACTION=="add", ENV{DEVTYPE}=="usb_device", '
    'MODE="0660", GROUP="plugdev", TAG+="uaccess"\n'
)
_SO_RE = re.compile(r"\.so(\.[0-9]+)*$")


class LinuxAdapter(PlatformAdapter):
    """Hiện thực :class:`PlatformAdapter` cho Linux (x86_64 và arm64/aarch64)."""

    def name(self) -> PlatformName:
        return "linux"

    def host_arch(self) -> HostArch:
        return detect_host_arch(rosetta=False)

    # -- Định vị module ------------------------------------------------- #
    def library_search_paths(self) -> list[Path]:
        return [
            Path("/usr/lib"),                    # PHẲNG — nơi FPT đặt fptca_v4.so!
            Path("/usr/lib64"),
            Path("/usr/lib/x86_64-linux-gnu"),
            Path("/usr/local/lib"),
            Path("/lib"),
            Path("/opt"),
        ]

    def glob_patterns(self) -> list[str]:
        return ["*.so", "*.so.*"]

    # ---- TẦNG 1: gói phần mềm (ưu tiên cao nhất) ---------------------- #
    def discover_from_system(self) -> list[Path]:
        """Dò module qua trình quản lý gói + .desktop (chính xác nhất)."""
        found: list[Path] = []
        found.extend(self._dpkg_modules())
        found.extend(self._rpm_modules())
        found.extend(self._desktop_modules())
        # Chỉ giữ file tồn tại thực tế.
        return [p for p in found if p.is_file()]

    def _dpkg_modules(self) -> list[Path]:
        """`dpkg -l` lọc gói CA/token -> `dpkg -L` -> các file .so.

        Ví dụ chính xác: dpkg -L fptca-4.0 -> /usr/lib/fptca_v4.so
        """
        out: list[Path] = []
        listing = self._run(["dpkg", "-l"])
        if not listing:
            return out
        for line in listing.decode("utf-8", "ignore").splitlines():
            if not line.startswith("ii"):
                continue
            parts = line.split(maxsplit=4)
            if len(parts) < 2:
                continue
            pkg = parts[1]
            desc = parts[4] if len(parts) >= 5 else ""
            if not (text_matches_ca_keyword(pkg) or text_matches_ca_keyword(desc)):
                continue
            files = self._run(["dpkg", "-L", pkg])
            for f in files.decode("utf-8", "ignore").splitlines():
                if _SO_RE.search(f):
                    out.append(Path(f))
        return out

    def _rpm_modules(self) -> list[Path]:
        """`rpm -qa` lọc gói CA/token -> `rpm -ql` -> các file .so."""
        out: list[Path] = []
        listing = self._run(["rpm", "-qa", "--qf", "%{NAME}\t%{SUMMARY}\n"])
        if not listing:
            return out
        for line in listing.decode("utf-8", "ignore").splitlines():
            name = line.split("\t", 1)[0]
            if not (text_matches_ca_keyword(name) or text_matches_ca_keyword(line)):
                continue
            files = self._run(["rpm", "-ql", name])
            for f in files.decode("utf-8", "ignore").splitlines():
                if _SO_RE.search(f):
                    out.append(Path(f))
        return out

    def _desktop_modules(self) -> list[Path]:
        """`/usr/share/applications/*.desktop` khớp từ khoá CA -> thư mục cài -> .so."""
        out: list[Path] = []
        desktop_dirs = [
            Path("/usr/share/applications"),
            Path.home() / ".local/share/applications",
        ]
        for ddir in desktop_dirs:
            if not ddir.is_dir():
                continue
            for entry in ddir.glob("*.desktop"):
                text = self._read_text(entry)
                if not text_matches_ca_keyword(text):
                    continue
                for exec_dir in self._exec_dirs(text):
                    if exec_dir.is_dir():
                        out.extend(exec_dir.glob("*.so"))
        return out

    @staticmethod
    def _exec_dirs(desktop_text: str) -> list[Path]:
        dirs: list[Path] = []
        for m in re.finditer(r"^Exec=(\S+)", desktop_text, re.MULTILINE):
            exe = Path(m.group(1))
            if exe.parent and str(exe.parent) not in ("", "."):
                dirs.append(exe.parent)
        return dirs

    # ---- TẦNG 2: cấu hình người dùng / p11-kit / NSS ----------------- #
    def discover_from_user_config(self) -> list[Path]:
        """Nạp thêm: env + file cấu hình (base) + p11-kit + NSS dò ngược."""
        paths = super().discover_from_user_config()
        paths.extend(self._p11kit_modules())
        paths.extend(self._nss_modules())
        return [p for p in paths if p.is_file()] or paths

    def _p11kit_modules(self) -> list[Path]:
        out: list[Path] = []
        listing = self._run(["p11-kit", "list-modules"])
        if listing:
            text = listing.decode("utf-8", "ignore")
            for m in re.finditer(r"^\s*path:\s*(?P<p>\S+)", text, re.MULTILINE):
                out.append(Path(m.group("p")))
        for cfg_dir in (Path("/usr/share/p11-kit/modules"), Path("/etc/pkcs11/modules")):
            if cfg_dir.is_dir():
                for cfg in cfg_dir.iterdir():
                    if cfg.is_file():
                        for m in re.finditer(
                            r"^\s*module:\s*(?P<p>\S+)", self._read_text(cfg), re.MULTILINE
                        ):
                            p = Path(m.group("p"))
                            if p.is_absolute():
                                out.append(p)
        return out

    def _nss_modules(self) -> list[Path]:
        """Dò ngược NSS DB (người dùng ĐÃ TỰ NẠP module theo readme của CA)."""
        out: list[Path] = []
        dbdirs = [Path.home() / ".pki" / "nssdb"]
        ff = Path.home() / ".mozilla" / "firefox"
        if ff.is_dir():
            dbdirs.extend(p for p in ff.glob("*") if p.is_dir())
        for db in dbdirs:
            if not db.is_dir():
                continue
            listing = self._run(["modutil", "-dbdir", f"sql:{db}", "-list"])
            if not listing:
                continue
            for m in re.finditer(
                r"library name:\s*(?P<p>\S+)", listing.decode("utf-8", "ignore")
            ):
                candidate = Path(m.group("p"))
                if candidate.is_absolute():
                    out.append(candidate)
        return out

    # -- Kiến trúc & cầu nối -------------------------------------------- #
    def check_binary_arch(self, path: Path) -> BinaryArch:
        """Đọc ELF header (EI_CLASS: 1=ELF32, 2=ELF64; e_machine cho họ CPU)."""
        return self._parse_elf_arch(path)

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

    def spawn_bridge_helper(self, lib_path: Path) -> "BridgeClient":
        from core.bridge.client import BridgeClient
        from core.errors import BridgeUnavailableError

        bridge_python = os.environ.get("VN_ESIGN_BRIDGE_PYTHON")
        launcher = os.environ.get("VN_ESIGN_BRIDGE_LAUNCHER")
        if not bridge_python:
            raise BridgeUnavailableError(
                "Cần Python đúng-arch cho helper nhưng chưa cấu hình.",
                detail=self.arch_bridge_hint(),
            )
        command = ([launcher] if launcher else []) + [bridge_python, "-m", "core.bridge.helper"]
        return BridgeClient(
            command, cwd=str(self._repo_root()), env=os.environ.copy(),
            name=f"linux-bridge:{lib_path.name}",
        )

    def arch_bridge_hint(self) -> str:
        return (
            ".so lệch arch/bitness với host.\n"
            "  • ELF32 x86 trên host x86_64 (vd. FPT fptca_v4.so): cài multilib i386:\n"
            "      sudo dpkg --add-architecture i386 && sudo apt install libc6:i386\n"
            "    rồi đặt VN_ESIGN_BRIDGE_PYTHON trỏ tới Python 32-bit.\n"
            "  • Khác họ CPU (x86_64 <-> arm64): cài emulator qemu-user (qemu-x86_64) "
            "hoặc box64, đặt VN_ESIGN_BRIDGE_PYTHON + VN_ESIGN_BRIDGE_LAUNCHER."
        )

    # -- Chẩn đoán ------------------------------------------------------ #
    def library_warnings(self, path: Path) -> list[str]:
        """Cảnh báo thiếu dependency (ldd '... => not found') — thường lib đời cũ."""
        proc = self._run_proc(["ldd", str(path)])
        if proc is None:
            return []
        missing = [
            line.split("=>")[0].strip()
            for line in proc.stdout.splitlines()
            if "not found" in line
        ]
        if missing:
            return [
                "Thiếu thư viện phụ thuộc (module đời cũ?): "
                + ", ".join(missing)
                + ". Cài các gói tương ứng hoặc dùng bản module mới hơn."
            ]
        return []

    def platform_notes(self) -> list[str]:
        notes: list[str] = []
        ready, _ = self.pcsc_backend_ready()
        if not ready or self._usb_present_but_no_reader():
            notes.append(self.udev_rules_hint())
        return notes

    def udev_rules_hint(self) -> str:
        return (
            "Nếu `lsusb` thấy token nhưng không có reader/slot (thiếu quyền udev), "
            "tạo /etc/udev/rules.d/99-vn-token.rules:\n\n"
            + _UDEV_RULES_CONTENT
            + "\nRồi: sudo udevadm control --reload-rules && sudo udevadm trigger\n"
            "và thêm user vào nhóm plugdev rồi ĐĂNG NHẬP LẠI:\n"
            "    sudo usermod -aG plugdev $USER"
        )

    def _usb_present_but_no_reader(self) -> bool:
        out = self._run(["lsusb"])
        if not (out and out.strip()):
            return False
        try:
            from smartcard.System import readers  # type: ignore[import-untyped]

            return len(readers()) == 0
        except Exception:  # noqa: BLE001
            return False

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
        if self._pcscd_running():
            return True, ""
        return False, (
            "Chưa truy cập được PC/SC (pcscd chưa chạy). Cài & bật:\n"
            "  sudo apt install pcscd libccid opensc && sudo systemctl enable --now pcscd\n"
            "  (Fedora/RHEL: sudo dnf install pcsc-lite ccid opensc && "
            "sudo systemctl enable --now pcscd)"
        )

    def _pcscd_running(self) -> bool:
        proc = self._run_proc(["pgrep", "-x", "pcscd"])
        if proc is not None and proc.returncode == 0 and proc.stdout.strip():
            return True
        proc = self._run_proc(["systemctl", "is-active", "pcscd"])
        return proc is not None and proc.stdout.strip() == "active"

    def certstore_fallback(self) -> list[FallbackCert]:
        """Xuất chứng thư từ NSS DB (~/.pki/nssdb) qua certutil (PEM -> DER).

        NSS DB là nơi Firefox/Chrome/middleware lưu chứng thư — có thể còn cert
        của token cả khi module PKCS#11 không dò ra. Tag ``LINUX_NSS`` + nickname
        để audit.
        """
        certs: list[FallbackCert] = []
        nssdb = Path.home() / ".pki" / "nssdb"
        if not nssdb.is_dir():
            return certs
        listing = self._run_proc(["certutil", "-d", f"sql:{nssdb}", "-L"])
        if listing is None or listing.returncode != 0:
            return certs
        for line in listing.stdout.splitlines()[4:]:
            parts = line.split()
            if not parts:
                continue
            nickname = line[: line.rfind(parts[-1])].strip()
            if not nickname:
                continue
            pem = self._run(["certutil", "-d", f"sql:{nssdb}", "-L", "-a", "-n", nickname])
            for der in _pem_to_der(pem.decode("utf-8", "ignore")):
                certs.append(
                    FallbackCert(der=der, source=FALLBACK_LINUX_NSS, origin=nickname)
                )
        return certs

    def nss_modules(self) -> list[str]:
        """Liệt kê PKCS#11 module đã đăng ký với NSS (``modutil -list``).

        Chỉ để CHẨN ĐOÁN. Trả rỗng nếu không có DB/modutil.
        """
        nssdb = Path.home() / ".pki" / "nssdb"
        if not nssdb.is_dir():
            return []
        proc = self._run_proc(["modutil", "-dbdir", f"sql:{nssdb}", "-list"])
        if proc is None or proc.returncode != 0:
            return []
        return [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]

    def enroll_module_to_nss(self, lib_path: Path, *, name: str = "VN eSign Token") -> str:
        """Trả LỆNH ``modutil -add`` để đăng ký module vào NSS (Firefox/Chrome).

        ⚠️ CHỈ IN RA / TRẢ VỀ lệnh — TUYỆT ĐỐI KHÔNG tự chạy khi chưa xin phép
        (sửa NSS DB của trình duyệt là thao tác có tác dụng phụ). Người dùng tự
        chạy sau khi đồng ý.
        """
        nssdb = Path.home() / ".pki" / "nssdb"
        return (
            f'modutil -dbdir sql:{nssdb} -add "{name}" '
            f'-libfile "{lib_path}"'
        )

    # -- Thư mục chuẩn & chạy nền --------------------------------------- #
    def config_dir(self) -> Path:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
        return Path(base) / "vn-esign-suite"

    def log_dir(self) -> Path:
        base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
        return Path(base) / "vn-esign-suite" / "logs"

    def service_install_hint(self) -> str:
        return (
            "Chạy daemon vn-esign dưới nền trên Linux:\n"
            "  • systemd user unit (mẫu trong packaging/linux/):\n"
            "      systemctl --user enable --now vn-esign.service\n"
            "  • Bảo đảm pcscd đang chạy. Service chỉ bind 127.0.0.1."
        )

    # -- Helper subprocess ---------------------------------------------- #
    @staticmethod
    def _run(cmd: list[str]) -> bytes:
        try:
            return subprocess.run(cmd, capture_output=True, timeout=15, check=False).stdout
        except (FileNotFoundError, OSError):
            return b""

    @staticmethod
    def _run_proc(cmd: list[str]) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(cmd, capture_output=True, timeout=15, check=False, text=True)
        except (FileNotFoundError, OSError):
            return None

    @staticmethod
    def _read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""


def _pem_to_der(pem_text: str) -> list[bytes]:
    import base64

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
