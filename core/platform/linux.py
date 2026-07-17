"""Adapter Linux — TRỤC 1. p11-kit + NSS DB là fallback.

Lưu ý TRACK B (CA rebrand): trên Linux, FPT-CA phát hành module riêng
``/usr/lib/fptca_v4.so`` (gói dpkg ``fptca-4.0``, ĐÃ XÁC NHẬN). Việc quét chỉ
theo tên chip (Track A) sẽ KHÔNG bao giờ dò ra nó — vì vậy discovery Track B
(dữ liệu ``vendor_intel.yaml``) là bắt buộc. Bản thân adapter chỉ cung cấp
đường dẫn tìm kiếm; logic Track A/B nằm ở ``core/discovery.py``.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from .base import (
    BinaryArch,
    HostArch,
    PlatformAdapter,
    PlatformName,
    detect_host_arch,
)

if TYPE_CHECKING:
    from core.bridge.client import BridgeClient

_UDEV_RULES_CONTENT = (
    "# /etc/udev/rules.d/99-vn-esign-token.rules\n"
    "# Cấp quyền USB token ký số cho nhóm plugdev + uaccess.\n"
    'SUBSYSTEM=="usb", ACTION=="add", ENV{DEVTYPE}=="usb_device", '
    'MODE="0660", GROUP="plugdev", TAG+="uaccess"\n'
)


class LinuxAdapter(PlatformAdapter):
    """Hiện thực :class:`PlatformAdapter` cho Linux (x86_64 và arm64/aarch64)."""

    def name(self) -> PlatformName:
        return "linux"

    def host_arch(self) -> HostArch:
        return detect_host_arch(rosetta=False)

    # -- Định vị module ------------------------------------------------- #
    def library_search_paths(self) -> list[Path]:
        return [
            Path("/usr/lib"),
            Path("/usr/lib64"),
            Path("/usr/lib/x86_64-linux-gnu"),
            Path("/usr/lib/aarch64-linux-gnu"),
            Path("/usr/local/lib"),
            Path("/usr/lib/pkcs11"),
            Path("/usr/lib64/pkcs11"),
            Path("/opt"),
            Path("/lib"),
            Path("/lib64"),
            Path.home() / ".local/lib",
        ]

    def glob_patterns(self) -> list[str]:
        return ["*.so", "*.so.*"]

    def discover_from_system(self) -> list[Path]:
        """Ưu tiên ``p11-kit list-modules``; đọc *.module trong các thư mục cấu hình."""
        found: list[Path] = []
        out = self._run(["p11-kit", "list-modules"])
        if out:
            text = out.decode("utf-8", "ignore")
            for m in re.finditer(r"^\s*path:\s*(?P<p>\S+)", text, re.MULTILINE):
                found.append(Path(m.group("p")))
        for cfg_dir in (
            Path("/usr/share/p11-kit/modules"),
            Path("/etc/pkcs11/modules"),
        ):
            if cfg_dir.is_dir():
                for cfg in cfg_dir.iterdir():
                    if cfg.is_file():
                        found.extend(self._modules_from_config(cfg))
        return found

    @staticmethod
    def _modules_from_config(cfg: Path) -> list[Path]:
        out: list[Path] = []
        try:
            text = cfg.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return out
        for m in re.finditer(r"^\s*module:\s*(?P<p>\S+)", text, re.MULTILINE):
            p = Path(m.group("p"))
            if p.is_absolute():
                out.append(p)
        return out

    # -- Kiến trúc & cầu nối -------------------------------------------- #
    def check_binary_arch(self, path: Path) -> BinaryArch:
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
        command = ([launcher] if launcher else []) + [
            bridge_python, "-m", "core.bridge.helper",
        ]
        return BridgeClient(
            command, cwd=str(self._repo_root()), env=os.environ.copy(),
            name=f"linux-bridge:{lib_path.name}",
        )

    def arch_bridge_hint(self) -> str:
        return (
            ".so lệch arch/bitness với host (vd. x86_64 trên host arm64).\n"
            "  • Cài emulator: qemu-user (qemu-x86_64) hoặc box64.\n"
            "  • Đặt VN_ESIGN_BRIDGE_PYTHON (Python đúng-arch) và "
            "VN_ESIGN_BRIDGE_LAUNCHER (emulator)."
        )

    # -- Chẩn đoán ------------------------------------------------------ #
    def platform_notes(self) -> list[str]:
        notes: list[str] = []
        ready, _ = self.pcsc_backend_ready()
        if not ready or self._usb_present_but_no_reader():
            notes.append(self.udev_rules_hint())
        return notes

    def udev_rules_hint(self) -> str:
        return (
            "Nếu `lsusb` thấy token nhưng không có reader/slot (thiếu quyền udev), "
            "tạo /etc/udev/rules.d/99-vn-esign-token.rules:\n\n"
            + _UDEV_RULES_CONTENT
            + "\nRồi: sudo udevadm control --reload-rules && sudo udevadm trigger\n"
            "và: sudo usermod -aG plugdev $USER  (đăng nhập lại)"
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
            "  Debian/Ubuntu: sudo apt install pcscd libccid opensc && "
            "sudo systemctl enable --now pcscd\n"
            "  Fedora/RHEL:   sudo dnf install pcsc-lite ccid opensc && "
            "sudo systemctl enable --now pcscd"
        )

    def _pcscd_running(self) -> bool:
        proc = self._run_proc(["pgrep", "-x", "pcscd"])
        if proc is not None and proc.returncode == 0 and proc.stdout.strip():
            return True
        proc = self._run_proc(["systemctl", "is-active", "pcscd"])
        return proc is not None and proc.stdout.strip() == "active"

    def certstore_fallback(self) -> list[bytes]:
        certs: list[bytes] = []
        nssdb = Path.home() / ".pki" / "nssdb"
        if not nssdb.is_dir():
            return certs
        listing = self._run_proc(["certutil", "-L", "-d", f"sql:{nssdb}"])
        if listing is None or listing.returncode != 0:
            return certs
        for line in listing.stdout.splitlines()[4:]:
            parts = line.split()
            if not parts:
                continue
            nickname = line[: line.rfind(parts[-1])].strip()
            if not nickname:
                continue
            der = self._run(["certutil", "-L", "-d", f"sql:{nssdb}", "-n", nickname, "-r"])
            if der:
                certs.append(der)
        return certs

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
