"""Vòng đời & hạ tầng chạy nền của daemon — ĐA NỀN TẢNG qua adapter.

Gồm:
    * :func:`configure_logging` — log XOAY VÒNG vào ``adapter.log_dir()``, có bộ
      lọc CHE PIN (không bao giờ ghi PIN ra log).
    * :func:`find_free_port` — dùng cổng cố định nếu trống, nếu bận thì tự dò
      cổng ephemeral (chỉ trên loopback).
    * :func:`write_state_file` / :func:`read_state_file` — ghi ``service.json``
      (host/port/pid) vào ``config_dir`` để tầng web tìm thấy daemon.
    * :class:`PcscEventsSource` — nguồn sự kiện cắm/rút thẻ (bọc PCSCProbe).

⭐ TUYỆT ĐỐI KHÔNG tải/chạy installer bên thứ ba ở đây — daemon chỉ PHÁT HIỆN &
HƯỚNG DẪN. Ra mạng chỉ được phép cho: đồng bộ kho tin cậy (rootca.gov.vn) và
CRL/OCSP/TSA — và đều nằm ở module khác, có xác nhận người vận hành.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, cast

LOGGER_NAME = "vn_esign.service"
STATE_FILENAME = "service.json"


# --------------------------------------------------------------------------- #
# Logging: xoay vòng + che PIN                                                 #
# --------------------------------------------------------------------------- #
class PinRedactionFilter(logging.Filter):
    """Che mọi thứ trông giống PIN trong log (phòng thủ chiều sâu)."""

    _PATTERNS = (
        re.compile(r'("?pin"?\s*[:=]\s*")([^"]*)(")', re.IGNORECASE),
        re.compile(r'("?pin"?\s*[:=]\s*)([^\s",}]+)', re.IGNORECASE),
    )

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001
            return True
        redacted = msg
        for pat in self._PATTERNS:
            redacted = pat.sub(lambda m: m.group(1) + "***" + (m.group(3) if m.lastindex and m.lastindex >= 3 else ""), redacted)
        if redacted != msg:
            record.msg = redacted
            record.args = ()
        return True


def configure_logging(log_dir: Path, *, level: int = logging.INFO) -> logging.Logger:
    """Thiết lập logger xoay vòng cho daemon (idempotent)."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    if any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
        return logger
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = RotatingFileHandler(
            log_dir / "service.log", maxBytes=1_000_000, backupCount=5, encoding="utf-8"
        )
    except OSError:
        handler = logging.NullHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler.addFilter(PinRedactionFilter())
    logger.addHandler(handler)
    return logger


# --------------------------------------------------------------------------- #
# Cổng loopback                                                                #
# --------------------------------------------------------------------------- #
def find_free_port(preferred: int, host: str = "127.0.0.1") -> int:
    """Trả ``preferred`` nếu bind được, ngược lại một cổng ephemeral trống.

    Chỉ thử trên ``host`` loopback. Ném ``OSError`` nếu không cấp phát được cổng.
    """
    for candidate in (preferred, 0):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((host, candidate))
                return int(sock.getsockname()[1])
        except OSError:
            continue
    raise OSError("Không cấp phát được cổng loopback để bind daemon.")


# --------------------------------------------------------------------------- #
# File trạng thái (để web định vị daemon)                                      #
# --------------------------------------------------------------------------- #
def state_file_path(config_dir: Path) -> Path:
    return config_dir / STATE_FILENAME


def write_state_file(config_dir: Path, *, host: str, port: int, version: str) -> Path:
    """Ghi ``service.json`` (host/port/pid) — ghi tạm rồi đổi tên (nguyên tử)."""
    path = state_file_path(config_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "host": host,
        "port": port,
        "pid": os.getpid(),
        "version": version,
        "url": f"http://{host}:{port}",
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)  # chỉ chủ sở hữu đọc được
    except OSError:
        pass
    return path


def read_state_file(config_dir: Path) -> dict[str, Any] | None:
    try:
        return cast(
            "dict[str, Any]",
            json.loads(state_file_path(config_dir).read_text(encoding="utf-8")),
        )
    except (OSError, ValueError):
        return None


def remove_state_file(config_dir: Path) -> None:
    try:
        state_file_path(config_dir).unlink()
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Nguồn sự kiện cắm/rút thẻ (bọc PCSCProbe cho WebSocket /events)               #
# --------------------------------------------------------------------------- #
class PcscEventsSource:
    """Sinh sự kiện cắm/rút bằng poll trạng thái PC/SC (không cần luồng nền)."""

    def __init__(self, probe: Any) -> None:
        self._probe = probe
        self._state: dict[str, str] = {}

    def readers(self) -> list[str]:
        try:
            return list(self._probe.list_readers())
        except Exception:  # noqa: BLE001 - PC/SC chưa sẵn sàng -> rỗng
            return []

    def poll(self) -> list[dict[str, str]]:
        try:
            events, self._state = self._probe.poll_diff(self._state)
            return cast("list[dict[str, str]]", events)
        except Exception:  # noqa: BLE001
            return []


__all__ = [
    "LOGGER_NAME",
    "PinRedactionFilter",
    "configure_logging",
    "find_free_port",
    "state_file_path",
    "write_state_file",
    "read_state_file",
    "remove_state_file",
    "PcscEventsSource",
]
