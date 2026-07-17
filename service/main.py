"""Điểm vào tương thích ngược — uỷ quyền cho :mod:`service.app`.

Ứng dụng chính (đầy đủ endpoint + middleware bảo mật) nằm ở ``service/app.py``.
File này giữ lại ``create_app`` / ``app`` / ``main`` để lệnh cũ vẫn chạy:

    python -m service.main
    uvicorn service.main:app --host 127.0.0.1 --port 8787
"""

from __future__ import annotations

from service.app import DEFAULT_HOST, DEFAULT_PORT, app, create_app, run

__all__ = ["create_app", "app", "main", "DEFAULT_HOST", "DEFAULT_PORT"]


def main() -> None:
    """Chạy daemon (bind loopback, tự dò cổng, ghi file trạng thái)."""
    run()


if __name__ == "__main__":
    main()
