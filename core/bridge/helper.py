"""Phía SERVER của bridge — chạy trong tiến trình helper CÙNG ARCH với module.

Chạy: ``python -m core.bridge.helper`` (hoặc .exe 32-bit trên Windows, hoặc
``arch -x86_64 <python> -m core.bridge.helper`` dưới Rosetta trên macOS).

Ở giai đoạn scaffolding này CHƯA có logic đọc token — helper mới hỗ trợ
``ping`` (báo cáo arch/bits để host kiểm chứng cầu nối). Method ``enumerate``
là chỗ dành sẵn cho giai đoạn đọc token (PROMPT sau), hiện trả lỗi rõ ràng.
"""

from __future__ import annotations

import importlib.util
import os
import platform
import sys
from typing import Any, TextIO

from .protocol import SHUTDOWN, decode, encode, make_error, make_result


def _env_info() -> dict[str, Any]:
    """Thông tin môi trường helper để host kiểm chứng đúng arch."""
    return {
        "machine": platform.machine(),
        "bits": 64 if sys.maxsize > 2**32 else 32,
        "pykcs11": importlib.util.find_spec("PyKCS11") is not None,
        "pid": os.getpid(),
    }


def _dispatch(method: str, params: dict[str, Any]) -> Any:
    """Định tuyến một lời gọi RPC."""
    if method == "ping":
        return {"pong": True, **_env_info()}
    if method == "shutdown":
        return SHUTDOWN
    if method == "enumerate":
        # Chỗ dành sẵn cho giai đoạn đọc token (chưa hiện thực ở prompt này).
        raise NotImplementedError(
            "enumerate: logic đọc token sẽ được hiện thực ở giai đoạn sau."
        )
    raise ValueError(f"Phương thức RPC không hỗ trợ: {method!r}")


def serve(stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
    """Vòng lặp server: đọc request JSON từ stdin, ghi response ra stdout.

    Mọi ngoại lệ được gói thành response lỗi (không làm sập helper giữa chừng).
    Kết thúc khi EOF hoặc nhận method ``shutdown``.
    """
    inp = stdin or sys.stdin
    out = stdout or sys.stdout
    for line in inp:
        req = decode(line)
        if req is None:
            continue
        rid = req.get("id")
        method = req.get("method", "")
        params = req.get("params") or {}
        try:
            result = _dispatch(method, params)
            if result is SHUTDOWN:
                out.write(encode(make_result(rid, {"bye": True})))
                out.flush()
                return
            out.write(encode(make_result(rid, result)))
        except Exception as exc:  # noqa: BLE001 - gói lỗi, không sập helper
            out.write(encode(make_error(rid, "helper_error", str(exc))))
        out.flush()


def main(argv: list[str] | None = None) -> int:
    _ = argv
    serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
