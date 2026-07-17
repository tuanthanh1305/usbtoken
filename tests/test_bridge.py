"""Test arch bridge qua tiến trình con thật + serve() với StringIO."""

from __future__ import annotations

import sys

import pytest

from core.bridge import BridgeClient, BridgeError, serve


def _client() -> BridgeClient:
    return BridgeClient([sys.executable, "-m", "core.bridge.helper"], cwd=".", name="test")


def test_ping_roundtrip() -> None:
    c = _client()
    try:
        info = c.ping(timeout=10)
        assert info["pong"] is True
        assert info["bits"] in (32, 64)
        assert "machine" in info
    finally:
        c.close()


def test_enumerate_bad_module_errors() -> None:
    c = _client()
    try:
        # Module không nạp được -> lỗi lan qua RPC (helper KHÔNG sập).
        with pytest.raises(BridgeError):
            c.enumerate_tokens("/khong/ton/tai/module.so", timeout=10)
    finally:
        c.close()


def test_get_info_bad_module_returns_error_dict() -> None:
    c = _client()
    try:
        info = c.get_info("/khong/ton/tai/module.so", timeout=10)
        assert info["ok"] is False and info["error"]  # get_info không ném, trả dict
    finally:
        c.close()


def test_close_idempotent() -> None:
    c = _client()
    c.close()
    c.close()


def test_serve_ping_stringio() -> None:
    import io
    import json

    stdin = io.StringIO(
        json.dumps({"id": 1, "method": "ping", "params": {}}) + "\n"
        + json.dumps({"id": 2, "method": "shutdown", "params": {}}) + "\n"
    )
    stdout = io.StringIO()
    serve(stdin=stdin, stdout=stdout)
    lines = [ln for ln in stdout.getvalue().splitlines() if ln.strip()]
    assert json.loads(lines[0])["result"]["pong"] is True
    assert json.loads(lines[1])["result"]["bye"] is True
