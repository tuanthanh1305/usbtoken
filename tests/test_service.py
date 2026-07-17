"""Test daemon FastAPI qua TestClient."""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from service.main import create_app
from tests.certs import make_chain


def _client() -> TestClient:
    # Daemon chỉ phục vụ loopback -> đặt base_url 127.0.0.1 để qua kiểm Host header.
    return TestClient(create_app(), base_url="http://127.0.0.1:8787")


def test_health() -> None:
    r = _client().get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_platform() -> None:
    r = _client().get("/api/platform")
    assert r.status_code == 200
    body = r.json()
    assert body["name"] in {"windows", "macos", "linux"}
    assert "rosetta" in body


def test_modules_list() -> None:
    r = _client().get("/api/modules")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_trust_status() -> None:
    r = _client().get("/api/trust/status")
    assert r.status_code == 200
    body = r.json()
    assert "trust_store" in body
    assert body["fully_configured"] is False  # Phụ lục chưa điền


def test_validate_untrusted_with_empty_store() -> None:
    _, _, leaf = make_chain()
    r = _client().post(
        "/api/validate",
        json={"certificate_b64": base64.b64encode(leaf.der).decode(), "allow_network": False},
    )
    assert r.status_code == 200
    body = r.json()
    # Kho tin cậy mặc định rỗng -> KHÔNG dựng được đường dẫn tin cậy -> INVALID
    # (fail-closed), kèm lý do tiếng Việt.
    assert body["status"] == "invalid"
    assert body["reasons_vi"]
