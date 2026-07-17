"""Test daemon FastAPI qua TestClient."""

from __future__ import annotations

import base64

from fastapi.testclient import TestClient

from service.main import create_app
from tests.certs import make_chain


def _client() -> TestClient:
    return TestClient(create_app())


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
    # Kho tin cậy mặc định rỗng -> UNTRUSTED, kèm lý do tiếng Việt.
    assert body["status"] == "untrusted"
    assert body["reasons_vi"]
