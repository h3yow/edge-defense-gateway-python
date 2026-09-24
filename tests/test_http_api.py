"""End-to-end HTTP checks through the FastAPI app (TestClient)."""

from __future__ import annotations

import logging

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

import main as service
from edge_gateway.config import build_inmemory_gateway
from edge_gateway.models import DenyReason

logger = logging.getLogger(__name__)


@pytest.fixture()
def client():
    # Replace the process-wide gateway with an isolated in-memory one so the
    # on-disk ./data state can never leak between test runs/cases.
    service.gateway = build_inmemory_gateway()
    with TestClient(service.app) as c:
        yield c


def test_root_ok(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_normal_request_allowed(client):
    r = client.get("/api/orders", headers={"X-Client-Id": "http-good"})
    body = r.json()
    logger.info("normal http body=%s", body)
    assert r.status_code == 200
    assert body["decision"]["verdict"] == "allow"


def test_rule_violation_returns_403(client):
    r = client.get("/api/%2e%2e/secret", headers={"X-Client-Id": "http-evil"})
    logger.info("rule violation status=%s body=%s", r.status_code, r.json())
    assert r.status_code == 403
    assert r.json()["reason"] == DenyReason.RULE_VIOLATION.value


def test_entries_share_state_rate_limit_429(client):
    headers = {"X-Client-Id": "http-shared"}
    codes = []
    # default policy: 5 / 10s; alternate entries to prove shared counters
    for i in range(6):
        entry = "api" if i % 2 == 0 else "portal"
        r = client.get(f"/{entry}/ping", headers=headers)
        codes.append(r.status_code)
    logger.info("shared-entry codes=%s", codes)
    assert codes == [200, 200, 200, 200, 200, 429]


def test_admin_client_snapshot_endpoint(client):
    client.get("/api/%2e%2e/x", headers={"X-Client-Id": "http-snap"})
    r = client.get("/admin/clients/http-snap")
    body = r.json()
    logger.info("snapshot endpoint body=%s", body)
    assert body["identity"] == "http-snap"
    assert body["total_violations"] == 1
    assert "rate_window" in body
