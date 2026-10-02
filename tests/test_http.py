"""HTTP 入口集成：三种结果的状态码与原因头可区分，判定依据随响应返回。"""

import logging

from fastapi.testclient import TestClient

from gateway.service import build_engine
from main import create_app

logging.basicConfig(level=logging.INFO)


def _client(tmp_path, limit=100, window=10.0):
    eng = build_engine(state_path=str(tmp_path / "rep.json"), limit=limit, window_seconds=window)
    return TestClient(create_app(eng)), eng


def test_normal_request_allowed(tmp_path):
    client, _ = _client(tmp_path)
    r = client.get("/gateway/home", headers={"X-Client-Id": "good"})
    logging.info("normal status=%s body=%s", r.status_code, r.json())
    assert r.status_code == 200
    assert r.json()["allowed"] is True
    assert "snapshot" in r.json()


def test_rule_hit_403_with_distinct_reason(tmp_path):
    client, _ = _client(tmp_path)
    r = client.get("/gateway/admin/console", headers={"X-Client-Id": "scanner"})
    logging.info("rule status=%s body=%s", r.status_code, r.json())
    assert r.status_code == 403
    assert r.headers["x-deny-reason"] == "rule_matched"
    assert r.json()["rule_id"] == "block-admin"


def test_rate_limit_429_distinct_from_403(tmp_path):
    client, _ = _client(tmp_path, limit=2, window=10.0)
    codes = [
        client.get("/gateway/home", headers={"X-Client-Id": "burst"}).status_code
        for _ in range(3)
    ]
    last = client.get("/gateway/home", headers={"X-Client-Id": "burst"})
    logging.info("codes=%s last reason=%s", codes, last.headers.get("x-deny-reason"))
    assert codes == [200, 200, 429]
    assert last.status_code == 429
    assert last.headers["x-deny-reason"] == "rate_limited"


def test_quarantine_blocks_normal_path_after_repeated_attacks(tmp_path):
    client, _ = _client(tmp_path)
    for _ in range(3):
        r = client.get("/gateway/admin", headers={"X-Client-Id": "evil"})
        assert r.headers["x-deny-reason"] == "rule_matched"
    r = client.get("/gateway/home", headers={"X-Client-Id": "evil"})
    logging.info("quarantined status=%s body=%s", r.status_code, r.json())
    assert r.status_code == 403
    assert r.headers["x-deny-reason"] == "quarantined"
    assert r.json()["snapshot"]["reputation"]["level"] == "quarantined"


def test_tiered_quota_visible_in_response(tmp_path):
    """默认装配：restricted 身份只有 2/s，响应快照能看到档位、阈值与剩余额度。"""
    eng = build_engine(state_path=str(tmp_path / "rep.json"))
    client = TestClient(create_app(eng))
    # 两次规则命中 -> restricted（不触发限流维度）
    for _ in range(2):
        client.get("/gateway/admin", headers={"X-Client-Id": "watch"})
    # 正常路径：restricted 档阈值 2
    r1 = client.get("/gateway/home", headers={"X-Client-Id": "watch"})
    r2 = client.get("/gateway/home", headers={"X-Client-Id": "watch"})
    r3 = client.get("/gateway/home", headers={"X-Client-Id": "watch"})
    rl1 = r1.json()["snapshot"]["rate_limit"]
    rl3 = r3.json()["snapshot"]["rate_limit"]
    logging.info("tier response r1=%s r3=%s", rl1, rl3)
    assert r1.status_code == 200 and r2.status_code == 200
    assert r3.status_code == 429
    assert r3.headers["x-deny-reason"] == "rate_limited"
    assert rl1["tier"] == "restricted"
    assert rl1["limit"] == 2 and rl1["remaining"] == 1
    assert rl3["tier"] == "restricted"
    assert rl3["remaining"] == 0


def test_normal_tier_quota_matches_legacy_default(tmp_path):
    """全新身份走 normal 档：默认装配 10/s，第 11 次 429（与老版本默认行为一致）。"""
    eng = build_engine(state_path=str(tmp_path / "rep.json"))
    client = TestClient(create_app(eng))
    codes = [
        client.get("/gateway/home", headers={"X-Client-Id": "plain"}).status_code
        for _ in range(11)
    ]
    logging.info("normal-tier codes=%s", codes)
    assert codes == [200] * 10 + [429]
