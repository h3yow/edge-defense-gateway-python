"""Gateway integration: 3-dimension decisions, reasons, entries, recovery."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor

from edge_gateway.clock import FakeClock
from edge_gateway.config import build_default_rules
from edge_gateway.gateway import DefenseGateway
from edge_gateway.models import DenyReason, RequestContext
from edge_gateway.reputation import ReputationManager
from edge_gateway.rules import RuleEngine
from edge_gateway.store import InMemoryStore, JsonFileStore

logger = logging.getLogger(__name__)


def build(tmp_path=None, clock=None, limit=5, window=10.0, quar=30.0, cool=15.0):
    clock = clock or FakeClock()
    if tmp_path is None:
        store = InMemoryStore()
    else:
        store = JsonFileStore(tmp_path / "state.json", tmp_path / "audit.jsonl")
    reputation = ReputationManager(
        store=store, clock=clock,
        quarantine_seconds=quar, recovery_cooldown_seconds=cool,
    )
    return DefenseGateway(
        rule_engine=RuleEngine(build_default_rules()),
        reputation=reputation,
        store=store,
        clock=clock,
        base_limit=limit,
        window_seconds=window,
    ), clock, store


def ctx(path="/ping", identity="u1", entrypoint="api", **kw):
    return RequestContext(identity=identity, path=path, entrypoint=entrypoint, **kw)


def test_clean_traffic_is_allowed_with_explanation():
    gw, _, _ = build()
    d = gw.inspect(ctx("/healthy", identity="good"))
    logger.info("clean decision=%s", d.to_dict())
    assert d.allowed and d.reason is None
    assert d.detail["rate"]["remaining"] == 4
    assert d.detail["client_state"]["level"] == "NORMAL"


def test_rule_violation_denied_and_distinguishes_from_rate_limit():
    gw, _, _ = build()
    d = gw.inspect(ctx("/etc/../passwd", identity="evil"))
    logger.info("rule decision=%s snapshot=%s", d.to_dict(), gw.client_snapshot("evil"))
    assert not d.allowed
    assert d.reason is DenyReason.RULE_VIOLATION
    assert d.detail["rule_id"] == "R001"


def test_admin_path_blocked_but_normal_api_paths_allowed():
    gw, _, _ = build()
    blocked = gw.inspect(ctx("/admin/users", identity="x"))
    also_blocked = gw.inspect(ctx("/v2/administration", identity="y"))  # no boundary match
    allowed = gw.inspect(ctx("/api/orders", identity="z"))
    logger.info("admin=%s lookalike=%s normal=%s",
                blocked.reason, also_blocked.reason, allowed.verdict)
    assert blocked.reason is DenyReason.RULE_VIOLATION
    assert also_blocked.allowed  # word-boundary regex must not over-match
    assert allowed.allowed


def test_rate_limited_reason_distinct_and_no_reputation_change():
    gw, _, _ = build(limit=3, window=10.0)
    decisions = [gw.inspect(ctx("/ping", identity="r")) for _ in range(4)]
    reasons = [d.reason for d in decisions]
    logger.info("reasons=%s snapshot=%s", reasons, gw.client_snapshot("r"))
    assert reasons[:3] == [None, None, None]
    assert reasons[3] is DenyReason.RATE_LIMITED
    # Rate limiting must not count as a rule violation.
    assert gw.client_snapshot("r")["total_violations"] == 0
    assert gw.client_snapshot("r")["level"] == "NORMAL"


def test_window_expiry_restores_quota_through_gateway():
    gw, clock, _ = build(limit=2, window=5.0)
    assert gw.inspect(ctx(identity="w")).allowed
    assert gw.inspect(ctx(identity="w")).allowed
    assert gw.inspect(ctx(identity="w")).reason is DenyReason.RATE_LIMITED
    clock.advance(5.0)
    d = gw.inspect(ctx(identity="w"))
    logger.info("post-expiry decision=%s", d.to_dict())
    assert d.allowed and d.detail["rate"]["used"] == 1


def test_quarantine_blocks_across_both_entries_until_release():
    gw, clock, _ = build(limit=100, window=10.0)
    # 4 violations from the api entry.
    for p in ("/../a", "/../b", "/../c", "/../d"):
        d = gw.inspect(ctx(p, identity="q", entrypoint="api"))
        assert d.reason is DenyReason.RULE_VIOLATION
    # While isolated, even clean requests via portal are denied with its reason.
    d_portal = gw.inspect(ctx("/portal-home", identity="q", entrypoint="portal"))
    d_api = gw.inspect(ctx("/api-home", identity="q", entrypoint="api"))
    logger.info("quarantined portal=%s api=%s", d_portal.reason, d_api.reason)
    assert d_portal.reason is DenyReason.IN_QUARANTINE
    assert d_api.reason is DenyReason.IN_QUARANTINE
    assert gw.client_snapshot("q")["is_quarantined"] is True

    clock.advance(30.0)  # released into recovery stage 0 (multiplier 0.25)
    d_rel = gw.inspect(ctx("/portal-home", identity="q", entrypoint="portal"))
    logger.info("after release decision=%s snapshot=%s",
                d_rel.to_dict(), gw.client_snapshot("q"))
    assert d_rel.allowed
    # floor(100 * 0.25) = 25 quota
    assert d_rel.detail["rate"]["limit"] == 25


def test_recovery_stage_quota_grows_then_normal():
    gw, clock, _ = build(limit=4, window=10.0)
    for _ in range(4):
        gw.inspect(ctx("/../x", identity="rec"))
    clock.advance(30.0)
    # stage 0: floor(4*0.25)=1
    d0 = gw.inspect(ctx("/ok", identity="rec"))
    assert d0.allowed and d0.detail["rate"]["limit"] == 1
    d0b = gw.inspect(ctx("/ok", identity="rec"))
    assert d0b.reason is DenyReason.RATE_LIMITED
    clock.advance(15.0)  # stage 1: floor(4*0.5)=2
    d1 = gw.inspect(ctx("/ok", identity="rec"))
    assert d1.allowed and d1.detail["rate"]["limit"] == 2
    clock.advance(15.0)  # fully recovered -> NORMAL
    d2 = gw.inspect(ctx("/ok", identity="rec"))
    assert d2.allowed and d2.detail["rate"]["limit"] == 4
    assert gw.client_snapshot("rec")["level"] == "NORMAL"


def test_concurrent_requests_deterministic_quota_consumption():
    gw, _, _ = build(limit=50, window=60.0)

    def worker(i):
        return gw.inspect(ctx("/ping", identity="conc", entrypoint="api" if i % 2 else "portal"))

    with ThreadPoolExecutor(max_workers=16) as pool:
        decisions = list(pool.map(worker, range(100)))
    allowed = sum(d.allowed for d in decisions)
    rate_limited = sum(d.reason is DenyReason.RATE_LIMITED for d in decisions)
    snapshot = gw.client_snapshot("conc")
    logger.info("concurrent allowed=%d rate_limited=%d window=%s",
                allowed, rate_limited, snapshot["rate_window"])
    assert allowed == 50
    assert rate_limited == 50
    assert snapshot["rate_window"]["used"] == 50
    assert snapshot["total_violations"] == 0


def test_state_reproduced_after_restart(tmp_path):
    gw1, clock, store = build(tmp_path, limit=10, window=10.0)
    for _ in range(4):
        gw1.inspect(ctx("/../x", identity="persist"))
    kinds_before = [e["kind"] for e in store.read_audit()]

    gw2, _, _ = build(tmp_path, clock=clock, limit=10, window=10.0)
    d = gw2.inspect(ctx("/anything", identity="persist"))
    kinds_after = [e["kind"] for e in store.read_audit()]
    logger.info("after restart reason=%s snapshot=%s audit=%s",
                d.reason, gw2.client_snapshot("persist"), kinds_after)
    assert d.reason is DenyReason.IN_QUARANTINE
    assert gw2.client_snapshot("persist")["quarantine_count"] == 1
    assert kinds_before == kinds_after[: len(kinds_before)]


def test_rule_violation_takes_priority_over_rate_limit():
    gw, _, _ = build(limit=2, window=60.0)
    gw.inspect(ctx("/ok", identity="prio"))
    gw.inspect(ctx("/ok", identity="prio"))
    assert gw.inspect(ctx("/ok", identity="prio")).reason is DenyReason.RATE_LIMITED
    # Quota exhausted, but this request also violates a rule: rule wins.
    d = gw.inspect(ctx("/%2e%2e/x", identity="prio"))
    logger.info("priority decision=%s", d.to_dict())
    assert d.reason is DenyReason.RULE_VIOLATION
    # The violating request still consumed no rate slot beyond the cap, and
    # reputation recorded exactly one violation.
    snap = gw.client_snapshot("prio")
    assert snap["total_violations"] == 1
    assert snap["rate_window"]["used"] == 2
