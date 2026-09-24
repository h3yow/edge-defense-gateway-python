"""Rule matching and sliding-window limiter: boundaries, expiry, concurrency."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from itertools import chain

from edge_gateway.clock import FakeClock
from edge_gateway.models import RequestContext, Rule
from edge_gateway.ratelimit import SlidingWindowRateLimiter
from edge_gateway.rules import RuleEngine

logger = logging.getLogger(__name__)


def req(path: str = "/hello", identity: str = "u1", **kw) -> RequestContext:
    return RequestContext(identity=identity, path=path, **kw)


def test_rules_hit_and_no_false_positive():
    engine = RuleEngine([
        Rule("bad", "contains evil", lambda r: "evil" in r.path),
    ])
    hit = engine.match(req("/evil/path"))
    clean = engine.match(req("/healthy/resource"))
    logger.info("rule hit=%s clean=%s", hit, clean)
    assert hit is not None and hit.rule_id == "bad"
    assert clean is None  # normal traffic must not be误伤


def test_rules_first_match_wins_in_order():
    engine = RuleEngine([
        Rule("first", "first", lambda r: True),
        Rule("second", "second", lambda r: True),
    ])
    assert engine.match(req()).rule_id == "first"


def test_ratelimit_boundary_exact_limit_then_deny():
    clock = FakeClock()
    rl = SlidingWindowRateLimiter(limit=3, window_seconds=10.0, clock=clock)
    results = [rl.check_and_consume("u") for _ in range(4)]
    logger.info("boundary results: %s", [r[0] for r in results])
    assert [ok for ok, _ in results] == [True, True, True, False]
    deny_info = results[3][1]
    assert deny_info["used"] == 3 and deny_info["remaining"] == 0
    assert deny_info["retry_after"] > 0


def test_ratelimit_window_expiry_restores_quota():
    clock = FakeClock()
    rl = SlidingWindowRateLimiter(limit=2, window_seconds=5.0, clock=clock)
    assert rl.check_and_consume("u")[0] is True
    assert rl.check_and_consume("u")[0] is True
    assert rl.check_and_consume("u")[0] is False
    # Boundary: exactly at window end, the oldest hit (t) is <= now-w => evicted.
    clock.advance(5.0)
    allowed, info = rl.check_and_consume("u")
    logger.info("after expiry allowed=%s info=%s", allowed, info)
    assert allowed is True and info["used"] == 1


def test_ratelimit_identities_isolated():
    clock = FakeClock()
    rl = SlidingWindowRateLimiter(limit=1, window_seconds=10.0, clock=clock)
    assert rl.check_and_consume("a")[0] is True
    assert rl.check_and_consume("b")[0] is True
    assert rl.check_and_consume("a")[0] is False
    assert rl.check_and_consume("b")[0] is False


def test_ratelimit_concurrent_counting_exact_no_lost_or_duplicate():
    rl = SlidingWindowRateLimiter(limit=100, window_seconds=60.0)
    n_threads, per_thread = 20, 10

    def worker(_):
        return [rl.check_and_consume("bulk")[0] for _ in range(per_thread)]

    with ThreadPoolExecutor(max_workers=n_threads) as pool:
        all_results = list(chain.from_iterable(pool.map(worker, range(n_threads))))

    allowed = sum(all_results)
    denied = len(all_results) - allowed
    snapshot = rl.snapshot("bulk")
    logger.info("concurrent allowed=%d denied=%d snapshot=%s", allowed, denied, snapshot)
    assert allowed == 100
    assert denied == 100
    assert snapshot["used"] == 100  # no lost or duplicated hits
