"""限流器：阈值边界确定性、窗口恢复、并发不丢不重。"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from gateway.rate_limiter import SlidingWindowRateLimiter

logging.basicConfig(level=logging.INFO)


def test_threshold_boundary_is_deterministic():
    rl = SlidingWindowRateLimiter(limit=3, window_seconds=1.0)
    results = [rl.check("c1", now=0.0) for _ in range(5)]
    snap = rl.snapshot("c1", now=0.0)
    logging.info("boundary results=%s snapshot=%s", results, snap)
    assert results == [True, True, True, False, False]
    assert snap["used"] == 3 and snap["remaining"] == 0


def test_quota_recovers_after_window_expiry():
    rl = SlidingWindowRateLimiter(limit=2, window_seconds=1.0)
    assert rl.check("c1", 0.0) is True
    assert rl.check("c1", 0.5) is True
    assert rl.check("c1", 0.9) is False
    # t=1.0：0.0 恰好落在左边界，已过期淘汰
    assert rl.remaining("c1", 1.0) == 1
    assert rl.check("c1", 1.0) is True
    assert rl.check("c1", 1.1) is False
    # t=2.0：窗口内仅 1.1 之后……实际上 0.5/1.0 全部过期
    assert rl.check("c2", 0.0) is True  # 不同身份互不影响
    assert rl.remaining("c1", 2.0) == 2
    assert rl.check("c1", 2.0) is True
    logging.info("recovery snapshot=%s", rl.snapshot("c1", 2.0))


def test_concurrent_checks_count_exactly():
    rl = SlidingWindowRateLimiter(limit=500, window_seconds=10.0)
    allowed = []
    lock = threading.Lock()

    def worker() -> None:
        ok = rl.check("hot", now=1.0)
        with lock:
            allowed.append(ok)

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda _: worker(), range(1000)))

    snap = rl.snapshot("hot", now=1.0)
    logging.info("concurrent allowed=%d denied=%d snapshot=%s",
                 sum(allowed), len(allowed) - sum(allowed), snap)
    assert sum(allowed) == 500
    assert len(allowed) - sum(allowed) == 500
    assert snap["used"] == 500


def test_per_identity_isolation():
    rl = SlidingWindowRateLimiter(limit=1, window_seconds=1.0)
    assert rl.check("a", 0.0) is True
    assert rl.check("b", 0.0) is True
    assert rl.check("a", 0.1) is False
    assert rl.check("b", 0.1) is False
