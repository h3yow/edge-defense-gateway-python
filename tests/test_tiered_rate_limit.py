"""分档限流：额度随信誉等级走，阈值确定、并发精确、响应可见档位与剩余。

覆盖场景：
- 默认装配下 normal 身份额度与旧行为一致；
- 等级变差 -> 下一次请求立即按更低档位判定（阈值边界确定）；
- 隔离身份直接拒绝且不占额度；
- 多线程并发打入同一身份时，分档计数不丢不重；
- 判定快照中可见本次档位（tier_level / limit / remaining）。
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from gateway.engine import DefenseEngine
from gateway.models import DenyReason, ReputationLevel, RequestContext, Rule
from gateway.rate_limiter import SlidingWindowRateLimiter
from gateway.reputation import ReputationManager
from gateway.rules import RuleEngine
from gateway.service import default_level_limits

logging.basicConfig(level=logging.INFO)

TIERS = {
    ReputationLevel.NORMAL: 8,
    ReputationLevel.SUSPECT: 4,
    ReputationLevel.RESTRICTED: 2,
}


class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self.t

    def advance(self, dt: float) -> None:
        with self._lock:
            self.t += dt


def _engine(tmp_path, limit=8, window=1000.0, tiers=None):
    clock = FakeClock()
    rules = RuleEngine(
        [Rule(rule_id="block-admin", path_prefix="/admin", description="后台探测")]
    )
    rep = ReputationManager(state_path=str(tmp_path / "rep.json"))
    rl = SlidingWindowRateLimiter(limit=limit, window_seconds=window)
    eng = DefenseEngine(rules, rep, rl, clock=clock, level_limits=tiers or TIERS)
    return eng, clock, rep, rl


def _hit(eng, client, path="/home"):
    return eng.evaluate(RequestContext(client_id=client, path=path))


def test_default_tiers_keep_normal_quota_unchanged():
    """场景：默认分档参数。结论：normal=limit，suspect=limit/2，restricted=limit/4。"""
    tiers = default_level_limits(10)
    logging.info("default tiers=%s", {k.value: v for k, v in tiers.items()})
    assert tiers[ReputationLevel.NORMAL] == 10  # 与旧行为一致
    assert tiers[ReputationLevel.SUSPECT] == 5
    assert tiers[ReputationLevel.RESTRICTED] == 2
    assert default_level_limits(1)[ReputationLevel.RESTRICTED] == 1  # 至少为 1


def test_normal_identity_matches_legacy_behavior(tmp_path):
    """场景：normal 身份打满额度。结论：第 limit 次放行、第 limit+1 次拒绝，与旧限流一致。"""
    eng, clock, _, _ = _engine(tmp_path)
    results = [_hit(eng, "c1").allowed for _ in range(10)]
    snap = _hit(eng, "c1").snapshot["rate_limit"]
    logging.info("normal results=%s snapshot=%s", results, snap)
    assert results == [True] * 8 + [False] * 2
    assert snap["tier_level"] == "normal"
    assert snap["limit"] == 8 and snap["remaining"] == 0


def test_level_drop_takes_effect_on_next_request(tmp_path):
    """场景：等级在请求之间变差。结论：下一次请求立即按新档位判定，边界确定。"""
    eng, clock, rep, _ = _engine(tmp_path)
    # normal 档（8）先用掉 4 个额度
    assert all(_hit(eng, "c1").allowed for _ in range(4))
    # 1 次违规 -> SUSPECT（档 4）：窗口内已用 4，立即触顶
    rep.record_violation("c1", "rule_matched", clock())
    d = _hit(eng, "c1")
    logging.info("suspect decision=%s snapshot=%s", d.reason, d.snapshot["rate_limit"])
    assert d.allowed is False and d.reason is DenyReason.RATE_LIMITED
    assert d.snapshot["rate_limit"]["tier_level"] == "suspect"
    assert d.snapshot["rate_limit"]["limit"] == 4
    assert d.snapshot["rate_limit"]["remaining"] == 0
    # 再违规 -> RESTRICTED（档 2）：更低档同样立即生效
    rep.record_violation("c1", "rule_matched", clock())
    d2 = _hit(eng, "c1")
    logging.info("restricted decision=%s snapshot=%s", d2.reason, d2.snapshot["rate_limit"])
    assert d2.reason is DenyReason.RATE_LIMITED
    assert d2.snapshot["rate_limit"]["tier_level"] == "restricted"
    assert d2.snapshot["rate_limit"]["limit"] == 2


def test_tier_threshold_boundary_is_deterministic(tmp_path):
    """场景：suspect 档（4）边界。结论：恰好第 4 次放行、第 5 次拒绝。"""
    eng, clock, rep, _ = _engine(tmp_path)
    rep.record_violation("c1", "rule_matched", clock())  # -> SUSPECT
    results = [_hit(eng, "c1").allowed for _ in range(6)]
    logging.info("suspect boundary results=%s", results)
    assert results == [True, True, True, True, False, False]


def test_quarantined_identity_denied_without_consuming_quota(tmp_path):
    """场景：隔离身份。结论：直接 quarantined 拒绝，限流额度分毫不动。"""
    eng, clock, rep, rl = _engine(tmp_path)
    for t in (0.0, 0.1, 0.2):
        rep.record_violation("c1", "rule_matched", t)
    d = _hit(eng, "c1")
    logging.info("quarantined decision=%s remaining=%s", d.reason, rl.remaining("c1", clock()))
    assert d.reason is DenyReason.QUARANTINED
    assert rl.remaining("c1", clock()) == 8  # 未消耗任何额度


def test_concurrent_requests_count_exactly_per_tier(tmp_path):
    """场景：300 并发打到 suspect 档（4->50 放大验证）。结论：恰好 50 放行、250 拒绝。"""
    tiers = {ReputationLevel.SUSPECT: 50}
    eng, clock, rep, rl = _engine(tmp_path, limit=1000, tiers=tiers)
    rep.record_violation("hot", "rule_matched", clock())  # -> SUSPECT，档 50
    outcomes: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        d = _hit(eng, "hot")
        with lock:
            outcomes.append(d.allowed)

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda _: worker(), range(300)))

    snap = rl.snapshot("hot", clock(), limit=50)
    logging.info("concurrent allowed=%d denied=%d snapshot=%s",
                 sum(outcomes), len(outcomes) - sum(outcomes), snap)
    assert sum(outcomes) == 50
    assert len(outcomes) - sum(outcomes) == 250
    assert snap["used"] == 50 and snap["remaining"] == 0
