"""信誉分档限流：档位阈值确定性、等级变化即时换档、隔离不占额度、并发精确计数、快照可解释。

默认分档（service.build_engine）：normal=10/s（与老行为一致）、suspect=5/s、
restricted=2/s、quarantined=0（直接拒绝）。本文件多数用例直接构造引擎，
便于精确控制各档阈值与时间。
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from gateway.engine import DefenseEngine
from gateway.models import DenyReason, ReputationLevel, RequestContext, Rule
from gateway.rate_limiter import SlidingWindowRateLimiter
from gateway.reputation import ReputationManager
from gateway.rules import RuleEngine
from gateway.service import build_engine

logging.basicConfig(level=logging.INFO)


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


def _engine(tmp_path, tiers=None, limit=100, window=1.0, **rep_kw):
    clock = FakeClock()
    rules = RuleEngine(
        [Rule(rule_id="block-admin", path_prefix="/admin", description="后台探测")]
    )
    rep = ReputationManager(
        state_path=str(tmp_path / "rep.json"),
        base_quarantine_seconds=10.0,
        recover_step_seconds=5.0,
        good_bonus_seconds=1.0,
        good_bonus_interval_seconds=0.5,
        **rep_kw,
    )
    rl = SlidingWindowRateLimiter(limit=limit, window_seconds=window)
    if tiers is None:
        tiers = {
            ReputationLevel.NORMAL: limit,
            ReputationLevel.SUSPECT: 5,
            ReputationLevel.RESTRICTED: 2,
            ReputationLevel.QUARANTINED: 0,
        }
    eng = DefenseEngine(rules, rep, rl, clock=clock, tier_limits=tiers)
    return eng, clock, rep, rl


def test_default_config_normal_quota_unchanged(tmp_path):
    """默认装配下正常身份额度仍是 10 次/1s：老行为不变。"""
    clock = FakeClock()
    eng = build_engine(
        state_path=str(tmp_path / "rep.json"),
        rules=[Rule(rule_id="x", path_prefix="/no-such-prefix")],
        clock=clock,
    )
    decisions = [
        eng.evaluate(RequestContext(client_id="plain", path="/home"))
        for _ in range(12)
    ]
    allowed = [d.allowed for d in decisions]
    last = decisions[-1]
    logging.info(
        "default-tier allowed=%d denied=%d last_rate_snapshot=%s",
        sum(allowed), len(allowed) - sum(allowed), last.snapshot["rate_limit"],
    )
    assert allowed == [True] * 10 + [False] * 2
    assert decisions[-1].reason is DenyReason.RATE_LIMITED
    assert last.snapshot["rate_limit"]["tier"] == "normal"
    assert last.snapshot["rate_limit"]["limit"] == 10


def test_each_tier_threshold_boundary_is_deterministic(tmp_path):
    """suspect=5：第 5 次放行、第 6 次拒绝；restricted=2：第 2 次放行、第 3 次拒绝。"""
    eng, _, rep, _ = _engine(tmp_path)
    rep.record_violation("s1", "rule", 0.0)  # -> suspect
    rep.record_violation("r1", "rule", 0.0)
    rep.record_violation("r1", "rule", 0.1)  # -> restricted

    s_results = [
        eng.evaluate(RequestContext(client_id="s1", path="/home")).allowed
        for _ in range(7)
    ]
    r_results = [
        eng.evaluate(RequestContext(client_id="r1", path="/home")).allowed
        for _ in range(4)
    ]
    logging.info("suspect results=%s restricted results=%s", s_results, r_results)
    assert s_results == [True] * 5 + [False] * 2
    assert r_results == [True] * 2 + [False] * 2


def test_tier_change_applies_at_next_request(tmp_path):
    """窗口内额度历史共用：等级一变，下一次请求立即按新档判定，无需等窗口滑动。"""
    eng, clock, rep, _ = _engine(tmp_path, limit=100)
    # 正常身份先用掉 4 次（normal 档 100，本可继续）
    for _ in range(4):
        assert eng.evaluate(RequestContext(client_id="c", path="/home")).allowed
    # 外部事件使其升级为 suspect（档 5）：剩余只有 1
    rep.record_violation("c", "external_signal", clock())
    d5 = eng.evaluate(RequestContext(client_id="c", path="/home"))
    d6 = eng.evaluate(RequestContext(client_id="c", path="/home"))
    logging.info(
        "after tier change d5.allowed=%s d6.reason=%s snapshot=%s",
        d5.allowed, d6.reason, d6.snapshot["rate_limit"],
    )
    assert d5.allowed is True
    assert d5.snapshot["rate_limit"]["tier"] == "suspect"
    assert d6.allowed is False
    assert d6.reason is DenyReason.RATE_LIMITED
    # 快照能看出档位与剩余额度
    assert d6.snapshot["rate_limit"] == {
        "client_id": "c",
        "limit": 5,
        "window_seconds": 1.0,
        "used": 5,
        "remaining": 0,
        "timestamps": d6.snapshot["rate_limit"]["timestamps"],
        "tier": "suspect",
    }


def test_quarantine_denies_directly_and_consumes_no_quota(tmp_path):
    """隔离身份直接拒绝，且不占用任何限流额度（各档均如此）。"""
    eng, clock, _, rl = _engine(tmp_path, limit=100)
    for t in (0.0, 1.0, 2.0):
        clock.t = t
        eng.evaluate(RequestContext(client_id="evil", path="/admin"))
    # 已隔离：正常路径一律 quarantined
    decisions = [
        eng.evaluate(RequestContext(client_id="evil", path="/home"))
        for _ in range(5)
    ]
    assert all(d.reason is DenyReason.QUARANTINED for d in decisions)
    # 限流窗口一次都没有登记（规则命中在维度 1、隔离在维度 2，都到不了维度 3）
    assert rl.snapshot("evil", clock(), limit=100)["used"] == 0
    snap = decisions[-1].snapshot["rate_limit"]
    logging.info("quarantined rate snapshot=%s", snap)
    assert snap["tier"] == "quarantined"
    assert snap["used"] == 0


def test_concurrent_tiered_checks_count_exactly(tmp_path):
    """同一档位下多入口并发：放行数严格等于档位阈值，计数不丢不重。"""
    eng, _, rep, _ = _engine(
        tmp_path,
        tiers={
            ReputationLevel.NORMAL: 100,
            ReputationLevel.SUSPECT: 100,
            ReputationLevel.RESTRICTED: 100,
            ReputationLevel.QUARANTINED: 0,
        },
        limit=100,
        window=10.0,
    )
    # 直接置为 restricted：两次违规（不进隔离）
    rep.record_violation("hot", "rule", 0.0)
    rep.record_violation("hot", "rule", 0.1)
    assert rep.get_level("hot", 0.1) is ReputationLevel.RESTRICTED

    outcomes: list[tuple[bool, DenyReason | None]] = []
    lock = threading.Lock()

    def worker() -> None:
        d = eng.evaluate(RequestContext(client_id="hot", path="/home"))
        with lock:
            outcomes.append((d.allowed, d.reason))

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda _: worker(), range(500)))

    allowed = sum(1 for a, _ in outcomes if a)
    denied = [(r) for _, r in outcomes if r is DenyReason.RATE_LIMITED]
    logging.info("tiered concurrent allowed=%d rate_limited=%d", allowed, len(denied))
    assert allowed == 100
    assert len(denied) == 400
    assert len(outcomes) == 500


def test_custom_tier_limits_are_configurable(tmp_path):
    """自定义分档表立即生效；未列出的档位回落到限流器统一阈值。"""
    clock = FakeClock()
    rep = ReputationManager(state_path=str(tmp_path / "rep.json"))
    rl = SlidingWindowRateLimiter(limit=100, window_seconds=1.0)
    eng = DefenseEngine(
        RuleEngine([]), rep, rl, clock=clock,
        tier_limits={ReputationLevel.SUSPECT: 1},
    )
    rep.record_violation("c", "rule", 0.0)  # suspect
    assert eng.evaluate(RequestContext(client_id="c", path="/home")).allowed
    d2 = eng.evaluate(RequestContext(client_id="c", path="/home"))
    assert d2.allowed is False and d2.reason is DenyReason.RATE_LIMITED
    # normal 档未配置 -> 回落到 limiter.limit=100
    assert eng.evaluate(RequestContext(client_id="other", path="/home")).allowed


def test_tiering_disabled_falls_back_to_flat_limit(tmp_path):
    """关闭分档时，所有非隔离等级共享统一阈值（老行为）。"""
    clock = FakeClock()
    rep = ReputationManager(state_path=str(tmp_path / "rep.json"))
    rl = SlidingWindowRateLimiter(limit=3, window_seconds=1.0)
    eng = DefenseEngine(RuleEngine([]), rep, rl, clock=clock, tier_limits=None)
    rep.record_violation("c", "rule", 0.0)  # suspect，但不分档
    results = [
        eng.evaluate(RequestContext(client_id="c", path="/home")).allowed
        for _ in range(4)
    ]
    logging.info("flat-limit results=%s", results)
    assert results == [True, True, True, False]
