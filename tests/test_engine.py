"""判定编排集成：多维度一致判定、原因可区分、并发、隔离恢复。"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from gateway.engine import DefenseEngine
from gateway.models import DenyReason, ReputationLevel, RequestContext, Rule
from gateway.rate_limiter import SlidingWindowRateLimiter
from gateway.reputation import ReputationManager
from gateway.rules import RuleEngine

logging.basicConfig(level=logging.INFO)


class FakeClock:
    """可手动推进的时钟，保证阈值与恢复行为确定。"""

    def __init__(self) -> None:
        self.t = 0.0
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self.t

    def advance(self, dt: float) -> None:
        with self._lock:
            self.t += dt


def _engine(tmp_path, limit=3, window=1.0):
    clock = FakeClock()
    rules = RuleEngine(
        [Rule(rule_id="block-admin", path_prefix="/admin", description="后台探测")]
    )
    rep = ReputationManager(
        state_path=str(tmp_path / "rep.json"),
        base_quarantine_seconds=10.0,
        recover_step_seconds=5.0,
    )
    rl = SlidingWindowRateLimiter(limit=limit, window_seconds=window)
    eng = DefenseEngine(rules, rep, rl, clock=clock)
    return eng, clock, rep, rl


def test_normal_traffic_is_never_falsely_blocked(tmp_path):
    eng, _, rep, _ = _engine(tmp_path, limit=100)
    for i in range(50):
        d = eng.evaluate(RequestContext(client_id="good", path=f"/home/{i}"))
        assert d.allowed, d
    assert rep.get_level("good", 0.0) is ReputationLevel.NORMAL


def test_rule_hit_is_distinct_from_rate_limit(tmp_path):
    eng, _, _, _ = _engine(tmp_path, limit=100)
    d_rule = eng.evaluate(RequestContext(client_id="c1", path="/admin/x"))
    d_ok = eng.evaluate(RequestContext(client_id="c1", path="/home"))
    logging.info("rule decision=%s normal decision=%s", d_rule.reason, d_ok.allowed)
    assert d_rule.allowed is False
    assert d_rule.reason is DenyReason.RULE_MATCHED
    assert d_rule.rule_id == "block-admin"
    assert d_ok.allowed is True


def test_rate_limit_reason_distinct(tmp_path):
    eng, _, _, _ = _engine(tmp_path, limit=3, window=10.0)
    decisions = [
        eng.evaluate(RequestContext(client_id="burst", path="/home"))
        for _ in range(5)
    ]
    reasons = [d.reason for d in decisions]
    logging.info("burst reasons=%s last_snapshot=%s", reasons, decisions[-1].snapshot)
    assert reasons == [None, None, None, DenyReason.RATE_LIMITED, DenyReason.RATE_LIMITED]


def test_repeated_rule_hits_escalate_to_quarantine(tmp_path):
    eng, clock, rep, _ = _engine(tmp_path, limit=100)
    outcomes = []
    # 前 3 次：规则命中（第 3 次后进入隔离）
    for _ in range(3):
        outcomes.append(eng.evaluate(RequestContext(client_id="evil", path="/admin")))
    # 隔离期内即使访问正常路径也被拒绝，原因是 quarantined
    d_quar = eng.evaluate(RequestContext(client_id="evil", path="/home"))
    logging.info(
        "rule outcomes=%s quarantine=%s snapshot=%s",
        [d.reason for d in outcomes], d_quar.reason, d_quar.snapshot,
    )
    assert [d.reason for d in outcomes] == [DenyReason.RULE_MATCHED] * 3
    assert d_quar.reason is DenyReason.QUARANTINED
    assert rep.get_level("evil", clock()) is ReputationLevel.QUARANTINED

    # 隔离到期：先进入 RESTRICTED 观察期，正常路径放行，限流维度仍生效
    clock.advance(10.0)
    d_released = eng.evaluate(RequestContext(client_id="evil", path="/home"))
    logging.info("after release allowed=%s snapshot=%s",
                 d_released.allowed, d_released.snapshot)
    assert d_released.allowed is True
    assert rep.get_level("evil", clock()) is ReputationLevel.RESTRICTED

    # 继续无违规，逐级退避恢复（每级需要一个完整观察步 5s）
    clock.advance(5.0)
    assert rep.get_level("evil", clock()) is ReputationLevel.SUSPECT
    clock.advance(5.0)
    assert rep.get_level("evil", clock()) is ReputationLevel.NORMAL


def test_quarantine_does_not_consume_rate_quota(tmp_path):
    eng, clock, _, rl = _engine(tmp_path, limit=2)
    # 先打到隔离
    for _ in range(3):
        eng.evaluate(RequestContext(client_id="evil", path="/admin"))
    assert eng.evaluate(RequestContext(client_id="evil", path="/home")).reason is DenyReason.QUARANTINED
    # 隔离拒绝不消耗限流额度：另一身份视角无关，直接查 evil 剩余额度（规则命中也不走限流）
    assert rl.remaining("evil", clock()) == 2


def test_concurrent_requests_have_consistent_decisions(tmp_path):
    eng, _, rep, _ = _engine(tmp_path, limit=1000, window=1000.0)
    decisions: dict[int, tuple[str, bool, DenyReason | None]] = {}
    lock = threading.Lock()

    def worker(i: int) -> None:
        # 一半请求打规则路径，一半打正常路径
        path = "/admin" if i % 2 == 0 else "/home"
        d = eng.evaluate(RequestContext(client_id="mix", path=path))
        with lock:
            decisions[i] = (path, d.allowed, d.reason)

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(worker, range(200)))

    admin = [v for v in decisions.values() if v[0] == "/admin"]
    home = [v for v in decisions.values() if v[0] == "/home"]
    rule_denies = sum(r is DenyReason.RULE_MATCHED for _, _, r in decisions.values())
    quarantined = sum(r is DenyReason.QUARANTINED for _, _, r in decisions.values())
    allowed = sum(a for _, a, _ in decisions.values())
    logging.info("concurrent rule=%d quarantined=%d allowed=%d total=%d",
                 rule_denies, quarantined, allowed, len(decisions))

    # 不变量 1：所有命中规则的请求必被拒，原因只能是 rule_matched/quarantined
    assert all(
        (not a) and r in (DenyReason.RULE_MATCHED, DenyReason.QUARANTINED)
        for _, a, r in admin
    )
    # 不变量 2：正常路径的请求要么放行，要么因隔离被拒（绝不出现 rule_matched）
    assert all(
        (a and r is None) or r is DenyReason.QUARANTINED
        for _, a, r in home
    )
    # 不变量 3：至少 3 次规则命中记录在信誉系统中，最终必然进入隔离
    assert rule_denies >= 3
    assert rep.get_level("mix", 0.0) is ReputationLevel.QUARANTINED
    assert quarantined >= 1
    assert rule_denies + quarantined + allowed == 200
