"""状态回收与有界保留：边界取舍、隔离/观察期豁免、休眠保留、重启一致、引擎周期回收。

时间约定：隔离在 t=2 进入（base=10 时到期 t=12），
restricted -> suspect 在 t=17，suspect -> normal 在 t=22。
"""

import logging

from gateway.engine import DefenseEngine
from gateway.models import ReputationLevel, RequestContext
from gateway.rate_limiter import SlidingWindowRateLimiter
from gateway.reputation import ReputationManager
from gateway.rules import RuleEngine

logging.basicConfig(level=logging.INFO)


def _mgr(tmp_path, **kw):
    defaults = dict(
        state_path=str(tmp_path / "rep.json"),
        base_quarantine_seconds=10.0,
        max_quarantine_seconds=100000.0,
        recover_step_seconds=5.0,
        inactive_ttl_seconds=10.0,
        dormant_ttl_seconds=100.0,
        max_dormant_identities=1000,
        max_events=1000,
    )
    defaults.update(kw)
    return ReputationManager(**defaults)


def _quarantine_once(mgr: ReputationManager, cid: str = "old") -> None:
    for t in (0.0, 1.0, 2.0):
        mgr.record_violation(cid, "rule", t)


def _recover_to_normal(mgr: ReputationManager, cid: str = "old") -> None:
    assert mgr.get_level(cid, 12.0) is ReputationLevel.RESTRICTED
    assert mgr.get_level(cid, 17.0) is ReputationLevel.SUSPECT
    assert mgr.get_level(cid, 22.0) is ReputationLevel.NORMAL


def test_long_inactive_normal_identity_is_reaped_to_dormant(tmp_path):
    """正常身份超过 inactive_ttl 未活动：软回收为休眠，活动结论归零但保留隔离次数。"""
    mgr = _mgr(tmp_path)
    _quarantine_once(mgr)
    _recover_to_normal(mgr)
    # t=22 起不再活动；t=40 已超过 ttl 10s
    result = mgr.reap_inactive(40.0)
    logging.info("reap result=%s dormant=%s", result, mgr.dormant_identities())
    assert result["reaped"] == ["old"]
    dormant = mgr.dormant_identities()
    assert "old" in dormant
    assert dormant["old"]["quarantine_count"] == 1
    # 回收时该身份的历史事件流水已被清除
    assert mgr.events("old") == []
    # 回收后再次出现：活动结论按全新正常身份，但历史隔离次数被带回
    snap = mgr.snapshot("old", 40.0)
    logging.info("revived snapshot=%s events=%s", snap, mgr.events("old"))
    assert snap["level"] == "normal"
    assert snap["violations"] == 0
    assert snap["quarantine_count"] == 1
    # 唤醒只产生一条 revived 事件，旧的违规/隔离历史不会回流
    assert [e["event"] for e in mgr.events("old")] == ["revived"]


def test_inactive_boundary_is_deterministic(tmp_path):
    """边界确定：静默时长 == ttl 保留（<=），刚超出才回收（>）。"""
    mgr = _mgr(tmp_path, inactive_ttl_seconds=10.0)
    mgr.note_clean_activity("edge", 100.0)
    assert mgr.reap_inactive(110.0)["reaped"] == []  # 恰好 10s，保留
    logging.info("at exact boundary dormant=%s", mgr.dormant_identities())
    assert "edge" not in mgr.dormant_identities()
    result = mgr.reap_inactive(110.0 + 1e-6)  # 刚超出
    assert result["reaped"] == ["edge"]
    assert "edge" in mgr.dormant_identities()


def test_quarantined_identity_never_reaped(tmp_path):
    """隔离中的身份即使长时间无活动也绝不回收。"""
    mgr = _mgr(tmp_path, base_quarantine_seconds=10000.0)
    _quarantine_once(mgr, "jailed")
    result = mgr.reap_inactive(9999.0)
    logging.info("quarantined reap result=%s", result)
    assert result["reaped"] == []
    snap = mgr.snapshot("jailed", 9999.0)
    assert snap["level"] == "quarantined"
    assert snap["quarantine_count"] == 1


def test_probation_identity_never_reaped(tmp_path):
    """观察恢复期中（restricted/suspect）即使静默超过 ttl 也不回收。"""
    mgr = _mgr(tmp_path, inactive_ttl_seconds=2.0)
    _quarantine_once(mgr, "p")
    # 12 释放为 restricted；静默略超 ttl 仍在 restricted
    assert mgr.get_level("p", 12.0) is ReputationLevel.RESTRICTED
    result = mgr.reap_inactive(13.0 + 1e-6)
    logging.info("restricted reap result=%s", result)
    assert result["reaped"] == []
    assert mgr.get_level("p", 13.0 + 1e-6) is ReputationLevel.RESTRICTED

    # suspect 阶段同样豁免：先让 q 走到 suspect，再静默
    _quarantine_once(mgr, "q")
    assert mgr.get_level("q", 12.0) is ReputationLevel.RESTRICTED
    assert mgr.get_level("q", 17.0) is ReputationLevel.SUSPECT
    result2 = mgr.reap_inactive(18.0 + 1e-6)
    logging.info("suspect reap result=%s", result2)
    assert "q" not in result2["reaped"]
    assert mgr.get_level("q", 18.0 + 1e-6) is ReputationLevel.SUSPECT


def test_recently_active_identity_is_kept(tmp_path):
    mgr = _mgr(tmp_path, inactive_ttl_seconds=10.0)
    mgr.note_clean_activity("fresh", 100.0)
    mgr.note_clean_activity("fresh", 105.0)
    assert mgr.reap_inactive(110.0)["reaped"] == []  # 距上次活动仅 5s


def test_dormant_identity_reoffense_keeps_quarantine_count(tmp_path):
    """休眠身份再次出现：带回历史隔离次数，再犯时退避倍数延续（结论不退回从没见过）。"""
    mgr = _mgr(tmp_path, dormant_ttl_seconds=10000.0)
    _quarantine_once(mgr, "ghost")
    _recover_to_normal(mgr, "ghost")
    mgr.reap_inactive(40.0)
    assert "ghost" in mgr.dormant_identities()

    # 休眠后重新出现，马上连续违规 3 次：应按“第 2 次隔离”20s，而不是第 1 次 10s
    mgr.note_clean_activity("ghost", 50.0)
    for t in (51.0, 52.0, 53.0):
        level = mgr.record_violation("ghost", "rule", t)
    snap = mgr.snapshot("ghost", 53.0)
    logging.info("dormant reoffense snapshot=%s", snap)
    assert level is ReputationLevel.QUARANTINED
    assert snap["quarantine_count"] == 2
    assert snap["quarantined_until"] == 73.0  # 53 + 20
    assert any(e["event"] == "revived" for e in mgr.events("ghost"))


def test_dormant_ttl_and_cap_are_bounded(tmp_path):
    """休眠身份也有界：超容量按最近活动淘汰最旧；超 dormant_ttl 真正遗忘。"""
    mgr = _mgr(
        tmp_path, inactive_ttl_seconds=1.0,
        dormant_ttl_seconds=5.0, max_dormant_identities=2,
    )
    mgr.note_clean_activity("a", 0.0)
    mgr.note_clean_activity("b", 1.0)
    mgr.note_clean_activity("c", 2.0)
    # 都静默超 active ttl
    result = mgr.reap_inactive(4.0)
    dormant = mgr.dormant_identities()
    logging.info("cap reap result=%s dormant=%s", result, dormant)
    assert set(result["reaped"]) == {"a", "b", "c"}
    # 容量 2：最旧的 a 立即被遗忘
    assert set(dormant) == {"b", "c"}
    assert "a" in result["forgotten"]

    # a 已彻底遗忘：重新出现是全新身份，无历史隔离次数
    snap = mgr.snapshot("a", 4.0)
    assert snap["quarantine_count"] == 0

    # 休眠超时：b 的 last_seen=1.0，now=6.001 静默超过 5s -> 遗忘
    result2 = mgr.reap_inactive(6.0 + 1e-6)
    logging.info("ttl reap result=%s", result2)
    assert "b" in result2["forgotten"]
    assert "b" not in mgr.dormant_identities()
    assert "c" in mgr.dormant_identities()


def test_reaped_state_consistent_after_restart(tmp_path):
    """回收后重启：休眠集合与结论完整复现，不会把已回收身份当老活跃态。"""
    path = str(tmp_path / "rep.json")
    mgr1 = ReputationManager(
        state_path=path, base_quarantine_seconds=10.0,
        inactive_ttl_seconds=10.0, dormant_ttl_seconds=10000.0,
    )
    _quarantine_once(mgr1, "rep")
    _recover_to_normal(mgr1, "rep")
    mgr1.reap_inactive(40.0)
    dormant_before = mgr1.dormant_identities()

    mgr2 = ReputationManager(
        state_path=path, base_quarantine_seconds=10.0,
        inactive_ttl_seconds=10.0, dormant_ttl_seconds=10000.0,
    )
    mgr2.load()
    logging.info("after restart dormant=%s", mgr2.dormant_identities())
    assert mgr2.dormant_identities() == dormant_before
    # 重启后再犯：隔离次数延续，仍是第 2 次隔离（20s）
    for t in (50.0, 51.0, 52.0):
        mgr2.record_violation("rep", "rule", t)
    snap = mgr2.snapshot("rep", 52.0)
    logging.info("post-restart reoffense snapshot=%s", snap)
    assert snap["quarantine_count"] == 2
    assert snap["quarantined_until"] == 72.0


def test_events_are_bounded_and_oldest_dropped(tmp_path):
    """事件流水在每次落盘时裁剪；重启后仍然有界。"""
    mgr = _mgr(tmp_path, max_events=10)
    for i in range(20):
        mgr.record_violation(f"cli{i}", "rule", float(i))  # 每次各 2 条事件
    assert len(mgr.events()) == 10
    mgr2 = _mgr(tmp_path, max_events=10)
    mgr2.load()
    assert len(mgr2.events()) == 10
    logging.info("bounded events tail=%s", mgr2.events()[-1])


def test_engine_periodic_reap_clears_state(tmp_path):
    """引擎按间隔自动回收，并同步清掉限流器内该身份的窗口计数。"""
    clock_value = [0.0]

    class Clock:
        def __call__(self):
            return clock_value[0]

    rep = ReputationManager(
        state_path=str(tmp_path / "rep.json"),
        inactive_ttl_seconds=10.0, dormant_ttl_seconds=10000.0,
    )
    rl = SlidingWindowRateLimiter(limit=100, window_seconds=1.0)
    eng = DefenseEngine(
        RuleEngine([]), rep, rl, clock=Clock(), reap_interval_seconds=5.0,
    )
    eng.evaluate(RequestContext(client_id="gone", path="/home"))
    assert rl.snapshot("gone", 0.0, limit=100)["used"] == 1
    # t=4：还没到回收间隔，不回收
    clock_value[0] = 4.0
    eng.evaluate(RequestContext(client_id="other", path="/home"))
    assert "gone" not in rep.dormant_identities()
    # t=11：到达回收间隔，gone 已静默 11s > ttl
    clock_value[0] = 11.0
    eng.evaluate(RequestContext(client_id="other", path="/home"))
    logging.info("dormant after engine reap=%s", rep.dormant_identities())
    assert "gone" in rep.dormant_identities()
    # 限流器窗口也已同步清掉
    assert rl.snapshot("gone", 11.0, limit=100)["used"] == 0
