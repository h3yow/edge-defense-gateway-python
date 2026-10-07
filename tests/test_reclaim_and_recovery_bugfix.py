"""本轮缺陷修复专项：回收真正有界 + 良好行为真正加速。

每条用例都打印“场景 / 结论 / 关键状态”，覆盖：
- 回收前后活跃身份规模真正下降；多波一次性身份不会让规模无限上涨；
- 隔离中 / 观察期 / 最近活动身份绝不误回收；
- 有隔离前科的身份回收后进前科归档，重启再犯退避次数与时长完全一致；
  归档表本身按保留期有界遗忘（遗忘后按首次身份处理，边界明确）；
- 默认配置下持续良好请求比“只熬时间”明显更快脱身，且恢复步标记 via=good_behavior；
- 同一时刻刷量最多推进一个恢复步，无法瞬间跳过观察期（也不被并发多算）；
- 再违规：良好信用与恢复进度清零、立即回退、该重新隔离就重新隔离；
- 重启：未兑现的良好信用不白攒也不重攒；同一时刻并发只推进一次；
- 引擎层：只有真正放行的请求计良好，规则命中 / 限流拒绝一律不计。
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from gateway.engine import DefenseEngine
from gateway.models import DenyReason, ReputationLevel, RequestContext, Rule
from gateway.rate_limiter import SlidingWindowRateLimiter
from gateway.reputation import ReputationManager
from gateway.rules import RuleEngine

logging.basicConfig(level=logging.INFO)


def _mgr(tmp_path, name="rep.json", **kw):
    args = dict(
        state_path=str(tmp_path / name),
        base_quarantine_seconds=10.0,
        recover_step_seconds=5.0,   # 良好步 floor 随之默认为 2s，每步需 3 次良好请求
        gc_idle_seconds=5.0,
        gc_interval_seconds=60.0,
    )
    args.update(kw)
    return ReputationManager(**args)


def _quarantine(mgr, client="c", times=(0.0, 1.0, 2.0)):
    for t in times:
        mgr.record_violation(client, "rule", t)  # 3 次连续违规 -> 隔离至 t=12


def _release_and_probation(mgr, client="c"):
    """隔离到期释放并进入观察期（RESTRICTED，level_since=12）。"""
    mgr.get_level(client, 12.0)


# ---------------------------------------------------------------------------
# 一、状态回收：规模真正下降、保留边界清晰
# ---------------------------------------------------------------------------

def test_gc_actually_shrinks_active_state_size(tmp_path):
    """场景：500 个只出现一两次的身份，再周期性回收两轮。
    结论：回收后活跃身份数真正归零（旧实现只是打标记，规模永远不降）。"""
    mgr = _mgr(tmp_path)
    for wave in range(2):
        base = wave * 500
        for i in range(250):
            mgr.get_level(f"once-{base + i}", 0.0)            # 只查一次
            mgr.get_level(f"twice-{base + i}", 0.0)
            mgr.get_level(f"twice-{base + i}", 0.5)           # 来两次后消失
        before = mgr.state_size()
        stats = mgr.gc(20.0 + wave)
        logging.info(
            "场景=大规模一次性身份 wave=%d 结论=活跃规模 %d->%d 归档=%d 彻底清除=%d",
            wave, before, stats["states"], stats["archives"],
            len(stats["forgotten"]),
        )
        assert before == 500
        assert stats["states"] == 0                          # 真正从内存移除
        assert stats["archives"] == 0                        # 无前科，不留归档
        assert mgr.state_size() == 0
        assert len(stats["reclaimed"]) == 500


def test_protected_identities_never_reclaimed(tmp_path):
    """场景：隔离中 / RESTRICTED / SUSPECT / 最近活动 NORMAL 同时存在。
    结论：一个都不被回收，状态与事件完整保留；只有真正闲置的 NORMAL 被清。"""
    mgr = _mgr(tmp_path)
    _quarantine(mgr, "quar")                  # 隔离至 12
    _quarantine(mgr, "restr")
    mgr.get_level("restr", 12.0)             # -> RESTRICTED
    _quarantine(mgr, "susp")
    mgr.get_level("susp", 12.0)
    mgr.get_level("susp", 17.5)             # -> SUSPECT
    mgr.get_level("active", 11.0)           # 最近活动的 NORMAL
    mgr.get_level("gone", 0.0)             # 闲置 NORMAL

    stats = mgr.gc(11.5)
    logging.info(
        "场景=四类受保护身份 结论=回收=%s（仅 gone） 关键状态 quar=%s restr=%s susp=%s active=%s",
        stats["reclaimed"],
        mgr.get_level("quar", 11.5).value,
        mgr.get_level("restr", 11.5).value,
        mgr.get_level("susp", 11.5).value,
        mgr.get_level("active", 11.5).value,
    )
    assert stats["reclaimed"] == ["gone"]
    assert mgr.state_size() == 4
    assert mgr.get_level("quar", 11.5) is ReputationLevel.QUARANTINED
    assert mgr.get_level("restr", 11.5) is ReputationLevel.RESTRICTED
    assert mgr.get_level("susp", 11.5) is ReputationLevel.SUSPECT
    # 受保护身份的事件流水不丢
    assert any(e["event"] == "quarantined" for e in mgr.events("quar"))


def test_prior_offender_archived_and_backoff_identical_after_restart(tmp_path):
    """场景：有隔离前科身份回收（活动状态删除、归档表留最小结论）后重启再犯。
    结论：quarantine_count 续上，第二次隔离时长与从未回收完全一致（20s）。"""
    path = str(tmp_path / "rep.json")
    mgr = ReputationManager(state_path=path, base_quarantine_seconds=10.0,
                            recover_step_seconds=5.0, gc_idle_seconds=5.0)
    _quarantine(mgr, "c4")
    mgr.get_level("c4", 13.0)
    mgr.get_level("c4", 18.0)
    mgr.get_level("c4", 23.0)                    # -> NORMAL，前科 count=1
    stats = mgr.gc(200.0)
    logging.info("场景=前科身份回收 结论=活跃 %d 归档 %d 明细=%s",
                 stats["states"], stats["archives"], stats["archived"])
    assert stats["states"] == 0
    assert stats["archives"] == 1 and stats["archived"] == ["c4"]
    assert mgr.state_size() == 0 and mgr.archive_size() == 1

    mgr2 = ReputationManager(state_path=path, base_quarantine_seconds=10.0,
                             recover_step_seconds=5.0, gc_idle_seconds=5.0)
    mgr2.load()
    # 原地复活：前科带回来
    assert mgr2.get_level("c4", 300.0) is ReputationLevel.NORMAL
    assert mgr2.snapshot("c4", 300.0)["quarantine_count"] == 1
    for t in (300.0, 301.0, 302.0):
        mgr2.record_violation("c4", "rule", t)
    snap = mgr2.snapshot("c4", 302.0)
    logging.info("场景=回收重启后再犯 结论=count=%s until=%s（对照首次应为 312）",
                 snap["quarantine_count"], snap["quarantined_until"])
    assert snap["quarantine_count"] == 2
    assert snap["quarantined_until"] == 322.0    # 302 + 20s，退避与未回收一致

    for t in (300.0, 301.0, 302.0):
        mgr2.record_violation("fresh", "rule", t)
    assert mgr2.snapshot("fresh", 302.0)["quarantined_until"] == 312.0


def test_archive_is_bounded_by_history_ttl(tmp_path):
    """场景：归档条目超过历史保留期仍未回来。
    结论：被彻底遗忘，归档表规模有界；遗忘后再犯按首次身份处理（边界明确）。"""
    mgr = _mgr(tmp_path, gc_history_ttl_seconds=1000.0)
    _quarantine(mgr, "old")
    mgr.get_level("old", 12.0)
    mgr.get_level("old", 17.0)
    mgr.get_level("old", 22.0)
    mgr.gc(100.0)
    assert mgr.archive_size() == 1

    kept = mgr.gc(900.0)                       # 未过保留期
    gone = mgr.gc(1101.0)                      # 距归档 1001s >= 1000
    logging.info("场景=归档保留期边界 结论=未过期=%s 过期遗忘=%s 归档规模=%d",
                 kept["archives_expired"], gone["archives_expired"], mgr.archive_size())
    assert kept["archives_expired"] == []
    assert gone["archives_expired"] == ["old"]
    assert mgr.archive_size() == 0

    # 彻底遗忘后再犯：无前科，按首次隔离 10s
    for t in (2000.0, 2001.0, 2002.0):
        mgr.record_violation("old", "rule", t)
    snap = mgr.snapshot("old", 2002.0)
    logging.info("场景=遗忘后再犯 结论=count=%s until=%s（退化为首次，符合保留期边界）",
                 snap["quarantine_count"], snap["quarantined_until"])
    assert snap["quarantine_count"] == 1
    assert snap["quarantined_until"] == 2012.0


# ---------------------------------------------------------------------------
# 二、良好行为加速恢复
# ---------------------------------------------------------------------------

def test_good_behavior_recovers_noticeably_faster_than_idle(tmp_path):
    """场景：默认参数（floor=2s、每步 3 次良好请求）对比“持续良好”与“再不出现”。
    结论：良好身份约 6s 回 NORMAL；同一时刻只熬时间的身份仍在 RESTRICTED。"""
    active = _mgr(tmp_path, name="a.json")
    idle = _mgr(tmp_path, name="b.json")
    for m in (active, idle):
        _quarantine(m)
        _release_and_probation(m)              # RESTRICTED since t=12

    # 持续良好：floor(2s) 后 3 次良好 -> 15s 进 SUSPECT；再一轮 -> 18s 进 NORMAL
    for t in (14.0, 14.5, 15.0):
        active.note_good_request("c", t)
    lvl_mid = active.snapshot("c", 15.0)
    for t in (17.0, 17.5, 18.0):
        active.note_good_request("c", t)
    lvl_active_end = active.get_level("c", 18.0)

    lvl_idle_16 = idle.get_level("c", 16.0)    # 只熬时间：16s 仍 RESTRICTED
    lvl_idle_18 = idle.get_level("c", 18.0)    # 18s 才 SUSPECT
    recover_events = [e for e in active.events("c") if e["event"] == "recover"]
    logging.info(
        "场景=良好 vs 熬时间 结论=良好 15s=%s 18s=%s；熬时间 16s=%s 18s=%s；恢复步 via=%s",
        lvl_mid["level"], lvl_active_end.value, lvl_idle_16.value, lvl_idle_18.value,
        [(e["level"], e.get("via")) for e in recover_events],
    )
    assert lvl_mid["level"] == "suspect"
    assert lvl_active_end is ReputationLevel.NORMAL
    assert lvl_idle_16 is ReputationLevel.RESTRICTED
    assert lvl_idle_18 is ReputationLevel.SUSPECT
    assert all(e.get("via") == "good_behavior" for e in recover_events)


def test_instant_burst_advances_at_most_one_step(tmp_path):
    """场景：floor 刚到的同一时刻刷 100 个良好请求。
    结论：最多推进一个恢复步，不能瞬间从观察期跳回 NORMAL（防刷量绕过）。"""
    mgr = _mgr(tmp_path)
    _quarantine(mgr)
    _release_and_probation(mgr)                 # RESTRICTED since 12
    levels = {mgr.note_good_request("c", 14.0) for _ in range(100)}
    snap = mgr.snapshot("c", 14.0)
    logging.info("场景=同一时刻刷量 结论=出现的等级=%s 最终=%s progress=%s 新级credit=%s",
                 sorted(x.value for x in levels), snap["level"],
                 snap["recovery_progress"], snap["good_credit"])
    assert snap["level"] == "suspect"          # 最多进一格
    assert snap["recovery_progress"] == 1
    assert snap["good_credit"] == 0            # 没把剩余 97 次灌进 SUSPECT


def test_reoffense_clears_credit_and_retreats(tmp_path):
    """场景：观察期攒了良好信用后再违规。
    结论：信用/进度清零、立即回退；再犯一次重新隔离且时长翻倍。"""
    mgr = _mgr(tmp_path)
    _quarantine(mgr)
    _release_and_probation(mgr)
    # 先靠良好行为推进到 SUSPECT（t=15），在 SUSPECT 内攒 2/3 信用
    for t in (14.0, 14.5, 15.0):
        mgr.note_good_request("c", t)           # -> SUSPECT since 15
    for t in (17.0, 17.5):
        mgr.note_good_request("c", t)           # SUSPECT 内攒 2/3 信用
    assert mgr.snapshot("c", 17.5)["level"] == "suspect"
    before = mgr.snapshot("c", 17.5)
    lvl = mgr.record_violation("c", "rule", 18.0)
    after = mgr.snapshot("c", 18.0)
    v_events = [e for e in mgr.events("c") if e["event"] == "violation"]
    logging.info(
        "场景=良好期再违规 结论=违规前 credit=%s -> 等级=%s credit=%s progress=%s 事件清除字段=%s",
        before["good_credit"], lvl.value, after["good_credit"],
        after["recovery_progress"],
        {k: v_events[-1][k] for k in ("good_credit_cleared", "recovery_progress_cleared")},
    )
    assert lvl is ReputationLevel.RESTRICTED   # suspect(violations=1)+1=2 立即回退
    assert after["good_credit"] == 0
    assert v_events[-1]["good_credit_cleared"] == 2

    lvl2 = mgr.record_violation("c", "rule", 18.5)
    snap2 = mgr.snapshot("c", 18.5)
    logging.info("场景=回退后再犯 结论=%s count=%s until=%s",
                 lvl2.value, snap2["quarantine_count"], snap2["quarantined_until"])
    assert lvl2 is ReputationLevel.QUARANTINED
    assert snap2["quarantine_count"] == 2
    assert snap2["quarantined_until"] == 38.5  # 18.5 + 20s


def test_good_credit_survives_restart_without_double_count(tmp_path):
    """场景：攒了 2/3 信用后重启。
    结论：信用完整恢复（不白攒），再来一次即升级；同刻重复调用不重攒。"""
    path = str(tmp_path / "rep.json")
    kw = dict(base_quarantine_seconds=10.0, recover_step_seconds=5.0)
    m1 = ReputationManager(state_path=path, **kw)
    _quarantine(m1)
    _release_and_probation(m1)
    for t in (14.0, 14.5):
        m1.note_good_request("c", t)
    events_before = m1.events("c")

    m2 = ReputationManager(state_path=path, **kw)
    m2.load()
    snap = m2.snapshot("c", 14.5)
    logging.info("场景=攒信用后重启 结论=level=%s good_credit=%s（应 restricted/2，不白攒）",
                 snap["level"], snap["good_credit"])
    # 重启后未再出现请求：信用原封不动（不白攒、也不自动升级）
    assert snap["level"] == "restricted"
    assert snap["good_credit"] == 2

    # floor 之前（t<14）的重复调用不计信用、不升级（持续时间不够）
    assert m2.note_good_request("c", 13.9) is ReputationLevel.RESTRICTED
    assert m2.snapshot("c", 13.9)["good_credit"] == 2
    # floor 之后再来一次良好：用重启前攒的 2 点 + 这 1 点恰好达标升级（不重攒）
    assert m2.note_good_request("c", 15.0) is ReputationLevel.SUSPECT
    snap_after = m2.snapshot("c", 15.0)
    logging.info("场景=重启后继续表现 结论=level=%s 新级credit=%s recover事件数=%d（信用续上、只推进一次）",
                 snap_after["level"], snap_after["good_credit"],
                 len([e for e in m2.events("c") if e["event"] == "recover"]))
    assert snap_after["good_credit"] == 0
    assert len([e for e in m2.events("c") if e["event"] == "recover"]) == 1
    # 重启前已有的事件没有重复产生
    assert m2.events("c")[: len(events_before)] == events_before


def test_concurrent_good_requests_advance_exactly_once(tmp_path):
    """场景：已有 2/3 信用时 64 线程同刻打第 3 次良好请求。
    结论：全部看到 SUSPECT，恢复步只推进一次，信用不灌进新等级。"""
    mgr = _mgr(tmp_path)
    _quarantine(mgr)
    _release_and_probation(mgr)
    for t in (14.0, 14.5):
        mgr.note_good_request("c", t)          # credit=2

    levels: list[ReputationLevel] = []
    lock = threading.Lock()

    def worker() -> None:
        with lock:
            levels.append(mgr.note_good_request("c", 15.0))

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda _: worker(), range(64)))

    snap = mgr.snapshot("c", 15.0)
    recover_events = [e for e in mgr.events("c") if e["event"] == "recover"]
    logging.info("场景=并发达标 结论=等级集合=%s recover事件=%d progress=%s 新级credit=%s",
                 {x.value for x in levels}, len(recover_events),
                 snap["recovery_progress"], snap["good_credit"])
    assert {x for x in levels} == {ReputationLevel.SUSPECT}
    assert len(recover_events) == 1
    assert snap["recovery_progress"] == 1
    assert snap["good_credit"] == 0


# ---------------------------------------------------------------------------
# 三、引擎层：只有真正放行的良好请求才计信用
# ---------------------------------------------------------------------------

class FakeClock:
    def __init__(self) -> None:
        self.t = 0.0
        self._lock = threading.Lock()

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        with self._lock:
            self.t += dt


def _engine(tmp_path, limit=10, window=10.0, tiers=None):
    clock = FakeClock()
    rules = RuleEngine([Rule(rule_id="block-admin", path_prefix="/admin",
                             description="后台探测")])
    rep = ReputationManager(
        state_path=str(tmp_path / "rep.json"),
        base_quarantine_seconds=10.0,
        recover_step_seconds=5.0,
    )
    rl = SlidingWindowRateLimiter(limit=limit, window_seconds=window)
    eng = DefenseEngine(rules, rep, rl, clock=clock, level_limits=tiers)
    return eng, clock, rep


def test_only_allowed_requests_accrue_good_credit(tmp_path):
    """场景：观察期身份 1 次限流拒绝 + 1 次放行（restricted 档收紧为 1，窗口短）。
    结论：放行计 1 点良好信用；限流拒绝、规则命中一律不计。"""
    tiers = {
        ReputationLevel.NORMAL: 100,
        ReputationLevel.SUSPECT: 100,
        ReputationLevel.RESTRICTED: 1,
    }
    eng, clock, rep = _engine(tmp_path, limit=100, window=2.5, tiers=tiers)
    for _ in range(3):
        eng.evaluate(RequestContext(client_id="c", path="/admin"))   # -> 隔离至 12
    clock.advance(12.0)
    eng.evaluate(RequestContext(client_id="c", path="/home"))        # 到期释放 RESTRICTED，耗尽 restricted 档
    clock.advance(2.0)                                                # t=14，过 floor，窗口仍含 t=12
    d_rl = eng.evaluate(RequestContext(client_id="c", path="/home"))  # 档=1 且同窗口：429，不计良好
    snap0 = rep.snapshot("c", clock())
    assert d_rl.reason is DenyReason.RATE_LIMITED
    assert snap0["good_credit"] == 0

    # 窗口翻篇（<5s，时间恢复还没推进，仍在 RESTRICTED）：放行才计良好，随后规则命中清零
    clock.advance(0.6)                                               # t=14.6，窗口(t=12.1~) 翻篇
    d_ok = eng.evaluate(RequestContext(client_id="c", path="/home"))  # 放行：+1
    assert d_ok.allowed is True
    assert rep.snapshot("c", clock())["good_credit"] == 1            # 只有放行计良好
    d_rule = eng.evaluate(RequestContext(client_id="c", path="/admin"))
    snap2 = rep.snapshot("c", clock())
    logging.info("场景=放行/限流/规则三类 结论=限流不计(%s) 放行计1 规则命中=%s后credit=%s level=%s",
                 d_rl.reason, d_rule.reason, snap2["good_credit"], snap2["level"])
    assert d_rule.reason is DenyReason.RULE_MATCHED
    assert snap2["good_credit"] == 0


def test_legacy_archived_statefile_migrates_to_archive_table(tmp_path):
    """场景：升级到新版本，磁盘上还是旧格式——回收只打 archived 标记、
    条目仍留在 states 数组，且没有 archives 字段。
    结论：加载时自动迁移：archived 条目转入前科归档表并从活动表移除，
    活动身份原样保留；迁移后再犯退避仍续得上。"""
    import json

    path = tmp_path / "legacy.json"
    json.dump(
        {
            "states": [
                {
                    "client_id": "a", "violations": 0, "level": "normal",
                    "quarantine_count": 2, "quarantined_until": 0.0,
                    "level_since": 0.0, "recovery_progress": 0,
                    "last_seen": 50.0, "archived": True,
                },
                {
                    "client_id": "b", "violations": 1, "level": "suspect",
                    "quarantine_count": 0, "quarantined_until": 0.0,
                    "level_since": 60.0, "recovery_progress": 0,
                    "last_seen": 60.0, "archived": False,
                },
            ],
            "events": [],
        },
        open(path, "w", encoding="utf-8"),
    )
    mgr = ReputationManager(
        state_path=str(path),
        base_quarantine_seconds=10.0,
        recover_step_seconds=5.0,
        gc_idle_seconds=5.0,
    )
    mgr.load()
    logging.info("场景=旧格式状态文件升级 结论=活跃=%s 归档=%s",
                 mgr.state_size(), mgr.archive_size())
    assert mgr.state_size() == 1
    assert mgr.archive_size() == 1
    # 活动身份不受迁移影响：加载当时（t=60）仍是 suspect（未被时间推进）
    assert mgr.get_level("b", 60.0) is ReputationLevel.SUSPECT
    # 旧版“归档”身份复活，前科续上
    assert mgr.get_level("a", 1000.0) is ReputationLevel.NORMAL
    assert mgr.snapshot("a", 1000.0)["quarantine_count"] == 2
