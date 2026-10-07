"""表现良好加速恢复：时间/请求双驱动进度、违规清零回退、重启复现、并发不多算。

覆盖场景：
- 观察期持续无违规 -> 时间驱动进度达标后跳级加速恢复（比逐级退避更快脱身）；
- 默认阈值下时间驱动的恢复节奏与旧行为一致；
- 观察期持续放行 -> 请求驱动进度达标立即降级，默认配置下明显快于只按时间熬；
- 观察期再违规 -> 两项进度都清零、立即回退、该重新隔离就重新隔离；
- 进度随重启完整恢复：不白攒（重启后进度还在）、不重攒（同一步不重复累计）；
- 并发查询/并发放行下进度只累计一次（不多算、不少算）；
- 读路径（get_level/is_blocked/snapshot）不累计放行进度，请求不会被算重；
- 引擎联动：放行请求经引擎驱动加速，响应快照可见进度。
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from gateway.models import ReputationLevel
from gateway.reputation import ReputationManager

logging.basicConfig(level=logging.INFO)


def _mgr(tmp_path, name="rep.json", **kw):
    args = dict(
        state_path=str(tmp_path / name),
        base_quarantine_seconds=10.0,
        recover_step_seconds=5.0,
    )
    args.update(kw)
    return ReputationManager(**args)


def _quarantine(mgr, client="c1"):
    for t in (0.0, 1.0, 2.0):
        mgr.record_violation(client, "rule", t)  # 3 次 -> 隔离至 t=12


def test_good_behavior_accelerates_recovery(tmp_path):
    """场景：accel=1。结论：隔离到期后一个干净步直接回 NORMAL，跳过 SUSPECT。"""
    mgr = _mgr(tmp_path, good_accel_steps=1)
    _quarantine(mgr)
    assert mgr.get_level("c1", 12.0) is ReputationLevel.RESTRICTED  # 到期进入观察期
    lvl = mgr.get_level("c1", 17.0)  # 第一个干净步即达标，跳级
    events = [e["event"] for e in mgr.events("c1")]
    logging.info("accelerated level=%s events=%s snapshot=%s",
                 lvl, events, mgr.snapshot("c1", 17.0))
    assert lvl is ReputationLevel.NORMAL
    assert "accelerated_recover" in events
    # 对比不加速（阈值极大）：同一时刻只能到 SUSPECT
    mgr2 = _mgr(tmp_path, name="rep2.json", good_accel_steps=99)
    _quarantine(mgr2)
    mgr2.get_level("c1", 12.0)
    assert mgr2.get_level("c1", 17.0) is ReputationLevel.SUSPECT
    assert mgr2.get_level("c1", 22.0) is ReputationLevel.NORMAL
    logging.info("no-accel timeline: 17->suspect 22->normal（加速版 17 即 normal）")


def test_default_threshold_matches_legacy_ladder(tmp_path):
    """场景：默认 accel=2。结论：RESTRICTED->SUSPECT->NORMAL 各一步，节奏同旧行为。"""
    mgr = _mgr(tmp_path)  # 默认 good_accel_steps=2
    _quarantine(mgr)
    assert mgr.get_level("c1", 12.0) is ReputationLevel.RESTRICTED
    assert mgr.get_level("c1", 17.0) is ReputationLevel.SUSPECT
    snap = mgr.snapshot("c1", 17.0)
    logging.info("mid-ladder snapshot=%s", snap)
    assert snap["recovery_progress"] == 1  # 进度在累积
    assert mgr.get_level("c1", 22.0) is ReputationLevel.NORMAL
    assert mgr.snapshot("c1", 22.0)["recovery_progress"] == 0  # 达标兑现后归零


def test_reoffense_clears_progress_and_requarantines(tmp_path):
    """场景：观察期攒了进度又违规。结论：进度清零、立即回退，再犯即重新隔离且时长翻倍。"""
    mgr = _mgr(tmp_path)
    _quarantine(mgr)
    mgr.get_level("c1", 12.0)   # -> RESTRICTED
    mgr.get_level("c1", 17.0)   # -> SUSPECT，progress=1
    lvl = mgr.record_violation("c1", "rule", 18.0)  # 再犯：进度清零
    snap = mgr.snapshot("c1", 18.0)
    v_events = [e for e in mgr.events("c1") if e["event"] == "violation"]
    logging.info("reoffense level=%s snapshot=%s last_violation=%s",
                 lvl, snap, v_events[-1])
    assert lvl is ReputationLevel.RESTRICTED  # violations 1+1=2，立即回退
    assert snap["recovery_progress"] == 0
    assert v_events[-1]["recovery_progress_cleared"] == 1
    # 再犯一次 -> 连续 3 次，重新隔离且第二次隔离时长翻倍（20s）
    lvl2 = mgr.record_violation("c1", "rule", 18.5)
    snap2 = mgr.snapshot("c1", 18.5)
    logging.info("requarantine level=%s snapshot=%s", lvl2, snap2)
    assert lvl2 is ReputationLevel.QUARANTINED
    assert snap2["quarantine_count"] == 2
    assert snap2["quarantined_until"] == 38.5


def test_progress_survives_restart_without_double_counting(tmp_path):
    """场景：攒了进度后重启。结论：进度完整恢复；同一恢复步不会被重复累计。"""
    path_kw = dict(base_quarantine_seconds=10.0, recover_step_seconds=5.0)
    mgr1 = ReputationManager(state_path=str(tmp_path / "rep.json"), **path_kw)
    _quarantine(mgr1)
    mgr1.get_level("c1", 12.0)   # -> RESTRICTED（迁移即落盘）
    mgr1.get_level("c1", 17.0)   # -> SUSPECT，progress=1（迁移即落盘）
    events_before = mgr1.events("c1")

    # 模拟进程重启：同一状态文件重建
    mgr2 = ReputationManager(state_path=str(tmp_path / "rep.json"), **path_kw)
    mgr2.load()
    snap = mgr2.snapshot("c1", 17.0)
    logging.info("after restart snapshot=%s", snap)
    assert snap["level"] == "suspect"
    assert snap["recovery_progress"] == 1  # 不白攒：进度还在

    # 同一时刻反复查询：不重攒（progress 不动、不重复发事件）
    for _ in range(5):
        assert mgr2.get_level("c1", 17.0) is ReputationLevel.SUSPECT
    assert mgr2.snapshot("c1", 17.0)["recovery_progress"] == 1
    assert mgr2.events("c1") == events_before  # 重启后未重复产生事件

    # 到点继续：第二个干净步达标 -> 加速回 NORMAL
    assert mgr2.get_level("c1", 22.0) is ReputationLevel.NORMAL
    kinds = [e["event"] for e in mgr2.events("c1")]
    logging.info("post-restart final events=%s", kinds)
    assert "accelerated_recover" in kinds


def test_concurrent_advance_counts_step_once(tmp_path):
    """场景：64 线程并发查询同一恢复中的身份。结论：恢复步恰好累计一次。"""
    mgr = _mgr(tmp_path)
    _quarantine(mgr)
    mgr.get_level("c1", 12.0)  # -> RESTRICTED

    levels = []
    lock = threading.Lock()

    def worker() -> None:
        lvl = mgr.get_level("c1", 17.0)
        with lock:
            levels.append(lvl)

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda _: worker(), range(64)))

    recover_events = [e for e in mgr.events("c1") if e["event"] == "recover"]
    snap = mgr.snapshot("c1", 17.0)
    logging.info("concurrent levels=%s recover_events=%d progress=%d",
                 set(levels), len(recover_events), snap["recovery_progress"])
    assert set(levels) == {ReputationLevel.SUSPECT}
    assert len(recover_events) == 1          # 只推进了一次
    assert snap["recovery_progress"] == 1    # 进度不多算


def test_good_requests_accelerate_observation_recovery(tmp_path):
    """场景：默认配置下，观察期身份持续放行 vs 不再出现的身份。
    结论：活跃身份 4 次放行即回 NORMAL（同一时刻），远快于只按时间熬的 10s。"""
    active = _mgr(tmp_path, name="active.json")  # 默认 good_accel_steps=2
    idle = _mgr(tmp_path, name="idle.json")
    _quarantine(active)
    _quarantine(idle)
    assert active.get_level("c1", 12.0) is ReputationLevel.RESTRICTED
    assert idle.get_level("c1", 12.0) is ReputationLevel.RESTRICTED

    # 活跃：观察期内每次放行累计进度，每 2 次降一级，同一时刻脱身
    timeline = [active.record_good("c1", 12.0) for _ in range(4)]
    logging.info("active timeline=%s snapshot=%s",
                 [l.value for l in timeline], active.snapshot("c1", 12.0))
    assert timeline == [
        ReputationLevel.RESTRICTED,  # 第 1 次：进度 1
        ReputationLevel.SUSPECT,     # 第 2 次：达标降为可疑
        ReputationLevel.SUSPECT,     # 第 3 次：进度 1
        ReputationLevel.NORMAL,      # 第 4 次：达标恢复正常
    ]
    accel = [e for e in active.events("c1") if e["event"] == "accelerated_recover"]
    assert len(accel) == 2

    # 对照：不再出现的身份同一时刻还在 RESTRICTED，要熬到 22.0 才 NORMAL
    assert idle.get_level("c1", 12.0) is ReputationLevel.RESTRICTED
    assert idle.get_level("c1", 17.0) is ReputationLevel.SUSPECT
    assert idle.get_level("c1", 22.0) is ReputationLevel.NORMAL
    logging.info("idle timeline: 12->restricted 17->suspect 22->normal"
                 "（活跃身份 12.0 即 normal）")


def test_reoffense_clears_good_progress_and_requarantines(tmp_path):
    """场景：观察期攒了放行进度又违规。结论：进度清零、立即回退，
    达到连续违规阈值就重新隔离且退避时长翻倍。"""
    mgr = _mgr(tmp_path)
    _quarantine(mgr)
    mgr.get_level("c1", 12.0)                       # -> RESTRICTED（观察期）
    mgr.record_good("c1", 12.0)                     # good_progress=1
    assert mgr.snapshot("c1", 12.0)["good_progress"] == 1

    lvl = mgr.record_violation("c1", "rule", 13.0)  # 再犯：2+1=3 -> 重新隔离
    snap = mgr.snapshot("c1", 13.0)
    v = [e for e in mgr.events("c1") if e["event"] == "violation"][-1]
    logging.info("reoffense level=%s snapshot=%s violation=%s", lvl, snap, v)
    assert lvl is ReputationLevel.QUARANTINED
    assert snap["good_progress"] == 0               # 攒的进度清零
    assert v["good_progress_cleared"] == 1
    assert snap["quarantine_count"] == 2
    assert snap["quarantined_until"] == 33.0        # 第二次隔离 20s（翻倍）

    # 未达隔离阈值的回退：SUSPECT 攒 1 次放行后违规 -> 回 RESTRICTED、进度清零
    mgr.get_level("c1", 33.0)                       # 到期 -> RESTRICTED
    mgr.record_good("c1", 33.0)
    mgr.record_good("c1", 33.0)                     # 达标 -> SUSPECT
    mgr.record_good("c1", 33.0)                     # good_progress=1
    lvl2 = mgr.record_violation("c1", "rule", 34.0)  # 1+1=2 -> RESTRICTED
    snap2 = mgr.snapshot("c1", 34.0)
    logging.info("step-back level=%s snapshot=%s", lvl2, snap2)
    assert lvl2 is ReputationLevel.RESTRICTED
    assert snap2["good_progress"] == 0


def test_good_progress_survives_restart_without_double_counting(tmp_path):
    """场景：观察期攒了放行进度后重启。结论：进度不白攒（重启后还在）、
    不重攒（重启后续上一次即达标，不会从头累计）。"""
    kw = dict(base_quarantine_seconds=10.0, recover_step_seconds=5.0)
    mgr1 = ReputationManager(state_path=str(tmp_path / "rep.json"), **kw)
    _quarantine(mgr1)
    mgr1.get_level("c1", 12.0)                      # -> RESTRICTED
    mgr1.record_good("c1", 12.0)                    # good_progress=1（落盘）

    mgr2 = ReputationManager(state_path=str(tmp_path / "rep.json"), **kw)
    mgr2.load()
    snap = mgr2.snapshot("c1", 12.0)
    logging.info("after restart snapshot=%s", snap)
    assert snap["in_recovery"] is True
    assert snap["good_progress"] == 1               # 不白攒：进度还在

    lvl = mgr2.record_good("c1", 12.0)              # 续上：第 2 次即达标降级
    logging.info("post-restart level=%s snapshot=%s",
                 lvl, mgr2.snapshot("c1", 12.0))
    assert lvl is ReputationLevel.SUSPECT           # 不重攒：不需要重新攒 2 次
    assert mgr2.snapshot("c1", 12.0)["good_progress"] == 0  # 兑现后归零


def test_concurrent_good_requests_count_exactly(tmp_path):
    """场景：64 线程并发放行同一观察期身份（阈值调大避免中途降级）。
    结论：进度恰好累计 64 次，不多算、不少算。"""
    mgr = _mgr(tmp_path, good_accel_steps=1000)
    _quarantine(mgr)
    mgr.get_level("c1", 12.0)                       # -> RESTRICTED，进入观察期

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda _: mgr.record_good("c1", 12.0), range(64)))

    snap = mgr.snapshot("c1", 12.0)
    logging.info("concurrent good_progress=%s level=%s",
                 snap["good_progress"], snap["level"])
    assert snap["good_progress"] == 64              # 每个并发请求恰好算一次
    assert snap["level"] == "restricted"            # 阈值未到不降级


def test_concurrent_good_requests_drop_level_once_per_threshold(tmp_path):
    """场景：64 线程并发放行（默认阈值 2）。结论：每次达标只降一级、
    降级事件恰好各一次，最终回 NORMAL 后不再累计。"""
    mgr = _mgr(tmp_path)                            # 默认 good_accel_steps=2
    _quarantine(mgr)
    mgr.get_level("c1", 12.0)

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda _: mgr.record_good("c1", 12.0), range(64)))

    accel = [e for e in mgr.events("c1") if e["event"] == "accelerated_recover"]
    snap = mgr.snapshot("c1", 12.0)
    logging.info("concurrent accel_events=%d final=%s", len(accel), snap)
    assert len(accel) == 2                          # RESTRICTED->SUSPECT->NORMAL 各一次
    assert snap["level"] == "normal"
    assert snap["good_progress"] == 0
    assert snap["in_recovery"] is False             # 观察期结束


def test_read_paths_do_not_count_good_progress(tmp_path):
    """场景：观察期身份被反复查询/判定/快照。结论：读路径不累计放行进度，
    同一次请求经过多个调用点也不会被算重。"""
    mgr = _mgr(tmp_path)
    _quarantine(mgr)
    mgr.get_level("c1", 12.0)                       # -> RESTRICTED
    for _ in range(10):
        mgr.get_level("c1", 12.0)
        mgr.is_blocked("c1", 12.0)
        mgr.snapshot("c1", 12.0)
    snap = mgr.snapshot("c1", 12.0)
    logging.info("read-only snapshot=%s", snap)
    assert snap["good_progress"] == 0               # 读路径一次都没算
    assert snap["level"] == "restricted"


def test_engine_allowed_requests_accelerate_recovery(tmp_path):
    """场景（引擎联动）：隔离到期后持续打正常路径，全部放行。
    结论：放行请求驱动加速，默认配置下第 4 次放行即回 NORMAL，
    且响应快照里能看到进度累计过程。"""
    from gateway.engine import DefenseEngine
    from gateway.models import RequestContext, Rule
    from gateway.rate_limiter import SlidingWindowRateLimiter
    from gateway.rules import RuleEngine

    now = [0.0]
    mgr = _mgr(tmp_path)
    eng = DefenseEngine(
        rules=RuleEngine([Rule(rule_id="block-admin", path_prefix="/admin")]),
        reputation=mgr,
        limiter=SlidingWindowRateLimiter(limit=100, window_seconds=1.0),
        clock=lambda: now[0],
    )

    def hit(path):
        return eng.evaluate(RequestContext(client_id="c1", path=path))

    for _ in range(3):
        hit("/admin")                               # -> 隔离至 t=10
    now[0] = 10.0
    seen = []
    for _ in range(4):
        d = hit("/home")
        assert d.allowed
        seen.append(d.snapshot["reputation"]["good_progress"])
    logging.info("engine-driven good_progress per allow=%s final=%s",
                 seen, mgr.snapshot("c1", 10.0))
    assert seen == [1, 0, 1, 0]                     # 每 2 次兑现一次降级
    assert mgr.get_level("c1", 10.0) is ReputationLevel.NORMAL
