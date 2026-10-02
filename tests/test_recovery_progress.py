"""表现良好加速恢复：进度累积、违规清零回退、重启复现、并发不多算。

覆盖场景：
- 观察期持续无违规 -> 进度达标后跳级加速恢复（比逐级退避更快脱身）；
- 默认阈值下恢复节奏与旧行为一致；
- 观察期再违规 -> 进度清零、立即回退、该重新隔离就重新隔离；
- 进度随重启完整恢复：不白攒（重启后进度还在）、不重攒（同一步不重复累计）；
- 并发查询下恢复步只累计一次。
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
