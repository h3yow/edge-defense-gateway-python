"""观察恢复期“表现好更快脱身”：良好进度加速、再犯清零回退、并发不多算、重启不丢不重。

规则（recover_step=5s, good_bonus=1s, bonus_interval=0.5s）：
  - 时间自然流逝每秒 1 秒进度（保底路径，与老行为一致）；
  - 观察期内每 0.5s 来一次干净请求，进度额外 +1s；
  - 进度满 5s 降一级；任何新违规进度清零并立即回退/重新隔离。
"""

import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from gateway.models import ReputationLevel
from gateway.reputation import ReputationManager

logging.basicConfig(level=logging.INFO)


def _mgr(tmp_path, **kw):
    defaults = dict(
        base_quarantine_seconds=10.0,
        recover_step_seconds=5.0,
        good_bonus_seconds=1.0,
        good_bonus_interval_seconds=0.5,
    )
    defaults.update(kw)
    return ReputationManager(state_path=str(tmp_path / "rep.json"), **defaults)


def _quarantine_then_release(mgr: ReputationManager) -> None:
    for t in (0.0, 1.0, 2.0):
        mgr.record_violation("c1", "rule", t)
    assert mgr.get_level("c1", 12.0) is ReputationLevel.RESTRICTED


def test_clean_requests_accelerate_recovery(tmp_path):
    """积极来干净请求：restricted 恢复到 normal 比纯等待更快。"""
    mgr = _mgr(tmp_path)
    _quarantine_then_release(mgr)

    # 12.0 释放进入 restricted；此后每 0.5s 来一次干净请求。
    # 自然进度按总流逝封顶，奖励每次额外 +1s：
    # 12.5: max(0.5自然, 0)+1 = 1.5；13.0: max(1.0,1.5)+1 = 2.5 …… 14.5: 5.5 满档
    for t in (12.5, 13.0, 13.5, 14.0, 14.5):
        mgr.note_clean_activity("c1", t)
    snap14 = mgr.snapshot("c1", 14.5)
    logging.info("accelerated at t=14.5 level=%s snapshot=%s", snap14["level"], snap14)
    # 自然 2.5s + 5 次奖励各 1s = 7.5s（封顶后累计 5.5）：已降到 suspect
    assert snap14["level"] == "suspect"
    assert snap14["recover_progress"] == 0.0  # 降档时进度清零

    # 继续积极活动：17.0 即可恢复 normal（纯等待需到 22.0，整整快 5s）
    for t in (15.0, 15.5, 16.0, 16.5, 17.0):
        mgr.note_clean_activity("c1", t)
    assert mgr.get_level("c1", 17.0) is ReputationLevel.NORMAL

    # 纯等待对照：另一身份不带任何干净请求，17.0 才刚到 suspect，22.0 才 normal
    for t in (0.0, 1.0, 2.0):
        mgr.record_violation("idle", "rule", t)
    assert mgr.get_level("idle", 12.0) is ReputationLevel.RESTRICTED
    assert mgr.get_level("idle", 14.5) is ReputationLevel.RESTRICTED
    assert mgr.get_level("idle", 17.0) is ReputationLevel.SUSPECT
    assert mgr.get_level("idle", 22.0) is ReputationLevel.NORMAL


def test_violation_resets_progress_and_rolls_back(tmp_path):
    """攒了进度后再违规：进度立即清零，立刻按违规规则回退/重新隔离。"""
    mgr = _mgr(tmp_path)
    _quarantine_then_release(mgr)

    # restricted 观察期攒进度：12.5 -> 1.5，13.0 -> 2.5
    mgr.note_clean_activity("c1", 12.5)
    mgr.note_clean_activity("c1", 13.0)
    snap = mgr.snapshot("c1", 13.0)
    logging.info("progress before reoffense snapshot=%s", snap)
    assert snap["level"] == "restricted"
    assert snap["recover_progress"] == 2.5

    # 再违规：restricted 下 violations 2 -> 3，立即重新隔离，进度清零
    level = mgr.record_violation("c1", "rule", 13.1)
    snap_after = mgr.snapshot("c1", 13.1)
    logging.info("reoffense level=%s snapshot=%s", level, snap_after)
    assert level is ReputationLevel.QUARANTINED
    assert snap_after["quarantine_count"] == 2
    assert snap_after["quarantined_until"] == 33.1  # 第二次隔离 20s
    assert snap_after["recover_progress"] == 0.0
    assert any(e["event"] == "progress_reset" for e in mgr.events("c1"))


def test_suspect_level_violation_rolls_back_to_restricted(tmp_path):
    """suspect 观察期再犯（未到 3 次）：进度清零并回退一级到 restricted。"""
    mgr = _mgr(tmp_path)
    _quarantine_then_release(mgr)
    # 快速降到 suspect（14.5 满档降一级）
    for t in (12.5, 13.0, 13.5, 14.0, 14.5):
        mgr.note_clean_activity("c1", t)
    assert mgr.get_level("c1", 14.5) is ReputationLevel.SUSPECT
    # suspect 阶段攒点进度：15.0 -> 1.5（0.5 自然 + 1 奖励）
    mgr.note_clean_activity("c1", 15.0)
    snap_before = mgr.snapshot("c1", 15.0)
    logging.info("suspect before reoffense=%s", snap_before)
    assert snap_before["recover_progress"] == 1.5

    level = mgr.record_violation("c1", "rule", 15.1)
    snap_after = mgr.snapshot("c1", 15.1)
    logging.info("suspect reoffense level=%s snapshot=%s", level, snap_after)
    assert level is ReputationLevel.RESTRICTED
    assert snap_after["violations"] == 2
    assert snap_after["recover_progress"] == 0.0


def test_concurrent_clean_requests_do_not_double_count(tmp_path):
    """同一时刻并发干净请求：节流间隔内只发一次奖励，进度不会被多算。"""
    mgr = _mgr(tmp_path)
    _quarantine_then_release(mgr)

    barrier = threading.Barrier(32)

    def worker() -> None:
        barrier.wait()
        mgr.note_clean_activity("c1", 12.6)  # 全部同一逻辑时刻

    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda _: worker(), range(32)))

    snap = mgr.snapshot("c1", 12.6)
    logging.info("concurrent clean snapshot=%s", snap)
    # 自然进度 0.6s + 仅 1 次奖励 1s = 1.6s；绝不出现 32 次奖励
    assert 1.5 < snap["recover_progress"] <= 1.6 + 1e-9
    assert snap["level"] == "restricted"
    # 紧接着再来一个请求（距上次奖励不足 0.5s）不发奖励
    mgr.note_clean_activity("c1", 12.9)
    snap2 = mgr.snapshot("c1", 12.9)
    assert snap2["recover_progress"] <= 1.9 + 1e-9


def test_progress_survives_restart_without_loss_or_double(tmp_path):
    """重启后进度按锚点继续：攒了多少就是多少，重启本身不发奖励、不重复攒。"""
    path = str(tmp_path / "rep.json")
    mgr1 = _mgr(tmp_path)
    _quarantine_then_release(mgr1)
    mgr1.note_clean_activity("c1", 12.5)
    mgr1.note_clean_activity("c1", 13.0)
    snap_before = mgr1.snapshot("c1", 13.0)
    events_before = mgr1.events("c1")
    logging.info("before restart snapshot=%s events_tail=%s",
                 snap_before, events_before[-3:])
    assert snap_before["level"] == "restricted"
    progress_before = snap_before["recover_progress"]
    assert 2.5 - 1e-9 <= progress_before <= 2.5 + 1e-9

    # 重启：同一时刻重建，结论与进度必须一致
    mgr2 = _mgr(tmp_path)
    mgr2.load()
    snap_after = mgr2.snapshot("c1", 13.0)
    logging.info("after restart snapshot=%s", snap_after)
    assert snap_after["level"] == "restricted"
    assert abs(snap_after["recover_progress"] - progress_before) < 1e-9
    assert mgr2.events("c1") == events_before

    # 0.4s 后（距上次奖励 0.4s < 0.5s）来请求：不发新奖励，自然进度也未超过存量
    mgr2.note_clean_activity("c1", 13.4)
    snap_throttled = mgr2.snapshot("c1", 13.4)
    logging.info("post-restart throttled snapshot=%s", snap_throttled)
    assert snap_throttled["recover_progress"] == progress_before

    # 再 0.1s（距上次奖励 0.5s 整）：补发一次奖励 -> 2.5 + 1 = 3.5
    mgr2.note_clean_activity("c1", 13.5)
    snap_bonus = mgr2.snapshot("c1", 13.5)
    logging.info("post-restart bonus snapshot=%s", snap_bonus)
    assert 3.5 - 1e-9 <= snap_bonus["recover_progress"] <= 3.5 + 1e-9


def test_pure_time_path_unchanged_when_idle(tmp_path):
    """没有干净请求时恢复节奏与老版本完全一致：每 5s 降一级。"""
    mgr = _mgr(tmp_path)
    _quarantine_then_release(mgr)
    assert mgr.get_level("c1", 16.999) is ReputationLevel.RESTRICTED
    assert mgr.get_level("c1", 17.0) is ReputationLevel.SUSPECT
    assert mgr.get_level("c1", 21.999) is ReputationLevel.SUSPECT
    assert mgr.get_level("c1", 22.0) is ReputationLevel.NORMAL
    logging.info("idle recovery events=%s",
                 [e["event"] for e in mgr.events("c1")])
    # 纯等待路径不应出现任何良好奖励事件
    assert not any(e["event"] == "good_progress" for e in mgr.events("c1"))


def test_bonus_can_be_disabled(tmp_path):
    """good_bonus_seconds=0 时退化为纯时间恢复。"""
    mgr = _mgr(tmp_path, good_bonus_seconds=0.0)
    _quarantine_then_release(mgr)
    for t in (12.5, 13.0, 13.5, 14.0, 14.5):
        mgr.note_clean_activity("c1", t)
    snap = mgr.snapshot("c1", 14.5)
    logging.info("bonus-disabled snapshot=%s", snap)
    assert snap["level"] == "restricted"
    assert abs(snap["recover_progress"] - 2.5) < 1e-9
    assert not any(e["event"] == "good_progress" for e in mgr.events("c1"))
