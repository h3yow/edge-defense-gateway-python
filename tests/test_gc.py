"""状态回收与保留边界：闲置真回收、保护隔离/观察期身份、结论可复现、规模有界。

覆盖场景：
- 闲置 NORMAL 身份被真正移出活动状态表；隔离中、观察恢复期、最近活动的身份绝不回收；
- 恢复完成后又长期闲置的身份最终会被回收（状态不无限膨胀）；
- 大批量一次性身份下，活动状态表与归档记录规模都有界（不随见过的身份数增长）；
- 回收不丢结论：quarantine_count 进入归档表并落盘，重启后再次隔离时长与回收前一致；
- 归档记录本身有界：超过保留期彻底过期、超过条数上限淘汰最旧；
- 被回收身份再次出现原地复活，判定结论不变；
- 事件流水按边界保留（超出丢弃最旧）；
- 请求路径上的自动回收按间隔触发。
"""

import json
import logging

from gateway.models import ReputationLevel
from gateway.reputation import ReputationManager

logging.basicConfig(level=logging.INFO)


def _mgr(tmp_path, name="rep.json", **kw):
    args = dict(
        state_path=str(tmp_path / name),
        base_quarantine_seconds=10.0,
        recover_step_seconds=5.0,
        gc_idle_seconds=5.0,
        gc_interval_seconds=60.0,
    )
    args.update(kw)
    return ReputationManager(**args)


def test_idle_normal_reclaimed_but_protected_levels_kept(tmp_path):
    """场景：隔离中/观察期/闲置 NORMAL 三类身份同时存在。
    结论：只有闲置 NORMAL 被归档，其余原样保留。"""
    mgr = _mgr(tmp_path)
    # q：3 次违规 -> 隔离至 t=12
    for t in (0.0, 1.0, 2.0):
        mgr.record_violation("q", "rule", t)
    # old：NORMAL 且从 t=0 起不再出现
    mgr.get_level("old", 0.0)
    # t=11：q 仍在隔离（until=12）且 idle 9s > ttl 5s；old idle 11s
    stats = mgr.gc(11.0)
    logging.info("gc@11 stats=%s q=%s old=%s",
                 stats, mgr.snapshot("q", 11.0), mgr.events())
    assert stats["reclaimed"] == ["old"]
    assert mgr.get_level("q", 11.0) is ReputationLevel.QUARANTINED  # 隔离中绝不回收

    # q 到期进入观察期（RESTRICTED/SUSPECT）：恢复期也不回收
    mgr.get_level("q", 13.0)   # -> RESTRICTED
    stats = mgr.gc(120.0)      # 推进一步 -> SUSPECT，仍在观察期
    logging.info("gc@120 stats=%s q_level=%s", stats, mgr.get_level("q", 120.0))
    assert "q" not in stats["reclaimed"]
    assert mgr.get_level("q", 120.0) is ReputationLevel.SUSPECT

    # 恢复完成（NORMAL）且持续闲置：最终被回收，状态不无限膨胀
    stats = mgr.gc(126.0)
    logging.info("gc@126 stats=%s", stats)
    assert "q" in stats["reclaimed"]


def test_recently_active_kept_with_full_events(tmp_path):
    """场景：最近有活动的身份。结论：状态与事件完整保留，不被误回收。"""
    mgr = _mgr(tmp_path)
    mgr.record_violation("busy", "rule", 100.0)  # SUSPECT 有事件
    mgr.get_level("busy", 104.0)                 # 最近活动：last_seen=104（仍在观察期）
    stats = mgr.gc(104.5)                        # idle 0.5s < ttl 5s
    events = mgr.events("busy")
    logging.info("gc stats=%s busy_events=%s", stats, events)
    assert stats["reclaimed"] == []
    assert len(events) >= 2  # violation + escalate 事件都在
    assert mgr.get_level("busy", 104.5) is ReputationLevel.SUSPECT


def test_reclaim_preserves_conclusions_across_restart(tmp_path):
    """场景：有隔离前科的身份被回收并重启。结论：再次隔离时长与未回收一致，
    不会退化成“从没见过”（第 1 次隔离）。"""
    path = str(tmp_path / "rep.json")
    mgr = _mgr(tmp_path)
    for t in (0.0, 1.0, 2.0):
        mgr.record_violation("c4", "rule", t)      # 第 1 次隔离，count=1
    mgr.get_level("c4", 13.0)                       # -> RESTRICTED
    mgr.get_level("c4", 18.0)                       # -> SUSPECT
    mgr.get_level("c4", 23.0)                       # -> NORMAL
    stats = mgr.gc(200.0)                           # 闲置归档
    assert stats["reclaimed"] == ["c4"]
    logging.info("reclaimed c4, persisted=%s",
                 json.load(open(path))["states"])

    # 重启重建
    mgr2 = _mgr(tmp_path)
    mgr2.load()
    # 再次连续 3 次违规：quarantine_count 应续上（=2），隔离 20s 而非 10s
    for t in (300.0, 301.0, 302.0):
        mgr2.record_violation("c4", "rule", t)
    snap = mgr2.snapshot("c4", 302.0)
    logging.info("post-reclaim restart snapshot=%s", snap)
    assert snap["quarantine_count"] == 2
    assert snap["quarantined_until"] == 322.0  # 与从未回收的结论完全一致

    # 对照：从没见过的身份首次隔离只有 10s
    for t in (300.0, 301.0, 302.0):
        mgr2.record_violation("fresh", "rule", t)
    assert mgr2.snapshot("fresh", 302.0)["quarantined_until"] == 312.0


def test_archived_identity_revives_on_return(tmp_path):
    """场景：已归档身份再次出现。结论：原地复活，等级/前科结论不变。"""
    mgr = _mgr(tmp_path)
    for t in (0.0, 1.0, 2.0):
        mgr.record_violation("c5", "rule", t)
    mgr.get_level("c5", 13.0)
    mgr.get_level("c5", 18.0)
    mgr.get_level("c5", 23.0)  # -> NORMAL，count=1
    mgr.gc(200.0)              # 归档
    lvl = mgr.get_level("c5", 500.0)  # 再次出现
    snap = mgr.snapshot("c5", 500.0)
    logging.info("revived level=%s snapshot=%s", lvl, snap)
    assert lvl is ReputationLevel.NORMAL
    assert snap["archived"] is False
    assert snap["quarantine_count"] == 1  # 前科未丢


def test_event_retention_bound_drops_oldest(tmp_path):
    """场景：单身份事件超过保留边界。结论：只留最近 N 条，最旧被丢弃。"""
    mgr = _mgr(tmp_path, max_events_per_client=5)
    for i in range(8):
        mgr.record_violation("noisy", "rule", float(i))
    events = mgr.events("noisy")
    logging.info("bounded events=%s", [(e["event"], e["ts"]) for e in events])
    assert len(events) == 5
    assert events[-1]["ts"] == 7.0          # 最新的保留
    assert all(e["ts"] >= 6.0 for e in events if e["event"] == "violation")


def test_auto_gc_triggered_on_request_path(tmp_path):
    """场景：不显式调 gc。结论：请求路径上按 gc_interval 自动触发回收。"""
    mgr = _mgr(tmp_path, gc_idle_seconds=5.0, gc_interval_seconds=60.0)
    mgr.get_level("idle-one", 0.0)   # NORMAL，之后不再出现
    mgr.get_level("probe", 0.0)      # 触发首次 gc 基线
    mgr.get_level("probe", 1000.0)   # 距上次 gc > 60s -> 自动回收
    gc_events = [e for e in mgr.events() if e["event"] == "gc"]
    logging.info("auto gc events=%s", gc_events)
    assert gc_events and "idle-one" in gc_events[-1]["reclaimed"]


def test_state_table_shrinks_and_stays_bounded(tmp_path):
    """场景：5 波×200 个一次性身份，波间周期回收。
    结论：活动状态表被真正清空（不是只打标记），归档记录也封顶，
    身份规模不随见过的身份总数（1000）无限增长。"""
    mgr = _mgr(
        tmp_path,
        gc_idle_seconds=5.0,
        gc_archive_seconds=100.0,
        gc_archive_max_entries=50,
    )
    seen_total = 0
    for wave in range(5):
        base = wave * 1000.0
        for i in range(200):
            mgr.get_level(f"one-off-{wave}-{i}", base + i * 0.01)
        seen_total += 200
        before = mgr.gc(base + 2.0)["states"]   # 波内回收前：200 个活动状态
        stats = mgr.gc(base + 500.0)            # 波后回收：全部闲置 -> 真删除
        logging.info(
            "wave=%d before_gc_states=%d after=%s", wave, before, stats,
        )
        assert before == 200
        assert stats["states"] == 0             # 活动状态表真正收缩
        assert stats["archived"] <= 50          # 归档记录封顶
    final = mgr.gc(5 * 1000.0 + 500.0)
    logging.info(
        "final=%s seen_total=%d in_memory=%d",
        final, seen_total, final["states"] + final["archived"],
    )
    assert seen_total == 1000
    assert final["states"] == 0
    assert final["archived"] <= 50  # 见过 1000 个身份，内存里最多留 50 条结论


def test_archive_record_expires_after_archive_seconds(tmp_path):
    """场景：有前科的身份被回收后长期不再出现，超过归档保留期。
    结论：归档记录彻底过期删除；日后再犯按“第一次见”处理（保留期内
    结论一致、超期后才允许退化，规模因此有界）。"""
    mgr = _mgr(tmp_path, gc_idle_seconds=5.0, gc_archive_seconds=100.0)
    for t in (0.0, 1.0, 2.0):
        mgr.record_violation("c9", "rule", t)       # 第 1 次隔离，count=1
    mgr.get_level("c9", 13.0)
    mgr.get_level("c9", 18.0)
    mgr.get_level("c9", 23.0)                       # -> NORMAL
    stats = mgr.gc(50.0)                            # 回收 -> 归档（archived_at=50）
    assert stats["reclaimed"] == ["c9"] and stats["archived"] == 1

    stats = mgr.gc(200.0)                           # 200-50=150 >= 100 -> 过期
    logging.info("archive expiry stats=%s", stats)
    assert "c9" in stats["archive_expired"]
    assert stats["archived"] == 0

    # 归档已过期：再犯按第一次见，首次隔离 10s（对照保留期内应为 20s）
    for t in (300.0, 301.0, 302.0):
        mgr.record_violation("c9", "rule", t)
    snap = mgr.snapshot("c9", 302.0)
    logging.info("post-expiry snapshot=%s", snap)
    assert snap["quarantine_count"] == 1
    assert snap["quarantined_until"] == 312.0


def test_archive_bounded_by_max_entries_evicts_oldest(tmp_path):
    """场景：归档条数超过上限。结论：最旧的归档记录被淘汰，规模封顶。"""
    mgr = _mgr(
        tmp_path,
        gc_idle_seconds=5.0,
        gc_archive_seconds=10**9,   # 关闭时间过期，只验证条数上限
        gc_archive_max_entries=3,
    )
    for i in range(5):
        mgr.get_level(f"c{i}", 0.0)                 # 5 个一次性身份
    stats = mgr.gc(100.0)
    logging.info("archive cap stats=%s remaining=%s",
                 stats, sorted(mgr._archive))
    assert len(stats["reclaimed"]) == 5
    assert stats["archived"] == 3                   # 封顶
    assert set(mgr._archive) == {"c2", "c3", "c4"}  # 最旧的 c0/c1 被淘汰
