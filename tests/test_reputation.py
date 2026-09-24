"""信誉：逐级升级、隔离期拒绝、退避恢复、重启复现与事件追溯。"""

import logging

from gateway.models import ReputationLevel
from gateway.reputation import ReputationManager

logging.basicConfig(level=logging.INFO)


def _mgr(tmp_path, **kw):
    return ReputationManager(
        state_path=str(tmp_path / "rep.json"),
        base_quarantine_seconds=10.0,
        recover_step_seconds=5.0,
        **kw,
    )


def test_escalation_and_quarantine(tmp_path):
    mgr = _mgr(tmp_path)
    l1 = mgr.record_violation("c1", "rule", 0.0)
    l2 = mgr.record_violation("c1", "rule", 1.0)
    l3 = mgr.record_violation("c1", "rule", 2.0)
    snap = mgr.snapshot("c1", 2.0)
    logging.info("levels=%s %s %s snapshot=%s", l1, l2, l3, snap)
    assert (l1, l2, l3) == (
        ReputationLevel.SUSPECT,
        ReputationLevel.RESTRICTED,
        ReputationLevel.QUARANTINED,
    )
    assert mgr.is_blocked("c1", 9.999) is True
    assert mgr.get_level("c1", 9.999) is ReputationLevel.QUARANTINED


def test_quarantine_release_and_gradual_recovery(tmp_path):
    mgr = _mgr(tmp_path)
    for t in (0.0, 1.0, 2.0):
        mgr.record_violation("c1", "rule", t)
    # 隔离到 t=12
    assert mgr.is_blocked("c1", 11.9) is True
    # t=12 到期：降为 RESTRICTED（观察期），不再一律拒绝
    lvl = mgr.get_level("c1", 12.0)
    logging.info("released level=%s snapshot=%s", lvl, mgr.snapshot("c1", 12.0))
    assert lvl is ReputationLevel.RESTRICTED
    assert mgr.is_blocked("c1", 12.0) is False
    # 观察期无违规：每 5s 降一级
    assert mgr.get_level("c1", 17.0) is ReputationLevel.SUSPECT
    assert mgr.get_level("c1", 22.0) is ReputationLevel.NORMAL


def test_reoffense_during_probation_re_quarantines(tmp_path):
    mgr = _mgr(tmp_path)
    for t in (0.0, 1.0, 2.0):
        mgr.record_violation("c1", "rule", t)
    mgr.get_level("c1", 12.0)  # 到期降为 RESTRICTED
    mgr.record_violation("c1", "rule", 13.0)  # 观察期再犯
    snap = mgr.snapshot("c1", 13.0)
    logging.info("re-offense snapshot=%s", snap)
    assert snap["level"] == "quarantined"
    assert snap["quarantine_count"] == 2
    # 第二次隔离时长翻倍：13 -> 33
    assert snap["quarantined_until"] == 33.0


def test_state_survives_restart_with_audit_trail(tmp_path):
    path = str(tmp_path / "rep.json")
    mgr1 = ReputationManager(state_path=path, base_quarantine_seconds=10.0)
    mgr1.record_violation("c1", "rule_matched", 0.0)
    mgr1.record_violation("c1", "rule_matched", 1.0)
    events_before = mgr1.events("c1")

    mgr2 = ReputationManager(state_path=path, base_quarantine_seconds=10.0)
    mgr2.load()
    snap = mgr2.snapshot("c1", 1.0)
    logging.info("restart snapshot=%s events=%s", snap, mgr2.events("c1"))
    assert snap["level"] == "restricted"
    assert snap["violations"] == 2
    assert mgr2.events("c1") == events_before
    assert any(e["event"] == "escalate" for e in mgr2.events("c1"))


def test_unknown_client_is_normal_and_not_blocked(tmp_path):
    mgr = _mgr(tmp_path)
    assert mgr.get_level("nobody", 0.0) is ReputationLevel.NORMAL
    assert mgr.is_blocked("nobody", 0.0) is False
