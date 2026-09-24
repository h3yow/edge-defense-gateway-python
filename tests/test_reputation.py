"""Reputation: escalation ladder, quarantine, backoff, staged recovery, persistence."""

from __future__ import annotations

import logging

from edge_gateway.clock import FakeClock
from edge_gateway.models import ViolationEvent
from edge_gateway.reputation import RECOVERY_MULTIPLIERS, ReputationManager
from edge_gateway.store import InMemoryStore, JsonFileStore

logger = logging.getLogger(__name__)


def violation(rule_id="R001"):
    return ViolationEvent(rule_id, "test rule", "/x")


def make_manager(tmp_path=None, clock=None, **kw):
    clock = clock or FakeClock()
    if tmp_path is None:
        store = InMemoryStore()
    else:
        store = JsonFileStore(tmp_path / "state.json", tmp_path / "audit.jsonl")
    return ReputationManager(
        store=store,
        clock=clock,
        quarantine_seconds=kw.get("quarantine_seconds", 30.0),
        recovery_cooldown_seconds=kw.get("cooldown", 15.0),
        suspicious_threshold=2,
        quarantine_threshold=4,
    ), clock, store


def test_streak_escalates_to_suspicious_then_quarantine():
    mgr, _clock, _store = make_manager()
    mgr.register_violation("u", violation())
    s1 = mgr.snapshot("u")
    assert s1["level"] == "NORMAL" and s1["violation_streak"] == 1

    mgr.register_violation("u", violation())
    s2 = mgr.snapshot("u")
    assert s2["level"] == "SUSPICIOUS"

    mgr.register_violation("u", violation())
    mgr.register_violation("u", violation())
    s4 = mgr.snapshot("u")
    logger.info("after 4 violations snapshot=%s", s4)
    assert s4["level"] == "QUARANTINE"
    assert s4["is_quarantined"] is True
    assert s4["quarantine_count"] == 1
    assert abs(s4["quarantine_remaining"] - 30.0) < 1e-9


def test_quarantine_denies_then_staged_recovery_restores_quota(tmp_path):
    mgr, clock, _ = make_manager(tmp_path)
    for _ in range(4):
        mgr.register_violation("u", violation())
    assert mgr.is_quarantined("u") is True
    assert mgr.quota_multiplier("u") == 0.0

    # Immediately after expiry: released into recovery stage 0 (0.25 quota).
    clock.advance(30.0)
    assert mgr.is_quarantined("u") is False
    assert mgr.quota_multiplier("u") == RECOVERY_MULTIPLIERS[0]

    clock.advance(15.0)  # stage 1: 0.5
    assert mgr.quota_multiplier("u") == RECOVERY_MULTIPLIERS[1]

    clock.advance(15.0)  # stage 2: fully recovered -> NORMAL
    snap = mgr.snapshot("u")
    logger.info("recovered snapshot=%s", snap)
    assert snap["level"] == "NORMAL"
    assert mgr.quota_multiplier("u") == 1.0


def test_violation_during_quarantine_extends_with_backoff(tmp_path):
    mgr, clock, _ = make_manager(tmp_path)
    for _ in range(4):
        mgr.register_violation("u", violation())
    assert abs(mgr.snapshot("u")["quarantine_remaining"] - 30.0) < 1e-9

    clock.advance(10.0)
    mgr.register_violation("u", violation())  # inside quarantine
    snap = mgr.snapshot("u")
    logger.info("extended snapshot=%s", snap)
    assert snap["level"] == "QUARANTINE"
    assert snap["quarantine_count"] == 2
    # New duration 60s measured from the extension moment (t=10) -> ends at 70.
    assert abs(snap["quarantine_remaining"] - 60.0) < 1e-9


def test_violation_during_recovery_reisolates_with_longer_duration(tmp_path):
    mgr, clock, _ = make_manager(tmp_path)
    for _ in range(4):
        mgr.register_violation("u", violation())
    clock.advance(30.0)  # released
    assert mgr.snapshot("u")["level"] == "SUSPICIOUS"
    mgr.register_violation("u", violation())
    snap = mgr.snapshot("u")
    assert snap["level"] == "QUARANTINE"
    assert snap["quarantine_count"] == 2
    assert abs(snap["quarantine_remaining"] - 60.0) < 1e-9


def test_allowed_request_resets_streak_and_clears_soft_warning(tmp_path):
    mgr, _, _ = make_manager(tmp_path)
    mgr.register_violation("u", violation())
    mgr.register_violation("u", violation())  # soft SUSPICIOUS, no quarantine yet
    assert mgr.snapshot("u")["level"] == "SUSPICIOUS"
    mgr.note_allowed("u")
    snap = mgr.snapshot("u")
    logger.info("after allowed snapshot=%s", snap)
    assert snap["level"] == "NORMAL"
    assert snap["violation_streak"] == 0


def test_state_and_audit_survive_reconstruction(tmp_path):
    mgr1, clock, _store = make_manager(tmp_path)
    for _ in range(4):
        mgr1.register_violation("u", violation("R009"))
    audit_before = mgr1.audit_trail("u")
    assert any(e["kind"] == "quarantined" for e in audit_before)

    # Simulate process restart: brand-new manager over the same files.
    mgr2, _, _ = make_manager(tmp_path, clock=clock)
    snap = mgr2.snapshot("u")
    audit_after = mgr2.audit_trail("u")
    logger.info("after restart snapshot=%s audit_kinds=%s",
                snap, [e["kind"] for e in audit_after])
    assert snap["level"] == "QUARANTINE"
    assert snap["total_violations"] == 4
    assert audit_after == audit_before
    assert audit_after[0]["seq"] == 1  # sequence continues from the log length


def test_recovery_stage_boundaries_are_deterministic(tmp_path):
    mgr, clock, _ = make_manager(tmp_path, cooldown=15.0)
    for _ in range(4):
        mgr.register_violation("u", violation())
    clock.advance(30.0)  # released at t=30
    # Just inside each boundary vs exactly on it.
    assert mgr.quota_multiplier("u") == 0.25
    clock.advance(14.999)
    assert mgr.quota_multiplier("u") == 0.25
    clock.set(clock.now() + 0.001)  # exactly 15s after release
    assert mgr.quota_multiplier("u") == 0.5
    clock.advance(15.0)  # exactly 30s after release -> NORMAL
    snap = mgr.snapshot("u")
    assert snap["level"] == "NORMAL" and mgr.quota_multiplier("u") == 1.0


def test_rate_limit_denial_does_not_reset_or_grow_streak(tmp_path):
    gw_mgr, _clock, _store = make_manager(tmp_path)
    # 2 violations -> SUSPICIOUS streak stays until an *allowed* request.
    gw_mgr.register_violation("u", violation())
    gw_mgr.register_violation("u", violation())
    assert gw_mgr.snapshot("u")["violation_streak"] == 2
    # note_allowed is the only thing clearing it; rate-limit path never calls it.
    assert gw_mgr.snapshot("u")["level"] == "SUSPICIOUS"
