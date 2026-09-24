"""Reputation accumulation, quarantine isolation and gradual recovery.

Escalation model
----------------
Consecutive rule violations (a streak) climb a ladder:

* streak 1        -> NORMAL
* streak reaches 2 -> SUSPICIOUS (quota shrinks, request still served)
* streak reaches 4 -> QUARANTINE #1 (all requests denied until it expires)

A new rule violation while already in quarantine extends the isolation with an
exponentially backed-off duration (base * 2**quarantine_count).

Recovery model
--------------
When a quarantine expires the client is released into SUSPICIOUS recovery and
moves through cooldown stages, each one restoring more quota:

    stage 0 : multiplier 0.25   (elapsed < cooldown)
    stage 1 : multiplier 0.50   (elapsed < 2 * cooldown)
    stage 2 : fully recovered to NORMAL (elapsed >= 2 * cooldown)

Any rule violation during recovery immediately re-enters quarantine with the
next (longer) duration. A fully allowed request resets the streak to zero.

All transitions are persisted to the state file and appended to the audit log,
so the exact status is reproduced after a process restart.
"""

from __future__ import annotations

import threading
from typing import Any

from edge_gateway.clock import Clock, SystemClock
from edge_gateway.models import AuditEvent, ClientState, ReputationLevel
from edge_gateway.store import InMemoryStore, StateStore

# Recovery stages after release: index == stage, value == quota multiplier.
RECOVERY_MULTIPLIERS = (0.25, 0.5, 1.0)
SUSPICIOUS_MULTIPLIER = 0.5


class ReputationManager:
    def __init__(
        self,
        store: StateStore | None = None,
        clock: Clock | None = None,
        *,
        suspicious_threshold: int = 2,
        quarantine_threshold: int = 4,
        quarantine_seconds: float = 30.0,
        recovery_cooldown_seconds: float = 15.0,
        backoff_factor: float = 2.0,
    ) -> None:
        self._store = store or InMemoryStore()
        self._clock = clock or SystemClock()
        self.suspicious_threshold = suspicious_threshold
        self.quarantine_threshold = quarantine_threshold
        self.quarantine_seconds = float(quarantine_seconds)
        self.recovery_cooldown_seconds = float(recovery_cooldown_seconds)
        self.backoff_factor = float(backoff_factor)
        self._lock = threading.RLock()
        self._states: dict[str, ClientState] = {}
        self._seq = 0
        self._load()

    # ------------------------------------------------------------------ load

    def _load(self) -> None:
        raw = self._store.load_states()
        for identity, data in raw.items():
            self._states[identity] = ClientState.from_dict(data)
        self._seq = len(self._store.read_audit())

    # ------------------------------------------------------------------ audit

    def _audit_locked(self, identity: str, kind: str, payload: dict[str, Any]) -> None:
        self._seq += 1
        event = AuditEvent(
            seq=self._seq,
            timestamp=self._clock.now(),
            identity=identity,
            kind=kind,
            payload=payload,
        )
        self._store.append_audit(event.to_dict())

    def _persist_locked(self, state: ClientState) -> None:
        state.updated_at = self._clock.now()
        all_states = {ident: s.to_dict() for ident, s in self._states.items()}
        self._store.save_states(all_states)

    def _get_locked(self, identity: str) -> ClientState:
        state = self._states.get(identity)
        if state is None:
            state = ClientState(identity=identity, updated_at=self._clock.now())
            self._states[identity] = state
        return state

    # ------------------------------------------------------------ time-based

    def _quarantine_duration_locked(self, count: int) -> float:
        # count is 1-based: #1 -> base, #2 -> base*factor, #3 -> base*factor^2
        return self.quarantine_seconds * (self.backoff_factor ** (count - 1))

    def recovery_stage(self, state: ClientState, now: float | None = None) -> int:
        """0-based recovery stage for a post-quarantine SUSPICIOUS client."""
        now = self._clock.now() if now is None else now
        if state.level is not ReputationLevel.SUSPICIOUS or state.released_at is None:
            return 0
        if state.quarantine_count == 0:
            # Soft-warning SUSPICIOUS clients are not on the timed ladder.
            return 0
        elapsed = max(0.0, now - state.released_at)
        # Stage k spans [k*cooldown, (k+1)*cooldown). Compare against the
        # upper bounds explicitly so float error cannot hold back recovery.
        stage = len(RECOVERY_MULTIPLIERS) - 1
        for k in range(len(RECOVERY_MULTIPLIERS) - 1):
            if elapsed < (k + 1) * self.recovery_cooldown_seconds:
                stage = k
                break
        return stage

    def quota_multiplier(self, identity: str) -> float:
        """Current rate-limit quota multiplier after applying time recovery."""
        with self._lock:
            state = self._apply_time_transitions(identity)
            if state.level is ReputationLevel.QUARANTINE:
                return 0.0
            if state.level is ReputationLevel.NORMAL or state.level is ReputationLevel.TRUSTED:
                return 1.0
            if state.quarantine_count > 0:
                return RECOVERY_MULTIPLIERS[self.recovery_stage(state)]
            return SUSPICIOUS_MULTIPLIER

    def _apply_time_transitions(self, identity: str) -> ClientState:
        """Lazily release expired quarantines and advance timed recovery."""
        state = self._get_locked(identity)
        now = self._clock.now()
        changed = False

        if (
            state.level is ReputationLevel.QUARANTINE
            and state.quarantined_until is not None
            and now >= state.quarantined_until
        ):
            state.level = ReputationLevel.SUSPICIOUS
            state.released_at = state.quarantined_until
            state.quarantined_until = None
            state.violation_streak = 0
            self._audit_locked(
                identity,
                "quarantine_released",
                {"released_at": state.released_at, "stage": 0},
            )
            changed = True

        if state.level is ReputationLevel.SUSPICIOUS and state.quarantine_count > 0:
            stage = self.recovery_stage(state, now)
            if stage >= len(RECOVERY_MULTIPLIERS) - 1:
                state.level = ReputationLevel.NORMAL
                self._audit_locked(identity, "recovered", {"to_level": "NORMAL"})
                changed = True

        if changed:
            self._persist_locked(state)
        return state

    # --------------------------------------------------------------- mutations

    def register_violation(self, identity: str, event: Any) -> dict[str, Any]:
        """Record a rule violation and escalate reputation as needed."""
        with self._lock:
            now = self._clock.now()
            state = self._apply_time_transitions(identity)
            state.violation_streak += 1
            state.total_violations += 1
            streak = state.violation_streak

            violation_info = {
                "rule_id": event.rule_id,
                "rule_description": event.rule_description,
                "path": event.path,
                "streak": streak,
            }
            self._audit_locked(identity, "violation_registered", violation_info)

            if state.level is ReputationLevel.QUARANTINE:
                # Violating while isolated extends isolation with backoff.
                state.quarantine_count += 1
                duration = self._quarantine_duration_locked(state.quarantine_count)
                state.quarantined_until = now + duration
                state.violation_streak = 0
                self._audit_locked(
                    identity,
                    "quarantine_extended",
                    {"quarantine_count": state.quarantine_count, "duration": duration},
                )
                self._persist_locked(state)
                return self.snapshot(identity)

            if state.level is ReputationLevel.SUSPICIOUS and state.quarantine_count > 0:
                # Violating during post-quarantine recovery re-isolates with
                # the next (longer) duration.
                self._enter_quarantine_locked(state, now)
                self._persist_locked(state)
                return self.snapshot(identity)

            if streak >= self.quarantine_threshold:
                self._enter_quarantine_locked(state, now)
            elif streak >= self.suspicious_threshold and state.level is ReputationLevel.NORMAL:
                state.level = ReputationLevel.SUSPICIOUS
                self._audit_locked(identity, "level_changed", {"to_level": "SUSPICIOUS"})

            self._persist_locked(state)
            return self.snapshot(identity)

    def _enter_quarantine_locked(self, state: ClientState, now: float) -> None:
        state.quarantine_count += 1
        duration = self._quarantine_duration_locked(state.quarantine_count)
        state.level = ReputationLevel.QUARANTINE
        state.quarantined_until = now + duration
        state.violation_streak = 0
        self._audit_locked(
            state.identity,
            "quarantined",
            {
                "quarantine_count": state.quarantine_count,
                "duration": duration,
                "until": state.quarantined_until,
            },
        )

    def note_allowed(self, identity: str) -> None:
        """A fully-allowed request resets the streak and clears soft warnings."""
        with self._lock:
            state = self._apply_time_transitions(identity)
            changed = False
            if state.violation_streak != 0:
                state.violation_streak = 0
                changed = True
            if (
                state.level is ReputationLevel.SUSPICIOUS
                and state.quarantine_count == 0
            ):
                # Soft warning earned by a short streak: one clean call clears.
                state.level = ReputationLevel.NORMAL
                self._audit_locked(identity, "level_changed", {"to_level": "NORMAL"})
                changed = True
            if changed:
                self._persist_locked(state)

    # ------------------------------------------------------------------ reads

    def is_quarantined(self, identity: str) -> bool:
        with self._lock:
            state = self._apply_time_transitions(identity)
            return state.level is ReputationLevel.QUARANTINE

    def current(self, identity: str) -> dict[str, Any]:
        with self._lock:
            return self.snapshot(identity)

    def snapshot(self, identity: str) -> dict[str, Any]:
        """Must be called under self._lock (state may be refreshed first)."""
        state = self._apply_time_transitions(identity)
        now = self._clock.now()
        snap = state.snapshot()
        snap["is_quarantined"] = state.level is ReputationLevel.QUARANTINE
        snap["quota_multiplier"] = self._multiplier_locked(state)
        snap["recovery_stage"] = self.recovery_stage(state, now)
        if state.quarantined_until is not None:
            snap["quarantine_remaining"] = max(0.0, state.quarantined_until - now)
        return snap

    def _multiplier_locked(self, state: ClientState) -> float:
        if state.level is ReputationLevel.QUARANTINE:
            return 0.0
        if state.level in (ReputationLevel.NORMAL, ReputationLevel.TRUSTED):
            return 1.0
        if state.quarantine_count > 0:
            return RECOVERY_MULTIPLIERS[self.recovery_stage(state)]
        return SUSPICIOUS_MULTIPLIER

    def audit_trail(self, identity: str | None = None) -> list[dict[str, Any]]:
        events = self._store.read_audit()
        if identity is None:
            return events
        return [e for e in events if e.get("identity") == identity]
