"""Core domain types: requests, decisions, rules, reputation and audit events."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class DenyReason(str, Enum):
    """Stable, distinguishable reasons for a denial.

    The string values are part of the public contract: clients, logs and
    tests rely on them staying unchanged.
    """

    RULE_VIOLATION = "rule_violation"
    IN_QUARANTINE = "in_quarantine"
    RATE_LIMITED = "rate_limited"


class ReputationLevel(int, Enum):
    """Reputation escalates with the integer value."""

    TRUSTED = 0
    NORMAL = 1
    SUSPICIOUS = 2
    QUARANTINE = 3


@dataclass(frozen=True)
class RequestContext:
    identity: str
    path: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    entrypoint: str = "default"


# A matcher inspects a request and returns True when the rule is violated.
Matcher = Callable[[RequestContext], bool]


@dataclass(frozen=True)
class Rule:
    rule_id: str
    description: str
    matcher: Matcher | None = None


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: DenyReason | None
    identity: str
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "reason": self.reason.value if self.reason is not None else None,
            "identity": self.identity,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class ViolationEvent:
    rule_id: str
    rule_description: str
    path: str


@dataclass
class ClientState:
    """Mutable reputation state for one identity."""

    identity: str
    level: ReputationLevel = ReputationLevel.NORMAL
    violation_streak: int = 0
    quarantined_until: float | None = None
    total_violations: int = 0
    updated_at: float = 0.0
    # How many times this identity has been isolated (drives escalating
    # quarantine durations).
    quarantine_count: int = 0
    # When the last quarantine was released; drives gradual recovery staging.
    released_at: float | None = None

    def is_quarantined(self, now: float) -> bool:
        return (
            self.level is ReputationLevel.QUARANTINE
            and self.quarantined_until is not None
            and now < self.quarantined_until
        )

    def snapshot(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "level": self.level.name,
            "level_value": int(self.level),
            "violation_streak": self.violation_streak,
            "quarantined_until": self.quarantined_until,
            "total_violations": self.total_violations,
            "updated_at": self.updated_at,
            "quarantine_count": self.quarantine_count,
            "released_at": self.released_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "level": int(self.level),
            "violation_streak": self.violation_streak,
            "quarantined_until": self.quarantined_until,
            "total_violations": self.total_violations,
            "updated_at": self.updated_at,
            "quarantine_count": self.quarantine_count,
            "released_at": self.released_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClientState:
        return cls(
            identity=data["identity"],
            level=ReputationLevel(int(data["level"])),
            violation_streak=int(data.get("violation_streak", 0)),
            quarantined_until=data.get("quarantined_until"),
            total_violations=int(data.get("total_violations", 0)),
            updated_at=float(data.get("updated_at", 0.0)),
            quarantine_count=int(data.get("quarantine_count", 0)),
            released_at=data.get("released_at"),
        )


@dataclass(frozen=True)
class AuditEvent:
    seq: int
    timestamp: float
    identity: str
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "identity": self.identity,
            "kind": self.kind,
            "payload": self.payload,
        }
