"""Defense gateway: every request passes all three dimensions.

Evaluation order (and therefore stable reason priority):

1. Rule matching. A hit denies with ``rule_violation`` AND feeds reputation.
2. Quarantine. An isolated identity denies with ``in_quarantine`` (a rule hit
   discovered while isolated still extends the isolation via step 1).
3. Sliding-window rate limit. Over-quota denies with ``rate_limited`` — this
   never affects reputation, so throttling and interception stay separable.
4. Otherwise the request is allowed.
"""

from __future__ import annotations

import threading
from typing import Any

from edge_gateway.clock import Clock, SystemClock
from edge_gateway.models import Decision, DenyReason, RequestContext, Verdict
from edge_gateway.ratelimit import SlidingWindowRateLimiter
from edge_gateway.reputation import ReputationManager
from edge_gateway.rules import RuleEngine
from edge_gateway.store import InMemoryStore, StateStore


class DefenseGateway:
    def __init__(
        self,
        rule_engine: RuleEngine | None = None,
        reputation: ReputationManager | None = None,
        rate_limiter: SlidingWindowRateLimiter | None = None,
        store: StateStore | None = None,
        clock: Clock | None = None,
        *,
        base_limit: int = 10,
        window_seconds: float = 60.0,
    ) -> None:
        self._clock = clock or SystemClock()
        self._store = store or InMemoryStore()
        self.rules = rule_engine or RuleEngine()
        self.reputation = reputation or ReputationManager(store=self._store, clock=self._clock)
        self.rate_limiter = rate_limiter or SlidingWindowRateLimiter(
            limit=base_limit,
            window_seconds=window_seconds,
            clock=self._clock,
        )
        self._inspect_lock = threading.Lock()

    def inspect(self, request: RequestContext) -> Decision:
        # Serialize state transitions so concurrent entries (api/portal/...)
        # observe one consistent order for the same identity.
        with self._inspect_lock:
            # 1) Rule dimension ------------------------------------------------
            violation = self.rules.match(request)
            if violation is not None:
                client_snapshot = self.reputation.register_violation(
                    request.identity, violation
                )
                return Decision(
                    verdict=Verdict.DENY,
                    reason=DenyReason.RULE_VIOLATION,
                    identity=request.identity,
                    detail={
                        "rule_id": violation.rule_id,
                        "rule_description": violation.rule_description,
                        "entrypoint": request.entrypoint,
                        "path": request.path,
                        "client_state": client_snapshot,
                    },
                )

            # 2) Quarantine dimension -----------------------------------------
            if self.reputation.is_quarantined(request.identity):
                return Decision(
                    verdict=Verdict.DENY,
                    reason=DenyReason.IN_QUARANTINE,
                    identity=request.identity,
                    detail={
                        "entrypoint": request.entrypoint,
                        "path": request.path,
                        "client_state": self.reputation.snapshot(request.identity),
                    },
                )

            # 3) Rate dimension ------------------------------------------------
            multiplier = self.reputation.quota_multiplier(request.identity)
            allowed, rate_info = self.rate_limiter.check_and_consume(
                request.identity, multiplier=multiplier
            )
            if not allowed:
                return Decision(
                    verdict=Verdict.DENY,
                    reason=DenyReason.RATE_LIMITED,
                    identity=request.identity,
                    detail={
                        "entrypoint": request.entrypoint,
                        "path": request.path,
                        "rate": rate_info,
                        "client_state": self.reputation.snapshot(request.identity),
                    },
                )

            # 4) Allowed -------------------------------------------------------
            self.reputation.note_allowed(request.identity)
            return Decision(
                verdict=Verdict.ALLOW,
                reason=None,
                identity=request.identity,
                detail={
                    "entrypoint": request.entrypoint,
                    "path": request.path,
                    "rate": rate_info,
                    "client_state": self.reputation.snapshot(request.identity),
                },
            )

    def client_snapshot(self, identity: str) -> dict[str, Any]:
        snapshot = self.reputation.snapshot(identity)
        snapshot["rate_window"] = self.rate_limiter.snapshot(identity)
        return snapshot
