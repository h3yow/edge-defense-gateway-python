"""判定编排：同一请求依次经过规则、信誉、限流三个维度。

固定顺序（拒绝原因因此稳定、可区分、可解释）：
    1. 规则匹配   命中 -> 拒绝 rule_matched，并登记一次“规则违规”
    2. 信誉隔离   隔离中 -> 拒绝 quarantined
    3. 速率判定   窗口超限 -> 拒绝 rate_limited（不记规则违规）
    其余 -> 放行

规则违规会累积到信誉系统：连续命中规则最终升级为隔离。
限流拒绝不累积信誉（客户端可能只是突发，不应被定性为恶意），
但限流与规则拦截的 reason 明确区分。
"""

from __future__ import annotations

import logging
import threading
import time

from gateway.models import Decision, DenyReason, RequestContext
from gateway.rate_limiter import SlidingWindowRateLimiter
from gateway.reputation import ReputationManager
from gateway.rules import RuleEngine

logger = logging.getLogger("gateway.engine")


class DefenseEngine:
    def __init__(
        self,
        rules: RuleEngine,
        reputation: ReputationManager,
        limiter: SlidingWindowRateLimiter,
        clock=time.monotonic,
    ) -> None:
        self.rules = rules
        self.reputation = reputation
        self.limiter = limiter
        self._clock = clock
        self._lock = threading.Lock()

    def _snapshot(self, ctx: RequestContext, now: float) -> dict:
        return {
            "client_id": ctx.client_id,
            "path": ctx.path,
            "method": ctx.method,
            "rate_limit": self.limiter.snapshot(ctx.client_id, now),
            "reputation": self.reputation.snapshot(ctx.client_id, now),
        }

    def evaluate(self, ctx: RequestContext) -> Decision:
        now = self._clock()
        # 维度 1：规则匹配
        rule = self.rules.match(ctx)
        if rule is not None:
            level = self.reputation.record_violation(ctx.client_id, "rule_matched", now)
            snap = self._snapshot(ctx, now)
            logger.info(
                "DENY client=%s path=%s reason=rule_matched rule=%s level=%s snapshot=%s",
                ctx.client_id, ctx.path, rule.rule_id, level.value, snap,
            )
            return Decision(
                allowed=False,
                reason=DenyReason.RULE_MATCHED,
                detail=f"命中防护规则 {rule.rule_id}: {rule.description}",
                rule_id=rule.rule_id,
                snapshot=snap,
            )

        # 维度 2：信誉隔离（隔离期内一律拒绝，不消耗限流额度）
        if self.reputation.is_blocked(ctx.client_id, now):
            snap = self._snapshot(ctx, now)
            logger.info(
                "DENY client=%s path=%s reason=quarantined snapshot=%s",
                ctx.client_id, ctx.path, snap,
            )
            return Decision(
                allowed=False,
                reason=DenyReason.QUARANTINED,
                detail="来源处于隔离期，一律拒绝",
                snapshot=snap,
            )

        # 维度 3：滑动窗口限流（原子判定 + 登记）
        if not self.limiter.check(ctx.client_id, now):
            snap = self._snapshot(ctx, now)
            logger.info(
                "DENY client=%s path=%s reason=rate_limited snapshot=%s",
                ctx.client_id, ctx.path, snap,
            )
            return Decision(
                allowed=False,
                reason=DenyReason.RATE_LIMITED,
                detail=(
                    f"超过滑动窗口限额 {self.limiter.limit} 次/"
                    f"{self.limiter.window_seconds:g}s"
                ),
                snapshot=snap,
            )

        snap = self._snapshot(ctx, now)
        logger.info(
            "ALLOW client=%s path=%s snapshot=%s", ctx.client_id, ctx.path, snap
        )
        return Decision(allowed=True, detail="放行", snapshot=snap)
