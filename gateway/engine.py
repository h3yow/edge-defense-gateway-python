"""判定编排：同一请求依次经过规则、信誉、限流三个维度。

固定顺序（拒绝原因因此稳定、可区分、可解释）：
    1. 规则匹配   命中 -> 拒绝 rule_matched，并登记一次“规则违规”
    2. 信誉隔离   隔离中 -> 拒绝 quarantined（不消耗限流额度）
    3. 速率判定   按当前信誉等级对应的分档额度做滑动窗口判定，
                  超限 -> 拒绝 rate_limited（不记规则违规）
    其余 -> 放行

规则违规会累积到信誉系统：连续命中规则最终升级为隔离。
限流拒绝不累积信誉（客户端可能只是突发，不应被定性为恶意），
但限流与规则拦截的 reason 明确区分。

分档限流：level_limits 给出各信誉等级对应的窗口额度；缺省（None）时
所有等级共用 limiter 构造额度，与旧行为完全一致。等级在下一次请求
即生效（每次判定都实时取等级）。响应快照中包含本次所用档位与剩余额度。
"""

from __future__ import annotations

import logging
import threading
import time

from gateway.models import Decision, DenyReason, ReputationLevel, RequestContext
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
        level_limits: dict[ReputationLevel, int] | None = None,
    ) -> None:
        self.rules = rules
        self.reputation = reputation
        self.limiter = limiter
        self._clock = clock
        self._lock = threading.Lock()
        self._level_limits: dict[ReputationLevel, int] = dict(level_limits or {})
        for level, limit in self._level_limits.items():
            if limit < 1:
                raise ValueError(f"level limit for {level.value} must be >= 1")

    def _tier_limit(self, level: ReputationLevel) -> int:
        """该等级本次请求使用的限流额度；未配置的等级回退到构造额度。"""
        return self._level_limits.get(level, self.limiter.limit)

    def _snapshot(self, ctx: RequestContext, now: float, tier_limit: int) -> dict:
        snap = {
            "client_id": ctx.client_id,
            "path": ctx.path,
            "method": ctx.method,
            "rate_limit": self.limiter.snapshot(ctx.client_id, now, limit=tier_limit),
            "reputation": self.reputation.snapshot(ctx.client_id, now),
        }
        snap["rate_limit"]["tier_level"] = snap["reputation"]["level"]
        return snap

    def evaluate(self, ctx: RequestContext) -> Decision:
        now = self._clock()
        # 维度 1：规则匹配
        rule = self.rules.match(ctx)
        if rule is not None:
            level = self.reputation.record_violation(ctx.client_id, "rule_matched", now)
            snap = self._snapshot(ctx, now, self._tier_limit(level))
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
        level = self.reputation.get_level(ctx.client_id, now)
        if level is ReputationLevel.QUARANTINED:
            snap = self._snapshot(ctx, now, self.limiter.limit)
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

        # 维度 3：按信誉等级分档的滑动窗口限流（原子判定 + 登记）
        tier = self._tier_limit(level)
        if not self.limiter.check(ctx.client_id, now, limit=tier):
            snap = self._snapshot(ctx, now, tier)
            logger.info(
                "DENY client=%s path=%s reason=rate_limited tier=%s level=%s snapshot=%s",
                ctx.client_id, ctx.path, tier, level.value, snap,
            )
            return Decision(
                allowed=False,
                reason=DenyReason.RATE_LIMITED,
                detail=(
                    f"超过滑动窗口限额 {tier} 次/"
                    f"{self.limiter.window_seconds:g}s（{level.value} 档）"
                ),
                snapshot=snap,
            )

        # 放行 = 表现良好：观察期身份累计恢复进度（加速恢复的唯一计入口，
        # 读路径不累计，同一次请求不会被重复计数）
        self.reputation.record_good(ctx.client_id, now)
        snap = self._snapshot(ctx, now, tier)
        logger.info(
            "ALLOW client=%s path=%s tier=%s level=%s snapshot=%s",
            ctx.client_id, ctx.path, tier, level.value, snap,
        )
        return Decision(allowed=True, detail="放行", snapshot=snap)
