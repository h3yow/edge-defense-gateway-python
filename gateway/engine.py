"""判定编排：同一请求依次经过规则、信誉、限流三个维度。

固定顺序（拒绝原因因此稳定、可区分、可解释）：
    1. 规则匹配   命中 -> 拒绝 rule_matched，并登记一次“规则违规”
    2. 信誉隔离   隔离中 -> 拒绝 quarantined（不占限流额度）
    3. 速率判定   按当前信誉等级对应的分档阈值判定，
                  窗口超限 -> 拒绝 rate_limited（不记规则违规）
    其余 -> 放行

规则违规会累积到信誉系统：连续命中规则最终升级为隔离。
限流拒绝不累积信誉（客户端可能只是突发，不应被定性为恶意），
但限流与规则拦截的 reason 明确区分。

信誉分档限流：
    tier_limits 给出每个信誉等级的窗口阈值；身份等级一旦变化，
    下一次请求立即按新档位判定。未配置的档位回落到限流器自身阈值，
    因此默认直连构造（不传 tier_limits）与历史行为完全一致。

状态回收：
    引擎每 reap_interval_seconds 触发一次信誉系统的不活跃身份回收，
    同时同步清理限流器内对应身份的窗口计数。
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

# 装配层默认分档（service.build_engine 使用）：
# 正常身份额度与历史默认 10/s 保持一致；信誉越差阈值越低。
DEFAULT_TIER_LIMITS: dict[ReputationLevel, int] = {
    ReputationLevel.NORMAL: 10,
    ReputationLevel.SUSPECT: 5,
    ReputationLevel.RESTRICTED: 2,
    ReputationLevel.QUARANTINED: 0,
}


class DefenseEngine:
    def __init__(
        self,
        rules: RuleEngine,
        reputation: ReputationManager,
        limiter: SlidingWindowRateLimiter,
        clock=time.monotonic,
        tier_limits: dict[ReputationLevel, int] | None = None,
        reap_interval_seconds: float = 60.0,
    ) -> None:
        self.rules = rules
        self.reputation = reputation
        self.limiter = limiter
        self._clock = clock
        # None 表示不分档：所有等级都回落到 limiter 自带阈值（老行为）
        self.tier_limits = tier_limits
        self.reap_interval_seconds = reap_interval_seconds
        self._reap_lock = threading.Lock()
        self._last_reap_at: float | None = None

    def _tier_limit(self, level: ReputationLevel) -> int | None:
        """返回该等级生效阈值；未配置分档时返回 None（使用限流器默认阈值）。"""
        if self.tier_limits is None:
            return None
        return self.tier_limits.get(level, self.limiter.limit)

    def _snapshot(self, ctx: RequestContext, now: float, level: ReputationLevel | None = None) -> dict:
        if level is None:
            level = self.reputation.get_level(ctx.client_id, now)
        limit = self._tier_limit(level)
        rate_snap = self.limiter.snapshot(ctx.client_id, now, limit=limit)
        # 显式标注本次判定使用的信誉档位，响应里可直接看到“哪一档、剩多少”
        rate_snap["tier"] = level.value
        return {
            "client_id": ctx.client_id,
            "path": ctx.path,
            "method": ctx.method,
            "rate_limit": rate_snap,
            "reputation": self.reputation.snapshot(ctx.client_id, now),
        }

    def _maybe_reap(self, now: float) -> None:
        """按固定间隔触发回收；多入口并发下用锁保证只执行一次。"""
        if self._last_reap_at is not None and now - self._last_reap_at < self.reap_interval_seconds:
            return
        with self._reap_lock:
            if self._last_reap_at is not None and now - self._last_reap_at < self.reap_interval_seconds:
                return
            result = self.reputation.reap_inactive(now)
            for cid in result["reaped"]:
                self.limiter.reset(cid)
            self._last_reap_at = now
            if result["reaped"] or result["forgotten"]:
                logger.info("REAP at=%s result=%s", now, result)

    def evaluate(self, ctx: RequestContext) -> Decision:
        now = self._clock()
        self._maybe_reap(now)

        # 维度 1：规则匹配
        rule = self.rules.match(ctx)
        if rule is not None:
            level = self.reputation.record_violation(ctx.client_id, "rule_matched", now)
            snap = self._snapshot(ctx, now, level)
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

        # 维度 2：信誉隔离（隔离期内一律拒绝，不消耗限流额度）。
        # note_clean_activity 同时完成：时间驱动恢复推进 + 良好表现进度奖励。
        level = self.reputation.note_clean_activity(ctx.client_id, now)
        if level is ReputationLevel.QUARANTINED:
            snap = self._snapshot(ctx, now, level)
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

        # 维度 3：滑动窗口限流（原子判定 + 登记，阈值按当前信誉等级取档）
        limit = self._tier_limit(level)
        if not self.limiter.check(ctx.client_id, now, limit=limit):
            snap = self._snapshot(ctx, now, level)
            effective_limit = self.limiter.limit if limit is None else limit
            logger.info(
                "DENY client=%s path=%s reason=rate_limited tier=%s snapshot=%s",
                ctx.client_id, ctx.path, level.value, snap,
            )
            return Decision(
                allowed=False,
                reason=DenyReason.RATE_LIMITED,
                detail=(
                    f"超过信誉档位 {level.value} 的滑动窗口限额 "
                    f"{effective_limit} 次/{self.limiter.window_seconds:g}s"
                ),
                snapshot=snap,
            )

        snap = self._snapshot(ctx, now, level)
        logger.info(
            "ALLOW client=%s path=%s tier=%s snapshot=%s",
            ctx.client_id, ctx.path, level.value, snap,
        )
        return Decision(allowed=True, detail="放行", snapshot=snap)
