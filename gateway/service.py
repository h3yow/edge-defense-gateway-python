"""网关装配：默认规则、阈值、分档、回收参数与持久化路径的统一构造入口。"""

from __future__ import annotations

import time

from gateway.engine import DEFAULT_TIER_LIMITS, DefenseEngine
from gateway.models import ReputationLevel, Rule
from gateway.rate_limiter import SlidingWindowRateLimiter
from gateway.reputation import ReputationManager
from gateway.rules import RuleEngine

DEFAULT_RULES = [
    Rule(rule_id="block-admin", path_prefix="/admin", description="拦截后台路径探测"),
    Rule(rule_id="block-env", path_prefix="/.env", description="拦截敏感文件探测"),
]

# 传给 build_engine(tier_limits=...) 表示关闭分档、所有身份统一额度
TIER_LIMITS_DISABLED: object = object()


def build_engine(
    state_path: str = "data/reputation.json",
    limit: int = 10,
    window_seconds: float = 1.0,
    rules: list[Rule] | None = None,
    clock=time.monotonic,
    tier_limits: dict[ReputationLevel, int] | object | None = None,
    base_quarantine_seconds: float = 10.0,
    max_quarantine_seconds: float = 300.0,
    recover_step_seconds: float = 5.0,
    good_bonus_seconds: float = 1.0,
    good_bonus_interval_seconds: float = 0.5,
    inactive_ttl_seconds: float = 3600.0,
    dormant_ttl_seconds: float = 86400.0,
    max_dormant_identities: int = 1000,
    max_events: int = 2000,
    reap_interval_seconds: float = 60.0,
) -> DefenseEngine:
    rule_engine = RuleEngine(list(DEFAULT_RULES if rules is None else rules))
    reputation = ReputationManager(
        state_path=state_path,
        base_quarantine_seconds=base_quarantine_seconds,
        max_quarantine_seconds=max_quarantine_seconds,
        recover_step_seconds=recover_step_seconds,
        good_bonus_seconds=good_bonus_seconds,
        good_bonus_interval_seconds=good_bonus_interval_seconds,
        inactive_ttl_seconds=inactive_ttl_seconds,
        dormant_ttl_seconds=dormant_ttl_seconds,
        max_dormant_identities=max_dormant_identities,
        max_events=max_events,
    )
    reputation.load()
    limiter = SlidingWindowRateLimiter(limit=limit, window_seconds=window_seconds)
    # 分档解析：
    #   None（默认）-> 启用默认分档，且正常身份额度沿用 limit（历史行为不变）；
    #   dict         -> 完全自定义（缺失的档位回落到 limit）；
    #   TIER_LIMITS_DISABLED -> 关闭分档，所有等级统一使用 limit。
    if tier_limits is TIER_LIMITS_DISABLED:
        effective_tiers: dict[ReputationLevel, int] | None = None
    elif tier_limits is None:
        effective_tiers = dict(DEFAULT_TIER_LIMITS)
        effective_tiers[ReputationLevel.NORMAL] = limit
    else:
        effective_tiers = dict(tier_limits)  # type: ignore[arg-type]
    return DefenseEngine(
        rules=rule_engine,
        reputation=reputation,
        limiter=limiter,
        clock=clock,
        tier_limits=effective_tiers,
        reap_interval_seconds=reap_interval_seconds,
    )
