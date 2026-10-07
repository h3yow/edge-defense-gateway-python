"""网关装配：默认规则、阈值与持久化路径的统一构造入口。"""

from __future__ import annotations

import time

from gateway.engine import DefenseEngine
from gateway.models import ReputationLevel, Rule
from gateway.rate_limiter import SlidingWindowRateLimiter
from gateway.reputation import ReputationManager
from gateway.rules import RuleEngine

DEFAULT_RULES = [
    Rule(rule_id="block-admin", path_prefix="/admin", description="拦截后台路径探测"),
    Rule(rule_id="block-env", path_prefix="/.env", description="拦截敏感文件探测"),
]


def default_level_limits(limit: int) -> dict[ReputationLevel, int]:
    """默认分档：正常身份与旧行为一致；信誉越差额度越低。

    normal = limit（不变），suspect = limit/2，restricted = limit/4（至少 1）。
    隔离身份在限流之前已被整体拒绝，无需档位。
    """
    return {
        ReputationLevel.NORMAL: limit,
        ReputationLevel.SUSPECT: max(1, limit // 2),
        ReputationLevel.RESTRICTED: max(1, limit // 4),
    }


def build_engine(
    state_path: str = "data/reputation.json",
    limit: int = 10,
    window_seconds: float = 1.0,
    rules: list[Rule] | None = None,
    clock=time.monotonic,
    level_limits: dict[ReputationLevel, int] | None = None,
    good_accel_steps: int = 2,
    gc_idle_seconds: float = 3600.0,
    max_events_per_client: int = 100,
    gc_archive_seconds: float = 7 * 24 * 3600.0,
    gc_archive_max_entries: int = 10000,
) -> DefenseEngine:
    rule_engine = RuleEngine(list(DEFAULT_RULES if rules is None else rules))
    reputation = ReputationManager(
        state_path=state_path,
        good_accel_steps=good_accel_steps,
        gc_idle_seconds=gc_idle_seconds,
        max_events_per_client=max_events_per_client,
        gc_archive_seconds=gc_archive_seconds,
        gc_archive_max_entries=gc_archive_max_entries,
    )
    reputation.load()
    limiter = SlidingWindowRateLimiter(limit=limit, window_seconds=window_seconds)
    return DefenseEngine(
        rules=rule_engine,
        reputation=reputation,
        limiter=limiter,
        clock=clock,
        level_limits=default_level_limits(limit) if level_limits is None else level_limits,
    )
