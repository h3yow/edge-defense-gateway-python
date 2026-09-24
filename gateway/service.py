"""网关装配：默认规则、阈值与持久化路径的统一构造入口。"""

from __future__ import annotations

import time

from gateway.engine import DefenseEngine
from gateway.models import Rule
from gateway.rate_limiter import SlidingWindowRateLimiter
from gateway.reputation import ReputationManager
from gateway.rules import RuleEngine

DEFAULT_RULES = [
    Rule(rule_id="block-admin", path_prefix="/admin", description="拦截后台路径探测"),
    Rule(rule_id="block-env", path_prefix="/.env", description="拦截敏感文件探测"),
]


def build_engine(
    state_path: str = "data/reputation.json",
    limit: int = 10,
    window_seconds: float = 1.0,
    rules: list[Rule] | None = None,
    clock=time.monotonic,
) -> DefenseEngine:
    rule_engine = RuleEngine(list(DEFAULT_RULES if rules is None else rules))
    reputation = ReputationManager(state_path=state_path)
    reputation.load()
    limiter = SlidingWindowRateLimiter(limit=limit, window_seconds=window_seconds)
    return DefenseEngine(
        rules=rule_engine,
        reputation=reputation,
        limiter=limiter,
        clock=clock,
    )
