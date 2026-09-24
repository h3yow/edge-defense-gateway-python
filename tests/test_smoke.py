"""骨架冒烟测试：仅验证包可导入、对象可构造、枚举稳定。"""

from gateway.models import DenyReason, ReputationLevel, RequestContext, Rule
from gateway.rate_limiter import SlidingWindowRateLimiter
from gateway.reputation import ReputationManager
from gateway.rules import RuleEngine


def test_skeleton_imports_and_constructs():
    assert DenyReason.RULE_MATCHED.value == "rule_matched"
    assert DenyReason.QUARANTINED.value == "quarantined"
    assert DenyReason.RATE_LIMITED.value == "rate_limited"
    assert ReputationLevel.QUARANTINED.value == "quarantined"
    ctx = RequestContext(client_id="c1", path="/")
    assert ctx.client_id == "c1"
    Rule(rule_id="r1", path_prefix="/admin")
    RuleEngine([])
    SlidingWindowRateLimiter(limit=5, window_seconds=1.0)
    ReputationManager()
