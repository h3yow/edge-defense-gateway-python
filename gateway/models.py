"""共享类型定义：请求上下文、规则、信誉等级与判定结论。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DenyReason(str, Enum):
    """拒绝原因，取值稳定可区分，用于日志与调用方判断。"""

    RULE_MATCHED = "rule_matched"
    QUARANTINED = "quarantined"
    RATE_LIMITED = "rate_limited"


class ReputationLevel(str, Enum):
    """信誉等级：正常 -> 观察 -> 限制 -> 隔离。"""

    NORMAL = "normal"
    SUSPECT = "suspect"
    RESTRICTED = "restricted"
    QUARANTINED = "quarantined"


@dataclass(frozen=True)
class RequestContext:
    """一次请求的最小上下文。client_id 为限流与信誉归属的身份。"""

    client_id: str
    path: str
    method: str = "GET"
    ip: str = ""
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Rule:
    """一条防护规则。path_prefix 匹配路径前缀，methods 为空表示全部方法。"""

    rule_id: str
    path_prefix: str
    methods: frozenset[str] = frozenset()
    description: str = ""


@dataclass(frozen=True)
class Decision:
    """网关对一次请求的最终判定。"""

    allowed: bool
    reason: DenyReason | None = None
    detail: str = ""
    rule_id: str | None = None
    snapshot: dict = field(default_factory=dict)
