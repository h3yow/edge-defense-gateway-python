"""规则匹配维度：基于路径前缀与方法的静态规则表。

判定原则：只有明确命中的规则才拒绝；规则不命中时正常放行，不得误伤。
"""

from __future__ import annotations

from gateway.models import RequestContext, Rule


class RuleEngine:
    """维护规则集合并对请求做命中判定。"""

    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules: list[Rule] = list(rules or [])

    def add_rule(self, rule: Rule) -> None:
        """追加一条规则。rule_id 重复时抛错，保证拒绝原因可追溯到唯一规则。"""
        if any(r.rule_id == rule.rule_id for r in self._rules):
            raise ValueError(f"duplicated rule_id: {rule.rule_id}")
        self._rules.append(rule)

    def match(self, ctx: RequestContext) -> Rule | None:
        """返回第一条命中的规则；未命中返回 None。

        命中条件：请求路径以规则 path_prefix 开头（区分大小写），
        且方法在规则 methods 集合内；methods 为空表示匹配全部方法。
        """
        for rule in self._rules:
            if not ctx.path.startswith(rule.path_prefix):
                continue
            if rule.methods and ctx.method.upper() not in {m.upper() for m in rule.methods}:
                continue
            return rule
        return None
