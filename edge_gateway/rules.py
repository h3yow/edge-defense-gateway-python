"""Declarative rule matching engine.

Rules are evaluated in registration order; the first match wins. A request
that matches no rule is clean and must never be blocked by this dimension.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable

from edge_gateway.models import RequestContext, Rule, ViolationEvent


class RuleEngine:
    def __init__(self, rules: Iterable[Rule] | None = None) -> None:
        self._rules: list[Rule] = []
        self._lock = threading.Lock()
        if rules:
            for rule in rules:
                self.add_rule(rule)

    def add_rule(self, rule: Rule) -> None:
        with self._lock:
            if any(r.rule_id == rule.rule_id for r in self._rules):
                raise ValueError(f"duplicate rule_id: {rule.rule_id}")
            self._rules.append(rule)

    def rules(self) -> tuple[Rule, ...]:
        with self._lock:
            return tuple(self._rules)

    def match(self, request: RequestContext) -> ViolationEvent | None:
        """Return the first matching violation, or None when nothing hits."""
        for rule in self.rules():  # snapshot under lock; matching runs lock-free
            matcher = rule.matcher
            if matcher is not None and matcher(request):
                return ViolationEvent(
                    rule_id=rule.rule_id,
                    rule_description=rule.description,
                    path=request.path,
                )
        return None
