"""规则引擎：命中、未命中、方法限定的确定性验证。"""

import logging

from gateway.models import RequestContext, Rule
from gateway.rules import RuleEngine

logging.basicConfig(level=logging.INFO)


def _engine() -> RuleEngine:
    return RuleEngine(
        [
            Rule(rule_id="block-admin", path_prefix="/admin"),
            Rule(rule_id="post-only", path_prefix="/write", methods=frozenset({"POST"})),
        ]
    )


def test_rule_hit_blocks_and_miss_passes():
    eng = _engine()
    hit = eng.match(RequestContext(client_id="c1", path="/admin/console"))
    miss = eng.match(RequestContext(client_id="c1", path="/index.html"))
    logging.info("rule hit=%s miss=%s", hit, miss)
    assert hit is not None and hit.rule_id == "block-admin"
    assert miss is None


def test_method_scoped_rule():
    eng = _engine()
    post = eng.match(RequestContext(client_id="c1", path="/write/data", method="POST"))
    get = eng.match(RequestContext(client_id="c1", path="/write/data", method="GET"))
    logging.info("method-scoped post=%s get=%s", post, get)
    assert post is not None and post.rule_id == "post-only"
    assert get is None


def test_duplicated_rule_id_rejected():
    eng = _engine()
    import pytest

    with pytest.raises(ValueError):
        eng.add_rule(Rule(rule_id="block-admin", path_prefix="/x"))
