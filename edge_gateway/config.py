"""Default rule set and gateway wiring used by the FastAPI service."""

from __future__ import annotations

import re
from pathlib import Path

from edge_gateway.clock import SystemClock
from edge_gateway.gateway import DefenseGateway
from edge_gateway.models import RequestContext, Rule
from edge_gateway.reputation import ReputationManager
from edge_gateway.rules import RuleEngine
from edge_gateway.store import JsonFileStore

# Default protection policy (kept intentionally small and explainable):
#   5 requests / 10 s sliding window per identity,
#   30 s base quarantine, 15 s per recovery cooldown stage.
DEFAULT_LIMIT = 5
DEFAULT_WINDOW_SECONDS = 10.0
DEFAULT_QUARANTINE_SECONDS = 30.0
DEFAULT_RECOVERY_COOLDOWN_SECONDS = 15.0

_TRAVERSAL_RE = re.compile(r"\.\.[\\/]|%2e%2e[\\/]|%c0%af", re.IGNORECASE)
_SQLI_RE = re.compile(
    r"(?:'\s*or\s*'?\d*'?\s*=\s*'?\d*)|(?:--\s)|(?:;\s*drop\s+table)|(?:union\s+select)",
    re.IGNORECASE,
)
_XSS_RE = re.compile(r"<\s*script|javascript:|onerror\s*=|onload\s*=", re.IGNORECASE)
_ADMIN_RE = re.compile(r"(^|/)admin(/|$)|(^|/)\.internal(/|$)", re.IGNORECASE)


def _text_blob(request: RequestContext) -> str:
    parts = [request.path]
    parts.extend(f"{k}: {v}" for k, v in request.headers.items())
    parts.append(request.body.decode("utf-8", errors="ignore"))
    return "\n".join(parts)


def _match_traversal(request: RequestContext) -> bool:
    return bool(_TRAVERSAL_RE.search(request.path))


def _match_admin_path(request: RequestContext) -> bool:
    return bool(_ADMIN_RE.search(request.path))


def _match_sqli(request: RequestContext) -> bool:
    return bool(_SQLI_RE.search(_text_blob(request)))


def _match_xss(request: RequestContext) -> bool:
    return bool(_XSS_RE.search(_text_blob(request)))


def build_default_rules() -> list[Rule]:
    return [
        Rule("R001", "路径穿越攻击 (../ 或编码变体)", _match_traversal),
        Rule("R002", "禁止访问管理/内部路径", _match_admin_path),
        Rule("R003", "疑似 SQL 注入特征", _match_sqli),
        Rule("R004", "疑似 XSS 脚本注入特征", _match_xss),
    ]


def build_gateway(data_dir: str | Path = "./data") -> DefenseGateway:
    data_path = Path(data_dir)
    data_path.mkdir(parents=True, exist_ok=True)
    store = JsonFileStore(
        state_path=data_path / "client_states.json",
        audit_path=data_path / "audit.jsonl",
    )
    clock = SystemClock()
    rule_engine = RuleEngine(build_default_rules())
    reputation = ReputationManager(
        store=store,
        clock=clock,
        quarantine_seconds=DEFAULT_QUARANTINE_SECONDS,
        recovery_cooldown_seconds=DEFAULT_RECOVERY_COOLDOWN_SECONDS,
    )
    return DefenseGateway(
        rule_engine=rule_engine,
        reputation=reputation,
        store=store,
        clock=clock,
        base_limit=DEFAULT_LIMIT,
        window_seconds=DEFAULT_WINDOW_SECONDS,
    )


def build_inmemory_gateway() -> DefenseGateway:
    """Gateway with purely in-memory state (isolated unit/integration tests)."""
    from edge_gateway.store import InMemoryStore

    store = InMemoryStore()
    clock = SystemClock()
    rule_engine = RuleEngine(build_default_rules())
    reputation = ReputationManager(
        store=store,
        clock=clock,
        quarantine_seconds=DEFAULT_QUARANTINE_SECONDS,
        recovery_cooldown_seconds=DEFAULT_RECOVERY_COOLDOWN_SECONDS,
    )
    return DefenseGateway(
        rule_engine=rule_engine,
        reputation=reputation,
        store=store,
        clock=clock,
        base_limit=DEFAULT_LIMIT,
        window_seconds=DEFAULT_WINDOW_SECONDS,
    )
