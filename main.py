"""FastAPI 入口：HTTP 入口与直接调用 engine 共用同一套判定与状态。

状态码映射（原因可区分且稳定）：
    放行             200
    rule_matched    403
    quarantined     403（X-Deny-Reason 区分）
    rate_limited    429

响应体包含判定依据 detail 与状态快照 snapshot；X-Deny-Reason 头给出稳定原因码。
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from gateway.engine import DefenseEngine
from gateway.models import DenyReason, RequestContext
from gateway.service import build_engine

_DENY_STATUS = {
    DenyReason.RULE_MATCHED: 403,
    DenyReason.QUARANTINED: 403,
    DenyReason.RATE_LIMITED: 429,
}


def create_app(gateway_engine: DefenseEngine | None = None) -> FastAPI:
    app = FastAPI(title="edge-defense-gateway")
    app.state.engine = gateway_engine or build_engine(state_path="data/reputation.json")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.api_route("/gateway/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
    async def gateway_entry(path: str, request: Request) -> JSONResponse:
        engine = request.app.state.engine
        ctx = RequestContext(
            client_id=request.headers.get(
                "X-Client-Id",
                request.client.host if request.client else "anonymous",
            ),
            path=f"/{path}",
            method=request.method,
            ip=request.client.host if request.client else "",
            headers={k: v for k, v in request.headers.items()},
        )
        decision = engine.evaluate(ctx)
        body = {
            "allowed": decision.allowed,
            "reason": decision.reason.value if decision.reason else None,
            "detail": decision.detail,
            "rule_id": decision.rule_id,
            "snapshot": decision.snapshot,
        }
        if decision.allowed:
            return JSONResponse(status_code=200, content=body)
        resp = JSONResponse(status_code=_DENY_STATUS[decision.reason], content=body)
        resp.headers["X-Deny-Reason"] = decision.reason.value
        return resp

    return app


app = create_app()
