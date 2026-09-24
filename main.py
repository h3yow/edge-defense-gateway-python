"""FastAPI service exposing the local defense gateway.

Two protected entries share one gateway (and therefore one consistent local
state):

* ``/api/...``    -- public API entry
* ``/portal/...`` -- portal entry

Client identity is taken from the ``X-Client-Id`` header (default
``anonymous``), so local testing can simulate arbitrary sources.

Deny HTTP status codes:

* ``403`` -- rule violation or in-quarantine rejection
* ``429`` -- sliding-window rate limit
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from edge_gateway.config import build_gateway
from edge_gateway.models import DenyReason, RequestContext

app = FastAPI(title="edge-defense-gateway")
gateway = build_gateway()


async def _to_context(request: Request, entrypoint: str, path: str) -> RequestContext:
    body = await request.body()
    return RequestContext(
        identity=request.headers.get("x-client-id", "anonymous"),
        path=f"/{path}",
        method=request.method,
        headers={k.lower(): v for k, v in request.headers.items()},
        body=body,
        entrypoint=entrypoint,
    )


def _deny_status(reason: DenyReason | None) -> int:
    if reason is DenyReason.RATE_LIMITED:
        return 429
    return 403


def _ok_body(entrypoint: str, path: str, decision) -> dict:
    return {
        "status": "ok",
        "entrypoint": entrypoint,
        "echo_path": path,
        "decision": decision.to_dict(),
    }


@app.get("/")
def root():
    return {"service": "edge-defense-gateway", "status": "ok"}


@app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def api_entry(request: Request, path: str):
    context = await _to_context(request, "api", path)
    decision = gateway.inspect(context)
    if decision.allowed:
        return _ok_body("api", path, decision)
    return JSONResponse(status_code=_deny_status(decision.reason), content=decision.to_dict())


@app.api_route("/portal/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def portal_entry(request: Request, path: str):
    context = await _to_context(request, "portal", path)
    decision = gateway.inspect(context)
    if decision.allowed:
        return _ok_body("portal", path, decision)
    return JSONResponse(status_code=_deny_status(decision.reason), content=decision.to_dict())


@app.get("/admin/clients/{identity:path}")
def client_state(identity: str):
    return gateway.client_snapshot(identity)
