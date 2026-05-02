from dataclasses import dataclass
from re import Pattern, compile
from uuid import uuid4
from fastapi import Header, HTTPException, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

ROLE_PERMISSIONS = {
    "tenant_admin": {"*"},
    "security_lead": {"tenant:read", "tenant:write", "asset:read", "asset:write", "finding:read", "finding:write", "simulation:read", "simulation:run", "workflow:read", "workflow:comment", "workflow:approve", "policy:read", "policy:write", "report:read", "audit:read", "automation:run", "connector:read", "connector:run", "evidence:read", "evidence:write"},
    "security_analyst": {"tenant:read", "asset:read", "finding:read", "finding:write", "simulation:read", "simulation:run", "workflow:read", "workflow:comment", "report:read", "connector:read", "evidence:read"},
    "platform_owner": {"tenant:read", "asset:read", "asset:write", "finding:read", "simulation:read", "simulation:run", "workflow:read", "workflow:approve", "automation:run", "evidence:read", "evidence:write", "connector:read", "connector:run", "report:read"},
    "auditor": {"tenant:read", "finding:read", "asset:read", "workflow:read", "evidence:read", "report:read", "audit:read", "policy:read", "connector:read"},
    "automation_service": {"tenant:read", "asset:read", "finding:read", "simulation:read", "simulation:run", "automation:run", "evidence:write", "connector:read", "connector:run", "report:read"},
}


ROUTE_PERMISSIONS: list[tuple[Pattern[str], set[str], str]] = [
    (compile(r"^/api/health$"), {"GET"}, "tenant:read"),
    (compile(r"^/api/tenants$"), {"GET"}, "tenant:read"),
    (compile(r"^/api/tenants$"), {"POST"}, "tenant:write"),
    (compile(r"^/api/dashboard$"), {"GET"}, "report:read"),
    (compile(r"^/api/assets$"), {"GET"}, "asset:read"),
    (compile(r"^/api/assets$"), {"POST"}, "asset:write"),
    (compile(r"^/api/asset-graph$"), {"GET"}, "asset:read"),
    (compile(r"^/api/findings(/.+)?$"), {"GET"}, "finding:read"),
    (compile(r"^/api/findings(/.+)?$"), {"POST", "PATCH", "PUT", "DELETE"}, "finding:write"),
    (compile(r"^/api/ingest/.+$"), {"POST"}, "connector:run"),
    (compile(r"^/api/mock-ingest$"), {"POST"}, "connector:run"),
    (compile(r"^/api/remediation-actions$"), {"GET"}, "finding:read"),
    (compile(r"^/api/remediation-actions/.+/simulate$"), {"POST"}, "simulation:run"),
    (compile(r"^/api/remediation-actions/.+/plan$"), {"POST"}, "simulation:run"),
    (compile(r"^/api/remediation-actions/.+/workflow$"), {"POST"}, "workflow:approve"),
    (compile(r"^/api/simulations$"), {"GET"}, "simulation:read"),
    (compile(r"^/api/workflows$"), {"GET"}, "workflow:read"),
    (compile(r"^/api/virtual-patching$"), {"GET"}, "finding:read"),
    (compile(r"^/api/virtual-patching$"), {"POST"}, "automation:run"),
    (compile(r"^/api/attack-paths$"), {"GET"}, "finding:read"),
    (compile(r"^/api/attack-paths$"), {"POST"}, "report:read"),
    (compile(r"^/api/agentic$"), {"GET"}, "report:read"),
    (compile(r"^/api/agentic$"), {"POST"}, "automation:run"),
    (compile(r"^/api/policies$"), {"GET"}, "policy:read"),
    (compile(r"^/api/policies$"), {"POST"}, "policy:write"),
    (compile(r"^/api/governance/.+$"), {"GET"}, "report:read"),
    (compile(r"^/api/governance/.+$"), {"POST"}, "automation:run"),
    (compile(r"^/api/connectors$"), {"GET"}, "connector:read"),
    (compile(r"^/api/connectors$"), {"POST"}, "connector:run"),
    (compile(r"^/api/integrations$"), {"GET"}, "connector:read"),
    (compile(r"^/api/integrations$"), {"POST"}, "connector:run"),
    (compile(r"^/api/connectors/.+$"), {"POST"}, "connector:run"),
    (compile(r"^/api/workers/.+$"), {"POST"}, "automation:run"),
    (compile(r"^/api/reports$"), {"GET"}, "report:read"),
    (compile(r"^/api/audit$"), {"GET"}, "audit:read"),
    (compile(r"^/api/observability$"), {"GET"}, "audit:read"),
]


@dataclass(frozen=True)
class Principal:
    email: str
    role: str
    groups: tuple[str, ...]
    correlation_id: str


def can(role: str, permission: str) -> bool:
    permissions = ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["security_analyst"])
    return "*" in permissions or permission in permissions


def route_permission_for(path: str, method: str) -> str:
    for pattern, methods, permission in ROUTE_PERMISSIONS:
        if method.upper() in methods and pattern.match(path):
            return permission
    return "tenant:read"


async def principal_context(
    request: Request,
    x_user_email: str | None = Header(default=None),
    x_role: str | None = Header(default=None),
    x_correlation_id: str | None = Header(default=None),
) -> Principal:
    return Principal(
        email=x_user_email or "local-user@example.com",
        role=x_role or "security_analyst",
        groups=tuple(filter(None, (request.headers.get("x-groups") or "").split(","))),
        correlation_id=x_correlation_id or request.headers.get("x-request-id") or str(uuid4()),
    )


def require_permission(principal: Principal, permission: str) -> None:
    if not can(principal.role, permission):
        raise HTTPException(status_code=403, detail={"error": "forbidden", "permission": permission})


class AuthzMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or str(uuid4())
        correlation_id = request.headers.get("x-correlation-id") or request_id
        if request.url.path.startswith("/api/"):
            permission = route_permission_for(request.url.path, request.method)
            role = request.headers.get("x-role") or "tenant_admin"
            if not can(role, permission):
                return Response(
                    content=f'{{"error":"forbidden","permission":"{permission}","request_id":"{request_id}"}}',
                    media_type="application/json",
                    status_code=403,
                    headers={"x-request-id": request_id, "x-correlation-id": correlation_id},
                )
        response = await call_next(request)
        response.headers["x-request-id"] = request_id
        response.headers["x-correlation-id"] = correlation_id
        return response
