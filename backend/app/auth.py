from dataclasses import dataclass
from fastapi import Header, HTTPException, Request

ROLE_PERMISSIONS = {
    "tenant_admin": {"*"},
    "security_lead": {"finding:read", "finding:write", "simulation:run", "workflow:approve", "policy:write", "report:read", "automation:run"},
    "security_analyst": {"finding:read", "finding:write", "simulation:run", "workflow:comment", "report:read"},
    "platform_owner": {"asset:read", "simulation:run", "workflow:approve", "automation:run", "evidence:write"},
    "auditor": {"finding:read", "asset:read", "workflow:read", "evidence:read", "report:read", "audit:read"},
    "automation_service": {"simulation:run", "automation:run", "evidence:write", "connector:run"},
}


@dataclass(frozen=True)
class Principal:
    email: str
    role: str
    groups: tuple[str, ...]
    correlation_id: str


def can(role: str, permission: str) -> bool:
    permissions = ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["security_analyst"])
    return "*" in permissions or permission in permissions


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
        correlation_id=x_correlation_id or "local-correlation",
    )


def require_permission(principal: Principal, permission: str) -> None:
    if not can(principal.role, permission):
        raise HTTPException(status_code=403, detail={"error": "forbidden", "permission": permission})
