from motor.motor_asyncio import AsyncIOMotorDatabase
from app.config import get_settings
from app.models import Tenant, now


async def get_or_create_tenant(db: AsyncIOMotorDatabase, slug: str | None = None) -> Tenant:
    settings = get_settings()
    tenant_slug = slug or settings.default_tenant_slug
    found = await db.tenants.find_one({"slug": tenant_slug})
    if found:
        return Tenant.model_validate(found)
    tenant = Tenant(name=tenant_slug.replace("-", " ").title(), slug=tenant_slug)
    await db.tenants.insert_one(tenant.model_dump(by_alias=True))
    return tenant


async def touch_audit(
    db: AsyncIOMotorDatabase,
    tenant_id: str,
    actor: str,
    action: str,
    entity_type: str,
    entity_id: str | None = None,
    details: dict | None = None,
) -> None:
    await db.audit_logs.insert_one(
        {
            "_id": __import__("uuid").uuid4().hex,
            "tenant_id": tenant_id,
            "actor": actor,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "details": details or {},
            "created_at": now(),
        }
    )

