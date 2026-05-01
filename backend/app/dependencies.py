from fastapi import Header, Request
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database import get_db
from app.models import Tenant
from app.services.tenant import get_or_create_tenant


async def tenant_context(x_tenant_id: str | None = Header(default=None)) -> Tenant:
    db = get_db()
    if x_tenant_id:
        found = await db.tenants.find_one({"$or": [{"_id": x_tenant_id}, {"slug": x_tenant_id}]})
        if found:
            return Tenant.model_validate(found)
    return await get_or_create_tenant(db)


def database(request: Request) -> AsyncIOMotorDatabase:
    return get_db()

