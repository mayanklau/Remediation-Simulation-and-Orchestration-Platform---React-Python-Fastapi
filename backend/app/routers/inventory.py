from fastapi import APIRouter, Depends, Request
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.auth import Principal, principal_context, require_permission
from app.dependencies import database, tenant_context
from app.models import Asset, Tenant, now
from app.repositories import list_findings

router = APIRouter()


@router.get("/assets")
async def assets(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"assets": await db.assets.find({"tenant_id": tenant.id}).sort("updated_at", -1).to_list(300)}


@router.post("/assets")
async def create_asset(payload: dict, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    asset = Asset(tenant_id=tenant.id, **payload)
    await db.assets.insert_one(asset.model_dump(by_alias=True))
    return {"asset": asset}


@router.get("/findings")
async def findings(
    request: Request,
    tenant: Tenant = Depends(tenant_context),
    db: AsyncIOMotorDatabase = Depends(database),
    principal: Principal = Depends(principal_context),
):
    require_permission(principal, "finding:read")
    return {
        "findings": await list_findings(db, tenant.id, request.query_params.get("status"), request.query_params.get("severity"), 500),
        "correlation_id": principal.correlation_id,
    }


@router.patch("/findings/{finding_id}")
async def update_finding(finding_id: str, payload: dict, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    payload["updated_at"] = now()
    await db.findings.update_one({"_id": finding_id, "tenant_id": tenant.id}, {"$set": payload})
    return {"finding": await db.findings.find_one({"_id": finding_id, "tenant_id": tenant.id})}
