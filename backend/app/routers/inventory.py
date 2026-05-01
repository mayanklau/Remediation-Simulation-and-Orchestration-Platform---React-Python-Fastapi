from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.dependencies import database, tenant_context
from app.models import Asset, Tenant, now

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
async def findings(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"findings": await db.findings.find({"tenant_id": tenant.id}).sort("business_risk_score", -1).to_list(500)}


@router.patch("/findings/{finding_id}")
async def update_finding(finding_id: str, payload: dict, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    payload["updated_at"] = now()
    await db.findings.update_one({"_id": finding_id, "tenant_id": tenant.id}, {"$set": payload})
    return {"finding": await db.findings.find_one({"_id": finding_id, "tenant_id": tenant.id})}

