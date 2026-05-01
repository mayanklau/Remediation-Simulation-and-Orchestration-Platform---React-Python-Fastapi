from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.dependencies import database, tenant_context
from app.models import Tenant
from app.services.remediation import create_workflow, generate_plan, list_actions, run_simulation

router = APIRouter()


@router.get("/remediation-actions")
async def actions(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"actions": await list_actions(db, tenant.id)}


@router.post("/remediation-actions/{action_id}/simulate")
async def simulate(action_id: str, payload: dict | None = None, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    try:
        simulation = await run_simulation(db, tenant.id, action_id, (payload or {}).get("type", "standard"))
        return {"simulation": simulation}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/remediation-actions/{action_id}/plan")
async def plan(action_id: str, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    try:
        remediation_plan = await generate_plan(db, tenant.id, action_id)
        return {"plan": remediation_plan}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/remediation-actions/{action_id}/workflow")
async def workflow(action_id: str, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    try:
        item = await create_workflow(db, tenant.id, action_id)
        return {"workflow": item}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/simulations")
async def simulations(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"simulations": await db.simulations.find({"tenant_id": tenant.id}).sort("created_at", -1).to_list(200)}


@router.get("/workflows")
async def workflows(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"workflows": await db.workflow_items.find({"tenant_id": tenant.id}).sort("updated_at", -1).to_list(200)}

