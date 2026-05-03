from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.config import get_settings
from app.dependencies import database, tenant_context
from app.models import Tenant
from app.services.dashboard import asset_graph, dashboard
from app.services.application_logic_readiness import build_application_logic_readiness_model
from app.services.cyber_risk_intelligence import build_cyber_risk_intelligence_model
from app.services.enterprise_readiness import build_enterprise_readiness_catalog
from app.services.go_live import build_go_live_model
from app.services.production_effectiveness import build_production_effectiveness_model
from app.services.production_expansion import build_production_expansion_model
from app.services.production_reality import build_production_reality_model

router = APIRouter()


@router.get("/health")
async def health(db: AsyncIOMotorDatabase = Depends(database)):
    await db.command("ping")
    return {"status": "ok", "service": get_settings().app_name}


@router.get("/tenants")
async def tenants(db: AsyncIOMotorDatabase = Depends(database)):
    return {"tenants": await db.tenants.find({}).sort("created_at", -1).to_list(100)}


@router.post("/tenants")
async def create_tenant(payload: dict, db: AsyncIOMotorDatabase = Depends(database)):
    tenant = Tenant(name=payload["name"], slug=payload["slug"])
    await db.tenants.insert_one(tenant.model_dump(by_alias=True))
    return {"tenant": tenant}


@router.get("/dashboard")
async def get_dashboard(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return await dashboard(db, tenant.id)


@router.get("/asset-graph")
async def get_asset_graph(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return await asset_graph(db, tenant.id)


@router.get("/cyber-risk-intelligence")
async def cyber_risk_intelligence():
    return {"intelligence": build_cyber_risk_intelligence_model()}


@router.get("/observability")
async def observability(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    failures = await db.connector_runs.count_documents({"tenant_id": tenant.id, "status": {"$in": ["FAILED", "ERROR"]}})
    return {
        "tenant_id": tenant.id,
        "mongo": "connected",
        "failed_connector_runs": failures,
        "otel_configured": bool(get_settings().otel_exporter_otlp_endpoint),
        "alerts_configured": bool(get_settings().alert_webhook_url),
    }


@router.get("/enterprise-readiness")
async def enterprise_readiness():
    return {"readiness": build_enterprise_readiness_catalog()}


@router.get("/application-logic-readiness")
async def application_logic_readiness():
    return {"application_logic": build_application_logic_readiness_model()}


@router.get("/production-expansion")
async def production_expansion():
    return {"expansion": build_production_expansion_model()}


@router.get("/production-effectiveness")
async def production_effectiveness():
    return {"effectiveness": build_production_effectiveness_model()}


@router.get("/production-reality")
async def production_reality():
    return {"reality": build_production_reality_model()}


@router.get("/go-live")
async def go_live():
    return {"go_live": build_go_live_model()}
