from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.dependencies import database, tenant_context
from app.models import ConnectorRun, Policy, ReportSnapshot, Tenant
from app.services.agentic import build_agentic_model, run_agentic_plan
from app.services.attack_paths import build_attack_path_model, snapshot_attack_path_model
from app.services.tenant import touch_audit
from app.services.virtual_patching import activate_virtual_patching, build_virtual_patching_model

router = APIRouter()


@router.get("/virtual-patching")
async def virtual_patching(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return await build_virtual_patching_model(db, tenant.id)


@router.post("/virtual-patching")
async def activate_vp(payload: dict | None = None, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return await activate_virtual_patching(db, tenant.id)


@router.get("/attack-paths")
async def attack_paths(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"attack_paths": await build_attack_path_model(db, tenant.id)}


@router.post("/attack-paths")
async def snapshot_attack_paths(payload: dict | None = None, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    if payload and payload.get("action") not in [None, "snapshot"]:
        return {"error": "Unsupported attack path action"}
    return await snapshot_attack_path_model(db, tenant.id)


@router.get("/agentic")
async def agentic(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"agentic": await build_agentic_model(db, tenant.id)}


@router.post("/agentic")
async def run_agentic(payload: dict, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    result = await run_agentic_plan(db, tenant.id, payload)
    return {"result": result, "agentic": await build_agentic_model(db, tenant.id)}


@router.get("/policies")
async def policies(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"policies": await db.policies.find({"tenant_id": tenant.id}).sort("created_at", -1).to_list(200)}


@router.post("/policies")
async def create_policy(payload: dict, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    policy = Policy(tenant_id=tenant.id, name=payload["name"], policy_type=payload.get("policy_type", "governance"), rules=payload.get("rules", {}), enabled=payload.get("enabled", True))
    await db.policies.insert_one(policy.model_dump(by_alias=True))
    await touch_audit(db, tenant.id, "policy-engine", "policy_created", "policy", policy.id)
    return {"policy": policy}


@router.post("/governance/continuous-simulation")
async def continuous_simulation(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    report = ReportSnapshot(tenant_id=tenant.id, name="Continuous simulation readiness", type="continuous_simulation", data={"status": "enabled", "dry_run": True})
    await db.report_snapshots.insert_one(report.model_dump(by_alias=True))
    return {"report": report}


@router.get("/governance/predictive-risk")
async def predictive_risk(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    findings = await db.findings.find({"tenant_id": tenant.id}).to_list(500)
    projected = sum(f.get("business_risk_score", 0) for f in findings if f.get("status") == "OPEN") * 0.82
    return {"projected_residual_risk": round(projected, 2), "confidence": 0.76, "drivers": ["open critical findings", "internet exposure", "missing simulation coverage"]}


@router.post("/governance/apply-fix")
async def apply_fix(payload: dict, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    run = ConnectorRun(tenant_id=tenant.id, provider=payload.get("provider", "governance"), operation="apply_fix", dry_run=payload.get("dry_run", True), payload=payload, result={"status": "planned"})
    await db.connector_runs.insert_one(run.model_dump(by_alias=True))
    return {"run": run}


@router.post("/connectors/live")
async def connector_live(payload: dict, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    run = ConnectorRun(
        tenant_id=tenant.id,
        provider=payload.get("provider", "unknown"),
        operation=payload.get("operation", "unknown"),
        dry_run=payload.get("dry_run", True),
        endpoint=payload.get("endpoint"),
        payload=payload.get("payload", {}),
        result={"status": "dry_run_recorded" if payload.get("dry_run", True) else "submitted"},
    )
    await db.connector_runs.insert_one(run.model_dump(by_alias=True))
    return {"run": run}


@router.post("/workers/run")
async def workers_run(payload: dict, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    run = ConnectorRun(tenant_id=tenant.id, provider="worker", operation=payload.get("lane", "simulation"), dry_run=True, payload=payload, result={"processed": payload.get("limit", 5)})
    await db.connector_runs.insert_one(run.model_dump(by_alias=True))
    return {"run": run}


@router.get("/reports")
async def reports(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"reports": await db.report_snapshots.find({"tenant_id": tenant.id}).sort("created_at", -1).to_list(200)}


@router.get("/audit")
async def audit(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"audit": await db.audit_logs.find({"tenant_id": tenant.id}).sort("created_at", -1).to_list(200)}
