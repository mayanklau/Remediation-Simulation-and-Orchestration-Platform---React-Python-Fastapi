from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.dependencies import database, tenant_context
from app.models import ConnectorProfile, ConnectorRun, Policy, ReportSnapshot, Tenant, now
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
    provider = _normalize_provider(payload.get("provider", "unknown"))
    operation = payload.get("operation", "health_check")
    profile = await db.connector_profiles.find_one({"tenant_id": tenant.id, "provider": provider})
    run = ConnectorRun(
        tenant_id=tenant.id,
        provider=provider,
        operation=operation,
        dry_run=payload.get("dry_run", True),
        endpoint=payload.get("endpoint") or (profile or {}).get("endpoint"),
        payload=payload.get("payload", {}),
        result={
            "status": "dry_run_recorded" if payload.get("dry_run", True) else "submitted",
            "profile_found": bool(profile),
            "auth_mode": (profile or {}).get("auth_mode", payload.get("auth_mode", "manual_secret_reference")),
            "scopes": (profile or {}).get("scopes", []),
        },
    )
    await db.connector_runs.insert_one(run.model_dump(by_alias=True))
    await db.connector_profiles.update_one(
        {"tenant_id": tenant.id, "provider": provider},
        {"$set": {"health": {"status": run.status, "last_checked_at": now(), "operation": operation}, "updated_at": now()}},
    )
    return {"run": run}


@router.get("/connectors")
async def connectors(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {
        "profiles": await db.connector_profiles.find({"tenant_id": tenant.id}).sort("updated_at", -1).to_list(200),
        "runs": await db.connector_runs.find({"tenant_id": tenant.id}).sort("created_at", -1).to_list(50),
        "templates": _connector_templates(),
    }


@router.post("/connectors")
async def create_connector_profile(payload: dict, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    provider = _normalize_provider(payload["provider"])
    scopes = payload.get("scopes", ["read"])
    if isinstance(scopes, str):
        scopes = [scope.strip() for scope in scopes.split(",") if scope.strip()]
    profile = ConnectorProfile(
        tenant_id=tenant.id,
        provider=provider,
        name=payload.get("name") or f"{provider} connector",
        category=payload.get("category", "custom"),
        enabled=payload.get("enabled", True),
        auth_mode=payload.get("auth_mode", payload.get("authMode", "manual_secret_reference")),
        endpoint=payload.get("endpoint"),
        owner=payload.get("owner", "security-operations"),
        scopes=scopes,
        sync_cadence=payload.get("sync_cadence", payload.get("syncCadence", "manual")),
        environment=payload.get("environment", "pilot"),
        config=payload.get("config", {}),
        health={"status": "profile_created", "last_checked_at": now(), "message": "Manual connector profile created. Run a dry-run health check before live execution."},
    )
    data = profile.model_dump(by_alias=True)
    profile_id = data.pop("_id")
    created_at = data.pop("created_at")
    await db.connector_profiles.update_one(
        {"tenant_id": tenant.id, "provider": provider},
        {"$set": data, "$setOnInsert": {"_id": profile_id, "created_at": created_at}},
        upsert=True,
    )
    saved_profile = await db.connector_profiles.find_one({"tenant_id": tenant.id, "provider": provider})
    run = ConnectorRun(
        tenant_id=tenant.id,
        provider=provider,
        operation="profile_created",
        dry_run=True,
        endpoint=profile.endpoint,
        payload={"source": "frontend_integration_form", "category": profile.category, "scopes": scopes},
        result={"status": "profile_appended", "profile_id": saved_profile["_id"], "message": "Integration profile appended from frontend and persisted in backend."},
    )
    await db.connector_runs.insert_one(run.model_dump(by_alias=True))
    return {"profile": saved_profile, "run": run.model_dump(by_alias=True)}


@router.get("/integrations")
async def integrations(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return await connectors(tenant, db)


@router.post("/integrations")
async def create_integration(payload: dict, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return await create_connector_profile(payload, tenant, db)


@router.post("/workers/run")
async def workers_run(payload: dict, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    run = ConnectorRun(tenant_id=tenant.id, provider="worker", operation=payload.get("lane", "simulation"), dry_run=True, payload=payload, result={"processed": payload.get("limit", 5)})
    await db.connector_runs.insert_one(run.model_dump(by_alias=True))
    return {"run": run}


def _normalize_provider(provider: str) -> str:
    cleaned = "".join(char.lower() if char.isalnum() else "-" for char in str(provider).strip())
    return "-".join(part for part in cleaned.split("-") if part) or "custom"


def _connector_templates():
    return [
        {"provider": "tenable", "operation": "ingest_findings", "category": "scanner", "scopes": ["read:findings"]},
        {"provider": "wiz", "operation": "ingest_cloud_findings", "category": "cloud", "scopes": ["read:issues", "read:assets"]},
        {"provider": "jira", "operation": "create_issue", "category": "ticketing", "scopes": ["write:issues", "read:projects"]},
        {"provider": "github", "operation": "create_issue", "category": "code", "scopes": ["repo", "workflow"]},
        {"provider": "servicenow", "operation": "create_change", "category": "itsm", "scopes": ["change:write", "cmdb:read"]},
        {"provider": "qualys", "operation": "ingest_findings", "category": "scanner", "scopes": ["read:vulnerabilities", "read:assets"]},
        {"provider": "snyk", "operation": "ingest_code_findings", "category": "code", "scopes": ["read:issues", "read:projects"]},
        {"provider": "aws-security-hub", "operation": "ingest_security_findings", "category": "cloud", "scopes": ["securityhub:read", "organizations:read"]},
        {"provider": "defender", "operation": "ingest_endpoint_findings", "category": "endpoint", "scopes": ["machine:read", "alerts:read"]},
        {"provider": "crowdstrike", "operation": "ingest_endpoint_findings", "category": "endpoint", "scopes": ["hosts:read", "detections:read"]},
        {"provider": "custom-http", "operation": "health_check", "category": "custom", "scopes": ["read"]},
    ]


@router.get("/reports")
async def reports(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"reports": await db.report_snapshots.find({"tenant_id": tenant.id}).sort("created_at", -1).to_list(200)}


@router.get("/audit")
async def audit(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"audit": await db.audit_logs.find({"tenant_id": tenant.id}).sort("created_at", -1).to_list(200)}
