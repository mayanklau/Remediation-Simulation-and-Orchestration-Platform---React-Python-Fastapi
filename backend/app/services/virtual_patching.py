from motor.motor_asyncio import AsyncIOMotorDatabase
from app.models import ConnectorRun, Policy, now
from app.services.remediation import generate_plan, run_simulation
from app.services.tenant import touch_audit


def recommended_control(finding: dict, asset: dict | None) -> str:
    category = str(finding.get("category", "")).lower()
    if "iam" in category:
        return "conditional IAM deny"
    if "kubernetes" in category or "container" in category:
        return "admission controller policy"
    if "network" in category:
        return "microsegmentation deny rule"
    if asset and asset.get("internet_exposure"):
        return "WAF or API gateway virtual patch"
    return "service mesh policy"


async def build_virtual_patching_model(db: AsyncIOMotorDatabase, tenant_id: str) -> dict:
    findings = await db.findings.find({"tenant_id": tenant_id, "status": {"$nin": ["RESOLVED", "FALSE_POSITIVE"]}}).sort("business_risk_score", -1).to_list(100)
    asset_ids = [f.get("asset_id") for f in findings if f.get("asset_id")]
    assets = {a["_id"]: a for a in await db.assets.find({"_id": {"$in": asset_ids}}).to_list(100)}
    candidates = []
    breakers = []
    for finding in findings:
        asset = assets.get(finding.get("asset_id"))
        needs_virtual = bool((asset and asset.get("internet_exposure")) or not finding.get("patch_available") or finding.get("business_risk_score", 0) >= 75)
        if needs_virtual:
            score = min(100, finding.get("business_risk_score", 0) + (10 if asset and asset.get("internet_exposure") else 0))
            candidates.append({"finding_id": finding["_id"], "asset": asset.get("name") if asset else "Unmapped", "control": recommended_control(finding, asset), "score": round(score, 2)})
        if asset and asset.get("internet_exposure") and asset.get("criticality", 3) >= 4:
            breakers.append({"source": asset.get("name"), "target": "crown-jewel service", "breaker": "microsegmentation plus conditional deny", "score": 90})
    policies = await db.policies.find({"tenant_id": tenant_id, "policy_type": {"$in": ["virtual_patch", "path_breaker"]}}).to_list(100)
    return {
        "summary": {"virtual_patch_candidates": len(candidates), "path_breaker_candidates": len(breakers), "active_policies": len(policies)},
        "candidates": candidates[:25],
        "path_breakers": breakers[:25],
        "policies": policies,
    }


async def activate_virtual_patching(db: AsyncIOMotorDatabase, tenant_id: str) -> dict:
    model = await build_virtual_patching_model(db, tenant_id)
    policy = Policy(tenant_id=tenant_id, name="Virtual patch and path breaker guardrail", policy_type="virtual_patch", rules={"dry_run": True, "require_rollback": True})
    await db.policies.insert_one(policy.model_dump(by_alias=True))
    created_runs = 0
    for candidate in model["candidates"][:5]:
        run = ConnectorRun(
            tenant_id=tenant_id,
            provider="virtual-patching",
            operation="activate_control",
            dry_run=True,
            payload=candidate,
            result={"status": "planned", "enforcement": candidate["control"]},
        )
        await db.connector_runs.insert_one(run.model_dump(by_alias=True))
        created_runs += 1
        action = await db.remediation_actions.find_one({"tenant_id": tenant_id, "finding_id": candidate["finding_id"]})
        if action:
            await run_simulation(db, tenant_id, action["_id"], "virtual_patch_canary")
            await generate_plan(db, tenant_id, action["_id"])
    await touch_audit(db, tenant_id, "virtual-patching", "virtual_patching_activated", "policy", policy.id, {"runs": created_runs})
    return {"policy_id": policy.id, "dry_runs": created_runs, "model": await build_virtual_patching_model(db, tenant_id)}

