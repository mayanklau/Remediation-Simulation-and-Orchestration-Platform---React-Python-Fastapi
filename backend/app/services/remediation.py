from motor.motor_asyncio import AsyncIOMotorDatabase
from app.models import RemediationPlan, Simulation, WorkflowItem, now
from app.services.tenant import touch_audit


async def list_actions(db: AsyncIOMotorDatabase, tenant_id: str) -> list[dict]:
    actions = await db.remediation_actions.find({"tenant_id": tenant_id}).sort("updated_at", -1).to_list(200)
    finding_ids = [a["finding_id"] for a in actions]
    findings = {f["_id"]: f for f in await db.findings.find({"_id": {"$in": finding_ids}}).to_list(200)}
    asset_ids = [f.get("asset_id") for f in findings.values() if f.get("asset_id")]
    assets = {a["_id"]: a for a in await db.assets.find({"_id": {"$in": asset_ids}}).to_list(200)}
    for action in actions:
        finding = findings.get(action["finding_id"])
        action["finding"] = finding
        action["asset"] = assets.get(finding.get("asset_id")) if finding else None
    return actions


async def run_simulation(db: AsyncIOMotorDatabase, tenant_id: str, action_id: str, simulation_type: str = "standard") -> Simulation:
    action = await db.remediation_actions.find_one({"_id": action_id, "tenant_id": tenant_id})
    if not action:
        raise ValueError("remediation action not found")
    finding = await db.findings.find_one({"_id": action["finding_id"], "tenant_id": tenant_id})
    asset = await db.assets.find_one({"_id": finding.get("asset_id"), "tenant_id": tenant_id}) if finding and finding.get("asset_id") else None
    business_risk = float(finding.get("business_risk_score", 40)) if finding else 40
    exposure_penalty = 10 if asset and asset.get("internet_exposure") else 0
    production_penalty = 12 if asset and asset.get("environment") == "PRODUCTION" else 0
    rollback_penalty = max(0, int(action.get("complexity", 3)) - 2) * 5
    operational = min(100, 20 + exposure_penalty + production_penalty + rollback_penalty)
    risk_reduction = min(95, max(15, business_risk * 0.7 - operational * 0.1))
    confidence = max(50, min(98, 92 - operational * 0.25))
    simulation = Simulation(
        tenant_id=tenant_id,
        remediation_action_id=action_id,
        type=simulation_type,
        input={"action_type": action.get("action_type"), "asset": asset.get("name") if asset else None},
        result={
            "affected_assets": [asset.get("name")] if asset else [],
            "blast_radius": "high" if operational >= 45 else "moderate",
            "rollback_required": True,
            "approval_required": bool(asset and asset.get("environment") == "PRODUCTION"),
        },
        confidence=round(confidence, 2),
        risk_reduction_estimate=round(risk_reduction, 2),
        operational_risk=round(operational, 2),
        explanation="Simulation estimates risk reduction, production blast radius, rollback needs, and approval gates.",
    )
    await db.simulations.insert_one(simulation.model_dump(by_alias=True))
    await db.remediation_actions.update_one({"_id": action_id}, {"$set": {"status": "SIMULATED", "updated_at": now()}})
    await touch_audit(db, tenant_id, "simulation-engine", "simulation_completed", "simulation", simulation.id, {"action_id": action_id})
    return simulation


async def generate_plan(db: AsyncIOMotorDatabase, tenant_id: str, action_id: str) -> RemediationPlan:
    action = await db.remediation_actions.find_one({"_id": action_id, "tenant_id": tenant_id})
    if not action:
        raise ValueError("remediation action not found")
    latest_sim = await db.simulations.find_one({"tenant_id": tenant_id, "remediation_action_id": action_id}, sort=[("created_at", -1)])
    plan = RemediationPlan(
        tenant_id=tenant_id,
        remediation_action_id=action_id,
        title=f"Plan for {action['title']}",
        rollout_steps=[
            "Confirm owner, service tier, and change window.",
            "Run or refresh simulation and validate expected blast radius.",
            "Apply change in canary or lowest-risk segment first.",
            "Monitor service health, security signal, and rollback triggers.",
            "Expand rollout only after validation passes.",
        ],
        rollback_steps=[
            "Restore previous configuration or package version.",
            "Reopen blocked network or IAM dependency only if approved.",
            "Re-run validation and record rollback evidence.",
        ],
        validation_steps=[
            "Confirm finding is no longer reproducible.",
            "Confirm no critical service dependency failed.",
            "Confirm monitoring and audit records are attached.",
        ],
        evidence_required=[
            "Before state",
            "Simulation output",
            "Approval record",
            "Execution log",
            "Validation result",
            "Rollback plan",
        ],
    )
    if not latest_sim:
        plan.rollout_steps.insert(1, "Run a simulation before live execution.")
    await db.remediation_plans.insert_one(plan.model_dump(by_alias=True))
    await db.remediation_actions.update_one({"_id": action_id}, {"$set": {"status": "PLANNED", "updated_at": now()}})
    await touch_audit(db, tenant_id, "planner", "plan_created", "remediation_plan", plan.id, {"action_id": action_id})
    return plan


async def create_workflow(db: AsyncIOMotorDatabase, tenant_id: str, action_id: str) -> WorkflowItem:
    action = await db.remediation_actions.find_one({"_id": action_id, "tenant_id": tenant_id})
    if not action:
        raise ValueError("remediation action not found")
    workflow = WorkflowItem(
        tenant_id=tenant_id,
        remediation_action_id=action_id,
        title=f"Approval workflow for {action['title']}",
        approvals=[
            {"role": "security_owner", "status": "PENDING"},
            {"role": "service_owner", "status": "PENDING"},
            {"role": "change_advisory_board", "status": "PENDING"},
        ],
    )
    await db.workflow_items.insert_one(workflow.model_dump(by_alias=True))
    await db.remediation_actions.update_one({"_id": action_id}, {"$set": {"status": "PENDING_APPROVAL", "updated_at": now()}})
    await touch_audit(db, tenant_id, "workflow", "workflow_created", "workflow", workflow.id, {"action_id": action_id})
    return workflow

