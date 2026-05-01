from motor.motor_asyncio import AsyncIOMotorDatabase
from app.models import ReportSnapshot
from app.services.model_providers import complete_with_model, configured_model_providers
from app.services.tenant import touch_audit
from app.services.virtual_patching import build_virtual_patching_model


AGENT_TOOLS = [
    {"name": "ingest_findings", "mode": "dry_run_or_api", "risk": "low", "purpose": "Normalize external findings."},
    {"name": "run_simulation", "mode": "safe", "risk": "low", "purpose": "Estimate risk reduction and operational risk."},
    {"name": "generate_plan", "mode": "safe", "risk": "low", "purpose": "Create rollout, rollback, validation, and evidence plan."},
    {"name": "activate_virtual_patch", "mode": "dry_run_default", "risk": "medium", "purpose": "Create compensating controls before permanent remediation."},
    {"name": "break_attack_path", "mode": "dry_run_default", "risk": "medium", "purpose": "Interrupt risky reachability to crown-jewel targets."},
    {"name": "route_approval", "mode": "human_required", "risk": "medium", "purpose": "Create approval workflow."},
    {"name": "execute_connector", "mode": "dry_run_default", "risk": "high", "purpose": "Call Jira, GitHub, ServiceNow, cloud, IAM, or Kubernetes connectors."},
    {"name": "seal_evidence", "mode": "safe", "risk": "low", "purpose": "Hash-chain evidence pack after validation."},
]

SAFETY_RAILS = [
    "No live execution without explicit connector credentials and policy approval.",
    "Production assets require simulation, rollback plan, evidence plan, and human approval.",
    "Crown-jewel and internet-exposed assets require virtual patch or path-breaker assessment.",
    "All agent plans are tenant scoped and audit logged.",
    "External model output is advisory; deterministic policy gates decide execution eligibility.",
    "Secrets are referenced through configured providers and never included in model prompts.",
]


async def build_agentic_model(db: AsyncIOMotorDatabase, tenant_id: str) -> dict:
    findings = await db.findings.find({"tenant_id": tenant_id, "status": {"$nin": ["RESOLVED", "FALSE_POSITIVE"]}}).sort("business_risk_score", -1).to_list(20)
    actions = await db.remediation_actions.find({"tenant_id": tenant_id}).sort("updated_at", -1).to_list(20)
    workflows = await db.workflow_items.find({"tenant_id": tenant_id}).sort("updated_at", -1).to_list(20)
    simulations = await db.simulations.find({"tenant_id": tenant_id}).sort("created_at", -1).to_list(20)
    policies = await db.policies.find({"tenant_id": tenant_id}).to_list(50)
    evidence = await db.evidence_artifacts.find({"tenant_id": tenant_id}).to_list(50)
    reports = await db.report_snapshots.find({"tenant_id": tenant_id, "type": "agentic_plan"}).sort("created_at", -1).to_list(10)
    virtual = await build_virtual_patching_model(db, tenant_id)
    providers = configured_model_providers()
    readiness = min(
        100,
        35
        + (15 if any(p["provider"] != "deterministic" and p["configured"] for p in providers) else 0)
        + min(15, len(policies) * 2)
        + min(15, len(simulations))
        + min(10, len(workflows))
        + min(10, len(evidence)),
    )
    return {
        "readiness_score": readiness,
        "status": "agentic_ready" if readiness >= 85 else "human_supervised_ready" if readiness >= 65 else "needs_model_or_policy_setup",
        "providers": providers,
        "tool_registry": AGENT_TOOLS,
        "safety_rails": SAFETY_RAILS,
        "context": {
            "top_findings": [{"id": f["_id"], "title": f["title"], "severity": f["severity"], "business_risk": round(f.get("business_risk_score", 0), 2)} for f in findings],
            "action_count": len(actions),
            "workflow_count": len(workflows),
            "simulation_count": len(simulations),
            "policy_count": len(policies),
            "evidence_count": len(evidence),
            "virtual_patch_candidates": virtual["summary"]["virtual_patch_candidates"],
            "path_breaker_candidates": virtual["summary"]["path_breaker_candidates"],
        },
        "recent_agent_runs": reports,
    }


async def run_agentic_plan(db: AsyncIOMotorDatabase, tenant_id: str, payload: dict) -> dict:
    model = await build_agentic_model(db, tenant_id)
    goal = payload.get("goal", "prioritize")
    system = "\n".join(
        [
            "You are Remediation Twin's governed remediation agent.",
            "You may plan, prioritize, and recommend actions, but live execution must remain dry-run unless explicit policy and credentials are configured.",
            "Always include approval, rollback, validation, virtual patch, and evidence requirements.",
        ]
    )
    prompt = f"Goal: {goal}\nUser request: {payload.get('prompt', 'Create safest next remediation plan.')}\nTenant context: {model['context']}\nTools: {AGENT_TOOLS}\nSafety rails: {SAFETY_RAILS}"
    completion = await complete_with_model(system, prompt, payload.get("provider"))
    plan = {
        "summary": completion["output"],
        "autonomy_level": "supervised_agentic" if model["readiness_score"] >= 85 else "advisory_agentic",
        "execution_mode": "dry_run_default",
        "steps": [
            {"tool": "run_simulation", "status": "recommended", "reason": "Refresh confidence and operational risk before action."},
            {"tool": "activate_virtual_patch" if goal == "virtual_patch" else "generate_plan", "status": "recommended", "reason": "Create safe remediation or compensating-control plan."},
            {"tool": "route_approval", "status": "required_before_live", "reason": "Human approval is required before production execution."},
            {"tool": "seal_evidence", "status": "after_validation", "reason": "Evidence must be hash-chained after validation."},
        ],
    }
    report = ReportSnapshot(tenant_id=tenant_id, name="Agentic remediation plan", type="agentic_plan", data={"goal": goal, "completion": completion, "plan": plan, "dry_run": payload.get("dry_run", True)}, created_by=completion["provider"])
    await db.report_snapshots.insert_one(report.model_dump(by_alias=True))
    await touch_audit(db, tenant_id, "agentic-orchestrator", "agentic_plan_created", "report", report.id, {"goal": goal, "provider": completion["provider"]})
    return {"report": report.model_dump(by_alias=True), "completion": completion, "plan": plan}

