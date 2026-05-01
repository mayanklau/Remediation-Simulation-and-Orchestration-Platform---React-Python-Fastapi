from motor.motor_asyncio import AsyncIOMotorDatabase


async def dashboard(db: AsyncIOMotorDatabase, tenant_id: str) -> dict:
    findings = await db.findings.find({"tenant_id": tenant_id}).to_list(500)
    actions = await db.remediation_actions.find({"tenant_id": tenant_id}).to_list(500)
    simulations = await db.simulations.find({"tenant_id": tenant_id}).to_list(500)
    workflows = await db.workflow_items.find({"tenant_id": tenant_id}).to_list(500)
    evidence_count = await db.evidence_artifacts.count_documents({"tenant_id": tenant_id})
    open_findings = [f for f in findings if f.get("status") not in ["RESOLVED", "FALSE_POSITIVE"]]
    high_risk = [f for f in open_findings if f.get("business_risk_score", 0) >= 70]
    simulated_actions = {s.get("remediation_action_id") for s in simulations}
    return {
        "counts": {
            "findings": len(findings),
            "open_findings": len(open_findings),
            "assets": await db.assets.count_documents({"tenant_id": tenant_id}),
            "remediation_actions": len(actions),
            "simulations": len(simulations),
            "workflows": len(workflows),
            "evidence_artifacts": evidence_count,
        },
        "risk": {
            "high_risk_findings": len(high_risk),
            "total_business_risk": round(sum(f.get("business_risk_score", 0) for f in open_findings), 2),
            "simulation_coverage": round((len(simulated_actions) / len(actions)) * 100, 2) if actions else 0,
        },
        "top_findings": sorted(open_findings, key=lambda f: f.get("business_risk_score", 0), reverse=True)[:10],
    }


async def asset_graph(db: AsyncIOMotorDatabase, tenant_id: str) -> dict:
    assets = await db.assets.find({"tenant_id": tenant_id}).to_list(300)
    findings = await db.findings.find({"tenant_id": tenant_id, "status": {"$nin": ["RESOLVED", "FALSE_POSITIVE"]}}).to_list(500)
    risk_by_asset = {}
    for finding in findings:
        asset_id = finding.get("asset_id")
        if asset_id:
            risk_by_asset[asset_id] = risk_by_asset.get(asset_id, 0) + finding.get("business_risk_score", 0)
    nodes = [{"id": a["_id"], "label": a["name"], "type": a.get("type"), "environment": a.get("environment"), "risk": round(risk_by_asset.get(a["_id"], 0), 2), "internet_exposure": a.get("internet_exposure", False)} for a in assets]
    edges = []
    prod_assets = [a for a in assets if a.get("environment") == "PRODUCTION"]
    exposed = [a for a in assets if a.get("internet_exposure")]
    for source in exposed[:20]:
        for target in prod_assets[:3]:
            if source["_id"] != target["_id"]:
                edges.append({"from": source["_id"], "to": target["_id"], "relation": "potential_reachability", "confidence": 0.55})
    return {"nodes": nodes, "edges": edges, "summary": {"assets": len(nodes), "edges": len(edges), "exposed_assets": len(exposed)}}

