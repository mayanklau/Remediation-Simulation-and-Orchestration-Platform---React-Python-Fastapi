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
    nodes = [
        {
            "id": a["_id"],
            "label": a["name"],
            "type": a.get("type"),
            "environment": a.get("environment"),
            "criticality": a.get("criticality", 3),
            "data_sensitivity": a.get("data_sensitivity", 3),
            "risk": round(risk_by_asset.get(a["_id"], 0), 2),
            "internet_exposure": a.get("internet_exposure", False),
        }
        for a in assets
    ]
    edges = []
    prod_assets = [a for a in assets if a.get("environment") == "PRODUCTION"]
    exposed = [a for a in assets if a.get("internet_exposure")]
    for source in exposed[:20]:
        for target in prod_assets[:3]:
            if source["_id"] != target["_id"]:
                source_risk = risk_by_asset.get(source["_id"], 0)
                target_risk = risk_by_asset.get(target["_id"], 0)
                edges.append({
                    "id": f"{source['_id']}->{target['_id']}",
                    "from": source["_id"],
                    "to": target["_id"],
                    "relation": "potential_reachability",
                    "confidence": 0.55,
                    "risk_transfer": round((source_risk + target_risk) * 0.28, 2),
                })
    return {
        "nodes": nodes,
        "edges": edges,
        "library_graph": {
            "engine": "@xyflow/react",
            "layout": "risk-layered-dependency",
            "nodes": [
                {
                    "id": node["id"],
                    "label": node["label"],
                    "kind": "internet_exposed" if node.get("internet_exposure") else "production" if node.get("environment") == "PRODUCTION" else "asset",
                    "group": node.get("environment"),
                    "risk": node.get("risk", 0),
                    "maturity": max(0, round(100 - node.get("risk", 0) * 0.35 - (12 if node.get("internet_exposure") else 0))),
                    "metadata": {
                        "type": node.get("type"),
                        "criticality": node.get("criticality"),
                        "data_sensitivity": node.get("data_sensitivity"),
                    },
                }
                for node in nodes
            ],
            "edges": [
                {
                    "id": edge.get("id", f"{edge['from']}->{edge['to']}"),
                    "source": edge["from"],
                    "target": edge["to"],
                    "label": edge["relation"],
                    "kind": edge["relation"],
                    "weight": edge.get("risk_transfer", 20),
                    "confidence": edge.get("confidence", 0),
                }
                for edge in edges
            ],
        },
        "summary": {"assets": len(nodes), "edges": len(edges), "exposed_assets": len(exposed)},
    }
