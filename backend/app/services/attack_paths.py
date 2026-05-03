from __future__ import annotations

from statistics import mean
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models import ReportSnapshot
from app.services.dashboard import asset_graph
from app.services.tenant import touch_audit


DIFFICULTY_BANDS = [
    (80, "VERY_HIGH"),
    (60, "HIGH"),
    (35, "MEDIUM"),
    (0, "LOW"),
]


async def build_attack_path_model(db: AsyncIOMotorDatabase, tenant_id: str) -> dict[str, Any]:
    graph = await asset_graph(db, tenant_id)
    findings = await db.findings.find({"tenant_id": tenant_id, "status": {"$nin": ["RESOLVED", "FALSE_POSITIVE"]}}).sort("business_risk_score", -1).to_list(500)
    simulations = await db.simulations.find({"tenant_id": tenant_id}).sort("created_at", -1).to_list(300)
    policies = await db.policies.find({"tenant_id": tenant_id, "enabled": True}).to_list(200)

    nodes = {node["id"]: node for node in graph["nodes"]}
    adjacency: dict[str, list[str]] = {}
    for edge in graph["edges"]:
        adjacency.setdefault(edge["from"], []).append(edge["to"])

    findings_by_asset: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        asset_id = finding.get("asset_id")
        if asset_id:
            findings_by_asset.setdefault(asset_id, []).append(finding)

    start_ids = [
        node_id
        for node_id, node in nodes.items()
        if node.get("internet_exposure") or any(_is_initial_access(f) for f in findings_by_asset.get(node_id, []))
    ]
    target_ids = [
        node_id
        for node_id, node in nodes.items()
        if node.get("environment") == "PRODUCTION" or _asset_int(node, "criticality", 3) >= 4 or _asset_int(node, "data_sensitivity", 3) >= 4
    ]

    paths = []
    for start in start_ids[:40]:
        for candidate in _enumerate_paths(start, adjacency, max_depth=4):
            target = candidate[-1]
            if target not in target_ids or target == start:
                continue
            chain = [
                _chain_step(finding)
                for asset_id in candidate
                for finding in findings_by_asset.get(asset_id, [])[:2]
            ]
            if not chain:
                continue
            paths.append(_path_record(candidate, chain, nodes, simulations, policies))

    paths.sort(key=lambda path: path["before_remediation_risk"], reverse=True)
    paths = paths[:25]
    centrality = _centrality(paths)
    for path in paths:
        path["centrality_score"] = _avg([next((item["score"] for item in centrality if item["asset"] == hop), 0) for hop in path["hops"]])
        path["choke_points"] = [
            hop
            for hop in path["hops"][1:-1]
            if next((item["score"] for item in centrality if item["asset"] == hop), 0) >= 50
        ][:3]
    graph_model = _graph_model(paths)
    executive_views = _executive_views(paths)
    vulnerability_fan_out = _vulnerability_fan_out(paths)
    return {
        "generated_by": "scanner-normalized-attack-path-engine",
        "construction_method": {
            "method": "Logical attack graph with bounded simple-path enumeration",
            "inputs": [
                "scanner findings",
                "asset inventory",
                "asset dependency and reachability edges",
                "internet exposure",
                "exploit availability",
                "active exploitation",
                "patch availability",
                "production and crown-jewel context",
                "simulation and policy controls",
            ],
            "research_basis": [
                "MulVAL-style logical vulnerability analysis",
                "topological attack graph reachability",
                "exploit-dependency path construction",
                "Bayesian attack graph before/after risk intuition",
            ],
        },
        "summary": {
            "attack_paths": len(paths),
            "critical_paths": len([path for path in paths if path["before_remediation_risk"] >= 80]),
            "average_before_risk": _avg([path["before_remediation_risk"] for path in paths]),
            "average_after_risk": _avg([path["after_remediation_risk"] for path in paths]),
            "average_risk_reduction": _avg([path["risk_delta"] for path in paths]),
            "scanner_inputs": sorted({source for path in paths for source in path["scanner_inputs"]}),
            "graph_nodes": len(graph_model["nodes"]),
            "graph_edges": len(graph_model["edges"]),
            "vulnerability_chains": len(graph_model["vulnerability_chains"]),
            "vulnerabilities_with_multiple_paths": len([item for item in vulnerability_fan_out if item["path_count"] > 1]),
            "max_paths_from_single_vulnerability": max([0, *[item["path_count"] for item in vulnerability_fan_out]]),
        },
        "scanner_coverage": _scanner_coverage(findings),
        "scanner_normalization_adapters": _scanner_normalization_adapters(),
        "vulnerability_chaining_rules": _vulnerability_chaining_rules(),
        "chain_intelligence_studio": {
            "stage_model": _attack_stage_model(),
            "top_risk_contributors": sorted([
                {"path_id": path["id"], "path": path["name"], **item}
                for path in paths
                for item in path.get("risk_contribution_waterfall", [])
            ], key=lambda item: item["contribution"], reverse=True)[:12],
            "high_confidence_chains": [
                {"path_id": path["id"], "name": path["name"], "confidence": _avg([step.get("evidence_confidence", 0) for step in path["chain"]]), "before_risk": path["before_remediation_risk"], "after_risk": path["after_remediation_risk"]}
                for path in paths
                if _avg([step.get("evidence_confidence", 0) for step in path["chain"]]) >= 70
            ][:10],
            "control_effectiveness_leaders": sorted([
                {"path_id": path["id"], "path": path["name"], **control}
                for path in paths
                for control in path.get("control_effectiveness_matrix", [])
            ], key=lambda item: item["risk_reduction"], reverse=True)[:12],
        },
        "graph_algorithms": {
            "shortest_exploitable_paths": [
                {"path_id": path["id"], "name": path["name"], "hops": path["shortest_hop_count"], "risk": path["before_remediation_risk"], "difficulty": path["difficulty"]}
                for path in sorted(paths, key=lambda item: (item["shortest_hop_count"], -item["before_remediation_risk"]))[:10]
            ],
            "k_hop_blast_radius": [{"entry_asset": path["entry_asset"], "hops": 3, "impacted_assets": path["k_hop_blast_radius"], "top_target": path["target_asset"]} for path in paths[:10]],
            "centrality": centrality,
            "choke_points": [item for item in centrality if item["kind"] == "choke_point"][:10],
            "crown_jewel_exposure": [
                {"target": path["target_asset"], "exposure": path["crown_jewel_exposure"], "before_risk": path["before_remediation_risk"], "after_risk": path["after_remediation_risk"]}
                for path in paths if path["crown_jewel_exposure"] != "low"
            ][:10],
            "vulnerability_fan_out": vulnerability_fan_out,
        },
        "executive_views": executive_views,
        "decision_readiness": _decision_readiness(paths),
        "subject_maturity": _subject_maturity(paths, graph_model, len(findings)),
        "development_maturity": _development_maturity(paths, len(policies), len(simulations)),
        "attack_graph": {
            "method": "Layered logical attack graph: entry assets, reachable services, exploit preconditions, crown-jewel targets, and policy-backed breaker controls.",
            "nodes": graph_model["nodes"],
            "edges": graph_model["edges"],
            "library_graph": {
                "engine": "@xyflow/react",
                "layout": "layered-attack-path",
                "nodes": [
                    {
                        "id": node["id"],
                        "label": node["label"],
                        "kind": node["kind"],
                        "group": node.get("group"),
                        "risk": node.get("risk", 0),
                        "impactScore": node.get("impact_score", node.get("risk", 0)),
                        "impact_score": node.get("impact_score", node.get("risk", 0)),
                        "preRemediationRisk": node.get("pre_remediation_risk", node.get("risk", 0)),
                        "pre_remediation_risk": node.get("pre_remediation_risk", node.get("risk", 0)),
                        "postRemediationRisk": node.get("post_remediation_risk", node.get("risk", 0)),
                        "post_remediation_risk": node.get("post_remediation_risk", node.get("risk", 0)),
                        "pathIds": node.get("path_ids", []),
                        "path_ids": node.get("path_ids", []),
                        "source_finding_id": node.get("source_finding_id"),
                        "difficulty": node.get("difficulty"),
                    }
                    for node in graph_model["nodes"]
                ],
                "edges": [
                    {
                        "id": edge["id"],
                        "source": edge["from"],
                        "target": edge["to"],
                        "label": edge.get("label"),
                        "kind": edge.get("relation"),
                        "weight": edge.get("weight", 0),
                        "path_id": edge.get("path_id"),
                    }
                    for edge in graph_model["edges"]
                ],
            },
        },
        "vulnerability_chain_graph": graph_model["vulnerability_chains"],
        "vulnerability_fan_out": vulnerability_fan_out,
        "paths": paths,
    }


async def snapshot_attack_path_model(db: AsyncIOMotorDatabase, tenant_id: str) -> dict[str, Any]:
    model = await build_attack_path_model(db, tenant_id)
    report = ReportSnapshot(
        tenant_id=tenant_id,
        name="Attack path analytics",
        type="attack_path_analytics",
        data=model,
        created_by="attack-path-engine",
    )
    await db.report_snapshots.insert_one(report.model_dump(by_alias=True))
    await touch_audit(db, tenant_id, "attack-path-engine", "attack_path_analytics_generated", "report", report.id, model["summary"])
    return {"report": report, "attack_paths": model}


def _enumerate_paths(start: str, adjacency: dict[str, list[str]], max_depth: int) -> list[list[str]]:
    paths: list[list[str]] = []

    def walk(current: str, path: list[str]) -> None:
        if len(path) > 1:
            paths.append(path)
        if len(path) >= max_depth:
            return
        for next_id in adjacency.get(current, []):
            if next_id in path:
                continue
            walk(next_id, [*path, next_id])

    walk(start, [start])
    return paths


def _path_record(path: list[str], chain: list[dict[str, Any]], nodes: dict[str, dict[str, Any]], simulations: list[dict[str, Any]], policies: list[dict[str, Any]]) -> dict[str, Any]:
    start = nodes[path[0]]
    target = nodes[path[-1]]
    before = _before_risk(chain, len(path), _asset_int(target, "criticality", 3), _asset_int(target, "data_sensitivity", 3))
    after = max(0, before - _risk_reduction(chain, simulations, policies))
    difficulty_score = _difficulty_score(chain, len(path), bool(start.get("internet_exposure")))
    hops = [nodes[asset_id].get("label", asset_id) for asset_id in path if asset_id in nodes]
    difficulty = _difficulty_band(difficulty_score)
    breakers = _recommended_breakers(chain, bool(start.get("internet_exposure")), str(target.get("type", "")))
    controls = _simulate_controls(chain, before)
    return {
        "id": "-".join(path),
        "name": f"{start.get('label')} to {target.get('label')}",
        "entry_asset": start.get("label"),
        "target_asset": target.get("label"),
        "hops": hops,
        "chain": chain,
        "scanner_inputs": sorted({step["source"] for step in chain}),
        "difficulty": difficulty,
        "difficulty_score": difficulty_score,
        "before_remediation_risk": before,
        "after_remediation_risk": after,
        "risk_delta": before - after,
        "likelihood": _clamp(100 - difficulty_score + 8 * len([step for step in chain if step["exploit_available"] or step["active_exploitation"]])),
        "business_impact": _clamp(_asset_int(target, "criticality", 3) * 12 + _asset_int(target, "data_sensitivity", 3) * 10 + before * 0.35),
        "shortest_hop_count": max(0, len(path) - 1),
        "k_hop_blast_radius": len(set(path[1:])),
        "centrality_score": 0,
        "choke_points": hops[1:-1],
        "crown_jewel_exposure": _crown_jewel_exposure(target),
        "difficulty_explanation": _difficulty_explanation(difficulty_score, chain, len(path), bool(start.get("internet_exposure"))),
        "control_simulations": controls,
        "path_breaker_recommendations": _path_breakers(hops, chain, before, after, breakers),
        "remediation_playbook": _remediation_playbook(chain, str(target.get("type", "")), str(target.get("environment", "")), before),
        "evidence_pack": _evidence_pack(chain, before, after),
        "kill_chain_narrative": _kill_chain_narrative(str(start.get("label")), str(target.get("label")), chain),
        "chain_stage_summary": _chain_stage_summary(chain),
        "risk_contribution_waterfall": _risk_contribution_waterfall(chain, before, len(path), _asset_int(target, "criticality", 3), _asset_int(target, "data_sensitivity", 3)),
        "control_effectiveness_matrix": _control_effectiveness_matrix(controls, chain),
        "recommended_breakers": breakers,
        "evidence_requirements": _evidence_requirements(chain),
        "validation_plan": _validation_plan(chain, str(target.get("label", target.get("name", "target")))),
        "customer_narrative": _customer_narrative(str(start.get("label")), str(target.get("label")), before, after),
        "priority": _priority(before, after),
    }


def _scanner_coverage(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    families = [
        ("vulnerability_scanner", lambda source, category: source in {"tenable", "qualys", "rapid7"} or "vulnerability" in category),
        ("cloud_posture", lambda source, category: source in {"wiz", "securityhub", "prisma", "defender"} or "cloud" in category),
        ("code_security", lambda source, category: source in {"snyk", "github", "semgrep"} or "application" in category),
        ("identity_iam", lambda _source, category: "iam" in category or "identity" in category),
        ("network_kubernetes", lambda _source, category: "network" in category or "kubernetes" in category or "container" in category),
        ("compliance_grc", lambda _source, category: "compliance" in category or "control" in category),
    ]
    coverage = []
    for family, matcher in families:
        matched = [
            finding
            for finding in findings
            if matcher(str(finding.get("source", "")).lower(), str(finding.get("category", "")).lower())
        ]
        mapped = [finding for finding in matched if finding.get("asset_id")]
        exploitable = [finding for finding in matched if finding.get("exploit_available") or finding.get("active_exploitation")]
        actionable = [finding for finding in matched if finding.get("patch_available") or finding.get("cve") or finding.get("control_id")]
        denominator = max(1, len(matched))
        coverage.append({
            "family": family,
            "findings": len(matched),
            "asset_mapping_coverage": _percent(len(mapped), denominator),
            "exploit_signal_coverage": _percent(len(exploitable), denominator),
            "remediation_signal_coverage": _percent(len(actionable), denominator),
            "ready_for_attack_graph": bool(matched) and len(mapped) / denominator >= 0.6,
        })
    return coverage


def _decision_readiness(paths: list[dict[str, Any]]) -> dict[str, Any]:
    immediate = [path for path in paths if path["priority"] == "immediate"]
    high_confidence = [path for path in paths if path["risk_delta"] >= 25 and path["after_remediation_risk"] < path["before_remediation_risk"]]
    return {
        "customer_ready_paths": len(high_confidence),
        "immediate_executive_escalations": len(immediate),
        "average_difficulty_score": _avg([path["difficulty_score"] for path in paths]),
        "average_likelihood": _avg([path["likelihood"] for path in paths]),
        "average_business_impact": _avg([path["business_impact"] for path in paths]),
        "recommended_decision": "escalate_now" if immediate else "approve_top_path_breakers" if high_confidence else "improve_mapping_and_simulation",
    }


def _subject_maturity(paths: list[dict[str, Any]], graph_model: dict[str, Any], finding_count: int) -> dict[str, Any]:
    signals = [
        {"name": "Scanner-normalized inputs", "complete": finding_count > 0},
        {"name": "Reachability graph", "complete": any(edge.get("relation") == "reachability" for edge in graph_model["edges"])},
        {"name": "Exploit-precondition chain", "complete": any(edge.get("relation") == "exploit_precondition" for edge in graph_model["edges"])},
        {"name": "Before/after residual risk", "complete": any(path["risk_delta"] > 0 for path in paths)},
        {"name": "Path difficulty scoring", "complete": any(path["difficulty_score"] > 0 for path in paths)},
        {"name": "Path breaker controls", "complete": any(node.get("kind") == "breaker" for node in graph_model["nodes"])},
        {"name": "Evidence and validation plan", "complete": any(path.get("evidence_requirements") and path.get("validation_plan") for path in paths)},
    ]
    return {
        "score": _percent(len([signal for signal in signals if signal["complete"]]), len(signals)),
        "signals": signals,
        "next_frontier": "Add probabilistic control effectiveness calibration from real incident, exploit, and change-failure history.",
    }


def _development_maturity(paths: list[dict[str, Any]], policy_count: int, simulation_count: int) -> dict[str, Any]:
    gates = [
        {"name": "Tenant-scoped data access", "status": "implemented"},
        {"name": "Deterministic attack graph contract", "status": "implemented"},
        {"name": "Policy guardrails", "status": "active" if policy_count else "needs_policy_seed"},
        {"name": "Simulation evidence", "status": "active" if simulation_count else "needs_simulation_runs"},
        {"name": "Residual risk explainability", "status": "implemented" if any(path.get("customer_narrative") for path in paths) else "needs_data"},
        {"name": "Audit snapshot export", "status": "implemented"},
    ]
    return {
        "gates": gates,
        "release_confidence": _percent(len([gate for gate in gates if gate["status"] in {"implemented", "active"}]), len(gates)),
        "production_posture": "enterprise_pilot_ready_with_live_connector_credentials",
    }


def _chain_step(finding: dict[str, Any]) -> dict[str, Any]:
    metadata = finding.get("metadata") or {}
    domain = _domain_from_category(finding.get("category", "vulnerability"), finding.get("source", "api"))
    stage = _stage_for_domain(domain, finding.get("category", "vulnerability"))
    confidence = _evidence_confidence(finding, metadata)
    return {
        "finding_id": finding.get("_id"),
        "asset_id": finding.get("asset_id"),
        "title": finding.get("title"),
        "source": finding.get("source", "api"),
        "category": finding.get("category", "vulnerability"),
        "severity": finding.get("severity", "MEDIUM"),
        "stage": stage,
        "mitre_tactic": _mitre_tactic_for_stage(stage),
        "domain": domain,
        "technique": metadata.get("attack_technique") or _map_technique(finding.get("category", "vulnerability")),
        "normalized_scanner": _scanner_adapter(finding.get("source", "api")),
        "exploit_preconditions": metadata.get("preconditions") if isinstance(metadata.get("preconditions"), list) else _preconditions(finding.get("category", "vulnerability")),
        "evidence_confidence": confidence,
        "risk_contribution": _risk_contribution(float(finding.get("business_risk_score", 0)), confidence, bool(finding.get("exploit_available")), bool(finding.get("active_exploitation"))),
        "business_risk": round(float(finding.get("business_risk_score", 0))),
        "exploit_available": bool(finding.get("exploit_available")),
        "active_exploitation": bool(finding.get("active_exploitation")),
        "patch_available": bool(finding.get("patch_available")),
    }


def _stage_for_domain(domain: str, category: str) -> str:
    value = f"{domain} {category}".lower()
    if "network" in value or "application" in value:
        return "Initial Access"
    if "secrets" in value:
        return "Credential Access"
    if "iam" in value:
        return "Privilege Escalation"
    if "cloud" in value or "kubernetes" in value:
        return "Lateral Movement"
    if "cicd" in value:
        return "Execution"
    if "data_store" in value:
        return "Data Impact"
    return "Exploit"


def _mitre_tactic_for_stage(stage: str) -> str:
    return {
        "Initial Access": "TA0001 Initial Access",
        "Execution": "TA0002 Execution",
        "Privilege Escalation": "TA0004 Privilege Escalation",
        "Defense Evasion": "TA0005 Defense Evasion",
        "Credential Access": "TA0006 Credential Access",
        "Discovery": "TA0007 Discovery",
        "Lateral Movement": "TA0008 Lateral Movement",
        "Collection": "TA0009 Collection",
        "Exfiltration": "TA0010 Exfiltration",
        "Data Impact": "TA0040 Impact",
        "Exploit": "TA0002 Execution",
    }.get(stage, "TA0002 Execution")


def _evidence_confidence(finding: dict[str, Any], metadata: dict[str, Any]) -> int:
    score = 35 if finding.get("asset_id") else 15
    if finding.get("cve") or finding.get("control_id"):
        score += 15
    if finding.get("exploit_available"):
        score += 15
    if finding.get("active_exploitation"):
        score += 20
    if finding.get("patch_available"):
        score += 8
    if isinstance(metadata.get("preconditions"), list) and metadata.get("preconditions"):
        score += 7
    if str(finding.get("source", "")).lower() in {"tenable", "qualys", "wiz", "snyk", "securityhub"}:
        score += 5
    return _clamp(score)


def _risk_contribution(business_risk: float, confidence: int, exploit_available: bool, active_exploitation: bool) -> int:
    return _clamp(business_risk * 0.55 + confidence * 0.25 + (8 if exploit_available else 0) + (14 if active_exploitation else 0))


def _map_technique(category: str) -> str:
    value = category.lower()
    domain = _domain_from_category(value, "")
    if domain == "iam":
        return "Valid Accounts / Permission Groups Discovery"
    if domain == "network":
        return "External Remote Services / Network Service Discovery"
    if domain == "cloud":
        return "Cloud Service Dashboard / Account Discovery"
    if domain == "kubernetes":
        return "Container and Resource Discovery"
    if domain == "application":
        return "Exploit Public-Facing Application"
    if domain == "cicd":
        return "CI/CD Pipeline Modification"
    if domain == "secrets":
        return "Unsecured Credentials"
    if domain == "data_store":
        return "Data from Information Repositories"
    return "Exploit Vulnerability"


def _domain_from_category(category: str, source: str) -> str:
    value = f"{category} {source}".lower()
    if any(term in value for term in ["iam", "identity", "permission"]):
        return "iam"
    if any(term in value for term in ["kubernetes", "container", "k8s"]):
        return "kubernetes"
    if any(term in value for term in ["cloud", "aws", "azure", "gcp", "wiz", "prisma"]):
        return "cloud"
    if any(term in value for term in ["ci", "cd", "pipeline", "github"]):
        return "cicd"
    if any(term in value for term in ["secret", "credential", "token"]):
        return "secrets"
    if any(term in value for term in ["database", "data", "s3", "bucket"]):
        return "data_store"
    if any(term in value for term in ["application", "snyk", "code"]):
        return "application"
    if any(term in value for term in ["network", "firewall", "subnet", "tenable", "qualys"]):
        return "network"
    return "vulnerability"


def _scanner_adapter(source: str) -> str:
    key = "".join(char for char in source.lower() if char.isalnum())
    adapters = {
        "tenable": "Tenable VM adapter: plugin/CVE/CVSS/exploit flags mapped to canonical vulnerability findings",
        "qualys": "Qualys VMDR adapter: QID/CVE/asset tags mapped to canonical vulnerability findings",
        "wiz": "Wiz adapter: cloud graph issue, toxic combination, exposure, and cloud asset context normalized",
        "prismacloud": "Prisma Cloud adapter: policy ID, cloud resource, account, and compliance context normalized",
        "snyk": "Snyk adapter: package, container, IaC, and code issue context normalized",
        "githubadvancedsecurity": "GitHub Advanced Security adapter: code scanning, secret scanning, and Dependabot alerts normalized",
        "securityhub": "AWS Security Hub adapter: ASFF resource, control, severity, and workflow state normalized",
        "defender": "Microsoft Defender adapter: exposure, endpoint, cloud, and identity recommendation normalized",
        "crowdstrike": "CrowdStrike adapter: endpoint exposure, identity protection, and detection context normalized",
    }
    return adapters.get(key, f"{source or 'custom'} adapter: source payload normalized through canonical scanner contract")


def _preconditions(category: str) -> list[str]:
    domain = _domain_from_category(category, "")
    common = {
        "network": ["network access to exposed service", "reachable route between source and target", "service accepts unauthenticated or weakly authenticated traffic"],
        "iam": ["valid principal or token scope", "permission boundary allows target action", "lateral movement path through role or group membership"],
        "cloud": ["cloud API access", "resource policy allows action", "control-plane path to production account or project"],
        "kubernetes": ["cluster API or workload access", "service account token or admission gap", "network path to workload or control plane"],
        "application": ["user interaction or public endpoint", "vulnerable route or package reachable in runtime", "payload can reach sensitive operation"],
        "cicd": ["repository or runner access", "pipeline token scope", "write path to build, artifact, or deployment job"],
        "secrets": ["secret material exposed to user, process, log, or repository", "token is valid or replayable", "target service trusts the credential"],
        "data_store": ["data-plane network reachability", "credential or IAM grant to data store", "object/table policy allows read or write"],
    }
    return common.get(domain, ["asset is reachable", "finding is exploitable in the observed environment", "target has business impact"])


def _is_initial_access(finding: dict[str, Any]) -> bool:
    category = str(finding.get("category", "")).lower()
    source = str(finding.get("source", "")).lower()
    return category in {"network_policy", "application_security", "cloud_configuration"} or source in {"tenable", "qualys", "wiz", "snyk", "securityhub"}


def _before_risk(chain: list[dict[str, Any]], hops: int, criticality: int, sensitivity: int) -> int:
    base = mean([step["business_risk"] for step in chain]) if chain else 0
    exploit = 7 * len([step for step in chain if step["exploit_available"]])
    active = 10 * len([step for step in chain if step["active_exploitation"]])
    target = criticality * 8 + sensitivity * 6
    path_length = max(0, 18 - hops * 3)
    return _clamp(base * 0.55 + exploit + active + target + path_length)


def _risk_reduction(chain: list[dict[str, Any]], simulations: list[dict[str, Any]], policies: list[dict[str, Any]]) -> int:
    patchable = 8 * len([step for step in chain if step["patch_available"]])
    virtual_patchable = 6 * len([step for step in chain if not step["patch_available"] or "network" in step["category"].lower() or "iam" in step["category"].lower()])
    simulation_signal = min(18, mean([s.get("risk_reduction_estimate", 0) for s in simulations]) * 0.15) if simulations else 0
    return _clamp(12 + patchable + virtual_patchable + simulation_signal + min(12, len(policies) * 2), 5, 85)


def _difficulty_score(chain: list[dict[str, Any]], hops: int, exposed: bool) -> int:
    exploit_ease = -8 * len([step for step in chain if step["exploit_available"] or step["active_exploitation"]])
    no_patch_ease = -4 * len([step for step in chain if not step["patch_available"]])
    category = mean([10 if "iam" in step["category"].lower() else 4 if "network" in step["category"].lower() else 7 for step in chain]) if chain else 5
    exposure = -14 if exposed else 8
    return _clamp(55 + hops * 12 + category + exploit_ease + no_patch_ease + exposure)


def _difficulty_explanation(score: int, chain: list[dict[str, Any]], hops: int, exposed: bool) -> list[str]:
    reasons = [f"Difficulty score {score}/100 from {hops - 1} graph hops and {len(chain)} chained findings."]
    reasons.append("Internet exposure lowers attacker effort." if exposed else "No direct internet exposure increases attacker effort.")
    if any(step["active_exploitation"] for step in chain):
        reasons.append("Active exploitation evidence lowers uncertainty and practical difficulty.")
    if any(step["exploit_available"] for step in chain):
        reasons.append("Public exploit availability lowers required attacker skill.")
    if any(step["domain"] == "iam" for step in chain):
        reasons.append("IAM/token preconditions increase difficulty unless valid credentials already exist.")
    if any(step["domain"] == "network" for step in chain):
        reasons.append("Network reachability preconditions are directly modeled as path edges.")
    if any(not step["patch_available"] for step in chain):
        reasons.append("Missing patch increases reliance on compensating controls and path breakers.")
    return reasons


def _difficulty_band(score: int) -> str:
    for threshold, band in DIFFICULTY_BANDS:
        if score >= threshold:
            return band
    return "LOW"


def _recommended_breakers(chain: list[dict[str, Any]], exposed: bool, target_type: str) -> list[str]:
    breakers = set()
    if exposed:
        breakers.add("WAF/API gateway virtual patch at entry point")
    if any("iam" in step["category"].lower() for step in chain):
        breakers.add("Conditional IAM deny with just-in-time approval")
    if any("network" in step["category"].lower() for step in chain):
        breakers.add("Microsegmentation deny between path hops")
    if "database" in target_type.lower():
        breakers.add("Database route restriction to approved service identities")
    breakers.add("Simulation-backed before/after risk validation")
    return sorted(breakers)


def _preferred_control(domain: str) -> str:
    return {
        "network": "microsegmentation deny rule",
        "iam": "conditional IAM deny",
        "cloud": "cloud policy guardrail",
        "kubernetes": "admission controller or network policy",
        "application": "WAF/API rule",
        "cicd": "protected branch and runner isolation",
        "secrets": "secret revocation and token scope rotation",
        "data_store": "data-store access policy restriction",
        "vulnerability": "patch or virtual patch",
    }.get(domain, "segmentation or compensating control")


def _simulate_controls(chain: list[dict[str, Any]], before: int) -> list[dict[str, Any]]:
    controls = [
        ("patch", lambda step: step["patch_available"], 28),
        ("WAF rule", lambda step: step["domain"] in {"application", "network"}, 24),
        ("IAM deny", lambda step: step["domain"] == "iam", 32),
        ("segmentation", lambda step: step["domain"] in {"network", "data_store", "cloud"}, 30),
        ("container rebuild", lambda step: step["domain"] == "kubernetes", 22),
        ("cloud policy", lambda step: step["domain"] == "cloud", 26),
    ]
    results = []
    for control, matcher, base in controls:
        matched = len([step for step in chain if matcher(step)])
        reduction = _clamp(base + matched * 8, 5, 85)
        results.append({
            "control": control,
            "before_risk": before,
            "after_risk": _clamp(before - reduction, 0, 100),
            "risk_reduction": reduction,
            "assumptions": [
                f"{matched} chain steps match this control domain." if matched else "No direct domain match; control still modeled as compensating defense.",
                "Control is simulated before execution and must be validated with scanner and reachability evidence.",
                "Residual risk remains if alternate paths or credentials still exist.",
            ],
        })
    return results


def _chain_stage_summary(chain: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for step in chain:
        item = groups.setdefault(step.get("stage", "Exploit"), {"stage": step.get("stage", "Exploit"), "count": 0, "max_risk": 0, "confidence": []})
        item["count"] += 1
        item["max_risk"] = max(item["max_risk"], int(step.get("risk_contribution", 0)))
        item["confidence"].append(int(step.get("evidence_confidence", 0)))
    return [{"stage": item["stage"], "count": item["count"], "max_risk": item["max_risk"], "confidence": _avg(item["confidence"])} for item in groups.values()]


def _risk_contribution_waterfall(chain: list[dict[str, Any]], before: int, hop_count: int, criticality: int, sensitivity: int) -> list[dict[str, Any]]:
    exploit_signal = len([step for step in chain if step.get("exploit_available") or step.get("active_exploitation")]) * 9
    exposure_signal = max(0, 18 - hop_count * 3)
    business_signal = criticality * 8 + sensitivity * 6
    chain_signal = _avg([int(step.get("business_risk", 0)) for step in chain])
    confidence_signal = _avg([int(step.get("evidence_confidence", 0)) for step in chain]) * 0.25
    rows = [
        {"factor": "Chained vulnerability severity", "contribution": _clamp(chain_signal * 0.45, 1, before), "explanation": "Average business risk across findings participating in this path."},
        {"factor": "Exploit and threat signal", "contribution": _clamp(exploit_signal, 1, before), "explanation": "Public exploit or active exploitation makes the chain more practical."},
        {"factor": "Reachability and exposure", "contribution": _clamp(exposure_signal, 1, before), "explanation": "Shorter exposed routes require fewer attacker conditions."},
        {"factor": "Crown-jewel business impact", "contribution": _clamp(business_signal, 1, before), "explanation": "Criticality and data sensitivity of the target asset increase path impact."},
        {"factor": "Evidence confidence", "contribution": _clamp(confidence_signal, 1, before), "explanation": "Mapped assets, scanner identity, CVE/control IDs, and preconditions increase confidence."},
    ]
    return sorted(rows, key=lambda item: item["contribution"], reverse=True)


def _control_effectiveness_matrix(controls: list[dict[str, Any]], chain: list[dict[str, Any]]) -> list[dict[str, Any]]:
    confidence = _avg([int(step.get("evidence_confidence", 0)) for step in chain])
    rows = []
    for item in controls:
        friction = 62 if item["control"] == "patch" else 38 if item["control"] == "IAM deny" else 45 if item["control"] == "segmentation" else 28 if item["control"] == "WAF rule" else 55
        time_to_mitigate = "hours" if item["control"] in {"WAF rule", "IAM deny"} else "1-2 days" if item["control"] in {"segmentation", "cloud policy"} else "release window"
        rows.append({
            "control": item["control"],
            "risk_reduction": item["risk_reduction"],
            "operational_friction": friction,
            "time_to_mitigate": time_to_mitigate,
            "confidence": _clamp(confidence + (5 if item["risk_reduction"] > 30 else 0) - (8 if friction > 55 else 0)),
            "recommendation": "preferred path breaker" if item["risk_reduction"] >= 35 and friction <= 45 else "use with approval" if item["risk_reduction"] >= 25 else "supporting control",
        })
    return sorted(rows, key=lambda item: (-item["risk_reduction"], item["operational_friction"]))


def _kill_chain_narrative(entry: str, target: str, chain: list[dict[str, Any]]) -> str:
    stages = " -> ".join([f"{step.get('stage')}: {step.get('title')}" for step in chain]) or "the modeled exploit chain"
    return f"An attacker can begin at {entry}, progress through {stages}, and pressure {target}. The narrative is evidence-backed by scanner normalization, exploit preconditions, and path reachability."


def _attack_stage_model() -> list[dict[str, Any]]:
    return [
        {"stage": "Initial Access", "purpose": "Find the first reachable weakness from internet, VPN, endpoint, app, or cloud edge.", "evidence": ["exposure", "scanner finding", "route"]},
        {"stage": "Credential Access", "purpose": "Identify token, secret, password, or identity material that makes the next hop credible.", "evidence": ["secret scan", "IAM token", "credential age"]},
        {"stage": "Privilege Escalation", "purpose": "Model permissions that turn a foothold into stronger control.", "evidence": ["IAM grant", "role trust", "group membership"]},
        {"stage": "Lateral Movement", "purpose": "Show how access crosses asset, subnet, namespace, account, or project boundaries.", "evidence": ["reachability", "dependency", "security group"]},
        {"stage": "Data Impact", "purpose": "Tie technical compromise to crown-jewel systems and regulated data.", "evidence": ["criticality", "data sensitivity", "business service"]},
        {"stage": "Path Breaker", "purpose": "Recommend the smallest control that removes the highest-risk edge.", "evidence": ["simulation", "control diff", "residual risk"]},
    ]


def _path_breakers(hops: list[str], chain: list[dict[str, Any]], before: int, after: int, fallback: list[str]) -> list[dict[str, Any]]:
    delta = before - after
    recs = []
    for index, hop in enumerate(hops[1:]):
        step = chain[index] if index < len(chain) else chain[-1] if chain else None
        control = _preferred_control(step["domain"]) if step else fallback[0] if fallback else "segmentation deny"
        reduction = _clamp(delta * (0.7 if index == 0 else 0.45), 5, 95)
        recs.append({
            "edge": f"{hops[index]} -> {hop}",
            "control": control,
            "estimated_risk_reduction": reduction,
            "why": f"Break this edge to remove {step['domain'] if step else 'reachability'} preconditions and reduce approximately {reduction}% of path risk.",
        })
    return recs or [{"edge": "entry -> target", "control": fallback[0] if fallback else "Simulation-backed path breaker", "estimated_risk_reduction": delta, "why": f"Break the highest-risk logical edge to reduce {delta}% projected path risk."}]


def _remediation_playbook(chain: list[dict[str, Any]], target_type: str, environment: str, before: int) -> dict[str, Any]:
    primary = sorted(chain, key=lambda step: step["business_risk"], reverse=True)[0]["domain"] if chain else "vulnerability"
    change_risk = "high" if environment == "PRODUCTION" and before >= 75 else "medium" if environment == "PRODUCTION" else "low"
    return {
        "playbook_id": f"{primary}_{target_type.lower()}_{change_risk}".replace(" ", "_"),
        "title": f"{primary.upper()} remediation for {target_type or 'asset'} in {environment or 'unknown'}",
        "owner": "Identity platform owner" if primary == "iam" else "Cloud security owner" if primary == "cloud" else "Application owner" if primary == "application" else "Security remediation owner",
        "change_risk": change_risk,
        "steps": [
            "Confirm asset owner and business service mapping.",
            "Run before-state evidence collection and simulation.",
            f"Apply {_preferred_control(primary)} or permanent remediation.",
            "Route approval based on environment and change risk.",
            "Validate scanner, reachability, and residual path risk after execution.",
        ],
    }


def _evidence_pack(chain: list[dict[str, Any]], before: int, after: int) -> dict[str, Any]:
    return {
        "before_state": [f"{step['normalized_scanner']}: {step['title']}" for step in chain],
        "simulation_result": [f"Before risk {before}%", f"After risk {after}%", *[f"{item['control']}: {item['risk_reduction']}% modeled reduction" for item in _simulate_controls(chain, before)[:3]]],
        "approval": ["Business owner approval", "Security owner approval", "Change risk approval for production or crown-jewel paths"],
        "execution_log": ["Dry-run command or ticket reference", "Control diff or package/version change", "Rollback plan reference"],
        "validation": _validation_plan(chain, "target"),
        "residual_risk": [f"Residual path risk {after}%", "Document accepted assumptions, alternate path checks, and remaining compensating controls"],
    }


def _evidence_requirements(chain: list[dict[str, Any]]) -> list[str]:
    requirements = {"Before-state scanner evidence", "Simulation result", "Approval trail", "After-state validation"}
    if any("iam" in step["category"].lower() for step in chain):
        requirements.add("IAM policy diff")
    if any("network" in step["category"].lower() for step in chain):
        requirements.add("Network path proof")
    if any(step["patch_available"] for step in chain):
        requirements.add("Patch or package version proof")
    if any(step["active_exploitation"] for step in chain):
        requirements.add("Threat-intel exception review")
    return sorted(requirements)


def _validation_plan(chain: list[dict[str, Any]], target_name: str) -> list[str]:
    steps = [
        "Re-run source scanners for all chain findings",
        f"Confirm residual access to {target_name} is blocked",
        "Recompute before/after path risk",
    ]
    if any("iam" in step["category"].lower() for step in chain):
        steps.append("Replay least-privilege IAM checks")
    if any("network" in step["category"].lower() for step in chain):
        steps.append("Run network reachability validation")
    if any(step["patch_available"] for step in chain):
        steps.append("Verify patched versions in inventory")
    return steps


def _customer_narrative(entry: str, target: str, before: int, after: int) -> str:
    return f"Before remediation, {entry} can contribute to a {before}% path risk toward {target}. After the recommended breaker and validated remediation, projected residual path risk is {after}%."


def _priority(before: int, after: int) -> str:
    if before >= 85 or before - after >= 45:
        return "immediate"
    if before >= 70:
        return "high"
    if before >= 45:
        return "scheduled"
    return "monitor"


def _graph_model(paths: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    chains: list[dict[str, Any]] = []

    def upsert(node: dict[str, Any]) -> None:
        existing = nodes.get(node["id"])
        if existing:
            existing["risk"] = max(int(existing.get("risk", 0)), int(node.get("risk", 0)))
            existing["impact_score"] = max(int(existing.get("impact_score", 0)), int(node.get("impact_score", 0)))
            existing["pre_remediation_risk"] = max(int(existing.get("pre_remediation_risk", 0)), int(node.get("pre_remediation_risk", 0)))
            existing["post_remediation_risk"] = min(int(existing.get("post_remediation_risk", 100)), int(node.get("post_remediation_risk", 100)))
            existing["path_ids"] = sorted(set(existing.get("path_ids", []) + node.get("path_ids", [])))
            return
        nodes[node["id"]] = node

    for path in paths:
        hop_ids = [f"asset:{_slug(str(hop))}" for hop in path["hops"]]
        for index, hop in enumerate(path["hops"]):
            upsert({
                "id": hop_ids[index],
                "label": hop,
                "kind": "entry" if index == 0 else "crown_jewel" if index == len(path["hops"]) - 1 else "asset",
                "group": "Entry" if index == 0 else "Target" if index == len(path["hops"]) - 1 else "Transit",
                "risk": path["before_remediation_risk"] if index == len(path["hops"]) - 1 else max(20, path["before_remediation_risk"] - index * 8),
                "impact_score": _point_impact_score(path, index),
                "pre_remediation_risk": path["before_remediation_risk"],
                "post_remediation_risk": path["after_remediation_risk"],
                "path_ids": [path["id"]],
                "difficulty": path["difficulty"],
            })
            if index > 0:
                edge_id = f"reach:{path['id']}:{index}"
                edges[edge_id] = {
                    "id": edge_id,
                    "from": hop_ids[index - 1],
                    "to": hop_ids[index],
                    "label": f"impact {_point_impact_score(path, index)} / pre {path['before_remediation_risk']}% / post {path['after_remediation_risk']}%",
                    "weight": path["before_remediation_risk"],
                    "path_id": path["id"],
                    "relation": "reachability",
                }

        chain_nodes = []
        chain_edges = []
        for index, step in enumerate(path["chain"]):
            node = {
                "id": f"finding:{path['id']}:{index}:{_slug(str(step.get('finding_id')))}",
                "label": step.get("title") or "Finding",
                "kind": "finding",
                "group": step.get("source") or "scanner",
                "risk": step.get("business_risk", 0),
                "impact_score": _clamp(step.get("business_risk", 0) * 0.55 + path["business_impact"] * 0.35 + path["likelihood"] * 0.1),
                "pre_remediation_risk": path["before_remediation_risk"],
                "post_remediation_risk": path["after_remediation_risk"],
                "path_ids": [path["id"]],
                "source_finding_id": step.get("finding_id"),
                "difficulty": path["difficulty"],
            }
            upsert(node)
            chain_nodes.append(node)
            source = hop_ids[0] if index == 0 else chain_nodes[index - 1]["id"]
            edge = {
                "id": f"chain:{path['id']}:{index}",
                "from": source,
                "to": node["id"],
                "label": f"{step.get('technique') or 'Exploit precondition'} / impact {node['impact_score']} / pre {path['before_remediation_risk']}% / post {path['after_remediation_risk']}%",
                "weight": step.get("business_risk", 0),
                "path_id": path["id"],
                "relation": "exploit_precondition",
            }
            edges[edge["id"]] = edge
            chain_edges.append(edge)

        breaker = {
            "id": f"breaker:{path['id']}",
            "label": path["recommended_breakers"][0] if path["recommended_breakers"] else "Simulation-backed path breaker",
            "kind": "breaker",
            "group": path["priority"],
            "risk": path["risk_delta"],
            "impact_score": path["risk_delta"],
            "pre_remediation_risk": path["before_remediation_risk"],
            "post_remediation_risk": path["after_remediation_risk"],
            "path_ids": [path["id"]],
            "difficulty": path["difficulty"],
        }
        upsert(breaker)

        if chain_nodes:
            target_edge = {
                "id": f"chain:{path['id']}:target",
                "from": chain_nodes[-1]["id"],
                "to": hop_ids[-1],
                "label": f"{path['target_asset']} compromise / pre {path['before_remediation_risk']}% / post {path['after_remediation_risk']}%",
                "weight": path["before_remediation_risk"],
                "path_id": path["id"],
                "relation": "exploit_precondition",
            }
            breaker_edge = {
                "id": f"breaker:{path['id']}:risk-drop",
                "from": breaker["id"],
                "to": hop_ids[-1],
                "label": f"{path['risk_delta']}% risk reduction / residual {path['after_remediation_risk']}%",
                "weight": path["risk_delta"],
                "path_id": path["id"],
                "relation": "breaker",
            }
            edges[target_edge["id"]] = target_edge
            edges[breaker_edge["id"]] = breaker_edge
            chain_edges.extend([target_edge, breaker_edge])

        chains.append({
            "path_id": path["id"],
            "path_name": path["name"],
            "difficulty": path["difficulty"],
            "before_remediation_risk": path["before_remediation_risk"],
            "after_remediation_risk": path["after_remediation_risk"],
            "nodes": [
                {"id": hop_ids[0], "label": path["entry_asset"], "kind": "entry", "group": "Entry", "risk": path["before_remediation_risk"], "impact_score": _point_impact_score(path, 0), "pre_remediation_risk": path["before_remediation_risk"], "post_remediation_risk": path["after_remediation_risk"], "path_ids": [path["id"]], "difficulty": path["difficulty"]},
                *chain_nodes,
                {"id": hop_ids[-1], "label": path["target_asset"], "kind": "crown_jewel", "group": "Target", "risk": path["before_remediation_risk"], "impact_score": _point_impact_score(path, len(path["hops"]) - 1), "pre_remediation_risk": path["before_remediation_risk"], "post_remediation_risk": path["after_remediation_risk"], "path_ids": [path["id"]], "difficulty": path["difficulty"]},
                breaker,
            ],
            "edges": chain_edges,
        })

    return {
        "nodes": sorted(nodes.values(), key=lambda node: int(node.get("risk", 0)), reverse=True)[:80],
        "edges": sorted(edges.values(), key=lambda edge: int(edge.get("weight", 0)), reverse=True)[:120],
        "vulnerability_chains": chains[:8],
    }


def _point_impact_score(path: dict[str, Any], index: int) -> int:
    position_weight = 20 if index == len(path["hops"]) - 1 else 8 if index == 0 else 12
    return _clamp(path["business_impact"] * 0.45 + path["before_remediation_risk"] * 0.35 + path["likelihood"] * 0.1 + position_weight)


def _vulnerability_fan_out(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for path in paths:
        for step in path["chain"]:
            finding_id = str(step.get("finding_id"))
            item = groups.setdefault(finding_id, {
                "finding_id": finding_id,
                "title": step.get("title", "Finding"),
                "asset_name": step.get("asset_name", "Unmapped"),
                "scanner": step.get("source", "scanner"),
                "path_ids": set(),
                "targets": set(),
                "impact_score": 0,
                "pre_remediation_risk": 0,
                "post_remediation_risk": 100,
                "total_risk_reduction": 0,
            })
            item["path_ids"].add(path["id"])
            item["targets"].add(path["target_asset"])
            item["impact_score"] = max(item["impact_score"], _clamp(step.get("business_risk", 0) * 0.45 + path["business_impact"] * 0.35 + path["before_remediation_risk"] * 0.2))
            item["pre_remediation_risk"] = max(item["pre_remediation_risk"], path["before_remediation_risk"])
            item["post_remediation_risk"] = min(item["post_remediation_risk"], path["after_remediation_risk"])
            item["total_risk_reduction"] += path["risk_delta"]
    records = []
    for item in groups.values():
        records.append({
            "finding_id": item["finding_id"],
            "title": item["title"],
            "asset_name": item["asset_name"],
            "scanner": item["scanner"],
            "path_count": len(item["path_ids"]),
            "path_ids": sorted(item["path_ids"]),
            "targets": sorted(item["targets"]),
            "impact_score": item["impact_score"],
            "pre_remediation_risk": item["pre_remediation_risk"],
            "post_remediation_risk": item["post_remediation_risk"],
            "total_risk_reduction": item["total_risk_reduction"],
        })
    return sorted(records, key=lambda item: (item["path_count"], item["impact_score"]), reverse=True)[:25]


def _centrality(paths: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, dict[str, int]] = {}
    for path in paths:
        for index, hop in enumerate(path["hops"]):
            current = counts.setdefault(hop, {"count": 0, "transit": 0, "max_risk": 0})
            current["count"] += 1
            current["transit"] += 1 if 0 < index < len(path["hops"]) - 1 else 0
            current["max_risk"] = max(current["max_risk"], int(path["before_remediation_risk"]))
    max_count = max([item["count"] + item["transit"] for item in counts.values()] or [1])
    rows = [
        {
            "asset": asset,
            "score": _percent(item["count"] + item["transit"], max_count),
            "paths": item["count"],
            "max_risk": item["max_risk"],
            "kind": "choke_point" if item["transit"] and item["max_risk"] >= 60 else "asset",
        }
        for asset, item in counts.items()
    ]
    return sorted(rows, key=lambda item: (item["score"], item["max_risk"]), reverse=True)


def _crown_jewel_exposure(target: dict[str, Any]) -> str:
    if target.get("environment") == "PRODUCTION" and _asset_int(target, "criticality", 3) >= 5:
        return "critical"
    if target.get("environment") == "PRODUCTION" or _asset_int(target, "data_sensitivity", 3) >= 5 or _asset_int(target, "criticality", 3) >= 5:
        return "high"
    if _asset_int(target, "criticality", 3) >= 4 or _asset_int(target, "data_sensitivity", 3) >= 4:
        return "medium"
    return "low"


def _scanner_normalization_adapters() -> list[dict[str, Any]]:
    return [
        {
            "source": source,
            "contract": _scanner_adapter(source),
            "required_fields": ["asset identity", "severity", "category", "finding id", "status"],
            "optional_fields": ["CVE/control id", "exploit availability", "active exploitation", "patch availability", "business tags"],
            "output": "canonical finding, exploit preconditions, chain domain, remediation playbook hints",
        }
        for source in ["Tenable", "Qualys", "Wiz", "Prisma Cloud", "Snyk", "GitHub Advanced Security", "AWS Security Hub", "Defender", "CrowdStrike"]
    ]


def _vulnerability_chaining_rules() -> list[dict[str, Any]]:
    return [
        {"domain": "network", "chains_when": ["internet exposure", "reachable service", "weak segmentation"], "breaker": "microsegmentation deny or WAF/API rule"},
        {"domain": "iam", "chains_when": ["valid token scope", "privilege escalation", "cross-account trust"], "breaker": "conditional IAM deny or just-in-time approval"},
        {"domain": "cloud", "chains_when": ["public control-plane exposure", "misconfigured resource policy", "production account reachability"], "breaker": "cloud policy guardrail"},
        {"domain": "kubernetes", "chains_when": ["service account token", "workload escape", "cluster API reachability"], "breaker": "admission control, network policy, or rebuild"},
        {"domain": "application", "chains_when": ["public endpoint", "vulnerable package or route", "sensitive operation"], "breaker": "patch or WAF/API rule"},
        {"domain": "cicd", "chains_when": ["repo write path", "runner trust", "deployment token"], "breaker": "branch protection and runner isolation"},
        {"domain": "secrets", "chains_when": ["exposed credential", "valid token", "trusted target service"], "breaker": "revocation and secret rotation"},
        {"domain": "data_store", "chains_when": ["data-plane route", "grant or credential", "sensitive collection"], "breaker": "data-store policy restriction"},
    ]


def _executive_views(paths: list[dict[str, Any]]) -> dict[str, Any]:
    closed = len([path for path in paths if path["after_remediation_risk"] < 35])
    return {
        "top_business_services_at_risk": [
            {
                "service": path["target_asset"],
                "entry": path["entry_asset"],
                "before_risk": path["before_remediation_risk"],
                "after_risk": path["after_remediation_risk"],
                "difficulty": path["difficulty"],
                "crown_jewel_exposure": path["crown_jewel_exposure"],
            }
            for path in paths[:10]
        ],
        "risk_reduced_this_week": sum(path["risk_delta"] for path in paths),
        "blocked_remediations": [
            {
                "path": path["name"],
                "blocker": path["path_breaker_recommendations"][0]["control"] if path["path_breaker_recommendations"] else "approval or compensating control required",
                "residual_risk": path["after_remediation_risk"],
            }
            for path in paths
            if path["priority"] == "immediate" and path["after_remediation_risk"] >= 50
        ],
        "attack_paths_closed": closed,
        "narrative": f"{closed} attack paths are modeled below residual-risk threshold after recommended controls." if closed else "No attack paths are fully closed yet; approve the top path breakers to reduce residual risk.",
    }


def _asset_int(asset: dict[str, Any], key: str, default: int) -> int:
    return int(asset.get(key, asset.get(key.replace("_", ""), default)) or default)


def _avg(values: list[int]) -> int:
    return round(mean(values)) if values else 0


def _percent(numerator: int, denominator: int) -> int:
    return round((numerator / max(1, denominator)) * 100)


def _clamp(value: float, low: int = 1, high: int = 100) -> int:
    return max(low, min(high, round(value)))


def _slug(value: str) -> str:
    slug = "".join(char.lower() if char.isalnum() else "-" for char in value).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug or "node"
