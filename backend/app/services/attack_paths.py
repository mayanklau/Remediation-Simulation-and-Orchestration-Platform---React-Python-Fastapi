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
    graph_model = _graph_model(paths)
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
        },
        "scanner_coverage": _scanner_coverage(findings),
        "decision_readiness": _decision_readiness(paths),
        "subject_maturity": _subject_maturity(paths, graph_model, len(findings)),
        "development_maturity": _development_maturity(paths, len(policies), len(simulations)),
        "attack_graph": {
            "method": "Layered logical attack graph: entry assets, reachable services, exploit preconditions, crown-jewel targets, and policy-backed breaker controls.",
            "nodes": graph_model["nodes"],
            "edges": graph_model["edges"],
        },
        "vulnerability_chain_graph": graph_model["vulnerability_chains"],
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
    return {
        "id": "-".join(path),
        "name": f"{start.get('label')} to {target.get('label')}",
        "entry_asset": start.get("label"),
        "target_asset": target.get("label"),
        "hops": [nodes[asset_id].get("label", asset_id) for asset_id in path if asset_id in nodes],
        "chain": chain,
        "scanner_inputs": sorted({step["source"] for step in chain}),
        "difficulty": _difficulty_band(difficulty_score),
        "difficulty_score": difficulty_score,
        "before_remediation_risk": before,
        "after_remediation_risk": after,
        "risk_delta": before - after,
        "likelihood": _clamp(100 - difficulty_score + 8 * len([step for step in chain if step["exploit_available"] or step["active_exploitation"]])),
        "business_impact": _clamp(_asset_int(target, "criticality", 3) * 12 + _asset_int(target, "data_sensitivity", 3) * 10 + before * 0.35),
        "recommended_breakers": _recommended_breakers(chain, bool(start.get("internet_exposure")), str(target.get("type", ""))),
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
    return {
        "finding_id": finding.get("_id"),
        "asset_id": finding.get("asset_id"),
        "title": finding.get("title"),
        "source": finding.get("source", "api"),
        "category": finding.get("category", "vulnerability"),
        "severity": finding.get("severity", "MEDIUM"),
        "technique": metadata.get("attack_technique") or _map_technique(finding.get("category", "vulnerability")),
        "business_risk": round(float(finding.get("business_risk_score", 0))),
        "exploit_available": bool(finding.get("exploit_available")),
        "active_exploitation": bool(finding.get("active_exploitation")),
        "patch_available": bool(finding.get("patch_available")),
    }


def _map_technique(category: str) -> str:
    value = category.lower()
    if "iam" in value:
        return "Valid Accounts / Permission Groups Discovery"
    if "network" in value:
        return "External Remote Services / Network Service Discovery"
    if "cloud" in value:
        return "Cloud Service Dashboard / Account Discovery"
    if "container" in value or "kubernetes" in value:
        return "Container and Resource Discovery"
    if "application" in value:
        return "Exploit Public-Facing Application"
    return "Exploit Vulnerability"


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
                "difficulty": path["difficulty"],
            })
            if index > 0:
                edge_id = f"reach:{path['id']}:{index}"
                edges[edge_id] = {
                    "id": edge_id,
                    "from": hop_ids[index - 1],
                    "to": hop_ids[index],
                    "label": f"{path['difficulty']} / {path['before_remediation_risk']}%",
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
                "risk": step.get("business_risk_score", 0),
                "difficulty": path["difficulty"],
            }
            upsert(node)
            chain_nodes.append(node)
            source = hop_ids[0] if index == 0 else chain_nodes[index - 1]["id"]
            edge = {
                "id": f"chain:{path['id']}:{index}",
                "from": source,
                "to": node["id"],
                "label": step.get("technique") or "Exploit precondition",
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
            "difficulty": path["difficulty"],
        }
        upsert(breaker)

        if chain_nodes:
            target_edge = {
                "id": f"chain:{path['id']}:target",
                "from": chain_nodes[-1]["id"],
                "to": hop_ids[-1],
                "label": f"{path['target_asset']} compromise",
                "weight": path["before_remediation_risk"],
                "path_id": path["id"],
                "relation": "exploit_precondition",
            }
            breaker_edge = {
                "id": f"breaker:{path['id']}:risk-drop",
                "from": breaker["id"],
                "to": hop_ids[-1],
                "label": f"{path['risk_delta']}% risk reduction",
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
                {"id": hop_ids[0], "label": path["entry_asset"], "kind": "entry", "group": "Entry", "risk": path["before_remediation_risk"], "difficulty": path["difficulty"]},
                *chain_nodes,
                {"id": hop_ids[-1], "label": path["target_asset"], "kind": "crown_jewel", "group": "Target", "risk": path["before_remediation_risk"], "difficulty": path["difficulty"]},
                breaker,
            ],
            "edges": chain_edges,
        })

    return {
        "nodes": sorted(nodes.values(), key=lambda node: int(node.get("risk", 0)), reverse=True)[:80],
        "edges": sorted(edges.values(), key=lambda edge: int(edge.get("weight", 0)), reverse=True)[:120],
        "vulnerability_chains": chains[:8],
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
