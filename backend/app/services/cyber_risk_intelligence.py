def capability(id: str, name: str, subject_area: str, production_use: str, inputs: list[str], outputs: list[str], decision: str, status: str) -> dict:
    return {"id": id, "name": name, "subject_area": subject_area, "production_use": production_use, "inputs": inputs, "outputs": outputs, "decision": decision, "status": status}


def metric(id: str, name: str, formula: str, business_use: str, status: str) -> dict:
    return {"id": id, "name": name, "formula": formula, "business_use": business_use, "status": status}


def build_cyber_risk_intelligence_model() -> dict:
    capabilities = [
        capability("exploit_intel_fusion", "Exploit Intelligence Fusion", "threat intelligence", "Prioritize findings with KEV, EPSS-style probability, exploit availability, active exploitation, ransomware association, and compensating-control context.", ["CVE", "KEV", "exploit feed", "scanner finding", "control state"], ["exploit confidence", "active threat tag", "priority uplift"], "Escalate high-confidence exploited paths before generic severity queues.", "ready_to_wire"),
        capability("business_service_graph", "Business Service Risk Graph", "business impact", "Map assets and attack paths to revenue services, regulated data, customers, dependencies, and operational owners.", ["asset graph", "CMDB", "service catalog", "data classification"], ["service exposure", "blast radius", "owner accountability"], "Prioritize crown-jewel and customer-impacting paths over isolated hosts.", "implemented"),
        capability("attack_path_confidence", "Attack Path Confidence", "vulnerability analytics", "Classify paths as proven, inferred, scanner-only, topology-only, or validation-missing.", ["reachability", "scanner evidence", "asset dependency", "control evidence"], ["confidence label", "missing evidence", "validation request"], "Block automation when a path is high risk but low confidence.", "implemented"),
        capability("exposure_management", "Exposure Management Score", "exposure analytics", "Score internet, identity, cloud, Kubernetes, API, secrets, and third-party exposure as separate dimensions.", ["asset inventory", "IAM graph", "cloud posture", "API inventory", "secret findings"], ["exposure vector", "exposure delta", "path entry score"], "Select the right breaker: WAF, IAM deny, segmentation, secret rotation, or cloud policy.", "implemented"),
        capability("change_risk_modeling", "Change-Risk Modeling", "production safety", "Estimate breakage risk using asset criticality, dependency centrality, deployment history, maintenance windows, rollback quality, and owner confidence.", ["deployment history", "dependency graph", "rollback plan", "owner signal"], ["change risk", "approval route", "rollback requirement"], "Route risky fixes to CAB and recommend virtual patching when operational risk is too high.", "ready_to_wire"),
        capability("strategy_selector", "Remediation Strategy Selector", "remediation planning", "Choose patch, upgrade, config change, IAM deny, segmentation, WAF rule, virtual patch, container rebuild, secret rotation, or exception.", ["finding type", "asset type", "exploitability", "change risk", "control catalog"], ["primary strategy", "fallback strategy", "evidence checklist"], "Make remediation action generation domain-aware instead of one-size-fits-all.", "implemented"),
        capability("control_effectiveness", "Control Effectiveness Validation", "control assurance", "Prove whether a remediation reduced reachability, exploitability, privilege, exposure, or blast radius.", ["before state", "after scan", "reachability test", "policy state"], ["control effectiveness", "residual risk", "validation failure"], "Reopen work when a patch or compensating control did not actually reduce risk.", "ready_to_wire"),
        capability("threat_informed_priority", "Threat-Informed Prioritization", "adversary behavior", "Map paths and findings to MITRE ATT&CK, ransomware playbooks, cloud attack techniques, identity kill chains, and adversary behaviors.", ["finding category", "technique map", "threat campaign", "identity path"], ["technique tags", "threat narrative", "priority uplift"], "Explain why a lower-CVSS item matters when it unlocks a real adversary path.", "ready_to_wire"),
        capability("crown_jewel_governance", "Crown-Jewel Governance", "governance", "Define critical services, regulated data stores, production chokepoints, and mandatory approval thresholds.", ["service catalog", "data class", "environment", "criticality"], ["crown-jewel policy", "mandatory approvals", "breaker targets"], "Force higher governance for paths touching business-critical services.", "implemented"),
        capability("exception_governance", "Exception Governance", "risk acceptance", "Manage risk acceptance with expiry, owner, compensating control, business justification, residual risk, and executive approval.", ["risk owner", "residual risk", "expiry", "compensating control"], ["exception package", "expiry alert", "accepted risk ledger"], "Prevent permanent exceptions and weak residual-risk acceptance.", "implemented"),
        capability("campaign_intelligence", "Campaign Intelligence", "program execution", "Group work by exploit chain, business service, CVE family, owner, cloud account, app team, SLA breach, or path-breaker impact.", ["attack paths", "owners", "SLAs", "service graph"], ["campaign waves", "blocked work", "risk burn-down"], "Turn backlog noise into measurable remediation campaigns.", "implemented"),
        capability("continuous_validation", "Continuous Validation", "assurance", "Re-check closed findings, reopened scanner findings, control drift, cloud drift, IAM drift, and reintroduced vulnerable packages.", ["scanner deltas", "policy drift", "package inventory", "cloud config"], ["reopen signal", "drift alert", "validation score"], "Keep remediated risk closed instead of trusting one-time closure.", "ready_to_wire"),
        capability("scanner_trust", "Scanner Trust Scoring", "data quality", "Score each source by freshness, false positives, duplicate rate, mapping confidence, validation success, and coverage.", ["source freshness", "dedupe clusters", "validation outcomes"], ["trust score", "source weighting", "coverage gap"], "Weight risk decisions by data source quality.", "ready_to_wire"),
        capability("playbook_marketplace", "Remediation Playbook Marketplace", "domain automation", "Provide playbooks for CVEs, cloud misconfigs, IAM issues, Kubernetes risks, secrets, SAST findings, containers, and endpoint risks.", ["finding type", "asset type", "control catalog"], ["playbook", "automation hook", "evidence contract"], "Reduce analyst handwork while keeping execution governed.", "ready_to_wire"),
    ]
    economics = [
        metric("risk_reduced_per_hour", "Risk Reduced Per Engineering Hour", "risk_delta / estimated_engineering_hours", "Choose work with the best risk reduction for constrained teams.", "implemented"),
        metric("cost_of_delay", "Cost Of Delay", "daily_exposure_risk * days_blocked * business_criticality", "Escalate blocked fixes that get more expensive every day.", "ready_to_wire"),
        metric("sla_breach_cost", "SLA Breach Cost", "breach_probability * regulatory_or_contractual_impact", "Explain overdue remediation in financial terms.", "ready_to_wire"),
        metric("exception_cost", "Residual-Risk Acceptance Cost", "accepted_residual_risk * exception_duration * service_criticality", "Make exceptions visible as a cost, not a loophole.", "implemented"),
        metric("campaign_roi", "Campaign ROI", "risk_reduced - change_cost - exception_cost", "Compare campaigns by measurable cyber-risk economics.", "implemented"),
    ]
    narratives = [
        {"id": "weekly_risk_reduction", "title": "Risk Reduced This Week", "message": "Closed attack paths, residual risk reduction, and risk reduced per engineering hour.", "audience": "CISO"},
        {"id": "decisions_needed", "title": "Decisions Needed", "message": "High-value exceptions, blocked crown-jewel remediations, and controls needing executive approval.", "audience": "security leadership"},
        {"id": "service_exposure", "title": "Business Services Still Exposed", "message": "Services with exploitable paths, confidence gaps, and recommended path breakers.", "audience": "business owners"},
        {"id": "control_truth", "title": "Controls That Did Not Work", "message": "Remediations that failed validation or left material residual risk.", "audience": "risk committee"},
    ]
    total = len(capabilities) + len(economics)
    implemented = len([item for item in capabilities + economics if item["status"] == "implemented"])
    return {
        "summary": {
            "capabilities": len(capabilities),
            "economics_metrics": len(economics),
            "executive_narratives": len(narratives),
            "implemented": implemented,
            "ready_to_wire": len([item for item in capabilities + economics if item["status"] == "ready_to_wire"]),
            "external_required": len([item for item in capabilities + economics if item["status"] == "external_required"]),
            "intelligence_score": round((implemented / total) * 100),
            "operating_model": "threat_informed_business_risk_governance",
        },
        "capabilities": capabilities,
        "economics": economics,
        "narratives": narratives,
        "operating_rules": [
            "Severity alone never drives priority when exploitability, exposure, business service, and path position disagree.",
            "Every accepted risk needs owner, expiry, compensating control, residual risk, and approval evidence.",
            "Every closed remediation must be eligible for continuous validation and drift detection.",
            "Every executive risk statement must show confidence, assumptions, and before/after residual risk.",
        ],
    }
