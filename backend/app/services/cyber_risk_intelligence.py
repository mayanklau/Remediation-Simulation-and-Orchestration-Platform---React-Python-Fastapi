def capability(id: str, name: str, subject_area: str, production_use: str, inputs: list[str], outputs: list[str], decision: str, status: str) -> dict:
    return {"id": id, "name": name, "subject_area": subject_area, "production_use": production_use, "inputs": inputs, "outputs": outputs, "decision": decision, "status": status}


def metric(id: str, name: str, formula: str, business_use: str, status: str) -> dict:
    return {"id": id, "name": name, "formula": formula, "business_use": business_use, "status": status}


def scenario(id: str, name: str, kill_chain: list[str], decision_use: str, controls: list[str], status: str) -> dict:
    return {"id": id, "name": name, "kill_chain": kill_chain, "decision_use": decision_use, "controls": controls, "status": status}


def governance(id: str, name: str, scope: str, rule: str, output: str, status: str) -> dict:
    return {"id": id, "name": name, "scope": scope, "rule": rule, "output": output, "status": status}


def certification(id: str, source: str, required_fields: list[str], mapping: str) -> dict:
    return {"id": id, "source": source, "required_fields": required_fields, "mapping": mapping, "acceptance": "sample export, parser contract, normalized finding, asset match, and evidence trace"}


def mitre(id: str, stage: str, technique: str, preconditions: list[str], breaker_controls: str) -> dict:
    return {"id": id, "stage": stage, "technique": technique, "preconditions": preconditions, "breaker_controls": breaker_controls}


def confidence(label: str, score: int, explanation: str) -> dict:
    return {"label": label, "score": score, "explanation": explanation}


def impact(id: str, asset_class: str, signals: list[str], governance_rule: str) -> dict:
    return {"id": id, "asset_class": asset_class, "signals": signals, "governance": governance_rule}


def control_effect(control: str, objective: str, validation: list[str], time_to_mitigate: str) -> dict:
    return {"control": control, "objective": objective, "validation": validation, "time_to_mitigate": time_to_mitigate}


def build_subject_matter_maturity_pack() -> dict:
    return {
        "scanner_certification": [
            certification("tenable", "Tenable VM/Nessus", ["plugin_id", "cve", "cvss", "vpr", "asset_uuid", "port", "protocol"], "CVE and plugin evidence mapped to network/app exposure, exploitability, and affected asset identity."),
            certification("qualys", "Qualys VMDR", ["qid", "cve_id", "threat", "impact", "solution", "dns", "netbios", "tracking_method"], "QID evidence normalized into vulnerability, asset, remediation, and exception-ready evidence fields."),
            certification("wiz", "Wiz", ["issue_id", "toxic_combination", "cloud_resource", "subscription", "attack_path", "severity"], "Cloud finding and toxic-combination evidence mapped to cloud, IAM, data, and Kubernetes graph edges."),
            certification("prisma_cloud", "Prisma Cloud", ["policy_id", "resource_id", "account", "cloud_type", "compliance_standard"], "Cloud and Kubernetes policy violations mapped to guardrail remediation and control drift validation."),
            certification("snyk", "Snyk", ["issue_id", "package", "version", "fixed_in", "exploit_maturity", "project"], "Open-source/package findings mapped to app dependency paths, fix versions, and CI/CD control gates."),
            certification("ghas", "GitHub Advanced Security", ["alert_number", "rule_id", "secret_type", "repository", "workflow"], "Code scanning and secret alerts mapped to CI/CD, secret-rotation, and production-deploy attack chains."),
        ],
        "mitre_attack_depth": [
            mitre("initial_access", "Initial Access", "T1190 Exploit Public-Facing Application", ["internet exposure", "reachable service", "exploitable finding"], "patch, WAF rule, segmentation"),
            mitre("credential_access", "Credential Access", "T1552 Unsecured Credentials", ["secret finding", "token scope", "repo/build log exposure"], "secret rotation, secret scanning, runner isolation"),
            mitre("privilege_escalation", "Privilege Escalation", "T1098 Account Manipulation", ["over-privileged role", "trust policy", "group membership"], "IAM deny, least privilege, JIT access"),
            mitre("lateral_movement", "Lateral Movement", "T1021 Remote Services", ["network route", "service dependency", "identity reachability"], "segmentation, network policy, conditional access"),
            mitre("exfiltration", "Exfiltration", "T1041 Exfiltration Over C2 Channel", ["sensitive data store", "egress path", "token privilege"], "egress control, DLP, database access policy"),
            mitre("impact", "Impact", "T1486 Data Encrypted for Impact", ["backup access", "admin privilege", "ransomware signal"], "backup immutability, EDR isolation, privilege removal"),
        ],
        "exploitability_confidence_model": [
            confidence("proven", 95, "Observed exploit, reachable asset, validated preconditions, mapped business impact, and post-remediation validation plan."),
            confidence("high_confidence", 80, "Exploit available, KEV/EPSS signal, internet or identity exposure, and strong asset mapping."),
            confidence("inferred", 65, "Logical chain exists with partial evidence; requires reachability or credential validation before automation."),
            confidence("scanner_only", 45, "Scanner finding exists but topology, privilege, or exposure evidence is incomplete."),
            confidence("validation_missing", 25, "Risk cannot drive autonomous action until asset identity and control evidence are enriched."),
        ],
        "business_impact_model": [
            impact("crown_jewel", "Regulated or revenue-critical system", ["service tier", "data class", "customer impact", "availability dependency"], "mandatory executive approval for residual risk"),
            impact("production_service", "Customer-facing production workload", ["criticality", "SLO", "owner", "deployment window"], "CAB or service-owner approval for risky changes"),
            impact("identity_control_plane", "IAM, CI/CD, or admin control path", ["standing privilege", "token scope", "blast radius"], "path breaker prioritized over isolated patch queue"),
            impact("data_store", "Sensitive or regulated datastore", ["record volume", "encryption", "egress", "access path"], "exfiltration and compliance impact applied to risk"),
            impact("shared_platform", "Shared runtime, cluster, image, or gateway", ["tenant reach", "dependency centrality", "rollback plan"], "wave-based remediation and rollback evidence required"),
        ],
        "control_effectiveness_library": [
            control_effect("patch", "Remove vulnerable condition", ["version check", "rescan", "exploit precondition removed"], "release window"),
            control_effect("waf_rule", "Block public exploit payload or route", ["rule deployed", "request simulation", "false-positive review"], "hours"),
            control_effect("iam_deny", "Remove privilege edge", ["policy diff", "access simulation", "least privilege proof"], "hours"),
            control_effect("segmentation", "Remove reachability edge", ["network path test", "flow log review", "dependency exception"], "1-2 days"),
            control_effect("secret_rotation", "Invalidate credential edge", ["old token revoked", "new secret stored", "consumer restarted"], "hours"),
            control_effect("cloud_policy", "Prevent drift and unsafe cloud state", ["policy-as-code diff", "drift check", "cloud config validation"], "1-2 days"),
            control_effect("kubernetes_policy", "Block risky workload admission or runtime path", ["admission test", "RBAC review", "network policy test"], "release window"),
        ],
        "validation_and_exception_pack": [
            "Every closure requires before state, applied control, validation result, residual risk, owner, timestamp, and correlation ID.",
            "Every exception requires expiry, compensating control, business justification, risk owner, executive approver for crown jewels, and renewal workflow.",
            "Every failed validation reopens the remediation action and updates the attack path with residual risk.",
            "Every scanner-certified adapter has a sample export, mapping contract, data-quality checks, and customer acceptance evidence.",
        ],
        "pilot_acceptance_pack": [
            "Load customer scanner exports for at least two sources and reconcile asset identity with CMDB/cloud inventory.",
            "Demonstrate five vulnerability chains across network, IAM, cloud, Kubernetes, and CI/CD/secrets.",
            "Show pre-remediation and post-remediation path risk for patch, WAF, IAM deny, segmentation, and secret rotation.",
            "Generate evidence pack for one completed remediation, one exception, one failed validation, and one executive report.",
            "Agree success metrics: attack paths closed, risk reduced, backlog noise reduced, exception aging reduced, and validation pass rate.",
        ],
    }


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
    scenario_packs = [
        scenario("ransomware_path", "Ransomware Path Simulation", ["initial access", "privilege escalation", "lateral movement", "backup disruption", "impact"], "Prioritize fixes that stop encryption or backup tampering.", ["EDR isolation", "segmentation", "privileged access removal", "backup immutability"], "ready_to_wire"),
        scenario("cloud_takeover", "Cloud Takeover Simulation", ["initial access", "credential access", "privilege escalation", "persistence", "data exfiltration"], "Show how public exposure and IAM privilege become cloud control-plane compromise.", ["conditional deny", "least privilege", "SCP guardrail", "storage restriction"], "ready_to_wire"),
        scenario("identity_compromise", "Identity Compromise Simulation", ["phishing", "token theft", "privilege escalation", "lateral movement", "persistence"], "Prioritize standing privilege, stale access, service accounts, and conditional access gaps.", ["MFA enforcement", "JIT privilege", "token revocation", "conditional access"], "implemented"),
        scenario("cicd_poisoning", "CI/CD Poisoning Simulation", ["repo access", "secret theft", "pipeline tamper", "artifact poisoning", "production deploy"], "Connect code security and secrets findings to production takeover risk.", ["branch protection", "secret rotation", "signed artifacts", "runner isolation"], "ready_to_wire"),
        scenario("kubernetes_escape", "Kubernetes Escape Simulation", ["container exploit", "service account abuse", "node escape", "cluster lateral movement", "data access"], "Explain how container, RBAC, and network policy gaps chain together.", ["admission control", "RBAC minimization", "network policy", "node hardening"], "ready_to_wire"),
        scenario("data_exfiltration", "Data Exfiltration Simulation", ["initial access", "discovery", "credential access", "database reachability", "exfiltration"], "Prioritize paths to regulated records, customer data, and unencrypted stores.", ["egress restriction", "database access policy", "encryption", "DLP alert"], "implemented"),
    ]
    governance_matrix = [
        governance("risk_appetite", "Risk Appetite Engine", "business unit, service tier, data class, geography, regulation", "Residual risk must stay under appetite or require executive exception.", "appetite decision and approval route", "ready_to_wire"),
        governance("control_coverage_matrix", "Control Coverage Matrix", "attack path edge", "Every edge maps to preventive, detective, compensating, and recovery controls.", "coverage gap and path-breaker shortlist", "implemented"),
        governance("toxic_combinations", "Toxic Combination Detection", "asset, identity, finding, data, exposure", "Flag internet exposure plus admin privilege plus exploitable CVE plus sensitive data.", "toxic combination incident and priority uplift", "implemented"),
        governance("kill_chain_stages", "Attack Path Kill-Chain Staging", "path step", "Classify path steps by initial access, escalation, lateral movement, persistence, exfiltration, and impact.", "stage-aware remediation plan", "implemented"),
        governance("regulatory_mapping", "Regulatory Mapping", "evidence pack and control", "Map evidence to NIST CSF, ISO 27001, SOC 2, PCI DSS, HIPAA, GDPR, RBI, and SEBI.", "control-to-evidence export", "ready_to_wire"),
        governance("security_debt_ledger", "Security Debt Ledger", "accepted risk, overdue work, recurring exceptions, reintroduced findings", "Aged risk must be visible by owner, service, expiry, and business impact.", "security debt balance and aging report", "ready_to_wire"),
        governance("dynamic_sla", "SLA Intelligence", "exploitability, asset criticality, exposure, active threat, business service", "SLA adjusts by real-world risk instead of static severity.", "dynamic due date and escalation", "ready_to_wire"),
        governance("decision_simulator", "Executive Decision Simulator", "patch, virtual patch, accept, segment, defer", "Compare cost, risk delta, time, operational risk, and confidence.", "decision recommendation with tradeoffs", "implemented"),
        governance("dependency_planner", "Remediation Dependency Planner", "fix sequence, shared teams, change windows, conflicting controls", "Prevent broken campaigns caused by prerequisites and change conflicts.", "sequenced waves and blockers", "ready_to_wire"),
        governance("false_positive_adjudication", "False-Positive Adjudication", "finding disposition", "Disposition requires reason code, evidence, expiry, and scanner feedback.", "auditable false-positive record", "implemented"),
        governance("live_drift_watchlist", "Live Exposure Drift Watchlist", "crown jewels, internet edge, secrets, identities, compensating controls", "Notify when fragile exposure becomes materially worse.", "drift alert and reopened risk", "ready_to_wire"),
        governance("insurance_reporting", "Cyber Insurance Reporting", "controls, ransomware exposure, evidence, risk reduction", "Produce insurer-ready posture and evidence exports.", "insurance evidence package", "ready_to_wire"),
        governance("third_party_risk", "M&A And Third-Party Risk View", "supplier assets, inherited systems, external dependencies", "Compare inherited and external exposure with internal appetite.", "third-party exposure score", "ready_to_wire"),
        governance("identity_cloud_data_risk", "Identity, Cloud, And Data Risk Analytics", "IAM graph, cloud blast radius, sensitive datasets", "Connect privilege, public exposure, storage access, encryption, and exfiltration paths.", "combined identity-cloud-data path risk", "implemented"),
    ]
    scored_items = capabilities + economics + scenario_packs + governance_matrix
    total = len(scored_items)
    implemented = len([item for item in scored_items if item["status"] == "implemented"])
    subject_matter_maturity_pack = build_subject_matter_maturity_pack()
    return {
        "summary": {
            "capabilities": len(capabilities),
            "economics_metrics": len(economics),
            "executive_narratives": len(narratives),
            "scenario_packs": len(scenario_packs),
            "governance_controls": len(governance_matrix),
            "certification_tracks": len(subject_matter_maturity_pack["scanner_certification"]),
            "mitre_mapped_hops": len(subject_matter_maturity_pack["mitre_attack_depth"]),
            "control_validation_methods": len(subject_matter_maturity_pack["control_effectiveness_library"]),
            "implemented": implemented,
            "ready_to_wire": len([item for item in scored_items if item["status"] == "ready_to_wire"]),
            "external_required": len([item for item in scored_items if item["status"] == "external_required"]),
            "intelligence_score": round((implemented / total) * 100),
            "operating_model": "threat_informed_business_risk_governance",
        },
        "capabilities": capabilities,
        "economics": economics,
        "narratives": narratives,
        "scenario_packs": scenario_packs,
        "governance_matrix": governance_matrix,
        "subject_matter_maturity_pack": subject_matter_maturity_pack,
        "operating_rules": [
            "Severity alone never drives priority when exploitability, exposure, business service, and path position disagree.",
            "Every accepted risk needs owner, expiry, compensating control, residual risk, and approval evidence.",
            "Every closed remediation must be eligible for continuous validation and drift detection.",
            "Every executive risk statement must show confidence, assumptions, and before/after residual risk.",
        ],
    }
