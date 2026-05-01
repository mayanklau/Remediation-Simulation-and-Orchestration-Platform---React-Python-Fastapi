from __future__ import annotations

from statistics import mean
from typing import Any


def _percent(part: int, total: int) -> int:
    return 0 if total <= 0 else round((part / total) * 100)


def _scanner_family(source: str, category: str) -> str:
    text = f"{source} {category}".lower()
    if any(token in text for token in ["tenable", "qualys", "nessus", "rapid7", "vulnerability"]):
        return "vulnerability_scanner"
    if any(token in text for token in ["wiz", "aws", "azure", "gcp", "cloud"]):
        return "cloud_posture"
    if any(token in text for token in ["snyk", "github", "code", "appsec", "dependency"]):
        return "code_security"
    if any(token in text for token in ["iam", "identity", "permission"]):
        return "identity"
    if any(token in text for token in ["kubernetes", "container", "network"]):
        return "network_kubernetes"
    if "compliance" in text or "control" in text:
        return "compliance"
    return "custom_api"


def _scanner_coverage(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    families = ["vulnerability_scanner", "cloud_posture", "code_security", "identity", "network_kubernetes", "compliance", "custom_api"]
    rows = []
    for family in families:
        scoped = [f for f in findings if _scanner_family(str(f.get("source", "")), str(f.get("category", ""))) == family]
        total = len(scoped)
        mapped = len([f for f in scoped if f.get("asset_id") or f.get("asset") or f.get("asset_external_id")])
        exploit = len([f for f in scoped if f.get("exploit_available") is not None or f.get("active_exploitation") is not None or f.get("cve")])
        remediation = len([f for f in scoped if f.get("patch_available") is not None or f.get("remediation") or f.get("control_id")])
        rows.append({
            "family": family,
            "findings": total,
            "asset_mapping_coverage": _percent(mapped, total),
            "exploit_signal_coverage": _percent(exploit, total),
            "remediation_signal_coverage": _percent(remediation, total),
            "ready_for_attack_graph": total > 0 and mapped == total and exploit > 0,
        })
    return rows


def _decision_readiness(paths: list[dict[str, Any]]) -> dict[str, Any]:
    if not paths:
        return {
            "customer_ready_paths": 0,
            "immediate_executive_escalations": 0,
            "average_difficulty_score": 0,
            "average_likelihood": 0,
            "average_business_impact": 0,
            "recommended_decision": "needs_data",
        }
    ready = [p for p in paths if p.get("risk_delta", 0) >= 20 and p.get("after_remediation_risk", 100) <= 70]
    escalations = [p for p in paths if p.get("priority") == "immediate" or p.get("before_remediation_risk", 0) >= 85]
    avg = lambda key: round(mean([float(p.get(key, 0)) for p in paths]))
    return {
        "customer_ready_paths": len(ready),
        "immediate_executive_escalations": len(escalations),
        "average_difficulty_score": avg("difficulty_score"),
        "average_likelihood": avg("likelihood"),
        "average_business_impact": avg("business_impact"),
        "recommended_decision": "escalate_now" if escalations else "approve_campaign" if ready else "needs_more_context",
    }
