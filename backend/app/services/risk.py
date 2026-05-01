from datetime import timedelta
from app.models import Asset, Finding, now


SEVERITY_WEIGHT = {"LOW": 20, "MEDIUM": 40, "HIGH": 70, "CRITICAL": 90}


def score_finding(payload: dict, asset: Asset | None) -> tuple[float, float, str]:
    severity = str(payload.get("severity", "MEDIUM")).upper()
    base = SEVERITY_WEIGHT.get(severity, 40)
    exploit = 12 if payload.get("exploit_available") else 0
    active = 18 if payload.get("active_exploitation") else 0
    missing_patch = 8 if not payload.get("patch_available", False) else 0
    exposure = 12 if asset and asset.internet_exposure else 0
    criticality = (asset.criticality - 3) * 5 if asset else 0
    sensitivity = (asset.data_sensitivity - 3) * 4 if asset else 0
    risk = min(100, max(1, base + exploit + active + missing_patch))
    business = min(100, max(1, risk + exposure + criticality + sensitivity))
    explanation = (
        f"{severity} severity, exploit={bool(payload.get('exploit_available'))}, "
        f"active={bool(payload.get('active_exploitation'))}, exposure={bool(asset and asset.internet_exposure)}"
    )
    return float(risk), float(business), explanation


def due_date_for(severity: str):
    days = {"CRITICAL": 7, "HIGH": 14, "MEDIUM": 30, "LOW": 90}.get(severity.upper(), 30)
    return now() + timedelta(days=days)


def action_type_for(category: str) -> str:
    text = category.lower()
    if "iam" in text or "identity" in text:
        return "iam_policy"
    if "cloud" in text:
        return "cloud_control"
    if "network" in text:
        return "network_policy"
    if "kubernetes" in text or "container" in text:
        return "kubernetes_policy"
    if "compliance" in text:
        return "compliance_control"
    return "patch"

