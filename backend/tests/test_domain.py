from app.main import deterministic, risk_score
from app.services.attack_paths import _decision_readiness, _scanner_coverage


def test_risk_scoring_accounts_for_exposure():
    asset = {"criticality": 5, "data_sensitivity": 4, "internet_exposure": True}
    risk, business, explanation = risk_score({"severity": "CRITICAL", "exploit_available": True, "active_exploitation": True, "patch_available": False}, asset)
    assert risk >= 90
    assert business >= risk
    assert "exposure=True" in explanation


def test_model_provider_fallback():
    result = deterministic("use virtual patching", 0)
    assert result["used_external_model"] is False
    assert "virtual patching" in result["output"].lower()


def test_attack_path_maturity_helpers():
    coverage = _scanner_coverage([
        {
            "source": "tenable",
            "category": "vulnerability",
            "asset_id": "a1",
            "exploit_available": True,
            "active_exploitation": False,
            "patch_available": True,
            "cve": "CVE-2026-0001",
        }
    ])
    vuln = next(item for item in coverage if item["family"] == "vulnerability_scanner")
    assert vuln["ready_for_attack_graph"] is True
    assert vuln["asset_mapping_coverage"] == 100

    readiness = _decision_readiness([
        {
            "priority": "immediate",
            "risk_delta": 40,
            "after_remediation_risk": 30,
            "before_remediation_risk": 70,
            "difficulty_score": 55,
            "likelihood": 72,
            "business_impact": 88,
        }
    ])
    assert readiness["recommended_decision"] == "escalate_now"
