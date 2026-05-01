from app.main import deterministic, fingerprint, risk_score


def test_risk_scoring_accounts_for_exposure():
    asset = {"criticality": 5, "data_sensitivity": 4, "internet_exposure": True}
    risk, business, explanation = risk_score({"severity": "CRITICAL", "exploit_available": True, "active_exploitation": True, "patch_available": False}, asset)
    assert risk >= 90
    assert business >= risk
    assert "exposure=True" in explanation


def test_deterministic_model_fallback_mentions_virtual_patching():
    result = deterministic("use virtual patching", 0)
    assert result["used_external_model"] is False
    assert "virtual patching" in result["output"].lower()


def test_fingerprint_is_stable():
    payload = {"source": "scanner", "title": "Finding", "cve": "CVE-1"}
    assert fingerprint(payload, "asset-1") == fingerprint(payload, "asset-1")
