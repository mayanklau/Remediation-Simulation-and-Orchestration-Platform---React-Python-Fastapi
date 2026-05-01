import pytest
from app.services.model_providers import select_provider, deterministic_response
from app.services.risk import score_finding
from app.models import Asset


def test_risk_scoring_accounts_for_exposure():
    asset = Asset(tenant_id="t1", external_id="a1", name="prod", environment="PRODUCTION", criticality=5, data_sensitivity=4, internet_exposure=True)
    risk, business, explanation = score_finding({"severity": "CRITICAL", "exploit_available": True, "active_exploitation": True, "patch_available": False}, asset)
    assert risk >= 90
    assert business >= risk
    assert "exposure=True" in explanation


def test_model_provider_fallback():
    assert select_provider("openai_compatible") in {"deterministic", "openai_compatible"}
    result = deterministic_response("safe", "use virtual patching", 0)
    assert result["used_external_model"] is False
    assert "virtual patching" in result["output"].lower()

