import pytest
from app.auth import Principal, can, require_permission
from app.config import Settings
from app.workers import QueueJob, plan_for_lane
from app.services.cyber_risk_intelligence import build_cyber_risk_intelligence_model
from app.services.enterprise_readiness import build_enterprise_readiness_catalog
from app.services.application_logic_readiness import build_application_logic_readiness_model, can_transition
from app.services.go_live import build_go_live_model
from app.services.production_effectiveness import build_production_effectiveness_model
from app.services.production_expansion import build_production_expansion_model
from app.services.production_reality import build_production_reality_model


def test_production_config_requires_oidc_and_session_secret():
    settings = Settings(environment="production")
    with pytest.raises(ValueError):
        settings.validate_runtime()


def test_rbac_enforces_permissions():
    principal = Principal(email="a@example.com", role="auditor", groups=(), correlation_id="c1")
    assert can(principal.role, "audit:read")
    with pytest.raises(Exception):
        require_permission(principal, "policy:write")


def test_queue_worker_contracts_are_correlated():
    job = QueueJob(tenant_id="tenant-test", lane="simulation", payload={"action_id": "a1"}, priority="high")
    assert job.correlation_id
    assert "compute blast radius" in plan_for_lane(job.lane)
from app.auth import can, route_permission_for


def test_route_permission_contract_covers_enterprise_surfaces():
    assert route_permission_for("/api/findings", "GET") == "finding:read"
    assert route_permission_for("/api/remediation-actions/action-1/simulate", "POST") == "simulation:run"
    assert route_permission_for("/api/attack-paths", "POST") == "report:read"
    assert route_permission_for("/api/cyber-risk-intelligence", "GET") == "report:read"
    assert route_permission_for("/api/connectors", "GET") == "connector:read"
    assert route_permission_for("/api/connectors", "POST") == "connector:run"
    assert route_permission_for("/api/connectors/live", "POST") == "connector:run"
    assert route_permission_for("/api/integrations", "GET") == "connector:read"
    assert route_permission_for("/api/integrations", "POST") == "connector:run"
    assert route_permission_for("/api/enterprise-readiness", "GET") == "report:read"
    assert route_permission_for("/api/application-logic-readiness", "GET") == "report:read"
    assert route_permission_for("/api/production-expansion", "GET") == "report:read"
    assert route_permission_for("/api/production-effectiveness", "GET") == "report:read"
    assert route_permission_for("/api/production-reality", "GET") == "report:read"
    assert route_permission_for("/api/go-live", "GET") == "report:read"
    assert route_permission_for("/api/audit", "GET") == "audit:read"


def test_enterprise_readiness_catalog_covers_final_bar():
    catalog = build_enterprise_readiness_catalog()
    assert catalog["summary"]["categories"] >= 17
    assert catalog["summary"]["controls"] >= 60
    assert "dry-run by default" in catalog["summary"]["final_bar"]


def test_production_expansion_covers_new_product_modules():
    expansion = build_production_expansion_model()
    assert expansion["summary"]["modules"] >= 15
    assert "connector_marketplace" in [item["id"] for item in expansion["modules"]]
    assert "data_residency" in [item["id"] for item in expansion["modules"]]


def test_go_live_model_captures_launch_and_rollback():
    model = build_go_live_model()
    assert model["summary"]["sections"] >= 10
    assert "Deploy API, web, and workers" in model["launch_sequence"]
    assert "Rollback API and web images" in model["rollback_sequence"]


def test_production_effectiveness_covers_validation_and_dead_letters():
    model = build_production_effectiveness_model()
    assert model["summary"]["scheduler_lanes"] >= 8
    assert model["summary"]["data_quality_controls"] >= 8
    assert "after_scan" in [item["id"] for item in model["validation_loop"]]
    assert "dead_letters" in [item["id"] for item in model["observability_signals"]]


def test_production_reality_covers_below_waterline_controls():
    model = build_production_reality_model()
    assert model["summary"]["layers"] >= 6
    assert model["summary"]["controls"] >= 20
    assert "Load balancer health and timeout policy" in model["launch_blockers"]
    assert "dead_letters" in [control["id"] for layer in model["layers"] for control in layer["controls"]]


def test_cyber_risk_intelligence_covers_subject_matter_features():
    model = build_cyber_risk_intelligence_model()
    ids = [item["id"] for item in model["capabilities"]]
    assert "exploit_intel_fusion" in ids
    assert "control_effectiveness" in ids
    assert "exception_governance" in ids
    assert "risk_reduced_per_hour" in [item["id"] for item in model["economics"]]
    assert "ransomware_path" in [item["id"] for item in model["scenario_packs"]]
    assert "toxic_combinations" in [item["id"] for item in model["governance_matrix"]]
    assert "regulatory_mapping" in [item["id"] for item in model["governance_matrix"]]
    assert "identity_cloud_data_risk" in [item["id"] for item in model["governance_matrix"]]
    assert model["summary"]["certification_tracks"] >= 6
    assert model["summary"]["mitre_mapped_hops"] >= 6
    assert model["summary"]["control_validation_methods"] >= 7
    assert "tenable" in [item["id"] for item in model["subject_matter_maturity_pack"]["scanner_certification"]]
    assert "proven" in [item["label"] for item in model["subject_matter_maturity_pack"]["exploitability_confidence_model"]]
    assert len(model["subject_matter_maturity_pack"]["pilot_acceptance_pack"]) >= 5


def test_application_logic_readiness_defines_enforced_lifecycles():
    model = build_application_logic_readiness_model()
    assert model["summary"]["lifecycles"] >= 6
    assert model["summary"]["transitions"] >= 35
    assert model["summary"]["verdict"] == "app_logic_ready_with_external_infra_gates"
    assert "remediation_action" in [item["id"] for item in model["lifecycles"]]
    assert not can_transition("remediation_action", "PLANNED", "PENDING_APPROVAL", ["rollout_steps"])["allowed"]
    assert can_transition("remediation_action", "PLANNED", "PENDING_APPROVAL", ["rollout_steps", "validation_steps", "evidence_required"])["allowed"]


def test_rbac_keeps_auditors_read_only():
    assert can("auditor", route_permission_for("/api/reports", "GET"))
    assert not can("auditor", route_permission_for("/api/policies", "POST"))
    assert can("tenant_admin", route_permission_for("/api/policies", "POST"))
