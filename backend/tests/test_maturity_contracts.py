import pytest
from app.auth import Principal, can, require_permission
from app.config import Settings
from app.workers import QueueJob, plan_for_lane
from app.services.enterprise_readiness import build_enterprise_readiness_catalog


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
    assert route_permission_for("/api/connectors", "GET") == "connector:read"
    assert route_permission_for("/api/connectors", "POST") == "connector:run"
    assert route_permission_for("/api/connectors/live", "POST") == "connector:run"
    assert route_permission_for("/api/integrations", "GET") == "connector:read"
    assert route_permission_for("/api/integrations", "POST") == "connector:run"
    assert route_permission_for("/api/enterprise-readiness", "GET") == "report:read"
    assert route_permission_for("/api/audit", "GET") == "audit:read"


def test_enterprise_readiness_catalog_covers_final_bar():
    catalog = build_enterprise_readiness_catalog()
    assert catalog["summary"]["categories"] >= 17
    assert catalog["summary"]["controls"] >= 60
    assert "dry-run by default" in catalog["summary"]["final_bar"]


def test_rbac_keeps_auditors_read_only():
    assert can("auditor", route_permission_for("/api/reports", "GET"))
    assert not can("auditor", route_permission_for("/api/policies", "POST"))
    assert can("tenant_admin", route_permission_for("/api/policies", "POST"))
