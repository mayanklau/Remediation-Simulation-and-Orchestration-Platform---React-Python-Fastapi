import pytest
from app.auth import Principal, can, require_permission
from app.config import Settings
from app.workers import QueueJob, plan_for_lane


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
