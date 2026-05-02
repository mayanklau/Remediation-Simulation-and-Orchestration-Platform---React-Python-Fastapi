from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field


def now() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid4().hex


Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Environment = Literal["DEVELOPMENT", "STAGING", "PRODUCTION", "UNKNOWN"]


class MongoModel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)


class Tenant(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    name: str
    slug: str
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)


class Asset(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    tenant_id: str
    external_id: str
    name: str
    type: str = "OTHER"
    environment: Environment = "UNKNOWN"
    provider: str | None = None
    region: str | None = None
    criticality: int = 3
    data_sensitivity: int = 3
    internet_exposure: bool = False
    compliance_scope: str | None = None
    tags: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    team: str | None = None
    owner: str | None = None
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)


class Finding(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    tenant_id: str
    asset_id: str | None = None
    title: str
    description: str = ""
    severity: Severity
    status: str = "OPEN"
    cve: str | None = None
    control_id: str | None = None
    category: str = "vulnerability"
    source: str = "api"
    scanner_severity: str | None = None
    exploit_available: bool = False
    active_exploitation: bool = False
    patch_available: bool = False
    compensating_controls: str | None = None
    risk_score: float = 0
    business_risk_score: float = 0
    risk_explanation: str = ""
    fingerprint: str
    first_seen_at: datetime = Field(default_factory=now)
    last_seen_at: datetime = Field(default_factory=now)
    due_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)


class SourceFinding(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    tenant_id: str
    finding_id: str | None = None
    source: str
    source_id: str
    raw_payload: dict[str, Any]
    confidence: float = 0.7
    ingested_at: datetime = Field(default_factory=now)


class RemediationAction(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    tenant_id: str
    finding_id: str
    title: str
    summary: str
    action_type: str
    proposed_change: dict[str, Any] = Field(default_factory=dict)
    status: str = "NEW"
    owner_hint: str | None = None
    complexity: int = 3
    expected_risk_reduction: float = 0
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)


class Simulation(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    tenant_id: str
    remediation_action_id: str
    type: str
    status: str = "COMPLETED"
    input: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    confidence: float = 0
    risk_reduction_estimate: float = 0
    operational_risk: float = 0
    explanation: str = ""
    created_at: datetime = Field(default_factory=now)


class RemediationPlan(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    tenant_id: str
    remediation_action_id: str
    title: str
    rollout_steps: list[str]
    rollback_steps: list[str]
    validation_steps: list[str]
    evidence_required: list[str]
    created_at: datetime = Field(default_factory=now)


class WorkflowItem(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    tenant_id: str
    remediation_action_id: str
    title: str
    status: str = "PENDING_APPROVAL"
    approvals: list[dict[str, Any]] = Field(default_factory=list)
    comments: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)


class Policy(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    tenant_id: str
    name: str
    policy_type: str
    enabled: bool = True
    rules: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=now)


class ReportSnapshot(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    tenant_id: str
    name: str
    type: str
    data: dict[str, Any]
    created_by: str = "system"
    created_at: datetime = Field(default_factory=now)


class AuditLog(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    tenant_id: str
    actor: str
    action: str
    entity_type: str
    entity_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=now)


class ConnectorRun(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    tenant_id: str
    provider: str
    operation: str
    dry_run: bool = True
    status: str = "COMPLETED"
    endpoint: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=now)


class ConnectorProfile(MongoModel):
    id: str = Field(default_factory=new_id, alias="_id")
    tenant_id: str
    provider: str
    name: str
    category: str = "custom"
    enabled: bool = True
    auth_mode: str = "manual_secret_reference"
    endpoint: str | None = None
    owner: str = "security-operations"
    scopes: list[str] = Field(default_factory=list)
    sync_cadence: str = "manual"
    environment: str = "pilot"
    config: dict[str, Any] = Field(default_factory=dict)
    health: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)
