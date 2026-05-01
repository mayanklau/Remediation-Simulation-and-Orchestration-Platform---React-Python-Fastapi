from datetime import datetime, timezone
from uuid import uuid4
from pydantic import BaseModel, Field


class QueueJob(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    tenant_id: str
    lane: str
    payload: dict = Field(default_factory=dict)
    priority: str = "normal"
    correlation_id: str = Field(default_factory=lambda: uuid4().hex)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


WORKER_PLANS = {
    "ingestion": ["validate connector payload", "normalize source findings", "deduplicate", "upsert assets", "emit audit event"],
    "simulation": ["load action context", "compute blast radius", "model rollback", "score confidence", "persist result"],
    "connector_sync": ["resolve secret reference", "call connector in dry-run unless approved", "record connector run", "emit telemetry"],
    "evidence_generation": ["collect before state", "attach simulation", "attach approvals", "hash seal pack"],
    "report_snapshot": ["recompute metrics", "freeze analytics", "store snapshot", "route executive export"],
}


def plan_for_lane(lane: str) -> list[str]:
    return WORKER_PLANS.get(lane, ["reject unknown worker lane"])
