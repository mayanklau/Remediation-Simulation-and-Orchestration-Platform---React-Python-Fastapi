from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def emit_operational_signal(
    db: AsyncIOMotorDatabase,
    tenant_id: str,
    *,
    level: str,
    event: str,
    entity_type: str,
    entity_id: str,
    correlation_id: str,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = {
        "tenant_id": tenant_id,
        "actor": "observability",
        "action": event,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "details": {
            "level": level,
            "correlation_id": correlation_id,
            "attributes": attributes or {},
        },
        "created_at": now_iso(),
    }
    await db.audit_logs.insert_one(record)
    return {"recorded": True, "correlation_id": correlation_id, "level": level}
