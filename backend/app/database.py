from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING
from app.config import get_settings


class Mongo:
    client: AsyncIOMotorClient | None = None
    db: AsyncIOMotorDatabase | None = None


mongo = Mongo()


async def connect_mongo() -> None:
    settings = get_settings()
    mongo.client = AsyncIOMotorClient(settings.mongo_uri, uuidRepresentation="standard")
    mongo.db = mongo.client[settings.mongo_db]
    await ensure_indexes(mongo.db)


async def close_mongo() -> None:
    if mongo.client:
        mongo.client.close()
    mongo.client = None
    mongo.db = None


def get_db() -> AsyncIOMotorDatabase:
    if mongo.db is None:
        raise RuntimeError("MongoDB is not connected")
    return mongo.db


@asynccontextmanager
async def lifespan(_: Any) -> AsyncIterator[None]:
    await connect_mongo()
    try:
        yield
    finally:
        await close_mongo()


async def ensure_indexes(db: AsyncIOMotorDatabase) -> None:
    await db.tenants.create_index([("slug", ASCENDING)], unique=True)
    await db.assets.create_index([("tenant_id", ASCENDING), ("external_id", ASCENDING)], unique=True)
    await db.assets.create_index([("tenant_id", ASCENDING), ("environment", ASCENDING)])
    await db.findings.create_index([("tenant_id", ASCENDING), ("fingerprint", ASCENDING)], unique=True)
    await db.findings.create_index([("tenant_id", ASCENDING), ("business_risk_score", DESCENDING)])
    await db.source_findings.create_index([("tenant_id", ASCENDING), ("source", ASCENDING), ("source_id", ASCENDING)], unique=True)
    await db.remediation_actions.create_index([("tenant_id", ASCENDING), ("status", ASCENDING)])
    await db.simulations.create_index([("tenant_id", ASCENDING), ("created_at", DESCENDING)])
    await db.workflow_items.create_index([("tenant_id", ASCENDING), ("status", ASCENDING)])
    await db.audit_logs.create_index([("tenant_id", ASCENDING), ("created_at", DESCENDING)])
    await db.report_snapshots.create_index([("tenant_id", ASCENDING), ("created_at", DESCENDING)])
    await db.connector_runs.create_index([("tenant_id", ASCENDING), ("created_at", DESCENDING)])
    await db.connector_profiles.create_index([("tenant_id", ASCENDING), ("provider", ASCENDING)], unique=True)
    await db.policies.create_index([("tenant_id", ASCENDING), ("policy_type", ASCENDING)])
