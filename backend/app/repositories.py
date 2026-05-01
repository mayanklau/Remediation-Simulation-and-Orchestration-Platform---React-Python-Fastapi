from motor.motor_asyncio import AsyncIOMotorDatabase


async def list_findings(db: AsyncIOMotorDatabase, tenant_id: str, status: str | None = None, severity: str | None = None, limit: int = 200):
    query: dict = {"tenant_id": tenant_id}
    if status:
        query["status"] = status
    if severity:
        query["severity"] = severity
    return await db.findings.find(query).sort("business_risk_score", -1).to_list(limit)


async def assert_tenant_document(db: AsyncIOMotorDatabase, collection: str, tenant_id: str, document_id: str) -> None:
    found = await db[collection].find_one({"_id": document_id, "tenant_id": tenant_id}, {"_id": 1})
    if not found:
        raise ValueError(f"{collection} document not found in tenant boundary")
