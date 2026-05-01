import csv
from io import StringIO
from fastapi import APIRouter, Depends, File, UploadFile
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.dependencies import database, tenant_context
from app.models import Tenant
from app.services.ingestion import ingest_findings

router = APIRouter()


@router.post("/ingest/json")
async def ingest_json(payload: dict, tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    findings = payload.get("findings", [])
    return await ingest_findings(db, tenant.id, findings)


@router.post("/ingest/csv")
async def ingest_csv(file: UploadFile = File(...), tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    content = (await file.read()).decode("utf-8")
    rows = list(csv.DictReader(StringIO(content)))
    findings = []
    for row in rows:
        findings.append(
            {
                "source": row.get("source") or "csv",
                "source_id": row.get("source_id") or row.get("sourceId"),
                "title": row.get("title"),
                "description": row.get("description") or "",
                "severity": (row.get("severity") or "MEDIUM").upper(),
                "category": row.get("category") or "vulnerability",
                "cve": row.get("cve") or None,
                "patch_available": str(row.get("patch_available", "")).lower() == "true",
                "exploit_available": str(row.get("exploit_available", "")).lower() == "true",
                "active_exploitation": str(row.get("active_exploitation", "")).lower() == "true",
                "asset": {
                    "external_id": row.get("asset_external_id") or row.get("asset_name"),
                    "name": row.get("asset_name") or row.get("asset_external_id"),
                    "type": row.get("asset_type") or "OTHER",
                    "environment": row.get("environment") or "UNKNOWN",
                    "criticality": int(row.get("criticality") or 3),
                    "data_sensitivity": int(row.get("data_sensitivity") or 3),
                    "internet_exposure": str(row.get("internet_exposure", "")).lower() == "true",
                },
            }
        )
    return await ingest_findings(db, tenant.id, findings, actor="csv")


@router.post("/mock-ingest")
async def mock_ingest(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    findings = [
        {
            "source": "tenable",
            "source_id": "CVE-2026-0001",
            "title": "Internet exposed admin service",
            "severity": "CRITICAL",
            "category": "network_policy",
            "patch_available": False,
            "exploit_available": True,
            "active_exploitation": True,
            "asset": {"external_id": "prod-admin-01", "name": "prod-admin-01", "type": "VM", "environment": "PRODUCTION", "criticality": 5, "data_sensitivity": 4, "internet_exposure": True},
        },
        {
            "source": "wiz",
            "source_id": "IAM-001",
            "title": "Over-privileged production role",
            "severity": "HIGH",
            "category": "iam_policy",
            "patch_available": True,
            "asset": {"external_id": "iam-prod-deploy", "name": "iam-prod-deploy", "type": "IAM_ROLE", "environment": "PRODUCTION", "criticality": 4, "data_sensitivity": 4, "internet_exposure": False},
        },
    ]
    return await ingest_findings(db, tenant.id, findings, actor="mock")

