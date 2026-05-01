from hashlib import sha256
from typing import Any
from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo.errors import DuplicateKeyError
from app.models import Asset, Finding, RemediationAction, SourceFinding, now
from app.services.risk import action_type_for, due_date_for, score_finding
from app.services.tenant import touch_audit


def fingerprint(payload: dict[str, Any], asset_external_id: str | None) -> str:
    raw = "|".join(
        [
            str(payload.get("source", "api")).lower(),
            str(payload.get("title", "")).strip().lower(),
            str(payload.get("cve") or payload.get("control_id") or ""),
            str(asset_external_id or payload.get("asset_name") or "unmapped").lower(),
        ]
    )
    return sha256(raw.encode("utf-8")).hexdigest()


async def ingest_findings(db: AsyncIOMotorDatabase, tenant_id: str, findings: list[dict[str, Any]], actor: str = "api") -> dict[str, Any]:
    created = 0
    updated = 0
    actions_created = 0
    for payload in findings:
        asset = await upsert_asset(db, tenant_id, payload.get("asset") or payload)
        fp = fingerprint(payload, asset.external_id if asset else None)
        risk, business, explanation = score_finding(payload, asset)
        severity = str(payload.get("severity", "MEDIUM")).upper()
        document = Finding(
            tenant_id=tenant_id,
            asset_id=asset.id if asset else None,
            title=str(payload.get("title", "Untitled finding")),
            description=str(payload.get("description", "")),
            severity=severity,
            cve=payload.get("cve"),
            control_id=payload.get("control_id"),
            category=str(payload.get("category", "vulnerability")),
            source=str(payload.get("source", "api")),
            scanner_severity=payload.get("scanner_severity"),
            exploit_available=bool(payload.get("exploit_available", False)),
            active_exploitation=bool(payload.get("active_exploitation", False)),
            patch_available=bool(payload.get("patch_available", False)),
            compensating_controls=payload.get("compensating_controls"),
            risk_score=risk,
            business_risk_score=business,
            risk_explanation=explanation,
            fingerprint=fp,
            due_at=due_date_for(severity),
            metadata=payload.get("metadata") or {},
        )
        existing = await db.findings.find_one({"tenant_id": tenant_id, "fingerprint": fp})
        if existing:
            updated += 1
            await db.findings.update_one(
                {"_id": existing["_id"]},
                {"$set": {**document.model_dump(by_alias=True), "_id": existing["_id"], "first_seen_at": existing.get("first_seen_at", now()), "updated_at": now()}},
            )
            finding_id = existing["_id"]
        else:
            created += 1
            await db.findings.insert_one(document.model_dump(by_alias=True))
            finding_id = document.id
            action = build_action(tenant_id, finding_id, document, asset)
            await db.remediation_actions.insert_one(action.model_dump(by_alias=True))
            actions_created += 1
        await upsert_source_finding(db, tenant_id, finding_id, payload)
    await touch_audit(db, tenant_id, actor, "findings_ingested", "finding", details={"created": created, "updated": updated, "actions_created": actions_created})
    return {"created": created, "updated": updated, "actions_created": actions_created}


async def upsert_asset(db: AsyncIOMotorDatabase, tenant_id: str, payload: dict[str, Any]) -> Asset | None:
    external_id = payload.get("external_id") or payload.get("asset_external_id")
    name = payload.get("name") or payload.get("asset_name")
    if not external_id and not name:
        return None
    external_id = str(external_id or name)
    asset = Asset(
        tenant_id=tenant_id,
        external_id=external_id,
        name=str(name or external_id),
        type=str(payload.get("type") or payload.get("asset_type") or "OTHER"),
        environment=str(payload.get("environment") or "UNKNOWN").upper(),
        provider=payload.get("provider"),
        region=payload.get("region"),
        criticality=int(payload.get("criticality", 3)),
        data_sensitivity=int(payload.get("data_sensitivity", 3)),
        internet_exposure=bool(payload.get("internet_exposure", False)),
        compliance_scope=payload.get("compliance_scope"),
        tags=payload.get("tags") or {},
        metadata=payload.get("metadata") or {},
        owner=payload.get("owner"),
    )
    existing = await db.assets.find_one({"tenant_id": tenant_id, "external_id": external_id})
    if existing:
        await db.assets.update_one({"_id": existing["_id"]}, {"$set": {**asset.model_dump(by_alias=True), "_id": existing["_id"], "updated_at": now()}})
        asset.id = existing["_id"]
    else:
        try:
            await db.assets.insert_one(asset.model_dump(by_alias=True))
        except DuplicateKeyError:
            existing = await db.assets.find_one({"tenant_id": tenant_id, "external_id": external_id})
            asset.id = existing["_id"]
    return asset


async def upsert_source_finding(db: AsyncIOMotorDatabase, tenant_id: str, finding_id: str, payload: dict[str, Any]) -> None:
    source = str(payload.get("source", "api"))
    source_id = str(payload.get("source_id") or payload.get("sourceId") or fingerprint(payload, payload.get("asset_external_id")))
    doc = SourceFinding(tenant_id=tenant_id, finding_id=finding_id, source=source, source_id=source_id, raw_payload=payload)
    await db.source_findings.update_one(
        {"tenant_id": tenant_id, "source": source, "source_id": source_id},
        {"$set": doc.model_dump(by_alias=True)},
        upsert=True,
    )


def build_action(tenant_id: str, finding_id: str, finding: Finding, asset: Asset | None) -> RemediationAction:
    action_type = action_type_for(finding.category)
    verb = {
        "iam_policy": "Restrict IAM access",
        "cloud_control": "Harden cloud control",
        "network_policy": "Update network policy",
        "kubernetes_policy": "Apply Kubernetes guardrail",
        "compliance_control": "Restore compliance control",
        "patch": "Patch affected system",
    }.get(action_type, "Remediate finding")
    return RemediationAction(
        tenant_id=tenant_id,
        finding_id=finding_id,
        title=f"{verb}: {finding.title}",
        summary=f"Reduce {finding.severity} risk on {asset.name if asset else 'unmapped asset'} with governed rollout.",
        action_type=action_type,
        proposed_change={"asset": asset.name if asset else None, "category": finding.category, "patch_available": finding.patch_available},
        complexity=4 if finding.severity == "CRITICAL" else 3,
        expected_risk_reduction=min(95, finding.business_risk_score * 0.72),
    )

