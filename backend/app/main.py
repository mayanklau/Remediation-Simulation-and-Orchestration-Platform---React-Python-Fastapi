from __future__ import annotations

import hashlib
import os
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware


def now() -> datetime:
    return datetime.now(timezone.utc)


def oid() -> str:
    return uuid4().hex


class Settings(BaseModel):
    mongo_uri: str = Field(default_factory=lambda: os.getenv("MONGO_URI", "mongodb://localhost:27017"))
    mongo_db: str = Field(default_factory=lambda: os.getenv("MONGO_DB", "remediation_twin"))
    default_tenant_slug: str = Field(default_factory=lambda: os.getenv("DEFAULT_TENANT_SLUG", "default"))
    rate_limit_per_minute: int = Field(default_factory=lambda: int(os.getenv("RATE_LIMIT_PER_MINUTE", "120")))
    llm_base_url: str = Field(default_factory=lambda: os.getenv("LLM_BASE_URL", ""))
    llm_api_key: str = Field(default_factory=lambda: os.getenv("LLM_API_KEY", ""))
    llm_model: str = Field(default_factory=lambda: os.getenv("LLM_MODEL", ""))
    local_slm_url: str = Field(default_factory=lambda: os.getenv("LOCAL_SLM_URL", ""))
    local_slm_model: str = Field(default_factory=lambda: os.getenv("LOCAL_SLM_MODEL", ""))


settings = Settings()
client: AsyncIOMotorClient | None = None


async def db() -> AsyncIOMotorDatabase:
    if client is None:
        raise RuntimeError("Mongo is not connected")
    return client[settings.mongo_db]


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["x-content-type-options"] = "nosniff"
        response.headers["x-frame-options"] = "DENY"
        response.headers["referrer-policy"] = "strict-origin-when-cross-origin"
        response.headers["permissions-policy"] = "camera=(), microphone=(), geolocation=()"
        return response


class RateLimit(BaseHTTPMiddleware):
    buckets: dict[str, list[float]] = {}

    async def dispatch(self, request: Request, call_next):
        key = request.client.host if request.client else "unknown"
        current = time.time()
        window = [stamp for stamp in self.buckets.get(key, []) if current - stamp < 60]
        if len(window) >= settings.rate_limit_per_minute:
            return Response("rate limit exceeded", status_code=429)
        window.append(current)
        self.buckets[key] = window
        response = await call_next(request)
        response.headers["x-ratelimit-limit"] = str(settings.rate_limit_per_minute)
        response.headers["x-ratelimit-remaining"] = str(max(0, settings.rate_limit_per_minute - len(window)))
        return response


app = FastAPI(title="Remediation Twin API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.add_middleware(SecurityHeaders)
app.add_middleware(RateLimit)


@app.on_event("startup")
async def startup() -> None:
    global client
    client = AsyncIOMotorClient(settings.mongo_uri, uuidRepresentation="standard")
    database = client[settings.mongo_db]
    await database.tenants.create_index("slug", unique=True)
    await database.assets.create_index([("tenant_id", 1), ("external_id", 1)], unique=True)
    await database.findings.create_index([("tenant_id", 1), ("fingerprint", 1)], unique=True)
    await database.findings.create_index([("tenant_id", 1), ("business_risk_score", -1)])
    await database.remediation_actions.create_index([("tenant_id", 1), ("status", 1)])
    await database.audit.create_index([("tenant_id", 1), ("created_at", -1)])


@app.on_event("shutdown")
async def shutdown() -> None:
    if client:
        client.close()


async def tenant(x_tenant_id: str | None = Header(default=None), database: AsyncIOMotorDatabase = Depends(db)) -> dict:
    if x_tenant_id:
        found = await database.tenants.find_one({"$or": [{"_id": x_tenant_id}, {"slug": x_tenant_id}]})
        if found:
            return found
    found = await database.tenants.find_one({"slug": settings.default_tenant_slug})
    if found:
        return found
    doc = {"_id": oid(), "name": "Default", "slug": settings.default_tenant_slug, "created_at": now(), "updated_at": now()}
    await database.tenants.insert_one(doc)
    return doc


async def audit(database: AsyncIOMotorDatabase, tenant_id: str, actor: str, action: str, entity_type: str, entity_id: str | None = None, details: dict | None = None) -> None:
    await database.audit.insert_one({"_id": oid(), "tenant_id": tenant_id, "actor": actor, "action": action, "entity_type": entity_type, "entity_id": entity_id, "details": details or {}, "created_at": now()})


def risk_score(payload: dict, asset: dict | None) -> tuple[float, float, str]:
    base = {"LOW": 20, "MEDIUM": 40, "HIGH": 70, "CRITICAL": 90}.get(str(payload.get("severity", "MEDIUM")).upper(), 40)
    risk = min(100, base + (12 if payload.get("exploit_available") else 0) + (18 if payload.get("active_exploitation") else 0) + (8 if not payload.get("patch_available", False) else 0))
    business = min(100, risk + (12 if asset and asset.get("internet_exposure") else 0) + ((asset or {}).get("criticality", 3) - 3) * 5 + ((asset or {}).get("data_sensitivity", 3) - 3) * 4)
    return float(risk), float(business), f"severity={payload.get('severity')} exposure={bool(asset and asset.get('internet_exposure'))}"


def fingerprint(payload: dict, asset_external_id: str | None) -> str:
    raw = "|".join([str(payload.get("source", "api")).lower(), str(payload.get("title", "")).lower(), str(payload.get("cve") or payload.get("control_id") or ""), str(asset_external_id or "unmapped")])
    return hashlib.sha256(raw.encode()).hexdigest()


def action_type(category: str) -> str:
    text = category.lower()
    if "iam" in text:
        return "iam_policy"
    if "cloud" in text:
        return "cloud_control"
    if "network" in text:
        return "network_policy"
    if "kubernetes" in text or "container" in text:
        return "kubernetes_policy"
    return "patch"


async def upsert_asset(database: AsyncIOMotorDatabase, tenant_id: str, payload: dict) -> dict | None:
    external_id = payload.get("external_id") or payload.get("asset_external_id") or payload.get("name") or payload.get("asset_name")
    if not external_id:
        return None
    doc = {"_id": oid(), "tenant_id": tenant_id, "external_id": str(external_id), "name": str(payload.get("name") or payload.get("asset_name") or external_id), "type": payload.get("type") or payload.get("asset_type") or "OTHER", "environment": str(payload.get("environment") or "UNKNOWN").upper(), "criticality": int(payload.get("criticality", 3)), "data_sensitivity": int(payload.get("data_sensitivity", 3)), "internet_exposure": bool(payload.get("internet_exposure", False)), "metadata": payload.get("metadata", {}), "created_at": now(), "updated_at": now()}
    existing = await database.assets.find_one({"tenant_id": tenant_id, "external_id": doc["external_id"]})
    if existing:
        doc["_id"] = existing["_id"]
        doc["created_at"] = existing.get("created_at", now())
        await database.assets.update_one({"_id": existing["_id"]}, {"$set": doc})
    else:
        await database.assets.insert_one(doc)
    return doc


async def ingest(database: AsyncIOMotorDatabase, tenant_id: str, findings: list[dict], actor: str = "api") -> dict:
    created = updated = actions_created = 0
    for payload in findings:
        asset = await upsert_asset(database, tenant_id, payload.get("asset") or payload)
        fp = fingerprint(payload, asset["external_id"] if asset else None)
        risk, business, explanation = risk_score(payload, asset)
        severity = str(payload.get("severity", "MEDIUM")).upper()
        finding = {"_id": oid(), "tenant_id": tenant_id, "asset_id": asset["_id"] if asset else None, "title": payload.get("title", "Untitled finding"), "description": payload.get("description", ""), "severity": severity, "status": "OPEN", "category": payload.get("category", "vulnerability"), "source": payload.get("source", "api"), "cve": payload.get("cve"), "patch_available": bool(payload.get("patch_available", False)), "exploit_available": bool(payload.get("exploit_available", False)), "active_exploitation": bool(payload.get("active_exploitation", False)), "risk_score": risk, "business_risk_score": business, "risk_explanation": explanation, "fingerprint": fp, "due_at": now() + timedelta(days={"CRITICAL": 7, "HIGH": 14, "MEDIUM": 30, "LOW": 90}.get(severity, 30)), "created_at": now(), "updated_at": now()}
        existing = await database.findings.find_one({"tenant_id": tenant_id, "fingerprint": fp})
        if existing:
            updated += 1
            finding["_id"] = existing["_id"]
            finding["created_at"] = existing.get("created_at", now())
            await database.findings.update_one({"_id": existing["_id"]}, {"$set": finding})
            finding_id = existing["_id"]
        else:
            created += 1
            await database.findings.insert_one(finding)
            finding_id = finding["_id"]
            action = {"_id": oid(), "tenant_id": tenant_id, "finding_id": finding_id, "title": f"Remediate: {finding['title']}", "summary": f"Reduce {severity} risk with governed rollout.", "action_type": action_type(finding["category"]), "proposed_change": {"asset": asset["name"] if asset else None}, "status": "NEW", "complexity": 4 if severity == "CRITICAL" else 3, "expected_risk_reduction": min(95, business * 0.72), "created_at": now(), "updated_at": now()}
            await database.remediation_actions.insert_one(action)
            actions_created += 1
    await audit(database, tenant_id, actor, "findings_ingested", "finding", details={"created": created, "updated": updated, "actions_created": actions_created})
    return {"created": created, "updated": updated, "actions_created": actions_created}


def provider_status() -> list[dict]:
    return [{"provider": "deterministic", "configured": True, "model": "rules-engine"}, {"provider": "openai_compatible", "configured": bool(settings.llm_base_url and settings.llm_api_key), "model": settings.llm_model or "configured-model"}, {"provider": "local_slm", "configured": bool(settings.local_slm_url), "model": settings.local_slm_model or "local-small-language-model"}]


def deterministic(prompt: str, started: float, reason: str | None = None) -> dict:
    focus = "Prioritize virtual patching and attack-path interruption before permanent change." if "virtual" in prompt.lower() or "path" in prompt.lower() else "Prioritize risk reduction with approval and evidence gates."
    output = focus + "\n1. Gather tenant risk context.\n2. Run simulation before execution.\n3. Generate rollback, validation, and evidence requirements.\n4. Route approvals.\n5. Keep execution dry-run until credentials and policy approvals are verified."
    if reason:
        output += f"\n\nModel gateway fallback reason: {reason}"
    return {"provider": "deterministic", "model": "rules-engine", "output": output, "used_external_model": False, "latency_ms": int((time.time() - started) * 1000)}


async def complete_with_model(system: str, prompt: str, preferred: str | None = None) -> dict:
    started = time.time()
    provider = preferred if preferred in {"openai_compatible", "local_slm"} else "deterministic"
    if provider == "openai_compatible" and settings.llm_base_url and settings.llm_api_key:
        try:
            async with httpx.AsyncClient(timeout=30) as http:
                response = await http.post(f"{settings.llm_base_url.rstrip('/')}/chat/completions", headers={"authorization": f"Bearer {settings.llm_api_key}"}, json={"model": settings.llm_model, "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}], "temperature": 0.1})
                response.raise_for_status()
                data = response.json()
                return {"provider": provider, "model": settings.llm_model, "output": data.get("choices", [{}])[0].get("message", {}).get("content", ""), "used_external_model": True, "latency_ms": int((time.time() - started) * 1000)}
        except Exception as exc:
            return deterministic(prompt, started, str(exc))
    return deterministic(prompt, started)


def technique(category: str) -> str:
    text = category.lower()
    if "iam" in text: return "Valid Accounts / Permission Groups Discovery"
    if "network" in text: return "External Remote Services / Network Service Discovery"
    if "cloud" in text: return "Cloud Service Dashboard / Account Discovery"
    if "container" in text or "kubernetes" in text: return "Container and Resource Discovery"
    if "application" in text: return "Exploit Public-Facing Application"
    return "Exploit Vulnerability"


def clamp(value: float, low: int = 1, high: int = 100) -> int:
    return max(low, min(high, round(value)))


def band(score: int) -> str:
    return "VERY_HIGH" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 35 else "LOW"


def chain_step(f: dict) -> dict:
    meta = f.get("metadata", {}) or {}
    return {"finding_id": f.get("_id"), "asset_id": f.get("asset_id"), "title": f.get("title"), "source": f.get("source", "api"), "category": f.get("category", "vulnerability"), "severity": f.get("severity", "MEDIUM"), "technique": meta.get("attack_technique") or technique(f.get("category", "vulnerability")), "business_risk": round(f.get("business_risk_score", 0)), "exploit_available": bool(f.get("exploit_available")), "active_exploitation": bool(f.get("active_exploitation")), "patch_available": bool(f.get("patch_available"))}


def score_path(chain: list[dict], hops: int, target: dict, exposed: bool, policies: int, sim_avg: float) -> dict:
    avg = sum(s["business_risk"] for s in chain) / max(1, len(chain))
    before = clamp(avg * 0.55 + 7 * sum(s["exploit_available"] for s in chain) + 10 * sum(s["active_exploitation"] for s in chain) + target.get("criticality", 3) * 8 + target.get("data_sensitivity", 3) * 6 + max(0, 18 - hops * 3))
    reduction = clamp(12 + 8 * sum(s["patch_available"] for s in chain) + 6 * sum((not s["patch_available"]) or "network" in s["category"].lower() or "iam" in s["category"].lower() for s in chain) + min(18, sim_avg * 0.15) + min(12, policies * 2), 5, 85)
    after = max(0, before - reduction)
    difficulty = clamp(55 + hops * 12 - 8 * sum(s["exploit_available"] or s["active_exploitation"] for s in chain) - 4 * sum(not s["patch_available"] for s in chain) + (-14 if exposed else 8))
    return {"before_remediation_risk": before, "after_remediation_risk": after, "risk_delta": before - after, "difficulty_score": difficulty, "difficulty": band(difficulty), "likelihood": clamp(100 - difficulty), "business_impact": clamp(target.get("criticality", 3) * 12 + target.get("data_sensitivity", 3) * 10 + before * 0.35)}


async def attack_path_model(database: AsyncIOMotorDatabase, tenant_id: str) -> dict:
    assets = await database.assets.find({"tenant_id": tenant_id}).to_list(300)
    findings = await database.findings.find({"tenant_id": tenant_id, "status": "OPEN"}).sort("business_risk_score", -1).to_list(500)
    simulations = await database.simulations.find({"tenant_id": tenant_id}).to_list(300)
    policies = await database.policies.count_documents({"tenant_id": tenant_id, "enabled": True})
    by_asset: dict[str, list[dict]] = {}
    for f in findings:
        if f.get("asset_id"):
            by_asset.setdefault(f["asset_id"], []).append(f)
    starts = [a for a in assets if a.get("internet_exposure") or any(f.get("source", "").lower() in ["tenable", "qualys", "wiz", "snyk", "securityhub"] for f in by_asset.get(a["_id"], []))]
    targets = [a for a in assets if a.get("environment") == "PRODUCTION" or a.get("criticality", 3) >= 4 or a.get("data_sensitivity", 3) >= 4]
    sim_avg = sum(s.get("risk_reduction_estimate", 0) for s in simulations) / max(1, len(simulations))
    paths = []
    for start in starts[:25]:
        for target in targets[:25]:
            if start["_id"] == target["_id"]:
                continue
            chain = [chain_step(f) for f in (by_asset.get(start["_id"], [])[:2] + by_asset.get(target["_id"], [])[:2])]
            if not chain:
                continue
            scores = score_path(chain, 2, target, bool(start.get("internet_exposure")), policies, sim_avg)
            breakers = {"Simulation-backed before/after risk validation"}
            if start.get("internet_exposure"): breakers.add("WAF/API gateway virtual patch at entry point")
            if any("iam" in s["category"].lower() for s in chain): breakers.add("Conditional IAM deny with just-in-time approval")
            if any("network" in s["category"].lower() for s in chain): breakers.add("Microsegmentation deny between path hops")
            paths.append({"id": f"{start['_id']}-{target['_id']}", "name": f"{start['name']} to {target['name']}", "entry_asset": start["name"], "target_asset": target["name"], "hops": [start["name"], target["name"]], "chain": chain, "scanner_inputs": sorted({s["source"] for s in chain}), "recommended_breakers": sorted(breakers), "priority": "immediate" if scores["before_remediation_risk"] >= 85 or scores["risk_delta"] >= 45 else "high" if scores["before_remediation_risk"] >= 70 else "scheduled" if scores["before_remediation_risk"] >= 45 else "monitor", **scores})
    paths = sorted(paths, key=lambda p: p["before_remediation_risk"], reverse=True)[:25]
    avg = lambda values: round(sum(values) / len(values)) if values else 0
    return {"generated_by": "scanner-normalized-attack-path-engine", "construction_method": {"method": "Logical attack graph with bounded path enumeration", "inputs": ["scanner findings", "asset inventory", "exposure", "exploit availability", "active exploitation", "patch availability", "production and crown-jewel context", "simulation and policy controls"], "research_basis": ["MulVAL-style logical vulnerability analysis", "topological attack graph reachability", "exploit-dependency path construction", "Bayesian attack graph before/after risk intuition"]}, "summary": {"attack_paths": len(paths), "critical_paths": len([p for p in paths if p["before_remediation_risk"] >= 80]), "average_before_risk": avg([p["before_remediation_risk"] for p in paths]), "average_after_risk": avg([p["after_remediation_risk"] for p in paths]), "average_risk_reduction": avg([p["risk_delta"] for p in paths]), "scanner_inputs": sorted({s for p in paths for s in p["scanner_inputs"]})}, "paths": paths}


@app.get("/")
async def root():
    return {"service": "Remediation Twin API", "docs": "/docs"}


@app.get("/api/health")
async def health(database: AsyncIOMotorDatabase = Depends(db)):
    await database.command("ping")
    return {"status": "ok"}


@app.post("/api/mock-ingest")
async def mock_ingest(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    findings = [{"source": "tenable", "title": "Internet exposed admin service", "severity": "CRITICAL", "category": "network_policy", "patch_available": False, "exploit_available": True, "active_exploitation": True, "asset": {"external_id": "prod-admin-01", "name": "prod-admin-01", "type": "VM", "environment": "PRODUCTION", "criticality": 5, "data_sensitivity": 4, "internet_exposure": True}}, {"source": "wiz", "title": "Over-privileged production role", "severity": "HIGH", "category": "iam_policy", "patch_available": True, "asset": {"external_id": "iam-prod-deploy", "name": "iam-prod-deploy", "type": "IAM_ROLE", "environment": "PRODUCTION", "criticality": 4, "data_sensitivity": 4}}]
    return await ingest(database, t["_id"], findings, "mock")


@app.post("/api/ingest/json")
async def ingest_json(payload: dict, t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    return await ingest(database, t["_id"], payload.get("findings", []))


@app.get("/api/dashboard")
async def dashboard(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    findings = await database.findings.find({"tenant_id": t["_id"]}).to_list(500)
    actions = await database.remediation_actions.find({"tenant_id": t["_id"]}).to_list(500)
    simulations = await database.simulations.find({"tenant_id": t["_id"]}).to_list(500)
    open_findings = [f for f in findings if f.get("status") == "OPEN"]
    return {"counts": {"findings": len(findings), "open_findings": len(open_findings), "assets": await database.assets.count_documents({"tenant_id": t["_id"]}), "remediation_actions": len(actions), "simulations": len(simulations)}, "risk": {"total_business_risk": round(sum(f.get("business_risk_score", 0) for f in open_findings), 2), "simulation_coverage": round((len({s.get("remediation_action_id") for s in simulations}) / len(actions)) * 100, 2) if actions else 0}, "top_findings": sorted(open_findings, key=lambda f: f.get("business_risk_score", 0), reverse=True)[:10]}


@app.get("/api/assets")
async def assets(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    return {"assets": await database.assets.find({"tenant_id": t["_id"]}).sort("updated_at", -1).to_list(300)}


@app.get("/api/findings")
async def findings(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    return {"findings": await database.findings.find({"tenant_id": t["_id"]}).sort("business_risk_score", -1).to_list(500)}


@app.get("/api/attack-paths")
async def attack_paths(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    return {"attack_paths": await attack_path_model(database, t["_id"])}


@app.post("/api/attack-paths")
async def snapshot_attack_paths(payload: dict | None = None, t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    model = await attack_path_model(database, t["_id"])
    report = {"_id": oid(), "tenant_id": t["_id"], "name": "Attack path analytics", "type": "attack_path_analytics", "created_by": "attack-path-engine", "data": model, "created_at": now()}
    await database.report_snapshots.insert_one(report)
    await audit(database, t["_id"], "attack-path-engine", "attack_path_analytics_generated", "report", report["_id"], model["summary"])
    return {"report": report, "attack_paths": model}


@app.get("/api/remediation-actions")
async def actions(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    return {"actions": await database.remediation_actions.find({"tenant_id": t["_id"]}).sort("updated_at", -1).to_list(500)}


@app.post("/api/remediation-actions/{action_id}/simulate")
async def simulate(action_id: str, t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    action = await database.remediation_actions.find_one({"_id": action_id, "tenant_id": t["_id"]})
    if not action: raise HTTPException(404, "action not found")
    sim = {"_id": oid(), "tenant_id": t["_id"], "remediation_action_id": action_id, "type": "standard", "status": "COMPLETED", "confidence": 84, "risk_reduction_estimate": round(action.get("expected_risk_reduction", 40), 2), "operational_risk": 35, "result": {"rollback_required": True, "approval_required": True}, "created_at": now()}
    await database.simulations.insert_one(sim)
    await database.remediation_actions.update_one({"_id": action_id}, {"$set": {"status": "SIMULATED", "updated_at": now()}})
    await audit(database, t["_id"], "simulation-engine", "simulation_completed", "simulation", sim["_id"])
    return {"simulation": sim}


@app.post("/api/remediation-actions/{action_id}/plan")
async def plan(action_id: str, t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    action = await database.remediation_actions.find_one({"_id": action_id, "tenant_id": t["_id"]})
    if not action: raise HTTPException(404, "action not found")
    doc = {"_id": oid(), "tenant_id": t["_id"], "remediation_action_id": action_id, "title": f"Plan for {action['title']}", "rollout_steps": ["Confirm owner", "Run simulation", "Canary rollout", "Monitor", "Expand"], "rollback_steps": ["Restore previous state", "Validate service health"], "validation_steps": ["Confirm finding closure", "Attach evidence"], "evidence_required": ["before state", "simulation", "approval", "execution log", "validation"], "created_at": now()}
    await database.remediation_plans.insert_one(doc)
    await database.remediation_actions.update_one({"_id": action_id}, {"$set": {"status": "PLANNED", "updated_at": now()}})
    return {"plan": doc}


@app.post("/api/remediation-actions/{action_id}/workflow")
async def workflow(action_id: str, t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    doc = {"_id": oid(), "tenant_id": t["_id"], "remediation_action_id": action_id, "title": "Approval workflow", "status": "PENDING_APPROVAL", "approvals": [{"role": "security_owner", "status": "PENDING"}, {"role": "service_owner", "status": "PENDING"}, {"role": "CAB", "status": "PENDING"}], "created_at": now(), "updated_at": now()}
    await database.workflow_items.insert_one(doc)
    return {"workflow": doc}


@app.get("/api/virtual-patching")
async def virtual_patching(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    findings = await database.findings.find({"tenant_id": t["_id"], "status": "OPEN"}).sort("business_risk_score", -1).to_list(200)
    assets = {a["_id"]: a for a in await database.assets.find({"tenant_id": t["_id"]}).to_list(200)}
    candidates, breakers = [], []
    for f in findings:
        asset = assets.get(f.get("asset_id"))
        if (asset and asset.get("internet_exposure")) or not f.get("patch_available") or f.get("business_risk_score", 0) >= 75:
            candidates.append({"finding_id": f["_id"], "asset": asset.get("name") if asset else "Unmapped", "control": "WAF/API gateway virtual patch" if asset and asset.get("internet_exposure") else "policy compensating control", "score": round(f.get("business_risk_score", 0), 2)})
        if asset and asset.get("internet_exposure") and asset.get("criticality", 3) >= 4:
            breakers.append({"source": asset["name"], "target": "crown-jewel service", "breaker": "microsegmentation plus conditional deny", "score": 90})
    policies = await database.policies.count_documents({"tenant_id": t["_id"], "policy_type": {"$in": ["virtual_patch", "path_breaker"]}})
    return {"summary": {"virtual_patch_candidates": len(candidates), "path_breaker_candidates": len(breakers), "active_policies": policies}, "candidates": candidates, "path_breakers": breakers}


@app.post("/api/virtual-patching")
async def activate_virtual(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    policy = {"_id": oid(), "tenant_id": t["_id"], "name": "Virtual patch and path breaker guardrail", "policy_type": "virtual_patch", "enabled": True, "rules": {"dry_run": True, "require_rollback": True}, "created_at": now()}
    await database.policies.insert_one(policy)
    await audit(database, t["_id"], "virtual-patching", "virtual_patching_activated", "policy", policy["_id"])
    return {"policy": policy, "model": await virtual_patching(t, database)}


@app.get("/api/agentic")
async def agentic(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    providers = provider_status()
    virtual = await virtual_patching(t, database)
    paths = await attack_path_model(database, t["_id"])
    readiness = min(100, 35 + min(20, paths["summary"]["attack_paths"] * 4) + min(15, await database.policies.count_documents({"tenant_id": t["_id"]}) * 2))
    return {"agentic": {"readiness_score": readiness, "status": "human_supervised_ready" if readiness >= 65 else "needs_model_or_policy_setup", "providers": providers, "tool_registry": [{"name": "run_simulation", "mode": "safe", "risk": "low"}, {"name": "activate_virtual_patch", "mode": "dry_run_default", "risk": "medium"}, {"name": "analyze_attack_paths", "mode": "read_only", "risk": "low"}, {"name": "execute_connector", "mode": "dry_run_default", "risk": "high"}], "safety_rails": ["No live execution without credentials and policy approval", "Production assets require simulation, rollback, evidence, and approval", "Secrets never enter prompts"], "context": {"virtual": virtual["summary"], "attack_paths": paths["summary"]}, "recent_agent_runs": await database.report_snapshots.find({"tenant_id": t["_id"], "type": "agentic_plan"}).sort("created_at", -1).to_list(10)}}


@app.post("/api/agentic")
async def run_agentic(payload: dict, t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    model = await agentic(t, database)
    completion = await complete_with_model("You are Remediation Twin's governed remediation agent.", f"Goal: {payload.get('goal', 'prioritize')} Context: {model['agentic']['context']} Request: {payload.get('prompt', '')}", payload.get("provider"))
    plan = {"summary": completion["output"], "execution_mode": "dry_run_default", "steps": [{"tool": "analyze_attack_paths", "status": "required"}, {"tool": "run_simulation", "status": "recommended"}, {"tool": "activate_virtual_patch", "status": "recommended"}, {"tool": "route_approval", "status": "required_before_live"}]}
    report = {"_id": oid(), "tenant_id": t["_id"], "name": "Agentic remediation plan", "type": "agentic_plan", "created_by": completion["provider"], "data": {"completion": completion, "plan": plan}, "created_at": now()}
    await database.report_snapshots.insert_one(report)
    await audit(database, t["_id"], "agentic-orchestrator", "agentic_plan_created", "report", report["_id"])
    return {"result": {"report": report, "completion": completion, "plan": plan}, "agentic": (await agentic(t, database))["agentic"]}


@app.get("/api/policies")
async def policies(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    return {"policies": await database.policies.find({"tenant_id": t["_id"]}).sort("created_at", -1).to_list(200)}


@app.get("/api/reports")
async def reports(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    return {"reports": await database.report_snapshots.find({"tenant_id": t["_id"]}).sort("created_at", -1).to_list(200)}


@app.get("/api/audit")
async def audit_log(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    return {"audit": await database.audit.find({"tenant_id": t["_id"]}).sort("created_at", -1).to_list(200)}


@app.get("/api/observability")
async def observability(t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    return {"tenant_id": t["_id"], "mongo": "connected", "failed_connector_runs": await database.connector_runs.count_documents({"tenant_id": t["_id"], "status": "FAILED"})}


@app.post("/api/connectors/live")
async def connector(payload: dict, t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    run = {"_id": oid(), "tenant_id": t["_id"], "provider": payload.get("provider", "unknown"), "operation": payload.get("operation", "unknown"), "dry_run": payload.get("dry_run", True), "payload": payload.get("payload", {}), "result": {"status": "dry_run_recorded"}, "created_at": now()}
    await database.connector_runs.insert_one(run)
    return {"run": run}


@app.post("/api/workers/run")
async def worker(payload: dict, t: dict = Depends(tenant), database: AsyncIOMotorDatabase = Depends(db)):
    run = {"_id": oid(), "tenant_id": t["_id"], "provider": "worker", "operation": payload.get("lane", "simulation"), "dry_run": True, "payload": payload, "result": {"processed": payload.get("limit", 5)}, "created_at": now()}
    await database.connector_runs.insert_one(run)
    return {"run": run}
