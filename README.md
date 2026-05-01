# Remediation Twin: React + Python FastAPI + MongoDB

This repository is a full-stack refactor of Remediation Twin into:

- React + Vite frontend
- Python FastAPI backend
- MongoDB persistence
- Agentic model-provider abstraction for any LLM, SLM, enterprise gateway, or deterministic fallback

The product turns vulnerability, cloud, IAM, Kubernetes, application, compliance, scanner, and ticketing findings into prioritized remediation work that can be simulated, approved, virtually patched, routed through workflows, tracked through campaigns, and sealed with evidence.

## What Is Included

- Multi-tenant API surface using `x-tenant-id` or a default tenant.
- MongoDB collections and indexes for tenants, assets, findings, source findings, remediation actions, simulations, workflows, policies, reports, connector runs, and audit logs.
- JSON and CSV ingestion APIs with normalization, deduplication, asset upsert, risk scoring, and remediation action generation.
- Dashboard, findings, assets, asset graph, remediation queue, simulations, approvals, virtual patching, agentic orchestration, policies, reports, audit, and operations UI.
- Simulation engine with risk reduction, operational risk, confidence, blast-radius, approval, and rollback modeling.
- Remediation plan generation with rollout, rollback, validation, and evidence requirements.
- Virtual patching and path breaker module for compensating controls before permanent remediation.
- Agentic orchestrator with model-provider abstraction, tenant context builder, governed tool registry, safety rails, report persistence, and audit logging.
- Connector dry-run contracts for Jira, GitHub, ServiceNow, cloud, IAM, Kubernetes, CI/CD, and workers.
- Security headers, rate-limit middleware, CORS, environment contract, Docker Compose, and tests.

## Agentic Model Support

The backend can integrate with any model gateway while keeping execution governed and dry-run by default.

| Provider | Environment |
| --- | --- |
| Deterministic fallback | Always enabled |
| OpenAI-compatible or enterprise gateway | `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` |
| Anthropic-compatible | `ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL`, `ANTHROPIC_MODEL` |
| Gemini-compatible | `GEMINI_API_KEY`, `GEMINI_BASE_URL`, `GEMINI_MODEL` |
| Local SLM | `LOCAL_SLM_URL`, `LOCAL_SLM_MODEL` |

Model output is advisory. Deterministic policy gates still control simulation, approval, rollback, evidence, tenant isolation, and credential attestation.

## API Highlights

- `GET /api/health`
- `GET /api/dashboard`
- `POST /api/ingest/json`
- `POST /api/ingest/csv`
- `POST /api/mock-ingest`
- `GET /api/assets`
- `POST /api/assets`
- `GET /api/findings`
- `PATCH /api/findings/{finding_id}`
- `GET /api/asset-graph`
- `GET /api/remediation-actions`
- `POST /api/remediation-actions/{action_id}/simulate`
- `POST /api/remediation-actions/{action_id}/plan`
- `POST /api/remediation-actions/{action_id}/workflow`
- `GET /api/simulations`
- `GET /api/workflows`
- `GET /api/virtual-patching`
- `POST /api/virtual-patching`
- `GET /api/agentic`
- `POST /api/agentic`
- `GET /api/policies`
- `POST /api/policies`
- `POST /api/governance/continuous-simulation`
- `GET /api/governance/predictive-risk`
- `POST /api/governance/apply-fix`
- `POST /api/connectors/live`
- `POST /api/workers/run`
- `GET /api/reports`
- `GET /api/audit`
- `GET /api/observability`

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

Open:

- Frontend: `http://localhost:3000`
- API docs: `http://localhost:8000/docs`
- Health: `http://localhost:8000/api/health`

## Local Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Local Frontend

```bash
cd frontend
npm install
npm run dev
```

## Demo Flow

1. Open the frontend.
2. Click **Load prototype data**.
3. Review findings, assets, and remediation queue.
4. Simulate the first remediation action.
5. Generate a remediation plan and approval workflow.
6. Open Virtual Patch and activate controls.
7. Open Agentic and run an agent plan.
8. Review policies, reports, audit, and operations.

## Production Notes

Production deployment should use managed MongoDB, external secret manager, enterprise SSO, immutable object storage for evidence, queue-backed workers, OpenTelemetry tracing, alert routing, and environment-specific governance policy. Live execution is intentionally dry-run by default until enterprise credentials and approvals are configured.

