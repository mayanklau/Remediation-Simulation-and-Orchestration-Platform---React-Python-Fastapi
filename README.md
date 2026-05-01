# Remediation Twin: React + Python FastAPI + MongoDB

A full-stack refactor of Remediation Twin into React, Python FastAPI, and MongoDB.

The platform ingests vulnerability, cloud, IAM, Kubernetes, application, compliance, scanner, and ticketing findings; maps them to assets; scores business risk; simulates remediation; generates plans; routes approvals; activates virtual patches and attack-path breakers; runs agentic planning with any LLM/SLM/model gateway; and keeps execution dry-run and governed by default.

## Stack

- React + Vite frontend
- Python FastAPI backend
- MongoDB persistence through Motor
- Docker Compose for local full-stack runtime
- Agentic model abstraction for deterministic fallback, OpenAI-compatible gateways, Anthropic-compatible endpoints, Gemini-compatible endpoints, and local SLMs

## Capabilities

- Multi-tenant APIs using `x-tenant-id` or default tenant creation
- JSON finding ingestion with normalization, deduplication, asset upsert, risk scoring, and remediation action generation
- Dashboard, findings, assets, remediation queue, virtual patching, agentic orchestration, policies, reports, and audit UI
- Simulation engine with confidence, risk reduction, operational risk, rollback, and approval modeling
- Remediation plan generation with rollout, rollback, validation, and evidence requirements
- Virtual patching and path breaker recommendations for exposed or unpatchable risk
- Agentic orchestrator with model provider selection, safety rails, governed tool plan, report persistence, and audit logging
- Connector and worker dry-run endpoints for enterprise integration runway
- Security headers, rate limiting, CORS, Mongo indexes, tests, and production notes

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

## API Highlights

- `GET /api/health`
- `GET /api/dashboard`
- `POST /api/ingest/json`
- `POST /api/mock-ingest`
- `GET /api/assets`
- `GET /api/findings`
- `GET /api/remediation-actions`
- `POST /api/remediation-actions/{id}/simulate`
- `POST /api/remediation-actions/{id}/plan`
- `POST /api/remediation-actions/{id}/workflow`
- `GET /api/virtual-patching`
- `POST /api/virtual-patching`
- `GET /api/agentic`
- `POST /api/agentic`
- `GET /api/policies`
- `GET /api/reports`
- `GET /api/audit`
- `POST /api/connectors/live`
- `POST /api/workers/run`

## Agentic Model Providers

| Provider | Environment |
| --- | --- |
| Deterministic fallback | Always enabled |
| OpenAI-compatible gateway | `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` |
| Anthropic-compatible | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` |
| Gemini-compatible | `GEMINI_API_KEY`, `GEMINI_MODEL` |
| Local SLM | `LOCAL_SLM_URL`, `LOCAL_SLM_MODEL` |

Model output is advisory. Deterministic policy gates still control simulation, approval, rollback, evidence, tenant isolation, and credential attestation.

## Production Notes

Use managed MongoDB, external secrets, enterprise SSO, immutable evidence storage, queue-backed workers, OpenTelemetry, and alert routing for production. Live execution is intentionally dry-run until credentials, policy approvals, change windows, and rollback evidence are configured.
