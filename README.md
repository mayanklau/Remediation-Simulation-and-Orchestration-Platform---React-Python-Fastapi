# Remediation Twin: React + Python FastAPI + MongoDB

Remediation Twin is an enterprise remediation simulation, orchestration, and agentic governance platform refactored into a React frontend, Python FastAPI backend, and MongoDB persistence layer.

The platform helps enterprises move from chaotic vulnerability backlogs to governed remediation execution. It ingests findings from scanners, cloud security tools, IAM platforms, Kubernetes, code security, compliance systems, and ticketing tools; maps them to assets; scores business risk; simulates remediation; generates rollout and rollback plans; routes approvals; applies virtual patches and attack-path breakers; and records audit evidence.

## Why This Exists

Enterprises usually have many detection tools but no trusted system of action. Vulnerability management, cloud security, identity, application security, and GRC teams all create overlapping work. Engineering teams then receive tickets without clear blast radius, ownership, rollback guidance, approval context, or evidence requirements.

Remediation Twin creates a governed operating layer for:

- deciding which findings matter most
- mapping findings to real assets and business services
- simulating remediation before production change
- reducing risk with virtual patching when permanent remediation is delayed
- breaking risky attack paths before a full fix is safe
- routing human approvals for high-risk work
- generating evidence for audit and leadership reporting
- using agentic planning without allowing uncontrolled execution

## Technology Stack

| Layer | Technology |
| --- | --- |
| Frontend | React 19, Vite, TypeScript, Lucide icons |
| Backend | Python, FastAPI, Pydantic, Motor |
| Database | MongoDB |
| Local runtime | Docker Compose |
| API docs | FastAPI OpenAPI at `/docs` |
| Agentic runtime | Deterministic fallback plus optional LLM, SLM, or enterprise model gateway |

## Product Capabilities

- Multi-tenant API surface using `x-tenant-id` or default tenant creation.
- MongoDB collections for tenants, assets, findings, remediation actions, simulations, workflows, policies, reports, connector runs, and audit events.
- Finding ingestion with normalization, deduplication, asset upsert, fingerprinting, risk scoring, and remediation action creation.
- Asset inventory with environment, type, exposure, criticality, and data sensitivity.
- Business-risk scoring that accounts for severity, exploitability, active exploitation, patch availability, internet exposure, asset criticality, and data sensitivity.
- Remediation queue with simulation, plan generation, approval workflow, and status transitions.
- Simulation engine for risk reduction, operational risk, rollback requirement, approval requirement, and confidence.
- Remediation plan generation with rollout, rollback, validation, and evidence requirements.
- Virtual patching and path breaker recommendations for exposed, unpatchable, or crown-jewel risk.
- Agentic orchestrator that plans remediation with safety rails and model fallback.
- Governance policies for virtual patching, evidence gates, dry-run controls, and production approval.
- Reports, audit log, connector dry-runs, and worker dry-runs.
- React UI for dashboard, findings, assets, remediation, virtual patching, agentic planning, policies, reports, audit, and operations.
- Docker Compose for local MongoDB, API, and web runtime.

## Repository Structure

```text
.
├── backend/
│   ├── app/
│   │   └── main.py
│   ├── tests/
│   │   └── test_domain.py
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── main.tsx
│   │   ├── styles.css
│   │   └── vite-env.d.ts
│   ├── Dockerfile
│   ├── index.html
│   ├── package.json
│   └── tsconfig.json
├── docs/
│   ├── API.md
│   ├── ARCHITECTURE.md
│   └── SECURITY.md
├── PRD.md
├── docker-compose.yml
├── pytest.ini
└── README.md
```

## Core Application Flow

1. A tenant is resolved from `x-tenant-id` or a default tenant is created.
2. Findings are ingested through JSON or prototype ingestion.
3. Assets are upserted from finding payloads.
4. Findings are fingerprinted and deduplicated.
5. Technical risk and business risk are calculated.
6. A remediation action is generated for each new canonical finding.
7. Users simulate remediation to estimate risk reduction and operational risk.
8. Users generate rollout, rollback, validation, and evidence plans.
9. Users create approval workflows for governed execution.
10. Virtual patching recommends compensating controls and path breakers.
11. Agentic planning creates a governed tool plan with dry-run defaults.
12. Reports and audit logs preserve decision history.

## Agentic LLM and SLM Support

The agentic layer is model-agnostic. It can use external models when configured, but it always has a deterministic fallback so the platform remains usable in regulated, offline, or demo environments.

| Provider | Environment |
| --- | --- |
| Deterministic fallback | Always enabled |
| OpenAI-compatible gateway | `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` |
| Anthropic-compatible | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` |
| Gemini-compatible | `GEMINI_API_KEY`, `GEMINI_MODEL` |
| Local SLM | `LOCAL_SLM_URL`, `LOCAL_SLM_MODEL` |

Agentic safety rules:

- Model output is advisory.
- Live execution remains dry-run by default.
- Production assets require simulation, approval, rollback, and evidence.
- Raw secrets are not sent to prompts.
- Deterministic policy gates control execution eligibility.
- Agent plans are stored as report snapshots and audit events.

## API Highlights

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Service and Mongo health check |
| GET | `/api/dashboard` | Risk and remediation summary |
| POST | `/api/ingest/json` | Ingest real finding payloads |
| POST | `/api/mock-ingest` | Load prototype findings |
| GET | `/api/assets` | List assets |
| GET | `/api/findings` | List canonical findings |
| GET | `/api/remediation-actions` | List remediation actions |
| POST | `/api/remediation-actions/{id}/simulate` | Run simulation |
| POST | `/api/remediation-actions/{id}/plan` | Generate remediation plan |
| POST | `/api/remediation-actions/{id}/workflow` | Create approval workflow |
| GET | `/api/virtual-patching` | View virtual patch and path breaker candidates |
| POST | `/api/virtual-patching` | Activate dry-run virtual patch policy |
| GET | `/api/agentic` | View agentic readiness and provider status |
| POST | `/api/agentic` | Generate governed agent plan |
| GET | `/api/policies` | List governance policies |
| GET | `/api/reports` | List report snapshots |
| GET | `/api/audit` | List audit events |
| POST | `/api/connectors/live` | Record connector dry-run |
| POST | `/api/workers/run` | Record worker dry-run |
| GET | `/api/observability` | Runtime observability summary |

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

Run tests:

```bash
pytest
```

## Local Frontend

```bash
cd frontend
npm install
npm run dev
```

Build frontend:

```bash
npm run build
```

## Demo Flow

1. Open the frontend at `http://localhost:3000`.
2. Click **Load prototype data**.
3. Review dashboard risk, findings, assets, and remediation actions.
4. Open Remediation and simulate the first action.
5. Generate a remediation plan.
6. Create an approval workflow.
7. Open Virtual Patch and activate controls.
8. Open Agentic and run an agent plan.
9. Review policies, reports, audit, and operations.

## Production Readiness

The application includes the foundations expected for an enterprise pilot:

- tenant-scoped APIs
- MongoDB indexes for important query and uniqueness paths
- dry-run connector and worker contracts
- security headers
- rate-limit middleware
- risk scoring
- simulation and rollback modeling
- approval workflow creation
- virtual patching and path breaker planning
- agentic model fallback
- audit logging
- reports
- Docker Compose
- backend tests
- frontend build pipeline

For live production deployment, add managed MongoDB, external secret manager, enterprise SSO, immutable object storage for evidence, queue-backed workers, OpenTelemetry tracing, alert routing, centralized rate limiting, and organization-specific governance policies.

## Current Execution Policy

Live execution is intentionally disabled by default. The platform records dry-run connector and worker operations until production credentials, approval policies, change windows, rollback plans, and evidence storage are configured.

## Documentation

- [Product Requirements Document](PRD.md)
- [API Reference](docs/API.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY.md)
