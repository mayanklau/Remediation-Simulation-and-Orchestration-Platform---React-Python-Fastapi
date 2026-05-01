# Remediation Twin: React + Python FastAPI + MongoDB

Remediation Twin is an enterprise remediation simulation, orchestration, vulnerability analytics, and agentic governance platform refactored into a React frontend, Python FastAPI backend, and MongoDB persistence layer.

The platform helps enterprises move from chaotic vulnerability backlogs to governed remediation execution. It ingests findings from scanners, cloud security tools, IAM platforms, Kubernetes, code security, compliance systems, and ticketing tools; maps them to assets; chains vulnerabilities into attack paths; scores before and after remediation risk; simulates remediation; recommends virtual patches and path breakers; routes approvals; and records audit evidence.

## What Is Included

- React 19 + Vite + TypeScript frontend.
- Python FastAPI backend with OpenAPI docs at `/docs`.
- MongoDB persistence with tenant, asset, finding, action, simulation, workflow, policy, report, connector-run, and audit collections.
- Tenant-scoped APIs using `x-tenant-id` or default tenant creation.
- JSON and prototype ingestion with asset upsert, deduplication, fingerprinting, risk scoring, and remediation action creation.
- Asset inventory with exposure, environment, criticality, and data sensitivity.
- Vulnerability chaining and attack-path analytics from normalized scanner input.
- Attack-path difficulty levels: LOW, MEDIUM, HIGH, VERY_HIGH.
- Before-remediation risk, after-remediation residual risk, and expected risk delta.
- Remediation simulation, plan generation, approval workflow, evidence requirements, and audit logging.
- Virtual patching and path breaker recommendations.
- Agentic planner that can use an LLM, SLM, model gateway, or deterministic fallback.
- Dry-run connector and worker endpoints for production-safe integration testing.
- Docker Compose for local MongoDB, API, and web runtime.

## Attack Path Analytics

The `/api/attack-paths` endpoint turns scanner noise into end-to-end vulnerability analytics.

Construction method:

1. Normalize scanner findings into the canonical finding model.
2. Map findings to assets, criticality, sensitivity, and exposure.
3. Treat internet-exposed and scanner-indicated assets as possible initial access points.
4. Treat production, critical, and sensitive assets as crown-jewel targets.
5. Build bounded logical paths between initial access and crown-jewel targets.
6. Convert each path into ordered vulnerability chain steps with source scanner, category, severity, exploit status, active exploitation, patch state, business risk, and ATT&CK-style technique label.
7. Score difficulty from hop count, exposure, exploitability, active exploitation, patchability, and control friction.
8. Score before remediation risk and after remediation residual risk using simulations, policy controls, patching, virtual patching, and path breakers.
9. Recommend controls such as WAF/API gateway virtual patch, microsegmentation, conditional IAM deny, and path-risk validation.

API:

```bash
curl http://localhost:8000/api/attack-paths
curl -X POST http://localhost:8000/api/attack-paths \
  -H "content-type: application/json" \
  -d '{"action":"snapshot"}'
```

The React UI includes an **Attack Paths** page that shows summary metrics, path difficulty, before risk, after risk, risk delta, and construction method.

## Agentic LLM and SLM Support

The agentic layer is model-agnostic. It can use external models when configured, but always has a deterministic fallback.

| Provider | Environment |
| --- | --- |
| Deterministic fallback | Always enabled |
| OpenAI-compatible gateway | `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL` |
| Anthropic-compatible | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` |
| Gemini-compatible | `GEMINI_API_KEY`, `GEMINI_MODEL` |
| Local SLM | `LOCAL_SLM_URL`, `LOCAL_SLM_MODEL` |

Safety rules:

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
| GET | `/api/attack-paths` | Build vulnerability chains and attack paths |
| POST | `/api/attack-paths` | Snapshot attack-path analytics into reports and audit |
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
npm run build
```

## Production Readiness

The application includes the foundations expected for an enterprise pilot: tenant-scoped APIs, MongoDB indexes, dry-run connector and worker contracts, security headers, rate-limit middleware, risk scoring, vulnerability chaining, attack-path analytics, simulation and rollback modeling, approval workflow creation, virtual patching, path breaker planning, agentic fallback, audit logging, reports, Docker Compose, backend tests, and frontend build pipeline.

For live production deployment, add managed MongoDB, external secret manager, enterprise SSO, immutable object storage for evidence, queue-backed workers, OpenTelemetry tracing, alert routing, centralized rate limiting, and organization-specific governance policies.

## Documentation

- [Product Requirements Document](PRD.md)
- [API Reference](docs/API.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security Model](docs/SECURITY.md)
