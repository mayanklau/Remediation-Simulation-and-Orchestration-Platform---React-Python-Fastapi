# EY Remediation Twin: React + Python FastAPI + MongoDB

EY Remediation Twin is an enterprise remediation simulation, orchestration, and agentic governance platform refactored into a React frontend, Python FastAPI backend, and MongoDB persistence layer with an EY-inspired command center theme.

The platform helps enterprises move from chaotic vulnerability backlogs to governed remediation execution. It ingests findings from scanners, cloud security tools, IAM platforms, Kubernetes, code security, compliance systems, and ticketing tools; maps them to assets; constructs vulnerability chains and attack paths; scores business risk, path difficulty, and before/after remediation risk; simulates remediation; generates rollout and rollback plans; routes approvals; applies virtual patches and attack-path breakers; and records audit evidence.

## Why This Exists

Enterprises usually have many detection tools but no trusted system of action. Vulnerability management, cloud security, identity, application security, and GRC teams all create overlapping work. Engineering teams then receive tickets without clear blast radius, ownership, rollback guidance, approval context, or evidence requirements.

EY Remediation Twin creates a governed operating layer for:

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
- SSO/OIDC production contract, tenant-boundary dependency, RBAC permission helper, and middleware-backed route-level enforcement across the API surface.
- Repository/service structure for separating API routing from persistence logic and shared validation.
- Queue-worker contracts for ingestion, simulation, connector sync, evidence generation, report snapshots, post-remediation validation, and data-quality scans.
- MongoDB index manifest, backup/restore script, seed-free test fixtures, and persistence contract tests.
- Runtime configuration validation for local, dev, staging, and production.
- MongoDB collections for tenants, assets, findings, remediation actions, simulations, workflows, policies, reports, connector runs, and audit events.
- Finding ingestion with normalization, deduplication, asset upsert, fingerprinting, risk scoring, and remediation action creation.
- Asset inventory with environment, type, exposure, criticality, and data sensitivity.
- Graph-native vulnerability chaining and attack-path analytics across scanner-normalized inputs.
- Multi-path vulnerability fan-out so one discovered vulnerability can generate multiple attack paths, with each graph point showing impact score, pre-remediation risk, post-remediation residual risk, affected targets, and path-specific reduction.
- Advanced cyber-risk intelligence with exploit intelligence fusion, business-service risk graph, attack-path confidence, exposure management, adversary scenario packs, risk appetite, control coverage matrix, toxic-combination detection, kill-chain staging, regulatory mapping, security debt ledger, dynamic SLA intelligence, change-risk modeling, remediation strategy selection, control-effectiveness validation, threat-informed prioritization, crown-jewel governance, exception governance, campaign intelligence, continuous validation, scanner trust scoring, playbook marketplace, risk economics, and executive narratives.
- Business-risk scoring that accounts for severity, exploitability, active exploitation, patch availability, internet exposure, asset criticality, and data sensitivity.
- Attack-path difficulty scoring and before/after remediation risk for customer-facing decision support.
- Remediation queue with simulation, plan generation, approval workflow, and status transitions.
- Simulation engine for risk reduction, operational risk, rollback requirement, approval requirement, and confidence.
- Remediation plan generation with rollout, rollback, validation, and evidence requirements.
- Virtual patching and path breaker recommendations for exposed, unpatchable, or crown-jewel risk.
- Agentic orchestrator that plans remediation with safety rails and model fallback.
- Governance policies for virtual patching, evidence gates, dry-run controls, and production approval.
- Reports, audit log, connector dry-runs, and worker dry-runs.
- Manual connector and integration factory for any scanner, CMDB, ticketing, cloud, code, IAM, notification, or custom HTTP provider with Mongo-backed profile persistence and dry-run health checks.
- React UI for dashboard, findings, assets, remediation, virtual patching, agentic planning, policies, reports, audit, and operations, with React Flow graph-library canvases for pan, zoom, minimap, risk filtering, export, drill-down, empty states, and error-safe API loading.
- Once-and-for-all enterprise readiness catalog covering identity, tenancy, secrets, connectors, ingestion, vulnerability analytics, simulation, orchestration, AI governance, evidence, reporting, platform architecture, security, observability, testing, DevOps, product experience, and commercial packaging.
- Production expansion layer for admin onboarding, connector marketplace, data quality, attack-path validation, remediation economics, control drift, post-remediation validation, policy builder, plugin SDK, deployment hardening, security review, executive narratives, demo separation, E2E coverage, and data residency.
- Production effectiveness layer for scheduler lanes, retry/backoff/dead-letter contracts, data-quality gates, post-remediation validation, residual-risk evidence, observability signals, and operating rules that separate repo-ready capability from customer-specific go-live wiring.
- Go-live kit with production environment contract, production compose, static web container, launch sequence, rollback sequence, and identity/secrets/connectors/data/workers/observability/security/release/customer acceptance checks.
- Docker Compose for local MongoDB, API, and web runtime.
- CI/CD quality gates for Python compile, pytest, frontend build, dependency scans, Mongo index manifest checks, Docker builds, and container scans.

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
10. Attack-path analytics chain vulnerabilities from exposed entry points to production or crown-jewel targets.
11. Cyber-risk intelligence explains exploit probability, adversary scenarios, business-service exposure, path confidence, toxic combinations, regulatory obligations, dynamic SLAs, remediation economics, exceptions, validation, and executive narratives.
12. Virtual patching recommends compensating controls and path breakers.
13. Agentic planning creates a governed tool plan with dry-run defaults.
14. Manual connector profiles onboard arbitrary third-party systems and run dry-run checks before live execution.
15. Enterprise readiness maps every required control to implemented, contract-ready, or external-setup-required status.
16. Production expansion tracks the remaining enterprise product modules with APIs, workflows, evidence, gates, and owners.
17. Production effectiveness verifies queue reliability, data quality, validation loops, evidence sealing, and observability.
18. Go-live checks guide the final customer deployment and rollback path.
19. Reports and audit logs preserve decision history.

## Attack Path Analytics

Advanced analytics coverage:

- shortest exploitable path, k-hop blast radius, crown-jewel exposure, choke-point, and path-breaker scoring
- chaining rules for network, IAM, cloud, Kubernetes, application, CI/CD, secrets, and data-store findings
- exploit preconditions for privilege, network access, user interaction, token scope, and lateral movement
- before/after simulation by control type: patch, WAF/API rule, IAM deny, segmentation, container rebuild, and cloud policy
- executive views for business services at risk, risk reduced, blocked remediations, and attack paths closed

The `/api/attack-paths` backend and Attack Paths UI convert scanner findings into end-to-end vulnerability analytics:

- normalizes Tenable, Qualys, Wiz, Snyk, GitHub Advanced Security, AWS Security Hub, Kubernetes, IAM, cloud posture, compliance, CSV, and API findings into chain steps
- uses asset reachability, internet exposure, exploit availability, active exploitation, patchability, policy controls, and production/crown-jewel targeting
- builds bounded logical attack paths from likely entry points to high-value targets
- returns graph-library-ready attack path nodes and edges for entry assets, reachable services, exploit preconditions, targets, and breaker controls
- renders a React Flow Attack Path Graph UI that makes path traversal and risk transfer visible
- renders a Vulnerability Chaining Graph UI that shows ordered exploit steps, scanner source, mapped technique, difficulty, before/after risk, and breaker impact
- labels path difficulty as `LOW`, `MEDIUM`, `HIGH`, or `VERY_HIGH`
- compares before-remediation risk with estimated after-remediation residual risk
- recommends virtual patches, microsegmentation, conditional IAM denies, route restrictions, and simulation-backed path breakers
- snapshots the analytics into report and audit records

### Maturity Additions

The React/FastAPI/MongoDB version now includes the same enterprise maturity layer:

- scanner-family coverage for vulnerability scanners, cloud posture, code security, IAM, network/Kubernetes, and compliance inputs
- asset-mapping, exploit-signal, and remediation-signal coverage percentages so weak data is visible before customers trust an attack path
- decision-readiness metrics for customer-ready paths, executive escalations, average difficulty, likelihood, business impact, and release confidence
- subject-maturity checks for scanner normalization, reachability, exploit preconditions, before/after residual risk, path difficulty, breaker controls, evidence, and validation
- development-maturity gates for tenant-scoped access, deterministic graph contracts, policy guardrails, simulation evidence, explainability, and audit snapshots
- per-path evidence requirements, validation steps, and a customer-facing before/after risk narrative

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
| GET | `/api/attack-paths` | Attack graph, vulnerability chain graph, difficulty, and before/after risk |
| POST | `/api/attack-paths` | Snapshot attack-path analytics |
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
| GET | `/api/enterprise-readiness` | Once-and-for-all enterprise control catalog |
| GET | `/api/production-expansion` | Production expansion modules and readiness gates |
| GET | `/api/go-live` | Production launch and rollback control model |

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
7. Open Attack Paths and snapshot vulnerability-chain analytics.
8. Open Virtual Patch and activate controls.
9. Open Agentic and run an agent plan.
10. Review policies, reports, audit, and operations.

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
- vulnerability chaining and before/after attack-path risk
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
