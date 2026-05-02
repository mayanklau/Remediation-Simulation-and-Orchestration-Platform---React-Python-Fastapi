# Product Requirements Document: EY Remediation Twin React + FastAPI

## 1. Product Summary

**Product name:** EY Remediation Twin

**Category:** Enterprise remediation simulation, orchestration, and agentic governance platform

**Stack:** React, Python FastAPI, MongoDB

**Purpose:** Help enterprises turn security findings into prioritized, chained, simulated, approved, auditable remediation work with vulnerability-chain analytics, virtual patching, attack-path breakers, and governed agentic planning.

## 2. Problem Statement

Enterprises have many tools that detect risk but few systems that safely coordinate remediation. Vulnerability scanners, cloud security tools, IAM analyzers, code scanners, Kubernetes platforms, and compliance systems produce overlapping findings. Teams struggle to decide what matters, who owns it, what will break if remediated, whether a compensating control is safer, and what evidence is needed.

The result is duplicated tickets, delayed fixes, risky production changes, weak audit trails, and low trust between security and engineering.

## 3. Goals

- Provide a full-stack remediation platform using React, FastAPI, and MongoDB.
- Add SSO/OIDC, tenant isolation tests, and RBAC enforcement contracts on sensitive routes.
- Separate API routes from service, repository, DTO, and shared validation contracts.
- Add queue workers for ingestion, simulation, connector sync, evidence generation, report snapshots, post-remediation validation, and data-quality scans.
- Add manual connector and integration onboarding for arbitrary scanners, CMDB, ticketing, cloud, code, IAM, notification, and custom HTTP providers.
- Add a once-and-for-all enterprise readiness control catalog with implemented, contract-ready, and external-setup-required status.
- Add production expansion modules for onboarding, connector marketplace, data quality, validation, economics, drift, policy builder, plugin SDK, deployment, security review, executive reporting, demo separation, E2E testing, and data residency.
- Add a go-live kit covering production environment values, production compose, launch sequence, rollback sequence, and acceptance checks.
- Add production effectiveness controls for queue retries, dead letters, idempotency, source freshness, owner coverage, evidence completeness, post-remediation validation, and observability alerts.
- Add environment separation for local, dev, staging, and production with strict config validation.
- Ingest and normalize findings from multiple enterprise sources.
- Map findings to assets and business context.
- Construct graph-native scanner-normalized vulnerability chains and attack paths.
- Prioritize by technical and business risk.
- Score attack-path difficulty and before/after remediation risk.
- Simulate remediation before change.
- Generate rollout, rollback, validation, and evidence plans.
- Route high-risk work through approvals.
- Recommend virtual patches and attack-path breakers.
- Enable agentic planning with any LLM, SLM, model gateway, or deterministic fallback.
- Keep live execution governed and dry-run by default.
- Preserve audit logs and report snapshots.

## 4. Non-Goals

- Replace scanners, SIEM, SOAR, ITSM, or CI/CD systems.
- Execute production changes without credentials, approvals, rollback plans, and evidence gates.
- Store raw secrets in application data.
- Treat model output as authoritative execution permission.

## 5. Target Users

- CISO and security leadership
- Vulnerability management teams
- Cloud security teams
- IAM and identity teams
- Platform engineering
- Application security
- GRC and audit teams
- Change managers
- Service owners

## 6. Core User Journeys

### 6.1 Ingest Findings

Users can ingest findings through JSON or prototype ingestion. The system normalizes each finding, maps or creates an asset, calculates risk, deduplicates by fingerprint, and creates a remediation action for each new canonical finding.

### 6.2 Review Enterprise Risk

Users can open the dashboard to see counts, open findings, assets, remediation actions, simulations, total business risk, and simulation coverage.

### 6.3 Simulate Remediation

Users can simulate a remediation action to estimate confidence, risk reduction, operational risk, approval requirement, and rollback requirement.

### 6.4 Generate a Plan

Users can generate remediation plans with rollout steps, rollback steps, validation steps, and evidence requirements.

### 6.5 Route Approval

Users can create approval workflows with security owner, service owner, and CAB-style approvals.

### 6.6 Apply Virtual Patching

Users can identify exposed, high-risk, or unpatchable findings and activate dry-run virtual patch policies.

### 6.7 Analyze Vulnerability Chains

Users can open Attack Paths to see scanner-normalized chains from exposed entry points to production or crown-jewel targets. Each path shows difficulty, before-remediation risk, after-remediation residual risk, recommended breakers, and scanner sources.

### 6.8 Run Agentic Planning

Users can run an agentic plan using a configured LLM, SLM, model gateway, or deterministic fallback. The agent returns a governed plan with tool steps and safety rails.

### 6.9 Add Any Connector

Users can create a manual connector profile, select a template or define a custom provider, store endpoint metadata and secret references, and run a dry-run health check before enabling live integration work.

### 6.10 Review Enterprise Readiness

Users can review the complete enterprise control catalog across identity, tenancy, secrets, connectors, ingestion, analytics, simulation, remediation, AI governance, evidence, operations, testing, deployment, product experience, and commercial packaging.

### 6.11 Operate Product Completeness

Users can review production expansion modules with owners, API surfaces, workflows, readiness gates, and evidence outputs for the remaining enterprise capabilities.

### 6.12 Launch Production

Users can review go-live requirements, launch sequence, rollback sequence, and acceptance checks so deployment teams only need to provide customer-specific values.

## 7. Functional Requirements

| Area | Requirement |
| --- | --- |
| Auth and tenancy | Enforce tenant boundary and RBAC on sensitive APIs; require OIDC/session configuration in production. |
| Service architecture | Use repositories, services, DTOs, and shared validation instead of direct route persistence logic. |
| Connector onboarding | Support manual connector profiles for any provider with category, auth mode, endpoint, owner, scopes, cadence, config, health, and run history. |
| Enterprise readiness | Expose a complete control catalog that separates implemented controls from contract-ready integrations and customer external setup. |
| Production expansion | Expose product-completeness modules with workflow, evidence, API surface, owner, and readiness gates. |
| Go-live kit | Expose launch and rollback checks with production environment, identity, secrets, connectors, data, workers, observability, security, release, and customer acceptance requirements. |
| Queue workers | Support ingestion, simulation, connector sync, evidence generation, and report snapshot worker lanes. |
| CI/CD gates | Run compile, tests, frontend build, dependency audit, and container-scan readiness checks. |
| Tenancy | Resolve tenant through `x-tenant-id`; create default local tenant when missing. |
| Ingestion | Support JSON ingestion and prototype data load. |
| Deduplication | Fingerprint findings by source, title, CVE/control, and asset. |
| Asset mapping | Upsert assets from finding payloads. |
| Risk scoring | Score by severity, exploitability, active exploitation, patch availability, exposure, criticality, and sensitivity. |
| Vulnerability chaining | Convert findings from scanners, cloud, IAM, Kubernetes, code, compliance, CSV, and API sources into ordered chain steps. |
| Attack path construction | Build bounded logical attack paths from entry assets to production, critical, or sensitive targets using asset reachability and exploit preconditions. |
| Attack path graph UI | Render entry assets, reachability edges, exploit-precondition findings, crown-jewel targets, and breaker controls as a React Flow graph workbench with pan, zoom, minimap, filters, node inspector, and export. |
| Vulnerability chain graph UI | Render each ordered vulnerability chain as connected graph nodes with scanner source, mapped technique, difficulty, before/after risk, breaker outcome, and graph-library-ready API contracts. |
| Path difficulty | Label each attack path as `LOW`, `MEDIUM`, `HIGH`, or `VERY_HIGH`. |
| Before/after risk | Present pre-remediation path risk, residual risk after remediation, and expected risk delta. |
| Remediation actions | Create actions for new canonical findings. |
| Simulation | Estimate confidence, risk reduction, operational risk, approval, and rollback need. |
| Planning | Generate rollout, rollback, validation, and evidence steps. |
| Workflow | Create approval workflow items. |
| Virtual patching | Recommend compensating controls for exposed, unpatchable, and high-risk findings. |
| Path breakers | Recommend controls that interrupt reachability to high-value targets. |
| Agentic planning | Build model-agnostic plans with safety rails and deterministic fallback. |
| Policies | Store governance policy records. |
| Reports | Store report snapshots and agent plans. |
| Audit | Record important operational events. |
| Operations | Provide connector and worker dry-run endpoints. |

## Advanced Vulnerability Analytics Requirements

| Capability | Requirement |
| --- | --- |
| Graph algorithms | Identify shortest exploitable path, k-hop blast radius, centrality-style concentration, choke points, and crown-jewel exposure. |
| Domain chaining | Apply network, IAM, cloud, Kubernetes, application, CI/CD, secrets, and data-store chaining rules. |
| Exploit preconditions | Model required privilege, network access, user interaction, token scope, lateral movement, and control friction. |
| Difficulty explainability | Explain why a path is low, medium, high, or very high difficulty and list assumptions. |
| Control simulation | Score before/after risk for patching, WAF/API rules, IAM denies, segmentation, container rebuilds, and cloud policies. |
| Path breaker engine | Recommend the edge or control that removes the largest amount of path risk for the least change risk. |
| Executive views | Show business services at risk, weekly risk reduced, blocked remediations, and attack paths closed. |

## 8. Attack Path Analytics Requirements

The platform must provide scanner-agnostic vulnerability analytics:

| Capability | Requirement |
| --- | --- |
| Scanner input coverage | Support Tenable, Qualys, Wiz, Snyk, GitHub Advanced Security, AWS Security Hub, Kubernetes, IAM, cloud posture, compliance, CSV, and API scanner feeds through the canonical finding model. |
| Construction method | Use logical attack graph construction with bounded simple-path enumeration over asset reachability, exposure, exploitability, and target criticality. |
| Vulnerability chain steps | Include finding ID, source scanner, category, mapped technique, severity, business risk, exploit availability, active exploitation, and patch availability. |
| Graph model | Return attack graph nodes, attack graph edges, vulnerability chain graph nodes, vulnerability chain graph edges, breaker edges, and React Flow-ready node/edge projections in the API response. |
| Difficulty level | Calculate path difficulty from hop count, exposure, exploit availability, patchability, active exploitation, and control friction. |
| Customer risk view | Show before-remediation risk, after-remediation residual risk, risk delta, likelihood, and business impact. |
| Breaker advice | Recommend WAF/API gateway virtual patches, microsegmentation, conditional IAM denies, route restrictions, and simulation-backed controls. |
| Evidence | Persist snapshots as `attack_path_analytics` report records and audit the generation event. |

## 9. Agentic Requirements

The platform must support:

- deterministic fallback planning without external credentials
- OpenAI-compatible model gateways
- local SLM endpoints
- optional Anthropic and Gemini environment contracts
- provider readiness display in UI
- no raw secrets in prompts
- dry-run execution by default
- report persistence for every plan
- audit logging for every plan
- policy-gated execution eligibility

## 10. API Requirements

Required API endpoints:

- `GET /api/health`
- `GET /api/dashboard`
- `POST /api/ingest/json`
- `POST /api/mock-ingest`
- `GET /api/assets`
- `GET /api/attack-paths`
- `POST /api/attack-paths`
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
- `GET /api/observability`

## 11. Data Model

MongoDB collections:

- `tenants`
- `assets`
- `findings`
- `remediation_actions`
- `simulations`
- `remediation_plans`
- `workflow_items`
- `policies`
- `report_snapshots`
- `connector_runs`
- `audit`

Indexes:

- tenant slug uniqueness
- tenant asset external ID uniqueness
- tenant finding fingerprint uniqueness
- tenant finding business risk sort
- tenant remediation status lookup
- tenant audit time sort

## 12. UI Requirements

The React app must include:

- Dashboard
- Findings
- Assets
- Attack Paths
- Remediation
- Virtual Patch
- Agentic
- Policies
- Reports
- Audit
- Operations

Each page should be operational, not a marketing page. Actions should call real FastAPI endpoints.

## 13. Security Requirements

- Apply security headers.
- Apply local rate limiting.
- Keep connector execution dry-run by default.
- Avoid raw secret persistence.
- Keep model output advisory.
- Treat before/after attack-path risk as decision support, not execution approval.
- Require approvals for production-risk actions.
- Preserve audit records for high-impact events.

## 14. Production Readiness Requirements

Before live enterprise deployment, configure:

- managed MongoDB
- external secret manager
- enterprise SSO/OIDC
- immutable evidence storage
- queue-backed workers
- OpenTelemetry tracing
- alert routing
- centralized rate limits
- production policy configuration
- connector credentials
- backup and recovery process

## 15. Success Metrics

- ingestion success rate
- duplicate reduction
- percent of findings mapped to assets
- scanner-family graph readiness
- exploit-signal and remediation-signal coverage
- customer-ready attack paths
- executive attack-path escalations
- subject-maturity score
- development release-confidence score
- simulation coverage
- approval coverage
- evidence coverage
- business risk reduction
- average before/after attack-path risk delta
- critical vulnerability-chain reduction
- virtual patch candidate coverage
- path breaker coverage
- agentic readiness score
- audit completeness

## 16. Roadmap

### Phase 0: Prototype

- Mock ingestion
- Findings dashboard
- Asset mapping
- Basic risk scoring
- One simulation type
- Plan generation

### Phase 1: Production MVP

- Multi-tenant backend
- JSON and CSV ingestion
- MongoDB persistence
- Remediation queue
- Simulation engine v1
- Approval workflow
- Evidence and audit trail
- Agentic planner v1

### Phase 2: Enterprise Readiness

- SSO
- Advanced RBAC
- ServiceNow integration
- More scanner integrations
- Advanced reporting
- Audit hardening
- Scale improvements

### Phase 3: Automation Expansion

- CI/CD execution hooks
- Kubernetes rollout automation
- Cloud remediation automation
- IAM policy automation
- Risk-based auto-approval policies

### Phase 4: Autonomous Remediation Governance

- Policy-governed automated fixes
- Continuous simulation
- Predictive risk modeling
- Self-updating remediation campaigns
- Advanced AI planning and verification
