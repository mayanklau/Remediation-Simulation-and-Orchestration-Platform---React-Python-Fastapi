# Product Requirements Document: Remediation Twin React + FastAPI

## 1. Product Summary

**Product name:** Remediation Twin

**Category:** Enterprise remediation simulation, orchestration, and agentic governance platform

**Stack:** React, Python FastAPI, MongoDB

**Purpose:** Help enterprises turn security findings into prioritized, simulated, approved, auditable remediation work with virtual patching, attack-path breakers, and governed agentic planning.

## 2. Problem Statement

Enterprises have many tools that detect risk but few systems that safely coordinate remediation. Vulnerability scanners, cloud security tools, IAM analyzers, code scanners, Kubernetes platforms, and compliance systems produce overlapping findings. Teams struggle to decide what matters, who owns it, what will break if remediated, whether a compensating control is safer, and what evidence is needed.

The result is duplicated tickets, delayed fixes, risky production changes, weak audit trails, and low trust between security and engineering.

## 3. Goals

- Provide a full-stack remediation platform using React, FastAPI, and MongoDB.
- Ingest and normalize findings from multiple enterprise sources.
- Map findings to assets and business context.
- Prioritize by technical and business risk.
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

### 6.7 Run Agentic Planning

Users can run an agentic plan using a configured LLM, SLM, model gateway, or deterministic fallback. The agent returns a governed plan with tool steps and safety rails.

## 7. Functional Requirements

| Area | Requirement |
| --- | --- |
| Tenancy | Resolve tenant through `x-tenant-id`; create default local tenant when missing. |
| Ingestion | Support JSON ingestion and prototype data load. |
| Deduplication | Fingerprint findings by source, title, CVE/control, and asset. |
| Asset mapping | Upsert assets from finding payloads. |
| Risk scoring | Score by severity, exploitability, active exploitation, patch availability, exposure, criticality, and sensitivity. |
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

## 8. Agentic Requirements

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

## 9. API Requirements

Required API endpoints:

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
- `GET /api/observability`

## 10. Data Model

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

## 11. UI Requirements

The React app must include:

- Dashboard
- Findings
- Assets
- Remediation
- Virtual Patch
- Agentic
- Policies
- Reports
- Audit
- Operations

Each page should be operational, not a marketing page. Actions should call real FastAPI endpoints.

## 12. Security Requirements

- Apply security headers.
- Apply local rate limiting.
- Keep connector execution dry-run by default.
- Avoid raw secret persistence.
- Keep model output advisory.
- Require approvals for production-risk actions.
- Preserve audit records for high-impact events.

## 13. Production Readiness Requirements

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

## 14. Success Metrics

- ingestion success rate
- duplicate reduction
- percent of findings mapped to assets
- simulation coverage
- approval coverage
- evidence coverage
- business risk reduction
- virtual patch candidate coverage
- path breaker coverage
- agentic readiness score
- audit completeness

## 15. Roadmap

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
