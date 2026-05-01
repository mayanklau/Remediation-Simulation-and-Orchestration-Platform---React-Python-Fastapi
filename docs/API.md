# API Reference

All routes are under `/api`. Tenant context is resolved from `x-tenant-id`; if missing, the default tenant is created.

The API mirrors the original Remediation Twin surface while using FastAPI and MongoDB.

## Core

- `GET /api/health`
- `GET /api/tenants`
- `POST /api/tenants`
- `GET /api/dashboard`
- `GET /api/asset-graph`
- `GET /api/attack-paths`
- `POST /api/attack-paths`
- `GET /api/observability`

## Ingestion

- `POST /api/ingest/json`
- `POST /api/ingest/csv`
- `POST /api/mock-ingest`

## Remediation

- `GET /api/remediation-actions`
- `POST /api/remediation-actions/{action_id}/simulate`
- `POST /api/remediation-actions/{action_id}/plan`
- `POST /api/remediation-actions/{action_id}/workflow`
- `GET /api/simulations`
- `GET /api/workflows`

## Governance And Agentic

- `GET /api/virtual-patching`
- `POST /api/virtual-patching`
- `GET /api/attack-paths`
- `POST /api/attack-paths`
- `GET /api/agentic`
- `POST /api/agentic`
- `GET /api/policies`
- `POST /api/policies`
- `POST /api/governance/continuous-simulation`
- `GET /api/governance/predictive-risk`
- `POST /api/governance/apply-fix`

## Operations

- `POST /api/connectors/live`
- `POST /api/workers/run`
- `GET /api/reports`
- `GET /api/audit`

## Attack Path Analytics

`GET /api/attack-paths` returns scanner-normalized vulnerability chains, attack paths, path difficulty, before-remediation risk, after-remediation residual risk, recommended path breakers, and the construction method.

`POST /api/attack-paths` accepts:

```json
{ "action": "snapshot" }
```

The snapshot action stores the model in `report_snapshots` as `attack_path_analytics` and writes an audit event. Inputs are normalized from the canonical finding model, so Tenable, Qualys, Wiz, Snyk, GitHub Advanced Security, AWS Security Hub, Kubernetes, IAM, cloud posture, compliance, CSV, and API scanners can contribute chain steps.
