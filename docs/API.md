# API Reference

All routes are under `/api`. Tenant context is resolved from `x-tenant-id`; if missing, the default tenant is created.

The API mirrors the original Remediation Twin surface while using FastAPI and MongoDB.

## Core

- `GET /api/health`
- `GET /api/tenants`
- `POST /api/tenants`
- `GET /api/dashboard`
- `GET /api/asset-graph`
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

