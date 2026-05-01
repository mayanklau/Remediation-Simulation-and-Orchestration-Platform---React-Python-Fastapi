# Architecture

The refactored platform is split into:

- `frontend`: React + Vite application.
- `backend`: FastAPI service.
- `MongoDB`: persistence for all platform collections.

The backend keeps business logic in service modules:

- `ingestion.py`: normalization, deduplication, asset upsert, source-finding tracking, action generation.
- `risk.py`: technical and business risk scoring.
- `remediation.py`: simulation, plan generation, and workflow creation.
- `virtual_patching.py`: virtual patch candidates and path breaker activation.
- `agentic.py`: tenant context, tool registry, safety rails, report persistence, audit logging.
- `model_providers.py`: LLM, SLM, gateway, and deterministic fallback abstraction.
- `dashboard.py`: dashboard and asset graph aggregations.

Mongo indexes enforce tenant-scoped uniqueness for assets, findings, source findings, and query-critical collections.

