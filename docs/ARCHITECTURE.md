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
- `attack_paths.py`: vulnerability chaining, attack-path construction, difficulty scoring, before/after remediation risk, and report snapshots.
- `agentic.py`: tenant context, tool registry, safety rails, report persistence, audit logging.
- `model_providers.py`: LLM, SLM, gateway, and deterministic fallback abstraction.
- `dashboard.py`: dashboard and asset graph aggregations.

Attack-path construction uses a logical graph approach: canonical findings are grouped by asset, asset graph reachability supplies path edges, exposed and initial-access assets become entry points, production or crown-jewel assets become targets, and bounded simple paths are converted into vulnerability chains. Each path receives a difficulty band, before-remediation risk, after-remediation residual risk, and recommended path breakers.

Mongo indexes enforce tenant-scoped uniqueness for assets, findings, source findings, and query-critical collections.
