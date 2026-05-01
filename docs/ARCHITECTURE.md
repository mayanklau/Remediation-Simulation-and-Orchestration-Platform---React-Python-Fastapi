# Architecture

The refactor uses React + Vite for the frontend, FastAPI for the backend, and MongoDB for persistence.

The backend keeps tenant-scoped collections for tenants, assets, findings, remediation actions, simulations, workflows, policies, reports, connector runs, and audit events. Mongo indexes enforce uniqueness for tenant assets and finding fingerprints.

The agentic runtime supports deterministic fallback and model gateway integration while keeping live execution dry-run by default.
