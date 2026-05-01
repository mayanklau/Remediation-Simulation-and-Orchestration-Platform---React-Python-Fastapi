# Security Model

- Tenant context is explicit through `x-tenant-id` or isolated default tenant creation.
- Connector calls default to dry-run.
- Agentic model output is advisory and cannot bypass policy gates.
- Raw secrets are not included in model prompts.
- Attack-path analytics use tenant-scoped normalized findings and asset graph data only; scanner credentials and raw secrets are never required for path construction.
- Security headers are applied through middleware.
- Rate limiting is provided as an in-memory local guard and should be backed by Redis or gateway limits in production.
- Production assets require simulation, approval, rollback, and evidence gates before live execution.
- Before/after attack-path risk is decision support for prioritization, path breakers, approval, and evidence. It does not bypass workflow gates.
- Evidence sealing and immutable storage hooks are represented in the API surface for enterprise deployment.
