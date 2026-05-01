# Security Model

- Tenant context is explicit through `x-tenant-id` or isolated default tenant creation.
- Connector calls default to dry-run.
- Agentic model output is advisory and cannot bypass policy gates.
- Raw secrets are not included in model prompts.
- Security headers are applied through middleware.
- Rate limiting is provided as an in-memory local guard and should be backed by Redis or gateway limits in production.
- Production assets require simulation, approval, rollback, and evidence gates before live execution.
- Evidence sealing and immutable storage hooks are represented in the API surface for enterprise deployment.

