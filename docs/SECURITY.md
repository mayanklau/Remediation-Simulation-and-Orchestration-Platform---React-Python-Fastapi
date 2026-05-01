# Security Model

- Tenant context is resolved from `x-tenant-id` or a default local tenant.
- Connector and worker execution defaults to dry-run.
- Model output is advisory and cannot bypass deterministic gates.
- Raw secrets are not sent to prompts.
- Security headers and local rate limits are applied through middleware.
- Production execution requires simulation, approval, rollback, and evidence controls.
