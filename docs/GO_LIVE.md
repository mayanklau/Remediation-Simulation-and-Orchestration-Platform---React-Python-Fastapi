# Go-Live Runbook

This app includes the production launch path. Developers only need to provide customer-specific values and deploy.

1. Populate `.env.production.example` with real production values.
2. Run `python3 -m pytest` and `npm run build` in `frontend`.
3. Build with `docker compose -f docker-compose.prod.yml build`.
4. Start with `docker compose -f docker-compose.prod.yml up`.
5. Open `/api/go-live`, `/api/enterprise-readiness`, and `/api/production-expansion`.
6. Configure IdP, secret manager, evidence storage, telemetry, alert route, and connector credentials.
7. Run connector dry checks before live schedules.
8. Capture business, security, and platform go-live signoff.

Rollback: disable schedules, roll back API/web images, restore data only if required by the migration/index runbook, and re-run health and smoke tests.
