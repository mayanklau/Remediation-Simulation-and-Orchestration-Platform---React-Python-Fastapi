# Render And MongoDB Atlas Deployment

This repo is ready to run as a live React + FastAPI + MongoDB application.

## 1. Create MongoDB Atlas

Create an Atlas cluster, database user, network access rule, and copy the MongoDB connection string.

Use:

```bash
MONGO_URI=mongodb+srv://USER:PASSWORD@HOST/remediation_twin
MONGO_DB=remediation_twin
```

## 2. Deploy With Render Blueprint

In Render, create a new Blueprint from this GitHub repo. Render reads `render.yaml` and creates:

- `remediation-twin-fastapi-api`
- `remediation-twin-react-ui`

Set these environment variables in Render:

```bash
MONGO_URI=mongodb+srv://...
MONGO_DB=remediation_twin
ENVIRONMENT=production
SESSION_SECRET=<generated-or-strong-secret>
OIDC_ISSUER=<your-idp-issuer-or-demo-placeholder>
OIDC_CLIENT_ID=<your-idp-client-id-or-demo-placeholder>
CORS_ALLOWED_ORIGINS=https://your-frontend.onrender.com
VITE_API_BASE_URL=https://your-api.onrender.com/api
```

## 3. Backend Start Command

The backend Dockerfile starts FastAPI with Render's assigned port:

```bash
uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
```

## 4. Frontend Production Env

The React app reads:

```bash
VITE_API_BASE_URL=https://your-api.onrender.com/api
```

Set this before the frontend build. If the API URL changes, redeploy the frontend.

## 5. Health Check

Render uses:

```bash
/api/health
```

Validate manually:

```bash
API_BASE=https://your-api.onrender.com/api FRONTEND_URL=https://your-frontend.onrender.com ./scripts/validate-health.sh
```

## 6. Optional Cloud Demo Data

Only run this when you intentionally want demo records in the cloud database:

```bash
API_BASE=https://your-api.onrender.com/api ./scripts/load-demo-data.sh
```

Do not run the loader against a customer production tenant unless the customer explicitly wants seeded demo data.
