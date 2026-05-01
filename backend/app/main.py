from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.auth import AuthzMiddleware
from app.database import lifespan
from app.routers import core, governance, ingestion, inventory, remediation
from app.security import InMemoryRateLimitMiddleware, SecurityHeadersMiddleware


app = FastAPI(
    title="Remediation Twin API",
    description="Python FastAPI and MongoDB backend for remediation simulation, orchestration, virtual patching, and agentic governance.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(InMemoryRateLimitMiddleware)
app.add_middleware(AuthzMiddleware)

for router in [core.router, ingestion.router, inventory.router, remediation.router, governance.router]:
    app.include_router(router, prefix="/api")


@app.get("/")
async def root():
    return {"service": "Remediation Twin API", "docs": "/docs", "health": "/api/health"}
