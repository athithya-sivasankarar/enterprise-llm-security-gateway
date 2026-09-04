from contextlib import asynccontextmanager
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST

from backend.api.chat import router as chat_router
from backend.api.dashboard import router as dashboard_router
from backend.api.rbac import router as rbac_router
from backend.api.security_events import router as security_events_router
from backend.api.policies import router as policies_router
from backend.api.security_tests import router as security_tests_router
from backend.api.campaigns import router as campaigns_router
from backend.api.scheduler import router as scheduler_router
from backend.api.alerts import router as alerts_router
from backend.api.reports import router as reports_router
from backend.api.incidents import router as incidents_router
from backend.api.assets import router as assets_router
from backend.api.controls import router as controls_router
from backend.api.threatintel import router as threatintel_router
from backend.api.exposures import router as exposures_router
from backend.api.governance import router as governance_router
from backend.db.database import init_db, AsyncSessionLocal
from backend.services.policy_service import init_default_policy_if_empty
from backend.scheduler.worker import start_scheduler_worker, stop_scheduler_worker
from backend.observability.logging import setup_structured_logging
from backend.observability.tracing import init_tracing
from backend.observability.metrics import generate_prometheus_metrics


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize Structured JSON logging and OpenTelemetry
    setup_structured_logging()
    init_tracing(app)
    
    # Initialize PostgreSQL database schema and columns
    db_ok = await init_db()
    if db_ok:
        try:
            async with AsyncSessionLocal() as session:
                await init_default_policy_if_empty(session)
        except Exception:
            pass

    # Start background campaign scheduler if enabled
    start_scheduler_worker()

    yield

    # Gracefully stop scheduler worker on shutdown
    await stop_scheduler_worker()


app = FastAPI(
    title="Enterprise LLM Security Gateway",
    description="Security gateway, Policy Engine, RBAC enforcement, Prometheus metrics, and SOC monitoring for enterprise LLM interactions",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for local SOC dashboard interface
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"]
)

# Register API routers
app.include_router(chat_router)
app.include_router(dashboard_router)
app.include_router(rbac_router)
app.include_router(security_events_router)
app.include_router(policies_router)
app.include_router(security_tests_router)
app.include_router(campaigns_router)
app.include_router(scheduler_router)
app.include_router(alerts_router)
app.include_router(reports_router)
app.include_router(incidents_router)
app.include_router(assets_router)
app.include_router(controls_router)
app.include_router(threatintel_router)
app.include_router(exposures_router)
app.include_router(governance_router)







@app.get("/")
async def root():
    return {
        "message": "Enterprise LLM Security Gateway",
        "status": "online"
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy"
    }


@app.get("/metrics")
async def metrics():
    """
    Expose Prometheus-compatible application and security metrics.
    Never exposes raw prompts, responses, or API keys.
    """
    return Response(
        content=generate_prometheus_metrics(),
        media_type=CONTENT_TYPE_LATEST
    )
