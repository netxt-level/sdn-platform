import asyncio
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from app.api.analyzer import router as analyzer_router
from app.api.dashboard import router as dashboard_router
from app.api.controller import router as controller_router
from app.api.flows import router as flows_router
from app.api.path import router as path_router
from app.api.security import router as security_router
from app.api.settings import router as settings_router
from app.api.ws import router as ws_router
from app.db.elasticsearch import create_elasticsearch_indices
from app.core.auth import require_admin_api_key
from app.core.config import settings
from app.middleware.body_size import RequestBodySizeLimitMiddleware
from app.services.flow_reconciler import FlowReconciler


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_elasticsearch_indices()
    reconciler = FlowReconciler(
        interval_seconds=settings.flow_reconcile_interval_seconds,
    )
    task = asyncio.create_task(reconciler.run())
    try:
        yield
    finally:
        reconciler.stop()
        await task

app = FastAPI(
    title="SDN Platform API",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(RequestBodySizeLimitMiddleware)

app.include_router(analyzer_router)
app.include_router(
    dashboard_router,
    prefix="/api/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(require_admin_api_key)],
)
app.include_router(
    controller_router,
    prefix="/api/controller",
    tags=["controller"],
    dependencies=[Depends(require_admin_api_key)],
)
app.include_router(
    flows_router,
    prefix="/api/flows",
    tags=["flows"],
    dependencies=[Depends(require_admin_api_key)],
)
app.include_router(
    path_router,
    prefix="/api/path",
    tags=["path"],
    dependencies=[Depends(require_admin_api_key)],
)
app.include_router(
    security_router,
    prefix="/api/security",
    tags=["security"],
)
app.include_router(
    settings_router,
    prefix="/api/settings",
    tags=["settings"],
    dependencies=[Depends(require_admin_api_key)],
)
app.include_router(
    ws_router,
    prefix="/ws",
    tags=["websocket"],
)

@app.get("/health")
def health_check():
    return {
        "status": "ok",
    }
