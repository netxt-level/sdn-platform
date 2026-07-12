from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app.api.analyzer import router as analyzer_router
from app.api.dashboard import router as dashboard_router
from app.api.flows import router as flows_router
from app.api.path import router as path_router
from app.api.security import router as security_router
from app.api.ws import router as ws_router
from app.db.elasticsearch import create_elasticsearch_indices
from app.db.elasticsearch import is_elasticsearch_ready
from app.db.influxdb import is_influxdb_ready
from app.db.postgres import is_postgres_ready
from app.middleware.body_size import RequestBodySizeLimitMiddleware

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        create_elasticsearch_indices()
    except Exception:
        logger.warning(
            "Elasticsearch 준비가 늦어 보안 이벤트 인덱스 초기화를 건너뜁니다.",
            exc_info=True,
        )
    yield

app = FastAPI(
    title="SDN Platform API",
    lifespan=lifespan,
)
app.add_middleware(RequestBodySizeLimitMiddleware)

app.include_router(analyzer_router)
app.include_router(
    dashboard_router,
    prefix="/api/dashboard",
    tags=["dashboard"],
)
app.include_router(
    flows_router,
    prefix="/api/flows",
    tags=["flows"],
)
app.include_router(
    path_router,
    prefix="/api/path",
    tags=["path"],
)
app.include_router(
    security_router,
    prefix="/api/security",
    tags=["security"],
)
app.include_router(
    ws_router,
    prefix="/ws",
    tags=["websocket"],
)

@app.get("/health")
def health_check():
    return health_live()


@app.get("/health/live")
def health_live():
    return {
        "status": "ok",
    }


@app.get("/health/ready")
def health_ready():
    checks = {
        "postgres": is_postgres_ready(),
        "influxdb": is_influxdb_ready(),
        "elasticsearch": is_elasticsearch_ready(),
    }
    status = "ok" if all(checks.values()) else "degraded"
    body = {
        "status": status,
        **{
            name: "ok" if ready else "error"
            for name, ready in checks.items()
        },
    }

    if status == "ok":
        return body

    return JSONResponse(status_code=503, content=body)
