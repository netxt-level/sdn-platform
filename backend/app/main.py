from fastapi import FastAPI

from app.api.analyzer import router as analyzer_router
from app.api.analyzers import router as analyzers_router
from app.api.dashboard import router as dashboard_router
from app.api.flows import router as flows_router
from app.api.ws import router as ws_router

app = FastAPI(
    title="SDN Platform API",
)

app.include_router(analyzer_router)
app.include_router(
    analyzers_router,
    prefix="/api/analyzers",
    tags=["analyzers"],
)
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
    ws_router,
    prefix="/ws",
    tags=["websocket"],
)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
    }
