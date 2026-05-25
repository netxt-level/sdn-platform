from fastapi import FastAPI

from app.api.analyzer import router as analyzer_router
from app.db.elasticsearch import create_elasticsearch_indices


app = FastAPI(title="SDN Platform API")


@app.on_event("startup")
def startup():
    create_elasticsearch_indices()


app.include_router(analyzer_router)
