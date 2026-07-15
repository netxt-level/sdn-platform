"""Read-only REST API for controller health and connected switches."""

from threading import Thread

from fastapi import FastAPI
import uvicorn


def build_health_response(datapaths, settings):
    return {
        "status": "ready",
        "openflow_version": "1.3",
        "openflow_port": settings.openflow_port,
        "rest_port": settings.rest_port,
        "connected_switches": len(datapaths),
    }


def build_switches_response(datapaths):
    return {
        "switches": [
            {
                "dpid": f"{datapath.id:016x}",
                "state": "connected",
                "table_miss_installed": True,
            }
            for datapath in datapaths.snapshot()
        ]
    }


def create_api(datapaths, settings):
    app = FastAPI(
        title="SDN Controller API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/health")
    def health():
        return build_health_response(datapaths, settings)

    @app.get("/switches")
    def switches():
        return build_switches_response(datapaths)

    return app


class ControllerApiServer:
    """Run Uvicorn in a native daemon thread beside OS-Ken."""

    def __init__(self, datapaths, settings):
        config = uvicorn.Config(
            app=create_api(datapaths, settings),
            host=settings.rest_host,
            port=settings.rest_port,
            log_level="warning",
            access_log=False,
            lifespan="off",
        )
        self._server = uvicorn.Server(config)
        self._thread = Thread(
            target=self._server.run,
            name="controller-rest-api",
            daemon=True,
        )

    def start(self):
        self._thread.start()

    def stop(self):
        self._server.should_exit = True
        if self._thread.is_alive():
            self._thread.join(timeout=5)

    @property
    def is_alive(self):
        return self._thread.is_alive()
