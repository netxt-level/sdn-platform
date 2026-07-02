from app.repositories.flow_repository import FlowRepository


class FlowService:
    def __init__(self, flow_repository: FlowRepository | None = None):
        self.flow_repository = flow_repository or FlowRepository()

    def get_flows(self, src_ip: str | None = None) -> dict:
        return {
            "items": self.flow_repository.list_flows(src_ip),
        }
