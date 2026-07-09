from app.repositories.flow_repository import FlowRepository


class FlowService:
    def __init__(self, flow_repository: FlowRepository | None = None):
        self.flow_repository = flow_repository or FlowRepository()

    def get_flows(self, src_ip: str | None = None) -> dict:
        return {
            "items": self.flow_repository.list_flows(src_ip),
        }

    def create_flow(self, data: dict) -> dict:
        return self.flow_repository.create_manual_flow(
            switch_id=data.get("switch_id"),
            match=data["match"],
            action=data["action"],
            priority=data["priority"],
            idle_timeout=data.get("idle_timeout"),
            hard_timeout=data.get("hard_timeout"),
            rate_limit_pps=data.get("rate_limit_pps"),
        )
