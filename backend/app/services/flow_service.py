from datetime import datetime
from datetime import timezone

from app.clients.controller import ControllerClient
from app.clients.controller import ControllerClientError
from app.repositories.flow_repository import FlowRepository


class FlowService:
    def __init__(
        self,
        flow_repository: FlowRepository | None = None,
        controller_client: ControllerClient | None = None,
    ):
        self.flow_repository = flow_repository or FlowRepository()
        self.controller_client = controller_client or ControllerClient()

    def get_flows(self, src_ip: str | None = None) -> dict:
        return {
            "items": self.flow_repository.list_flows(src_ip),
        }

    def create_flow(self, data: dict) -> dict:
        flow_rule = self.flow_repository.create_manual_flow(
            switch_id=data.get("switch_id"),
            match=data["match"],
            action=data["action"],
            priority=data["priority"],
            idle_timeout=data.get("idle_timeout"),
            hard_timeout=data.get("hard_timeout"),
            rate_limit_pps=data.get("rate_limit_pps"),
        )
        requested_at = datetime.now(timezone.utc)
        applying = self.flow_repository.update_status(
            flow_rule["id"],
            status="APPLYING",
            requested_at=requested_at,
        )

        try:
            controller_response = self.controller_client.install_flow_rule(
                applying or flow_rule
            )
        except ControllerClientError as error:
            return self.flow_repository.update_status(
                flow_rule["id"],
                status="FAILED",
                controller_response=error.response,
                error_message=str(error),
                requested_at=requested_at,
            )

        return self.flow_repository.update_status(
            flow_rule["id"],
            status="APPLIED",
            controller_rule_id=controller_response["controller_rule_id"],
            controller_response=controller_response,
            requested_at=requested_at,
            applied_at=datetime.now(timezone.utc),
        )
