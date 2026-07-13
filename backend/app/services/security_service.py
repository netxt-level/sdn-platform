from __future__ import annotations

import asyncio
from typing import Any

from app.core.websocket import manager
from app.repositories.flow_repository import FlowRepository
from app.repositories.security_event_repository import SecurityEventRepository
from app.repositories.security_response_repository import SecurityResponseRepository


class SecurityService:
    def __init__(
        self,
        security_event_repository: SecurityEventRepository | None = None,
        security_response_repository: SecurityResponseRepository | None = None,
        flow_repository: FlowRepository | None = None,
    ):
        self.security_event_repository = (
            security_event_repository or SecurityEventRepository()
        )
        self.security_response_repository = (
            security_response_repository or SecurityResponseRepository()
        )
        self.flow_repository = flow_repository or FlowRepository()

    def get_events(self, limit: int) -> dict[str, Any]:
        return {
            "limit": limit,
            "items": self.security_event_repository.list_security_events(limit),
        }

    def get_responses(self, limit: int) -> dict[str, Any]:
        return {
            "limit": limit,
            "items": self.security_response_repository.list_responses(limit),
        }

    async def receive_events(self, payload: dict[str, Any]) -> None:
        events = payload.get("events", [])
        await asyncio.to_thread(
            self.security_event_repository.save_security_events,
            events,
        )
        responses, flow_rules = await asyncio.to_thread(
            self._create_responses_and_flow_rules,
            events,
        )

        await manager.broadcast({
            "type": "security_events",
            "data": {
                **payload,
                "security_responses": responses,
                "flow_rules": flow_rules,
            },
        })

    def _create_responses_and_flow_rules(
        self,
        events: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        responses = []
        flow_rules = []

        for event in events:
            response = self.security_response_repository.get_or_create_from_event(
                event,
            )
            responses.append(response)

            flow_rule = self.flow_repository.get_or_create_from_mitigation(
                event=event,
                security_response_id=response["id"],
            )
            if flow_rule is not None:
                linked_response = self.security_response_repository.link_flow_rule(
                    response["id"],
                    flow_rule,
                )
                if linked_response is not None:
                    responses[-1] = linked_response
                flow_rules.append(flow_rule)

        return responses, flow_rules
