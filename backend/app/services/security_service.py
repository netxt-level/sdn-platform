from __future__ import annotations

import asyncio
from datetime import datetime
from datetime import timezone
from typing import Any

from app.core.websocket import manager
from app.repositories.flow_repository import FlowRepository
from app.repositories.security_event_repository import SecurityEventRepository
from app.repositories.security_response_repository import SecurityResponseRepository
from app.services.flow_service import FlowService


class SecurityService:
    def __init__(
        self,
        security_event_repository: SecurityEventRepository | None = None,
        security_response_repository: SecurityResponseRepository | None = None,
        flow_repository: FlowRepository | None = None,
        flow_service: FlowService | None = None,
    ):
        self.security_event_repository = (
            security_event_repository or SecurityEventRepository()
        )
        self.security_response_repository = (
            security_response_repository or SecurityResponseRepository()
        )
        self.flow_repository = flow_repository or FlowRepository()
        self.flow_service = flow_service or FlowService(
            flow_repository=self.flow_repository,
        )

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
        responses, flow_rules = await asyncio.to_thread(
            self._process_events,
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

    def _process_events(
        self,
        events: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        self.security_event_repository.save_security_events(events)
        return self._create_responses_and_flow_rules(events)

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
                response, flow_rule = self._apply_automatic_response(
                    response,
                    flow_rule,
                )
                responses[-1] = response
                flow_rules.append(flow_rule)

        return responses, flow_rules

    def _apply_automatic_response(
        self,
        response: dict[str, Any],
        flow_rule: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if flow_rule.get("status") in {"APPLIED", "APPLYING"}:
            return response, flow_rule

        requested_at = datetime.now(timezone.utc)
        applying_response = self.security_response_repository.update_status(
            response["id"],
            status="APPLYING",
            decision_reason="automatically applying analyzer mitigation",
            approved_by="automatic-policy",
            approved_at=requested_at,
            requested_at=requested_at,
        )
        applied_flow = self.flow_service.apply_flow(flow_rule)
        completed_at = datetime.now(timezone.utc)
        applied = applied_flow["status"] == "APPLIED"
        response_payload = {
            "flow_rule_id": applied_flow["id"],
            "controller_rule_id": applied_flow.get("controller_rule_id"),
            "controller_response": applied_flow.get("controller_response"),
        }
        final_response = self.security_response_repository.update_status(
            response["id"],
            status="APPLIED" if applied else "FAILED",
            response_payload=response_payload,
            decision_reason=(
                "analyzer mitigation applied automatically"
                if applied
                else "automatic analyzer mitigation failed"
            ),
            approved_by="automatic-policy",
            approved_at=requested_at,
            requested_at=requested_at,
            completed_at=completed_at,
            error_message=applied_flow.get("error_message"),
        )
        return (
            final_response or applying_response or response,
            applied_flow,
        )
