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
        policy_events = [self._apply_response_policy(event) for event in events]
        self.security_event_repository.save_security_events(policy_events)
        responses, flow_rules = self._create_responses_and_flow_rules(policy_events)
        applied_event_ids = {
            flow_rule.get("source_event_id")
            for flow_rule in flow_rules
            if flow_rule.get("status") == "APPLIED"
        }
        for event in policy_events:
            if event.get("event_id") in applied_event_ids:
                self.security_event_repository.update_status(
                    event["event_id"],
                    "blocked",
                )
        return responses, flow_rules

    def respond_to_event(
        self,
        event_id: str,
        action: str,
    ) -> dict[str, Any]:
        event = self.security_event_repository.get_security_event(event_id)
        if event is None:
            raise KeyError(event_id)

        if action == "ignore":
            updated = self.security_event_repository.update_status(event_id, "ignored")
            return {"event": updated, "response": None, "flow_rule": None}
        if action == "resolve":
            updated = self.security_event_repository.update_status(event_id, "resolved")
            return {"event": updated, "response": None, "flow_rule": None}

        blocking_event = self._with_drop_mitigation(event)
        responses, flow_rules = self._create_responses_and_flow_rules(
            [blocking_event],
            approved_by="manual-operator",
        )
        flow_rule = flow_rules[0] if flow_rules else None
        status = "blocked" if flow_rule and flow_rule.get("status") == "APPLIED" else "detected"
        updated = self.security_event_repository.update_status(event_id, status)
        return {
            "event": updated,
            "response": responses[0] if responses else None,
            "flow_rule": flow_rule,
        }

    @staticmethod
    def _apply_response_policy(event: dict[str, Any]) -> dict[str, Any]:
        policy_event = dict(event)
        severity = str(
            event.get("severity")
            or ("high" if event.get("mitigation") else "medium")
        ).lower()
        if severity == "critical":
            policy_event = SecurityService._with_drop_mitigation(policy_event)
        elif severity != "high":
            policy_event["mitigation"] = None
        return policy_event

    @staticmethod
    def _with_drop_mitigation(event: dict[str, Any]) -> dict[str, Any]:
        policy_event = dict(event)
        protocol_number = {
            "ICMP": 1,
            "TCP": 6,
            "UDP": 17,
        }.get(str(event.get("protocol", "")).upper())
        match = {
            "eth_type": 2048,
            "ipv4_src": event.get("src_ip"),
            "ipv4_dst": event.get("dst_ip"),
        }
        if protocol_number is not None:
            match["ip_proto"] = protocol_number
        policy_event["recommended_action"] = "drop"
        policy_event["mitigation"] = {
            "action": "DROP",
            "target": "flow",
            "match": {
                key: value
                for key, value in match.items()
                if value is not None
            },
            "priority": 600,
            "idle_timeout": 60,
            "hard_timeout": 300,
        }
        return policy_event

    def _create_responses_and_flow_rules(
        self,
        events: list[dict[str, Any]],
        *,
        approved_by: str = "automatic-policy",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        responses = []
        flow_rules = []

        for event in events:
            response = self.security_response_repository.get_or_create_from_event(
                event,
            )
            responses.append(response)

            self._remove_superseded_rate_limit(event)

            flow_rule = self.flow_repository.get_or_create_from_mitigation(
                event=event,
                security_response_id=response["id"],
            )
            if flow_rule is not None:
                response, flow_rule = self._apply_automatic_response(
                    response,
                    flow_rule,
                    approved_by=approved_by,
                )
                responses[-1] = response
                flow_rules.append(flow_rule)

        return responses, flow_rules

    def _remove_superseded_rate_limit(self, event: dict[str, Any]) -> None:
        mitigation = event.get("mitigation") or {}
        fingerprint = event.get("event_fingerprint")
        if mitigation.get("action") != "DROP" or not fingerprint:
            return
        for flow_rule in self.flow_repository.list_by_fingerprint(fingerprint):
            if (
                flow_rule.get("action") == "RATE_LIMIT"
                and flow_rule.get("status") not in {"REMOVED", "EXPIRED"}
            ):
                self.flow_service.delete_flow(flow_rule["id"])

    def _apply_automatic_response(
        self,
        response: dict[str, Any],
        flow_rule: dict[str, Any],
        *,
        approved_by: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if flow_rule.get("status") in {"APPLIED", "APPLYING"}:
            return response, flow_rule

        requested_at = datetime.now(timezone.utc)
        automatic = approved_by == "automatic-policy"
        applying_response = self.security_response_repository.update_status(
            response["id"],
            status="APPLYING",
            decision_reason=(
                "automatically applying analyzer mitigation"
                if automatic
                else "applying mitigation requested by manual operator"
            ),
            approved_by=approved_by,
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
                (
                    "analyzer mitigation applied automatically"
                    if automatic
                    else "mitigation applied by manual operator"
                )
                if applied
                else (
                    "automatic analyzer mitigation failed"
                    if automatic
                    else "manual mitigation failed"
                )
            ),
            approved_by=approved_by,
            approved_at=requested_at,
            requested_at=requested_at,
            completed_at=completed_at,
            error_message=applied_flow.get("error_message"),
        )
        return (
            final_response or applying_response or response,
            applied_flow,
        )
