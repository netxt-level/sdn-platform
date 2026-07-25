from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db.session import SessionLocal
from app.models.flow_rule import FlowRule


def _to_dict(flow_rule: FlowRule) -> dict[str, Any]:
    match = flow_rule.match or {}

    return {
        "id": flow_rule.id,
        "source_event_id": flow_rule.source_event_id,
        "source_event_fingerprint": flow_rule.source_event_fingerprint,
        "security_response_id": flow_rule.security_response_id,
        "analyzer_id": flow_rule.analyzer_id,
        "switch_id": flow_rule.switch_id,
        "target": flow_rule.target,
        "action": flow_rule.action,
        "match": match,
        "priority": flow_rule.priority,
        "idle_timeout": flow_rule.idle_timeout,
        "hard_timeout": flow_rule.hard_timeout,
        "rate_limit_pps": flow_rule.rate_limit_pps,
        "status": flow_rule.status,
        "controller_rule_id": flow_rule.controller_rule_id,
        "controller_response": flow_rule.controller_response,
        "error_message": flow_rule.error_message,
        "requested_at": flow_rule.requested_at,
        "applied_at": flow_rule.applied_at,
        "removed_at": flow_rule.removed_at,
        "created_at": flow_rule.created_at,
        "updated_at": flow_rule.updated_at,
        "timestamp": flow_rule.created_at,
        "src_ip": match.get("ipv4_src"),
        "dst_ip": match.get("ipv4_dst"),
        "protocol": _protocol_name(match.get("ip_proto")),
    }


def _protocol_name(ip_proto: Any) -> str | None:
    if ip_proto == 1:
        return "ICMP"
    if ip_proto == 6:
        return "TCP"
    if ip_proto == 17:
        return "UDP"
    if ip_proto is None:
        return None

    return str(ip_proto)


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None

    return int(value)


class FlowRepository:
    def list_flows(self, src_ip: str | None = None) -> list[dict[str, Any]]:
        stmt = select(FlowRule).order_by(FlowRule.created_at.desc())
        if src_ip:
            stmt = stmt.where(FlowRule.match["ipv4_src"].as_string() == src_ip)

        with SessionLocal() as session:
            flow_rules = session.execute(stmt).scalars().all()

        return [_to_dict(flow_rule) for flow_rule in flow_rules]

    def get_flow(self, flow_rule_id: str) -> dict[str, Any] | None:
        with SessionLocal() as session:
            flow_rule = session.get(FlowRule, flow_rule_id)
            return None if flow_rule is None else _to_dict(flow_rule)

    def delete_flow(self, flow_rule_id: str) -> dict[str, Any] | None:
        with SessionLocal.begin() as session:
            flow_rule = session.get(FlowRule, flow_rule_id)
            if flow_rule is None:
                return None

            deleted = _to_dict(flow_rule)
            session.delete(flow_rule)
            return deleted

    def list_by_fingerprint(self, fingerprint: str) -> list[dict[str, Any]]:
        stmt = select(FlowRule).where(
            FlowRule.source_event_fingerprint == fingerprint,
        )
        with SessionLocal() as session:
            flow_rules = session.execute(stmt).scalars().all()
        return [_to_dict(flow_rule) for flow_rule in flow_rules]

    def create_manual_flow(
        self,
        *,
        switch_id: str | None,
        match: dict[str, Any],
        action: str,
        priority: int,
        analyzer_id: str = "manual",
        target: str = "flow",
        idle_timeout: int | None = None,
        hard_timeout: int | None = None,
        rate_limit_pps: int | None = None,
    ) -> dict[str, Any]:
        # 수동 추가는 컨트롤러 설치가 아니라 DB에 PENDING 후보를 생성하는 단계다.
        with SessionLocal.begin() as session:
            flow_rule = FlowRule(
                analyzer_id=analyzer_id,
                switch_id=switch_id,
                target=target,
                action=action.upper(),
                match=match,
                priority=priority,
                idle_timeout=idle_timeout,
                hard_timeout=hard_timeout,
                rate_limit_pps=rate_limit_pps,
            )
            session.add(flow_rule)
            session.flush()

            return _to_dict(flow_rule)

    def get_or_create_from_mitigation(
        self,
        *,
        event: dict[str, Any],
        security_response_id: str,
    ) -> dict[str, Any] | None:
        mitigation = event.get("mitigation")
        if not mitigation:
            return None

        action = str(mitigation["action"]).upper()
        event_id = event.get("event_id")
        fingerprint = event.get("event_fingerprint")

        try:
            with SessionLocal.begin() as session:
                flow_rule = None
                if event_id:
                    stmt = select(FlowRule).where(
                        FlowRule.source_event_id == event_id,
                        FlowRule.action == action,
                    )
                    flow_rule = session.execute(stmt).scalar_one_or_none()

                if flow_rule is None:
                    flow_rule = FlowRule(
                        source_event_id=event_id,
                        source_event_fingerprint=fingerprint,
                        security_response_id=security_response_id,
                        analyzer_id=event["analyzer_id"],
                        switch_id=mitigation.get("switch_id"),
                        target=mitigation.get("target", "flow"),
                        action=action,
                        match=mitigation.get("match") or {},
                        priority=int(mitigation["priority"]),
                        idle_timeout=_optional_int(mitigation.get("idle_timeout")),
                        hard_timeout=_optional_int(mitigation.get("hard_timeout")),
                        rate_limit_pps=_optional_int(
                            mitigation.get("rate_limit_pps")
                        ),
                    )
                    session.add(flow_rule)
                    session.flush()

                return _to_dict(flow_rule)
        except IntegrityError:
            if not event_id:
                raise
            with SessionLocal() as session:
                stmt = select(FlowRule).where(
                    FlowRule.source_event_id == event_id,
                    FlowRule.action == action,
                )
                flow_rule = session.execute(stmt).scalar_one_or_none()
            if flow_rule is None:
                raise
            return _to_dict(flow_rule)

    def update_status(
        self,
        flow_rule_id: str,
        *,
        status: str,
        controller_rule_id: str | None = None,
        controller_response: dict[str, Any] | None = None,
        switch_id: str | None = None,
        error_message: str | None = None,
        requested_at: datetime | None = None,
        applied_at: datetime | None = None,
        removed_at: datetime | None = None,
    ) -> dict[str, Any] | None:
        with SessionLocal.begin() as session:
            flow_rule = session.get(FlowRule, flow_rule_id)
            if flow_rule is None:
                return None

            flow_rule.status = status
            flow_rule.controller_rule_id = controller_rule_id
            flow_rule.controller_response = controller_response
            if switch_id is not None:
                flow_rule.switch_id = switch_id
            flow_rule.error_message = error_message
            flow_rule.requested_at = requested_at
            flow_rule.applied_at = applied_at
            flow_rule.removed_at = removed_at

            return _to_dict(flow_rule)
