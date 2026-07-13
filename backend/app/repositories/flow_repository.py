from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select

from app.db.session import SessionLocal
from app.models.flow_rule import FlowRule
from app.policies.flow_rule_policy import is_compatible_flow_rule


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


def _mark_reuse(flow_rule: dict[str, Any], reused: bool) -> dict[str, Any]:
    return {
        **flow_rule,
        "reused": reused,
        "flow_rule_reused": reused,
    }


class FlowRepository:
    def list_flows(
        self,
        src_ip: str | None = None,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        limit = min(max(limit, 1), 500)
        offset = max(offset, 0)
        stmt = select(FlowRule).order_by(FlowRule.created_at.desc())
        if src_ip:
            stmt = stmt.where(FlowRule.match["ipv4_src"].as_string() == src_ip)
        stmt = stmt.limit(limit).offset(offset)

        with SessionLocal() as session:
            flow_rules = session.execute(stmt).scalars().all()

        return [_to_dict(flow_rule) for flow_rule in flow_rules]

    def count_flows(self, src_ip: str | None = None) -> int:
        stmt = select(func.count()).select_from(FlowRule)
        if src_ip:
            stmt = stmt.where(FlowRule.match["ipv4_src"].as_string() == src_ip)

        with SessionLocal() as session:
            return int(session.execute(stmt).scalar_one())

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
        fingerprint = event.get("event_fingerprint")
        analyzer_id = event["analyzer_id"]
        match = mitigation.get("match") or {}
        switch_id = mitigation.get("switch_id")
        target = mitigation.get("target", "flow")

        with SessionLocal.begin() as session:
            flow_rule = None
            if fingerprint:
                stmt = (
                    select(FlowRule)
                    .where(
                        FlowRule.source_event_fingerprint == fingerprint,
                        FlowRule.action == action,
                        FlowRule.analyzer_id == analyzer_id,
                    )
                    .order_by(FlowRule.created_at.desc())
                )
                fingerprint_rules = session.execute(stmt).scalars().all()
                for candidate_rule in fingerprint_rules:
                    if is_compatible_flow_rule(
                        candidate_rule,
                        mitigation,
                        requested_action=action,
                    ):
                        flow_rule = candidate_rule
                        break

            if flow_rule is None:
                stmt = (
                    select(FlowRule)
                    .where(
                        FlowRule.match == match,
                        FlowRule.switch_id == switch_id,
                        FlowRule.target == target,
                        FlowRule.analyzer_id == analyzer_id,
                    )
                    .order_by(FlowRule.created_at.desc())
                )
                same_match_rules = session.execute(stmt).scalars().all()
                for existing_rule in same_match_rules:
                    if is_compatible_flow_rule(
                        existing_rule,
                        mitigation,
                        requested_action=action,
                    ):
                        return _mark_reuse(_to_dict(existing_rule), True)

            if flow_rule is None:
                flow_rule = FlowRule(
                    source_event_id=event.get("event_id"),
                    source_event_fingerprint=fingerprint,
                    security_response_id=security_response_id,
                    analyzer_id=analyzer_id,
                    switch_id=switch_id,
                    target=target,
                    action=action,
                    match=match,
                    priority=int(mitigation["priority"]),
                    idle_timeout=_optional_int(mitigation.get("idle_timeout")),
                    hard_timeout=_optional_int(mitigation.get("hard_timeout")),
                    rate_limit_pps=_optional_int(mitigation.get("rate_limit_pps")),
                )
                session.add(flow_rule)
                session.flush()

            return _mark_reuse(_to_dict(flow_rule), flow_rule.security_response_id != security_response_id)

    def update_status(
        self,
        flow_rule_id: str,
        *,
        status: str,
        controller_rule_id: str | None = None,
        controller_response: dict[str, Any] | None = None,
        error_message: str | None = None,
        requested_at: datetime | None = None,
        applied_at: datetime | None = None,
    ) -> dict[str, Any] | None:
        with SessionLocal.begin() as session:
            flow_rule = session.get(FlowRule, flow_rule_id)
            if flow_rule is None:
                return None

            flow_rule.status = status
            flow_rule.controller_rule_id = controller_rule_id
            flow_rule.controller_response = controller_response
            flow_rule.error_message = error_message
            flow_rule.requested_at = requested_at
            flow_rule.applied_at = applied_at
            flow_rule.updated_at = datetime.now(timezone.utc)

            return _to_dict(flow_rule)
