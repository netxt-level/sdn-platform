from __future__ import annotations

from typing import Any

from app.policies.flow_rule_policy import is_reusable_flow_rule
from app.repositories.flow_repository import FlowRepository
from app.services.dashboard_service import DashboardService

WARNING_BPS_THRESHOLD = 5_000_000


class PathService:
    def __init__(
        self,
        dashboard_service: DashboardService | None = None,
        flow_repository: FlowRepository | None = None,
    ):
        self.dashboard_service = dashboard_service or DashboardService()
        self.flow_repository = flow_repository or FlowRepository()

    def get_status(self) -> dict[str, Any]:
        summary = self.dashboard_service.get_summary()
        flow_rules = self.flow_repository.list_flows(limit=100)
        current_bps = float(summary.get("current_bps") or 0)

        # 실제 링크 계측 API가 없으므로 현재 트래픽 요약으로 경로 사용률을 파생한다.
        primary_utilization = min(
            100,
            round((current_bps / WARNING_BPS_THRESHOLD) * 70),
        )
        backup_utilization = min(
            100,
            max(0, round(primary_utilization * 0.45)),
        )
        active_path = self._decide_active_path(summary, flow_rules)

        return {
            "active_path": active_path,
            "network_status": summary.get("network_status", "normal"),
            "paths": {
                "primary": {
                    "name": "primary",
                    "nodes": ["s1", "s2", "s4"],
                    "utilization": primary_utilization,
                    "active": active_path == "primary",
                },
                "backup": {
                    "name": "backup",
                    "nodes": ["s1", "s3", "s4"],
                    "utilization": backup_utilization,
                    "active": active_path == "backup",
                },
            },
            "links": [
                {
                    "id": "s1-s2",
                    "source": "s1",
                    "target": "s2",
                    "path": "primary",
                    "active": active_path == "primary",
                    "utilization": primary_utilization,
                },
                {
                    "id": "s2-s4",
                    "source": "s2",
                    "target": "s4",
                    "path": "primary",
                    "active": active_path == "primary",
                    "utilization": max(0, primary_utilization - 3),
                },
                {
                    "id": "s1-s3",
                    "source": "s1",
                    "target": "s3",
                    "path": "backup",
                    "active": active_path == "backup",
                    "utilization": backup_utilization,
                },
                {
                    "id": "s3-s4",
                    "source": "s3",
                    "target": "s4",
                    "path": "backup",
                    "active": active_path == "backup",
                    "utilization": max(0, backup_utilization - 2),
                },
            ],
            "history": [self._history_item(rule) for rule in flow_rules[:8]],
        }

    def _decide_active_path(
        self,
        summary: dict[str, Any],
        flow_rules: list[dict[str, Any]],
    ) -> str:
        if summary.get("network_status") == "critical":
            return "backup"

        # 컨트롤러 적용 전에는 PENDING 대응 후보를 우회 필요 신호로 간주한다.
        has_pending_response = any(
            str(rule.get("status", "")).upper() == "PENDING"
            and str(rule.get("action", "")).upper() in {"RATE_LIMIT", "DROP"}
            and is_reusable_flow_rule(rule)
            for rule in flow_rules
        )

        return "backup" if has_pending_response else "primary"

    def _history_item(self, rule: dict[str, Any]) -> dict[str, Any]:
        action = str(rule.get("action") or "-")
        src = rule.get("src_ip") or rule.get("match", {}).get("ipv4_src")
        dst = rule.get("dst_ip") or rule.get("match", {}).get("ipv4_dst")
        reason = (
            f"{rule['source_event_id']} 대응"
            if rule.get("source_event_id")
            else f"{src or '*'} → {dst or '*'}"
        )

        return {
            "id": rule["id"],
            "time": rule.get("created_at") or rule.get("timestamp"),
            "from": "primary",
            "to": action,
            "reason": reason,
            "status": rule.get("status", "UNKNOWN"),
        }
