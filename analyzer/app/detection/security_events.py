from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import hashlib
from typing import Any

from .common import to_int, to_port


class PendingSecurityEventQueue:
    """전송 실패로 보안 이벤트가 사라지지 않도록 메모리에 보관한다."""

    def __init__(self, max_size: int = 500) -> None:
        self.max_size = max_size
        self.events: deque[dict[str, Any]] = deque()
        self.event_ids: set[str] = set()

    def add(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """새 이벤트를 대기 큐에 넣고, 크기 제한 때문에 밀려난 이벤트를 돌려준다."""

        dropped_events = []
        for event in events:
            event_id = str(event.get("event_id") or "")
            if not event_id or event_id in self.event_ids:
                continue

            self.events.append(event)
            self.event_ids.add(event_id)

            while len(self.events) > self.max_size:
                dropped = self.events.popleft()
                dropped_events.append(dropped)
                self.event_ids.discard(str(dropped.get("event_id") or ""))

        return dropped_events

    def payload(self, *, timestamp: str, analyzer_id: str) -> dict[str, Any]:
        return {
            "timestamp": timestamp,
            "analyzer_id": analyzer_id,
            "events": list(self.events),
        }

    def clear(self) -> None:
        self.events.clear()
        self.event_ids.clear()

    def __len__(self) -> int:
        return len(self.events)


class SecurityEventBuilder:
    """탐지 결과를 백엔드가 받는 공통 보안 이벤트 형식으로 변환한다."""

    def __init__(
        self,
        analyzer_id: str = "analyzer-1",
        event_dedup_window_sec: int = 60,
        rate_limit_priority: int = 500,
        rate_limit_idle_timeout: int = 60,
        rate_limit_hard_timeout: int = 300,
        rate_limit_pps: int = 100,
        drop_priority: int = 700,
        drop_idle_timeout: int = 30,
        drop_hard_timeout: int = 120,
    ) -> None:
        self.analyzer_id = analyzer_id
        self.event_dedup_window_sec = event_dedup_window_sec
        self.rate_limit_priority = rate_limit_priority
        self.rate_limit_idle_timeout = rate_limit_idle_timeout
        self.rate_limit_hard_timeout = rate_limit_hard_timeout
        self.rate_limit_pps = rate_limit_pps
        self.drop_priority = drop_priority
        self.drop_idle_timeout = drop_idle_timeout
        self.drop_hard_timeout = drop_hard_timeout

        # 같은 이벤트를 매 분석 주기마다 반복 전송하지 않기 위해 최근 이벤트를 기억한다.
        self.recent_events: dict[str, dict[str, Any]] = {}

    def build_security_events(
        self,
        packet_summary: dict[str, Any],
        detections: list[dict[str, Any]],
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()
        window_sec = packet_summary.get("window_sec", 1)
        event_window_sec = float(window_sec) if window_sec and window_sec > 0 else 1
        window_start_epoch = int(now.timestamp() // event_window_sec * event_window_sec)

        events = []
        for detection in detections:
            event = self._build_event(
                detection=detection,
                timestamp=timestamp,
                now=now,
                window_start_epoch=window_start_epoch,
            )
            if event is not None:
                events.append(event)

        self._cleanup_recent_events(now)
        return {
            "timestamp": timestamp,
            "analyzer_id": self.analyzer_id,
            "events": events,
        }

    def forget_events(self, events: list[dict[str, Any]]) -> None:
        """재전송할 수 없게 된 이벤트의 중복 억제 기록을 제거한다."""

        for event in events:
            dedup_key = event.get("dedup_key")
            if dedup_key:
                self.recent_events.pop(str(dedup_key), None)

    def _build_event(
        self,
        *,
        detection: dict[str, Any],
        timestamp: str,
        now: datetime,
        window_start_epoch: int,
    ) -> dict[str, Any] | None:
        src_ip = str(detection.get("src_ip") or "")
        dst_ip = str(detection.get("dst_ip") or "")
        if not src_ip or not dst_ip:
            return None

        evidence = self._build_evidence(detection)
        attack_type = str(detection.get("attack_type") or "UNKNOWN")
        protocol = str(detection.get("protocol") or "UNKNOWN")
        detection_rule = str(detection.get("detection_rule") or "unknown_rule")
        severity = str(detection.get("severity") or "medium")
        confidence = str(detection.get("confidence") or "medium")
        recommended_action = str(detection.get("recommended_action") or "log")
        response_level = str(detection.get("response_level") or "L0")

        fingerprint = _event_fingerprint(
            self.analyzer_id,
            attack_type,
            src_ip,
            dst_ip,
            protocol,
            detection_rule,
            str(evidence.get("destination_port") or ""),
            str(evidence.get("scan_type") or ""),
        )

        if self._is_duplicate(
            dedup_key=fingerprint,
            now=now,
            severity=severity,
            response_level=response_level,
        ):
            return None

        self.recent_events[fingerprint] = {
            "timestamp": now,
            "severity": severity,
            "response_level": response_level,
        }

        return {
            "event_id": _event_id(fingerprint, str(window_start_epoch)),
            "event_fingerprint": fingerprint,
            "dedup_key": fingerprint,
            "timestamp": timestamp,
            "analyzer_id": self.analyzer_id,
            "attack_category": detection.get("attack_category", "UNKNOWN"),
            "attack_type": attack_type,
            "severity": severity,
            "confidence": confidence,
            "status": "detected",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "detection_rule": detection_rule,
            "recommended_action": recommended_action,
            "response_level": response_level,
            "evidence": evidence,
            "mitigation": self._build_mitigation(
                detection=detection,
                evidence=evidence,
                action=recommended_action,
            ),
        }

    def _build_evidence(self, detection: dict[str, Any]) -> dict[str, Any]:
        evidence = dict(detection.get("evidence") or {})

        # 탐지기마다 자주 쓰는 값을 evidence에 모아 두면 화면과 보고서에서 설명하기 쉽다.
        for key in (
            "matched_conditions",
            "score",
            "pps",
            "bps",
            "window_seconds",
            "unique_dst_port_count",
            "unique_dst_ports",
            "syn_count",
            "target_count",
            "target_ips",
            "scan_type",
        ):
            if key in detection and key not in evidence:
                evidence[key] = detection[key]

        if "matched_conditions" not in evidence:
            evidence["matched_conditions"] = []
        if "score" not in evidence:
            evidence["score"] = 0
        if "destination_port" not in evidence:
            ports = evidence.get("unique_dst_ports") or []
            if len(ports) == 1:
                port = to_port(ports[0])
                if port is not None:
                    evidence["destination_port"] = port

        return evidence

    def _build_mitigation(
        self,
        *,
        detection: dict[str, Any],
        evidence: dict[str, Any],
        action: str,
    ) -> dict[str, Any] | None:
        if action not in {"rate_limit", "drop"}:
            return None

        protocol = str(detection.get("protocol") or "")
        src_ip = detection.get("src_ip")
        dst_ip = detection.get("dst_ip")
        if not src_ip or not dst_ip:
            return None

        match: dict[str, Any] = {
            "eth_type": 2048,
            "ipv4_src": src_ip,
        }
        if evidence.get("scan_type") != "horizontal":
            match["ipv4_dst"] = dst_ip

        ip_proto = {"ICMP": 1, "TCP": 6, "UDP": 17}.get(protocol)
        if ip_proto is not None:
            match["ip_proto"] = ip_proto

        destination_port = to_port(evidence.get("destination_port"))
        if destination_port is not None and protocol == "TCP":
            match["tcp_dst"] = destination_port
        if destination_port is not None and protocol == "UDP":
            match["udp_dst"] = destination_port
        icmp_type = to_int(evidence.get("icmp_type"))
        if protocol == "ICMP" and icmp_type is not None and 0 <= icmp_type <= 255:
            match["icmpv4_type"] = icmp_type

        if action == "rate_limit":
            return {
                "action": "RATE_LIMIT",
                "target": "flow",
                "match": match,
                "priority": self.rate_limit_priority,
                "idle_timeout": self.rate_limit_idle_timeout,
                "hard_timeout": self.rate_limit_hard_timeout,
                "rate_limit_pps": self.rate_limit_pps,
            }

        return {
            "action": "DROP",
            "target": "flow",
            "match": match,
            "priority": self.drop_priority,
            "idle_timeout": self.drop_idle_timeout,
            "hard_timeout": self.drop_hard_timeout,
        }

    def _is_duplicate(
        self,
        *,
        dedup_key: str,
        now: datetime,
        severity: str,
        response_level: str,
    ) -> bool:
        last_event = self.recent_events.get(dedup_key)
        if last_event is None:
            return False

        elapsed = (now - last_event["timestamp"]).total_seconds()
        if elapsed >= self.event_dedup_window_sec:
            return False

        # 위험도가 올라간 이벤트는 중복 억제 중이어도 다시 전송한다.
        if _policy_rank(response_level) > _policy_rank(last_event["response_level"]):
            return False

        if _severity_rank(severity) > _severity_rank(last_event["severity"]):
            return False

        return True

    def _cleanup_recent_events(self, now: datetime) -> None:
        stale_keys = [
            key
            for key, value in self.recent_events.items()
            if (now - value["timestamp"]).total_seconds()
            > self.event_dedup_window_sec * 2
        ]
        for key in stale_keys:
            self.recent_events.pop(key, None)


def _event_id(*parts: str) -> str:
    raw = "|".join(parts)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
    return f"evt-{digest}"


def _event_fingerprint(*parts: str) -> str:
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _policy_rank(value: str) -> int:
    return {
        "L0": 0,
        "L1": 1,
        "L2": 2,
        "L3": 3,
    }.get(value, 0)


def _severity_rank(value: str) -> int:
    return {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }.get(value, 0)
