from __future__ import annotations

from copy import deepcopy
from typing import Any


def correlate_detections(detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """같은 분석 구간에서 나온 탐지 결과를 대응 후보 기준으로 정리한다.

    Detector는 서로 독립적으로 증거를 만든다. 다만 같은 TCP 흐름에 대해
    Port Scan과 다중 서비스 SYN Flood가 동시에 잡히면 같은 OpenFlow match에
    RATE_LIMIT과 DROP 후보가 함께 생길 수 있다. 이 경우 더 강한 SYN Flood를
    유지하고 Port Scan 정보는 evidence에 관련 탐지로 남긴다.
    """

    correlated = [deepcopy(detection) for detection in detections]
    suppressed_indexes: set[int] = set()

    for syn_index, syn_detection in enumerate(correlated):
        if not _is_multi_service_syn_flood(syn_detection):
            continue

        related_port_scans = []
        for scan_index, scan_detection in enumerate(correlated):
            if scan_index == syn_index or scan_index in suppressed_indexes:
                continue
            if not _is_port_scan(scan_detection):
                continue
            if _flow_key(scan_detection) != _flow_key(syn_detection):
                continue
            if _response_rank(scan_detection) > _response_rank(syn_detection):
                continue

            related_port_scans.append(_related_detection(scan_detection))
            suppressed_indexes.add(scan_index)

        if related_port_scans:
            evidence = dict(syn_detection.get("evidence") or {})
            existing_related = list(evidence.get("related_detections") or [])
            evidence["related_detections"] = existing_related + related_port_scans
            evidence["suppressed_detection_count"] = (
                int(evidence.get("suppressed_detection_count") or 0)
                + len(related_port_scans)
            )
            evidence["correlation_policy"] = (
                "multi_service_syn_flood_over_port_scan"
            )
            syn_detection["evidence"] = evidence

            conditions = list(syn_detection.get("matched_conditions") or [])
            conditions.append("같은 흐름의 Port Scan 탐지를 SYN Flood 근거로 병합")
            syn_detection["matched_conditions"] = conditions

    return [
        detection
        for index, detection in enumerate(correlated)
        if index not in suppressed_indexes
    ]


def _flow_key(detection: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    return (
        detection.get("src_ip"),
        detection.get("dst_ip"),
        detection.get("protocol"),
    )


def _is_port_scan(detection: dict[str, Any]) -> bool:
    return detection.get("attack_type") == "PORT_SCAN"


def _is_multi_service_syn_flood(detection: dict[str, Any]) -> bool:
    evidence = detection.get("evidence") or {}
    return (
        detection.get("attack_type") == "SYN_FLOOD"
        and detection.get("detection_rule") == "tcp_syn_multi_service_rate"
        and bool(evidence.get("scan_like"))
    )


def _response_rank(detection: dict[str, Any]) -> int:
    response_level = str(detection.get("response_level") or "L0")
    return {
        "L0": 0,
        "L1": 1,
        "L2": 2,
        "L3": 3,
    }.get(response_level, 0)


def _related_detection(detection: dict[str, Any]) -> dict[str, Any]:
    evidence = detection.get("evidence") or {}
    return {
        "attack_type": detection.get("attack_type"),
        "detection_rule": detection.get("detection_rule"),
        "score": detection.get("score"),
        "severity": detection.get("severity"),
        "response_level": detection.get("response_level"),
        "recommended_action": detection.get("recommended_action"),
        "scan_type": evidence.get("scan_type"),
        "unique_dst_port_count": evidence.get("unique_dst_port_count"),
        "target_count": evidence.get("target_count"),
    }
