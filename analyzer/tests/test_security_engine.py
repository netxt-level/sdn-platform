from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app.detection.port_scan import PortScanDetector
from app.security import (
    DetectionConfig,
    LinkState,
    PacketRecord,
    SecurityAnalysisEngine,
    result_to_backend_payload,
    validate_backend_payload,
)
from app.security.io import load_security_input
from app.security.ryu_adapter import flow_rules_from_policies, packet_record_from_ryu


def test_port_scan_detector_builds_suspicious_host_alert() -> None:
    """20개 SYN 포트 접근이 대시보드용 의심 호스트 경고를 만드는지 확인한다."""

    detector = PortScanDetector(
        unique_port_threshold=20,
        syn_count_threshold=20,
        alert_cooldown_sec=60,
    )

    packets = [
        {
            "protocol": "TCP",
            "tcp_flags": "S",
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.4",
            "dst_port": port,
        }
        for port in range(1, 21)
    ]
    packets.append(
        {
            "protocol": "TCP",
            "tcp_flags": "S",
            "src_ip": "10.0.0.2",
            "dst_ip": "10.0.0.4",
            "dst_port": "invalid",
        }
    )

    alerts = detector.detect(packets)

    assert len(alerts) == 1
    assert alerts[0]["attack_type"] == "PORT_SCAN"
    assert alerts[0]["unique_dst_port_count"] == 20
    assert alerts[0]["syn_count"] == 20
    assert alerts[0]["response_level"] == "L2"


def test_final_arp_spoofing_sample_builds_event_and_drop_rule() -> None:
    """최종 발표 샘플이 ARP 이벤트와 좁은 DROP 조건을 함께 만드는지 확인한다."""

    sample_path = (
        Path(__file__).resolve().parents[2]
        / "samples"
        / "security_scenario_06_arp_spoofing_final.json"
    )
    packets, links, baseline, config = load_security_input(sample_path)

    result = SecurityAnalysisEngine(config=config, baseline=baseline).analyze(
        packets,
        links=links,
    )

    assert [event.attack_type for event in result.events] == ["ARP_SPOOFING"]
    event = result.events[0]
    assert event.dst_ip == "10.0.0.254"
    assert event.src_mac == "00:00:00:00:00:02"
    assert event.evidence["trusted_mac"] == "00:00:00:00:ff:ff"

    payload = result_to_backend_payload(result)
    # 엔진 결과가 프론트 필수 필드를 빠뜨리지 않고 백엔드 계약으로 변환돼야 한다.
    assert validate_backend_payload(payload) == []

    flow_rules = flow_rules_from_policies(result.policies, datapath_id="s1")
    # 공격 MAC이 게이트웨이 IP를 주장하는 ARP만 막고 다른 트래픽은 건드리지 않는다.
    assert flow_rules == [
        {
            "datapath_id": "s1",
            "priority": 650,
            "match": {
                "eth_type": 2054,
                "arp_spa": "10.0.0.254",
                "eth_src": "00:00:00:00:00:02",
            },
            "idle_timeout": 60,
            "hard_timeout": 300,
            "reason": "arp spoofing block",
            "actions": [],
            "instruction": "DROP",
        }
    ]


def test_security_engine_keeps_security_scope_focused() -> None:
    """입력이 섞여 있어도 현재 범위의 세 이벤트만 생성하는지 확인한다."""

    now = datetime(2026, 7, 3, tzinfo=timezone.utc)
    config = DetectionConfig(
        window_seconds=10,
        gateway_ip="10.0.0.254",
        gateway_mac="00:00:00:00:ff:ff",
        trusted_ip_mac={"10.0.0.254": "00:00:00:00:ff:ff"},
    )
    packets = [
        *[
            PacketRecord(
                timestamp=now,
                src_ip="10.0.0.2",
                dst_ip="10.0.0.4",
                protocol="TCP",
                dst_port=port,
                tcp_flags=("SYN",),
            )
            for port in range(1, 21)
        ],
        PacketRecord(
            timestamp=now,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.4",
            protocol="ICMP",
            packet_count=1200,
        ),
        PacketRecord(
            timestamp=now,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.4",
            protocol="UDP",
            packet_count=2500,
            byte_count=2_000_000,
        ),
        PacketRecord(
            timestamp=now,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.4",
            protocol="TCP",
            dst_port=80,
            tcp_flags=("SYN",),
            packet_count=1000,
        ),
        PacketRecord(
            timestamp=now,
            protocol="ARP",
            src_mac="00:00:00:00:00:02",
            arp_opcode="reply",
            arp_sender_ip="10.0.0.254",
            arp_sender_mac="00:00:00:00:00:02",
            arp_target_ip="10.0.0.1",
            arp_target_mac="00:00:00:00:00:01",
            packet_count=250,
        ),
    ]
    links = [
        LinkState(
            link_id="s1-s2",
            src_switch="s1",
            dst_switch="s2",
            utilization=0.8,
        ),
        LinkState(
            link_id="s2-s4",
            src_switch="s2",
            dst_switch="s4",
            status="down",
        ),
    ]

    result = SecurityAnalysisEngine(config=config).analyze(packets, links=links, now=now)
    attack_types = {event.attack_type for event in result.events}
    events_by_type = {event.attack_type: event for event in result.events}

    assert {"ARP_SPOOFING", "PORT_SCAN", "ICMP_FLOOD"}.issubset(attack_types)
    assert events_by_type["PORT_SCAN"].evidence["response_level"] == "L2"
    assert "tcp_syn_without_ack" in events_by_type["PORT_SCAN"].evidence["matched_conditions"]
    assert events_by_type["ICMP_FLOOD"].evidence["response_level"] == "L2"
    assert "min_packet_count_satisfied" in events_by_type["ICMP_FLOOD"].evidence["matched_conditions"]
    # 아래 항목은 공용 모델이나 과거 아이디어에 남아 있어도 현재 발표 범위가 아니다.
    assert "UDP_FLOOD" not in attack_types
    assert "SYN_FLOOD" not in attack_types
    assert "ARP_REPLY_STORM" not in attack_types
    assert "CONGESTION" not in attack_types
    assert "LINK_FAILURE" not in attack_types


def test_ryu_adapter_accepts_arp_eth_type() -> None:
    """Ryu가 ARP를 EtherType 숫자로 주어도 ARP 필드가 보존되는지 확인한다."""

    record = packet_record_from_ryu(
        {
            "timestamp": "2026-07-03T00:00:09+00:00",
            "eth_type": 0x0806,
            "eth_src": "00:00:00:00:00:02",
            "arp_spa": "10.0.0.254",
            "arp_sha": "00:00:00:00:00:02",
            "arp_tpa": "10.0.0.1",
            "arp_tha": "00:00:00:00:00:01",
            "arp_opcode": "reply",
        }
    )

    assert record.protocol == "ARP"
    assert record.arp_sender_ip == "10.0.0.254"
    assert record.arp_sender_mac == "00:00:00:00:00:02"
