import pytest
from pydantic import ValidationError

from app.schemas.analyzer import AnalyzerStatusRequest, PacketSummaryRequest
from app.schemas.flow import FlowRuleCreateRequest
from app.schemas.security import SecurityEventsRequest


def _security_event(**overrides):
    event = {
        "event_id": "evt-1",
        "event_fingerprint": "fingerprint-1",
        "dedup_key": "fingerprint-1",
        "timestamp": "2026-07-11T08:00:00+00:00",
        "analyzer_id": "analyzer-1",
        "attack_category": "FLOOD",
        "attack_type": "ICMP_FLOOD",
        "severity": "high",
        "confidence": "high",
        "status": "detected",
        "src_ip": "10.0.0.2",
        "dst_ip": "10.0.0.4",
        "protocol": "ICMP",
        "detection_rule": "icmp_flood_rate_threshold",
        "recommended_action": "rate_limit",
        "response_level": "L2",
        "evidence": {"score": 80, "icmp_type": 8},
        "mitigation": {
            "action": "RATE_LIMIT",
            "target": "flow",
            "match": {
                "eth_type": 2048,
                "ipv4_src": "10.0.0.2",
                "ipv4_dst": "10.0.0.4",
                "ip_proto": 1,
                "icmpv4_type": 8,
            },
            "priority": 500,
            "idle_timeout": 60,
            "hard_timeout": 300,
            "rate_limit_pps": 100,
        },
    }
    event.update(overrides)
    return event


def test_security_event_request_accepts_current_detection_payload():
    request = SecurityEventsRequest.model_validate({
        "timestamp": "2026-07-11T08:00:00+00:00",
        "analyzer_id": "analyzer-1",
        "events": [_security_event()],
    })

    data = request.model_dump(mode="json")

    assert data["events"][0]["src_ip"] == "10.0.0.2"
    assert data["events"][0]["mitigation"]["match"]["ip_proto"] == 1


def test_packet_summary_accepts_actual_float_window_seconds():
    request = PacketSummaryRequest.model_validate({
        "timestamp": "2026-07-11T08:00:00+00:00",
        "analyzer_id": "analyzer-1",
        "window_sec": 2.5,
        "total_packets": 10,
        "total_bits": 8000,
        "protocol_stats": {"TCP": 10},
        "host_stats": [
            {
                "src_ip": "10.0.0.2",
                "dst_ip": "10.0.0.4",
                "dst_port": 80,
                "protocol": "TCP",
                "packet_count": 10,
                "bit_count": 8000,
            }
        ],
    })

    assert request.window_sec == 2.5


def test_packet_summary_accepts_arp_and_other_protocols():
    request = PacketSummaryRequest.model_validate({
        "timestamp": "2026-07-11T08:00:00+00:00",
        "analyzer_id": "analyzer-1",
        "window_sec": 1,
        "total_packets": 2,
        "total_bits": 1600,
        "protocol_stats": {"ARP": 1, "OTHER": 1},
        "host_stats": [
            {
                "src_ip": "10.0.0.2",
                "dst_ip": "10.0.0.4",
                "protocol": "ARP",
                "packet_count": 1,
                "bit_count": 800,
            },
            {
                "src_ip": "10.0.0.3",
                "dst_ip": "10.0.0.5",
                "protocol": "OTHER",
                "packet_count": 1,
                "bit_count": 800,
            },
        ],
    })

    assert request.protocol_stats == {"ARP": 1, "OTHER": 1}


def test_packet_summary_rejects_unknown_host_stat_protocol():
    with pytest.raises(ValidationError):
        PacketSummaryRequest.model_validate({
            "timestamp": "2026-07-11T08:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "window_sec": 1,
            "total_packets": 1,
            "total_bits": 800,
            "protocol_stats": {"OTHER": 1},
            "host_stats": [
                {
                    "src_ip": "10.0.0.2",
                    "dst_ip": "10.0.0.4",
                    "protocol": "UNKNOWN",
                    "packet_count": 1,
                    "bit_count": 800,
                }
            ],
        })


def test_packet_summary_rejects_invalid_host_stat_ip():
    with pytest.raises(ValidationError):
        PacketSummaryRequest.model_validate({
            "timestamp": "2026-07-11T08:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "window_sec": 1,
            "total_packets": 1,
            "total_bits": 800,
            "protocol_stats": {"TCP": 1},
            "host_stats": [
                {
                    "src_ip": "not-an-ip",
                    "dst_ip": "10.0.0.4",
                    "protocol": "TCP",
                    "packet_count": 1,
                    "bit_count": 800,
                }
            ],
        })


def test_analyzer_status_accepts_runtime_security_metrics():
    request = AnalyzerStatusRequest.model_validate({
        "timestamp": "2026-07-11T08:00:00+00:00",
        "analyzer_id": "analyzer-1",
        "status": "running",
        "interface": "eth0",
        "capture_active": True,
        "backend_connected": False,
        "pending_security_event_count": 3,
        "dropped_security_event_count": 2,
        "packet_buffer_dropped_count": 1,
        "last_security_event_send_failure": "2026-07-11T08:00:01+00:00",
    })

    assert request.pending_security_event_count == 3
    assert request.dropped_security_event_count == 2
    assert request.packet_buffer_dropped_count == 1
    assert request.last_security_event_send_failure is not None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocol", "UNKNOWN_ATTACK_PROTO"),
        ("severity", "very-dangerous"),
        ("recommended_action", "DELETE_ALL"),
        ("response_level", "L100"),
        ("src_ip", "999.999.999.999"),
    ],
)
def test_security_event_request_rejects_invalid_values(field, value):
    event = _security_event(**{field: value})

    with pytest.raises(ValidationError):
        SecurityEventsRequest.model_validate({
            "timestamp": "2026-07-11T08:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "events": [event],
        })


def test_flow_rule_request_rejects_unknown_match_key():
    with pytest.raises(ValidationError):
        FlowRuleCreateRequest.model_validate({
            "switch_id": "s1",
            "match": {"anything": "anything"},
            "action": "DROP",
        })


def test_flow_rule_request_rejects_invalid_action():
    with pytest.raises(ValidationError):
        FlowRuleCreateRequest.model_validate({
            "switch_id": "s1",
            "match": {"ipv4_src": "10.0.0.2"},
            "action": "DELETE_ALL",
        })


def test_flow_rule_request_rejects_protocol_mismatch():
    with pytest.raises(ValidationError):
        FlowRuleCreateRequest.model_validate({
            "switch_id": "s1",
            "match": {
                "eth_type": 2048,
                "ipv4_src": "10.0.0.2",
                "ip_proto": 1,
                "tcp_dst": 80,
            },
            "action": "DROP",
        })


def test_flow_rule_request_requires_eth_type_for_ipv4_match():
    with pytest.raises(ValidationError):
        FlowRuleCreateRequest.model_validate({
            "switch_id": "s1",
            "match": {"ipv4_src": "10.0.0.2"},
            "action": "DROP",
        })


def test_flow_rule_request_rejects_tcp_without_tcp_protocol():
    with pytest.raises(ValidationError):
        FlowRuleCreateRequest.model_validate({
            "switch_id": "s1",
            "match": {
                "eth_type": 2048,
                "ipv4_src": "10.0.0.2",
                "tcp_dst": 80,
            },
            "action": "DROP",
        })


def test_flow_rule_request_rejects_udp_without_udp_protocol():
    with pytest.raises(ValidationError):
        FlowRuleCreateRequest.model_validate({
            "switch_id": "s1",
            "match": {
                "eth_type": 2048,
                "ipv4_src": "10.0.0.2",
                "ip_proto": 6,
                "udp_dst": 53,
            },
            "action": "DROP",
        })


def test_rate_limit_action_requires_rate_limit_pps():
    with pytest.raises(ValidationError):
        FlowRuleCreateRequest.model_validate({
            "switch_id": "s1",
            "match": {
                "eth_type": 2048,
                "ipv4_src": "10.0.0.2",
            },
            "action": "RATE_LIMIT",
        })


def test_drop_action_rejects_rate_limit_pps():
    with pytest.raises(ValidationError):
        FlowRuleCreateRequest.model_validate({
            "switch_id": "s1",
            "match": {
                "eth_type": 2048,
                "ipv4_src": "10.0.0.2",
            },
            "action": "DROP",
            "rate_limit_pps": 100,
        })


def test_flow_rule_request_normalizes_safe_action_values():
    request = FlowRuleCreateRequest.model_validate({
        "switch_id": "s1",
        "match": {
            "eth_type": 2048,
            "ipv4_src": "10.0.0.2",
            "ip_proto": 6,
            "tcp_dst": 80,
        },
        "action": "output:s2",
    })

    data = request.model_dump(mode="json", exclude_none=True)

    assert data["action"] == "OUTPUT:S2"
    assert data["match"]["ipv4_src"] == "10.0.0.2"


def test_flow_rule_request_requires_switch_id():
    with pytest.raises(ValidationError):
        FlowRuleCreateRequest.model_validate({
            "match": {
                "eth_type": 2048,
                "ipv4_src": "10.0.0.2",
            },
            "action": "DROP",
        })


def test_flow_rule_request_rejects_broad_drop_match():
    with pytest.raises(ValidationError):
        FlowRuleCreateRequest.model_validate({
            "switch_id": "s1",
            "match": {
                "eth_type": 2048,
                "ip_proto": 6,
            },
            "action": "DROP",
        })


def test_analyzer_payload_rejects_negative_counts():
    with pytest.raises(ValidationError):
        PacketSummaryRequest.model_validate({
            "timestamp": "2026-07-11T08:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "window_sec": 1,
            "total_packets": -1,
            "total_bits": 8000,
            "protocol_stats": {"TCP": 10},
            "host_stats": [],
        })


def test_packet_summary_request_rejects_unknown_protocol_stat_key():
    with pytest.raises(ValidationError):
        PacketSummaryRequest.model_validate({
            "timestamp": "2026-07-11T08:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "window_sec": 1,
            "total_packets": 1,
            "total_bits": 800,
            "protocol_stats": {"TCP_UNEXPECTED_LONG_NAME": 1},
            "host_stats": [],
        })


def test_analyzer_status_rejects_negative_runtime_metrics():
    with pytest.raises(ValidationError):
        AnalyzerStatusRequest.model_validate({
            "timestamp": "2026-07-11T08:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "status": "running",
            "interface": "eth0",
            "capture_active": True,
            "backend_connected": True,
            "pending_security_event_count": -1,
        })


def test_security_events_request_rejects_too_large_batch():
    with pytest.raises(ValidationError):
        SecurityEventsRequest.model_validate({
            "timestamp": "2026-07-11T08:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "events": [
                _security_event(event_id=f"evt-{index}")
                for index in range(101)
            ],
        })


def test_security_events_request_rejects_mismatched_analyzer_id():
    with pytest.raises(ValidationError):
        SecurityEventsRequest.model_validate({
            "timestamp": "2026-07-11T08:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "events": [_security_event(analyzer_id="analyzer-2")],
        })


def test_security_event_request_rejects_oversized_evidence_string():
    with pytest.raises(ValidationError):
        SecurityEventsRequest.model_validate({
            "timestamp": "2026-07-11T08:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "events": [
                _security_event(evidence={"blob": "x" * 4097})
            ],
        })


def test_security_event_request_rejects_oversized_evidence_list():
    target_ips = [f"10.0.0.{index}" for index in range(101)]

    with pytest.raises(ValidationError):
        SecurityEventsRequest.model_validate({
            "timestamp": "2026-07-11T08:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "events": [
                _security_event(evidence={"target_ips": target_ips})
            ],
        })


def test_security_event_request_rejects_values_longer_than_db_columns():
    with pytest.raises(ValidationError):
        SecurityEventsRequest.model_validate({
            "timestamp": "2026-07-11T08:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "events": [
                _security_event(
                    event_id="e" * 81,
                    event_fingerprint="f" * 129,
                    dedup_key="d" * 129,
                    detection_rule="r" * 129,
                )
            ],
        })


def test_packet_summary_request_rejects_too_many_host_stats():
    with pytest.raises(ValidationError):
        PacketSummaryRequest.model_validate({
            "timestamp": "2026-07-11T08:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "window_sec": 1,
            "total_packets": 101,
            "total_bits": 80800,
            "protocol_stats": {"TCP": 101},
            "host_stats": [
                {
                    "src_ip": "10.0.0.2",
                    "dst_ip": f"10.0.1.{index + 1}",
                    "protocol": "TCP",
                    "packet_count": 1,
                    "bit_count": 800,
                }
                for index in range(101)
            ],
        })
