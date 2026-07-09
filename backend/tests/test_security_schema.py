from app.schemas.security import SecurityEventsRequest


def test_arp_spoofing_event_accepts_mac_without_attacker_ip():
    payload = SecurityEventsRequest.model_validate(
        {
            "timestamp": "2026-07-09T00:00:00+00:00",
            "analyzer_id": "analyzer-1",
            "events": [
                {
                    "event_id": "evt-arp-1",
                    "event_fingerprint": "a" * 40,
                    "dedup_key": "a" * 40,
                    "timestamp": "2026-07-09T00:00:00+00:00",
                    "analyzer_id": "analyzer-1",
                    "attack_category": "L2_SPOOFING",
                    "attack_type": "ARP_SPOOFING",
                    "severity": "critical",
                    "confidence": "high",
                    "status": "detected",
                    "src_ip": None,
                    "src_mac": "00:00:00:00:00:02",
                    "dst_ip": "10.0.0.1",
                    "protocol": "ARP",
                    "detection_rule": "trusted_gateway_mac_mismatch",
                    "recommended_action": "block",
                    "response_level": "L3",
                    "evidence": {
                        "spoofed_ip": "10.0.0.254",
                        "trusted_mac": "00:00:00:00:ff:ff",
                    },
                    "mitigation": {
                        "action": "DROP",
                        "target": "flow",
                        "match": {
                            "eth_type": 2054,
                            "eth_src": "00:00:00:00:00:02",
                            "arp_spa": "10.0.0.254",
                        },
                        "priority": 650,
                    },
                }
            ],
        }
    )

    event = payload.events[0]
    assert event.src_ip is None
    assert event.src_mac == "00:00:00:00:00:02"
    assert event.mitigation["action"] == "DROP"
