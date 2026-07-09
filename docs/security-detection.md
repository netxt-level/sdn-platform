# 보안 탐지 구현 정리

## 범위

최종 시나리오는 `ARP_SPOOFING`이다. `PORT_SCAN`과 `ICMP_FLOOD`는 서로 다른 탐지 기준을 보여 주는 보조 항목이다.

| 이벤트 | 판단 기준 | 대응 |
|---|---|---|
| `ARP_SPOOFING` | Gateway IP를 신뢰 MAC이 아닌 값으로 주장하는 ARP Reply | `DROP` 후보 |
| `PORT_SCAN` | 같은 출발지·목적지에서 여러 TCP 포트로 향하는 SYN | 관찰 또는 알림 |
| `ICMP_FLOOD` | 같은 출발지·목적지의 ICMP pps가 기준 이상 | 조건 충족 시 `RATE_LIMIT` 후보 |

DDoS, UDP Flood, SYN Flood, 링크 혼잡, 링크 장애는 현재 보안 이벤트 범위에 포함하지 않는다.

## ARP Spoofing 시나리오

정상 기준:

```text
Gateway IP  : 10.0.0.254
Gateway MAC : 00:00:00:00:ff:ff
```

공격 입력:

```text
ARP Reply
10.0.0.254 is-at 00:00:00:00:00:02
target: 10.0.0.1
```

처리 순서:

1. `packet/parser.py`가 ARP opcode, sender IP/MAC, target IP/MAC을 추출한다.
2. `SecurityEventBuilder`가 ARP Reply만 확인한다.
3. sender IP가 보호 대상 Gateway IP인지 확인한다.
4. sender MAC을 신뢰 Gateway MAC과 비교한다.
5. 값이 다르면 `ARP_SPOOFING` Critical 이벤트를 만든다.
6. 공격자의 Ethernet source MAC과 위조 Gateway IP에만 일치하는 DROP 후보를 만든다.
7. Backend가 이벤트, 대응 내역, PENDING Flow Rule을 저장한다.
8. Frontend는 공격자 IP 대신 MAC을 출발지로 표시한다.

신뢰 정보가 없는 일반 IP에서 두 MAC이 관찰되더라도 어느 쪽이 공격자인지 판단할 수 없으므로 자동 DROP하지 않는다.

## ARP 이벤트 예시

```json
{
  "attack_category": "L2_SPOOFING",
  "attack_type": "ARP_SPOOFING",
  "severity": "critical",
  "confidence": "high",
  "status": "detected",
  "src_ip": null,
  "src_mac": "00:00:00:00:00:02",
  "dst_ip": "10.0.0.1",
  "protocol": "ARP",
  "detection_rule": "trusted_gateway_mac_mismatch",
  "recommended_action": "block",
  "response_level": "L3",
  "evidence": {
    "spoofed_ip": "10.0.0.254",
    "trusted_mac": "00:00:00:00:ff:ff",
    "claimed_mac": "00:00:00:00:00:02",
    "matched_conditions": [
      "arp_reply",
      "gateway_ip_claimed",
      "gateway_mac_mismatch"
    ]
  },
  "mitigation": {
    "action": "DROP",
    "target": "flow",
    "match": {
      "eth_type": 2054,
      "eth_src": "00:00:00:00:00:02",
      "arp_spa": "10.0.0.254"
    },
    "priority": 650,
    "idle_timeout": 60,
    "hard_timeout": 300
  }
}
```

`mitigation`은 Controller 적용 후보이며 자동 적용 완료를 의미하지 않는다.

## 저장과 화면 전달

```text
Analyzer SecurityEventBuilder
  -> POST /api/security/events
  -> Pydantic SecurityEventsRequest 검증
  -> Elasticsearch sdn-security-events
  -> PostgreSQL security_responses / flow_rules
  -> WebSocket security_events
  -> Frontend Security Events / Flow Rules
```

이벤트의 `event_fingerprint`는 같은 공격 흐름을 묶고, `event_id`는 발생 시간 창을 포함해 재발 사건을 구분한다. Analyzer는 중복 억제 시간 안의 동일 흐름을 다시 전송하지 않는다.

## 확인 방법

```bash
python -m pytest analyzer/tests backend/tests -q
```

Frontend:

```bash
cd frontend
npm run build
```
