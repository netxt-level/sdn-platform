# SDN 보안 탐지 정리

## 범위

보안 파트는 Analyzer가 넘겨주는 패킷 메타데이터와 링크 상태를 보고 보안 이벤트를 만든다. 이벤트는 Backend에 저장되고, Frontend에는 `security_event` WebSocket 메시지로 전달된다. Controller 쪽에서는 이벤트에 포함된 `flow_rule` 또는 `controller_requests`를 참고해 차단이나 우회 정책으로 바꿀 수 있다.

최종 시나리오는 ARP Spoofing이다. DDoS는 이번 범위에서 제외했다. 현재 토폴로지는 공격자가 h2 한 대라서 DDoS라고 부르기보다는 단일 공격자 기반 Flood/DoS에 가깝기 때문이다.

## 탐지 항목

| 항목 | 구분 | 판단 기준 | 대응 |
| --- | --- | --- | --- |
| `ARP_SPOOFING` | 최종 시나리오 | Gateway IP의 정상 MAC과 ARP Reply에서 주장하는 MAC이 다름 | `DROP` |
| `PORT_SCAN` | 공격 탐지 | 같은 출발지에서 짧은 시간 동안 여러 목적지 포트 접근 | `RATE_LIMIT` |
| `ICMP_FLOOD` | 공격 탐지 | ICMP PPS가 임계값 이상 | `RATE_LIMIT` |
| `UDP_FLOOD` | 공격 탐지 | UDP PPS 또는 BPS가 임계값 이상 | `RATE_LIMIT` |
| `SYN_FLOOD` | 공격 탐지 | SYN 비율 또는 SYN PPS가 임계값 이상 | `RATE_LIMIT` |
| `ARP_REPLY_STORM` | 공격/이상 트래픽 | ARP Reply가 짧은 시간에 과도하게 발생 | `RATE_LIMIT` |
| `CONGESTION` | 가용성 이벤트 | 링크 사용률, 지연, 큐 길이, 드롭 증가 | `REROUTE` |
| `LINK_FAILURE` | 가용성 이벤트 | 링크 상태가 down/failed/disabled | `REROUTE` |

혼잡과 링크 장애는 공격으로 단정하지 않는다. 다만 서비스가 끊기거나 느려지는 원인이 되기 때문에, SDN 컨트롤러가 대응해야 하는 네트워크 이상 상태로 분리했다.

## ARP Spoofing 흐름

1. 정상 Gateway 정보는 `10.0.0.254 -> 00:00:00:00:ff:ff`로 둔다.
2. 공격자 h2가 `10.0.0.254 is-at 00:00:00:00:00:02` ARP Reply를 보낸다.
3. Analyzer가 ARP 필드를 보안 엔진으로 넘긴다.
4. 보안 엔진은 정상 Gateway MAC과 관측 MAC을 비교한다.
5. 값이 다르면 `ARP_SPOOFING` 이벤트를 만든다.
6. 대응 정책은 위조 ARP Reply를 막는 `DROP` rule로 만든다.

예상 Flow Rule은 아래와 같다.

```json
{
  "instruction": "DROP",
  "priority": 650,
  "match": {
    "eth_type": 2054,
    "arp_spa": "10.0.0.254",
    "eth_src": "00:00:00:00:00:02"
  }
}
```

## 연동 포인트

Analyzer는 ARP 패킷에서 아래 필드를 넘겨야 한다.

| 필드 | 의미 |
| --- | --- |
| `protocol` 또는 `eth_type` | ARP 여부 |
| `arp_opcode` | request/reply |
| `arp_sender_ip` | ARP Reply가 주장하는 IP |
| `arp_sender_mac` | ARP Reply를 보낸 MAC |
| `arp_target_ip` | ARP 대상 IP |
| `arp_target_mac` | ARP 대상 MAC |

Backend는 `POST /api/security/events`로 이벤트 묶음을 받는다. 이벤트가 들어오면 저장하고, Frontend에는 `security_event` 메시지로 broadcast한다.

Frontend는 `AttackType`에 `ARP_SPOOFING`, `ARP_REPLY_STORM`, `CONGESTION`, `LINK_FAILURE`를 포함해야 한다.

## 확인 방법

```powershell
$env:PYTHONPATH="analyzer"
python -m app.security.demo --input samples/security_scenario_06_arp_spoofing_final.json --backend-out reports/security_arp_backend.json --flow-out reports/security_arp_flows.json
python -m pytest analyzer/tests/test_security_engine.py
```
