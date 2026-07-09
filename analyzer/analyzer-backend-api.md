# Analyzer → Backend API

## 공통 정보

- 기본 주소: `BACKEND_BASE_URL`
- 기본 Docker 주소: `http://backend:8000`
- Content-Type: `application/json`
- 요청 timeout: 3초

## 1. 패킷 요약

```http
POST /api/analyzer/packet-summary
```

```json
{
  "timestamp": "2026-07-09T00:00:00+00:00",
  "analyzer_id": "analyzer-1",
  "window_sec": 1,
  "total_packets": 120,
  "total_bits": 98304,
  "protocol_stats": {
    "TCP": 80,
    "UDP": 20,
    "ICMP": 19,
    "ARP": 1
  },
  "host_stats": []
}
```

Backend는 InfluxDB에 저장하고 `packet_summary` WebSocket 메시지를 보낸다.

## 2. 탐지 요약

```http
POST /api/analyzer/detection-summary
```

```json
{
  "timestamp": "2026-07-09T00:00:00+00:00",
  "analyzer_id": "analyzer-1",
  "network_status": "warning",
  "total_bps": 1000000,
  "total_pps": 1500,
  "active_flow_count": 5,
  "suspicious_host_count": 1,
  "suspicious_hosts": []
}
```

이 payload는 대시보드 상태용이다. 개별 보안 사건과 대응 근거는 다음 Security Events API로 분리한다.

## 3. 보안 이벤트

```http
POST /api/security/events
```

현재 이벤트 유형:

- `ARP_SPOOFING`
- `PORT_SCAN`
- `ICMP_FLOOD`

### 요청 구조

```json
{
  "timestamp": "2026-07-09T00:00:00+00:00",
  "analyzer_id": "analyzer-1",
  "events": []
}
```

### SecurityEvent 공통 필드

| 필드 | 타입 | 설명 |
|---|---|---|
| `event_id` | string | 시간 창을 포함한 개별 사건 ID |
| `event_fingerprint` | string | 같은 공격 흐름의 안정적인 ID |
| `dedup_key` | string | 중복 억제 기준 |
| `timestamp` | datetime | 이벤트 시각 |
| `analyzer_id` | string | Analyzer ID |
| `attack_category` | string | `L2_SPOOFING`, `RECON`, `FLOOD` |
| `attack_type` | string | 탐지 유형 |
| `severity` | string | `medium`, `high`, `critical` |
| `confidence` | string | `medium`, `high` |
| `status` | string | 최초 값 `detected` |
| `src_ip` | string/null | 신뢰 가능한 공격 출발지 IP |
| `src_mac` | string/null | ARP 공격자 MAC |
| `dst_ip` | string | 공격 대상 IP |
| `protocol` | string | `ARP`, `TCP`, `ICMP` |
| `detection_rule` | string | 탐지 규칙 이름 |
| `recommended_action` | string | 권장 대응 |
| `response_level` | string | `L1`, `L2`, `L3` |
| `evidence` | object | 판단 근거 |
| `mitigation` | object/null | Flow Rule 후보 |

### ARP Spoofing 예시

```json
{
  "event_id": "evt-example",
  "event_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "dedup_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "timestamp": "2026-07-09T00:00:00+00:00",
  "analyzer_id": "analyzer-1",
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
    "score": 100
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

### Backend 처리

1. `SecurityEventsRequest` Pydantic schema로 요청을 검증한다.
2. Elasticsearch `sdn-security-events`에 이벤트를 저장한다.
3. PostgreSQL `security_responses`에 대응 내역을 만든다.
4. mitigation이 있으면 PostgreSQL `flow_rules`에 PENDING 후보를 만든다.
5. `security_events` WebSocket 메시지를 방송한다.

## 4. Analyzer 상태

```http
POST /api/analyzer/status
```

```json
{
  "timestamp": "2026-07-09T00:00:00+00:00",
  "analyzer_id": "analyzer-1",
  "status": "running",
  "interface": "eth0",
  "capture_active": true,
  "backend_connected": true,
  "last_packet_at": "2026-07-09T00:00:00+00:00",
  "last_summary_sent_at": "2026-07-09T00:00:00+00:00",
  "error_message": null
}
```

## 실패 처리

- 연결 실패, timeout, HTTP 오류는 `False`로 반환한다.
- 분석 루프는 중단하지 않고 Analyzer 상태에 오류를 기록한다.
- 보안 이벤트가 존재할 때 해당 전송까지 성공해야 summary 전송 성공으로 처리한다.
- 현재 로컬 재시도 큐는 구현되어 있지 않다.
