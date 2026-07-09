# Backend API

기본 주소: `http://localhost:8000`

## API 목록

| 메서드 | 경로 | 역할 |
|---|---|---|
| `GET` | `/health` | 서버 상태 |
| `GET` | `/api/analyzer/status` | Analyzer 상태 조회 |
| `POST` | `/api/analyzer/status` | Analyzer 상태 저장 |
| `POST` | `/api/analyzer/packet-summary` | 패킷 요약 저장 |
| `POST` | `/api/analyzer/detection-summary` | 탐지 요약 저장 |
| `GET` | `/api/dashboard/summary` | 대시보드 요약 |
| `GET` | `/api/dashboard/traffic` | 트래픽 시계열 |
| `GET` | `/api/dashboard/protocols` | 프로토콜 통계 |
| `GET` | `/api/dashboard/suspicious-hosts` | 의심 호스트 |
| `GET` | `/api/security/events` | 보안 이벤트 |
| `POST` | `/api/security/events` | 보안 이벤트 수신 |
| `GET` | `/api/security/responses` | 보안 대응 내역 |
| `GET` | `/api/flows` | Flow Rule 목록 |
| `POST` | `/api/flows` | 수동 Flow Rule 후보 생성 |
| `GET` | `/api/path/status` | 경로 상태 |
| `WS` | `/ws/analyzer` | 실시간 메시지 |

## Analyzer API

### 상태 수신

```http
POST /api/analyzer/status
```

PostgreSQL `sdn_controller.analyzer`에 Analyzer별 최신 상태를 upsert하고 `analyzer_status`를 방송한다.

### 패킷 요약

```http
POST /api/analyzer/packet-summary
```

InfluxDB에 트래픽·프로토콜·호스트 통계를 저장하고 `packet_summary`를 방송한다.

### 탐지 요약

```http
POST /api/analyzer/detection-summary
```

대시보드용 네트워크 상태를 저장하고 `detection_summary`를 방송한다. 개별 보안 사건은 Security API를 사용한다.

## Security API

### 이벤트 수신

```http
POST /api/security/events
```

요청은 `backend/app/schemas/security.py`의 `SecurityEventsRequest`로 검증한다.

```json
{
  "timestamp": "2026-07-09T00:00:00+00:00",
  "analyzer_id": "analyzer-1",
  "events": [
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
        "reply_count": 1,
        "score": 95,
        "matched_conditions": [
          "ARP Reply 패킷",
          "Gateway IP를 sender IP로 사용",
          "신뢰 Gateway MAC과 다른 MAC 사용",
          "ARP sender MAC 확인됨",
          "Ethernet source MAC과 ARP sender MAC 일치",
          "대상 호스트 IP 포함"
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
  ]
}
```

처리 순서:

1. Elasticsearch `sdn-security-events`에 이벤트 원본 저장
2. PostgreSQL `security_responses`에 대응 내역 생성
3. mitigation이 있으면 PostgreSQL `flow_rules`에 PENDING 후보 생성
4. `security_events` WebSocket 메시지 방송

중복 방지:

- SecurityResponse: `event_fingerprint + response_action`
- FlowRule: `event_fingerprint + action`

### 이벤트 조회

```http
GET /api/security/events?limit=100
```

```json
{
  "limit": 100,
  "items": []
}
```

`limit` 범위는 1~500이다.

### 대응 내역 조회

```http
GET /api/security/responses?limit=50
```

대응 상태는 최초 `PENDING`이다. Controller 결과에 따라 `APPLIED`, `FAILED` 등으로 갱신하는 연동은 별도 단계다.

## Flow API

### 목록

```http
GET /api/flows
GET /api/flows?src_ip=10.0.0.2
```

ARP Flow Rule은 IP 대신 `src_mac`, `arp_spa` match를 사용할 수 있다.

### 수동 생성

```http
POST /api/flows
```

```json
{
  "switch_id": "s1",
  "match": {
    "ipv4_src": "10.0.0.2",
    "ipv4_dst": "10.0.0.4",
    "ip_proto": 1
  },
  "action": "RATE_LIMIT",
  "priority": 500,
  "idle_timeout": 60,
  "hard_timeout": 300,
  "rate_limit_pps": 100
}
```

생성 결과는 PostgreSQL에 `PENDING`으로 저장되며 이 API 자체가 Controller에 설치하지는 않는다.

## Dashboard API

조회 범위는 `5m`, `1h`, `24h`, `1w`처럼 duration 문자열을 사용한다.

```http
GET /api/dashboard/summary
GET /api/dashboard/traffic?range=5m&bucket=5s
GET /api/dashboard/protocols?range=1m
GET /api/dashboard/suspicious-hosts?range=1w
```

ARP Spoofing은 공격자 IP를 신뢰할 수 없으므로 의심 호스트 IP 집계보다 Security Events 화면의 MAC 표시를 우선한다.

## Path API

```http
GET /api/path/status
```

현재 경로 상태는 대시보드 요약과 PENDING Flow Rule을 조합한 프로젝트용 상태다. 실제 Controller 경로 전환 결과와의 동기화는 아직 연결되지 않았다.

## WebSocket

```http
WS /ws/analyzer
```

서버 메시지:

| 타입 | 내용 |
|---|---|
| `analyzer_status` | Analyzer 상태 |
| `packet_summary` | 패킷 요약 |
| `detection_summary` | 대시보드 탐지 요약 |
| `security_events` | 보안 이벤트 묶음, 대응 내역, Flow Rule 후보 |

보안 메시지 예시:

```json
{
  "type": "security_events",
  "data": {
    "timestamp": "2026-07-09T00:00:00+00:00",
    "analyzer_id": "analyzer-1",
    "events": [],
    "security_responses": [],
    "flow_rules": []
  }
}
```
