# Backend API 명세서

이 문서는 현재 코드 기준으로 백엔드 서버가 제공하는 HTTP/WebSocket API를 정리한다.

- FastAPI 앱: `backend/app/main.py`
- 분석 서버 수신 API: `backend/app/api/analyzer.py`
- 대시보드 조회 API: `backend/app/api/dashboard.py`
- 플로우 조회/생성 API: `backend/app/api/flows.py`
- 경로 제어 API: `backend/app/api/path.py`
- 보안 이벤트 조회 API: `backend/app/api/security.py`
- WebSocket API: `backend/app/api/ws.py`

## 기본 정보

| 항목 | 값 |
|---|---|
| 기본 HTTP URL | `http://localhost:8000` |
| 기본 WebSocket URL | `ws://localhost:8000/ws/analyzer` |
| Frontend rewrite | `/api/:path*` -> `${BACKEND_INTERNAL_URL}/api/:path*` |
| Content-Type | `application/json` |
| API 문서 | FastAPI 기본 `/docs`, `/redoc`, `/openapi.json` |

## 공통 규칙

### 성공 응답

분석 서버 수신용 POST API는 성공 시 아래 응답을 반환한다.

```json
{
  "ok": true
}
```

조회 API는 엔드포인트별 JSON 객체를 반환한다.

### 오류 응답

| 상황 | Status | 형식 |
|---|---:|---|
| Pydantic body/query 검증 실패 | 422 | FastAPI 기본 validation error |
| 잘못된 duration 값 | 400 | `{"detail": "Duration must look like 5s, 1m, 2h, 1d, or 1w"}` |
| 저장소 연결/처리 오류 | 500 | FastAPI 기본 internal server error |

### Duration Query 형식

`range`, `bucket` 파라미터는 아래 정규식을 따른다.

```text
^[1-9][0-9]*[smhdw]$
```

예: `5s`, `1m`, `2h`, `1d`, `1w`

## 1. Health Check

```http
GET /health
```

### Response Body

```json
{
  "status": "ok"
}
```

## 2. Analyzer API

### 2.1 분석 서버 상태 조회

```http
GET /api/analyzer/status
```

PostgreSQL `sdn_controller.analyzer`에 저장된 분석 서버 상태를 조회한다.

### Query Parameters

| 이름 | 타입 | 필수 | 기본값 | 설명 |
|---|---|---:|---|---|
| `analyzer_id` | `string` | X | 없음 | 지정하면 해당 분석 서버만 조회 |

### Response Body

```json
{
  "items": [
    {
      "analyzer_id": "analyzer-1",
      "status": "running",
      "interface": "en0",
      "capture_active": true,
      "backend_connected": true,
      "last_packet_at": "2026-05-24T10:00:04+00:00",
      "last_summary_sent_at": "2026-05-24T10:00:05+00:00",
      "error_message": null,
      "reported_at": "2026-05-24T10:00:05+00:00",
      "created_at": "2026-05-24T09:59:00+00:00",
      "updated_at": "2026-05-24T10:00:05+00:00"
    }
  ]
}
```

### 2.2 분석 서버 상태 수신

```http
POST /api/analyzer/status
```

분석 서버가 전송한 상태를 수신한다. 상세 request body는 `analyzer/analyzer-backend-api.md`의 "분석 서버 상태 전달"을 따른다.

### Response Body

```json
{
  "ok": true
}
```

### Side Effects

- PostgreSQL `sdn_controller.analyzer`에 upsert한다.
- WebSocket으로 `{"type":"analyzer_status","data":...}` 메시지를 broadcast한다.

### 2.3 패킷 요약 수신

```http
POST /api/analyzer/packet-summary
```

분석 서버가 전송한 패킷 요약을 수신한다. 상세 request body는 `analyzer/analyzer-backend-api.md`의 "패킷 요약 전달"을 따른다.

### Response Body

```json
{
  "ok": true
}
```

### Side Effects

- InfluxDB `traffic_summary`, `protocol_stats`, `host_traffic` measurement에 저장한다. `host_traffic`은 `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol` 기준의 집계 트래픽을 저장한다.
- WebSocket으로 `{"type":"packet_summary","data":...}` 메시지를 broadcast한다.

### 2.4 탐지 요약 수신

```http
POST /api/analyzer/detection-summary
```

분석 서버가 전송한 탐지 요약을 수신한다. 상세 request body는 `analyzer/analyzer-backend-api.md`의 "탐지 요약 전달"을 따른다.

현재 분석 서버 구현은 `total_bps=total_bits`, `total_pps=total_packets`로 전송한다. 기본 `WINDOW_SEC=1`에서는 초당 값과 동일하다.

### Response Body

```json
{
  "ok": true
}
```

### Side Effects

- InfluxDB `network_status` measurement에 저장한다.
- WebSocket으로 `{"type":"detection_summary","data":...}` 메시지를 broadcast한다.

## 3. Dashboard API

### 3.1 대시보드 요약

```http
GET /api/dashboard/summary
```

InfluxDB `traffic_summary` measurement의 최근 5분 데이터를 기반으로 합계 지표와 최신 pps/bps를 반환한다.

### Response Body

```json
{
  "total_packets": 12000,
  "total_bytes": 8892301,
  "current_pps": 90.0,
  "current_bps": 273960.0,
  "network_status": "normal"
}
```

### 3.2 트래픽 시계열

```http
GET /api/dashboard/traffic
```

InfluxDB `traffic_summary` measurement에서 트래픽 시계열을 조회한다.

### Query Parameters

| 이름 | 타입 | 필수 | 기본값 | 설명 |
|---|---|---:|---|---|
| `range` | `duration` | X | `5m` | 조회 기간 |
| `bucket` | `duration` | X | `5s` | 집계 bucket 크기 |

### Response Body

```json
{
  "range": "5m",
  "bucket": "5s",
  "items": [
    {
      "timestamp": "2026-05-24T10:00:00+00:00",
      "total_packets": 450,
      "total_bits": 1369800,
      "pps": 90.0,
      "bps": 273960.0
    }
  ]
}
```

### 3.3 프로토콜 통계

```http
GET /api/dashboard/protocols
```

InfluxDB `protocol_stats` measurement에서 프로토콜별 패킷 수를 조회한다.

### Query Parameters

| 이름 | 타입 | 필수 | 기본값 | 설명 |
|---|---|---:|---|---|
| `range` | `duration` | X | `1m` | 조회 기간 |

### Response Body

```json
{
  "range": "1m",
  "items": [
    {
      "protocol": "TCP",
      "packet_count": 870,
      "percentage": 96.7
    },
    {
      "protocol": "UDP",
      "packet_count": 30,
      "percentage": 3.3
    }
  ]
}
```

### 3.4 의심 호스트 조회

```http
GET /api/dashboard/suspicious-hosts
```

Elasticsearch `sdn-security-events` 인덱스의 최신 보안 이벤트에서 의심 호스트 목록을 파생해 조회한다.

### Query Parameters

| 이름 | 타입 | 필수 | 기본값 | 설명 |
|---|---|---:|---|---|
| `range` | `duration` | X | `1w` | 과거 클라이언트 호환용 파라미터. 현재 응답은 최신 보안 이벤트 기준 |

### Response Body

```json
{
  "range": "1w",
  "count": 1,
  "items": [
    {
      "timestamp": "2026-05-24T10:00:00+00:00",
      "analyzer_id": "analyzer-1",
      "host": "10.0.0.11",
      "ip": "10.0.0.11",
      "protocol": "TCP",
      "bps": 0.0,
      "pps": 0.0,
      "reasons": [
        "tcp_syn_unique_ports"
      ],
      "attack_type": "PORT_SCAN",
      "severity": "medium",
      "status": "detected"
    }
  ]
}
```

## 4. Flows API

### 4.1 Flow 목록 조회

```http
GET /api/flows
```

PostgreSQL `sdn_controller.flow_rules`에 저장된 flow rule 목록을 조회한다. `src_ip`를 지정하면 `match.ipv4_src` 기준으로 필터링한다.

### Query Parameters

| 이름 | 타입 | 필수 | 기본값 | 설명 |
|---|---|---:|---|---|
| `src_ip` | `string` | X | 없음 | `match.ipv4_src` 기준 필터 |

### Response Body

```json
{
  "items": [
    {
      "id": "rule-uuid-001",
      "source_event_id": "evt-4c8a9d4d4d5a",
      "source_event_fingerprint": "0ebbf7a9e17e3c7c894f6f06be0d0405f911adab",
      "security_response_id": "resp-uuid-001",
      "analyzer_id": "analyzer-1",
      "switch_id": null,
      "target": "flow",
      "action": "RATE_LIMIT",
      "match": {
        "eth_type": 2048,
        "ipv4_src": "10.0.0.2",
        "ipv4_dst": "10.0.0.4",
        "ip_proto": 1
      },
      "priority": 500,
      "idle_timeout": 60,
      "hard_timeout": 300,
      "rate_limit_pps": 100,
      "status": "PENDING",
      "controller_rule_id": null,
      "controller_response": null,
      "error_message": null,
      "requested_at": null,
      "applied_at": null,
      "created_at": "2026-05-24T10:00:00+00:00",
      "updated_at": "2026-05-24T10:00:00+00:00",
      "timestamp": "2026-05-24T10:00:00+00:00",
      "src_ip": "10.0.0.2",
      "dst_ip": "10.0.0.4",
      "protocol": "ICMP"
    }
  ]
}
```

### 4.2 Flow Rule 수동 생성

```http
POST /api/flows
```

운영자가 Flow Rule 화면에서 입력한 rule을 PostgreSQL `sdn_controller.flow_rules`에 `PENDING` 상태로 저장한다. 현재 구현은 DB 생성까지이며 SDN 컨트롤러 실제 설치는 수행하지 않는다.

### Request Body

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
  "rate_limit_pps": 100
}
```

### Request Fields

| 이름 | 타입 | 필수 | 기본값 | 설명 |
|---|---|---:|---|---|
| `switch_id` | `string \| null` | X | `null` | 적용 대상 스위치 ID |
| `match` | `object` | O | `{}` | flow match 조건 |
| `action` | `string` | O | 없음 | `RATE_LIMIT`, `DROP`, `output:s2` 등 |
| `priority` | `integer` | X | `100` | 우선순위. `1 <= priority <= 65535` |
| `idle_timeout` | `integer \| null` | X | `null` | idle timeout |
| `hard_timeout` | `integer \| null` | X | `null` | hard timeout |
| `rate_limit_pps` | `integer \| null` | X | `null` | rate limit pps |

### Response Body

생성된 flow rule 객체를 반환한다. 응답 필드는 `GET /api/flows`의 item과 동일하다.

## 5. Path API

### 경로 제어 상태 조회

```http
GET /api/path/status
```

Controller의 연속된 OpenFlow 포트 통계 snapshot을 비교해 스위치와 경로별
BPS/PPS를 계산한다. 메인 대시보드의 1경로·2경로 막대는 하드웨어 BPS 용량이
아니라 `PATH_CAPACITY_PPS` 대비 경로 PPS를 사용한다. 기본 1,000 PPS의
80%에서 분산을 시작하고 60% 미만이 3회 연속 관측되면 1경로로 복귀한다. 링크별
수치는 양 끝의 실제 연결 포트 counter를 사용하며, 물리 링크 상태(`state`)와
선택 경로 여부(`selected`)를 분리해 반환한다.

### Response Body

```json
{
  "active_path": "backup",
  "network_status": "normal",
  "paths": {
    "primary": {
      "name": "primary",
      "nodes": ["s1", "s2", "s4"],
      "utilization": 0,
      "pps": 950,
      "pps_utilization": 95,
      "active": false
    },
    "backup": {
      "name": "backup",
      "nodes": ["s1", "s3", "s4"],
      "utilization": 0,
      "pps": 420,
      "pps_utilization": 42,
      "active": true
    }
  },
  "links": [
    {
      "id": "s1-s2",
      "source": "s1",
      "target": "s2",
      "source_port": 4,
      "target_port": 1,
      "path": "primary",
      "state": "active",
      "selected": false,
      "active": true,
      "bps": 1000000.0,
      "rx_bps": 1000000.0,
      "tx_bps": 500000.0,
      "utilization": 10.0,
      "capacity_bps": 10000000,
      "pps": 950.0,
      "rx_pps": 500.0,
      "tx_pps": 450.0,
      "pps_utilization": 95.0,
      "capacity_pps": 1000,
      "sampled": true
    }
  ],
  "switches": [
    {
      "switch_id": "s1",
      "dpid": "0000000000000001",
      "state": "connected",
      "bps": 2000000.0,
      "rx_bps": 1000000.0,
      "tx_bps": 2000000.0,
      "utilization": 20.0,
      "capacity_bps": 10000000,
      "sample_interval_seconds": 5.0,
      "sampled": true,
      "ports": [
        {
          "port_no": 4,
          "bps": 1000000.0,
          "rx_bps": 1000000.0,
          "tx_bps": 500000.0,
          "utilization": 10.0,
          "capacity_bps": 10000000,
          "sampled": true
        }
      ],
      "status": "normal"
    }
  ],
  "utilization_source": "openflow_port_counter_delta",
  "path_distribution_mode": "balanced",
  "path_capacity_pps": 1000,
  "path_distribution_threshold_pps": 800,
  "path_distribution_recovery_pps": 600,
  "history": [
    {
      "id": "rule-uuid-001",
      "time": "2026-05-24T10:00:00+00:00",
      "from": "primary",
      "to": "RATE_LIMIT",
      "reason": "evt-001 대응",
      "status": "PENDING"
    }
  ]
}
```

PPS는 topology에 등록된 포트의 RX/TX packet counter 증분으로 계산한다.
OVS 미러 출력처럼 topology에 없는 관측용 포트는 제외한다. 경로 PPS는 해당
경로 링크 가운데 가장 큰 값을 사용하고, 기본 1,000 PPS를 100%로 표시한다.
800 PPS 이상에서 분산을 시작하며, 600 PPS 미만이 3회 연속 관측되면
1경로로 복귀한다. 1,000 PPS를 넘으면 백분율은 100%를 초과할 수 있지만
막대 길이는 100%로 제한한다. 첫 snapshot은 비교 대상이 없어
`sampled=false`를 반환한다.
`path_distribution_mode=balanced`이면 두 경로가 모두 선택 상태다.

## 6. Security API

### 보안 이벤트 수신

```http
POST /api/security/events
```

분석 서버가 전송한 공통 보안 이벤트 payload를 수신한다.

### Request Body

상세 request body는 `analyzer/analyzer-backend-api.md`의 "보안 이벤트 전달"을 따른다.

### Side Effects

- Elasticsearch `sdn-security-events` 인덱스에 이벤트 단위로 저장한다.
- PostgreSQL `sdn_controller.security_responses`에 이벤트별 대응 내역을 `PENDING` 상태로 저장한다.
- 이벤트에 `mitigation`이 있으면 PostgreSQL `sdn_controller.flow_rules`에 flow rule 후보를 `PENDING` 상태로 저장한다.
- WebSocket으로 `{"type":"security_events","data":...}` 메시지를 broadcast한다.

`security_responses`는 `event_fingerprint + response_action`, `flow_rules`는 `event_fingerprint + action` 기준으로 중복 생성을 방지한다.

### 보안 이벤트 목록 조회

```http
GET /api/security/events
```

Elasticsearch `sdn-security-events` 인덱스에서 최신 보안 이벤트를 조회한다.

### Query Parameters

| 이름 | 타입 | 필수 | 기본값 | 제약 | 설명 |
|---|---|---:|---|---|---|
| `limit` | `integer` | X | `50` | `1 <= limit <= 500` | 반환할 최대 이벤트 수 |

### Response Body

```json
{
  "limit": 50,
  "items": [
    {
      "id": "elastic-document-id",
      "@timestamp": "2026-05-24T10:00:00+00:00",
      "event_id": "evt-4c8a9d4d4d5a",
      "event_fingerprint": "0ebbf7a9e17e3c7c894f6f06be0d0405f911adab",
      "dedup_key": "0ebbf7a9e17e3c7c894f6f06be0d0405f911adab",
      "timestamp": "2026-05-24T10:00:00+00:00",
      "analyzer_id": "analyzer-1",
      "attack_category": "RECON",
      "attack_type": "PORT_SCAN",
      "severity": "medium",
      "confidence": "high",
      "status": "detected",
      "src_ip": "10.0.0.2",
      "dst_ip": "10.0.0.4",
      "protocol": "TCP",
      "detection_rule": "tcp_syn_unique_ports",
      "recommended_action": "alert",
      "response_level": "L2",
      "evidence": {
        "matched_conditions": [
          "tcp_syn_without_ack",
          "same_source_target_pair",
          "unique_dst_port_threshold_exceeded",
          "syn_count_threshold_satisfied"
        ],
        "window_seconds": 5,
        "unique_dst_port_count": 20,
        "unique_dst_ports": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
        "syn_count": 20,
        "score": 70
      },
      "mitigation": null
    }
  ]
}
```

### 보안 대응 목록 조회

```http
GET /api/security/responses
```

PostgreSQL `sdn_controller.security_responses`에 저장된 최신 보안 대응 내역을 조회한다.

### Query Parameters

| 이름 | 타입 | 필수 | 기본값 | 제약 | 설명 |
|---|---|---:|---|---|---|
| `limit` | `integer` | X | `50` | `1 <= limit <= 500` | 반환할 최대 대응 내역 수 |

### Response Body

```json
{
  "limit": 50,
  "items": [
    {
      "id": "resp-uuid-001",
      "source_event_id": "evt-4c8a9d4d4d5a",
      "source_event_fingerprint": "0ebbf7a9e17e3c7c894f6f06be0d0405f911adab",
      "analyzer_id": "analyzer-1",
      "attack_category": "DOS",
      "attack_type": "ICMP_FLOOD",
      "severity": "high",
      "recommended_action": "rate_limit",
      "response_action": "RATE_LIMIT",
      "response_level": "L2",
      "status": "PENDING",
      "decision_reason": "created from analyzer security event recommendation",
      "mitigation": {
        "action": "RATE_LIMIT",
        "target": "flow"
      },
      "response_payload": null,
      "approved_by": null,
      "detected_at": "2026-05-24T10:00:00+00:00",
      "approved_at": null,
      "requested_at": null,
      "completed_at": null,
      "error_message": null,
      "created_at": "2026-05-24T10:00:00+00:00",
      "updated_at": "2026-05-24T10:00:00+00:00"
    }
  ]
}
```

## 7. WebSocket API

```http
WS /ws/analyzer
```

백엔드가 분석 서버 수신 API에서 받은 이벤트를 실시간으로 broadcast한다. 클라이언트가 보낸 text message는 현재 별도 처리 없이 receive loop 유지에만 사용된다.

### Server -> Client Messages

#### Analyzer Status

```json
{
  "type": "analyzer_status",
  "data": {
    "timestamp": "2026-05-24T10:00:05+00:00",
    "analyzer_id": "analyzer-1",
    "status": "running",
    "interface": "en0",
    "capture_active": true,
    "backend_connected": true,
    "last_packet_at": "2026-05-24T10:00:04+00:00",
    "last_summary_sent_at": "2026-05-24T10:00:05+00:00",
    "error_message": null
  }
}
```

#### Packet Summary

```json
{
  "type": "packet_summary",
  "data": {
    "timestamp": "2026-05-24T10:00:00+00:00",
    "analyzer_id": "analyzer-1",
    "window_sec": 1,
    "total_packets": 90,
    "total_bits": 273960,
    "protocol_stats": {
      "TCP": 87
    },
    "host_stats": []
  }
}
```

#### Detection Summary

```json
{
  "type": "detection_summary",
  "data": {
    "timestamp": "2026-05-24T10:00:00+00:00",
    "analyzer_id": "analyzer-1",
    "network_status": "warning",
    "total_bps": 273960.0,
    "total_pps": 90.0,
    "active_flow_count": 15
  }
}
```

#### Security Events

```json
{
  "type": "security_events",
  "data": {
    "timestamp": "2026-05-24T10:00:00+00:00",
    "analyzer_id": "analyzer-1",
    "events": []
  }
}
```

프론트엔드 타입에는 과거 호환용으로 `traffic_analysis`, `security_event`, `topology_update` 메시지도 정의되어 있지만, 현재 백엔드 코드가 직접 broadcast하는 메시지는 `analyzer_status`, `packet_summary`, `detection_summary`, `security_events`다.

## 추가 예정

### 분석 서버 설정 변경 응답

백엔드가 분석 서버에 탐지 임계값, 캡처 상태, 정책 버전 같은 설정 변경을 요청하는 기능이 추가되면, 분석 서버가 적용 결과를 백엔드로 보고하는 별도 메시지를 도입할 수 있다.

현재 보안 대응과 flow rule 생성의 입력은 `POST /api/security/events`의 보안 이벤트이며, 별도의 분석 변경 메시지 API는 구현하지 않는다.
