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
| 요청 본문 크기 제한 초과 | 413 | `{"detail": "요청 본문 크기는 최대 ... bytes까지 허용됩니다."}` |
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
GET /health/live
GET /health/ready
```

`/health`와 `/health/live`는 백엔드 프로세스가 살아 있는지 확인한다. `/health/ready`는 PostgreSQL, InfluxDB, Elasticsearch 연결 가능 여부와 `sdn-security-events` 인덱스 존재 여부를 함께 확인한다.

### Response Body

```json
{
  "status": "ok"
}
```

Readiness가 일부 실패하면 HTTP `503`과 함께 아래처럼 반환한다.

```json
{
  "status": "degraded",
  "postgres": "ok",
  "influxdb": "error",
  "elasticsearch": "ok"
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
      "interface": "eth0",
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
- PostgreSQL에는 분석 서버 상태와 보안 이벤트 대기 수, 드롭 수, 패킷 버퍼 드롭 수, 마지막 보안 이벤트 전송 실패 시각을 함께 저장한다. 같은 payload는 WebSocket으로도 전달한다.

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

- InfluxDB `traffic_summary`, `protocol_stats`, `host_traffic` measurement에 저장한다. `host_traffic`은 `src_ip`, `dst_ip`, `protocol` 기준으로 합산한다.
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

InfluxDB `traffic_summary` measurement에서 트래픽 시계열을 조회한다. 여러 Analyzer가 같은 시간대에 값을 보내면 `_time` bucket 기준으로 합산해 전체 네트워크 트래픽으로 반환한다.

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

Elasticsearch `sdn-security-events` 인덱스의 보안 이벤트에서 의심 호스트 목록을 파생해 조회한다.

### Query Parameters

| 이름 | 타입 | 필수 | 기본값 | 설명 |
|---|---|---:|---|---|
| `range` | `duration` | X | `1w` | Elasticsearch `@timestamp` 기준 조회 기간. 예: `1h`, `1d`, `1w` |

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
| `limit` | `integer` | X | `100` | `1 <= limit <= 500` |
| `offset` | `integer` | X | `0` | `offset >= 0` |

### Response Body

```json
{
  "limit": 100,
  "offset": 0,
  "total": 1,
  "has_more": false,
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

관리자 권한을 가진 호출자가 전달한 rule을 PostgreSQL `sdn_controller.flow_rules`에 `PENDING` 상태로 저장한다. 현재 구현은 DB 생성까지이며 SDN 컨트롤러 실제 설치는 수행하지 않는다. 프론트엔드 Flow Rule 화면은 로그인/관리자 권한 확인 기능이 없으므로 이 생성 기능을 호출하지 않고 조회 전용으로 동작한다.

요청 본문은 최대 64KB까지 허용한다.

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
| `switch_id` | `string` | O | 없음 | 적용 대상 스위치 ID |
| `match` | `object` | O | 없음 | IPv4 OpenFlow match 조건. 허용 필드는 `eth_type`, `ipv4_src`, `ipv4_dst`, `ip_proto`, `tcp_src`, `tcp_dst`, `udp_src`, `udp_dst`, `icmpv4_type`, `icmpv4_code` |
| `action` | `string` | O | 없음 | `RATE_LIMIT`, `DROP`, `output:s2` 형식 |
| `priority` | `integer` | X | `100` | 우선순위. `1 <= priority <= 65535` |
| `idle_timeout` | `integer \| null` | X | `null` | idle timeout |
| `hard_timeout` | `integer \| null` | X | `null` | hard timeout |
| `rate_limit_pps` | `integer \| null` | X | `null` | rate limit pps |

`match`에 정의되지 않은 필드가 있거나, TCP/UDP/ICMP 조건과 `ip_proto`가 맞지 않으면 `422`로 거절한다. `DROP`과 `RATE_LIMIT`은 `eth_type` 또는 `ip_proto`만 있는 넓은 match를 허용하지 않고, IP 주소, 포트, ICMP 타입 중 하나 이상의 구체적인 조건이 필요하다.

### Response Body

생성된 flow rule 객체를 반환한다. 응답 필드는 `GET /api/flows`의 item과 동일하다.

## 5. Path API

### 경로 제어 상태 조회

```http
GET /api/path/status
```

대시보드 요약과 `sdn_controller.flow_rules`를 조합해 경로 제어 화면에서 사용할 기본/우회 경로 상태, 링크 사용률, 경로 변경 이력을 반환한다.

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
      "active": false
    },
    "backup": {
      "name": "backup",
      "nodes": ["s1", "s3", "s4"],
      "utilization": 0,
      "active": true
    }
  },
  "links": [
    {
      "id": "s1-s2",
      "source": "s1",
      "target": "s2",
      "path": "primary",
      "active": false,
      "utilization": 0
    }
  ],
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

현재 `active_path`는 네트워크 상태와 재사용 가능한 `PENDING` 대응 flow rule 존재 여부를 기반으로 파생한다. 10분이 지난 `PENDING` 후보는 경로 우회 판단에서 제외한다. 실제 컨트롤러 경로 전환 상태와 동기화하는 기능은 아직 연결되어 있지 않다.

## 6. Security API

### 보안 이벤트 수신

```http
POST /api/security/events
```

분석 서버가 전송한 공통 보안 이벤트 payload를 수신한다.

### Request Body

상세 request body는 `analyzer/analyzer-backend-api.md`의 "보안 이벤트 전달"을 따른다.

### Side Effects

- Elasticsearch `sdn-security-events` 인덱스에 `event_id`를 문서 `_id`로 사용해 bulk 저장한다. 같은 이벤트가 재전송되면 새 문서를 만들지 않고 기존 문서를 갱신한다. `evidence`는 `_source`에는 저장하지만 세부 key를 인덱싱하지 않는다.
- PostgreSQL `sdn_controller.security_responses`에 이벤트별 대응 내역을 `PENDING` 상태로 저장한다.
- 이벤트에 `mitigation`이 있으면 PostgreSQL `sdn_controller.flow_rules`에 flow rule 후보를 `PENDING` 상태로 저장한다. 기존 후보는 `switch_id`, `match`, `target`, action 강도, `rate_limit_pps`, `priority`, `idle_timeout`, `hard_timeout`이 새 요청보다 같거나 강할 때만 재사용한다. timeout `0`은 영구 규칙으로 보고, 신규 요청이 `0`이면 기존 규칙도 `0`일 때만 재사용한다. `APPLIED` 상태인데 `applied_at`이 없거나 남은 `hard_timeout`이 부족한 규칙은 재사용하지 않는다. 기존 후보를 재사용한 경우에도 해당 `security_response`의 `response_payload`에 `flow_rule_id`, `flow_rule_reused`, `flow_rule_action`, `flow_rule_switch_id`, `flow_rule_match`를 남긴다.
- WebSocket으로 `{"type":"security_events","data":...}` 메시지를 broadcast한다.

`SecurityEvent`는 현재 구현된 `PORT_SCAN`, `ICMP_FLOOD`, `UDP_FLOOD`, `SYN_FLOOD`와 IPv4 주소만 허용한다. 보안 이벤트 batch는 최대 100개이며, 요청 전체의 `analyzer_id`와 이벤트 내부 `analyzer_id`가 다르면 거부한다. `evidence`는 중첩 깊이, 문자열 길이, 리스트 길이, key 길이를 제한하고, `/api/security/events` 요청 본문은 최대 1MB로 제한한다.

`security_responses`는 `event_id + response_action` 기준으로 같은 이벤트 재전송 중복을 방지한다. 같은 fingerprint라도 새로운 `event_id`로 들어오면 별도 대응 이력으로 남긴다. `flow_rules`는 현재 재사용 가능한 상태이고 `switch_id`, `match`, `target`이 같으며 기존 action이 새 요청보다 같거나 강할 때만 재사용한다. `RATE_LIMIT`끼리는 `rate_limit_pps`가 더 낮거나 같을 때만 더 강한 제한으로 본다. `PENDING`과 `APPROVED` 상태가 10분을 넘거나 `APPLYING` 상태가 5분을 넘으면 적용이 멈춘 후보로 보고 재사용하지 않는다.

수동 Flow Rule 생성 요청은 `switch_id`가 필요하다. `DROP`과 `RATE_LIMIT`은 `eth_type`이나 `ip_proto`만 있는 넓은 match를 허용하지 않고, IP 주소, 포트, ICMP 타입 중 하나 이상의 구체적인 조건이 있어야 한다.

Analyzer 입력 API와 수동 Flow Rule 생성 API는 각각 `ANALYZER_API_KEY`, `ADMIN_API_KEY`를 요구한다. 키가 비어 있으면 기본적으로 서버 설정 오류로 처리하며, 로컬 개발에서만 `ALLOW_INSECURE_DEV_AUTH=true`를 명시해 인증을 비활성화할 수 있다. 프론트엔드의 `/api/flows` POST route는 사용자 로그인/권한 확인이 없으므로 현재 403을 반환한다.

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

백엔드가 분석 서버 수신 API에서 받은 이벤트를 실시간으로 broadcast한다. 여러 클라이언트에는 병렬로 전송하며, 전송 실패가 발생한 연결만 정리한다. 연결 종료와 예외는 logger에 남긴다. 클라이언트가 보낸 text message는 현재 별도 처리 없이 receive loop 유지에만 사용된다.

현재 WebSocket은 로그인 기반 인증을 적용하지 않는다. 공용 서버에 배포하려면 조회 API와 함께 Viewer/Operator/Admin 권한 모델을 추가해야 한다.

### Server -> Client Messages

#### Analyzer Status

```json
{
  "type": "analyzer_status",
  "data": {
    "timestamp": "2026-05-24T10:00:05+00:00",
    "analyzer_id": "analyzer-1",
    "status": "running",
    "interface": "eth0",
    "capture_active": true,
    "backend_connected": true,
    "last_packet_at": "2026-05-24T10:00:04+00:00",
    "last_summary_sent_at": "2026-05-24T10:00:05+00:00",
    "pending_security_event_count": 0,
    "dropped_security_event_count": 0,
    "packet_buffer_dropped_count": 0,
    "last_security_event_send_failure": null,
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
