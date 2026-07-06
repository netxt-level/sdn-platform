# Backend API 명세서

이 문서는 현재 코드 기준으로 백엔드 서버가 제공하는 HTTP/WebSocket API를 정리한다.

- FastAPI 앱: `backend/app/main.py`
- 분석 서버 수신 API: `backend/app/api/analyzer.py`
- 대시보드 조회 API: `backend/app/api/dashboard.py`
- 플로우 조회 API: `backend/app/api/flows.py`
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
- Elasticsearch `sdn-traffic-summary` 인덱스에 저장한다.
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

- InfluxDB `network_status`, `suspicious_host_traffic` measurement에 저장한다.
- Elasticsearch `sdn-detection-events` 인덱스에 저장한다.
- WebSocket으로 `{"type":"detection_summary","data":...}` 메시지를 broadcast한다.

## 3. Dashboard API

### 3.1 대시보드 요약

```http
GET /api/dashboard/summary
```

현재 코드에서는 고정 mock 값을 반환한다.

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

InfluxDB `suspicious_host_traffic` measurement에서 최신 의심 호스트 목록을 조회한다.

### Query Parameters

| 이름 | 타입 | 필수 | 기본값 | 설명 |
|---|---|---:|---|---|
| `range` | `duration` | X | `1w` | 조회 기간 |

### Response Body

```json
{
  "range": "1w",
  "count": 1,
  "items": [
    {
      "timestamp": "2026-05-24T10:00:00+00:00",
      "analyzer_id": "analyzer-1",
      "host": "52.182.143.209",
      "ip": "52.182.143.209",
      "protocol": "TCP",
      "bps": 81192.0,
      "pps": 16.0,
      "reasons": [
        "DoS"
      ],
      "attack_type": "DOS"
    }
  ]
}
```

## 4. Flows API

### Flow 목록 조회

```http
GET /api/flows
```

현재 코드에서는 고정 sample 값을 반환한다. `src_ip` query parameter를 받을 수 있지만, 현재 구현에서는 필터링에 사용하지 않는다.

### Query Parameters

| 이름 | 타입 | 필수 | 기본값 | 설명 |
|---|---|---:|---|---|
| `src_ip` | `string` | X | 없음 | 현재 미사용 |

### Response Body

```json
{
  "items": [
    {
      "timestamp": "2026-05-24T10:00:00+09:00",
      "src_ip": "52.182.143.209",
      "dst_ip": "172.30.1.3",
      "protocol": "TCP",
      "packet_count": 16,
      "byte_count": 10149
    }
  ]
}
```

## 5. Security API

### 보안 이벤트 목록 조회

```http
GET /api/security/events
```

Elasticsearch `sdn-detection-events` 인덱스에서 최신 탐지 이벤트를 조회한다.

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
      "timestamp": "2026-05-24T10:00:00+00:00",
      "analyzer_id": "analyzer-1",
      "network_status": "warning",
      "total_bps": 273960.0,
      "total_pps": 90.0,
      "active_flow_count": 15,
      "suspicious_host_count": 1,
      "suspicious_hosts": [
        {
          "host": "52.182.143.209",
          "ip": "52.182.143.209",
          "protocol": "TCP",
          "bps": 81192.0,
          "pps": 16.0,
          "reasons": [
            "DoS"
          ],
          "attack_type": "DOS"
        }
      ]
    }
  ]
}
```

## 6. WebSocket API

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
    "active_flow_count": 15,
    "suspicious_host_count": 1,
    "suspicious_hosts": []
  }
}
```

프론트엔드 타입에는 과거 호환용으로 `traffic_analysis`, `security_event`, `topology_update` 메시지도 정의되어 있지만, 현재 백엔드 코드가 직접 broadcast하는 메시지는 `analyzer_status`, `packet_summary`, `detection_summary`다.
