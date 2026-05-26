# Analyzer → Backend API 명세서

## 공통 규칙

### Content-Type

```http
Content-Type: application/json
```

### 공통 성공 응답

```json
{
  "success": true,
  "message": "요청 처리 성공"
}
```

### 공통 실패 응답

```json
{
  "success": false,
  "message": "요청 처리 실패",
  "error": {
    "code": "INVALID_REQUEST",
    "detail": "상세 오류 메시지"
  }
}
```

---

## 1. 패킷 요약 정보 전달

### Endpoint

```http
POST /api/backend/analyzer/packet-summary
```

### 설명

Analyzer가 일정 시간 동안 수집한 패킷 메타데이터를 요약하여 Backend로 전달한다.

패킷 payload 원문은 포함하지 않는다.

### Request Body

```json
{
  "timestamp": "2026-05-24T10:00:00+09:00",
  "analyzer_id": "analyzer-1",
  "window_sec": 1,
  "total_packets": 90,
  "total_bits": 273960,
  "protocol_stats": {
    "TCP": 87,
    "UDP": 2,
    "UNKNOWN": 1
  },
  "host_stats": [
    {
      "src_host": null,
      "src_ip": "52.182.143.209",
      "dst_host": null,
      "dst_ip": "172.30.1.3",
      "protocol": "TCP",
      "packet_count": 16,
      "bit_count": 81192
    }
  ]
}
```

### 주요 필드

| 필드 | 설명 |
|---|---|
| `timestamp` | 패킷 요약 생성 시각 |
| `analyzer_id` | Analyzer 식별자 |
| `window_sec` | 집계 시간 범위, 초 단위 |
| `total_packets` | 집계 시간 내 전체 패킷 수 |
| `total_bits` | 집계 시간 내 전체 비트 수 |
| `protocol_stats` | 프로토콜별 패킷 수 |
| `host_stats` | 출발지, 목적지, 프로토콜별 트래픽 요약 |

### `host_stats` 필드

| 필드 | 설명 |
|---|---|
| `src_host` | 출발지 호스트 이름, 알 수 없으면 `null` |
| `src_ip` | 출발지 IP |
| `dst_host` | 목적지 호스트 이름, 알 수 없으면 `null` |
| `dst_ip` | 목적지 IP |
| `protocol` | 프로토콜 이름 |
| `packet_count` | 해당 호스트 쌍과 프로토콜의 패킷 수 |
| `bit_count` | 해당 호스트 쌍과 프로토콜의 비트 수 |

### Response Body

```json
{
  "success": true,
  "message": "패킷 요약 정보 수신 완료"
}
```

---

## 2. 트래픽 통계 전달

### Endpoint

```http
POST /api/backend/analyzer/traffic-stats
```

### 설명

`packet-summary`를 기반으로 계산한 네트워크 상태 요약 정보를 Backend로 전달한다.

대시보드 카드, 프로토콜 비율 차트, 의심 호스트 표시 등에 사용한다.

### Request Body

```json
{
  "timestamp": "2026-05-24T10:00:00+09:00",
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
        "bps threshold exceeded"
      ]
    }
  ]
}
```

### 주요 필드

| 필드 | 설명 |
|---|---|
| `timestamp` | 트래픽 통계 생성 시각 |
| `analyzer_id` | Analyzer 식별자 |
| `network_status` | 네트워크 상태, `normal`, `warning`, `critical` |
| `total_bps` | 전체 초당 비트 수 |
| `total_pps` | 전체 초당 패킷 수 |
| `active_flow_count` | 현재 윈도우에서 관측된 flow 개수 |
| `suspicious_host_count` | suspicious 상태 host 수 |
| `suspicious_hosts` | 임계치 기준을 초과한 의심 host 목록 |

### `suspicious_hosts` 필드

| 필드 | 설명 |
|---|---|
| `host` | 출발지 호스트 이름 또는 IP |
| `ip` | 출발지 IP |
| `protocol` | 의심 트래픽의 프로토콜 |
| `bps` | 해당 host의 초당 총 비트 수 |
| `pps` | 해당 host의 초당 총 패킷 수 |
| `reasons` | 의심 호스트로 판단한 사유 목록 |

### Response Body

```json
{
  "success": true,
  "message": "트래픽 통계 수신 완료"
}
```

---

## 3. 분석 서버 상태 전달

### Endpoint

```http
POST /api/backend/analyzer/status
```

### 설명

Analyzer의 실행 상태, 캡처 상태, Backend 연결 상태를 Backend로 전달한다.

Frontend에서 Analyzer 연결 상태를 표시하는 데 사용할 수 있다.

### Request Body

```json
{
  "timestamp": "2026-05-24T10:00:05+09:00",
  "analyzer_id": "analyzer-1",
  "status": "running",
  "interface": "en0",
  "capture_active": true,
  "backend_connected": true,
  "last_packet_at": "2026-05-24T10:00:04+09:00",
  "last_summary_sent_at": "2026-05-24T10:00:05+09:00",
  "error_message": null
}
```

### 주요 필드

| 필드 | 설명 |
|---|---|
| `timestamp` | 상태 정보 생성 시각 |
| `analyzer_id` | Analyzer 식별자 |
| `status` | Analyzer 상태, `running`, `error`, `stopped` |
| `interface` | 캡처 중인 네트워크 인터페이스 |
| `capture_active` | 패킷 캡처 활성 여부 |
| `backend_connected` | Backend 전송 성공 여부 |
| `last_packet_at` | 마지막 패킷 수신 시각 |
| `last_summary_sent_at` | 마지막 packet-summary 또는 traffic-stats 전송 성공 시각 |
| `error_message` | 오류 메시지, 없으면 `null` |

### Response Body

```json
{
  "success": true,
  "message": "분석 서버 상태 수신 완료"
}
```

---

## 전송 주기

| 데이터 | 권장 전송 주기 |
|---|---|
| `packet-summary` | 1초 |
| `traffic-stats` | 1초 |
| `status` | 5초 |

---

## 저장 방향

Analyzer는 DB 저장 방식을 알 필요가 없다.

Backend는 수신한 JSON을 저장소 목적에 맞게 분해하여 저장한다.

예시:

| API | 저장 방향 |
|---|---|
| `packet-summary` | InfluxDB의 `packet_summary_total`, `protocol_traffic`, `host_traffic` 등으로 분해 저장 |
| `traffic-stats` | InfluxDB의 `traffic_status`, `suspicious_hosts` 등으로 분해 저장 |
| `status` | PostgreSQL 또는 InfluxDB에 최신 상태 중심으로 저장 |
