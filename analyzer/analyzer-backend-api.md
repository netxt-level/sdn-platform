# Analyzer -> Backend API 명세서

이 문서는 현재 코드 기준으로 분석 서버가 백엔드 서버에 전송하는 API를 정리한다.

- 분석 서버 호출 구현: `analyzer/app/backend_client.py`
- 분석 서버 payload 생성: `analyzer/app/packet/summary.py`, `analyzer/app/detection/traffic_stats.py`, `analyzer/app/detection/security_events.py`, `analyzer/app/analyzer_status.py`
- 백엔드 수신 스키마: `backend/app/schemas/analyzer.py`
- 백엔드 수신 라우터: `backend/app/api/analyzer.py`

## 기본 정보

| 항목 | 값 |
|---|---|
| 기본 Backend URL | `BACKEND_BASE_URL`, 기본값 `http://127.0.0.1:8000` |
| Content-Type | `application/json` |
| Timestamp 형식 | ISO 8601 문자열, 예: `2026-05-24T10:00:00+00:00` |
| 공통 성공 응답 | `{"ok": true}` |
| 유효성 검증 실패 | FastAPI 기본 `422 Unprocessable Entity` |

분석 서버는 `ANALYZER_WINDOW_SEC`마다 패킷 요약, 트래픽 상태 요약, 보안 이벤트를 전송하고, `ANALYZER_STATUS_INTERVAL_SEC`마다 상태를 전송한다.

| 환경변수 | 기본값 | 설명 |
|---|---:|---|
| `ANALYZER_ID` | `analyzer-1` | 분석 서버 식별자 |
| `ANALYZER_INTERFACE` | `eth0` | 패킷 캡처 인터페이스 |
| `ANALYZER_WINDOW_SEC` | `1` | 패킷/탐지 요약 집계 주기 |
| `ANALYZER_STATUS_INTERVAL_SEC` | `5` | 상태 보고 주기 |
| `BACKEND_BASE_URL` | `http://127.0.0.1:8000` | 백엔드 API base URL |
| `PORT_SCAN_WINDOW_SEC` | `5` | Port Scan SYN 집계 윈도우 |
| `PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD` | `15` | Port Scan 고유 목적지 포트 임계값 |
| `PORT_SCAN_SYN_COUNT_THRESHOLD` | `30` | Port Scan SYN 시도 수 보조 조건 기준 |
| `PORT_SCAN_MULTI_TARGET_WINDOW_SEC` | `30` | Port Scan 다중 목적지 판단 윈도우 |
| `PORT_SCAN_HORIZONTAL_TARGET_THRESHOLD` | `3` | Port Scan 수평 스캔 목적지 수 기준 |
| `PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD` | `50` | Port Scan 높은 고유 포트 수 기준 |
| `PORT_SCAN_ALERT_COOLDOWN_SEC` | `60` | Port Scan 중복 알림 억제 시간 |
| `ICMP_PPS_THRESHOLD` | `150` | ICMP Flood pps 임계값 |
| `ICMP_MIN_PACKET_COUNT` | `100` | ICMP Flood 최소 패킷 수 기준 |
| `ICMP_HIGH_PPS_THRESHOLD` | `500` | ICMP Flood high pps 기준 |
| `ICMP_CRITICAL_PPS_THRESHOLD` | `1000` | ICMP Flood critical pps 기준 |
| `UDP_PPS_THRESHOLD` | `250` | UDP Flood pps 임계값 |
| `UDP_MIN_PACKET_COUNT` | `100` | UDP Flood 최소 패킷 수 기준 |
| `UDP_HIGH_PPS_THRESHOLD` | `800` | UDP Flood high pps 기준 |
| `UDP_CRITICAL_PPS_THRESHOLD` | `1500` | UDP Flood critical pps 기준 |
| `UDP_BPS_THRESHOLD` | `2000000` | UDP Flood bps 임계값 |
| `UDP_HIGH_BPS_THRESHOLD` | `8000000` | UDP Flood high bps 기준 |
| `UDP_CRITICAL_BPS_THRESHOLD` | `15000000` | UDP Flood critical bps 기준 |
| `SYN_PPS_THRESHOLD` | `120` | SYN Flood pps 임계값 |
| `SYN_MIN_COUNT` | `30` | SYN Flood 최소 SYN 수 기준 |
| `SYN_HIGH_PPS_THRESHOLD` | `400` | SYN Flood high pps 기준 |
| `SYN_CRITICAL_PPS_THRESHOLD` | `800` | SYN Flood critical pps 기준 |
| `SYN_MAX_UNIQUE_PORTS` | `5` | SYN Flood로 볼 최대 목적지 포트 수 |
| `EVENT_DEDUP_WINDOW_SEC` | `60` | 보안 이벤트 공통 중복 억제 시간 |
| `RATE_LIMIT_PRIORITY` | `500` | Rate limit 후보 flow rule 우선순위 |
| `RATE_LIMIT_IDLE_TIMEOUT` | `60` | Rate limit 후보 idle timeout |
| `RATE_LIMIT_HARD_TIMEOUT` | `300` | Rate limit 후보 hard timeout |
| `RATE_LIMIT_PPS` | `100` | Rate limit 후보 제한 pps |
| `DROP_PRIORITY` | `700` | Drop 후보 flow rule 우선순위 |
| `DROP_IDLE_TIMEOUT` | `30` | Drop 후보 idle timeout |
| `DROP_HARD_TIMEOUT` | `120` | Drop 후보 hard timeout |

## 1. 패킷 요약 전달

```http
POST /api/analyzer/packet-summary
```

분석 서버가 집계 윈도우 동안 수집한 패킷을 프로토콜, 호스트 쌍 단위로 요약해 전송한다. 원본 패킷 payload는 포함하지 않는다.

### Request Body

```json
{
  "timestamp": "2026-05-24T10:00:00+00:00",
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
      "src_port": 443,
      "dst_host": null,
      "dst_ip": "172.30.1.3",
      "dst_port": 51544,
      "protocol": "TCP",
      "packet_count": 16,
      "bit_count": 81192
    }
  ]
}
```

### 필드

| 필드 | 타입 | 필수 | 설명 |
|---|---|---:|---|
| `timestamp` | `datetime` | O | 패킷 요약 생성 시각 |
| `analyzer_id` | `string` | O | 분석 서버 식별자 |
| `window_sec` | `integer` | O | 집계 시간, 초 단위 |
| `total_packets` | `integer` | O | 윈도우 내 전체 패킷 수 |
| `total_bits` | `integer` | O | 윈도우 내 전체 비트 수 |
| `protocol_stats` | `object<string, integer>` | O | 프로토콜별 패킷 수 |
| `host_stats` | `HostStat[]` | O | 출발지/목적지/프로토콜별 통계 |

### HostStat

| 필드 | 타입 | 필수 | 설명 |
|---|---|---:|---|
| `src_host` | `string \| null` | X | 출발지 호스트명 |
| `src_ip` | `string \| null` | X | 출발지 IP |
| `src_port` | `integer \| null` | X | 출발지 포트. 포트가 없는 프로토콜이면 `null` |
| `dst_host` | `string \| null` | X | 목적지 호스트명 |
| `dst_ip` | `string \| null` | X | 목적지 IP |
| `dst_port` | `integer \| null` | X | 목적지 포트. 포트가 없는 프로토콜이면 `null` |
| `protocol` | `string` | O | 프로토콜 이름 |
| `packet_count` | `integer` | O | 해당 호스트 쌍, 포트, 프로토콜의 패킷 수 |
| `bit_count` | `integer` | O | 해당 호스트 쌍, 포트, 프로토콜의 비트 수 |

### Response Body

```json
{
  "ok": true
}
```

### 백엔드 처리

- InfluxDB에 `traffic_summary`, `protocol_stats`, `host_traffic` measurement로 저장한다. `host_traffic`은 `src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol` 기준으로 조회할 수 있게 저장한다.
- WebSocket `/ws/analyzer` 구독자에게 아래 메시지를 broadcast한다.

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

## 2. 트래픽 상태 요약 전달

```http
POST /api/analyzer/detection-summary
```

분석 서버가 패킷 요약을 기반으로 네트워크 전체 트래픽 상태를 전송한다. 의심 호스트와 공격 탐지 결과는 이 payload에 포함하지 않고, `POST /api/security/events`로 분리한다.

코드상 분석 서버 메서드명은 `send_traffic_stats`지만, 실제 호출 경로는 기존 호환 경로인 `/api/analyzer/detection-summary`다.

### Request Body

```json
{
  "timestamp": "2026-05-24T10:00:00+00:00",
  "analyzer_id": "analyzer-1",
  "network_status": "warning",
  "total_bps": 273960.0,
  "total_pps": 90.0,
  "active_flow_count": 15
}
```

### 필드

| 필드 | 타입 | 필수 | 설명 |
|---|---|---:|---|
| `timestamp` | `datetime` | O | 탐지 요약 생성 시각 |
| `analyzer_id` | `string` | O | 분석 서버 식별자 |
| `network_status` | `string` | O | 네트워크 상태. 현재 생성값은 `normal`, `warning`, `critical` |
| `total_bps` | `number` | O | 전체 초당 비트 수 |
| `total_pps` | `number` | O | 전체 초당 패킷 수 |
| `active_flow_count` | `integer` | O | 현재 윈도우에서 관측한 flow 개수 |

`TrafficStatsBuilder`는 윈도우 내 누적 패킷 수와 비트 수를 `window_sec`로 나누어 `total_pps`, `total_bps`를 초당 값으로 생성한다.

`network_status`는 전체 트래픽 기준으로 계산한다.

- `critical`: 전체 `total_bps` 또는 `total_pps`가 critical 기준 이상
- `warning`: 전체 `total_bps` 또는 `total_pps`가 suspicious 기준 이상
- `normal`: 위 조건에 해당하지 않음

### Response Body

```json
{
  "ok": true
}
```

### 백엔드 처리

- InfluxDB에 `network_status` measurement로 저장한다.
- WebSocket `/ws/analyzer` 구독자에게 아래 메시지를 broadcast한다.

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

## 3. 보안 이벤트 전달

```http
POST /api/security/events
```

분석 서버가 보안 탐지 결과를 공통 이벤트 형식으로 전송한다. 현재 analyzer 구현 범위는 `PORT_SCAN`, `ICMP_FLOOD`, `UDP_FLOOD`, `SYN_FLOOD`다.

### Request Body

```json
{
  "timestamp": "2026-05-24T10:00:00+00:00",
  "analyzer_id": "analyzer-1",
  "events": [
    {
      "event_id": "evt-4c8a9d4d4d5a",
      "event_fingerprint": "0ebbf7a9e17e3c7c894f6f06be0d0405f911adab44a7e7d0d62f4f4a3f0d9b1a",
      "dedup_key": "0ebbf7a9e17e3c7c894f6f06be0d0405f911adab44a7e7d0d62f4f4a3f0d9b1a",
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
      "detection_rule": "tcp_syn_port_scan",
      "recommended_action": "alert",
      "response_level": "L1",
      "evidence": {
        "matched_conditions": [
          "TCP SYN 패킷",
          "ACK 없이 연결 시도",
          "단일 대상의 고유 목적지 포트 기준 초과"
        ],
        "window_seconds": 5,
        "unique_dst_port_count": 15,
        "unique_dst_ports": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        "syn_count": 15,
        "scan_type": "vertical",
        "score": 50
      },
      "mitigation": null
    },
    {
      "event_id": "evt-8e44e9b97a2c",
      "event_fingerprint": "764e3e790da17f7a5e21e51af7b4d06608bd450a3f114eead915a6c6b68f22ad",
      "dedup_key": "764e3e790da17f7a5e21e51af7b4d06608bd450a3f114eead915a6c6b68f22ad",
      "timestamp": "2026-05-24T10:00:00+00:00",
      "analyzer_id": "analyzer-1",
      "attack_category": "FLOOD",
      "attack_type": "UDP_FLOOD",
      "severity": "critical",
      "confidence": "high",
      "status": "detected",
      "src_ip": "10.0.0.2",
      "dst_ip": "10.0.0.4",
      "protocol": "UDP",
      "detection_rule": "udp_flood_rate_threshold",
      "recommended_action": "drop",
      "response_level": "L3",
      "evidence": {
        "matched_conditions": [
          "UDP 패킷",
          "BPS 기준 초과",
          "최소 패킷 수 기준 충족",
          "여러 분석 구간에서 반복 초과",
          "Critical 기준 즉시 초과"
        ],
        "window_seconds": 1,
        "packet_count": 2000,
        "pps": 2000,
        "bps": 16000000,
        "pps_threshold": 250,
        "bps_threshold": 2000000,
        "high_pps_threshold": 800,
        "critical_pps_threshold": 1500,
        "unique_dst_port_count": 1,
        "destination_port": 9999,
        "dominant_dst_port": 9999,
        "dominant_port_ratio": 1.0,
        "exceeded_windows": 2,
        "required_exceeded_windows": 2,
        "drop_allowed": true,
        "score": 90
      },
      "mitigation": {
        "action": "DROP",
        "target": "flow",
        "match": {
          "eth_type": 2048,
          "ipv4_src": "10.0.0.2",
          "ipv4_dst": "10.0.0.4",
          "ip_proto": 17,
          "udp_dst": 9999
        },
        "priority": 700,
        "idle_timeout": 30,
        "hard_timeout": 120
      }
    }
  ]
}
```

### 필드

| 필드 | 타입 | 필수 | 설명 |
|---|---|---:|---|
| `timestamp` | `datetime` | O | 이벤트 묶음 생성 시각 |
| `analyzer_id` | `string` | O | 분석 서버 식별자 |
| `events` | `SecurityEvent[]` | O | 보안 이벤트 목록 |

### SecurityEvent

| 필드 | 타입 | 필수 | 설명 |
|---|---|---:|---|
| `event_id` | `string` | O | 이벤트 식별자. `event_fingerprint + window_start_epoch` 기반으로 생성 |
| `event_fingerprint` | `string` | O | 같은 공격 흐름을 묶는 안정적인 fingerprint |
| `dedup_key` | `string` | O | 중복 억제 기준 키. 기본값은 `event_fingerprint` |
| `timestamp` | `datetime` | O | 이벤트 발생/생성 시각 |
| `analyzer_id` | `string` | O | 분석 서버 식별자 |
| `attack_category` | `string` | O | 공격 분류. 현재 `RECON`, `FLOOD` |
| `attack_type` | `string` | O | 탐지 유형. 현재 `PORT_SCAN`, `ICMP_FLOOD`, `UDP_FLOOD`, `SYN_FLOOD` |
| `severity` | `string` | O | 위험도. 현재 `low`, `medium`, `high`, `critical` |
| `confidence` | `string` | O | 탐지 신뢰도. 현재 `medium`, `high` |
| `status` | `string` | O | 이벤트 상태. 최초 생성값은 `detected` |
| `src_ip` | `string` | O | 공격/의심 트래픽 출발지 IP |
| `dst_ip` | `string` | O | 공격/의심 트래픽 대상 IP |
| `protocol` | `string` | O | 프로토콜 |
| `detection_rule` | `string` | O | 적용된 탐지 기준 이름 |
| `recommended_action` | `string` | O | 권장 대응. 현재 `log`, `alert`, `rate_limit`, `drop` |
| `response_level` | `string` | O | 대응 레벨. 현재 `L0`, `L1`, `L2`, `L3` |
| `evidence` | `object` | O | 탐지 유형별 상세 근거 |
| `mitigation` | `object \| null` | O | 컨트롤러 적용용 대응 후보. `alert` 이하는 `null`, `rate_limit`은 `RATE_LIMIT`, `drop`은 `DROP` 후보 |

### 탐지별 evidence

| attack_type | detection_rule | 주요 evidence |
|---|---|---|
| `PORT_SCAN` | `tcp_syn_port_scan` | `matched_conditions`, `window_seconds`, `scan_type`, `unique_dst_port_count`, `unique_dst_ports`, `target_count`, `target_ips`, `syn_count`, `score` |
| `ICMP_FLOOD` | `icmp_flood_rate_threshold` | `matched_conditions`, `window_seconds`, `icmp_type`, `packet_count`, `pps`, `bps`, `pps_threshold`, `high_pps_threshold`, `critical_pps_threshold`, `exceeded_windows`, `score` |
| `UDP_FLOOD` | `udp_flood_rate_threshold` | `matched_conditions`, `window_seconds`, `packet_count`, `pps`, `bps`, `destination_port`, `unique_dst_port_count`, `dominant_dst_port`, `dominant_port_ratio`, `pps_threshold`, `bps_threshold`, `exceeded_windows`, `score` |
| `SYN_FLOOD` | `tcp_syn_single_service_rate` | `matched_conditions`, `window_seconds`, `destination_port`, `syn_count`, `response_count`, `syn_response_ratio`, `unique_dst_port_count`, `score` |

### 백엔드 처리

백엔드는 `POST /api/security/events` 요청을 검증한 뒤 이벤트 단위로 처리한다.

- `backend/app/schemas/security.py`의 `SecurityEventPayload` / `SecurityEvent` 스키마로 요청을 검증한다.
- Elasticsearch `sdn-security-events` 인덱스에 이벤트 단위로 저장한다.
- PostgreSQL `sdn_controller.security_responses`에 이벤트별 대응 내역을 `PENDING` 상태로 저장한다.
- 이벤트에 `mitigation`이 있으면 PostgreSQL `sdn_controller.flow_rules`에 flow rule 후보를 `PENDING` 상태로 저장한다.
- WebSocket `/ws/analyzer` 구독자에게 `{"type":"security_events","data":...}` 메시지를 broadcast한다.
- 의심 호스트 조회는 저장된 보안 이벤트를 기반으로 제공한다.

## 4. 분석 서버 상태 전달

```http
POST /api/analyzer/status
```

분석 서버의 실행 상태, 캡처 상태, 백엔드 전송 상태를 전송한다.

### Request Body

```json
{
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
```

### 필드

| 필드 | 타입 | 필수 | 설명 |
|---|---|---:|---|
| `timestamp` | `datetime` | O | 상태 정보 생성 시각 |
| `analyzer_id` | `string` | O | 분석 서버 식별자 |
| `status` | `string` | O | 분석 서버 상태. 현재 생성값은 `running`, `error` |
| `interface` | `string` | O | 캡처 중인 네트워크 인터페이스 |
| `capture_active` | `boolean` | O | 패킷 캡처 활성 여부 |
| `backend_connected` | `boolean` | O | 최근 백엔드 전송 성공 여부 |
| `last_packet_at` | `datetime \| null` | X | 마지막 패킷 수신 시각 |
| `last_summary_sent_at` | `datetime \| null` | X | 마지막 요약 전송 성공 시각 |
| `error_message` | `string \| null` | X | 오류 메시지 |

### Response Body

```json
{
  "ok": true
}
```

### 백엔드 처리

- PostgreSQL `sdn_controller.analyzer` 테이블에 `analyzer_id` 기준 upsert한다.
- WebSocket `/ws/analyzer` 구독자에게 아래 메시지를 broadcast한다.

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

## 전송 실패 처리

분석 서버의 `BackendClient`는 각 POST 요청에 `timeout_sec=3.0`을 사용한다.

| 실패 유형 | 분석 서버 동작 |
|---|---|
| 연결 실패 | 콘솔에 전송 실패 로그 출력, `False` 반환 |
| Timeout | 콘솔에 timeout 로그 출력, `False` 반환 |
| HTTP 오류 응답 | 콘솔에 HTTP status 로그 출력, `False` 반환 |
| 기타 요청 오류 | 콘솔에 일반 요청 오류 로그 출력, `False` 반환 |

패킷 요약, 탐지 요약, 보안 이벤트 전송이 모두 성공하면 `backend_connected=true` 및 `last_summary_sent_at`을 갱신한다. 하나라도 실패하면 `backend_connected=false`, `error_message="failed to send analyzer metrics or security events"`로 상태를 갱신한다.

보안 이벤트 전송이 실패하면 이미 만든 이벤트를 메모리 대기 큐에 남겨 다음 분석 구간에서 다시 전송한다. 그래서 Port Scan처럼 탐지기 내부 cooldown이 있는 항목도 백엔드 장애 때문에 이벤트가 바로 유실되지 않는다. 큐 크기를 넘어서 밀려난 이벤트만 중복 억제 기록에서 제거해 이후 분석 구간에서 다시 만들어질 수 있게 한다.

## 추가 예정

### 분석 서버 설정 변경 응답

백엔드가 분석 서버에 탐지 임계값, 캡처 상태, 정책 버전 같은 설정 변경을 요청하는 기능이 추가되면, 분석 서버가 적용 결과를 백엔드로 보고하는 별도 메시지를 도입할 수 있다.

현재 analyzer 기반 보안 대응과 flow rule 후보 생성의 입력은 `POST /api/security/events`의 보안 이벤트다. 백엔드에는 운영자가 수동 flow rule을 추가하는 `POST /api/flows`도 있지만, analyzer는 이 API를 직접 호출하지 않는다. 별도의 분석 변경 메시지 API는 구현하지 않는다.
