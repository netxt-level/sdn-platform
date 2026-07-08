# Analyzer -> Backend API 명세서

이 문서는 현재 코드 기준으로 분석 서버가 백엔드 서버에 전송하는 API를 정리한다.

- 분석 서버 호출 구현: `analyzer/app/backend_client.py`
- 분석 서버 payload 생성: `analyzer/app/packet/summary.py`, `analyzer/app/detection/traffic_stats.py`, `analyzer/app/security/backend_contract.py`, `analyzer/app/analyzer_status.py`
- 백엔드 수신 스키마: `backend/app/schemas/analyzer.py`
- 백엔드 수신 라우터: `backend/app/api/analyzer.py`, `backend/app/api/security.py`

## 기본 정보

| 항목 | 값 |
|---|---|
| 기본 Backend URL | `BACKEND_BASE_URL`, 기본값 `http://127.0.0.1:8000` |
| Content-Type | `application/json` |
| Timestamp 형식 | ISO 8601 문자열, 예: `2026-05-24T10:00:00+00:00` |
| 공통 성공 응답 | `{"ok": true}` |
| 유효성 검증 실패 | FastAPI 기본 `422 Unprocessable Entity` |

분석 서버는 `ANALYZER_WINDOW_SEC`마다 패킷 요약, 탐지 요약, 보안 이벤트를 전송하고, `ANALYZER_STATUS_INTERVAL_SEC`마다 상태를 전송한다.

| 환경변수 | 기본값 | 설명 |
|---|---:|---|
| `ANALYZER_ID` | `analyzer-1` | 분석 서버 식별자 |
| `ANALYZER_INTERFACE` | `en0` | 패킷 캡처 인터페이스 |
| `ANALYZER_WINDOW_SEC` | `1` | 패킷/탐지 요약 집계 주기 |
| `ANALYZER_STATUS_INTERVAL_SEC` | `5` | 상태 보고 주기 |
| `SECURITY_WINDOW_SEC` | `10` | 보안 이벤트 판단용 rolling window |
| `SECURITY_EVENT_COOLDOWN_SEC` | `30` | 같은 보안 이벤트 중복 전송 억제 시간 |
| `SECURITY_GATEWAY_IP` | `10.0.0.254` | ARP Spoofing 판단에 사용할 Gateway IP |
| `SECURITY_GATEWAY_MAC` | `00:00:00:00:ff:ff` | 정상 Gateway MAC |
| `BACKEND_BASE_URL` | `http://127.0.0.1:8000` | 백엔드 API base URL |

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
      "dst_host": null,
      "dst_ip": "172.30.1.3",
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
| `dst_host` | `string \| null` | X | 목적지 호스트명 |
| `dst_ip` | `string \| null` | X | 목적지 IP |
| `protocol` | `string` | O | 프로토콜 이름 |
| `packet_count` | `integer` | O | 해당 호스트 쌍과 프로토콜의 패킷 수 |
| `bit_count` | `integer` | O | 해당 호스트 쌍과 프로토콜의 비트 수 |

### Response Body

```json
{
  "ok": true
}
```

### 백엔드 처리

- InfluxDB에 `traffic_summary`, `protocol_stats`, `host_traffic` measurement로 저장한다.
- Elasticsearch `sdn-traffic-summary` 인덱스에 저장한다.
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

## 2. 탐지 요약 전달

```http
POST /api/analyzer/detection-summary
```

분석 서버가 패킷 요약과 탐지기 결과를 기반으로 네트워크 상태 및 의심 호스트 목록을 전송한다.

코드상 분석 서버 메서드명은 `send_traffic_stats`지만, 실제 호출 경로는 `/api/analyzer/detection-summary`다.

### Request Body

```json
{
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
| `suspicious_host_count` | `integer` | O | 의심 호스트 수 |
| `suspicious_hosts` | `SuspiciousHost[]` | O | 의심 호스트 목록 |

`TrafficStatsBuilder`는 윈도우 내 누적 패킷 수와 비트 수를 `window_sec`로 나누어 `total_pps`, `total_bps`를 초당 값으로 생성한다.

### SuspiciousHost

| 필드 | 타입 | 필수 | 설명 |
|---|---|---:|---|
| `host` | `string \| null` | X | 호스트명 또는 IP |
| `ip` | `string` | O | 의심 호스트 IP |
| `protocol` | `string` | O | 의심 트래픽 프로토콜 |
| `bps` | `number` | O | 해당 호스트 초당 비트 수 |
| `pps` | `number` | O | 해당 호스트 초당 패킷 수 |
| `reasons` | `string[]` | O | 의심 판단 사유 |
| `attack_type` | `string \| null` | X | 공격/이상 트래픽 유형. 현재 생성값은 `DOS`, `PORT_SCAN` |

현재 백엔드의 탐지 요약 스키마는 위 필드만 모델에 포함한다. 포트 스캔 의심 호스트 탐지기가 내부적으로 만드는 `target_ip`, `unique_dst_port_count` 같은 추가 필드는 탐지 요약 payload에는 포함하지 않는다. 자세한 근거와 대응 후보는 별도 보안 이벤트 API로 전송한다.

### Response Body

```json
{
  "ok": true
}
```

### 백엔드 처리

- InfluxDB에 `network_status`, `suspicious_host_traffic` measurement로 저장한다.
- Elasticsearch `sdn-detection-events` 인덱스에 저장한다.
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
    "active_flow_count": 15,
    "suspicious_host_count": 1,
    "suspicious_hosts": []
  }
}
```

## 3. 보안 이벤트 전달

```http
POST /api/security/events
```

분석 서버가 보안 엔진에서 생성한 이벤트 묶음과 컨트롤러 대응 후보를 전송한다. 이벤트는 Elasticsearch에 저장되고, WebSocket `/ws/analyzer` 구독자에게 `security_event` 메시지로 broadcast된다.

### Request Body

```json
{
  "summary": {
    "window_seconds": 10,
    "packet_count": 5,
    "event_count": 1
  },
  "events": [
    {
      "id": "evt-170e39469b66",
      "event_id": "evt-170e39469b66",
      "occurred_at": "2026-07-03T00:00:09+00:00",
      "attack_type": "ARP_SPOOFING",
      "severity": "critical",
      "status": "detected",
      "src_ip": "",
      "src_mac": "00:00:00:00:00:02",
      "dst_ip": "10.0.0.254",
      "protocol": "ARP",
      "pps": 0.0,
      "bps": 0.0,
      "action": "block",
      "mitigation_action": "DROP",
      "evidence": {
        "spoofed_ip": "10.0.0.254",
        "attacker_mac": "00:00:00:00:00:02",
        "trusted_mac": "00:00:00:00:ff:ff"
      },
      "flow_rule": {
        "action": "DROP",
        "match": {
          "eth_type": "ARP",
          "arp_spa": "10.0.0.254",
          "eth_src": "00:00:00:00:00:02"
        },
        "priority": 650,
        "reason": "arp spoofing block"
      }
    }
  ],
  "controller_requests": [
    {
      "action": "DROP",
      "match": {
        "eth_type": "ARP",
        "arp_spa": "10.0.0.254",
        "eth_src": "00:00:00:00:00:02"
      },
      "priority": 650,
      "idle_timeout": 60,
      "hard_timeout": 300,
      "rate_limit_pps": null,
      "reroute_path": null,
      "reason": "arp spoofing block"
    }
  ]
}
```

### 주요 이벤트 필드

| 필드 | 타입 | 필수 | 설명 |
|---|---|---:|---|
| `id` | `string` | O | 프론트엔드 표시용 이벤트 ID |
| `event_id` | `string` | O | 분석 서버가 생성한 이벤트 ID |
| `occurred_at` | `datetime` | O | 이벤트 발생 시각 |
| `attack_type` | `string` | O | `ARP_SPOOFING`, `PORT_SCAN`, `ICMP_FLOOD` 등 이벤트 유형 |
| `severity` | `string` | O | 프론트엔드 표시용 위험도. `low`, `medium`, `high`, `critical` |
| `status` | `string` | O | 프론트엔드 표시용 상태. 기본값은 `detected` |
| `src_ip` | `string` | O | 출발지 IP. MAC 기반 이벤트에서는 빈 문자열일 수 있음 |
| `src_mac` | `string` | X | 출발지 MAC |
| `dst_ip` | `string` | O | 목적지 IP 또는 보호 대상 IP |
| `protocol` | `string` | O | `ARP`, `ICMP`, `TCP`, `UDP` 등 |
| `pps` | `number` | O | 이벤트 판단에 사용한 pps. 해당 없으면 `0.0` |
| `bps` | `number` | O | 이벤트 판단에 사용한 bps. 해당 없으면 `0.0` |
| `action` | `string` | O | 프론트엔드 표시용 조치. `none`, `block`, `reroute` |
| `mitigation_action` | `string` | O | 원본 대응 후보. `DROP`, `RATE_LIMIT`, `REROUTE`, `MONITOR_ONLY` |
| `evidence` | `object` | X | 탐지 근거 |
| `flow_rule` | `object \| null` | X | 대응 후보 flow rule |

### Response Body

```json
{
  "ok": true
}
```

### 백엔드 처리

- Elasticsearch `sdn-detection-events` 인덱스에 이벤트를 저장한다.
- WebSocket `/ws/analyzer` 구독자에게 이벤트별로 아래 메시지를 broadcast한다.

```json
{
  "type": "security_event",
  "data": {
    "id": "evt-170e39469b66",
    "attack_type": "ARP_SPOOFING",
    "severity": "critical",
    "status": "detected",
    "src_ip": "",
    "dst_ip": "10.0.0.254",
    "protocol": "ARP",
    "pps": 0.0,
    "bps": 0.0,
    "action": "block"
  }
}
```

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

패킷 요약, 탐지 요약, 보안 이벤트 전송이 모두 성공하면 `backend_connected=true` 및 `last_summary_sent_at`을 갱신한다. 하나라도 실패하면 `backend_connected=false`, `error_message="failed to send analyzer metrics"`로 상태를 갱신한다.
