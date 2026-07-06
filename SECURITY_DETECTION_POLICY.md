# 보안 탐지 및 대응 레벨 정책

이 문서는 SDN Platform에서 분석 서버가 생성하는 보안 탐지 이벤트와 항목별 대응 레벨을 정의한다. 현재 규정 범위는 `PORT_SCAN`, `ICMP_FLOOD`다.

그 외 탐지 항목은 이 문서의 확정 범위와 현재 구현 범위에 포함하지 않는다. 추가 항목은 담당자 간 API/탐지 기준 합의 후 별도 확장한다.

## 기본 원칙

탐지 항목마다 기본 대응 레벨을 정하되, 최종 대응 레벨은 탐지 강도와 충족 조건에 따라 조정한다.

```text
탐지 항목별 기본 레벨
+ 충족된 탐지 조건
+ 탐지 강도
+ confidence
= 최종 response_level / recommended_action
```

분석 서버는 직접 차단, rate limit, flow rule 설치를 수행하지 않는다. 분석 서버는 탐지 이벤트와 권장 대응 정보를 백엔드에 전달한다. 실제 대응 적용 여부는 백엔드/컨트롤러 정책에서 결정한다.

## 공통 이벤트 필드

보안 이벤트는 `POST /api/security/events`로 전달한다.

| 필드 | 설명 |
|---|---|
| `event_id` | 이벤트 식별자 |
| `timestamp` | 이벤트 생성 시각 |
| `analyzer_id` | 분석 서버 ID |
| `attack_category` | 공격 분류 |
| `attack_type` | 탐지 항목 |
| `severity` | 위험도 |
| `confidence` | 탐지 신뢰도 |
| `status` | 이벤트 상태. 최초 값은 `detected` |
| `src_ip` | 의심 트래픽 출발지 |
| `dst_ip` | 의심 트래픽 목적지 |
| `protocol` | 프로토콜 |
| `detection_rule` | 적용된 대표 탐지 기준 |
| `recommended_action` | 권장 대응 |
| `response_level` | 대응 레벨 |
| `evidence` | 탐지 근거 |
| `mitigation` | 적용 가능한 대응 요청 payload. 없으면 `null` |

## 대응 레벨

| 레벨 | 의미 | 백엔드 처리 | 컨트롤러/Flow Rule |
|---|---|---|---|
| `L1` | 관찰/기록 | 이벤트 저장, WebSocket 알림, 대시보드 표시 | 없음 |
| `L2` | 대응 권장 | 이벤트 저장, 알림, 대응 후보 생성 가능 | 승인 또는 정책에 따라 rate limit 후보 |
| `L3` | 강한 대응 권장 | 이벤트 저장, 높은 우선순위 알림, 대응 요청 생성 | 승인 또는 정책에 따라 차단/강한 제한 후보 |

현재 확정 범위에서 `PORT_SCAN`은 기본 `L1`, `ICMP_FLOOD`는 조건에 따라 `L1` 또는 `L2`를 사용한다. `L3`는 향후 자동 대응/차단 정책 합의 후 사용한다.

## PORT_SCAN

### 기본 정의

| 항목 | 값 |
|---|---|
| `attack_category` | `RECON` |
| `attack_type` | `PORT_SCAN` |
| `protocol` | `TCP` |
| 대표 `detection_rule` | `tcp_syn_unique_ports` |
| 기본 `response_level` | `L1` |
| 기본 `recommended_action` | `monitor` |
| 기본 `mitigation` | `null` |

### 탐지 기준

필수 조건:

| 조건 | 설명 |
|---|---|
| `tcp_syn_without_ack` | TCP SYN 플래그가 있고 ACK 플래그가 없는 연결 시도 |
| `same_source_target_pair` | 동일 `src_ip -> dst_ip` 기준으로 집계 |
| `unique_dst_port_threshold_exceeded` | 탐지 윈도우 내 서로 다른 목적지 포트 수가 기준 이상 |

기본 기준값:

| 기준값 | 기본값 |
|---|---:|
| `window_seconds` | `5` |
| `unique_dst_port_threshold` | `20` |

보조 조건:

| 조건 | 설명 |
|---|---|
| `syn_count_threshold_satisfied` | SYN 시도 수가 최소 샘플 수 이상 |
| `multi_target_scan` | 같은 출발지가 여러 목적지를 스캔 |
| `high_unique_dst_port_count` | 목적지 포트 수가 기본 기준을 크게 초과 |

### 대응 레벨 규정

| 조건 | `severity` | `confidence` | `response_level` | `recommended_action` | `mitigation` |
|---|---|---|---|---|---|
| 필수 조건 충족 | `medium` | `high` | `L1` | `monitor` | `null` |
| 필수 조건 + 보조 조건 1개 이상 | `medium` | `high` | `L2` | `alert` | `null` |

`PORT_SCAN`은 정찰 행위로 간주한다. 기본 정책은 자동 차단하지 않고 관찰/알림으로 둔다. 차단이나 rate limit은 오탐 가능성과 정상 진단 트래픽 가능성을 고려해 별도 운영 정책 승인 후 사용한다.

### 이벤트 예시

```json
{
  "event_id": "evt-...",
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
  "recommended_action": "monitor",
  "response_level": "L1",
  "evidence": {
    "matched_conditions": [
      "tcp_syn_without_ack",
      "same_source_target_pair",
      "unique_dst_port_threshold_exceeded"
    ],
    "window_seconds": 5,
    "unique_dst_port_count": 20,
    "unique_dst_ports": [21, 22, 23, 80, 443],
    "syn_count": 20,
    "score": 60
  },
  "mitigation": null
}
```

## ICMP_FLOOD

### 기본 정의

| 항목 | 값 |
|---|---|
| `attack_category` | `DDOS` |
| `attack_type` | `ICMP_FLOOD` |
| `protocol` | `ICMP` |
| 대표 `detection_rule` | `icmp_pps_threshold` |
| 기본 `response_level` | `L2` |
| 기본 `recommended_action` | `rate_limit` |

### 탐지 기준

필수 조건:

| 조건 | 설명 |
|---|---|
| `icmp_protocol` | 프로토콜이 ICMP |
| `same_source_target_pair` | 동일 `src_ip -> dst_ip` 기준으로 집계 |
| `icmp_pps_threshold_exceeded` | ICMP pps가 기준 이상 |

기본 기준값:

| 기준값 | 기본값 |
|---|---:|
| `window_seconds` | `1` |
| `icmp_pps_threshold` | `1000` |
| `min_packet_count` | 추후 설정값으로 분리 |

보조 조건:

| 조건 | 설명 |
|---|---|
| `min_packet_count_satisfied` | 최소 샘플 수 이상 |
| `high_pps_exceeded` | pps가 기준값을 크게 초과 |
| `baseline_spike_detected` | 평소 기준선 대비 급증 |

### 대응 레벨 규정

| 조건 | `severity` | `confidence` | `response_level` | `recommended_action` | `mitigation` |
|---|---|---|---|---|---|
| pps 기준만 충족 | `medium` | `medium` | `L1` | `monitor` | `null` |
| pps 기준 + 최소 샘플 조건 충족 | `high` | `medium` | `L2` | `rate_limit` | `RATE_LIMIT` 후보 |
| pps 기준 크게 초과 + 보조 조건 2개 이상 | `high` 또는 `critical` | `high` | `L3` | `rate_limit` | `RATE_LIMIT` 후보 |

현재 자동 적용은 하지 않는다. `mitigation`은 컨트롤러가 적용할 수 있는 후보 payload로만 제공한다.

### L2 Rate Limit 후보

```json
{
  "action": "RATE_LIMIT",
  "target": "flow",
  "match": {
    "eth_type": 2048,
    "ipv4_src": "10.0.0.2",
    "ipv4_dst": "10.0.0.4",
    "ip_proto": 1
  },
  "priority": 500,
  "idle_timeout": 60,
  "hard_timeout": 300,
  "rate_limit_pps": 100
}
```

### 이벤트 예시

```json
{
  "event_id": "evt-...",
  "timestamp": "2026-05-24T10:00:00+00:00",
  "analyzer_id": "analyzer-1",
  "attack_category": "DDOS",
  "attack_type": "ICMP_FLOOD",
  "severity": "high",
  "confidence": "medium",
  "status": "detected",
  "src_ip": "10.0.0.2",
  "dst_ip": "10.0.0.4",
  "protocol": "ICMP",
  "detection_rule": "icmp_pps_threshold",
  "recommended_action": "rate_limit",
  "response_level": "L2",
  "evidence": {
    "matched_conditions": [
      "icmp_protocol",
      "same_source_target_pair",
      "icmp_pps_threshold_exceeded",
      "min_packet_count_satisfied"
    ],
    "window_seconds": 1,
    "packet_count": 1200,
    "pps": 1200,
    "pps_threshold": 1000,
    "score": 80
  },
  "mitigation": {
    "action": "RATE_LIMIT",
    "target": "flow",
    "match": {
      "eth_type": 2048,
      "ipv4_src": "10.0.0.2",
      "ipv4_dst": "10.0.0.4",
      "ip_proto": 1
    },
    "priority": 500,
    "idle_timeout": 60,
    "hard_timeout": 300,
    "rate_limit_pps": 100
  }
}
```

## 이벤트 상태

분석 서버가 최초 생성하는 이벤트 상태는 항상 `detected`다. 이후 상태 변경은 백엔드/컨트롤러 대응 흐름에서 관리한다.

| 상태 | 의미 |
|---|---|
| `detected` | 탐지됨 |
| `mitigation_requested` | 대응 요청 생성됨 |
| `mitigating` | 대응 적용 중 |
| `mitigated` | 대응 적용 완료 |
| `failed` | 대응 실패 |
| `ignored` | 운영자 또는 정책에 의해 무시 |
| `resolved` | 정상화 또는 종료 |

## 구현 반영 TODO

| 항목 | 설명 |
|---|---|
| `matched_conditions` 추가 | 현재 security event evidence에 충족 조건 목록을 포함하도록 수정 |
| `score` 추가 | 조건별 가중치를 계산해 evidence에 포함 |
| `PORT_SCAN` evidence 보강 | `unique_dst_ports`, `syn_count` 추가 |
| `ICMP_FLOOD` mitigation 후보 추가 | L2 이상일 때 `RATE_LIMIT` 후보 payload 포함 |
| threshold 설정 분리 | 기준값을 환경변수 또는 analyzer config로 이동 |
| rolling window 적용 | ICMP flood 탐지에도 rolling window 적용 |
