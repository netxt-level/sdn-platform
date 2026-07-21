# 보안 탐지 명세서

## 1. 개요

이 문서는 SDN Platform에서 분석 서버가 생성하는 보안 탐지 이벤트, 탐지 기준, 대응 레벨, 대응 후보 payload를 정의한다.

현재 확정된 탐지 범위는 다음 두 가지다.

| attack_type | 설명 |
|---|---|
| `PORT_SCAN` | TCP SYN 기반 포트 스캔 탐지 |
| `ICMP_FLOOD` | ICMP pps 기반 flood 탐지 |

그 외 탐지 항목은 이 문서의 확정 범위와 현재 구현 범위에 포함하지 않는다. 추가 항목은 담당자 간 API/탐지 기준 합의 후 별도 확장한다.

탐지 기준은 SIEM 상관분석 방식처럼 짧은 시간창 안에서 같은 필드 조합이 일정 횟수 이상 반복되는지를 본다. Wazuh의 `frequency`, `timeframe`, `same_field`, `ignore` 방식과 유사하게, 이 문서는 집계 시간창, 반복 기준, 동일 대상 기준, 중복 억제 시간을 명시한다.

참고: https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html

## 2. 기본 원칙

분석 서버는 직접 차단, rate limit, flow rule 설치를 수행하지 않는다.

분석 서버의 역할은 다음으로 제한한다.

| 역할 | 설명 |
|---|---|
| 탐지 | 패킷 메타데이터를 기반으로 보안 이벤트 생성 |
| 분류 | `severity`, `confidence`, `response_level`, `recommended_action` 산출 |
| 제안 | 필요한 경우 `mitigation`에 대응 후보 payload 포함 |

실제 대응 적용 여부는 백엔드/컨트롤러 정책에서 결정한다. 현재 백엔드는 보안 대응 내역과 flow rule 후보를 DB에 저장하지만, SDN 컨트롤러에 실제 rule을 설치하는 단계는 아직 연결되어 있지 않다.

```text
탐지 항목별 기본 레벨
+ 충족된 탐지 조건
+ 탐지 강도
+ confidence
= 최종 response_level / recommended_action
```

## 3. 보안 이벤트 포맷

보안 이벤트는 `POST /api/security/events`로 전달한다.

### 3.1 공통 필드

| 필드 | 설명 |
|---|---|
| `event_id` | 이벤트 식별자 |
| `event_fingerprint` | 같은 공격 흐름을 묶는 안정적인 fingerprint |
| `dedup_key` | 중복 억제 기준 키. 기본값은 `event_fingerprint` |
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
| `mitigation` | 적용 가능한 대응 후보 payload. 없으면 `null` |

### 3.2 이벤트 식별 및 중복 억제

탐지 이벤트는 같은 공격 흐름을 안정적으로 묶기 위해 fingerprint를 만들고, 실제 이벤트 ID에는 발생 윈도우를 포함한다.

| 항목 | 값 |
|---|---|
| `event_fingerprint` | `sha1(analyzer_id + attack_type + src_ip + dst_ip + protocol + detection_rule)` |
| `event_id` | `evt-` + `sha1(event_fingerprint + window_start_epoch)` 앞 12자리 |
| `dedup_key` | `event_fingerprint` |
| `event_dedup_window_sec` | `60` |
| `alert_cooldown_sec` | `60` |

같은 `dedup_key`에서 `event_dedup_window_sec` 안에 이미 이벤트가 생성된 경우 새 이벤트를 만들지 않는다. 단, `response_level` 또는 `severity`가 상승한 경우에는 새 이벤트를 생성할 수 있다.

### 3.3 이벤트 상태

분석 서버가 최초 생성하는 이벤트 상태는 항상 `detected`다. 현재 프론트/백엔드 운영 화면에서 사용하는 보안 이벤트 상태는 아래 네 가지를 기준으로 한다.

| 상태 | 의미 |
|---|---|
| `detected` | 탐지됨 |
| `blocked` | 차단 처리됨 |
| `ignored` | 운영자 또는 정책에 의해 무시 |
| `resolved` | 정상화 또는 종료 |

보안 대응 내역과 flow rule 후보는 별도 lifecycle을 가진다. 현재 `security_responses`와 `flow_rules`는 생성 시 `PENDING` 상태로 저장되며, 향후 컨트롤러 연동 시 `APPLIED`, `FAILED`, `REMOVED` 같은 적용 상태를 확장할 수 있다.

## 4. Score 및 대응 레벨

### 4.1 Score 계산

`score`는 충족한 조건의 강도를 0-100 범위로 표현한다. 필수 조건을 모두 충족한 경우 기본 60점을 부여하고, 보조 조건에 따라 점수를 더한다. 최대값은 100이다.

| 탐지 | 조건 | 점수 |
|---|---|---:|
| `PORT_SCAN` | 필수 조건 충족 | `60` |
| `PORT_SCAN` | `syn_count_threshold_satisfied` | `+10` |
| `PORT_SCAN` | `multi_target_scan` | `+15` |
| `PORT_SCAN` | `high_unique_dst_port_count` | `+15` |
| `ICMP_FLOOD` | 필수 조건 충족 | `60` |
| `ICMP_FLOOD` | `min_packet_count_satisfied` | `+20` |
| `ICMP_FLOOD` | `high_pps_exceeded` | `+15` |
| `ICMP_FLOOD` | `baseline_spike_detected` | `+5` |

### 4.2 대응 레벨

| 레벨 | 의미 | 백엔드 처리 | 컨트롤러/Flow Rule |
|---|---|---|---|
| `L1` | 관찰/기록 | 이벤트 저장, WebSocket 알림, 대시보드 표시 | 없음 |
| `L2` | 대응 권장 | 이벤트 저장, 알림, 대응 후보 생성 가능 | 승인 또는 정책에 따라 rate limit 후보 |
| `L3` | 강한 대응 권장 | 이벤트 저장, 높은 우선순위 알림, 대응 요청 생성 | 승인 또는 정책에 따라 차단/강한 제한 후보 |

현재 확정 범위에서 `PORT_SCAN`은 기본 `L1`, `ICMP_FLOOD`는 조건에 따라 `L1` 또는 `L2`를 사용한다. `L3`는 자동 대응/차단 정책이 확정되기 전까지 analyzer가 생성하지 않는다.

## 5. PORT_SCAN 탐지 명세

### 5.1 기본 정의

| 항목 | 값 |
|---|---|
| `attack_category` | `RECON` |
| `attack_type` | `PORT_SCAN` |
| `protocol` | `TCP` |
| 대표 `detection_rule` | `tcp_syn_unique_ports` |
| 기본 `response_level` | `L1` |
| 기본 `recommended_action` | `monitor` |
| 기본 `mitigation` | `null` |

### 5.2 탐지 조건

필수 조건은 모두 충족해야 한다.

| 조건 | 설명 |
|---|---|
| `tcp_syn_without_ack` | TCP SYN 플래그가 있고 ACK 플래그가 없는 연결 시도 |
| `same_source_target_pair` | 동일 `src_ip -> dst_ip` 기준으로 집계 |
| `unique_dst_port_threshold_exceeded` | 탐지 윈도우 내 서로 다른 목적지 포트 수가 기준 이상 |

보조 조건은 대응 레벨과 score 산정에 사용한다.

| 조건 | 설명 |
|---|---|
| `syn_count_threshold_satisfied` | 탐지 윈도우 내 SYN 시도 수가 `20` 이상 |
| `multi_target_scan` | 같은 출발지가 `30`초 안에 서로 다른 목적지 `3`개 이상을 스캔 |
| `high_unique_dst_port_count` | 동일 `src_ip -> dst_ip`에서 고유 목적지 포트 수가 `50` 이상 |

### 5.3 기준값

| 기준값 | 기본값 |
|---|---:|
| `window_seconds` | `5` |
| `unique_dst_port_threshold` | `20` |
| `syn_count_threshold` | `20` |
| `multi_target_window_seconds` | `30` |
| `multi_target_threshold` | `3` |
| `high_unique_dst_port_threshold` | `50` |
| `alert_cooldown_sec` | `60` |

### 5.4 대응 레벨 규정

| 조건 | `severity` | `confidence` | `response_level` | `recommended_action` | `mitigation` |
|---|---|---|---|---|---|
| 필수 조건 충족, `score=60` | `medium` | `high` | `L1` | `monitor` | `null` |
| 필수 조건 + 보조 조건 1개 이상, `score >= 70` | `medium` | `high` | `L2` | `alert` | `null` |

`PORT_SCAN`은 정찰 행위로 간주한다. 기본 정책은 자동 차단하지 않고 관찰/알림으로 둔다. 차단이나 rate limit은 오탐 가능성과 정상 진단 트래픽 가능성을 고려해 별도 운영 정책 승인 후 사용한다.

### 5.5 이벤트 예시

```json
{
  "event_id": "evt-...",
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
```

## 6. ICMP_FLOOD 탐지 명세

### 6.1 기본 정의

| 항목 | 값 |
|---|---|
| `attack_category` | `DDOS` |
| `attack_type` | `ICMP_FLOOD` |
| `protocol` | `ICMP` |
| 대표 `detection_rule` | `icmp_pps_threshold` |
| 기본 `response_level` | `L2` |
| 기본 `recommended_action` | `rate_limit` |

### 6.2 탐지 조건

필수 조건은 모두 충족해야 한다.

| 조건 | 설명 |
|---|---|
| `icmp_protocol` | 프로토콜이 ICMP |
| `same_source_target_pair` | 동일 `src_ip -> dst_ip` 기준으로 집계 |
| `icmp_pps_threshold_exceeded` | ICMP pps가 기준 이상 |

보조 조건은 대응 레벨과 score 산정에 사용한다.

| 조건 | 설명 |
|---|---|
| `min_packet_count_satisfied` | 탐지 윈도우 내 ICMP 패킷 수가 `1000` 이상 |
| `high_pps_exceeded` | ICMP pps가 `3000` 이상 또는 `icmp_pps_threshold * 3.0` 이상 |
| `baseline_spike_detected` | ICMP pps가 `max(baseline_avg_pps * 5.0, 100)` 이상 |

`baseline_avg_pps`가 아직 계산되지 않았거나 신뢰할 수 있는 표본이 부족하면 `baseline_spike_detected`는 충족하지 않은 것으로 본다.

### 6.3 기준값

| 기준값 | 기본값 |
|---|---:|
| `window_seconds` | `1` |
| `icmp_pps_threshold` | `1000` |
| `min_packet_count` | `1000` |
| `high_pps_threshold` | `3000` |
| `high_pps_multiplier` | `3.0` |
| `baseline_spike_multiplier` | `5.0` |
| `baseline_min_pps` | `100` |
| `alert_cooldown_sec` | `60` |

### 6.4 대응 레벨 규정

| 조건 | `severity` | `confidence` | `response_level` | `recommended_action` | `mitigation` |
|---|---|---|---|---|---|
| pps 기준만 충족, `score=60` | `medium` | `medium` | `L1` | `monitor` | `null` |
| pps 기준 + 최소 샘플 조건 충족, `score >= 80` | `high` | `medium` | `L2` | `rate_limit` | `RATE_LIMIT` 후보 |
| pps 기준 크게 초과 + 보조 조건 2개 이상, `score >= 95` | `critical` | `high` | `L2` | `drop` | `DROP` 후보 |

현재 자동 적용은 하지 않는다. `mitigation`은 컨트롤러가 적용할 수 있는 후보 payload로만 제공한다.

### 6.5 이벤트 예시

```json
{
  "event_id": "evt-...",
  "event_fingerprint": "764e3e790da17f7a5e21e51af7b4d06608bd450a",
  "dedup_key": "764e3e790da17f7a5e21e51af7b4d06608bd450a",
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
    "min_packet_count": 1000,
    "high_pps_threshold": 3000,
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

## 7. Mitigation 후보 명세

`mitigation`은 analyzer가 제안하는 대응 payload다. analyzer는 직접 Controller를
호출하지 않는다. Backend가 `security_responses`와 `flow_rules`를 생성하고
Controller에 자동 적용한 뒤 `APPLIED` 또는 `FAILED` 결과를 저장한다.

| 탐지 | 조건 | mitigation |
|---|---|---|
| `PORT_SCAN` | 모든 경우 | `null` |
| `ICMP_FLOOD` | `L1` | `null` |
| `ICMP_FLOOD` | `L2` | `RATE_LIMIT` 후보 |

### 7.1 RATE_LIMIT 기본값

| 항목 | 기본값 |
|---|---:|
| `action` | `RATE_LIMIT` |
| `target` | `flow` |
| `match.eth_type` | `2048` |
| `match.ip_proto` | `1` |
| `priority` | `500` |
| `idle_timeout` | `60` |
| `hard_timeout` | `300` |
| `rate_limit_pps` | `100` |

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

## 8. 구현 반영 TODO

| 항목 | 설명 |
|---|---|
| rolling window 적용 | ICMP flood 탐지에도 rolling window 적용 |
| controller 적용 연동 | `flow_rules`의 `PENDING` 후보를 SDN 컨트롤러에 설치/해제하고 상태를 갱신 |
| 이벤트 상태 변경 API | `detected`, `blocked`, `ignored`, `resolved` 상태 전환과 처리 이력 저장 |
