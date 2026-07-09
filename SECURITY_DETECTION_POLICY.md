# 보안 탐지 및 대응 정책

## 1. 적용 범위

| 탐지 유형 | 역할 | 자동 생성 대응 |
|---|---|---|
| `ARP_SPOOFING` | 최종 시나리오 | L3 `DROP` 후보 |
| `PORT_SCAN` | 보조 탐지 | 없음, L1/L2 관찰·알림 |
| `ICMP_FLOOD` | 보조 탐지 | L2 `RATE_LIMIT` 후보 |

DDoS, UDP Flood, SYN Flood, 링크 혼잡, 링크 장애는 현재 보안 이벤트 범위가 아니다.

## 2. 공통 처리 원칙

1. Analyzer가 패킷 메타데이터를 탐지한다.
2. 탐지 결과는 공통 `SecurityEvent`로 만든다.
3. 같은 공격 흐름은 `event_fingerprint`로 식별한다.
4. 실제 발생 건은 시간 창을 포함한 `event_id`로 구분한다.
5. 중복 억제 시간 안의 동일 흐름은 다시 전송하지 않는다.
6. Backend는 이벤트를 검증하고 원본을 Elasticsearch에 저장한다.
7. 모든 이벤트는 PostgreSQL `security_responses`에 `PENDING` 대응 내역을 만든다.
8. `mitigation`이 있는 이벤트만 PostgreSQL `flow_rules`에 `PENDING` 후보를 만든다.
9. 실제 스위치 적용 완료는 Controller 결과를 받은 뒤 결정한다.

## 3. 공통 이벤트 형식

| 필드 | 설명 |
|---|---|
| `event_id` | 발생 시간 창을 포함한 개별 사건 ID |
| `event_fingerprint` | 같은 공격 흐름을 묶는 SHA-1 fingerprint |
| `dedup_key` | 중복 억제 키, 현재 fingerprint와 동일 |
| `timestamp` | 이벤트 생성 시각 |
| `analyzer_id` | 분석 서버 ID |
| `attack_category` | `L2_SPOOFING`, `RECON`, `FLOOD` |
| `attack_type` | `ARP_SPOOFING`, `PORT_SCAN`, `ICMP_FLOOD` |
| `severity` | `medium`, `high`, `critical` |
| `confidence` | `medium`, `high` |
| `status` | 최초 생성 시 `detected` |
| `src_ip` | 신뢰 가능한 출발지 IP, ARP에서는 `null` 가능 |
| `src_mac` | ARP 공격자의 Ethernet source MAC |
| `dst_ip` | 공격 대상 IP |
| `protocol` | `ARP`, `TCP`, `ICMP` |
| `detection_rule` | 적용된 탐지 규칙 |
| `recommended_action` | `monitor`, `alert`, `rate_limit`, `block` |
| `response_level` | `L1`, `L2`, `L3` |
| `evidence` | 판단 근거와 실제 관찰값 |
| `mitigation` | Flow Rule 후보 또는 `null` |

## 4. 대응 레벨

| 레벨 | 의미 | 정책 |
|---|---|---|
| `L1` | 기준만 만족한 관찰 대상 | 이벤트 기록, 자동 Flow Rule 없음 |
| `L2` | 보조 조건까지 충족한 높은 의심 | 알림 또는 RATE_LIMIT 후보 |
| `L3` | 신뢰 기준 위반이 명확한 공격 | 좁은 범위의 DROP 후보 |

## 5. ARP Spoofing

### 5.1 보호 대상

| 설정 | 기본값 |
|---|---|
| Gateway IP | `10.0.0.254` |
| Gateway MAC | `00:00:00:00:ff:ff` |

### 5.2 필수 조건

- 프로토콜이 ARP다.
- opcode가 Reply다.
- ARP sender IP가 보호 대상 Gateway IP다.
- ARP sender MAC이 신뢰 Gateway MAC과 다르다.

신뢰 기준이 없는 일반 IP의 MAC 중복만으로는 공격자를 확정하지 않고 이벤트나 DROP 후보를 만들지 않는다.

### 5.3 이벤트

| 항목 | 값 |
|---|---|
| `attack_category` | `L2_SPOOFING` |
| `attack_type` | `ARP_SPOOFING` |
| `severity` | `critical` |
| `confidence` | `high` |
| `detection_rule` | `trusted_gateway_mac_mismatch` |
| `recommended_action` | `block` |
| `response_level` | `L3` |

주요 evidence:

- `spoofed_ip`
- `trusted_mac`
- `claimed_mac`
- `ethernet_src_mac`
- `arp_target_ip`
- `matched_conditions`
- `score=100`

### 5.4 DROP 후보

```json
{
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
```

전체 호스트를 막는 것이 아니라 해당 MAC이 Gateway IP를 주장하는 ARP만 대상으로 한다.

## 6. Port Scan

### 6.1 필수 조건

- TCP SYN은 있고 ACK는 없는 패킷이다.
- 출발지 IP와 목적지 IP가 존재한다.
- 기본 5초 안에 고유 목적지 포트가 20개 이상이다.

### 6.2 점수

| 조건 | 점수 |
|---|---:|
| 필수 조건 충족 | 60 |
| SYN 수 20 이상 | +10 |
| 30초 동안 스캔 대상 3개 이상 | +15 |
| 고유 목적지 포트 50개 이상 | +15 |

보조 조건이 없으면 L1 `monitor`, 하나 이상이면 L2 `alert`다. 정찰 행위는 정상 점검과 구분이 어려워 자동 차단하지 않는다.

## 7. ICMP Flood

### 7.1 필수 조건

- 프로토콜이 ICMP다.
- 같은 출발지·목적지 쌍으로 집계한다.
- 기본 1초 창에서 pps가 1000 이상이다.

### 7.2 점수

| 조건 | 점수 |
|---|---:|
| pps 기준 충족 | 60 |
| 패킷 수 1000 이상 | +20 |
| pps 3000 이상 | +15 |

| 결과 | 정책 |
|---|---|
| 60점, L1 | 모니터링, mitigation 없음 |
| 80점 이상, L2 | RATE_LIMIT 후보 |
| 95점 이상 | confidence `high` |

ICMP 이벤트의 `attack_category`는 `FLOOD`다. 분산 공격 전체를 의미하는 `DDoS`로 기록하지 않는다.

## 8. RATE_LIMIT 후보

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

## 9. 테스트 기준

- 정상 Gateway ARP Reply는 탐지하지 않는다.
- ARP Request는 최종 Spoofing 이벤트로 만들지 않는다.
- 신뢰 기준이 없는 IP-MAC 중복은 자동 DROP하지 않는다.
- Gateway MAC 불일치는 Critical ARP 이벤트와 DROP 후보를 만든다.
- Port Scan 19개 포트는 탐지하지 않고 20개부터 탐지한다.
- ICMP L1은 mitigation이 없고 L2는 RATE_LIMIT 후보를 만든다.
- 동일 fingerprint는 중복 억제 시간 안에 다시 생성하지 않는다.
- escalation된 이벤트는 중복 억제를 우회한다.
