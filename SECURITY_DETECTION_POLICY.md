# 보안 탐지 및 대응 정책

## 1. 적용 범위

| 탐지 유형 | 역할 | 자동 생성 대응 |
|---|---|---|
| `ARP_SPOOFING` | 최종 시나리오 | 근거가 충분하면 L3 `DROP` 후보 |
| `PORT_SCAN` | 보조 탐지 | 자동 차단 없음, L1/L2 관찰·알림 |
| `ICMP_FLOOD` | 보조 탐지 | 높은 점수일 때 L2 `RATE_LIMIT` 후보 |

DDoS, UDP Flood, SYN Flood, 링크 혼잡, 링크 장애는 현재 보안 이벤트 범위가 아니다.

## 2. 공통 처리 원칙

1. Analyzer가 패킷 메타데이터를 만든다.
2. 탐지 결과는 공통 `SecurityEvent` 형식으로 정리한다.
3. 같은 공격 흐름은 `event_fingerprint`로 묶는다.
4. 실제 발생 건은 시간 창이 포함된 `event_id`로 구분한다.
5. 중복 억제 시간 안의 동일 흐름은 다시 전송하지 않는다.
6. Backend는 이벤트를 검증하고 Elasticsearch에 원본을 저장한다.
7. 모든 이벤트는 PostgreSQL `security_responses`에 `PENDING` 대응 내역을 만든다.
8. `mitigation`이 있는 이벤트만 PostgreSQL `flow_rules`에 `PENDING` 후보를 만든다.
9. 실제 스위치 적용 완료는 Controller 결과를 받은 뒤 판단한다.

## 3. 대응 레벨

| 레벨 | 의미 | 정책 |
|---|---|---|
| `L1` | 기준을 막 넘은 관찰 대상 | 이벤트 기록, 자동 Flow Rule 없음 |
| `L2` | 보조 근거가 같이 있는 높은 의심 | 알림 또는 RATE_LIMIT 후보 |
| `L3` | 신뢰 기준 위반이 뚜렷한 공격 | 좁은 범위의 DROP 후보 |

## 4. ARP Spoofing

### 4.1 기본 판단

- 프로토콜이 ARP다.
- opcode가 Reply다.
- ARP sender IP가 보호 대상 Gateway IP다.
- ARP sender MAC이 신뢰 Gateway MAC과 다르다.

신뢰 기준이 없는 일반 IP의 MAC 중복만으로는 공격자를 확정하지 않는다. 이 경우 이벤트나 DROP 후보를 만들지 않는다.

### 4.2 추가 근거

| 추가 근거 | 의미 |
|---|---|
| ARP sender MAC 확인 | 위조를 주장한 MAC이 실제로 들어 있다. |
| Ethernet source MAC과 ARP sender MAC 일치 | 프레임 출발 MAC과 ARP 내부 MAC이 같은 흐름이다. |
| 대상 호스트 IP 포함 | 특정 피해 호스트에게 향하는 Reply로 볼 수 있다. |
| 같은 위조 Reply 반복 관측 | 같은 위조 정보가 짧은 시간에 반복된다. |

### 4.3 점수와 대응

| 점수 | 대응 |
|---:|---|
| 85점 미만 | L1 `monitor` |
| 85점 이상 | L2 `alert` |
| 95점 이상 | L3 `block`, `DROP` 후보 생성 |

최종 시나리오 샘플은 Gateway IP를 다른 MAC이 주장하고, 대상 호스트 IP도 포함하므로 L3 `DROP` 후보까지 생성된다.

## 5. Port Scan

### 5.1 기본 판단

- TCP 패킷이다.
- SYN은 있고 ACK는 없다.
- 출발지 IP, 목적지 IP, 목적지 포트가 있다.
- 기본 5초 안에 고유 목적지 포트가 10개 이상이다.

### 5.2 추가 근거

| 조건 | 점수 |
|---|---:|
| 기본 조건 충족 | 50 |
| SYN 시도 수 10개 이상 | +10 |
| 30초 동안 대상 IP 2개 이상 | +15 |
| 관리/서비스 포트 3개 이상 포함 | +10 |
| 고유 목적지 포트 25개 이상 | +15 |

70점 미만은 L1 `monitor`, 70점 이상은 L2 `alert`다. Port Scan은 정상 점검과 비슷하게 보일 수 있어 자동 차단하지 않는다.

## 6. ICMP Flood

### 6.1 기본 판단

- 프로토콜이 ICMP다.
- 같은 출발지·목적지 쌍으로 집계한다.
- 기본 1초 창에서 pps가 100 이상이다.

### 6.2 추가 근거

| 조건 | 점수 |
|---|---:|
| pps 기준 충족 | 50 |
| 패킷 수 100개 이상 | +15 |
| 패킷 수가 기준의 2배 이상 | +10 |
| pps 300 이상 | +20 |
| 평균 ICMP payload 512 byte 이상 | +10 |

80점 미만은 L1 `monitor`, 80점 이상은 L2 `rate_limit` 후보를 만든다. ICMP 이벤트의 `attack_category`는 `FLOOD`이며, 분산 공격 전체를 뜻하는 DDoS로 기록하지 않는다.

## 7. 테스트 기준

- 정상 Gateway ARP Reply는 탐지하지 않는다.
- ARP Request는 최종 Spoofing 이벤트로 만들지 않는다.
- 신뢰 기준이 없는 IP-MAC 중복은 자동 DROP하지 않는다.
- 근거가 부족한 ARP Gateway MAC 불일치는 L2 알림까지만 만든다.
- 대상 호스트까지 확인된 ARP Spoofing은 L3 DROP 후보를 만든다.
- Port Scan은 9개 포트에서는 탐지하지 않고 10개 포트부터 탐지한다.
- Port Scan에 관리/서비스 포트가 여러 개 포함되면 L2 알림으로 올린다.
- ICMP Flood는 100 pps부터 기록하고, 높은 점수일 때만 RATE_LIMIT 후보를 만든다.
- 동일 fingerprint는 중복 억제 시간 안에 다시 생성하지 않는다.
- 대응 레벨이 올라간 이벤트는 중복 억제를 우회한다.
