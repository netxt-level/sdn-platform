# SDN Analyzer

분석 서버는 네트워크 인터페이스에서 패킷을 캡처하고, 짧은 분석 주기마다 패킷 요약·트래픽 상태·보안 이벤트를 만들어 백엔드로 전송한다.

## 실행 흐름

```text
Scapy capture
  -> packet/parser.py
  -> packet/summary.py
  -> detection/port_scan.py
  -> detection/security_events.py
  -> backend_client.py
  -> Backend API
```

보안 이벤트는 `SecurityEventBuilder` 한 곳에서 생성한다. 과거의 별도 `app/security` 엔진은 제거해 탐지 기준과 payload 형식이 둘로 갈라지지 않게 했다.

## 보안 탐지 범위

| 탐지 | 기준 | 대응 후보 |
|---|---|---|
| `ARP_SPOOFING` | 신뢰 Gateway IP를 다른 MAC이 주장하는 ARP Reply | 근거가 충분하면 `DROP`, L3 |
| `PORT_SCAN` | 짧은 시간에 같은 대상의 여러 TCP 포트로 향하는 SYN | 자동 대응 없음, L1/L2 알림 |
| `ICMP_FLOOD` | 출발지·목적지별 ICMP pps가 기준 이상 | 높은 점수에서 `RATE_LIMIT` |

`DDoS`, 링크 혼잡, 링크 장애는 현재 보안 이벤트 범위가 아니다. ICMP 탐지는 분산 공격 전체가 아니라 관찰 가능한 단일 출발지 기반 Flood로 다룬다.

ARP Spoofing은 다음 조건을 만족할 때 생성한다.

1. ARP Reply다.
2. sender IP가 설정된 Gateway IP와 같다.
3. sender MAC이 신뢰 Gateway MAC과 다르다.

이후 대상 호스트 IP 포함, Ethernet source MAC 일치, 반복 관측 같은 추가 근거를 점수에 더한다. 근거가 부족하면 L1/L2로 기록하고, 충분하면 L3 DROP 후보를 만든다.

신뢰 기준이 없는 일반 IP에서 MAC이 둘 이상 보이는 경우에는 공격자를 확정할 수 없으므로 자동 DROP하지 않는다.

## 주요 파일

| 파일 | 역할 |
|---|---|
| `app/main.py` | 캡처·분석·상태 전송 루프 |
| `app/config.py` | 환경변수 검증과 설정 객체 |
| `app/packet/parser.py` | ARP/IP/TCP/UDP/ICMP 메타데이터 추출 |
| `app/detection/port_scan.py` | Port Scan 윈도우 집계와 점수 계산 |
| `app/detection/security_events.py` | 세 탐지를 공통 SecurityEvent와 mitigation으로 변환 |
| `app/backend_client.py` | Backend API 전송 |
| `tests/test_security_detection_policy.py` | 탐지 경계값·중복 억제·ARP 오탐 방지 테스트 |

## 환경변수

| 이름 | 기본값 | 설명 |
|---|---:|---|
| `ANALYZER_WINDOW_SEC` | `1` | 패킷·보안 이벤트 생성 주기 |
| `SECURITY_GATEWAY_IP` | `10.0.0.254` | ARP 보호 대상 Gateway IP |
| `SECURITY_GATEWAY_MAC` | `00:00:00:00:ff:ff` | 신뢰 Gateway MAC |
| `ARP_DROP_PRIORITY` | `650` | ARP DROP 후보 우선순위 |
| `ARP_DROP_IDLE_TIMEOUT` | `60` | ARP DROP 후보 idle timeout |
| `ARP_DROP_HARD_TIMEOUT` | `300` | ARP DROP 후보 hard timeout |
| `PORT_SCAN_WINDOW_SEC` | `5` | Port Scan 집계 시간 |
| `PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD` | `10` | 고유 목적지 포트 기준 |
| `PORT_SCAN_SYN_COUNT_THRESHOLD` | `10` | SYN 수 보조 기준 |
| `PORT_SCAN_MULTI_TARGET_THRESHOLD` | `2` | 여러 대상 IP 스캔 기준 |
| `PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD` | `25` | 높은 고유 포트 수 기준 |
| `PORT_SCAN_COMMON_PORT_HIT_THRESHOLD` | `3` | 관리/서비스 포트 포함 기준 |
| `PORT_SCAN_ALERT_COOLDOWN_SEC` | `30` | 동일 스캔 알림 억제 시간 |
| `ICMP_PPS_THRESHOLD` | `100` | ICMP Flood 기록 기준 |
| `ICMP_MIN_PACKET_COUNT` | `100` | 패킷 수 보조 기준 |
| `ICMP_HIGH_PPS_THRESHOLD` | `300` | 높은 pps 기준 |
| `ICMP_LARGE_PAYLOAD_THRESHOLD` | `512` | 큰 ICMP payload 기준 |
| `EVENT_DEDUP_WINDOW_SEC` | `60` | 동일 보안 흐름 중복 억제 시간 |
| `RATE_LIMIT_PPS` | `100` | ICMP RATE_LIMIT 후보 pps |

전체 설정은 루트 `.env.example`을 기준으로 한다.

## 백엔드 연동

```http
POST /api/analyzer/packet-summary
POST /api/analyzer/detection-summary
POST /api/security/events
POST /api/analyzer/status
```

`POST /api/security/events`는 `timestamp`, `analyzer_id`, `events`를 전송한다. Backend는 Pydantic으로 검증한 뒤 다음을 수행한다.

1. Elasticsearch `sdn-security-events`에 원본 이벤트를 저장한다.
2. PostgreSQL `security_responses`에 대응 내역을 만든다.
3. `mitigation`이 있으면 PostgreSQL `flow_rules`에 `PENDING` 후보를 만든다.
4. WebSocket `security_events` 메시지로 화면에 전달한다.

Analyzer가 `DROP`이나 `RATE_LIMIT`을 만들었다고 실제 스위치 적용이 끝난 것은 아니다. Controller 적용 결과가 `APPLIED`로 바뀌어야 완료 상태다.

## 테스트

```bash
python -m pytest analyzer/tests -q
```

테스트는 정상 Gateway ARP, ARP Request 제외, 신뢰 기준 없는 IP의 자동 DROP 방지, Gateway MAC 불일치, Port Scan 경계값, ICMP 대응 레벨, 이벤트 중복 억제를 확인한다.
