# 보안 탐지 구현 정리

이 문서는 분석 서버 안에서 보안 담당 범위로 구현한 탐지 흐름을 정리한 자료다. 현재 구현은 백엔드, 프론트엔드, 컨트롤러 구조를 바꾸지 않고, 분석 서버가 보안 이벤트와 대응 후보를 생성하는 데 초점을 둔다.

## 현재 구현 범위

| 항목 | 구현 파일 | 설명 |
|---|---|---|
| 공통 점수 정책 | `app/detection/common.py` | 탐지 점수를 위험도와 대응 후보로 변환 |
| ICMP Flood | `app/detection/flood.py` | ICMP Echo Request 증가가 반복되는지 탐지 |
| UDP Flood | `app/detection/flood.py` | 목적지 포트별 UDP 패킷 수와 트래픽 양을 함께 보고 탐지 |
| Port Scan | `app/detection/port_scan.py` | TCP SYN 패턴으로 수직 스캔과 수평 스캔을 탐지 |
| SYN Flood | `app/detection/syn_flood.py` | 특정 서비스로 SYN 요청이 몰리고 SYN/ACK 응답이 부족한지 탐지 |
| 보안 이벤트 변환 | `app/detection/security_events.py` | 탐지 결과를 백엔드 SecurityEvent 형식으로 변환 |
| 실행 연결 | `app/main.py` | 분석 주기마다 각 탐지기를 실행하고 이벤트를 전송 |
| 설정값 | `app/config.py` | 탐지 기준값을 환경변수로 조정 |
| 테스트 | `tests/test_security_detection_policy.py` | 탐지 기준, 이벤트 변환, 중복 억제, 상태 정리 검증 |

## 이번 범위에서 제외한 항목

ARP Spoofing은 이번 구현에서 제외했다. ARP Spoofing은 IP-MAC Binding, MAC 충돌, 보호 대상 IP 관리가 필요하고, 현재 백엔드 보안 이벤트 스키마도 IP와 프로토콜 중심이다. 따라서 이번 브랜치에서는 4개 탐지기를 안정화하고, ARP Spoofing은 별도 PR에서 Parser와 이벤트 스키마를 함께 검토하는 편이 안전하다.

대응 후 자동 복구도 이번 구현에서는 실제 실행하지 않는다. 현재 분석 서버는 `RATE_LIMIT` 또는 `DROP`을 바로 적용하지 않고, 백엔드와 컨트롤러가 사용할 수 있는 대응 후보만 생성한다. 실제 Flow Rule 적용, 정상화 확인, Rule 해제는 컨트롤러 연동이 확정된 뒤 진행한다.

## 공통 점수 정책

| 점수 | 위험도 | 기본 대응 후보 | 의미 |
|---:|---|---|---|
| 0~44 | Low | 로그 | 참고용 기록 |
| 45~69 | Medium | 알림 | 관리자가 확인해야 하는 의심 이벤트 |
| 70~84 | High | Rate Limit | 트래픽을 줄이는 대응 후보 생성 |
| 85~100 | Critical | 임시 Drop 후보 | 강한 공격으로 보고 차단 후보 생성 |

단, Flood 계열은 순간적인 Critical 급증이 한 번 발생했다고 바로 Drop 후보를 만들지 않는다. 첫 Critical은 Rate Limit 후보로 보내고, 다음 분석 구간에서도 공격이 지속되면 Drop 후보로 승격한다. Port Scan은 정상 점검과 혼동될 수 있으므로 Critical이어도 Drop 대신 Rate Limit 후보까지만 생성한다.

## 탐지 기준

### ICMP Flood

ICMP Flood는 ping 요청에 해당하는 ICMP Echo Request가 짧은 시간 안에 반복적으로 증가하는 상황을 본다. Echo Reply, Destination Unreachable 같은 다른 ICMP 메시지는 네트워크 진단이나 오류 알림일 수 있으므로 Flood 집계에서 제외한다.

| 기준 | 기본값 | 설명 |
|---|---:|---|
| `ICMP_PPS_THRESHOLD` | 150 | 초당 ICMP 패킷 수 기준 |
| `ICMP_MIN_PACKET_COUNT` | 100 | 최소 패킷 수 기준 |
| `ICMP_HIGH_PPS_THRESHOLD` | 500 | 높은 위험으로 보는 ICMP PPS |
| `ICMP_CRITICAL_PPS_THRESHOLD` | 1000 | Critical로 보는 ICMP PPS |

### UDP Flood

UDP Flood는 작은 패킷을 많이 보내는 공격과 큰 패킷으로 대역폭을 채우는 공격을 모두 보기 위해 PPS와 BPS를 함께 사용한다. 대응 후보가 너무 넓어지지 않도록 `(출발지 IP, 목적지 IP, 목적지 포트)` 단위로 집계한다.

| 기준 | 기본값 | 설명 |
|---|---:|---|
| `UDP_PPS_THRESHOLD` | 250 | 초당 UDP 패킷 수 기준 |
| `UDP_MIN_PACKET_COUNT` | 100 | 최소 패킷 수 기준 |
| `UDP_HIGH_PPS_THRESHOLD` | 800 | 높은 위험으로 보는 UDP PPS |
| `UDP_CRITICAL_PPS_THRESHOLD` | 1500 | Critical로 보는 UDP PPS |
| `UDP_BPS_THRESHOLD` | 2000000 | 초당 UDP bit 수 기준 |
| `UDP_HIGH_BPS_THRESHOLD` | 8000000 | 높은 위험으로 보는 UDP BPS |
| `UDP_CRITICAL_BPS_THRESHOLD` | 15000000 | Critical로 보는 UDP BPS |

### Port Scan

Port Scan은 TCP SYN 패킷을 보고 판단한다. 한 대상 IP의 여러 포트를 훑으면 수직 스캔, 여러 대상 IP의 같은 포트를 훑으면 수평 스캔으로 구분한다.

| 기준 | 기본값 | 설명 |
|---|---:|---|
| `PORT_SCAN_WINDOW_SEC` | 5 | 수직 스캔 판단 시간 |
| `PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD` | 15 | 한 대상에서 의심으로 보는 고유 목적지 포트 수 |
| `PORT_SCAN_SYN_COUNT_THRESHOLD` | 30 | 보조 조건으로 보는 SYN 시도 수 |
| `PORT_SCAN_MULTI_TARGET_WINDOW_SEC` | 30 | 수평 스캔 판단 시간 |
| `PORT_SCAN_HORIZONTAL_TARGET_THRESHOLD` | 3 | 같은 포트로 접근한 대상 IP 수 기준 |
| `PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD` | 50 | 높은 위험으로 보는 고유 목적지 포트 수 |

수평 스캔 기준은 기본 실습 토폴로지가 4개 호스트 수준인 점을 고려해 3으로 낮췄다. 기준이 8이면 기본 토폴로지에서는 수평 스캔이 절대 탐지되지 않는다.

기본 수직 스캔 기준인 15개 포트 탐지는 먼저 Medium Alert로 처리한다. SYN 시도 수가 더 많거나, 50개 이상 포트를 훑거나, 수평 스캔 대상 수가 크게 늘어나는 경우에 High로 올라가 Rate Limit 후보를 만든다.

### SYN Flood

SYN Flood는 특정 목적지 IP와 포트로 SYN 패킷이 몰리는 상황을 본다. Port Scan과 겹치지 않도록 여러 포트를 넓게 훑는 경우는 Port Scan이 담당하고, SYN Flood는 단일 서비스 집중 패턴을 우선한다.

| 기준 | 기본값 | 설명 |
|---|---:|---|
| `SYN_PPS_THRESHOLD` | 120 | 초당 SYN 패킷 수 기준 |
| `SYN_MIN_COUNT` | 30 | 최소 SYN 수 기준 |
| `SYN_HIGH_PPS_THRESHOLD` | 400 | 높은 위험으로 보는 SYN PPS |
| `SYN_CRITICAL_PPS_THRESHOLD` | 800 | Critical로 보는 SYN PPS |
| `SYN_MAX_UNIQUE_PORTS` | 5 | SYN Flood로 볼 수 있는 최대 목적지 포트 수 |

SYN 대비 응답 비율은 단독 핵심 기준이 아니라 보조 판단으로 사용한다. 정상 TCP 연결처럼 SYN에 대한 SYN/ACK 흐름이 충분하면 SYN Flood로 판단하지 않도록 했다. 최종 ACK는 응답 수에 넣지 않아 정상 연결 하나가 두 번 계산되는 문제를 피한다.

## 이벤트 흐름

```text
패킷 캡처
  -> 패킷 메타데이터 파싱
  -> ICMP / UDP / Port Scan / SYN 탐지
  -> 위험도 점수 계산
  -> 중복 이벤트 억제
  -> SecurityEvent 변환
  -> 보안 이벤트 대기 큐 저장
  -> 백엔드 /api/security/events 전송
```

탐지 결과는 `src_ip`, `dst_ip`, `attack_type`, `protocol`, `evidence` 중심으로 정리한다. `host`, `ip`, `target_ip`처럼 같은 의미의 중복 필드는 사용하지 않는다.

보안 이벤트 전송에 실패하면 해당 이벤트를 메모리 대기 큐에 남겨 다음 분석 구간에서 다시 전송한다. 그래서 Port Scan처럼 자체 cooldown이 있는 탐지 결과도 백엔드 장애 때문에 바로 사라지지 않는다. 현재 큐는 프로세스 메모리 기반이므로, 장기 운영 단계에서는 파일이나 SQLite 기반 outbox로 확장할 수 있다.

## 대응 흐름

현재 분석 서버가 직접 차단을 실행하지는 않는다. 이벤트에 포함되는 `mitigation`은 백엔드와 컨트롤러가 사용할 수 있는 대응 후보이다.

```text
Low      -> 로그
Medium   -> 알림
High     -> Rate Limit 후보
Critical -> 첫 탐지는 Rate Limit 후보, 지속 시 Drop 후보
```

이 구조는 Self-Healing의 앞단에 해당한다. 실제 Self-Healing 완성 흐름은 다음 단계까지 확장되어야 한다.

```text
탐지
  -> 대응 후보 생성
  -> Controller Flow 적용
  -> 트래픽 감소 여부 확인
  -> 정상 호스트 통신 확인
  -> 공격 종료 판단
  -> 임시 정책 해제
```

## 검증 방법

```bash
python -m compileall -q analyzer/app analyzer/tests backend/app backend/tests
python -m pytest analyzer/tests backend/tests -q
git diff --check
```

현재 테스트는 다음을 확인한다.

- Port Scan 기준 이하 트래픽은 탐지하지 않음
- 수직 Port Scan과 수평 Port Scan을 구분함
- 수평 Port Scan의 분석 윈도우가 30초로 기록됨
- 수평 Port Scan 대응 후보는 단일 목적지 IP가 아니라 출발지 IP와 목적지 포트를 기준으로 생성됨
- Port Scan cooldown이 반복 알림을 억제함
- timezone 없는 timestamp도 안전하게 처리함
- 유효하지 않은 포트 번호는 탐지 대상에서 제외함
- ICMP Echo Reply와 Destination Unreachable은 Flood로 탐지하지 않음
- ICMP Flood는 반복 초과 후 탐지함
- ICMP Flood 대응 후보에는 `icmpv4_type=8`이 포함됨
- Flood 상태 기록은 일정 시간이 지나면 정리됨
- UDP Critical은 첫 탐지에서 Rate Limit, 지속 시 Drop으로 승격됨
- UDP Flood는 목적지 포트별로 집계되고 대응 후보에 `udp_dst`가 포함됨
- 잘못된 패킷 크기와 `window_sec=0`을 안전하게 처리함
- 정상 TCP handshake는 SYN Flood로 탐지하지 않음
- SYN 응답 계산은 SYN/ACK만 사용하며 최종 ACK를 중복 응답으로 세지 않음
- SYN 응답 계산은 패킷 순서가 뒤집혀도 정상 연결을 공격으로 보지 않음
- SYN Flood는 Port Scan과 역할이 겹치지 않음
- 탐지 결과가 백엔드 SecurityEvent 형식과 대응 후보로 변환됨
- 이벤트 식별자는 SHA-256 기반 fingerprint를 사용함
- 같은 이벤트는 중복 전송하지 않음
- 위험도가 상승한 이벤트는 중복 억제 중이어도 다시 전송됨
- 전송 실패한 보안 이벤트는 메모리 대기 큐에 남아 다음 주기에 재전송 가능함
- 잘못된 환경변수 값과 임계값 순서 오류를 시작 시점에 차단함

## 남은 확장 항목

현재 구현은 4개 탐지기를 안정화한 단계이다. 최종 Self-Healing 구조로 확장하려면 다음 항목을 별도로 진행해야 한다.

- ARP Spoofing 탐지
- 정상 트래픽 Baseline 기반 동적 임계값
- 공격 유형별 Rate Limit 값 분리
- Backend API와 실제 이벤트 저장 검증
- Controller Flow Rule 적용 검증
- 대응 후 정상화 확인
- 임시 Flow Rule 자동 해제
