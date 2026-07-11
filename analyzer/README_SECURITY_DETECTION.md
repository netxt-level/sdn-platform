# 보안 탐지 구현 정리

이 문서는 분석 서버 안에서 보안 담당 범위로 구현한 탐지 흐름을 정리한 자료다. 현재 구현은 백엔드, 프론트엔드, 컨트롤러 구조를 바꾸지 않고, 분석 서버가 보안 이벤트와 대응 후보를 생성하는 데 초점을 둔다.

## 현재 구현 범위

| 항목 | 구현 파일 | 설명 |
|---|---|---|
| 공통 점수 정책 | `app/detection/common.py` | 탐지 점수를 위험도와 대응 후보로 변환 |
| ICMP Flood | `app/detection/flood.py` | ICMP Echo Request 증가가 반복되는지 탐지 |
| UDP Flood | `app/detection/flood.py` | 목적지 포트별 집계와 출발지-목적지 합산 집계를 함께 보고 탐지 |
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

UDP Flood는 작은 패킷을 많이 보내는 공격과 큰 패킷으로 대역폭을 채우는 공격을 모두 보기 위해 PPS와 BPS를 함께 사용한다. 기본 대응 후보는 너무 넓어지지 않도록 `(출발지 IP, 목적지 IP, 목적지 포트)` 단위로 만든다. 다만 공격자가 여러 목적지 포트로 트래픽을 나누는 경우도 놓치지 않도록 `(출발지 IP, 목적지 IP)` 합산 기준을 추가로 본다. 특정 포트가 기준을 넘으면 `udp_dst`가 포함된 좁은 대응 후보를 만들고, 여러 포트 합산 기준도 함께 넘으면 전체 UDP 흐름 후보도 같이 남긴다.

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
| `SECURITY_TRUSTED_SOURCE_IPS` | 없음 | 관리 호스트 IPv4 목록. 수평 스캔 기준만 완화하고 완전히 제외하지는 않음 |
| `TRUSTED_HORIZONTAL_SCAN_THRESHOLD` | 10 | 관리 호스트에 적용할 수평 스캔 대상 IP 수 기준 |
| `PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD` | 50 | 높은 위험으로 보는 고유 목적지 포트 수 |

수평 스캔 기준은 기본 실습 토폴로지가 4개 호스트 수준인 점을 고려해 3으로 낮췄다. 기준이 8이면 기본 토폴로지에서는 수평 스캔이 절대 탐지되지 않는다.

관리 호스트는 일반 호스트보다 넓은 수평 스캔 기준을 적용하지만, 현재 실습 토폴로지처럼 대상 호스트 수가 적은 환경에서는 반복 SYN 조건도 함께 본다. 관리 호스트가 3개 대상에 한 번씩 접근하는 것은 정상 점검으로 넘기고, 같은 범위에서 SYN 시도 수가 `PORT_SCAN_SYN_COUNT_THRESHOLD` 이상 반복되면 수평 스캔으로 탐지한다.

기본 수직 스캔 기준인 15개 포트 탐지는 먼저 Medium Alert로 처리한다. SYN 시도 수가 더 많거나, 50개 이상 포트를 훑거나, 수평 스캔 대상 수가 크게 늘어나는 경우에 High로 올라가 Rate Limit 후보를 만든다.

### SYN Flood

SYN Flood는 SYN 패킷이 몰리고 SYN/ACK 응답이 부족한 상황을 본다. 단일 목적지 포트에 집중되는 경우를 기본으로 보고, 여러 포트로 나뉘어 들어오더라도 출발지-목적지 전체 SYN PPS가 높으면 다중 서비스 SYN Flood로 묶어 판단한다.

| 기준 | 기본값 | 설명 |
|---|---:|---|
| `SYN_PPS_THRESHOLD` | 120 | 초당 SYN 패킷 수 기준 |
| `SYN_MIN_COUNT` | 30 | 최소 SYN 수 기준 |
| `SYN_HIGH_PPS_THRESHOLD` | 400 | 높은 위험으로 보는 SYN PPS |
| `SYN_CRITICAL_PPS_THRESHOLD` | 800 | Critical로 보는 SYN PPS |
| `SYN_MAX_UNIQUE_PORTS` | 5 | SYN Flood로 볼 수 있는 최대 목적지 포트 수 |

SYN 대비 응답 비율은 단독 핵심 기준이 아니라 보조 판단으로 사용한다. 정상 TCP 연결처럼 SYN에 대한 SYN/ACK 흐름이 충분하면 SYN Flood로 판단하지 않도록 했다. 최종 ACK는 응답 수에 넣지 않아 정상 연결 하나가 두 번 계산되는 문제를 피한다.

다중 서비스 SYN Flood와 Port Scan이 같은 흐름에서 동시에 탐지되면 Analyzer는 더 강한 SYN Flood 이벤트를 유지하고, Port Scan은 `related_detections` evidence로 묶는다. 이렇게 하면 같은 출발지/목적지에 Rate Limit과 Drop 후보가 중복으로 만들어지는 상황을 줄일 수 있다.

## 이벤트 흐름

```text
패킷 캡처
  -> 패킷 메타데이터 파싱
  -> ICMP / UDP / Port Scan / SYN 탐지
  -> 위험도 점수 계산
  -> 탐지 결과 상관관계 정리
  -> 중복 이벤트 억제
  -> SecurityEvent 변환
  -> 보안 이벤트 대기 큐 저장
  -> 백엔드 /api/security/events 전송
```

탐지 결과는 `src_ip`, `dst_ip`, `attack_type`, `protocol`, `evidence` 중심으로 정리한다. `host`, `ip`, `target_ip`처럼 같은 의미의 중복 필드는 사용하지 않는다.

대응 후보는 현재 IPv4 OpenFlow match를 기준으로 생성한다. 그래서 잘못된 IP 주소와 IPv6 주소는 보안 이벤트 변환 단계에서 제외한다.

보안 이벤트 전송에 실패하면 해당 이벤트를 메모리 대기 큐에 남겨 다음 분석 구간에서 다시 전송한다. 재전송은 한 번에 최대 `SECURITY_EVENT_SEND_BATCH_SIZE`개씩 진행하고, 큐는 기본 `SECURITY_EVENT_QUEUE_MAX_SIZE=500`개까지만 보관한다. 큐가 가득 차서 오래된 이벤트가 밀려나면 로그에 남기고 중복 억제 기록에서도 제거해 이후 분석 구간에서 다시 만들어질 수 있게 한다.

백엔드는 `event_id`를 Elasticsearch 문서 ID로 사용해 저장한다. 그래서 Analyzer가 같은 이벤트를 재전송하더라도 보안 이벤트 문서가 중복으로 계속 쌓이지 않고 기존 문서가 갱신된다. 현재 큐는 프로세스 메모리 기반이므로, 장기 운영 단계에서는 파일이나 SQLite 기반 outbox로 확장할 수 있다.

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
npm --prefix frontend run lint
npm --prefix frontend run build
git diff --check
```

## 최근 보강한 탐지 기준

- SYN Flood는 단일 목적지 포트에 몰리는 경우를 기본으로 탐지한다. 추가로 여러 포트에 나뉘어 들어오지만 출발지-목적지 전체 SYN PPS가 높은 경우도 다중 서비스 SYN Flood로 탐지한다.
- Port Scan과 다중 서비스 SYN Flood가 같은 흐름에서 동시에 잡히면 SYN Flood 이벤트만 유지하고 Port Scan 근거를 관련 탐지로 붙인다.
- Port Scan은 패킷 원본을 계속 들고 있지 않고 초 단위 버킷에 집계값만 저장한다.
- Port Scan 수평 스캔은 대상 IP 개수와 SYN 시도 수를 함께 본다. 대상 IP 수만으로 알림을 만들면 작은 실습 토폴로지에서 오탐이 쉽게 생기기 때문이다.
- Port Scan 알림 쿨다운은 유지하되, 기존 알림보다 점수나 위험도가 올라가면 다시 알림을 만든다.
- Flow Rule 대응 정보는 백엔드에서 한 번 더 검증한다. IPv4 조건은 `eth_type=2048`, TCP는 `ip_proto=6`, UDP는 `ip_proto=17`, ICMP는 `ip_proto=1`을 요구한다. 수동 Flow Rule은 `switch_id`가 필요하며, 차단/제한 계열 action은 너무 넓은 match로 생성되지 않도록 구체적인 IP, 포트, ICMP 타입 조건을 요구한다.
- Flood PPS와 패킷 요약은 실제 분석 스냅샷 간격을 사용한다. 백엔드 전송 지연으로 분석 간격이 길어져도 고정 1초로 나누지 않는다.
- 패킷 요약은 임시 `src_port`와 `dst_port`를 집계 키에서 제외하고 출발지/목적지/프로토콜 단위로 합산한다. 대표 포트 값은 InfluxDB tag가 아니라 field로 저장한다.
- Analyzer 분석 루프와 백엔드 HTTP 전송 루프를 분리해 전송 지연이 분석 주기를 직접 막지 않게 했다.
- Analyzer 상태에는 보안 이벤트 대기열, 드롭 수, 패킷 버퍼 드롭 수, 마지막 전송 실패 시각을 포함하며 백엔드 DB에도 저장한다.

현재 테스트는 다음을 확인한다.

- Port Scan 기준 이하 트래픽은 탐지하지 않음
- 수직 Port Scan과 수평 Port Scan을 구분함
- 수평 Port Scan의 분석 윈도우가 30초로 기록됨
- 수평 Port Scan 대응 후보는 단일 목적지 IP가 아니라 출발지 IP와 목적지 포트를 기준으로 생성됨
- 관리 호스트는 수평 Port Scan 기준만 완화하고 기준 초과 시에는 탐지함
- 관리 호스트는 작은 토폴로지에서도 반복 SYN이 충분하면 수평 Port Scan으로 탐지함
- Port Scan은 오래된 초 단위 버킷을 정리해 메모리 증가를 억제함
- Port Scan cooldown이 반복 알림을 억제함
- timezone 없는 timestamp도 안전하게 처리함
- 유효하지 않은 포트 번호는 탐지 대상에서 제외함
- 유효하지 않은 IP 주소는 탐지와 이벤트 변환 대상에서 제외함
- IPv6 주소는 현재 IPv4 대응 후보 범위와 맞지 않아 이벤트 변환 대상에서 제외함
- ICMP Echo Reply와 Destination Unreachable은 Flood로 탐지하지 않음
- ICMP Flood는 반복 초과 후 탐지함
- ICMP Flood 대응 후보에는 `icmpv4_type=8`이 포함됨
- Flood 상태 기록은 일정 시간이 지나면 정리됨
- UDP Critical은 첫 탐지에서 Rate Limit, 지속 시 Drop으로 승격됨
- UDP Flood는 목적지 포트별로 집계되고 대응 후보에 `udp_dst`가 포함됨
- UDP Flood는 여러 목적지 포트로 나뉜 트래픽도 출발지-목적지 합산 기준으로 탐지함
- UDP Flood는 특정 포트 탐지와 출발지-목적지 합산 탐지가 동시에 필요하면 둘 다 생성함
- 잘못된 패킷 크기와 `window_sec=0`을 안전하게 처리함
- 정상 TCP handshake는 SYN Flood로 탐지하지 않음
- SYN 응답 계산은 SYN/ACK만 사용하며 최종 ACK를 중복 응답으로 세지 않음
- SYN 응답 계산은 패킷 순서가 뒤집혀도 정상 연결을 공격으로 보지 않음
- SYN Flood는 Port Scan과 역할이 겹치지 않음
- 다중 서비스 SYN Flood와 Port Scan이 같은 흐름에서 동시에 잡히면 상관관계로 하나의 대응 후보만 유지함
- 탐지 결과가 백엔드 SecurityEvent 형식과 대응 후보로 변환됨
- 이벤트 식별자는 SHA-256 기반 fingerprint를 사용함
- 같은 이벤트는 중복 전송하지 않음
- 위험도가 상승한 이벤트는 중복 억제 중이어도 다시 전송됨
- 전송 실패한 보안 이벤트는 메모리 대기 큐에 남아 다음 주기에 재전송 가능함
- 보안 이벤트 대기 큐는 배치 전송, 크기 제한, 초과 이벤트 제거를 처리함
- 잘못된 환경변수 값과 임계값 순서 오류를 시작 시점에 차단함
- 패킷 버퍼 최대 크기 설정이 잘못되면 시작 시점에 차단함

## 남은 확장 항목

현재 구현은 4개 탐지기를 안정화한 단계이다. 최종 Self-Healing 구조로 확장하려면 다음 항목을 별도로 진행해야 한다.

- ARP Spoofing 탐지
- 여러 출발지에서 하나의 목적지로 몰리는 분산 DDoS 탐지
- 정상 트래픽 Baseline 기반 동적 임계값
- 공격 유형별 Rate Limit 값 분리
- Backend API와 실제 이벤트 저장 검증
- Controller Flow Rule 적용 검증
- 대응 후 정상화 확인
- 임시 Flow Rule 자동 해제
