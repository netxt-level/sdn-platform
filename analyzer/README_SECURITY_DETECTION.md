# 보안 탐지 구현 정리

이 문서는 분석 서버 안에서 보안 담당 범위로 구현한 탐지 흐름을 정리한 자료다. 현재 구현은 백엔드, 프론트엔드, 컨트롤러 구조를 바꾸지 않고, 분석 서버가 보안 이벤트와 대응 후보를 생성하는 데 초점을 둔다.

## 현재 구현 범위

| 항목 | 구현 파일 | 설명 |
|---|---|---|
| 공통 점수 정책 | `app/detection/common.py` | 탐지 점수를 위험도와 대응 후보로 변환 |
| ICMP Flood | `app/detection/flood.py` | ICMP Echo Request 증가가 반복되는지 탐지 |
| UDP Flood | `app/detection/flood.py` | 목적지 포트별 집계와 출발지-목적지 합산 집계를 함께 보고 탐지 |
| Port Scan | `app/detection/port_scan.py` | TCP SYN 패턴으로 수직 스캔과 수평 스캔을 탐지 |
| SYN Flood | `app/detection/syn_flood.py` | 특정 서비스로 SYN 요청이 몰리고 최종 연결 완료율이 낮은지 탐지 |
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

패킷에 timestamp가 있으면 ICMP/UDP/SYN Flood는 분석 루프 실행 간격이 아니라 패킷 timestamp 기준 1초 bucket을 시간 순서대로 모두 처리한다. 그래서 분석 루프가 잠깐 늦어 한 번에 여러 초의 패킷이 들어와도 실제로 이어진 bucket은 지속 초과로 누적하고, 중간에 빈 초가 있으면 history를 초기화해 떨어진 burst를 지속 공격으로 묶지 않는다. 같은 1초 bucket이 여러 분석 호출에 나뉘어 들어오면 기존 bucket 집계와 합산하되 history는 한 번만 갱신한다. 실제로 1초 동안 몰린 Flood가 긴 분석 윈도우 평균으로 희석되어 사라지는 문제도 줄인다. Port Scan도 처리 지연에 흔들리지 않도록 패킷 timestamp 기반 watermark로 윈도우를 정리한다. timestamp가 없는 테스트 데이터나 특수 캡처 환경에서는 기존처럼 실제 분석 윈도우 시간을 사용한다.

| 기준 | 기본값 | 설명 |
|---|---:|---|
| `ICMP_PPS_THRESHOLD` | 150 | 초당 ICMP 패킷 수 기준 |
| `ICMP_MIN_PACKET_COUNT` | 100 | 최소 패킷 수 기준 |
| `ICMP_HIGH_PPS_THRESHOLD` | 500 | 높은 위험으로 보는 ICMP PPS |
| `ICMP_CRITICAL_PPS_THRESHOLD` | 1000 | Critical로 보는 ICMP PPS |

### UDP Flood

UDP Flood는 작은 패킷을 많이 보내는 공격과 큰 패킷으로 대역폭을 채우는 공격을 모두 보기 위해 PPS와 BPS를 함께 사용한다. 기본 대응 후보는 너무 넓어지지 않도록 `(출발지 IP, 목적지 IP, 목적지 포트)` 단위로 만든다. 다만 공격자가 여러 목적지 포트로 트래픽을 나누는 경우도 놓치지 않도록 `(출발지 IP, 목적지 IP)` 합산 기준을 추가로 본다. 특정 포트와 전체 UDP 흐름이 동시에 잡히고 전체 흐름의 대응 단계가 같거나 더 강하면 전체 흐름 이벤트만 전송하고, 서비스별 포트 근거는 `related_service_detections`에 남긴다.

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

SYN Flood는 SYN 패킷이 몰리고 연결이 끝까지 완료되지 않는 상황을 본다. 단일 목적지 포트에 집중되는 경우를 기본으로 보고, 여러 포트로 나뉘어 들어오더라도 출발지-목적지 전체 SYN PPS가 높고 연결 완료율이 낮으면 다중 서비스 SYN Flood로 묶어 판단한다.

| 기준 | 기본값 | 설명 |
|---|---:|---|
| `SYN_PPS_THRESHOLD` | 120 | 초당 SYN 패킷 수 기준 |
| `SYN_MIN_COUNT` | 30 | 최소 SYN 수 기준 |
| `SYN_HIGH_PPS_THRESHOLD` | 400 | 높은 위험으로 보는 SYN PPS |
| `SYN_CRITICAL_PPS_THRESHOLD` | 800 | Critical로 보는 SYN PPS |
| `SYN_MAX_UNIQUE_PORTS` | 5 | SYN Flood로 볼 수 있는 최대 목적지 포트 수 |

SYN 대비 SYN/ACK 비율은 보조 판단으로 사용하고, 최종 ACK는 별도 완료 수로 기록한다. 정상 TCP 연결처럼 SYN, SYN/ACK, 최종 ACK가 이어지면 SYN Flood로 보지 않는다. 반대로 SYN/ACK가 충분해도 최종 ACK가 거의 없으면 half-open 연결로 보고 SYN Flood 근거에 포함한다.

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

대응 후보는 현재 IPv4 OpenFlow match를 기준으로 생성한다. 그래서 잘못된 IP 주소와 IPv6 주소는 보안 이벤트 변환 단계에서 제외한다. 패킷 요약은 `ARP`, `OTHER`까지 통계로 보낼 수 있지만, 보안 이벤트는 현재 탐지기가 실제로 만드는 `ICMP`, `UDP`, `TCP` 프로토콜만 전송한다.

보안 이벤트 전송에 실패하면 해당 이벤트를 메모리 대기 큐에 남겨 다음 분석 구간에서 다시 전송한다. 재전송은 한 번에 최대 `SECURITY_EVENT_SEND_BATCH_SIZE`개씩 진행하고, 큐는 기본 `SECURITY_EVENT_QUEUE_MAX_SIZE=500`개까지만 보관한다. 큐가 가득 차서 오래된 이벤트가 밀려나면 로그에 남기고 중복 억제 기록에서도 제거해 이후 분석 구간에서 다시 만들어질 수 있게 한다.

백엔드는 `event_id`를 Elasticsearch 문서 ID로 사용해 저장한다. 그래서 Analyzer가 같은 이벤트를 재전송하더라도 보안 이벤트 문서가 중복으로 계속 쌓이지 않고 기존 문서가 갱신된다. evidence는 화면 상세 확인을 위해 `_source`에 남기지만, 임의 key가 Elasticsearch field를 계속 늘리지 않도록 세부 key는 인덱싱하지 않는다. 현재 큐는 프로세스 메모리 기반이므로, 장기 운영 단계에서는 파일이나 SQLite 기반 outbox로 확장할 수 있다.

보안 이벤트 POST 요청은 최대 1MB까지 허용한다. 이 제한은 개별 evidence 값 제한과 별도로, 대형 JSON이 검증 전에 메모리에 크게 올라가는 상황을 줄이기 위한 백엔드 보호 장치다. Analyzer가 400/413/422 응답을 받으면 같은 batch를 계속 재시도하지 않고 batch 크기를 절반으로 줄여 다시 전송한다. 하나의 이벤트까지 나눈 뒤에도 같은 오류가 나오면 해당 이벤트를 dead letter로 이동해 같은 fingerprint가 계속 재전송되지 않게 하고, 뒤의 정상 이벤트가 막히지 않게 한다. dead letter는 기본 1시간 뒤 만료되며 최대 1000개까지만 유지한다.

packet summary와 traffic stats는 보안 이벤트와 다르게 오래된 값을 모두 보낼 필요가 적다. 백엔드가 잠시 느려졌을 때 오래된 대시보드 요약이 길게 밀리면 화면이 뒤늦게 갱신되므로, 통계 전송 큐는 작게 유지하고 오래된 요약보다 최신 요약을 우선한다.

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
- UDP pair 전체 Flood가 서비스별 UDP Flood보다 같거나 강한 대응 단계로 잡히면 pair 이벤트만 유지하고 서비스별 포트 근거를 관련 탐지로 붙인다.
- Port Scan은 패킷 원본을 계속 들고 있지 않고 초 단위 버킷에 집계값만 저장한다.
- Port Scan 수평 스캔은 대상 IP 개수와 SYN 시도 수를 함께 본다. 대상 IP 수만으로 알림을 만들면 작은 실습 토폴로지에서 오탐이 쉽게 생기기 때문이다.
- Port Scan 알림 쿨다운은 유지하되, 기존 알림보다 점수나 위험도가 올라가면 다시 알림을 만든다.
- Flow Rule 대응 정보는 백엔드에서 한 번 더 검증한다. IPv4 조건은 `eth_type=2048`, TCP는 `ip_proto=6`, UDP는 `ip_proto=17`, ICMP는 `ip_proto=1`을 요구한다. 수동 Flow Rule은 `switch_id`가 필요하며, 차단/제한 계열 action은 너무 넓은 match로 생성되지 않도록 구체적인 IP, 포트, ICMP 타입 조건을 요구한다.
- Flood PPS는 패킷 timestamp가 있으면 snapshot 안의 1초 bucket을 시간 순서대로 모두 처리하고, 빈 초가 있으면 지속 초과 history를 초기화한다. 같은 1초 bucket이 여러 분석 호출에 나뉘면 집계는 합산하고 history는 한 번만 갱신한다. timestamp가 없으면 실제 분석 스냅샷 간격을 사용한다. 패킷 요약은 실제 분석 스냅샷 간격을 사용한다.
- 패킷 요약은 포트 값을 제외하고 출발지/목적지/프로토콜 단위로 합산한다. 포트별 근거는 보안 이벤트 evidence에서 확인한다.
- Analyzer 분석 루프와 백엔드 HTTP 전송 루프를 분리해 전송 지연이 분석 주기를 직접 막지 않게 했다.
- 백엔드 전송 큐에서는 보안 이벤트를 packet summary와 traffic stats보다 먼저 전송한다.
- packet summary와 traffic stats 전송 큐는 작게 유지해 오래된 대시보드 요약이 누적되지 않도록 했다.
- Analyzer 상태에는 보안 이벤트 대기열, 드롭 수, 패킷 버퍼 드롭 수, 마지막 전송 실패 시각을 포함하며 백엔드 DB에도 저장한다.
- Analyzer 분석 루프 오류는 다음 정상 분석 뒤 복구되며, 백엔드 전송 성공만으로 분석 오류 메시지를 지우지 않는다.
- 패킷 파서는 ARP를 `ARP`로, 그 외 미분류 프로토콜은 `OTHER`로 정리한다. 단, ARP와 OTHER는 패킷 요약 통계용이며 현재 보안 이벤트로는 전송하지 않는다.
- Analyzer는 `scapy.all` 대신 필요한 캡처 함수만 import하고, 현재 검증된 Scapy 버전을 고정해 IPv4 중심 실습 환경의 재현성을 높인다.

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
- timestamp가 있는 ICMP/UDP/SYN Flood는 분석이 지연되어도 1초 bucket을 시간 순서대로 처리하고, 비연속 bucket이나 같은 bucket의 분할 입력을 지속 공격으로 잘못 누적하지 않음
- ICMP Flood 대응 후보에는 `icmpv4_type=8`이 포함됨
- Flood 상태 기록은 일정 시간이 지나면 정리됨
- UDP Critical은 첫 탐지에서 Rate Limit, 지속 시 Drop으로 승격됨
- UDP Flood는 목적지 포트별로 집계되고 대응 후보에 `udp_dst`가 포함됨
- UDP Flood는 여러 목적지 포트로 나뉜 트래픽도 출발지-목적지 합산 기준으로 탐지함
- UDP Flood는 특정 포트 탐지와 출발지-목적지 합산 탐지가 겹치면 더 강한 대응 흐름 하나로 정리함
- 잘못된 패킷 크기와 `window_sec=0`을 안전하게 처리함
- 정상 TCP handshake는 SYN Flood로 탐지하지 않음
- SYN 응답 계산은 SYN/ACK와 최종 ACK 완료 수를 분리해 half-open 연결을 판단함
- SYN 응답 계산은 패킷 순서가 뒤집혀도 정상 연결을 공격으로 보지 않음
- SYN Flood는 Port Scan과 역할이 겹치지 않음
- 다중 서비스 SYN Flood와 Port Scan이 같은 흐름에서 동시에 잡히면 상관관계로 하나의 대응 후보만 유지함
- 탐지 결과가 백엔드 SecurityEvent 형식과 대응 후보로 변환됨
- 보안 이벤트 변환 단계에서 지원하지 않는 프로토콜은 전송 대상에서 제외됨
- 이벤트 식별자는 SHA-256 기반 fingerprint를 사용함
- 같은 이벤트는 중복 전송하지 않음
- 위험도가 상승한 이벤트는 중복 억제 중이어도 다시 전송됨
- 전송 실패한 보안 이벤트는 메모리 대기 큐에 남아 다음 주기에 재전송 가능함
- 보안 이벤트 대기 큐는 배치 전송, 크기 제한, 초과 이벤트 제거를 처리함
- 백엔드가 400/413/422를 반환하면 보안 이벤트 batch 크기를 줄여 재전송하고, 단일 이벤트까지 실패하면 dead letter로 이동함
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
