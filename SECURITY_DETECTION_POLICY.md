# 보안 탐지 정책

이 문서는 Analyzer가 생성하는 보안 탐지 이벤트의 기준과 대응 후보 생성 방식을 정리한다. Analyzer는 Controller에 직접 차단 규칙을 설치하지 않고, 백엔드가 저장하거나 Controller가 사용할 수 있는 대응 후보만 만든다.

## 구현 범위

| attack_type | 구현 파일 | 설명 |
|---|---|---|
| `PORT_SCAN` | `analyzer/app/detection/port_scan.py` | TCP SYN 기반 수직/수평 Port Scan 탐지 |
| `ICMP_FLOOD` | `analyzer/app/detection/flood.py` | ICMP Echo Request 기반 Flood 탐지 |
| `UDP_FLOOD` | `analyzer/app/detection/flood.py` | UDP 포트별/출발지-목적지 합산 Flood 탐지 |
| `SYN_FLOOD` | `analyzer/app/detection/syn_flood.py` | 단일/다중 서비스 SYN Flood 탐지 |

현재 탐지는 IPv4 보안 이벤트와 IPv4 OpenFlow match 생성을 기준으로 한다. 잘못된 IP 주소와 IPv6 주소는 이벤트 변환 단계에서 제외한다.

백엔드는 보안 이벤트 수신 시 현재 구현된 `PORT_SCAN`, `ICMP_FLOOD`, `UDP_FLOOD`, `SYN_FLOOD`만 허용한다. 위험도, 신뢰도, 권장 대응, 대응 레벨도 정해진 값만 통과시키며, 대응 후보의 match는 IPv4 OpenFlow 필드만 허용한다.

## 점수와 대응

| 점수 | 위험도 | 대응 후보 |
|---:|---|---|
| 0~44 | Low | 로그 |
| 45~69 | Medium | 알림 |
| 70~84 | High | Rate Limit 후보 |
| 85~100 | Critical | Drop 후보 가능 |

Flood 계열은 Critical 기준을 한 번 넘었다고 바로 Drop 후보를 만들지 않는다. 첫 Critical은 Rate Limit 후보로 보내고, 다음 분석 구간에서도 공격이 지속되면 Drop 후보로 승격한다. 이 구분은 evidence의 `mitigation_stage`, `drop_allowed`, `escalation_reason`에 기록한다.

Port Scan은 정상 점검과 비슷하게 보일 수 있으므로 Critical 수준이어도 Drop 대신 Rate Limit 후보까지만 만든다.

## ICMP Flood

ICMP Flood는 ICMP Echo Request만 본다. Echo Reply, Destination Unreachable, Time Exceeded 같은 메시지는 진단 또는 오류 알림일 수 있으므로 집계하지 않는다.

| 기준 | 기본값 |
|---|---:|
| `ICMP_PPS_THRESHOLD` | 150 |
| `ICMP_MIN_PACKET_COUNT` | 100 |
| `ICMP_HIGH_PPS_THRESHOLD` | 500 |
| `ICMP_CRITICAL_PPS_THRESHOLD` | 1000 |

대응 후보에는 `ip_proto=1`, `icmpv4_type=8`이 포함된다.

## UDP Flood

UDP Flood는 PPS와 BPS를 함께 본다. 작은 패킷을 많이 보내는 공격과 큰 패킷으로 대역폭을 채우는 공격을 모두 다루기 위해서다.

| 집계 방식 | 목적 |
|---|---|
| `(src_ip, dst_ip, dst_port)` | 특정 UDP 서비스 공격을 좁게 대응 |
| `(src_ip, dst_ip)` | 여러 목적지 포트로 나눠 보내는 공격 탐지 |

특정 포트 기준으로 탐지되면 대응 후보에 `udp_dst`가 들어간다. 여러 포트 합산 기준도 동시에 넘으면 pair 전체 이벤트도 함께 만든다. pair 이벤트는 `destination_port`가 없을 수 있다.

| 기준 | 기본값 |
|---|---:|
| `UDP_PPS_THRESHOLD` | 250 |
| `UDP_MIN_PACKET_COUNT` | 100 |
| `UDP_HIGH_PPS_THRESHOLD` | 800 |
| `UDP_CRITICAL_PPS_THRESHOLD` | 1500 |
| `UDP_BPS_THRESHOLD` | 2000000 |
| `UDP_HIGH_BPS_THRESHOLD` | 8000000 |
| `UDP_CRITICAL_BPS_THRESHOLD` | 15000000 |

2 Mbps BPS 기준은 Mininet 실습과 공격 시연에는 유용하지만, 정상 UDP 성능 테스트에서는 민감할 수 있다. 실제 운영 기준으로 쓰려면 관리 트래픽 정책이나 Baseline 보정이 필요하다.

## SYN Flood

SYN Flood는 SYN 요청이 몰리고 SYN/ACK 응답이 부족한 상황을 본다. 기본은 특정 목적지 IP와 포트에 집중되는 단일 서비스 패턴이다. 다만 여러 포트로 나뉜 SYN이 Port Scan처럼 보이더라도 전체 SYN 양이 크고 응답이 부족하면 다중 서비스 SYN Flood로 묶어 탐지한다.

| 기준 | 기본값 |
|---|---:|
| `SYN_PPS_THRESHOLD` | 120 |
| `SYN_MIN_COUNT` | 30 |
| `SYN_HIGH_PPS_THRESHOLD` | 400 |
| `SYN_CRITICAL_PPS_THRESHOLD` | 800 |
| `SYN_MAX_UNIQUE_PORTS` | 5 |

응답 계산에는 서버가 보내는 SYN/ACK만 사용한다. 최종 ACK는 정상 연결 하나를 두 번 계산할 수 있어 응답 수에 넣지 않는다.

다중 서비스 SYN Flood와 Port Scan이 같은 출발지, 목적지, 프로토콜에서 동시에 잡히면 같은 흐름에 대응 후보가 두 개 생길 수 있다. 이 경우 Analyzer는 더 강한 대응 후보인 SYN Flood를 유지하고 Port Scan 근거는 `related_detections` evidence로 붙인다.

## Port Scan

Port Scan은 TCP SYN 패킷을 기준으로 수직 스캔과 수평 스캔을 구분한다.

| 유형 | 설명 |
|---|---|
| 수직 스캔 | 한 대상 IP의 여러 포트를 확인 |
| 수평 스캔 | 여러 대상 IP의 같은 포트를 확인 |

| 기준 | 기본값 |
|---|---:|
| `PORT_SCAN_WINDOW_SEC` | 5 |
| `PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD` | 15 |
| `PORT_SCAN_SYN_COUNT_THRESHOLD` | 30 |
| `PORT_SCAN_MULTI_TARGET_WINDOW_SEC` | 30 |
| `PORT_SCAN_HORIZONTAL_TARGET_THRESHOLD` | 3 |
| `TRUSTED_HORIZONTAL_SCAN_THRESHOLD` | 10 |
| `PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD` | 50 |
| `PORT_SCAN_ALERT_COOLDOWN_SEC` | 60 |

관리 호스트는 수평 스캔 기준을 완전히 면제하지 않고 완화만 한다. 작은 토폴로지에서는 대상 수만으로는 탐지가 어려울 수 있어, `PORT_SCAN_SYN_COUNT_THRESHOLD` 이상의 반복 SYN이면 관리 호스트도 탐지한다.

## 이벤트 안정성

- 같은 이벤트는 fingerprint로 중복 억제한다.
- Elasticsearch와 프론트엔드 병합은 `event_id`를 우선 사용한다.
- 위험도나 대응 단계가 올라가면 중복 억제 중이어도 다시 전송한다.
- 백엔드 전송 실패 이벤트는 메모리 대기 큐에 저장한다.
- 큐는 기본 500개까지 보관하고, 기본 100개씩 배치 전송한다.
- 큐가 가득 차면 오래된 이벤트를 제거하고 중복 억제 기록도 해제한다.

현재 큐는 메모리 기반이므로 프로세스가 종료되면 대기 이벤트가 사라진다. 장시간 운영 기준으로는 SQLite 또는 파일 기반 outbox가 필요하다.

## 현재 한계

- 여러 출발지가 동시에 한 목적지를 공격하는 분산 DDoS 집계는 아직 없다.
- Low-and-Slow 장기 누적 탐지는 아직 없다.
- Baseline 기반 동적 임계값은 아직 없다.
- FIN/NULL/XMAS/UDP Scan은 아직 탐지하지 않는다.
- 실제 Controller Flow Rule 설치와 자동 해제는 아직 구현 범위 밖이다.
- Elasticsearch에는 `event_id`를 문서 ID로 사용해 저장하므로, Analyzer가 같은 이벤트를 재전송해도 중복 문서가 쌓이지 않는다.

## 검증 기준

```bash
python -m compileall -q analyzer/app analyzer/tests backend/app backend/tests
python -m pytest analyzer/tests backend/tests -q
npm --prefix frontend run lint
npm --prefix frontend run build
git diff --check
```

## 최근 검토 반영 사항

- SYN Flood는 단일 서비스 기준을 기본으로 보되, 6~14개 포트처럼 Port Scan 기준에는 아직 못 미치면서 전체 SYN 양이 큰 구간을 놓치지 않도록 출발지-목적지 단위의 다중 서비스 SYN Flood 기준을 추가했다.
- Port Scan과 다중 서비스 SYN Flood가 같은 흐름에서 동시에 잡히면 더 강한 SYN Flood 이벤트만 전송하고, Port Scan은 관련 근거로 묶는다.
- Port Scan은 패킷을 계속 보관하지 않고 초 단위 버킷에 필요한 집계만 저장한다. 장시간 실행 시 메모리 증가를 줄이기 위한 처리다.
- Port Scan의 수평 스캔은 대상 IP 수만으로 판단하지 않고 최소 SYN 시도 수를 함께 확인한다. 작은 Mininet 토폴로지에서 대상 3개에 1회씩 접근한 정상 점검 트래픽이 바로 알림으로 잡히는 문제를 줄이기 위한 기준이다.
- Port Scan 쿨다운은 같은 수준의 반복 알림은 막지만, 점수나 위험도가 올라간 경우에는 새 알림을 허용한다. 이전 알림보다 위험해진 상황이 묻히지 않도록 하기 위한 처리다.
- Flow Rule 입력은 `switch_id`를 필수로 받고, IPv4 match에 `eth_type=2048`을 요구한다. TCP/UDP/ICMP 조건은 각각 맞는 `ip_proto`가 있을 때만 허용하며, `DROP`/`RATE_LIMIT`은 IP, 포트, ICMP 타입 중 하나 이상의 구체적인 match가 있어야 한다.
- 프론트엔드는 `DROP`과 `RATE_LIMIT` 대응을 구분해서 표시하고, `packet_count`를 그대로 PPS로 보지 않고 `window_seconds`와 함께 계산한다.
- Analyzer는 고정 `ANALYZER_WINDOW_SEC`가 아니라 실제 스냅샷 간격을 `window_sec`에 담아 Flood PPS 계산과 트래픽 요약에 사용한다.
- 패킷 요약의 host 통계는 임시 `src_port`와 `dst_port`를 집계 키에서 제외하고 출발지/목적지/프로토콜 단위로 합산한다. InfluxDB에는 대표 포트만 field로 저장해 카디널리티 증가와 동일 timestamp 덮어쓰기 위험을 줄인다.
- Analyzer 분석 루프와 백엔드 HTTP 전송 루프를 분리했다. 백엔드가 잠시 느려져도 패킷 분석 주기가 바로 막히지 않도록 하기 위한 구조다.
- Analyzer 런타임 메트릭은 PostgreSQL에도 저장한다. 보안 이벤트 대기열 수, 드롭된 이벤트 수, 패킷 버퍼 드롭 수, 마지막 보안 이벤트 전송 실패 시각이 새로고침 뒤에도 유지된다.
