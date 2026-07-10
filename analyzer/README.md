# SDN Analyzer

분석 서버는 네트워크 인터페이스에서 패킷을 캡처하고, 짧은 시간 윈도우 단위로 패킷 요약, 트래픽 상태 요약, 보안 이벤트를 만들어 백엔드 서버로 전송한다. 컨트롤러에 직접 flow rule을 설치하지 않고, 탐지 결과와 대응 후보 payload만 백엔드에 전달한다.

## 실행 흐름

```text
app/packet/capture.py
  -> app/packet/parser.py
  -> app/packet/summary.py
  -> app/detection/traffic_stats.py
  -> app/detection/port_scan.py / app/detection/flood.py / app/detection/syn_flood.py
  -> app/detection/security_events.py
  -> app/backend_client.py
  -> backend /api/analyzer/*, /api/security/events
```

## 주요 파일

| 파일 | 역할 |
|---|---|
| `app/main.py` | 실행 진입점, 캡처/분석/상태 전송 루프 구성 |
| `app/config.py` | 환경변수 파싱 및 설정 객체 생성 |
| `app/packet/capture.py` | Scapy 기반 패킷 캡처 |
| `app/packet/parser.py` | 패킷에서 IP, 포트, 프로토콜, 크기, TCP flag 추출 |
| `app/packet/summary.py` | 윈도우 단위 패킷/프로토콜/호스트 통계 생성 |
| `app/detection/traffic_stats.py` | bps/pps 계산, 네트워크 상태 생성 |
| `app/detection/common.py` | 공통 점수 정책과 안전한 값 변환 함수 |
| `app/detection/flood.py` | ICMP Flood, UDP Flood 탐지 |
| `app/detection/port_scan.py` | TCP SYN 기반 포트 스캔 의심 탐지 |
| `app/detection/syn_flood.py` | 단일 서비스 집중 SYN Flood 탐지 |
| `app/detection/security_events.py` | 보안 탐지 결과를 공통 보안 이벤트 payload와 대응 후보로 변환 |
| `app/analyzer_status.py` | 분석 서버 상태 payload 생성 |
| `app/backend_client.py` | 백엔드 API 전송 |
| `analyzer-backend-api.md` | 분석 서버 -> 백엔드 API 상세 명세 |

## 환경변수

| 이름 | 기본값 | 설명 |
|---|---|---|
| `ANALYZER_ID` | `analyzer-1` | 분석 서버 식별자 |
| `ANALYZER_INTERFACE` | `eth0` | 패킷 캡처 인터페이스 |
| `ANALYZER_WINDOW_SEC` | `1` | 패킷/탐지 요약 생성 주기 |
| `ANALYZER_STATUS_INTERVAL_SEC` | `5` | 상태 전송 주기 |
| `BACKEND_BASE_URL` | `http://127.0.0.1:8000` | 백엔드 API 주소 |
| `PORT_SCAN_WINDOW_SEC` | `5` | Port Scan SYN 집계 윈도우 |
| `PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD` | `15` | Port Scan 고유 목적지 포트 임계값 |
| `PORT_SCAN_SYN_COUNT_THRESHOLD` | `30` | Port Scan SYN 시도 수 보조 조건 기준 |
| `PORT_SCAN_MULTI_TARGET_WINDOW_SEC` | `30` | Port Scan 다중 목적지 판단 윈도우 |
| `PORT_SCAN_HORIZONTAL_TARGET_THRESHOLD` | `3` | Port Scan 수평 스캔 목적지 수 기준 |
| `PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD` | `50` | Port Scan 높은 고유 포트 수 기준 |
| `PORT_SCAN_ALERT_COOLDOWN_SEC` | `60` | Port Scan 중복 알림 억제 시간 |
| `ICMP_PPS_THRESHOLD` | `150` | ICMP Flood pps 임계값 |
| `ICMP_MIN_PACKET_COUNT` | `100` | ICMP Flood 최소 패킷 수 기준 |
| `ICMP_HIGH_PPS_THRESHOLD` | `500` | ICMP Flood high pps 기준 |
| `ICMP_CRITICAL_PPS_THRESHOLD` | `1000` | ICMP Flood critical pps 기준 |
| `UDP_PPS_THRESHOLD` | `250` | UDP Flood pps 임계값 |
| `UDP_MIN_PACKET_COUNT` | `100` | UDP Flood 최소 패킷 수 기준 |
| `UDP_HIGH_PPS_THRESHOLD` | `800` | UDP Flood high pps 기준 |
| `UDP_CRITICAL_PPS_THRESHOLD` | `1500` | UDP Flood critical pps 기준 |
| `UDP_BPS_THRESHOLD` | `2000000` | UDP Flood bps 임계값 |
| `UDP_HIGH_BPS_THRESHOLD` | `8000000` | UDP Flood high bps 기준 |
| `UDP_CRITICAL_BPS_THRESHOLD` | `15000000` | UDP Flood critical bps 기준 |
| `SYN_PPS_THRESHOLD` | `120` | SYN Flood pps 임계값 |
| `SYN_MIN_COUNT` | `30` | SYN Flood 최소 SYN 수 기준 |
| `SYN_HIGH_PPS_THRESHOLD` | `400` | SYN Flood high pps 기준 |
| `SYN_CRITICAL_PPS_THRESHOLD` | `800` | SYN Flood critical pps 기준 |
| `SYN_MAX_UNIQUE_PORTS` | `5` | SYN Flood로 볼 최대 목적지 포트 수 |
| `EVENT_DEDUP_WINDOW_SEC` | `60` | 보안 이벤트 공통 중복 억제 시간 |
| `RATE_LIMIT_PRIORITY` | `500` | Rate limit 후보 flow rule 우선순위 |
| `RATE_LIMIT_IDLE_TIMEOUT` | `60` | Rate limit 후보 idle timeout |
| `RATE_LIMIT_HARD_TIMEOUT` | `300` | Rate limit 후보 hard timeout |
| `RATE_LIMIT_PPS` | `100` | Rate limit 후보 제한 pps |
| `DROP_PRIORITY` | `700` | Drop 후보 flow rule 우선순위 |
| `DROP_IDLE_TIMEOUT` | `30` | Drop 후보 idle timeout |
| `DROP_HARD_TIMEOUT` | `120` | Drop 후보 hard timeout |

Docker Compose 실행 시에는 루트 `.env` 또는 `.env.example`의 값을 사용한다.

## 백엔드 전송 API

| 메서드 | 경로 | 설명 |
|---|---|---|
| `POST` | `/api/analyzer/packet-summary` | 패킷 요약 전송 |
| `POST` | `/api/analyzer/detection-summary` | 트래픽 상태 요약 전송 |
| `POST` | `/api/security/events` | 보안 이벤트 전송 |
| `POST` | `/api/analyzer/status` | 분석 서버 상태 전송 |

요청/응답 필드 상세는 `analyzer-backend-api.md`를 기준으로 한다.

백엔드는 `POST /api/security/events`로 받은 이벤트를 Elasticsearch에 저장하고, 이벤트별 보안 대응 내역을 PostgreSQL `security_responses`에 생성한다. 이벤트에 `mitigation`이 있으면 PostgreSQL `flow_rules`에 `PENDING` 상태의 flow rule 후보도 생성한다.

## 현재 탐지 범위

현재 구현된 탐지는 다음 네 가지다.

| 탐지 | 구현 위치 | 설명 |
|---|---|---|
| Port Scan | `app/detection/port_scan.py` | TCP SYN 패턴으로 수직/수평 스캔 탐지 |
| ICMP Flood | `app/detection/flood.py` | ICMP Echo Request가 반복적으로 기준 이상이면 탐지 |
| UDP Flood | `app/detection/flood.py` | 같은 목적지 포트로 UDP pps와 bps가 반복적으로 기준 이상이면 탐지 |
| SYN Flood | `app/detection/syn_flood.py` | 단일 서비스에 SYN 패킷이 집중되고 SYN/ACK 응답이 부족하면 탐지 |

탐지 기준값과 탐지 이벤트 상세 필드는 보안/탐지 담당자와 합의 후 변경한다. 탐지 조건과 대응 레벨 정책은 `README_SECURITY_DETECTION.md`를 기준으로 한다.

## 개발 시 주의사항

- 분석 서버는 컨트롤러에 직접 대응 요청을 보내지 않는다.
- 자동 대응에 필요한 payload는 `mitigation`으로만 제안한다. 실제 승인, 저장, 컨트롤러 적용 여부는 백엔드/컨트롤러 쪽 책임이다.
- `total_bps`, `total_pps`는 윈도우 내 누적 값을 `window_sec`로 나눈 초당 값이다.
- 분석 루프와 상태 전송 루프는 예외가 발생해도 오류 상태를 기록하고 계속 실행된다.
- 백엔드 전송 실패는 로그로 남기고 해당 전송은 실패 처리한다.
- 보안 이벤트 전송이 실패하면 메모리 대기 큐에 남겨 다음 분석 구간에서 다시 전송한다.
- 패킷 캡처에는 OS/컨테이너 권한이 필요할 수 있다.

## 팀원이 주로 수정할 곳

탐지 로직을 추가하거나 조정할 때는 보통 아래 파일을 수정한다.

```text
app/detection/port_scan.py
app/detection/flood.py
app/detection/syn_flood.py
app/detection/security_events.py
app/packet/parser.py
```

백엔드 전송 payload를 바꿔야 한다면 아래 파일과 백엔드 스키마를 함께 확인한다.

```text
app/packet/summary.py
app/detection/traffic_stats.py
app/detection/security_events.py
app/backend_client.py
../backend/app/schemas/analyzer.py
../backend/app/schemas/security.py
```
