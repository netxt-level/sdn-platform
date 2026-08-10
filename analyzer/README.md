# SDN Analyzer

- 상태: 패킷 관측·6종 탐지·영속 전달 구현
- 기준일: 2026-08-11

분석 서버는 네트워크 인터페이스에서 패킷을 캡처하고, 짧은 시간 윈도우 단위로 패킷 요약, 트래픽 상태 요약, 보안 이벤트를 만들어 백엔드 서버로 전송한다. 컨트롤러에 직접 flow rule을 설치하지 않고, 탐지 결과와 대응 후보 payload만 백엔드에 전달한다.

## 실행 흐름

```text
app/packet/capture.py
  -> app/packet/parser.py
  -> app/packet/summary.py
  -> app/detection/traffic_stats.py / app/detection/port_scan.py
     / app/detection/server_behavior.py / app/detection/security_events.py
  -> app/outbox.py
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
| `app/detection/port_scan.py` | TCP SYN 기반 포트 스캔 의심 탐지 |
| `app/detection/server_behavior.py` | 보호 서버의 역할 위반·내부 확산·송신량·Beacon 탐지 |
| `app/detection/security_events.py` | 포트 스캔/DDoS 탐지 결과를 공통 보안 이벤트 payload로 변환 |
| `app/outbox.py` | SQLite WAL 기반 영속 전송 Queue, 재시도, Dead Letter 관리 |
| `app/analyzer_status.py` | 분석 서버 상태 payload 생성 |
| `app/backend_client.py` | 백엔드 API 전송 |
| `analyzer-backend-api.md` | 분석 서버 -> 백엔드 API 상세 명세 |

## 환경변수

| 이름 | 기본값 | 설명 |
|---|---|---|
| `ANALYZER_ID` | `analyzer-1` | 분석 서버 식별자 |
| `ANALYZER_INTERFACE` | `en0` | 패킷 캡처 인터페이스 |
| `ANALYZER_WINDOW_SEC` | `1` | 패킷/탐지 요약 생성 주기 |
| `ANALYZER_STATUS_INTERVAL_SEC` | `5` | 상태 전송 주기 |
| `ANALYZER_OUTBOX_PATH` | `/var/lib/sdn-analyzer/outbox.db` | 영속 Outbox SQLite 경로 |
| `ANALYZER_OUTBOX_DELIVERY_POLL_SEC` | `1` | 전달 Queue 확인 주기 |
| `ANALYZER_OUTBOX_DELIVERY_BATCH_SIZE` | `100` | 한 번에 전달할 최대 메시지 수 |
| `ANALYZER_OUTBOX_RETRY_BASE_SEC` | `1` | 일시 오류 첫 재시도 지연 |
| `ANALYZER_OUTBOX_RETRY_MAX_SEC` | `60` | 지수 Backoff 최대 지연 |
| `BACKEND_BASE_URL` | `http://127.0.0.1:8000` | 백엔드 API 주소 |
| `ANALYZER_API_KEY` | 빈 값 | Analyzer 수신 API의 `X-API-Key`; 운영 시 필수 |
| `PORT_SCAN_WINDOW_SEC` | `5` | Port Scan SYN 집계 윈도우 |
| `PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD` | `20` | Port Scan 고유 목적지 포트 임계값 |
| `PORT_SCAN_SYN_COUNT_THRESHOLD` | `20` | Port Scan SYN 시도 수 보조 조건 기준 |
| `PORT_SCAN_MULTI_TARGET_WINDOW_SEC` | `30` | Port Scan 다중 목적지 판단 윈도우 |
| `PORT_SCAN_MULTI_TARGET_THRESHOLD` | `3` | Port Scan 다중 목적지 개수 기준 |
| `PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD` | `50` | Port Scan 높은 고유 포트 수 기준 |
| `PORT_SCAN_ALERT_COOLDOWN_SEC` | `60` | Port Scan 중복 알림 억제 시간 |
| `PROTECTED_SERVER_IPS` | `10.0.0.100` | 서버 행위 탐지 대상 IP 목록 |
| `SERVER_EGRESS_ALLOWLIST` | 빈 값 | 보호 서버가 연결을 시작해도 허용할 목적지 IP 목록 |
| `SERVER_BEHAVIOR_ALERT_COOLDOWN_SEC` | `60` | 서버 행위 이벤트 중복 억제 시간 |
| `LATERAL_FANOUT_WINDOW_SEC` | `30` | 내부 확산 목적지 집계 윈도우 |
| `LATERAL_FANOUT_UNIQUE_DST_THRESHOLD` | `2` | 내부 확산 고유 목적지 IP 기준 |
| `LATERAL_FANOUT_CONNECTION_THRESHOLD` | `3` | 내부 확산 연결 시도 기준 |
| `EXFIL_VOLUME_WINDOW_SEC` | `10` | 비정상 송신량 집계 윈도우 |
| `EXFIL_OUTBOUND_BPS_THRESHOLD` | `1000000` | 비정상 송신량 절대 bps 기준 |
| `EXFIL_BASELINE_MULTIPLIER` | `3.0` | 정상 기준선 대비 송신량 배수 |
| `EXFIL_SUSTAINED_WINDOWS` | `3` | 송신량 기준을 연속 충족해야 하는 윈도우 수 |
| `C2_BEACON_WINDOW_SEC` | `300` | 주기적 연결 관찰 윈도우 |
| `C2_BEACON_MIN_CONNECTIONS` | `6` | Beacon 판정 최소 연결 수 |
| `C2_BEACON_MIN_INTERVAL_SEC` | `20` | Beacon 주기 하한 |
| `C2_BEACON_MAX_INTERVAL_SEC` | `90` | Beacon 주기 상한 |
| `C2_BEACON_MAX_JITTER_RATIO` | `0.2` | 연결 주기 최대 편차 비율 |
| `ICMP_PPS_THRESHOLD` | `1000` | ICMP Flood pps 임계값 |
| `ICMP_MIN_PACKET_COUNT` | `1000` | ICMP Flood 최소 패킷 수 기준 |
| `ICMP_HIGH_PPS_THRESHOLD` | `3000` | ICMP Flood high pps 기준 |
| `ICMP_HIGH_PPS_MULTIPLIER` | `3.0` | ICMP Flood high pps 배수 기준 |
| `ICMP_BASELINE_SPIKE_MULTIPLIER` | `5.0` | 호환용 예약 설정; 현재 ICMP 점수에는 미반영 |
| `ICMP_BASELINE_MIN_PPS` | `100` | 호환용 예약 설정; 현재 ICMP 점수에는 미반영 |
| `ICMP_ALERT_COOLDOWN_SEC` | `60` | ICMP Flood 중복 알림 억제 시간 |
| `EVENT_DEDUP_WINDOW_SEC` | `60` | 보안 이벤트 공통 중복 억제 시간 |
| `RATE_LIMIT_PRIORITY` | `500` | Rate limit 후보 flow rule 우선순위 |
| `RATE_LIMIT_IDLE_TIMEOUT` | `60` | Rate limit 후보 idle timeout |
| `RATE_LIMIT_HARD_TIMEOUT` | `300` | Rate limit 후보 hard timeout |
| `RATE_LIMIT_PPS` | `100` | Rate limit 후보 제한 pps |

Docker Compose 실행 시에는 루트 `.env` 또는 `.env.example`의 값을 사용한다.

## 백엔드 전송 API

| 메서드 | 경로 | 설명 |
|---|---|---|
| `POST` | `/api/analyzer/packet-summary` | 패킷 요약 전송 |
| `POST` | `/api/analyzer/detection-summary` | 트래픽 상태 요약 전송 |
| `POST` | `/api/security/events` | 보안 이벤트 전송 |
| `POST` | `/api/analyzer/status` | 분석 서버 상태 전송 |

요청/응답 필드 상세는 `analyzer-backend-api.md`를 기준으로 한다.

백엔드는 `POST /api/security/events`로 받은 이벤트를 Elasticsearch에 저장하고, 이벤트별 보안 대응 내역을 PostgreSQL `security_responses`에 생성한다. 이벤트에 `mitigation`이 있으면 PostgreSQL `flow_rules`에 flow rule을 생성하고 Controller에 자동 적용한 뒤 결과를 `APPLIED` 또는 `FAILED`로 저장한다.

## 현재 탐지 범위

현재 구현된 탐지는 다음과 같다.

| 탐지 | 구현 위치 | 설명 |
|---|---|---|
| Port Scan | `app/detection/port_scan.py`, `app/detection/security_events.py` | 짧은 시간 안에 같은 대상의 여러 TCP 목적지 포트로 SYN 패킷을 보내면 탐지 |
| ICMP Flood | `app/detection/security_events.py` | ICMP pps가 기준 이상이면 탐지 |
| Server Egress | `app/detection/server_behavior.py` | 보호 서버가 허용 목록 밖 목적지로 시작한 TCP 연결 탐지 |
| Lateral Movement | `app/detection/server_behavior.py` | 보호 서버가 짧은 시간에 여러 목적지로 연결하는 행위 탐지 |
| Data Exfiltration | `app/detection/server_behavior.py` | 서버가 시작한 Flow의 지속적인 outbound bps 이상 탐지 |
| C2 Beacon | `app/detection/server_behavior.py` | 같은 목적지·포트로 반복되는 낮은 jitter 연결 탐지 |

탐지 기준값과 탐지 이벤트 상세 필드는 보안/탐지 담당자와 합의 후 변경한다.
모든 탐지 조건과 대응 레벨 정책은 `../SECURITY_DETECTION_POLICY.md`를
기준으로 한다.

## 개발 시 주의사항

- 분석 서버는 컨트롤러에 직접 대응 요청을 보내지 않는다.
- 자동 대응에 필요한 payload는 `mitigation`으로만 제안한다. 실제 저장, 정책 승인 표시, Controller 적용과 결과 기록은 백엔드/Controller 책임이다.
- `total_bps`, `total_pps`는 윈도우 내 누적 값을 `window_sec`로 나눈 초당 값이다.
- 분석 루프와 상태 전송 루프는 예외가 발생해도 오류 상태를 기록하고 계속 실행된다.
- 패킷·탐지 요약과 보안 이벤트는 Outbox에 먼저 저장한다. 연결 오류와 5xx는
  지수 Backoff로 재시도하고, 재시도할 수 없는 4xx는 Dead Letter로 보존한다.
- 루트 `docker-compose.yml`은 `/var/lib/sdn-analyzer` volume을 연결한다. 현재
  Multipass bootstrap이 단독 사용하는 `docker-compose.dataplane.yml`에는
  volume과 `ANALYZER_API_KEY` 전달이 없으므로 두 Compose 파일 병합 또는 배치
  수정 전에는 secure-default 전달과 재생성 내구성이 보장되지 않는다.
- 상태 보고는 Outbox 대상이 아니므로 실패하면 다음 주기에 다시 보고한다.
- 패킷 캡처에는 OS/컨테이너 권한이 필요할 수 있다.

## 팀원이 주로 수정할 곳

탐지 로직을 추가하거나 조정할 때는 보통 아래 파일을 수정한다.

```text
app/detection/port_scan.py
app/detection/server_behavior.py
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
