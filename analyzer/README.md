# SDN Analyzer

분석 서버는 네트워크 인터페이스에서 패킷을 캡처하고, 짧은 시간 윈도우 단위로 트래픽 요약, 탐지 요약, 보안 이벤트를 만들어 백엔드 서버로 전송한다. 컨트롤러에 직접 flow rule을 설치하지 않고, 탐지 결과와 대응 후보만 백엔드에 전달한다.

## 실행 흐름

```text
app/packet/capture.py
  -> app/packet/parser.py
  -> app/packet/summary.py
  -> app/detection/traffic_stats.py / app/detection/port_scan.py / app/security/runtime.py
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
| `app/detection/traffic_stats.py` | bps/pps 계산, DoS 의심 호스트, 네트워크 상태 생성 |
| `app/detection/port_scan.py` | TCP SYN 기반 포트 스캔 의심 탐지 |
| `app/security/engine.py` | ARP Spoofing 중심 보안 이벤트와 Port Scan/ICMP Flood 보조 탐지 |
| `app/security/runtime.py` | 보안 탐지용 rolling window와 이벤트 중복 억제 관리 |
| `app/security/backend_contract.py` | 보안 이벤트를 백엔드/프론트엔드 payload 형태로 변환 |
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
| `SECURITY_WINDOW_SEC` | `10` | 보안 이벤트 판단용 rolling window |
| `SECURITY_GATEWAY_IP` | `10.0.0.254` | ARP Spoofing 판단에 사용할 Gateway IP |
| `SECURITY_GATEWAY_MAC` | `00:00:00:00:ff:ff` | 정상 Gateway MAC |
| `SECURITY_EVENT_COOLDOWN_SEC` | `30` | 같은 보안 이벤트 중복 전송 억제 시간 |
| `PORT_SCAN_WINDOW_SEC` | `5` | Port Scan SYN 집계 윈도우 |
| `PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD` | `20` | Port Scan 고유 목적지 포트 임계값 |
| `PORT_SCAN_SYN_COUNT_THRESHOLD` | `20` | Port Scan SYN 시도 수 보조 조건 기준 |
| `PORT_SCAN_MULTI_TARGET_WINDOW_SEC` | `30` | Port Scan 다중 목적지 판단 윈도우 |
| `PORT_SCAN_MULTI_TARGET_THRESHOLD` | `3` | Port Scan 다중 목적지 개수 기준 |
| `PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD` | `50` | Port Scan 높은 고유 포트 수 기준 |
| `PORT_SCAN_ALERT_COOLDOWN_SEC` | `60` | Port Scan 의심 호스트 중복 알림 억제 시간 |
| `ICMP_PPS_THRESHOLD` | `100` | ICMP Flood pps 임계값 |
| `SECURITY_RATE_LIMIT_PPS` | `50` | 보안 이벤트 rate limit 후보 pps |
| `BACKEND_BASE_URL` | `http://127.0.0.1:8000` | 백엔드 API 주소 |

Docker Compose 실행 시에는 루트 `.env` 또는 `.env.example`의 값을 사용한다.

## 백엔드 전송 API

| 메서드 | 경로 | 설명 |
|---|---|---|
| `POST` | `/api/analyzer/packet-summary` | 패킷 요약 전송 |
| `POST` | `/api/analyzer/detection-summary` | 탐지 요약 전송 |
| `POST` | `/api/security/events` | 보안 이벤트 전송 |
| `POST` | `/api/analyzer/status` | 분석 서버 상태 전송 |

요청/응답 필드 상세는 `analyzer-backend-api.md`를 기준으로 한다.

## 현재 탐지 범위

분석 서버에는 대시보드용 탐지 요약과 보안 이벤트용 탐지가 함께 있다. 최종 보안 시나리오는 ARP Spoofing이며, Port Scan과 ICMP Flood는 보조 탐지로 둔다.

| 탐지 | 구현 위치 | 설명 |
|---|---|---|
| DoS 의심 | `app/detection/traffic_stats.py` | 대시보드 탐지 요약용. 호스트별 pps/bps가 기준 이상이면 의심 호스트로 포함 |
| Port Scan 의심 | `app/detection/port_scan.py` | 대시보드 탐지 요약용. 짧은 시간 안에 같은 대상의 여러 TCP 목적지 포트로 SYN 패킷을 보내면 탐지 |
| ARP Spoofing | `app/security/engine.py` | Gateway IP의 정상 MAC과 ARP Reply sender MAC이 다르면 탐지 |
| Port Scan 보안 이벤트 | `app/security/engine.py` | TCP SYN 기반 스캔 근거를 보안 이벤트로 생성하는 보조 탐지 |
| ICMP Flood 보안 이벤트 | `app/security/engine.py` | ICMP PPS와 최소 패킷 수 기준으로 생성하는 보조 탐지 |

보안 이벤트 범위에는 DDoS, UDP Flood, SYN Flood, 링크 혼잡, 링크 장애를 포함하지 않는다. 탐지 기준값과 이벤트 상세 필드는 보안/탐지 담당자와 합의 후 변경한다.

## 개발 시 주의사항

- 분석 서버는 컨트롤러에 직접 대응 요청을 보내지 않는다.
- 자동 대응에 필요한 payload는 백엔드와 계약을 먼저 정한 뒤 추가한다.
- `total_bps`, `total_pps`는 윈도우 내 누적 값을 `window_sec`로 나눈 초당 값이다.
- 분석 루프와 상태 전송 루프는 예외가 발생해도 오류 상태를 기록하고 계속 실행된다.
- 백엔드 전송 실패는 로그로 남기고 해당 전송은 실패 처리한다.
- 패킷 캡처에는 OS/컨테이너 권한이 필요할 수 있다.

## 팀원이 주로 수정할 곳

탐지 로직을 추가하거나 조정할 때는 보통 아래 파일을 수정한다.

```text
app/detection/traffic_stats.py
app/detection/port_scan.py
app/security/engine.py
app/packet/parser.py
```

백엔드 전송 payload를 바꿔야 한다면 아래 파일과 백엔드 스키마를 함께 확인한다.

```text
app/packet/summary.py
app/detection/traffic_stats.py
app/security/backend_contract.py
app/backend_client.py
../backend/app/schemas/analyzer.py
```
