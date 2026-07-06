# SDN Analyzer

분석 서버는 네트워크 인터페이스에서 패킷을 캡처하고, 짧은 시간 윈도우 단위로 패킷 요약, 트래픽 상태 요약, 보안 이벤트를 만들어 백엔드 서버로 전송한다. 컨트롤러에 직접 flow rule을 설치하지 않고, 탐지 결과와 상태만 백엔드에 전달한다.

## 실행 흐름

```text
app/packet/capture.py
  -> app/packet/parser.py
  -> app/packet/summary.py
  -> app/detection/traffic_stats.py / app/detection/port_scan.py / app/detection/security_events.py
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
| `app/detection/security_events.py` | 포트 스캔/DDoS 탐지 결과를 공통 보안 이벤트 payload로 변환 |
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
| `BACKEND_BASE_URL` | `http://127.0.0.1:8000` | 백엔드 API 주소 |

Docker Compose 실행 시에는 루트 `.env` 또는 `.env.example`의 값을 사용한다.

## 백엔드 전송 API

| 메서드 | 경로 | 설명 |
|---|---|---|
| `POST` | `/api/analyzer/packet-summary` | 패킷 요약 전송 |
| `POST` | `/api/analyzer/detection-summary` | 트래픽 상태 요약 전송 |
| `POST` | `/api/security/events` | 보안 이벤트 전송 |
| `POST` | `/api/analyzer/status` | 분석 서버 상태 전송 |

요청/응답 필드 상세는 `analyzer-backend-api.md`를 기준으로 한다.

## 현재 탐지 범위

현재 구현된 탐지는 다음 두 가지다.

| 탐지 | 구현 위치 | 설명 |
|---|---|---|
| Port Scan | `app/detection/port_scan.py`, `app/detection/security_events.py` | 짧은 시간 안에 같은 대상의 여러 TCP 목적지 포트로 SYN 패킷을 보내면 탐지 |
| ICMP Flood | `app/detection/security_events.py` | ICMP pps가 기준 이상이면 탐지 |

탐지 기준값과 탐지 이벤트 상세 필드는 보안/탐지 담당자와 합의 후 변경한다. `PORT_SCAN`, `ICMP_FLOOD`의 탐지 조건과 대응 레벨 정책은 `../SECURITY_DETECTION_POLICY.md`를 기준으로 한다.

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
app/detection/port_scan.py
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
