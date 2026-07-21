# SDN Platform 현재 진행 및 구현 사항

이 문서는 현재 코드 기준으로 분석 서버, 백엔드 서버, 프론트엔드 서버의 구현 상태를 정리한다.

## 전체 구성

| 영역 | 경로 | 역할 |
|---|---|---|
| 분석 서버 | `analyzer/` | 패킷 캡처, 패킷 요약 생성, 이상 트래픽 탐지, 백엔드 전송 |
| 백엔드 서버 | `backend/` | 분석 서버 데이터 수신, DB 저장, 조회 API, WebSocket broadcast |
| 프론트엔드 서버 | `frontend/` | 실시간 대시보드, 트래픽/보안/토폴로지 화면 |
| DB/인프라 | `docker-compose.yml`, `migrations/` | PostgreSQL, InfluxDB, Elasticsearch, Alembic migration |

## 분석 서버

### 진행 상태

분석 서버는 패킷 캡처부터 백엔드 전송까지 기본 흐름이 구현되어 있다. 현재 구현은 지정한 네트워크 인터페이스에서 패킷을 캡처하고, 일정 시간 단위로 패킷 요약과 탐지 요약을 만들어 백엔드 API로 전송한다.

### 주요 구현 파일

| 파일 | 구현 내용 |
|---|---|
| `analyzer/app/main.py` | 분석 서버 실행 진입점, 캡처 루프, 분석 루프, 상태 전송 루프 |
| `analyzer/app/config.py` | 환경변수 파싱 및 분석 서버 설정 생성 |
| `analyzer/app/packet/capture.py` | 네트워크 인터페이스 패킷 캡처 |
| `analyzer/app/packet/parser.py` | 캡처 패킷에서 IP, 포트, 프로토콜, 크기 등 메타데이터 추출 |
| `analyzer/app/packet/summary.py` | 윈도우 단위 패킷 요약 생성 |
| `analyzer/app/detection/traffic_stats.py` | 네트워크 상태, bps/pps, 의심 호스트 목록 생성 |
| `analyzer/app/detection/port_scan.py` | TCP SYN 기반 포트 스캔 의심 탐지 |
| `analyzer/app/analyzer_status.py` | 분석 서버 상태 관리 |
| `analyzer/app/backend_client.py` | 백엔드 API 전송 클라이언트 |
| `analyzer/analyzer-backend-api.md` | 분석 서버 -> 백엔드 API 명세 |

### 구현된 기능

- 네트워크 인터페이스 기반 패킷 캡처
- 패킷 메타데이터 파싱
- `ANALYZER_WINDOW_SEC` 단위 패킷 요약 생성
- 프로토콜별 패킷 수 집계
- 출발지/목적지/프로토콜별 host traffic 집계
- 전체 패킷 수, 전체 bit 수 계산
- ICMP pps 기준 ICMP Flood 탐지
- TCP SYN 패턴 기반 포트 스캔 의심 탐지
- 분석 서버 상태 생성 및 주기적 보고
- 분석 루프와 상태 전송 루프 예외 발생 시 오류 상태 기록 후 루프 유지
- 백엔드 연결 실패/timeout/HTTP 오류 처리
- 백엔드 API 전송

### 백엔드 전송 API

| 메서드 | 경로 | 설명 |
|---|---|---|
| `POST` | `/api/analyzer/packet-summary` | 패킷 요약 전송 |
| `POST` | `/api/analyzer/detection-summary` | 탐지 요약 전송 |
| `POST` | `/api/analyzer/status` | 분석 서버 상태 전송 |

### 환경변수

| 이름 | 기본값 | 설명 |
|---|---|---|
| `ANALYZER_ID` | `analyzer-1` | 분석 서버 ID |
| `ANALYZER_INTERFACE` | `en0` | 패킷 캡처 인터페이스 |
| `ANALYZER_WINDOW_SEC` | `1` | 패킷/탐지 요약 생성 주기 |
| `ANALYZER_STATUS_INTERVAL_SEC` | `5` | 상태 전송 주기 |
| `BACKEND_BASE_URL` | `http://127.0.0.1:8000` | 백엔드 서버 주소 |

### 현재 주의사항

- `total_bps`, `total_pps` 필드는 윈도우 내 누적 비트 수와 패킷 수를 `ANALYZER_WINDOW_SEC`로 나누어 초당 값으로 계산한다.
- `analyzer/app/detection/port_scan.py`는 `analyzer/app/main.py`에서 import하므로 커밋 시 반드시 함께 포함해야 한다.

## 백엔드 서버

### 진행 상태

백엔드 서버는 FastAPI 기반으로 구현되어 있으며, 분석 서버가 전송한 데이터를 수신해 PostgreSQL, InfluxDB, Elasticsearch에 저장한다. 또한 프론트엔드가 사용할 조회 API와 실시간 WebSocket broadcast 기능이 구현되어 있다.

### 주요 구현 파일

| 파일 | 구현 내용 |
|---|---|
| `backend/app/main.py` | FastAPI 앱 생성 및 라우터 등록 |
| `backend/app/api/analyzer.py` | 분석 서버 데이터 수신 API |
| `backend/app/api/dashboard.py` | 대시보드 조회 API |
| `backend/app/api/flows.py` | flow rule 목록 조회 및 수동 생성 API |
| `backend/app/api/path.py` | 경로 제어 상태 조회 API |
| `backend/app/api/security.py` | 보안 이벤트 조회 API |
| `backend/app/api/ws.py` | WebSocket 연결 및 broadcast 관리 |
| `backend/app/services/path_service.py` | 대시보드 요약과 flow rule DB 기반 경로 상태 구성 |
| `backend/app/schemas/analyzer.py` | 분석 서버 요청 body Pydantic 스키마 |
| `backend/app/db/postgres.py` | PostgreSQL 분석 서버 상태 저장/조회 |
| `backend/app/db/influxdb.py` | InfluxDB 트래픽/탐지 데이터 저장 및 조회 |
| `backend/app/db/elasticsearch.py` | Elasticsearch 인덱스 생성 및 이벤트 저장/조회 |
| `backend/backend-api.md` | 백엔드 HTTP/WebSocket API 명세 |

### 구현된 API

| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/health` | 백엔드 서버 상태 확인 |
| `GET` | `/api/analyzer/status` | 분석 서버 상태 조회 |
| `POST` | `/api/analyzer/status` | 분석 서버 상태 수신 |
| `POST` | `/api/analyzer/packet-summary` | 패킷 요약 수신 |
| `POST` | `/api/analyzer/detection-summary` | 탐지 요약 수신 |
| `GET` | `/api/dashboard/summary` | 최근 트래픽 기반 대시보드 요약 조회 |
| `GET` | `/api/dashboard/traffic` | InfluxDB 트래픽 시계열 조회 |
| `GET` | `/api/dashboard/protocols` | InfluxDB 프로토콜 통계 조회 |
| `GET` | `/api/dashboard/suspicious-hosts` | InfluxDB 의심 호스트 조회 |
| `GET` | `/api/flows` | PostgreSQL flow rule과 Controller topology/통계 통합 조회 |
| `POST` | `/api/flows` | 수동 flow rule 생성 |
| `DELETE` | `/api/flows/{id}` | Controller Flow Rule 제거 및 상태 저장 |
| `GET` | `/api/path/status` | 경로 제어 상태 조회 |
| `GET` | `/api/security/events` | Elasticsearch 탐지 이벤트 조회 |
| `GET` | `/api/security/responses` | PostgreSQL 보안 대응 내역 조회 |
| `WS` | `/ws/analyzer` | 실시간 분석 이벤트 broadcast |

### 저장소 연동

| 저장소 | 저장/조회 내용 |
|---|---|
| PostgreSQL | 분석 서버 최신 상태, 보안 대응 내역, flow rule 적용 상태, `sdn_controller.analyzer`, `sdn_controller.security_responses`, `sdn_controller.flow_rules` |
| InfluxDB | 트래픽 시계열, 프로토콜 통계, host traffic, 네트워크 상태, 의심 호스트 |
| Elasticsearch | 트래픽 요약 문서, 탐지 이벤트 문서 |

### WebSocket 메시지

현재 백엔드가 직접 broadcast하는 메시지 타입은 다음과 같다.

| 타입 | 발생 시점 |
|---|---|
| `analyzer_status` | 분석 서버 상태 수신 후 |
| `packet_summary` | 패킷 요약 수신 후 |
| `detection_summary` | 탐지 요약 수신 후 |

### 현재 주의사항

- `/api/dashboard/summary`는 InfluxDB 최근 5분 트래픽 시계열을 기반으로 총 패킷 수, 총 byte 수, 최신 pps/bps, 네트워크 상태를 계산한다.
- `/api/security/events`는 보안 이벤트를 Elasticsearch에 저장한다. `mitigation`이 있으면 PostgreSQL에 보안 대응 내역과 flow rule을 생성하고 Controller에 자동 적용한 뒤 두 레코드의 최종 상태를 저장한다.
- `/api/flows`는 DB 기반 flow rule 조회·생성·삭제를 제공한다. 생성과 삭제는 Controller Barrier 확인 결과에 따라 최종 상태와 Controller 응답이 저장된다.
- `/api/path/status`는 대시보드 요약과 flow rule DB를 조합해 기본/우회 경로 상태, 링크 사용률, 경로 변경 이력을 반환한다.
- InfluxDB duration query는 `5s`, `1m`, `2h`, `1d`, `1w` 같은 형식만 허용한다.
- `backend/app/scripts/seed_suspicious_hosts.py`는 의심 호스트 테스트 데이터를 넣기 위한 보조 스크립트다.

## 프론트엔드 서버

### 진행 상태

프론트엔드는 Next.js 기반으로 구현되어 있으며, 대시보드와 여러 운영 화면이 구성되어 있다. 실시간 WebSocket 데이터와 백엔드 조회 API를 함께 사용해 트래픽, 프로토콜, 분석 서버 상태, 의심 호스트 정보를 표시한다.

### 주요 구현 파일

| 파일 | 구현 내용 |
|---|---|
| `frontend/app/page.tsx` | 메인 대시보드 화면 |
| `frontend/hooks/useRealtime.ts` | WebSocket 연결, 히스토리 조회, 실시간 상태 관리 |
| `frontend/components/dashboard/TrafficTrend.tsx` | 트래픽 시계열 차트 |
| `frontend/components/dashboard/ProtocolBars.tsx` | 프로토콜별 비율/패킷 수 표시 |
| `frontend/components/dashboard/AnalyzerStatusPanel.tsx` | 분석 서버 상태 표시 |
| `frontend/components/dashboard/MetricCard.tsx` | 대시보드 지표 카드 |
| `frontend/app/security/events/page.tsx` | 보안 이벤트 화면 |
| `frontend/app/topology/page.tsx` | 토폴로지 화면 |
| `frontend/app/path/page.tsx` | 경로 제어 화면, `/api/path/status` 연동 |
| `frontend/app/flow-rules/page.tsx` | 실제 연결 스위치와 OpenFlow 통계를 사용하는 Flow rule 조회/생성/삭제 화면 |
| `frontend/lib/flowApi.ts` | Flow Rule 조회/생성/삭제 API 클라이언트 |
| `frontend/types/flow.ts` | Flow Rule 및 Controller 상태 API 타입 |
| `frontend/app/settings/page.tsx` | 설정 화면 |
| `frontend/types/analyzer.ts` | 분석/탐지 관련 TypeScript 타입 |
| `frontend/types/realtime.ts` | 실시간 메시지 타입 |

### 구현된 화면

| 화면 | 경로 | 상태 |
|---|---|---|
| 대시보드 | `/` | 구현됨 |
| Flow Rules | `/flow-rules` | 구현됨 |
| Path | `/path` | 구현됨 |
| Security Events | `/security/events` | 구현됨 |
| Topology | `/topology` | 구현됨 |
| Settings | `/settings` | 구현됨 |

### 대시보드 구현 사항

- 분석 서버 상태 카드 표시
- 패킷 수, bps, 의심 호스트 수 등 주요 지표 표시
- 최근 5분 트래픽 시계열 표시
- 최근 1분 프로토콜 통계 표시
- 의심 호스트 목록 표시
- 의심 호스트 공격 유형별 필터링
- ICMP Flood/Port Scan 유형별 배지 스타일 적용
- WebSocket 실시간 데이터 수신
- 초기 로딩 시 백엔드 히스토리 API 조회
- DB 의심 호스트를 5초마다 polling
- 실시간 의심 호스트와 DB 의심 호스트 병합

### 백엔드 연동

| 연동 | 경로 |
|---|---|
| WebSocket | `ws://localhost:8000/ws/analyzer` 또는 `NEXT_PUBLIC_WS_URL` |
| 트래픽 히스토리 | `/api/dashboard/traffic?range=5m&bucket=5s` |
| 프로토콜 통계 | `/api/dashboard/protocols?range=1m` |
| 의심 호스트 | `/api/dashboard/suspicious-hosts?range=1w` |
| 보안 이벤트 | `/api/security/events?limit=100` |
| Flow Rule | `/api/flows` |
| 경로 제어 | `/api/path/status` |

Next.js rewrite 설정으로 프론트엔드의 `/api/:path*` 요청은 `${BACKEND_INTERNAL_URL}/api/:path*`로 전달된다.

### 현재 주의사항

- WebSocket URL은 `NEXT_PUBLIC_WS_URL`이 없으면 현재 브라우저 host 기준 `:8000/ws/analyzer`로 fallback된다.
- 프론트 타입에는 과거 호환용 `traffic_analysis`, `security_event`, `topology_update` 메시지가 남아 있지만, 현재 백엔드가 직접 broadcast하는 메시지는 `analyzer_status`, `packet_summary`, `detection_summary`, `security_events`다.
- `보안 규칙` 단독 페이지는 제거되었고, 보안 대응 흐름은 보안 이벤트, 경로 제어, Flow Rule 화면에서 관리한다.
- 수동 Flow Rule은 SDN Controller 설치와 삭제까지 수행한다. `DROP`, `OUTPUT:<port|인접 switch>`, OVS Meter 기반 `RATE_LIMIT`을 지원하며 삭제 시 `REMOVING -> REMOVED`를 저장한다. Backend 만료 상태 재조정은 추가 구현이 필요하다.
- Flow Rule 화면의 스위치와 `OUTPUT` 대상은 Controller topology에서 구성하고, cookie가 일치하는 OpenFlow packet/byte 통계를 5초마다 표시한다. Controller 장애 시 DB 이력과 명시적 연결 오류를 표시한다.

## 인프라 및 실행 구성

### Docker Compose

`docker-compose.yml` 기준으로 다음 서비스가 통합되어 있다.

- PostgreSQL
- InfluxDB
- Elasticsearch
- Backend
- Frontend

### Migration

Alembic migration은 `migrations/`에 구성되어 있다.

| 파일 | 내용 |
|---|---|
| `migrations/versions/001_init_schema.py` | `sdn_controller` schema 및 `updated_at` trigger 함수 생성 |
| `migrations/versions/002_create_sdn_tables.py` | `sdn_controller.analyzer` 테이블 생성 |
| `migrations/versions/003_create_flow_rules.py` | `sdn_controller.flow_rules` 테이블 생성 |
| `migrations/versions/004_create_security_responses.py` | `sdn_controller.security_responses` 테이블 생성 및 flow rule 연결 컬럼 추가 |

## 커밋 전 체크 사항

- 분석 서버 커밋에는 `analyzer/app/main.py`, `analyzer/app/detection/traffic_stats.py`, `analyzer/app/detection/port_scan.py`, `analyzer/analyzer-backend-api.md` 포함 여부를 확인한다.
- 백엔드 커밋에는 `backend/app/api/dashboard.py`, `backend/app/api/flows.py`, `backend/app/api/path.py`, `backend/app/services/path_service.py`, `backend/app/db/influxdb.py`, `backend/app/schemas/analyzer.py`, `backend/backend-api.md` 포함 여부를 확인한다.
- 프론트엔드 커밋에는 `frontend/app/page.tsx`, `frontend/app/security/events/page.tsx`, `frontend/app/path/page.tsx`, `frontend/app/flow-rules/page.tsx`, `frontend/hooks/useRealtime.ts`, `frontend/types/analyzer.ts` 포함 여부를 확인한다.
- `__pycache__/`, `.DS_Store` 같은 생성 파일은 커밋하지 않는 것이 좋다.
