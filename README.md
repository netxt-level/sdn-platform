# SDN Platform

SDN Platform은 네트워크 트래픽을 수집, 분석하고 대시보드에서 실시간으로 확인하기 위한 통합 플랫폼이다. 현재 구현은 분석 서버, 백엔드 API 서버, 프론트엔드 대시보드, PostgreSQL, InfluxDB, Elasticsearch를 Docker Compose로 함께 실행하는 구조다.

## 현재 진행 요약

| 영역 | 경로 | 진행 상태 |
|---|---|---|
| 분석 서버 | `analyzer/` | 패킷 캡처, 패킷 요약, DoS/Port Scan 의심 탐지, 백엔드 전송 구현 |
| 백엔드 서버 | `backend/` | 분석 데이터 수신, DB 저장, 조회 API, WebSocket broadcast 구현 |
| 프론트엔드 | `frontend/` | 실시간 대시보드와 운영 화면 구현 |

## 전체 구조

```text
패킷 캡처
  -> analyzer
  -> backend API
  -> PostgreSQL / InfluxDB / Elasticsearch
  -> WebSocket / REST API
  -> frontend dashboard
```

### 주요 서비스

| 서비스 | 기본 포트 | 역할 |
|---|---:|---|
| Frontend | `3000` | Next.js 대시보드 |
| Backend | `8000` | FastAPI API 서버 |
| PostgreSQL | `5433` -> `5432` | 분석 서버 상태 저장 |
| InfluxDB | `8086` | 트래픽 시계열/탐지 지표 저장 |
| Elasticsearch | `9200`, `9300` | 보안 이벤트 저장 |

## 기술 스택

### Analyzer

- Python
- Scapy
- requests

### Backend

- Python
- FastAPI
- SQLAlchemy
- psycopg
- InfluxDB Client
- Elasticsearch Python Client
- Alembic

### Frontend

- Next.js 15
- React 19
- TypeScript
- Tailwind CSS
- Recharts
- lucide-react

### Infrastructure

- Docker Compose

## 구현된 기능

보안 탐지 항목과 대응 레벨 정책은 `SECURITY_DETECTION_POLICY.md`를 기준으로 한다.

### 분석 서버

- 지정 네트워크 인터페이스에서 패킷 캡처
- IP, 포트, 프로토콜, 패킷 크기, TCP flag 등 메타데이터 파싱
- `ANALYZER_WINDOW_SEC` 단위 패킷 요약 생성
- 프로토콜별 패킷 수 집계
- 출발지/목적지/프로토콜별 host traffic 집계
- 전체 패킷 수와 전체 bit 수 계산
- bps/pps 기반 DoS 의심 호스트 탐지
- TCP SYN 패턴 기반 Port Scan 의심 탐지
- 분석 서버 상태 주기적 보고
- 백엔드 전송 실패, timeout, HTTP 오류 처리
- 분석 루프/상태 전송 루프 예외 발생 시 오류 상태 기록 후 루프 유지

### 백엔드 서버

- 분석 서버 상태 수신 및 PostgreSQL upsert
- 패킷 요약 수신 및 InfluxDB 저장
- 트래픽 상태 요약 수신 및 InfluxDB 저장
- 보안 이벤트 수신 및 Elasticsearch 저장
- 대시보드 조회 API 제공
- 보안 이벤트 조회 API 제공
- Flow 목록 조회 API 제공
- WebSocket으로 분석 이벤트 실시간 broadcast

### 프론트엔드

- 분석 서버 상태 표시
- 전체 패킷, BPS, 의심 호스트 수 등 주요 지표 표시
- 최근 5분 트래픽 시계열 차트
- 최근 1분 프로토콜 통계 표시
- 의심 호스트 목록 표시
- DoS/Port Scan 유형별 필터링
- WebSocket 실시간 수신
- 백엔드 히스토리 API 초기 조회
- DB 의심 호스트 polling 및 실시간 데이터 병합

## 화면 구성

| 화면 | 경로 | 상태 |
|---|---|---|
| 대시보드 | `/` | 구현됨 |
| Flow Rules | `/flow-rules` | 구현중 |
| Path | `/path` | 구현중 |
| Security Events | `/security/events` | 구현중 |
| Security Rules | `/security/rules` | 구현중 |
| Topology | `/topology` | 구현중 |
| Settings | `/settings` | 구현중 |

## API 요약

### Backend HTTP API

| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/health` | 백엔드 상태 확인 |
| `GET` | `/api/analyzer/status` | 분석 서버 상태 조회 |
| `POST` | `/api/analyzer/status` | 분석 서버 상태 수신 |
| `POST` | `/api/analyzer/packet-summary` | 패킷 요약 수신 |
| `POST` | `/api/analyzer/detection-summary` | 트래픽 상태 요약 수신 |
| `GET` | `/api/dashboard/summary` | 대시보드 요약 조회 |
| `GET` | `/api/dashboard/traffic` | 트래픽 시계열 조회 |
| `GET` | `/api/dashboard/protocols` | 프로토콜 통계 조회 |
| `GET` | `/api/dashboard/suspicious-hosts` | 의심 호스트 조회 |
| `GET` | `/api/flows` | Flow 목록 조회 |
| `GET` | `/api/security/events` | 보안 이벤트 조회 |

### WebSocket

| 경로 | 설명 |
|---|---|
| `/ws/analyzer` | 분석 서버 상태, 패킷 요약, 탐지 요약 실시간 broadcast |

현재 백엔드가 직접 broadcast하는 메시지 타입은 다음과 같다.

| 타입 | 발생 시점 |
|---|---|
| `analyzer_status` | 분석 서버 상태 수신 후 |
| `packet_summary` | 패킷 요약 수신 후 |
| `detection_summary` | 탐지 요약 수신 후 |

상세 API 명세는 아래 문서를 참고한다.

- `backend/backend-api.md`
- `analyzer/analyzer-backend-api.md`

## 실행 방법

### 1. 환경변수 준비

```bash
cp .env.example .env
```

기본값은 Docker Compose 실행 기준으로 작성되어 있다. 분석 서버가 캡처할 인터페이스는 환경에 맞게 수정해야 한다.

```env
ANALYZER_INTERFACE=eth0
```

로컬 macOS에서 직접 분석 서버를 실행하는 경우에는 보통 `en0` 같은 인터페이스를 사용한다.

### 2. 전체 서비스 실행

```bash
docker compose up --build
```

실행 후 주요 접속 URL은 다음과 같다.

| 항목 | URL |
|---|---|
| 프론트엔드 | `http://localhost:3000` |
| 백엔드 API | `http://localhost:8000` |
| FastAPI Docs | `http://localhost:8000/docs` |
| InfluxDB | `http://localhost:8086` |
| Elasticsearch | `http://localhost:9200` |

### 3. 백엔드 상태 확인

```bash
curl http://localhost:8000/health
```

정상 응답:

```json
{
  "status": "ok"
}
```

### 4. 서비스 종료

```bash
docker compose down
```

볼륨까지 삭제하려면 다음 명령을 사용한다.

```bash
docker compose down -v
```

## 환경변수

주요 환경변수는 `.env.example`에 정의되어 있다.

| 이름 | 기본값 | 설명 |
|---|---|---|
| `POSTGRES_DB` | `sdn_platform` | PostgreSQL DB 이름 |
| `POSTGRES_USER` | `sdn_user` | PostgreSQL 사용자 |
| `POSTGRES_PASSWORD` | `sdn_password` | PostgreSQL 비밀번호 |
| `POSTGRES_HOST_PORT` | `5433` | 호스트에서 접근할 PostgreSQL 포트 |
| `INFLUXDB_ORG` | `sdn_org` | InfluxDB organization |
| `INFLUXDB_BUCKET` | `sdn_metrics` | InfluxDB bucket |
| `INFLUXDB_TOKEN` | `influx_id_token` | InfluxDB admin token |
| `ELASTICSEARCH_HTTP_PORT` | `9200` | Elasticsearch HTTP 포트 |
| `ANALYZER_ID` | `analyzer-1` | 분석 서버 ID |
| `ANALYZER_INTERFACE` | `eth0` | 패킷 캡처 인터페이스 |
| `ANALYZER_WINDOW_SEC` | `1` | 패킷/탐지 요약 생성 주기 |
| `ANALYZER_STATUS_INTERVAL_SEC` | `5` | 분석 서버 상태 전송 주기 |
| `PORT_SCAN_WINDOW_SEC` | `5` | Port Scan SYN 집계 윈도우 |
| `PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD` | `20` | Port Scan 고유 목적지 포트 임계값 |
| `PORT_SCAN_SYN_COUNT_THRESHOLD` | `20` | Port Scan SYN 시도 수 보조 조건 기준 |
| `PORT_SCAN_MULTI_TARGET_WINDOW_SEC` | `30` | Port Scan 다중 목적지 판단 윈도우 |
| `PORT_SCAN_MULTI_TARGET_THRESHOLD` | `3` | Port Scan 다중 목적지 개수 기준 |
| `PORT_SCAN_HIGH_UNIQUE_DST_PORT_THRESHOLD` | `50` | Port Scan 높은 고유 포트 수 기준 |
| `PORT_SCAN_ALERT_COOLDOWN_SEC` | `60` | Port Scan 중복 알림 억제 시간 |
| `ICMP_PPS_THRESHOLD` | `1000` | ICMP Flood pps 임계값 |
| `ICMP_MIN_PACKET_COUNT` | `1000` | ICMP Flood 최소 패킷 수 기준 |
| `ICMP_HIGH_PPS_THRESHOLD` | `3000` | ICMP Flood high pps 기준 |
| `ICMP_HIGH_PPS_MULTIPLIER` | `3.0` | ICMP Flood high pps 배수 기준 |
| `ICMP_BASELINE_SPIKE_MULTIPLIER` | `5.0` | ICMP baseline 급증 배수 기준 |
| `ICMP_BASELINE_MIN_PPS` | `100` | ICMP baseline 급증 최소 pps 기준 |
| `ICMP_ALERT_COOLDOWN_SEC` | `60` | ICMP Flood 중복 알림 억제 시간 |
| `RATE_LIMIT_PRIORITY` | `500` | Rate limit 후보 flow rule 우선순위 |
| `RATE_LIMIT_IDLE_TIMEOUT` | `60` | Rate limit 후보 idle timeout |
| `RATE_LIMIT_HARD_TIMEOUT` | `300` | Rate limit 후보 hard timeout |
| `RATE_LIMIT_PPS` | `100` | Rate limit 후보 제한 pps |
| `BACKEND_BASE_URL` | `http://backend:8000` | 분석 서버가 호출할 백엔드 주소 |
| `FRONTEND_PORT` | `3000` | 프론트엔드 호스트 포트 |
| `FRONTEND_BACKEND_INTERNAL_URL` | `http://backend:8000` | Next.js rewrite가 사용할 내부 백엔드 주소 |
| `NEXT_PUBLIC_WS_URL` | `ws://localhost:8000/ws/analyzer` | 브라우저 WebSocket 주소 |

## 데이터 저장 구조

| 저장소 | 저장 내용 |
|---|---|
| PostgreSQL | 분석 서버 최신 상태, `sdn_controller.analyzer` |
| InfluxDB | 트래픽 시계열, 프로토콜 통계, 포트 포함 host traffic, 네트워크 상태 |
| Elasticsearch | 보안 이벤트 문서, `sdn-security-events` |

Alembic migration은 `migrations/`에 있다.

| 파일 | 내용 |
|---|---|
| `migrations/versions/001_init_schema.py` | `sdn_controller` schema 및 `updated_at` trigger 함수 생성 |
| `migrations/versions/002_create_sdn_tables.py` | `sdn_controller.analyzer` 테이블 생성 |

## 현재 제한 사항

- `/api/dashboard/summary`는 현재 고정 mock 값을 반환한다.
- `/api/flows`는 현재 sample 값을 반환하며 `src_ip` query parameter를 실제 필터링에 사용하지 않는다.
- 일부 프론트엔드 화면은 mock/static 데이터 기반 UI를 포함한다.
- `backend/tests/` 디렉터리는 있으나 실제 테스트 코드는 아직 작성되어 있지 않다.
- 프론트엔드 타입에는 과거 호환용 WebSocket 메시지 타입이 일부 남아 있다.
- 패킷 캡처는 OS/컨테이너 권한과 네트워크 인터페이스 설정에 영향을 받는다.

## 성능 확인 및 테스트 다음 단계

성능 테스트는 다음 순서로 진행하는 것이 좋다.

1. 백엔드 API별 기본 응답 시간 확인
2. `k6`, `JMeter`, `Locust` 중 하나로 부하 테스트 스크립트 작성
3. `/api/analyzer/packet-summary`, `/api/analyzer/detection-summary`, `/api/dashboard/traffic`, `/api/security/events`를 우선 테스트
4. 동시 사용자 수 또는 요청량을 단계적으로 증가
5. CPU, 메모리, DB connection, InfluxDB query latency, Elasticsearch search latency 확인
6. 30분 이상 장시간 테스트로 메모리 증가 여부 확인
7. 병목 API를 기준으로 쿼리, 저장 로직, WebSocket broadcast, 프론트 렌더링을 분리해 점검

우선 수집하면 좋은 지표는 다음과 같다.

| 지표 | 설명 |
|---|---|
| 평균 응답 시간 | 일반적인 요청 처리 속도 |
| p95/p99 응답 시간 | 느린 요청의 꼬리 지연 |
| RPS | 초당 처리 요청 수 |
| 에러율 | 4xx/5xx, timeout 비율 |
| CPU/Memory | 서버 자원 사용량 |
| DB connection | PostgreSQL/InfluxDB/Elasticsearch 연결 상태 |
| WebSocket client 수 | 실시간 broadcast 부하 기준 |

## 주요 문서

- `IMPLEMENTATION_STATUS.md`: 현재 구현 상태 상세 정리
- `backend/backend-api.md`: 백엔드 HTTP/WebSocket API 명세
- `analyzer/README.md`: 분석 서버 구현 및 운영 메모
- `analyzer/analyzer-backend-api.md`: 분석 서버와 백엔드 사이의 API 계약
- `migrations/README`: Alembic migration 안내

## 커밋 전 체크

- `__pycache__/`, `.DS_Store`, `.next/`, `node_modules/` 같은 생성 파일은 커밋하지 않는다.
- 분석 서버 payload를 수정하면 백엔드 Pydantic schema와 API 문서를 함께 확인한다.
- 백엔드 broadcast 메시지를 수정하면 프론트엔드 `types/realtime.ts`, `hooks/useRealtime.ts`를 함께 확인한다.
- DB 구조를 수정하면 Alembic migration을 추가한다.
