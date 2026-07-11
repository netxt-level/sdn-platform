# SDN Platform

SDN Platform은 네트워크 트래픽을 수집, 분석하고 대시보드에서 실시간으로 확인하기 위한 통합 플랫폼이다. 현재 구현은 분석 서버, 백엔드 API 서버, 프론트엔드 대시보드, PostgreSQL, InfluxDB, Elasticsearch를 Docker Compose로 함께 실행하는 구조다.

## 현재 진행 요약

| 영역 | 경로 | 진행 상태 |
|---|---|---|
| 분석 서버 | `analyzer/` | 패킷 캡처, 패킷 요약, ICMP/UDP/SYN Flood와 Port Scan 탐지, 백엔드 전송 구현 |
| 백엔드 서버 | `backend/` | 분석 데이터 수신, DB 저장, 조회/생성 API, WebSocket broadcast 구현 |
| 프론트엔드 | `frontend/` | 실시간 대시보드와 보안 이벤트/경로/Flow Rule 운영 화면 구현 |

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

보안 탐지 항목과 대응 레벨 정책은 `analyzer/README_SECURITY_DETECTION.md`를 기준으로 한다.

### 분석 서버

- 지정 네트워크 인터페이스에서 패킷 캡처
- IP, 포트, 프로토콜, 패킷 크기, TCP flag 등 메타데이터 파싱
- `ANALYZER_WINDOW_SEC` 단위 패킷 요약 생성
- 프로토콜별 패킷 수 집계
- 출발지/목적지/프로토콜별 host traffic 집계
- 전체 패킷 수와 전체 bit 수 계산
- ICMP pps 기반 ICMP Flood 탐지
- UDP pps/bps 기반 UDP Flood 탐지. 목적지 포트별 기준과 출발지-목적지 합산 기준을 함께 사용
- 단일/다중 서비스 SYN Flood 탐지
- TCP SYN 패턴 기반 Port Scan 의심 탐지
- 분석 서버 상태 주기적 보고
- 백엔드 전송 실패, timeout, HTTP 오류 처리
- 분석 루프와 백엔드 전송 루프 분리
- 분석 지연 시 패킷 버퍼 최대 크기 제한과 초과 로그 처리
- 분석 루프/상태 전송 루프 예외 발생 시 오류 상태 기록 후 루프 유지

### 백엔드 서버

- 분석 서버 상태 수신 및 PostgreSQL upsert
- 패킷 요약 수신 및 InfluxDB 저장
- 트래픽 상태 요약 수신 및 InfluxDB 저장
- 보안 이벤트 수신 및 Elasticsearch bulk 저장
- 대시보드 조회 API 제공
- 보안 이벤트 조회 API 제공
- 보안 이벤트와 수동 Flow Rule 입력 검증
- Flow 목록 조회 및 수동 Flow Rule 생성 API 제공
- 경로 제어 상태 조회 API 제공
- 보안 대응 내역과 flow rule 후보를 PostgreSQL에 저장
- WebSocket으로 분석 이벤트 실시간 병렬 broadcast

### 프론트엔드

- 분석 서버 상태 표시
- 전체 패킷, BPS, 의심 호스트 수 등 주요 지표 표시
- 최근 5분 트래픽 시계열 차트
- 최근 1분 프로토콜 통계 표시
- 의심 호스트 목록 표시
- ICMP Flood/Port Scan 유형별 필터링
- WebSocket 실시간 수신
- 백엔드 히스토리 API 초기 조회
- DB 의심 호스트 polling 및 실시간 데이터 병합
- 보안 이벤트 목록/상세 화면을 실제 보안 이벤트 API에 연결
- 처리 완료/긴급 처리 필터와 미처리 high 이상 이벤트 알림 표시
- 경로 제어 화면을 백엔드 경로 상태 API에 연결
- Flow Rule 화면을 실제 조회/수동 생성 API에 연결

## 화면 구성

| 화면 | 경로 | 상태 |
|---|---|---|
| 대시보드 | `/` | 구현됨 |
| Flow Rules | `/flow-rules` | 구현됨 |
| Path | `/path` | 구현됨 |
| Security Events | `/security/events` | 구현됨 |
| Topology | `/topology` | 구현중 |
| Settings | `/settings` | 구현중 |

## API 요약

### Backend HTTP API

| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/health` | 백엔드 상태 확인 |
| `GET` | `/health/live` | 백엔드 프로세스 생존 확인 |
| `GET` | `/health/ready` | PostgreSQL, InfluxDB, Elasticsearch 준비 상태 확인 |
| `GET` | `/api/analyzer/status` | 분석 서버 상태 조회 |
| `POST` | `/api/analyzer/status` | 분석 서버 상태 수신 |
| `POST` | `/api/analyzer/packet-summary` | 패킷 요약 수신 |
| `POST` | `/api/analyzer/detection-summary` | 트래픽 상태 요약 수신 |
| `GET` | `/api/dashboard/summary` | 대시보드 요약 조회 |
| `GET` | `/api/dashboard/traffic` | 트래픽 시계열 조회 |
| `GET` | `/api/dashboard/protocols` | 프로토콜 통계 조회 |
| `GET` | `/api/dashboard/suspicious-hosts` | 의심 호스트 조회 |
| `GET` | `/api/flows` | Flow 목록 조회 |
| `POST` | `/api/flows` | 수동 Flow Rule 생성 |
| `GET` | `/api/path/status` | 경로 제어 상태 조회 |
| `GET` | `/api/security/events` | 보안 이벤트 조회 |
| `GET` | `/api/security/responses` | 보안 대응 내역 조회 |

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
| `security_events` | 보안 이벤트 수신 후 |

상세 API 명세는 아래 문서를 참고한다.

- `backend/backend-api.md`
- `analyzer/analyzer-backend-api.md`

## 실행 방법

### 1. 환경변수 준비

```bash
cp .env.example .env
```

기본값은 Docker Compose 실행 기준으로 작성되어 있다. 분석 서버가 캡처할 인터페이스는 환경에 맞게 수정해야 한다.
개인 `.env`에는 실제 비밀번호나 토큰이 들어갈 수 있으므로 Git이나 ZIP 결과물에 포함하지 않는다.

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
curl http://localhost:8000/health/ready
```

정상 응답:

```json
{
  "status": "ok"
}
```

저장소 중 일부가 준비되지 않으면 `/health/ready`는 `503`과 함께 `degraded` 상태를 반환한다.

### 4. 서비스 종료

```bash
docker compose down
```

볼륨까지 삭제하려면 다음 명령을 사용한다.

```bash
docker compose down -v
```

## 패킷 미러링 확인

Analyzer는 자신이 캡처하는 인터페이스로 들어온 패킷만 볼 수 있다. Docker 권한에 `NET_RAW`, `NET_ADMIN`이 있어도 Mininet이나 OVS 스위치의 트래픽이 자동으로 Analyzer 컨테이너에 들어오지는 않는다.

SDN 공격 시나리오를 시연할 때는 다음 중 하나로 트래픽을 Analyzer가 보는 인터페이스에 전달해야 한다.

- OVS Port Mirroring
- SPAN 또는 TAP 구조
- host network
- veth 연결
- 보안 분석 전용 미러링 포트

OVS 미러링을 쓰는 경우에는 다음 순서로 확인한다.

```bash
ovs-vsctl list-br
ovs-vsctl list-ports <bridge>
ovs-vsctl list interface
```

미러 출력 포트를 정한 뒤 Analyzer의 `ANALYZER_INTERFACE`를 해당 인터페이스 이름으로 맞춘다. 시연 전에는 다음처럼 실제 패킷이 보이는지 먼저 확인한다.

```bash
tcpdump -i <analyzer-interface> -n icmp
```

공격 트래픽을 발생시켰는데 `tcpdump`에 패킷이 보이지 않으면 탐지 코드 문제가 아니라 미러링 또는 인터페이스 연결 문제일 가능성이 높다.

## 환경변수

주요 환경변수는 `.env.example`에 정의되어 있다.

| 이름 | 기본값 | 설명 |
|---|---|---|
| `POSTGRES_DB` | `sdn_platform` | PostgreSQL DB 이름 |
| `POSTGRES_USER` | `sdn_user` | PostgreSQL 사용자 |
| `POSTGRES_PASSWORD` | `change_me_postgres_password` | PostgreSQL 예시 비밀번호. 실제 값은 개인 `.env`에서 변경 |
| `POSTGRES_HOST_PORT` | `5433` | 호스트에서 접근할 PostgreSQL 포트 |
| `INFLUXDB_ORG` | `sdn_org` | InfluxDB organization |
| `INFLUXDB_BUCKET` | `sdn_metrics` | InfluxDB bucket |
| `INFLUXDB_TOKEN` | `change_me_influx_token` | InfluxDB 예시 admin token. 실제 값은 개인 `.env`에서 변경 |
| `ELASTICSEARCH_HTTP_PORT` | `9200` | Elasticsearch HTTP 포트 |
| `ANALYZER_ID` | `analyzer-1` | 분석 서버 ID |
| `ANALYZER_INTERFACE` | `eth0` | 패킷 캡처 인터페이스 |
| `ANALYZER_WINDOW_SEC` | `1` | 패킷/탐지 요약 생성 주기 |
| `ANALYZER_STATUS_INTERVAL_SEC` | `5` | 분석 서버 상태 전송 주기 |
| `ANALYZER_PACKET_BUFFER_MAX_SIZE` | `100000` | 분석 지연 시 메모리에 보관할 최대 패킷 수 |
| `PORT_SCAN_WINDOW_SEC` | `5` | Port Scan SYN 집계 윈도우 |
| `PORT_SCAN_UNIQUE_DST_PORT_THRESHOLD` | `15` | Port Scan 고유 목적지 포트 임계값 |
| `PORT_SCAN_SYN_COUNT_THRESHOLD` | `30` | Port Scan SYN 시도 수 보조 조건 기준 |
| `PORT_SCAN_MULTI_TARGET_WINDOW_SEC` | `30` | Port Scan 다중 목적지 판단 윈도우 |
| `PORT_SCAN_HORIZONTAL_TARGET_THRESHOLD` | `3` | Port Scan 수평 스캔 목적지 수 기준 |
| `SECURITY_TRUSTED_SOURCE_IPS` | `` | 관리 호스트 IPv4 목록. 쉼표로 여러 개 입력하며 수평 Port Scan 기준만 완화 |
| `TRUSTED_HORIZONTAL_SCAN_THRESHOLD` | `10` | 관리 호스트의 수평 Port Scan 목적지 수 기준. 작은 토폴로지에서는 반복 SYN 기준도 함께 적용 |
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
| `SECURITY_EVENT_QUEUE_MAX_SIZE` | `500` | 백엔드 전송 실패 시 보안 이벤트를 보관할 최대 개수 |
| `SECURITY_EVENT_SEND_BATCH_SIZE` | `100` | 대기 중인 보안 이벤트를 한 번에 재전송할 개수 |
| `BACKEND_BASE_URL` | `http://backend:8000` | 분석 서버가 호출할 백엔드 주소 |
| `FRONTEND_PORT` | `3000` | 프론트엔드 호스트 포트 |
| `FRONTEND_BACKEND_INTERNAL_URL` | `http://backend:8000` | Next.js rewrite가 사용할 내부 백엔드 주소 |
| `NEXT_PUBLIC_WS_URL` | `ws://localhost:8000/ws/analyzer` | 브라우저 WebSocket 주소 |

## 데이터 저장 구조

| 저장소 | 저장 내용 |
|---|---|
| PostgreSQL | 분석 서버 최신 상태, 보안 대응 내역, flow rule 적용 상태, `sdn_controller.analyzer`, `sdn_controller.security_responses`, `sdn_controller.flow_rules` |
| InfluxDB | 트래픽 시계열, 프로토콜 통계, 상위 host traffic, 네트워크 상태 |
| Elasticsearch | 보안 이벤트 문서, `sdn-security-events` |

Alembic migration은 `migrations/`에 있다.

| 파일 | 내용 |
|---|---|
| `migrations/versions/001_init_schema.py` | `sdn_controller` schema 및 `updated_at` trigger 함수 생성 |
| `migrations/versions/002_create_sdn_tables.py` | `sdn_controller.analyzer` 테이블 생성 |
| `migrations/versions/003_create_flow_rules.py` | `sdn_controller.flow_rules` 테이블 생성 |
| `migrations/versions/004_create_security_responses.py` | `sdn_controller.security_responses` 테이블 생성 및 flow rule 연결 컬럼 추가 |
| `migrations/versions/005_add_analyzer_runtime_metrics.py` | Analyzer 런타임 큐/드롭 메트릭 컬럼 추가 |

## 현재 제한 사항

- `/api/dashboard/summary`는 InfluxDB 최근 5분 트래픽 시계열을 기반으로 요약 지표를 계산한다.
- `/api/security/events`는 `event_id`를 Elasticsearch 문서 ID로 사용해 보안 이벤트를 저장하고, PostgreSQL에 보안 대응 내역과 flow rule 후보를 생성한다.
- `/api/flows`는 `sdn_controller.flow_rules` 조회와 수동 생성 기능을 제공한다. 생성된 rule은 현재 `PENDING` 상태로 DB에 저장되며 컨트롤러에 실제 설치되지는 않는다.
- 보안 이벤트와 Flow Rule 입력은 현재 구현 범위에 맞게 IPv4, 허용 프로토콜, 허용 action, OpenFlow match 필드를 검증한다.
- Analyzer 상태에는 보안 이벤트 대기열 수, 드롭된 이벤트 수, 패킷 버퍼 드롭 수, 마지막 보안 이벤트 전송 실패 시각을 함께 저장한다.
- host traffic은 `src_port`와 `dst_port`를 집계 키에서 제외하고 출발지/목적지/프로토콜 단위로 합산한다. InfluxDB에서는 대표 포트를 tag가 아니라 field로 저장한다.
- `/api/path/status`는 대시보드 요약과 flow rule DB를 조합해 경로 제어 화면 데이터를 제공한다.
- 일부 프론트엔드 화면은 아직 mock/static 데이터 기반 UI를 포함한다.
- 프론트엔드 타입에는 과거 호환용 WebSocket 메시지 타입이 일부 남아 있다.
- 패킷 캡처는 OS/컨테이너 권한과 네트워크 인터페이스 설정에 영향을 받는다.

## 테스트

Analyzer 보안 탐지 명세 단위 테스트는 표준 라이브러리 `unittest`로 실행한다.

```bash
PYTHONPYCACHEPREFIX=/private/tmp/sdn-platform-pycache python3 -m unittest discover -s analyzer/tests -v
```

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
- `.env`처럼 실제 비밀번호나 토큰이 들어갈 수 있는 파일은 커밋하거나 ZIP에 포함하지 않는다.
- 분석 서버 payload를 수정하면 백엔드 Pydantic schema와 API 문서를 함께 확인한다.
- 백엔드 broadcast 메시지를 수정하면 프론트엔드 `types/realtime.ts`, `hooks/useRealtime.ts`를 함께 확인한다.
- DB 구조를 수정하면 Alembic migration을 추가한다.
