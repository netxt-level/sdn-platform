# SDN Platform 구현 상태

이 문서는 현재 코드 기준으로 구현된 범위와 아직 남은 범위를 구분한다. 발표나 PR 설명에서는 이 문서를 기준으로 “구현됨”, “후보 생성까지만 구현됨”, “미구현”을 나누어 설명한다.

## 전체 구성

| 영역 | 경로 | 현재 상태 |
|---|---|---|
| 분석 서버 | `analyzer/` | 패킷 캡처, 패킷 요약, 보안 탐지, 보안 이벤트 생성, 백엔드 전송 구현 |
| 백엔드 서버 | `backend/` | 분석 데이터 수신, DB 저장, 조회 API, WebSocket broadcast 구현 |
| 프론트엔드 | `frontend/` | 대시보드, 보안 이벤트, 경로, Flow Rule 운영 화면 구현 |
| 인프라 | `docker-compose.yml`, `migrations/` | PostgreSQL, InfluxDB, Elasticsearch, Alembic migration 구성 |

## 완료

- ICMP Echo Request 기반 ICMP Flood 탐지
- UDP 목적지 포트별 Flood 탐지
- UDP 출발지-목적지 합산 Flood 탐지
- 단일/다중 서비스 SYN Flood 탐지
- TCP SYN 기반 수직/수평 Port Scan 탐지
- 관리 호스트 수평 Port Scan 기준 완화와 반복 SYN 보조 탐지
- 탐지 결과 점수화, 위험도 분류, 대응 후보 생성
- 보안 이벤트 중복 억제
- 보안 이벤트 전송 실패 시 메모리 대기 큐 저장
- 보안 이벤트 배치 재전송
- 400/413/422 응답 시 보안 이벤트 batch 크기 축소 재전송
- 패킷 버퍼 최대 크기 제한과 초과 로그
- IPv4 주소 검증
- 백엔드 보안 이벤트 저장 및 대응 후보 `PENDING` 저장
- Elasticsearch `event_id` 기반 upsert와 bulk 저장
- 보안 이벤트 API 입력 검증
- Analyzer API Key 기반 입력 API 보호
- 보안 이벤트 batch 크기, 주요 문자열 길이, evidence 크기 제한
- Analyzer POST 요청 본문 크기 제한
- 보안 이벤트 요청 `analyzer_id`와 이벤트별 `analyzer_id` 일치 검증
- 수동 Flow Rule API match/action 입력 검증
- 수동 Flow Rule 생성용 관리자 API Key 검증
- 프론트엔드 Flow Rule 수동 생성 비활성화
- Flow Rule 조회 기본 pagination
- Flow Rule 조회 전체 개수와 다음 페이지 여부 반환
- Flow Rule 재사용 시 `switch_id`, `match`, `target`, action 강도, `rate_limit_pps`, `priority`, timeout 비교
- 재사용된 Flow Rule과 새 보안 대응 이력 연결 정보 저장
- 의심 호스트 조회 `range`를 Elasticsearch 시간 조건에 반영
- 여러 Analyzer의 트래픽 시계열을 시간 bucket 기준으로 합산
- WebSocket 병렬 broadcast와 실패 연결 정리
- `/health/live`, `/health/ready` 분리
- Docker Compose 저장소 healthcheck와 backend readiness 연동
- Elasticsearch 보안 이벤트 인덱스 존재 여부 readiness 확인
- Elasticsearch evidence 세부 key 인덱싱 비활성화
- Frontend Docker production build와 build-time API/WebSocket 주소 주입
- Analyzer 분석 오류 발생 후 다음 정상 분석 시 상태 복구
- 대시보드용 통계 전송 큐를 작게 유지해 오래된 요약 누적 방지

## 부분 구현

| 항목 | 현재 범위 | 남은 범위 |
|---|---|---|
| Rate Limit | Analyzer가 `mitigation` 후보를 만들고 백엔드가 DB에 저장 | Controller/OVS Meter 실제 적용 |
| Drop | Analyzer가 `DROP` 후보를 만들고 백엔드가 DB에 저장 | Controller Flow Rule 실제 설치 |
| Self-Healing | 탐지와 대응 후보 생성까지 구현 | 적용 효과 확인, 정상 통신 확인, 자동 해제, 상태 머신 |
| 경로 우회 | 화면과 백엔드 조회 구조 일부 존재 | 실제 경로 재계산과 Controller 반영 |
| 보안 이벤트 상태 관리 | 이벤트 저장과 조회 | 처리 완료, 무시, 해결 상태 전환 정책 |
| 저장소 상태 관리 | readiness에서 연결 상태 확인 | 장애 원인 상세 로깅과 운영 알림 |
| 관리자 인증 | Analyzer 입력 API와 수동 Flow Rule 생성 API Key 검증, 프론트 수동 생성 차단 | 사용자 로그인, Viewer/Operator/Admin 역할 분리 |

## 미구현

- ARP Spoofing 탐지
- 목적지 전체 기준 분산 DDoS 탐지
- Low-and-Slow 장기 누적 탐지
- Baseline 기반 동적 임계값
- FIN/NULL/XMAS/UDP Scan 탐지
- Controller Flow Rule 실제 설치/삭제
- OVS Meter 기반 Rate Limit
- 대응 효과 검증
- Persistent Outbox
- 사용자 로그인 기반 관리자 권한 관리
- 조회 API와 WebSocket 인증

## 주요 환경변수

| 이름 | 기본값 | 설명 |
|---|---:|---|
| `ANALYZER_INTERFACE` | `eth0` | Docker Compose 기준 패킷 캡처 인터페이스 |
| `ANALYZER_WINDOW_SEC` | `1` | 패킷 요약과 탐지 실행 주기 |
| `ANALYZER_PACKET_BUFFER_MAX_SIZE` | `100000` | 분석 지연 시 메모리에 보관할 최대 패킷 수 |
| `PORT_SCAN_HORIZONTAL_TARGET_THRESHOLD` | `3` | 일반 호스트 수평 Port Scan 대상 수 기준 |
| `SECURITY_TRUSTED_SOURCE_IPS` | 없음 | 관리 호스트 IPv4 목록 |
| `TRUSTED_HORIZONTAL_SCAN_THRESHOLD` | `10` | 관리 호스트 수평 Port Scan 대상 수 기준 |
| `SECURITY_EVENT_QUEUE_MAX_SIZE` | `500` | 재전송 대기 보안 이벤트 최대 개수 |
| `SECURITY_EVENT_SEND_BATCH_SIZE` | `100` | 보안 이벤트 재전송 배치 크기 |

로컬 macOS에서 분석 서버를 직접 실행할 때는 `ANALYZER_INTERFACE=en0`처럼 실제 인터페이스에 맞게 바꿀 수 있다.

## 주의 사항

- `.env`는 실제 비밀번호와 토큰을 담을 수 있으므로 Git과 ZIP 결과물에 포함하지 않는다.
- `.env.example`은 실행 예시용 값만 유지하고 실제 운영 비밀번호를 넣지 않는다.
- `__pycache__`, `.pytest_cache`, `.DS_Store`, `*.pyc`는 결과물에 포함하지 않는다.
- 현재 Analyzer의 대응 후보는 IPv4 OpenFlow match 기준이므로 IPv6 주소는 보안 이벤트 변환에서 제외한다.
- 현재 Flood 탐지는 단일 출발지 기준이다. 여러 출발지가 동시에 한 목적지를 공격하는 분산 DDoS는 별도 집계가 필요하다.
- `change_me_*` 환경변수 값은 시연용 예시이므로 공유 서버나 운영 환경에서는 반드시 개인 `.env`에서 변경한다.
- Docker Compose는 주요 비밀번호와 API Key가 없으면 시작하지 않는다.
- 프론트엔드 Docker build에 들어가는 `FRONTEND_BACKEND_INTERNAL_URL`, `NEXT_PUBLIC_WS_URL`을 바꾸면 이미 빌드된 이미지에는 반영되지 않으므로 다시 빌드해야 한다.

## 검증 명령

```bash
python -m compileall -q analyzer/app analyzer/tests backend/app backend/tests
python -m pytest analyzer/tests backend/tests -q
npm --prefix frontend run lint
npm --prefix frontend run build
docker compose --env-file .env.example config --quiet
git diff --check
```

## 최근 검토 반영

- SYN Flood와 Port Scan 사이에 빠질 수 있던 6~14개 포트 SYN 집중 구간을 다중 서비스 SYN Flood 기준으로 보완했다.
- Port Scan 수평 스캔은 대상 IP 수와 최소 SYN 시도 수를 함께 확인하도록 조정했다.
- Port Scan 쿨다운 중에도 더 높은 점수나 위험도로 올라간 이벤트는 다시 알림으로 남기도록 수정했다.
- Flow Rule 입력 검증을 강화해 잘못된 OpenFlow match와 `RATE_LIMIT`/`DROP` 옵션 조합을 차단했다.
- 프론트엔드 보안 이벤트 표시에서 `DROP`, `RATE_LIMIT`, 포트 evidence, PPS 계산이 실제 이벤트 구조와 맞도록 정리했다.
- 실제 분석 스냅샷 간격을 `window_sec`로 사용해 백엔드 전송 지연 시 PPS가 과대 계산되는 문제를 줄였다.
- 패킷 요약 host 통계를 상위 50개로 제한하고, host 통계에서는 `src_port`와 `dst_port`를 제외했다.
- Port Scan과 다중 서비스 SYN Flood가 같은 흐름에서 동시에 잡히면 더 강한 SYN Flood 이벤트만 유지하고 Port Scan 근거는 관련 탐지로 묶도록 정리했다.
- Port Scan은 초 단위 버킷 집계로 바꿔 패킷 단위 이벤트가 계속 쌓이지 않게 했다.
- Analyzer 분석 루프와 백엔드 HTTP 전송 루프를 분리해 전송 지연이 분석 주기를 직접 막지 않도록 했다.
- UDP pair 전체 Flood와 서비스별 UDP Flood가 같은 흐름에서 중복 대응 후보를 만들지 않도록 상관분석을 추가했다.
- Security Response는 `event_id`별 이력으로 남기고, Flow Rule은 활성 상태의 동일 match만 재사용하도록 조정했다.
- Analyzer 입력 API에 선택형 API Key 검증을 추가하고, 보안 이벤트 batch, 주요 문자열 길이, evidence 크기를 제한했다.
- 보안 이벤트 요청의 analyzer ID와 이벤트 내부 analyzer ID가 다르면 거부하도록 검증을 추가했다.
- Analyzer POST API에 경로별 요청 본문 크기 제한을 추가했다.
- 백엔드 전송 순서를 보안 이벤트 우선으로 바꿨다.
- Frontend Docker는 개발 서버 대신 production build 후 `next start`로 실행한다.
- Frontend Docker build 시 백엔드 내부 주소와 WebSocket 주소를 build argument로 전달하도록 수정했다.
- 사용자 권한 검증 없는 관리자 proxy가 되지 않도록 프론트엔드 수동 Flow Rule 생성 POST를 차단했다.
- Analyzer 런타임 메트릭을 PostgreSQL에 저장하도록 모델, repository, migration을 추가했다.
- Analyzer 분석 루프 오류는 다음 정상 분석 후 복구되도록 하고, 백엔드 전송 성공이 분석 오류 메시지를 지우지 않게 분리했다.
- 10분이 지난 `PENDING`/`APPROVED` Flow Rule과 5분이 지난 `APPLYING` Flow Rule은 재사용하지 않도록 정책을 추가했다.
- 오래된 `PENDING` Flow Rule은 Path 화면의 우회 경로 판단에서도 제외했다.
- Flow Rule 조회에 기본 `limit=100`, 최대 `limit=500` pagination과 `total`, `has_more` 응답을 추가했다.
- Flow Rule 재사용은 같은 fingerprint만 보지 않고 실제 `switch_id`, `match`, `target`, action 강도, `rate_limit_pps`, `priority`, `idle_timeout`, `hard_timeout`을 함께 비교하도록 보강했다. `APPLIED`인데 `applied_at`이 없거나 남은 `hard_timeout`이 부족한 규칙은 재사용하지 않는다.
- 재사용된 Flow Rule도 새 보안 대응 이력의 `response_payload`에서 추적할 수 있도록 연결 정보를 남겼다.
- 의심 호스트 조회의 `range` 파라미터를 Elasticsearch `@timestamp` 조건에 반영했다.
- 여러 Analyzer가 같은 시간대에 보낸 트래픽 시계열은 InfluxDB 조회에서 시간 bucket 기준으로 합산하도록 조정했다.
- ICMP/UDP/SYN Flood는 패킷 timestamp가 있으면 snapshot 안의 1초 bucket을 시간 순서대로 모두 처리해 분석 지연으로 순간 Flood가 희석되거나 지속 초과 횟수가 누락되는 문제를 줄였다. 단, 중간에 빈 초가 있으면 history를 초기화해 떨어진 burst를 지속 공격으로 묶지 않는다.
- 보안 이벤트 batch가 400/413/422로 거부되면 batch 크기를 줄여 재시도하고, 하나의 이벤트까지 나눈 뒤에도 같은 오류가 나면 해당 이벤트만 큐에서 제거하도록 했다.
- Elasticsearch evidence 세부 key 인덱싱을 비활성화해 mapping field 증가를 줄였다.
- Docker Compose에서 주요 비밀번호/API Key를 필수 환경변수로 요구하고 DB/Elasticsearch 포트 기본 바인딩을 `127.0.0.1`로 제한했다.
- PostgreSQL 접속 URL은 SQLAlchemy `URL.create()`로 생성해 비밀번호에 `@`, `:`, `/`, `#` 같은 특수문자가 있어도 파싱 오류가 나지 않도록 했다.
- 아직 API가 없는 보안 이벤트 조치 버튼과 설정 입력은 비활성화해 실제 적용되는 기능처럼 보이지 않게 했다.
- ESLint 9 기준 설정을 추가해 `npm run lint`가 정상 검증 명령으로 동작하게 했다.
