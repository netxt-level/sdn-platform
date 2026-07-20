# `sdn-platform-v1` 전체 코드 리뷰

## 1. 리뷰 기준과 결론

- 대상 브랜치: `origin/sdn-platform-v1`
- 대상 커밋: `13e83bd9b057a6f4d14f6f9fc227ddec95d8daca`
- 커밋 시각: 2026-07-16 18:58:17 +09:00
- 리뷰 방식: 현재 작업 트리와 분리한 `/tmp` 스냅샷에서 정적 검토, 단위 테스트, 프런트엔드 빌드, Compose/Shell 구문 검사, 의존성 감사를 수행했다.
- 사용자 소유의 현재 작업 트리 변경은 수정하지 않았다.

결론적으로, Controller의 L2 학습·경로 계산·링크 장애 전환 기반은 테스트가 잘 갖춰져 있고 구조도 비교적 명확하다. 그러나 현재 브랜치는 **운영 가능한 종단간 SDN 보안 플랫폼 상태는 아니다.** 특히 Git에 포함된 비밀 설정, Analyzer 관측 경로 부재, 이벤트 전송 실패 시 유실, Controller와 Backend Flow Rule의 미연동, 영구 중복 처리 키 때문에 우선순위 높은 수정이 필요하다.

### 심각도 요약

| 심각도 | 건수 | 의미 |
|---|---:|---|
| Critical | 1 | 즉시 비밀값 폐기·교체 필요 |
| High | 7 | 데이터 유실, 보안 노출, 핵심 기능 오동작 |
| Medium | 13 | 장애 복원력, 탐지 정확도, 상태 정합성 저하 |
| Low / 품질 | 5 | 미사용 코드, 문서·도구·유지보수 문제 |

## 2. 우선 조치 사항

### CR-01. 실제 `.env`가 Git에 포함되어 있다 — Critical

근거:

- `origin/sdn-platform-v1` 트리에 `.env`와 `.env.example`이 모두 존재한다.
- `.env`에는 `POSTGRES_PASSWORD`, `INFLUXDB_PASSWORD`, `INFLUXDB_TOKEN`, `ELASTIC_PASSWORD`가 비어 있지 않은 상태로 저장되어 있다. 리뷰 과정에서 실제 값은 출력하지 않았다.
- `.gitignore:1`에서 `.env`를 무시하도록 했지만 이미 추적 중인 파일에는 효력이 없다.
- 확인된 `.env` 변경 이력: 커밋 `209a4f9e`.

영향:

- 저장소 접근자가 DB/InfluxDB/Elasticsearch 자격증명을 획득할 수 있다.
- 현재 브랜치에서 파일만 삭제해도 과거 Git 이력에는 값이 남는다.

권고:

1. 포함된 모든 비밀번호와 토큰을 즉시 폐기하고 새 값으로 교체한다.
2. `.env`를 Git 인덱스에서 제거하고 `.env.example`만 유지한다.
3. 공개 또는 공유된 저장소라면 `git filter-repo` 같은 도구로 이력에서 제거한 뒤 영향 범위를 공지한다.
4. CI secret scanning을 추가하고 운영 환경에서는 Docker/Kubernetes secret 또는 별도 secret manager를 사용한다.

### HI-01. Analyzer가 Mininet 트래픽을 관측할 수 없다 — High

근거:

- `docker-compose.yml:17-52`의 Analyzer는 일반 Docker 네트워크에서 기본 `eth0`을 캡처한다.
- `docker-compose.dataplane.yml:1-36`은 host network를 사용하지만 기본 인터페이스만 지정하며 OVS Mirror/sensor 인터페이스를 만들지 않는다.
- `data-plane/docs/vm-setup.md:32-34`도 OVS Mirror와 전용 sensor 인터페이스가 후속 범위라고 명시한다.

영향:

- Analyzer 컨테이너가 실행 중이어도 `h1/h2/h3/web` 사이 트래픽이 집계·탐지되지 않는다.
- ICMP Flood/Port Scan 테스트와 Security Event → 대응 후보 생성 경로가 실제 데이터 플레인과 연결되지 않는다.

권고:

- OVS Mirror → 전용 veth/sensor 인터페이스를 구성하고 `ANALYZER_INTERFACE`를 해당 인터페이스로 고정한다.
- Analyzer 시작 전에 `tcpdump`로 양방향 Mininet 트래픽이 보이는지 검증하는 smoke test를 추가한다.
- 컨테이너 healthcheck에 “인터페이스 존재 + 최근 패킷 관측 + Backend 전송 가능”을 반영한다.

### HI-02. Backend 장애 시 메트릭과 보안 이벤트가 재시도 없이 유실된다 — High

근거:

- `analyzer/app/main.py:107-110`에서 패킷 버퍼를 먼저 비운다.
- `analyzer/app/main.py:133-142`에서 세 HTTP 요청을 순차 전송하며, 실패 payload를 큐에 되돌리지 않는다.
- 특히 `send_security_events()` 반환값은 확인하지 않는다.
- `analyzer/app/detection/security_events.py:278-290`은 전송 전에 중복 억제 상태를 기록한다.

영향:

- 연결 실패나 응답 손실 한 번으로 해당 윈도우의 집계와 Security Event가 영구 소실된다.
- 보안 이벤트 전송이 실패해도 dedup window 동안 같은 이벤트가 다시 생성되지 않는다.
- Controller/Backend 장애 동안 발생한 대응 후보를 나중에 복구할 수 없다.

권고:

- 메트릭과 이벤트를 분리된 bounded queue 또는 로컬 durable outbox에 넣고 성공 응답 후 제거한다.
- `event_id`를 idempotency key로 사용하고 지수 backoff+jitter로 재시도한다.
- 보안 이벤트 dedup 상태는 생성 시점이 아니라 전송 성공 또는 durable enqueue 성공 시점에 확정한다.
- 큐 포화·폐기량·최대 지연을 상태 API와 로그로 노출한다.

### HI-03. 동일 공격의 후속 사건이 영구적으로 기존 대응/Flow Rule에 묶인다 — High

근거:

- 이벤트 fingerprint는 `analyzer/app/detection/security_events.py:268-275`처럼 Analyzer, 공격 유형, 출발지/목적지, 프로토콜, 탐지 규칙으로만 구성되어 사건 시각이 포함되지 않는다.
- `backend/app/repositories/security_response_repository.py:64-96`은 `fingerprint + action`으로 기존 대응을 재사용한다.
- `backend/app/repositories/flow_repository.py:104-142`도 같은 방식으로 기존 Flow Rule을 재사용한다.
- migrations `003`, `004`는 위 조합을 unique index로 강제한다.

영향:

- 첫 사건이 `REMOVED`, `EXPIRED`, `FAILED`가 된 뒤 같은 공격이 다시 발생해도 새 대응과 새 규칙이 생성되지 않는다.
- `source_event_id`, `detected_at`, severity/mitigation도 최신 사건으로 갱신되지 않는다.
- 동시 중복 요청은 select 후 insert 경쟁으로 unique violation/500을 만들 수 있다.

권고:

- 사건 식별은 `event_id`를 사용하고, dedup은 별도의 시간 제한 키/상태로 처리한다.
- “활성 규칙 재사용”이 필요하면 `fingerprint + action + active status`를 애플리케이션 정책으로 판단하고 종료 규칙은 새 사건에 재사용하지 않는다.
- PostgreSQL upsert 또는 unique violation 재조회로 경쟁 조건을 처리한다.

### HI-04. Backend Flow Rule과 실제 Controller/OpenFlow 규칙이 연결되어 있지 않다 — High

근거:

- `data-plane/controller/app/api.py:37-53`은 `/health`, `/switches`만 제공한다.
- `backend/app/repositories/flow_repository.py:73-102`의 수동 Flow Rule 생성은 DB에 `PENDING` 레코드만 만든다.
- `FlowRepository.update_status()`는 `backend/app/repositories/flow_repository.py:146-169`에 존재하지만 호출자가 없다.
- Controller의 `DROP`, `OUTPUT`, `RATE_LIMIT`, Meter 설치/삭제 API와 Backend controller client가 없다.

영향:

- 화면에서 “Flow Rule 추가”가 성공해도 스위치에는 아무 규칙도 설치되지 않는다.
- Security Event에서 만들어진 RATE_LIMIT 후보도 계속 `PENDING`으로 남는다.
- Controller rule ID, OpenFlow ack/barrier, 만료/삭제 reconciliation이 수행되지 않는다.

권고:

- Controller에 검증된 Flow Rule CRUD, topology, installed-rule 조회 API를 추가한다.
- Backend에 timeout, idempotency key, bounded retry를 가진 controller adapter와 reconciliation worker를 추가한다.
- `PENDING → APPLYING → APPLIED/FAILED → EXPIRED/REMOVED` 전이를 명시하고 barrier/error 응답 후에만 `APPLIED`로 전환한다.
- RATE_LIMIT은 OVS Meter로 구현하고 meter lifecycle을 규칙과 함께 관리한다.

### HI-05. 인증 없는 API와 데이터 저장소가 모든 호스트 인터페이스에 노출된다 — High

근거:

- Backend/Controller API에 인증·인가 미들웨어가 없다.
- `docker-compose.yml:10-15`, `84-90`은 Backend/Frontend를 모든 인터페이스에 publish한다.
- `docker-compose.yml:92-132`는 PostgreSQL, InfluxDB, Elasticsearch 포트도 호스트에 publish한다.
- `docker-compose.yml:127-129`는 Elasticsearch 보안을 비활성화한다.
- `docker-compose.yml:62-66`은 Controller REST를 host network의 `0.0.0.0`에 bind한다.

영향:

- 같은 네트워크의 사용자가 이벤트 주입, Flow Rule 후보 생성, 보안 이벤트 열람, 데이터 저장소 직접 접근을 시도할 수 있다.
- 향후 Controller write API가 추가되면 인증 부재가 실제 네트워크 제어 권한 노출로 이어진다.

권고:

- 최소한 내부 API key/mTLS와 역할별 인증을 추가하고 Analyzer/Backend/Controller 자격증명을 분리한다.
- 개발용 포트는 `127.0.0.1`에만 bind하고 데이터베이스 포트는 필요할 때만 profile로 노출한다.
- WebSocket origin/auth 검증, 요청 크기 제한, rate limit을 추가한다.

### HI-06. 느리거나 끊어진 WebSocket 클라이언트가 Analyzer 수집 API를 실패시킬 수 있다 — High

근거:

- `backend/app/core/websocket.py:17-27`은 모든 소켓에 순차적으로 `await send_json()`한다.
- 예외는 `RuntimeError`만 잡는다.
- Analyzer/보안 서비스는 저장 직후 같은 요청 안에서 broadcast를 기다린다.

영향:

- 느린 클라이언트 하나가 ingestion 응답을 지연시킨다.
- `OSError`, WebSocket 전송 예외 등이 전파되면 데이터는 저장됐지만 API는 500을 반환할 수 있다.
- 송신 측이 재시도하는 구조로 바뀌면 저장된 데이터의 중복 가능성이 커진다.

권고:

- 수집 트랜잭션과 WebSocket fan-out을 queue/pub-sub로 분리한다.
- 클라이언트별 bounded send queue, timeout, 예외별 disconnect를 적용한다.
- 저장 성공 응답은 broadcast 성공 여부와 분리한다.

### HI-07. UI가 실제 제어·연결 상태와 다른 운영 신호를 표시한다 — High

근거:

- `frontend/components/layout/Shell.tsx:149-162`는 실제 상태와 무관하게 “컨트롤러 연결됨”, “LIVE READY”를 표시한다.
- `frontend/app/path/page.tsx:238-252`의 자동 우회, 임계값, 경로 전환 버튼은 handler/API 호출이 없다.
- `frontend/app/security/events/page.tsx:259-272`의 처리 확인/차단/무시/해결 버튼도 동작하지 않는다.
- `frontend/app/settings/page.tsx:4-44`의 설정 입력은 저장 상태나 API가 없는 정적 입력이다.
- `frontend/app/page.tsx:183-201`의 경로 사용률은 72%, 38%로 하드코딩되어 있다.

영향:

- 운영자가 연결·차단·우회가 실제 수행되었다고 오인할 수 있다.
- 보안 화면의 핵심 신뢰성이 훼손된다.

권고:

- 구현되지 않은 제어는 disabled와 “미지원/PENDING 후보” 라벨을 표시한다.
- Controller/Backend의 실제 상태 API를 단일 source of truth로 사용한다.
- Shell의 연결 표시는 Controller health, switch 수, Analyzer freshness를 조합해 계산한다.

## 3. 예외 처리·정합성·성능 문제

### ME-01. 보안 이벤트 저장은 idempotent하거나 원자적이지 않다 — Medium

- `backend/app/db/elasticsearch.py:70-81`은 `event_id`를 document ID로 쓰지 않아 동일 이벤트 재전송 시 중복 문서가 생긴다.
- `backend/app/services/security_service.py:38-50`은 Elasticsearch 저장, PostgreSQL response 생성, Flow Rule 생성을 순차 수행한다. 중간 실패 시 일부만 반영된다.
- `create_elasticsearch_indices()`와 `index_security_event()`가 만든 client는 닫지 않는다 (`backend/app/db/elasticsearch.py:17-81`). 이벤트마다 새 client를 만드는 구조와 결합되어 자원 누수가 발생할 수 있다.

개선: Elasticsearch `_id=event_id`, bulk API, 재사용 client, 명시적 close, outbox/saga 또는 reconciliation을 사용한다.

### ME-02. 입력 검증과 요청 크기 제한이 부족하다 — Medium

- `backend/app/schemas/analyzer.py:5-42`의 카운트·window·bps/pps는 음수와 과대값을 허용한다.
- `backend/app/schemas/security.py:7-31`의 IP, severity, protocol, action은 일반 문자열이고 `events`, `evidence`, `mitigation` 크기 제한이 없다.
- `backend/app/api/flows.py:10-17`은 action/switch/match 조합을 검증하지 않는다.

영향: 잘못된 통계, Influx/Elasticsearch 고카디널리티·대용량 쓰기, 향후 위험한 OpenFlow match/action 전달이 가능하다.

개선: `IPvAnyAddress`, Enum/Literal, `ge/le`, 문자열/목록 길이 제한, action별 필수·금지 필드 검증, ASGI request body limit을 추가한다.

### ME-03. 동기 DB/HTTP I/O가 async 요청·분석 루프를 막고 탐지 윈도우를 왜곡한다 — Medium

- Backend의 async ingestion endpoint 내부에서 SQLAlchemy/InfluxDB/Elasticsearch 동기 호출을 직접 수행한다.
- Analyzer는 `analyzer/app/main.py:133-142`에서 최대 3초 timeout 요청을 직렬 실행한다.
- 다음 loop는 전송이 끝난 뒤 다시 `WINDOW_SEC`만큼 sleep하지만 summary의 `window_sec`은 고정값이다.
- `analyzer/app/detection/port_scan.py:34-61`은 실제 `packet.timestamp`를 무시하고 해당 batch의 모든 SYN에 같은 처리 시각을 부여한다.

영향: Backend 장애 시 실제 7~10초 패킷을 1초 또는 5초 윈도우로 계산해 pps와 포트 스캔 조건이 과대/과소 평가될 수 있다.

개선: 캡처·집계·전송을 queue로 분리하고 monotonic window 경계를 사용한다. 탐지는 패킷 capture timestamp를 기준으로 하고 실제 window duration을 payload에 기록한다.

### ME-04. 문서화된 ICMP 설정 세 개가 실제 탐지에 사용되지 않는다 — Medium

- `icmp_baseline_spike_multiplier`, `icmp_baseline_min_pps`, `icmp_alert_cooldown_sec`는 `analyzer/app/detection/security_events.py:17-39`에서 저장만 하고 이후 참조되지 않는다.
- `SECURITY_DETECTION_POLICY.md:108-111`, `238-257`은 baseline spike 점수와 cooldown을 구현된 정책처럼 설명한다.

영향: 환경변수를 조정해도 탐지 결과가 바뀌지 않으며 문서와 운영 동작이 다르다.

개선: rolling baseline/표본 신뢰 조건/cooldown을 구현하고 경계 테스트를 추가하거나, 구현 전까지 설정과 문서에서 제거한다.

### ME-05. 공격 키가 다양해질수록 Analyzer 메모리가 계속 증가한다 — Medium

- `SecurityEventBuilder.recent_events`는 `analyzer/app/detection/security_events.py:39,286-290`에서 추가되지만 만료 삭제가 없다.
- `PortScanDetector.last_alert_at`도 `analyzer/app/detection/port_scan.py:29-32,125-129`에서 추가되며 삭제되지 않는다.

개선: dedup/cooldown 만료 시 주기적으로 제거하고 최대 항목 수를 제한한다. 고유 출발지 IP를 대량 생성하는 테스트를 추가한다.

### ME-06. L2 Flow 설치 실패를 추적하지 않고 성공처럼 로그한다 — Medium

- Controller는 Flow-Mod들을 보낸 직후 `data-plane/controller/app/controller.py:559-588`에서 `l2_path_installed`를 기록한다.
- OpenFlow error handler는 Table-Miss XID만 추적하며 일반 L2 Flow-Mod 오류는 untracked warning이 된다 (`controller.py:119-146`).

영향: 스위치가 규칙을 거부해도 Controller 로그는 경로 설치 성공으로 보일 수 있다.

개선: batch/barrier XID를 경로 설치 작업과 연결하고 Flow-Mod error/timeout을 상태로 관리한다.

### ME-07. DEAD 이벤트 없는 datapath 교체 시 포트 상태를 다시 동기화하지 않는다 — Medium

- `data-plane/controller/app/controller.py:164-200`은 `ActiveTopology.connect_switch()`가 새 연결로 판정할 때만 PortDesc를 요청한다.
- 동일 DPID의 새 datapath가 이전 DEAD 이벤트 전에 등록되면 registry는 교체되지만 topology는 이미 connected라서 PortDesc 요청을 생략한다.

영향: 새 세션의 실제 포트 down/up 상태 대신 이전 세션 상태로 경로를 계산할 수 있다.

개선: datapath 객체가 바뀌면 항상 해당 스위치 endpoint 상태를 pending으로 초기화하고 PortDesc를 재요청한다.

### ME-08. `range` 파라미터가 의심 호스트 조회에 적용되지 않는다 — Medium

- `backend/app/services/dashboard_service.py:65-71`은 `range_value`를 응답에 되돌려주기만 한다.
- 실제 조회는 Elasticsearch 최신 100개 이벤트로 고정된다 (`backend/app/db/elasticsearch.py:111-145`).

영향: UI의 “최근 1주 DB 저장 기준”이 실제 데이터 범위와 다르다.

개선: range를 초 단위로 검증·변환해 Elasticsearch timestamp range query에 적용하고 pagination/aggregation을 사용한다.

### ME-09. 프런트가 서로 다른 사건을 fingerprint 기준으로 합친다 — Medium

- `frontend/hooks/useRealtime.ts:436-452`는 `event_fingerprint`를 우선 key로 사용한다.
- fingerprint는 사건 시각을 포함하지 않으므로 dedup window 이후 재발한 사건도 하나로 덮어쓴다.
- `frontend/hooks/useRealtime.ts:343-359`는 `RATE_LIMIT`을 `block`으로 표시한다.

개선: 사건 목록은 `event_id`/Elasticsearch document ID로 식별하고 fingerprint는 그룹화 필드로만 사용한다. UI action에 `rate_limit`을 별도 표현한다.

### ME-10. 프런트 fetch 오류가 처리되지 않거나 연결 성공으로 오인된다 — Medium

- `frontend/app/flow-rules/page.tsx:84-119,121-158`은 네트워크 예외를 처리하지 않는다.
- `frontend/app/path/page.tsx:81-105`도 `finally`만 있고 catch가 없어 interval Promise rejection이 발생할 수 있다.
- 두 화면 모두 요청 실패 여부가 아니라 `loading=false`를 connected 상태로 표시한다.
- `fetchDashboardSuspiciousHosts()`는 일시적인 HTTP 오류를 빈 배열로 바꾸고 다음 polling에서 기존 호스트를 지운다 (`frontend/hooks/useRealtime.ts:477-488,889-912`).

개선: 공통 API client에 timeout/AbortController/error state를 두고, stale data와 empty data를 구분한다. connected는 마지막 성공 시각과 실제 health로 계산한다.

### ME-11. Controller와 Backend health가 readiness를 의미하지 않는다 — Medium

- Controller `/health`는 스위치 0대와 Table-Miss 실패 상태에서도 항상 `ready`다 (`data-plane/controller/app/api.py:9-16`).
- Backend `/health`는 PostgreSQL, InfluxDB, Elasticsearch 연결을 확인하지 않는다 (`backend/app/main.py:52-55`).
- Compose가 이 endpoint를 컨테이너 health로 사용한다.

개선: liveness와 readiness를 분리하고, Controller readiness에는 API thread, 예상 스위치 수/최소 연결 수, Table-Miss 상태를 포함한다. Backend readiness에는 의존 저장소의 bounded ping을 포함한다.

### ME-12. 다중 Analyzer 집계 시 최신값 선택이 잘못될 수 있다 — Medium

- InfluxDB query는 analyzer tag별 table/group을 유지한 채 각 table 내부에서만 sort한다 (`backend/app/db/influxdb.py:46-81`).
- `DashboardService.get_summary()`는 결합 결과의 마지막 원소를 최신값으로 가정한다 (`backend/app/services/dashboard_service.py:27-39`).

영향: Analyzer가 두 대 이상이면 `current_pps/current_bps`가 시간상 최신 샘플이 아닐 수 있다.

개선: Flux에서 analyzer group을 명시적으로 합치거나 Python에서 timestamp로 전역 정렬·집계한다.

### ME-13. PostgreSQL DSN 문자열 조합이 특수문자 자격증명을 깨뜨린다 — Medium

- `backend/app/core/config.py:19-26`은 user/password를 URL escaping 없이 f-string으로 조합한다.

개선: SQLAlchemy `URL.create()`를 사용하고 비밀번호를 로그에 노출하지 않는다.

## 4. 미사용 코드와 정리 후보

다음 항목은 production import/call이 없거나 테스트에서만 사용된다. 바로 삭제하기 전에 향후 API 계획을 확인하되, 현재 상태로는 사용 여부를 오해하게 한다.

| 후보 | 근거/설명 |
|---|---|
| `frontend/lib/mockData.ts` 전체 | 어떤 production 파일에서도 import하지 않는다. 실제 토폴로지의 `web/10.0.0.100` 대신 과거 `h4/10.0.0.4` 데이터도 남아 있다. |
| `FlowRepository.update_status()` | 정의만 있고 호출자가 없다. Controller lifecycle 미연동을 드러낸다. |
| `HostRegistry.get_by_ipv4()` | Controller production 경로에서는 사용하지 않고 테스트에서만 사용한다. |
| `HostRegistry.snapshot()`, `__len__()` | 현재 Controller production 경로에 소비자가 없다. |
| `packet_parser.parse_source_identity()` | 테스트 전용 wrapper이며 Controller는 `parse_packet_metadata()`만 사용한다. |
| unweighted routing 계열 | `PRIMARY_SWITCH_GRAPH`, `calculate_unweighted_path/route/bidirectional_routes`는 테스트에서만 사용하고 production은 weighted routing만 사용한다. |
| 정적 flood helper | `FLOOD_TREE_PORTS`와 module-level `get_flood_output_ports()`는 테스트에서만 사용하며 production은 `ActiveTopology.get_flood_output_ports()`를 사용한다. |
| `ControllerApiServer.is_alive` | 내부 property가 호출되지 않는다. readiness에 연결하면 의미가 생긴다. |
| ICMP baseline/cooldown 설정 | 설정/문서에는 있으나 탐지 로직에서 사용되지 않는다. 단순 dead code가 아니라 운영 오해를 만드는 설정이다. |
| `SecurityRule` 타입 | 사용처가 dead `mockData.ts`뿐이다. |

권고: dead-code 검사를 CI에 추가하고, “향후 사용 예정” 코드라면 issue/feature flag와 함께 격리한다. 테스트만을 위한 과거 구현을 production 모듈에 유지하기보다 현재 weighted/active topology API 기준으로 테스트를 갱신한다.

## 5. 배포·의존성·개발 품질

### LQ-01. 프런트 lint 명령이 비대화형 환경에서 실행되지 않는다

- `npm run lint`는 ESLint 설정이 없어 Next.js 설정 선택 prompt를 띄우고 exit 1이 된다.
- CI에서 정적 검사가 자동 수행되지 않는 상태다.

개선: ESLint flat config를 커밋하고 script를 `eslint .`로 전환한다.

### LQ-02. 운영 Compose가 Next.js 개발 서버를 실행한다

- `frontend/Dockerfile:13`은 `npm run dev`를 실행한다.
- production build는 성공하지만 실제 image/runtime은 이를 사용하지 않는다.

개선: multi-stage build로 `next build` 후 `next start` 또는 standalone output을 사용하고 non-root user로 실행한다.

### LQ-03. Python 의존성이 대부분 고정되지 않았다

- Backend/Analyzer requirements는 대부분 버전 pin과 hash가 없다.
- 같은 커밋도 빌드 시점에 따라 다른 패키지가 설치될 수 있다.

개선: lock/constraints 파일, Dependabot/Renovate, 재현 가능한 image digest를 사용한다.

### LQ-04. 프런트 의존성에 moderate 취약점 3개가 보고된다

`npm audit` 결과:

- `js-yaml@4.1.1`: GHSA-h67p-54hq-rp68
- Next 내부 `postcss@8.4.31`: GHSA-qx2v-qp2m-jg93
- 이를 통해 `next@15.5.18`도 moderate로 보고됨

High/Critical은 0개였다. 자동 제안이 부정확한 구버전 Next downgrade를 제시하므로 그대로 적용하지 말고, 최신 호환 Next에서 내부 PostCSS가 수정됐는지 확인한 후 업그레이드해야 한다.

### LQ-05. 정적 품질 경고와 문서 불일치가 남아 있다

- `ruff check`는 5건을 보고했다: `backend/app/scripts/seed_suspicious_hosts.py` E402 2건, `migrations/env.py` E402 2건/F401 1건.
- `frontend/app/topology/page.tsx:16`은 `h1-h4`를 설명하지만 실제 호스트는 `h1/h2/h3/web`이다.
- Dashboard 설명은 “Ryu 컨트롤러”라고 하지만 구현은 OS-Ken이다 (`frontend/app/page.tsx:89`).
- `settings` 페이지는 navigation에 없고 기능도 연결되지 않았다.

## 6. 테스트 및 검증 결과

### 실행 결과

| 검사 | 결과 |
|---|---|
| Backend tests | 4 passed |
| Analyzer policy tests | 9 passed |
| Controller tests (target Docker image, Python 3.11/os-ken) | 103 passed |
| Mininet pure tests | 10 passed |
| 합계 | 126 passed |
| Frontend `npm run build` | 성공, 9개 route 정적 생성 |
| Frontend `npm run lint` | 실패: ESLint 설정 prompt |
| Python compileall | 성공 (`PYTHONPYCACHEPREFIX=/tmp/...` 사용) |
| Bash `-n` | 성공 |
| `docker compose --profile dataplane config --quiet` | 성공 |
| `ruff check` | 5건 실패 |
| `npm audit` | moderate 3, high/critical 0 |

### 실행하지 못했거나 별도 환경이 필요한 항목

- 해당 커밋의 실제 Mininet `pingall`, failover, host spoofing, iperf3 통합 시나리오는 Linux/OVS 환경을 변경하므로 이번 읽기 중심 리뷰에서는 실행하지 않았다.
- Analyzer Mirror/sensor 통합 테스트는 대상 브랜치에 구현 자체가 없어 실행 대상이 없다.
- Backend 실제 PostgreSQL/InfluxDB/Elasticsearch 통합 테스트는 제공되지 않았다.

### 테스트 공백

1. Analyzer BackendClient timeout/HTTP 오류/retry/outbox 테스트가 없다.
2. capture/parser/summary/config/main thread 테스트가 거의 없고 정책 테스트 1개 파일에 집중되어 있다.
3. Backend 테스트는 repository를 stub 처리해 DB transaction, migration, Elasticsearch idempotency, Influx query를 검증하지 않는다.
4. 동시 동일 이벤트 처리와 unique constraint 경쟁 테스트가 없다.
5. WebSocket slow/disconnect client가 ingestion에 미치는 테스트가 없다.
6. Controller L2 Flow-Mod error/barrier, 새 datapath가 DEAD보다 먼저 오는 reconnect 순서 테스트가 없다.
7. Frontend component/hook 테스트가 전혀 없으며 이벤트 merge, polling 오류, 버튼 비활성 상태가 검증되지 않는다.
8. 실제 Controller ↔ Backend ↔ OVS Flow/Meter lifecycle 테스트가 없다.

## 7. 권장 수정 순서

1. **비밀 대응:** `.env` 자격증명 전부 교체, Git 추적·이력 제거, secret scan 적용.
2. **관측 경로 완성:** OVS Mirror/sensor 인터페이스를 만들고 `tcpdump → Analyzer → Backend`를 먼저 통과시킨다.
3. **유실 방지:** Analyzer durable queue/outbox와 Backend idempotent `event_id` 저장을 구현한다.
4. **사건 모델 수정:** fingerprint 영구 unique를 제거하고 사건(`event_id`)과 활성 대응 재사용 정책을 분리한다.
5. **제어 경로 완성:** Controller Flow/Meter API, Backend adapter, ack/barrier, lifecycle/reconciliation을 구현한다.
6. **노출 축소:** API 인증, loopback binding, DB 포트 비공개, request limit을 적용한다.
7. **운영 UI 정직성:** 미구현 버튼을 비활성화하고 실제 health/topology/rule 상태만 표시한다.
8. **복원력 개선:** WebSocket fan-out 분리, sync I/O worker화, retry/backoff, readiness를 추가한다.
9. **품질 게이트:** ESLint 설정, ruff clean, integration tests, dependency locking/audit를 CI 필수 조건으로 만든다.

## 8. 긍정적인 부분

- Controller routing/topology/host registry가 OpenFlow 객체와 상당 부분 분리되어 단위 테스트하기 쉽다.
- Dijkstra equal-cost 결정성이 명시적이고 테스트되어 있다.
- stale datapath disconnect 방어, Table-Miss barrier 상태 추적, active link endpoint 양방향 확인이 구현되어 있다.
- Mininet DPID, host identity, switch port가 고정되어 재현성 있는 lab 기반을 제공한다.
- Packet-Out으로 첫 패킷을 전달하고 관리 L2 cookie 범위를 분리한 설계는 적절하다.
- 현재 범위의 Controller 단위 테스트 103개와 failover 시나리오 스크립트는 이후 확장에 좋은 기반이다.

