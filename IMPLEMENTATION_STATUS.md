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
- 패킷 버퍼 최대 크기 제한과 초과 로그
- IPv4 주소 검증
- 백엔드 보안 이벤트 저장 및 대응 후보 `PENDING` 저장
- Elasticsearch `event_id` 기반 upsert와 bulk 저장
- 보안 이벤트 API 입력 검증
- 수동 Flow Rule API match/action 입력 검증
- WebSocket 병렬 broadcast와 실패 연결 정리
- `/health/live`, `/health/ready` 분리
- Docker Compose 저장소 healthcheck와 backend readiness 연동

## 부분 구현

| 항목 | 현재 범위 | 남은 범위 |
|---|---|---|
| Rate Limit | Analyzer가 `mitigation` 후보를 만들고 백엔드가 DB에 저장 | Controller/OVS Meter 실제 적용 |
| Drop | Analyzer가 `DROP` 후보를 만들고 백엔드가 DB에 저장 | Controller Flow Rule 실제 설치 |
| Self-Healing | 탐지와 대응 후보 생성까지 구현 | 적용 효과 확인, 정상 통신 확인, 자동 해제, 상태 머신 |
| 경로 우회 | 화면과 백엔드 조회 구조 일부 존재 | 실제 경로 재계산과 Controller 반영 |
| 보안 이벤트 상태 관리 | 이벤트 저장과 조회 | 처리 완료, 무시, 해결 상태 전환 정책 |
| 저장소 상태 관리 | readiness에서 연결 상태 확인 | 장애 원인 상세 로깅과 운영 알림 |

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
- 패킷 요약 host 통계를 상위 50개로 제한하고, 임시 `src_port`와 `dst_port`를 집계 키에서 제외했다.
- Port Scan과 다중 서비스 SYN Flood가 같은 흐름에서 동시에 잡히면 더 강한 SYN Flood 이벤트만 유지하고 Port Scan 근거는 관련 탐지로 묶도록 정리했다.
- Port Scan은 초 단위 버킷 집계로 바꿔 패킷 단위 이벤트가 계속 쌓이지 않게 했다.
- Analyzer 분석 루프와 백엔드 HTTP 전송 루프를 분리해 전송 지연이 분석 주기를 직접 막지 않도록 했다.
- Analyzer 런타임 메트릭을 PostgreSQL에 저장하도록 모델, repository, migration을 추가했다.
- 아직 API가 없는 보안 이벤트 조치 버튼과 설정 입력은 비활성화해 실제 적용되는 기능처럼 보이지 않게 했다.
- ESLint 9 기준 설정을 추가해 `npm run lint`가 정상 검증 명령으로 동작하게 했다.
