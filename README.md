# SDN Platform

> 탐지부터 대응 검증까지 연결하는 네트워크 보안 자동화 플랫폼

- 문서 기준일: 2026-08-11
- 현재 기준 브랜치: `sdn-platform-v1`
- 현재 성격: SDN 기반 폐루프 NDR MVP 및 격리 검증 플랫폼

SDN Platform은 네트워크 트래픽에서 위협을 탐지하고, 탐지 결과를 실행 가능한
대응 정책으로 변환하며, SDN Controller를 통해 정책을 적용한 뒤 실제 적용
상태까지 추적한다.

이 프로젝트의 중심은 스위치 자체나 트래픽 대시보드가 아니다. 핵심은 다음
보안 대응 흐름을 하나의 시스템으로 연결하는 것이다.

```text
관측          탐지          정책 판단          대응 적용          결과 검증
Packet ──> Analyzer ──> Backend ──> Controller ──> Flow/Meter
   ^                          │                         │
   └──────────────────────────┴── 통계·상태 재조정 <───┘
```

Mininet과 Open vSwitch는 제품의 목적이 아니라 이 흐름이 실제 네트워크
동작으로 이어지는지 재현하고 검증하기 위한 격리된 실행 환경이다.

## 해결하려는 문제

일반적인 모니터링 시스템은 이상 트래픽을 보여주거나 알림을 발생시키는 데서
끝난다. 실제 네트워크 대응은 운영자가 별도의 장비나 도구에서 수행해야 하며,
명령이 정상적으로 적용됐는지도 다시 확인해야 한다.

SDN Platform은 이 간극을 다음과 같이 연결한다.

1. 네트워크 패킷과 트래픽 지표를 수집한다.
2. 공격 유형과 심각도를 판별하고 보안 이벤트를 생성한다.
3. 이벤트를 `RATE_LIMIT` 또는 `DROP` 같은 대응 정책으로 변환한다.
4. SDN Controller가 OpenFlow Rule과 OVS Meter를 적용한다.
5. Barrier 응답, Flow 통계, Controller 상태를 이용해 적용 결과를 확인한다.
6. Backend 기록과 실제 Controller 상태가 다르면 재조정한다.
7. 운영자는 전체 탐지·판단·대응 이력을 대시보드에서 확인하고 개입할 수 있다.

대표 검증 시나리오는 다음과 같다.

```text
격리된 공격 트래픽 발생
  -> Analyzer가 이상 징후 탐지
  -> Backend가 이벤트 저장 및 대응 정책 결정
  -> Controller가 RATE_LIMIT 또는 DROP 적용
  -> OVS Flow/Meter와 트래픽 통계로 효과 확인
  -> Backend와 대시보드에 최종 상태 반영
```

## 제품 범위

### 핵심 기능

- 패킷 캡처와 트래픽 요약
- ICMP Flood, Port Scan, 서버 역할 위반, 내부 확산, 비정상 송신량,
  주기적 C2 연결 탐지
- 탐지 이벤트의 심각도·대응 레벨·중복 억제 정책
- 자동 또는 운영자 승인 기반 보안 대응
- `DROP`, `OUTPUT`, `RATE_LIMIT` Flow Rule 적용
- OVS Meter 기반 패킷 속도 제한
- Flow Rule 적용·실패·제거·만료 lifecycle 추적
- Backend–Controller 상태 재조정
- 보안 이벤트, 대응 내역, Flow 통계의 실시간 시각화

### 대응을 지지하는 네트워크 기능

- OpenFlow 1.3 스위치 연결과 L2 Forwarding
- 호스트 학습과 최단 경로 계산
- Primary/Backup 경로와 링크 장애 우회
- 포트·Flow 통계 수집과 혼잡 기반 경로 재계산
- OVS Mirror와 전용 Sensor 인터페이스를 이용한 Analyzer 캡처 경로

### 실행·검증 환경

- Mininet 기반 격리 토폴로지
- Open vSwitch 기반 Flow Rule 및 Meter 검증
- Multipass Ubuntu VM 기반 macOS/Windows 개발 환경
- Mutillidae 기반 격리 웹 보안 실험 환경
- 공격 탐지, 자동 대응, 장애 우회, 속도 제한 자동 검증 시나리오

공격 및 부하 생성 시나리오는 반드시 격리된 Mininet Lab 안에서만 실행한다.

## 시스템 구성

| 구성요소 | 책임 |
|---|---|
| Analyzer | 패킷 캡처, 트래픽 집계, 이상 징후 탐지, 전달 실패 데이터 보존 |
| Backend | 이벤트 저장, 대응 정책 결정, Flow lifecycle 관리, Controller 연동 및 재조정 |
| Controller | OpenFlow Rule과 Meter 적용, 경로 계산, 스위치·토폴로지·통계 관리 |
| Frontend | 탐지 이벤트, 대응 결과, Flow Rule, 토폴로지, 서비스 상태 표시 및 운영자 개입 |
| PostgreSQL | Analyzer 상태, 보안 대응, Flow Rule, 런타임 설정 저장 |
| InfluxDB | 트래픽·프로토콜·호스트·네트워크 시계열 저장 |
| Elasticsearch | 보안 이벤트와 탐지 문서 저장 |
| Mininet/OVS | Controller 명령의 실행 대상이자 전체 보안 자동화 흐름의 검증 환경 |

### 배치 구조

기본 개발 환경은 제어 영역과 Linux 데이터 플레인을 분리한다.

```text
Development host                         Ubuntu Multipass VM
----------------                         -------------------
Frontend                                 Analyzer
Backend                                  SDN Controller
PostgreSQL / InfluxDB / Elasticsearch    Mininet / Open vSwitch
                                         Sensor veth / OVS Mirror
```

Analyzer는 VM의 기본 네트워크 인터페이스가 아니라 OVS Mirror에 연결된 전용
`sdn-sensor0` 인터페이스에서 Mininet 트래픽을 관찰한다.

## 탐지와 대응

탐지 기준과 대응 레벨은
[`SECURITY_DETECTION_POLICY.md`](SECURITY_DETECTION_POLICY.md)를 기준으로 한다.

| 탐지 유형 | 주요 기준 | 기본 처리 |
|---|---|---|
| `PORT_SCAN` | TCP SYN, 동일 출발지·목적지, 고유 목적지 포트 수 | 관찰 또는 운영자 판단 |
| `ICMP_FLOOD` | 동일 출발지·목적지의 ICMP PPS 임계값 | 정책에 따른 Rate Limit 후보 |
| `SERVER_EGRESS` | 보호 서버가 시작한 허용 목록 밖 TCP 연결 | 운영자 확인 |
| `LATERAL_MOVEMENT` | 보호 서버의 단시간 다중 목적지 연결 | Critical/Drop 정책 |
| `DATA_EXFILTRATION` | 서버 시작 Flow의 지속적인 송신량 이상 | 운영자 확인 |
| `C2_BEACON` | 서버 시작 연결의 반복 주기와 낮은 jitter | 운영자 확인 |

Backend는 이벤트 심각도와 mitigation을 검토해 대응 여부를 결정한다. 자동
대응 설정을 끌 수 있으며, 운영자는 Security Events 화면에서 이벤트를 직접
차단·무시·종료할 수 있다.

### 상태 추적

보안 이벤트는 다음 운영 상태를 사용한다.

```text
detected -> blocked | ignored | resolved
```

보안 대응과 Flow Rule은 요청과 실제 적용 결과를 분리해 기록한다.

```text
PENDING -> APPLYING -> APPLIED
                    -> FAILED

APPLIED -> REMOVING -> REMOVED
                     -> REMOVE_FAILED
        -> EXPIRED
```

Flow Rule은 Controller가 OpenFlow Barrier Reply를 확인한 뒤에만 `APPLIED`로
기록된다. Backend는 주기적으로 Controller의 실제 규칙과 저장된 상태를
비교해 누락되거나 만료된 규칙을 재조정한다.

## 현재 구현 상태

| 영역 | 상태 |
|---|---|
| 패킷 캡처·요약 | 구현 |
| Port Scan·ICMP Flood·보호 서버 행위 탐지 | 구현 |
| Analyzer 영속 Outbox·재시도·Dead Letter | 구현 |
| 보안 이벤트 저장·실시간 전달 | 구현 |
| 자동/수동 대응 정책 | 구현 |
| Flow Rule 설치·삭제·상태 재조정 | 구현 |
| OVS Meter 기반 `RATE_LIMIT` | 구현 |
| L2 Forwarding·최단 경로·장애 우회 | 구현 |
| PPS 임계값 기반 TCP Flow 경로 분산·복귀 | 구현 |
| OVS Mirror 기반 Analyzer 관찰 경로 | 구현 |
| 토폴로지·Flow·보안 이벤트 운영 화면 | 구현 |
| API Key·WebSocket 단기 토큰 보호 | 구현 |
| 격리된 데이터 플레인 자동 검증 | 구현 |
| secure-default Multipass bootstrap 배치 | 구현 |

세부 구현 현황은
[`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md)에서 확인할 수 있다.

## 프로젝트 구조

```text
analyzer/                 패킷 수집, 탐지, Backend 전송
backend/                  정책 판단, 저장, API, Controller 연동
frontend/                 보안 운영 대시보드
data-plane/
  controller/             OpenFlow 1.3 Controller
  mininet/                토폴로지와 검증 시나리오
  infrastructure/         Multipass VM 구성
  scripts/                시작, 종료, 정리, 검증
  docs/                   데이터 플레인 운영 문서
migrations/               PostgreSQL Alembic migration
docker-compose.yml        전체 서비스 정의
```

## 시작하기

### 1. 사전 요구사항

- Docker와 Docker Compose
- 전체 데이터 플레인 검증 시 Multipass
- 프로젝트 루트의 `.env`

Mininet과 Open vSwitch는 Linux 커널 기능을 사용하므로 macOS와 Windows에서는
Multipass Ubuntu VM이 필요하다.

### 2. 환경변수 준비

```bash
cp .env.example .env
```

`.env.example`의 다음 값은 실행 전에 서로 다른 안전한 값으로 교체한다.

- `POSTGRES_PASSWORD`
- `INFLUXDB_PASSWORD`
- `INFLUXDB_TOKEN`
- `ADMIN_API_KEY`
- `ANALYZER_API_KEY`
- `CONTROLLER_API_KEY`
- `WEBSOCKET_TOKEN_SECRET`

인증 키가 비어 있으면 보호된 API가 요청을 거부한다. `.env.example`의 예시
값은 공개된 값이므로 그대로 사용하지 않는다. 격리된 로컬 개발에서만 인증을
생략해야 할 경우 `ALLOW_INSECURE_DEV_AUTH=true`를 명시적으로 사용한다.

### 3. 애플리케이션 영역만 실행

Controller와 Mininet 없이 Backend, Frontend, 저장소를 확인하려면 다음과
같이 실행한다.

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.control-plane.yml \
  up -d --build postgres influxdb elasticsearch

docker compose \
  -f docker-compose.yml \
  -f docker-compose.control-plane.yml \
  run --rm migrate

docker compose \
  -f docker-compose.yml \
  -f docker-compose.control-plane.yml \
  up -d --build backend frontend
```

코드 변경 후 Backend와 Frontend를 다시 빌드할 때는 다음 전용 명령을 사용한다.
이 스크립트는 실행 중인 Backend 또는 `.env`에서 인증 키를 보존하고,
Multipass의 현재 Controller IP와 host gateway를 자동으로 계산한다. 필수 키나
Controller 연결을 확인할 수 없으면 기존 컨테이너를 재생성하기 전에 중단한다.

```bash
./data-plane/scripts/restart-control-plane.sh
```

한 서비스만 다시 빌드할 수도 있다.

```bash
./data-plane/scripts/restart-control-plane.sh frontend
./data-plane/scripts/restart-control-plane.sh backend
```

| 서비스 | 기본 주소 |
|---|---|
| Frontend | `http://127.0.0.1:3000` |
| Backend | `http://127.0.0.1:8000` |
| Backend Health | `http://127.0.0.1:8000/health` |

Backend의 Swagger/OpenAPI 문서는 보안상 기본 비활성화되어 있다.

### 4. 전체 보안 자동화 환경 실행

macOS 또는 Linux 호스트에서는 기본 `dataplane` 프로필을 권장한다.

```bash
./data-plane/infrastructure/multipass/bootstrap.sh
```

Windows PowerShell:

```powershell
.\data-plane\infrastructure\multipass\bootstrap.ps1
```

이 명령은 호스트에 Backend, Frontend, 저장소를 실행하고 VM에 Analyzer,
Controller와 Mininet/OVS 실행 환경을 구성한다. 기본 `auto` 인터페이스는
`sdn-sensor0`으로 해석되며, bootstrap이 Sensor veth를 먼저 준비한다. Analyzer는
루트 Compose와 dataplane overlay를 병합해 실행하므로 API Key, 영속 Outbox
volume과 host network가 함께 적용된다.

Mininet은 `--sensor-mirror` 옵션이나 Mirror 검증 시나리오로 실행해야 실제
트래픽이 Sensor에 복제된다.

모든 서비스를 VM 안에서 실행하려면 다음 프로필을 사용한다.

```bash
./data-plane/infrastructure/multipass/bootstrap.sh --profile full
```

자세한 설치와 복구 절차는
[`data-plane/docs/vm-setup.md`](data-plane/docs/vm-setup.md)를 참고한다.

### 5. 상태 확인

```bash
curl http://127.0.0.1:8000/health
```

Controller는 VM 내부에서 실행된다.

```bash
VM_IP="$(multipass list --format csv | awk -F, '$1 == "sdn-lab" {print $3}')"
curl "http://${VM_IP}:8080/health"
curl -H "X-API-Key: <CONTROLLER_API_KEY>" \
  "http://${VM_IP}:8080/switches"
```

### 6. 종료와 정리

애플리케이션 영역 종료:

```bash
docker compose \
  -f docker-compose.yml \
  -f docker-compose.control-plane.yml \
  down
```

Mininet, OVS, Sensor 상태 정리:

```bash
./data-plane/scripts/cleanup.sh
```

데이터베이스 볼륨 삭제는 저장 데이터를 영구 제거하므로 필요한 경우에만
`docker compose down -v`를 실행한다.

## 주요 API

관리 API는 `X-API-Key: <ADMIN_API_KEY>`, Analyzer 수신 API는
`X-API-Key: <ANALYZER_API_KEY>`를 요구한다.

### 탐지 수신과 조회

| 메서드 | 경로 | 설명 |
|---|---|---|
| `POST` | `/api/analyzer/packet-summary` | 패킷 요약 수신 |
| `POST` | `/api/analyzer/detection-summary` | 트래픽·탐지 요약 수신 |
| `POST` | `/api/security/events` | 보안 이벤트 수신 및 대응 정책 처리 |
| `GET` | `/api/security/events` | 보안 이벤트 조회 |
| `GET` | `/api/security/responses` | 대응 이력 조회 |
| `POST` | `/api/security/events/{event_id}/actions` | 차단·무시·종료 수동 처리 |

### 대응 적용과 검증

| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/api/controller/status` | Controller 연결 및 준비 상태 |
| `GET` | `/api/flows` | 저장된 규칙과 실제 Flow 통계 조회 |
| `POST` | `/api/flows` | 수동 Flow Rule 생성 및 적용 |
| `DELETE` | `/api/flows/{id}` | Flow Rule 제거 |
| `POST` | `/api/flows/reconcile` | Backend–Controller 상태 재조정 |
| `GET` | `/api/path/status` | 경로, 링크, 스위치 사용률 조회 |
| `GET`/`PUT` | `/api/settings` | 자동 대응 런타임 설정 조회·변경 |

### 운영 화면 데이터

| 메서드 | 경로 | 설명 |
|---|---|---|
| `GET` | `/api/dashboard/summary` | 대시보드 요약 |
| `GET` | `/api/dashboard/traffic` | 트래픽 시계열 |
| `GET` | `/api/dashboard/protocols` | 프로토콜 통계 |
| `GET` | `/api/dashboard/suspicious-hosts` | 의심 호스트 |
| `POST` | `/ws/token` | WebSocket 접속 토큰 발급 |
| `WS` | `/ws/analyzer` | 상태·탐지·대응 실시간 전달 |

상세 계약은 [`backend/backend-api.md`](backend/backend-api.md)와
[`analyzer/analyzer-backend-api.md`](analyzer/analyzer-backend-api.md)를
참고한다.

## 운영 화면

| 화면 | 경로 | 목적 |
|---|---|---|
| Dashboard | `/` | 트래픽, 탐지, 서비스 상태 요약 |
| Security Events | `/security/events` | 이벤트 확인과 수동 대응 |
| Flow Rules | `/flow-rules` | 적용 규칙, 통계, 수동 생성·삭제 |
| Topology | `/topology` | 실제 링크, 경로, 포트 사용률 확인 |
| Settings | `/settings` | 자동 대응 정책 활성화 설정 |

## 검증

### 단위 테스트

Python 3.10 이상 환경에 `requirements-dev.txt`와 각 구성요소의
`requirements.txt`가 설치되어 있어야 한다. 서비스별 `app` 패키지가
충돌하지 않도록 테스트도 구성요소별로 실행한다.

```bash
python3 -m pytest analyzer/tests
python3 -m pytest backend/tests
(cd data-plane/controller && python3 -m unittest discover -s tests -v)
(cd data-plane/mininet && python3 -m unittest discover -s tests -v)
```

### 데이터 플레인 통합 검증

```bash
./data-plane/scripts/verify.sh
```

통합 검증은 다음 항목을 확인한다.

- 스위치 연결, 호스트 학습, `pingall`
- Primary/Backup 경로와 링크 장애·복구
- Flow Rule 설치·삭제와 OpenFlow Barrier 응답
- OVS Meter 설치·정리와 Rate Limit 효과
- OVS Mirror와 Sensor 인터페이스의 양방향 패킷 관찰
- 검증 종료 후 남은 OVS Bridge 부재

Analyzer 탐지부터 Backend 대응, Controller 적용까지의 시나리오는
`data-plane/mininet/scenarios/analyzer_detection_response.py`에 있다.
웹 접근 이후 서버 권한 상승을 증명 전용 helper로 안전하게 모의하는 수동
검증 절차는
`data-plane/docs/server-privilege-escalation-scenario.md`에 있다.

## 주요 문서

- [`SECURITY_DETECTION_POLICY.md`](SECURITY_DETECTION_POLICY.md): 탐지 조건과 대응 정책
- [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md): 구성요소별 구현 상태
- [`backend/backend-api.md`](backend/backend-api.md): Backend HTTP/WebSocket 계약
- [`analyzer/analyzer-backend-api.md`](analyzer/analyzer-backend-api.md): Analyzer–Backend 계약
- [`data-plane/docs/controller-foundation.md`](data-plane/docs/controller-foundation.md): Controller 구조와 REST API
- [`data-plane/docs/analyzer-mirror.md`](data-plane/docs/analyzer-mirror.md): Mirror와 Sensor 캡처 경로
- [`data-plane/docs/mininet-topology.md`](data-plane/docs/mininet-topology.md): Lab 토폴로지와 주소·포트 맵
- [`data-plane/docs/vm-setup.md`](data-plane/docs/vm-setup.md): Multipass 설치, 실행, 복구
- [`data-plane/docs/mutillidae-lab.md`](data-plane/docs/mutillidae-lab.md): 격리 웹 보안 실험 환경
- [`data-plane/docs/server-privilege-escalation-scenario.md`](data-plane/docs/server-privilege-escalation-scenario.md): 서버 권한 상승 수동 검증

## 개발 원칙

- 기능은 `관측 -> 탐지 -> 정책 판단 -> 대응 적용 -> 결과 검증` 흐름에 어떤
  역할을 하는지 설명할 수 있어야 한다.
- Packet-In 처리 경로에서 동기 Backend 요청을 수행하지 않는다.
- Controller 명령 전송과 실제 적용 완료를 같은 상태로 취급하지 않는다.
- Analyzer는 탐지, Controller는 네트워크 제어, Backend는 정책과 상태 관리의
  책임을 유지한다.
- 공격 및 부하 테스트는 외부 네트워크가 아닌 격리된 Mininet Lab에서만 수행한다.
- API payload를 변경하면 Analyzer, Backend schema, Frontend 타입과 관련
  문서를 함께 확인한다.
