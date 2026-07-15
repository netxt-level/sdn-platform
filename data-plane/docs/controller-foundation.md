# OpenFlow Controller Foundation

- 상태: 구현 전 최종 제안
- 적용 단계: Milestone 1 — Controller starts and one switch connects
- 최종 수정일: 2026-07-15

## 목표

OpenFlow 1.3 Controller를 컨테이너 서비스로 추가하고 Mininet이 생성한 OVS 스위치 한 대를 연결한다. 스위치 연결 상태를 관리하고 Table-Miss Rule을 설치하며, REST API와 운영 로그를 통해 상태를 확인할 수 있어야 한다.

이번 단계는 전체 네트워크 통신을 구현하는 단계가 아니다. MAC 학습, ARP 처리, L2 전달, 경로 계산은 Controller 기반과 단일 스위치 연결이 검증된 이후 구현한다.

## 기술 결정

| 항목 | 선택 |
|---|---|
| Controller Framework | OS-Ken 3.1.1 |
| Python | 3.11 |
| REST API | FastAPI |
| OpenFlow | 1.3 전용 |
| OpenFlow Port | 6653 |
| REST Port | 8080 |
| 실행 위치 | Multipass Ubuntu VM의 Docker 컨테이너 |
| 네트워크 모드 | `host` |

OS-Ken 3.1.1은 독립 Controller 실행기인 `osken-manager`를 제공하는 계열이면서 Python 3.11을 지원한다. 최신 OS-Ken 4.x는 실행기가 제거된 라이브러리 중심 배포이므로 이번 MVP에는 사용하지 않는다.

의존성은 재현 가능한 빌드를 위해 정확한 버전으로 고정한다. 최신 OS-Ken으로 전환할 때는 별도 실행기 구현과 호환성 검증을 독립 작업으로 수행한다.

## 실행 구조

```text
macOS/Windows Docker
├── Backend
├── Frontend
└── Databases
       ▲
       │ HTTP
       │
Ubuntu Multipass VM
├── Controller container (host network)
│   ├── OS-Ken event loop
│   │   ├── OpenFlow :6653
│   │   ├── switch connection events
│   │   └── Flow-Mod / Barrier processing
│   └── FastAPI thread
│       ├── GET /health
│       └── GET /switches
├── Analyzer container (host network)
├── Mininet
└── Open vSwitch
```

Mininet과 Controller가 동일한 Linux VM 네트워크를 사용하므로 OVS는 `127.0.0.1:6653`으로 연결한다. 외부 주소나 Docker bridge IP를 하드코딩하지 않는다.

## 디렉터리 구조

```text
data-plane/controller/
├── app/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── controller.py
│   ├── datapaths.py
│   ├── flow_manager.py
│   ├── api.py
│   └── logging_config.py
├── tests/
│   ├── test_config.py
│   ├── test_datapaths.py
│   ├── test_table_miss.py
│   └── test_api.py
├── Dockerfile
└── requirements.txt
```

`topology.py`와 `routing.py`는 아직 만들지 않는다. 사용되지 않는 빈 구현을 미리 추가하지 않고 해당 기능을 구현하는 단계에서 생성한다.

## 모듈 책임

### `main.py`

- 환경변수 검증
- OS-Ken 실행 인자 구성
- Controller 애플리케이션 실행
- 종료 신호 처리

### `config.py`

- OpenFlow/REST 주소와 포트
- 로그 레벨
- 환경변수 타입과 범위 검증
- 개발자별 주소 하드코딩 방지

### `controller.py`

- OpenFlow 1.3 버전 고정
- Switch Features 이벤트 처리
- Datapath 연결·해제 이벤트 처리
- Barrier Reply 및 OpenFlow Error 처리
- Packet-In hot path에서 HTTP 호출 금지

### `datapaths.py`

- DPID 기준 Datapath 등록
- 재연결 시 최신 Datapath 객체로 교체
- 오래된 연결의 해제 이벤트가 새 연결을 제거하지 않도록 객체 비교
- REST API용 읽기 전용 Switch 상태 제공

### `flow_manager.py`

- Table-Miss Rule 생성
- Controller 예약 Cookie 관리
- Flow-Mod 전송
- Barrier Request 발행과 설치 확인 상태 연결

### `api.py`

- Controller 상태 조회
- 연결된 Switch 목록 조회
- OpenFlow 객체 직접 접근 금지
- 공유 상태 접근 시 Lock 또는 thread-safe snapshot 사용

### `logging_config.py`

- JSON 구조화 로그
- Switch 연결·해제 로그
- Table-Miss 설치 요청·확인·실패 로그
- DPID, OpenFlow XID, Cookie 등 진단 필드 포함

## 스위치 연결 처리

```text
OVS TCP connection
  → OpenFlow 1.3 negotiation
  → Switch Features received
  → Datapath registered
  → Table-Miss Flow-Mod sent
  → Barrier Request sent
  → Barrier Reply received
  → Table-Miss status confirmed
```

연결 상태는 OS-Ken의 Dispatcher 이벤트를 기준으로 관리한다.

```text
MAIN_DISPATCHER
  → register or replace the Datapath for the DPID

DEAD_DISPATCHER
  → remove only when the disconnected object is still current
```

## Table-Miss Rule

```text
table=0
priority=0
match=all
action=CONTROLLER
idle_timeout=0
hard_timeout=0
cookie=reserved controller cookie
```

동일한 Table, Match, Priority, Cookie를 사용해 재연결 시 규칙이 비정상적으로 중복되지 않게 한다. Flow-Mod 직후 Barrier Request를 전송하며 Barrier Reply가 확인되기 전에는 설치 완료로 기록하지 않는다.

이번 단계의 Packet-In 처리는 전달 결정을 수행하지 않는다. 패킷 전달, MAC 학습 및 Packet-Out은 L2 Forwarding 단계에서 구현한다.

## REST와 OpenFlow 스레드 경계

```text
FastAPI thread
  ↕ thread-safe snapshots / command queue
OS-Ken event loop
```

FastAPI 스레드는 Datapath에 직접 `send_msg()`를 호출하지 않는다. 이번 단계의 API는 읽기 전용 상태만 제공한다. 향후 Flow Rule 변경 API는 명령 Queue에 요청을 넣고 OS-Ken 이벤트 루프가 이를 소비하도록 확장한다.

Packet-In 처리 중 Backend나 다른 외부 서비스에 동기 HTTP 요청을 보내지 않는다.

## REST API

### `GET /health`

Controller 프로세스와 OpenFlow Listener가 정상이면 Switch 연결 여부와 관계없이 HTTP 200을 반환한다.

```json
{
  "status": "ready",
  "openflow_version": "1.3",
  "openflow_port": 6653,
  "rest_port": 8080,
  "connected_switches": 0
}
```

### `GET /switches`

```json
{
  "switches": [
    {
      "dpid": "0000000000000001",
      "state": "connected",
      "table_miss_installed": true
    }
  ]
}
```

이번 단계에서는 `POST /flows`, `DELETE /flows/{id}`, `GET /topology`를 노출하지 않는다.

## 환경변수

```env
CONTROLLER_OPENFLOW_HOST=0.0.0.0
CONTROLLER_OPENFLOW_PORT=6653
CONTROLLER_REST_HOST=0.0.0.0
CONTROLLER_REST_PORT=8080
CONTROLLER_LOG_LEVEL=INFO
```

Backend 주소는 아직 사용하지 않으므로 이번 단계에 추가하지 않는다. Controller와 Backend를 실제로 연동하는 단계에서 timeout, retry 및 인증 설정과 함께 추가한다.

## Docker Compose 적용

기존 루트 `docker-compose.yml`에 Controller 서비스를 최소 추가한다. 기존 서비스 정의와 API 계약은 변경하지 않는다.

기본 하이브리드 프로필에서는 다음과 같이 배치한다.

```text
Development host
  Backend, Frontend, PostgreSQL, InfluxDB, Elasticsearch

Ubuntu VM
  Controller, Analyzer, Mininet, Open vSwitch
```

Controller 컨테이너는 VM의 `host` 네트워크를 사용한다. 기본 하이브리드 부트스트랩은 VM에서 Controller와 Analyzer만 실행해야 하며 Backend와 데이터베이스 컨테이너를 VM에 시작하지 않는다.

## 단일 스위치 통합 검증

전체 토폴로지를 만들기 전에 임시 Switch 한 대만 연결한다.

```text
Mininet
└── s1 (DPID 0000000000000001)
      └── tcp:127.0.0.1:6653, OpenFlow 1.3
```

검증 순서:

1. Controller 컨테이너를 시작한다.
2. `GET /health`가 HTTP 200인지 확인한다.
3. Mininet으로 `s1`을 생성하고 OpenFlow 1.3을 강제한다.
4. `GET /switches`에서 DPID를 확인한다.
5. `ovs-ofctl -O OpenFlow13 dump-flows s1`로 Table-Miss Rule을 확인한다.
6. OVS의 Controller 연결을 해제하고 다시 연결한다.
7. 연결 상태가 정상 복구되고 Table-Miss Rule이 한 개만 존재하는지 확인한다.
8. Controller를 재시작하고 OVS가 재연결되는지 확인한다.

이번 단계에서는 L2 전달을 구현하지 않으므로 `pingall` 성공을 완료 조건으로 사용하지 않는다.

## 단위 테스트

- 환경변수 기본값과 잘못된 포트 검증
- Datapath 최초 등록
- 동일 DPID 재연결 시 객체 교체
- 오래된 Datapath 해제 이벤트 무시
- Table-Miss Match, Priority, Action, Cookie 검증
- Health API 응답
- Switch API snapshot 응답

## 이번 단계 제외 범위

- 전체 `s1~s4` 토폴로지
- 호스트 MAC/IP 학습
- ARP 및 Broadcast 처리
- L2 전달 및 Packet-Out
- Dijkstra 경로 계산
- Primary/Backup 경로 우회
- Backend Flow Rule 연동
- OVS Meter 기반 Rate Limit
- Analyzer OVS Mirror
- 공격 및 부하 테스트

## 완료 기준

- Controller 컨테이너가 정상 실행된다.
- Controller Health API가 HTTP 200을 반환한다.
- OVS Switch가 OpenFlow 1.3으로 연결된다.
- 연결된 DPID가 REST API와 로그에서 확인된다.
- Table-Miss Rule 설치가 Barrier Reply로 확인된다.
- Switch 또는 Controller 재연결 후 규칙이 비정상적으로 중복되지 않는다.
- Controller 단위 테스트와 단일 Switch 통합 검증이 통과한다.

## 공식 참고 자료

- [OS-Ken 3.1.1](https://pypi.org/project/os-ken/3.1.1/)
- [OS-Ken OpenFlow 1.3 Reference](https://docs.openstack.org/os-ken/latest/ofproto_v1_3_ref.html)
- [OS-Ken Application API](https://docs.openstack.org/os-ken/latest/os_ken_app_api.html)
- [OS-Ken 2026.1 Release Notes](https://docs.openstack.org/releasenotes/os-ken/2026.1.html)
