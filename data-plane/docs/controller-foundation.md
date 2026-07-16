# OpenFlow Controller 인프라

- 상태: Controller·L2·경로 우회 구현 및 자동 검증 완료
- 적용 범위: `feat/data-plane-infrastructure`
- 최종 수정일: 2026-07-16

## 목표와 현재 범위

OS-Ken 기반 OpenFlow 1.3 Controller가 Mininet의 OVS 스위치 4개를 관리하고,
호스트 학습·기본 L2 전달·가중치 기반 경로 선택·링크 장애 우회를 수행한다.
현재 브랜치는 독립 실행 가능한 데이터 플레인 인프라까지만 담당한다.

현재 구현된 기능:

- OpenFlow 1.3 전용 Listener와 Table-Miss Rule
- Datapath 연결·해제·재연결 관리
- ARP/IPv4 Packet-In과 첫 패킷 Packet-Out
- 호스트 MAC/IP/DPID/Port 학습
- 활성 토폴로지와 동적 Flooding Tree
- Dijkstra Primary/Backup 경로 계산
- 양방향 학습형 L2 Flow 설치
- PortStatus 기반 링크 down/up 감지
- 토폴로지 변경 시 내부 L2 Flow 무효화
- Controller 재시작 후 OVS 재연결과 호스트 재학습
- 읽기 전용 Health/Switch REST API

현재 브랜치에서 제외하는 기능:

- Backend Flow Rule 적용과 상태 동기화
- `POST /flows`, `DELETE /flows/{id}`, `GET /topology`
- OVS Meter 기반 `RATE_LIMIT`
- Analyzer OVS Mirror와 Mininet 트래픽 캡처
- 보안 이벤트 기반 DROP/Rate Limit 종단 간 대응

위 기능은 인프라 브랜치를 기반으로 별도 연동 브랜치에서 구현한다.

## 기술 구성

| 항목 | 값 |
|---|---|
| Controller Framework | OS-Ken `3.1.1` |
| Python | `3.11` |
| REST API | FastAPI/Uvicorn |
| OpenFlow | `1.3` 전용 |
| OpenFlow Port | `6653` |
| REST Port | `8080` |
| 실행 위치 | Multipass Ubuntu VM의 Docker 컨테이너 |
| Docker Network | `host` |

Controller와 Mininet은 같은 Linux VM에서 실행한다. OVS Remote Controller는
기본적으로 `127.0.0.1:6653`을 사용하며 포트는 환경변수와 실행 인자로
변경할 수 있다.

## 실행 구조

```text
Development host
├── Backend / Frontend / Databases
└── data-plane 운영 스크립트
          │ Multipass exec
          ▼
Ubuntu VM
├── sdn-controller (Docker host network)
│   ├── OS-Ken OpenFlow :6653
│   └── FastAPI REST :8080
├── Mininet hosts
├── Open vSwitch s1~s4
└── sdn-analyzer (캡처 경로 연동 전)
```

Packet-In 처리 경로에서는 Backend HTTP 요청을 수행하지 않는다. Controller는
스위치·토폴로지·경로 상태를 관리하고, 외부 서비스 연동은 후속 브랜치에서
별도 Queue/Retry 구조로 추가한다.

## 디렉터리와 모듈

```text
data-plane/controller/
├── app/
│   ├── api.py
│   ├── config.py
│   ├── controller.py
│   ├── datapaths.py
│   ├── flow_manager.py
│   ├── hosts.py
│   ├── packet_parser.py
│   ├── routing.py
│   └── topology.py
├── tests/
├── Dockerfile
└── requirements.txt
```

| 모듈 | 책임 |
|---|---|
| `controller.py` | OS-Ken 이벤트, Packet-In, PortStatus, 경로 설치 |
| `datapaths.py` | 최신 Datapath 등록과 stale disconnect 방지 |
| `hosts.py` | 호스트 MAC/IP/접속 위치 학습 |
| `packet_parser.py` | Ethernet, ARP, IPv4 메타데이터 추출 |
| `topology.py` | 고정 포트 맵, 활성 스위치·링크, Flooding Tree |
| `routing.py` | 순수 Dijkstra와 출력 포트 계산 |
| `flow_manager.py` | Table-Miss, L2 Flow, Packet-Out, Flow 삭제 메시지 |
| `api.py` | `/health`, `/switches` 읽기 전용 API |
| `config.py` | OpenFlow/REST 포트 환경변수 검증 |

경로 알고리즘과 활성 토폴로지 계산은 OpenFlow 객체와 분리되어 단위 테스트가
가능하다.

## 스위치 연결과 Table-Miss

```text
OVS TCP connect
→ OpenFlow 1.3 negotiation
→ Switch Features
→ Table-Miss Flow-Mod
→ MAIN_DISPATCHER Datapath registration
→ transit ports pending
→ Port Description request/reply
→ active topology registration
```

재연결 시 동일 DPID의 최신 Datapath 객체로 교체한다. 이전 연결에서 늦게 온
DEAD_DISPATCHER 이벤트는 현재 연결을 제거하지 않는다. 스위치가 연결되면 모든
transit 포트를 미확인 상태로 두고 OpenFlow Port Description을 요청한다. 링크
양쪽 포트의 현재 상태가 모두 정상으로 확인된 뒤에만 경로 계산에 포함한다.

Table-Miss Rule:

| 항목 | 값 |
|---|---|
| Table | `0` |
| Priority | `0` |
| Match | 전체 |
| Action | `CONTROLLER` |
| Idle/Hard timeout | `0 / 0` |
| Cookie | `0x53444e0000000001` |

현재 API의 `table_miss_installed`는 Switch Features 처리 시 Flow-Mod를
전송했다는 의미다. Barrier Reply 기반 설치 확인과 외부 Rule lifecycle은
후속 Flow Rule 관리 단계의 범위다.

## Packet-In과 호스트 학습

Controller는 고정된 호스트 연결 포트에서만 출발지 호스트를 학습한다.

- `s1`: 1번 `h1`, 2번 `h2`, 3번 `h3`
- `s4`: 3번 `web`

학습 정보는 MAC, IPv4, DPID, 입력 포트다. 호스트가 이동하면 해당 MAC이
출발지 또는 목적지인 Controller 관리 L2 Flow를 모든 연결 스위치에서
삭제한다.

지원 전달 범위:

- ARP `0x0806`
- IPv4 `0x0800`
- Broadcast와 Unknown Unicast의 루프 없는 Packet-Out
- 목적지를 아는 Unicast의 순방향·역방향 Flow

IPv6, LLDP 및 그 밖의 Ethertype는 현재 전달 대상에서 제외한다.

## L2 Flow

| 항목 | 값 |
|---|---|
| Match | `eth_src`, `eth_dst`, `eth_type` |
| Priority | `100` |
| Idle timeout | `60초` |
| Hard timeout | `0` |
| Action | 계산된 포트로 `OUTPUT` |
| Cookie prefix | `0x53444e10` |

첫 패킷은 Packet-Out으로 전달하고 같은 통신의 이후 패킷은 OVS Flow가
처리한다. 토폴로지 변경 시 Cookie mask로 Controller 관리 L2 Flow만 제거해
Table-Miss와 향후 외부 Rule 영역을 보존한다.

## 경로와 장애 우회

정상 경로 비용:

```text
s1 --1-- s2 --1-- s4   total=2
s1 -10-- s3 -10-- s4   total=20
```

Dijkstra는 정상 상태에서 `s1-s2-s4`를 선택한다. 동일 비용이면 전체 DPID
경로를 사전순으로 비교한다. `PortStatus`가 `PORT_DOWN`, `LINK_DOWN`,
`BLOCKED` 또는 Port DELETE를 알리면 링크 끝점 상태를 갱신한다. 양쪽 끝점이
정상일 때만 활성 링크로 사용한다.

Controller 재시작 시에도 스위치별 Port Description을 다시 조회한다. 따라서
재시작 전에 내려가 있던 링크를 정상으로 가정하지 않고 Backup 경로 상태를
유지한다.

링크 상태가 바뀌면 기존 L2 Flow를 삭제한다. 다음 패킷은 변경된 그래프에서
경로를 다시 계산하므로 Primary 장애 시 `s1-s3-s4`로 우회하고, 복구 시 다시
Primary로 돌아간다. Broadcast/ARP도 활성 그래프의 최소 신장 트리를 사용해
Backup 경로를 통과할 수 있다.

## REST API

### `GET /health`

```json
{
  "status": "ready",
  "openflow_version": "1.3",
  "openflow_port": 6653,
  "rest_port": 8080,
  "connected_switches": 4
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

현재 REST API는 읽기 전용이며 API 문서 URL은 비활성화되어 있다.

## 환경변수

```env
CONTROLLER_OPENFLOW_PORT=6653
CONTROLLER_REST_HOST=0.0.0.0
CONTROLLER_REST_PORT=8080
```

OpenFlow bind host는 OS-Ken 실행기가 관리한다. Backend 주소나 인증 정보는
현재 Controller에서 사용하지 않는다.

## 실행과 검증

```bash
./data-plane/scripts/start.sh
curl "http://<VM_IP>:8080/health"
curl "http://<VM_IP>:8080/switches"
```

전체 자동 검증:

```bash
./data-plane/scripts/verify.sh
```

자동 검증은 다음을 포함한다.

- `pingall` 12/12
- Primary와 Backup 출력 포트
- 링크 down/up과 Flow 무효화
- Primary 링크 down 상태의 Controller 재시작과 포트 상태 재동기화
- 재시작 후 Backup 유지와 링크 복구 후 Primary 복귀
- 호스트 재학습과 Primary Flow 복구
- TCLink 지연과 `iperf3` 대역폭 제한
- 종료 후 잔여 OVS 브리지 확인

Controller 단위 테스트는 의존성이 설치된 이미지에서 실행한다.

```bash
multipass exec sdn-lab -- docker run --rm \
  -v /home/ubuntu/sdn-platform/data-plane/controller/tests:/app/tests \
  sdn-platform-controller \
  python -m unittest discover -s tests
```

## 운영 로그

```bash
multipass exec sdn-lab -- docker logs --since 5m sdn-controller
```

주요 이벤트:

- `switch_connected`, `switch_reconnected`, `switch_disconnected`
- `port_description_requested`, `port_description_synchronized`
- `topology_switch_activated`
- `topology_link_down`, `topology_link_up`
- `host_learned`, `host_ip_updated`, `host_moved`
- `l2_path_installed`, `l2_flows_invalidated`

## 알려진 제한사항

- OS-Ken 3.1.1의 eventlet deprecation 경고가 시작 로그에 출력된다.
- REST API는 실제 Flow 설치/삭제 명령을 아직 제공하지 않는다.
- 외부 Flow Rule acknowledgement와 lifecycle은 구현하지 않았다.
- 링크 비용은 현재 고정 정책값이며 실시간 혼잡도를 반영하지 않는다.
- Controller 재시작 후 기존 L2 Flow 정합성은 자동 검증에서 Flow를 제거하고
  Port Description 기반 Backup 경로와 호스트 재학습을 확인하는 방식이다.
- Analyzer는 아직 Mininet Mirror 인터페이스에 연결되지 않았다.
