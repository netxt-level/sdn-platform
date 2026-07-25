# OpenFlow Controller 인프라

- 상태: Controller·L2·경로 우회·외부 Flow Rule·OVS Meter 구현 및 검증 완료
- 적용 범위: `feat/analyzer-sensor-integration`
- 최종 수정일: 2026-07-20

## 목표와 현재 범위

OS-Ken 기반 OpenFlow 1.3 Controller가 Mininet의 OVS 스위치 4개를 관리하고,
호스트 학습·기본 L2 전달·가중치 기반 경로 선택·링크 장애 우회를 수행한다.
현재 브랜치는 독립 실행 가능한 데이터 플레인 인프라까지만 담당한다.

현재 구현된 기능:

- OpenFlow 1.3 전용 Listener와 확인 가능한 Table-Miss Rule
- Datapath 연결·해제·재연결 관리
- ARP/IPv4 Packet-In과 첫 패킷 Packet-Out
- 고정 접속 포트별 호스트 MAC/IP 검증과 위치 학습
- 활성 토폴로지와 동적 Flooding Tree
- Dijkstra Primary/Backup 경로 계산
- 양방향 학습형 L2 Flow 설치
- PortStatus 기반 링크 down/up 감지
- 토폴로지 변경 시 내부 L2 Flow 무효화
- Controller 재시작 후 OVS 재연결과 호스트 재학습
- Health/Switch REST API
- Backend 요청 Flow Rule 설치 및 Barrier 기반 적용 확인
- Backend 요청 Flow Rule 삭제 및 Barrier 기반 제거 확인
- OVS Meter PKTPS 기반 `RATE_LIMIT`과 timeout cleanup
- 활성 Topology 조회와 L2 경로 재계산 API

현재 브랜치에서 제외하는 기능:

- Backend와 Controller의 만료 상태 재조정

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
│   ├── flow_operations.py
│   ├── hosts.py
│   ├── packet_parser.py
│   ├── routing.py
│   ├── table_miss.py
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
| `flow_operations.py` | Backend 요청 Flow-Mod의 Barrier/Error lifecycle 추적 |
| `table_miss.py` | Barrier/Error/timeout 기반 Table-Miss 상태 추적 |
| `api.py` | Health, switch 조회, 외부 Flow Rule 설치 REST API |
| `config.py` | OpenFlow/REST 포트 환경변수 검증 |

경로 알고리즘과 활성 토폴로지 계산은 OpenFlow 객체와 분리되어 단위 테스트가
가능하다.

## 스위치 연결과 Table-Miss

```text
OVS TCP connect
→ OpenFlow 1.3 negotiation
→ Switch Features
→ Policy Table-Miss와 Forwarding Table-Miss Flow-Mod
→ Barrier Request
→ Barrier Reply 또는 OpenFlow Error
→ MAIN_DISPATCHER Datapath registration
→ transit ports pending
→ Port Description request/reply
→ active topology registration
```

재연결 시 동일 DPID의 최신 Datapath 객체로 교체한다. 이전 연결에서 늦게 온
DEAD_DISPATCHER 이벤트는 현재 연결을 제거하지 않는다. 스위치가 연결되면 모든
transit 포트를 미확인 상태로 두고 OpenFlow Port Description을 요청한다. 링크
양쪽 포트의 현재 상태가 모두 정상으로 확인된 뒤에만 경로 계산에 포함한다.

Controller는 정책과 포워딩을 두 테이블로 분리한다.

| Table | 역할 | Table-Miss |
|---|---|---|
| `0` | 외부 보안 정책, DROP, RATE_LIMIT | `GOTO_TABLE:1` |
| `1` | 학습형 L2 포워딩 | `CONTROLLER` |

정책 Table-Miss cookie는 `0x53444e0000000002`, 포워딩 Table-Miss cookie는
`0x53444e0000000001`이다. 두 Flow-Mod 뒤의 단일 Barrier Reply로 파이프라인
전체 설치를 확인한다.

Table-Miss 상태는 다음 lifecycle을 사용한다.

```text
unknown → pending → installed
                  ↘ failed
```

- `pending`: Flow-Mod와 Barrier Request를 전송한 상태
- `installed`: 일치하는 Barrier Reply를 받고 앞선 Flow-Mod 관련 Error가 없는 상태
- `failed`: 일치하는 OpenFlow Error를 받거나 5초 안에 Barrier Reply가 없는 상태

DPID뿐 아니라 현재 Datapath 객체와 Flow/Barrier XID를 함께 비교한다. 따라서
재연결 전 Datapath에서 늦게 도착한 Reply, Error, disconnect가 새 연결 상태를
변경하지 않는다. 외부 Flow Rule도 별도 registry에서 동일하게 Barrier,
OpenFlow Error 및 disconnect를 추적한다.

## Packet-In과 호스트 학습

Controller는 고정된 호스트 연결 포트에서만 출발지 호스트를 학습하며, 각
포트에 선언된 MAC/IP가 모두 일치하는 ARP·IPv4 패킷만 허용한다.

- `s1`: 1번 `h1`, 2번 `h2`, 3번 `h3`
- `s4`: 3번 `web`

학습 정보는 MAC, IPv4, DPID, 입력 포트다. 선언과 다른 출발지는
`host_spoof_rejected` 경고를 남기고 학습, Flooding, Packet-Out을 수행하지
않는다. 미지원 Ethertype는 호스트 바인딩 경고를 만들지 않고 기존 정책대로
무시한다.

지원 전달 범위:

- ARP `0x0806`
- IPv4 `0x0800`
- Broadcast와 Unknown Unicast의 루프 없는 Packet-Out
- 목적지를 아는 Unicast의 순방향·역방향 Flow

IPv6, LLDP 및 그 밖의 Ethertype는 현재 전달 대상에서 제외한다.

## L2 Flow

| 항목 | 값 |
|---|---|
| Match | `in_port`, `eth_src`, `eth_dst`, `eth_type`, 출발지 IP |
| Table | `1` |
| Priority | `100` |
| Idle timeout | `60초` |
| Hard timeout | `0` |
| Action | 계산된 포트로 `OUTPUT` |
| Cookie prefix | `0x53444e10` |

첫 패킷은 Packet-Out으로 전달하고 같은 통신의 이후 패킷은 OVS Flow가
처리한다. 토폴로지 변경 시 Cookie mask로 Controller 관리 L2 Flow만 제거해
Table-Miss와 향후 외부 Rule 영역을 보존한다.

`in_port`는 출발 호스트 포트와 경로의 이전 스위치 포트로 계산한다. 따라서
h3가 h1의 MAC을 복제해도 s1의 h1 전용 Flow는 입력 포트가 달라 재사용할 수
없다. IPv4는 `ipv4_src`, ARP는 `arp_spa`를 함께 매치해 IP만 바꾸는 우회도
막는다. Table-Miss로 올라온 패킷은 고정 바인딩 검증에서 차단된다.

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
      "table_miss_state": "installed",
      "table_miss_installed": true,
      "table_miss_error": null
    }
  ]
}
```

### `POST /flow-rules`

Backend가 저장한 rule ID를 그대로 받아 안정적인 OpenFlow cookie를 생성한다.
지원 match는 IPv4 source/destination, IP protocol, TCP/UDP port,
ICMP type/code 및 Ethernet source/destination이다. IPv4 전제 필드는
`eth_type=2048`을 자동으로 추가한다.

지원 action:

- `DROP`
- `OUTPUT:<port>`
- `OUTPUT:<인접 switch>` (예: `output:s2`)
- `RATE_LIMIT` (`rate_limit_pps` 필수)

Flow-Mod 전송 후 Barrier Reply를 확인한 경우에만 `APPLIED`를 반환한다.
OpenFlow Error 또는 5초 timeout은 오류 응답에 원인을 포함한다. 동일한
`rule_id`의 `pending`/`installed` 요청은 다시 전송하지 않는다.

`RATE_LIMIT`은 `rate_limit_pps`를 OpenFlow Meter `OFPMF_PKTPS` rate로
그대로 변환한다. Meter의 drop band를 통과한 패킷은 Table 1의 기존 L2
포워딩을 계속 사용하므로 Packet-In hot path를 증가시키지 않는다. 동일한
switch와 rate를 쓰는 rule은 Meter를 안전하게 공유하며, 마지막 rule의
idle/hard timeout이 발생하면 Meter를 삭제한다.

### `GET /flow-rules`

현재 Controller 프로세스가 추적하는 Backend 요청 rule과 적용 상태를 반환한다.
이 목록은 메모리 상태이며 영속 상태의 기준은 PostgreSQL
`sdn_controller.flow_rules`이다.

### `DELETE /flow-rules/{rule_id}`

안정적인 rule cookie와 exact cookie mask를 사용해 Table 0의 해당 정책만
삭제한다. Flow-Mod 뒤의 Barrier Reply 또는 FlowRemoved를 확인한 경우에만
`REMOVED`를 반환한다. 동일 rule의 반복 삭제는 멱등하게 처리한다. Controller
재시작으로 메모리 기록이 없으면 `switch_id` query가 필요하며 Backend가 이를
자동으로 전달한다. `RATE_LIMIT`의 마지막 참조가 제거되면 Meter도 삭제한다.

### `GET /meters`

현재 Controller가 할당한 `meter_id`, DPID, `rate_limit_pps`, 참조 rule ID를
반환한다.

### `GET /topology`

구성된 switch, 현재 활성/비활성 link와 양쪽 port, link cost, 학습된 Host
위치를 반환한다.

### `GET /stats`

`CONTROLLER_STATS_INTERVAL_SECONDS` 주기로 수집한 switch port packet/byte/error
counter와 flow packet/byte/duration counter의 최신 snapshot을 반환한다.

### `POST /paths/recalculate`

요청 본문의 `preferred_path`에 `primary` 또는 `backup`을 전달한다. Controller는
선택 경로의 link cost를 1, 대기 경로의 link cost를 10으로 원자적으로 바꾼 뒤
현재 모든 학습형 L2 Flow를 제거한다. 다음 패킷은 갱신된 활성 topology
snapshot에서 경로를 다시 계산한다. 요청 본문을 생략하면 `primary`를 사용한다.

```json
{
  "preferred_path": "backup"
}
```

Backend의 `GET /api/path/status`는 OpenFlow port counter 사용률이 저장된 혼잡
임계값 이상이고 대기 경로의 사용률이 더 낮을 때 이 API를 호출한다. 복귀 시에는
임계값보다 10% 낮은 히스테리시스를 적용한다.

API 문서 URL은 비활성화되어 있다.

격리된 Mininet 설치 검증:

```bash
sudo python3 data-plane/mininet/scenarios/external_flow.py
sudo python3 data-plane/mininet/scenarios/rate_limit.py
sudo python3 data-plane/mininet/scenarios/automatic_response.py \
  --backend-url http://127.0.0.1:8000
sudo python3 data-plane/mininet/scenarios/analyzer_detection_response.py \
  --backend-url http://127.0.0.1:8000 \
  --analyzer-id analyzer-1
```

이 시나리오는 h1→web ICMP가 정상 전달되는지 먼저 확인한 뒤 s1에 우선순위
500 DROP rule을 설치한다. REST 응답의 `APPLIED`, OVS flow dump의 cookie와
DROP action, ICMP 차단, topology 조회, 경로 재계산, `REMOVED`, 통신 복구를
차례로 검증하고 Mininet 상태를 정리한다.
RATE_LIMIT 시나리오는 1200-byte UDP를 100Mbps로 전송해 baseline을 측정한 뒤
100pps Meter 적용 후 대역폭 감소와 hard timeout 뒤 Meter 정리를 확인한다.
자동 대응 시나리오는 Analyzer 형식 이벤트의 DB/Controller 적용을 확인하고,
Analyzer 탐지 시나리오는 OVS Mirror로 복제한 실제 ICMP Flood를 Analyzer가
탐지해 `security_responses`, `flow_rules`, s1 Meter까지 연결하는지 확인한다.

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

일반 `start.sh`는 VM에 있는 기존 Controller 이미지를 사용한다. 현재 로컬
`data-plane/`을 VM에 동기화하고 이미지를 다시 만들려면 전체 검증 명령을
사용한다. 필요하면 다음처럼 Controller 시작만 강제 재빌드할 수 있다.

```bash
CONTROLLER_REBUILD=true ./data-plane/scripts/start.sh
```

전체 자동 검증:

```bash
./data-plane/scripts/verify.sh
```

`verify.sh`는 시나리오 실행 전에 현재 `data-plane/`만 VM 프로젝트 복사본에
교체 동기화하고 파일별 SHA-256을 비교한다. 일치한 소스로 Controller 이미지를
재빌드하고 컨테이너를 강제 재생성하므로 이전 VM 코드나 이미지로 검증하지
않는다.

자동 검증은 다음을 포함한다.

- `pingall` 12/12
- 연결된 스위치 4개의 Table-Miss Barrier 확인
- Primary와 Backup 출력 포트
- 링크 down/up과 Flow 무효화
- Primary 링크 down 상태의 Controller 재시작과 포트 상태 재동기화
- 재시작 후 Backup 유지와 링크 복구 후 Primary 복귀
- 호스트 재학습과 Primary Flow 복구
- 고정 포트별 MAC/IP 바인딩과 기존 L2 Flow의 `in_port` 검증
- h3의 MAC/IP 위조 차단, 정상 h1 영향 없음, 주소 복구 후 통신
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
- `table_miss_pending`, `table_miss_installed`, `table_miss_failed`
- `port_description_requested`, `port_description_synchronized`
- `topology_switch_activated`
- `topology_link_down`, `topology_link_up`
- `host_learned`, `host_ip_updated`, `host_moved`
- `host_spoof_rejected`
- `l2_path_installed`, `l2_flows_invalidated`
- `external_flow_installed`, `external_flow_failed`
- `external_flow_removed`, `external_flow_expired`, `meter_removed`, `meters_released`

## 알려진 제한사항

- OS-Ken 3.1.1의 eventlet deprecation 경고가 시작 로그에 출력된다.
- 현재 Host 바인딩은 고정 Mininet 토폴로지의 네 호스트 전용이다. 동적 Host
  이동, DHCP 주소 변경, 신규 access 포트 등록은 지원하지 않는다.
- Controller는 timeout 만료와 Meter 정리를 추적하지만 이를 Backend의
  `EXPIRED` 상태로 재조정하는 기능은 아직 없다.
- 링크 비용은 현재 고정 정책값이며 실시간 혼잡도를 반영하지 않는다.
- Controller 재시작 후 기존 L2 Flow 정합성은 자동 검증에서 Flow를 제거하고
  Port Description 기반 Backup 경로와 호스트 재학습을 확인하는 방식이다.
