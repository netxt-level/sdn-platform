# Mininet 토폴로지

## 구성

```text
h1(user)  ─┐
h2(admin) ─┼─ s1 ─┬─ s2 ─┬─ s4 ─ web
h3(attack)─┘      └─ s3 ─┘
```

Mininet과 Open vSwitch는 Ubuntu VM에서 실행하며, 네 스위치는 VM의
`127.0.0.1:6653`에 연결된 Remote Controller를 사용한다. 모든 스위치는
OpenFlow 1.3과 `secure` fail mode를 사용한다.

## 스위치 DPID

| 스위치 | DPID |
|---|---|
| `s1` | `0000000000000001` |
| `s2` | `0000000000000002` |
| `s3` | `0000000000000003` |
| `s4` | `0000000000000004` |

## 호스트 주소

| 호스트 | 역할 | IP | MAC |
|---|---|---|---|
| `h1` | 일반 사용자 | `10.0.0.1/24` | `00:00:00:00:00:01` |
| `h2` | 관리자 | `10.0.0.2/24` | `00:00:00:00:00:02` |
| `h3` | 공격 테스트 | `10.0.0.3/24` | `00:00:00:00:00:03` |
| `web` | 피해 대상 웹 서버 | `10.0.0.100/24` | `00:00:00:00:01:00` |

## 스위치 포트

| 스위치 | 포트 | 연결 대상 |
|---|---:|---|
| `s1` | 1 | `h1` |
| `s1` | 2 | `h2` |
| `s1` | 3 | `h3` |
| `s1` | 4 | `s2` |
| `s1` | 5 | `s3` |
| `s2` | 1 | `s1` |
| `s2` | 2 | `s4` |
| `s3` | 1 | `s1` |
| `s3` | 2 | `s4` |
| `s4` | 1 | `s2` |
| `s4` | 2 | `s3` |
| `s4` | 3 | `web` |

각 호스트 인터페이스는 해당 네임스페이스의 0번 Mininet 포트를 사용한다.

## 검증

Controller를 시작한 후 호스트 주소, 포트 연결, 스위치 연결 상태 및
`pingall`을 자동 검증한다.

```bash
./data-plane/scripts/start.sh
multipass exec sdn-lab -- sudo python3 \
  /home/ubuntu/sdn-platform/data-plane/mininet/topology.py --verify
```

대화형 CLI를 사용하려면 `--verify`를 생략한다.

```bash
multipass exec sdn-lab -- sudo python3 \
  /home/ubuntu/sdn-platform/data-plane/mininet/topology.py
```

현재 Controller는 Table-Miss Rule과 학습 기반 ARP·IPv4 Unicast Flow를
설치한다. Broadcast와 목적지 위치를 모르는 패킷은 Packet-Out으로 전달한다.

## 호스트 위치 학습

Controller는 Packet-In의 Ethernet 출발지와 ARP 또는 IPv4 출발지 주소를
이용해 호스트의 MAC, IPv4, DPID 및 입력 포트를 학습한다. 현재 고정
토폴로지에서 호스트 연결 포트로 지정된 `s1`의 1~3번과 `s4`의 3번만 학습
대상이며, 스위치 간 transit 포트에서 관측한 MAC은 호스트로 등록하지 않는다.

학습 로그는 다음 명령으로 확인한다.

```bash
multipass exec sdn-lab -- docker logs --since 5m sdn-controller
```

`host_learned`, `host_ip_updated`, `host_moved` 로그에는 학습한 MAC, IPv4,
DPID와 입력 포트가 포함된다. 두 호스트의 위치를 모두 알면 목적지별
Unicast Flow 설치에 이 정보를 사용한다.

## Flooding Tree와 Unknown Unicast 정책

Broadcast storm을 막기 위해 활성 링크 그래프에서 최소 신장 트리를
계산하고 해당 트리 포트로만 Flooding한다. 정상 상태의 트리는 다음과 같다.

```text
s3
 |
s1 -- s2 -- s4
```

정상 상태에서는 `s3-s4` 링크가 트리에서 제외된다. `s1-s2`가 down이면
트리를 `s1-s3-s4-s2` 형태로 다시 계산해 ARP와 Unknown Unicast도 Backup
경로를 통과할 수 있게 한다. 각 Packet-Out은 입력 포트를 제외한 현재 트리
포트로만 출력한다.

- ARP Request와 Reply: Flooding Tree로 전달
- IPv4 Broadcast/Multicast: Flooding Tree로 전달
- 아직 목적지 Flow가 없는 IPv4 Unicast: Flooding Tree로 전달
- LLDP, IPv6 및 그 밖의 Ethertype: 현재 전달 대상에서 제외

Broadcast와 아직 위치를 모르는 목적지 패킷은 Table-Miss로 Controller에
전달된다. 출발지와 목적지 위치를 모두 학습하면 Controller가 목적지별
Unicast Flow를 설치한다.

## 가중치 기반 경로 계산

목적지별 Unicast Flow는 활성 링크 그래프에서 Dijkstra 최소 비용 경로를
계산해 설치한다. 정상 상태에서는 비용이 낮은 Primary 경로를 사용한다.

```text
h1/s1 → s1(port 4) → s2(port 2) → s4(port 3) → web
web   → s4(port 1) → s2(port 1) → s1(port 1) → h1
```

동일 스위치에 연결된 호스트는 해당 스위치의 목적지 호스트 포트만 출력
포트로 사용한다. 경로 계산 모듈은 OpenFlow 객체와 분리되어 있으며,
스위치 경로와 각 스위치의 출력 포트만 반환한다.

## 학습 기반 Unicast Flow

두 호스트의 위치가 모두 알려진 ARP 또는 IPv4 Unicast Packet-In을 받으면
현재 최소 비용 경로의 모든 스위치에 순방향과 역방향 Flow를 설치한다. 첫
패킷은 Packet-Out으로 전달하며 이후 패킷은 스위치가 직접 처리한다.

| 항목 | 값 |
|---|---|
| Match | `eth_src`, `eth_dst`, `eth_type` |
| 지원 Ethertype | ARP `0x0806`, IPv4 `0x0800` |
| Action | 계산된 포트로 `OUTPUT` |
| Priority | `100` |
| Idle timeout | `60초` |
| Hard timeout | `0` |
| Cookie prefix | `0x53444e10` |

호스트의 스위치 또는 포트가 변경되면 해당 MAC이 출발지나 목적지인 내부 L2
Flow를 모든 연결 스위치에서 제거한다. Broadcast, 목적지 위치를 모르는
Unicast, IPv6 및 미지원 Ethertype 정책은 이전 단계와 동일하다.

설치된 Rule은 Mininet 실행 중 다음 명령으로 확인한다.

```bash
multipass exec sdn-lab -- sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

## 가중치 기반 Dijkstra 계산

전체 다이아몬드 토폴로지를 포함하는 별도 가중 그래프에서 Dijkstra 최단
경로를 계산한다.

| 링크 | 비용 | 역할 |
|---|---:|---|
| `s1-s2` | 1 | Primary |
| `s2-s4` | 1 | Primary |
| `s1-s3` | 10 | Backup |
| `s3-s4` | 10 | Backup |

정상 상태에서는 총비용 2인 `s1-s2-s4`를 선택한다. Primary 링크가
비활성화되면 총비용 20인 `s1-s3-s4`를 선택할 수 있다. 동일 비용 경로는
전체 DPID 경로를 사전순으로 비교해 결정적으로 선택한다.

Controller는 접속된 스위치와 활성 링크만 포함하는 그래프 스냅샷으로
새 Unicast 경로를 계산한다. 스위치가 연결되면 그래프에 추가되고 연결이
끊기면 해당 스위치와 연결된 링크가 경로 계산 대상에서 제외된다.

Controller는 OpenFlow `PortStatus`의 포트 설정과 `LINK_DOWN`, `BLOCKED`,
삭제 상태를 반영한다. 링크 양쪽 포트가 모두 정상일 때만 활성 링크로
간주한다. 링크 또는 스위치 상태가 바뀌면 Controller Cookie 범위에 해당하는
학습형 L2 Flow를 모든 연결 스위치에서 제거한다. 다음 패킷부터 변경된
그래프와 Flooding Tree를 사용하므로 Primary 장애 시 Backup으로 우회하고,
Primary 복구 후에는 다시 비용이 낮은 경로로 복귀한다.

Mininet CLI에서 다음 순서로 장애와 복구를 확인할 수 있다.

```text
h1 ping -c 2 10.0.0.100
link s1 s2 down
h1 ping -c 2 10.0.0.100
link s1 s2 up
h1 ping -c 2 10.0.0.100
```

Controller 로그의 `topology_link_down`, `topology_link_up`,
`l2_flows_invalidated`, `l2_path_installed` 이벤트로 선택 경로를 확인한다.

## 자동 장애·복구 검증

macOS 프로젝트 루트에서 다음 한 명령으로 전체 인프라 시나리오를 실행한다.

```bash
./data-plane/scripts/verify.sh
```

스크립트는 Controller를 시작한 뒤 VM 안에서 다음 항목을 순서대로 검증한다.

1. OpenFlow 1.3 스위치 4개 연결
2. 고정 Host IP/MAC 및 Switch Port 구성
3. Controller Health의 연결 스위치 수
4. 초기 `pingall`과 Primary `s1-s2-s4` Flow
5. `s1-s2` 장애 후 Backup `s1-s3-s4` Flow
6. 링크 복구 후 Primary 경로 복귀
7. 최종 `pingall` 12/12 수신
8. Mininet 네트워크 및 인터페이스 정리

경로 검증은 ping 결과만 확인하지 않고 `ovs-ofctl dump-flows` 출력의
`h1 → web` IPv4 Flow와 각 스위치 출력 포트를 비교한다. 실패하더라도
시나리오의 `finally`에서 Mininet을 중지하며, 강제 종료 등으로 상태가
남았을 때는 다음 명령으로 정리한다.

```bash
./data-plane/scripts/cleanup.sh
```
