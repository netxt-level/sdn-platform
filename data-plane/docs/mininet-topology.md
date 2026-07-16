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

Broadcast storm을 막기 위해 Flooding은 다음 트리 링크만 사용한다.

```text
s3
 |
s1 -- s2 -- s4
```

`s3-s4` 링크는 Backup 경로용으로 유지하지만 Broadcast와 Unknown Unicast
Flooding에는 사용하지 않는다. 각 Packet-Out은 입력 포트를 제외한 트리
포트로만 출력한다.

- ARP Request와 Reply: Flooding Tree로 전달
- IPv4 Broadcast/Multicast: Flooding Tree로 전달
- 아직 목적지 Flow가 없는 IPv4 Unicast: Flooding Tree로 전달
- LLDP, IPv6 및 그 밖의 Ethertype: 현재 전달 대상에서 제외

Broadcast와 아직 위치를 모르는 목적지 패킷은 Table-Miss로 Controller에
전달된다. 출발지와 목적지 위치를 모두 학습하면 Controller가 목적지별
Unicast Flow를 설치한다.

## Primary 경로 계산

목적지별 Unicast Flow 설치에 사용할 Primary 스위치 그래프는 Flooding
Tree와 동일하다. `s3-s4` 링크는 Backup으로 유지하며 Primary 계산에서는
제외한다.

```text
h1/s1 → s1(port 4) → s2(port 2) → s4(port 3) → web
web   → s4(port 1) → s2(port 1) → s1(port 1) → h1
```

동일 스위치에 연결된 호스트는 해당 스위치의 목적지 호스트 포트만 출력
포트로 사용한다. 경로 계산 모듈은 OpenFlow 객체와 분리되어 있으며,
스위치 경로와 각 스위치의 출력 포트만 반환한다.

## 학습 기반 Unicast Flow

두 호스트의 위치가 모두 알려진 ARP 또는 IPv4 Unicast Packet-In을 받으면
Primary 경로의 모든 스위치에 순방향과 역방향 Flow를 설치한다. 첫 패킷은
Packet-Out으로 전달하며 이후 패킷은 스위치가 직접 처리한다.

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

개별 설정 링크를 양방향으로 활성화·비활성화하는 상태 관리도 제공한다.
다만 현재는 OVS의 실제 포트 down/up 이벤트를 상태 관리에 전달하지 않으므로,
양 끝 스위치가 연결된 설정 링크는 활성 상태로 간주한다. 실제 링크 이벤트
감지, 기존 Flow 무효화 및 Backup 경로 재설치는 다음 체크포인트에서 연결한다.
