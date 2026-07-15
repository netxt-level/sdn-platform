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

Controller를 시작한 후 호스트 주소, 포트 연결 및 스위치 연결 상태를
자동 검증한다.

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

현재 Controller는 Table-Miss Rule까지만 설치한다. 호스트와 스위치 구성이
정상이더라도 ARP 및 L2 전달 구현 전에는 `pingall` 성공을 기대하지 않는다.

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
DPID와 입력 포트가 포함된다. 이 단계는 위치 학습만 수행하며 Packet-Out이나
전달 Flow는 아직 설치하지 않는다.
