# OVS Mirror와 Sensor veth

- 상태: `s1` Mirror·tcpdump 구현, secure-default Analyzer 배치 보완 필요
- 최종 수정일: 2026-08-11

## 캡처 구조

```text
h1/h2/h3 -- s1 -- s2/s3 -- s4 -- web
              |
              | ingress Mirror: s1 ports 1,2,3,4,5
              v
       sdn-mirror0 (s1 port 6)
              |
           veth pair
              |
       sdn-sensor0
              |
 Analyzer (host network)
```

`sdn-sensor0`과 `sdn-mirror0`은 VM root network namespace에 생성되는 전용
veth pair다. 두 인터페이스는 IP 주소 없이 `UP`, promiscuous 상태로 유지한다.
`sdn-mirror0`은 Mininet 실행 중에만 `s1`의 OpenFlow port 6으로 연결된다.

Mirror는 `s1` port 1(`h1`), port 2(`h2`), port 3(`h3`), port 4(`s2`),
port 5(`s3`)의 ingress를 선택한다. 따라서 Primary와 Backup 어느 경로에서도
요청과 응답을 각각 한 번씩 복제하며, Mirror output 자체를 다시 source로
선택하지 않는다. 현재 고정 토폴로지에서는 `s1` 내부 host-to-host 트래픽과
`h1/h2/h3`과 `web` 사이 트래픽을 모두 관찰한다.

## 수명주기

- `setup-sensor.sh`는 Sensor veth를 멱등 생성한다. 현재 Multipass bootstrap은
  이 스크립트를 자동 호출하지 않으므로 최초 구성 후 별도로 실행한다. Analyzer가
  안정적으로 인터페이스를 유지하도록 veth 수명주기는 Mininet 실행과 분리한다.
- Mininet이 `s1`을 시작한 뒤 OVS Mirror와 output port 6을 연결한다.
- 정상 시나리오 종료 시 Mirror와 OVS port만 제거하고 veth는 유지한다.
- 전체 `cleanup.sh`는 Analyzer가 실행 중이면 veth를 삭제하지 않고 중지
  명령과 함께 실패한다. Analyzer를 중지한 뒤 다시 실행하면 Mirror, OVS
  port, veth, 잔여 Mininet 상태 순으로 정리한다.
- 같은 이름의 인터페이스가 다른 종류이거나 서로 peer가 아니면 덮어쓰지 않고
  명확한 오류로 중단한다.

## 준비와 대화형 실행

현재는 Multipass bootstrap 뒤에 다음 명령으로 Sensor veth를 준비한다. 기존 VM
복구나 단독 진단에서도 같은 명령을 사용할 수 있다.

```bash
./data-plane/scripts/sync-vm.sh
./data-plane/scripts/setup-sensor.sh
```

Controller를 시작하고 Mirror가 연결된 Mininet CLI를 연다.

```bash
./data-plane/scripts/start.sh
multipass exec sdn-lab -- sudo python3 \
  /home/ubuntu/sdn-platform/data-plane/mininet/topology.py \
  --sensor-mirror
```

다른 인터페이스명이나 포트가 필요한 환경은 `topology.py`의 다음 옵션으로
설정할 수 있다.

```text
--sensor-interface
--mirror-interface
--mirror-switch
--mirror-name
--mirror-port
--mirror-source-port  # 반복 가능
```

확정 기본값은 `sdn-sensor0`, `sdn-mirror0`, `s1`,
`sdn-analyzer-mirror`, output port 6, source ports 1·2·3·4·5다.

## 자동 캡처 검증

전체 data-plane 검증에는 `mirror_capture.py`가 포함된다.

```bash
./data-plane/scripts/verify.sh
```

Mirror 단계만 다시 실행하려면 Controller를 먼저 시작한 뒤 다음을 사용한다.

```bash
multipass exec sdn-lab -- sudo python3 -u \
  /home/ubuntu/sdn-platform/data-plane/mininet/scenarios/mirror_capture.py \
  --controller-host 127.0.0.1 \
  --controller-port 6653
```

시나리오는 다음을 확인한다.

1. `setup-sensor.sh` 또는 시나리오 준비 후 veth pair가 존재하고 두 인터페이스가 `UP`, promiscuous
   상태인지 확인한다.
2. `sdn-mirror0`이 s1 port 6인지, Mirror source가 1·2·3·4·5인지 OVSDB UUID로
   확인한다.
3. Primary `s1-s2-s4`에서 ICMP Echo Request와 Reply를 `tcpdump`로 확인한다.
4. `s1-s2`를 내린 뒤 Backup `s1-s3-s4`에서도 양방향 ICMP를 확인한다.
5. Mirror/OVS port가 제거되고 Sensor veth만 유지되는지 확인한다.

## 운영 진단과 정리

```bash
multipass exec sdn-lab -- sudo ip -details link show sdn-sensor0
multipass exec sdn-lab -- sudo ip -details link show sdn-mirror0
multipass exec sdn-lab -- sudo ovs-vsctl list Mirror
multipass exec sdn-lab -- sudo ovs-ofctl -O OpenFlow13 show s1
multipass exec sdn-lab -- sudo tcpdump -nn -i sdn-sensor0 icmp
```

Mirror만 제거하고 veth를 유지할 때:

```bash
multipass exec sdn-lab -- sudo python3 \
  /home/ubuntu/sdn-platform/data-plane/mininet/sensor.py detach
```

전체 정리:

```bash
# Analyzer가 실행 중이면 먼저 중지한다.
multipass exec sdn-lab -- docker stop sdn-analyzer
./data-plane/scripts/cleanup.sh
```

Analyzer가 실행 중인 상태에서 `cleanup.sh`를 호출하면 Sensor veth를 유지하고
중지 절차를 안내한 뒤 실패해야 한다.

Analyzer 연결 단계에서는 VM Analyzer를 host network로 실행하고
`ANALYZER_INTERFACE=sdn-sensor0`을 지정한다. `analyzer_detection_response.py`
시나리오는 실제 OVS 복제, ICMP Flood 탐지, Security Event/Response와 Flow Rule
저장, Controller의 s1 Meter 설치까지 종단 간 검증한다.

루트 Compose와 dataplane overlay를 병합하면 host network와 Analyzer API Key,
Outbox volume을 함께 적용할 수 있다. 현재 bootstrap은 overlay만 사용하므로
이 병합 또는 스크립트 보완이 필요하다. 또한 종단 간 시나리오의 Backend 조회
요청과 기본 `verify.sh`의 Controller REST 시나리오는 아직 secure-default API
Key를 모두 전달하지 않는다. 인증을 활성화한 최신 환경에서는 Key 전달을
보완한 뒤 실행해야 한다.
