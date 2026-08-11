# 서버 권한 상승 검증 시나리오

- 시나리오 ID: `SDN-PE-01`
- 상태: 권한 상승 증명은 수동, 침해 후 네트워크 탐지·대응 비교는 자동화
- 기준일: 2026-08-11
- 대상: 격리된 `sdn-lab` Multipass VM과 Mininet 데이터 플레인
- 공격 출발지: `h3` (`10.0.0.3`)
- 웹 대상: `web` (`10.0.0.100:80`)
- 권한 상승 대상 계정: `sdn-pe-lab-svc`

## 목적

웹 서버 침해 뒤 서비스 계정의 권한이 root로 상승하는 상황을 안전하게
재현하고, 네트워크 증거와 서버 내부 증거가 서로 다른 관측 지점에서
수집되는지 확인한다.

이 시나리오는 실제 취약점 악용이나 root shell 획득을 수행하지 않는다.
root 소유의 고정 스크립트를 제한된 `sudo` 규칙으로 한 번 실행해
`/run/sdn-pe-lab/proof.json`을 만드는 것으로 권한 경계 통과를 증명한다.
스크립트는 인자를 거부하며 다른 명령을 실행하는 기능이 없다.

## 현재 플랫폼에서 검증하는 범위

```text
h3
 │  1. 제한된 정찰 및 HTTP 접근
 ▼
OVS Mirror ──> Analyzer ──> PORT_SCAN 이벤트
 │
 ▼
web / Mutillidae
 │  2. 초기 foothold는 시뮬레이션
 ▼
sdn-pe-lab-svc
 │  3. 의도적으로 잘못 부여한 단일 sudo 권한 사용
 ▼
root proof file ──> sudo/auth 로그
```

현재 Analyzer는 네트워크 패킷 기반 `PORT_SCAN`, `ICMP_FLOOD`와 보호 서버의
`SERVER_EGRESS`, `LATERAL_MOVEMENT`, `DATA_EXFILTRATION`, `C2_BEACON`을
탐지한다. 서버 내부의 `sudo`, 프로세스 UID 변경, 파일 생성은 OVS Mirror에서
보이지 않는다. 따라서 합격 판정은 다음 두 증거를 결합한다.

- 네트워크 증거: `sdn-sensor0` PCAP, Analyzer의 `PORT_SCAN` 이벤트
- 호스트 증거: `sudo` 인증 로그, root 소유 proof 파일

`PRIVILEGE_ESCALATION` 같은 미지원 이벤트를 `/api/security/events`에
인위적으로 넣어 탐지 성공으로 처리하지 않는다. 호스트 감사 이벤트를
플랫폼에 수집하는 기능은 별도 탐지 확장 범위다.

## 안전 조건

- `sdn-lab` 외부의 호스트, 컨테이너, IP에는 실행하지 않는다.
- Mutillidae는 VM의 `127.0.0.1`과 Mininet의 `web` 주소로만 노출한다.
- 실행 전에 VM snapshot 또는 재생성 가능한 기준 상태를 준비한다.
- 기존에 `sdn-pe-lab-svc` 사용자나 `/etc/sudoers.d/sdn-pe-lab` 파일이
  존재하면 덮어쓰지 말고 중단한다.
- root shell, reverse shell, 커널 exploit, 컨테이너 escape는 사용하지 않는다.
- 결과 수집 후 시나리오 계정, `sudoers` 규칙, proof 파일을 모두 제거한다.

## 사전 준비

프로젝트를 VM에 동기화하고 Mutillidae를 시작한다.

```bash
./data-plane/scripts/sync-vm.sh
./data-plane/scripts/start-mutillidae.sh --initialize
./data-plane/scripts/start.sh
```

Controller, Backend, Analyzer가 준비된 상태에서 Sensor Mirror와 Mutillidae
proxy가 포함된 Mininet CLI를 연다.

현재 bootstrap은 기본 Analyzer를 `sdn-sensor0`에 연결하고 병합 Compose로
실행한다. 과거 bootstrap으로 만든 VM을 재사용해 캡처 NIC가 다르면
`./data-plane/scripts/setup-sensor.sh`와 `data-plane/docs/vm-setup.md`의 수동
재생성 절차로 복구한다.

```bash
multipass exec sdn-lab -- sudo python3 \
  /home/ubuntu/sdn-platform/data-plane/mininet/topology.py \
  --sensor-mirror \
  --mutillidae-proxy
```

별도 터미널에서 시작 시각과 구성요소 상태를 기록한다.

```bash
date -u +'%Y-%m-%dT%H:%M:%SZ'
multipass exec sdn-lab -- curl --fail --silent \
  http://127.0.0.1:8080/health
multipass exec sdn-lab -- docker ps --format \
  'table {{.Names}}\t{{.Status}}'
```

### 탐지만/자동 대응 비교 자동화

`LATERAL_MOVEMENT`는 구현된 다음 스크립트로 같은 트래픽을 두 모드에서 비교할 수
있다. 스크립트는 `web`에서 h1과 h2로 30초 안에 TCP 연결 3건을 만들며,
실행마다 Mininet과 Mirror를 생성하고 종료 시 정리한다. 외부 주소는 사용하지
않는다.

각 실행 사이에는 Analyzer를 재생성해 이벤트 중복 억제와 탐지기 메모리
상태를 초기화한다.

```bash
multipass exec sdn-lab -- env \
  COMPOSE_IGNORE_ORPHANS=true \
  BACKEND_BASE_URL=http://192.168.252.1:8000 \
  ANALYZER_INTERFACE=sdn-sensor0 \
  docker compose \
  -f /home/ubuntu/sdn-platform/docker-compose.yml \
  -f /home/ubuntu/sdn-platform/docker-compose.dataplane.yml \
  up -d --force-recreate --no-deps analyzer
```

탐지만 실행:

```bash
multipass exec sdn-lab -- sudo env \
  ADMIN_API_KEY='<ADMIN_API_KEY>' \
  python3 \
  /home/ubuntu/sdn-platform/data-plane/mininet/scenarios/server_behavior_response.py \
  --mode detect \
  --backend-url http://192.168.252.1:8000
```

자동 대응 실행 전 Analyzer를 다시 재생성한 뒤 같은 스크립트의 모드만
바꾼다.

```bash
multipass exec sdn-lab -- sudo env \
  ADMIN_API_KEY='<ADMIN_API_KEY>' \
  python3 \
  /home/ubuntu/sdn-platform/data-plane/mininet/scenarios/server_behavior_response.py \
  --mode respond \
  --backend-url http://192.168.252.1:8000
```

합격 기준:

- `detect`: `LATERAL_MOVEMENT` 이벤트는 `detected`지만 `flow_id`,
  `controller_rule_id`는 `null`이다. reconciliation 주기 후에도 연계 Flow가
  생성되지 않는다.
- `respond`: 같은 이벤트가 `blocked`, DROP Flow가 `APPLIED`이고 보호 서버의
  ingress 스위치 `s4`에서 Controller rule ID와 Barrier 응답이 반환된다.
- 두 실행 모두 종료 후 Mininet 브리지와 OVS Mirror가 남지 않는다.

## 1. 정상 기준선

Mininet CLI에서 정상 사용자인 `h1`의 HTTP 요청을 확인한다.

```text
h1 curl -fsS -H 'Host: mutillidae.localhost' http://10.0.0.100/ -o /dev/null
```

별도 터미널에서 Sensor가 요청과 응답을 관찰하는지 확인한다.

```bash
multipass exec sdn-lab -- sudo timeout 10 \
  tcpdump -nn -i sdn-sensor0 \
  'host 10.0.0.100 and tcp port 80'
```

합격 기준:

- `h1` 요청이 성공한다.
- Sensor에 `h1`과 `web` 사이의 양방향 TCP 트래픽이 보인다.
- 의도하지 않은 보안 이벤트나 Flow Rule이 생성되지 않는다.

## 2. 제한된 정찰과 웹 접근

Mininet CLI에서 `h3`가 `web`의 25개 TCP 포트에 제한된 연결을 시도한 뒤
정상 HTTP 요청을 한 번 보낸다. 이 명령은 격리 주소 하나만 대상으로 한다.

```text
h3 sh -c 'for port in $(seq 1 25); do timeout 1 bash -c "echo >/dev/tcp/10.0.0.100/${port}" >/dev/null 2>&1 & done; wait; true'
h3 curl -fsS -H 'Host: mutillidae.localhost' http://10.0.0.100/ -o /dev/null
```

합격 기준:

- PCAP에 `10.0.0.3 -> 10.0.0.100` TCP SYN과 HTTP 요청이 남는다.
- Analyzer가 실행 중이고 기본 임계값을 사용한다면 `PORT_SCAN` 이벤트가
  생성된다.
- 정찰은 `sdn-lab` 밖의 주소로 전송되지 않는다.

이 단계는 초기 침해 전 네트워크 흔적을 만든다. 현재 Mutillidae 구성에서
검증된 원격 코드 실행 경로가 없으므로, 웹 취약점으로 OS shell을 얻었다고
가정하지 않는다. 다음 단계에서 서비스 계정을 직접 사용해 foothold 이후만
재현한다.

## 3. 증명 전용 권한 상승 환경 준비

Mininet CLI는 계속 실행해 둔 채 별도 터미널에서 전용 서비스 계정과 고정
proof helper를 만든다. 먼저 충돌 여부를 확인한다.

```bash
multipass exec sdn-lab -- getent passwd sdn-pe-lab-svc
multipass exec sdn-lab -- sudo test -e /etc/sudoers.d/sdn-pe-lab
```

두 명령 모두 아무 결과 없이 실패해야 한다. 하나라도 성공하면 시나리오를
중단하고 기존 자산의 소유자를 확인한다.

전용 계정과 helper를 준비한다.

```bash
multipass exec sdn-lab -- sudo useradd \
  --system \
  --create-home \
  --home-dir /var/lib/sdn-pe-lab \
  --shell /bin/bash \
  sdn-pe-lab-svc
multipass exec sdn-lab -- sudo install \
  -o root \
  -g root \
  -m 0755 \
  /home/ubuntu/sdn-platform/data-plane/mininet/scenarios/server_privilege_escalation_proof.sh \
  /usr/local/libexec/sdn-pe-lab-proof
```

`sudoers` 규칙은 해당 계정이 root로 이 helper 하나만 실행하도록 제한한다.

```bash
printf '%s\n' \
  'sdn-pe-lab-svc ALL=(root) NOPASSWD: /usr/local/libexec/sdn-pe-lab-proof' |
  multipass exec sdn-lab -- sudo tee /etc/sudoers.d/sdn-pe-lab
multipass exec sdn-lab -- sudo chmod 0440 \
  /etc/sudoers.d/sdn-pe-lab
multipass exec sdn-lab -- sudo visudo -cf \
  /etc/sudoers.d/sdn-pe-lab
```

합격 기준:

- helper와 `sudoers` 파일의 소유자가 `root:root`다.
- helper는 서비스 계정이 수정할 수 없다.
- `visudo` 검사가 성공한다.
- 서비스 계정은 helper 외의 `sudo` 명령을 실행할 수 없다.

## 4. 권한 상승 실행

먼저 서비스 계정의 권한을 기록한다.

```bash
multipass exec sdn-lab -- sudo -u sdn-pe-lab-svc id
```

증명 전용 helper를 실행한다.

```bash
multipass exec sdn-lab -- sudo -u sdn-pe-lab-svc \
  sudo -n /usr/local/libexec/sdn-pe-lab-proof
```

다른 명령이 허용되지 않는지 음성 검증한다.

```bash
multipass exec sdn-lab -- sudo -u sdn-pe-lab-svc \
  sudo -n /usr/bin/id
```

마지막 명령은 실패해야 한다. 성공하면 제한이 잘못된 것이므로 즉시
`sudoers` 파일을 제거하고 시나리오를 중단한다.

## 5. 증거 확인

proof 파일의 소유권, 권한, 내용을 확인한다.

```bash
multipass exec sdn-lab -- sudo stat \
  --format 'owner=%U group=%G mode=%a path=%n' \
  /run/sdn-pe-lab/proof.json
multipass exec sdn-lab -- sudo jq . \
  /run/sdn-pe-lab/proof.json
```

기대값:

```text
owner=root group=root mode=600 path=/run/sdn-pe-lab/proof.json
```

JSON의 `scenario`는 `SDN-PE-01`, `effective_uid`는 `0`,
`effective_user`는 `root`여야 한다.

Ubuntu의 `sudo` 로그를 확인한다. 이미지 설정에 따라 한 위치만 존재할 수
있다.

```bash
multipass exec sdn-lab -- sudo journalctl \
  --since '-15 minutes' \
  --no-pager \
  _COMM=sudo
multipass exec sdn-lab -- sudo grep sdn-pe-lab-svc \
  /var/log/auth.log
```

필수 증거:

- 서비스 계정의 원래 UID
- helper 실행 시각
- root 소유 proof 파일과 `effective_uid=0`
- 허용되지 않은 `/usr/bin/id` 실행 거부
- 같은 시간대의 `h3` 정찰/HTTP PCAP
- Analyzer가 생성한 `PORT_SCAN` 이벤트 ID(생성된 경우)

## 6. 침해 후 네트워크 행위 탐지

로컬 권한 상승 자체와 별도로, 침해된 `web` 서버가 보이는 후속 네트워크
행위를 검증한다. Analyzer가 기본 서버 행위 설정으로 실행 중이어야 한다.

```text
PROTECTED_SERVER_IPS=10.0.0.100
SERVER_EGRESS_ALLOWLIST=
```

### 6.1 역할 위반 통신

Mininet CLI에서 `h3`에 일회성 HTTP 대상을 열고 `web`이 연결을 시작한다.

```text
h3 sh -c 'python3 -m http.server 4444 --bind 10.0.0.3 >/tmp/sdn-pe-http.log 2>&1 & echo $! >/tmp/sdn-pe-http.pid'
web curl --fail --max-time 3 http://10.0.0.3:4444/ -o /dev/null
```

`SERVER_EGRESS` 이벤트의 출발지는 `10.0.0.100`, 목적지는 `10.0.0.3`,
탐지 규칙은 `protected_server_tcp_egress`여야 한다. 정상 HTTP 응답의
`SYN+ACK`만으로는 이 이벤트가 생성되지 않아야 한다.

### 6.2 목적지 확산

이 규칙은 Critical 이벤트가 되어 자동 대응 설정에 따라 DROP Flow가 적용될
수 있으므로 송신량과 Beacon 검증을 마친 뒤 마지막에 실행한다.

```text
web timeout 1 bash -c 'echo >/dev/tcp/10.0.0.1/8001'
web timeout 1 bash -c 'echo >/dev/tcp/10.0.0.2/8002'
web timeout 1 bash -c 'echo >/dev/tcp/10.0.0.2/8003'
```

30초 안에 목적지 IP 2개와 연결 시도 3건이 관측되면
`LATERAL_MOVEMENT` 이벤트가 생성되어야 한다. evidence의
`destination_ips`에는 `10.0.0.1`, `10.0.0.2`가 포함되어야 한다.

### 6.3 비정상 송신량

`h3`에 일회성 iperf3 서버를 시작하고 `web`에서 5초간 송신한다.

```text
h3 sh -c 'iperf3 -s -1 -p 5201 >/tmp/sdn-pe-iperf.log 2>&1 &'
web iperf3 -c 10.0.0.3 -p 5201 -t 5
```

기본 설정에서는 서버가 시작한 Flow의 송신량이 `1 Mbps`를 3개 윈도우
연속 초과하면 `DATA_EXFILTRATION` 이벤트가 생성되어야 한다. evidence의
`bps`, `effective_bps_threshold`, `sustained_windows`를 기록한다.

### 6.4 주기적 연결

6회의 연결을 30초 간격으로 반복한다. 기본 설정에서는 약 150초가 필요하다.

```text
web sh -c 'for count in $(seq 1 6); do curl --silent --max-time 3 http://10.0.0.3:4444/ -o /dev/null; if [ "$count" -lt 6 ]; then sleep 30; fi; done'
```

`C2_BEACON` 이벤트의 중앙 연결 간격은 약 30초, jitter는 `0.2` 이하여야 한다.
단순 연결 5회 이하이거나 간격 편차가 큰 연결은 이벤트를 만들지 않아야 한다.

구현 순서는 역할 위반, 목적지 확산, 비정상 송신량, 주기적 연결이지만 실제
통합 실행에서는 Critical 차단이 뒤 단계에 영향을 주지 않도록
`역할 위반 → 비정상 송신량 → 주기적 연결 → 목적지 확산` 순서로 실행한다.

## 7. 대응 검증

Security Events 화면에서 `h3`의 `PORT_SCAN` 이벤트를 확인한다. 현재 정책상
Port Scan은 기본적으로 관찰 또는 운영자 판단 대상이며, 권한 상승 증거만으로
자동 `DROP`이 적용되지는 않는다.

운영자가 `h3`를 차단하기로 결정한 경우 기존 수동 차단 흐름으로
`10.0.0.3 -> 10.0.0.100` Flow Rule을 적용하고 다음을 확인한다.

- Backend Flow Rule 상태가 Barrier 확인 후 `APPLIED`가 된다.
- `s1`에 해당 cookie의 `DROP` Flow가 존재한다.
- `h3`의 신규 HTTP 연결은 실패한다.
- `h1`의 정상 HTTP 연결은 계속 성공한다.
- 규칙 제거 후 `h3` 연결이 복구되고 상태가 `REMOVED`가 된다.

이 시나리오에서 자동 차단 정책을 새로 추가하거나 기존 탐지 임계값을
변경하지 않는다.

## 8. 정리

증거를 보관한 뒤 Mininet CLI에서 `h3`의 일회성 HTTP 프로세스를 먼저
종료한다. PID 파일에 기록한 정확한 프로세스만 대상으로 한다.

```text
h3 sh -c 'if test -f /tmp/sdn-pe-http.pid; then kill "$(cat /tmp/sdn-pe-http.pid)" 2>/dev/null || true; fi; rm -f /tmp/sdn-pe-http.pid /tmp/sdn-pe-http.log /tmp/sdn-pe-iperf.log'
```

추가한 VM 자산만 정확히 제거한다.

```bash
multipass exec sdn-lab -- sudo rm -f \
  /etc/sudoers.d/sdn-pe-lab
multipass exec sdn-lab -- sudo rm -f \
  /usr/local/libexec/sdn-pe-lab-proof
multipass exec sdn-lab -- sudo rm -f \
  /run/sdn-pe-lab/proof.json
multipass exec sdn-lab -- sudo rmdir \
  /run/sdn-pe-lab
multipass exec sdn-lab -- sudo userdel --remove \
  sdn-pe-lab-svc
```

Mininet CLI에서 `exit`한 뒤 Mutillidae와 잔여 데이터 플레인 상태를 정리한다.

```bash
./data-plane/scripts/stop-mutillidae.sh
./data-plane/scripts/cleanup.sh
```

정리 합격 기준:

- `getent passwd sdn-pe-lab-svc`가 실패한다.
- `/etc/sudoers.d/sdn-pe-lab`,
  `/usr/local/libexec/sdn-pe-lab-proof`,
  `/run/sdn-pe-lab`이 존재하지 않는다.
- 잔여 Mininet bridge와 interface가 없다.
- 정상 개발 서비스에는 변경이 없다.

## 최종 합격 기준

| 구간 | 합격 조건 |
|---|---|
| 격리 | 모든 공격 트래픽이 `h3 -> web` 범위를 벗어나지 않음 |
| 네트워크 관측 | 정찰과 HTTP 트래픽이 Sensor PCAP에 존재 |
| 네트워크 탐지 | 기본 임계값에서 `PORT_SCAN` 이벤트 생성 |
| 권한 경계 | 비-root 서비스 계정으로 시작해 root proof 파일 생성 |
| 최소 권한 | helper 외의 `sudo` 명령은 거부 |
| 호스트 증거 | 실행과 거부 기록이 `sudo`/auth 로그에 존재 |
| 플랫폼 정직성 | 권한 상승 자체를 Analyzer 탐지로 오인하지 않음 |
| 역할 위반 | `web` 시작 연결에서 `SERVER_EGRESS` 생성 |
| 목적지 확산 | 목적지 2개·연결 3건에서 `LATERAL_MOVEMENT` 생성 |
| 송신량 | 서버 시작 Flow의 지속 송신에서 `DATA_EXFILTRATION` 생성 |
| Beacon | 6회의 낮은 jitter 연결에서 `C2_BEACON` 생성 |
| 대응 | 선택한 DROP 규칙이 h3만 차단하고 정상 h1은 유지 |
| 복구 | 계정, 규칙, helper, proof, Mininet 상태가 제거됨 |

## 결과 보관

실행별로 다음 자료를 별도 디렉터리에 보관한다.

```text
results/server-privilege-escalation/<실행-ID>/
  metadata.json
  sensor.pcap
  analyzer-events.json
  sudo.log
  proof.json
  ovs-flows-before.txt
  ovs-flows-after.txt
  timeline.md
```

`metadata.json`에는 Git commit, VM 이미지, 실행자, 시작/종료 시각과 적용한
Flow Rule ID를 기록한다. PCAP, 인증 로그, 세션 정보는 외부에 공개하지 않는다.

## 알려진 제한사항

- 초기 웹 침해는 실제 RCE가 아니라 명시적인 foothold 시뮬레이션이다.
- proof helper는 안전한 검증 장치이며 실제 취약점 exploit이 아니다.
- OVS Mirror는 서버 내부 권한 상승 자체가 아니라 역할 위반, 목적지 확산,
  비정상 송신량, 주기적 C2 연결 같은 후속 네트워크 행위를 탐지한다.
- `auditd`, eBPF 또는 EDR 이벤트를 Backend에 수집하는 파이프라인은 아직 없다.
- 서버 내부 행위 탐지 기능을 추가할 때는 Analyzer의 네트워크 역할과 분리된
  host telemetry 수집기 및 별도 탐지 정책을 설계해야 한다.
