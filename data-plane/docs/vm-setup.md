# 재현 가능한 SDN Lab VM

- 상태: macOS/Windows Multipass 기반 구현, secure-default Analyzer 배치 보완 필요
- 기본 VM: Ubuntu 24.04, 4 CPU, 8 GB RAM, 40 GB Disk
- 최종 수정일: 2026-08-11

## VM이 필요한 이유

Mininet과 Open vSwitch는 Linux network namespace, veth, traffic control과
커널 datapath를 사용한다. macOS나 Windows에서는 이 기능을 직접 실행할 수
없으므로 Multipass Ubuntu VM을 데이터 플레인 실행 환경으로 사용한다.

VM 한 대 안에서 Controller, Mininet/OVS와 Analyzer 컨테이너를 실행한다.
Mininet의 `h1`, `h2`, `h3`, `web`은 별도 VM이나 Docker 컨테이너가 아니라
Linux network namespace로 생성된다.

## 기본 배치

```text
Development host                     Ubuntu Multipass VM
----------------                     -------------------
Backend / Frontend                   sdn-controller
PostgreSQL / InfluxDB                Mininet h1/h2/h3/web
Elasticsearch                        Open vSwitch s1~s4
                                     sdn-analyzer
```

기본 `dataplane` 프로필은 기존 애플리케이션과 데이터베이스를 개발 호스트에
유지한다. VM에는 Controller와 Analyzer만 Docker로 실행하며 Mininet/OVS는
VM Linux 환경에서 직접 실행한다.

Analyzer 컨테이너가 실행된다는 사실만으로 Mininet 트래픽을 볼 수 있는 것은
아니다. 전용 `sdn-sensor0` veth와 OVS Mirror 코드는 구현되어 있지만 현재
bootstrap은 이를 자동 생성하지 않는다. 운영자는 Sensor를 준비하고 Analyzer
인터페이스를 명시적으로 변경해야 한다.

## 사전 요구사항

호스트에 다음 프로그램을 먼저 설치한다.

- Multipass
- Docker Desktop 또는 호스트 Docker Engine
- `tar`, `curl`
- 프로젝트 루트의 `.env`

부트스트랩은 Multipass와 호스트 Docker 자체를 설치하지 않는다.

## macOS/Linux 호스트

기본 구성:

```bash
./data-plane/infrastructure/multipass/bootstrap.sh
```

리소스와 프로필 지정:

```bash
./data-plane/infrastructure/multipass/bootstrap.sh \
  --name sdn-lab \
  --cpus 4 \
  --memory 8G \
  --disk 40G \
  --image 24.04 \
  --profile dataplane \
  --interface auto
```

대응 환경변수:

```text
VM_NAME
VM_CPUS
VM_MEMORY
VM_DISK
VM_IMAGE
DEPLOYMENT_PROFILE
VM_ANALYZER_INTERFACE
```

## Windows PowerShell

```powershell
.\data-plane\infrastructure\multipass\bootstrap.ps1
```

사용자 지정:

```powershell
.\data-plane\infrastructure\multipass\bootstrap.ps1 `
  -VmName sdn-lab `
  -Cpus 4 `
  -Memory 8G `
  -Disk 40G `
  -Image 24.04 `
  -Profile dataplane `
  -AnalyzerInterface auto
```

새 컴퓨터에서도 Multipass와 Docker를 설치하고 저장소와 `.env`를 준비한 뒤
같은 부트스트랩 명령을 실행한다. 운영체제가 바뀌어도 VM 내부 Ubuntu 구성과
프로젝트 경로는 동일하다.

## 부트스트랩 수행 내용

1. 기존 `sdn-lab` VM을 재사용하거나 새로 생성한다.
2. cloud-init 완료를 기다린다.
3. Mininet, OVS, `iperf3`, `tcpdump`, Docker와 진단 도구를 설치한다.
4. 생성 파일을 제외한 프로젝트를 tar로 묶어 VM에 동기화한다.
5. 선택한 배치 프로필에 맞게 Compose 서비스를 시작한다. `auto` 인터페이스는
   VM 기본 경로 NIC를 선택한다.
6. 데이터베이스 migration과 서비스 health를 확인한다.
7. Mininet/OVS 기본 동작과 Controller health를 검증한다.

`sdn-sensor0 ↔ sdn-mirror0` 생성과 Analyzer 전환은 현재 bootstrap 이후의 별도
운영 단계다.

VM 프로젝트 복사본은 `/home/ubuntu/sdn-platform`에 생성된다. 부트스트랩을
다시 실행하면 이 디렉터리를 새 스냅샷으로 교체한다. Docker volume은 별도로
유지되지만 VM 프로젝트 디렉터리에서 직접 수정한 파일은 보존 대상이 아니다.
전체 플랫폼 부트스트랩 없이 데이터 플레인 코드만 갱신할 때는
`data-plane/scripts/sync-vm.sh`를 사용한다.

## 배치 프로필

### `dataplane` 기본 프로필

- 호스트: Backend, Frontend, PostgreSQL, InfluxDB, Elasticsearch
- VM: Controller, Analyzer, Mininet, OVS
- VM의 Backend/Frontend/DB 컨테이너가 실행 중이면 중지한다.
- Analyzer는 Multipass 기본 게이트웨이를 통해 호스트 Backend 주소를 사용한다.

bootstrap 직후 Analyzer 인터페이스는 기본적으로 `auto`가 선택한 VM 기본 경로
NIC다. 이 인터페이스는 Backend 통신은 가능하지만 Mininet host-to-host
트래픽을 관찰하지 못한다. NDR 데이터 플레인 검증 전에는 아래 절차로
`sdn-sensor0`으로 전환한다.

### `full` 프로필

문제 재현이나 완전 독립 실행이 필요할 때 모든 Compose 서비스를 VM에서
실행할 수 있다.

```bash
./data-plane/infrastructure/multipass/bootstrap.sh --profile full
```

PowerShell에서는 `-Profile full`을 사용한다. 일상 개발에는 서비스 중복과
리소스 사용이 적은 `dataplane` 프로필을 권장한다.

## Compose 파일 역할

| 파일 | 역할 |
|---|---|
| `docker-compose.yml` | 기존 플랫폼과 Controller 서비스 정의 |
| `docker-compose.control-plane.yml` | 호스트 제어 플레인 오버레이 |
| `docker-compose.dataplane.yml` | VM Analyzer 실행 정의 |

현재 브랜치에서 Compose 파일을 전면 재작성하지 않으며, Controller는 기존
루트 Compose의 `dataplane` profile을 사용한다.

## Controller와 Mininet 운영

Controller 시작:

```bash
./data-plane/scripts/start.sh
```

Sensor veth 준비와 OVS Mirror 운영은 `data-plane/docs/analyzer-mirror.md`를
참고한다. bootstrap 후 veth를 준비하려면 다음 명령을 사용한다.

```bash
./data-plane/scripts/setup-sensor.sh
```

그 다음 Analyzer를 `ANALYZER_INTERFACE=sdn-sensor0`으로 재생성한다. Backend가
호스트에서 실행되는 `dataplane` 프로필은 VM 기본 gateway를 사용한다.

```bash
HOST_GATEWAY="$(multipass exec sdn-lab -- \
  ip route show default | awk '{print $3; exit}')"
multipass exec sdn-lab -- env \
  COMPOSE_IGNORE_ORPHANS=true \
  BACKEND_BASE_URL="http://${HOST_GATEWAY}:8000" \
  ANALYZER_INTERFACE=sdn-sensor0 \
  docker compose \
  -f /home/ubuntu/sdn-platform/docker-compose.yml \
  -f /home/ubuntu/sdn-platform/docker-compose.dataplane.yml \
  up -d --build --force-recreate --no-deps analyzer
```

두 파일을 병합하는 이유는 기본 Compose에 정의된 `ANALYZER_API_KEY`와
`analyzer_outbox` volume을 유지하면서 overlay의 host network를 적용하기
위해서다. 현재 bootstrap은 overlay만 사용하므로 이 수동 재생성 전에는
secure-default Backend 전달이 실패하고 Outbox는 컨테이너 재생성에 영속적이지
않다.

현재 로컬 데이터 플레인만 VM에 동기화:

```bash
./data-plane/scripts/sync-vm.sh
```

동기화 스크립트는 VM의 `data-plane/`만 교체하며 Backend, Frontend,
Analyzer, 데이터베이스와 Docker volume은 변경하지 않는다. 동기화 후 로컬과
VM 파일별 SHA-256이 다르면 실패한다.

Controller 이미지 강제 재빌드와 컨테이너 재생성:

```bash
CONTROLLER_REBUILD=true ./data-plane/scripts/start.sh
```

Controller 정지:

```bash
./data-plane/scripts/stop.sh
```

Controller 컨테이너와 잔여 Mininet/OVS 상태 정리:

```bash
./data-plane/scripts/cleanup.sh
```

Analyzer가 실행 중이면 `cleanup.sh`는 Sensor veth를 삭제하지 않고 Analyzer
중지 절차를 출력한 뒤 실패한다. Analyzer를 중지하고 같은 명령을 다시
실행해야 전체 Sensor와 Mininet/OVS 상태를 제거한다.

전체 인프라 검증:

```bash
./data-plane/scripts/verify.sh
```

`verify.sh`는 `sync-vm.sh`를 먼저 실행하고 Controller 이미지를 재빌드한 뒤
다음을 자동 확인한다.

- 스위치 4개, 고정 Host/Port, `pingall`
- 스위치별 Table-Miss Barrier Reply 기반 설치 상태
- Primary/Backup 경로와 링크 장애·복구
- Primary 링크 down 상태의 Controller 재시작과 OVS 포트 상태 재동기화
- 호스트 재학습과 Primary Flow 복구
- L2 Flow의 경로별 `in_port`와 고정 Host MAC/IP 바인딩
- h3의 MAC/IP 위조 차단과 정상 호스트 통신 회귀
- TCLink 지연과 `iperf3` 대역폭 제한
- s1 OVS Mirror source/output 포트와 Sensor veth 상태
- Primary/Backup 경로의 양방향 ICMP `tcpdump` 캡처
- 종료 후 잔여 OVS 브리지 부재

현재 외부 Flow와 RATE_LIMIT 시나리오는 Controller API Key header를 전달하지
않는다. `.env.example`처럼 Controller 인증이 활성화된 구성에서는 해당 단계가
실패하므로, 최신 전체 통과를 주장하기 전에 시나리오 Key 전달을 보완해야 한다.

실패하거나 강제 종료해 상태가 남았으면 `cleanup.sh`를 실행한다.

## 상태 확인

VM 정보:

```bash
multipass info sdn-lab
multipass shell sdn-lab
```

컨테이너:

```bash
multipass exec sdn-lab -- docker ps
```

Controller REST:

```bash
VM_IP="$(multipass list --format csv | awk -F, '$1 == "sdn-lab" {print $3}')"
curl "http://${VM_IP}:8080/health"
curl -H "X-API-Key: <CONTROLLER_API_KEY>" \
  "http://${VM_IP}:8080/switches"
```

OVS 잔여 브리지:

```bash
multipass exec sdn-lab -- sudo ovs-vsctl list-br
```

## VM 자원 변경

- CPU와 메모리는 VM을 정지한 뒤 Multipass 설정으로 변경할 수 있다.
- Disk는 확장할 수 있지만 일반적으로 축소할 수 없다.
- 리소스를 변경한 뒤 `multipass info sdn-lab`으로 적용값을 확인한다.
- VM을 삭제하면 내부 프로젝트 복사본과 VM 로컬 상태도 삭제된다.

## 접속 주소

기본 `dataplane` 프로필:

| 서비스 | 주소 |
|---|---|
| Frontend | `http://127.0.0.1:3000` |
| Backend | `http://127.0.0.1:8000` |
| Backend Health | `http://127.0.0.1:8000/health` |
| Controller | `http://<VM_IP>:8080` |
| OpenFlow | `<VM_IP>:6653` 또는 VM 내부 `127.0.0.1:6653` |

## 알려진 제한사항과 안전 수칙

- 공격·Flood·부하 생성은 격리된 Mininet namespace 안에서만 수행한다.
- Analyzer의 기본 VM NIC에서는 Mininet host-to-host 트래픽이 보이지 않는다.
  `ANALYZER_INTERFACE=sdn-sensor0`과 실행 중인 OVS Mirror가 필요하다.
- Sensor veth와 Mirror의 패킷 복제부터 Analyzer 탐지, Backend 저장,
  Controller Meter 설치까지 `analyzer_detection_response.py`로 검증할 수 있다.
- 현재 `dataplane` bootstrap의 Analyzer overlay에는 `ANALYZER_API_KEY`와 Outbox
  volume이 없고 `full` 프로필 Analyzer는 host network가 아니므로, 위 수동
  병합 절차나 배치 스크립트 보완 없이는 secure-default Mirror 종단 간 경로가
  완성되지 않는다.
- Backend·Controller 관리 API는 각각 Admin·Controller API Key를 요구하며,
  `.env.example`의 공개 예시 키를 실제 값으로 교체해야 한다.
- 호스트 방화벽이 VM의 Backend/Frontend 접근을 차단하면 부트스트랩 검증이
  실패할 수 있다.
- Windows에서도 같은 Ubuntu 구성을 만들지만 Multipass/Hyper-V 설정에 따라
  VM IP 대역이 달라질 수 있다.
- VM 프로젝트 복사본을 직접 수정하지 말고 호스트 저장소를 수정한다. 전체
  플랫폼 갱신은 부트스트랩을, 데이터 플레인 검증은 `verify.sh`를 사용한다.
