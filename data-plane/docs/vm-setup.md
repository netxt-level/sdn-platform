# 재현 가능한 SDN Lab VM

- 상태: macOS/Windows용 Multipass 자동 구성 구현 완료
- 기본 VM: Ubuntu 24.04, 4 CPU, 8 GB RAM, 40 GB Disk
- 최종 수정일: 2026-07-16

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

Analyzer 컨테이너가 실행된다는 사실은 Mininet 트래픽 캡처가 완료됐다는
의미가 아니다. OVS Mirror와 전용 sensor 인터페이스는 후속 연동 브랜치의
범위다.

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
5. 선택한 배치 프로필에 맞게 Compose 서비스를 시작한다.
6. 데이터베이스 migration과 서비스 health를 확인한다.
7. Mininet/OVS 기본 동작과 Controller health를 검증한다.

VM 프로젝트 복사본은 `/home/ubuntu/sdn-platform`에 생성된다. 부트스트랩을
다시 실행하면 이 디렉터리를 새 스냅샷으로 교체한다. Docker volume은 별도로
유지되지만 VM 프로젝트 디렉터리에서 직접 수정한 파일은 보존 대상이 아니다.

## 배치 프로필

### `dataplane` 기본 프로필

- 호스트: Backend, Frontend, PostgreSQL, InfluxDB, Elasticsearch
- VM: Controller, Analyzer, Mininet, OVS
- VM의 Backend/Frontend/DB 컨테이너가 실행 중이면 중지한다.
- Analyzer는 Multipass 기본 게이트웨이를 통해 호스트 Backend 주소를 사용한다.

Analyzer 인터페이스가 `auto`이면 VM 기본 경로 NIC를 사용한다. 이 설정은
호스트-VM 통신 검증용이며 Mininet 패킷 관찰 경로는 아니다.

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

Controller 정지:

```bash
./data-plane/scripts/stop.sh
```

Controller 컨테이너와 잔여 Mininet/OVS 상태 정리:

```bash
./data-plane/scripts/cleanup.sh
```

전체 인프라 검증:

```bash
./data-plane/scripts/verify.sh
```

`verify.sh`는 Controller를 실행한 뒤 다음을 자동 확인한다.

- 스위치 4개, 고정 Host/Port, `pingall`
- Primary/Backup 경로와 링크 장애·복구
- Primary 링크 down 상태의 Controller 재시작과 OVS 포트 상태 재동기화
- 호스트 재학습과 Primary Flow 복구
- TCLink 지연과 `iperf3` 대역폭 제한
- 종료 후 잔여 OVS 브리지 부재

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
curl "http://${VM_IP}:8080/switches"
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
| Backend API 문서 | `http://127.0.0.1:8000/docs` |
| Controller | `http://<VM_IP>:8080` |
| OpenFlow | `<VM_IP>:6653` 또는 VM 내부 `127.0.0.1:6653` |

## 알려진 제한사항과 안전 수칙

- 공격·Flood·부하 생성은 격리된 Mininet namespace 안에서만 수행한다.
- Analyzer의 기본 VM NIC에서는 Mininet host-to-host 트래픽이 보이지 않는다.
- OVS Mirror/sensor 인터페이스는 아직 자동 구성하지 않는다.
- 호스트 방화벽이 VM의 Backend/Frontend 접근을 차단하면 부트스트랩 검증이
  실패할 수 있다.
- Windows에서도 같은 Ubuntu 구성을 만들지만 Multipass/Hyper-V 설정에 따라
  VM IP 대역이 달라질 수 있다.
- VM 프로젝트 복사본을 직접 수정하지 말고 호스트 저장소 수정 후 다시
  부트스트랩한다.
