# Reproducible SDN Lab

이 프로젝트는 Mininet과 Open vSwitch가 필요한 Linux 데이터 플레인을 Multipass VM에 만들고, 애플리케이션 서비스는 개발 호스트의 Docker에서 실행하는 하이브리드 구성을 기본으로 사용합니다.

## 기본 배치

```text
macOS/Windows Docker                 Ubuntu Multipass VM
-------------------                 -------------------
Frontend                            Mininet / Open vSwitch
Backend          <--- HTTP ------   Analyzer
PostgreSQL                          Controller (추가 예정)
InfluxDB                            OVS mirror/sensor0 (추가 예정)
Elasticsearch                       공격자/사용자/웹 호스트 (추가 예정)
```

`dataplane` 프로필이 기본값입니다.

- 개발 호스트: Backend, Frontend, PostgreSQL, InfluxDB, Elasticsearch
- Linux VM: Mininet, OVS, Analyzer와 이후 추가할 Controller/가상 호스트
- VM의 Analyzer는 Multipass 기본 게이트웨이를 통해 호스트의 Backend에 연결
- VM에 있던 기존 데이터 볼륨은 삭제하지 않지만, `dataplane` 프로필에서는 DB 컨테이너를 실행하지 않음

기존처럼 모든 서비스를 VM에 실행해야 할 때만 `full` 프로필을 사용합니다.

## 생성되는 환경

- Ubuntu 24.04 LTS Multipass 인스턴스 `sdn-lab`
- CPU 4개, 메모리 8GB, 디스크 40GB
- Mininet, Open vSwitch, `iperf3`, `tcpdump` 및 네트워크 진단 도구
- Docker Engine과 Docker Compose
- 생성 파일과 캐시를 제외한 VM용 프로젝트 스냅샷
- 데이터베이스 마이그레이션
- Mininet/OVS `pingall`, 호스트 서비스, VM Analyzer 통신 검증

Multipass와 호스트 Docker는 자동으로 설치하지 않습니다. 먼저 두 프로그램을 설치하고 CLI가 PATH에 있는지 확인해야 합니다.

## macOS와 Linux

기본 하이브리드 구성:

```bash
./data-plane/infrastructure/multipass/bootstrap.sh
```

리소스와 Analyzer 인터페이스 지정:

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

동일한 값은 `VM_NAME`, `VM_CPUS`, `VM_MEMORY`, `VM_DISK`, `VM_IMAGE`, `DEPLOYMENT_PROFILE`, `VM_ANALYZER_INTERFACE` 환경변수로도 지정할 수 있습니다.

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

## Compose 파일 역할

- `docker-compose.yml`: 기존 전체 애플리케이션 정의이며 변경하지 않음
- `docker-compose.control-plane.yml`: 호스트 DB 마이그레이션용 오버레이
- `docker-compose.dataplane.yml`: VM에서 실행할 Analyzer 정의

Analyzer는 VM의 `network_mode: host`로 실행됩니다. 따라서 이후 OVS Mirror가 연결된 `sensor0`를 만들면 다음처럼 재실행해 동일한 컨테이너가 해당 인터페이스를 캡처할 수 있습니다.

```bash
./data-plane/infrastructure/multipass/bootstrap.sh --interface sensor0
```

현재 `sensor0` 구성 전에는 `auto`가 기본값이며, VM의 기본 경로 NIC(예: `enp0s1`)를 자동으로 찾습니다. 이 상태는 호스트-VM 연결 검증용이며 Mininet 트래픽 캡처 완료를 의미하지 않습니다.

## 전체 VM 프로필

문제 재현이나 독립 실행을 위해 모든 기존 Compose 서비스를 VM 안에서 실행할 수 있습니다.

```bash
./data-plane/infrastructure/multipass/bootstrap.sh --profile full
```

PowerShell에서는 `-Profile full`을 사용합니다.

## 재실행 동작

- 기존 VM을 시작해 재사용
- Ubuntu 패키지를 다시 확인
- 호스트 소스를 VM 스냅샷으로 동기화
- Docker 볼륨 유지
- 필요한 이미지만 빌드
- Alembic 마이그레이션을 `head`까지 적용
- 선택한 프로필에 맞는 컨테이너 위치와 통신을 재검증

VM의 `/home/ubuntu/sdn-platform`은 생성된 복사본입니다. 코드는 호스트에서 수정하고 부트스트랩을 다시 실행해야 합니다.

## 운영 명령

VM 셸 열기:

```bash
multipass shell sdn-lab
```

VM 정지 및 시작:

```bash
multipass stop sdn-lab
multipass start sdn-lab
```

상태 확인:

```bash
multipass info sdn-lab
docker compose ps
multipass exec sdn-lab -- docker ps
```

하이브리드 환경 검증만 다시 실행할 때는 호스트 게이트웨이를 전달해야 합니다. 일반적으로 자동 부트스트랩을 다시 실행하는 것이 안전합니다.

## 접속 주소

`dataplane` 프로필에서는 개발 호스트에서 다음 주소를 사용합니다.

- Frontend: `http://127.0.0.1:3000`
- Backend: `http://127.0.0.1:8000`
- API 문서: `http://127.0.0.1:8000/docs`

## 주의 사항

- VM 디스크는 나중에 확장할 수 있지만 일반적으로 축소할 수 없습니다.
- 공격 및 부하 생성은 격리된 Mininet 토폴로지 내부에서만 수행합니다.
- `dataplane` 전환은 VM의 기존 Docker 볼륨을 보존합니다.
- 호스트 방화벽이 Multipass VM에서 포트 8000과 3000 접근을 차단하면 검증이 실패합니다.
- Windows에서도 Multipass와 Docker Desktop을 설치한 뒤 같은 PowerShell 스크립트를 사용합니다.
