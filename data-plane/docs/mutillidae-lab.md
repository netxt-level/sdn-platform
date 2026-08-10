# Mutillidae II 공격 테스트 대상

- 상태: amd64/arm64 격리 배치와 Mininet relay 구현
- 기준일: 2026-08-11

Mutillidae II는 의도적으로 취약한 애플리케이션이다. 이 구성은 인터넷이나
개발자 LAN에 서비스를 공개하지 않고 `sdn-lab` VM과 Mininet 데이터 플레인
안에서만 사용한다.

## 배치 구조

```text
h1/h2/h3 -> s1 -> s2 또는 s3 -> s4 -> web:80
                                             |
                                      관리용 veth (격리)
                                             |
VM 127.0.0.1:8088 -> Mutillidae www -> database / LDAP
```

Mutillidae 컨테이너의 HTTP 포트는 VM의 `127.0.0.1:8088`에만 게시된다.
Mininet을 `--mutillidae-proxy` 옵션으로 실행하면 `web(10.0.0.100):80`과 VM
loopback 사이에 관리용 veth와 두 TCP relay를 만든다. 클라이언트 요청과 응답은
기존 `h1/h2/h3 -> OVS -> web` 구간을 그대로 지나므로 OVS Mirror에서 캡처할 수
있다. 관리용 veth는 OVS에 연결되지 않으며 Mininet 종료 시 제거된다.

시작 스크립트는 VM Docker 아키텍처를 자동 감지한다. 일반적인 Intel/AMD 기반
Windows·Linux VM의 `amd64`에서는 공식 사전 빌드 이미지를 사용한다. Apple
Silicon 또는 Windows on ARM의 `arm64`에서는 공식 이미지에 ARM manifest가
없으므로 공식 Mutillidae 소스를 고정 커밋으로 네이티브 빌드한다. ARM 구성은
게시판·SQL Injection·XSS 등 HTTP/DB 실습 범위에 집중하며 LDAP 컨테이너는
실행하지 않으므로 LDAP 전용 실습은 지원하지 않는다.

## 최초 시작

호스트 프로젝트를 VM에 동기화하고 공식 사전 빌드 이미지를 시작한다.

```bash
./data-plane/scripts/sync-vm.sh
./data-plane/scripts/start-mutillidae.sh --pull --initialize
```

`--initialize`는 Mutillidae 데이터베이스를 다시 만든다. DB Docker volume은
컨테이너 종료 후에도 보존되므로 기존 시나리오 데이터가 필요한 이후 실행에서는
이 옵션을 제외한다.

Controller가 준비된 상태에서 Mininet을 시작한다.

```bash
multipass exec sdn-lab -- sudo python3 \
  /home/ubuntu/sdn-platform/data-plane/mininet/topology.py \
  --sensor-mirror \
  --mutillidae-proxy
```

이미 실행 중인 Mininet 세션을 재시작하지 않으려면 다음 명령으로 현재 `web`
네임스페이스에 연결한다. 토폴로지가 끝나면 관리 veth와 relay도 자동 종료된다.

```bash
./data-plane/scripts/attach-mutillidae.sh
```

컨테이너는 유지하면서 현재 Mininet 세션에서만 분리할 수 있다.

```bash
./data-plane/scripts/detach-mutillidae.sh
```

Mininet CLI에서 다음 명령으로 웹 서비스와 경로를 확인한다.

```text
h1 curl -fsS -H 'Host: mutillidae.localhost' http://10.0.0.100/ -o /dev/null
h2 curl -fsS -H 'Host: mutillidae.localhost' http://10.0.0.100/ -o /dev/null
h3 curl -fsS -H 'Host: mutillidae.localhost' http://10.0.0.100/ -o /dev/null
```

호스트 브라우저에서 직접 접근하려면 별도 포트 공개 대신 SSH 터널이나 Mininet
호스트를 경유하는 프록시를 사용해야 한다. 기본 구성은 의도적으로 브라우저가
VM IP를 통해 Mutillidae에 직접 접근하지 못하게 한다.

## 캡처와 로그

Sensor 인터페이스의 HTTP 트래픽을 확인한다.

```bash
multipass exec sdn-lab -- sudo tcpdump -ni sdn-sensor0 \
  'host 10.0.0.100 and tcp port 80'
```

애플리케이션 및 DB 컨테이너 로그를 확인한다.

```bash
multipass exec sdn-lab -- docker compose \
  --project-name sdn-mutillidae \
  --file /home/ubuntu/sdn-platform/data-plane/web/mutillidae/docker-compose.yml \
  logs --since 10m www database
```

ARM VM에서는 위 명령의 Compose 파일을 `docker-compose.arm64.yml`로 바꾼다.

TCP relay 구조에서는 네트워크 원본 주소가 OVS/PCAP에는 보존되지만 Mutillidae
컨테이너 access log에는 relay 주소로 기록될 수 있다. 시나리오 상관 분석의
기준은 PCAP의 원본 IP, HTTP 요청 시각, 애플리케이션 로그 시각으로 삼는다.

## 종료

Mininet CLI에서 `exit`한 뒤 컨테이너를 중지한다.

```bash
./data-plane/scripts/stop-mutillidae.sh
```

DB와 적용 가능한 보조 서비스 볼륨은 보존된다. DB를 초기 상태로 되돌릴 때는
다음 시작에서 명시적으로 `--initialize`를 사용한다.

정상 100명, 피크 300명, 스트레스 500명을 기준으로 한 웹 부하와 SDN 경로
테스트 계획은 `data-plane/docs/web-load-test-plan.md`를 참고한다.

웹 접근 이후의 서버 권한 상승을 안전하게 모의하고 네트워크 증거와 호스트
증거를 함께 확인하는 절차는
`data-plane/docs/server-privilege-escalation-scenario.md`를 참고한다.

Mutillidae 자체의 취약점 탐지나 웹 애플리케이션 방화벽은 현재 플랫폼 범위가
아니다. 이 서비스는 네트워크 관측·탐지·대응 시나리오를 재현하는 격리 대상이며,
외부 네트워크나 개발자 LAN에 공개하면 안 된다.
