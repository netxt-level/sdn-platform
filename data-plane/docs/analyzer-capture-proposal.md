# Analyzer 캡처 경로 설계

- 상태: `s1` 연결 위치 확정, 구현 반영·검증 전
- 대상 브랜치: `feat/analyzer-sensor-integration`
- 수정 범위: 우선 `data-plane/` 내부만 사용
- 확정 사항: Analyzer 전용 OVS Mirror 출력은 `s1`에 연결

## 목표

Mininet의 호스트 간 양방향 트래픽을 `s1`의 OVS Mirror에서 전용 Sensor
인터페이스로 복제해 VM의 Analyzer 컨테이너가 실제 패킷을 캡처하도록 한다.
기존 Analyzer 탐지 로직과 Backend API 계약은 변경하지 않는다.

첫 체크포인트의 완료 기준은 Analyzer 연동 전 `tcpdump`로 복제 패킷을
확인하는 것이다. 그 다음 체크포인트에서 기존 Analyzer를 Sensor 인터페이스로
실행하고 Packet Summary와 Security Event의 Backend 저장을 검증한다.

## 확정 구조

```text
h1/h2/h3 -- s1 -- s2/s3 -- s4 -- web
              |
              | OVS Mirror
              | select_src_port: s1 ports 1, 2, 3, 4, 5
              v
       sdn-mirror0 (s1 port 6)
              |
           veth pair
              |
       sdn-sensor0 (no IP)
              |
    Analyzer (host network)
              |
           Backend
```

인터페이스 역할:

| 이름 | 위치 | 역할 |
|---|---|---|
| `sdn-sensor0` | VM root network namespace | Analyzer 전용 캡처 인터페이스 |
| `sdn-mirror0` | VM root network namespace, 실행 중 `s1`에 연결 | OVS Mirror 출력 포트 |
| `s1` port `6` | OVS | Mirror 전용 고정 포트. Controller 전달·Flooding 대상에서 제외 |

두 veth 인터페이스는 `UP`과 promiscuous 상태로 두고 IP 주소를 할당하지 않는다.
Analyzer는 이미 VM에서 `network_mode: host`로 실행되므로
`ANALYZER_INTERFACE=sdn-sensor0`만 사용하면 별도 Docker network 연결 없이
인터페이스를 볼 수 있다. 기존 Compose에는 `NET_RAW`, `NET_ADMIN` 권한도
설정되어 있다.

## Mirror 범위

MVP에서는 `s1`의 기존 호스트·스위치 연결 포트 전체를 Mirror source로
선택한다.

| s1 포트 | 연결 대상 | Mirror source |
|---:|---|---|
| `1` | `h1` User | 포함 |
| `2` | `h2` Administrator | 포함 |
| `3` | `h3` Attacker | 포함 |
| `4` | `s2` Primary | 포함 |
| `5` | `s3` Backup | 포함 |
| `6` | `sdn-mirror0` | 제외, Mirror output |

`select_all`이나 ingress/egress 동시 복제를 사용하지 않는다. 현재 고정
토폴로지의 모든 Endpoint 트래픽은 어느 방향이든 `s1`의 1~5번 포트 중
하나로 들어오므로 ingress만 선택하면 요청과 응답을 모두 관찰하면서 동일
프레임의 중복 복제를 줄일 수 있다.

이 구성은 `h1 ↔ h2`, `h2 ↔ h3` 같은 동일 `s1` 호스트 간 트래픽과
`h1/h2/h3 ↔ web` 트래픽을 관찰한다. 향후 `s1`을 거치지 않는 Endpoint가
추가되면 별도 Mirror 출력과 집계 구조가 필요하다.

## 수명주기와 실행 순서

Sensor veth와 OVS Mirror의 수명주기를 분리한다.

1. Multipass VM bootstrap이 Analyzer를 시작하기 전에
   `sdn-sensor0 ↔ sdn-mirror0` veth를 멱등 생성한다. macOS/Linux용
   `bootstrap.sh`와 Windows용 `bootstrap.ps1`이 같은 순서를 보장한다.
2. Analyzer를 `ANALYZER_INTERFACE=sdn-sensor0`으로 시작한다.
3. Mininet이 `s1`을 만든 뒤 `sdn-mirror0`을 `s1` port 6으로 연결한다.
4. `s1` ports 1, 2, 3, 4, 5를 source로 하는 OVS Mirror를 생성한다.
5. Mininet 종료 시 Mirror와 `s1` 연결만 제거한다.
6. 일반 재실행에서는 veth를 유지해 Analyzer의 캡처 인터페이스가 사라지지
   않게 한다.
7. 전체 data-plane cleanup은 Analyzer가 실행 중이면 Sensor veth를 삭제하지
   않고 명확한 오류와 Analyzer 중지 명령을 출력한다. 사용자가 Analyzer를
   중지한 뒤 cleanup을 다시 실행하면 veth까지 제거한다.

Mininet이 없는 동안 Analyzer는 패킷이 들어오지 않는 `sdn-sensor0`에서 계속
대기할 수 있다. 다음 Mininet 실행에서 Mirror가 다시 연결되면 Analyzer를
재시작하지 않아도 캡처가 이어진다.

## 구현 체크포인트

### A. Sensor와 Mirror 기반 코드

`data-plane/` 내부에 다음 책임을 추가한다.

- Sensor veth 멱등 생성과 상태 확인
- VM bootstrap에서 Analyzer 시작 전 Sensor veth 생성
- `s1` port 6 연결
- OVS Mirror 멱등 생성·교체
- Mirror 해제와 전체 Sensor 정리
- Analyzer 실행 중 전체 Sensor cleanup 거부
- Mininet 시작 실패와 강제 종료 후 재실행 안전성
- 인터페이스 이름, 대상 스위치, 대상 포트를 설정값으로 관리

예상 파일은 다음과 같다.

```text
data-plane/
  mininet/
    sensor.py
    scenarios/
      mirror_capture.py
  scripts/
    setup-sensor.sh
    cleanup.sh
    verify.sh
```

이 체크포인트에서는 `analyzer/`, `backend/`, 루트 Compose 파일을 수정하지
않는다.

### B. 패킷 복제 검증

격리된 Mininet 안에서 다음을 자동 확인한다.

1. `sdn-sensor0`, `sdn-mirror0` 존재와 Link UP
2. `sdn-mirror0`이 `s1` port 6으로 연결됨
3. OVS Mirror가 `s1` ports 1, 2, 3, 4, 5만 source로 사용함
4. `h1 → web` ICMP Echo Request가 `sdn-sensor0`에서 관찰됨
5. `web → h1` ICMP Echo Reply가 `sdn-sensor0`에서 관찰됨
6. Primary 링크 장애 후 Backup을 통과한 동일 트래픽도 관찰됨
7. 테스트 종료 후 OVS Mirror와 Mininet bridge가 남지 않음
8. Sensor veth는 Analyzer 지속 실행을 위해 유지됨

패킷 캡처는 먼저 VM 호스트의 `tcpdump`로 검증한다. 이 단계가 통과하기 전에
Analyzer나 Backend 문제를 디버깅하지 않는다.

### C. Analyzer 연결

캡처 경로 검증 후 기존 Analyzer 실행 환경에 다음 설정만 적용한다.

```env
ANALYZER_INTERFACE=sdn-sensor0
```

확인 항목:

- Analyzer 컨테이너에서 `sdn-sensor0` 조회 가능
- Analyzer `capture_active=true`
- 컨테이너 재시작 횟수 증가 없음
- ping 트래픽의 Packet Summary가 기존 Backend API로 전송됨
- Analyzer 중지나 Backend 실패가 Mininet forwarding에 영향을 주지 않음

Analyzer 또는 루트 Compose 변경이 필요하다고 확인되면 실제 수정 전에 별도
승인을 받는다.

### D. 보안 이벤트 종단 간 검증

기존 탐지 로직을 변경하지 않고 격리된 h3에서 지원 공격 시나리오 하나를
실행한다. 우선 ICMP Flood 또는 Port Scan 중 현재 임계값으로 안정적으로
재현되는 시나리오를 선택한다.

완료 기준:

- Sensor에서 공격 패킷 확인
- Analyzer 로그에서 탐지 확인
- Backend에 Packet Summary 저장 확인
- Backend에 Security Event 저장 확인
- 외부 네트워크로 공격 패킷이 나가지 않음

## 실패 처리

- 이미 존재하는 veth는 상태를 확인한 뒤 재사용한다.
- 이름이 같지만 veth가 아니거나 peer가 다르면 실패 이유를 출력하고 중단한다.
- `s1`이 없으면 Mirror 연결을 시도하지 않고 명확한 오류를 반환한다.
- 동일 이름의 오래된 Mirror는 삭제 후 현재 포트 참조로 다시 만든다.
- Mirror 생성 중 실패하면 생성한 OVS port를 제거하되 Sensor veth는 유지한다.
- Analyzer 컨테이너가 실행 중이면 전체 cleanup은 `sdn-sensor0`과
  `sdn-mirror0`을 유지하고 비정상 종료한다. 출력에는 Analyzer를 중지한 뒤
  cleanup을 다시 실행하라는 복구 절차를 포함한다.
- 전체 cleanup은 Mirror, OVS port, veth 순서로 멱등 제거한다.
- Analyzer와 Backend 실패는 패킷 전달 경로를 변경하지 않는다.

## 운영 확인 명령

구현 후 다음 형태의 명령을 제공한다.

```bash
ip -details link show sdn-sensor0
ip -details link show sdn-mirror0
ovs-vsctl list Mirror
ovs-ofctl -O OpenFlow13 show s1
tcpdump -nn -i sdn-sensor0 icmp
docker inspect sdn-analyzer
docker logs --since 5m sdn-analyzer
```

## 구현 순서와 첫 범위

먼저 A와 B를 구현한다. 즉, Sensor veth와 `s1` Mirror를 만들고 실제 ICMP가
`tcpdump`에 복제되는 것까지 검증한다. Analyzer·Backend 연결은 해당 결과를
확인한 뒤 진행한다.
