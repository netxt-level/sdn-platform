# SDN Platform 구현 현황

- 기준일: 2026-08-11
- 기준 브랜치: `sdn-platform-v1`
- 현재 단계: SDN 기반 폐루프 NDR MVP와 격리 Lab 검증 구현

이 문서는 현재 소스 코드에 존재하는 기능과 아직 운영망 수준으로 검증되지 않은
범위를 구분한다. 과거 브랜치 계획보다 코드와 자동 시나리오를 우선 기준으로
한다.

## 전체 진행도

```text
OVS Mirror
    ↓
Analyzer ── Security Event ──> Backend Policy
    │                              ↓
    └─ Packet/Traffic Summary   Flow lifecycle
                                   ↓
                              SDN Controller
                                   ↓
                         OpenFlow Rule / OVS Meter
                                   ↓
                         통계·Barrier·상태 재조정
```

| 영역 | 상태 | 현재 범위 |
|---|---|---|
| 네트워크 관측 구성요소 | 구현 | `s1` OVS Mirror와 `sdn-sensor0` 기반 양방향 캡처 |
| 패킷 요약·시계열 | 구현 | 프로토콜·호스트·포트별 집계, BPS/PPS |
| 위협 탐지 | 구현 | Port Scan, ICMP Flood, 보호 서버 행위 4종 |
| 전달 내구성 | 구현 | SQLite WAL Outbox, 지수 Backoff, Dead Letter |
| 이벤트 저장·운영 | 구현 | Elasticsearch, PostgreSQL, WebSocket, 수동 작업 |
| 자동 대응 | 구현 | 정책 기반 DROP/RATE_LIMIT 후보 적용 |
| Controller | 구현 | OpenFlow 1.3, L2, 경로, Flow/Meter lifecycle |
| 경로 복원력 | 구현 | Primary/Backup 장애 우회와 복구 |
| 부하 분산 | 구현 | PPS 임계값과 TCP 5-tuple 기반 2경로 분산 |
| 상태 검증 | 구현 | Barrier, Flow 통계, 주기적 Backend 재조정 |
| 운영 화면 | 구현 | Dashboard, Security, Flow, Topology, Settings |
| 격리 통합 시나리오 | 구현 | Mininet/OVS 시나리오와 Multipass 실행 스크립트 |
| secure-default Multipass bootstrap | 구현 | Sensor 자동 준비, Compose 병합, Analyzer Key·Outbox volume·host network |
| 운영망 제품화 | 미완료 | 다중 Sensor, HA, 대규모 성능, L7 분석은 후속 범위 |

## Analyzer

### 구현 상태

Analyzer는 지정 인터페이스에서 Scapy로 패킷을 캡처해 L2~L4 메타데이터를
만들고, 시간창 단위로 요약·탐지 결과를 생성한다. Mininet 트래픽을 관측하는
배치에서는 OVS Mirror에 연결된 `sdn-sensor0`을 사용한다. Multipass
bootstrap은 `auto`를 이 인터페이스로 해석하고 Analyzer 시작 전에 Sensor
veth를 멱등 준비한다.

| 기능 | 상태 | 구현 위치 |
|---|---|---|
| Ethernet/IPv4/TCP/UDP/ICMP 파싱 | 구현 | `analyzer/app/packet/parser.py` |
| 패킷·프로토콜·호스트 Flow 집계 | 구현 | `packet/summary.py` |
| 전체 BPS/PPS와 네트워크 상태 | 구현 | `detection/traffic_stats.py` |
| TCP SYN Port Scan | 구현 | `detection/port_scan.py` |
| ICMP Flood | 구현 | `detection/security_events.py` |
| Server Egress | 구현 | `detection/server_behavior.py` |
| Lateral Movement | 구현 | `detection/server_behavior.py` |
| Data Exfiltration | 구현 | `detection/server_behavior.py` |
| C2 Beacon | 구현 | `detection/server_behavior.py` |
| 이벤트 fingerprint·윈도우 중복 억제 | 구현 | `detection/security_events.py` |
| 영속 전달 Queue | 구현 | `outbox.py` |
| 상태 보고 | 구현 | `analyzer_status.py` |

패킷·탐지 요약과 보안 이벤트는 한 분석 윈도우 단위로 SQLite Outbox에 먼저
저장된다. 연결 오류, timeout, `5xx`, `408`, `425`, `429`는 지수 Backoff로
재시도하고 그 밖의 `4xx`는 Dead Letter로 보존한다. 상태 보고는 별도 주기이며
Outbox에 넣지 않는다.

### 현재 제한

- 원본 PCAP 저장·검색과 TCP session 재조립은 제공하지 않는다.
- DNS·HTTP·TLS 내용, JA3/JA4 같은 암호화 트래픽 fingerprint는 분석하지 않는다.
- ICMP 탐지는 현재 분석 윈도우의 절대 PPS 기준 중심이다.
- ICMP baseline 관련 두 환경변수는 현재 점수 계산에 반영되지 않는다.
- 탐지기의 연결 이력과 행동 baseline은 메모리 상태라 재시작 후 다시 수집한다.

## Backend

### 구현 상태

Backend는 FastAPI 기반 정책·상태 관리 계층이다. Analyzer 입력을 저장하고,
자동 대응 설정과 이벤트 심각도를 평가해 Controller 작업을 생성한다.

| 책임 | 상태 |
|---|---|
| Analyzer 상태·요약 수신 | 구현 |
| PostgreSQL/InfluxDB/Elasticsearch 저장 | 구현 |
| Security Event 조회와 실시간 broadcast | 구현 |
| `block`·`ignore`·`resolve` 수동 작업 | 구현 |
| 자동 대응 활성화 설정 | 구현 |
| Flow Rule 생성·삭제 lifecycle | 구현 |
| Controller timeout·제한 재시도 | 구현 |
| Controller 실제 상태 재조정 | 구현 |
| Controller·Dashboard·Path 조회 API | 구현 |
| 요청 크기 제한과 역할별 API Key | 구현 |
| WebSocket Origin·단기 서명 토큰 | 구현 |

자동 대응이 비활성화되면 이벤트와 Security Response는 기록하지만 Analyzer가
제안한 mitigation을 Flow Rule로 자동 적용하지 않는다. 수동 이벤트 차단과
수동 Flow Rule 생성은 계속 사용할 수 있다.

Flow lifecycle:

```text
PENDING -> APPLYING -> APPLIED
                    -> FAILED

APPLIED -> REMOVING -> REMOVED
                     -> REMOVE_FAILED
        -> EXPIRED
```

`FlowReconciler`는 기본 30초마다 PostgreSQL과 Controller의 메모리 Rule 목록을
비교한다. Controller가 보고한 만료·제거를 반영하고, Backend에 활성 상태지만
Controller에 없는 Rule은 동일 ID/cookie로 다시 설치한다.

### 저장소

| 저장소 | 데이터 |
|---|---|
| PostgreSQL | Analyzer 상태, Flow Rule, Security Response, 런타임 설정 |
| InfluxDB | 패킷·프로토콜·호스트·네트워크 시계열 |
| Elasticsearch | 패킷 요약 문서와 Security Event |

## Controller와 데이터 플레인

### Controller

OS-Ken 기반 Controller는 OpenFlow 1.3 스위치를 관리하며 FastAPI REST를 같은
프로세스의 별도 스레드에서 제공한다.

- 정책 Table 0과 L2 Forwarding Table 1 분리
- Barrier 확인 기반 Table-Miss·외부 Flow 작업
- 고정 access port의 MAC/IP 바인딩과 host spoof 차단
- ARP/IPv4 학습, 첫 패킷 Packet-Out, 양방향 L2 Flow
- 가중 Dijkstra Primary/Backup 경로
- PortStatus와 Port Description 기반 장애·재연결 처리
- 포트·Flow 통계 수집
- TCP 5-tuple 단위 경로 분산과 hysteresis 복귀
- `DROP`, `OUTPUT`, `RATE_LIMIT` 외부 정책
- PKTPS OVS Meter 공유·참조 해제·timeout cleanup
- `/health` 외 REST API의 Controller API Key 보호

외부 Rule은 안정적인 Backend ID에서 cookie를 계산한다. Controller는
Flow-Mod/Meter-Mod 뒤의 Barrier Reply를 받기 전에 `APPLIED`를 반환하지 않는다.

### Mininet/OVS

```text
h1/h2/h3 -- s1 -- s2 -- s4 -- web
               \-- s3 --/
```

- 고정 DPID·IP·MAC·포트 맵
- OpenFlow 1.3과 secure fail mode
- 링크별 bandwidth·delay·loss 설정
- `s1` port 6 전용 OVS Mirror output
- Mutillidae 격리 웹 서비스 relay
- Mininet 종료와 stale OVS 상태 cleanup

`data-plane/scripts/verify.sh`는 failover, host spoofing, 링크 성능, 외부
Flow Rule, RATE_LIMIT, Mirror 캡처를 순서대로 실행한다. Analyzer·Backend가
필요한 자동 대응과 서버 행위 시나리오는 별도 실행 파일로 제공한다.
현재 외부 Flow·RATE_LIMIT 시나리오는 Controller `X-API-Key`를 보내지 않으므로
인증이 활성화된 기본 보안 구성에서는 추가 보완 없이 통과하지 않는다.

## Frontend

| 화면 | 경로 | 현재 기능 |
|---|---|---|
| Dashboard | `/` | 트래픽, 프로토콜, Analyzer/Controller 상태, 경로 PPS |
| Security Events | `/security/events` | 필터·검색·상세, block/ignore/resolve |
| Flow Rules | `/flow-rules` | 실제 topology 대상 Rule 생성·삭제와 counter |
| Topology | `/topology` | switch/link/host와 Primary/Backup 상태 |
| Settings | `/settings` | 자동 대응과 혼잡 표시 기준 설정 |

Frontend는 Next.js rewrite를 통해 Admin API Key를 Backend 요청에 전달한다.
WebSocket은 Admin API로 단기 토큰을 발급받은 뒤 허용 Origin과 subprotocol을
사용해 연결한다. Controller를 사용할 수 없으면 DB 이력과 명시적인 연결 오류를
표시한다.

## 배포와 보안

| 배치 | Development host | Multipass VM |
|---|---|---|
| `dataplane` | Backend, Frontend, DB | Controller, Analyzer, Mininet/OVS; Sensor 자동 준비와 병합 Compose 적용 |
| `full` | 실행 스크립트 | 전체 서비스와 Mininet/OVS; Analyzer host network와 Sensor 자동 적용 |

서비스와 저장소 포트는 기본적으로 `127.0.0.1`에 bind한다. Analyzer,
Controller, Admin API Key는 서로 분리하고 WebSocket 토큰 서명 키도 별도로
설정한다. `.env.example` 값은 공개 예시이므로 실제 실행 전에 교체해야 한다.

## Migration

| 버전 | 내용 |
|---|---|
| `001` | `sdn_controller` schema와 공통 timestamp trigger |
| `002` | Analyzer 상태 테이블 |
| `003` | Flow Rule 테이블 |
| `004` | Security Response와 Flow 연계 |
| `005` | Flow Rule 제거 시각과 제거 lifecycle |
| `006` | 런타임 플랫폼 설정 |
| `007` | event ID 기준 Security Response/Flow identity |

## 검증 상태

### 저장소에 포함된 자동 검증

- Analyzer 정책, Outbox, Backend client와 서버 행위 단위 테스트
- Backend 인증, 저장·정책, Flow lifecycle·재조정, Dashboard/Path 단위 테스트
- Controller routing, topology, host, Flow, Meter, 통계 단위 테스트
- Mininet Sensor, link config, TCP relay 단위 테스트
- Multipass 기반 data-plane 통합 검증 스크립트
- Analyzer ICMP Flood → Backend → Controller Meter 종단 간 시나리오
- Lateral Movement 탐지만/자동 DROP 비교 시나리오

단위 테스트는 Python 3.10 이상과 각 구성요소 의존성이 설치된 환경에서
구성요소별로 실행해야 한다. 현재 macOS host에서 의존성 없이 직접 실행하면
`pytest`, FastAPI 또는 OS-Ken 부재로 실행되지 않으므로 Controller 이미지나
개발 의존성 환경을 사용한다.

통합 스크립트와 종단 간 시나리오가 저장소에 있다는 사실과 현재 환경에서의
최신 통과 결과는 구분해야 한다. bootstrap의 Sensor와 Analyzer secure-default
구성은 반영됐지만, 일부 시나리오의 API Key 전달을 보완한 뒤 전체 Multipass
검증을 다시 실행해야 한다.

## 남은 우선순위

현재 주요 공백은 구현 유무보다 운영망 제품화와 NDR 조사 깊이에 있다.

1. 다중 Mirror/Sensor 등록, health 집계와 설정 배포
2. secure-default 환경의 나머지 통합 시나리오 API Key 전달
3. 운영 규모 패킷 손실·Queue 성장·Controller 처리량 측정
4. DNS·HTTP·TLS metadata와 암호화 트래픽 분석
5. PCAP/session 검색, 사건 timeline과 hunting 기능
6. 자산·사용자 문맥, threat intelligence, 탐지 규칙 versioning
7. Controller/Backend HA와 재시작 복구 시간 검증
8. 탐지별 오탐 기준선과 운영 승인 정책 고도화

서버 내부 `sudo`, 프로세스, 파일 변경은 네트워크 Analyzer 범위가 아니다.
필요하면 `auditd`, eBPF 또는 EDR telemetry를 별도 수집기로 설계해야 한다.
