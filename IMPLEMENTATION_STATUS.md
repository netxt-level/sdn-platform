# SDN Platform 구현 상태

기준 브랜치: `feat/security-arp-spoofing`

## 전체 흐름

```text
Packet Capture
  -> Analyzer summary / SecurityEvent
  -> Backend validation
  -> InfluxDB / Elasticsearch / PostgreSQL
  -> REST / WebSocket
  -> Dashboard / Security Events / Flow Rules
```

## Analyzer

구현 완료:

- Scapy 패킷 캡처와 ARP/IP/TCP/UDP/ICMP 파싱
- 패킷·프로토콜·호스트 통계 생성
- Port Scan 윈도우 집계와 중복 알림 억제
- ICMP Flood pps·score·대응 레벨 판단
- ARP Spoofing 신뢰 Gateway MAC 비교
- 공통 SecurityEvent, fingerprint, event ID, evidence 생성
- Backend 전송 오류 처리와 상태 보고

보안 탐지 구현 위치:

| 파일 | 역할 |
|---|---|
| `analyzer/app/packet/parser.py` | ARP와 L3/L4 메타데이터 추출 |
| `analyzer/app/detection/port_scan.py` | SYN 기반 Port Scan |
| `analyzer/app/detection/security_events.py` | ARP/Port/ICMP 공통 이벤트 생성 |
| `analyzer/tests/test_security_detection_policy.py` | 보안 탐지 정책 회귀 테스트 |

과거 별도 `analyzer/app/security` 패키지는 제거했다. 탐지 엔진과 이벤트 계약은 `SecurityEventBuilder` 하나만 사용한다.

## Backend

구현 완료:

- Analyzer 상태 PostgreSQL 저장
- 패킷·트래픽 요약 InfluxDB 저장
- 보안 이벤트 Pydantic 검증
- 보안 이벤트 Elasticsearch `sdn-security-events` 저장
- 이벤트별 SecurityResponse 생성
- mitigation별 PENDING Flow Rule 생성
- Flow Rule 조회·수동 생성 API
- 경로 상태 API
- WebSocket `security_events` 묶음 전송

보안 API:

| 메서드 | 경로 | 역할 |
|---|---|---|
| `POST` | `/api/security/events` | 이벤트 수신·저장·대응 후보 생성 |
| `GET` | `/api/security/events` | 최근 보안 이벤트 조회 |
| `GET` | `/api/security/responses` | 대응 내역 조회 |
| `GET` | `/api/flows` | Flow Rule 후보 조회 |
| `POST` | `/api/flows` | 수동 Flow Rule 후보 생성 |

## Frontend

구현 완료:

- 초기 REST 이력과 WebSocket 실시간 데이터 병합
- ARP Spoofing, Port Scan, ICMP Flood 이벤트 표시
- 범위·공격 유형·IP/MAC 검색 필터
- 이벤트 행 선택과 상세 정보 표시
- ARP 공격자 MAC fallback 표시
- 대응 후보가 있으면 Flow Rules 화면으로 이동
- fingerprint가 아닌 event ID 기준 사건 이력 유지
- 트래픽·경로·Flow Rule 화면 Backend 연동

## 현재 보안 범위

| 이벤트 | 상태 | 대응 |
|---|---|---|
| `ARP_SPOOFING` | 최종 시나리오 | 근거 점수에 따라 L1/L2/L3, 충분하면 DROP 후보 |
| `PORT_SCAN` | 보조 탐지 | L1/L2 관찰·알림 |
| `ICMP_FLOOD` | 보조 탐지 | 높은 점수에서 L2 RATE_LIMIT 후보 |

제외:

- DDoS
- UDP Flood
- SYN Flood
- 링크 혼잡 보안 이벤트
- 링크 장애 보안 이벤트
- 보안 이벤트 기반 우회 경로 자동 전환

## 저장 구조

| 저장소 | 데이터 |
|---|---|
| PostgreSQL | Analyzer 상태, SecurityResponse, FlowRule |
| InfluxDB | 트래픽·프로토콜·호스트 통계 |
| Elasticsearch | 원본 SecurityEvent |

## 아직 남은 연동

- PENDING Flow Rule을 Controller에 실제 설치하는 호출
- Controller 결과에 따른 `APPLIED`, `FAILED` 상태 갱신
- 실제 인터페이스 기반 end-to-end 공격 재현
- 장시간·고부하 패킷 캡처 성능 검증

## 검증 명령

```bash
python -m pytest analyzer/tests backend/tests -q
python -m compileall -q analyzer/app backend/app
```

```bash
cd frontend
npm run build
```

## 커밋 전 확인

- Analyzer payload 변경 시 `backend/app/schemas/security.py`를 함께 확인한다.
- WebSocket 변경 시 `frontend/types/realtime.ts`와 `frontend/hooks/useRealtime.ts`를 함께 확인한다.
- DB 구조 변경 시 Alembic migration을 추가한다.
- 실제 Controller 적용 전에는 `PENDING`을 차단 완료로 표현하지 않는다.
