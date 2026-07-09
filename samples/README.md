# 보안 담당 샘플

이 README는 전체 프로젝트 샘플이 아니라, 보안 담당 파트에서 추가한 시나리오 샘플만 정리한다.
전체 실행 방식과 배포 설명은 프로젝트 README를 따르고, 여기서는 ARP Spoofing 최종 시나리오 확인에 필요한 파일만 다룬다.

| 파일 | 보안 담당 확인 내용 | 기대 결과 |
| --- | --- | --- |
| `security_scenario_06_arp_spoofing_final.json` | 최종 ARP Spoofing 시나리오. h2가 Gateway IP를 자신의 MAC으로 속이는 상황이다. | `ARP_SPOOFING` |

샘플은 현재 `SecurityEventBuilder` 입력 구조인 `security_config`, `packet_summary`, `packets`로 구성하며 Analyzer 테스트에서 직접 읽어 검증한다.

DDoS는 이번 최종 보안 범위에 포함하지 않는다. ICMP 보조 항목은 `ICMP_FLOOD`로 구분한다.
