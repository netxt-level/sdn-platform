import os

from dotenv import load_dotenv
from elasticsearch import Elasticsearch

load_dotenv()

# env 파일 환경변수 로드
def get_env(name: str, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if value is None:
        raise RuntimeError(f"Missing environment variable: {name}")
    return value

# elasticsearch 클라이언트 생성 함수
def get_elasticsearch_client() -> Elasticsearch:

    host = get_env("ELASTICSEARCH_HOST", "localhost")
    port = get_env("ELASTICSEARCH_HTTP_PORT", "9200")
    # password = get_env("ELASTIC_PASSWORD")

    return Elasticsearch(
        f"http://{host}:{port}",
        # basic_auth=("elastic", password),
    )

def create_elasticsearch_indices() -> None:
    """
    SDN 프로젝트에서 사용할 Elasticsearch 인덱스를 생성

    생성 대상:
        1. sdn-traffic-summary
            - 트래픽 요약 데이터 저장
            - analyzer가 일정 시간 단위로 계산한 패킷 수, 비트 수, 호스트별 통계 저장

        2. sdn-detection-events
            - 이상 트래픽 탐지 결과 저장
            - 네트워크 상태, 의심 호스트, 탐지 이유 등을 저장
    """

    # Elasticsearch 클라이언트 생성
    es = get_elasticsearch_client()
    
    # elasticsearch가 요청을 받을 준비가 되었는지 대기
    for attempt in range(30):
        try:
            if es.ping():
                break
        except ElasticsearchConnectionError:
            pass

        time.sleep(2)
    else:
        raise RuntimeError("Elasticsearch is not ready")

    # 1. 트래픽 요약 인덱스 생성
    # 예시 데이터:
    # {
    #   "@timestamp": "2026-05-24T10:00:05+09:00",
    #   "analyzer_id": "analyzer-1",
    #   "window_sec": 1,
    #   "total_packets": 120,
    #   "total_bits": 98304,
    #   "protocol_stats": {
    #       "TCP": 80,
    #       "UDP": 20,
    #       "ICMP": 20
    #   },
    #   "host_stats": [...]

    # 인덱스가 존재하지 않을 때만 생성
    if not es.indices.exists(index="sdn-traffic-summary"):
        es.indices.create(
            index="sdn-traffic-summary",

            # mappings는 Elasticsearch에 저장할 필드 타입을 정의
            mappings={
                "properties": {
                    "@timestamp": {"type": "date"},         # 로그 또는 이벤트 발생 시각
                    "analyzer_id": {"type": "keyword"},     # 패킷 수신 분석 서버 ID
                    "window_sec": {"type": "integer"},      # 트래픽 집계 시간
                    "total_packets": {"type": "long"},      # 수집된 전체 패킷 수
                    "total_bits": {"type": "long"},         # 수집된 전체 비트 수
                    "protocol_stats": {"type": "object"},   # 프로토콜별 통계

                    # 호스트 간 통신 통계
                    "host_stats": {
                        "type": "nested",
                        "properties": {
                            "src_host": {"type": "keyword"},    # 출발지 호스트 이름
                            "src_ip": {"type": "ip"},           # 출발지 IP
                            "dst_host": {"type": "keyword"},    # 목적지 호스트 이름
                            "dst_ip": {"type": "ip"},           # 목적지 IP
                            "protocol": {"type": "keyword"},    # 해당 통신에서 사용된 프로토콜
                            "packet_count": {"type": "long"},   # 해당 호스트 간 통신 패킷 수
                            "bit_count": {"type": "long"},      # 해당 호스트 간 통신 비트 수
                        },
                    },
                }
            },
        )

    # 2. 탐지 이벤트 인덱스 생성
    # 예시 데이터:
    # {
    #   "@timestamp": "2026-05-24T10:00:05+09:00",
    #   "analyzer_id": "analyzer-1",
    #   "network_status": "warning",
    #   "total_bps": 1000000.5,
    #   "total_pps": 1500.2,
    #   "active_flow_count": 25,
    #   "suspicious_host_count": 1,
    #   "suspicious_hosts": [...]
    # }

    # 인덱스가 존재하지 않을 때만 생성
    if not es.indices.exists(index="sdn-detection-events"):
        es.indices.create(
            index="sdn-detection-events",

            mappings={
                "properties": {
                    "@timestamp": {"type": "date"},                 # 탐지 이벤트 발생 시각
                    "analyzer_id": {"type": "keyword"},             # 패킷 수신 분석 서버 ID
                    "network_status": {"type": "keyword"},          # 전체 네트워크 상태
                    "total_bps": {"type": "double"},                # 전체 네트워크 bps
                    "total_pps": {"type": "double"},                # 전체 네트워크 pps
                    "active_flow_count": {"type": "integer"},       # 현재 활성 flow 개수
                    "suspicious_host_count": {"type": "integer"},   # 의심 호스트 수

                    # 의심 호스트 목록
                    "suspicious_hosts": {
                        "type": "nested",
                        "properties": {
                            "host": {"type": "keyword"},            # 의심 호스트 이름
                            "ip": {"type": "ip"},                   # 의심 호스트 IP 주소
                            "protocol": {"type": "keyword"},        # 의심 트래픽 프로토콜
                            "bps": {"type": "double"},              # 해당 호스트의 bps
                            "pps": {"type": "double"},              # 해당 호스트의 pps
                            "reasons": {"type": "keyword"},         # 의심 사유
                        },
                    },
                }
            },
        )
    
def index_traffic_summary(payload: dict) -> None:
    """
    traffic summary payload를 Elasticsearch에 저장한다.

    저장 위치:
        index: sdn-traffic-summary

    payload의 timestamp는 Elasticsearch 표준 필드명인 @timestamp로도 복사한다.
    """

    es = get_elasticsearch_client()

    document = {
        **payload,
        "@timestamp": payload["timestamp"],
    }

    es.index(
        index="sdn-traffic-summary",
        document=document,
    )


def index_detection_event(payload: dict) -> None:
    """
    detection summary payload를 Elasticsearch에 저장한다.

    저장 위치:
        index: sdn-detection-events

    payload의 timestamp는 Elasticsearch 표준 필드명인 @timestamp로도 복사한다.
    """

    es = get_elasticsearch_client()

    document = {
        **payload,
        "@timestamp": payload["timestamp"],
    }

    es.index(
        index="sdn-detection-events",
        document=document,
    )
