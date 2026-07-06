import time

from elasticsearch import Elasticsearch
from elasticsearch import ConnectionError as ElasticsearchConnectionError

from app.core.config import settings

# elasticsearch 클라이언트 생성 함수
def get_elasticsearch_client() -> Elasticsearch:
    # password = get_env("ELASTIC_PASSWORD")

    return Elasticsearch(
        settings.elasticsearch_url,
        # basic_auth=("elastic", password),
    )

def create_elasticsearch_indices() -> None:
    """
    SDN 프로젝트에서 사용할 Elasticsearch 인덱스를 생성

    생성 대상:
        1. sdn-security-events
            - 포트 스캔, ICMP flood 같은 보안 이벤트 저장
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

    if not es.indices.exists(index="sdn-security-events"):
        es.indices.create(
            index="sdn-security-events",
            mappings={
                "properties": {
                    "@timestamp": {"type": "date"},
                    "event_id": {"type": "keyword"},
                    "event_fingerprint": {"type": "keyword"},
                    "dedup_key": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "analyzer_id": {"type": "keyword"},
                    "attack_category": {"type": "keyword"},
                    "attack_type": {"type": "keyword"},
                    "severity": {"type": "keyword"},
                    "confidence": {"type": "keyword"},
                    "status": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "dst_ip": {"type": "ip"},
                    "protocol": {"type": "keyword"},
                    "detection_rule": {"type": "keyword"},
                    "recommended_action": {"type": "keyword"},
                    "response_level": {"type": "keyword"},
                    "evidence": {"type": "object", "enabled": True},
                    "mitigation": {"type": "object", "enabled": True},
                }
            },
        )


def index_security_event(payload: dict) -> None:
    es = get_elasticsearch_client()

    document = {
        **payload,
        "@timestamp": payload["timestamp"],
    }

    es.index(
        index="sdn-security-events",
        document=document,
    )


def search_security_events(limit: int = 50) -> list[dict]:
    es = get_elasticsearch_client()
    try:
        response = es.search(
            index="sdn-security-events",
            size=limit,
            sort=[
                {"@timestamp": {"order": "desc"}},
            ],
            query={
                "match_all": {},
            },
        )

        items = []
        for hit in response["hits"]["hits"]:
            source = hit["_source"]
            items.append({
                "id": hit["_id"],
                **source,
            })

        return items
    finally:
        es.close()


def query_suspicious_hosts_from_security_events(
    limit: int = 100,
) -> list[dict]:
    events = search_security_events(limit)
    hosts: dict[tuple[str, str, str], dict] = {}

    for event in events:
        ip = event.get("src_ip")
        if not ip:
            continue

        protocol = event.get("protocol") or "UNKNOWN"
        attack_type = event.get("attack_type") or "UNKNOWN"
        key = (ip, protocol, attack_type)
        evidence = event.get("evidence") or {}
        reason = event.get("detection_rule") or attack_type

        hosts.setdefault(
            key,
            {
                "timestamp": event.get("timestamp") or event.get("@timestamp"),
                "analyzer_id": event.get("analyzer_id"),
                "host": ip,
                "ip": ip,
                "protocol": protocol,
                "bps": float(evidence.get("bps") or 0),
                "pps": float(evidence.get("pps") or 0),
                "reasons": [reason],
                "attack_type": attack_type,
                "severity": event.get("severity"),
                "status": event.get("status"),
            },
        )

    return sorted(
        hosts.values(),
        key=lambda item: (
            item.get("severity") == "critical",
            item.get("severity") == "high",
            item["bps"],
            item["pps"],
            item["ip"],
        ),
        reverse=True,
    )
