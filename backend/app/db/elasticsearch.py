import time
from typing import Any

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

from app.core.config import settings


SECURITY_EVENTS_INDEX = "sdn-security-events"
SECURITY_EVENTS_MAPPING = {
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
        # evidence는 화면 상세 확인용 원문으로 보관하고, 임의 key가
        # Elasticsearch field를 계속 늘리지 않도록 인덱싱하지 않는다.
        "evidence": {"type": "object", "enabled": False},
        "mitigation": {"type": "object", "enabled": True},
    }
}


def get_elasticsearch_client() -> Elasticsearch:
    return Elasticsearch(
        settings.elasticsearch_url,
    )


def is_elasticsearch_ready() -> bool:
    es = get_elasticsearch_client()
    try:
        return bool(es.ping()) and bool(
            es.indices.exists(index=SECURITY_EVENTS_INDEX)
        )
    except Exception:
        return False
    finally:
        es.close()


def create_elasticsearch_indices() -> None:
    es = get_elasticsearch_client()

    try:
        # Elasticsearch가 요청을 받을 수 있을 때만 인덱스 생성을 시도한다.
        for _ in range(30):
            try:
                if es.ping():
                    break
            except Exception:
                pass

            time.sleep(2)
        else:
            raise RuntimeError("Elasticsearch is not ready")

        _ensure_security_events_index(es)
    finally:
        es.close()


def _ensure_security_events_index(es: Elasticsearch) -> None:
    if not es.indices.exists(index=SECURITY_EVENTS_INDEX):
        es.indices.create(
            index=SECURITY_EVENTS_INDEX,
            mappings=SECURITY_EVENTS_MAPPING,
        )


def index_security_events(events: list[dict[str, Any]]) -> None:
    if not events:
        return

    es = get_elasticsearch_client()
    try:
        _ensure_security_events_index(es)
        actions = [
            {
                "_op_type": "index",
                "_index": SECURITY_EVENTS_INDEX,
                "_id": event["event_id"],
                "_source": {
                    **event,
                    "@timestamp": event["timestamp"],
                },
            }
            for event in events
        ]
        bulk(es, actions)
    finally:
        es.close()


def index_security_event(payload: dict[str, Any]) -> None:
    index_security_events([payload])


def search_security_events(
    limit: int = 50,
    range_value: str | None = None,
) -> list[dict]:
    query: dict[str, Any]
    if range_value:
        query = {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{range_value}",
                            }
                        }
                    }
                ]
            }
        }
    else:
        query = {
            "match_all": {},
        }

    es = get_elasticsearch_client()
    try:
        response = es.search(
            index=SECURITY_EVENTS_INDEX,
            size=limit,
            sort=[
                {"@timestamp": {"order": "desc"}},
            ],
            query=query,
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


def _number_from_evidence(evidence: dict, *keys: str) -> float:
    for key in keys:
        value = evidence.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return float(value)
    return 0.0


def _pps_from_evidence(evidence: dict) -> float:
    explicit_pps = _number_from_evidence(evidence, "syn_pps", "pps")
    if explicit_pps > 0:
        return explicit_pps

    packet_count = _number_from_evidence(evidence, "packet_count", "syn_count")
    window_seconds = _number_from_evidence(evidence, "window_seconds")
    if packet_count > 0 and window_seconds > 0:
        return packet_count / window_seconds

    return 0.0


def query_suspicious_hosts_from_security_events(
    limit: int = 100,
    range_value: str | None = None,
) -> list[dict]:
    events = search_security_events(limit, range_value=range_value)
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
                "pps": _pps_from_evidence(evidence),
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
