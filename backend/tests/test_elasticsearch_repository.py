import sys
import types


elasticsearch_stub = types.ModuleType("elasticsearch")
elasticsearch_stub.Elasticsearch = object
elasticsearch_stub.ConnectionError = RuntimeError

helpers_stub = types.ModuleType("elasticsearch.helpers")
helpers_stub.bulk = lambda es, actions: None

dotenv_stub = types.ModuleType("dotenv")
dotenv_stub.load_dotenv = lambda: None

sys.modules.setdefault("elasticsearch", elasticsearch_stub)
sys.modules.setdefault("elasticsearch.helpers", helpers_stub)
sys.modules.setdefault("dotenv", dotenv_stub)

from app.db import elasticsearch as elasticsearch_module  # noqa: E402


class StubElasticsearchClient:
    def __init__(self):
        self.closed = False
        self.indices = types.SimpleNamespace(
            exists=lambda index: True,
            create=lambda index, mappings: None,
        )

    def close(self):
        self.closed = True


def test_index_security_events_uses_event_id_as_document_id(monkeypatch):
    client = StubElasticsearchClient()
    captured = {}

    def fake_bulk(es, actions):
        captured["client"] = es
        captured["actions"] = actions

    monkeypatch.setattr(
        elasticsearch_module,
        "get_elasticsearch_client",
        lambda: client,
    )
    monkeypatch.setattr(elasticsearch_module, "bulk", fake_bulk)

    elasticsearch_module.index_security_events([
        {
            "event_id": "evt-1",
            "timestamp": "2026-07-11T08:00:00+00:00",
            "attack_type": "ICMP_FLOOD",
        },
        {
            "event_id": "evt-2",
            "timestamp": "2026-07-11T08:00:01+00:00",
            "attack_type": "PORT_SCAN",
        },
    ])

    assert captured["client"] is client
    assert captured["actions"] == [
        {
            "_op_type": "index",
            "_index": "sdn-security-events",
            "_id": "evt-1",
            "_source": {
                "event_id": "evt-1",
                "timestamp": "2026-07-11T08:00:00+00:00",
                "attack_type": "ICMP_FLOOD",
                "@timestamp": "2026-07-11T08:00:00+00:00",
            },
        },
        {
            "_op_type": "index",
            "_index": "sdn-security-events",
            "_id": "evt-2",
            "_source": {
                "event_id": "evt-2",
                "timestamp": "2026-07-11T08:00:01+00:00",
                "attack_type": "PORT_SCAN",
                "@timestamp": "2026-07-11T08:00:01+00:00",
            },
        },
    ]
    assert client.closed is True


def test_index_security_events_skips_empty_batch(monkeypatch):
    called = False

    def fake_get_client():
        nonlocal called
        called = True

    monkeypatch.setattr(
        elasticsearch_module,
        "get_elasticsearch_client",
        fake_get_client,
    )

    elasticsearch_module.index_security_events([])

    assert called is False


def test_security_events_mapping_does_not_index_evidence_keys():
    evidence_mapping = (
        elasticsearch_module.SECURITY_EVENTS_MAPPING["properties"]["evidence"]
    )

    assert evidence_mapping == {"type": "object", "enabled": False}


def test_suspicious_hosts_use_syn_pps_when_pps_is_missing(monkeypatch):
    monkeypatch.setattr(
        elasticsearch_module,
        "search_security_events",
        lambda limit, range_value=None: [
            {
                "timestamp": "2026-07-11T08:00:00+00:00",
                "analyzer_id": "analyzer-1",
                "attack_type": "SYN_FLOOD",
                "severity": "high",
                "status": "detected",
                "src_ip": "10.0.0.2",
                "protocol": "TCP",
                "detection_rule": "tcp_syn_single_service_rate",
                "evidence": {
                    "syn_pps": 120.0,
                    "syn_count": 240,
                    "window_seconds": 2,
                },
            }
        ],
    )

    hosts = elasticsearch_module.query_suspicious_hosts_from_security_events()

    assert hosts[0]["ip"] == "10.0.0.2"
    assert hosts[0]["pps"] == 120.0


def test_search_security_events_applies_range_filter(monkeypatch):
    client = StubElasticsearchClient()
    captured = {}

    def fake_search(**kwargs):
        captured.update(kwargs)
        return {"hits": {"hits": []}}

    client.search = fake_search
    monkeypatch.setattr(
        elasticsearch_module,
        "get_elasticsearch_client",
        lambda: client,
    )

    events = elasticsearch_module.search_security_events(
        limit=10,
        range_value="1h",
    )

    assert events == []
    assert captured["size"] == 10
    assert captured["query"] == {
        "bool": {
            "filter": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": "now-1h",
                        }
                    }
                }
            ]
        }
    }
    assert client.closed is True
