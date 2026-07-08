import asyncio


class RecordingManager:
    def __init__(self):
        self.messages = []

    async def broadcast(self, message):
        self.messages.append(message)


class StubAnalyzerRepository:
    def __init__(self):
        self.saved_statuses = []

    def list_statuses(self, analyzer_id=None):
        return [{"analyzer_id": analyzer_id or "analyzer-1"}]

    def save_status(self, payload):
        self.saved_statuses.append(payload)


class StubTrafficRepository:
    def __init__(self):
        self.packet_summaries = []
        self.detection_summaries = []

    def save_packet_summary(self, payload):
        self.packet_summaries.append(payload)

    def save_detection_summary_metrics(self, payload):
        self.detection_summaries.append(payload)


def test_analyzer_service_persists_and_broadcasts_payloads(load_service_module):
    manager = RecordingManager()
    module = load_service_module(
        "analyzer_service",
        stubs={
            "app.core.websocket": {"manager": manager},
            "app.repositories.analyzer_repository": {
                "AnalyzerRepository": StubAnalyzerRepository,
            },
            "app.repositories.traffic_repository": {
                "TrafficRepository": StubTrafficRepository,
            },
        },
    )
    analyzer_repository = StubAnalyzerRepository()
    traffic_repository = StubTrafficRepository()
    service = module.AnalyzerService(
        analyzer_repository=analyzer_repository,
        traffic_repository=traffic_repository,
    )

    status = {"analyzer_id": "analyzer-1", "status": "running"}
    packet_summary = {"analyzer_id": "analyzer-1", "total_packets": 12}
    detection_summary = {"analyzer_id": "analyzer-1", "network_status": "normal"}

    asyncio.run(service.receive_status(status))
    asyncio.run(service.receive_packet_summary(packet_summary))
    asyncio.run(service.receive_detection_summary(detection_summary))

    assert analyzer_repository.saved_statuses == [status]
    assert traffic_repository.packet_summaries == [packet_summary]
    assert traffic_repository.detection_summaries == [detection_summary]
    assert manager.messages == [
        {"type": "analyzer_status", "data": status},
        {"type": "packet_summary", "data": packet_summary},
        {"type": "detection_summary", "data": detection_summary},
    ]
