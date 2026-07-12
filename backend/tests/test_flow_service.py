class StubFlowRepository:
    def __init__(self):
        self.calls = []
        self.count_calls = []

    def list_flows(self, src_ip=None, *, limit=100, offset=0):
        self.calls.append((src_ip, limit, offset))
        return [{"id": "flow-1"}]

    def count_flows(self, src_ip=None):
        self.count_calls.append(src_ip)
        return 41


def test_flow_service_passes_pagination_to_repository(load_service_module):
    module = load_service_module(
        "flow_service",
        stubs={
            "app.repositories.flow_repository": {
                "FlowRepository": StubFlowRepository
            },
        },
    )
    repository = StubFlowRepository()
    service = module.FlowService(flow_repository=repository)

    result = service.get_flows("10.0.0.2", limit=20, offset=40)

    assert result == {
        "items": [{"id": "flow-1"}],
        "limit": 20,
        "offset": 40,
        "total": 41,
        "has_more": False,
    }
    assert repository.calls == [("10.0.0.2", 20, 40)]
    assert repository.count_calls == ["10.0.0.2"]
