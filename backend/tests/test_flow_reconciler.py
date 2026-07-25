import asyncio
import importlib
import sys
import types


flow_service_module = types.ModuleType("app.services.flow_service")
flow_service_module.FlowService = object
previous_flow_service_module = sys.modules.get("app.services.flow_service")
sys.modules["app.services.flow_service"] = flow_service_module
FlowReconciler = importlib.import_module(
    "app.services.flow_reconciler"
).FlowReconciler
if previous_flow_service_module is None:
    del sys.modules["app.services.flow_service"]
else:
    sys.modules["app.services.flow_service"] = previous_flow_service_module


class RecordingFlowService:
    def __init__(self):
        self.calls = 0

    def reconcile_flows(self):
        self.calls += 1
        return {"status": "COMPLETED"}


def test_reconciler_runs_periodically_and_stops_cleanly():
    async def scenario():
        service = RecordingFlowService()
        reconciler = FlowReconciler(service, interval_seconds=0.01)
        task = asyncio.create_task(reconciler.run())
        await asyncio.sleep(0.025)
        reconciler.stop()
        await task
        return service.calls

    assert asyncio.run(scenario()) >= 2
