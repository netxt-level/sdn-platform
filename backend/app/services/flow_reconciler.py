"""Bounded background reconciliation for pending Controller operations."""

import asyncio
import logging

from app.services.flow_service import FlowService


logger = logging.getLogger(__name__)


class FlowReconciler:
    def __init__(self, flow_service=None, interval_seconds=30.0):
        self.flow_service = flow_service or FlowService()
        self.interval_seconds = interval_seconds
        self._stop = asyncio.Event()

    async def run(self):
        while not self._stop.is_set():
            result = await asyncio.to_thread(
                self.flow_service.reconcile_flows,
            )
            if result.get("status") not in {"COMPLETED"}:
                logger.warning("flow_reconciliation result=%s", result)
            try:
                await asyncio.wait_for(
                    self._stop.wait(),
                    timeout=self.interval_seconds,
                )
            except TimeoutError:
                continue

    def stop(self):
        self._stop.set()
