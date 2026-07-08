from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from .backend_contract import result_to_backend_payload
from .baseline import BaselineProfile
from .engine import SecurityAnalysisEngine
from .io import link_from_dict
from .models import AnalysisResult, DetectionConfig, LinkState, PacketRecord
from .ryu_adapter import flow_rules_from_policies, packet_record_from_ryu


@dataclass(frozen=True)
class SecurityRuntimeOutput:
    analysis: AnalysisResult
    backend_payload: dict[str, Any]
    flow_rules: list[dict[str, Any]]

    @property
    def has_events(self) -> bool:
        return self.analysis.has_events


class SecurityRuntime:
    """Analyzer의 짧은 분석 주기를 보완하는 보안 런타임.

    기본 분석 윈도우는 1초처럼 짧을 수 있다. Port Scan이나 ICMP Flood는 몇 초에
    걸쳐 쌓인 패턴을 봐야 하므로, 여기서 보안 판단용 rolling window를 따로
    유지한다.
    """

    def __init__(
        self,
        config: DetectionConfig | None = None,
        baseline: BaselineProfile | None = None,
        *,
        datapath_id: str | None = None,
        max_window_multiplier: float = 2.0,
        event_cooldown_seconds: float = 0.0,
    ) -> None:
        self.config = config or DetectionConfig()
        self.engine = SecurityAnalysisEngine(config=self.config, baseline=baseline)
        self.datapath_id = datapath_id
        self.max_window_multiplier = max(max_window_multiplier, 1.0)
        self.event_cooldown_seconds = max(event_cooldown_seconds, 0.0)
        self._packets: deque[PacketRecord] = deque()
        self._last_emitted_at: dict[str, datetime] = {}

    @property
    def buffered_packet_count(self) -> int:
        return sum(max(packet.packet_count, 1) for packet in self._packets)

    def observe_packet(self, packet: PacketRecord | dict[str, Any]) -> PacketRecord:
        record = packet if isinstance(packet, PacketRecord) else packet_record_from_ryu(packet)
        self._packets.append(record)
        self._prune(_latest_time(self._packets))
        return record

    def observe_packets(self, packets: Iterable[PacketRecord | dict[str, Any]]) -> list[PacketRecord]:
        records = [self.observe_packet(packet) for packet in packets]
        if records:
            self._prune(max(record.timestamp for record in records))
        return records

    def clear(self) -> None:
        self._packets.clear()
        self._last_emitted_at.clear()

    def analyze(
        self,
        links: Iterable[LinkState | dict[str, Any]] | None = None,
        *,
        now: datetime | None = None,
        datapath_id: str | None = None,
    ) -> SecurityRuntimeOutput:
        analysis_time = now or _latest_time(self._packets)
        self._prune(analysis_time)
        link_states = [_coerce_link(link) for link in (links or [])]
        analysis = self.engine.analyze(list(self._packets), links=link_states, now=analysis_time)
        analysis = self._apply_event_cooldown(analysis, analysis_time)
        return SecurityRuntimeOutput(
            analysis=analysis,
            backend_payload=result_to_backend_payload(analysis),
            flow_rules=flow_rules_from_policies(
                analysis.policies,
                datapath_id=datapath_id or self.datapath_id,
            ),
        )

    def analyze_snapshot(
        self,
        packets: Iterable[PacketRecord | dict[str, Any]],
        links: Iterable[LinkState | dict[str, Any]] | None = None,
        *,
        now: datetime | None = None,
        datapath_id: str | None = None,
    ) -> SecurityRuntimeOutput:
        self.observe_packets(packets)
        return self.analyze(links=links, now=now, datapath_id=datapath_id)

    def _prune(self, now: datetime) -> None:
        retention_seconds = self.config.window_seconds * self.max_window_multiplier
        cutoff = now.timestamp() - retention_seconds
        while self._packets and self._packets[0].timestamp.timestamp() < cutoff:
            self._packets.popleft()

    def _apply_event_cooldown(self, analysis: AnalysisResult, now: datetime) -> AnalysisResult:
        if self.event_cooldown_seconds <= 0 or not analysis.events:
            return analysis

        filtered_events = []
        for event in analysis.events:
            last_emitted = self._last_emitted_at.get(event.event_id)
            if last_emitted is not None and (now - last_emitted).total_seconds() < self.event_cooldown_seconds:
                continue
            filtered_events.append(event)
            self._last_emitted_at[event.event_id] = now

        filtered_policies = [event.policy for event in filtered_events if event.policy is not None]
        return AnalysisResult(
            window_seconds=analysis.window_seconds,
            packet_count=analysis.packet_count,
            events=filtered_events,
            policies=filtered_policies,
        )


def _latest_time(packets: Iterable[PacketRecord]) -> datetime:
    packet_list = list(packets)
    if packet_list:
        return max(packet.timestamp for packet in packet_list)
    return datetime.now(timezone.utc)


def _coerce_link(link: LinkState | dict[str, Any]) -> LinkState:
    if isinstance(link, LinkState):
        return link
    return link_from_dict(link)
