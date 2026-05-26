"use client";

import { PageHeader } from "@/components/layout/PageHeader";
import { SecurityEventsTable } from "@/components/security/SecurityEventsTable";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { formatBitsPerSecond, formatDateTime, formatNumber } from "@/lib/format";
import { useRealtime } from "@/hooks/useRealtime";
import { AlertTriangle, Ban, CheckCircle2, Radio, ShieldAlert } from "lucide-react";

export default function SecurityEventsPage() {
  const state = useRealtime();
  const selectedEvent = state.securityEvents[0];
  const highCount = state.securityEvents.filter((event) => event.severity === "high" || event.severity === "critical").length;
  const blockedCount = state.securityEvents.filter((event) => event.status === "blocked").length;
  const resolvedCount = state.securityEvents.filter((event) => event.status === "resolved").length;

  return (
    <>
      <PageHeader
        title="보안 이벤트"
        description="ICMP Flood, SYN Flood, UDP Flood, Port Scan 같은 탐지 이벤트와 대응 상태를 관리합니다."
        connected={state.connected}
        source={state.source}
      />

      <div className="grid grid-cols-5 gap-4 max-xl:grid-cols-2 max-sm:grid-cols-1">
        <MetricCard label="전체 이벤트" value={formatNumber(state.securityEvents.length)} foot="오늘" icon={ShieldAlert} tone="blue" />
        <MetricCard label="고위험" value={formatNumber(highCount)} foot="대응 필요" icon={AlertTriangle} tone="red" />
        <MetricCard label="중위험" value="2" foot="모니터링 중" icon={Radio} tone="amber" />
        <MetricCard label="차단 조치" value={formatNumber(blockedCount)} foot="Flow Rule 적용" icon={Ban} tone="red" />
        <MetricCard label="해소됨" value={formatNumber(resolvedCount)} foot="정상 복귀" icon={CheckCircle2} tone="teal" />
      </div>

      <div className="mt-4 grid grid-cols-[1fr_360px] gap-4 max-xl:grid-cols-1">
        <Panel
          title="보안 이벤트 목록"
          action={
            <div className="flex flex-wrap items-center gap-2">
              {["전체", "ICMP Flood", "SYN Flood", "UDP Flood", "Port Scan"].map((label, index) => (
                <button
                  key={label}
                  className={[
                    "font-mono-ui rounded-full border px-3 py-1 text-[10px]",
                    index === 0
                      ? "border-red bg-[var(--red-dim)] text-red"
                      : "border-line2 text-muted"
                  ].join(" ")}
                >
                  {label}
                </button>
              ))}
              <input className="font-mono-ui h-8 w-40 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none" placeholder="IP 검색" disabled />
            </div>
          }
        >
          <SecurityEventsTable events={state.securityEvents} />
        </Panel>

        <div className="grid gap-4">
          <Panel title="이벤트 상세">
            <div className="font-mono-ui grid gap-3 text-[11px]">
              <div className="flex items-center justify-between">
                <span className="text-faint">Event ID</span>
                <strong>{selectedEvent.id}</strong>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-faint">공격 유형</span>
                <StatusBadge value={selectedEvent.attack_type} tone="critical" />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-faint">위험도</span>
                <StatusBadge value={selectedEvent.severity} tone="critical" />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-faint">출발지</span>
                <strong className="text-accent">{selectedEvent.src_ip}</strong>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-faint">목적지</span>
                <strong className="text-yellow">{selectedEvent.dst_ip}</strong>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-faint">트래픽</span>
                <strong>{formatNumber(selectedEvent.pps)} pps · {formatBitsPerSecond(selectedEvent.bps)}</strong>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-faint">발생 시간</span>
                <strong>{formatDateTime(selectedEvent.occurred_at)}</strong>
              </div>
              <div className="rounded border border-line bg-sidebar p-3 leading-6 text-muted">
                <span className="text-faint">[12:41:33]</span> <span className="text-accent">{selectedEvent.src_ip}</span> → <span className="text-yellow">{selectedEvent.dst_ip}</span> {selectedEvent.protocol} pkt={selectedEvent.pps} <span className="text-red">[{selectedEvent.status.toUpperCase()}]</span>
                <br />
                <span className="text-faint">[12:41:34]</span> Flow Rule 후보: DROP src={selectedEvent.src_ip}
                <br />
                <span className="text-faint">[12:41:35]</span> 미러링 패킷 분석 완료
              </div>
              <button className="rounded border border-red bg-[var(--red-dim)] px-3 py-2 text-left text-red">공격 호스트 차단</button>
              <button className="rounded border border-line2 bg-[var(--yellow-dim)] px-3 py-2 text-left text-yellow">우회 경로 전환</button>
              <button className="rounded border border-line2 bg-[var(--green-dim)] px-3 py-2 text-left text-green">해결 처리</button>
            </div>
          </Panel>

          <Panel title="공격 유형 분포">
            <div className="grid gap-3">
              {[
                ["ICMP Flood", 10, "bg-red"],
                ["SYN Flood", 7, "bg-yellow"],
                ["UDP Flood", 4, "bg-accent"],
                ["Port Scan", 3, "bg-purple"]
              ].map(([label, value, color]) => (
                <div key={label as string} className="font-mono-ui">
                  <div className="mb-1 flex justify-between text-[11px]">
                    <span className="text-muted">{label}</span>
                    <span>{value}</span>
                  </div>
                  <div className="h-1.5 rounded bg-sidebar">
                    <div className={`h-full rounded ${color}`} style={{ width: `${Number(value) * 8}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}
