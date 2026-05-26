"use client";

import { Activity, Database, RadioTower, Search, TrendingUp } from "lucide-react";

import { MetricCard } from "@/components/dashboard/MetricCard";
import { ProtocolBars } from "@/components/dashboard/ProtocolBars";
import { TrafficTrend } from "@/components/dashboard/TrafficTrend";
import { PageHeader } from "@/components/layout/PageHeader";
import { HostStatsTable } from "@/components/traffic/HostStatsTable";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { formatBitsPerSecond, formatNumber } from "@/lib/format";
import { useRealtime } from "@/hooks/useRealtime";

const packetLogs = [
  { time: "12:41:33", src: "10.0.0.2", dst: "10.0.0.4", protocol: "ICMP", sport: "-", dport: "-", size: "64B", path: "mirror", action: "drop" },
  { time: "12:41:31", src: "10.0.0.1", dst: "10.0.0.4", protocol: "TCP", sport: "51244", dport: "80", size: "1.4KB", path: "primary", action: "allow" },
  { time: "12:41:28", src: "10.0.0.3", dst: "10.0.0.4", protocol: "UDP", sport: "53000", dport: "53", size: "512B", path: "backup", action: "mirror" },
  { time: "12:41:22", src: "10.0.0.2", dst: "10.0.0.4", protocol: "TCP", sport: "42311", dport: "22", size: "920B", path: "primary", action: "drop" }
];

export default function TrafficPage() {
  const state = useRealtime();
  const { packetSummary, detectionSummary } = state;

  return (
    <>
      <PageHeader
        title="트래픽"
        description="출발지, 목적지, 프로토콜 기준으로 Flow 수준의 트래픽 요약을 확인합니다."
        connected={state.connected}
        source={state.source}
      />

      <div className="grid grid-cols-4 gap-4 max-xl:grid-cols-2 max-sm:grid-cols-1">
        <MetricCard label="실시간 PPS" value={formatNumber(detectionSummary.total_pps)} foot="전체 네트워크" icon={Activity} tone="blue" />
        <MetricCard label="실시간 BPS" value={formatBitsPerSecond(detectionSummary.total_bps)} foot="전체 대역폭 사용" icon={RadioTower} tone="teal" />
        <MetricCard label="총 패킷 수" value="1.24M" foot="+12.4% 어제 대비" icon={TrendingUp} tone="amber" />
        <MetricCard label="총 바이트" value="3.8GB" foot="정상 범위" icon={Database} tone="teal" />
      </div>

      <div className="mt-4 grid grid-cols-2 gap-4 max-xl:grid-cols-1">
        <Panel
          title="PPS / BPS 추이"
          action={
            <div className="flex gap-1">
              <button className="font-mono-ui rounded border border-line2 bg-[var(--accent-dim)] px-2 py-1 text-[10px] text-accent">PPS</button>
              <button className="font-mono-ui rounded border border-line2 px-2 py-1 text-[10px] text-muted">BPS</button>
            </div>
          }
        >
          <TrafficTrend pps={detectionSummary.total_pps} bps={detectionSummary.total_bps} />
        </Panel>

        <Panel title="호스트별 트래픽">
          <div className="grid gap-3">
            {packetSummary.host_stats.slice(0, 4).map((row) => {
              const value = Math.round((row.bit_count / packetSummary.total_bits) * 100);
              return (
                <div key={`${row.src_ip}-${row.protocol}`} className="font-mono-ui">
                  <div className="mb-1 flex justify-between text-[11px]">
                    <span className="text-muted">{row.src_host ?? row.src_ip} · {row.protocol}</span>
                    <span className="text-ink">{value}%</span>
                  </div>
                  <div className="h-1.5 rounded bg-sidebar">
                    <div className="h-full rounded bg-accent" style={{ width: `${value}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-4 max-xl:grid-cols-1">
        <Panel title="프로토콜 분포">
          <ProtocolBars stats={packetSummary.protocol_stats} />
        </Panel>

        <Panel title="경로별 트래픽">
          <div className="grid gap-4">
            {[
              { name: "Primary s1-s2-s4", value: 63, tone: "text-accent bg-accent" },
              { name: "Backup s1-s3-s4", value: 24, tone: "text-yellow bg-yellow" },
              { name: "Mirrored Analyzer", value: 13, tone: "text-purple bg-purple" }
            ].map((item) => (
              <div key={item.name} className="font-mono-ui">
                <div className="mb-1 flex justify-between text-[11px]">
                  <span className="text-muted">{item.name}</span>
                  <span className={item.tone.split(" ")[0]}>{item.value}%</span>
                </div>
                <div className="h-1.5 rounded bg-sidebar">
                  <div className={`h-full rounded ${item.tone.split(" ")[1]}`} style={{ width: `${item.value}%` }} />
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>

      <div className="mt-4">
        <Panel
          title="패킷 로그"
          action={
            <div className="flex flex-wrap items-center gap-2">
              <div className="hidden h-8 items-center gap-2 rounded border border-line2 bg-sidebar px-3 md:flex">
                <Search className="h-4 w-4 text-muted" />
                <input className="font-mono-ui w-40 bg-transparent text-[11px] outline-none" placeholder="출발지 IP 필터" disabled />
              </div>
              <button className="font-mono-ui rounded border border-accent bg-[var(--accent-dim)] px-2 py-1 text-[10px] text-accent">최신순</button>
              <button className="font-mono-ui rounded border border-line2 px-2 py-1 text-[10px] text-muted">오래된순</button>
            </div>
          }
        >
          <div className="overflow-x-auto">
            <table className="font-mono-ui w-full border-collapse text-[11px]">
              <thead>
                <tr className="border-b border-line bg-sidebar text-left text-[9px] uppercase tracking-[0.15em] text-faint">
                  <th className="px-3 py-3">시간</th>
                  <th className="px-3 py-3">출발지 IP</th>
                  <th className="px-3 py-3">목적지 IP</th>
                  <th className="px-3 py-3">프로토콜</th>
                  <th className="px-3 py-3">src Port</th>
                  <th className="px-3 py-3">dst Port</th>
                  <th className="px-3 py-3">크기</th>
                  <th className="px-3 py-3">경로</th>
                  <th className="px-3 py-3">처리</th>
                </tr>
              </thead>
              <tbody>
                {packetLogs.map((log) => (
                  <tr key={`${log.time}-${log.src}-${log.protocol}`} className="border-b border-line last:border-0">
                    <td className="px-3 py-3">{log.time}</td>
                    <td className="px-3 py-3">{log.src}</td>
                    <td className="px-3 py-3">{log.dst}</td>
                    <td className="px-3 py-3"><StatusBadge value={log.protocol} tone={log.protocol === "ICMP" ? "critical" : "muted"} /></td>
                    <td className="px-3 py-3">{log.sport}</td>
                    <td className="px-3 py-3">{log.dport}</td>
                    <td className="px-3 py-3">{log.size}</td>
                    <td className="px-3 py-3">{log.path}</td>
                    <td className="px-3 py-3"><StatusBadge value={log.action} tone={log.action === "drop" ? "critical" : "normal"} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>

      <div className="mt-4">
        <Panel title="호스트별 트래픽 상세">
          <HostStatsTable rows={packetSummary.host_stats} />
        </Panel>
      </div>
    </>
  );
}
