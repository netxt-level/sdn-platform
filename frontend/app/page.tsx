"use client";

import {
  Activity,
  AlertTriangle,
  Ban,
  RadioTower
} from "lucide-react";

import { AnalyzerStatusPanel } from "@/components/dashboard/AnalyzerStatusPanel";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { ProtocolBars } from "@/components/dashboard/ProtocolBars";
import { TrafficTrend } from "@/components/dashboard/TrafficTrend";
import { PageHeader } from "@/components/layout/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { formatBitsPerSecond, formatNumber } from "@/lib/format";
import { useRealtime } from "@/hooks/useRealtime";

export default function DashboardPage() {
  const state = useRealtime();
  const { analyzerStatus, packetSummary, detectionSummary } = state;
  const recentDetectionCount = state.securityEvents.length;

  return (
    <>
      <PageHeader
        title="대시보드"
        description="Mininet, OVS, Ryu 컨트롤러, 분석 서버에서 들어오는 트래픽과 보안 상태를 한 화면에서 확인합니다."
        connected={state.connected}
        source={state.source}
      />

      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-3 max-xl:col-span-6 max-sm:col-span-12">
          <MetricCard
            label="전체 패킷"
            value={formatNumber(packetSummary.total_packets)}
            foot="최근 10초 집계 기준"
            icon={Activity}
            tone="blue"
          />
        </div>
        <div className="col-span-3 max-xl:col-span-6 max-sm:col-span-12">
          <MetricCard
            label="총 BPS"
            value={formatBitsPerSecond(detectionSummary.total_bps)}
            foot="최근 10초 집계 기준"
            icon={RadioTower}
            tone="teal"
          />
        </div>
        <div className="col-span-3 max-xl:col-span-6 max-sm:col-span-12">
          <MetricCard
            label="활성 호스트"
            value="4"
            foot="h1-h4 online"
            icon={AlertTriangle}
            tone="amber"
          />
        </div>
        <div className="col-span-3 max-xl:col-span-6 max-sm:col-span-12">
          <MetricCard
            label="탐지 이벤트"
            value={formatNumber(recentDetectionCount)}
            foot="최근 10분 보안 이벤트 탐지 횟수"
            icon={Ban}
            tone="red"
          />
        </div>

        <Panel
          title="분석 서버 상태"
          className="col-span-3 max-xl:col-span-12"
          action={
            <StatusBadge
              value={detectionSummary.network_status}
              tone={detectionSummary.network_status}
            />
          }
        >
          <AnalyzerStatusPanel status={analyzerStatus} />
        </Panel>

        <Panel title="실시간 트래픽" className="col-span-6 max-xl:col-span-8 max-lg:col-span-12">
          <TrafficTrend pps={detectionSummary.total_pps} bps={detectionSummary.total_bps} />
        </Panel>

        <Panel title="프로토콜 비율" className="col-span-3 max-xl:col-span-4 max-lg:col-span-12">
          <ProtocolBars stats={packetSummary.protocol_stats} />
        </Panel>

        <Panel title="경로 상태" className="col-span-6 max-xl:col-span-12">
          <div className="grid gap-4">
            {[
              ["기본 경로", "s1 → s2 → s4", 72, "text-yellow", "bg-yellow"],
              ["우회 경로", "s1 → s3 → s4", 38, "text-green", "bg-green"]
            ].map(([label, path, value, textClass, barClass]) => (
              <div key={label as string} className="font-mono-ui">
                <div className="mb-2 flex items-center justify-between text-[11px]">
                  <div>
                    <strong className="block text-ink">{label}</strong>
                    <span className="text-muted">{path}</span>
                  </div>
                  <span className={textClass as string}>{value}%</span>
                </div>
                <div className="h-1.5 rounded bg-sidebar">
                  <div className={`h-full rounded ${barClass}`} style={{ width: `${value}%` }} />
                </div>
              </div>
            ))}
          </div>
        </Panel>

        <Panel title="최근 보안 이벤트" className="col-span-6 max-xl:col-span-12">
          <div className="grid gap-3">
            {state.securityEvents.slice(0, 3).map((event) => (
              <div key={event.id} className="font-mono-ui flex items-center justify-between gap-3 rounded border border-line bg-sidebar px-3 py-3 text-[11px]">
                <div>
                  <strong className="block text-ink">{event.attack_type}</strong>
                  <span className="text-muted">{event.src_ip} → {event.dst_ip}</span>
                </div>
                <StatusBadge value={event.status} tone={event.status === "blocked" ? "critical" : "warning"} />
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </>
  );
}
