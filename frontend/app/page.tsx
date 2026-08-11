"use client";

import { useEffect, useMemo, useState } from "react";
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
import { getPathStatus } from "@/lib/pathApi";
import { useRealtime } from "@/hooks/useRealtime";
import type { SuspiciousHost } from "@/types/analyzer";
import type { PathInfo, PathStatus } from "@/types/path";

const ALL_ATTACK_TYPES = "ALL";

const attackTypeLabels: Record<string, string> = {
  DOS: "DoS 의심",
  PORT_SCAN: "포트 스캔 의심"
};

function getSuspiciousHostType(host: SuspiciousHost): string {
  return host.attack_type?.trim().toUpperCase() || "DOS";
}

function formatAttackTypeLabel(attackType: string): string {
  return (
    attackTypeLabels[attackType] ??
    `${attackType.replaceAll("_", " ")} 의심`
  );
}

function getSuspiciousHostTag(host: SuspiciousHost): string {
  return formatAttackTypeLabel(getSuspiciousHostType(host));
}

function getSuspiciousHostTagClass(host: SuspiciousHost): string {
  const attackType = getSuspiciousHostType(host);

  if (attackType === "PORT_SCAN") {
    return "border-[var(--yellow)] bg-[var(--yellow-dim)] text-yellow";
  }

  if (attackType === "DOS") {
    return "border-[var(--red)] bg-[var(--red-dim)] text-red";
  }

  return "border-accent bg-[var(--accent-dim)] text-accent";
}

function utilizationLabel(item: PathInfo): string {
  if (item.pps_utilization > 0 && item.pps_utilization < 0.01) return "<0.01%";
  return `${item.pps_utilization.toFixed(2)}%`;
}

function utilizationColor(item: PathInfo): string {
  if (item.pps_utilization >= 90) return "text-red";
  if (item.pps_utilization >= 70) return "text-yellow";
  return item.active ? "text-green" : "text-faint";
}

function utilizationBar(item: PathInfo): string {
  if (item.pps_utilization >= 90) return "bg-red";
  if (item.pps_utilization >= 70) return "bg-yellow";
  return item.active ? "bg-green" : "bg-faint";
}

export default function DashboardPage() {
  const state = useRealtime();
  const { analyzerStatus, dashboardSummary, packetSummary, detectionSummary } = state;
  const [trafficMetric, setTrafficMetric] = useState<"packets" | "bps">("packets");
  const [suspiciousHostTypeFilter, setSuspiciousHostTypeFilter] =
    useState(ALL_ATTACK_TYPES);
  const [pathStatus, setPathStatus] = useState<PathStatus | null>(null);
  const suspiciousHostTypes = useMemo(
    () =>
      Array.from(
        new Set(
          detectionSummary.suspicious_hosts.map((host) =>
            getSuspiciousHostType(host)
          )
        )
      ).sort(),
    [detectionSummary.suspicious_hosts]
  );
  const filteredSuspiciousHosts = useMemo(
    () =>
      suspiciousHostTypeFilter === ALL_ATTACK_TYPES
        ? detectionSummary.suspicious_hosts
        : detectionSummary.suspicious_hosts.filter(
            (host) => getSuspiciousHostType(host) === suspiciousHostTypeFilter
          ),
    [detectionSummary.suspicious_hosts, suspiciousHostTypeFilter]
  );

  useEffect(() => {
    let ignored = false;

    async function loadSwitchUtilization() {
      try {
        const nextPathStatus = await getPathStatus();
        if (!ignored) setPathStatus(nextPathStatus);
      } catch {
        // Dashboard packet monitoring remains available if Controller is down.
      }
    }

    void loadSwitchUtilization();
    const intervalId = window.setInterval(loadSwitchUtilization, 1000);
    return () => {
      ignored = true;
      window.clearInterval(intervalId);
    };
  }, []);

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
            value={formatNumber(dashboardSummary.totalPackets)}
            foot="최근 5분 API 집계 기준"
            icon={Activity}
            tone="blue"
          />
        </div>
        <div className="col-span-3 max-xl:col-span-6 max-sm:col-span-12">
          <MetricCard
            label="총 BPS"
            value={formatBitsPerSecond(dashboardSummary.currentBps)}
            foot="최신 summary API 기준"
            icon={RadioTower}
            tone="teal"
          />
        </div>
        <div className="col-span-3 max-xl:col-span-6 max-sm:col-span-12">
          <MetricCard
            label="활성 플로우"
            value={formatNumber(detectionSummary.active_flow_count)}
            foot="최근 탐지 요약 기준"
            icon={AlertTriangle}
            tone="amber"
          />
        </div>
        <div className="col-span-3 max-xl:col-span-6 max-sm:col-span-12">
          <MetricCard
            label="의심 호스트"
            value={formatNumber(detectionSummary.suspicious_host_count)}
            foot="최근 1주 DB 저장 기준"
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

        <Panel
          title="트래픽 추이"
          className="col-span-6 max-xl:col-span-8 max-lg:col-span-12"
          action={
            <div className="font-mono-ui flex items-center gap-2 text-[10px]">
              {[
                { key: "packets", label: "PPS" },
                { key: "bps", label: "BPS" }
              ].map((item) => (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => setTrafficMetric(item.key as "packets" | "bps")}
                  className={`rounded border px-2 py-1 ${
                    trafficMetric === item.key
                      ? "border-accent bg-[var(--accent-dim)] text-accent"
                      : "border-line2 text-muted"
                  }`}
                >
                  {item.label}
                </button>
              ))}
              <StatusBadge value="최근 5분" tone="muted" />
            </div>
          }
        >
          <TrafficTrend
            packets={packetSummary.total_packets}
            bps={detectionSummary.total_bps}
            metric={trafficMetric}
            data={state.trafficSeries}
          />
        </Panel>

        <Panel title="프로토콜 비율" className="col-span-3 max-xl:col-span-4 max-lg:col-span-12">
          <ProtocolBars stats={packetSummary.protocol_stats} />
        </Panel>

        <Panel
          title="경로 PPS 사용률"
          className="col-span-6 max-xl:col-span-12"
          action={
            pathStatus
              ? (
                  <StatusBadge
                    value={
                      pathStatus.path_distribution_mode === "balanced"
                        ? "1·2경로 분산 중"
                        : pathStatus.active_path === "backup"
                          ? "2경로 사용 중"
                          : "1경로 사용 중"
                    }
                    tone="normal"
                  />
                )
              : <StatusBadge value="조회 중" tone="muted" />
          }
        >
          <div className="grid gap-4">
            {pathStatus &&
              ([
                ["primary", "1경로", pathStatus.paths.primary],
                ["backup", "2경로", pathStatus.paths.backup]
              ] as const).map(([key, label, item]) => (
              <div key={key} className="font-mono-ui">
                <div className="mb-2 flex items-center justify-between gap-3 text-[11px]">
                  <div>
                    <strong className="block text-ink">{label}</strong>
                    <span className="text-muted">
                      {item.nodes.join(" → ")} · {formatNumber(Math.round(item.pps))} PPS /
                      {" "}{formatNumber(pathStatus.path_capacity_pps)} PPS
                    </span>
                  </div>
                  <span className={utilizationColor(item)}>{utilizationLabel(item)}</span>
                </div>
                <div className="h-1.5 rounded bg-sidebar">
                  <div
                    className={`h-full rounded ${utilizationBar(item)}`}
                    style={{
                      width: `${Math.min(
                        100,
                        Math.max(item.pps > 0 ? 1 : 0, item.pps_utilization)
                      )}%`
                    }}
                  />
                </div>
              </div>
            ))}
            {!pathStatus && (
              <p className="font-mono-ui text-[11px] text-muted">
                Controller 경로 PPS 통계를 기다리는 중입니다.
              </p>
            )}
          </div>
        </Panel>

        <Panel
          title="의심 호스트 목록"
          className="col-span-6 max-xl:col-span-12"
          action={
            <select
              value={suspiciousHostTypeFilter}
              onChange={(event) => setSuspiciousHostTypeFilter(event.target.value)}
              className="font-mono-ui h-8 rounded border border-line2 bg-panel2 px-2 text-[11px] font-bold text-ink outline-none"
            >
              <option value={ALL_ATTACK_TYPES}>
                전체 ({formatNumber(detectionSummary.suspicious_hosts.length)})
              </option>
              {suspiciousHostTypes.map((attackType) => (
                <option key={attackType} value={attackType}>
                  {formatAttackTypeLabel(attackType)} (
                  {formatNumber(
                    detectionSummary.suspicious_hosts.filter(
                      (host) => getSuspiciousHostType(host) === attackType
                    ).length
                  )}
                  )
                </option>
              ))}
            </select>
          }
          bodyClassName="max-h-80 overflow-y-auto"
        >
          <div className="grid gap-3 pr-1">
            {detectionSummary.suspicious_hosts.length === 0 ? (
              <div className="font-mono-ui rounded border border-line bg-sidebar px-3 py-3 text-[11px] text-muted">
                최근 1주 동안 DB에 저장된 의심 호스트가 없습니다.
              </div>
            ) : null}

            {detectionSummary.suspicious_hosts.length > 0 &&
            filteredSuspiciousHosts.length === 0 ? (
              <div className="font-mono-ui rounded border border-line bg-sidebar px-3 py-3 text-[11px] text-muted">
                선택한 유형의 의심 호스트가 없습니다.
              </div>
            ) : null}

            {filteredSuspiciousHosts.map((host) => (
              <div key={host.ip} className="font-mono-ui flex items-center justify-between gap-3 rounded border border-line bg-sidebar px-3 py-3 text-[11px]">
                <div className="min-w-0">
                  <span className={`mb-2 inline-flex min-h-5 items-center rounded border px-2 text-[9px] font-bold uppercase ${getSuspiciousHostTagClass(host)}`}>
                    {getSuspiciousHostTag(host)}
                  </span>
                  <strong className="block text-ink">{host.host || host.ip}</strong>
                  <span className="block truncate text-muted">
                    {host.protocol} · {host.reasons.join(", ")}
                  </span>
                </div>
                <div className="shrink-0 text-right">
                  <span className="block text-ink">{formatBitsPerSecond(host.bps)}</span>
                  <span className="text-muted">{formatNumber(host.pps)} pps</span>
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </>
  );
}
