"use client";

import { useEffect, useMemo, useState } from "react";
import { Ban, GitBranch, Repeat2, ShieldAlert, Workflow } from "lucide-react";

import { MetricCard } from "@/components/dashboard/MetricCard";
import { PageHeader } from "@/components/layout/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { formatNumber } from "@/lib/format";

type FlowRule = {
  id: string;
  switch_id?: string | null;
  match: Record<string, unknown>;
  action: string;
  priority: number;
  packets?: number;
  bytes?: number;
  status: string;
};

type FlowRulesResponse = {
  items?: FlowRule[];
};

function formatMatch(match: Record<string, unknown>) {
  const entries = Object.entries(match);

  if (!entries.length) {
    return "-";
  }

  return entries.map(([key, value]) => `${key}=${String(value)}`).join(", ");
}

export default function FlowRulesPage() {
  const [flowRules, setFlowRules] = useState<FlowRule[]>([]);
  const [selectedSwitch, setSelectedSwitch] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const filteredRules = useMemo(
    () =>
      selectedSwitch === "ALL"
        ? flowRules
        : flowRules.filter((rule) => rule.switch_id === selectedSwitch),
    [flowRules, selectedSwitch]
  );
  const selectedRule = useMemo(
    () =>
      filteredRules.find((rule) => rule.id === selectedRuleId) ??
      filteredRules[0],
    [filteredRules, selectedRuleId]
  );
  const dropCount = flowRules.filter((rule) => rule.action.toUpperCase() === "DROP").length;
  const forwardCount = flowRules.filter((rule) => rule.action.toLowerCase().startsWith("output")).length;
  const rateLimitCount = flowRules.filter((rule) => rule.action.toUpperCase() === "RATE_LIMIT").length;
  const activeSwitches = new Set(flowRules.map((rule) => rule.switch_id).filter(Boolean)).size;

  useEffect(() => {
    let ignored = false;

    async function load() {
      try {
        const response = await fetch("/api/flows", { cache: "no-store" });

        if (!response.ok) {
          return;
        }

        const data = (await response.json()) as FlowRulesResponse;

        if (!ignored) {
          setFlowRules(data.items ?? []);
        }
      } finally {
        if (!ignored) {
          setLoading(false);
        }
      }
    }

    load();

    return () => {
      ignored = true;
    };
  }, []);

  useEffect(() => {
    if (!filteredRules.length) {
      setSelectedRuleId(null);
      return;
    }

    if (!selectedRuleId || !filteredRules.some((rule) => rule.id === selectedRuleId)) {
      setSelectedRuleId(filteredRules[0].id);
    }
  }, [filteredRules, selectedRuleId]);

  return (
    <>
      <PageHeader
        title="Flow Rules"
        description="스위치별 Flow Rule의 match, action, priority, 적용 상태를 확인합니다."
        connected={!loading}
        source={loading ? "waiting" : "history"}
      />

      <div className="grid grid-cols-5 gap-4 max-xl:grid-cols-2 max-sm:grid-cols-1">
        <MetricCard label="전체 Flow Rule" value={formatNumber(flowRules.length)} foot="DB 조회" icon={GitBranch} tone="blue" />
        <MetricCard label="DROP Rule" value={formatNumber(dropCount)} foot="차단 규칙" icon={Ban} tone="red" />
        <MetricCard label="FORWARD Rule" value={formatNumber(forwardCount)} foot="전달 규칙" icon={Repeat2} tone="teal" />
        <MetricCard label="RATE LIMIT" value={formatNumber(rateLimitCount)} foot="속도 제한" icon={ShieldAlert} tone="amber" />
        <MetricCard label="Active Switch" value={formatNumber(activeSwitches)} foot="switch_id 기준" icon={Workflow} tone="teal" />
      </div>

      <div className="mt-4 grid grid-cols-[1fr_340px] gap-4 max-xl:grid-cols-1">
        <Panel
          title="스위치 Flow Rule"
          action={
            <div className="flex flex-wrap gap-2">
              {["ALL", "s1", "s2", "s3", "s4"].map((sw) => (
                <button
                  key={sw}
                  type="button"
                  onClick={() => setSelectedSwitch(sw)}
                  className={`font-mono-ui rounded border px-3 py-1 text-[10px] ${selectedSwitch === sw ? "border-accent bg-[var(--accent-dim)] text-accent" : "border-line2 text-muted"}`}
                >
                  {sw}
                </button>
              ))}
            </div>
          }
        >
          <div className="overflow-x-auto">
            <table className="font-mono-ui w-full border-collapse text-[11px]">
              <thead>
                <tr className="border-b border-line bg-sidebar text-left text-[9px] uppercase tracking-[0.15em] text-faint">
                  <th className="px-3 py-3 font-black">Switch</th>
                  <th className="px-3 py-3 font-black">Match</th>
                  <th className="px-3 py-3 font-black">Action</th>
                  <th className="px-3 py-3 text-right font-black">Priority</th>
                  <th className="px-3 py-3 text-right font-black">Packets</th>
                  <th className="px-3 py-3 text-right font-black">Bytes</th>
                  <th className="px-3 py-3 font-black">상태</th>
                </tr>
              </thead>
              <tbody>
                {filteredRules.map((rule) => (
                  <tr
                    key={rule.id}
                    onClick={() => setSelectedRuleId(rule.id)}
                    className={`cursor-pointer border-b border-line last:border-0 ${selectedRule?.id === rule.id ? "bg-[var(--accent-dim)]" : ""}`}
                  >
                    <td className="px-3 py-3 font-black">{rule.switch_id ?? "-"}</td>
                    <td className="px-3 py-3">{formatMatch(rule.match)}</td>
                    <td className={`px-3 py-3 ${rule.action.toUpperCase() === "DROP" ? "text-red" : "text-accent"}`}>{rule.action}</td>
                    <td className="px-3 py-3 text-right">{rule.priority}</td>
                    <td className="px-3 py-3 text-right">{typeof rule.packets === "number" ? formatNumber(rule.packets) : "-"}</td>
                    <td className="px-3 py-3 text-right">{typeof rule.bytes === "number" ? formatNumber(rule.bytes) : "-"}</td>
                    <td className="px-3 py-3"><StatusBadge value={rule.status.toLowerCase()} tone={rule.status === "APPLIED" ? "normal" : "muted"} /></td>
                  </tr>
                ))}
                {!filteredRules.length && (
                  <tr>
                    <td colSpan={7} className="px-3 py-6 text-center text-muted">
                      {loading ? "Flow Rule 조회 중" : "Flow Rule이 없습니다."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>

        <div className="grid gap-4">
          <Panel title="Rule 상세">
            {selectedRule ? (
              <div className="font-mono-ui grid gap-3 text-[11px]">
                <div className="flex justify-between"><span className="text-faint">Switch</span><strong>{selectedRule.switch_id ?? "-"}</strong></div>
                <div className="flex justify-between"><span className="text-faint">Priority</span><strong>{selectedRule.priority}</strong></div>
                <div className="rounded border border-line bg-sidebar p-3 leading-6">
                  <span className="text-faint">match</span><br />
                  <span className="text-accent">{formatMatch(selectedRule.match)}</span>
                </div>
                <div className="rounded border border-line bg-sidebar p-3">
                  <span className="text-faint">action </span>
                  <strong className={selectedRule.action.toUpperCase() === "DROP" ? "text-red" : "text-accent"}>{selectedRule.action}</strong>
                </div>
              </div>
            ) : (
              <div className="font-mono-ui rounded border border-line bg-sidebar p-4 text-[11px] text-muted">
                선택 가능한 Flow Rule이 없습니다.
              </div>
            )}
          </Panel>

          <Panel title="수동 Flow Rule" action={<ShieldAlert className="h-4 w-4 text-muted" />}>
            <div className="font-mono-ui rounded border border-line bg-sidebar p-4 text-[11px] leading-6 text-muted">
              로그인과 관리자 권한 확인이 연결되기 전까지 화면에서 직접 Flow Rule을 추가하지 않습니다.
              현재 화면은 Analyzer가 만든 대응 후보와 저장된 Rule을 조회하는 용도로 사용합니다.
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}
