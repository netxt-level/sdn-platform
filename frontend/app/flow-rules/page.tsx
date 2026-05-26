import { Ban, GitBranch, Plus, Repeat2, ShieldAlert, Workflow } from "lucide-react";

import { MetricCard } from "@/components/dashboard/MetricCard";
import { PageHeader } from "@/components/layout/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";

const flowRules = [
  {
    switch_id: "s1",
    match: "ipv4_dst=10.0.0.4",
    action: "output:s2",
    priority: 100,
    packets: 1284,
    bytes: 1022400
  },
  {
    switch_id: "s1",
    match: "ipv4_src=10.0.0.2",
    action: "drop",
    priority: 320,
    packets: 4821,
    bytes: 2100000
  },
  {
    switch_id: "s1",
    match: "in_port=2",
    action: "output:analyzer",
    priority: 250,
    packets: 1440,
    bytes: 730000
  },
  {
    switch_id: "s3",
    match: "ipv4_dst=10.0.0.4",
    action: "output:s4",
    priority: 90,
    packets: 318,
    bytes: 244000
  },
  {
    switch_id: "s2",
    match: "ipv4_dst=10.0.0.4",
    action: "output:s4",
    priority: 100,
    packets: 1188,
    bytes: 946000
  }
];

export default function FlowRulesPage() {
  const selectedRule = flowRules[1];
  const dropCount = flowRules.filter((rule) => rule.action === "drop").length;
  const forwardCount = flowRules.filter((rule) => rule.action.startsWith("output")).length;

  return (
    <>
      <PageHeader
        title="Flow Rules"
        description="스위치별 Flow Rule의 match, action, priority, packet count, byte count를 확인합니다."
      />

      <div className="grid grid-cols-5 gap-4 max-xl:grid-cols-2 max-sm:grid-cols-1">
        <MetricCard label="전체 Flow Rule" value={String(flowRules.length)} foot="4개 스위치 합산" icon={GitBranch} tone="blue" />
        <MetricCard label="DROP Rule" value={String(dropCount)} foot="차단 규칙" icon={Ban} tone="red" />
        <MetricCard label="FORWARD Rule" value={String(forwardCount)} foot="전달 규칙" icon={Repeat2} tone="teal" />
        <MetricCard label="MIRROR Rule" value="1" foot="분석기 전송" icon={ShieldAlert} tone="amber" />
        <MetricCard label="Active Switch" value="4" foot="s1-s4 연결" icon={Workflow} tone="teal" />
      </div>

      <div className="mt-4 grid grid-cols-[1fr_340px] gap-4 max-xl:grid-cols-1">
        <Panel
          title="스위치 Flow Rule"
          action={
            <div className="flex flex-wrap gap-2">
              {["ALL", "s1", "s2", "s3", "s4"].map((sw, index) => (
                <button key={sw} className={`font-mono-ui rounded border px-3 py-1 text-[10px] ${index === 0 ? "border-accent bg-[var(--accent-dim)] text-accent" : "border-line2 text-muted"}`}>
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
                {flowRules.map((rule) => (
                  <tr key={`${rule.switch_id}-${rule.match}`} className="border-b border-line last:border-0">
                    <td className="px-3 py-3 font-black">{rule.switch_id}</td>
                    <td className="px-3 py-3">{rule.match}</td>
                    <td className={`px-3 py-3 ${rule.action === "drop" ? "text-red" : "text-accent"}`}>{rule.action}</td>
                    <td className="px-3 py-3 text-right">{rule.priority}</td>
                    <td className="px-3 py-3 text-right">{rule.packets}</td>
                    <td className="px-3 py-3 text-right">{rule.bytes}</td>
                    <td className="px-3 py-3"><StatusBadge value="installed" tone="normal" /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>

        <div className="grid gap-4">
          <Panel title="Rule 상세">
            <div className="font-mono-ui grid gap-3 text-[11px]">
              <div className="flex justify-between"><span className="text-faint">Switch</span><strong>{selectedRule.switch_id}</strong></div>
              <div className="flex justify-between"><span className="text-faint">Priority</span><strong>{selectedRule.priority}</strong></div>
              <div className="rounded border border-line bg-sidebar p-3 leading-6">
                <span className="text-faint">match</span><br />
                <span className="text-accent">{selectedRule.match}</span>
              </div>
              <div className="rounded border border-line bg-sidebar p-3">
                <span className="text-faint">action </span>
                <strong className={selectedRule.action === "drop" ? "text-red" : "text-accent"}>{selectedRule.action}</strong>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <button className="rounded border border-line2 px-3 py-2 text-muted">수정</button>
                <button className="rounded border border-red bg-[var(--red-dim)] px-3 py-2 text-red">삭제</button>
              </div>
            </div>
          </Panel>

          <Panel title="Flow Rule 추가" action={<Plus className="h-4 w-4 text-accent" />}>
            <div className="grid gap-3">
              <select className="font-mono-ui h-9 rounded border border-line2 bg-sidebar px-3 text-[11px]"><option>s1</option><option>s2</option><option>s3</option><option>s4</option></select>
              <input className="font-mono-ui h-9 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none" placeholder="match: ipv4_src=10.0.0.2" />
              <input className="font-mono-ui h-9 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none" placeholder="action: drop 또는 output:s2" />
              <button className="font-mono-ui rounded border border-line2 bg-[var(--accent-dim)] px-3 py-2 text-[11px] text-accent">규칙 추가</button>
            </div>
          </Panel>
        </div>
      </div>
    </>
  );
}
