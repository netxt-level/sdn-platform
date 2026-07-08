"use client";

import { PageHeader } from "@/components/layout/PageHeader";
import { TopologyMap } from "@/components/topology/TopologyMap";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { useRealtime } from "@/hooks/useRealtime";

export default function TopologyPage() {
  const state = useRealtime();

  return (
    <div className="flex h-[calc(100vh-112px)] min-h-0 flex-col overflow-hidden">
      <PageHeader
        title="토폴로지"
        description="h1-h4 호스트, s1-s4 스위치, 기본 경로와 우회 경로의 활성 상태를 시각화합니다."
        connected={state.connected}
        source={state.source}
      />

      <div className="grid min-h-0 flex-1 grid-cols-12 gap-4">
        <Panel
          title="네트워크 맵"
          className="col-span-8 h-full max-xl:col-span-12"
          bodyClassName="flex-1"
          action={
            <div className="flex items-center gap-3">
              <div className="font-mono-ui hidden gap-3 text-[9px] text-muted md:flex">
                <span className="flex items-center gap-1"><i className="h-0.5 w-5 bg-accent" />기본 경로</span>
                <span className="flex items-center gap-1"><i className="h-0.5 w-5 border-t-2 border-dashed border-yellow" />우회 경로</span>
                <span className="flex items-center gap-1"><i className="h-2 w-2 rounded-full bg-red" />공격 트래픽</span>
              </div>
              <StatusBadge value={`${state.topology.active_path} path`} tone="normal" />
            </div>
          }
        >
          <TopologyMap topology={state.topology} />
        </Panel>

        <Panel title="링크 상태" className="col-span-4 h-full max-xl:col-span-12" bodyClassName="flex-1">
          <div className="grid h-full gap-3 overflow-y-auto pr-1">
            {state.topology.links.map((link) => (
              <div
                key={link.id}
                className="font-mono-ui flex items-center justify-between gap-3 rounded border border-line bg-sidebar px-3 py-3"
              >
                <div>
                  <strong className="block text-sm">{link.source} → {link.target}</strong>
                  <span className="text-xs text-muted">{link.path} · 사용률 {link.utilization}%</span>
                </div>
                <StatusBadge value={link.active ? "active" : "standby"} tone={link.active ? "normal" : "muted"} />
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </div>
  );
}
