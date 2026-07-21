"use client";

import { useEffect, useState } from "react";

import { PageHeader } from "@/components/layout/PageHeader";
import { TopologyMap } from "@/components/topology/TopologyMap";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { getTopologyState } from "@/lib/topologyApi";
import type { TopologyState } from "@/types/topology";

const initialTopology: TopologyState = {
  active_path: "primary",
  nodes: [],
  links: []
};

export default function TopologyPage() {
  const [topology, setTopology] = useState(initialTopology);
  const [connected, setConnected] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    let ignored = false;

    async function loadTopology() {
      try {
        const nextTopology = await getTopologyState();
        if (ignored) return;

        setTopology(nextTopology);
        setConnected(nextTopology.nodes.length > 0);
        setErrorMessage(
          nextTopology.nodes.length > 0
            ? null
            : "Controller 토폴로지 정보를 불러올 수 없습니다."
        );
      } catch {
        if (ignored) return;
        setConnected(false);
        setErrorMessage("토폴로지 API 연결에 실패했습니다.");
      }
    }

    void loadTopology();
    const intervalId = window.setInterval(loadTopology, 5000);

    return () => {
      ignored = true;
      window.clearInterval(intervalId);
    };
  }, []);

  return (
    <div className="flex h-[calc(100vh-112px)] min-h-0 flex-col overflow-hidden">
      <PageHeader
        title="토폴로지"
        description="Controller API에서 조회한 호스트와 스위치, 기본 경로와 우회 경로의 상태를 시각화합니다."
        connected={connected}
        source={connected ? "controller" : "waiting"}
      />

      {errorMessage && (
        <div className="font-mono-ui mb-4 rounded border border-yellow/40 bg-[var(--yellow-dim)] px-4 py-3 text-[11px] text-yellow">
          {errorMessage}
        </div>
      )}

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
              <StatusBadge value={`${topology.active_path} path`} tone="normal" />
            </div>
          }
        >
          <TopologyMap topology={topology} />
        </Panel>

        <Panel title="링크 상태" className="col-span-4 h-full max-xl:col-span-12" bodyClassName="flex-1">
          <div className="grid h-full gap-3 overflow-y-auto pr-1">
            {topology.links.map((link) => (
              <div
                key={link.id}
                className="font-mono-ui flex items-center justify-between gap-3 rounded border border-line bg-sidebar px-3 py-3"
              >
                <div>
                  <strong className="block text-sm">{link.source} → {link.target}</strong>
                  <span className="text-xs text-muted">{link.path} · 사용률 {link.utilization.toFixed(2)}%</span>
                </div>
                <StatusBadge value={link.active ? "active" : "standby"} tone={link.active ? "normal" : "muted"} />
              </div>
            ))}
            {!topology.links.length && (
              <div className="font-mono-ui grid min-h-32 place-items-center rounded border border-dashed border-line2 px-4 text-center text-[11px] text-muted">
                토폴로지 링크 정보를 기다리는 중입니다.
              </div>
            )}
          </div>
        </Panel>
      </div>
    </div>
  );
}
