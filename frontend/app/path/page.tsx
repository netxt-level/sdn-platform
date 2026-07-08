"use client";

import { useEffect, useMemo, useState } from "react";
import { Route } from "lucide-react";

import { PageHeader } from "@/components/layout/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { formatDateTime } from "@/lib/format";

type PathLink = {
  id: string;
  source: string;
  target: string;
  path: "primary" | "backup";
  active: boolean;
  utilization: number;
};

type PathInfo = {
  name: "primary" | "backup";
  nodes: string[];
  utilization: number;
  active: boolean;
};

type PathHistoryItem = {
  id: string;
  time?: string | null;
  from: string;
  to: string;
  reason: string;
  status: string;
};

type PathStatus = {
  active_path: "primary" | "backup";
  network_status: "normal" | "warning" | "critical";
  paths: {
    primary: PathInfo;
    backup: PathInfo;
  };
  links: PathLink[];
  history: PathHistoryItem[];
};

const initialPathStatus: PathStatus = {
  active_path: "primary",
  network_status: "normal",
  paths: {
    primary: {
      name: "primary",
      nodes: ["-"],
      utilization: 0,
      active: true
    },
    backup: {
      name: "backup",
      nodes: ["-"],
      utilization: 0,
      active: false
    }
  },
  links: [],
  history: []
};

export default function PathPage() {
  const [pathStatus, setPathStatus] = useState<PathStatus>(initialPathStatus);
  const [pathLoading, setPathLoading] = useState(true);
  const linkStats = useMemo(
    () => pathStatus.links,
    [pathStatus.links]
  );
  const primaryPath = pathStatus.paths.primary;
  const backupPath = pathStatus.paths.backup;
  const congestionState =
    pathStatus.network_status === "normal" ? "NORMAL" : "WARNING";
  const pathHistory = pathStatus.history;

  useEffect(() => {
    let ignored = false;

    async function loadPathStatus() {
      try {
        const response = await fetch("/api/path/status", { cache: "no-store" });

        if (!response.ok) {
          return;
        }

        const data = (await response.json()) as PathStatus;

        if (!ignored) {
          setPathStatus(data);
        }
      } finally {
        if (!ignored) {
          setPathLoading(false);
        }
      }
    }

    loadPathStatus();
    const intervalId = window.setInterval(loadPathStatus, 15000);

    return () => {
      ignored = true;
      window.clearInterval(intervalId);
    };
  }, []);

  return (
    <>
      <PageHeader
        title="경로 제어"
        description="기본 경로와 우회 경로의 사용률, 전환 상태, 경로 변경 이력을 확인합니다."
        connected={!pathLoading}
        source={pathLoading ? "waiting" : "history"}
      />

      <div className="grid grid-cols-3 gap-4 max-xl:grid-cols-1">
        <section className="relative overflow-hidden rounded-lg border border-line bg-panel p-5">
          <div className="absolute left-0 right-0 top-0 h-0.5 bg-accent" />
          <p className="font-mono-ui mb-3 text-[9px] font-bold uppercase tracking-[0.2em] text-accent">
            기본 경로
          </p>
          <div className="font-mono-ui mb-3 flex items-center gap-2 text-sm font-bold">
            {primaryPath.nodes.map((node, index) => (
              <span key={`${node}-${index}`} className="contents">
                {index > 0 && <span className="text-faint">→</span>}
                <span className="rounded border border-line2 bg-panel2 px-2 py-1">
                  {node}
                </span>
              </span>
            ))}
          </div>
          <p className="font-mono-ui text-[11px] text-muted">
            링크 사용률 <b className={primaryPath.utilization >= 70 ? "text-yellow" : "text-accent"}>{primaryPath.utilization}%</b>
          </p>
          <div className="mt-3 h-1 rounded bg-sidebar">
            <div
              className={`h-full rounded ${primaryPath.utilization >= 70 ? "bg-yellow" : "bg-accent"}`}
              style={{ width: `${primaryPath.utilization}%` }}
            />
          </div>
        </section>

        <section className="relative overflow-hidden rounded-lg border border-line bg-panel p-5">
          <div className="absolute left-0 right-0 top-0 h-0.5 bg-yellow" />
          <p className="font-mono-ui mb-3 text-[9px] font-bold uppercase tracking-[0.2em] text-yellow">
            우회 경로
          </p>
          <div className="font-mono-ui mb-3 flex items-center gap-2 text-sm font-bold">
            {backupPath.nodes.map((node, index) => (
              <span key={`${node}-${index}`} className="contents">
                {index > 0 && <span className="text-faint">→</span>}
                <span className="rounded border border-line2 bg-panel2 px-2 py-1">
                  {node}
                </span>
              </span>
            ))}
          </div>
          <p className="font-mono-ui text-[11px] text-muted">
            링크 사용률 <b className={backupPath.utilization >= 70 ? "text-yellow" : "text-green"}>{backupPath.utilization}%</b>
          </p>
          <div className="mt-3 h-1 rounded bg-sidebar">
            <div
              className={`h-full rounded ${backupPath.utilization >= 70 ? "bg-yellow" : "bg-green"}`}
              style={{ width: `${backupPath.utilization}%` }}
            />
          </div>
        </section>

        <section className="relative overflow-hidden rounded-lg border border-line bg-panel p-5">
          <div className="absolute left-0 right-0 top-0 h-0.5 bg-red" />
          <p className="font-mono-ui mb-3 text-[9px] font-bold uppercase tracking-[0.2em] text-red">
            혼잡 상태
          </p>
          <p className={`font-mono-ui text-2xl font-black ${congestionState === "WARNING" ? "text-red" : "text-green"}`}>
            {congestionState}
          </p>
          <p className="font-mono-ui mt-2 text-[11px] text-muted">
            {pathStatus.active_path === "backup"
              ? "우회 경로 사용 중"
              : primaryPath.utilization >= 70
                ? "기본 경로 임계값 근접, 자동 우회 대기"
                : "기본 경로 정상 사용 중"}
          </p>
        </section>
      </div>

      <div className="mt-4 grid grid-cols-[1fr_320px] gap-4 max-xl:grid-cols-1">
        <Panel title="경로 변경 이력">
          <div className="overflow-x-auto">
            <table className="font-mono-ui w-full border-collapse text-[11px]">
              <thead>
                <tr className="border-b border-line bg-sidebar text-left text-[9px] uppercase tracking-[0.15em] text-faint">
                  <th className="px-3 py-3">시간</th>
                  <th className="px-3 py-3">이전 경로</th>
                  <th className="px-3 py-3">변경 경로</th>
                  <th className="px-3 py-3">사유</th>
                  <th className="px-3 py-3">처리</th>
                </tr>
              </thead>
              <tbody>
                {pathHistory.map((item) => (
                  <tr key={item.id} className="border-b border-line last:border-0">
                    <td className="px-3 py-3">{formatDateTime(item.time)}</td>
                    <td className="px-3 py-3">{item.from}</td>
                    <td className="px-3 py-3">{item.to}</td>
                    <td className="px-3 py-3">{item.reason}</td>
                    <td className="px-3 py-3">
                      <StatusBadge value={item.status} tone={item.status === "applied" || item.status === "installed" ? "normal" : "muted"} />
                    </td>
                  </tr>
                ))}
                {!pathHistory.length && (
                  <tr>
                    <td className="px-3 py-6 text-center text-muted" colSpan={5}>
                      {pathLoading ? "경로 상태 조회 중" : "경로 변경 이력이 없습니다."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Panel>

        <Panel title="링크 사용률" action={<Route className="h-4 w-4 text-accent" />}>
          <div className="grid gap-3">
            <div className="border-b border-line pb-3">
              <div className="font-mono-ui mb-3 text-[9px] uppercase tracking-[0.2em] text-faint">
                제어 정책
              </div>
              <div className="font-mono-ui grid gap-3 text-[11px]">
                <div className="flex items-center justify-between">
                  <span className="text-muted">자동 우회</span>
                  <span className="rounded border border-accent bg-[var(--accent-dim)] px-2 py-1 text-accent">ON</span>
                </div>
                <div>
                  <div className="mb-1 flex justify-between text-faint">
                    <span>혼잡 임계값</span>
                    <span className="text-yellow">70%</span>
                  </div>
                  <input type="range" min="1" max="100" defaultValue="70" className="w-full accent-[var(--accent)]" />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <button className="rounded border border-line2 bg-[var(--accent-dim)] px-2 py-2 text-accent">기본 전환</button>
                  <button className="rounded border border-line2 bg-[var(--yellow-dim)] px-2 py-2 text-yellow">우회 전환</button>
                  <button className="rounded border border-line2 bg-[var(--green-dim)] px-2 py-2 text-green">자동 복귀</button>
                  <button className="rounded border border-red bg-[var(--red-dim)] px-2 py-2 text-red">격리 경로</button>
                </div>
              </div>
            </div>
            {linkStats.map((link) => (
              <div key={link.id} className="rounded border border-line bg-sidebar p-3">
                <div className="font-mono-ui mb-2 flex items-center justify-between text-[11px]">
                  <strong>{link.source} → {link.target}</strong>
                  <span className={link.utilization >= 70 ? "text-yellow" : "text-accent"}>
                    {link.utilization}%
                  </span>
                </div>
                <div className="h-1 rounded bg-panel2">
                  <div
                    className={`h-full rounded ${link.utilization >= 70 ? "bg-yellow" : "bg-accent"}`}
                    style={{ width: `${link.utilization}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </Panel>
      </div>
    </>
  );
}
