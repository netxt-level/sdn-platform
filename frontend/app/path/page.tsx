import { Route } from "lucide-react";

import { PageHeader } from "@/components/layout/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { mockTopology } from "@/lib/mockData";

const pathHistory = [
  {
    time: "12:41:35",
    from: "primary",
    to: "backup",
    reason: "ICMP Flood 대응",
    status: "manual"
  },
  {
    time: "12:38:10",
    from: "backup",
    to: "primary",
    reason: "혼잡 해소",
    status: "auto"
  },
  {
    time: "12:31:02",
    from: "primary",
    to: "backup",
    reason: "링크 사용률 70% 초과",
    status: "auto"
  }
];

const linkStats = mockTopology.links.filter((link) => link.path !== "access");

export default function PathPage() {
  return (
    <>
      <PageHeader
        title="경로 제어"
        description="기본 경로와 우회 경로의 사용률, 전환 상태, 경로 변경 이력을 확인합니다."
      />

      <div className="grid grid-cols-3 gap-4 max-xl:grid-cols-1">
        <section className="relative overflow-hidden rounded-lg border border-line bg-panel p-5">
          <div className="absolute left-0 right-0 top-0 h-0.5 bg-accent" />
          <p className="font-mono-ui mb-3 text-[9px] font-bold uppercase tracking-[0.2em] text-accent">
            기본 경로
          </p>
          <div className="font-mono-ui mb-3 flex items-center gap-2 text-sm font-bold">
            <span className="rounded border border-line2 bg-panel2 px-2 py-1">s1</span>
            <span className="text-faint">→</span>
            <span className="rounded border border-line2 bg-panel2 px-2 py-1 text-yellow">s2</span>
            <span className="text-faint">→</span>
            <span className="rounded border border-line2 bg-panel2 px-2 py-1">s4</span>
          </div>
          <p className="font-mono-ui text-[11px] text-muted">
            링크 사용률 <b className="text-yellow">72%</b>
          </p>
          <div className="mt-3 h-1 rounded bg-sidebar">
            <div className="h-full w-[72%] rounded bg-yellow" />
          </div>
        </section>

        <section className="relative overflow-hidden rounded-lg border border-line bg-panel p-5">
          <div className="absolute left-0 right-0 top-0 h-0.5 bg-yellow" />
          <p className="font-mono-ui mb-3 text-[9px] font-bold uppercase tracking-[0.2em] text-yellow">
            우회 경로
          </p>
          <div className="font-mono-ui mb-3 flex items-center gap-2 text-sm font-bold">
            <span className="rounded border border-line2 bg-panel2 px-2 py-1">s1</span>
            <span className="text-faint">→</span>
            <span className="rounded border border-line2 bg-panel2 px-2 py-1 text-yellow">s3</span>
            <span className="text-faint">→</span>
            <span className="rounded border border-line2 bg-panel2 px-2 py-1">s4</span>
          </div>
          <p className="font-mono-ui text-[11px] text-muted">
            링크 사용률 <b className="text-green">38%</b>
          </p>
          <div className="mt-3 h-1 rounded bg-sidebar">
            <div className="h-full w-[38%] rounded bg-green" />
          </div>
        </section>

        <section className="relative overflow-hidden rounded-lg border border-line bg-panel p-5">
          <div className="absolute left-0 right-0 top-0 h-0.5 bg-red" />
          <p className="font-mono-ui mb-3 text-[9px] font-bold uppercase tracking-[0.2em] text-red">
            혼잡 상태
          </p>
          <p className="font-mono-ui text-2xl font-black text-red">WARNING</p>
          <p className="font-mono-ui mt-2 text-[11px] text-muted">
            기본 경로 임계값 근접, 자동 우회 대기
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
                  <tr key={`${item.time}-${item.reason}`} className="border-b border-line last:border-0">
                    <td className="px-3 py-3">{item.time}</td>
                    <td className="px-3 py-3">{item.from}</td>
                    <td className="px-3 py-3">{item.to}</td>
                    <td className="px-3 py-3">{item.reason}</td>
                    <td className="px-3 py-3">
                      <StatusBadge value={item.status} tone={item.status === "auto" ? "normal" : "muted"} />
                    </td>
                  </tr>
                ))}
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
