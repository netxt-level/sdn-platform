import { Plus, Trash2 } from "lucide-react";

import { PageHeader } from "@/components/layout/PageHeader";
import { Panel } from "@/components/ui/Panel";
import { StatusBadge } from "@/components/ui/StatusBadge";
import { mockRules } from "@/lib/mockData";
import { formatDateTime } from "@/lib/format";

export default function SecurityRulesPage() {
  const ruleTypes = ["IP 차단", "MAC 차단", "포트 차단", "프로토콜"];

  return (
    <>
      <PageHeader
        title="보안 규칙"
        description="IP, MAC, 포트, 프로토콜 기반 차단 규칙을 만들고 적용 상태를 확인합니다."
      />

      <div className="grid grid-cols-12 gap-4">
        <Panel title="보안 규칙 추가" className="col-span-4 max-xl:col-span-12" action={<Plus className="h-4 w-4 text-accent" />}>
          <div className="mb-4 grid grid-cols-4 border-b border-line text-center max-sm:grid-cols-2">
            {ruleTypes.map((type, index) => (
              <button
                key={type}
                className={[
                  "font-mono-ui border-b-2 px-2 py-3 text-[10px]",
                  index === 0 ? "border-accent text-accent" : "border-transparent text-muted"
                ].join(" ")}
              >
                {type}
              </button>
            ))}
          </div>

          <div className="grid gap-4">
            <label className="grid gap-1">
              <span className="font-mono-ui text-[9px] uppercase tracking-[0.16em] text-faint">IP 주소</span>
              <input className="font-mono-ui h-10 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none" placeholder="예: 10.0.0.2 또는 10.0.0.0/24" />
              <span className="font-mono-ui text-[9px] text-faint">단일 IP 또는 CIDR 표기 사용 가능</span>
            </label>

            <div className="grid grid-cols-2 gap-3">
              <label className="grid gap-1">
                <span className="font-mono-ui text-[9px] uppercase tracking-[0.16em] text-faint">방향</span>
                <select className="font-mono-ui h-10 rounded border border-line2 bg-sidebar px-3 text-[11px]">
                  <option>출발지 (src)</option>
                  <option>목적지 (dst)</option>
                  <option>양방향</option>
                </select>
              </label>
              <label className="grid gap-1">
                <span className="font-mono-ui text-[9px] uppercase tracking-[0.16em] text-faint">적용 스위치</span>
                <select className="font-mono-ui h-10 rounded border border-line2 bg-sidebar px-3 text-[11px]">
                  <option>s1 (진입 스위치)</option>
                  <option>s2 (기본 경로)</option>
                  <option>s3 (우회 경로)</option>
                  <option>s4 (목적지)</option>
                  <option>전체 스위치</option>
                </select>
              </label>
            </div>

            <label className="grid gap-1">
              <span className="font-mono-ui text-[9px] uppercase tracking-[0.16em] text-faint">우선순위 <b className="text-accent">200</b></span>
              <input type="range" min="1" max="400" defaultValue="200" className="accent-[var(--accent)]" />
            </label>

            <label className="grid gap-1">
              <span className="font-mono-ui text-[9px] uppercase tracking-[0.16em] text-faint">메모</span>
              <input className="font-mono-ui h-10 rounded border border-line2 bg-sidebar px-3 text-[11px] outline-none" placeholder="규칙 설명 (선택)" />
            </label>

            <button className="font-mono-ui h-10 rounded border border-line2 bg-[var(--accent-dim)] px-4 text-[11px] font-bold text-accent">
              IP 차단 규칙 적용
            </button>
          </div>
        </Panel>

        <Panel title="등록된 규칙" className="col-span-8 max-xl:col-span-12">
          <div className="overflow-x-auto">
            <table className="font-mono-ui w-full border-collapse text-[11px]">
              <thead>
                <tr className="border-b border-line bg-sidebar text-left text-[9px] uppercase tracking-[0.15em] text-faint">
                  <th className="px-3 py-3">유형</th>
                  <th className="px-3 py-3">대상</th>
                  <th className="px-3 py-3">Action</th>
                  <th className="px-3 py-3">Switch</th>
                  <th className="px-3 py-3 text-right">Priority</th>
                  <th className="px-3 py-3">상태</th>
                  <th className="px-3 py-3">생성</th>
                  <th className="px-3 py-3">관리</th>
                </tr>
              </thead>
              <tbody>
                {mockRules.map((rule, index) => (
                  <tr key={rule.id} className="border-b border-line last:border-0">
                    <td className="px-3 py-3"><StatusBadge value={rule.type} tone="muted" /></td>
                    <td className="px-3 py-3 font-bold text-ink">{rule.value}</td>
                    <td className="px-3 py-3 text-red">DROP</td>
                    <td className="px-3 py-3">{index % 2 === 0 ? "s1" : "ALL"}</td>
                    <td className="px-3 py-3 text-right">{200 - index * 20}</td>
                    <td className="px-3 py-3"><StatusBadge value={rule.enabled ? "active" : "inactive"} tone={rule.enabled ? "normal" : "muted"} /></td>
                    <td className="px-3 py-3">{formatDateTime(rule.created_at)}</td>
                    <td className="px-3 py-3">
                      <div className="flex gap-2">
                        <button className="rounded border border-line2 px-2 py-1 text-[9px] text-muted">toggle</button>
                        <button className="rounded border border-red bg-[var(--red-dim)] px-2 py-1 text-[9px] text-red" title="삭제">
                          <Trash2 className="h-3 w-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </>
  );
}
