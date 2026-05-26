import type { SecurityEvent } from "@/types/security";
import { formatBitsPerSecond, formatDateTime, formatNumber } from "@/lib/format";
import { StatusBadge } from "@/components/ui/StatusBadge";

const severityTone = {
  low: "muted",
  medium: "warning",
  high: "critical",
  critical: "critical"
} as const;

export function SecurityEventsTable({ events }: { events: SecurityEvent[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="font-mono-ui w-full border-collapse text-[11px]">
        <thead>
          <tr className="border-b border-line bg-sidebar text-left text-[9px] uppercase tracking-[0.15em] text-faint">
            <th className="px-3 py-3 font-black">시간</th>
            <th className="px-3 py-3 font-black">공격 유형</th>
            <th className="px-3 py-3 font-black">위험도</th>
            <th className="px-3 py-3 font-black">출발지</th>
            <th className="px-3 py-3 font-black">목적지</th>
            <th className="px-3 py-3 text-right font-black">PPS</th>
            <th className="px-3 py-3 text-right font-black">BPS</th>
            <th className="px-3 py-3 font-black">상태</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id} className="border-b border-line last:border-0">
              <td className="px-3 py-3">{formatDateTime(event.occurred_at)}</td>
              <td className="px-3 py-3 font-black">{event.attack_type}</td>
              <td className="px-3 py-3">
                <StatusBadge value={event.severity} tone={severityTone[event.severity]} />
              </td>
              <td className="px-3 py-3">{event.src_ip}</td>
              <td className="px-3 py-3">{event.dst_ip}</td>
              <td className="px-3 py-3 text-right">{formatNumber(event.pps)}</td>
              <td className="px-3 py-3 text-right">{formatBitsPerSecond(event.bps)}</td>
              <td className="px-3 py-3">{event.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
