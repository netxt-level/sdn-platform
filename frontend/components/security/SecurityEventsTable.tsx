import type { SecurityEvent } from "@/types/security";
import { formatBitsPerSecond, formatDateTime, formatNumber } from "@/lib/format";
import { StatusBadge } from "@/components/ui/StatusBadge";

const severityTone = {
  low: "muted",
  medium: "warning",
  high: "critical",
  critical: "critical"
} as const;

type SecurityEventsTableProps = {
  events: SecurityEvent[];
  selectedEventId?: string;
  onSelectEvent?: (event: SecurityEvent) => void;
};

export function SecurityEventsTable({
  events,
  selectedEventId,
  onSelectEvent
}: SecurityEventsTableProps) {
  return (
    <div className="max-h-[520px] overflow-auto">
      <table className="font-mono-ui w-full border-collapse text-[11px]">
        <thead className="sticky top-0 z-10">
          <tr className="border-b border-line bg-sidebar text-left text-[9px] uppercase tracking-[0.15em] text-faint">
            <th className="px-3 py-3 font-black">시간</th>
            <th className="px-3 py-3 font-black">공격 유형</th>
            <th className="px-3 py-3 font-black">위험도</th>
            <th className="px-3 py-3 font-black">출발지</th>
            <th className="px-3 py-3 text-right font-black">PPS</th>
            <th className="px-3 py-3 text-right font-black">BPS</th>
            <th className="px-3 py-3 font-black">상태</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr
              key={event.id}
              tabIndex={0}
              onClick={() => onSelectEvent?.(event)}
              onKeyDown={(keyEvent) => {
                if (keyEvent.key === "Enter" || keyEvent.key === " ") {
                  keyEvent.preventDefault();
                  onSelectEvent?.(event);
                }
              }}
              className={[
                "cursor-pointer border-b border-line outline-none last:border-0 hover:bg-[var(--accent-dim)]",
                selectedEventId === event.id
                  ? "bg-[var(--accent-dim)] hover:bg-[var(--accent-dim)]"
                  : ""
              ].join(" ")}
            >
              <td className="px-3 py-3">{formatDateTime(event.occurred_at)}</td>
              <td className="px-3 py-3 font-black">{event.attack_type}</td>
              <td className="px-3 py-3">
                <StatusBadge value={event.severity} tone={severityTone[event.severity]} />
              </td>
              <td className="px-3 py-3">{event.src_mac || event.src_ip || "-"}</td>
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
