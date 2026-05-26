import type { AnalyzerStatus } from "@/types/analyzer";
import { formatDateTime } from "@/lib/format";
import { StatusBadge } from "@/components/ui/StatusBadge";

export function AnalyzerStatusPanel({ status }: { status: AnalyzerStatus }) {
  const rows = [
    ["Analyzer ID", status.analyzer_id],
    ["상태", status.status],
    ["인터페이스", status.interface],
    ["캡처", status.capture_active ? "active" : "inactive"],
    ["백엔드", status.backend_connected ? "connected" : "disconnected"],
    ["마지막 패킷", formatDateTime(status.last_packet_at)],
    ["마지막 전송", formatDateTime(status.last_summary_sent_at)]
  ];

  return (
    <div className="grid gap-3">
      {rows.map(([label, value]) => (
        <div
          key={label}
          className="flex items-center justify-between gap-4 border-b border-line pb-3 last:border-0 last:pb-0"
        >
          <span className="font-mono-ui text-[11px] text-faint">{label}</span>
          {label === "상태" ? (
            <StatusBadge value={value} tone={value === "running" ? "normal" : "critical"} />
          ) : (
            <strong className="font-mono-ui text-right text-[11px] text-ink">{value}</strong>
          )}
        </div>
      ))}
    </div>
  );
}
