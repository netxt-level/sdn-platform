import type { HostStat } from "@/types/analyzer";
import { formatBitsPerSecond, formatNumber } from "@/lib/format";

export function HostStatsTable({ rows }: { rows: HostStat[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="font-mono-ui w-full border-collapse text-[11px]">
        <thead>
          <tr className="border-b border-line bg-sidebar text-left text-[9px] uppercase tracking-[0.15em] text-faint">
            <th className="px-3 py-3 font-black">출발지</th>
            <th className="px-3 py-3 font-black">목적지</th>
            <th className="px-3 py-3 font-black">프로토콜</th>
            <th className="px-3 py-3 text-right font-black">패킷</th>
            <th className="px-3 py-3 text-right font-black">트래픽</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={`${row.src_ip}-${row.dst_ip}-${row.protocol}`}
              className="border-b border-line last:border-0"
            >
              <td className="px-3 py-3">
                <strong>{row.src_host ?? "-"}</strong>
                <span className="block text-[10px] text-muted">{row.src_ip ?? "-"}</span>
              </td>
              <td className="px-3 py-3">
                <strong>{row.dst_host ?? "-"}</strong>
                <span className="block text-[10px] text-muted">{row.dst_ip ?? "-"}</span>
              </td>
              <td className="px-3 py-3 font-bold">{row.protocol}</td>
              <td className="px-3 py-3 text-right">{formatNumber(row.packet_count)}</td>
              <td className="px-3 py-3 text-right">{formatBitsPerSecond(row.bit_count)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
