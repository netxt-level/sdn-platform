import { formatNumber } from "@/lib/format";

export function ProtocolBars({ stats }: { stats: Record<string, number> }) {
  const entries = Object.entries(stats);
  const max = Math.max(...entries.map(([, value]) => value), 1);

  return (
    <div className="grid gap-4">
      {entries.map(([protocol, value]) => (
        <div
          key={protocol}
          className="font-mono-ui grid grid-cols-[72px_minmax(0,1fr)_64px] items-center gap-3 text-[11px]"
        >
          <strong>{protocol}</strong>
          <div className="h-1.5 overflow-hidden rounded-full bg-sidebar">
            <div
              className="h-full rounded-full bg-accent"
              style={{ width: `${Math.max((value / max) * 100, 4)}%` }}
            />
          </div>
          <span className="text-right text-muted">{formatNumber(value)}</span>
        </div>
      ))}
    </div>
  );
}
