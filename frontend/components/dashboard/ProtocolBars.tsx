export function ProtocolBars({ stats }: { stats: Record<string, number> }) {
  const entries = Object.entries(stats).sort(
    ([, leftValue], [, rightValue]) => rightValue - leftValue
  );
  const total = entries.reduce((sum, [, value]) => sum + value, 0);

  return (
    <div className="grid gap-4">
      {entries.map(([protocol, value]) => {
        const percentage = total > 0 ? (value / total) * 100 : 0;

        return (
          <div
            key={protocol}
            className="font-mono-ui grid grid-cols-[72px_minmax(0,1fr)_64px] items-center gap-3 text-[11px]"
          >
            <strong>{protocol}</strong>
            <div className="h-1.5 overflow-hidden rounded-full bg-sidebar">
              <div
                className="h-full rounded-full bg-accent"
                style={{ width: `${Math.max(percentage, 4)}%` }}
              />
            </div>
            <span className="text-right text-muted">{percentage.toFixed(1)}%</span>
          </div>
        );
      })}
    </div>
  );
}
