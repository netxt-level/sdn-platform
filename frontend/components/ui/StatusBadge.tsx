type StatusBadgeProps = {
  value: string;
  tone?: "normal" | "warning" | "critical" | "muted";
};

const toneClass = {
  normal: "bg-[var(--green-dim)] text-green border-line2",
  warning: "bg-[var(--yellow-dim)] text-yellow border-line2",
  critical: "bg-[var(--red-dim)] text-red border-line2",
  muted: "bg-panel2 text-faint border-line"
};

export function StatusBadge({ value, tone = "normal" }: StatusBadgeProps) {
  return (
    <span className={`font-mono-ui inline-flex min-h-5 items-center rounded border px-2 text-[9px] font-bold uppercase ${toneClass[tone]}`}>
      {value}
    </span>
  );
}
