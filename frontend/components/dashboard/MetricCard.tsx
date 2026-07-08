import type { LucideIcon } from "lucide-react";

type MetricCardProps = {
  label: string;
  value: string;
  foot: string;
  icon: LucideIcon;
  tone?: "teal" | "blue" | "amber" | "red";
};

const toneClass = {
  teal: "bg-[var(--accent-dim)] text-accent border-line2",
  blue: "bg-[var(--accent-dim)] text-accent border-line2",
  amber: "bg-[var(--yellow-dim)] text-yellow border-line2",
  red: "bg-[var(--red-dim)] text-red border-line2"
};

export function MetricCard({
  label,
  value,
  foot,
  icon: Icon,
  tone = "teal"
}: MetricCardProps) {
  return (
    <section className="relative overflow-hidden rounded-lg border border-line bg-panel p-4">
      <div className="absolute left-0 right-0 top-0 h-0.5 bg-accent" />
      <div className="mb-4 flex items-center justify-between gap-3">
        <span className="font-mono-ui text-[9px] font-bold uppercase tracking-[0.18em] text-faint">{label}</span>
        <span className={`grid h-8 w-8 place-items-center rounded border ${toneClass[tone]}`}>
          <Icon className="h-5 w-5" />
        </span>
      </div>
      <p className="font-mono-ui text-2xl font-black text-accent">{value}</p>
      <p className="font-mono-ui mt-2 text-[10px] text-faint">{foot}</p>
    </section>
  );
}
