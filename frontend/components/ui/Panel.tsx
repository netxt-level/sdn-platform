import type { ReactNode } from "react";

export function Panel({
  title,
  action,
  children,
  className = "",
  bodyClassName = ""
}: {
  title: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={`flex flex-col overflow-hidden rounded-lg border border-line bg-panel ${className}`}>
      <div className="flex min-h-12 items-center justify-between gap-3 border-b border-line px-4">
        <h2 className="panel-title-mark font-mono-ui flex items-center gap-2 text-xs font-bold tracking-wide text-ink">
          {title}
        </h2>
        {action}
      </div>
      <div className={`min-h-0 p-4 ${bodyClassName}`}>{children}</div>
    </section>
  );
}
