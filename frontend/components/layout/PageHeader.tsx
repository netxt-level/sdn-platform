"use client";

import { RefreshCw } from "lucide-react";

type PageHeaderProps = {
  title: string;
  description: string;
  connected?: boolean;
  source?: "waiting" | "history" | "websocket";
};

export function PageHeader({
  title,
  description,
  connected = false,
  source = "waiting"
}: PageHeaderProps) {
  return (
    <header className="mb-5 flex items-center justify-between gap-4 max-sm:items-start max-sm:flex-col">
      <div>
        <p className="font-mono-ui mb-1 text-[10px] font-bold uppercase tracking-[0.18em] text-faint">
          {source === "websocket"
            ? "WebSocket Live"
            : source === "history"
              ? "DB History"
              : "Waiting for Data"}
        </p>
        <h1 className="text-2xl font-bold tracking-normal text-ink max-sm:text-xl">
          {title}
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-muted">{description}</p>
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          className="grid h-9 w-9 place-items-center rounded border border-line2 bg-panel text-muted"
          title="새로고침"
          onClick={() => window.location.reload()}
        >
          <RefreshCw className="h-4 w-4" />
        </button>
        <div className="font-mono-ui flex h-9 items-center gap-2 rounded border border-line2 bg-panel px-3 text-[11px] font-bold">
          <span
            className={[
              "h-2 w-2 rounded-full",
              connected ? "bg-green" : "bg-yellow"
            ].join(" ")}
          />
          {connected ? "연결됨" : "대기 중"}
        </div>
      </div>
    </header>
  );
}
