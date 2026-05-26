import { Server, ShieldAlert, SquareStack } from "lucide-react";

import type { TopologyState } from "@/types/topology";

const positions: Record<string, { x: number; y: number }> = {
  h1: { x: 10, y: 20 },
  h2: { x: 10, y: 42 },
  h3: { x: 10, y: 64 },
  s1: { x: 30, y: 42 },
  s2: { x: 51, y: 24 },
  s3: { x: 51, y: 60 },
  s4: { x: 72, y: 42 },
  h4: { x: 90, y: 42 }
};

const statusClass = {
  normal: "border-accent bg-panel2 text-accent",
  warning: "border-yellow bg-panel text-yellow",
  blocked: "border-red bg-panel text-red",
  offline: "border-line2 bg-panel2 text-faint"
};

const hostClass: Record<string, string> = {
  h1: "border-[#8fcf6a] bg-[#e8f7dc] text-[#2f741f]",
  h2: "border-[#f0a13a] bg-[#fff0d6] text-[#b86b00]",
  h3: "border-[#8fcf6a] bg-[#e8f7dc] text-[#2f741f]",
  h4: "border-[#8fcf6a] bg-[#e8f7dc] text-[#2f741f]"
};

const linkPaths: Record<string, string> = {
  "h1-s1": "M 15 20 L 25 38",
  "h2-s1": "M 15 42 L 25 42",
  "h3-s1": "M 15 64 L 25 46",
  "s1-s2": "M 35 39 L 46 28",
  "s1-s3": "M 35 45 L 46 56",
  "s2-s4": "M 56 27 L 67 38",
  "s3-s4": "M 56 57 L 67 46",
  "s4-h4": "M 77 42 L 85 42"
};

export function TopologyMap({ topology }: { topology: TopologyState }) {
  return (
    <div className="relative h-full min-h-0 overflow-hidden rounded-lg border border-line bg-sidebar">
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
        {topology.links.map((link) => {
          const source = positions[link.source];
          const target = positions[link.target];
          const stroke = link.path === "backup" ? "var(--accent)" : link.active ? "var(--accent)" : "var(--border2)";
          const width = link.active ? 0.9 : 0.45;

          if (linkPaths[link.id]) {
            return (
              <path
                key={link.id}
                d={linkPaths[link.id]}
                fill="none"
                stroke={stroke}
                strokeWidth={width}
                strokeDasharray={link.path === "backup" ? "2 2" : undefined}
                vectorEffect="non-scaling-stroke"
              />
            );
          }

          return (
            <line
              key={link.id}
              x1={source.x}
              y1={source.y}
              x2={target.x}
              y2={target.y}
              stroke={stroke}
              strokeWidth={width}
              strokeDasharray={link.path === "backup" ? "2 2" : undefined}
              vectorEffect="non-scaling-stroke"
            />
          );
        })}
      </svg>

      {topology.nodes.map((node) => {
        const position = positions[node.id];
        const Icon = node.type === "host" ? Server : SquareStack;

        return (
          <div
            key={node.id}
            className={`absolute -translate-x-1/2 -translate-y-1/2 ${node.id === "h2" ? "z-30" : "z-10"}`}
            style={{ left: `${position.x}%`, top: `${position.y}%` }}
          >
            <div
              className={`font-mono-ui flex h-[54px] w-[104px] items-center gap-2 rounded-md border px-2.5 py-2 ${hostClass[node.id] ?? statusClass[node.status]}`}
            >
              {node.status === "warning" ? (
                <ShieldAlert className="h-3.5 w-3.5 shrink-0" />
              ) : (
                <Icon className="h-3.5 w-3.5 shrink-0" />
              )}
              <div className="min-w-0">
                <strong className="block text-[12px] leading-tight">{node.label}</strong>
                <span className="block whitespace-nowrap text-[10px] leading-tight">{node.role}</span>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
