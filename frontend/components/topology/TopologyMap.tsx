import { useMemo } from "react";
import { Server, ShieldAlert, SquareStack } from "lucide-react";

import type { TopologyNode, TopologyState } from "@/types/topology";

type Position = { x: number; y: number };

function spreadY(index: number, count: number): number {
  if (count <= 1) return 50;
  return 22 + (index * 56) / (count - 1);
}

export function calculateTopologyLayout(topology: TopologyState) {
  const positions: Record<string, Position> = {};
  const switches = topology.nodes
    .filter((node) => node.type === "switch")
    .sort((left, right) => left.id.localeCompare(right.id));
  const switchIds = new Set(switches.map((node) => node.id));
  const adjacency = new Map<string, Set<string>>(
    switches.map((node) => [node.id, new Set<string>()])
  );
  const accessHosts = new Map<string, TopologyNode[]>();

  for (const link of topology.links) {
    if (link.path === "access") {
      const switchId = switchIds.has(link.source) ? link.source : link.target;
      const hostId = switchId === link.source ? link.target : link.source;
      const host = topology.nodes.find((node) => node.id === hostId);
      if (host) accessHosts.set(switchId, [...(accessHosts.get(switchId) ?? []), host]);
      continue;
    }
    if (switchIds.has(link.source) && switchIds.has(link.target)) {
      adjacency.get(link.source)?.add(link.target);
      adjacency.get(link.target)?.add(link.source);
    }
  }

  const root = switches.reduce<TopologyNode | null>((selected, node) => {
    if (!selected) return node;
    const selectedCount = accessHosts.get(selected.id)?.length ?? 0;
    const nodeCount = accessHosts.get(node.id)?.length ?? 0;
    return nodeCount > selectedCount ? node : selected;
  }, null);
  const levels = new Map<string, number>();
  if (root) {
    levels.set(root.id, 0);
    const queue = [root.id];
    while (queue.length) {
      const current = queue.shift()!;
      for (const neighbor of Array.from(adjacency.get(current) ?? []).sort()) {
        if (levels.has(neighbor)) continue;
        levels.set(neighbor, (levels.get(current) ?? 0) + 1);
        queue.push(neighbor);
      }
    }
  }
  let maxLevel = Math.max(0, ...levels.values());
  for (const node of switches) {
    if (!levels.has(node.id)) levels.set(node.id, ++maxLevel);
  }
  maxLevel = Math.max(0, ...levels.values());

  const switchesByLevel = new Map<number, TopologyNode[]>();
  for (const node of switches) {
    const level = levels.get(node.id) ?? 0;
    switchesByLevel.set(level, [...(switchesByLevel.get(level) ?? []), node]);
  }
  for (const [level, nodes] of switchesByLevel) {
    nodes.sort((left, right) => left.id.localeCompare(right.id));
    nodes.forEach((node, index) => {
      positions[node.id] = {
        x: maxLevel === 0 ? 50 : 30 + (level * 40) / maxLevel,
        y: spreadY(index, nodes.length)
      };
    });
  }

  for (const [switchId, hosts] of accessHosts) {
    const switchPosition = positions[switchId];
    if (!switchPosition) continue;
    const level = levels.get(switchId) ?? 0;
    const sortedHosts = hosts.sort((left, right) => left.id.localeCompare(right.id));
    sortedHosts.forEach((host, index) => {
      const edgeSide = level === 0 ? "left" : level === maxLevel ? "right" : null;
      positions[host.id] = {
        x: edgeSide === "left" ? 10 : edgeSide === "right" ? 90 : switchPosition.x + 14,
        y: edgeSide ? spreadY(index, sortedHosts.length) : Math.min(88, switchPosition.y + 14 + index * 12)
      };
    });
  }

  const unplaced = topology.nodes.filter((node) => !positions[node.id]);
  unplaced.forEach((node, index) => {
    positions[node.id] = { x: 10 + (index % 5) * 20, y: 88 };
  });
  return positions;
}

function clipLine(source: Position, target: Position) {
  const clip = (from: Position, to: Position) => {
    const dx = to.x - from.x;
    const dy = to.y - from.y;
    if (dx === 0 && dy === 0) return from;
    const scale = Math.min(
      1,
      Math.abs(dx) > 0 ? 7 / Math.abs(dx) : Number.POSITIVE_INFINITY,
      Math.abs(dy) > 0 ? 5 / Math.abs(dy) : Number.POSITIVE_INFINITY
    );
    return { x: from.x + dx * scale, y: from.y + dy * scale };
  };
  return { source: clip(source, target), target: clip(target, source) };
}

const statusClass = {
  normal: "border-accent bg-[#eef4fa] text-accent",
  warning: "border-yellow bg-[#fff7e6] text-yellow",
  blocked: "border-red bg-[#fff0f2] text-red",
  offline: "border-line2 bg-[#f4f7fb] text-faint"
};

const hostClass: Record<string, string> = {
  h1: "border-[#8fcf6a] bg-[#e8f7dc] text-[#2f741f]",
  h2: "border-accent bg-[#eaf7fb] text-accent",
  h3: "border-[#f0a13a] bg-[#fff0d6] text-[#b86b00]",
  web: "border-[#8fcf6a] bg-[#e8f7dc] text-[#2f741f]"
};

export function TopologyMap({ topology }: { topology: TopologyState }) {
  const positions = useMemo(() => calculateTopologyLayout(topology), [topology]);

  return (
    <div className="relative h-full min-h-0 overflow-hidden rounded-lg border border-line bg-sidebar">
      <svg className="absolute inset-0 h-full w-full" viewBox="0 0 100 100" preserveAspectRatio="none">
        {topology.links.map((link) => {
          const source = positions[link.source];
          const target = positions[link.target];
          const stroke =
            link.state === "down"
              ? "var(--red)"
              : link.selected
                ? "var(--accent)"
                : link.state === "up"
                  ? "var(--yellow)"
                  : "var(--border2)";
          const width = link.selected ? 0.9 : 0.55;
          const opacity =
            link.state === "down" ? 0.8 : link.selected ? 0.68 : 0.48;
          const dasharray =
            link.state === "down"
              ? "1.5 1.5"
              : !link.selected && link.path !== "access"
                ? "2 2"
                : undefined;

          if (!source || !target) return null;
          const clipped = clipLine(source, target);

          return (
            <line
              key={link.id}
              x1={clipped.source.x}
              y1={clipped.source.y}
              x2={clipped.target.x}
              y2={clipped.target.y}
              stroke={stroke}
              strokeOpacity={opacity}
              strokeWidth={width}
              strokeDasharray={dasharray}
              vectorEffect="non-scaling-stroke"
            />
          );
        })}
      </svg>

      {topology.nodes.map((node) => {
        const position = positions[node.id];
        const Icon = node.type === "host" ? Server : SquareStack;

        if (!position) return null;

        return (
          <div
            key={node.id}
            className="absolute z-20 -translate-x-1/2 -translate-y-1/2"
            style={{ left: `${position.x}%`, top: `${position.y}%` }}
          >
            <div
              className={`font-mono-ui flex h-[54px] w-[clamp(96px,18%,124px)] items-center gap-2 rounded-md border px-2.5 py-2 shadow-sm ${hostClass[node.id] ?? statusClass[node.status]}`}
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

      {!topology.nodes.length && (
        <div className="font-mono-ui absolute inset-0 grid place-items-center text-[11px] text-muted">
          Controller 토폴로지 정보를 기다리는 중입니다.
        </div>
      )}
    </div>
  );
}
