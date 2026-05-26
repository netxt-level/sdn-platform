"use client";

import { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

import { formatBitsPerSecond, formatNumber } from "@/lib/format";

const baseSeries = [
  { minutesAgo: 10, packetRatio: 0.62, bpsRatio: 0.52 },
  { minutesAgo: 8, packetRatio: 0.73, bpsRatio: 0.61 },
  { minutesAgo: 6, packetRatio: 0.81, bpsRatio: 0.74 },
  { minutesAgo: 4, packetRatio: 0.92, bpsRatio: 0.83 },
  { minutesAgo: 2, packetRatio: 0.86, bpsRatio: 0.78 },
  { minutesAgo: 0, packetRatio: 1, bpsRatio: 1 }
];

type TrafficTrendProps = {
  packets: number;
  bps: number;
  metric?: "packets" | "bps";
};

function formatAxisValue(value: number): string {
  if (Math.abs(value) >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(value >= 10_000_000 ? 0 : 1)}M`;
  }

  if (Math.abs(value) >= 1_000) {
    return `${Math.round(value / 1_000)}K`;
  }

  return String(value);
}

function formatTimeLabel(minutesAgo: number): string {
  const date = new Date(Date.now() - minutesAgo * 60 * 1000);

  return new Intl.DateTimeFormat("ko-KR", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false
  }).format(date);
}

export function TrafficTrend({ packets, bps, metric = "packets" }: TrafficTrendProps) {
  const [mounted, setMounted] = useState(false);
  const data = baseSeries.map((point) => ({
    time: formatTimeLabel(point.minutesAgo),
    packets: Math.round(packets * point.packetRatio),
    bps: Math.round(bps * point.bpsRatio)
  }));
  const isBps = metric === "bps";
  const dataKey = isBps ? "bps" : "packets";
  const stroke = isBps ? "var(--green)" : "var(--accent)";
  const fillId = isBps ? "bpsFill" : "packetsFill";

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return <div className="h-56 rounded bg-panel2" />;
  }

  return (
    <div className="h-56">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ top: 12, right: 12, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id="packetsFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#3767a8" stopOpacity={0.34} />
              <stop offset="95%" stopColor="#3767a8" stopOpacity={0.02} />
            </linearGradient>
            <linearGradient id="bpsFill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#11736b" stopOpacity={0.32} />
              <stop offset="95%" stopColor="#11736b" stopOpacity={0.02} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
          <XAxis
            dataKey="time"
            axisLine={false}
            tickLine={false}
            tick={{ fill: "var(--text2)", fontSize: 11, fontFamily: "var(--mono)" }}
          />
          <YAxis
            axisLine={false}
            tickLine={false}
            tick={{ fill: "var(--text2)", fontSize: 11, fontFamily: "var(--mono)" }}
            tickFormatter={(value) => formatAxisValue(Number(value))}
            width={44}
          />
          <Tooltip
            formatter={(value) => {
              const numericValue = Number(value ?? 0);

              if (isBps) {
                return [formatBitsPerSecond(numericValue), "BPS"];
              }

              return [`${formatNumber(numericValue)} packets`, "패킷 수"];
            }}
            contentStyle={{
              background: "var(--panel)",
              border: "1px solid var(--border)",
              borderRadius: 6,
              color: "var(--text)",
              fontFamily: "var(--mono)"
            }}
          />
          <Area
            type="monotone"
            dataKey={dataKey}
            name={dataKey}
            stroke={stroke}
            strokeWidth={2}
            fill={`url(#${fillId})`}
            dot={false}
            activeDot={{ r: 4 }}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
