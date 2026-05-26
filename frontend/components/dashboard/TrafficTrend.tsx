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

type TrafficTrendProps = {
  packets: number;
  bps: number;
  metric?: "packets" | "bps";
};

type TrafficPoint = {
  time: string;
  packets: number;
  bps: number;
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

function formatTimeLabel(date: Date): string {
  return new Intl.DateTimeFormat("ko-KR", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(date);
}

function createInitialSeries(packets: number, bps: number): TrafficPoint[] {
  const now = Date.now();

  return Array.from({ length: 12 }, (_, index) => {
    const age = 11 - index;
    const ratio = 0.72 + index * 0.025;

    return {
      time: formatTimeLabel(new Date(now - age * 1000)),
      packets: Math.round(packets * ratio),
      bps: Math.round(bps * ratio)
    };
  });
}

export function TrafficTrend({ packets, bps, metric = "packets" }: TrafficTrendProps) {
  const [mounted, setMounted] = useState(false);
  const [data, setData] = useState<TrafficPoint[]>(() =>
    createInitialSeries(packets, bps)
  );
  const isBps = metric === "bps";
  const dataKey = isBps ? "bps" : "packets";
  const stroke = isBps ? "var(--green)" : "var(--accent)";
  const fillId = isBps ? "bpsFill" : "packetsFill";

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    setData((prev) => [
      ...prev.slice(-11),
      {
        time: formatTimeLabel(new Date()),
        packets,
        bps
      }
    ]);
  }, [bps, packets]);

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
