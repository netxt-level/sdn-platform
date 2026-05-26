"use client";

import { useEffect, useMemo, useState } from "react";
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
  data?: TrafficPoint[];
};

type TrafficPoint = {
  timestampMs: number;
  time: string;
  pps: number;
  bps: number;
};

const ONE_MINUTE_MS = 60 * 1000;
const FIVE_MINUTES_MS = 5 * ONE_MINUTE_MS;

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

function getNiceStep(value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    return 1;
  }

  const magnitude = 10 ** Math.floor(Math.log10(value));
  const normalized = value / magnitude;

  if (normalized <= 1) return magnitude;
  if (normalized <= 2) return 2 * magnitude;
  if (normalized <= 2.5) return 2.5 * magnitude;
  if (normalized <= 5) return 5 * magnitude;

  return 10 * magnitude;
}

function getYAxisTicks(maxValue: number): number[] {
  const paddedMax = Math.max(maxValue * 1.1, 1);
  const step = getNiceStep(paddedMax / 4);

  return [0, step, step * 2, step * 3, step * 4];
}

export function TrafficTrend({
  metric = "packets",
  data: trafficData
}: TrafficTrendProps) {
  const [mounted, setMounted] = useState(false);
  const isBps = metric === "bps";
  const dataKey = isBps ? "bps" : "pps";
  const stroke = isBps ? "var(--green)" : "var(--accent)";
  const fillId = isBps ? "bpsFill" : "packetsFill";
  const chartData = trafficData ?? [];
  const yAxisTicks = useMemo(() => {
    const maxValue = Math.max(
      ...chartData.map((point) => Number(point[dataKey]) || 0)
    );

    return getYAxisTicks(maxValue);
  }, [chartData, dataKey]);
  const yAxisMax = yAxisTicks.at(-1) ?? 1;
  const latestTimestampMs = chartData.at(-1)?.timestampMs ?? Date.now();
  const xAxisDomain = useMemo<[number, number]>(
    () => [latestTimestampMs - FIVE_MINUTES_MS, latestTimestampMs],
    [latestTimestampMs]
  );
  const xAxisTicks = useMemo(() => {
    const ticks: number[] = [];
    const firstTick =
      Math.ceil(xAxisDomain[0] / ONE_MINUTE_MS) * ONE_MINUTE_MS;

    for (
      let tick = firstTick;
      tick <= xAxisDomain[1];
      tick += ONE_MINUTE_MS
    ) {
      ticks.push(tick);
    }

    return ticks;
  }, [xAxisDomain]);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return <div className="h-56 rounded bg-panel2" />;
  }

  return (
    <div className="h-56">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 12, right: 12, left: 0, bottom: 0 }}>
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
            dataKey="timestampMs"
            type="number"
            domain={xAxisDomain}
            ticks={xAxisTicks}
            tickFormatter={(value) => formatTimeLabel(new Date(Number(value))).slice(0, 5)}
            axisLine={false}
            tickLine={false}
            tick={{ fill: "var(--text2)", fontSize: 11, fontFamily: "var(--mono)" }}
          />
          <YAxis
            axisLine={false}
            tickLine={false}
            tick={{ fill: "var(--text2)", fontSize: 11, fontFamily: "var(--mono)" }}
            tickFormatter={(value) => formatAxisValue(Number(value))}
            ticks={yAxisTicks}
            width={44}
            domain={[0, yAxisMax]}
          />
          <Tooltip
            labelFormatter={(value) => formatTimeLabel(new Date(Number(value)))}
            formatter={(value) => {
              const numericValue = Number(value ?? 0);

              if (isBps) {
                return [formatBitsPerSecond(numericValue), "BPS"];
              }

              return [`${formatNumber(numericValue)} pps`, "PPS"];
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
