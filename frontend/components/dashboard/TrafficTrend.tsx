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
  { time: "12:00", ppsRatio: 0.54, bpsRatio: 0.42 },
  { time: "12:01", ppsRatio: 0.62, bpsRatio: 0.48 },
  { time: "12:02", ppsRatio: 0.58, bpsRatio: 0.44 },
  { time: "12:03", ppsRatio: 0.73, bpsRatio: 0.61 },
  { time: "12:04", ppsRatio: 0.66, bpsRatio: 0.56 },
  { time: "12:05", ppsRatio: 0.81, bpsRatio: 0.68 },
  { time: "12:06", ppsRatio: 0.77, bpsRatio: 0.72 },
  { time: "12:07", ppsRatio: 0.92, bpsRatio: 0.84 }
];

type TrafficTrendProps = {
  pps: number;
  bps: number;
};

export function TrafficTrend({ pps, bps }: TrafficTrendProps) {
  const [mounted, setMounted] = useState(false);
  const data = baseSeries.map((point, index) => ({
    time: index === baseSeries.length - 1 ? "now" : point.time,
    pps: Math.round(pps * point.ppsRatio),
    bps: Math.round(bps * point.bpsRatio)
  }));

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
            <linearGradient id="ppsFill" x1="0" y1="0" x2="0" y2="1">
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
            yAxisId="pps"
            axisLine={false}
            tickLine={false}
            tick={{ fill: "var(--text2)", fontSize: 11, fontFamily: "var(--mono)" }}
            width={44}
          />
          <YAxis yAxisId="bps" orientation="right" hide />
          <Tooltip
            formatter={(value, name) => {
              const numericValue = Number(value ?? 0);

              if (name === "bps") {
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
            yAxisId="bps"
            type="monotone"
            dataKey="bps"
            stroke="#11736b"
            strokeWidth={2}
            fill="url(#bpsFill)"
            dot={false}
            activeDot={{ r: 4 }}
            isAnimationActive={false}
          />
          <Area
            yAxisId="pps"
            type="monotone"
            dataKey="pps"
            stroke="#3767a8"
            strokeWidth={2}
            fill="url(#ppsFill)"
            dot={false}
            activeDot={{ r: 4 }}
            isAnimationActive={false}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
