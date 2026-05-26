"use client";

import { useEffect, useMemo, useState } from "react";

import type {
  AnalyzerStatus,
  DetectionSummary,
  IncomingDetectionSummary,
  IncomingPacketSummary,
  NetworkStatus,
  PacketSummary
} from "@/types/analyzer";
import type { RealtimeMessage } from "@/types/realtime";
import type { SecurityEvent } from "@/types/security";
import type { TopologyState } from "@/types/topology";
export type RealtimeState = {
  connected: boolean;
  source: "waiting" | "websocket";
  analyzerStatus: AnalyzerStatus;
  packetSummary: PacketSummary;
  detectionSummary: DetectionSummary;
  trafficSeries: TrafficSeriesPoint[];
  securityEvents: SecurityEvent[];
  topology: TopologyState;
};

export type TrafficSeriesPoint = {
  timestampMs: number;
  time: string;
  pps: number;
  bps: number;
};

type TrafficSample = {
  timestampMs: number;
  analyzerId: string;
  windowSec: number;
  totalPackets: number;
  totalBits: number;
  protocolStats: Record<string, number>;
};

const FIVE_SECONDS_MS = 5 * 1000;
const ONE_MINUTE_MS = 60 * 1000;
const FIVE_MINUTES_MS = 5 * ONE_MINUTE_MS;

const websocketUrl =
  process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws/analyzer";

const initialTimestamp = new Date(0).toISOString();

const initialAnalyzerStatus: AnalyzerStatus = {
  timestamp: initialTimestamp,
  analyzer_id: "-",
  status: "waiting",
  interface: "-",
  capture_active: false,
  backend_connected: false,
  last_packet_at: null,
  last_summary_sent_at: null,
  error_message: null
};

const initialPacketSummary: PacketSummary = {
  timestamp: initialTimestamp,
  analyzer_id: "-",
  window_sec: 1,
  total_packets: 0,
  total_bits: 0,
  protocol_stats: {},
  host_stats: []
};

const initialDetectionSummary: DetectionSummary = {
  timestamp: initialTimestamp,
  analyzer_id: "-",
  network_status: "normal",
  total_bps: 0,
  total_pps: 0,
  active_flow_count: 0,
  suspicious_host_count: 0,
  suspicious_hosts: []
};

const initialTopology: TopologyState = {
  active_path: "primary",
  nodes: [],
  links: []
};

function normalizeNetworkStatus(status?: string): NetworkStatus {
  if (status === "warning" || status === "critical") {
    return status;
  }

  return "normal";
}

function normalizePacketSummary(summary: IncomingPacketSummary): PacketSummary {
  const totalBits = summary.total_bits ?? (summary.total_bytes ?? 0) * 8;

  return {
    timestamp: summary.timestamp,
    analyzer_id: summary.analyzer_id,
    window_sec: summary.window_sec,
    total_packets: summary.total_packets ?? 0,
    total_bits: totalBits,
    protocol_stats: summary.protocol_stats ?? {},
    host_stats: (summary.host_stats ?? []).map((hostStat) => ({
      src_host: hostStat.src_host ?? null,
      src_ip: hostStat.src_ip ?? null,
      dst_host: hostStat.dst_host ?? null,
      dst_ip: hostStat.dst_ip ?? null,
      protocol: hostStat.protocol,
      packet_count: hostStat.packet_count,
      bit_count: hostStat.bit_count ?? (hostStat.byte_count ?? 0) * 8
    }))
  };
}

function toTimestampMs(value: string): number {
  const timestampMs = new Date(value).getTime();

  return Number.isFinite(timestampMs) ? timestampMs : Date.now();
}

function toTrafficSample(summary: PacketSummary): TrafficSample {
  return {
    timestampMs: toTimestampMs(summary.timestamp),
    analyzerId: summary.analyzer_id,
    windowSec: summary.window_sec,
    totalPackets: summary.total_packets,
    totalBits: summary.total_bits,
    protocolStats: summary.protocol_stats
  };
}

function formatSecondLabel(timestampMs: number): string {
  return new Intl.DateTimeFormat("ko-KR", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(new Date(timestampMs));
}

function buildTrafficSeries(samples: TrafficSample[]): TrafficSeriesPoint[] {
  const referenceMs = samples.at(-1)?.timestampMs ?? Date.now();
  const latestCompleteBucketEnd =
    Math.floor(referenceMs / FIVE_SECONDS_MS) * FIVE_SECONDS_MS;
  const visibleSamples = samples.filter(
    (sample) => sample.timestampMs > referenceMs - FIVE_MINUTES_MS
  );
  const buckets = new Map<
    number,
    {
      totalPackets: number;
      totalBits: number;
      totalWindowSec: number;
    }
  >();

  visibleSamples.forEach((sample) => {
    const bucketStart =
      Math.floor(sample.timestampMs / FIVE_SECONDS_MS) * FIVE_SECONDS_MS;
    const bucketEnd = bucketStart + FIVE_SECONDS_MS;

    if (bucketEnd > latestCompleteBucketEnd) {
      return;
    }

    const bucket = buckets.get(bucketStart) ?? {
      totalPackets: 0,
      totalBits: 0,
      totalWindowSec: 0
    };

    bucket.totalPackets += sample.totalPackets;
    bucket.totalBits += sample.totalBits;
    bucket.totalWindowSec += sample.windowSec;
    buckets.set(bucketStart, bucket);
  });

  return Array.from(buckets.entries())
    .sort(([leftStart], [rightStart]) => leftStart - rightStart)
    .map(([bucketStart, bucket]) => {
      const bucketEnd = bucketStart + FIVE_SECONDS_MS;
      const divisor = Math.max(bucket.totalWindowSec, 1);

      return {
        timestampMs: bucketEnd,
        time: formatSecondLabel(bucketEnd),
        pps: Math.round(bucket.totalPackets / divisor),
        bps: Math.round(bucket.totalBits / divisor)
      };
    });
}

function aggregatePacketSummary(
  latest: PacketSummary,
  samples: TrafficSample[]
): PacketSummary {
  const referenceMs = samples.at(-1)?.timestampMs ?? Date.now();
  const oneMinuteSamples = samples.filter(
    (sample) => sample.timestampMs > referenceMs - ONE_MINUTE_MS
  );
  const protocolStats = oneMinuteSamples.reduce<Record<string, number>>(
    (stats, sample) => {
      Object.entries(sample.protocolStats).forEach(([protocol, value]) => {
        stats[protocol] = (stats[protocol] ?? 0) + value;
      });

      return stats;
    },
    {}
  );

  return {
    ...latest,
    total_packets: oneMinuteSamples.reduce(
      (sum, sample) => sum + sample.totalPackets,
      0
    ),
    total_bits: oneMinuteSamples.reduce(
      (sum, sample) => sum + sample.totalBits,
      0
    ),
    protocol_stats: protocolStats
  };
}

function aggregateDetectionSummary(
  latest: DetectionSummary,
  samples: TrafficSample[]
): DetectionSummary {
  const referenceMs = samples.at(-1)?.timestampMs ?? Date.now();
  const fiveSecondSamples = samples.filter(
    (sample) => sample.timestampMs > referenceMs - FIVE_SECONDS_MS
  );
  const totalBits = fiveSecondSamples.reduce(
    (sum, sample) => sum + sample.totalBits,
    0
  );
  const totalPackets = fiveSecondSamples.reduce(
    (sum, sample) => sum + sample.totalPackets,
    0
  );

  return {
    ...latest,
    total_bps: Math.round(totalBits / 5),
    total_pps: Math.round(totalPackets / 5)
  };
}

function isPacketSummaryPayload(data: unknown): data is IncomingPacketSummary {
  return Boolean(
    data &&
      typeof data === "object" &&
      "timestamp" in data &&
      "analyzer_id" in data &&
      "window_sec" in data &&
      ("total_packets" in data || "total_bits" in data || "total_bytes" in data)
  );
}

function isDetectionSummaryPayload(
  data: unknown
): data is IncomingDetectionSummary {
  return Boolean(
    data &&
      typeof data === "object" &&
      "timestamp" in data &&
      "analyzer_id" in data &&
      ("network_status" in data ||
        "total_bps" in data ||
        "top_talkers" in data ||
        "suspicious_hosts" in data)
  );
}

function parseRealtimeMessage(rawData: string): RealtimeMessage | null {
  const parsed = JSON.parse(rawData) as unknown;

  if (!parsed || typeof parsed !== "object") {
    return null;
  }

  if ("type" in parsed && "data" in parsed) {
    return parsed as RealtimeMessage;
  }

  if ("type" in parsed && parsed.type === "echo" && "message" in parsed) {
    const echoMessage = parsed.message;

    if (typeof echoMessage === "string") {
      return parseRealtimeMessage(echoMessage);
    }
  }

  if (isPacketSummaryPayload(parsed)) {
    return {
      type: "packet_summary",
      data: parsed
    };
  }

  if (isDetectionSummaryPayload(parsed)) {
    return {
      type: "detection_summary",
      data: parsed
    };
  }

  return null;
}

function normalizeDetectionSummary(
  summary: IncomingDetectionSummary
): DetectionSummary {
  const topTalkers = summary.top_talkers ?? [];
  const suspiciousHosts =
    summary.suspicious_hosts ??
    topTalkers
      .filter((talker) => talker.status && talker.status !== "normal")
      .map((talker) => ({
        host: talker.host ?? null,
        ip: talker.ip,
        protocol: talker.protocol ?? "UNKNOWN",
        bps: talker.bps,
        pps: talker.pps,
        reasons: talker.reasons ?? [`host status: ${talker.status}`]
      }));

  return {
    timestamp: summary.timestamp,
    analyzer_id: summary.analyzer_id,
    network_status: normalizeNetworkStatus(summary.network_status),
    total_bps:
      summary.total_bps ?? topTalkers.reduce((sum, talker) => sum + talker.bps, 0),
    total_pps:
      summary.total_pps ?? topTalkers.reduce((sum, talker) => sum + talker.pps, 0),
    active_flow_count: summary.active_flow_count ?? topTalkers.length,
    suspicious_host_count:
      summary.suspicious_host_count ?? suspiciousHosts.length,
    suspicious_hosts: suspiciousHosts
  };
}

export function useRealtime(): RealtimeState {
  const [connected, setConnected] = useState(false);
  const [source, setSource] = useState<"waiting" | "websocket">("waiting");
  const [analyzerStatus, setAnalyzerStatus] = useState(initialAnalyzerStatus);
  const [packetSummary, setPacketSummary] = useState(initialPacketSummary);
  const [detectionSummary, setDetectionSummary] = useState(initialDetectionSummary);
  const [trafficSamples, setTrafficSamples] = useState<TrafficSample[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [topology, setTopology] = useState(initialTopology);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let closedByEffect = false;

    const connect = () => {
      socket = new WebSocket(websocketUrl);

      socket.onopen = () => {
        setConnected(true);
      };

      socket.onclose = () => {
        setConnected(false);

        if (!closedByEffect) {
          reconnectTimer = setTimeout(connect, 3000);
        }
      };

      socket.onerror = () => {
        setConnected(false);
      };

      socket.onmessage = (event) => {
        try {
          const message = parseRealtimeMessage(event.data);

          if (!message) {
            return;
          }

          setSource("websocket");

          if (message.type === "analyzer_status") {
            setAnalyzerStatus(message.data);
          }

          if (message.type === "packet_summary") {
            const nextPacketSummary = normalizePacketSummary(message.data);
            const computedBps =
              nextPacketSummary.window_sec > 0
                ? nextPacketSummary.total_bits / nextPacketSummary.window_sec
                : 0;

            setPacketSummary(nextPacketSummary);
            setTrafficSamples((prev) => {
              const nextSample = toTrafficSample(nextPacketSummary);

              return [...prev, nextSample].filter(
                (sample) => sample.timestampMs > nextSample.timestampMs - FIVE_MINUTES_MS
              );
            });
            setDetectionSummary((prev) => ({
              ...prev,
              timestamp: nextPacketSummary.timestamp,
              analyzer_id: nextPacketSummary.analyzer_id,
              total_bps: computedBps,
              total_pps:
                nextPacketSummary.window_sec > 0
                  ? nextPacketSummary.total_packets / nextPacketSummary.window_sec
                  : 0
            }));
            setAnalyzerStatus((prev) => ({
              ...prev,
              timestamp: nextPacketSummary.timestamp,
              analyzer_id: nextPacketSummary.analyzer_id,
              status: "running",
              capture_active: true,
              backend_connected: true,
              last_packet_at: nextPacketSummary.timestamp,
              last_summary_sent_at: nextPacketSummary.timestamp,
              error_message: null
            }));
          }

          if (
            message.type === "detection_summary" ||
            message.type === "traffic_analysis"
          ) {
            const nextDetectionSummary = normalizeDetectionSummary(message.data);

            setDetectionSummary(nextDetectionSummary);
            setAnalyzerStatus((prev) => ({
              ...prev,
              timestamp: nextDetectionSummary.timestamp,
              analyzer_id: nextDetectionSummary.analyzer_id,
              status: "running",
              backend_connected: true,
              last_summary_sent_at: nextDetectionSummary.timestamp,
              error_message: null
            }));
          }

          if (message.type === "security_event") {
            setSecurityEvents((prev) => [message.data, ...prev].slice(0, 100));
          }

          if (message.type === "topology_update") {
            setTopology(message.data);
          }
        } catch {
          // Invalid messages are ignored so one bad frame does not break the dashboard.
        }
      };
    };

    connect();

    return () => {
      closedByEffect = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, []);

  const aggregatedPacketSummary = useMemo(
    () => aggregatePacketSummary(packetSummary, trafficSamples),
    [packetSummary, trafficSamples]
  );
  const aggregatedDetectionSummary = useMemo(
    () => aggregateDetectionSummary(detectionSummary, trafficSamples),
    [detectionSummary, trafficSamples]
  );
  const trafficSeries = useMemo(
    () => buildTrafficSeries(trafficSamples),
    [trafficSamples]
  );

  return useMemo(
    () => ({
      connected,
      source,
      analyzerStatus,
      packetSummary: aggregatedPacketSummary,
      detectionSummary: aggregatedDetectionSummary,
      trafficSeries,
      securityEvents,
      topology
    }),
    [
      aggregatedDetectionSummary,
      aggregatedPacketSummary,
      analyzerStatus,
      connected,
      securityEvents,
      source,
      topology,
      trafficSeries
    ]
  );
}
