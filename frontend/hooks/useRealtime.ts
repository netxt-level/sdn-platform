"use client";

import { useEffect, useMemo, useState } from "react";

import type {
  AnalyzerStatus,
  DetectionSummary,
  IncomingDetectionSummary,
  IncomingPacketSummary,
  NetworkStatus,
  PacketSummary,
  SuspiciousHost
} from "@/types/analyzer";
import type { RealtimeMessage } from "@/types/realtime";
import type { SecurityEvent } from "@/types/security";
import type { TopologyState } from "@/types/topology";
export type RealtimeState = {
  connected: boolean;
  source: "waiting" | "history" | "websocket";
  dashboardSummary: DashboardSummary;
  analyzerStatus: AnalyzerStatus;
  packetSummary: PacketSummary;
  detectionSummary: DetectionSummary;
  trafficSeries: TrafficSeriesPoint[];
  securityEvents: SecurityEvent[];
  topology: TopologyState;
};

export type DashboardSummary = {
  totalPackets: number;
  totalBytes: number;
  currentPps: number;
  currentBps: number;
  networkStatus: NetworkStatus;
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
  bucketed?: boolean;
};

type DashboardTrafficItem = {
  timestamp: string;
  total_packets?: number;
  total_bits?: number;
  pps?: number;
  bps?: number;
};

type DashboardTrafficResponse = {
  items?: DashboardTrafficItem[];
};

type DashboardSummaryResponse = {
  total_packets?: number;
  total_bytes?: number;
  current_pps?: number;
  current_bps?: number;
  network_status?: string;
};

type AnalyzerStatusResponse = {
  items?: Array<AnalyzerStatus & { reported_at?: string | null }>;
};

type DashboardProtocolItem = {
  protocol: string;
  packet_count: number;
};

type DashboardProtocolsResponse = {
  items?: DashboardProtocolItem[];
};

type DashboardSuspiciousHostsResponse = {
  count?: number;
  items?: SuspiciousHost[];
};

const FIVE_SECONDS_MS = 5 * 1000;
const ONE_MINUTE_MS = 60 * 1000;
const FIVE_MINUTES_MS = 5 * ONE_MINUTE_MS;
const SUSPICIOUS_HOST_REFRESH_MS = 5 * 1000;
const DASHBOARD_SUMMARY_REFRESH_MS = 5 * 1000;

const configuredWebsocketUrl = process.env.NEXT_PUBLIC_WS_URL;

function isLoopbackHost(hostname: string) {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1";
}

function getWebsocketUrl() {
  const fallbackProtocol =
    typeof window !== "undefined" && window.location.protocol === "https:"
      ? "wss:"
      : "ws:";
  const fallbackHost =
    typeof window !== "undefined" ? window.location.hostname : "localhost";
  const fallbackUrl = `${fallbackProtocol}//${fallbackHost}:8000/ws/analyzer`;

  if (!configuredWebsocketUrl) {
    return fallbackUrl;
  }

  if (typeof window === "undefined") {
    return configuredWebsocketUrl;
  }

  try {
    const url = new URL(configuredWebsocketUrl);
    const pageHost = window.location.hostname;

    if (isLoopbackHost(url.hostname) && !isLoopbackHost(pageHost)) {
      url.hostname = pageHost;
    }

    return url.toString();
  } catch {
    return configuredWebsocketUrl;
  }
}

const initialTimestamp = new Date(0).toISOString();

const initialDashboardSummary: DashboardSummary = {
  totalPackets: 0,
  totalBytes: 0,
  currentPps: 0,
  currentBps: 0,
  networkStatus: "normal"
};

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

function normalizeDashboardSummary(summary: DashboardSummaryResponse): DashboardSummary {
  return {
    totalPackets: summary.total_packets ?? 0,
    totalBytes: summary.total_bytes ?? 0,
    currentPps: summary.current_pps ?? 0,
    currentBps: summary.current_bps ?? 0,
    networkStatus: normalizeNetworkStatus(summary.network_status)
  };
}

function normalizeStoredAnalyzerStatus(
  status: AnalyzerStatus & { reported_at?: string | null }
): AnalyzerStatus {
  return {
    timestamp: status.timestamp ?? status.reported_at ?? initialTimestamp,
    analyzer_id: status.analyzer_id,
    status: status.status,
    interface: status.interface,
    capture_active: status.capture_active,
    backend_connected: status.backend_connected,
    last_packet_at: status.last_packet_at ?? null,
    last_summary_sent_at: status.last_summary_sent_at ?? null,
    error_message: status.error_message ?? null
  };
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
    protocolStats: summary.protocol_stats,
    bucketed: false
  };
}

function toHistoryTrafficSample(item: DashboardTrafficItem): TrafficSample {
  const totalBits = item.total_bits ?? Math.round((item.bps ?? 0) * 5);
  const totalPackets =
    item.total_packets ?? Math.round((item.pps ?? 0) * 5);

  return {
    timestampMs: toTimestampMs(item.timestamp),
    analyzerId: "-",
    windowSec: 5,
    totalPackets,
    totalBits,
    protocolStats: {},
    bucketed: true
  };
}

function toProtocolStats(items: DashboardProtocolItem[]): Record<string, number> {
  return items.reduce<Record<string, number>>((stats, item) => {
    stats[item.protocol || "UNKNOWN"] =
      (stats[item.protocol || "UNKNOWN"] ?? 0) + (item.packet_count ?? 0);

    return stats;
  }, {});
}

function normalizeAttackType(attackType?: string | null): string {
  const normalizedAttackType = attackType?.trim().toUpperCase();

  return normalizedAttackType || "DOS";
}

function normalizeSuspiciousHosts(items: SuspiciousHost[]): SuspiciousHost[] {
  return items.map((host) => ({
    host: host.host ?? null,
    ip: host.ip,
    protocol: host.protocol ?? "UNKNOWN",
    bps: host.bps ?? 0,
    pps: host.pps ?? 0,
    attack_type: normalizeAttackType(host.attack_type),
    reasons:
      Array.isArray(host.reasons) && host.reasons.length > 0
        ? host.reasons
        : ["stored suspicious host"]
  }));
}

function mergeSuspiciousHosts(
  historyHosts: SuspiciousHost[],
  liveHosts: SuspiciousHost[]
): SuspiciousHost[] {
  const hosts = new Map<string, SuspiciousHost>();

  historyHosts.forEach((host) => {
    hosts.set(`${host.ip}-${host.protocol}-${host.attack_type ?? "UNKNOWN"}`, host);
  });

  liveHosts.forEach((host) => {
    hosts.set(`${host.ip}-${host.protocol}-${host.attack_type ?? "UNKNOWN"}`, host);
  });

  return Array.from(hosts.values()).sort(
    (left, right) =>
      right.bps - left.bps ||
      right.pps - left.pps ||
      left.ip.localeCompare(right.ip)
  );
}

async function fetchDashboardSuspiciousHosts(): Promise<SuspiciousHost[]> {
  const response = await fetch("/api/dashboard/suspicious-hosts?range=1w");

  if (!response.ok) {
    return [];
  }

  const suspiciousHosts =
    (await response.json()) as DashboardSuspiciousHostsResponse;

  return normalizeSuspiciousHosts(suspiciousHosts.items ?? []);
}

async function fetchDashboardSummary(): Promise<DashboardSummary | null> {
  const response = await fetch("/api/dashboard/summary");

  if (!response.ok) {
    return null;
  }

  return normalizeDashboardSummary(
    (await response.json()) as DashboardSummaryResponse
  );
}

function removeTrailingPartialBucket(samples: TrafficSample[]): TrafficSample[] {
  if (samples.length === 0) {
    return samples;
  }

  const lastSample = samples[samples.length - 1];

  if (lastSample.timestampMs % FIVE_SECONDS_MS === 0) {
    return samples;
  }

  return samples.slice(0, -1);
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
  const points = new Map<number, TrafficSeriesPoint>();
  const buckets = new Map<
    number,
    {
      totalPackets: number;
      totalBits: number;
      totalWindowSec: number;
    }
  >();

  visibleSamples.forEach((sample) => {
    if (sample.bucketed) {
      const divisor = Math.max(sample.windowSec, 1);

      points.set(sample.timestampMs, {
        timestampMs: sample.timestampMs,
        time: formatSecondLabel(sample.timestampMs),
        pps: Math.round(sample.totalPackets / divisor),
        bps: Math.round(sample.totalBits / divisor)
      });
      return;
    }

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

  buckets.forEach((bucket, bucketStart) => {
    const bucketEnd = bucketStart + FIVE_SECONDS_MS;
    const divisor = Math.max(bucket.totalWindowSec, 1);

    points.set(bucketEnd, {
      timestampMs: bucketEnd,
      time: formatSecondLabel(bucketEnd),
      pps: Math.round(bucket.totalPackets / divisor),
      bps: Math.round(bucket.totalBits / divisor)
    });
  });

  return Array.from(points.values())
    .sort((left, right) => left.timestampMs - right.timestampMs);
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
  const hasProtocolStats = Object.keys(protocolStats).length > 0;

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
    protocol_stats: hasProtocolStats ? protocolStats : latest.protocol_stats
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
  const suspiciousHosts = normalizeSuspiciousHosts(
    summary.suspicious_hosts ??
      topTalkers
        .filter((talker) => talker.status && talker.status !== "normal")
        .map((talker) => ({
          host: talker.host ?? null,
          ip: talker.ip,
          protocol: talker.protocol ?? "UNKNOWN",
          bps: talker.bps,
          pps: talker.pps,
          attack_type: "DOS",
          reasons: talker.reasons ?? [`host status: ${talker.status}`]
        }))
  );

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
  const [source, setSource] = useState<"waiting" | "history" | "websocket">("waiting");
  const [dashboardSummary, setDashboardSummary] = useState(initialDashboardSummary);
  const [analyzerStatus, setAnalyzerStatus] = useState(initialAnalyzerStatus);
  const [packetSummary, setPacketSummary] = useState(initialPacketSummary);
  const [detectionSummary, setDetectionSummary] = useState(initialDetectionSummary);
  const [dbSuspiciousHosts, setDbSuspiciousHosts] = useState<SuspiciousHost[]>([]);
  const [trafficSamples, setTrafficSamples] = useState<TrafficSample[]>([]);
  const [securityEvents, setSecurityEvents] = useState<SecurityEvent[]>([]);
  const [topology, setTopology] = useState(initialTopology);

  useEffect(() => {
    let ignored = false;
    let refreshTimer: ReturnType<typeof setInterval> | null = null;

    const loadDashboardHistory = async () => {
      try {
        const [
          analyzerStatusResponse,
          trafficResponse,
          protocolsResponse,
          dashboardSummaryResponse,
          historySuspiciousHosts
        ] = await Promise.all([
          fetch("/api/analyzer/status"),
          fetch("/api/dashboard/traffic?range=5m&bucket=5s"),
          fetch("/api/dashboard/protocols?range=1m"),
          fetchDashboardSummary(),
          fetchDashboardSuspiciousHosts()
        ]);

        if (!trafficResponse.ok || !protocolsResponse.ok) {
          return;
        }

        const traffic =
          (await trafficResponse.json()) as DashboardTrafficResponse;
        const protocols =
          (await protocolsResponse.json()) as DashboardProtocolsResponse;
        const summary = dashboardSummaryResponse;
        const analyzerStatuses = analyzerStatusResponse.ok
          ? ((await analyzerStatusResponse.json()) as AnalyzerStatusResponse)
          : null;

        if (ignored) {
          return;
        }

        if (summary) {
          setDashboardSummary(summary);
          setDetectionSummary((prev) => ({
            ...prev,
            network_status: summary.networkStatus,
            total_bps: summary.currentBps,
            total_pps: summary.currentPps
          }));
        }

        const latestAnalyzerStatus = analyzerStatuses?.items?.[0];
        if (latestAnalyzerStatus) {
          setAnalyzerStatus(normalizeStoredAnalyzerStatus(latestAnalyzerStatus));
        }

        const protocolStats = toProtocolStats(protocols.items ?? []);
        setDbSuspiciousHosts(historySuspiciousHosts);
        const historySamples = (traffic.items ?? [])
          .map(toHistoryTrafficSample)
          .sort((left, right) => left.timestampMs - right.timestampMs);
        const completedHistorySamples =
          removeTrailingPartialBucket(historySamples);

        if (completedHistorySamples.length > 0) {
          const lastSample =
            completedHistorySamples[completedHistorySamples.length - 1];
          completedHistorySamples[completedHistorySamples.length - 1] = {
            ...lastSample,
            protocolStats
          };

          setTrafficSamples(completedHistorySamples);
          setPacketSummary({
            timestamp: new Date(lastSample.timestampMs).toISOString(),
            analyzer_id: lastSample.analyzerId,
            window_sec: lastSample.windowSec,
            total_packets: lastSample.totalPackets,
            total_bits: lastSample.totalBits,
            protocol_stats: protocolStats,
            host_stats: []
          });
          setDetectionSummary((prev) => ({
            ...prev,
            timestamp: new Date(lastSample.timestampMs).toISOString(),
            total_bps:
              summary?.currentBps ??
              Math.round(lastSample.totalBits / Math.max(lastSample.windowSec, 1)),
            total_pps:
              summary?.currentPps ??
              Math.round(lastSample.totalPackets / Math.max(lastSample.windowSec, 1)),
            suspicious_host_count: historySuspiciousHosts.length,
            suspicious_hosts: historySuspiciousHosts
          }));
        } else if (Object.keys(protocolStats).length > 0) {
          setPacketSummary((prev) => ({
            ...prev,
            protocol_stats: protocolStats
          }));
        }

        if (historySuspiciousHosts.length > 0) {
          setDetectionSummary((prev) => ({
            ...prev,
            suspicious_host_count: historySuspiciousHosts.length,
            suspicious_hosts: historySuspiciousHosts
          }));
        }

        if (
          completedHistorySamples.length > 0 ||
          Object.keys(protocolStats).length > 0 ||
          historySuspiciousHosts.length > 0
        ) {
          setSource("history");
        }
      } catch {
        // If history is unavailable, the dashboard still waits for live WebSocket data.
      }
    };

    void loadDashboardHistory();
    refreshTimer = setInterval(() => {
      void Promise.all([
        fetchDashboardSummary(),
        fetchDashboardSuspiciousHosts()
      ])
        .then(([summary, historySuspiciousHosts]) => {
          if (!ignored) {
            if (summary) {
              setDashboardSummary(summary);
              setDetectionSummary((prev) => ({
                ...prev,
                network_status: summary.networkStatus,
                total_bps: summary.currentBps,
                total_pps: summary.currentPps
              }));
            }
            setDbSuspiciousHosts(historySuspiciousHosts);
          }
        })
        .catch(() => {
          // Suspicious host polling is best-effort; live WebSocket data still updates the dashboard.
        });
    }, Math.max(SUSPICIOUS_HOST_REFRESH_MS, DASHBOARD_SUMMARY_REFRESH_MS));

    return () => {
      ignored = true;
      if (refreshTimer) clearInterval(refreshTimer);
    };
  }, []);

  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let closedByEffect = false;

    const connect = () => {
      socket = new WebSocket(getWebsocketUrl());

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
              const samplesWithoutSameTimestamp = prev.filter(
                (sample) => sample.timestampMs !== nextSample.timestampMs
              );

              return [...samplesWithoutSameTimestamp, nextSample].filter(
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

            setDashboardSummary((prev) => ({
              ...prev,
              currentBps: nextDetectionSummary.total_bps,
              currentPps: nextDetectionSummary.total_pps,
              networkStatus: nextDetectionSummary.network_status
            }));
            setDetectionSummary(nextDetectionSummary);
            if (nextDetectionSummary.suspicious_hosts.length > 0) {
              setDbSuspiciousHosts((prev) =>
                mergeSuspiciousHosts(
                  prev,
                  nextDetectionSummary.suspicious_hosts
                )
              );
            }
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
  const visibleDetectionSummary = useMemo(() => {
    const suspiciousHosts = mergeSuspiciousHosts(
      dbSuspiciousHosts,
      aggregatedDetectionSummary.suspicious_hosts
    );

    return {
      ...aggregatedDetectionSummary,
      suspicious_host_count: suspiciousHosts.length,
      suspicious_hosts: suspiciousHosts
    };
  }, [aggregatedDetectionSummary, dbSuspiciousHosts]);
  const trafficSeries = useMemo(
    () => buildTrafficSeries(trafficSamples),
    [trafficSamples]
  );

  return useMemo(
    () => ({
      connected,
      source,
      dashboardSummary,
      analyzerStatus,
      packetSummary: aggregatedPacketSummary,
      detectionSummary: visibleDetectionSummary,
      trafficSeries,
      securityEvents,
      topology
    }),
    [
      aggregatedPacketSummary,
      analyzerStatus,
      connected,
      dashboardSummary,
      securityEvents,
      source,
      topology,
      trafficSeries,
      visibleDetectionSummary
    ]
  );
}
