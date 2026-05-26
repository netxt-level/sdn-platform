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
import {
  mockAnalyzerStatus,
  mockDetectionSummary,
  mockPacketSummary,
  mockSecurityEvents,
  mockTopology
} from "@/lib/mockData";

export type RealtimeState = {
  connected: boolean;
  source: "mock" | "websocket";
  analyzerStatus: AnalyzerStatus;
  packetSummary: PacketSummary;
  detectionSummary: DetectionSummary;
  securityEvents: SecurityEvent[];
  topology: TopologyState;
};

const websocketUrl =
  process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws/analyzer";

function randomBetween(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

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
  const [source, setSource] = useState<"mock" | "websocket">("mock");
  const [lastLiveMessageAt, setLastLiveMessageAt] = useState<number | null>(null);
  const [analyzerStatus, setAnalyzerStatus] = useState(mockAnalyzerStatus);
  const [packetSummary, setPacketSummary] = useState(mockPacketSummary);
  const [detectionSummary, setDetectionSummary] = useState(mockDetectionSummary);
  const [securityEvents, setSecurityEvents] = useState(mockSecurityEvents);
  const [topology, setTopology] = useState(mockTopology);

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

          setLastLiveMessageAt(Date.now());
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

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      const nowMs = Date.now();
      const shouldUseMock =
        !lastLiveMessageAt || nowMs - lastLiveMessageAt > 5000;

      if (!shouldUseMock) {
        return;
      }

      const now = new Date(nowMs).toISOString();
      const tcpPackets = randomBetween(760, 1200);
      const udpPackets = randomBetween(120, 360);
      const icmpPackets = randomBetween(20, 140);
      const unknownPackets = randomBetween(0, 30);
      const totalPackets =
        tcpPackets + udpPackets + icmpPackets + unknownPackets;
      const totalBits = totalPackets * randomBetween(5200, 8200);
      const totalBps = Math.round(totalBits * randomBetween(7, 12) / 10);
      const totalPps = totalPackets;
      const isWarning = icmpPackets > 100 || udpPackets > 320;

      setSource("mock");
      setAnalyzerStatus((prev) => ({
        ...prev,
        timestamp: now,
        status: "running",
        capture_active: true,
        backend_connected: connected,
        last_packet_at: now,
        last_summary_sent_at: now,
        error_message: connected ? null : "waiting for live analyzer data"
      }));
      setPacketSummary((prev) => ({
        ...prev,
        timestamp: now,
        total_packets: totalPackets,
        total_bits: totalBits,
        protocol_stats: {
          TCP: tcpPackets,
          UDP: udpPackets,
          ICMP: icmpPackets,
          UNKNOWN: unknownPackets
        }
      }));
      setDetectionSummary((prev) => ({
        ...prev,
        timestamp: now,
        network_status: isWarning ? "warning" : "normal",
        total_bps: totalBps,
        total_pps: totalPps,
        active_flow_count: randomBetween(12, 28),
        suspicious_host_count: isWarning ? 1 : 0,
        suspicious_hosts: isWarning
          ? [
              {
                host: "h2",
                ip: "10.0.0.2",
                protocol: icmpPackets > 100 ? "ICMP" : "UDP",
                bps: Math.round(totalBps * 0.22),
                pps: Math.round(totalPps * 0.18),
                reasons: ["Mock traffic threshold exceeded"]
              }
            ]
          : []
      }));
    }, 1000);

    return () => window.clearInterval(intervalId);
  }, [lastLiveMessageAt]);

  return useMemo(
    () => ({
      connected,
      source,
      analyzerStatus,
      packetSummary,
      detectionSummary,
      securityEvents,
      topology
    }),
    [
      analyzerStatus,
      connected,
      detectionSummary,
      packetSummary,
      securityEvents,
      source,
      topology
    ]
  );
}
