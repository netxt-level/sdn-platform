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

function normalizeNetworkStatus(status?: string): NetworkStatus {
  if (status === "warning" || status === "critical") {
    return status;
  }

  return "normal";
}

function normalizePacketSummary(summary: IncomingPacketSummary): PacketSummary {
  return {
    timestamp: summary.timestamp,
    analyzer_id: summary.analyzer_id,
    window_sec: summary.window_sec,
    total_packets: summary.total_packets ?? 0,
    total_bits: summary.total_bits ?? (summary.total_bytes ?? 0) * 8,
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
        setSource("websocket");
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
          const message = JSON.parse(event.data) as RealtimeMessage;

          if (message.type === "analyzer_status") {
            setAnalyzerStatus(message.data);
          }

          if (message.type === "packet_summary") {
            setPacketSummary(normalizePacketSummary(message.data));
          }

          if (
            message.type === "detection_summary" ||
            message.type === "traffic_analysis"
          ) {
            setDetectionSummary(normalizeDetectionSummary(message.data));
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
