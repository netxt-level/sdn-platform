"use client";

import { useEffect, useMemo, useState } from "react";

import type {
  AnalyzerStatus,
  DetectionSummary,
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
            setPacketSummary(message.data);
          }

          if (message.type === "detection_summary") {
            setDetectionSummary(message.data);
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
