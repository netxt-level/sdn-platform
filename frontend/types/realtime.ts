import type {
  AnalyzerChangeMessage,
  AnalyzerStatus,
  DetectionSummary,
  IncomingDetectionSummary,
  IncomingPacketSummary,
  PacketSummary
} from "@/types/analyzer";
import type { SecurityEvent } from "@/types/security";
import type { TopologyState } from "@/types/topology";

export type RealtimeMessage =
  | { type: "analyzer_status"; data: AnalyzerStatus }
  | { type: "analyzer_change"; data: AnalyzerChangeMessage }
  | { type: "packet_summary"; data: PacketSummary | IncomingPacketSummary }
  | { type: "detection_summary"; data: DetectionSummary | IncomingDetectionSummary }
  | { type: "traffic_analysis"; data: IncomingDetectionSummary }
  | { type: "security_event"; data: SecurityEvent }
  | { type: "topology_update"; data: TopologyState };
