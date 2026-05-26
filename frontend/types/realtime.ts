import type {
  AnalyzerStatus,
  DetectionSummary,
  PacketSummary
} from "@/types/analyzer";
import type { SecurityEvent } from "@/types/security";
import type { TopologyState } from "@/types/topology";

export type RealtimeMessage =
  | { type: "analyzer_status"; data: AnalyzerStatus }
  | { type: "packet_summary"; data: PacketSummary }
  | { type: "detection_summary"; data: DetectionSummary }
  | { type: "security_event"; data: SecurityEvent }
  | { type: "topology_update"; data: TopologyState };
