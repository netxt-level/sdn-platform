import type { PathStatus } from "@/types/path";

export async function getPathStatus(): Promise<PathStatus> {
  const response = await fetch("/api/path/status", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`경로 상태 조회 실패: HTTP ${response.status}`);
  }
  return response.json() as Promise<PathStatus>;
}
