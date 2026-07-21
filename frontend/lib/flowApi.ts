import type {
  FlowRule,
  FlowRuleCreatePayload,
  FlowRulesResponse
} from "@/types/flow";

export class FlowApiError extends Error {}

async function errorMessage(response: Response) {
  try {
    const body = (await response.json()) as {
      detail?: string;
      error_message?: string | null;
    };
    return body.error_message ?? body.detail ?? `HTTP ${response.status}`;
  } catch {
    return `HTTP ${response.status}`;
  }
}

export async function getFlowRules(): Promise<FlowRulesResponse> {
  const response = await fetch("/api/flows", { cache: "no-store" });
  if (!response.ok) {
    throw new FlowApiError(await errorMessage(response));
  }
  return response.json() as Promise<FlowRulesResponse>;
}

export async function createFlowRule(
  payload: FlowRuleCreatePayload
): Promise<FlowRule> {
  const response = await fetch("/api/flows", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!response.ok) {
    throw new FlowApiError(await errorMessage(response));
  }
  return response.json() as Promise<FlowRule>;
}

export async function removeFlowRule(ruleId: string): Promise<FlowRule> {
  const response = await fetch(`/api/flows/${encodeURIComponent(ruleId)}`, {
    method: "DELETE"
  });
  const result = (await response.json()) as FlowRule & { detail?: string };
  if (!response.ok || result.status !== "REMOVED") {
    throw new FlowApiError(
      result.error_message
        ?? result.detail
        ?? result.status
        ?? `HTTP ${response.status}`
    );
  }
  return result;
}
