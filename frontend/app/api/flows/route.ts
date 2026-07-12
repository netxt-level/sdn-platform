import { NextResponse } from "next/server";

const backendUrl = process.env.BACKEND_INTERNAL_URL ?? "http://localhost:8000";

function backendFlowUrl(request: Request) {
  const requestUrl = new URL(request.url);
  const targetUrl = new URL("/api/flows", backendUrl);
  targetUrl.search = requestUrl.search;
  return targetUrl;
}

async function proxyBackendResponse(response: Response) {
  const body = await response.text();
  const contentType = response.headers.get("content-type") ?? "application/json";

  return new Response(body, {
    status: response.status,
    headers: {
      "content-type": contentType
    }
  });
}

export async function GET(request: Request) {
  try {
    const response = await fetch(backendFlowUrl(request), {
      method: "GET",
      cache: "no-store"
    });

    return proxyBackendResponse(response);
  } catch {
    return NextResponse.json({ detail: "Flow Rule 조회 실패" }, { status: 502 });
  }
}

export async function POST() {
  return NextResponse.json(
    { detail: "수동 Flow Rule 생성은 관리자 권한 기능 연결 후 사용할 수 있습니다." },
    { status: 403 }
  );
}
