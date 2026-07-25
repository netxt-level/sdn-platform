import { NextRequest, NextResponse } from "next/server";

export function middleware(request: NextRequest) {
  const backendUrl =
    process.env.BACKEND_INTERNAL_URL ?? "http://localhost:8000";
  const apiKey = process.env.BACKEND_API_KEY;

  if (!apiKey) {
    return NextResponse.json(
      { detail: "Backend API authentication is not configured" },
      { status: 503 }
    );
  }

  const destination = new URL(
    `${request.nextUrl.pathname}${request.nextUrl.search}`,
    backendUrl
  );
  const headers = new Headers(request.headers);
  headers.set("X-API-Key", apiKey);

  return NextResponse.rewrite(destination, {
    request: { headers }
  });
}

export const config = {
  matcher: ["/api/:path*", "/ws/token"]
};
