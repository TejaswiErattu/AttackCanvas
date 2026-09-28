import { NextResponse } from "next/server";

// SEEDED:n-ctl-middleware-headers
const SECURITY_HEADERS: Record<string, string> = {
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
  "X-Frame-Options": "DENY",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
};

export function middleware() {
  const response = NextResponse.next();
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) response.headers.set(name, value);
  return response;
}

export const config = { matcher: "/:path*" };
