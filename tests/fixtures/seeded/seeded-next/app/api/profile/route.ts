import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth";
import { query } from "@/lib/db";

// SEEDED:n-cors-wildcard
const CORS_HEADERS = { "Access-Control-Allow-Origin": "*" };

export const GET = withAuth(async (_request, user) => {
  const { rows } = await query("SELECT id, email, display_name FROM users WHERE id = $1", [user.sub]);
  return NextResponse.json(rows[0], { headers: CORS_HEADERS });
});

export function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: { ...CORS_HEADERS, "Access-Control-Allow-Headers": "authorization" },
  });
}
