import { NextResponse } from "next/server";
import { withRole } from "@/lib/auth";
import { query } from "@/lib/db";

type Context = { params: Promise<{ id: string }> };

// SEEDED:n-ctl-with-role
export const DELETE = withRole("admin", async (_request, _user, { params }: Context) => {
  const { id } = await params;
  await query("DELETE FROM users WHERE id = $1", [id]);
  return new NextResponse(null, { status: 204 });
});
