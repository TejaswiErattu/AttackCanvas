import { NextResponse } from "next/server";
import { withAuth } from "@/lib/auth";
import { query } from "@/lib/db";
import { OrderInput } from "@/lib/validation";

export const GET = withAuth(async (_request, user) => {
  const { rows } = await query("SELECT id, sku, quantity FROM orders WHERE user_id = $1", [user.sub]);
  return NextResponse.json(rows);
});

// SEEDED:n-ctl-with-auth-barrel
// SEEDED:n-ctl-zod-barrel
// SEEDED:n-ctl-next-errors
export const POST = withAuth(async (request, user) => {
  const order = OrderInput.parse(await request.json());
  const { rows } = await query(
    "INSERT INTO orders (user_id, sku, quantity) VALUES ($1, $2, $3) RETURNING id",
    [user.sub, order.sku, order.quantity],
  );
  return NextResponse.json(rows[0], { status: 201 });
});
