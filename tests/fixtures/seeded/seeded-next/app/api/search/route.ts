import { NextResponse } from "next/server";
import { pool } from "@/lib/db";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const sort = searchParams.get("sort") ?? "name";
  // SEEDED:n-sql-concat
  const { rows } = await pool.query("SELECT id, name, price_cents FROM products ORDER BY " + sort);
  return NextResponse.json(rows);
}
