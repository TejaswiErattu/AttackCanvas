import { NextResponse } from "next/server";
import { query } from "@/lib/db";
import { ExportRange } from "@/lib/validation";

function toCsv(rows: Record<string, unknown>[]): string {
  const header = Object.keys(rows[0] ?? {});
  return [header.join(","), ...rows.map((row) => header.map((key) => String(row[key])).join(","))].join("\n");
}

// SEEDED:n-export-unauth
export async function POST(request: Request) {
  const { from, to } = ExportRange.parse(await request.json());
  const { rows } = await query(
    "SELECT id, user_id, sku, quantity, created_at FROM orders WHERE created_at BETWEEN $1 AND $2",
    [from, to],
  );
  return new NextResponse(toCsv(rows), { headers: { "content-type": "text/csv" } });
}
