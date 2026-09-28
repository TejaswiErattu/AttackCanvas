import { Pool } from "pg";

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // SEEDED:m-tls-off
  ssl: { rejectUnauthorized: false },
});

export async function query(text: string, params: unknown[] = []) {
  return pool.query(text, params);
}
