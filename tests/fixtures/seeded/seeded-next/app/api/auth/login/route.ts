import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { query } from "@/lib/db";
import { logger } from "@/lib/logger";
import { loginLimiter } from "@/lib/rate-limit";
import { issueToken } from "@/lib/tokens";
import { LoginInput } from "@/lib/validation";

// SEEDED:n-ctl-login-limiter
export async function POST(request: Request) {
  const ip = request.headers.get("x-forwarded-for") ?? "unknown";
  const { success } = await loginLimiter.limit(ip);
  if (!success) return NextResponse.json({ error: "too many attempts" }, { status: 429 });

  const { email, password } = LoginInput.parse(await request.json());
  const { rows } = await query("SELECT id, role, password_hash FROM users WHERE email = $1", [email]);
  const user = rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    logger.warn({ ip }, "login failed");
    return NextResponse.json({ error: "invalid credentials" }, { status: 401 });
  }
  logger.info({ userId: user.id }, "login succeeded");
  return NextResponse.json({ token: issueToken(user.id, user.role) });
}
