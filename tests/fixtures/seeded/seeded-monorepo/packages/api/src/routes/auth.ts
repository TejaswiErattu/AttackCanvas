import { Router } from "express";
import { z } from "zod";
import { loginLimiter, verifyPassword } from "@acme/auth";
import { query } from "../db";

const router = Router();

const Credentials = z.object({ email: z.string().email(), password: z.string().min(8) });

// SEEDED:m-ctl-limiter-pkg
// SEEDED:m-ctl-cross-pkg-kdf
router.post("/login", loginLimiter, async (req, res) => {
  const { email, password } = Credentials.parse(req.body);
  const { rows } = await query("SELECT id, password_hash FROM users WHERE email = $1", [email]);
  const user = rows[0];
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return res.status(401).json({ error: "invalid credentials" });
  }
  req.session = { userId: user.id };
  res.json({ ok: true });
});

export default router;
