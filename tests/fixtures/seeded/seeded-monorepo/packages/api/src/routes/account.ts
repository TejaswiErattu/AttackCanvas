import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "@acme/auth";
import { query } from "../db";

const router = Router();

const EmailChange = z.object({ email: z.string().email() });

// SEEDED:m-csrf-form
router.post("/email", requireAuth, async (req, res) => {
  const { email } = EmailChange.parse(req.body);
  await query("UPDATE users SET email = $1 WHERE id = $2", [email, req.session!.userId]);
  res.redirect("/account");
});

export default router;
