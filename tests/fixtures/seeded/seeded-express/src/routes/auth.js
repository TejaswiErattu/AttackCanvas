const express = require("express");
const { z } = require("zod");
const { collection } = require("../db");
const { hashPassword } = require("../services/passwords");

const router = express.Router();

const Credentials = z.object({ email: z.string().email(), password: z.string().min(8) });

// SEEDED:x-login-ratelimit
router.post("/login", async (req, res) => {
  const { email, password } = Credentials.parse(req.body);
  const user = await collection("users").findOne({ email });
  if (!user || user.passwordHash !== hashPassword(password, user.salt)) {
    console.warn("login failed");
    return res.status(401).json({ error: "invalid credentials" });
  }
  req.session.regenerate((error) => {
    if (error) return res.status(500).end();
    req.session.userId = String(user._id);
    req.session.role = user.role;
    res.json({ ok: true });
  });
});

router.post("/logout", (req, res) => {
  req.session.destroy(() => res.status(204).end());
});

module.exports = router;
