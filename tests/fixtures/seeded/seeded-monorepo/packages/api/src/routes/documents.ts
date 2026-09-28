import { Router } from "express";
import { guard, requireAuth } from "@acme/auth";
import { query } from "../db";

const router = Router();

// SEEDED:m-ctl-cross-pkg-owner
router.get("/:documentId", requireAuth, guard, async (req, res) => {
  const { rows } = await query("SELECT id, title, body FROM documents WHERE id = $1", [
    req.params.documentId,
  ]);
  res.json(rows[0] ?? null);
});

export default router;
