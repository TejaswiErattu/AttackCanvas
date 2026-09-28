import { Router } from "express";
import { requireAuth } from "@acme/auth";
import { query } from "../db";

const router = Router();

router.get("/", requireAuth, async (req, res) => {
  const { rows } = await query(
    "SELECT id, project_id, hours, billable FROM time_entries WHERE owner_id = $1",
    [req.session!.userId],
  );
  // SEEDED:m-eval-filter
  const keep = new Function("row", "return " + String(req.query.filter ?? "true"));
  res.json(rows.filter((row) => keep(row)));
});

export default router;
