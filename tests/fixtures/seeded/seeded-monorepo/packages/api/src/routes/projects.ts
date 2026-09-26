import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "@acme/auth";
import { query } from "../db";

const router = Router();

const ProjectInput = z.object({ name: z.string().min(1).max(120) });

// SEEDED:m-ctl-barrel-guard
router.post("/", requireAuth, async (req, res) => {
  const { name } = ProjectInput.parse(req.body);
  const { rows } = await query(
    "INSERT INTO projects (name, owner_id) VALUES ($1, $2) RETURNING id",
    [name, req.session!.userId],
  );
  res.status(201).json(rows[0]);
});

// SEEDED:m-authz-project
router.patch("/:projectId", requireAuth, async (req, res) => {
  const { name } = ProjectInput.parse(req.body);
  await query("UPDATE projects SET name = $1 WHERE id = $2", [name, req.params.projectId]);
  res.status(204).end();
});

export default router;
