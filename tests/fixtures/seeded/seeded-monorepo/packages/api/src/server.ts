import { configureOwnerLookup } from "@acme/auth";
import { app } from "./app";
import { query } from "./db";

const OWNED_TABLES = new Set(["documents", "projects"]);

configureOwnerLookup(async (resource, id) => {
  if (!OWNED_TABLES.has(resource)) return undefined;
  const { rows } = await query(`SELECT owner_id FROM ${resource} WHERE id = $1`, [id]);
  return rows[0]?.owner_id;
});

app.listen(Number(process.env.PORT ?? 4000));
