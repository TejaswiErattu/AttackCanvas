import type { NextFunction, Request, Response } from "express";
import { lookupOwner } from "./session";

/** Only the owner of the record named in the URL may continue. */
// SEEDED:m-ctl-cross-pkg-owner
export async function guard(req: Request, res: Response, next: NextFunction) {
  const resource = req.baseUrl.split("/").pop() ?? "";
  const id = Object.values(req.params)[0] ?? "";
  const ownerId = await lookupOwner(resource, id);
  if (ownerId === undefined || ownerId !== req.session?.userId) {
    return res.status(404).end();
  }
  next();
}
