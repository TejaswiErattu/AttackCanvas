import type { NextFunction, Request, Response } from "express";

type OwnerLookup = (resource: string, id: string) => Promise<string | undefined>;

let ownerLookup: OwnerLookup = async () => undefined;

export function configureOwnerLookup(lookup: OwnerLookup) {
  ownerLookup = lookup;
}

export function lookupOwner(resource: string, id: string) {
  return ownerLookup(resource, id);
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.session?.userId) return res.status(401).json({ error: "sign in required" });
  next();
}
