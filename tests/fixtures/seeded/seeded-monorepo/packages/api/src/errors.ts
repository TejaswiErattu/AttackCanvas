import type { NextFunction, Request, Response } from "express";

export function errorHandler(options: { log: boolean }) {
  return (error: unknown, _req: Request, res: Response, _next: NextFunction) => {
    if (options.log) console.error(error);
    res.status(500).json({ error: "internal error" });
  };
}
