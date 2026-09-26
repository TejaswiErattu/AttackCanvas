import rateLimit from "express-rate-limit";

// SEEDED:m-ctl-limiter-pkg
export const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});
