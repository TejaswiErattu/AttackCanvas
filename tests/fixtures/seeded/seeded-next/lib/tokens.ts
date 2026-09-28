import jwt from "jsonwebtoken";

export type TokenClaims = { sub: string; role: "customer" | "admin" };

const SIGNING_KEY = "seeded-demo-signing-key-not-a-secret";

export function issueToken(userId: string, role: TokenClaims["role"] = "customer"): string {
  // SEEDED:n-jwt-literal
  return jwt.sign({ sub: userId, role }, SIGNING_KEY, { expiresIn: "1h" });
}

export function verifyAccessToken(token: string): TokenClaims | null {
  try {
    // SEEDED:n-jwt-none
    return jwt.verify(token, SIGNING_KEY, { algorithms: ["HS256", "none"] }) as TokenClaims;
  } catch {
    return null;
  }
}
